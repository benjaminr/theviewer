//! Dock panel: crypto and compression constants found anywhere in the file
//! ([`crate::crypto_constants::scan_constants`]), grouped by algorithm.
//!
//! The whole document is scanned on a background thread in overlapping
//! chunks, so constants straddling a chunk boundary are still found. An
//! unedited file is read straight from its on-disk mapping; an edited one is
//! copied first (up to [`EDITED_SCAN_LIMIT`]). Clicking a match selects its
//! bytes; "Highlight in view" pins every match onto the raster.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, RichText, Sense, Ui};
use rayon::prelude::*;

use crate::app::ViewerApp;
use crate::crypto_constants::{self, CryptoMatch};
use crate::theme;

/// Bytes scanned per chunk.
const CHUNK_BYTES: usize = 16 * 1024 * 1024;
/// Largest edited document copied for scanning.
pub const EDITED_SCAN_LIMIT: usize = 256 * 1024 * 1024;
/// How often to look for finished results while a scan runs.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Matches below this confidence are hidden unless asked for.
const WEAK_CONFIDENCE: f32 = 0.5;
/// Prefix of the ids of findings this panel pins to the view.
const PINNED_ID_PREFIX: &str = "crypto:";

/// Which document a scan describes, so stale results can be flagged.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DocumentKey {
    path: Option<std::path::PathBuf>,
    len: usize,
    version: u64,
}

impl DocumentKey {
    fn of(app: &ViewerApp) -> Self {
        DocumentKey { path: app.document.path().map(Into::into), len: app.document.len(), version: app.document.version() }
    }
}

/// A finished scan.
struct ScanResult {
    key: DocumentKey,
    scanned: usize,
    matches: Vec<CryptoMatch>,
}

/// Everything the crypto constants panel keeps between frames.
#[derive(Default)]
pub struct CryptoConstantsState {
    pending: Option<Receiver<ScanResult>>,
    /// Bytes scanned so far by the running scan, and the total.
    progress: Option<(Arc<AtomicUsize>, usize)>,
    result: Option<ScanResult>,
    /// Also list matches of short constants that occur by coincidence.
    pub show_weak: bool,
}

impl CryptoConstantsState {
    /// Matches from the last finished scan, ordered by offset.
    pub fn matches(&self) -> &[CryptoMatch] {
        self.result.as_ref().map_or(&[], |result| result.matches.as_slice())
    }
}

/// Scan `bytes` in overlapping chunks across all cores, counting progress.
fn scan_in_chunks(bytes: &[u8], progress: &AtomicUsize) -> Vec<CryptoMatch> {
    let starts: Vec<usize> = (0..bytes.len()).step_by(CHUNK_BYTES).collect();
    let mut matches: Vec<CryptoMatch> = starts
        .into_par_iter()
        .flat_map_iter(|start| {
            let end = (start + CHUNK_BYTES + crypto_constants::RECOMMENDED_OVERLAP).min(bytes.len());
            let found = crypto_constants::scan_constants(&bytes[start..end], start);
            progress.fetch_add((end - start).min(CHUNK_BYTES), Ordering::Relaxed);
            found
        })
        .collect();
    matches.sort_by(|a, b| a.start.cmp(&b.start).then(b.len.cmp(&a.len)));
    // The overlap means a match near a boundary is found by both chunks.
    let mut seen = HashSet::new();
    matches.retain(|found| seen.insert((found.start, found.len, found.title())));
    matches
}

fn start_scan(state: &mut CryptoConstantsState, app: &mut ViewerApp) {
    let key = DocumentKey::of(app);
    let progress = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = mpsc::channel();
    let worker_progress = Arc::clone(&progress);
    let total;
    if app.document.is_modified() {
        let bytes = app.document.read_range(0, EDITED_SCAN_LIMIT);
        total = bytes.len();
        thread::spawn(move || {
            let matches = scan_in_chunks(&bytes, &worker_progress);
            // The receiver may be gone if the panel was closed; nothing to do then.
            let _ = sender.send(ScanResult { key, scanned: bytes.len(), matches });
        });
    } else {
        let backing = app.document.original();
        total = backing.as_slice().len();
        thread::spawn(move || {
            let bytes = backing.as_slice();
            let matches = scan_in_chunks(bytes, &worker_progress);
            let _ = sender.send(ScanResult { key, scanned: bytes.len(), matches });
        });
    }
    state.pending = Some(receiver);
    state.progress = Some((progress, total));
}

fn poll(state: &mut CryptoConstantsState, ctx: &egui::Context) {
    let Some(receiver) = &state.pending else { return };
    match receiver.try_recv() {
        Ok(result) => {
            state.result = Some(result);
            state.pending = None;
            state.progress = None;
        }
        Err(mpsc::TryRecvError::Empty) => ctx.request_repaint_after(POLL_INTERVAL),
        Err(mpsc::TryRecvError::Disconnected) => {
            state.pending = None;
            state.progress = None;
        }
    }
}

/// Replace this panel's pinned findings with the shown matches.
fn pin_matches(app: &mut ViewerApp, matches: &[&CryptoMatch]) {
    app.bench.pinned.retain(|finding| !finding.id.starts_with(PINNED_ID_PREFIX));
    app.bench.pinned.extend(matches.iter().map(|found| found.to_finding()));
}

fn unpin_matches(app: &mut ViewerApp) {
    app.bench.pinned.retain(|finding| !finding.id.starts_with(PINNED_ID_PREFIX));
}

/// Show the crypto constants panel.
pub fn show_crypto_constants(state: &mut CryptoConstantsState, app: &mut ViewerApp, ui: &mut Ui) {
    poll(state, ui.ctx());
    ui.horizontal_wrapped(|ui| {
        let scanning = state.pending.is_some();
        let label = format!("Scan whole file ({})", crate::compress::human_bytes(app.document.len()));
        if ui.add_enabled(!scanning, egui::Button::new(label)).clicked() {
            start_scan(state, app);
        }
        if let Some((progress, total)) = &state.progress {
            ui.spinner();
            let done = progress.load(Ordering::Relaxed).min(*total);
            let fraction = if *total == 0 { 1.0 } else { done as f32 / *total as f32 };
            ui.add(egui::ProgressBar::new(fraction).desired_width(140.0).show_percentage());
        }
        ui.checkbox(&mut state.show_weak, "Show weak matches")
            .on_hover_text("Short constants such as the TEA delta also turn up by coincidence");
    });

    let Some(result) = &state.result else {
        ui.label(
            RichText::new(
                "Finds well-known constants that betray crypto and compression code: AES S-boxes and T-tables, MD5/SHA initial values and round constants, CRC tables, deflate base tables, Blowfish, DES, ChaCha/Salsa, TEA, RSA exponents, elliptic-curve primes and Base64 tables.",
            )
            .color(theme::TEXT_DIM),
        );
        return;
    };
    if result.key != DocumentKey::of(app) {
        ui.label(RichText::new("The document has changed since this scan; scan again to refresh.").color(theme::CURSOR));
    }
    if result.scanned < app.document.len() {
        ui.label(
            RichText::new(format!("Only the first {} of the edited document were scanned.", crate::compress::human_bytes(result.scanned)))
                .small()
                .color(theme::TEXT_DIM),
        );
    }

    let shown: Vec<&CryptoMatch> =
        result.matches.iter().filter(|found| state.show_weak || found.confidence >= WEAK_CONFIDENCE).collect();
    let hidden = result.matches.len() - shown.len();
    ui.horizontal_wrapped(|ui| {
        let summary = if hidden > 0 { format!("{} matches ({hidden} weak hidden)", shown.len()) } else { format!("{} matches", shown.len()) };
        ui.label(RichText::new(summary).small().color(theme::TEXT_DIM));
        if !shown.is_empty() && ui.small_button("Highlight in view").on_hover_text("Outline every listed match on the raster").clicked() {
            pin_matches(app, &shown);
        }
        if app.bench.pinned.iter().any(|finding| finding.id.starts_with(PINNED_ID_PREFIX)) && ui.small_button("Clear highlights").clicked() {
            unpin_matches(app);
        }
    });
    if shown.is_empty() {
        ui.label(RichText::new("No known constants found.").color(theme::TEXT_DIM));
        return;
    }

    let mut by_algorithm: BTreeMap<&str, Vec<&CryptoMatch>> = BTreeMap::new();
    for found in &shown {
        by_algorithm.entry(found.algorithm).or_default().push(found);
    }
    let mut chosen: Option<CryptoMatch> = None;
    egui::ScrollArea::vertical().id_salt("crypto-constants").show(ui, |ui| {
        for (algorithm, matches) in &by_algorithm {
            egui::CollapsingHeader::new(RichText::new(format!("{algorithm} ({})", matches.len())).strong())
                .id_salt(("crypto-algorithm", *algorithm))
                .default_open(true)
                .show(ui, |ui| {
                    for found in matches {
                        if show_match_row(ui, found) {
                            chosen = Some((*found).clone());
                        }
                    }
                });
        }
    });
    if let Some(found) = chosen {
        app.select_pattern(&found.to_finding());
    }
}

/// One clickable line per match; returns whether it was clicked.
fn show_match_row(ui: &mut Ui, found: &CryptoMatch) -> bool {
    let colour = if found.confidence >= WEAK_CONFIDENCE { theme::TEXT } else { theme::TEXT_DIM };
    ui.horizontal(|ui| {
        let offset = ui
            .add(egui::Label::new(RichText::new(format!("{:#010x}", found.start)).monospace().color(theme::ACCENT)).sense(Sense::click()))
            .on_hover_text("Select these bytes");
        ui.label(RichText::new(&found.table).color(colour));
        ui.label(RichText::new(found.detail()).small().color(theme::TEXT_DIM));
        ui.label(RichText::new(format!("{:.0}%", found.confidence * 100.0)).small().color(theme::TEXT_DIM))
            .on_hover_text("Confidence");
        offset.clicked()
    })
    .inner
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    use super::*;
    use crate::app::Launch;
    use crate::document::Document;

    /// Longest a background job may take in a test.
    const JOB_TIMEOUT: Duration = Duration::from_secs(20);
    const SBOX_OFFSET: usize = 5000;

    type PanelHarness = Harness<'static, (CryptoConstantsState, ViewerApp)>;

    fn harness_for(document: Document) -> PanelHarness {
        let mut app = ViewerApp::new(Launch::default());
        app.document = document;
        Harness::new_ui_state(
            |ui, (state, app): &mut (CryptoConstantsState, ViewerApp)| show_crypto_constants(state, app, ui),
            (CryptoConstantsState::default(), app),
        )
    }

    fn scan(harness: &mut PanelHarness) {
        harness.step();
        harness.get_by_label_contains("Scan whole file").click();
        harness.step();
        let started = Instant::now();
        while harness.state().0.pending.is_some() && started.elapsed() < JOB_TIMEOUT {
            thread::sleep(POLL_INTERVAL / 5);
            harness.step();
        }
        harness.step();
    }

    #[test]
    fn a_scanned_aes_sbox_is_listed_and_clicking_it_selects_its_bytes() {
        let mut bytes = vec![0x11u8; 3 * CHUNK_BYTES / 2];
        bytes[SBOX_OFFSET..SBOX_OFFSET + 256].copy_from_slice(&crypto_constants::aes_sbox());
        // Straddle the first chunk boundary to exercise the overlap.
        let straddling = CHUNK_BYTES - 100;
        bytes[straddling..straddling + 256].copy_from_slice(&crypto_constants::aes_inverse_sbox());
        let mut harness = harness_for(Document::from_bytes(bytes));
        scan(&mut harness);
        let titles: Vec<String> = harness.state().0.matches().iter().map(CryptoMatch::title).collect();
        assert_eq!(titles, vec!["AES S-box", "AES inverse S-box"]);
        assert!(harness.query_by_label_contains("AES (2)").is_some());
        harness.get_by_label(&format!("{SBOX_OFFSET:#010x}")).click();
        harness.step();
        assert_eq!(harness.state().1.selection(), Some((SBOX_OFFSET, 256)));
    }

    #[test]
    fn an_edited_document_is_scanned_including_its_edits() {
        let mut document = Document::from_bytes(vec![0u8; 4096]);
        document.overwrite(100, b"expand 32-byte k");
        let mut harness = harness_for(document);
        scan(&mut harness);
        let matches = harness.state().0.matches();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].start, 100);
    }
}
