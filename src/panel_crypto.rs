//! The crypto and obfuscation panel: repeated-block (ECB) detection, keys and
//! certificates, and attacks on simple ciphers beyond plain XOR.
//!
//! Every search runs on a background thread; results remember which document
//! they came from and are dropped when another one is shown.

use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui::{self, Color32, RichText, Sense, Ui, vec2};

use crate::app::ViewerApp;
use crate::blocks::{self, BlockReport};
use crate::ciphers::{self, CipherCandidate};
use crate::keys::{self, KeyFinding, KeyFormat, KeyKind};
use crate::plugin::{Category, Finding};
use crate::theme;

/// Largest selection decoded by the cipher attacks.
const DECODE_LIMIT: usize = crate::api::tools::crypto::ATTACK_LIMIT;
/// Bytes from the cursor decoded when nothing is selected.
const CURSOR_WINDOW: usize = 64 * 1024;
/// How often the panel looks for finished background work.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Height of the repeat-map strip.
const STRIP_HEIGHT: f32 = 18.0;
/// Widest a key finding's description may be before it is truncated (points).
const KEY_DETAIL_WIDTH: f32 = 520.0;

/// Which document a result belongs to: its name and length.
type DocumentKey = (String, usize);

/// A background job and the result it delivers.
struct Job<T> {
    receiver: Receiver<T>,
    document: DocumentKey,
}

/// Results of a search together with the document they describe.
struct Done<T> {
    value: T,
    document: DocumentKey,
}

/// Cipher candidates for the range `start..start + len`.
pub(crate) struct DecodeResults {
    pub start: usize,
    pub len: usize,
    pub candidates: Vec<CipherCandidate>,
}

/// State of the crypto panel, kept between frames.
#[derive(Default)]
pub struct CryptoState {
    blocks_job: Option<Job<BlockReport>>,
    blocks: Option<Done<BlockReport>>,
    keys_job: Option<Job<Vec<KeyFinding>>>,
    keys: Option<Done<Vec<KeyFinding>>>,
    decode_job: Option<Job<DecodeResults>>,
    decode: Option<Done<DecodeResults>>,
    /// Known plaintext for crib dragging, with `\xHH` escapes.
    crib: String,
    crib_error: Option<String>,
}

/// Draw the crypto panel.
pub fn show_crypto(state: &mut CryptoState, app: &mut ViewerApp, ui: &mut egui::Ui) {
    let document = document_key(app);
    collect_finished(state, &document);
    if state.blocks_job.is_some() || state.keys_job.is_some() || state.decode_job.is_some() {
        ui.ctx().request_repaint_after(POLL_INTERVAL);
    }
    egui::ScrollArea::vertical().id_salt("crypto-panel").show(ui, |ui| {
        egui::CollapsingHeader::new(RichText::new("Repeated blocks").strong()).default_open(true).show(ui, |ui| show_blocks(state, app, ui));
        egui::CollapsingHeader::new(RichText::new("Keys and certificates").strong()).default_open(true).show(ui, |ui| show_keys(state, app, ui));
        egui::CollapsingHeader::new(RichText::new("Decode").strong()).default_open(true).show(ui, |ui| show_decode(state, app, ui));
    });
}

fn document_key(app: &ViewerApp) -> DocumentKey {
    (app.display_name(), app.document.len())
}

/// A job of the window's document's, and where its result is to be sent.
fn awaited<T>(app: &ViewerApp) -> (Job<T>, mpsc::Sender<T>) {
    let (sender, receiver) = mpsc::channel();
    (Job { receiver, document: document_key(app) }, sender)
}

/// Wait for a search `crypto.repeated_blocks` started; returns where its report is sent.
pub(crate) fn await_blocks(app: &mut ViewerApp) -> mpsc::Sender<BlockReport> {
    let (job, sender) = awaited(app);
    app.bench.panels.crypto.blocks_job = Some(job);
    sender
}

/// Wait for a search `crypto.find_keys` started; returns where its findings are sent.
pub(crate) fn await_keys(app: &mut ViewerApp) -> mpsc::Sender<Vec<KeyFinding>> {
    let (job, sender) = awaited(app);
    app.bench.panels.crypto.keys_job = Some(job);
    sender
}

/// Wait for attacks `crypto.attack` started; returns where the decodes are sent.
pub(crate) fn await_decode(app: &mut ViewerApp) -> mpsc::Sender<DecodeResults> {
    let (job, sender) = awaited(app);
    app.bench.panels.crypto.decode_job = Some(job);
    sender
}

/// Move a finished job's result into `done`; drop results for other documents.
fn poll<T>(job: &mut Option<Job<T>>, done: &mut Option<Done<T>>, document: &DocumentKey) {
    if let Some(pending) = job
        && let Ok(value) = pending.receiver.try_recv()
    {
        let finished = job.take().map(|pending| pending.document);
        *done = finished.map(|document| Done { value, document });
    }
    if job.as_ref().is_some_and(|pending| &pending.document != document) {
        *job = None;
    }
    if done.as_ref().is_some_and(|result| &result.document != document) {
        *done = None;
    }
}

fn collect_finished(state: &mut CryptoState, document: &DocumentKey) {
    poll(&mut state.blocks_job, &mut state.blocks, document);
    poll(&mut state.keys_job, &mut state.keys, document);
    poll(&mut state.decode_job, &mut state.decode, document);
}

fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).small().color(theme::TEXT_DIM)
}

// ---------------------------------------------------------------------------
// Repeated blocks
// ---------------------------------------------------------------------------

/// The selection, else the whole file, capped at `limit`.
fn selection_or_file(app: &ViewerApp, limit: usize) -> (usize, usize, &'static str) {
    match app.selection() {
        Some((start, len)) => (start, len.min(limit), "selection"),
        None => (0, app.document.len().min(limit), "whole file"),
    }
}

fn show_blocks(state: &mut CryptoState, app: &mut ViewerApp, ui: &mut Ui) {
    let (start, len, what) = selection_or_file(app, blocks::MAX_ANALYSED_BYTES);
    ui.horizontal(|ui| {
        let busy = state.blocks_job.is_some();
        if ui.add_enabled(!busy && len > 0, egui::Button::new(format!("Look for repeated blocks in {what} ({})", crate::compress::human_bytes(len)))).clicked() {
            app.perform_later("crypto.repeated_blocks", serde_json::json!({ "start": start, "len": len }));
        }
        if busy {
            ui.spinner();
        }
    });
    let Some(done) = &state.blocks else {
        ui.label(dim("Counts 8- and 16-byte blocks that look random yet repeat: the mark of ECB-mode encryption. CBC, CTR, stream ciphers and compression leave no repeats."));
        return;
    };
    let report = &done.value;
    let verdict_colour = match report.verdict {
        blocks::BlockVerdict::LikelyEcb { .. } => theme::CURSOR,
        _ => theme::ACCENT,
    };
    ui.label(RichText::new(report.verdict.label()).color(verdict_colour));
    let best = report.best;
    ui.label(dim(format!(
        "{} of {} high-entropy {}-byte blocks repeat ({:.1}%), alignment {} · {} analysed from {:#x}",
        best.repeated_blocks,
        best.eligible_blocks,
        best.block_size,
        best.repeat_ratio() * 100.0,
        best.alignment,
        crate::compress::human_bytes(report.analysed_len),
        report.start
    )));
    let mut jump = draw_repeat_strip(ui, report);
    ui.horizontal(|ui| {
        theme::swatch(ui, theme::BACKGROUND, "low entropy");
        theme::swatch(ui, theme::SURFACE_RAISED, "no repeats");
        theme::swatch(ui, theme::CURSOR, "repeats");
    });
    if !report.top_repeats.is_empty() {
        ui.label(RichText::new("Most repeated blocks").strong());
        for repeat in &report.top_repeats {
            ui.horizontal(|ui| {
                ui.monospace(RichText::new(format!("{:>5}×", repeat.count)).color(theme::ACCENT));
                ui.monospace(keys::short_hex(&repeat.bytes, repeat.bytes.len()));
                for &offset in repeat.offsets.iter().take(4) {
                    if ui.small_button(format!("{offset:#x}")).clicked() {
                        jump = Some(offset);
                    }
                }
                if repeat.offsets.len() > 4 {
                    ui.label(dim("…"));
                }
            });
        }
    }
    if let Some(offset) = jump {
        app.jump_found(offset);
    }
}

fn strip_colour(ratio: Option<f32>) -> Color32 {
    match ratio {
        None => theme::BACKGROUND,
        Some(ratio) if ratio <= 0.0 => theme::SURFACE_RAISED,
        Some(ratio) => theme::ACCENT_DIM.lerp_to_gamma(theme::CURSOR, ratio.clamp(0.0, 1.0)),
    }
}

/// Draw the repeat map; returns the offset clicked, if any.
fn draw_repeat_strip(ui: &mut Ui, report: &BlockReport) -> Option<usize> {
    let width = ui.available_width().max(1.0);
    let (rect, response) = ui.allocate_exact_size(vec2(width, STRIP_HEIGHT), Sense::click());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 2.0, theme::BACKGROUND);
    let count = report.regions.len().max(1) as f32;
    for (index, region) in report.regions.iter().enumerate() {
        let left = rect.left() + rect.width() * index as f32 / count;
        let right = rect.left() + rect.width() * (index + 1) as f32 / count;
        let cell = egui::Rect::from_min_max(egui::pos2(left, rect.top()), egui::pos2(right.max(left + 1.0), rect.bottom()));
        painter.rect_filled(cell, 0.0, strip_colour(region.repeat_ratio()));
    }
    let region_under = |x: f32| {
        let index = ((x - rect.left()) / rect.width() * count) as usize;
        report.regions.get(index.min(report.regions.len().saturating_sub(1)))
    };
    let hovered = response.hover_pos().and_then(|pointer| region_under(pointer.x)).copied();
    let clicked = response.interact_pointer_pos().filter(|_| response.clicked()).and_then(|pointer| region_under(pointer.x)).map(|region| region.offset);
    if let Some(region) = hovered {
        let text = match region.repeat_ratio() {
            Some(ratio) => format!("{:#x}: {} of {} high-entropy blocks repeat ({:.0}%); click to jump", region.offset, region.repeated_blocks, region.eligible_blocks, ratio * 100.0),
            None => format!("{:#x}: no high-entropy blocks", region.offset),
        };
        response.on_hover_text(text);
    }
    clicked
}

// ---------------------------------------------------------------------------
// Keys and certificates
// ---------------------------------------------------------------------------

fn kind_colour(kind: KeyKind) -> Color32 {
    match kind {
        KeyKind::PrivateKey => theme::DANGER,
        KeyKind::Certificate => theme::ACCENT,
        KeyKind::PublicKey => theme::CLASS_TEXT,
        KeyKind::OtherPem => theme::TEXT,
        KeyKind::RawKeyCandidate => theme::CURSOR,
    }
}

/// A finding for `app.select_finding`, so selection behaves as in Findings.
fn as_finding(key: &KeyFinding) -> Finding {
    let category = match key.format {
        KeyFormat::Pem | KeyFormat::OpenSsh => Category::Encoding,
        KeyFormat::Der => Category::Structure,
        KeyFormat::Raw => Category::HighEntropy,
    };
    Finding::new(format!("crypto:{}", key.kind.label()), "panel_crypto", category, key.offset, key.len)
        .title(format!("{} ({})", key.kind.label(), key.format.label()))
        .detail(key.detail.clone())
        .confidence(key.confidence)
}

fn show_keys(state: &mut CryptoState, app: &mut ViewerApp, ui: &mut Ui) {
    let len = app.document.len().min(keys::MAX_SCAN_BYTES);
    ui.horizontal(|ui| {
        let busy = state.keys_job.is_some();
        if ui.add_enabled(!busy && len > 0, egui::Button::new(format!("Find keys and certificates ({})", crate::compress::human_bytes(len)))).clicked() {
            app.perform_later("crypto.find_keys", serde_json::json!({ "start": 0, "len": len }));
        }
        if busy {
            ui.spinner();
        }
    });
    let Some(done) = &state.keys else {
        ui.label(dim("PEM blocks, DER certificates and keys (X.509, PKCS#1, PKCS#8, SEC1), OpenSSH keys, and random-looking 16/24/32-byte runs amid structured data that could be raw symmetric keys."));
        return;
    };
    let findings = &done.value;
    if findings.is_empty() {
        ui.label(dim("Nothing found."));
        return;
    }
    let limit_note = if findings.len() >= keys::MAX_FINDINGS { " (stopped at the limit)" } else { "" };
    ui.label(dim(format!("{} found{limit_note}; click one to select it", findings.len())));
    let mut chosen = None;
    for finding in findings {
        ui.horizontal(|ui| {
            if ui.add(egui::Label::new(RichText::new(format!("{:#010x}", finding.offset)).monospace().color(theme::TEXT_DIM)).sense(Sense::click())).clicked() {
                chosen = Some(as_finding(finding));
            }
            ui.label(RichText::new(finding.kind.label()).small().color(kind_colour(finding.kind)));
            ui.label(dim(format!("{} · {} B · {:.0}%", finding.format.label(), finding.len, finding.confidence * 100.0)));
            ui.scope(|ui| {
                ui.set_max_width(KEY_DETAIL_WIDTH);
                let colour = if finding.confidence < 0.5 { theme::TEXT_DIM } else { theme::TEXT };
                if ui.add(egui::Label::new(RichText::new(&finding.detail).color(colour)).truncate().sense(Sense::click())).clicked() {
                    chosen = Some(as_finding(finding));
                }
            });
        });
    }
    if let Some(finding) = chosen {
        app.select_finding(&finding);
    }
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// The selection (capped), else a window from the cursor.
fn decode_range(app: &ViewerApp) -> (usize, usize) {
    let (start, len) = app.selection().map(|(start, len)| (start, len.min(DECODE_LIMIT))).unwrap_or((app.cursor, CURSOR_WINDOW));
    (start, len.min(app.document.len().saturating_sub(start)))
}

fn show_decode(state: &mut CryptoState, app: &mut ViewerApp, ui: &mut Ui) {
    show_crib_controls(state, ui);
    let (start, len) = decode_range(app);
    ui.horizontal(|ui| {
        let busy = state.decode_job.is_some();
        if ui.add_enabled(!busy && len > 0, egui::Button::new(format!("Try cipher attacks on {len} bytes at {start:#x}"))).clicked() {
            start_decode(state, app, start, len);
        }
        if busy {
            ui.spinner();
        }
        ui.label(dim("select the suspect bytes first; without a selection, 64 KiB from the cursor"));
    });
    let Some(done) = &state.decode else {
        ui.label(dim("Rolling XOR, XOR with the previous byte, ADD/SUB with a constant or repeating key, bit rotation, XOR combined with ADD, and crib dragging, ranked by how much the result looks like text or structured data. Plain XOR is in the XOR tab."));
        return;
    };
    let results = &done.value;
    if results.candidates.is_empty() {
        ui.label(dim("No convincing decode."));
        return;
    }
    let mut action = None;
    for (index, candidate) in results.candidates.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.monospace(RichText::new(format!("{:.2}", candidate.score)).color(theme::ACCENT));
            ui.label(RichText::new(candidate.transform.describe()).strong());
            let magic = candidate.magic.map(|name| format!(" · starts like a {name}")).unwrap_or_default();
            ui.label(dim(format!("{:.0}% printable · {:.2} bits/byte{magic} · {}", candidate.printable_fraction * 100.0, candidate.entropy, candidate.reason)));
            if ui.small_button("Open decoded").on_hover_text("Open the decoded bytes as a document; Back returns").clicked() {
                action = Some((index, false));
            }
            if ui.small_button("Apply in place").on_hover_text("Replace the bytes with the decode (undoable)").clicked() {
                action = Some((index, true));
            }
        });
        ui.monospace(RichText::new(&candidate.preview).small().color(theme::TEXT_DIM));
    }
    if let Some((index, in_place)) = action {
        let (start, len) = (results.start, results.len);
        let transform = results.candidates[index].transform.clone();
        apply_decode(app, start, len, &transform, in_place);
        if in_place {
            // The previews describe the bytes as they were before the edit.
            state.decode = None;
        }
    }
}

fn show_crib_controls(state: &mut CryptoState, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.label("Crib");
        let edit = ui.add(egui::TextEdit::singleline(&mut state.crib).hint_text("known plaintext, e.g. PK\\x03\\x04").desired_width(180.0));
        if edit.changed() {
            state.crib_error = None;
        }
        for (label, bytes) in ciphers::PRESET_CRIBS {
            if ui.small_button(label).clicked() {
                state.crib = ciphers::crib_text(bytes);
                state.crib_error = None;
            }
        }
        if !state.crib.is_empty() && ui.small_button("Clear").clicked() {
            state.crib.clear();
            state.crib_error = None;
        }
    });
    if let Some(error) = &state.crib_error {
        ui.label(RichText::new(error).small().color(theme::DANGER));
    }
}

/// The person asks for the cipher attacks on `len` bytes at `start`, with
/// the crib typed: `crypto.attack`, carried out once the panel is drawn. A
/// crib that cannot be read is said under it instead.
fn start_decode(state: &mut CryptoState, app: &mut ViewerApp, start: usize, len: usize) {
    let mut params = serde_json::json!({ "start": start, "len": len });
    if !state.crib.is_empty() {
        if let Err(error) = ciphers::parse_crib(&state.crib) {
            state.crib_error = Some(error);
            return;
        }
        params["crib"] = serde_json::Value::String(state.crib.clone());
    }
    app.perform_later("crypto.attack", params);
}

/// The person uses a decode: written over the bytes as an undoable step
/// (`bytes.replace`), or opened as a document of its own (`documents.derive`).
fn apply_decode(app: &mut ViewerApp, start: usize, len: usize, transform: &ciphers::Transform, in_place: bool) {
    let bytes = app.document.read_range(start, len);
    let decoded = crate::api::values::encode_bytes(&transform.apply(&bytes), Default::default());
    let description = transform.describe();
    if in_place {
        if app.perform("bytes.replace", serde_json::json!({ "start": start, "len": len, "data": decoded })).is_ok() {
            app.restore_selection(start, len);
            app.status = format!("{description}: applied to {len} bytes at {start:#x}");
        }
    } else {
        let name = format!("{} › decoded@{start:#x}", app.display_name());
        if app.perform("documents.derive", serde_json::json!({ "data": decoded, "name": name })).is_ok() {
            app.status = format!("Opened the decode ({description})");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::actions::take_performed;
    use crate::app::Launch;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        take_performed();
        app
    }

    #[test]
    fn the_searches_are_jobs_of_the_person_s_carried_out_once_the_panel_is_drawn() {
        let mut app = app_with(&[0x42u8; 4096]);
        let mut state = CryptoState { crib: "PK\\x03\\x04".to_string(), ..Default::default() };
        start_decode(&mut state, &mut app, 16, 256);
        app.perform_later("crypto.repeated_blocks", json!({"start": 0, "len": 4096}));
        assert!(take_performed().is_empty());
        app.perform_waiting_actions();
        let performed = take_performed();
        assert_eq!(performed[0], ("crypto.attack".to_string(), json!({"start": 16, "len": 256, "crib": "PK\\x03\\x04"})));
        let crypto = &app.bench.panels.crypto;
        assert!(crypto.decode_job.is_some() && crypto.blocks_job.is_some(), "the panel waits for both");
        let report = crypto.blocks_job.as_ref().unwrap().receiver.recv_timeout(Duration::from_secs(60)).expect("the search finishes");
        assert_eq!(report.analysed_len, 4096);
    }

    #[test]
    fn a_crib_that_cannot_be_read_is_said_under_it_without_a_step() {
        let mut app = app_with(&[0u8; 64]);
        let mut state = CryptoState { crib: "\\xZZ".to_string(), ..Default::default() };
        start_decode(&mut state, &mut app, 0, 64);
        app.perform_waiting_actions();
        assert!(take_performed().is_empty());
        assert!(state.crib_error.is_some());
    }

    #[test]
    fn a_decode_is_applied_as_a_replacement_or_opened_as_a_derived_document() {
        let mut app = app_with(&[0x10, 0x20, 0x30, 0x40]);
        let rotate = ciphers::Transform::RotateLeft { bits: 4 };
        apply_decode(&mut app, 1, 2, &rotate, true);
        assert_eq!(take_performed(), [("bytes.replace".to_string(), json!({"start": 1, "len": 2, "data": "0203"}))]);
        assert_eq!(app.document.read_range(0, 4), [0x10, 0x02, 0x03, 0x40]);
        assert_eq!(app.status, format!("{}: applied to 2 bytes at 0x1", rotate.describe()));
        apply_decode(&mut app, 0, 1, &rotate, false);
        assert_eq!(take_performed(), [("documents.derive".to_string(), json!({"data": "01", "name": "test.bin › decoded@0x0"}))]);
        assert_eq!(app.display_name(), "test.bin › decoded@0x0");
    }
}
