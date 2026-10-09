//! Dock tabs for byte statistics, strings and XOR key recovery.

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};

use eframe::egui::{self, Color32, Rect, RichText, Sense, TextureHandle, Ui, pos2, vec2};
use egui_plot::{Bar, BarChart, Legend, Line, Plot, PlotPoints};

use crate::app::ViewerApp;
use crate::sheets::PerSheet;
use crate::stats::{self, ByteStats, Repeat, Verdict};
use crate::strings::{self, Encoding, FoundString};
use crate::theme;
use crate::journal::anchors::{Anchor, Pick, StepRef};
use crate::send_to::{self, Carried, Carry, Sending, Slot, Target};
use crate::xor::XorCandidate;

/// Largest range analysed for statistics and strings.
pub(crate) const SCAN_LIMIT: usize = 64 * 1024 * 1024;
/// Largest range searched for XOR keys.
const XOR_LIMIT: usize = crate::api::tools::xor::XOR_LIMIT;
/// Most strings kept.
pub(crate) const MAX_STRINGS: usize = 200_000;

pub struct StatsResult {
    pub start: usize,
    pub len: usize,
    pub stats: ByteStats,
    pub verdict: Verdict,
    digraph: Vec<u32>,
    pub entropy: Vec<(usize, f32)>,
    pub compressibility: Vec<(usize, f32)>,
    pub repeats: Vec<Repeat>,
}

/// The strings found in a span.
pub struct FoundStrings {
    pub start: usize,
    pub len: usize,
    /// Shared, so the tab can draw them while it carries one elsewhere.
    pub strings: Arc<Vec<FoundString>>,
    /// The `strings.find` step that found them, when the person's search
    /// did: what a string carried elsewhere is picked from.
    pub step: Option<u64>,
}

/// The keys `xor.recover_keys` proposed for a span.
#[derive(Clone)]
pub struct XorResults {
    pub start: usize,
    pub len: usize,
    pub candidates: Vec<XorCandidate>,
    /// The likely key lengths, with their scores.
    pub lengths: Vec<(usize, f64)>,
    /// The read that proposed them, which a key carried elsewhere is
    /// picked from.
    pub step: Option<u64>,
}

pub struct StatsState {
    pending: Option<Receiver<StatsResult>>,
    pub result: Option<StatsResult>,
    heatmap: Option<TextureHandle>,

    /// A search running, with the sheet it searches and its step.
    strings_pending: Option<(String, Option<u64>, Receiver<FoundStrings>)>,
    /// The strings found, kept for each sheet searched.
    pub strings: PerSheet<FoundStrings>,
    pub min_chars: usize,
    pub encodings: [bool; 4],
    pub filter: String,
    pub interesting_only: bool,

    /// The keys recovered, kept for each sheet.
    pub xor_candidates: PerSheet<XorResults>,
    /// The key of the XOR tab's Apply row, as hex.
    pub xor_key: String,
    /// Where that key came from, when it was sent from another tool.
    pub xor_key_bound: Option<send_to::Bound>,
}

/// What the Statistics tab worked out about one sheet, kept while it is
/// parked.
#[derive(Default)]
pub struct StatisticsResults {
    pending: Option<Receiver<StatsResult>>,
    result: Option<StatsResult>,
    heatmap: Option<TextureHandle>,
}

impl Default for StatsState {
    fn default() -> Self {
        StatsState {
            pending: None,
            result: None,
            heatmap: None,
            strings_pending: None,
            strings: PerSheet::default(),
            min_chars: 6,
            encodings: [true, true, true, false],
            filter: String::new(),
            interesting_only: false,
            xor_candidates: PerSheet::default(),
            xor_key: String::new(),
            xor_key_bound: None,
        }
    }
}

impl StatsState {
    /// Sheet `sheet` has new bytes: what was worked out about it goes.
    pub fn document_changed(&mut self, sheet: &str) {
        self.put_statistics(StatisticsResults::default());
        self.strings.closed(sheet);
        self.xor_candidates.closed(sheet);
        if self.strings_pending.as_ref().is_some_and(|(searched, ..)| searched == sheet) {
            self.strings_pending = None;
        }
    }

    /// Sheet `to` is shown: its strings and keys are shown again.
    pub fn sheet_switched(&mut self, to: &str) {
        self.strings.switched(to);
        self.xor_candidates.switched(to);
    }

    /// Sheet `id` closed: what was found in it goes.
    pub fn sheet_closed(&mut self, id: &str) {
        self.strings.closed(id);
        self.xor_candidates.closed(id);
    }

    /// Take the statistics of the sheet shown, to keep while it is parked.
    pub fn take_statistics(&mut self) -> StatisticsResults {
        StatisticsResults { pending: self.pending.take(), result: self.result.take(), heatmap: self.heatmap.take() }
    }

    /// Show the statistics kept for the sheet now shown.
    pub fn put_statistics(&mut self, kept: StatisticsResults) {
        (self.pending, self.result, self.heatmap) = (kept.pending, kept.result, kept.heatmap);
    }
}

/// The selection, else the whole file, capped.
fn scope(app: &ViewerApp, limit: usize) -> (usize, usize, &'static str) {
    match app.selection() {
        Some((start, len)) => (start, len.min(limit), "selection"),
        None => (0, app.document.len().min(limit), "whole file"),
    }
}

impl ViewerApp {
    /// The person picks bytes a tool found: `selection.set` with them (at
    /// least one byte), brought into the middle of the view. Returns
    /// whether they were selected.
    pub(crate) fn select_found(&mut self, start: usize, len: usize) -> bool {
        let start = start.min(self.document.len());
        let len = len.max(1).min(self.document.len() - start);
        let selected = self.perform("selection.set", serde_json::json!({ "selection": { "range": [start, len] } })).is_ok();
        if selected {
            self.reveal_cursor_centred();
            self.reveal_cursor_in_hex(true);
        }
        selected
    }

    /// [`ViewerApp::select_found`] for bytes a tool found in sheet `sheet`:
    /// another sheet is shown first, and the bytes selected in it, once the
    /// frame is drawn.
    pub(crate) fn select_found_in(&mut self, sheet: &str, start: usize, len: usize) {
        if sheet == self.document_id() {
            self.select_found(start, len);
            return;
        }
        self.perform_later("documents.activate", serde_json::json!({ "doc": sheet }));
        self.perform_later("selection.set", serde_json::json!({ "doc": sheet, "selection": { "range": [start, len.max(1)] } }));
    }

    /// [`ViewerApp::jump_found`] to an offset a tool found in sheet
    /// `sheet`, shown first when another is.
    pub(crate) fn jump_found_in(&mut self, sheet: &str, offset: usize) {
        if sheet == self.document_id() {
            self.jump_found(offset);
            return;
        }
        self.perform_later("documents.activate", serde_json::json!({ "doc": sheet }));
        self.perform_later("cursor.set", serde_json::json!({ "doc": sheet, "offset": offset }));
    }

    /// The person follows a tool to an offset: `cursor.set`, brought into
    /// the middle of the view. Offsets past the end go to the end.
    pub(crate) fn jump_found(&mut self, offset: usize) {
        let offset = offset.min(self.document.len());
        if self.perform("cursor.set", serde_json::json!({ "offset": offset })).is_ok() {
            self.reveal_cursor_centred();
            self.reveal_cursor_in_hex(true);
        }
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/// The person asks for the statistics of the selection, else the whole
/// file: `statistics.analyse`, with the span.
pub fn start_statistics(app: &mut ViewerApp) {
    let (start, len, _) = scope(app, SCAN_LIMIT);
    let _ = app.perform("statistics.analyse", serde_json::json!({ "start": start, "len": len }));
}

/// Measure `bytes` (from document offset `start`) as the Statistics tab shows them.
pub(crate) fn measure(bytes: &[u8], start: usize) -> StatsResult {
    let stats = stats::byte_stats(bytes);
    let verdict = stats::verdict(&stats);
    let window = (bytes.len() / 512).clamp(256, 64 * 1024);
    StatsResult {
        start,
        len: bytes.len(),
        verdict,
        digraph: stats::digraph_counts(bytes),
        entropy: stats::sliding_entropy(bytes, window, 1024),
        compressibility: stats::compressibility(bytes, window.max(1024), 512),
        repeats: stats::repeated_sequences(bytes, 4, 32, 40),
        stats,
    }
}

/// Wait for a measure `statistics.analyse` started, to show it in the
/// Statistics tab; returns where the measure is sent.
pub(crate) fn await_statistics(app: &mut ViewerApp) -> Sender<StatsResult> {
    let (sender, receiver) = mpsc::channel();
    app.bench.tools.stats.pending = Some(receiver);
    app.note_tool_result(crate::dock::DockTab::Statistics);
    sender
}

pub fn show_statistics(app: &mut ViewerApp, ui: &mut Ui) {
    if let Some(receiver) = &app.bench.tools.stats.pending
        && let Ok(result) = receiver.try_recv()
    {
        app.bench.tools.stats.heatmap = Some(crate::analysis_tools::heatmap_texture(ui.ctx(), "digraph", &result.digraph));
        app.bench.tools.stats.result = Some(result);
        app.bench.tools.stats.pending = None;
    }
    let (start, len, what) = scope(app, SCAN_LIMIT);
    ui.horizontal(|ui| {
        if ui.button(format!("Analyse {what} ({})", crate::compress::human_bytes(len))).clicked() {
            start_statistics(app);
        }
        if app.bench.tools.stats.pending.is_some() {
            ui.spinner();
        }
        let _ = start;
    });
    let Some(result) = &app.bench.tools.stats.result else {
        ui.label(
            RichText::new("Byte histogram, the ent randomness tests (entropy, chi-square, serial correlation, Monte Carlo π) with a plain verdict, a byte-pair fingerprint, entropy and compressibility along the data, and the most repeated byte sequences.")
                .color(theme::TEXT_DIM),
        );
        return;
    };
    let s = &result.stats;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(result.verdict.label).heading().color(theme::ACCENT));
        ui.label(RichText::new(&result.verdict.explanation).color(theme::TEXT_DIM));
    });
    egui::Grid::new("stats-grid").num_columns(6).spacing([18.0, 2.0]).show(ui, |ui| {
        let cell = |ui: &mut Ui, name: &str, value: String| {
            ui.label(RichText::new(name).color(theme::TEXT_DIM));
            ui.monospace(value);
        };
        cell(ui, "entropy", format!("{:.4} bits/byte", s.entropy));
        cell(ui, "chi-square", format!("{:.1} (p {:.4})", s.chi_square, s.chi_square_p));
        cell(ui, "mean", format!("{:.3} (random 127.5)", s.mean));
        ui.end_row();
        cell(ui, "serial corr.", format!("{:+.5}", s.serial_correlation));
        cell(ui, "Monte Carlo π", format!("{:.5} ({:.2}% off)", s.monte_carlo_pi, s.pi_error_percent));
        cell(ui, "distinct", format!("{} of 256", s.distinct_values));
        ui.end_row();
        cell(ui, "printable", format!("{:.1}%", s.printable_fraction * 100.0));
        cell(ui, "zero", format!("{:.1}%", s.zero_fraction * 100.0));
        cell(ui, "≥ 0x80", format!("{:.1}%", s.high_fraction * 100.0));
        ui.end_row();
    });
    ui.separator();

    let width = ui.available_width();
    let height = (ui.available_height() - 8.0).clamp(160.0, 260.0);
    let base = result.start;
    let mut jump = None;
    ui.horizontal_top(|ui| {
        // Byte histogram.
        ui.vertical(|ui| {
            ui.set_width(width * 0.34);
            ui.label(RichText::new("Byte values").small().color(theme::TEXT_DIM));
            let bars: Vec<Bar> = s.histogram.iter().enumerate().map(|(value, &count)| Bar::new(value as f64, count as f64).width(1.0).fill(crate::raster::byte_class_colour(value as u8))).collect();
            Plot::new("byte-histogram").height(height).show_x(true).allow_scroll(false).show(ui, |plot| plot.bar_chart(BarChart::new("count", bars)));
        });
        // Byte-pair fingerprint.
        ui.vertical(|ui| {
            ui.label(RichText::new("Byte pairs (x = byte, y = next)").small().color(theme::TEXT_DIM));
            if let Some(texture) = &app.bench.tools.stats.heatmap {
                let side = height.min(width * 0.25);
                let (rect, response) = ui.allocate_exact_size(vec2(side, side), Sense::hover());
                ui.painter().image(texture.id(), rect, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
                if let Some(pointer) = response.hover_pos() {
                    let a = ((pointer.x - rect.min.x) / side * 256.0) as usize;
                    let b = ((pointer.y - rect.min.y) / side * 256.0) as usize;
                    let count = result.digraph.get(a.min(255) * 256 + b.min(255)).copied().unwrap_or(0);
                    response.on_hover_text(format!("{:02X} followed by {:02X}: {count} times", a.min(255), b.min(255)));
                }
            }
        });
        // Entropy and compressibility along the data.
        ui.vertical(|ui| {
            ui.label(RichText::new("Entropy (bits/byte) and compressed size (×8) along the range; click to jump").small().color(theme::TEXT_DIM));
            let entropy: Vec<[f64; 2]> = result.entropy.iter().map(|&(o, e)| [o as f64, e as f64]).collect();
            let ratio: Vec<[f64; 2]> = result.compressibility.iter().map(|&(o, r)| [o as f64, (r as f64 * 8.0).min(9.0)]).collect();
            let response = Plot::new("entropy-plot").height(height).legend(Legend::default()).allow_scroll(false).show(ui, |plot| {
                plot.line(Line::new("entropy", PlotPoints::new(entropy)).color(theme::ACCENT));
                plot.line(Line::new("compressed ×8", PlotPoints::new(ratio)).color(theme::CURSOR));
                plot.pointer_coordinate()
            });
            if response.response.clicked()
                && let Some(point) = response.inner
            {
                jump = Some(base + point.x.max(0.0) as usize);
            }
        });
    });

    ui.separator();
    ui.label(RichText::new("Most repeated byte sequences").strong());
    let repeats = result.repeats.clone();
    let mut chosen = None;
    egui::ScrollArea::vertical().id_salt("repeats").max_height(160.0).show(ui, |ui| {
        for repeat in &repeats {
            ui.horizontal(|ui| {
                ui.monospace(RichText::new(format!("{:>6}×", repeat.count)).color(theme::ACCENT));
                let hex: String = repeat.bytes.iter().take(24).map(|b| format!("{b:02x} ")).collect();
                let text: String = repeat.bytes.iter().take(24).map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' }).collect();
                ui.monospace(hex);
                ui.monospace(RichText::new(text).color(theme::TEXT_DIM));
                if let Some(&first) = repeat.first_offsets.first()
                    && ui.small_button(format!("{:#x}", base + first)).clicked()
                {
                    chosen = Some((base + first, repeat.bytes.len(), repeat.bytes.clone()));
                }
            });
        }
    });
    if let Some(offset) = jump {
        app.jump_found(offset);
    }
    if let Some((offset, len, bytes)) = chosen
        && app.select_found(offset, len)
    {
        // Also prime search, so F3 walks the other occurrences.
        app.search_mode = crate::search::SearchMode::Hex;
        app.search_text = crate::ops::to_hex_string(&bytes);
        app.search_count = None;
        app.status = "Selected; press F3 for the next occurrence".to_string();
    }
}

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

/// The person asks for the strings in the selection, else the whole file,
/// with the tab's options: `strings.find`.
pub(crate) fn start_strings(app: &mut ViewerApp) {
    let (start, len, _) = scope(app, SCAN_LIMIT);
    let options = &app.bench.tools.stats;
    let min_chars = options.min_chars.max(crate::api::tools::strings::FEWEST_CHARS);
    let encodings: Vec<crate::api::tools::strings::StringEncoding> =
        Encoding::ALL.iter().zip(options.encodings).filter(|(_, on)| *on).map(|(encoding, _)| crate::api::tools::strings::StringEncoding::of(*encoding)).collect();
    let _ = app.perform("strings.find", serde_json::json!({ "start": start, "len": len, "min_chars": min_chars, "encodings": encodings }));
}

/// Find the strings in `bytes` (from document offset `start`).
pub(crate) fn find_strings(bytes: &[u8], start: usize, min_chars: usize, encodings: &[Encoding]) -> FoundStrings {
    FoundStrings { start, len: bytes.len(), strings: Arc::new(strings::extract(bytes, start, min_chars, encodings, MAX_STRINGS)), step: None }
}

/// Wait for a search `strings.find` started, to show it in the Strings
/// tab; returns where the strings are sent.
pub(crate) fn await_strings(app: &mut ViewerApp) -> Sender<FoundStrings> {
    app.note_tool_result(crate::dock::DockTab::Strings);
    let (sender, receiver) = mpsc::channel();
    let step = app.journal.step_being_recorded();
    app.bench.tools.stats.strings_pending = Some((app.document_id(), step, receiver));
    sender
}

pub fn show_strings(app: &mut ViewerApp, ui: &mut Ui) {
    let active = app.document_id();
    let stats = &mut app.bench.tools.stats;
    if let Some((sheet, step, receiver)) = &stats.strings_pending
        && let Ok(mut found) = receiver.try_recv()
    {
        let sheet = sheet.clone();
        found.step = *step;
        stats.strings.deliver(&sheet, found, &active);
        stats.strings_pending = None;
    }
    stats.strings.switched(&active);
    let (_, len, what) = scope(app, SCAN_LIMIT);
    ui.horizontal_wrapped(|ui| {
        if ui.button(format!("Find strings in {what} ({})", crate::compress::human_bytes(len))).clicked() {
            start_strings(app);
        }
        if app.bench.tools.stats.strings_pending.is_some() {
            ui.spinner();
        }
        ui.label("min");
        ui.add(egui::DragValue::new(&mut app.bench.tools.stats.min_chars).range(2..=256).suffix(" chars"));
        for (index, encoding) in Encoding::ALL.iter().enumerate() {
            ui.checkbox(&mut app.bench.tools.stats.encodings[index], encoding.label());
        }
        ui.separator();
        ui.add(egui::TextEdit::singleline(&mut app.bench.tools.stats.filter).hint_text("filter…").desired_width(160.0));
        ui.checkbox(&mut app.bench.tools.stats.interesting_only, "Only URLs, paths, keys…");
    });
    let Some(sheet) = app.bench.tools.stats.strings.sheet().map(str::to_string) else { return };
    crate::sheets::view::results_of_other_sheet(app, ui, &sheet);
    let Some((found, step)) = app.bench.tools.stats.strings.get().map(|found| (found.strings.clone(), found.step)) else { return };
    let filter = app.bench.tools.stats.filter.to_lowercase();
    let interesting_only = app.bench.tools.stats.interesting_only;
    let shown: Vec<(usize, Option<&'static str>)> = found
        .iter()
        .enumerate()
        .map(|(index, string)| (index, strings::classify(&string.text)))
        .filter(|(index, tag)| (!interesting_only || tag.is_some()) && (filter.is_empty() || found[*index].text.to_lowercase().contains(&filter)))
        .collect();
    ui.label(RichText::new(format!("{} strings{}", shown.len(), if found.len() >= MAX_STRINGS { " (stopped at the limit)" } else { "" })).small().color(theme::TEXT_DIM));
    let mut chosen = None;
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
    egui::ScrollArea::vertical().id_salt("strings-list").show_rows(ui, row_height, shown.len(), |ui, range| {
        for &(index, tag) in &shown[range] {
            let string = &found[index];
            ui.horizontal(|ui| {
                if ui.add(egui::Label::new(RichText::new(format!("{:#010x}", string.offset)).monospace().color(theme::TEXT_DIM)).sense(Sense::click())).clicked() {
                    chosen = Some((string.offset, string.len_bytes));
                }
                ui.label(RichText::new(string.encoding.label()).small().color(theme::TEXT_DIM));
                if let Some(tag) = tag {
                    ui.label(RichText::new(tag).small().color(theme::CURSOR));
                }
                if ui.small_button("Use as key").on_hover_text("XOR with this text in the XOR tab, keeping where it came from").clicked() {
                    send_to::send_later(app, Sending::To(Target::XorKey), string_carry(&found, step, index, &sheet));
                }
                let text = ui.add(egui::Label::new(RichText::new(&string.text).monospace()).truncate().sense(Sense::click()));
                text.context_menu(|ui| {
                    let carry = string_carry(&found, step, index, &sheet);
                    send_to::menu(app, ui, &carry);
                });
            });
        }
    });
    if let Some((offset, len)) = chosen {
        app.select_found_in(&sheet, offset, len);
    }
}

/// What the string at `index` of those found in `sheet` carries elsewhere:
/// its text, found again on another file as a pick from the strings the
/// search (step `step`) found: the first whose text has the same shape,
/// when it is the first such, else the one at its place.
pub(crate) fn string_carry(found: &[FoundString], step: Option<u64>, index: usize, sheet: &str) -> Carry {
    let string = &found[index];
    let pattern = crate::journal::provenance::shape_of(&string.text).filter(|pattern| {
        let Ok(regex) = regex_lite::Regex::new(pattern) else { return false };
        found.iter().position(|other| regex.is_match(&other.text)) == Some(index)
    });
    let (anchor, from) = match step {
        Some(step) => {
            let condition = pattern.as_ref().map(|pattern| serde_json::Map::from_iter([("text".to_string(), serde_json::json!({ "regex": pattern }))]));
            let nth = if condition.is_some() { 0 } else { index };
            let pick = Pick { step: StepRef::Number(step), list: "job.strings".to_string(), condition, sort: None, nth, field: Some("text".to_string()) };
            let from = match &pattern {
                Some(pattern) => format!("from step {step}, string /{}/", pattern_shown(pattern)),
                None => format!("from step {step}, string {}", index + 1),
            };
            (Some(Anchor::Pick { pick }), from)
        }
        None => (None, format!("string at {:#x}", string.offset)),
    };
    Carry::value(Carried::Text(string.text.clone()), anchor, from, sheet).with_span(string.offset, string.len_bytes)
}

/// A shape's pattern as a chip shows it: its fixed start without escapes,
/// `^NC500-` for `^NC500\-[0-9A-F]{8}$`, or the whole pattern when it has
/// none.
fn pattern_shown(pattern: &str) -> String {
    match pattern.find('[') {
        Some(at) if at > 1 => pattern[..at].replace('\\', ""),
        _ => pattern.to_string(),
    }
}

// ---------------------------------------------------------------------------
// XOR
// ---------------------------------------------------------------------------

/// The person asks for the XOR keys of the bytes at `start`:
/// `xor.recover_keys`, shown in the XOR tab.
fn find_xor_keys(app: &mut ViewerApp, start: usize, len: usize) {
    let params = serde_json::json!({ "start": start, "len": len, "max_key": crate::api::tools::xor::DEFAULT_MAX_KEY });
    if let Ok(found) = app.perform_typed::<crate::api::tools::xor::RecoveredKeys>("xor.recover_keys", params) {
        // The read the keys came from, which a key carried elsewhere cites.
        let step = app.journal.last_step();
        show_xor_keys(app, &found, step);
    }
}

/// Show keys recovered in the XOR tab.
fn show_xor_keys(app: &mut ViewerApp, found: &crate::api::tools::xor::RecoveredKeys, step: Option<u64>) {
    let lengths = found.key_lengths.iter().map(|length| (length.length, length.score)).collect();
    let sheet = app.document_id();
    let results = XorResults { start: found.start as usize, len: found.len as usize, candidates: found.xor_candidates(), lengths, step };
    app.bench.tools.stats.xor_candidates.set(&sheet, results);
    app.note_tool_result(crate::dock::DockTab::Xor);
}

/// Recover the keys again for the same bytes, after an edit: the app's own
/// work, not the person's step.
pub(crate) fn refresh_xor(app: &mut ViewerApp) {
    let Some(XorResults { start, len, .. }) = app.bench.tools.stats.xor_candidates.of(&app.document_id()).cloned() else { return };
    let params = crate::api::tools::xor::RecoverKeysParams { start: start as u64, len: Some(len.min(app.document.len().saturating_sub(start)) as u64), ..Default::default() };
    match crate::api::tools::xor::recover_keys(app, params) {
        Ok(found) => show_xor_keys(app, &found, None),
        Err(error) => app.status = format!("XOR keys: {}", error.message),
    }
}

/// The bytes the XOR tab works on: the selection, else 64 KiB from the
/// cursor, capped.
fn xor_span(app: &ViewerApp) -> (usize, usize) {
    let (start, len) = app.selection().map(|(start, len)| (start, len.min(XOR_LIMIT))).unwrap_or((app.cursor, XOR_LIMIT.min(64 * 1024)));
    (start, len.min(app.document.len().saturating_sub(start)))
}

pub fn show_xor(app: &mut ViewerApp, ui: &mut Ui) {
    let (start, len) = xor_span(app);
    ui.horizontal(|ui| {
        if ui.button(format!("Find XOR keys for {} bytes at {start:#x}", len)).clicked() {
            find_xor_keys(app, start, len);
        }
        ui.label(RichText::new("select the suspect bytes first; without a selection, 64 KiB from the cursor").small().color(theme::TEXT_DIM));
    });
    show_xor_key_row(app, ui, start, len);
    let active = app.document_id();
    app.bench.tools.stats.xor_candidates.switched(&active);
    let Some((sheet, results)) = app.bench.tools.stats.xor_candidates.shown().map(|(sheet, found)| (sheet.to_string(), found.clone())) else {
        ui.label(
            RichText::new("Recovers single-byte and repeating-key XOR by letter frequency, index of coincidence and the key showing through zero padding. Preview a decode, or apply it as an undoable edit.")
                .color(theme::TEXT_DIM),
        );
        return;
    };
    crate::sheets::view::results_of_other_sheet(app, ui, &sheet);
    if !results.lengths.is_empty() {
        let text: Vec<String> = results.lengths.iter().map(|(length, score)| format!("{length} ({score:.3})")).collect();
        ui.label(RichText::new(format!("Likely key lengths: {}", text.join(", "))).small().color(theme::TEXT_DIM));
    }
    if results.candidates.is_empty() {
        ui.label(RichText::new("No convincing key.").color(theme::TEXT_DIM));
        return;
    }
    let mut action: Option<(Vec<u8>, bool)> = None;
    egui::ScrollArea::vertical().id_salt("xor-candidates").show(ui, |ui| {
        for (index, candidate) in results.candidates.iter().enumerate() {
            ui.horizontal(|ui| {
                let key: String = candidate.key.iter().map(|b| format!("{b:02x}")).collect();
                let printable: String = candidate.key.iter().map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' }).collect();
                let key_label = ui.add(egui::Label::new(RichText::new(format!("key {key}")).monospace().color(theme::ACCENT)).sense(Sense::click()));
                key_label.context_menu(|ui| {
                    let carry = xor_key_carry(&results, index, &sheet);
                    send_to::menu(app, ui, &carry);
                });
                if candidate.key.len() > 1 {
                    ui.monospace(RichText::new(format!("\"{printable}\"")).color(theme::TEXT_DIM));
                }
                ui.label(RichText::new(format!("{:.0}% printable · {}", candidate.printable_fraction * 100.0, candidate.reason)).small().color(theme::TEXT_DIM));
                if ui.small_button("Use as key").on_hover_text("Put this key in the Key field above, keeping where it came from").clicked() {
                    send_to::send_later(app, Sending::To(Target::XorKey), xor_key_carry(&results, index, &sheet));
                }
                if ui.small_button("Preview").on_hover_text("Open the decoded bytes as a document; Back returns").clicked() {
                    action = Some((candidate.key.clone(), false));
                }
                if ui.small_button("Apply").on_hover_text("Replace the bytes with the decode (undoable)").clicked() {
                    action = Some((candidate.key.clone(), true));
                }
            });
            ui.monospace(RichText::new(&candidate.preview).small().color(theme::TEXT_DIM));
        }
    });
    if let Some((key, in_place)) = action {
        use_xor_key(app, &sheet, results.start, results.len, &key, in_place);
    }
}

/// What the key at `index` of those proposed in `sheet` carries elsewhere:
/// its bytes, found again on another file as the key at the same rank of
/// those `xor.recover_keys` proposes there.
pub(crate) fn xor_key_carry(results: &XorResults, index: usize, sheet: &str) -> Carry {
    let key = results.candidates[index].key.clone();
    let rank = if index == 0 { "the top key".to_string() } else { format!("key {}", index + 1) };
    let (anchor, from) = match results.step {
        Some(step) => {
            let pick = Pick { step: StepRef::Number(step), list: "result.candidates".to_string(), condition: None, sort: None, nth: index, field: Some("key".to_string()) };
            (Some(Anchor::Pick { pick }), format!("from step {step}, {rank}"))
        }
        None => (None, rank),
    };
    Carry::value(Carried::Bytes(key), anchor, from, sheet)
}

/// The XOR tab's own key, applied to the bytes the tab works on.
fn show_xor_key_row(app: &mut ViewerApp, ui: &mut Ui, start: usize, len: usize) {
    let mut apply = false;
    ui.horizontal(|ui| {
        ui.label("Key");
        let stats = &mut app.bench.tools.stats;
        let field = send_to::bound_field(ui, &mut stats.xor_key, &mut stats.xor_key_bound, "hex, or Send to here", 160.0);
        if let Some(carry) = field.dropped {
            send_to::send_later(app, Sending::To(Target::XorKey), carry);
        }
        let ready = !app.bench.tools.stats.xor_key.trim().is_empty() && len > 0;
        apply = ui.add_enabled(ready, egui::Button::new(format!("Apply to {len} bytes at {start:#x}"))).on_hover_text("XOR the bytes with this key, repeated from their start").clicked();
    });
    if apply {
        apply_xor_key_field(app, start, len);
    }
}

/// The person XORs `len` bytes at `start` of the sheet shown with the key
/// typed (or sent) into the XOR tab: `transform.apply`.
pub(crate) fn apply_xor_key_field(app: &mut ViewerApp, start: usize, len: usize) -> bool {
    let Some(key) = crate::ops::parse_hex(&app.bench.tools.stats.xor_key).filter(|key| !key.is_empty()) else {
        app.status = "The key must be hex bytes, e.g. 5A or DEADBEEF".to_string();
        return false;
    };
    let key_hex = crate::ops::to_compact_hex(&key);
    let params = serde_json::json!({ "selection": { "range": [start, len] }, "operation": { "op": "xor", "key": key_hex } });
    let derived_from = send_to::Bound::at(&app.bench.tools.stats.xor_key_bound, "operation.key");
    let applied = app.perform_derived("transform.apply", params, derived_from).is_ok();
    if applied {
        app.status = format!("XOR {key_hex} applied to {len} bytes at {start:#x}");
    }
    applied
}

/// The inputs of the XOR tab a carry can fill: its key, with bytes.
pub fn slots(carry: &Carry) -> Vec<Slot> {
    if carry.has_bytes() { vec![Slot { label: "XOR tab · key", target: Target::XorKey }] } else { Vec::new() }
}

/// Fill the XOR tab's key with what `carry` holds, as hex.
pub(crate) fn fill_xor_key(app: &mut ViewerApp, carry: &Carry) -> Result<String, String> {
    let filled = carry.as_hex(app).ok_or_else(|| send_to::does_not_fit(carry, "an XOR key"))?;
    app.bench.tools.stats.xor_key = filled.text;
    app.bench.tools.stats.xor_key_bound = filled.bound;
    Ok(format!("The XOR tab's key is {}", carry.summary()))
}

/// The person applies a key to the bytes of sheet `sheet` it was found
/// for: as an undoable edit (`transform.apply`), or opened decoded as a
/// document of its own (`documents.derive`). Another sheet than the one
/// shown is named.
fn use_xor_key(app: &mut ViewerApp, sheet: &str, start: usize, len: usize, key: &[u8], in_place: bool) {
    let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let operation = serde_json::json!({ "op": "xor", "key": key_hex });
    let shown = sheet == app.document_id();
    if in_place {
        let mut params = serde_json::json!({ "selection": { "range": [start, len] }, "operation": operation });
        if !shown {
            params["doc"] = serde_json::json!(sheet);
        }
        if app.perform("transform.apply", params).is_ok() {
            if shown {
                app.restore_selection(start, len);
            }
            app.status = format!("XOR {key_hex} applied to {len} bytes at {start:#x}");
        }
    } else {
        let name = format!("{} › xor {key_hex}@{start:#x}", app.sheet_title(sheet).unwrap_or_else(|| app.display_name()));
        let mut params = serde_json::json!({ "start": start, "len": len, "name": name, "transform": operation });
        if !shown {
            params["doc"] = serde_json::json!(sheet);
        }
        let _ = app.perform("documents.derive", params);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::actions::take_performed;
    use crate::app::Launch;

    /// Longest a test waits for a tool's job.
    const PATIENCE: Duration = Duration::from_secs(30);

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        take_performed();
        app
    }

    /// What `pending` delivers, waiting for it.
    fn wait_for<T>(pending: &Option<Receiver<T>>) -> T {
        let receiver = pending.as_ref().expect("a job is pending");
        receiver.recv_timeout(PATIENCE).expect("the job delivers its result")
    }

    fn notes() -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes.extend(b"Visit https://example.com/manual for the manual. ".repeat(40));
        bytes
    }

    #[test]
    fn asking_for_statistics_measures_the_selection_in_a_job_of_the_person_s() {
        let mut app = app_with(&notes());
        app.restore_selection(64, 1000);
        start_statistics(&mut app);
        assert_eq!(take_performed(), [("statistics.analyse".to_string(), json!({"start": 64, "len": 1000}))]);
        let result = wait_for(&app.bench.tools.stats.pending);
        assert_eq!((result.start, result.len, result.verdict.label), (64, 1000, "Text"));
        app.run_bus();
        let job = app.bus.jobs().list().into_iter().find(|job| job.title == "Byte statistics").expect("the measure is a job");
        assert_eq!(job.producer, "panel");
    }

    #[test]
    fn finding_strings_passes_the_tab_s_options_and_fills_the_tab() {
        let mut app = app_with(&notes());
        app.bench.tools.stats.min_chars = 8;
        app.bench.tools.stats.encodings = [true, false, false, true];
        start_strings(&mut app);
        let expected = json!({"start": 0, "len": notes().len(), "min_chars": 8, "encodings": ["ascii", "utf16be"]});
        assert_eq!(take_performed(), [("strings.find".to_string(), expected)]);
        let found = wait_for(&app.bench.tools.stats.strings_pending.take().map(|(_, _, receiver)| receiver));
        assert_eq!(found.strings.first().map(|string| string.offset), Some(64));
        assert!(found.strings.iter().all(|string| string.text.chars().count() >= 8));
    }

    #[test]
    fn recovering_xor_keys_reads_them_through_the_api_and_lists_them() {
        let hidden = crate::xor::apply(&notes()[64..], &[0x5A], 0);
        let mut app = app_with(&hidden);
        find_xor_keys(&mut app, 0, hidden.len());
        assert_eq!(take_performed(), [("xor.recover_keys".to_string(), json!({"start": 0, "len": hidden.len(), "max_key": 32}))]);
        let XorResults { start, len, candidates, .. } = app.bench.tools.stats.xor_candidates.get().cloned().expect("keys listed");
        assert_eq!((start, len), (0, hidden.len()));
        assert_eq!(candidates.first().map(|candidate| candidate.key.clone()), Some(vec![0x5A]));
    }

    #[test]
    fn applying_a_xor_key_is_an_undoable_transform_and_previewing_it_opens_a_derived_document() {
        let hidden = crate::xor::apply(b"plain words", &[0x20], 0);
        let mut app = app_with(&hidden);
        let sheet = app.document_id();
        use_xor_key(&mut app, &sheet, 0, hidden.len(), &[0x20], true);
        let operation = json!({"op": "xor", "key": "20"});
        assert_eq!(take_performed(), [("transform.apply".to_string(), json!({"selection": {"range": [0, hidden.len()]}, "operation": operation}))]);
        assert_eq!(app.document.read_range(0, hidden.len()), b"plain words");
        assert_eq!(app.status, format!("XOR 20 applied to {} bytes at 0x0", hidden.len()));
        use_xor_key(&mut app, &sheet, 0, 5, &[0x20], false);
        let name = "test.bin › xor 20@0x0";
        assert_eq!(take_performed(), [("documents.derive".to_string(), json!({"start": 0, "len": 5, "name": name, "transform": operation}))]);
        assert_eq!(app.display_name(), name);
        assert_eq!(app.document.read_range(0, 5), b"PLAIN");
    }

    #[test]
    fn picking_what_a_tool_found_selects_or_moves_the_cursor_through_the_api() {
        let mut app = app_with(&notes());
        assert!(app.select_found(70, 5));
        app.jump_found(10_000);
        assert_eq!(
            take_performed(),
            [("selection.set".to_string(), json!({"selection": {"range": [70, 5]}})), ("cursor.set".to_string(), json!({"offset": notes().len()}))]
        );
        assert_eq!(app.cursor, notes().len(), "past the end goes to the end");
    }

    /// The strings `strings.find` found in `app`'s document, as the tab
    /// keeps them, with the step that found them.
    fn strings_found(app: &mut ViewerApp) -> FoundStrings {
        start_strings(app);
        let (_, step, receiver) = app.bench.tools.stats.strings_pending.take().expect("a search is pending");
        let mut found = receiver.recv_timeout(PATIENCE).expect("the search finishes");
        found.step = step;
        app.run_bus();
        found
    }

    #[test]
    fn a_string_sent_to_a_variable_is_bound_with_the_pick_that_finds_it_again() {
        let mut app = app_with(b"\0\0config for unit\0\0NC500-2F357657\0\0NC500-00000000\0\0");
        let found = strings_found(&mut app);
        let index = found.strings.iter().position(|string| string.text == "NC500-2F357657").expect("the serial is found");
        let carry = string_carry(&found.strings, found.step, index, &app.document_id());
        let Carry::Value(carried) = &carry else { panic!("a string carries a value") };
        assert_eq!(carried.from, format!("from step {}, string /^NC500-/", found.step.unwrap()));
        take_performed();
        send_to::bind_variable(&mut app, &carry, "$serial").unwrap();
        assert_eq!(take_performed(), [("vars.set".to_string(), json!({"name": "serial", "value": "NC500-2F357657"}))]);
        let listed = app.perform("vars.list", json!({})).unwrap();
        let shape = crate::journal::provenance::shape_of("NC500-2F357657").unwrap();
        let expected = json!({"pick": {"step": found.step, "list": "job.strings", "where": {"text": {"regex": shape}}, "field": "text"}});
        assert_eq!(listed["variables"][0]["anchor"], expected, "the first string of its shape, found again by that shape");
    }

    #[test]
    fn a_string_that_is_not_the_first_of_its_shape_is_picked_by_its_place() {
        let mut app = app_with(b"\0\0NC500-00000000\0\0NC500-2F357657\0\0");
        let found = strings_found(&mut app);
        let carry = string_carry(&found.strings, found.step, 1, &app.document_id());
        let Carry::Value(carried) = carry else { panic!("a string carries a value") };
        let Some(Anchor::Pick { pick }) = carried.anchor else { panic!("a pick") };
        assert_eq!((pick.condition, pick.nth), (None, 1));
    }

    #[test]
    fn a_key_sent_to_the_xor_tab_fills_its_key_and_applying_it_is_a_transform() {
        let hidden = crate::xor::apply(&notes()[64..], &[0x5A], 0);
        let mut app = app_with(&hidden);
        find_xor_keys(&mut app, 0, hidden.len());
        let results = app.bench.tools.stats.xor_candidates.get().cloned().expect("keys listed");
        let carry = xor_key_carry(&results, 0, &app.document_id());
        assert!(slots(&carry).iter().any(|slot| slot.target == Target::XorKey));
        send_to::send(&mut app, Target::XorKey, &carry).unwrap();
        assert_eq!(app.bench.tools.stats.xor_key, "5a");
        take_performed();
        assert!(apply_xor_key_field(&mut app, 0, 4));
        assert_eq!(take_performed(), [("transform.apply".to_string(), json!({"selection": {"range": [0, 4]}, "operation": {"op": "xor", "key": "5a"}}))]);
        assert_eq!(app.document.read_range(0, 4), &notes()[64..68]);
    }

    #[test]
    fn use_as_key_on_a_candidate_fills_the_xor_tab_s_key_with_where_it_came_from() {
        use egui_kittest::kittest::Queryable;
        let hidden = crate::xor::apply(&notes()[64..], &[0x5A], 0);
        let mut app = app_with(&hidden);
        find_xor_keys(&mut app, 0, hidden.len());
        let mut harness = egui_kittest::Harness::new_ui_state(
            |ui, app: &mut ViewerApp| {
                app.perform_waiting_actions();
                show_xor(app, ui);
            },
            app,
        );
        harness.step();
        harness.get_all_by_label("Use as key").next().expect("each candidate offers it").click();
        harness.run();
        assert_eq!(harness.state().bench.tools.stats.xor_key, "5a");
        assert!(harness.state().status.starts_with("The XOR tab's key is 5a"), "{}", harness.state().status);
    }

    /// The XOR tab drawn as the window draws it.
    fn xor_tab(app: ViewerApp) -> egui_kittest::Harness<'static, ViewerApp> {
        egui_kittest::Harness::new_ui_state(
            |ui, app: &mut ViewerApp| {
                app.perform_waiting_actions();
                show_xor(app, ui);
            },
            app,
        )
    }

    #[test]
    fn a_string_sent_to_the_xor_key_shows_as_a_chip_and_the_xor_journals_its_anchor() {
        use egui_kittest::kittest::Queryable;
        let mut app = app_with(b"\0\0NC500-2F357657\0\0some config text here\0\0");
        let found = strings_found(&mut app);
        let carry = string_carry(&found.strings, found.step, 0, &app.document_id());
        send_to::send(&mut app, Target::XorKey, &carry).unwrap();
        app.restore_selection(19, 8);
        let mut harness = xor_tab(app);
        harness.run();
        harness.get_by_label("NC500-2F357657");
        harness.get_by_label(&format!("· from step {}, string /^NC500-/", found.step.unwrap()));
        take_performed();
        harness.get_by_label("Apply to 8 bytes at 0x13").click();
        harness.run();
        let app = harness.state();
        let entry = app.journal.entries().rev().find(|entry| entry.method == "transform.apply").expect("the XOR is a step");
        assert_eq!(entry.params["operation"]["key"], crate::ops::to_compact_hex(b"NC500-2F357657"));
        let Some(Anchor::Then { of, then }) = entry.derived_from.get("operation.key") else { panic!("the key keeps where it came from: {:?}", entry.derived_from) };
        assert!(matches!(of.as_ref(), Anchor::Pick { pick } if pick.step == StepRef::Number(found.step.unwrap()) && pick.list == "job.strings"));
        assert_eq!(then, &[crate::journal::anchors::Operation::Encode(crate::journal::anchors::then::Encoding::TextToHex)]);
    }

    #[test]
    fn unbinding_a_chip_keeps_the_value_as_a_literal() {
        use egui_kittest::kittest::Queryable;
        let mut app = app_with(&[0u8; 16]);
        let carry = Carry::variable("serial", &json!("AB"), app.document_id());
        send_to::send(&mut app, Target::XorKey, &carry).unwrap();
        let mut harness = xor_tab(app);
        harness.run();
        harness.get_by_label("· $serial");
        harness.get_by_label("✕").click();
        harness.run();
        let stats = &harness.state().bench.tools.stats;
        assert_eq!((stats.xor_key.as_str(), stats.xor_key_bound.is_none()), ("4142", true));
        assert!(harness.get_all_by_value("4142").next().is_some(), "the key is a text box again, holding the value");
    }
}
