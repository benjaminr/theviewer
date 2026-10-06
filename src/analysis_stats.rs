//! Dock tabs for byte statistics, strings and XOR key recovery.

use std::sync::mpsc::{self, Receiver};
use std::thread;

use eframe::egui::{self, Color32, Rect, RichText, Sense, TextureHandle, Ui, pos2, vec2};
use egui_plot::{Bar, BarChart, Legend, Line, Plot, PlotPoints};

use crate::app::ViewerApp;
use crate::stats::{self, ByteStats, Repeat, Verdict};
use crate::strings::{self, Encoding, FoundString};
use crate::theme;
use crate::xor::{self, XorCandidate};

/// Largest range analysed for statistics and strings.
const SCAN_LIMIT: usize = 64 * 1024 * 1024;
/// Largest range searched for XOR keys.
const XOR_LIMIT: usize = 1024 * 1024;
/// Most strings kept.
const MAX_STRINGS: usize = 200_000;

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

/// XOR results for (start, len): candidates and likely key lengths.
pub type XorResults = (usize, usize, Vec<XorCandidate>, Vec<(usize, f64)>);

pub struct StatsState {
    pending: Option<Receiver<StatsResult>>,
    pub result: Option<StatsResult>,
    heatmap: Option<TextureHandle>,

    strings_pending: Option<Receiver<(usize, Vec<FoundString>)>>,
    pub strings: Option<(usize, Vec<FoundString>)>,
    pub min_chars: usize,
    pub encodings: [bool; 4],
    pub filter: String,
    pub interesting_only: bool,

    pub xor_candidates: Option<XorResults>,
}

impl Default for StatsState {
    fn default() -> Self {
        StatsState {
            pending: None,
            result: None,
            heatmap: None,
            strings_pending: None,
            strings: None,
            min_chars: 6,
            encodings: [true, true, true, false],
            filter: String::new(),
            interesting_only: false,
            xor_candidates: None,
        }
    }
}

impl StatsState {
    pub fn document_changed(&mut self) {
        *self = StatsState { min_chars: self.min_chars, encodings: self.encodings, ..Default::default() };
    }
}

/// The selection, else the whole file, capped.
fn scope(app: &ViewerApp, limit: usize) -> (usize, usize, &'static str) {
    match app.selection() {
        Some((start, len)) => (start, len.min(limit), "selection"),
        None => (0, app.document.len().min(limit), "whole file"),
    }
}

fn select_range(app: &mut ViewerApp, start: usize, len: usize) {
    app.anchor = Some(start);
    app.cursor = start + len.max(1);
    app.reveal_cursor_centred();
    app.reveal_cursor_in_hex(true);
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

pub fn start_statistics(app: &mut ViewerApp) {
    let (start, len, _) = scope(app, SCAN_LIMIT);
    let bytes = app.document.read_range(start, len);
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let stats = stats::byte_stats(&bytes);
        let verdict = stats::verdict(&stats);
        let window = (bytes.len() / 512).clamp(256, 64 * 1024);
        let result = StatsResult {
            start,
            len: bytes.len(),
            verdict,
            digraph: stats::digraph_counts(&bytes),
            entropy: stats::sliding_entropy(&bytes, window, 1024),
            compressibility: stats::compressibility(&bytes, window.max(1024), 512),
            repeats: stats::repeated_sequences(&bytes, 4, 32, 40),
            stats,
        };
        let _ = sender.send(result);
    });
    app.bench.tools.stats.pending = Some(receiver);
    app.note_tool_result(crate::dock::DockTab::Statistics);
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
        app.jump_to_offset(offset);
    }
    if let Some((offset, len, bytes)) = chosen {
        // Also prime search, so F3 walks the other occurrences.
        app.search_mode = crate::search::SearchMode::Hex;
        app.search_text = crate::ops::to_hex_string(&bytes);
        app.search_count = None;
        select_range(app, offset, len);
        app.status = "Selected; press F3 for the next occurrence".to_string();
    }
}

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

pub(crate) fn start_strings(app: &mut ViewerApp) {
    app.note_tool_result(crate::dock::DockTab::Strings);
    let (start, len, _) = scope(app, SCAN_LIMIT);
    let bytes = app.document.read_range(start, len);
    let min_chars = app.bench.tools.stats.min_chars.max(2);
    let encodings: Vec<Encoding> = Encoding::ALL.iter().zip(app.bench.tools.stats.encodings).filter(|(_, on)| *on).map(|(e, _)| *e).collect();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let found = strings::extract(&bytes, start, min_chars, &encodings, MAX_STRINGS);
        let _ = sender.send((start, found));
    });
    app.bench.tools.stats.strings_pending = Some(receiver);
}

pub fn show_strings(app: &mut ViewerApp, ui: &mut Ui) {
    if let Some(receiver) = &app.bench.tools.stats.strings_pending
        && let Ok(found) = receiver.try_recv()
    {
        app.bench.tools.stats.strings = Some(found);
        app.bench.tools.stats.strings_pending = None;
    }
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
    let Some((_, found)) = &app.bench.tools.stats.strings else { return };
    let filter = app.bench.tools.stats.filter.to_lowercase();
    let interesting_only = app.bench.tools.stats.interesting_only;
    let shown: Vec<(&FoundString, Option<&'static str>)> = found
        .iter()
        .map(|s| (s, strings::classify(&s.text)))
        .filter(|(s, tag)| (!interesting_only || tag.is_some()) && (filter.is_empty() || s.text.to_lowercase().contains(&filter)))
        .collect();
    ui.label(RichText::new(format!("{} strings{}", shown.len(), if found.len() >= MAX_STRINGS { " (stopped at the limit)" } else { "" })).small().color(theme::TEXT_DIM));
    let mut chosen = None;
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
    egui::ScrollArea::vertical().id_salt("strings-list").show_rows(ui, row_height, shown.len(), |ui, range| {
        for (string, tag) in &shown[range] {
            ui.horizontal(|ui| {
                if ui.add(egui::Label::new(RichText::new(format!("{:#010x}", string.offset)).monospace().color(theme::TEXT_DIM)).sense(Sense::click())).clicked() {
                    chosen = Some((string.offset, string.len_bytes));
                }
                ui.label(RichText::new(string.encoding.label()).small().color(theme::TEXT_DIM));
                if let Some(tag) = tag {
                    ui.label(RichText::new(*tag).small().color(theme::CURSOR));
                }
                ui.add(egui::Label::new(RichText::new(&string.text).monospace()).truncate());
            });
        }
    });
    if let Some((offset, len)) = chosen {
        select_range(app, offset, len);
    }
}

// ---------------------------------------------------------------------------
// XOR
// ---------------------------------------------------------------------------

/// Recover XOR keys for the bytes at `start`.
fn find_xor_keys(app: &mut ViewerApp, start: usize, len: usize) {
    let bytes = app.document.read_range(start, len);
    let candidates = xor::recover_keys(&bytes, 32, 12);
    let lengths = xor::guess_key_lengths(&bytes, 32).into_iter().take(6).collect();
    app.bench.tools.stats.xor_candidates = Some((start, len, candidates, lengths));
    app.note_tool_result(crate::dock::DockTab::Xor);
}

/// Recover the keys again for the same bytes, after an edit.
pub(crate) fn refresh_xor(app: &mut ViewerApp) {
    if let Some((start, len, ..)) = app.bench.tools.stats.xor_candidates.clone() {
        find_xor_keys(app, start, len);
    }
}

pub fn show_xor(app: &mut ViewerApp, ui: &mut Ui) {
    let (start, len) = app.selection().map(|(s, l)| (s, l.min(XOR_LIMIT))).unwrap_or((app.cursor, XOR_LIMIT.min(64 * 1024)));
    let len = len.min(app.document.len().saturating_sub(start));
    ui.horizontal(|ui| {
        if ui.button(format!("Find XOR keys for {} bytes at {start:#x}", len)).clicked() {
            find_xor_keys(app, start, len);
        }
        ui.label(RichText::new("select the suspect bytes first; without a selection, 64 KiB from the cursor").small().color(theme::TEXT_DIM));
    });
    let Some((start, len, candidates, lengths)) = app.bench.tools.stats.xor_candidates.clone() else {
        ui.label(
            RichText::new("Recovers single-byte and repeating-key XOR by letter frequency, index of coincidence and the key showing through zero padding. Preview a decode, or apply it as an undoable edit.")
                .color(theme::TEXT_DIM),
        );
        return;
    };
    if !lengths.is_empty() {
        let text: Vec<String> = lengths.iter().map(|(length, score)| format!("{length} ({score:.3})")).collect();
        ui.label(RichText::new(format!("Likely key lengths: {}", text.join(", "))).small().color(theme::TEXT_DIM));
    }
    if candidates.is_empty() {
        ui.label(RichText::new("No convincing key.").color(theme::TEXT_DIM));
        return;
    }
    let mut action: Option<(Vec<u8>, bool)> = None;
    egui::ScrollArea::vertical().id_salt("xor-candidates").show(ui, |ui| {
        for candidate in &candidates {
            ui.horizontal(|ui| {
                let key: String = candidate.key.iter().map(|b| format!("{b:02x}")).collect();
                let printable: String = candidate.key.iter().map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' }).collect();
                ui.monospace(RichText::new(format!("key {key}")).color(theme::ACCENT));
                if candidate.key.len() > 1 {
                    ui.monospace(RichText::new(format!("\"{printable}\"")).color(theme::TEXT_DIM));
                }
                ui.label(RichText::new(format!("{:.0}% printable · {}", candidate.printable_fraction * 100.0, candidate.reason)).small().color(theme::TEXT_DIM));
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
        let bytes = app.document.read_range(start, len);
        let decoded = xor::apply(&bytes, &key, 0);
        let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        if in_place {
            app.document.replace(start, len, &decoded);
            app.restore_selection(start, len);
            app.status = format!("XOR {key_hex} applied to {len} bytes at {start:#x}");
        } else {
            app.open_derived(decoded, format!("{} › xor {key_hex}@{start:#x}", app.display_name()));
        }
    }
}
