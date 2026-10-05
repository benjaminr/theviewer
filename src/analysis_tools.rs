//! Dock tabs for diagnosing unknown data: column profiling of records,
//! protocol analysis of message streams, byte statistics, strings and XOR.

use std::sync::mpsc::{self, Receiver};
use std::thread;

use eframe::egui::{self, Color32, ColorImage, Rect, RichText, Sense, Stroke, TextureHandle, TextureOptions, Ui, pos2, vec2};

use crate::app::ViewerApp;
use crate::columns::{self, ColumnKind, ColumnProfile, FieldGuess};
use crate::plugin::{Category, Finding};
use crate::protocol::{self, FramingCandidate, Message, MessageField};
use crate::theme;

/// Largest stream handed to protocol analysis.
const PROTOCOL_LIMIT: usize = 16 * 1024 * 1024;
/// Records profiled per column.
const PROFILE_RECORDS: usize = 4096;
/// Messages listed in the protocol table.
const LISTED_MESSAGES: usize = 1000;
/// Messages outlined on the raster.
const PINNED_MESSAGES: usize = 5000;

/// A finished protocol analysis: base offset, the bytes, the report and all framings.
type ProtocolResult = (usize, Vec<u8>, protocol::ProtocolReport, Vec<FramingCandidate>);

/// State for this module's tabs.
#[derive(Default)]
pub struct ToolsState {
    pub record_len: usize,
    pub columns: Option<(usize, usize, Vec<ColumnProfile>, Vec<FieldGuess>)>,
    /// How many records the column profile covers.
    pub columns_records: usize,

    protocol_pending: Option<Receiver<ProtocolResult>>,
    pub protocol: Option<ProtocolView>,

    pub stats: crate::analysis_stats::StatsState,
}

impl ToolsState {
    pub fn document_changed(&mut self) {
        self.columns = None;
        self.protocol = None;
        self.protocol_pending = None;
        self.stats.document_changed();
    }
}

/// A protocol analysis result, possibly re-split with a chosen framing.
pub struct ProtocolView {
    pub base: usize,
    bytes: Vec<u8>,
    pub report: protocol::ProtocolReport,
    pub candidates: Vec<FramingCandidate>,
    pub chosen: usize,
}

fn kind_colour(kind: ColumnKind) -> Color32 {
    match kind {
        ColumnKind::Constant => Color32::from_rgb(90, 96, 110),
        ColumnKind::Counter => Category::Counter.colour(),
        ColumnKind::Monotonic => Category::OffsetTable.colour(),
        ColumnKind::LowCardinality => Category::Structure.colour(),
        ColumnKind::Text => Category::Text.colour(),
        ColumnKind::Random => Category::HighEntropy.colour(),
        ColumnKind::Mixed => theme::ACCENT_DIM,
    }
}

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

/// Where record analysis starts: the selection, else the start of the record
/// (counted from the view origin) that holds the cursor.
fn records_origin(app: &ViewerApp, record_len: usize) -> usize {
    if let Some((start, _)) = app.selection() {
        return start;
    }
    let origin = app.shape.byte_offset;
    let into_table = app.cursor.saturating_sub(origin);
    origin + into_table / record_len.max(1) * record_len.max(1)
}

pub fn show_columns(app: &mut ViewerApp, ui: &mut Ui) {
    if app.bench.tools.record_len == 0 {
        app.bench.tools.record_len = app
            .period_scan
            .as_ref()
            .and_then(|scan| scan.candidates.first().map(|c| c.period))
            .unwrap_or_else(|| app.shape.row_stride())
            .clamp(1, 65_536);
    }
    let origin = records_origin(app, app.bench.tools.record_len);
    ui.horizontal(|ui| {
        ui.label("Record length");
        ui.add(egui::DragValue::new(&mut app.bench.tools.record_len).range(1..=65_536).suffix(" B"));
        if ui.button("Use row width").on_hover_text("The raster's bytes per row").clicked() {
            app.bench.tools.record_len = app.shape.row_stride();
        }
        if let Some(best) = app.period_scan.as_ref().and_then(|s| s.candidates.first()).map(|c| c.period)
            && ui.button(format!("Use detected {best} B")).clicked()
        {
            app.bench.tools.record_len = best;
        }
        if let Some((_, _, profiles, _)) = &app.bench.tools.columns
            && !profiles.is_empty()
        {
            let records = app.bench.tools.columns_records;
            ui.label(RichText::new(format!("{records} records from {origin:#x}")).small().color(theme::TEXT_DIM))
                .on_hover_text("From the cursor's record (or the selection) to where the records stop looking alike");
        }
    });
    let record_len = app.bench.tools.record_len.max(1);
    let key = (origin, record_len);
    if app.bench.tools.columns.as_ref().map(|c| (c.0, c.1)) != Some(key) {
        let bytes = app.document.read_range(origin, record_len * PROFILE_RECORDS);
        // Within a selection every record counts; otherwise stop where the table does.
        let records = match app.selection() {
            Some((_, len)) => (len / record_len).clamp(1, PROFILE_RECORDS),
            None => columns::table_length(&bytes, record_len, PROFILE_RECORDS),
        };
        let bytes = &bytes[..(records * record_len).min(bytes.len())];
        app.bench.tools.columns_records = records;
        let profiles = columns::profile(bytes, record_len, PROFILE_RECORDS);
        let fields = columns::group_fields(bytes, record_len, &profiles, app.document.len());
        app.bench.tools.columns = Some((origin, record_len, profiles, fields));
    }
    let (_, _, profiles, fields) = app.bench.tools.columns.clone().expect("filled above");
    if profiles.is_empty() {
        ui.label(RichText::new("Not enough data for one record.").color(theme::TEXT_DIM));
        return;
    }

    // One bar per byte position: colour by kind, height by entropy.
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 56.0), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, theme::BACKGROUND);
    let width = rect.width() / profiles.len() as f32;
    for profile in &profiles {
        let x = rect.min.x + profile.position as f32 * width;
        let height = (profile.entropy / 8.0).clamp(0.05, 1.0) * (rect.height() - 4.0);
        let bar = Rect::from_min_max(pos2(x, rect.max.y - height), pos2((x + width - 1.0).max(x + 1.0), rect.max.y));
        painter.rect_filled(bar, 0.0, kind_colour(profile.kind));
    }
    for field in &fields {
        let x = rect.min.x + field.start as f32 * width;
        painter.line_segment([pos2(x, rect.min.y), pos2(x, rect.max.y)], Stroke::new(1.0, theme::OUTLINE));
    }
    if let Some(pointer) = response.hover_pos() {
        let position = (((pointer.x - rect.min.x) / width) as usize).min(profiles.len() - 1);
        let profile = &profiles[position];
        response.on_hover_text(format!(
            "byte {position}: {} ({}), entropy {:.2} bits, {} distinct, most common {:02X} in {:.0}%, changes {:.0}% of records",
            profile.kind.label(),
            profile.kind.description(),
            profile.entropy,
            profile.distinct,
            profile.most_common,
            profile.most_common_fraction * 100.0,
            profile.changes_fraction * 100.0
        ));
    }
    ui.horizontal_wrapped(|ui| {
        for kind in [ColumnKind::Constant, ColumnKind::Counter, ColumnKind::Monotonic, ColumnKind::LowCardinality, ColumnKind::Text, ColumnKind::Random, ColumnKind::Mixed] {
            crate::theme::swatch(ui, kind_colour(kind), kind.label());
        }
        ui.label(RichText::new("· bar height is entropy across records").small().color(theme::TEXT_DIM));
    });

    ui.horizontal(|ui| {
        ui.label(RichText::new("Fields").strong());
        if ui.button("Apply as template").on_hover_text("Turn these fields into a template and decode every record").clicked() {
            let source = columns::to_template(record_len, &fields);
            app.anchor = None;
            app.set_cursor(origin, false);
            app.apply_template_source(&source);
        }
    });
    let mut chosen = None;
    egui::ScrollArea::vertical().id_salt("column-fields").show(ui, |ui| {
        egui::Grid::new("column-fields-grid").striped(true).spacing([14.0, 2.0]).show(ui, |ui| {
            for field in &fields {
                if ui.add(egui::Label::new(RichText::new(format!("+{}", field.start)).monospace()).sense(Sense::click())).clicked() {
                    chosen = Some((origin + field.start, field.len));
                }
                ui.monospace(format!("{} B", field.len));
                ui.label(RichText::new(&field.kind).strong());
                ui.label(RichText::new(&field.detail).color(theme::TEXT_DIM));
                ui.end_row();
            }
        });
    });
    if let Some((start, len)) = chosen {
        app.anchor = Some(start);
        app.cursor = start + len;
        app.reveal_cursor_centred();
        app.reveal_cursor_in_hex(true);
    }
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

pub fn start_protocol(app: &mut ViewerApp) {
    let (start, len) = app.selection().unwrap_or((0, app.document.len()));
    let bytes = app.document.read_range(start, len.min(PROTOCOL_LIMIT));
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let candidates = protocol::detect_framing(&bytes, 8);
        let report = protocol::analyse(&bytes);
        let _ = sender.send((start, bytes, report, candidates));
    });
    app.bench.tools.protocol_pending = Some(receiver);
}

fn poll_protocol(app: &mut ViewerApp) {
    let Some(receiver) = &app.bench.tools.protocol_pending else { return };
    if let Ok((base, bytes, report, candidates)) = receiver.try_recv() {
        app.bench.tools.protocol_pending = None;
        app.bench.tools.protocol = Some(ProtocolView { base, bytes, report, candidates, chosen: 0 });
        pin_messages(app);
    }
}

/// Outline each message on the raster as a protocol finding.
fn pin_messages(app: &mut ViewerApp) {
    app.bench.pinned.retain(|f| f.id != "message");
    let Some(view) = &app.bench.tools.protocol else { return };
    let base = view.base;
    let found: Vec<Finding> = view
        .report
        .messages
        .iter()
        .take(PINNED_MESSAGES)
        .enumerate()
        .map(|(index, message)| {
            Finding::new("message", "protocol", Category::Protocol, base + message.offset, message.len.max(1))
                .title(format!("Message {index}"))
                .detail(format!("{} bytes", message.len))
                .confidence(0.6)
        })
        .collect();
    app.bench.pinned.extend(found);
}

/// Re-split and re-analyse with another framing candidate.
fn choose_framing(app: &mut ViewerApp, index: usize) {
    let Some(view) = &mut app.bench.tools.protocol else { return };
    let Some(candidate) = view.candidates.get(index).cloned() else { return };
    let messages = protocol::split(&view.bytes, &candidate.framing, 100_000);
    let fields = protocol::analyse_fields(&view.bytes, &messages, 32);
    let lengths: Vec<usize> = messages.iter().map(|m| m.len).collect();
    view.report.length_min = lengths.iter().copied().min().unwrap_or(0);
    view.report.length_max = lengths.iter().copied().max().unwrap_or(0);
    view.report.length_mean = if lengths.is_empty() { 0.0 } else { lengths.iter().sum::<usize>() as f64 / lengths.len() as f64 };
    view.report.framing = Some(candidate);
    view.report.messages = messages;
    view.report.fields = fields;
    view.chosen = index;
    pin_messages(app);
}

pub fn show_protocol(app: &mut ViewerApp, ui: &mut Ui) {
    poll_protocol(app);
    ui.horizontal(|ui| {
        let scope = if app.selection().is_some() { "the selection" } else { "the whole file" };
        if ui.button(format!("Analyse {scope} as a message stream")).clicked() {
            start_protocol(app);
        }
        if app.bench.tools.protocol_pending.is_some() {
            ui.spinner();
            ui.label(RichText::new("Looking for framing and fields…").color(theme::TEXT_DIM));
        }
    });
    let Some(view) = &app.bench.tools.protocol else {
        ui.label(
            RichText::new("For captures, serial logs and files of messages: finds how messages are framed (sync words, delimiters, length prefixes, fixed size), splits them, and works out which header bytes are types, sequence numbers, lengths, timestamps and checksums.")
                .color(theme::TEXT_DIM),
        );
        return;
    };
    let base = view.base;
    let report = view.report.clone();
    let candidates = view.candidates.clone();
    let chosen = view.chosen;
    let mut pick = None;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Framing").strong());
        if candidates.is_empty() {
            ui.label(RichText::new("no consistent framing found").color(theme::TEXT_DIM));
        }
        for (index, candidate) in candidates.iter().enumerate() {
            let text = format!("{} · {} msgs · {:.0}%", candidate.framing.describe(), candidate.messages, candidate.coverage * 100.0);
            if ui.selectable_label(index == chosen, text).clicked() && index != chosen {
                pick = Some(index);
            }
        }
    });
    if let Some(index) = pick {
        choose_framing(app, index);
        return;
    }
    if report.messages.is_empty() {
        return;
    }
    ui.label(RichText::new(format!(
        "{} messages, {}–{} bytes (mean {:.1})",
        report.messages.len(),
        report.length_min,
        report.length_max,
        report.length_mean
    ))
    .color(theme::TEXT_DIM));
    if !report.type_counts.is_empty() {
        let types: Vec<String> = report.type_counts.iter().map(|(value, count)| format!("{value}×{count}")).collect();
        ui.label(RichText::new(format!("Message types: {}", types.join("  "))).small());
    }
    let width = ui.available_width();
    let mut select: Option<(usize, usize)> = None;
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width((width * 0.45).max(280.0));
            ui.horizontal(|ui| {
                ui.label(RichText::new("Fields").strong());
                if let Some(source) = protocol::to_template(&report)
                    && ui.button("Apply as template").clicked()
                {
                    app.set_cursor(base + report.messages[0].offset, false);
                    app.apply_template_source(&source);
                }
            });
            egui::ScrollArea::vertical().id_salt("protocol-fields").show(ui, |ui| {
                for field in &report.fields {
                    show_message_field(ui, field);
                }
            });
        });
        ui.separator();
        ui.vertical(|ui| {
            ui.label(RichText::new("Messages").strong());
            egui::ScrollArea::vertical().id_salt("protocol-messages").show(ui, |ui| {
                for (index, message) in report.messages.iter().take(LISTED_MESSAGES).enumerate() {
                    let preview = hex_preview(&app.bench.tools.protocol.as_ref().expect("checked").bytes, message, 20);
                    let text = format!("{index:>5}  {:#08x}  {:>5} B  {preview}", base + message.offset, message.len);
                    if ui.add(egui::Label::new(RichText::new(text).monospace().small()).sense(Sense::click())).clicked() {
                        select = Some((base + message.offset, message.len));
                    }
                }
                if report.messages.len() > LISTED_MESSAGES {
                    ui.label(RichText::new(format!("… {} more", report.messages.len() - LISTED_MESSAGES)).color(theme::TEXT_DIM));
                }
            });
        });
    });
    if let Some((start, len)) = select {
        app.anchor = Some(start);
        app.cursor = start + len.max(1);
        app.reveal_cursor_centred();
        app.reveal_cursor_in_hex(true);
    }
}

fn show_message_field(ui: &mut Ui, field: &MessageField) {
    let position = if field.from_end {
        format!("end−{}", field.start)
    } else if field.len == 0 {
        format!("{}…", field.start)
    } else {
        format!("{}..{}", field.start, field.start + field.len)
    };
    ui.horizontal_wrapped(|ui| {
        ui.monospace(RichText::new(position).color(theme::TEXT_DIM));
        ui.label(RichText::new(&field.kind).strong());
        if !field.detail.is_empty() {
            ui.label(RichText::new(&field.detail).small().color(theme::TEXT_DIM));
        }
        if !field.values.is_empty() {
            ui.label(RichText::new(field.values.join(", ")).small().monospace());
        }
    });
}

fn hex_preview(bytes: &[u8], message: &Message, max: usize) -> String {
    let end = (message.offset + message.len.min(max)).min(bytes.len());
    let mut text: String = bytes[message.offset.min(end)..end].iter().map(|b| format!("{b:02x} ")).collect();
    if message.len > max {
        text.push('…');
    }
    text
}

/// A 256×256 texture from pair counts, log-scaled; used by the statistics tab.
pub fn heatmap_texture(ctx: &egui::Context, name: &str, counts: &[u32]) -> TextureHandle {
    let max = counts.iter().copied().max().unwrap_or(1).max(1) as f32;
    let lut = crate::raster::Palette::Inferno.lut();
    let pixels: Vec<Color32> = counts
        .iter()
        .map(|&count| if count == 0 { Color32::BLACK } else { lut[(((count as f32).ln_1p() / max.ln_1p()) * 255.0) as usize] })
        .collect();
    ctx.load_texture(name, ColorImage::new([256, 256], pixels), TextureOptions::NEAREST)
}
