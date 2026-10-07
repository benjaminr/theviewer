//! Dock tabs for diagnosing unknown data: column profiling of records,
//! protocol analysis of message streams, byte statistics, strings and XOR.

use std::sync::mpsc::{self, Receiver};
use std::thread;

use eframe::egui::{self, Color32, ColorImage, Rect, RichText, Sense, Stroke, TextureHandle, TextureOptions, Ui, pos2, vec2};

use crate::app::ViewerApp;
use crate::bus::{Draft, Payload};
use crate::bus::topics::{FieldsGuessed, FrameSpan, FramesDefined, ProtocolIdentified, RecordWidthEstimated};
use crate::api::tools::columns::{MOST_RECORD_LEN, PROFILE_RECORDS, Profiled, profile_records};
use crate::columns::{self, ColumnKind, ColumnProfile, FieldGuess};
use crate::packets;
use crate::plugin::{Category, Finding};
use crate::api::tools::protocol::{FRAMING_CANDIDATES, PROTOCOL_LIMIT, ProtocolResult};
use crate::protocol::{self, Framing, FramingCandidate, Message, MessageField};
use crate::theme;

/// Messages listed in the protocol table.
const LISTED_MESSAGES: usize = 1000;
/// Messages outlined on the raster.
const PINNED_MESSAGES: usize = 5000;

impl ViewerApp {
    /// Select `len` bytes at `start` because the person clicked them in a
    /// tool (a record, a field, a message, a region), through
    /// `selection.set`, and bring them into view; a span of no bytes puts
    /// the cursor there instead.
    pub fn select_from_tool(&mut self, start: usize, len: usize) {
        let start = start.min(self.document.len());
        let len = len.min(self.document.len() - start);
        let done = if len == 0 {
            self.perform("cursor.set", serde_json::json!({ "offset": start }))
        } else {
            self.perform("selection.set", serde_json::json!({ "selection": { "range": [start, len] } }))
        };
        if done.is_ok() {
            self.reveal_cursor_centred();
            self.reveal_cursor_in_hex(true);
        }
    }
}

/// State for this module's tabs.
#[derive(Default)]
pub struct ToolsState {
    pub record_len: usize,
    pub columns: Option<(usize, usize, Vec<ColumnProfile>, Vec<FieldGuess>)>,
    /// How many records the column profile covers.
    pub columns_records: usize,

    protocol_pending: Option<Receiver<ProtocolView>>,
    pub protocol: Option<ProtocolView>,

    pub stats: crate::analysis_stats::StatsState,
}

impl ToolsState {
    /// Whether a protocol analysis is running.
    pub fn protocol_pending(&self) -> bool {
        self.protocol_pending.is_some()
    }

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
    /// The protocol the messages read as, such as DNS, when they do.
    pub messages_decode_as: Option<packets::Detection>,
}

/// Most messages a chosen framing splits a stream into.
const MAX_SPLIT_MESSAGES: usize = 100_000;
/// Header positions whose fields are worked out after a framing is chosen.
const FIELD_PREFIX: usize = 32;

impl ProtocolView {
    /// The `bytes` from `start` split with `framing` alone.
    pub fn with_framing(start: usize, bytes: Vec<u8>, framing: Framing) -> ProtocolView {
        let candidate = candidate_of(&bytes, framing);
        let mut view = ProtocolView::new(start, bytes, protocol::ProtocolReport::default(), vec![candidate]);
        view.choose(0);
        view
    }

    /// Re-split and re-analyse with framing candidate `index`.
    fn choose(&mut self, index: usize) {
        let Some(candidate) = self.candidates.get(index).cloned() else { return };
        let messages = protocol::split(&self.bytes, &candidate.framing, MAX_SPLIT_MESSAGES);
        let fields = protocol::analyse_fields(&self.bytes, &messages, FIELD_PREFIX);
        let lengths: Vec<usize> = messages.iter().map(|m| m.len).collect();
        self.report.length_min = lengths.iter().copied().min().unwrap_or(0);
        self.report.length_max = lengths.iter().copied().max().unwrap_or(0);
        self.report.length_mean = if lengths.is_empty() { 0.0 } else { lengths.iter().sum::<usize>() as f64 / lengths.len() as f64 };
        self.report.framing = Some(candidate);
        self.report.messages = messages;
        self.report.fields = fields;
        self.chosen = index;
        self.detect_message_protocol();
    }

    fn new(base: usize, bytes: Vec<u8>, report: protocol::ProtocolReport, candidates: Vec<FramingCandidate>) -> ProtocolView {
        let mut view = ProtocolView { base, bytes, report, candidates, chosen: 0, messages_decode_as: None };
        view.detect_message_protocol();
        view
    }

    /// Find out whether the messages are a protocol the packet viewer
    /// dissects.
    fn detect_message_protocol(&mut self) {
        let messages: Vec<&[u8]> = self.report.messages.iter().filter_map(|message| self.bytes.get(message.offset..message.offset + message.len)).collect();
        self.messages_decode_as = packets::detect_frame_protocol(&messages);
    }

    /// The bytes that were analysed; message offsets count from their start,
    /// which is document offset `base`.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
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

/// The record width published on the bus (by the period scan), if any.
fn estimated_record_width(app: &ViewerApp) -> Option<usize> {
    app.bus.latest::<RecordWidthEstimated>(&app.document_id()).map(|(_, estimate)| estimate.width)
}

pub fn show_columns(app: &mut ViewerApp, ui: &mut Ui) {
    if app.bench.tools.record_len == 0 {
        app.bench.tools.record_len = estimated_record_width(app).unwrap_or_else(|| app.shape.row_stride()).clamp(1, 65_536);
    }
    let origin = records_origin(app, app.bench.tools.record_len);
    let mut chosen_len = None;
    ui.horizontal(|ui| {
        ui.label("Record length");
        let length = ui.add(egui::DragValue::new(&mut app.bench.tools.record_len).range(1..=MOST_RECORD_LEN).suffix(" B"));
        // A drag profiles as it goes, and is the person's step once it ends.
        if length.drag_stopped() || (length.changed() && !length.dragged()) {
            chosen_len = Some(app.bench.tools.record_len);
        }
        if ui.button("Use row width").on_hover_text("The raster's bytes per row").clicked() {
            chosen_len = Some(app.shape.row_stride());
        }
        if let Some(best) = estimated_record_width(app)
            && ui.button(format!("Use detected {best} B")).clicked()
        {
            chosen_len = Some(best);
        }
        if let Some((_, _, profiles, _)) = &app.bench.tools.columns
            && !profiles.is_empty()
        {
            let records = app.bench.tools.columns_records;
            ui.label(RichText::new(format!("{records} records from {origin:#x}")).small().color(theme::TEXT_DIM))
                .on_hover_text("From the cursor's record (or the selection) to where the records stop looking alike");
        }
    });
    if let Some(record_len) = chosen_len {
        profile_columns(app, record_len);
    }
    let record_len = app.bench.tools.record_len.max(1);
    let origin = records_origin(app, record_len);
    let key = (origin, record_len);
    // The cursor moved to other records (or a drag is under way): profile
    // them, as the tool does by itself.
    if app.bench.tools.columns.as_ref().map(|c| (c.0, c.1)) != Some(key) {
        let bytes = app.document.read_range(origin, record_len * PROFILE_RECORDS);
        // Within a selection every record counts; otherwise stop where the table does.
        let selected = app.selection().map(|(_, len)| len);
        let profiled = profile_records(&bytes, record_len, selected, app.document.len());
        app.show_column_profile(origin, record_len, profiled);
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
            app.apply_template_from_tool(&source, origin);
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
        app.select_from_tool(start, len);
    }
}

/// Profile the records `record_len` bytes long from the cursor's record
/// (or the selection) because the person chose that length, through
/// `columns.profile`.
pub fn profile_columns(app: &mut ViewerApp, record_len: usize) {
    let record_len = record_len.clamp(1, MOST_RECORD_LEN);
    let origin = records_origin(app, record_len);
    let mut params = serde_json::json!({ "start": origin, "record_len": record_len });
    if let Some((_, len)) = app.selection() {
        params["len"] = len.into();
    }
    let _ = app.perform("columns.profile", params);
}

impl ViewerApp {
    /// Show a column profile of the records `record_len` bytes long from
    /// `start` in the Columns tool: what `columns.profile` does in the window.
    pub fn show_column_profile(&mut self, start: usize, record_len: usize, profiled: Profiled) {
        let tools = &mut self.bench.tools;
        tools.record_len = record_len;
        tools.columns_records = profiled.records;
        tools.columns = Some((start, record_len, profiled.profiles, profiled.fields));
        self.note_tool_result(crate::dock::DockTab::Columns);
    }
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// The stream the Protocol tool analyses: the selection, else the whole
/// file, up to [`PROTOCOL_LIMIT`].
fn protocol_span(app: &ViewerApp) -> (usize, usize) {
    let (start, len) = app.selection().unwrap_or((0, app.document.len()));
    (start, len.min(PROTOCOL_LIMIT))
}

/// Analyse the selection (else the whole file) as a message stream
/// because the person asked to, through `protocol.analyse`.
pub fn analyse_protocol(app: &mut ViewerApp) {
    let (start, len) = protocol_span(app);
    let _ = app.perform("protocol.analyse", serde_json::json!({ "start": start, "len": len }));
}

/// The analysis the app starts by itself, as the Protocol tool's: on
/// launch with the tool asked for, to refresh it after an edit, and for
/// the packet viewer waiting for messages.
pub fn start_protocol(app: &mut ViewerApp) {
    let (start, len) = protocol_span(app);
    analyse_protocol_from(app, start, len, PROTOCOL_PRODUCER);
}

/// Analyse `len` bytes from `start` as a message stream on a thread, as a
/// job of `producer`'s, and show what is found in the Protocol tool. What
/// `protocol.analyse` does in the window. Returns the job.
pub fn analyse_protocol_from(app: &mut ViewerApp, start: usize, len: usize, producer: &str) -> String {
    app.note_tool_result(crate::dock::DockTab::Protocol);
    let bytes = app.document.read_range(start, len.min(PROTOCOL_LIMIT));
    let (sender, receiver) = mpsc::channel();
    let about = (app.document_id(), app.document.version());
    let job = app.bus.start_job("protocol", "Protocol analysis", producer, Some(about.clone()));
    let id = job.id().to_string();
    let publisher = app.bus.publisher();
    thread::spawn(move || {
        if let Some(view) = run_protocol_analysis(start, bytes, &job, &publisher, about) {
            let _ = sender.send(view);
        }
    });
    app.bench.tools.protocol_pending = Some(receiver);
    id
}

/// Analyse `bytes` (from document offset `start`) as a message stream,
/// publish what is found about the document `about` names, and finish
/// `job` with it, unless the job was cancelled.
pub fn run_protocol_analysis(start: usize, bytes: Vec<u8>, job: &crate::bus::JobHandle, publisher: &crate::bus::Publisher, about: (String, u64)) -> Option<ProtocolView> {
    let candidates = protocol::detect_framing(&bytes, FRAMING_CANDIDATES);
    if job.is_cancelled() {
        job.finish_cancelled();
        return None;
    }
    let report = protocol::analyse(&bytes);
    let view = ProtocolView::new(start, bytes, report, candidates);
    if job.is_cancelled() {
        job.finish_cancelled();
        return None;
    }
    // What it found is on the bus before the job is said to be done,
    // so whoever waits for the job finds the frames there.
    for draft in framing_facts(&view) {
        publisher.publish(draft.about(about.0.clone(), about.1));
    }
    let result = serde_json::to_value(ProtocolResult::of(&view)).ok();
    job.finish_with(view.report.framing.is_some(), format!("{} messages", view.report.messages.len()), result);
    Some(view)
}

/// Whether a protocol analysis is running.
pub fn protocol_running(app: &ViewerApp) -> bool {
    app.bench.tools.protocol_pending()
}

/// Collect a finished protocol analysis, if one has arrived. Called every
/// frame, whether or not the Protocol tab is showing.
pub fn poll_protocol(app: &mut ViewerApp) {
    let Some(receiver) = &app.bench.tools.protocol_pending else { return };
    match receiver.try_recv() {
        Ok(view) => {
            app.bench.tools.protocol_pending = None;
            app.bench.tools.protocol = Some(view);
            pin_messages(app);
        }
        // Cancelled: the analysis ended without a result.
        Err(mpsc::TryRecvError::Disconnected) => app.bench.tools.protocol_pending = None,
        Err(mpsc::TryRecvError::Empty) => {}
    }
}

/// What publishes the protocol tool's framing, the fields it guessed and the
/// protocol its messages read as.
pub const PROTOCOL_PRODUCER: &str = "tool:protocol";

/// The messages the framing found (with the framing, so they can be split
/// again), the fields guessed in them and the protocol they read as, ready
/// to be said about the document.
pub(crate) fn framing_facts(view: &ProtocolView) -> Vec<Draft> {
    let base = view.base;
    let (span_start, span_len) = (base, view.bytes.len());
    let origin = view.report.framing.as_ref().map_or_else(|| "protocol analysis".to_string(), |candidate| candidate.framing.describe());
    let mut defined = FramesDefined::new(view.report.messages.iter().map(|message| (base + message.offset, message.len)), origin);
    if let Some(candidate) = &view.report.framing {
        defined = defined.with_framing(candidate.framing.clone());
    }
    let frames: Vec<FrameSpan> = defined.frames.clone();
    let draft = |payload| Draft::new(PROTOCOL_PRODUCER, payload).span(span_start, span_len);
    let guessed = FieldsGuessed { fields: view.report.fields.clone(), template: protocol::to_template(&view.report) };
    let identified = match view.messages_decode_as {
        Some(detection) => draft(Payload::ProtocolIdentified(ProtocolIdentified {
            protocol: detection.protocol.label().to_string(),
            how: format!("frame detection read {} of {} sampled messages in full", detection.matched, detection.sampled),
            frames,
        })),
        None => draft(Payload::ProtocolIdentified(ProtocolIdentified { protocol: String::new(), how: String::new(), frames: Vec::new() })).retraction(),
    };
    vec![draft(Payload::FramesDefined(defined)), draft(Payload::FieldsGuessed(guessed)), identified]
}

/// Publish the messages the framing found, the fields guessed and the
/// protocol they read as, about the document as it is now.
fn publish_framing(app: &mut ViewerApp) {
    let Some(view) = &app.bench.tools.protocol else { return };
    for draft in framing_facts(view) {
        let about = app.draft(draft.producer.clone(), draft.payload.clone());
        app.bus.publish(Draft { document: about.document, version: about.version, caused_by: about.caused_by, ..draft });
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

/// Choose the framing candidate `index` of the analysis shown because the
/// person picked it, through `protocol.choose_framing`.
fn choose_framing(app: &mut ViewerApp, index: usize) {
    let Some(view) = &app.bench.tools.protocol else { return };
    let Some(candidate) = view.candidates.get(index) else { return };
    let params = serde_json::json!({ "start": view.base, "len": view.bytes.len(), "framing": candidate.framing });
    let _ = app.perform("protocol.choose_framing", params);
}

/// Split the `bytes` from `start` with `framing` and show the messages in
/// the Protocol tool, re-splitting the analysis shown when it is of the
/// same bytes: what `protocol.choose_framing` does in the window.
pub fn show_protocol_framing(app: &mut ViewerApp, start: usize, bytes: Vec<u8>, framing: Framing) -> &ProtocolView {
    app.note_tool_result(crate::dock::DockTab::Protocol);
    match &mut app.bench.tools.protocol {
        Some(view) if view.base == start && view.bytes == bytes => {
            let index = match view.candidates.iter().position(|candidate| candidate.framing == framing) {
                Some(index) => index,
                None => {
                    view.candidates.push(candidate_of(&view.bytes, framing));
                    view.candidates.len() - 1
                }
            };
            view.choose(index);
        }
        _ => app.bench.tools.protocol = Some(ProtocolView::with_framing(start, bytes, framing)),
    }
    pin_messages(app);
    publish_framing(app);
    app.bench.tools.protocol.as_ref().expect("shown above")
}

/// `framing` as a candidate for `bytes`, with how many messages it makes
/// and how much of the bytes they cover.
fn candidate_of(bytes: &[u8], framing: Framing) -> FramingCandidate {
    let messages = protocol::split(bytes, &framing, MAX_SPLIT_MESSAGES);
    let covered: usize = messages.iter().map(|message| message.len).sum();
    let coverage = if bytes.is_empty() { 0.0 } else { covered as f64 / bytes.len() as f64 };
    FramingCandidate { framing, score: coverage, messages: messages.len(), coverage }
}

pub fn show_protocol(app: &mut ViewerApp, ui: &mut Ui) {
    poll_protocol(app);
    ui.horizontal(|ui| {
        let scope = if app.selection().is_some() { "the selection" } else { "the whole file" };
        if ui.button(format!("Analyse {scope} as a message stream")).clicked() {
            analyse_protocol(app);
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
    let messages_decode_as = view.messages_decode_as;
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
    if let Some(detection) = messages_decode_as.filter(|_| app.preferences.detect_frame_protocols) {
        ui.label(
            RichText::new(format!(
                "The messages are {} ({} of {} sampled read in full); the packet viewer decodes them as it.",
                detection.protocol.label(),
                detection.matched,
                detection.sampled
            ))
            .color(theme::ACCENT),
        );
    }
    if ui.button("Open in packet viewer").on_hover_text("List these messages as packets: dissect, filter, edit and export them").clicked() {
        crate::panel_packets::open_protocol_messages(app);
    }
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
                    app.apply_template_from_tool(&source, base + report.messages[0].offset);
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
        app.select_from_tool(start, len.max(1));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_the_framing_found_are_named_by_the_protocol_they_read_as() {
        let mut bytes = Vec::new();
        let mut messages = Vec::new();
        for transaction in 0..5u8 {
            messages.push(Message { offset: bytes.len(), len: 12 });
            bytes.extend_from_slice(&[0, transaction, 0, 0, 0, 6, 1, 4, 0, 0, 0, 2]);
        }
        let report = protocol::ProtocolReport { messages, ..Default::default() };
        let view = ProtocolView::new(0, bytes, report, Vec::new());
        assert_eq!(view.messages_decode_as.map(|detection| detection.protocol), Some(packets::FrameProtocol::ModbusTcp));
        let unknown = ProtocolView::new(0, vec![0xA5; 40], protocol::ProtocolReport { messages: vec![Message { offset: 0, len: 20 }, Message { offset: 20, len: 20 }], ..Default::default() }, Vec::new());
        assert_eq!(unknown.messages_decode_as, None);
    }

    use serde_json::json;

    use crate::actions::take_performed;
    use crate::app::Launch;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        take_performed();
        app
    }

    /// Records of 4 bytes: a constant, a counter, a letter and a varying byte.
    fn records() -> Vec<u8> {
        (0..64u8).flat_map(|index| [0xA5, index, b'x', index.wrapping_mul(37)]).collect()
    }

    /// Messages of 12 bytes, each starting with the sync word A5 5A and a counter.
    fn messages() -> Vec<u8> {
        (0..40u8).flat_map(|index| [0xA5, 0x5A, index, 8, 1, 2, 3, 4, index.wrapping_mul(13), 6, 7, 8]).collect()
    }

    /// Collect the protocol analysis once it has finished.
    fn wait_for_protocol(app: &mut ViewerApp) {
        let begun = std::time::Instant::now();
        while protocol_running(app) && begun.elapsed() < std::time::Duration::from_secs(30) {
            poll_protocol(app);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        app.run_bus();
    }

    #[test]
    fn choosing_a_record_length_profiles_the_columns_through_the_api() {
        let mut app = app_with(&records());
        profile_columns(&mut app, 4);
        assert_eq!(take_performed(), [("columns.profile".to_string(), json!({"start": 0, "record_len": 4}))]);
        let (start, record_len, profiles, fields) = app.bench.tools.columns.clone().expect("the Columns tool shows the profile");
        assert_eq!((start, record_len, app.bench.tools.record_len, app.bench.tools.columns_records), (0, 4, 4, 64));
        assert_eq!(profiles[1].kind, ColumnKind::Counter);
        assert!(!fields.is_empty());
        app.restore_selection(8, 40);
        profile_columns(&mut app, 4);
        assert_eq!(take_performed(), [("columns.profile".to_string(), json!({"start": 8, "record_len": 4, "len": 40}))], "the selection's records, every one counting");
        assert_eq!(app.bench.tools.columns_records, 10);
    }

    #[test]
    fn analysing_a_message_stream_is_a_protocol_job_of_the_person_s_that_fills_the_tool() {
        let mut app = app_with(&messages());
        analyse_protocol(&mut app);
        assert_eq!(take_performed(), [("protocol.analyse".to_string(), json!({"start": 0, "len": 480}))]);
        wait_for_protocol(&mut app);
        let view = app.bench.tools.protocol.as_ref().expect("the Protocol tool shows the analysis");
        assert_eq!(view.report.messages.len(), 40);
        assert!(app.bench.pinned.iter().any(|pinned| pinned.id == "message"), "the messages are outlined");
        let job = app.bus.jobs().list().into_iter().find(|job| job.title == "Protocol analysis").expect("a job");
        assert_eq!(job.producer, "panel");
        assert_eq!(job.result.as_ref().map(|result| result["messages"].as_array().unwrap().len()), Some(40), "the job's result carries the messages");
    }

    #[test]
    fn the_analysis_the_app_starts_by_itself_is_the_tool_s_own() {
        let mut app = app_with(&messages());
        start_protocol(&mut app);
        assert!(take_performed().is_empty());
        wait_for_protocol(&mut app);
        let job = app.bus.jobs().list().into_iter().find(|job| job.title == "Protocol analysis").expect("a job");
        assert_eq!(job.producer, PROTOCOL_PRODUCER);
    }

    #[test]
    fn choosing_another_framing_splits_the_messages_again_through_the_api() {
        let mut app = app_with(&messages());
        start_protocol(&mut app);
        wait_for_protocol(&mut app);
        let fixed = Framing::FixedSize { len: 24 };
        let chosen = show_protocol_framing(&mut app, 0, messages(), fixed.clone());
        assert_eq!(chosen.report.messages.len(), 20);
        let index = chosen.chosen;
        assert!(app.bench.tools.protocol.as_ref().unwrap().candidates.len() > 1, "the framing joins the analysis's candidates");
        choose_framing(&mut app, 0);
        let performed = take_performed();
        assert_eq!(performed.len(), 1);
        assert_eq!(performed[0].0, "protocol.choose_framing");
        assert_eq!((performed[0].1["start"].clone(), performed[0].1["len"].clone()), (json!(0), json!(480)));
        assert_ne!(performed[0].1["framing"], serde_json::to_value(&fixed).unwrap(), "the first candidate, not the one chosen before (#{index})");
        assert_eq!(app.bench.tools.protocol.as_ref().unwrap().chosen, 0);
        assert_eq!(app.bench.tools.protocol.as_ref().unwrap().report.messages.len(), 40);
    }
}
