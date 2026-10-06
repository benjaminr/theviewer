//! Dock panel: reference notes on the formats at the cursor.
//!
//! The formats enclosing the cursor are listed as a stack, outermost first:
//! the findings and parsed structure covering it, then, inside a packet of a
//! capture, the packet's dissected layers (a layer encloses everything after
//! its header). The chosen format's notes from [`crate::reference`] are shown
//! with its specifications, a header diagram and a table of this instance's
//! fields with what each one means. Pointing at a field outlines its bytes in
//! the main view; clicking selects them.
//!
//! RFC text is only fetched when the user asks for it, on a background
//! thread, and kept under `~/.cache/theviewer/rfc` for next time.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Align2, Color32, FontId, Rect, RichText, Sense, Stroke, StrokeKind, Ui, pos2, vec2};

use crate::app::ViewerApp;
use crate::dock::DockTab;
use crate::packets::{self, PacketSet};
use crate::panel_packets::{self, PacketLayers};
use crate::plugin::{Category, Field, Finding};
use crate::reference::{self, FormatReference, Library};
use crate::theme;

/// How often to look for fetched RFC text.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Largest RFC text downloaded.
const RFC_DOWNLOAD_LIMIT: usize = 4 * 1024 * 1024;
const RFC_TEXT_HEIGHT: f32 = 320.0;
/// Bytes in one row of the header diagram: 32 bits, as RFCs draw them.
const DIAGRAM_BYTES_PER_ROW: usize = 4;
/// Most rows drawn in the header diagram.
const DIAGRAM_MAX_ROWS: usize = 16;
const DIAGRAM_RULER_HEIGHT: f32 = 24.0;
const DIAGRAM_ROW_HEIGHT: f32 = 28.0;
const DIAGRAM_OFFSET_WIDTH: f32 = 44.0;
const DIAGRAM_MIN_WIDTH: f32 = 260.0;
const DIAGRAM_MAX_WIDTH: f32 = 760.0;
/// Box fills in the header diagram, muted so the text stays readable.
const DIAGRAM_TINTS: [Color32; 6] = [
    Color32::from_rgb(40, 66, 74),
    Color32::from_rgb(56, 54, 82),
    Color32::from_rgb(70, 60, 42),
    Color32::from_rgb(44, 70, 54),
    Color32::from_rgb(72, 50, 62),
    Color32::from_rgb(50, 60, 80),
];
/// Most rows listed in the field table, and how deep nested fields go.
const TABLE_MAX_ROWS: usize = 400;
const TABLE_MAX_DEPTH: usize = 6;
/// Longest field value shown in the table before it is shortened.
const TABLE_VALUE_CHARS: usize = 48;
const TABLE_MEANING_WIDTH: f32 = 360.0;

// ---------------------------------------------------------------------------
// The stack of formats at the cursor
// ---------------------------------------------------------------------------

/// One format enclosing the cursor.
#[derive(Clone, Debug, PartialEq)]
pub struct StackEntry {
    /// Short name for the breadcrumb, such as "UDP".
    pub label: String,
    /// The name the app knows the format by: a finding id or a layer name.
    pub key: String,
    /// The reference entry with notes on this format, if there is one.
    pub reference_id: Option<String>,
    /// The instance's bytes in the document: the finding, or the layer's header.
    pub start: usize,
    pub len: usize,
    /// The instance's fields, with document offsets.
    pub fields: Vec<Field>,
}

impl StackEntry {
    /// The notes on this format in the embedded library.
    pub fn reference(&self) -> Option<&'static FormatReference> {
        self.reference_id.as_deref().and_then(|id| reference::library().by_id(id))
    }

    fn is_same_instance(&self, other: &StackEntry) -> bool {
        self.start == other.start && (self.key == other.key || self.reference_id.is_some() && self.reference_id == other.reference_id)
    }
}

/// Whether a finding names a format worth explaining, rather than a pattern
/// such as a counter or a run of text.
fn is_format(finding: &Finding, library: &Library) -> bool {
    if finding.weak() {
        return false;
    }
    let format_category = matches!(
        finding.category,
        Category::Signature
            | Category::Executable
            | Category::Image
            | Category::Archive
            | Category::Document
            | Category::Filesystem
            | Category::Compressed
            | Category::Protocol
    );
    format_category || !finding.fields.is_empty() || library.lookup_finding(&finding.id, &finding.title).is_some()
}

/// The breadcrumb name: the notes' short name when they have one, else the
/// name the app uses.
fn label_for(fallback: &str, notes: Option<&FormatReference>) -> String {
    match notes {
        Some(notes) if notes.short_name() != notes.name => notes.short_name().to_string(),
        _ => fallback.to_string(),
    }
}

/// A field and its children moved by `base` bytes.
fn shifted(field: &Field, base: usize) -> Field {
    Field {
        name: field.name.clone(),
        offset: field.offset + base,
        len: field.len,
        value: field.value.clone(),
        children: field.children.iter().map(|child| shifted(child, base)).collect(),
    }
}

/// Every known format enclosing `position`, outermost first: the findings
/// covering it and the layers of `packet` that start at or before it. Two
/// findings for the same instance (a signature and a parser's structure,
/// say) are kept once, with the more detailed fields.
pub fn build_stack(library: &Library, findings: &[Finding], packet: Option<&PacketLayers>, position: usize) -> Vec<StackEntry> {
    // Each entry with the length of what it encloses, for ordering.
    let mut scoped: Vec<(usize, StackEntry)> = Vec::new();
    for finding in findings.iter().filter(|finding| finding.start <= position && position < finding.end() && is_format(finding, library)) {
        let notes = library.lookup_finding(&finding.id, &finding.title);
        let name = if finding.title.is_empty() { finding.id.as_str() } else { finding.title.as_str() };
        let entry = StackEntry {
            label: label_for(name, notes),
            key: finding.id.clone(),
            reference_id: notes.map(|notes| notes.id.clone()),
            start: finding.start,
            len: finding.len,
            fields: finding.fields.clone(),
        };
        scoped.push((finding.len, entry));
    }
    if let Some(packet) = packet {
        let packet_end = packet.offset + packet.len;
        for layer in packet.layers.iter().filter(|layer| packet.offset + layer.offset <= position) {
            let start = packet.offset + layer.offset;
            let notes = library.lookup(&layer.name);
            let entry = StackEntry {
                label: label_for(&layer.name, notes),
                key: layer.name.clone(),
                reference_id: notes.map(|notes| notes.id.clone()),
                start,
                len: layer.len,
                fields: layer.fields.iter().map(|field| shifted(field, packet.offset)).collect(),
            };
            scoped.push((packet_end.saturating_sub(start), entry));
        }
    }
    // Widest first; the sort is stable, so equals keep their order.
    scoped.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.start.cmp(&b.1.start)));
    let mut stack: Vec<StackEntry> = Vec::new();
    for (_, entry) in scoped {
        match stack.iter_mut().find(|kept| kept.is_same_instance(&entry)) {
            Some(kept) if entry.fields.len() > kept.fields.len() => *kept = entry,
            Some(_) => {}
            None => stack.push(entry),
        }
    }
    stack
}

/// The entry to show when nothing was asked for: the innermost with notes,
/// else the innermost.
pub fn default_choice(stack: &[StackEntry]) -> Option<usize> {
    stack.iter().rposition(|entry| entry.reference_id.is_some()).or(stack.len().checked_sub(1))
}

/// The innermost entry known by `key`: its finding id or layer name, or any
/// name of the same reference entry.
fn position_of(stack: &[StackEntry], key: &str) -> Option<usize> {
    let wanted_id = reference::lookup(key).map(|notes| notes.id.as_str());
    stack
        .iter()
        .rposition(|entry| entry.key.eq_ignore_ascii_case(key) || wanted_id.is_some() && entry.reference_id.as_deref() == wanted_id)
}

/// Where the stack is built for: the selection's start, or the cursor (a
/// selection made by clicking a field leaves the cursor just after it).
fn focus_position(app: &ViewerApp) -> usize {
    app.selection().map_or(app.cursor, |(start, _)| start)
}

/// The findings covering `position`, with the parsed structure at the
/// cursor when it covers it too.
fn findings_at(app: &ViewerApp, position: usize) -> Vec<Finding> {
    let mut findings: Vec<Finding> = app.patterns_in(position, position + 1).cloned().collect();
    if let Some(structure) = &app.cursor_structure
        && structure.start <= position
        && position < structure.end()
    {
        findings.push(structure.clone());
    }
    findings
}

/// A capture's packets, read once per capture and document version for when
/// the packet viewer is not showing that capture.
struct CaptureCache {
    start: usize,
    len: usize,
    version: u64,
    set: Option<PacketSet>,
}

/// The dissected packet holding `position`: from the packet viewer when it
/// shows that packet, else from a capture finding covering it.
fn packet_at(app: &mut ViewerApp, position: usize, findings: &[Finding], cache: &mut Option<CaptureCache>) -> Option<PacketLayers> {
    if let Some(layers) = panel_packets::layers_at(app, position) {
        return Some(layers);
    }
    let capture = findings.iter().find(|finding| finding.id == "pcap" || finding.id == "pcapng")?;
    let version = app.document.version();
    let current = cache.as_ref().is_some_and(|cached| (cached.start, cached.len, cached.version) == (capture.start, capture.len, version));
    if !current {
        let bytes = app.document.read_range(capture.start, capture.len.min(panel_packets::CAPTURE_READ_LIMIT));
        let set = packets::sources::from_capture(&bytes, capture.start).ok();
        *cache = Some(CaptureCache { start: capture.start, len: capture.len, version, set });
    }
    let set = cache.as_ref()?.set.as_ref()?;
    let packet = set.packets.iter().find(|packet| position >= packet.offset && position < packet.end())?.clone();
    let bytes = app.document.read_range(packet.offset, packet.len.min(panel_packets::PACKET_READ_LIMIT));
    Some(PacketLayers { offset: packet.offset, len: packet.len, layers: packets::dissect(&bytes, packet.link).layers })
}

/// The stack at the cursor, worked out afresh (for the assistant).
pub fn stack_at_cursor(app: &mut ViewerApp) -> Vec<StackEntry> {
    let position = focus_position(app);
    let findings = findings_at(app, position);
    let packet = packet_at(app, position, &findings, &mut None);
    build_stack(reference::library(), &findings, packet.as_ref(), position)
}

/// Most reference entries sent to the assistant with a question, and most
/// characters of them in all.
const ASSISTANT_NOTES: usize = 3;
const ASSISTANT_NOTES_CHARS: usize = 6 * 1024;

/// The notes on the formats in `stack` as plain text for the assistant:
/// innermost first, each format once, at most [`ASSISTANT_NOTES`] of them
/// and [`ASSISTANT_NOTES_CHARS`] characters in all (the last is cut short).
pub fn notes_for_assistant(stack: &[StackEntry]) -> Vec<String> {
    let mut seen = Vec::new();
    let mut notes = Vec::new();
    let mut room = ASSISTANT_NOTES_CHARS;
    for entry in stack.iter().rev() {
        let Some(reference) = entry.reference() else { continue };
        if seen.contains(&reference.id) || notes.len() == ASSISTANT_NOTES || room == 0 {
            continue;
        }
        seen.push(reference.id.clone());
        let mut text = reference.to_plain_text();
        if text.len() > room {
            let mut cut = room;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
            text.push_str("\n[notes cut short]");
            room = 0;
        } else {
            room -= text.len();
        }
        notes.push(text);
    }
    notes
}

/// Open the Reference tab on the format known by `key` (a finding id or
/// layer name), once the cursor is inside it.
pub fn open_reference_for(app: &mut ViewerApp, key: &str) {
    app.bench.panels.reference.follow(key);
    app.dock.toggle(DockTab::Reference);
}

// ---------------------------------------------------------------------------
// The header diagram's layout
// ---------------------------------------------------------------------------

/// Fields drawn as one box: those with exactly the same bytes, such as two
/// bit fields sharing a byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagramGroup {
    /// Bytes from the instance's start.
    pub offset: usize,
    pub len: usize,
    /// Indices of the fields in the group.
    pub fields: Vec<usize>,
}

/// One box of the diagram: a group's bytes within one row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagramBox {
    pub group: usize,
    pub row: usize,
    /// First byte of the row the box covers, and how many bytes.
    pub column: usize,
    pub width: usize,
    /// The group started on an earlier row.
    pub continued: bool,
    /// The group goes on past this row.
    pub continues: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiagramLayout {
    pub groups: Vec<DiagramGroup>,
    pub boxes: Vec<DiagramBox>,
    pub rows: usize,
    /// Bytes of the instance past the last row drawn.
    pub hidden_bytes: usize,
}

/// Lay fields, given as `(offset, len)` from the instance's start, out in
/// rows of `per_row` bytes, at most `max_rows` of them. A field that wraps
/// is split into one box per row. A field overlapping bytes already taken
/// is left out of the diagram (the field table still lists it).
pub fn layout_diagram(spans: &[(usize, usize)], instance_len: usize, per_row: usize, max_rows: usize) -> DiagramLayout {
    let shown = instance_len.min(per_row * max_rows);
    let mut order: Vec<usize> = (0..spans.len()).collect();
    order.sort_by_key(|&index| spans[index].0);
    let mut groups: Vec<DiagramGroup> = Vec::new();
    for index in order {
        let (offset, len) = spans[index];
        if len == 0 || offset >= shown {
            continue;
        }
        if let Some(group) = groups.iter_mut().find(|group| (group.offset, group.len) == (offset, len)) {
            group.fields.push(index);
            continue;
        }
        let overlaps = groups.iter().any(|group| offset < group.offset + group.len && group.offset < offset + len);
        if !overlaps {
            groups.push(DiagramGroup { offset, len, fields: vec![index] });
        }
    }
    let mut boxes = Vec::new();
    for (index, group) in groups.iter().enumerate() {
        let group_end = group.offset + group.len;
        let end = group_end.min(shown);
        let mut at = group.offset;
        while at < end {
            let row = at / per_row;
            let row_end = ((row + 1) * per_row).min(end);
            boxes.push(DiagramBox { group: index, row, column: at % per_row, width: row_end - at, continued: at > group.offset, continues: row_end < group_end });
            at = row_end;
        }
    }
    DiagramLayout { groups, boxes, rows: shown.div_ceil(per_row), hidden_bytes: instance_len - shown }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// What the stack was built from, so it is rebuilt only when that changes.
#[derive(Clone, Debug, PartialEq)]
struct StackKey {
    position: usize,
    version: u64,
    findings: Vec<(String, usize, usize)>,
    packets: (u64, u64),
}

/// RFC text asked for by the user.
struct RfcView {
    reference_id: String,
    number: u32,
    section: Option<String>,
    text: RfcText,
}

enum RfcText {
    Loading(Receiver<Result<String, String>>),
    /// The section (or the whole RFC), with a note when the section was
    /// not found.
    Ready { shown: String, note: Option<String> },
    Failed(String),
}

/// Everything the Reference panel keeps between frames.
#[derive(Default)]
pub struct ReferenceState {
    stack: Vec<StackEntry>,
    stack_key: Option<StackKey>,
    /// The stack entry shown.
    chosen: Option<usize>,
    /// A format asked for by another panel or a click, by key; chosen when
    /// the stack next holds it.
    wanted: Option<String>,
    /// A reference entry opened from "Carries", shown without an instance.
    browsing: Option<String>,
    rfc: Option<RfcView>,
    capture: Option<CaptureCache>,
}

impl ReferenceState {
    /// Show the format known by `key` as soon as the cursor is inside it.
    pub fn follow(&mut self, key: &str) {
        self.wanted = Some(key.to_string());
        self.browsing = None;
        self.stack_key = None;
    }

    /// The formats enclosing the cursor, outermost first.
    pub fn stack(&self) -> &[StackEntry] {
        &self.stack
    }

    /// The entry being shown, unless a carried format is being browsed.
    pub fn chosen_entry(&self) -> Option<&StackEntry> {
        if self.browsing.is_some() {
            return None;
        }
        self.chosen.and_then(|index| self.stack.get(index))
    }
}

/// Rebuild the stack when the cursor, the document, the findings or the
/// packet viewer's dissection changed.
fn refresh_stack(state: &mut ReferenceState, app: &mut ViewerApp) {
    let position = focus_position(app);
    let findings = findings_at(app, position);
    let packets_state = &app.bench.panels.packets;
    let key = StackKey {
        position,
        version: app.document.version(),
        findings: findings.iter().map(|finding| (finding.id.clone(), finding.start, finding.len)).collect(),
        packets: (packets_state.rows_generation, packets_state.raw_generation),
    };
    if state.stack_key.as_ref() == Some(&key) {
        return;
    }
    let packet = packet_at(app, position, &findings, &mut state.capture);
    state.stack = build_stack(reference::library(), &findings, packet.as_ref(), position);
    state.stack_key = Some(key);
    let wanted = state.wanted.as_deref().and_then(|key| position_of(&state.stack, key));
    if wanted.is_some() {
        state.wanted = None;
    }
    state.chosen = wanted.or_else(|| default_choice(&state.stack));
}

fn request_rfc(state: &mut ReferenceState, reference_id: &str, number: u32, section: Option<String>) {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let cache = reference::rfc_cache_dir();
        let result = reference::load_rfc_text(cache.as_deref(), number, |url| {
            let bytes = crate::sources::fetch_url(url, RFC_DOWNLOAD_LIMIT)?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        });
        let _ = sender.send(result);
    });
    state.rfc = Some(RfcView { reference_id: reference_id.to_string(), number, section, text: RfcText::Loading(receiver) });
}

fn poll_rfc(state: &mut ReferenceState, ctx: &egui::Context) {
    let Some(view) = &mut state.rfc else { return };
    let RfcText::Loading(receiver) = &view.text else { return };
    view.text = match receiver.try_recv() {
        Ok(Ok(text)) => match view.section.as_deref() {
            None => RfcText::Ready { shown: text, note: None },
            Some(section) => match reference::rfc_section(&text, section) {
                Some(shown) => RfcText::Ready { shown, note: None },
                None => RfcText::Ready { shown: text, note: Some(format!("§{section} was not found, so the whole RFC is shown.")) },
            },
        },
        Ok(Err(error)) => RfcText::Failed(error),
        Err(TryRecvError::Empty) => {
            ctx.request_repaint_after(POLL_INTERVAL);
            return;
        }
        Err(TryRecvError::Disconnected) => RfcText::Failed("The download stopped unexpectedly.".to_string()),
    };
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

/// What the user asked for this frame, carried out once drawing is done.
enum Action {
    Choose(usize),
    Browse(String),
    StopBrowsing,
    SelectBytes { start: usize, len: usize, name: String },
    FetchRfc { reference_id: String, number: u32, section: Option<String> },
    HideRfc,
}

/// Draw the Reference panel.
pub fn show_reference(state: &mut ReferenceState, app: &mut ViewerApp, ui: &mut Ui) {
    poll_rfc(state, ui.ctx());
    refresh_stack(state, app);
    let mut actions = Vec::new();
    egui::ScrollArea::vertical()
        .id_salt("reference-panel")
        .auto_shrink([false, false])
        .show(ui, |ui| show_body(state, app, ui, &mut actions));
    for action in actions {
        act(state, app, action);
    }
}

fn act(state: &mut ReferenceState, app: &mut ViewerApp, action: Action) {
    match action {
        Action::Choose(index) => {
            state.chosen = Some(index);
            state.browsing = None;
            state.wanted = None;
        }
        Action::Browse(id) => state.browsing = Some(id),
        Action::StopBrowsing => state.browsing = None,
        Action::SelectBytes { start, len, name } => {
            // Stay on this format while the cursor moves into the field.
            state.wanted = state.chosen_entry().map(|entry| entry.key.clone());
            let finding = Finding::new("field", "reference", Category::Structure, start, len.max(1)).title(name);
            app.select_pattern(&finding);
        }
        Action::FetchRfc { reference_id, number, section } => request_rfc(state, &reference_id, number, section),
        Action::HideRfc => state.rfc = None,
    }
}

fn show_body(state: &ReferenceState, app: &mut ViewerApp, ui: &mut Ui, actions: &mut Vec<Action>) {
    show_breadcrumb(state, app, ui, actions);
    ui.separator();
    if let Some(notes) = state.browsing.as_deref().and_then(|id| reference::library().by_id(id)) {
        if ui.small_button("← Back to the cursor").clicked() {
            actions.push(Action::StopBrowsing);
        }
        show_notes(state, ui, notes, actions);
        return;
    }
    let Some(entry) = state.chosen_entry() else {
        ui.label(
            RichText::new(
                "Nothing known encloses the cursor. Move it onto a structure, a compressed stream or a packet of a capture to read how that format is organised, what each field means and where it is specified.",
            )
            .color(theme::TEXT_DIM),
        );
        return;
    };
    let notes = entry.reference();
    match notes {
        Some(notes) => show_notes(state, ui, notes, actions),
        None => {
            ui.label(RichText::new(&entry.label).heading());
            ui.label(RichText::new(format!("No notes on {} yet; its fields are listed below as the parser reads them.", entry.label)).color(theme::TEXT_DIM));
        }
    }
    if entry.fields.is_empty() {
        return;
    }
    let position = focus_position(app);
    ui.add_space(6.0);
    egui::CollapsingHeader::new(RichText::new("Layout").strong()).id_salt("reference-layout").default_open(true).show(ui, |ui| {
        show_diagram(app, ui, entry, notes, position, actions);
    });
    egui::CollapsingHeader::new(RichText::new("Fields").strong()).id_salt("reference-fields").default_open(true).show(ui, |ui| {
        show_field_table(app, ui, entry, notes, position, actions);
    });
}

/// The stack as a clickable path, outermost first.
fn show_breadcrumb(state: &ReferenceState, app: &mut ViewerApp, ui: &mut Ui, actions: &mut Vec<Action>) {
    if state.stack.is_empty() {
        return;
    }
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        for (index, entry) in state.stack.iter().enumerate() {
            if index > 0 {
                ui.label(RichText::new("›").color(theme::TEXT_DIM));
            }
            let text = if entry.reference_id.is_some() { RichText::new(&entry.label) } else { RichText::new(&entry.label).color(theme::TEXT_DIM) };
            let selected = state.browsing.is_none() && state.chosen == Some(index);
            let notes = if entry.reference_id.is_some() { "" } else { " · no notes yet" };
            let response = ui.selectable_label(selected, text).on_hover_text(format!("{} bytes at {:#x}{notes}", entry.len, entry.start));
            if response.hovered() {
                app.point_at_bytes(entry.start, entry.len);
            }
            if response.clicked() {
                actions.push(Action::Choose(index));
            }
        }
    });
}

/// Name, summary, organisation, carried formats and specifications.
fn show_notes(state: &ReferenceState, ui: &mut Ui, notes: &FormatReference, actions: &mut Vec<Action>) {
    ui.label(RichText::new(&notes.name).heading());
    ui.label(RichText::new(&notes.summary).color(theme::TEXT_DIM));
    ui.add_space(4.0);
    for paragraph in notes.organisation.trim().split("\n\n") {
        ui.label(paragraph.trim());
        ui.add_space(2.0);
    }
    if !notes.carries.is_empty() {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Carries:").color(theme::TEXT_DIM));
            for id in &notes.carries {
                let carried = reference::library().by_id(id);
                let name = carried.map_or(id.as_str(), |carried| carried.short_name());
                let hover = carried.map_or(id.as_str(), |carried| carried.name.as_str());
                if ui.link(name).on_hover_text(hover).clicked() {
                    actions.push(Action::Browse(id.clone()));
                }
            }
        });
    }
    if !notes.specs.is_empty() {
        ui.add_space(4.0);
        ui.label(RichText::new("Specifications").strong());
        for spec in &notes.specs {
            ui.horizontal_wrapped(|ui| {
                let section = spec.section.as_deref().map(|section| format!(" §{section}")).unwrap_or_default();
                let url = match spec.rfc {
                    Some(number) if spec.section.is_some() => reference::rfc_html_url(number, spec.section.as_deref()),
                    _ => spec.url.clone(),
                };
                ui.hyperlink_to(format!("{}{section}", spec.document), url);
                ui.label(RichText::new(&spec.title).color(theme::TEXT_DIM));
                if let Some(number) = spec.rfc {
                    let label = spec.section.as_deref().map_or("Show RFC".to_string(), |section| format!("Show §{section}"));
                    let hint = format!("Fetch the text of RFC {number} from the RFC Editor; it is then kept in ~/.cache/theviewer/rfc");
                    if ui.small_button(label).on_hover_text(hint).clicked() {
                        actions.push(Action::FetchRfc { reference_id: notes.id.clone(), number, section: spec.section.clone() });
                    }
                }
            });
        }
    }
    show_rfc_text(state, ui, notes, actions);
}

fn show_rfc_text(state: &ReferenceState, ui: &mut Ui, notes: &FormatReference, actions: &mut Vec<Action>) {
    let Some(view) = state.rfc.as_ref().filter(|view| view.reference_id == notes.id) else { return };
    let title = match &view.section {
        Some(section) => format!("RFC {} §{section}", view.number),
        None => format!("RFC {}", view.number),
    };
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).strong());
        if ui.small_button("Hide").clicked() {
            actions.push(Action::HideRfc);
        }
    });
    match &view.text {
        RfcText::Loading(_) => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new(format!("Fetching RFC {}…", view.number)).color(theme::TEXT_DIM));
            });
        }
        RfcText::Failed(error) => {
            ui.label(RichText::new(format!("RFC {} could not be fetched. {error}", view.number)).color(theme::DANGER));
        }
        RfcText::Ready { shown, note } => {
            if let Some(note) = note {
                ui.label(RichText::new(note).small().color(theme::TEXT_DIM));
            }
            egui::Frame::new().fill(theme::SURFACE).corner_radius(4).inner_margin(6).show(ui, |ui| {
                egui::ScrollArea::both().id_salt("rfc-text").max_height(RFC_TEXT_HEIGHT).show(ui, |ui| {
                    ui.add(egui::Label::new(RichText::new(shown).monospace().size(11.0)).extend());
                });
            });
        }
    }
}

/// A field's meaning from the notes, if they have one.
fn meaning_of<'a>(notes: Option<&'a FormatReference>, field: &Field) -> Option<&'a str> {
    notes.and_then(|notes| notes.field(&field.name)).map(|note| note.meaning.as_str())
}

/// Whether `position` lies in `field` (a zero-length field counts its offset).
fn holds(field: &Field, position: usize) -> bool {
    position >= field.offset && position < field.end().max(field.offset + 1)
}

/// Fields and their children in display order, with their depth.
fn flatten<'a>(fields: &'a [Field], depth: usize, out: &mut Vec<(usize, &'a Field)>) {
    for field in fields {
        if out.len() >= TABLE_MAX_ROWS {
            return;
        }
        out.push((depth, field));
        if depth + 1 < TABLE_MAX_DEPTH {
            flatten(&field.children, depth + 1, out);
        }
    }
}

fn count_fields(fields: &[Field]) -> usize {
    fields.iter().map(|field| 1 + count_fields(&field.children)).sum()
}

fn shortened(text: &str, max_chars: usize) -> String {
    match text.char_indices().nth(max_chars) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_string(),
    }
}

/// The instance's fields with offset, length, value and meaning. Pointing
/// at a row outlines its bytes; clicking selects them.
fn show_field_table(app: &mut ViewerApp, ui: &mut Ui, entry: &StackEntry, notes: Option<&FormatReference>, position: usize, actions: &mut Vec<Action>) {
    let mut rows = Vec::new();
    flatten(&entry.fields, 0, &mut rows);
    let header = |ui: &mut Ui, text: &str| {
        ui.label(RichText::new(text).small().color(theme::TEXT_DIM));
    };
    egui::Grid::new("reference-field-table").num_columns(5).striped(true).spacing(vec2(12.0, 3.0)).show(ui, |ui| {
        for title in ["Field", "Offset", "Length", "Value", "Meaning"] {
            header(ui, title);
        }
        ui.end_row();
        for &(depth, field) in &rows {
            let colour = if holds(field, position) { theme::CURSOR } else { theme::TEXT };
            let relative = field.offset.saturating_sub(entry.start);
            let explanation = notes.and_then(|notes| notes.explain_field(&field.name));
            let mut cells = Vec::new();
            cells.push(
                ui.horizontal(|ui| {
                    ui.add_space(depth as f32 * 12.0);
                    let name = ui.add(egui::Label::new(RichText::new(&field.name).color(colour)).selectable(false).sense(Sense::click()));
                    match &explanation {
                        Some(explanation) => name.on_hover_text(explanation.as_str()),
                        None => name,
                    }
                })
                .inner,
            );
            cells.push(
                ui.add(egui::Label::new(RichText::new(format!("+{relative}")).monospace().color(theme::TEXT_DIM)).selectable(false).sense(Sense::click()))
                    .on_hover_text(format!("{:#x} in the document", field.offset)),
            );
            cells.push(ui.add(egui::Label::new(RichText::new(field.len.to_string()).monospace().color(theme::TEXT_DIM)).selectable(false).sense(Sense::click())));
            let value = ui.add(egui::Label::new(shortened(&field.value, TABLE_VALUE_CHARS)).selectable(false).sense(Sense::click()));
            cells.push(if field.value.chars().count() > TABLE_VALUE_CHARS { value.on_hover_text(&field.value) } else { value });
            let meaning = meaning_of(notes, field).unwrap_or_default();
            cells.push(
                ui.scope(|ui| {
                    ui.set_max_width(TABLE_MEANING_WIDTH);
                    ui.add(egui::Label::new(RichText::new(meaning).color(theme::TEXT_DIM)).wrap().selectable(false).sense(Sense::click()))
                })
                .inner,
            );
            ui.end_row();
            if cells.iter().any(|cell| cell.hovered()) {
                app.point_at_bytes(field.offset, field.len);
            }
            if cells.iter().any(|cell| cell.clicked()) {
                actions.push(Action::SelectBytes { start: field.offset, len: field.len, name: field.name.clone() });
            }
        }
    });
    let total = count_fields(&entry.fields);
    if total > rows.len() {
        ui.label(RichText::new(format!("… {} more fields", total - rows.len())).small().color(theme::TEXT_DIM));
    }
}

/// The instance's top-level fields as an RFC-style diagram: 32 bits a row,
/// each field a box over its bytes. Pointing at a box outlines its bytes and
/// explains it; clicking selects them.
fn show_diagram(app: &mut ViewerApp, ui: &mut Ui, entry: &StackEntry, notes: Option<&FormatReference>, position: usize, actions: &mut Vec<Action>) {
    // Fields that start before the instance (none should) are left out.
    let spans: Vec<(usize, usize)> = entry.fields.iter().map(|field| field.offset.checked_sub(entry.start).map_or((0, 0), |relative| (relative, field.len))).collect();
    let layout = layout_diagram(&spans, entry.len, DIAGRAM_BYTES_PER_ROW, DIAGRAM_MAX_ROWS);
    if layout.boxes.is_empty() {
        ui.label(RichText::new("No fields to draw.").small().color(theme::TEXT_DIM));
        return;
    }
    let width = ui.available_width().clamp(DIAGRAM_MIN_WIDTH, DIAGRAM_MAX_WIDTH);
    let height = DIAGRAM_RULER_HEIGHT + layout.rows as f32 * DIAGRAM_ROW_HEIGHT;
    let (rect, response) = ui.allocate_exact_size(vec2(width, height), Sense::click());
    let left = rect.min.x + DIAGRAM_OFFSET_WIDTH;
    let byte_width = (width - DIAGRAM_OFFSET_WIDTH) / DIAGRAM_BYTES_PER_ROW as f32;
    let top = rect.min.y + DIAGRAM_RULER_HEIGHT;
    let box_rect = |diagram_box: &DiagramBox| {
        Rect::from_min_size(
            pos2(left + diagram_box.column as f32 * byte_width, top + diagram_box.row as f32 * DIAGRAM_ROW_HEIGHT),
            vec2(diagram_box.width as f32 * byte_width, DIAGRAM_ROW_HEIGHT),
        )
        .shrink(1.0)
    };
    let hovered = response.hover_pos().and_then(|pointer| layout.boxes.iter().find(|diagram_box| box_rect(diagram_box).contains(pointer))).map(|diagram_box| diagram_box.group);
    let painter = ui.painter_at(rect);
    paint_ruler(&painter, rect, left, byte_width);
    let small = FontId::monospace(10.0);
    for row in 0..layout.rows {
        let y = top + row as f32 * DIAGRAM_ROW_HEIGHT;
        painter.text(pos2(rect.min.x + 2.0, y + DIAGRAM_ROW_HEIGHT / 2.0), Align2::LEFT_CENTER, format!("+{}", row * DIAGRAM_BYTES_PER_ROW), small.clone(), theme::TEXT_DIM);
        // Byte cells, which show through where no field covers the bytes.
        for column in 0..DIAGRAM_BYTES_PER_ROW {
            let cell = Rect::from_min_size(pos2(left + column as f32 * byte_width, y), vec2(byte_width, DIAGRAM_ROW_HEIGHT)).shrink(1.0);
            painter.rect_stroke(cell, 2.0, Stroke::new(1.0, theme::OUTLINE.gamma_multiply(0.6)), StrokeKind::Inside);
        }
    }
    for diagram_box in &layout.boxes {
        let group = &layout.groups[diagram_box.group];
        let area = box_rect(diagram_box);
        let start = entry.start + group.offset;
        let under_cursor = position >= start && position < start + group.len;
        let mut fill = DIAGRAM_TINTS[diagram_box.group % DIAGRAM_TINTS.len()];
        if hovered == Some(diagram_box.group) {
            fill = fill.gamma_multiply(1.6);
        }
        painter.rect_filled(area, 3.0, fill);
        let stroke = if under_cursor { Stroke::new(2.0, theme::CURSOR) } else { Stroke::new(1.0, theme::OUTLINE) };
        painter.rect_stroke(area, 3.0, stroke, StrokeKind::Inside);
        let names: Vec<&str> = group.fields.iter().map(|&index| entry.fields[index].name.as_str()).collect();
        let mut label = names.join(" / ");
        if diagram_box.continued {
            label = format!("… {label}");
        }
        if diagram_box.continues {
            label.push_str(" …");
        }
        let colour = if diagram_box.continued { theme::TEXT_DIM } else { theme::TEXT };
        let mut job = egui::text::LayoutJob::single_section(label, egui::TextFormat::simple(FontId::proportional(11.0), colour));
        job.wrap = egui::text::TextWrapping::truncate_at_width((area.width() - 6.0).max(4.0));
        let galley = painter.layout_job(job);
        let at = area.center() - galley.size() / 2.0;
        painter.galley(at, galley, colour);
    }
    if let Some(group) = hovered.map(|index| &layout.groups[index]) {
        app.point_at_bytes(entry.start + group.offset, group.len);
        if response.clicked() {
            let name = group.fields.iter().map(|&index| entry.fields[index].name.as_str()).collect::<Vec<_>>().join(" / ");
            actions.push(Action::SelectBytes { start: entry.start + group.offset, len: group.len, name });
        }
        response.on_hover_ui_at_pointer(|ui| {
            for &index in &group.fields {
                let field = &entry.fields[index];
                ui.label(RichText::new(format!("{} = {}", field.name, shortened(&field.value, TABLE_VALUE_CHARS))).strong());
                ui.label(RichText::new(format!("+{} · {} bytes", group.offset, group.len)).small().color(theme::TEXT_DIM));
                if let Some(explanation) = notes.and_then(|notes| notes.explain_field(&field.name)) {
                    ui.label(explanation);
                }
            }
        });
    }
    if layout.hidden_bytes > 0 {
        ui.label(RichText::new(format!("… {} more bytes", layout.hidden_bytes)).small().color(theme::TEXT_DIM));
    }
}

/// Bit numbers across the top, tens above units, as RFC diagrams have them.
fn paint_ruler(painter: &egui::Painter, rect: Rect, left: f32, byte_width: f32) {
    let bit_width = byte_width / 8.0;
    let font = FontId::monospace(9.0);
    for bit in 0..DIAGRAM_BYTES_PER_ROW * 8 {
        let x = left + (bit as f32 + 0.5) * bit_width;
        if bit % 10 == 0 {
            painter.text(pos2(x, rect.min.y + 1.0), Align2::CENTER_TOP, (bit / 10).to_string(), font.clone(), theme::TEXT_DIM);
        }
        painter.text(pos2(x, rect.min.y + 11.0), Align2::CENTER_TOP, (bit % 10).to_string(), font.clone(), theme::TEXT_DIM);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::Layer;

    const NOTES: &str = r#"
[[format]]
id = "udp"
name = "User Datagram Protocol"
keys = ["UDP", "User Datagram Protocol"]
summary = "Datagrams between ports."
organisation = "An eight-byte header."

[[format]]
id = "pcap"
name = "pcap capture file"
keys = ["pcap"]
summary = "Captured packets."
organisation = "A file header, then records."
"#;

    fn library() -> Library {
        Library::parse(&[("notes.toml", NOTES)]).unwrap()
    }

    fn capture_finding() -> Finding {
        Finding::new("pcap", "protocol", Category::Protocol, 100, 400).title("pcap capture").fields(vec![Field::new("file header", 100, 24, "Ethernet")])
    }

    /// A packet at 140: Ethernet (14 bytes), IPv4 (20), UDP (8), then DNS.
    fn packet() -> PacketLayers {
        let layer = |name: &str, offset: usize, len: usize| Layer { name: name.to_string(), offset, len, fields: vec![Field::new("Field", offset, len, "")] };
        PacketLayers {
            offset: 140,
            len: 80,
            layers: vec![layer("Ethernet II", 0, 14), layer("Internet Protocol version 4", 14, 20), layer("User Datagram Protocol", 34, 8), layer("DNS", 42, 38)],
        }
    }

    fn labels(stack: &[StackEntry]) -> Vec<&str> {
        stack.iter().map(|entry| entry.label.as_str()).collect()
    }

    #[test]
    fn a_udp_header_in_a_capture_is_stacked_from_the_capture_inwards() {
        let library = library();
        let findings = vec![capture_finding(), Finding::new("counter", "patterns", Category::Counter, 150, 10)];
        let stack = build_stack(&library, &findings, Some(&packet()), 140 + 36);
        assert_eq!(labels(&stack), vec!["pcap capture", "Ethernet II", "Internet Protocol version 4", "UDP"]);
        let udp = &stack[3];
        assert_eq!((udp.start, udp.len, udp.reference_id.as_deref()), (174, 8, Some("udp")));
        assert_eq!(udp.fields[0].offset, 174, "layer fields are moved to document offsets");
        assert_eq!(default_choice(&stack), Some(3));
    }

    #[test]
    fn the_innermost_format_with_notes_is_shown_first_but_every_layer_is_listed() {
        let library = library();
        let stack = build_stack(&library, &[capture_finding()], Some(&packet()), 140 + 50);
        assert_eq!(labels(&stack), vec!["pcap capture", "Ethernet II", "Internet Protocol version 4", "UDP", "DNS"]);
        assert!(stack[4].reference_id.is_none(), "DNS has no notes in this library");
        assert_eq!(default_choice(&stack), Some(3), "UDP is the innermost with notes");
        assert_eq!(position_of(&stack, "Ethernet II"), Some(1));
    }

    #[test]
    fn a_signature_and_a_parsed_structure_of_the_same_bytes_are_one_entry() {
        let library = library();
        let signature = Finding::new("pcap", "signatures", Category::Signature, 100, 4).title("pcap magic");
        let mut duplicate = capture_finding();
        duplicate.fields.clear();
        let stack = build_stack(&library, &[signature, duplicate, capture_finding()], None, 101);
        assert_eq!(stack.len(), 1, "{stack:?}");
        assert_eq!(stack[0].fields.len(), 1, "the entry with fields is kept");
        assert!(build_stack(&library, &[capture_finding()], None, 99).is_empty());
    }

    #[test]
    fn the_assistant_is_sent_each_format_with_notes_once_innermost_first() {
        let entry = |key: &str, reference_id: Option<&str>| StackEntry {
            label: key.to_string(),
            key: key.to_string(),
            reference_id: reference_id.map(str::to_string),
            start: 0,
            len: 8,
            fields: Vec::new(),
        };
        let stack = vec![entry("Ethernet II", None), entry("udp", Some("udp")), entry("User Datagram Protocol", Some("udp"))];
        let notes = notes_for_assistant(&stack);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].starts_with("User Datagram Protocol\n"), "{}", notes[0]);
        assert!(notes[0].len() <= ASSISTANT_NOTES_CHARS);
    }

    #[test]
    fn diagram_fields_wrap_across_rows_and_shared_bytes_share_a_box() {
        // Version and header length share byte 0; an 8-byte address starts
        // half way along the first row and runs over two more.
        let spans = [(0, 1), (0, 1), (1, 1), (2, 8), (5, 2)];
        let layout = layout_diagram(&spans, 12, 4, 16);
        assert_eq!(layout.groups[0].fields, vec![0, 1]);
        assert_eq!(layout.groups.len(), 3, "the overlapping field is left out");
        let address: Vec<(usize, usize, usize, bool, bool)> =
            layout.boxes.iter().filter(|b| b.group == 2).map(|b| (b.row, b.column, b.width, b.continued, b.continues)).collect();
        assert_eq!(address, vec![(0, 2, 2, false, true), (1, 0, 4, true, true), (2, 0, 2, true, false)]);
        assert_eq!((layout.rows, layout.hidden_bytes), (3, 0));
    }

    #[test]
    fn a_long_instance_is_cut_after_the_last_row_drawn() {
        let layout = layout_diagram(&[(0, 24), (24, 1000)], 1024, 4, 16);
        assert_eq!(layout.rows, 16);
        assert_eq!(layout.hidden_bytes, 1024 - 64);
        let last = layout.boxes.last().unwrap();
        assert_eq!((last.group, last.row, last.continues), (1, 15, true));
    }
}
