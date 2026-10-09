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

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Align2, Color32, FontId, Rect, RichText, Sense, Stroke, StrokeKind, Ui, pos2, vec2};

use crate::app::ViewerApp;
use crate::send_to::{self, Carried, Carry};
use crate::bus::topics::{FieldsDecoded, ProtocolIdentified, ReferenceFocus};
use crate::bus::{Message, MessageId, Payload, Topic};
use crate::dock::DockTab;
use crate::packets::{self, Flow, Layer, PacketSet};
use crate::panel_packets::{self, PacketLayers};
use crate::plugin::{Category, Field, Finding};
use crate::reference::{self, FormatReference, Library};
use crate::text::truncate_chars;
use crate::theme;

/// How often to look for fetched RFC text.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How sure a format guessed from a port or number is.
const GUESS_CONFIDENCE: f32 = 0.5;
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
    /// Set when the format was not dissected but guessed, from the port,
    /// EtherType or IP protocol number of the packet carrying it.
    pub guess: Option<Guess>,
}

/// Why an undissected payload is thought to be a format.
#[derive(Clone, Debug, PartialEq)]
pub struct Guess {
    /// Such as "UDP port 67 is registered to it".
    pub reason: String,
    /// What the guess rests on: "port", "EtherType" or "IP protocol number".
    pub evidence: &'static str,
    /// Other entries the same evidence points to, as (reference id, reason).
    pub alternatives: Vec<(String, String)>,
}

impl StackEntry {
    /// The notes on this format in the embedded library.
    pub fn reference(&self) -> Option<&'static FormatReference> {
        self.reference_id.as_deref().and_then(|id| reference::library().by_id(id))
    }

    fn is_same_instance(&self, other: &StackEntry) -> bool {
        self.start == other.start && (self.key == other.key || self.reference_id.is_some() && self.reference_id == other.reference_id)
    }

    /// Of two entries for one instance, whether this one should replace
    /// `kept`: it has more fields, or it was found where `kept` was guessed.
    fn is_better_than(&self, kept: &StackEntry) -> bool {
        self.fields.len() > kept.fields.len() || kept.guess.is_some() && self.guess.is_none()
    }

    /// Take a guess's alternative `id` as the guess, keeping the current one
    /// among the alternatives.
    fn pick_alternative(&mut self, library: &Library, id: &str) {
        let Some(guess) = &mut self.guess else { return };
        let Some(at) = guess.alternatives.iter().position(|(alternative, _)| alternative == id) else { return };
        let Some(notes) = library.by_id(id) else { return };
        let (_, reason) = guess.alternatives.remove(at);
        let previous_reason = std::mem::replace(&mut guess.reason, reason);
        if let Some(previous) = self.reference_id.replace(notes.id.clone()) {
            guess.alternatives.insert(at, (previous, previous_reason));
        }
        self.label = guessed_label(notes);
        self.key = notes.id.clone();
    }
}

/// A guessed format's breadcrumb, such as "DHCP?".
fn guessed_label(notes: &FormatReference) -> String {
    format!("{}?", notes.short_name())
}

// ---------------------------------------------------------------------------
// Naming a payload that was not dissected
// ---------------------------------------------------------------------------

/// The layer names the dissector gives bytes it could not decode: a
/// transport payload no application parser claimed, and an Ethernet payload
/// of an unknown EtherType. A payload of an undecoded IP protocol is named
/// after the protocol instead, such as "GRE".
const UNDISSECTED_PAYLOAD: &str = "Payload";
const UNDISSECTED_FRAME_DATA: &str = "Data";

/// Port numbers below this are the IANA's well-known (system) ports.
const WELL_KNOWN_PORT_LIMIT: u16 = 1024;

/// What an undissected payload probably is.
#[derive(Clone, Debug, PartialEq)]
pub struct PayloadGuess {
    /// The packet layer holding the payload.
    pub layer: usize,
    /// Candidate reference ids with why each is likely, likeliest first.
    pub candidates: Vec<(String, String)>,
    /// What the guess rests on: "port", "EtherType" or "IP protocol number".
    pub evidence: &'static str,
}

/// The format a packet's undissected payload most likely holds, from the
/// flow's ports, the EtherType or the IP protocol number, by the ports,
/// EtherTypes and IP protocols the notes in `library` list. `None` when the
/// payload was dissected, its layer's name already has notes, or nothing in
/// the library claims the evidence.
pub fn guess_payload(library: &Library, packet: &PacketLayers) -> Option<PayloadGuess> {
    let (layer, payload) = packet.layers.iter().enumerate().find(|(_, layer)| is_undissected(packet, layer))?;
    if library.lookup(&payload.name).is_some() {
        return None;
    }
    let (candidates, evidence) = match packet.flow {
        Some(flow) if flow.transport.has_ports() => (candidates_by_port(library, &flow), "port"),
        Some(Flow { transport: packets::Transport::Other(protocol), .. }) => {
            let reason = format!("IP protocol {protocol} announces it");
            (library.by_ip_protocol(protocol).iter().map(|notes| (notes.id.clone(), reason.clone())).collect(), "IP protocol number")
        }
        _ => {
            let ether_type = packet.ether_type?;
            let reason = format!("EtherType {ether_type:#06x} announces it");
            (library.by_ethertype(ether_type).iter().map(|notes| (notes.id.clone(), reason.clone())).collect(), "EtherType")
        }
    };
    (!candidates.is_empty()).then_some(PayloadGuess { layer, candidates, evidence })
}

/// Whether `layer` holds bytes the dissector could not decode: the
/// transport payload when no parser claimed it, or an Ethernet payload of
/// an unknown EtherType.
fn is_undissected(packet: &PacketLayers, layer: &Layer) -> bool {
    match packet.flow {
        Some(flow) if flow.transport.has_ports() => layer.name == UNDISSECTED_PAYLOAD,
        Some(Flow { transport: packets::Transport::Other(_), .. }) => packet.payload.is_some_and(|(offset, _)| offset == layer.offset),
        Some(_) => false,
        None => packet.ether_type.is_some() && layer.name == UNDISSECTED_FRAME_DATA,
    }
}

/// Entries on the flow's ports: a well-known port's before the other's, and
/// the destination's before the source's, each entry once.
fn candidates_by_port(library: &Library, flow: &Flow) -> Vec<(String, String)> {
    let transport = match flow.transport {
        packets::Transport::Tcp => reference::Transport::Tcp,
        packets::Transport::Udp => reference::Transport::Udp,
        _ => return Vec::new(),
    };
    let mut ports: Vec<(u16, bool)> = [flow.destination.port.map(|port| (port, true)), flow.source.port.map(|port| (port, false))].into_iter().flatten().collect();
    ports.sort_by_key(|&(port, is_destination)| (port >= WELL_KNOWN_PORT_LIMIT, !is_destination));
    let mut candidates: Vec<(String, String)> = Vec::new();
    for (port, _) in ports {
        for notes in library.by_port(transport, port) {
            if !candidates.iter().any(|(id, _)| *id == notes.id) {
                candidates.push((notes.id.clone(), format!("{} port {port} is registered to it", transport.name().to_uppercase())));
            }
        }
    }
    candidates
}

/// The stack entry for a guessed payload, its first candidate chosen.
fn guessed_entry(library: &Library, packet: &PacketLayers, guess: PayloadGuess) -> Option<StackEntry> {
    let layer = &packet.layers[guess.layer];
    let mut candidates = guess.candidates.into_iter();
    let (id, reason) = candidates.next()?;
    let notes = library.by_id(&id)?;
    Some(StackEntry {
        label: guessed_label(notes),
        key: notes.id.clone(),
        reference_id: Some(notes.id.clone()),
        start: packet.offset + layer.offset,
        len: layer.len,
        fields: Vec::new(),
        guess: Some(Guess { reason, evidence: guess.evidence, alternatives: candidates.collect() }),
    })
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
    // Where a dissector has read the bytes at the cursor, a finding starting
    // inside that packet is a guess about bytes already explained (a DNS
    // name taken for CBOR), so only findings around the packet are stacked.
    let dissected = packet.filter(|packet| dissects(packet, position));
    let guessed_inside = |finding: &Finding| dissected.is_some_and(|packet| finding.start >= packet.offset && finding.start < packet.offset + packet.len);
    for finding in findings.iter().filter(|finding| finding.start <= position && position < finding.end() && is_format(finding, library) && !guessed_inside(finding)) {
        let notes = library.lookup_finding(&finding.id, &finding.title);
        let name = if finding.title.is_empty() { finding.id.as_str() } else { finding.title.as_str() };
        let entry = StackEntry {
            label: label_for(name, notes),
            key: finding.id.clone(),
            reference_id: notes.map(|notes| notes.id.clone()),
            start: finding.start,
            len: finding.len,
            fields: finding.fields.clone(),
            guess: None,
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
                guess: None,
            };
            scoped.push((packet_end.saturating_sub(start), entry));
        }
        // Pushed after the payload's own layer, which encloses as much, so it
        // follows that layer in the stack.
        if let Some(guessed) = guess_payload(library, packet).and_then(|guess| guessed_entry(library, packet, guess))
            && guessed.start <= position
        {
            scoped.push((packet_end.saturating_sub(guessed.start), guessed));
        }
    }
    // Widest first; the sort is stable, so equals keep their order.
    scoped.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.start.cmp(&b.1.start)));
    let mut stack: Vec<StackEntry> = Vec::new();
    for (_, entry) in scoped {
        match stack.iter_mut().find(|kept| kept.is_same_instance(&entry)) {
            Some(kept) if entry.is_better_than(kept) => *kept = entry,
            Some(_) => {}
            None => stack.push(entry),
        }
    }
    stack
}

/// Whether a field of one of the packet's layers covers `position`.
fn dissects(packet: &PacketLayers, position: usize) -> bool {
    fn covers(fields: &[Field], at: usize) -> bool {
        fields.iter().any(|field| (field.offset <= at && at < field.offset + field.len) || covers(&field.children, at))
    }
    position.checked_sub(packet.offset).is_some_and(|at| packet.layers.iter().any(|layer| covers(&layer.fields, at)))
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
    let Some((start, len)) = app.selection() else { return app.cursor };
    innermost_layer_in(app, start, len).unwrap_or(start)
}

/// Where the innermost layer of the decoded packet at `start` begins, when
/// it begins inside the selection `start..start + len`: a packet chosen in
/// the packet viewer selects its record header too, but is about its DNS.
fn innermost_layer_in(app: &ViewerApp, start: usize, len: usize) -> Option<usize> {
    let fact = decoded_at(app, start)?;
    let (span, decoded) = (fact.draft.span?, fact.payload_as::<FieldsDecoded>()?);
    let packet = PacketLayers::from_decoded(span.start, span.len, decoded);
    packet.layers.iter().map(|layer| packet.offset + layer.offset).filter(|&layer_start| layer_start >= start && layer_start < start + len).max()
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

/// The newest current `fields.decoded` fact whose packet holds `position`.
fn decoded_at(app: &ViewerApp, position: usize) -> Option<Arc<Message>> {
    app.bus
        .facts_in(Topic::FieldsDecoded, &app.document_id(), position, 1)
        .into_iter()
        .filter(|fact| !app.bus.is_stale(fact))
        .max_by_key(|fact| fact.id)
        .cloned()
}

/// The dissected packet holding `position`: as decoded on the bus (by the
/// packet viewer, for its chosen packet), else from a capture finding
/// covering it.
fn packet_at(app: &mut ViewerApp, position: usize, findings: &[Finding], cache: &mut Option<CaptureCache>) -> Option<PacketLayers> {
    if let Some(fact) = decoded_at(app, position)
        && let (Some(span), Some(decoded)) = (fact.draft.span, fact.payload_as::<FieldsDecoded>())
    {
        return Some(PacketLayers::from_decoded(span.start, span.len, decoded));
    }
    let capture = findings.iter().find(|finding| crate::parsers::captures::CAPTURE_FINDING_IDS.contains(&finding.id.as_str()))?;
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
    Some(PacketLayers::from_dissection(packet.offset, packet.len, &packets::dissect(&bytes, packet.link)))
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

/// Ask the Reference tab, as `producer`, to show the format known by `key`
/// (a finding id or layer name) once the cursor is inside it.
pub fn focus_reference(app: &ViewerApp, producer: &str, key: &str) {
    app.publish(producer, Payload::ReferenceFocus(ReferenceFocus { key: key.to_string() }));
}

/// Open the Reference tab on the format known by `key`, as [`focus_reference`].
pub fn open_reference_for(app: &mut ViewerApp, producer: &str, key: &str) {
    focus_reference(app, producer, key);
    app.dock.toggle(DockTab::Reference);
}

/// Show the format a `reference.focus` message asks for. Runs whether or
/// not the tab is showing, so it is there when the tab is opened.
pub fn follow_focus(app: &mut ViewerApp, message: &Arc<Message>) {
    if let Some(focus) = message.payload_as::<ReferenceFocus>() {
        app.bench.panels.reference.follow(&focus.key);
    }
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
    /// The `fields.decoded` fact the packet's layers came from.
    decoded: Option<MessageId>,
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
    /// A reference entry opened from "Carries" or the list of every entry,
    /// shown without an instance.
    browsing: Option<String>,
    /// The list of every entry is shown, filtered by `filter`.
    listing: bool,
    filter: String,
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
    let key = StackKey {
        position,
        version: app.document.version(),
        findings: findings.iter().map(|finding| (finding.id.clone(), finding.start, finding.len)).collect(),
        decoded: decoded_at(app, position).map(|fact| fact.id),
    };
    if state.stack_key.as_ref() == Some(&key) {
        return;
    }
    let packet = packet_at(app, position, &findings, &mut state.capture);
    state.stack = build_stack(reference::library(), &findings, packet.as_ref(), position);
    state.stack_key = Some(key);
    publish_guesses(&state.stack, app);
    let wanted = state.wanted.as_deref().and_then(|key| position_of(&state.stack, key));
    if wanted.is_some() {
        state.wanted = None;
    }
    state.chosen = wanted.or_else(|| default_choice(&state.stack));
}

/// Publish the payloads the stack guessed the format of by their port,
/// EtherType or IP protocol number, one fact per payload.
fn publish_guesses(stack: &[StackEntry], app: &ViewerApp) {
    for entry in stack {
        let Some(guess) = &entry.guess else { continue };
        let protocol = entry.reference().map_or_else(|| entry.label.clone(), |notes| notes.name.clone());
        let identified = ProtocolIdentified { protocol, how: guess.reason.clone(), frames: Vec::new() };
        let draft = app.draft("tool:reference-guess", Payload::ProtocolIdentified(identified)).span(entry.start, entry.len).confidence(GUESS_CONFIDENCE).key(entry.start.to_string());
        app.bus.publish(draft);
    }
}

fn request_rfc(state: &mut ReferenceState, reference_id: &str, number: u32, section: Option<String>) {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(crate::api::reference::fetch_rfc(number));
    });
    state.rfc = Some(RfcView { reference_id: reference_id.to_string(), number, section, text: RfcText::Loading(receiver) });
}

fn poll_rfc(state: &mut ReferenceState, ctx: &egui::Context) {
    let Some(view) = &mut state.rfc else { return };
    let RfcText::Loading(receiver) = &view.text else { return };
    view.text = match receiver.try_recv() {
        Ok(Ok(text)) => {
            let (shown, note) = crate::api::reference::rfc_part(text, view.section.as_deref());
            RfcText::Ready { shown, note }
        }
        Ok(Err(error)) => RfcText::Failed(error),
        Err(TryRecvError::Empty) => {
            ctx.request_repaint_after(POLL_INTERVAL);
            return;
        }
        Err(TryRecvError::Disconnected) => RfcText::Failed("The download stopped unexpectedly.".to_string()),
    };
}

/// Look again at the stack once the user's notes were read again: what
/// `reference.reload` does in the window.
pub(crate) fn notes_reloaded(app: &mut ViewerApp) {
    app.bench.panels.reference.stack_key = None;
}

/// Take reference entry `id` in place of the format guessed for the payload
/// at `at`, when the panel shows such a guess: what
/// `reference.pick_alternative` does in the window. Returns whether it did.
pub(crate) fn pick_alternative_at(app: &mut ViewerApp, at: usize, id: &str) -> bool {
    let state = &mut app.bench.panels.reference;
    let Some(entry) = state.stack.iter_mut().find(|entry| entry.start == at && entry.guess.as_ref().is_some_and(|guess| guess.alternatives.iter().any(|(alternative, _)| alternative == id))) else {
        return false;
    };
    entry.pick_alternative(reference::library(), id);
    true
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
    /// Take another entry on the same evidence as a guessed format.
    PickAlternative { index: usize, id: String },
    ShowList,
    ReloadUserNotes,
}

/// Draw the Reference panel.
pub fn show_reference(state: &mut ReferenceState, app: &mut ViewerApp, ui: &mut Ui) {
    poll_rfc(state, ui.ctx());
    refresh_stack(state, app);
    let mut actions = Vec::new();
    egui::ScrollArea::vertical().id_salt("reference-panel").auto_shrink([false, false]).show(ui, |ui| {
        if state.listing {
            show_list(state, ui, &mut actions);
        } else {
            show_body(state, app, ui, &mut actions);
        }
    });
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
        Action::Browse(id) => {
            state.browsing = Some(id);
            state.listing = false;
        }
        Action::StopBrowsing => {
            state.browsing = None;
            state.listing = false;
        }
        Action::PickAlternative { index, id } => {
            if let Some(entry) = state.stack.get_mut(index) {
                entry.pick_alternative(reference::library(), &id);
            }
        }
        Action::ShowList => state.listing = true,
        Action::ReloadUserNotes => {
            let loaded = reference::reload_user_notes();
            app.status = match loaded.problems.len() {
                0 => format!("Reloaded your reference notes ({} files)", loaded.user_files),
                count => format!("Reloaded your reference notes; {count} could not be read"),
            };
            state.stack_key = None;
        }
        Action::SelectBytes { start, len, name } => {
            // Stay on this format while the cursor moves into the field.
            state.wanted = state.chosen_entry().map(|entry| entry.key.clone());
            let finding = Finding::new("field", "reference", Category::Structure, start, len.max(1)).title(name);
            app.select_finding(&finding);
        }
        Action::FetchRfc { reference_id, number, section } => request_rfc(state, &reference_id, number, section),
        Action::HideRfc => state.rfc = None,
    }
}

fn show_body(state: &ReferenceState, app: &mut ViewerApp, ui: &mut Ui, actions: &mut Vec<Action>) {
    show_breadcrumb(state, app, ui, actions);
    ui.separator();
    if let Some(notes) = state.browsing.as_deref().and_then(|id| reference::library().by_id(id)) {
        ui.horizontal(|ui| {
            if ui.small_button("← Back to the cursor").clicked() {
                actions.push(Action::StopBrowsing);
            }
            if ui.small_button("All notes").clicked() {
                actions.push(Action::ShowList);
            }
        });
        show_heading(ui, notes);
        ui.add_space(4.0);
        show_background(state, ui, notes, actions);
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
        Some(notes) => show_heading(ui, notes),
        None => {
            ui.label(RichText::new(&entry.label).heading());
            ui.label(RichText::new(format!("No notes on {} yet; its fields are listed below as the parser reads them.", entry.label)).color(theme::TEXT_DIM));
        }
    }
    if let Some(guess) = &entry.guess {
        show_guess(state, ui, guess, actions);
    }
    // The live instance comes first, so a short pane still shows the bytes
    // under the cursor; the background reading follows.
    if !entry.fields.is_empty() {
        let position = focus_position(app);
        ui.add_space(6.0);
        egui::CollapsingHeader::new(RichText::new("Layout").strong()).id_salt("reference-layout").default_open(true).show(ui, |ui| {
            show_diagram(app, ui, entry, notes, position, actions);
        });
        egui::CollapsingHeader::new(RichText::new("Fields").strong()).id_salt("reference-fields").default_open(true).show(ui, |ui| {
            show_field_table(app, ui, entry, notes, position, actions);
        });
    }
    if let Some(notes) = notes {
        ui.add_space(6.0);
        show_background(state, ui, notes, actions);
    }
}

/// Why a format was guessed rather than dissected, and the other entries
/// the same evidence points to, which can be taken instead.
fn show_guess(state: &ReferenceState, ui: &mut Ui, guess: &Guess, actions: &mut Vec<Action>) {
    let carried = match guess.evidence {
        "port" => "what this port usually carries",
        "EtherType" => "what this EtherType usually announces",
        _ => "what this IP protocol number usually carries",
    };
    ui.label(RichText::new(format!("Not dissected; the notes describe {carried}.")).color(theme::TEXT_DIM));
    let name = state.chosen_entry().and_then(StackEntry::reference).map_or("", |notes| notes.short_name());
    ui.label(RichText::new(format!("Likely {name}: {}.", guess.reason)).small().color(theme::TEXT_DIM));
    let Some(index) = state.chosen.filter(|_| !guess.alternatives.is_empty()) else { return };
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Or perhaps:").color(theme::TEXT_DIM));
        for (id, reason) in &guess.alternatives {
            let Some(notes) = reference::library().by_id(id) else { continue };
            if ui.link(notes.short_name()).on_hover_text(format!("{}: {reason}", notes.name)).clicked() {
                actions.push(Action::PickAlternative { index, id: id.clone() });
            }
        }
    });
}

/// The stack as a clickable path, outermost first, then a link to the list
/// of every entry.
fn show_breadcrumb(state: &ReferenceState, app: &mut ViewerApp, ui: &mut Ui, actions: &mut Vec<Action>) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        for (index, entry) in state.stack.iter().enumerate() {
            if index > 0 {
                ui.label(RichText::new("›").color(theme::TEXT_DIM));
            }
            let text = if entry.reference_id.is_some() { RichText::new(&entry.label) } else { RichText::new(&entry.label).color(theme::TEXT_DIM) };
            let selected = state.browsing.is_none() && state.chosen == Some(index);
            let notes = match (&entry.guess, entry.reference()) {
                (Some(guess), Some(notes)) => format!(" · likely {}: {}", notes.short_name(), guess.reason),
                (None, None) => " · no notes yet".to_string(),
                _ => String::new(),
            };
            let response = ui.selectable_label(selected, text).on_hover_text(format!("{} bytes at {:#x}{notes}", entry.len, entry.start));
            if response.hovered() {
                app.point_at_bytes(entry.start, entry.len);
            }
            if response.clicked() {
                actions.push(Action::Choose(index));
            }
        }
        if !state.stack.is_empty() {
            ui.add_space(8.0);
        }
        let count = reference::library().entries().len();
        if ui.link("Browse all…").on_hover_text(format!("List and search all {count} reference notes")).clicked() {
            actions.push(Action::ShowList);
        }
    });
}

/// Every entry under its group, filtered by what the user types: words,
/// a port such as `udp/67`, or a number. Clicking an entry opens its notes.
fn show_list(state: &mut ReferenceState, ui: &mut Ui, actions: &mut Vec<Action>) {
    let loaded = reference::loaded_notes();
    let library = &loaded.library;
    ui.horizontal(|ui| {
        if ui.small_button("← Back to the cursor").clicked() {
            actions.push(Action::StopBrowsing);
        }
        ui.add(egui::TextEdit::singleline(&mut state.filter).hint_text("Search names, keys or ports (udp/67, 502)").desired_width(260.0));
    });
    let found = library.search(&state.filter);
    let filtering = !state.filter.trim().is_empty();
    let count = if filtering { format!("{} of {} notes", found.len(), library.entries().len()) } else { format!("{} notes", found.len()) };
    ui.label(RichText::new(count).small().color(theme::TEXT_DIM));
    show_user_notes_status(loaded, ui, actions);
    ui.separator();
    for (group, entries) in reference::grouped(&found) {
        // Groups stay folded until the user searches, so the list is short.
        let header = egui::CollapsingHeader::new(RichText::new(format!("{group} ({})", entries.len())).strong()).id_salt(("reference-group", group));
        let header = if filtering { header.open(Some(true)) } else { header };
        header.show(ui, |ui| {
            for notes in entries {
                ui.horizontal_wrapped(|ui| {
                    if ui.link(notes.short_name()).on_hover_text(&notes.summary).clicked() {
                        actions.push(Action::Browse(notes.id.clone()));
                    }
                    let mut detail = if notes.short_name() == notes.name { String::new() } else { notes.name.clone() };
                    if !notes.ports.is_empty() {
                        detail = format!("{detail} {}", notes.ports.join(" ")).trim().to_string();
                    }
                    ui.label(RichText::new(detail).small().color(theme::TEXT_DIM));
                });
            }
        });
    }
}

/// Where your own notes come from, which of them could not be read, and a
/// way to read them again.
fn show_user_notes_status(loaded: &reference::LoadedNotes, ui: &mut Ui, actions: &mut Vec<Action>) {
    let folder = reference::user_notes_dir().map_or_else(|| "~/.config/theviewer/reference".to_string(), |dir| dir.display().to_string());
    ui.horizontal_wrapped(|ui| {
        let files = match loaded.user_files {
            1 => "1 file".to_string(),
            count => format!("{count} files"),
        };
        ui.label(RichText::new(format!("Your notes: {files} from {folder}")).small().color(theme::TEXT_DIM))
            .on_hover_text("Write entries in the same TOML form as the built-in notes; an entry with a built-in id replaces it.");
        if ui.small_button("Reload your notes").clicked() {
            actions.push(Action::ReloadUserNotes);
        }
    });
    if !loaded.problems.is_empty() {
        let files = if loaded.problems.len() == 1 { "1 file".to_string() } else { format!("{} files", loaded.problems.len()) };
        ui.label(RichText::new(format!("{files} of your notes could not be read:")).color(theme::DANGER));
        for problem in &loaded.problems {
            ui.label(RichText::new(problem).small().color(theme::DANGER));
        }
    }
}

/// Name, summary and the protocol's Wireshark name.
fn show_heading(ui: &mut Ui, notes: &FormatReference) {
    ui.label(RichText::new(&notes.name).heading());
    ui.label(RichText::new(&notes.summary).color(theme::TEXT_DIM));
    if let Some(name) = &notes.wireshark {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Wireshark:").color(theme::TEXT_DIM));
            wireshark_name(ui, name);
        });
    }
}

/// A Wireshark display-filter name in monospace; clicking copies it.
fn wireshark_name(ui: &mut Ui, name: &str) -> egui::Response {
    let response = ui
        .add(egui::Label::new(RichText::new(name).monospace()).selectable(false).sense(Sense::click()))
        .on_hover_text(format!("Wireshark display-filter name; click to copy {name}"));
    if response.clicked() {
        ui.ctx().copy_text(name.to_string());
    }
    response
}

/// How the format is organised, what it carries and where it is specified.
fn show_background(state: &ReferenceState, ui: &mut Ui, notes: &FormatReference, actions: &mut Vec<Action>) {
    ui.label(RichText::new("How it is organised").strong());
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

/// The instance's fields with offset, length, value and meaning. Pointing
/// at a row outlines its bytes; clicking selects them.
fn show_field_table(app: &mut ViewerApp, ui: &mut Ui, entry: &StackEntry, notes: Option<&FormatReference>, position: usize, actions: &mut Vec<Action>) {
    let mut rows = Vec::new();
    flatten(&entry.fields, 0, &mut rows);
    let header = |ui: &mut Ui, text: &str| {
        ui.label(RichText::new(text).small().color(theme::TEXT_DIM));
    };
    // The Wireshark column is shown only when the notes name some fields.
    let any_wireshark = notes.is_some_and(|notes| notes.fields.iter().any(|note| note.wireshark.is_some()));
    let columns: &[&str] = if any_wireshark { &["Field", "Offset", "Length", "Value", "Meaning", "Wireshark"] } else { &["Field", "Offset", "Length", "Value", "Meaning"] };
    egui::Grid::new("reference-field-table").num_columns(columns.len()).striped(true).spacing(vec2(12.0, 3.0)).show(ui, |ui| {
        for title in columns {
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
                    let name = ui.add(egui::Label::new(RichText::new(&field.name).color(colour)).selectable(false).sense(Sense::click_and_drag()));
                    send_to::drag_source(&name, || field_carry(app, entry, field));
                    name.context_menu(|ui| {
                        let carry = field_carry(app, entry, field);
                        send_to::menu(app, ui, &carry);
                    });
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
            let value = ui.add(egui::Label::new(truncate_chars(&field.value, TABLE_VALUE_CHARS)).selectable(false).sense(Sense::click()));
            cells.push(if field.value.chars().count() > TABLE_VALUE_CHARS { value.on_hover_text(&field.value) } else { value });
            let meaning = meaning_of(notes, field).unwrap_or_default();
            cells.push(
                ui.scope(|ui| {
                    ui.set_max_width(TABLE_MEANING_WIDTH);
                    ui.add(egui::Label::new(RichText::new(meaning).color(theme::TEXT_DIM)).wrap().selectable(false).sense(Sense::click()))
                })
                .inner,
            );
            // Clicking the Wireshark name copies it rather than selecting the bytes.
            let mut copy_cell_hovered = false;
            if any_wireshark {
                match notes.and_then(|notes| notes.field(&field.name)).and_then(|note| note.wireshark.as_deref()) {
                    Some(name) => copy_cell_hovered = wireshark_name(ui, name).hovered(),
                    None => {
                        ui.label("");
                    }
                }
            }
            ui.end_row();
            if copy_cell_hovered || cells.iter().any(|cell| cell.hovered()) {
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

/// What a field of `entry` carries elsewhere: its value (a number when it
/// reads as one) and its bytes, found again on another file as the field's
/// value when a parser recognised the structure.
fn field_carry(app: &ViewerApp, entry: &StackEntry, field: &Field) -> Carry {
    let structure = Finding::new(entry.key.clone(), "reference", Category::Structure, entry.start, entry.len).fields(entry.fields.clone());
    let by_a_parser = app.registry.has_parser(&entry.key);
    let anchor = crate::journal::provenance::structure_anchor(&structure, field.offset, field.len)
        .filter(|_| by_a_parser)
        .map(|anchor| crate::journal::provenance::with_part(&anchor, crate::journal::anchors::Part::Value));
    let value = match crate::ops::parse_offset(field.value.trim()) {
        Some(number) => Carried::Number(number as u64),
        None => Carried::Text(field.value.clone()),
    };
    Carry::value(value, anchor, format!("field {}", field.name), app.document_id()).with_span(field.offset, field.len)
}

/// The fields a diagram draws, up to document offset `end`: the most
/// detailed ones, so a header made of named parts shows each part rather than
/// one box for the whole header.
fn diagram_fields(fields: &[Field], end: usize) -> Vec<&Field> {
    let mut leaves = Vec::new();
    collect_leaf_fields(fields, end, &mut leaves);
    leaves
}

fn collect_leaf_fields<'a>(fields: &'a [Field], end: usize, out: &mut Vec<&'a Field>) {
    for field in fields.iter().filter(|field| field.offset < end) {
        if field.children.is_empty() {
            out.push(field);
        } else {
            collect_leaf_fields(&field.children, end, out);
        }
    }
}

/// The instance's most detailed fields as an RFC-style diagram: 32 bits a row,
/// each field a box over its bytes. Pointing at a box outlines its bytes and
/// explains it; clicking selects them.
fn show_diagram(app: &mut ViewerApp, ui: &mut Ui, entry: &StackEntry, notes: Option<&FormatReference>, position: usize, actions: &mut Vec<Action>) {
    let fields = diagram_fields(&entry.fields, entry.start + DIAGRAM_BYTES_PER_ROW * DIAGRAM_MAX_ROWS);
    // Fields that start before the instance (none should) are left out.
    let spans: Vec<(usize, usize)> = fields.iter().map(|field| field.offset.checked_sub(entry.start).map_or((0, 0), |relative| (relative, field.len))).collect();
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
        let names: Vec<&str> = group.fields.iter().map(|&index| fields[index].name.as_str()).collect();
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
            let name = group.fields.iter().map(|&index| fields[index].name.as_str()).collect::<Vec<_>>().join(" / ");
            actions.push(Action::SelectBytes { start: entry.start + group.offset, len: group.len, name });
        }
        response.on_hover_ui_at_pointer(|ui| {
            for &index in &group.fields {
                let field = fields[index];
                ui.label(RichText::new(format!("{} = {}", field.name, truncate_chars(&field.value, TABLE_VALUE_CHARS))).strong());
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

    #[test]
    fn a_field_clicked_in_the_reference_tab_is_the_person_s_selection_through_the_api() {
        let mut app = ViewerApp::new(crate::app::Launch::default());
        app.open_bytes(vec![0; 64], "test.bin".to_string());
        app.run_bus();
        crate::actions::take_performed();
        let mut state = ReferenceState::default();
        act(&mut state, &mut app, Action::SelectBytes { start: 4, len: 2, name: "magic".to_string() });
        assert_eq!(crate::actions::take_performed(), [("selection.set".to_string(), serde_json::json!({ "selection": { "range": [4, 2] } }))]);
        assert_eq!((app.selection(), app.cursor), (Some((4, 2)), 6));
        assert!(app.status.contains("magic"), "the status bar names the field: {}", app.status);
    }

    #[test]
    fn the_reference_tab_takes_up_a_format_asked_for_on_the_bus_even_while_hidden() {
        let mut app = ViewerApp::new(crate::app::Launch::default());
        focus_reference(&app, "panel:packets", "Internet Protocol version 4");
        assert_eq!(app.bench.panels.reference.wanted, None, "nothing happens until the bus is delivered");
        app.run_bus();
        assert_eq!(app.bench.panels.reference.wanted.as_deref(), Some("Internet Protocol version 4"));
        let focus = app.bus.recent().find(|message| message.topic() == crate::bus::Topic::ReferenceFocus).unwrap();
        assert_eq!(focus.producer(), "panel:packets");
    }

    #[test]
    fn the_diagram_draws_a_headers_named_parts_rather_than_one_box() {
        let header = Field::new("file header", 0, 8, "").with_children(vec![Field::new("magic", 0, 4, "a1b2c3d4"), Field::new("version", 4, 4, "2.4")]);
        let record = Field::new("packet 1", 8, 100, "").with_children(vec![Field::new("record header", 8, 16, "")]);
        let late = Field::new("packet 2", 500, 10, "");
        let fields = [header, record, late];
        let names: Vec<&str> = diagram_fields(&fields, 64).iter().map(|field| field.name.as_str()).collect();
        assert_eq!(names, ["magic", "version", "record header"], "leaves only, and nothing past the rows drawn");
    }

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
            ..PacketLayers::default()
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
    fn a_guess_about_bytes_a_dissector_read_is_left_out_of_the_stack() {
        let library = library();
        let targa = Finding::new("signature:image/x-tga", "signatures", Category::Image, 140 + 50, 5).title("Targa image data");
        let stack = build_stack(&library, &[capture_finding(), targa.clone()], Some(&packet()), 140 + 52);
        assert_eq!(labels(&stack), vec!["pcap capture", "Ethernet II", "Internet Protocol version 4", "UDP", "DNS"]);
        let undissected = PacketLayers { layers: Vec::new(), ..packet() };
        let stack = build_stack(&library, &[capture_finding(), targa], Some(&undissected), 140 + 52);
        assert_eq!(labels(&stack).last(), Some(&"Targa image data"), "kept where no dissector read the bytes");
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
            guess: None,
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

    const PORT_NOTES: &str = r#"
[[format]]
id = "dhcp"
name = "Dynamic Host Configuration Protocol"
keys = ["DHCP"]
summary = "Hands out addresses."
organisation = "A BOOTP message with options."
ports = ["udp/67", "udp/68"]

[[format]]
id = "rogue"
name = "Something else on port 67"
keys = ["Rogue"]
summary = "Shares a port."
organisation = "Unknown."
ports = ["udp/67"]

[[format]]
id = "gre-tunnel"
name = "Generic Routing Encapsulation"
keys = ["Generic Routing Encapsulation"]
summary = "Tunnels packets."
organisation = "Four bytes of flags and protocol type."
ip_protocols = [47]
ethertypes = [0x88be]
"#;

    fn port_library() -> Library {
        Library::parse(&[("ports.toml", PORT_NOTES)]).unwrap()
    }

    /// An IPv4 packet at 100 from 10.0.0.2:`source` to 10.0.0.1:`destination`
    /// whose 20-byte payload, after an 8-byte UDP header, was not dissected.
    fn udp_packet(source: u16, destination: u16) -> PacketLayers {
        let address = |last: u8| std::net::IpAddr::from([10, 0, 0, last]);
        let layer = |name: &str, offset: usize, len: usize| Layer { name: name.to_string(), offset, len, fields: vec![Field::new("Data", offset, len, "")] };
        PacketLayers {
            offset: 100,
            len: 62,
            layers: vec![layer("Ethernet II", 0, 14), layer("Internet Protocol version 4", 14, 20), layer("User Datagram Protocol", 34, 8), layer("Payload", 42, 20)],
            flow: Some(Flow {
                transport: packets::Transport::Udp,
                source: packets::Endpoint { address: address(2), port: Some(source) },
                destination: packets::Endpoint { address: address(1), port: Some(destination) },
                tcp_sequence: None,
            }),
            payload: Some((42, 20)),
            ether_type: Some(0x0800),
        }
    }

    #[test]
    fn an_undissected_payload_is_named_by_its_well_known_port_as_a_guess() {
        let library = port_library();
        let stack = build_stack(&library, &[], Some(&udp_packet(50_000, 67)), 100 + 45);
        let guessed = stack.last().unwrap();
        assert_eq!(labels(&stack), ["Ethernet II", "Internet Protocol version 4", "User Datagram Protocol", "Payload", "DHCP?"]);
        assert_eq!((guessed.start, guessed.len, guessed.fields.len()), (142, 20, 0), "the payload's bytes, with no fields");
        let guess = guessed.guess.as_ref().unwrap();
        assert_eq!(guess.reason, "UDP port 67 is registered to it");
        assert_eq!(guess.alternatives, [("rogue".to_string(), "UDP port 67 is registered to it".to_string())]);
        assert_eq!(default_choice(&stack), Some(4));

        // A reply from 67 to 68 is named by the well-known destination first.
        let reply = guess_payload(&library, &udp_packet(67, 68)).unwrap();
        assert_eq!(reply.candidates[0], ("dhcp".to_string(), "UDP port 68 is registered to it".to_string()));
        assert!(guess_payload(&library, &udp_packet(4000, 9999)).is_none(), "nothing claims either port");
        assert!(build_stack(&library, &[], Some(&udp_packet(50_000, 67)), 100 + 40).iter().all(|entry| entry.guess.is_none()), "not before the payload");
    }

    #[test]
    fn another_entry_on_the_same_port_can_be_picked_instead() {
        let library = port_library();
        let mut stack = build_stack(&library, &[], Some(&udp_packet(50_000, 67)), 145);
        let guessed = stack.last_mut().unwrap();
        guessed.pick_alternative(&library, "rogue");
        assert_eq!((guessed.label.as_str(), guessed.reference_id.as_deref()), ("Rogue?", Some("rogue")));
        assert_eq!(guessed.guess.as_ref().unwrap().alternatives[0].0, "dhcp", "the first guess stays on offer");
    }

    #[test]
    fn undecoded_ip_protocols_and_ethertypes_are_named_too_unless_their_layer_has_notes() {
        let library = port_library();
        let mut gre = udp_packet(1, 2);
        gre.layers.truncate(2);
        gre.layers.push(Layer { name: "GRE".to_string(), offset: 34, len: 28, fields: Vec::new() });
        gre.flow = gre.flow.map(|flow| Flow { transport: packets::Transport::Other(47), ..flow });
        gre.payload = Some((34, 28));
        let guess = guess_payload(&library, &gre).unwrap();
        assert_eq!((guess.layer, guess.candidates[0].0.as_str(), guess.evidence), (2, "gre-tunnel", "IP protocol number"));

        let mut frame = udp_packet(1, 2);
        frame.layers.truncate(1);
        frame.layers.push(Layer { name: "Data".to_string(), offset: 14, len: 48, fields: Vec::new() });
        (frame.flow, frame.payload, frame.ether_type) = (None, None, Some(0x88be));
        assert_eq!(guess_payload(&library, &frame).unwrap().candidates[0].1, "EtherType 0x88be announces it");

        let mut named = gre.clone();
        named.layers[2].name = "Generic Routing Encapsulation".to_string();
        assert!(guess_payload(&library, &named).is_none(), "a layer whose name has notes is left as it is");
    }
}
