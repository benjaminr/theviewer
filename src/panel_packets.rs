//! Dock panel: the packet viewer.
//!
//! Packets come from the protocol analysis's messages, a capture inside the
//! document (pcap, pcapng, snoop, Network Monitor or ERF, or one of these
//! compressed with gzip, which is opened decompressed), the selection (as one packet, or cut into
//! records), or a cluster from the message alignment. They are listed in a
//! filterable table, dissected layer by layer, summarised into conversations
//! and endpoints, followed as streams, edited in place and exported as pcap.
//!
//! The panel follows the document. Every packet set remembers how it was
//! found ([`Recipe`]); when the document's version changes, the packets are
//! found again and dissected again on a background thread, a moment after the
//! last edit, keeping the selected packets where their offsets survive. The
//! selected packet's detail is re-read on every change, so edits show at once.
//! Selection runs both ways: choosing a packet or field selects its bytes in
//! the main view, and moving the main view's cursor into a packet selects that
//! packet and the field under the cursor.
//!
//! This module holds the state, the sources and the live pipeline; the tables,
//! the detail tree, the hex editor and the operations on packets are drawn by
//! [`crate::panel_packets_view`], and the splitting rules, the raster and hex
//! grids (one packet per row) and the column operations by
//! [`crate::panel_packets_grid`].

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText, Ui};

use crate::analysis_tools;
use crate::api::packet_sets::{self, CaptureEntry, CaptureList, PatternPlace};
use crate::app::ViewerApp;
use crate::analysis_tools::PROTOCOL_PRODUCER;
use crate::bus::topics::{FieldsDecoded, FieldsGuessed, FramesDefined, ProtocolIdentified, SelectionChanged, TemplateApplied};
use crate::bus::{Draft, JobHandle, Message, Payload, Publisher};
use crate::dock::DockTab;
use crate::journal::DerivedFrom;
use crate::packets::sources;
#[cfg(test)]
use crate::packets::sources::Recipe;
use crate::packets::split;
use crate::packets::{self, Detection, Dissection, Flow, FrameProtocol, Layer, LinkKind, PacketSet, RawFrames, SetHints, Summary};
use crate::parsers::captures::{CAPTURE_FINDING_IDS, GZIP_CAPTURE_FINDING_ID};
use crate::panel_packets_grid::{self as grid, GridState};
use crate::panel_packets_tshark::{self as tshark_view, TsharkState};
use crate::panel_packets_view as view;
use crate::panels;
use crate::plugin::{Category, Finding};
use crate::selection::Selection;
use crate::templates::Template;
use crate::theme;

/// How often the panel looks for finished background work.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How long the document must stay unchanged before the packets are found
/// and dissected again.
const LIVE_DEBOUNCE: Duration = Duration::from_millis(300);
/// Most bytes of a capture read when loading it.
pub(crate) const CAPTURE_READ_LIMIT: usize = 128 * 1024 * 1024;
/// Most bytes scanned for captures from the start of the document.
const SCAN_LIMIT: usize = 64 * 1024 * 1024;
/// Most bytes of all packets read for the packet list.
const ARENA_LIMIT: usize = 256 * 1024 * 1024;
/// Most bytes read from any one packet.
pub(crate) const PACKET_READ_LIMIT: usize = 16 * 1024 * 1024;
/// Bytes at a finding's start read to check it is a capture.
const CAPTURE_HEADER_PROBE: usize = 12;

/// Which link type to dissect the packets with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LinkChoice {
    /// Each packet's own link type (from its capture, or raw frames).
    #[default]
    Auto,
    Ethernet,
    RawIp,
    RawFrames,
}

impl LinkChoice {
    pub const ALL: [LinkChoice; 4] = [LinkChoice::Auto, LinkChoice::Ethernet, LinkChoice::RawIp, LinkChoice::RawFrames];

    pub fn label(self) -> &'static str {
        match self {
            LinkChoice::Auto => "Link: auto",
            LinkChoice::Ethernet => "Link: Ethernet",
            LinkChoice::RawIp => "Link: raw IP",
            LinkChoice::RawFrames => "Link: raw frames",
        }
    }

    /// The link type to use for a packet whose own link type is `own`.
    pub fn apply(self, own: LinkKind) -> LinkKind {
        match self {
            LinkChoice::Auto => own,
            LinkChoice::Ethernet => LinkKind::Ethernet,
            LinkChoice::RawIp => LinkKind::RawIp,
            LinkChoice::RawFrames => LinkKind::Unknown,
        }
    }
}

/// How the frames of unknown format in a set are decoded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FrameChoice {
    /// Nothing chosen for this set: the protocol detected, when the
    /// preference allows detection, else the field guesses.
    #[default]
    Default,
    /// The protocol detected, whatever the preference says.
    Detect,
    /// This protocol, whatever was detected.
    Protocol(FrameProtocol),
    /// The template when one is chosen, else the field guesses; never a
    /// protocol.
    Raw,
}

/// What detection found for the frames of unknown format in a set.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum FrameDetection {
    /// Detection was not run: there are no such frames, or it was not asked
    /// for.
    #[default]
    NotRun,
    Unrecognised,
    Found(Detection),
}

impl FrameDetection {
    pub fn protocol(self) -> Option<FrameProtocol> {
        match self {
            FrameDetection::Found(detection) => Some(detection.protocol),
            _ => None,
        }
    }
}

/// Which part of the panel is showing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PacketsView {
    #[default]
    Packets,
    Conversations,
    Endpoints,
    Stream,
}

impl PacketsView {
    pub const ALL: [PacketsView; 4] = [PacketsView::Packets, PacketsView::Conversations, PacketsView::Endpoints, PacketsView::Stream];

    pub fn label(self) -> &'static str {
        match self {
            PacketsView::Packets => "Packets",
            PacketsView::Conversations => "Conversations",
            PacketsView::Endpoints => "Endpoints",
            PacketsView::Stream => "Follow stream",
        }
    }
}

/// The packet list's view of one packet.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PacketRow {
    /// The link type the packet was dissected with.
    pub link: LinkKind,
    pub summary: Summary,
    pub protocols: Vec<&'static str>,
    pub flow: Option<Flow>,
    /// The transport payload, as `(offset, len)` within the packet.
    pub payload: Option<(usize, usize)>,
    /// Protocols tshark named, once the packet has been decoded with it.
    pub tshark_protocols: Vec<String>,
}

impl From<Dissection> for PacketRow {
    fn from(dissection: Dissection) -> Self {
        PacketRow {
            link: dissection.link,
            summary: dissection.summary,
            protocols: dissection.protocols,
            flow: dissection.flow,
            payload: dissection.payload,
            tshark_protocols: dissection.tshark_protocols,
        }
    }
}

/// Every packet's bytes, read once for the list, filters and streams.
#[derive(Debug, Default)]
pub struct PacketBytes {
    data: Vec<u8>,
    /// Where each packet's bytes sit in `data`, as `(start, len)`.
    spans: Vec<(usize, usize)>,
}

impl PacketBytes {
    /// The bytes read of packet `index` (fewer than its length when it was
    /// too long, or when the read budget ran out).
    pub fn packet(&self, index: usize) -> &[u8] {
        self.spans.get(index).map_or(&[], |&(start, len)| &self.data[start..start + len])
    }
}

/// The document as it was when the packets were read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub version: u64,
    pub document_len: usize,
}

/// A finished background dissection, with the set it describes.
struct DissectionJob {
    set: PacketSet,
    bytes: Arc<PacketBytes>,
    rows: Vec<PacketRow>,
    snapshot: Snapshot,
    /// What the whole set says about its flows, for dissecting one packet
    /// again later.
    hints: SetHints,
    /// The protocol the frames of unknown format were decoded as.
    decode_as: Option<FrameProtocol>,
    detection: FrameDetection,
}

/// The selected packet, dissected from the document's current bytes.
pub(crate) struct Detail {
    pub index: usize,
    pub version: u64,
    pub link_choice: LinkChoice,
    pub raw_generation: u64,
    /// tshark's results the dissection was merged with.
    pub tshark_generation: u64,
    pub bytes: Vec<u8>,
    pub dissection: Dissection,
}

/// A field value being typed in the detail tree.
pub(crate) struct FieldEdit {
    /// Where the field sits in the packet.
    pub offset: usize,
    pub len: usize,
    pub little_endian: bool,
    pub text: String,
    pub error: Option<String>,
}

/// The hex editor's cursor within the selected packet.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HexCursor {
    pub position: usize,
    /// The high nibble has been typed; the next digit completes the byte.
    pub pending_low_nibble: bool,
}

/// Conversations and endpoints, for one generation of rows.
pub(crate) struct Statistics {
    pub generation: u64,
    pub conversations: Vec<packets::Conversation>,
    pub endpoints: Vec<packets::EndpointStats>,
}

/// A line for the user under the controls.
pub(crate) struct Note {
    pub text: String,
    pub is_error: bool,
}

/// Everything the packet viewer keeps between frames.
#[derive(Default)]
pub struct PacketsState {
    pub(crate) set: Option<PacketSet>,
    /// Whether the packets are in offset order, for finding one by offset.
    pub(crate) sorted: bool,
    /// A set waiting to be read and dissected.
    incoming: Option<PacketSet>,
    pub(crate) built: Option<Snapshot>,
    /// The document version the latest dissection was started for.
    requested_version: Option<u64>,
    change_noticed: Option<Instant>,
    /// Set when the document was replaced by another one (opening a packet
    /// as a document, say); the packets then describe a document not shown.
    pub(crate) foreign_document: bool,
    pub(crate) bytes: Arc<PacketBytes>,
    pending: Option<Receiver<DissectionJob>>,
    /// The dissection running, to tell a cancelled one from a failure.
    pending_job: Option<JobHandle>,
    pub(crate) rows: Vec<PacketRow>,
    pub(crate) rows_generation: u64,
    /// Counts readings of the packets; results computed for one reading
    /// (tshark's decodes) are dropped when the packets are read again.
    pub(crate) set_generation: u64,
    /// Decoding with Wireshark's tshark.
    pub tshark: TsharkState,

    pub(crate) link_choice: LinkChoice,
    pub(crate) raw: RawFrames,
    pub(crate) raw_label: String,
    /// Whether the focused packet's fields are said on `fields.decoded`.
    fields_published: bool,
    /// The source of the template raw frames are decoded with.
    pub(crate) raw_template_source: Option<String>,
    pub(crate) raw_generation: u64,
    pub(crate) suggested_template: Option<String>,
    /// How this set's frames of unknown format are decoded.
    pub(crate) frame_choice: FrameChoice,
    /// What detection found for them, shown whether or not it is used.
    pub(crate) frame_detection: FrameDetection,

    pub(crate) filter_text: String,
    filter_key: Option<(String, u64)>,
    pub(crate) filter_error: Option<String>,
    pub(crate) visible: Vec<usize>,

    pub(crate) selected: BTreeSet<usize>,
    pub(crate) focus: Option<usize>,
    pub(crate) detail: Option<Detail>,
    /// The chosen field, as `(offset, len)` within the packet.
    pub(crate) selected_field: Option<(usize, usize)>,
    /// Where the main view's cursor sits in the focused packet, if it does.
    pub(crate) cursor_in_packet: Option<usize>,
    pub(crate) hex: HexCursor,
    pub(crate) field_edit: Option<FieldEdit>,
    pub(crate) view: PacketsView,
    pub(crate) statistics: Option<Statistics>,
    pub(crate) stream: Option<packets::Stream>,
    pub(crate) stream_as_hex: bool,

    captures: Vec<CaptureEntry>,
    captures_searched: bool,
    split_length: usize,
    delimiter_text: String,
    marker_starts_packet: bool,
    pub(crate) operation_text: String,
    pub(crate) operation_on_field: bool,
    awaiting_protocol: bool,
    pub(crate) note: Option<Note>,
    pub(crate) scroll_to_row: Option<usize>,
    /// Whether the pointer was over the packet list last frame; the list is
    /// not scrolled under the user's hand.
    pub(crate) list_hovered: bool,
    /// The height of the pane, for sizing the list inside the scrolling panel.
    pub(crate) pane_height: f32,
    /// The raster and hex grids, the splitting rules and column selection.
    pub grid: GridState,
    /// The id of the API's packet set shown (`set-1`), when the packets
    /// came from `packets.sets.create`; the methods on a set take it.
    pub(crate) api_set: Option<String>,
    /// A set (or a new decoding of one) asked for and not shown yet, with
    /// what to say once it is; still here when the panel is next drawn, the
    /// call failed.
    pub(crate) expected: Option<Expected>,
    /// The selection the viewer last made in the document, as
    /// `selection.changed` says it, so the viewer does not follow it back.
    pub(crate) own_selection: Option<(usize, Option<Selection>)>,
}

/// What the viewer asked the API for, and what to say once it is shown.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Expected {
    /// A set or a decoding, with nothing more to say.
    Set,
    /// A range split by the rules form: say how it split.
    Split { start: usize, len: usize },
    /// The protocol analysis's messages: take its field guesses too.
    ProtocolMessages,
}

impl PacketsState {
    /// Show `set` in the viewer, replacing what was there. The packets are
    /// read and dissected the next time the panel is drawn.
    pub fn load(&mut self, set: PacketSet) {
        self.incoming = Some(set);
        self.api_set = None;
        self.selected.clear();
        self.focus = None;
        self.detail = None;
        self.selected_field = None;
        self.field_edit = None;
        self.stream = None;
        self.foreign_document = false;
        self.raw.guesses.clear();
        self.suggested_template = None;
        // A choice of protocol belongs to the set it was made for; a
        // template stays, as it did before protocols could be chosen.
        if self.raw.template.is_none() || self.frame_choice != FrameChoice::Raw {
            self.frame_choice = FrameChoice::Default;
            self.raw.template = None;
            self.raw_label.clear();
        }
        self.frame_detection = FrameDetection::NotRun;
        self.awaiting_protocol = false;
        self.note = None;
    }

    /// The packets shown, once they have been read.
    pub fn packet_set(&self) -> Option<&PacketSet> {
        self.set.as_ref()
    }

    pub fn rows(&self) -> &[PacketRow] {
        &self.rows
    }

    /// Indices of the packets the filter keeps.
    pub fn visible_rows(&self) -> &[usize] {
        &self.visible
    }

    /// The selected packets, in order.
    pub fn selected_packets(&self) -> Vec<usize> {
        self.selected.iter().copied().collect()
    }

    pub fn focused_packet(&self) -> Option<usize> {
        self.focus
    }

    /// The protocol frames of unknown format are decoded as.
    pub fn decoded_as(&self) -> Option<FrameProtocol> {
        self.raw.decode_as
    }

    /// What detection found for the frames of unknown format.
    pub fn frame_detection(&self) -> FrameDetection {
        self.frame_detection
    }

    /// Decode the frames of unknown format as `choice` says, dissecting
    /// them again.
    pub fn choose_frame_decoding(&mut self, choice: FrameChoice) {
        self.frame_choice = choice;
        if choice != FrameChoice::Raw {
            self.raw.template = None;
            self.raw_label.clear();
        }
        self.raw.decode_as = match choice {
            FrameChoice::Protocol(protocol) => Some(protocol),
            _ => None,
        };
        self.raw_generation += 1;
        if let Some(set) = self.set.clone() {
            self.incoming.get_or_insert(set);
        }
    }

    /// Whether packets are being read, dissected or waited for.
    pub fn is_busy(&self) -> bool {
        self.is_reading() || self.awaiting_protocol || self.expected.is_some() || self.tshark.is_busy()
    }

    /// Whether the packets are being read or dissected, or soon will be.
    pub(crate) fn is_reading(&self) -> bool {
        self.incoming.is_some() || self.pending.is_some() || self.change_noticed.is_some()
    }

    pub fn set_filter(&mut self, text: &str) {
        self.filter_text = text.to_string();
    }

    /// The document was swapped for another; the packets no longer describe it.
    pub fn document_replaced(&mut self) {
        if self.set.is_some() || self.incoming.is_some() {
            self.foreign_document = true;
        }
    }

    pub(crate) fn show_note(&mut self, text: impl Into<String>, is_error: bool) {
        self.note = Some(Note { text: text.into(), is_error });
    }

    /// The rows changed: forget everything computed from the old ones.
    pub(crate) fn rows_changed(&mut self) {
        self.rows_generation += 1;
        self.filter_key = None;
        self.statistics = None;
    }

    /// The packet holding document offset `position`, if any.
    pub(crate) fn packet_at(&self, position: usize) -> Option<usize> {
        let set = self.set.as_ref()?;
        let holds = |index: usize| set.packets.get(index).is_some_and(|p| position >= p.offset && position < p.end());
        if self.sorted {
            let after = set.packets.partition_point(|packet| packet.offset <= position);
            return after.checked_sub(1).filter(|&index| holds(index));
        }
        (0..set.packets.len()).find(|&index| holds(index))
    }
}

// ---------------------------------------------------------------------------
// Entry points for the rest of the app
// ---------------------------------------------------------------------------

/// Run `work` with the packet viewer's state lent out of the app.
fn with_state<R>(app: &mut ViewerApp, work: impl FnOnce(&mut PacketsState, &mut ViewerApp) -> R) -> R {
    let mut state = std::mem::take(&mut app.bench.panels.packets);
    let result = work(&mut state, app);
    app.bench.panels.packets = state;
    result
}

/// Load `set`, which a tool found, into the packet viewer and bring its tab
/// forward. It is kept as a set the API knows, so the methods on a set
/// (decoding, export, deleting packets) can name it.
pub fn open_in_packet_viewer(app: &mut ViewerApp, set: PacketSet) {
    let document = app.document_id();
    let id = app.packet_sets.keep(&document, set, (app.document.version(), app.document.len()));
    show_api_set(app, &id);
    app.dock.toggle(DockTab::Packets);
}

/// The id of the API set the viewer shows. Packets put in the viewer some
/// other way (by a test, or a tool not yet asking the API) are kept as a
/// set first, so the methods on a set can name them.
pub(crate) fn api_set_id(state: &mut PacketsState, app: &mut ViewerApp) -> Option<String> {
    if let Some(id) = &state.api_set
        && app.packet_sets.get(id).is_some()
    {
        return Some(id.clone());
    }
    let set = state.incoming.clone().or_else(|| state.set.clone())?;
    let built = state.built.map_or((app.document.version(), app.document.len()), |built| (built.version, built.document_len));
    let id = app.packet_sets.keep(&app.document_id(), set, built);
    state.api_set = Some(id.clone());
    Some(id)
}

/// The panel's choice of link for a set's `link`.
fn link_choice_of(link: Option<LinkKind>) -> LinkChoice {
    match link {
        Some(LinkKind::Ethernet) => LinkChoice::Ethernet,
        Some(LinkKind::RawIp) => LinkChoice::RawIp,
        Some(LinkKind::Unknown) => LinkChoice::RawFrames,
        _ => LinkChoice::Auto,
    }
}

/// The link the panel's choice puts over every packet, as the API takes it:
/// null for each packet's own.
fn link_param(choice: LinkChoice) -> serde_json::Value {
    match choice {
        LinkChoice::Auto => serde_json::Value::Null,
        chosen => serde_json::json!(chosen.apply(LinkKind::Unknown)),
    }
}

/// Show the packet set `id` made through the API in the panel, with the
/// decoding it was given, when it is about the document shown. The set
/// already shown, grown or decoded anew, is read again keeping the packets
/// chosen; another set replaces it.
pub fn show_api_set(app: &mut ViewerApp, id: &str) {
    let Some(stored) = app.packet_sets.get(id) else { return };
    if stored.info.doc != app.document_id() {
        return;
    }
    let (set, info, template) = (stored.packets.clone(), stored.info.clone(), stored.params.template.clone());
    let expected = app.bench.panels.packets.expected.take();
    let guessed = match expected {
        Some(Expected::ProtocolMessages) => app.bus.latest_from::<FieldsGuessed>(&info.doc, PROTOCOL_PRODUCER).map(|(_, guessed)| guessed.clone()),
        _ => None,
    };
    let state = &mut app.bench.panels.packets;
    let again = state.api_set.as_deref() == Some(id) && (state.set.is_some() || state.incoming.is_some());
    let lengths = split::frame_lengths(&set).map(|lengths| lengths.to_string()).unwrap_or_default();
    if again {
        state.incoming = Some(set);
        state.foreign_document = false;
    } else {
        state.load(set);
        state.api_set = Some(id.to_string());
    }
    state.link_choice = link_choice_of(info.link);
    state.frame_choice = match (info.decode_as, info.detect) {
        (Some(protocol), _) => FrameChoice::Protocol(protocol),
        (None, true) => FrameChoice::Detect,
        (None, false) => FrameChoice::Raw,
    };
    state.raw.decode_as = info.decode_as;
    match template.and_then(|source| Template::parse(&source).ok().map(|parsed| (source, parsed))) {
        Some((source, parsed)) => {
            let unchanged = state.raw_template_source.as_deref() == Some(source.as_str()) && state.raw.template.is_some() && !state.raw_label.is_empty();
            state.raw_label = match info.template_name.as_deref() {
                Some(packet_sets::PROTOCOL_TEMPLATE) => PROTOCOL_TEMPLATE.to_string(),
                Some(name) => format!("Template: {name}"),
                None if unchanged => state.raw_label.clone(),
                None => format!("Template: {}", parsed.name()),
            };
            state.raw.template = Some(parsed);
            state.raw_template_source = Some(source);
        }
        None => {
            state.raw.template = None;
            state.raw_label.clear();
        }
    }
    state.raw_generation += 1;
    match expected {
        Some(Expected::Split { start, len }) => {
            state.grid.columns = None;
            state.grid.block_rows = None;
            state.show_note(format!("Split {len} bytes at {start:#x}: {lengths}."), false);
        }
        Some(Expected::ProtocolMessages) => {
            if let Some(guessed) = guessed {
                state.raw.guesses = guessed.fields;
                state.suggested_template = guessed.template;
            }
        }
        Some(Expected::Set) | None => {}
    }
    if !again && let Some(note) = info.notes.first() {
        state.show_note(note.clone(), false);
    }
}

/// Ask for `method` now, the viewer's state being in the app (from the
/// palette, a menu or another panel), expecting a set shown; a failure is
/// said in the viewer as well as on the status bar.
fn ask_now(app: &mut ViewerApp, method: &str, params: serde_json::Value, expected: Expected) -> bool {
    app.bench.panels.packets.expected = Some(expected);
    let done = app.perform(method, params).is_ok();
    let status = app.status.clone();
    let state = &mut app.bench.panels.packets;
    state.expected = None;
    if !done {
        state.show_note(status, true);
    }
    done
}

/// [`ask_now`] for a call whose span is the selection's: the journal notes
/// that the span equal to the selection came from it, and `also` where
/// other values came from.
fn ask_now_of_selection(app: &mut ViewerApp, method: &str, params: serde_json::Value, expected: Expected, also: DerivedFrom) -> bool {
    let mut derived_from = app.selection_call_provenance(&params);
    derived_from.extend(also);
    app.with_provenance(derived_from, |app| ask_now(app, method, params, expected))
}

/// Ask for `method` once the viewer is drawn (its state is lent out while it
/// is, and the set the method shows would land on the placeholder),
/// expecting a set shown; a failure is said in the viewer when it is next
/// drawn.
pub(crate) fn ask_after_drawing(state: &mut PacketsState, app: &mut ViewerApp, method: &str, params: serde_json::Value, expected: Expected) {
    state.expected = Some(expected);
    app.perform_later(method, params);
}

/// [`ask_after_drawing`] for a call whose span is the selection's: the
/// journal notes that the span equal to the selection came from it, and
/// `also` where other values came from (a detected length field).
pub(crate) fn ask_after_drawing_of_selection(state: &mut PacketsState, app: &mut ViewerApp, method: &str, params: serde_json::Value, expected: Expected, also: DerivedFrom) {
    let mut derived_from = app.selection_call_provenance(&params);
    derived_from.extend(also);
    state.expected = Some(expected);
    app.perform_later_derived(method, params, derived_from);
}

/// Load the protocol analysis's messages, starting the analysis first if it
/// has not been run.
pub fn open_protocol_messages(app: &mut ViewerApp) {
    match protocol_messages_call(app, &app.bench.panels.packets) {
        Some(Ok(params)) => drop(ask_now(app, "packets.sets.create", params, Expected::ProtocolMessages)),
        Some(Err(note)) => app.bench.panels.packets.show_note(note, true),
        None => with_state(app, wait_for_protocol),
    }
    app.dock.toggle(DockTab::Packets);
}

/// Load the capture whose header is at `offset`.
pub fn open_capture_at(app: &mut ViewerApp, offset: usize) {
    let gzipped = is_gzipped_at(app, offset);
    let params = capture_call(&app.bench.panels.packets, app, offset, gzipped);
    ask_now(app, "packets.sets.create", params, Expected::Set);
    app.dock.toggle(DockTab::Packets);
}

/// Whether the capture at `offset` is compressed with gzip.
fn is_gzipped_at(app: &mut ViewerApp, offset: usize) -> bool {
    sources::gzip::looks_like(&app.document.read_range(offset, CAPTURE_HEADER_PROBE))
}

/// `packets.sets.create` for the capture whose header (or gzip stream) is
/// at `offset`. A capture compressed with gzip is opened decompressed as a
/// document of its own (Back returns to this one), its packets read there.
fn capture_call(state: &PacketsState, app: &ViewerApp, offset: usize, gzipped: bool) -> serde_json::Value {
    let mut params = serde_json::json!({ "from": "capture", "start": offset });
    if gzipped {
        params["gunzip"] = serde_json::json!(true);
    }
    with_decoding(state, app, params)
}

/// The start of a capture covering `offset`: a capture finding around it,
/// or a capture header right there.
pub fn capture_containing(app: &mut ViewerApp, offset: usize) -> Option<usize> {
    let finding = app.patterns_in(offset, offset + 1).find(|finding| is_capture_finding(&finding.id)).map(|finding| finding.start);
    finding.or_else(|| sources::capture_format(&app.document.read_range(offset, CAPTURE_HEADER_PROBE)).map(|_| offset))
}

/// Add the selection to the packet viewer as one packet.
pub fn add_selection_as_packet(app: &mut ViewerApp) {
    let call = with_state(app, add_selection_call);
    match call {
        Ok((method, params)) => {
            ask_now_of_selection(app, method, params, Expected::Set, DerivedFrom::new());
        }
        Err(note) => app.bench.panels.packets.show_note(note, true),
    }
    app.dock.toggle(DockTab::Packets);
}

/// Cut the selection into packets one raster row long, as
/// `packets.sets.create`, decoded as the viewer decodes frames now.
pub fn split_selection_by_row_width(app: &mut ViewerApp) {
    match split_call(&app.bench.panels.packets, app, app.shape.row_stride()) {
        Ok(params) => {
            ask_now_of_selection(app, "packets.sets.create", params, Expected::Set, DerivedFrom::new());
        }
        Err(note) => app.bench.panels.packets.show_note(note, true),
    }
    app.dock.toggle(DockTab::Packets);
}

/// How a new set is read and decoded, as `packets.sets.create` takes it:
/// the link chosen, whether to detect the protocol of frames of unknown
/// format (as the preference says), or the template chosen for them, which
/// stays from one set to the next. A protocol chosen belongs to the set it
/// was chosen for. The step says how the set was decoded.
pub(crate) fn current_decoding(state: &PacketsState, app: &ViewerApp) -> serde_json::Map<String, serde_json::Value> {
    let mut decoding = serde_json::Map::new();
    if state.link_choice != LinkChoice::Auto {
        decoding.insert("link".into(), link_param(state.link_choice));
    }
    let template = state.raw_template_source.as_ref().filter(|_| state.raw.template.is_some() && state.frame_choice == FrameChoice::Raw);
    match template {
        Some(source) => {
            decoding.insert("detect".into(), serde_json::json!(false));
            decoding.insert("template".into(), serde_json::json!(source));
        }
        None => drop(decoding.insert("detect".into(), serde_json::json!(app.preferences.detect_frame_protocols))),
    }
    decoding
}

/// `params` for `packets.sets.create` with the decoding a new set gets.
fn with_decoding(state: &PacketsState, app: &ViewerApp, mut params: serde_json::Value) -> serde_json::Value {
    params.as_object_mut().expect("an object").extend(current_decoding(state, app));
    params
}

/// How frames of unknown format are decoded, by choice of protocol, of
/// detection, or of a template.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Decoding {
    Frames(FrameChoice),
    /// The template the protocol analysis suggested.
    ProtocolTemplate,
    /// A built-in or saved template, by name.
    NamedTemplate(String),
    /// A template's source.
    Template(String),
}

/// The decoding the viewer shows now.
fn shown_decoding(state: &PacketsState) -> Decoding {
    match (&state.raw.template, &state.raw_template_source) {
        (Some(_), Some(source)) if state.frame_choice == FrameChoice::Raw => {
            if state.raw_label == PROTOCOL_TEMPLATE {
                return Decoding::ProtocolTemplate;
            }
            let named = state.raw_label.strip_prefix("Template: ").filter(|name| packet_sets::available_templates().iter().any(|(known, source_known)| known == name && source_known == source));
            named.map_or_else(|| Decoding::Template(source.clone()), |name| Decoding::NamedTemplate(name.to_string()))
        }
        _ => Decoding::Frames(state.frame_choice),
    }
}

/// `packets.decode_as` for set `set`, decoded as `decoding` says, with every
/// packet read as `link` says.
fn decode_as_call(set: &str, decoding: Decoding, link: LinkChoice, detection_allowed: bool) -> serde_json::Value {
    let mut params = serde_json::json!({ "set": set, "link": link_param(link) });
    let fields = params.as_object_mut().expect("an object");
    match decoding {
        Decoding::Frames(FrameChoice::Protocol(protocol)) => drop(fields.insert("protocol".into(), serde_json::json!(protocol))),
        Decoding::Frames(FrameChoice::Detect) => drop(fields.insert("detect".into(), serde_json::json!(true))),
        Decoding::Frames(FrameChoice::Default) => drop(fields.insert("detect".into(), serde_json::json!(detection_allowed))),
        Decoding::Frames(FrameChoice::Raw) => drop(fields.insert("detect".into(), serde_json::json!(false))),
        Decoding::ProtocolTemplate => {
            fields.insert("detect".into(), serde_json::json!(false));
            fields.insert("template".into(), serde_json::json!(packet_sets::PROTOCOL_TEMPLATE));
        }
        Decoding::NamedTemplate(name) => {
            fields.insert("detect".into(), serde_json::json!(false));
            fields.insert("template_name".into(), serde_json::json!(name));
        }
        Decoding::Template(source) => {
            fields.insert("detect".into(), serde_json::json!(false));
            fields.insert("template".into(), serde_json::json!(source));
        }
    }
    params
}

/// Decode the shown set as `decoding` says, read as `link` says, through
/// `packets.decode_as` once the viewer is drawn.
fn ask_to_decode_as(state: &mut PacketsState, app: &mut ViewerApp, decoding: Decoding, link: LinkChoice) {
    let Some(set) = api_set_id(state, app) else { return };
    let params = decode_as_call(&set, decoding, link, app.preferences.detect_frame_protocols);
    ask_after_drawing(state, app, "packets.decode_as", params, Expected::Set);
}

/// For `--tool packets`: load the first capture in the document, else the
/// protocol analysis's messages. The app's own doing, so not a step of the
/// person's.
pub fn auto_load(app: &mut ViewerApp) {
    if !load_first_capture(app) {
        match protocol_messages_call(app, &app.bench.panels.packets) {
            Some(Ok(params)) => {
                app.bench.panels.packets.expected = Some(Expected::ProtocolMessages);
                let _ = crate::api::call(app, &crate::api::Caller::Panel, "packets.sets.create", params);
                app.bench.panels.packets.expected = None;
            }
            Some(Err(note)) => app.bench.panels.packets.show_note(note, true),
            None => with_state(app, wait_for_protocol),
        }
    }
}

/// Load the first capture in the document, unless packets are already
/// listed. For layouts that open on the packets, so they are not empty.
pub fn load_capture_if_empty(app: &mut ViewerApp) {
    let state = &app.bench.panels.packets;
    if state.set.is_none() && state.incoming.is_none() {
        load_first_capture(app);
    }
}

/// Load the first capture in the start of the document, as the app's own
/// doing rather than a step of the person's. Whether there was one.
fn load_first_capture(app: &mut ViewerApp) -> bool {
    let bytes = app.document.read_range(0, SCAN_LIMIT);
    let Some(capture) = sources::find_captures(&bytes, 0).into_iter().next() else { return false };
    let params = capture_call(&app.bench.panels.packets, app, capture.offset, capture.gzipped);
    app.bench.panels.packets.expected = Some(Expected::Set);
    if let Err(error) = crate::api::call(app, &crate::api::Caller::Panel, "packets.sets.create", params) {
        app.bench.panels.packets.show_note(error.message, true);
    }
    app.bench.panels.packets.expected = None;
    true
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/// Load the messages the protocol analysis published on `frames.defined`,
/// with the fields it guessed, or start the analysis and wait for it.
fn load_from_protocol(state: &mut PacketsState, app: &mut ViewerApp) {
    match protocol_messages_call(app, state) {
        Some(Ok(params)) => {
            state.awaiting_protocol = false;
            ask_after_drawing(state, app, "packets.sets.create", params, Expected::ProtocolMessages);
        }
        Some(Err(note)) => {
            state.awaiting_protocol = false;
            state.show_note(note, true);
        }
        None => wait_for_protocol(state, app),
    }
}

/// Start the protocol analysis, unless it is running, and wait for its messages.
fn wait_for_protocol(state: &mut PacketsState, app: &mut ViewerApp) {
    if !analysis_tools::protocol_running(app) {
        analysis_tools::start_protocol(app);
    }
    state.awaiting_protocol = true;
    state.show_note("Finding the message framing…", false);
}

/// `packets.sets.create` for one packet per message the protocol analysis
/// framed: split again from the document with its framing, so the set
/// follows edits, or else the frames as listed. `None` while the analysis
/// has published no messages; a note when they cannot be packets.
fn protocol_messages_call(app: &ViewerApp, state: &PacketsState) -> Option<Result<serde_json::Value, String>> {
    let (fact, frames) = app.bus.latest_from::<FramesDefined>(&app.document_id(), PROTOCOL_PRODUCER)?;
    let params = match (&frames.framing, fact.draft.span) {
        (Some(framing), Some(span)) => serde_json::json!({ "from": "protocol_framing", "start": span.start, "len": span.len, "framing": framing }),
        _ if frames.frames.is_empty() => return Some(Err("The protocol analysis found no messages to take packets from.".to_string())),
        _ => serde_json::json!({ "from": "selection", "ranges": frames.frames.iter().map(|frame| (frame.start, frame.len)).collect::<Vec<_>>() }),
    };
    Some(Ok(with_decoding(state, app, params)))
}

/// When a protocol analysis the viewer waits for finishes, load its
/// messages, which it published before saying it was done. Runs whether or
/// not the panel is showing.
pub fn follow_protocol_job(app: &mut ViewerApp, message: &Arc<Message>) {
    if message.producer() != PROTOCOL_PRODUCER || !app.bench.panels.packets.awaiting_protocol {
        return;
    }
    panels::with(app, |panels| &mut panels.packets, |state, app| {
        state.awaiting_protocol = false;
        state.note = None;
        let framed = app.bus.latest_from::<FramesDefined>(&app.document_id(), PROTOCOL_PRODUCER).is_some();
        if framed {
            load_from_protocol(state, app);
        } else {
            state.show_note("The protocol analysis stopped without a result.", true);
        }
    });
}

/// Whether a finding is a capture the packet viewer can load.
fn is_capture_finding(id: &str) -> bool {
    CAPTURE_FINDING_IDS.contains(&id) || id == GZIP_CAPTURE_FINDING_ID
}

/// The call that adds the selection to the set shown as one packet, or
/// makes a set of it when none is shown; a note when nothing is selected.
fn add_selection_call(state: &mut PacketsState, app: &mut ViewerApp) -> Result<(&'static str, serde_json::Value), String> {
    let Some((start, len)) = app.selection() else {
        return Err("Select the packet's bytes first.".to_string());
    };
    // Added to what is shown (or what is about to be), so packets can be
    // gathered one at a time.
    match api_set_id(state, app) {
        Some(set) => Ok(("packets.sets.add_packets", serde_json::json!({ "set": set, "ranges": [[start, len]] }))),
        None => Ok(("packets.sets.create", with_decoding(state, app, serde_json::json!({ "from": "selection", "ranges": [[start, len]] })))),
    }
}

/// `packets.sets.create` cutting the selection into records of
/// `record_len` bytes; a note when nothing is selected.
fn split_call(state: &PacketsState, app: &ViewerApp, record_len: usize) -> Result<serde_json::Value, String> {
    let Some((start, len)) = app.selection() else {
        return Err("Select the records first.".to_string());
    };
    Ok(with_decoding(state, app, serde_json::json!({ "from": "split_fixed", "start": start, "len": len, "record_len": record_len })))
}

/// `packets.sets.create` cutting the selection at every delimiter the
/// viewer's field holds; a note when nothing is selected or the delimiter
/// is not hex.
fn delimiter_call(state: &PacketsState, app: &ViewerApp) -> Result<serde_json::Value, String> {
    let Some((start, len)) = app.selection() else {
        return Err("Select the bytes to split first.".to_string());
    };
    let delimiter = packets::parse_hex(&state.delimiter_text).map_err(|reason| format!("The delimiter must be hex bytes, such as 0D0A: {reason}."))?;
    let place = if state.marker_starts_packet { PatternPlace::StartsPacket } else { PatternPlace::Separates };
    let params = serde_json::json!({ "from": "pattern", "start": start, "len": len, "pattern": crate::ops::to_compact_hex(&delimiter), "pattern_mode": place });
    Ok(with_decoding(state, app, params))
}

/// Ask, once the viewer is drawn, for the set `call` makes, or say why
/// there is none.
fn ask_for_set(state: &mut PacketsState, app: &mut ViewerApp, call: Result<(&'static str, serde_json::Value), String>) {
    match call {
        Ok((method, params)) => {
            ask_after_drawing_of_selection(state, app, method, params, Expected::Set, DerivedFrom::new());
        }
        Err(note) => state.show_note(note, true),
    }
}

/// Look for captures in the first part of the document and inside any
/// capture findings past it, through `packets.find_captures`.
fn find_captures(state: &mut PacketsState, app: &mut ViewerApp) {
    let mut regions = vec![(0usize, SCAN_LIMIT)];
    regions.extend(app.patterns_in(SCAN_LIMIT, usize::MAX).filter(|finding| is_capture_finding(&finding.id)).map(|finding| (finding.start, finding.len.min(CAPTURE_READ_LIMIT))));
    let mut captures: Vec<CaptureEntry> = Vec::new();
    for (start, len) in regions {
        let len = len.min(app.document.len().saturating_sub(start));
        let Ok(found) = app.perform_typed::<CaptureList>("packets.find_captures", serde_json::json!({ "start": start, "len": len })) else { continue };
        for capture in found.captures {
            if !captures.iter().any(|known| known.offset == capture.offset) {
                captures.push(capture);
            }
        }
    }
    state.captures = captures;
    state.captures_searched = true;
}

// ---------------------------------------------------------------------------
// Reading, dissecting and following the document
// ---------------------------------------------------------------------------

/// Read every packet of `set` from the document and dissect them all on a
/// background thread.
fn start_dissection(state: &mut PacketsState, app: &mut ViewerApp, set: PacketSet) {
    let mut bytes = PacketBytes::default();
    for packet in &set.packets {
        let room = ARENA_LIMIT.saturating_sub(bytes.data.len());
        let want = packet.len.min(PACKET_READ_LIMIT).min(room);
        let start = bytes.data.len();
        bytes.data.resize(start + want, 0);
        let read = app.document.read_into(packet.offset, &mut bytes.data[start..]);
        bytes.data.truncate(start + read);
        bytes.spans.push((start, read));
    }
    let snapshot = Snapshot { version: app.document.version(), document_len: app.document.len() };
    state.requested_version = Some(snapshot.version);
    let links: Vec<LinkKind> = set.packets.iter().map(|packet| state.link_choice.apply(packet.link)).collect();
    let mut raw = state.raw.clone();
    let detection_allowed = app.preferences.detect_frame_protocols;
    let choice = state.frame_choice;
    let (sender, receiver) = mpsc::channel();
    let job = app.start_job("dissection", "Dissecting packets");
    state.pending_job = Some(job.clone());
    let publisher = app.bus.publisher();
    let document = app.document_id();
    thread::spawn(move || {
        raw.hints = SetHints::learn(links.iter().enumerate().map(|(index, &link)| (bytes.packet(index), link)));
        let detection = detect_frames(&bytes, &links, choice, detection_allowed);
        raw.decode_as = match choice {
            FrameChoice::Protocol(protocol) => Some(protocol),
            FrameChoice::Default if detection_allowed => detection.protocol(),
            FrameChoice::Detect => detection.protocol(),
            FrameChoice::Default | FrameChoice::Raw => None,
        };
        let total = links.len() as u64;
        let mut rows = Vec::with_capacity(links.len());
        for (index, &link) in links.iter().enumerate() {
            if job.is_cancelled() {
                return job.finish_cancelled();
            }
            rows.push(PacketRow::from(packets::dissect_with(bytes.packet(index), link, &raw)));
            job.progress(index as u64 + 1, Some(total));
        }
        publish_packet_facts(&publisher, &set, &links, detection, (&document, snapshot.version));
        job.finish(true, format!("{} packets from {}", set.packets.len(), set.name));
        let _ = sender.send(DissectionJob { set, bytes: Arc::new(bytes), rows, snapshot, hints: raw.hints, decode_as: raw.decode_as, detection });
    });
    state.pending = Some(receiver);
}

/// What publishes the packet viewer's frames and the protocol detected for them.
pub(crate) const PACKETS_PRODUCER: &str = "panel:packets";

/// Publish where the packets are and, when detection found one, the
/// protocol of the frames of unknown format.
fn publish_packet_facts(publisher: &Publisher, set: &PacketSet, links: &[LinkKind], detection: FrameDetection, (document, version): (&str, u64)) {
    let start = set.packets.iter().map(|packet| packet.offset).min().unwrap_or(0);
    let end = set.packets.iter().map(|packet| packet.end()).max().unwrap_or(start);
    let draft = |payload| Draft::new(PACKETS_PRODUCER, payload).about(document, version).span(start, end - start);
    publisher.publish(draft(Payload::FramesDefined(FramesDefined::new(set.packets.iter().map(|packet| (packet.offset, packet.len)), set.name.clone()))));
    let unknown = set.packets.iter().zip(links).filter(|(_, link)| **link == LinkKind::Unknown).map(|(packet, _)| (packet.offset, packet.len));
    let frames = FramesDefined::new(unknown, String::new()).frames;
    let blank = ProtocolIdentified { protocol: String::new(), how: String::new(), frames: Vec::new() };
    publisher.publish(match detection {
        FrameDetection::Found(found) => draft(Payload::ProtocolIdentified(ProtocolIdentified {
            protocol: found.protocol.label().to_string(),
            how: format!("frame detection read {} of {} sampled frames in full", found.matched, found.sampled),
            frames,
        })),
        FrameDetection::NotRun | FrameDetection::Unrecognised => draft(Payload::ProtocolIdentified(blank)).retraction(),
    });
}

/// Detect the protocol of the frames of unknown format, when there are any
/// and detection is allowed or asked for. With the preference on, it runs
/// even under a choice it will not override, so the panel can say what it
/// found.
fn detect_frames(bytes: &PacketBytes, links: &[LinkKind], choice: FrameChoice, allowed: bool) -> FrameDetection {
    if !allowed && choice != FrameChoice::Detect {
        return FrameDetection::NotRun;
    }
    let frames: Vec<&[u8]> = links.iter().enumerate().filter(|(_, link)| **link == LinkKind::Unknown).map(|(index, _)| bytes.packet(index)).collect();
    if frames.is_empty() {
        return FrameDetection::NotRun;
    }
    packets::detect_frame_protocol(&frames).map_or(FrameDetection::Unrecognised, FrameDetection::Found)
}

fn poll_dissection(state: &mut PacketsState, ctx: &egui::Context) {
    let Some(receiver) = &state.pending else { return };
    match receiver.try_recv() {
        Ok(job) => {
            state.pending = None;
            state.pending_job = None;
            install(state, job);
        }
        Err(TryRecvError::Empty) => ctx.request_repaint_after(POLL_INTERVAL),
        Err(TryRecvError::Disconnected) => {
            state.pending = None;
            let cancelled = state.pending_job.take().is_some_and(|job| job.is_cancelled());
            state.show_note(if cancelled { "Dissecting the packets was cancelled." } else { "Dissecting the packets stopped unexpectedly." }, !cancelled);
        }
    }
}

/// Show a finished dissection, keeping the selection on packets whose
/// offsets survived.
fn install(state: &mut PacketsState, job: DissectionJob) {
    let previous_offsets: HashMap<usize, usize> = state.set.as_ref().map_or_else(HashMap::new, |set| set.packets.iter().enumerate().map(|(i, p)| (i, p.offset)).collect());
    let new_index: HashMap<usize, usize> = job.set.packets.iter().enumerate().map(|(i, p)| (p.offset, i)).collect();
    let remap = |index: usize| previous_offsets.get(&index).and_then(|offset| new_index.get(offset)).copied();
    let carried_over = state.selected.iter().filter_map(|&index| remap(index)).collect();
    state.focus = state.focus.and_then(remap);
    state.selected = carried_over;
    if state.focus.is_none() {
        state.selected_field = None;
        state.field_edit = None;
    }
    state.sorted = job.set.packets.windows(2).all(|pair| pair[0].offset <= pair[1].offset);
    state.set = Some(job.set);
    state.bytes = job.bytes;
    state.rows = job.rows;
    state.raw.hints = job.hints;
    state.raw.decode_as = job.decode_as;
    state.frame_detection = job.detection;
    state.built = Some(job.snapshot);
    state.detail = None;
    state.set_generation += 1;
    state.rows_changed();
}

/// After the document changes, and once it has been still for a moment, find
/// and dissect the packets again.
fn follow_document(state: &mut PacketsState, app: &mut ViewerApp, ctx: &egui::Context) {
    let Some(built) = state.built else { return };
    if state.foreign_document {
        return;
    }
    if Some(app.document.version()) == state.requested_version {
        state.change_noticed = None;
        return;
    }
    let noticed = *state.change_noticed.get_or_insert_with(Instant::now);
    let waited = noticed.elapsed();
    if waited < LIVE_DEBOUNCE {
        ctx.request_repaint_after(LIVE_DEBOUNCE - waited);
        return;
    }
    state.change_noticed = None;
    refresh_from_document(state, app, built);
}

/// Find the packets again with their recipe, then dissect them.
pub(crate) fn refresh_from_document(state: &mut PacketsState, app: &mut ViewerApp, built: Snapshot) {
    let Some(set) = state.set.clone() else { return };
    let growth = app.document.len() as i64 - built.document_len as i64;
    let refreshed = match set.recipe.range(growth, app.document.len(), CAPTURE_READ_LIMIT) {
        None => set,
        Some((start, len)) => {
            let bytes = app.document.read_range(start, len);
            match set.recipe.rebuild(&bytes, start) {
                Ok(found) => found,
                Err(error) => {
                    state.show_note(format!("After the edit the packets could not be found again: {error}"), true);
                    set
                }
            }
        }
    };
    start_dissection(state, app, refreshed);
}

/// Dissect the focused packet from the document's current bytes whenever it,
/// the document or the decoding changes.
fn refresh_detail(state: &mut PacketsState, app: &mut ViewerApp) {
    let Some(index) = state.focus else {
        state.detail = None;
        if state.fields_published {
            publish_focused_fields(state, app);
        }
        return;
    };
    let Some(packet) = state.set.as_ref().and_then(|set| set.packets.get(index)) else {
        state.detail = None;
        return;
    };
    let version = app.document.version();
    let current = state.detail.as_ref().is_some_and(|detail| {
        detail.index == index
            && detail.version == version
            && detail.link_choice == state.link_choice
            && detail.raw_generation == state.raw_generation
            && detail.tshark_generation == state.tshark.generation
    });
    if current || state.foreign_document {
        return;
    }
    let bytes = app.document.read_range(packet.offset, packet.len.min(PACKET_READ_LIMIT));
    let mut dissection = packets::dissect_with(&bytes, state.link_choice.apply(packet.link), &state.raw);
    // tshark decoded the bytes as they were read; once the document has
    // changed since, its layers no longer describe them.
    if state.built.is_some_and(|built| built.version == version) {
        dissection = tshark_view::merged(state, index, dissection);
    }
    state.hex.position = state.hex.position.min(bytes.len().saturating_sub(1));
    state.detail = Some(Detail {
        index,
        version,
        link_choice: state.link_choice,
        raw_generation: state.raw_generation,
        tshark_generation: state.tshark.generation,
        bytes,
        dissection,
    });
    publish_focused_fields(state, app);
}

/// When the selection changes, unless the packet viewer made the change
/// itself, follow it. Runs whether or not the panel is showing.
pub fn follow_selection(app: &mut ViewerApp, message: &Arc<Message>) {
    if app.bus.caused_by_producer(message, PACKETS_PRODUCER) {
        return;
    }
    if let Some(changed) = message.payload_as::<SelectionChanged>() {
        let state = &mut app.bench.panels.packets;
        let own = state.own_selection.as_ref().is_some_and(|(cursor, selection)| *cursor == changed.cursor && *selection == changed.selection);
        if own {
            state.own_selection = None;
            return;
        }
    }
    panels::with(app, |panels| &mut panels.packets, |state, app| {
        let focus = state.focus;
        follow_main_selection(state, app);
        if state.focus != focus || state.focus.is_some() {
            publish_focused_fields(state, app);
        }
    });
}

/// When the main view's cursor moves into a packet, select that packet (and
/// note the field under the cursor), scrolling the list only when the user
/// is not working in it.
fn follow_main_selection(state: &mut PacketsState, app: &ViewerApp) {
    let position = app.selection().map_or(app.cursor, |(start, _)| start);
    let Some(index) = state.packet_at(position) else {
        state.cursor_in_packet = None;
        return;
    };
    let offset = state.set.as_ref().map_or(0, |set| set.packets[index].offset);
    state.cursor_in_packet = Some(position - offset);
    if state.focus != Some(index) {
        state.focus = Some(index);
        state.selected = BTreeSet::from([index]);
        state.selected_field = None;
        state.field_edit = None;
        if !state.list_hovered {
            state.scroll_to_row = Some(index);
        }
    }
}

/// Say on `fields.decoded` how the focused packet dissects, at document
/// offsets: from the detail when it is current, else dissected afresh. When
/// no packet is focused, what was said is withdrawn.
pub(crate) fn publish_focused_fields(state: &mut PacketsState, app: &mut ViewerApp) {
    if state.foreign_document {
        return;
    }
    let focused = state.focus.and_then(|index| Some((index, state.set.as_ref()?.packets.get(index)?.clone())));
    let Some((index, packet)) = focused else {
        let blank = FieldsDecoded { layers: Vec::new(), flow: None, payload: None, ether_type: None };
        app.bus.publish(app.draft(PACKETS_PRODUCER, Payload::FieldsDecoded(blank)).retraction());
        state.fields_published = false;
        return;
    };
    let version = app.document.version();
    let dissection = match &state.detail {
        Some(detail) if detail.index == index && detail.version == version && detail.link_choice == state.link_choice && detail.raw_generation == state.raw_generation && detail.tshark_generation == state.tshark.generation => {
            detail.dissection.clone()
        }
        _ => {
            let bytes = app.document.read_range(packet.offset, packet.len.min(PACKET_READ_LIMIT));
            let dissection = packets::dissect_with(&bytes, state.link_choice.apply(packet.link), &state.raw);
            // tshark's layers describe the bytes as they were read.
            if state.built.is_some_and(|built| built.version == version) { tshark_view::merged(state, index, dissection) } else { dissection }
        }
    };
    let decoded = decoded_fields(packet.offset, &dissection);
    app.bus.publish(app.draft(PACKETS_PRODUCER, Payload::FieldsDecoded(decoded)).span(packet.offset, packet.len));
    state.fields_published = true;
}

/// A dissection of the packet at document offset `offset`, with its
/// offsets moved into the document.
fn decoded_fields(offset: usize, dissection: &Dissection) -> FieldsDecoded {
    fn shift(fields: &mut [crate::plugin::Field], by: usize) {
        for field in fields {
            field.offset += by;
            shift(&mut field.children, by);
        }
    }
    let layers = dissection
        .layers
        .iter()
        .cloned()
        .map(|mut layer| {
            layer.offset += offset;
            shift(&mut layer.fields, offset);
            layer
        })
        .collect();
    let payload = dissection.payload.map(|(start, len)| crate::bus::Span { start: offset + start, len });
    FieldsDecoded { layers, flow: dissection.flow, payload, ether_type: dissection.ether_type }
}

/// After an edit, say again how the focused packet dissects. Runs whether
/// or not the panel is showing.
pub fn decode_focused_after_edit(app: &mut ViewerApp, _message: &Arc<Message>) {
    if app.bench.panels.packets.focus.is_none() {
        return;
    }
    panels::with(app, |panels| &mut panels.packets, publish_focused_fields);
}

/// A dissected packet: where it lies in the document and its layers, whose
/// field offsets are relative to the packet's first byte.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PacketLayers {
    pub offset: usize,
    pub len: usize,
    pub layers: Vec<Layer>,
    /// Addresses, ports and transport, for naming a payload not dissected.
    pub flow: Option<Flow>,
    /// The transport payload as `(offset, len)` from the packet's first byte.
    pub payload: Option<(usize, usize)>,
    /// The EtherType after the Ethernet header and any VLAN tags.
    pub ether_type: Option<u16>,
}

impl PacketLayers {
    /// The layers of a packet at document offset `offset`.
    pub fn from_dissection(offset: usize, len: usize, dissection: &Dissection) -> PacketLayers {
        PacketLayers { offset, len, layers: dissection.layers.clone(), flow: dissection.flow, payload: dissection.payload, ether_type: dissection.ether_type }
    }

    /// The layers `fields.decoded` gives for the packet at document offset
    /// `offset`, with their offsets made relative to the packet again.
    pub fn from_decoded(offset: usize, len: usize, decoded: &FieldsDecoded) -> PacketLayers {
        fn unshift(fields: &mut [crate::plugin::Field], by: usize) {
            for field in fields {
                field.offset = field.offset.saturating_sub(by);
                unshift(&mut field.children, by);
            }
        }
        let layers = decoded
            .layers
            .iter()
            .cloned()
            .map(|mut layer| {
                layer.offset = layer.offset.saturating_sub(offset);
                unshift(&mut layer.fields, offset);
                layer
            })
            .collect();
        let payload = decoded.payload.map(|span| (span.start.saturating_sub(offset), span.len));
        PacketLayers { offset, len, layers, flow: decoded.flow, payload, ether_type: decoded.ether_type }
    }
}

/// Publish the main view's selection as one the panel made, so it is not
/// followed back.
pub(crate) fn claim_main_selection(app: &mut ViewerApp) {
    app.publish_selection(PACKETS_PRODUCER);
}

/// Select `ranges` in the document as the person did in the viewer,
/// through `selection.set`, remembering the selection made so the viewer
/// does not follow it back. Whether it was made.
pub(crate) fn select_ranges_in_document(state: &mut PacketsState, app: &mut ViewerApp, ranges: Vec<(usize, usize)>) -> bool {
    let len = app.document.len();
    let ranges = crate::selection::normalise_ranges(ranges.into_iter().filter(|&(start, _)| start < len).map(|(start, range_len)| (start, range_len.min(len - start))).collect());
    let selection = match ranges.as_slice() {
        [] => return false,
        [(start, len)] => Selection::Range(*start, *len),
        _ => Selection::Ranges(ranges),
    };
    if app.perform("selection.set", serde_json::json!({ "selection": selection })).is_err() {
        return false;
    }
    state.own_selection = Some((app.cursor, app.current_selection()));
    true
}

/// Select document bytes in the main view, as `selection.set`, and bring
/// them into view, saying what they are on the status bar.
pub(crate) fn select_in_document(state: &mut PacketsState, app: &mut ViewerApp, start: usize, len: usize, title: String) {
    if !select_ranges_in_document(state, app, vec![(start, len.max(1))]) {
        return;
    }
    if let Some(row) = app.raster_row_of(start)
        && (row < app.top_row || row >= app.top_row + app.visible_rows)
    {
        app.top_row = row.saturating_sub(app.visible_rows / 3);
        app.clamp_top_row();
    }
    app.reveal_cursor_centred();
    app.reveal_cursor_in_hex(true);
    app.status = Finding::new("packet", "packets", Category::Protocol, start, len.max(1)).title(title).description();
}

/// Bring the filter up to date with the rows.
pub(crate) fn refresh_filter(state: &mut PacketsState) {
    let key = (state.filter_text.clone(), state.rows_generation);
    if state.filter_key.as_ref() == Some(&key) {
        return;
    }
    state.filter_key = Some(key);
    let Some(set) = &state.set else {
        state.visible.clear();
        return;
    };
    match packets::parse_filter(&state.filter_text) {
        Ok(filter) => {
            state.filter_error = None;
            // Rows keep no fields, so a packet is dissected again, once, only
            // when a term asks for a field by its Wireshark name.
            let asks_for_fields = filter.terms.iter().any(|term| matches!(term, packets::filter::Term::Field { .. }));
            let state_now: &PacketsState = state;
            state.visible = (0..state_now.rows.len())
                .filter(|&index| {
                    let row = &state_now.rows[index];
                    let dissection = std::cell::OnceCell::new();
                    let values = |name: &str| {
                        let dissection = dissection.get_or_init(|| {
                            let ours = packets::dissect_with(state_now.bytes.packet(index), row.link, &state_now.raw);
                            crate::panel_packets_tshark::merged(state_now, index, ours)
                        });
                        packets::filter::wireshark_values(dissection, name)
                    };
                    let subject = packets::FilterSubject {
                        protocols: &row.protocols,
                        tshark_protocols: &row.tshark_protocols,
                        flow: row.flow.as_ref(),
                        summary: &row.summary,
                        bytes: state_now.bytes.packet(index),
                        len: set.packets.get(index).map_or(0, |p| p.len),
                        fields: asks_for_fields.then_some(&values as &packets::filter::FieldValues),
                    };
                    filter.matches(&subject)
                })
                .collect();
        }
        Err(error) => {
            state.filter_error = Some(error.to_string());
            state.visible = (0..state.rows.len()).collect();
        }
    }
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

/// Show the packet viewer.
pub fn show_packets(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    let ctx = ui.ctx().clone();
    if state.expected.take().is_some() {
        // The set asked for last frame was not shown: the call failed, and
        // the status bar says why.
        state.show_note(app.status.clone(), true);
    }
    poll_dissection(state, &ctx);
    tshark_view::poll(state, app, &ctx);
    if let Some(set) = state.incoming.take() {
        start_dissection(state, app, set);
    }
    follow_document(state, app, &ctx);
    refresh_filter(state);
    tshark_view::decode_automatically(state, app);
    refresh_detail(state, app);

    state.pane_height = ui.available_height();
    egui::ScrollArea::vertical().id_salt("packets-panel").auto_shrink([false, false]).show(ui, |ui| show_body(state, app, ui));
    if !app.actions_after_drawing.is_empty() {
        // What was asked for while drawing is done next frame: have one.
        ctx.request_repaint();
    }
}

/// Everything below the polling: controls, then the chosen view.
fn show_body(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    show_controls(state, app, ui);
    grid::show_split_rules(state, app, ui);
    show_captures(state, app, ui);
    show_status(state, app, ui);
    if state.set.is_none() {
        ui.label(
            RichText::new("Lists packets taken from the document — the protocol framing's messages, a pcap or pcapng capture inside the file, or the selection — and dissects Ethernet, IP, TCP, UDP, DNS, HTTP, NTP, Modbus, MQTT and more. Frames split from the file are decoded as the protocol they turn out to be. Edits in the document show here as you make them.")
                .color(theme::TEXT_DIM),
        );
        return;
    }
    tshark_view::show_controls(state, app, ui);
    ui.horizontal_wrapped(|ui| {
        for choice in PacketsView::ALL {
            if ui.selectable_label(state.view == choice, choice.label()).clicked() {
                state.view = choice;
            }
        }
    });
    ui.separator();
    match state.view {
        PacketsView::Packets => view::show_packet_view(state, app, ui),
        PacketsView::Conversations => view::show_conversations(state, app, ui),
        PacketsView::Endpoints => view::show_endpoints(state, ui),
        PacketsView::Stream => view::show_stream(state, app, ui),
    }
}

/// Where packets come from, the link type and the raw-frame decoding, in
/// one wrapping row.
fn show_controls(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    let has_selection = app.selection().is_some();
    let stride = app.shape.row_stride();
    if state.split_length == 0 {
        state.split_length = stride.max(1);
    }
    let mut redo = false;
    ui.horizontal_wrapped(|ui| {
        if ui.button("From protocol framing").on_hover_text("One packet per message of the protocol analysis (run first if needed)").clicked() {
            load_from_protocol(state, app);
        }
        if ui.button("Find captures").on_hover_text("Look for captures inside the document: pcap, pcapng, snoop, Network Monitor 2.x and ERF, and any of them compressed with gzip").clicked() {
            find_captures(state, app);
        }
        ui.menu_button("From the selection", |ui| {
            if !has_selection {
                ui.label(RichText::new("Select some bytes in the view first.").color(theme::TEXT_DIM));
            }
            if ui.add_enabled(has_selection, egui::Button::new("Selection as one packet")).clicked() {
                let call = add_selection_call(state, app);
                ask_for_set(state, app, call);
                ui.close();
            }
            if ui.add_enabled(has_selection, egui::Button::new(format!("Split by row width ({stride} B)"))).clicked() {
                let call = split_call(state, app, stride).map(|params| ("packets.sets.create", params));
                ask_for_set(state, app, call);
                ui.close();
            }
            ui.separator();
            ui.horizontal(|ui| {
                ui.add(egui::DragValue::new(&mut state.split_length).range(1..=1_048_576).suffix(" B"));
                if ui.add_enabled(has_selection, egui::Button::new("Split by length")).clicked() {
                    let call = split_call(state, app, state.split_length).map(|params| ("packets.sets.create", params));
                    ask_for_set(state, app, call);
                    ui.close();
                }
            });
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut state.delimiter_text).hint_text("hex, e.g. 0D0A").desired_width(110.0));
                if ui.add_enabled(has_selection, egui::Button::new("Split by delimiter")).clicked() {
                    let call = delimiter_call(state, app).map(|params| ("packets.sets.create", params));
                    ask_for_set(state, app, call);
                    ui.close();
                }
            });
            ui.checkbox(&mut state.marker_starts_packet, "The delimiter starts each packet (a sync word)")
                .on_hover_text("Keep the bytes at the start of each packet instead of dropping them between packets");
        });
        view::start_row_unless_fits(ui, view::combo_width(ui));
        let mut link = state.link_choice;
        egui::ComboBox::from_id_salt("packets-link").selected_text(state.link_choice.label()).show_ui(ui, |ui| {
            for choice in LinkChoice::ALL {
                if ui.selectable_value(&mut link, choice, choice.label()).changed() {
                    redo = true;
                }
            }
        });
        if redo {
            // The set is read as the new link says once the API has it.
            ask_to_decode_as(state, app, shown_decoding(state), link);
        }
        view::start_row_unless_fits(ui, view::combo_width(ui));
        show_frame_decoding(state, app, ui);
    });
}

/// The "Decode frames as" choice: detection, each protocol, the field
/// guesses and the templates, each asked for as `packets.decode_as`.
fn show_frame_decoding(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    let detection_allowed = app.preferences.detect_frame_protocols;
    let detected_label = detection_label(state.frame_detection);
    let mut chosen = None;
    egui::ComboBox::from_id_salt("packets-raw-template").selected_text(frame_decoding_label(state, detection_allowed)).show_ui(ui, |ui| {
        let detecting = matches!(state.frame_choice, FrameChoice::Detect) || (detection_allowed && state.frame_choice == FrameChoice::Default);
        let detect_label = if detection_allowed { detected_label.as_str() } else { "Detect now" };
        if ui.selectable_label(detecting, detect_label).on_hover_text("Find out which protocol the frames are from a sample of them, and decode them as it").clicked() {
            chosen = Some(Decoding::Frames(FrameChoice::Detect));
        }
        for protocol in FrameProtocol::ALL {
            if ui.selectable_label(state.frame_choice == FrameChoice::Protocol(protocol), protocol.label()).clicked() {
                chosen = Some(Decoding::Frames(FrameChoice::Protocol(protocol)));
            }
        }
        ui.separator();
        let raw_chosen = !detecting && matches!(state.frame_choice, FrameChoice::Default | FrameChoice::Raw);
        if ui.selectable_label(raw_chosen && state.raw.template.is_none(), FIELD_GUESSES).on_hover_text("The fields the protocol analysis guessed").clicked() {
            chosen = Some(Decoding::Frames(FrameChoice::Raw));
        }
        if state.suggested_template.is_some() && ui.selectable_label(raw_chosen && state.raw_label == PROTOCOL_TEMPLATE, PROTOCOL_TEMPLATE).clicked() {
            chosen = Some(Decoding::ProtocolTemplate);
        }
        for (name, _) in packet_sets::available_templates() {
            let label = format!("Template: {name}");
            if ui.selectable_label(raw_chosen && state.raw_label == label, &label).clicked() {
                chosen = Some(Decoding::NamedTemplate(name));
            }
        }
    });
    if let Some(decoding) = chosen {
        ask_to_decode_as(state, app, decoding, state.link_choice);
    }
}

/// The "Auto" entry, naming what detection found.
fn detection_label(detection: FrameDetection) -> String {
    match detection {
        FrameDetection::Found(detection) => format!("Auto ({})", detection.protocol.label()),
        FrameDetection::Unrecognised => "Auto (nothing recognised: field guesses)".to_string(),
        FrameDetection::NotRun => "Auto".to_string(),
    }
}

/// The decoding shown on the closed "Decode frames as" choice.
fn frame_decoding_label(state: &PacketsState, detection_allowed: bool) -> String {
    let selected = match state.frame_choice {
        FrameChoice::Default if detection_allowed => detection_label(state.frame_detection),
        FrameChoice::Detect => detection_label(state.frame_detection),
        FrameChoice::Protocol(protocol) => protocol.label().to_string(),
        FrameChoice::Default | FrameChoice::Raw if state.raw_label.is_empty() => FIELD_GUESSES.to_string(),
        FrameChoice::Default | FrameChoice::Raw => state.raw_label.clone(),
    };
    format!("Decode frames as: {selected}")
}

/// The choice of decoding frames with the protocol analysis's field guesses.
const FIELD_GUESSES: &str = "Field guesses";
/// The choice of decoding frames with the template the protocol analysis
/// suggests.
const PROTOCOL_TEMPLATE: &str = "Protocol template";

/// Use a template for raw frames, dissecting them again.
#[cfg(test)]
fn choose_template(state: &mut PacketsState, label: &str, source: &str) {
    match Template::parse(source) {
        Ok(template) => {
            state.choose_frame_decoding(FrameChoice::Raw);
            state.raw.template = Some(template);
            state.raw_label = label.to_string();
            state.raw_template_source = Some(source.to_string());
        }
        Err(error) => state.show_note(format!("The template could not be read: {error}"), true),
    }
}

/// When a template of the name the raw frames are decoded with (the
/// protocol template, say) is applied again with other source, edited in
/// the Template tool, decode the frames with the new source. Runs whether
/// or not the panel is showing.
pub fn follow_applied_template(app: &mut ViewerApp, message: &Arc<Message>) {
    let Some(applied) = message.payload_as::<TemplateApplied>() else { return };
    let state = &mut app.bench.panels.packets;
    let decoding_with_it = state.raw.template.as_ref().is_some_and(|template| template.name() == applied.name);
    if message.draft.retracts || !decoding_with_it || applied.source.is_empty() || state.raw_template_source.as_deref() == Some(applied.source.as_str()) {
        return;
    }
    let Ok(template) = Template::parse(&applied.source) else { return };
    state.raw.template = Some(template);
    state.raw_template_source = Some(applied.source.clone());
    state.raw_generation += 1;
    if let Some(set) = state.set.clone() {
        state.incoming.get_or_insert(set);
    }
}

fn show_captures(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    if !state.captures_searched {
        return;
    }
    if state.captures.is_empty() {
        ui.label(RichText::new(format!("No capture found in the first {} or in the findings.", crate::compress::human_bytes(SCAN_LIMIT))).small().color(theme::TEXT_DIM));
        return;
    }
    let mut chosen = None;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Captures:").small().color(theme::TEXT_DIM));
        for capture in &state.captures {
            let hint = if capture.gzipped { "Open the decompressed capture as a document of its own and load its packets" } else { "Load this capture's packets" };
            if ui.small_button(&capture.description).on_hover_text(hint).clicked() {
                chosen = Some((capture.offset as usize, capture.gzipped));
            }
        }
    });
    if let Some((offset, gzipped)) = chosen {
        let params = capture_call(state, app, offset, gzipped);
        ask_after_drawing(state, app, "packets.sets.create", params, Expected::Set);
    }
}

fn show_status(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    if let Some(note) = &state.note {
        let colour = if note.is_error { theme::DANGER } else { theme::TEXT_DIM };
        ui.add(egui::Label::new(RichText::new(&note.text).color(colour)).wrap());
    }
    if state.pending.is_some() || state.awaiting_protocol || state.change_noticed.is_some() {
        ui.horizontal(|ui| {
            ui.spinner();
            let what = if state.change_noticed.is_some() { "Waiting for the edits to settle…" } else { "Reading and dissecting packets…" };
            ui.label(RichText::new(what).color(theme::TEXT_DIM));
        });
    }
    if state.foreign_document {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("These packets were read from another document.").color(theme::DANGER));
            if ui.small_button("Find them in this document").on_hover_text("Find the packets again in the document now shown, the same way").clicked() {
                find_again_here(state, app);
            }
        });
    }
    if let Some(set) = &state.set {
        let mut caption = format!("{} · {}", set.name, set.description);
        if let Some(lengths) = packets::split::frame_lengths(set) {
            caption.push_str(&format!(" · {lengths}"));
        }
        if let Some(decoding) = frame_decoding_caption(state, set) {
            caption.push_str(" · ");
            caption.push_str(&decoding);
        }
        if let Some(cap) = set.cap_note() {
            caption.push_str(" · ");
            caption.push_str(&cap);
        }
        ui.add(egui::Label::new(RichText::new(caption).small().color(theme::TEXT_DIM)).wrap());
    }
}

/// Find the packets, read from another document, again in the one shown,
/// as `packets.sets.refresh` once the viewer is drawn.
fn find_again_here(state: &mut PacketsState, app: &mut ViewerApp) {
    if let Some(set) = api_set_id(state, app) {
        let params = serde_json::json!({ "set": set, "doc": app.document_id() });
        ask_after_drawing(state, app, "packets.sets.refresh", params, Expected::Set);
    }
}

/// How the set's frames of unknown format were decoded, for the status
/// line: the protocol and whether it was detected or chosen, or why the
/// frames show their field guesses or a template.
fn frame_decoding_caption(state: &PacketsState, set: &PacketSet) -> Option<String> {
    let raw_frames = set.packets.iter().filter(|packet| state.link_choice.apply(packet.link) == LinkKind::Unknown).count();
    if raw_frames == 0 || state.pending.is_some() {
        return None;
    }
    let shown_raw = if state.raw.template.is_some() { "shown with the template" } else { "shown with the field guesses" };
    let detection = state.frame_detection;
    let text = match (state.raw.decode_as, state.frame_choice) {
        (Some(protocol), FrameChoice::Protocol(_)) => {
            let decoded = state.rows.iter().filter(|row| row.protocols.contains(&protocol.key())).count();
            let suggestion = detection.protocol().filter(|&found| found != protocol).map(|found| format!("; detection suggests {}", found.label())).unwrap_or_default();
            format!("decoded as {} (chosen; {decoded} of {raw_frames} frames read{suggestion})", protocol.label())
        }
        (Some(protocol), _) => match detection {
            FrameDetection::Found(found) => format!("decoded as {} (detected, {} of {} sampled)", protocol.label(), found.matched, found.sampled),
            _ => format!("decoded as {}", protocol.label()),
        },
        (None, _) => match detection {
            FrameDetection::Found(found) => format!("{shown_raw}; detection suggests {}", found.protocol.label()),
            FrameDetection::Unrecognised => format!("no frame protocol recognised: {shown_raw}"),
            FrameDetection::NotRun => return None,
        },
    };
    Some(text)
}

#[cfg(test)]
mod tests {
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;
    use etherparse::PacketBuilder;

    use super::*;
    use crate::app::Launch;
    use crate::document::Document;

    const JOB_TIMEOUT: Duration = Duration::from_secs(20);

    type PanelHarness = Harness<'static, (PacketsState, ViewerApp)>;

    fn harness_for(bytes: Vec<u8>) -> PanelHarness {
        let mut app = ViewerApp::new(Launch::default());
        app.document = Document::from_bytes(bytes);
        Harness::builder().with_size(egui::vec2(1100.0, 900.0)).build_ui_state(
            |ui, (state, app): &mut (PacketsState, ViewerApp)| {
                // The app carries out what was asked for while drawing and
                // delivers the bus before drawing; both reach the panel's
                // state where the app keeps it.
                std::mem::swap(state, &mut app.bench.panels.packets);
                app.perform_waiting_actions();
                app.run_bus();
                std::mem::swap(state, &mut app.bench.panels.packets);
                show_packets(state, app, ui)
            },
            (PacketsState::default(), app),
        )
    }

    fn settle(harness: &mut PanelHarness) {
        harness.step();
        let started = Instant::now();
        while harness.state().0.is_busy() && started.elapsed() < JOB_TIMEOUT {
            thread::sleep(POLL_INTERVAL / 5);
            harness.step();
        }
        harness.step();
    }

    fn udp_packet(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).udp(source_port, destination_port);
        let mut packet = Vec::new();
        builder.write(&mut packet, payload).unwrap();
        packet
    }

    /// A raw-IP pcap of three UDP packets after some leading bytes.
    fn document_with_capture() -> (Vec<u8>, usize) {
        let packets = [udp_packet(4000, 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01"), udp_packet(4001, 9999, b"other"), udp_packet(4002, 9999, b"third")];
        let mut capture = Vec::new();
        capture.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
        capture.extend_from_slice(&[2, 0, 4, 0]);
        capture.extend_from_slice(&[0; 8]);
        capture.extend_from_slice(&65_535u32.to_le_bytes());
        capture.extend_from_slice(&101u32.to_le_bytes());
        for (index, packet) in packets.iter().enumerate() {
            capture.extend_from_slice(&(100 + index as u32).to_le_bytes());
            capture.extend_from_slice(&0u32.to_le_bytes());
            capture.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            capture.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            capture.extend_from_slice(packet);
        }
        let mut document = vec![0x11u8; 100];
        let at = document.len();
        document.extend_from_slice(&capture);
        document.extend(std::iter::repeat_n(0x22u8, 50));
        (document, at)
    }

    /// Load the capture at `at` as a client would, through
    /// `packets.sets.create`, into the panel's state.
    fn load_capture_into(harness: &mut PanelHarness, at: usize) {
        let (state, app) = harness.state_mut();
        std::mem::swap(state, &mut app.bench.panels.packets);
        crate::api::call(app, &crate::api::Caller::Panel, "packets.sets.create", serde_json::json!({ "from": "capture", "start": at })).expect("a capture");
        let (state, app) = harness.state_mut();
        std::mem::swap(state, &mut app.bench.panels.packets);
        settle(harness);
    }

    #[test]
    fn find_captures_lists_a_network_monitor_capture_inside_a_larger_file_and_loads_it() {
        let frames = [udp_packet(4000, 53, b"query"), udp_packet(4001, 9999, b"other")];
        let ethernet: Vec<Vec<u8>> = frames
            .iter()
            .map(|ip| {
                let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00];
                frame.extend_from_slice(ip);
                frame
            })
            .collect();
        let test_frames: Vec<sources::netmon::tests::TestFrame> = ethernet.iter().map(|data| sources::netmon::tests::TestFrame { data, offset_micros: 0, media_type: 1 }).collect();
        let mut document = vec![0x11u8; 300];
        let at = document.len();
        document.extend_from_slice(&sources::netmon::tests::netmon_file(0x02, &test_frames));
        document.extend(std::iter::repeat_n(0x22u8, 80));
        let mut harness = harness_for(document);
        crate::actions::take_performed();
        harness.get_by_label("Find captures").click();
        settle(&mut harness);
        let len = harness.state().1.document.len();
        assert_eq!(crate::actions::take_performed(), [("packets.find_captures".to_string(), serde_json::json!({ "start": 0, "len": len }))]);
        let listed = format!("Network Monitor at {at:#x} · Ethernet · 2 packets");
        harness.get_by_label(&listed).click();
        settle(&mut harness);
        let (state, _) = harness.state();
        assert_eq!(state.rows().len(), 2);
        assert_eq!(state.rows()[1].summary.source, "10.0.0.2");
        assert_eq!(state.packet_set().unwrap().packets[0].offset, at + 72 + 16);
    }

    #[test]
    fn a_gzipped_snoop_capture_opens_decompressed_with_its_packets() {
        let packet = udp_packet(4000, 9999, b"inside gzip");
        let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00];
        frame.extend_from_slice(&packet);
        let snoop = sources::snoop::tests::snoop_file(4, &[(&frame, 1, 0)]);
        let compressed = crate::compress::compress(crate::compress::Codec::Gzip, &snoop).unwrap();
        let mut harness = harness_for(compressed);
        harness.get_by_label("Find captures").click();
        settle(&mut harness);
        crate::actions::take_performed();
        harness.get_by_label_contains("snoop (gzip) at 0x0").click();
        settle(&mut harness);
        let performed = crate::actions::take_performed();
        assert_eq!(performed[0], ("packets.sets.create".to_string(), serde_json::json!({ "from": "capture", "start": 0, "gunzip": true, "detect": true })));
        let (state, app) = harness.state();
        assert_eq!(app.document.len(), snoop.len(), "the decompressed capture is the document now");
        assert_eq!(state.rows().len(), 1);
        assert_eq!(state.rows()[0].summary.destination, "10.0.0.1");
        assert!(!state.foreign_document);
    }

    #[test]
    fn a_capture_in_the_document_is_listed_and_selecting_a_packet_selects_its_bytes() {
        let (document, at) = document_with_capture();
        let mut harness = harness_for(document);
        load_capture_into(&mut harness, at);
        settle(&mut harness);
        assert_eq!(harness.state().0.rows().len(), 3);
        assert_eq!(harness.state().0.rows()[0].summary.protocol, "DNS");

        harness.state_mut().0.set_filter("udp port:9999");
        settle(&mut harness);
        assert_eq!(harness.state().0.visible_rows(), &[1, 2]);

        harness.get_by_label_contains("4002 → 9999").click();
        settle(&mut harness);
        let (state, app) = harness.state();
        let packet = &state.packet_set().unwrap().packets[2];
        assert_eq!(app.selection(), Some((packet.offset, packet.len)));
        assert_eq!(state.focused_packet(), Some(2));
    }

    #[test]
    fn moving_the_main_cursor_into_a_packet_selects_that_packet() {
        let (document, at) = document_with_capture();
        let mut harness = harness_for(document);
        load_capture_into(&mut harness, at);
        settle(&mut harness);
        let second = harness.state().0.packet_set().unwrap().packets[1].clone();
        // Main cursor on the UDP destination port of the second packet.
        harness.state_mut().1.set_cursor(second.offset + 22, false);
        settle(&mut harness);
        let state = &harness.state().0;
        assert_eq!(state.focused_packet(), Some(1));
        assert_eq!(state.cursor_in_packet, Some(22));
    }

    /// Move the panel's state into the app, as when the panel is not drawn.
    fn hide_panel(harness: &mut PanelHarness) {
        let state = std::mem::take(&mut harness.state_mut().0);
        harness.state_mut().1.bench.panels.packets = state;
    }

    #[test]
    fn packets_follow_the_main_cursor_even_while_the_panel_is_hidden() {
        let (document, at) = document_with_capture();
        let mut harness = harness_for(document);
        load_capture_into(&mut harness, at);
        settle(&mut harness);
        let third = harness.state().0.packet_set().unwrap().packets[2].clone();
        hide_panel(&mut harness);
        let app = &mut harness.state_mut().1;
        app.set_cursor(third.offset + 3, false);
        app.run_bus();
        assert_eq!(app.bench.panels.packets.focused_packet(), Some(2));
        assert_eq!(app.bench.panels.packets.cursor_in_packet, Some(3));
    }

    #[test]
    fn a_selection_the_packet_viewer_made_is_not_followed_back() {
        let (document, at) = document_with_capture();
        let mut harness = harness_for(document);
        load_capture_into(&mut harness, at);
        settle(&mut harness);
        hide_panel(&mut harness);
        let app = &mut harness.state_mut().1;
        let third = app.bench.panels.packets.packet_set().unwrap().packets[2].clone();
        app.bench.panels.packets.focus = Some(0);
        crate::actions::take_performed();
        with_state(app, |state, app| select_in_document(state, app, third.offset, 4, "Bytes".to_string()));
        assert_eq!(crate::actions::take_performed(), [("selection.set".to_string(), serde_json::json!({ "selection": { "range": [third.offset, 4] } }))]);
        app.run_bus();
        assert_eq!(app.bench.panels.packets.focused_packet(), Some(0), "the viewer's own selection leaves its focus be");
        assert_eq!(app.selection(), Some((third.offset, 4)));
        let changed = app.bus.recent().rev().find(|message| message.topic() == crate::bus::Topic::SelectionChanged).unwrap();
        assert_eq!(changed.producer(), "panel", "the person's selection, made through the API");

        // The same bytes selected in the main view are followed.
        app.set_cursor(0, false);
        app.run_bus();
        app.select_ranges(vec![(third.offset, 4)], None);
        app.run_bus();
        assert_eq!(app.bench.panels.packets.focused_packet(), Some(2));
    }

    #[test]
    fn editing_the_document_dissects_the_packets_again_and_keeps_the_selection() {
        let (document, at) = document_with_capture();
        let mut harness = harness_for(document);
        load_capture_into(&mut harness, at);
        settle(&mut harness);
        let first = harness.state().0.packet_set().unwrap().packets[1].clone();
        harness.state_mut().0.focus = Some(1);
        harness.state_mut().0.selected = BTreeSet::from([1]);
        // Overwrite the destination port (bytes 22..24 of the packet) with 123.
        harness.state_mut().1.document.overwrite(first.offset + 22, &123u16.to_be_bytes());
        settle(&mut harness);
        let state = &harness.state().0;
        assert!(state.rows()[1].summary.info.contains("→ 123"), "{:?}", state.rows()[1].summary);
        assert_eq!(state.focused_packet(), Some(1));
        assert!(state.detail.as_ref().is_some_and(|d| d.bytes[22..24] == 123u16.to_be_bytes()));
    }

    #[test]
    fn deleting_a_selected_packet_removes_its_record_and_undo_brings_it_back() {
        let (document, at) = document_with_capture();
        let original_len = document.len();
        let mut harness = harness_for(document);
        load_capture_into(&mut harness, at);
        settle(&mut harness);
        let record = harness.state().0.packet_set().unwrap().packets[1].record.expect("a pcap record");
        crate::actions::take_performed();
        {
            let (state, app) = harness.state_mut();
            state.selected = BTreeSet::from([1]);
            state.focus = Some(1);
            view::delete_selected_packets(state, app);
        }
        assert_eq!(crate::actions::take_performed(), [("packets.delete".to_string(), serde_json::json!({ "set": "set-1", "indices": [1] }))]);
        settle(&mut harness);
        let (state, app) = harness.state();
        assert_eq!(app.document.len(), original_len - record.1);
        assert_eq!(state.rows().len(), 2, "the capture is still readable, one packet shorter");
        harness.state_mut().1.undo();
        settle(&mut harness);
        assert_eq!(harness.state().0.rows().len(), 3);
    }

    /// Frames of a sync byte 0xAA, a u16 big-endian payload length and the
    /// payload, with the document offset of each frame.
    fn length_prefixed_stream() -> (Vec<u8>, Vec<usize>) {
        let mut stream = Vec::new();
        let mut starts = Vec::new();
        for index in 0..12u8 {
            starts.push(stream.len());
            let payload: Vec<u8> = (0..(index % 5 + 3)).map(|byte| byte ^ index.wrapping_mul(29)).collect();
            stream.push(0xAA);
            stream.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            stream.extend_from_slice(&payload);
        }
        (stream, starts)
    }

    /// Back-to-back Modbus/TCP read requests, which carry their own length.
    fn modbus_stream(frames: u16) -> Vec<u8> {
        let mut stream = Vec::new();
        for transaction in 0..frames {
            stream.extend_from_slice(&transaction.to_be_bytes());
            stream.extend_from_slice(&[0, 0, 0, 6, 1, 3]);
            stream.extend_from_slice(&(100 + transaction).to_be_bytes());
            stream.extend_from_slice(&[0, 2]);
        }
        stream
    }

    /// Split the whole document by the MBAP length field.
    fn split_modbus(harness: &mut PanelHarness) {
        let (state, app) = harness.state_mut();
        state.grid.split.rule = grid::SplitRule::LengthField;
        state.grid.split.whole_document = true;
        state.grid.split.field = packets::split::LengthField { offset: 4, ..Default::default() };
        grid::split_now(state, app);
        settle(harness);
    }

    fn row_protocols(harness: &PanelHarness) -> Vec<String> {
        harness.state().0.rows().iter().map(|row| row.summary.protocol.clone()).collect()
    }

    #[test]
    fn split_modbus_frames_are_detected_decoded_and_can_be_shown_raw_instead() {
        let mut harness = harness_for(modbus_stream(6));
        split_modbus(&mut harness);
        assert_eq!(row_protocols(&harness), vec!["Modbus/TCP"; 6]);
        assert!(harness.state().0.rows()[1].summary.info.contains("trans 1"), "{}", harness.state().0.rows()[1].summary.info);
        assert!(harness.query_by_label_contains("decoded as Modbus/TCP (detected, 6 of 6 sampled)").is_some());
        assert_eq!(frame_decoding_label(&harness.state().0, true), "Decode frames as: Auto (Modbus/TCP)");

        harness.state_mut().0.choose_frame_decoding(FrameChoice::Raw);
        settle(&mut harness);
        assert_eq!(row_protocols(&harness), vec!["Data"; 6], "the user's choice is not overridden by detection");
        assert!(harness.query_by_label_contains("shown with the field guesses; detection suggests Modbus/TCP").is_some());
        // Editing the document dissects again under the same choice.
        harness.state_mut().1.document.overwrite(9, &[7]);
        settle(&mut harness);
        assert_eq!(row_protocols(&harness), vec!["Data"; 6]);
        assert!(harness.state().0.rows()[0].summary.info.contains("00 07"), "{:?}", harness.state().0.rows()[0].summary);
    }

    #[test]
    fn a_chosen_protocol_decodes_the_frames_it_reads_and_leaves_the_rest_to_the_field_guesses() {
        let mut harness = harness_for(modbus_stream(4));
        split_modbus(&mut harness);
        harness.state_mut().0.choose_frame_decoding(FrameChoice::Protocol(FrameProtocol::Dns));
        settle(&mut harness);
        assert_eq!(harness.state().0.decoded_as(), Some(FrameProtocol::Dns));
        assert_eq!(row_protocols(&harness), vec!["Data"; 4], "Modbus frames are not DNS");
        assert!(harness.query_by_label_contains("decoded as DNS (chosen; 0 of 4 frames read; detection suggests Modbus/TCP)").is_some());
        let (state, app) = harness.state_mut();
        state.focus = Some(0);
        refresh_detail(state, app);
        let notes = &state.detail.as_ref().expect("a detail").dissection.notes;
        assert_eq!(notes, &["This frame does not decode as DNS, so it is shown with the field guesses instead"]);

        harness.state_mut().0.choose_frame_decoding(FrameChoice::Protocol(FrameProtocol::ModbusTcp));
        settle(&mut harness);
        assert_eq!(row_protocols(&harness), vec!["Modbus/TCP"; 4]);
    }

    #[test]
    fn with_detection_turned_off_frames_show_their_field_guesses_until_detection_is_asked_for() {
        let mut harness = harness_for(modbus_stream(5));
        harness.state_mut().1.preferences.detect_frame_protocols = false;
        split_modbus(&mut harness);
        assert_eq!(row_protocols(&harness), vec!["Data"; 5]);
        assert_eq!(harness.state().0.frame_detection(), FrameDetection::NotRun);
        assert_eq!(frame_decoding_label(&harness.state().0, false), "Decode frames as: Field guesses");

        harness.state_mut().0.choose_frame_decoding(FrameChoice::Detect);
        settle(&mut harness);
        assert_eq!(row_protocols(&harness), vec!["Modbus/TCP"; 5]);
        assert!(harness.query_by_label_contains("decoded as Modbus/TCP (detected, 5 of 5 sampled)").is_some());

        // A new set starts again from the preference.
        split_modbus(&mut harness);
        assert_eq!(row_protocols(&harness), vec!["Data"; 5]);
    }

    #[test]
    fn the_hex_grid_names_selected_columns_by_the_fields_of_the_decoded_protocol() {
        let mut harness = harness_for(modbus_stream(4));
        split_modbus(&mut harness);
        harness.get_by_label("Hex").click();
        settle(&mut harness);
        harness.state_mut().0.grid.columns = Some((6, 2));
        settle(&mut harness);
        assert!(harness.query_by_label_contains("in 4 packets: Unit ID (Modbus/TCP), Function code (Modbus/TCP)").is_some());

        // Shown with the field guesses instead, the columns are not named.
        harness.state_mut().0.choose_frame_decoding(FrameChoice::Raw);
        settle(&mut harness);
        assert!(harness.query_by_label_contains("(Modbus/TCP)").is_none());
    }

    fn click_at(harness: &mut PanelHarness, position: egui::Pos2) {
        harness.hover_at(position);
        harness.step();
        harness.event(egui::Event::PointerButton { pos: position, button: egui::PointerButton::Primary, pressed: true, modifiers: egui::Modifiers::NONE });
        harness.step();
        harness.event(egui::Event::PointerButton { pos: position, button: egui::PointerButton::Primary, pressed: false, modifiers: egui::Modifiers::NONE });
        harness.step();
        harness.step();
    }

    #[test]
    fn a_column_of_a_length_field_split_is_xored_in_every_packet_from_the_raster_and_hex_views_and_undone_in_one_step() {
        let (stream, starts) = length_prefixed_stream();
        let original = stream.clone();
        let mut harness = harness_for(stream);
        {
            let (state, app) = harness.state_mut();
            state.grid.split.rule = grid::SplitRule::LengthField;
            state.grid.split.whole_document = true;
            state.grid.split.field = packets::split::LengthField { offset: 1, ..Default::default() };
            grid::split_now(state, app);
        }
        settle(&mut harness);
        let found: Vec<usize> = harness.state().0.packet_set().expect("frames").packets.iter().map(|p| p.offset).collect();
        assert_eq!(found, starts);

        harness.get_by_label("Raster").click();
        settle(&mut harness);
        assert_eq!(harness.state().0.grid.row_count(), 12);
        assert_eq!(harness.state().0.grid.column_count(), 3 + 7, "the longest frame has a 7-byte payload");
        let ruler = harness.state().0.grid.ruler.expect("the raster's ruler was drawn");
        click_at(&mut harness, ruler.column_centre(3));
        assert_eq!(harness.state().0.grid.columns, Some((3, 1)), "clicking the ruler selects that column");

        harness.get_by_label("Hex").click();
        settle(&mut harness);
        let ruler = harness.state().0.grid.ruler.expect("the hex grid's ruler was drawn");
        click_at(&mut harness, ruler.column_centre(4));
        assert_eq!(harness.state().0.grid.columns, Some((4, 1)));

        harness.state_mut().0.grid.operation_text = "FF".to_string();
        crate::actions::take_performed();
        harness.get_by_label("XOR column").click();
        settle(&mut harness);
        let performed = crate::actions::take_performed();
        let xor = performed.iter().find(|(method, _)| method == "packets.columns.apply").expect("the column operation");
        assert_eq!(xor.1, serde_json::json!({ "set": "set-1", "first": 4, "width": 1, "record_headers": false, "op": "xor", "key": "ff" }), "every packet, so none are named");
        let edited = harness.state_mut().1.document.read_range(0, original.len());
        for (at, (&now, &before)) in edited.iter().zip(&original).enumerate() {
            let in_column = at.checked_sub(4).is_some_and(|start| starts.contains(&start));
            let expected = if in_column { before ^ 0xFF } else { before };
            assert_eq!(now, expected, "byte {at:#x} (in the column: {in_column})");
        }

        harness.state_mut().1.undo();
        settle(&mut harness);
        assert_eq!(harness.state_mut().1.document.read_range(0, original.len()), original, "one undo restores every packet");
    }

    /// Press at `from`, drag to `to` and release, a frame at a time.
    fn drag_between(harness: &mut PanelHarness, from: egui::Pos2, to: egui::Pos2) {
        harness.hover_at(from);
        harness.step();
        harness.event(egui::Event::PointerButton { pos: from, button: egui::PointerButton::Primary, pressed: true, modifiers: egui::Modifiers::NONE });
        harness.step();
        harness.event(egui::Event::PointerMoved(from.lerp(to, 0.5)));
        harness.step();
        harness.event(egui::Event::PointerMoved(to));
        harness.step();
        harness.event(egui::Event::PointerButton { pos: to, button: egui::PointerButton::Primary, pressed: false, modifiers: egui::Modifiers::NONE });
        harness.step();
    }

    #[test]
    fn dragging_across_packets_selects_a_block_and_an_operation_changes_only_that_block() {
        let (stream, starts) = length_prefixed_stream();
        let original = stream.clone();
        let mut harness = harness_for(stream);
        {
            let (state, app) = harness.state_mut();
            state.grid.split.rule = grid::SplitRule::LengthField;
            state.grid.split.whole_document = true;
            state.grid.split.field = packets::split::LengthField { offset: 1, ..Default::default() };
            grid::split_now(state, app);
            state.grid.layout = grid::PacketLayout::Hex;
        }
        settle(&mut harness);
        let ruler = harness.state().0.grid.ruler.expect("the hex grid was drawn");
        // Rows are 16 points tall below the ruler; aim at the middle of a cell.
        let cell = |row: f32, column: usize| ruler.column_centre(column) + egui::vec2(0.0, 8.0 + 16.0 * row + 4.0);
        drag_between(&mut harness, cell(1.0, 1), cell(3.0, 2));
        assert_eq!(harness.state().0.grid.columns, Some((1, 2)), "columns 1 and 2");
        assert_eq!(harness.state().0.grid.block_rows, Some((1, 3)), "packets 2 to 4");
        assert!(harness.query_by_label_contains("Block: packets 2–4").is_some());

        harness.state_mut().0.grid.operation_text = "FF".to_string();
        crate::actions::take_performed();
        harness.get_by_label("XOR column").click();
        settle(&mut harness);
        let performed = crate::actions::take_performed();
        let xor = performed.iter().find(|(method, _)| method == "packets.columns.apply").expect("the column operation");
        assert_eq!(xor.1["indices"], serde_json::json!([1, 2, 3]), "the block's packets, by their index in the set");
        let edited = harness.state_mut().1.document.read_range(0, original.len());
        for (at, (&now, &before)) in edited.iter().zip(&original).enumerate() {
            let in_block = starts[1..4].iter().any(|&start| at == start + 1 || at == start + 2);
            assert_eq!(now, if in_block { before ^ 0xFF } else { before }, "byte {at:#x} (in the block: {in_block})");
        }
        harness.state_mut().1.undo();
        settle(&mut harness);
        assert_eq!(harness.state_mut().1.document.read_range(0, original.len()), original);
    }

    #[test]
    fn auto_detect_fills_in_the_length_field_and_clicking_a_hex_cell_selects_that_byte() {
        let (stream, starts) = length_prefixed_stream();
        let mut repeated = stream.clone();
        for _ in 0..4 {
            repeated.extend_from_slice(&stream);
        }
        let mut harness = harness_for(repeated);
        {
            let (state, app) = harness.state_mut();
            state.grid.split.whole_document = true;
            grid::detect_length_field(state, app);
            assert_eq!((state.grid.split.field.offset, state.grid.split.field.big_endian), (1, true), "{:?}", state.note.as_ref().map(|n| &n.text));
            grid::split_now(state, app);
            state.grid.layout = grid::PacketLayout::Hex;
        }
        settle(&mut harness);
        assert_eq!(harness.state().0.rows().len(), 60);
        let ruler = harness.state().0.grid.ruler.expect("the hex grid was drawn");
        // The second row's first payload byte: one row below the ruler, column 3.
        let cell = ruler.column_centre(3) + egui::vec2(0.0, 8.0 + 16.0 + 4.0);
        click_at(&mut harness, cell);
        let (state, app) = harness.state();
        assert_eq!(app.selection(), Some((starts[1] + 3, 1)));
        assert_eq!(state.focused_packet(), Some(1));
    }

    #[test]
    fn deleting_a_column_of_fixed_width_records_shortens_each_record_and_one_undo_restores_them() {
        let records: Vec<u8> = (0..40u8).collect();
        let mut harness = harness_for(records.clone());
        {
            let (state, app) = harness.state_mut();
            state.grid.split.rule = grid::SplitRule::FixedWidth;
            state.grid.split.whole_document = true;
            state.grid.split.row_width = 8;
            grid::split_now(state, app);
        }
        settle(&mut harness);
        {
            let (state, app) = harness.state_mut();
            state.grid.layout = grid::PacketLayout::Raster;
            grid::refresh_rows(state, app);
            state.grid.columns = Some((2, 3));
            crate::actions::take_performed();
            grid::delete_columns(state, app);
        }
        assert_eq!(
            crate::actions::take_performed(),
            [("packets.columns.delete".to_string(), serde_json::json!({ "set": "set-1", "first": 2, "width": 3, "record_headers": false }))]
        );
        settle(&mut harness);
        {
            let (state, app) = harness.state_mut();
            grid::refresh_rows(state, app);
            state.grid.columns = Some((0, 2));
            state.grid.block_rows = Some((1, 2));
            grid::copy_columns(state, app, &egui::Context::default(), true);
        }
        assert_eq!(
            crate::actions::take_performed(),
            [("packets.columns.read".to_string(), serde_json::json!({ "set": "set-1", "first": 0, "width": 2, "record_headers": false, "indices": [1, 2], "format": "csv" }))]
        );
        assert_eq!(harness.state().0.note.as_ref().map(|note| note.text.as_str()), Some("Copied columns +0..+2 of 2 packets."));
        let expected: Vec<u8> = records.chunks(8).flat_map(|record| [&record[..2], &record[5..]].concat()).collect();
        assert_eq!(harness.state_mut().1.document.read_range(0, 64), expected);
        let lengths: Vec<usize> = harness.state().0.packet_set().expect("records").packets.iter().map(|p| p.len).collect();
        assert_eq!(lengths, vec![5; 5], "the records are found again five bytes wide");
        harness.state_mut().1.undo();
        settle(&mut harness);
        assert_eq!(harness.state_mut().1.document.read_range(0, 64), records);
    }

    #[test]
    fn an_operation_on_a_field_changes_that_field_in_every_selected_packet() {
        let (document, at) = document_with_capture();
        let mut harness = harness_for(document);
        load_capture_into(&mut harness, at);
        settle(&mut harness);
        {
            let (state, app) = harness.state_mut();
            state.selected = BTreeSet::from([1, 2]);
            state.focus = Some(1);
            state.selected_field = Some((22, 2));
            state.operation_on_field = true;
            state.operation_text = "00 7B".to_string();
            view::apply_operation(state, app, &packets::edit::ByteOperation::Fill(vec![0x00, 0x7B]));
        }
        settle(&mut harness);
        let rows = harness.state().0.rows();
        assert!(rows[1].summary.info.contains("→ 123") && rows[2].summary.info.contains("→ 123"), "{:?}", rows.iter().map(|r| &r.summary.info).collect::<Vec<_>>());
        assert!(rows[0].summary.protocol == "DNS", "unselected packets are untouched");
    }

    /// Messages that each start with a sync word, a sequence number and a
    /// type, which the protocol analysis frames.
    fn sync_word_stream(messages: u8) -> Vec<u8> {
        let mut stream = Vec::new();
        for index in 0..messages {
            stream.extend_from_slice(&[0x7E, 0x7E, index, index % 3, 0x10, 0x20, 0x30, index ^ 0x5A]);
        }
        stream
    }

    /// Where the protocol analysis's messages are.
    fn fact_span(app: &ViewerApp) -> crate::bus::Span {
        let (fact, _) = app.bus.latest_from::<FramesDefined>(&app.document_id(), PROTOCOL_PRODUCER).expect("the analysis published its messages");
        fact.draft.span.expect("a span")
    }

    #[test]
    fn the_protocol_analysis_s_messages_reach_the_hidden_packet_viewer_through_the_bus() {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(sync_word_stream(40), "stream.bin".to_string());
        app.run_bus();
        open_protocol_messages(&mut app);
        assert!(app.bench.panels.packets.awaiting_protocol, "the analysis is started and waited for");
        let started = Instant::now();
        while app.bench.panels.packets.awaiting_protocol && started.elapsed() < JOB_TIMEOUT {
            thread::sleep(POLL_INTERVAL / 5);
            app.run_bus();
        }
        let (_, frames) = app.bus.latest_from::<FramesDefined>(&app.document_id(), PROTOCOL_PRODUCER).expect("the analysis published its messages");
        assert!(frames.framing.is_some(), "with the framing that cut them");
        let (total, span, framing) = (frames.total, fact_span(&app), frames.framing.clone());
        crate::actions::take_performed();
        // Asked for while the panel's state was lent out; done before the next frame.
        app.perform_waiting_actions();
        let performed = crate::actions::take_performed();
        assert_eq!(performed.len(), 1);
        assert_eq!(performed[0].0, "packets.sets.create");
        assert_eq!(
            performed[0].1,
            serde_json::json!({ "from": "protocol_framing", "start": span.start, "len": span.len, "framing": framing, "detect": true }),
            "the step says where the messages are and how they were cut"
        );
        let state = &app.bench.panels.packets;
        assert!(state.note.as_ref().is_none_or(|note| !note.is_error));
        let set = state.incoming.as_ref().expect("the messages wait to be dissected");
        assert_eq!(set.len(), total);
        assert!(matches!(set.recipe, Recipe::Framing { .. }), "split again from the document after edits");
        assert!(!state.raw.guesses.is_empty(), "with the fields the analysis guessed");
    }

    #[test]
    fn raw_frames_follow_their_template_applied_again_with_new_source_even_while_hidden() {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(vec![1, 0, 2, 0, 3, 0, 4, 0], "records.bin".to_string());
        app.bench.panels.packets.load(sources::split_fixed(0, 8, 2, LinkKind::Unknown).unwrap());
        let first = "endian little\nstruct Frame { n: u16 }\nroot Frame";
        choose_template(&mut app.bench.panels.packets, "Template: Frame", first);
        let generation = app.bench.panels.packets.raw_generation;
        // The person edits the template in the Template tool and applies it again.
        let edited = "endian little\nstruct Frame { low: u8\n high: u8 }\nroot Frame";
        app.apply_template_source(edited);
        app.run_bus();
        let state = &app.bench.panels.packets;
        assert_eq!(state.raw_template_source.as_deref(), Some(edited));
        assert!(state.raw_generation > generation, "the frames are decoded again");
        let other = "endian little\nstruct Other { n: u16 }\nroot Other";
        app.apply_template_source(other);
        app.run_bus();
        assert_eq!(app.bench.panels.packets.raw_template_source.as_deref(), Some(edited), "another template leaves the frames alone");
    }

    #[test]
    fn the_chosen_packet_s_fields_are_said_on_the_bus_for_the_reference_tab_even_while_hidden() {
        let (document, at) = document_with_capture();
        let mut harness = harness_for(document);
        load_capture_into(&mut harness, at);
        settle(&mut harness);
        let third = harness.state().0.packet_set().unwrap().packets[2].clone();
        hide_panel(&mut harness);
        let app = &mut harness.state_mut().1;
        app.set_cursor(third.offset + 3, false);
        app.run_bus();
        let (fact, decoded) = app.bus.latest_from::<FieldsDecoded>(&app.document_id(), PACKETS_PRODUCER).expect("the chosen packet's fields");
        assert_eq!(fact.draft.span, Some(crate::bus::Span { start: third.offset, len: third.len }));
        assert!(decoded.layers.iter().all(|layer| layer.offset >= third.offset), "at document offsets");
        let stack = crate::panel_reference::stack_at_cursor(app);
        assert!(stack.iter().any(|entry| entry.label == "IPv4"), "the Reference tab reads them: {:?}", stack.iter().map(|entry| &entry.label).collect::<Vec<_>>());

        // An edit inside the packet is dissected again, the panel still hidden.
        app.document.replace(third.offset + third.len - 1, 1, b"!");
        app.run_bus();
        app.run_bus();
        let (fact, _) = app.bus.latest_from::<FieldsDecoded>(&app.document_id(), PACKETS_PRODUCER).unwrap();
        assert!(!app.bus.is_stale(fact), "said again for the edited bytes");
    }

    #[test]
    fn splitting_the_selection_by_row_width_makes_an_api_packet_set_the_viewer_shows() {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(vec![0x42; 96], "records.bin".to_string());
        app.set_width(16);
        app.restore_selection(16, 64);
        crate::actions::take_performed();
        let split = crate::commands::commands().into_iter().find(|command| command.id == "tools.packets_rows").unwrap();
        (split.run)(&mut app, &egui::Context::default());
        let performed = crate::actions::take_performed();
        assert_eq!(performed.len(), 1);
        assert_eq!(performed[0].0, "packets.sets.create");
        assert_eq!(performed[0].1, serde_json::json!({"from": "split_fixed", "start": 16, "len": 64, "record_len": 16, "detect": true}), "the step says how to split and decode");
        let state = &app.bench.panels.packets;
        assert_eq!(state.incoming.as_ref().map(|set| set.len()), Some(4));
        assert_eq!(state.api_set.as_deref(), Some("set-1"), "the viewer knows the set's id for the methods on it");
        let listed = crate::api::call(&mut app, &crate::api::Caller::Panel, "packets.sets.list", serde_json::json!({})).unwrap();
        assert_eq!(listed["sets"][0]["count"], 4);
    }

    #[test]
    fn splitting_with_nothing_selected_says_so_in_the_viewer() {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(vec![0x42; 96], "records.bin".to_string());
        split_selection_by_row_width(&mut app);
        assert_eq!(app.bench.panels.packets.note.as_ref().map(|note| note.text.as_str()), Some("Select the records first."));
        assert!(crate::actions::take_performed().is_empty());
    }

    #[test]
    fn a_packet_set_made_through_the_api_shows_in_the_packet_viewer_with_its_decoding() {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(modbus_stream(4), "modbus.bin".to_string());
        let caller = crate::api::Caller::Mcp("test".into());
        let created = crate::api::call(&mut app, &caller, "packets.sets.create", serde_json::json!({"from": "length_field", "length_field": {"offset": 4, "encoding": "u16", "big_endian": true, "counts": "after_field"}, "decode_as": "modbus_tcp"})).unwrap();
        assert_eq!(created["count"], 4, "{created}");
        let state = &app.bench.panels.packets;
        assert_eq!(state.incoming.as_ref().map(|set| set.len()), Some(4), "loaded for the panel to dissect");
        assert_eq!(state.frame_choice, FrameChoice::Protocol(FrameProtocol::ModbusTcp));
        crate::api::call(&mut app, &caller, "packets.decode_as", serde_json::json!({"set": "set-1", "detect": false})).unwrap();
        assert_eq!(app.bench.panels.packets.frame_choice, FrameChoice::Raw, "a new decoding shows too");
    }

    /// An app showing `bytes`, with nothing performed yet.
    fn app_with(bytes: Vec<u8>) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes, "test.bin".to_string());
        app.run_bus();
        crate::actions::take_performed();
        app
    }

    /// What was performed since last asked, after carrying out what the
    /// viewer asked for while it was drawn.
    fn performed_after_drawing(app: &mut ViewerApp) -> Vec<(String, serde_json::Value)> {
        app.perform_waiting_actions();
        crate::actions::take_performed()
    }

    #[test]
    fn the_selection_becomes_a_set_of_one_packet_and_then_grows_by_one_packet_at_a_time() {
        let mut app = app_with(vec![0x42; 64]);
        app.restore_selection(4, 8);
        let add = crate::commands::commands().into_iter().find(|command| command.id == "tools.packets_selection").unwrap();
        (add.run)(&mut app, &egui::Context::default());
        assert_eq!(crate::actions::take_performed(), [("packets.sets.create".to_string(), serde_json::json!({ "from": "selection", "ranges": [[4, 8]], "detect": true }))]);
        app.restore_selection(20, 6);
        (add.run)(&mut app, &egui::Context::default());
        assert_eq!(crate::actions::take_performed(), [("packets.sets.add_packets".to_string(), serde_json::json!({ "set": "set-1", "ranges": [[20, 6]] }))]);
        let state = &app.bench.panels.packets;
        assert_eq!(state.incoming.as_ref().map(|set| set.len()), Some(2), "the set grew rather than being replaced");
        assert_eq!(state.api_set.as_deref(), Some("set-1"));
    }

    #[test]
    fn opening_a_capture_from_the_findings_makes_a_set_of_it() {
        let (document, at) = document_with_capture();
        let mut app = app_with(document);
        open_capture_at(&mut app, at);
        assert_eq!(crate::actions::take_performed(), [("packets.sets.create".to_string(), serde_json::json!({ "from": "capture", "start": at, "detect": true }))]);
        assert_eq!(app.bench.panels.packets.incoming.as_ref().map(|set| set.len()), Some(3));
        open_capture_at(&mut app, 3);
        assert!(app.bench.panels.packets.note.as_ref().is_some_and(|note| note.is_error), "no capture there is said in the viewer");
    }

    #[test]
    fn splitting_the_selection_by_length_or_at_a_delimiter_asks_for_a_set_once_the_viewer_is_drawn() {
        let mut app = app_with(b"one\r\ntwo\r\nthree\r\n".to_vec());
        app.restore_selection(0, 17);
        with_state(&mut app, |state, app| {
            let call = split_call(state, app, 5).map(|params| ("packets.sets.create", params));
            ask_for_set(state, app, call);
        });
        assert!(crate::actions::take_performed().is_empty(), "not while the viewer is drawn");
        assert_eq!(performed_after_drawing(&mut app), [("packets.sets.create".to_string(), serde_json::json!({ "from": "split_fixed", "start": 0, "len": 17, "record_len": 5, "detect": true }))]);
        assert_eq!(app.bench.panels.packets.incoming.as_ref().map(|set| set.len()), Some(4));
        with_state(&mut app, |state, app| {
            state.delimiter_text = "0D0A".to_string();
            let call = delimiter_call(state, app).map(|params| ("packets.sets.create", params));
            ask_for_set(state, app, call);
        });
        let performed = performed_after_drawing(&mut app);
        assert_eq!(performed[0].1, serde_json::json!({ "from": "pattern", "start": 0, "len": 17, "pattern": "0d0a", "pattern_mode": "separates", "detect": true }));
        let pieces: Vec<usize> = app.bench.panels.packets.incoming.as_ref().unwrap().packets.iter().map(|packet| packet.len).collect();
        assert_eq!(pieces, [3, 3, 5]);
        with_state(&mut app, |state, app| {
            state.delimiter_text = "zz".to_string();
            let call = delimiter_call(state, app).map(|params| ("packets.sets.create", params));
            ask_for_set(state, app, call);
        });
        assert!(app.bench.panels.packets.note.as_ref().is_some_and(|note| note.text.starts_with("The delimiter must be hex bytes")));
    }

    #[test]
    fn a_set_the_viewer_asked_for_that_cannot_be_made_is_said_in_the_viewer() {
        let mut harness = harness_for(vec![0u8; 8]);
        {
            let (state, app) = harness.state_mut();
            ask_after_drawing(state, app, "packets.sets.create", serde_json::json!({ "from": "capture", "start": 0 }), Expected::Set);
        }
        settle(&mut harness);
        let note = harness.state().0.note.as_ref().expect("a note");
        assert!(note.is_error && note.text.to_lowercase().contains("capture"), "{}", note.text);
    }

    #[test]
    fn the_split_rules_form_splits_through_the_api_and_says_how_the_range_split() {
        let mut harness = harness_for(modbus_stream(3));
        crate::actions::take_performed();
        split_modbus(&mut harness);
        let performed = crate::actions::take_performed();
        let create = performed.iter().find(|(method, _)| method == "packets.sets.create").expect("the split");
        assert_eq!(create.1["from"], "length_field");
        assert_eq!(create.1["length_field"]["offset"], 4);
        assert_eq!((create.1["start"].as_u64(), create.1["len"].as_u64()), (Some(0), Some(36)));
        let note = harness.state().0.note.as_ref().map(|note| note.text.clone()).unwrap_or_default();
        assert!(note.starts_with("Split 36 bytes at 0x0: 3 frames"), "{note}");
    }

    #[test]
    fn auto_detect_asks_the_api_for_the_length_field() {
        let (stream, _) = length_prefixed_stream();
        let mut app = app_with(stream.repeat(5));
        with_state(&mut app, |state, app| {
            state.grid.split.whole_document = true;
            grid::detect_length_field(state, app);
        });
        let performed = crate::actions::take_performed();
        assert_eq!(performed, [("packets.detect_length_field".to_string(), serde_json::json!({ "start": 0, "len": stream.len() * 5 }))]);
    }

    #[test]
    fn choosing_a_link_and_a_protocol_decodes_the_set_anew_keeping_the_packets_chosen() {
        let mut app = app_with(modbus_stream(4));
        crate::actions::take_performed();
        crate::api::call(&mut app, &crate::api::Caller::Panel, "packets.sets.create", serde_json::json!({ "from": "split_fixed", "record_len": 12 })).unwrap();
        app.bench.panels.packets.selected = BTreeSet::from([2]);
        app.bench.panels.packets.focus = Some(2);
        with_state(&mut app, |state, app| ask_to_decode_as(state, app, Decoding::Frames(FrameChoice::Protocol(FrameProtocol::ModbusTcp)), LinkChoice::RawFrames));
        assert_eq!(performed_after_drawing(&mut app), [("packets.decode_as".to_string(), serde_json::json!({ "set": "set-1", "link": "unknown", "protocol": "modbus_tcp" }))]);
        let state = &app.bench.panels.packets;
        assert_eq!((state.frame_choice, state.link_choice), (FrameChoice::Protocol(FrameProtocol::ModbusTcp), LinkChoice::RawFrames));
        assert_eq!((state.focus, state.selected_packets()), (Some(2), vec![2]), "the same set, decoded anew");
        with_state(&mut app, |state, app| ask_to_decode_as(state, app, shown_decoding(state), LinkChoice::Auto));
        assert_eq!(performed_after_drawing(&mut app)[0].1, serde_json::json!({ "set": "set-1", "link": null, "protocol": "modbus_tcp" }));
        let (name, _) = packet_sets::available_templates().into_iter().next().unwrap();
        with_state(&mut app, |state, app| ask_to_decode_as(state, app, Decoding::NamedTemplate(name.clone()), LinkChoice::Auto));
        assert_eq!(performed_after_drawing(&mut app)[0].1, serde_json::json!({ "set": "set-1", "link": null, "detect": false, "template_name": name }));
        assert_eq!(app.bench.panels.packets.raw_label, format!("Template: {name}"));
    }

    #[test]
    fn packets_read_from_another_document_are_found_again_in_the_one_shown() {
        let mut app = app_with(vec![7u8; 32]);
        crate::api::call(&mut app, &crate::api::Caller::Panel, "packets.sets.create", serde_json::json!({ "from": "split_fixed", "record_len": 8 })).unwrap();
        app.perform("documents.derive", serde_json::json!({ "start": 0, "len": 16 })).unwrap();
        app.bench.panels.packets.foreign_document = true;
        crate::actions::take_performed();
        with_state(&mut app, find_again_here);
        let derived = app.document_id();
        assert_eq!(performed_after_drawing(&mut app), [("packets.sets.refresh".to_string(), serde_json::json!({ "set": "set-1", "doc": derived }))]);
        let state = &app.bench.panels.packets;
        assert!(!state.foreign_document);
        assert_eq!(state.incoming.as_ref().map(|set| set.len()), Some(2), "16 bytes of 8-byte records");
    }

    #[test]
    fn decoding_with_tshark_is_asked_for_the_packets_shown_once_the_viewer_is_drawn() {
        let mut app = app_with(vec![7u8; 32]);
        crate::api::call(&mut app, &crate::api::Caller::Panel, "packets.sets.create", serde_json::json!({ "from": "split_fixed", "record_len": 8 })).unwrap();
        with_state(&mut app, |state, app| {
            state.rows = vec![PacketRow::default(); 4];
            state.visible = vec![1, 3];
            tshark_view::ask_to_decode(state, app, None);
            tshark_view::ask_to_decode(state, app, Some(2));
        });
        let asked: Vec<serde_json::Value> = app.actions_after_drawing.iter().map(|(_, params, _)| params.clone()).collect();
        assert_eq!(asked, [serde_json::json!({ "set": "set-1", "mode": "fill_gaps", "indices": [1, 3] }), serde_json::json!({ "set": "set-1", "mode": "fill_gaps", "indices": [2] })]);
        assert!(app.actions_after_drawing.iter().all(|(method, _, _)| method == "packets.tshark_decode"));
    }
}
