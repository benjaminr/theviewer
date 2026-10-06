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
use crate::api::workspace::WINDOW_DOCUMENT_ID;
use crate::app::ViewerApp;
use crate::bus::topics::{FramesDefined, ProtocolIdentified};
use crate::bus::window::job_finished;
use crate::bus::{Draft, Payload, Publisher};
use crate::dock::DockTab;
use crate::packets::sources::{self, CaptureLocation, MarkerMode, Recipe};
use crate::packets::{self, Detection, Dissection, Flow, FrameProtocol, Layer, LinkKind, PacketSet, RawFrames, SetHints, Summary};
use crate::parsers::captures::{CAPTURE_FINDING_IDS, GZIP_CAPTURE_FINDING_ID};
use crate::panel_packets_grid::{self as grid, GridState};
use crate::panel_packets_tshark::{self as tshark_view, TsharkState};
use crate::panel_packets_view as view;
use crate::plugin::{Category, Finding};
use crate::templates::{self, Template};
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
/// Most bytes of the selection read to split at a delimiter.
const SPLIT_READ_LIMIT: usize = 64 * 1024 * 1024;
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

    captures: Vec<CaptureLocation>,
    captures_pending: Option<Receiver<Vec<CaptureLocation>>>,
    captures_searched: bool,
    split_length: usize,
    delimiter_text: String,
    marker_starts_packet: bool,
    pub(crate) operation_text: String,
    pub(crate) operation_on_field: bool,
    awaiting_protocol: bool,
    pub(crate) note: Option<Note>,
    last_main_selection: Option<(usize, Option<usize>)>,
    pub(crate) scroll_to_row: Option<usize>,
    /// Whether the pointer was over the packet list last frame; the list is
    /// not scrolled under the user's hand.
    pub(crate) list_hovered: bool,
    /// The height of the pane, for sizing the list inside the scrolling panel.
    pub(crate) pane_height: f32,
    /// The raster and hex grids, the splitting rules and column selection.
    pub grid: GridState,
}

impl PacketsState {
    /// Show `set` in the viewer, replacing what was there. The packets are
    /// read and dissected the next time the panel is drawn.
    pub fn load(&mut self, set: PacketSet) {
        self.incoming = Some(set);
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
        self.is_reading() || self.awaiting_protocol || self.captures_pending.is_some() || self.tshark.is_busy()
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

    fn show_note(&mut self, text: impl Into<String>, is_error: bool) {
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

/// Load `set` into the packet viewer and bring its tab forward.
pub fn open_in_packet_viewer(app: &mut ViewerApp, set: PacketSet) {
    app.bench.panels.packets.load(set);
    app.dock.toggle(DockTab::Packets);
}

/// Load the protocol analysis's messages, starting the analysis first if it
/// has not been run.
pub fn open_protocol_messages(app: &mut ViewerApp) {
    with_state(app, load_from_protocol);
    app.dock.toggle(DockTab::Packets);
}

/// Load the capture whose header is at `offset`.
pub fn open_capture_at(app: &mut ViewerApp, offset: usize) {
    with_state(app, |state, app| load_capture(state, app, offset));
    app.dock.toggle(DockTab::Packets);
}

/// The start of a capture covering `offset`: a capture finding around it,
/// or a capture header right there.
pub fn capture_containing(app: &mut ViewerApp, offset: usize) -> Option<usize> {
    let finding = app.patterns_in(offset, offset + 1).find(|finding| is_capture_finding(&finding.id)).map(|finding| finding.start);
    finding.or_else(|| sources::capture_format(&app.document.read_range(offset, CAPTURE_HEADER_PROBE)).map(|_| offset))
}

/// Add the selection to the packet viewer as one packet.
pub fn add_selection_as_packet(app: &mut ViewerApp) {
    with_state(app, add_selection);
    app.dock.toggle(DockTab::Packets);
}

/// Cut the selection into packets one raster row long.
pub fn split_selection_by_row_width(app: &mut ViewerApp) {
    let stride = app.shape.row_stride();
    with_state(app, |state, app| split_selection_by_length(state, app, stride));
    app.dock.toggle(DockTab::Packets);
}

/// For `--tool packets`: load the first capture in the document, else the
/// protocol analysis's messages.
pub fn auto_load(app: &mut ViewerApp) {
    with_state(app, |state, app| {
        let bytes = app.document.read_range(0, SCAN_LIMIT);
        match sources::find_captures(&bytes, 0).first() {
            Some(capture) => load_capture(state, app, capture.offset),
            None => load_from_protocol(state, app),
        }
    });
}

/// Load the first capture in the document, unless packets are already
/// listed. For layouts that open on the packets, so they are not empty.
pub fn load_capture_if_empty(app: &mut ViewerApp) {
    with_state(app, |state, app| {
        if state.set.is_some() || state.incoming.is_some() {
            return;
        }
        let bytes = app.document.read_range(0, SCAN_LIMIT);
        if let Some(capture) = sources::find_captures(&bytes, 0).first() {
            load_capture(state, app, capture.offset);
        }
    });
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

fn load_from_protocol(state: &mut PacketsState, app: &mut ViewerApp) {
    analysis_tools::poll_protocol(app);
    let Some(protocol) = &app.bench.tools.protocol else {
        if !app.bench.tools.protocol_pending() {
            analysis_tools::start_protocol(app);
        }
        state.awaiting_protocol = true;
        state.show_note("Finding the message framing…", false);
        return;
    };
    let base = protocol.base;
    let mut set = match sources::from_messages(&protocol.report.messages, base, &format!("protocol messages at {base:#x}")) {
        Ok(set) => set,
        Err(_) => {
            state.awaiting_protocol = false;
            state.show_note("The protocol analysis found no messages to take packets from.", true);
            return;
        }
    };
    if let Some(candidate) = &protocol.report.framing {
        set.description = format!("{} messages, {}", set.len(), candidate.framing.describe());
        set.recipe = Recipe::Framing { start: base, len: protocol.bytes().len(), framing: candidate.framing.clone() };
    }
    let guesses = protocol.report.fields.clone();
    let suggestion = crate::protocol::to_template(&protocol.report);
    state.load(set);
    state.raw.guesses = guesses;
    state.suggested_template = suggestion;
}

/// Whether a finding is a capture the packet viewer can load.
fn is_capture_finding(id: &str) -> bool {
    CAPTURE_FINDING_IDS.contains(&id) || id == GZIP_CAPTURE_FINDING_ID
}

fn load_capture(state: &mut PacketsState, app: &mut ViewerApp, offset: usize) {
    let bytes = app.document.read_range(offset, CAPTURE_READ_LIMIT);
    if sources::gzip::looks_like(&bytes) {
        load_gzipped_capture(state, app, offset, &bytes);
        return;
    }
    match sources::from_capture(&bytes, offset) {
        Ok(set) => state.load(set),
        Err(error) => state.show_note(error.to_string(), true),
    }
}

/// A capture compressed with gzip: its packets are not ranges of the
/// document, so the decompressed capture is opened as a document of its own
/// (Back returns to this one) and its packets are read from there.
fn load_gzipped_capture(state: &mut PacketsState, app: &mut ViewerApp, offset: usize, bytes: &[u8]) {
    let capture = match sources::gzip::gunzip(bytes, offset) {
        Ok(capture) => capture,
        Err(error) => {
            state.show_note(error.to_string(), true);
            return;
        }
    };
    let set = match sources::from_capture(&capture.data, 0) {
        Ok(set) => set,
        Err(error) => {
            state.show_note(format!("The gzip stream at {offset:#x} decompresses to a {} header, but: {error}", capture.format.label()), true);
            return;
        }
    };
    let name = format!("{} › {} capture decompressed from {offset:#x}", app.display_name(), capture.format.label());
    let truncated = capture.truncated;
    app.open_derived(capture.data, name);
    state.load(set);
    if truncated {
        let limit = crate::compress::human_bytes(sources::gzip::MAX_GUNZIPPED_LEN);
        state.show_note(format!("Only the first {limit} of the decompressed capture were opened."), false);
    }
}

fn add_selection(state: &mut PacketsState, app: &mut ViewerApp) {
    let Some((start, len)) = app.selection() else {
        state.show_note("Select the packet's bytes first.", true);
        return;
    };
    let link = state.link_choice.apply(LinkKind::Unknown);
    let packet = packets::Packet::new(start, len, link, format!("range {start:#x}"));
    // Add to what is shown (or what is about to be), so packets can be
    // gathered one at a time.
    let mut set = match state.incoming.take().or_else(|| state.set.clone()) {
        Some(mut set) => {
            set.recipe = Recipe::Fixed;
            set.name = "packets added by hand".to_string();
            set.description = format!("{} ranges added by hand", set.len() + 1);
            set
        }
        None => match sources::single(start, len, link) {
            Ok(set) => {
                state.load(set);
                return;
            }
            Err(error) => {
                state.show_note(error.to_string(), true);
                return;
            }
        },
    };
    if !set.push(packet) {
        state.show_note(set.cap_note().unwrap_or_default(), true);
        return;
    }
    let (selected, choice, template, label) = (state.selected.clone(), state.frame_choice, state.raw.template.clone(), state.raw_label.clone());
    state.load(set);
    // The set grows rather than being replaced, so its decoding stays.
    state.selected = selected;
    state.frame_choice = choice;
    state.raw.template = template;
    state.raw_label = label;
}

fn split_selection_by_length(state: &mut PacketsState, app: &mut ViewerApp, record_len: usize) {
    let Some((start, len)) = app.selection() else {
        state.show_note("Select the records first.", true);
        return;
    };
    match sources::split_fixed(start, len, record_len, state.link_choice.apply(LinkKind::Unknown)) {
        Ok(set) => state.load(set),
        Err(error) => state.show_note(error.to_string(), true),
    }
}

fn split_selection_by_delimiter(state: &mut PacketsState, app: &mut ViewerApp) {
    let Some((start, len)) = app.selection() else {
        state.show_note("Select the bytes to split first.", true);
        return;
    };
    let delimiter = match packets::parse_hex(&state.delimiter_text) {
        Ok(delimiter) => delimiter,
        Err(reason) => {
            state.show_note(format!("The delimiter must be hex bytes, such as 0D0A: {reason}."), true);
            return;
        }
    };
    let bytes = app.document.read_range(start, len.min(SPLIT_READ_LIMIT));
    let mode = if state.marker_starts_packet { MarkerMode::StartsPacket } else { MarkerMode::Separator };
    match sources::split_by_marker(&bytes, start, &delimiter, mode, state.link_choice.apply(LinkKind::Unknown)) {
        Ok(set) => state.load(set),
        Err(error) => state.show_note(error.to_string(), true),
    }
}

/// Look for captures in the first part of the document and inside any
/// capture findings, on a background thread.
fn start_capture_search(state: &mut PacketsState, app: &mut ViewerApp) {
    let mut regions = vec![(0usize, app.document.read_range(0, SCAN_LIMIT))];
    let found: Vec<(usize, usize)> = app.patterns_in(SCAN_LIMIT, usize::MAX).filter(|f| is_capture_finding(&f.id)).map(|f| (f.start, f.len)).collect();
    for (start, len) in found {
        regions.push((start, app.document.read_range(start, len.min(CAPTURE_READ_LIMIT))));
    }
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut captures: Vec<CaptureLocation> = Vec::new();
        for (base, bytes) in &regions {
            for capture in sources::find_captures(bytes, *base) {
                if !captures.iter().any(|known| known.offset == capture.offset) {
                    captures.push(capture);
                }
            }
        }
        let _ = sender.send(captures);
    });
    state.captures_pending = Some(receiver);
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
    let job = app.publish_job_started("dissection", "Dissecting packets");
    let publisher = app.bus.publisher();
    thread::spawn(move || {
        raw.hints = SetHints::learn(links.iter().enumerate().map(|(index, &link)| (bytes.packet(index), link)));
        let detection = detect_frames(&bytes, &links, choice, detection_allowed);
        raw.decode_as = match choice {
            FrameChoice::Protocol(protocol) => Some(protocol),
            FrameChoice::Default if detection_allowed => detection.protocol(),
            FrameChoice::Detect => detection.protocol(),
            FrameChoice::Default | FrameChoice::Raw => None,
        };
        let rows = links
            .iter()
            .enumerate()
            .map(|(index, &link)| {
                let dissection = packets::dissect_with(bytes.packet(index), link, &raw);
                PacketRow::from(dissection)
            })
            .collect();
        publish_packet_facts(&publisher, &set, &links, detection, snapshot.version);
        publisher.publish(job_finished(&job, "Dissecting packets", true, format!("{} packets from {}", set.packets.len(), set.name)));
        let _ = sender.send(DissectionJob { set, bytes: Arc::new(bytes), rows, snapshot, hints: raw.hints, decode_as: raw.decode_as, detection });
    });
    state.pending = Some(receiver);
}

/// What publishes the packet viewer's frames and the protocol detected for them.
pub(crate) const PACKETS_PRODUCER: &str = "panel:packets";

/// Publish where the packets are and, when detection found one, the
/// protocol of the frames of unknown format.
fn publish_packet_facts(publisher: &Publisher, set: &PacketSet, links: &[LinkKind], detection: FrameDetection, version: u64) {
    let start = set.packets.iter().map(|packet| packet.offset).min().unwrap_or(0);
    let end = set.packets.iter().map(|packet| packet.end()).max().unwrap_or(start);
    let draft = |payload| Draft::new(PACKETS_PRODUCER, payload).about(WINDOW_DOCUMENT_ID, version).span(start, end - start);
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

/// Dissect the shown packets again, for a new link type or decoding.
pub(crate) fn redissect(state: &mut PacketsState, app: &mut ViewerApp) {
    if let Some(set) = state.incoming.take().or_else(|| state.set.clone()) {
        start_dissection(state, app, set);
    }
}

fn poll_dissection(state: &mut PacketsState, ctx: &egui::Context) {
    let Some(receiver) = &state.pending else { return };
    match receiver.try_recv() {
        Ok(job) => {
            state.pending = None;
            install(state, job);
        }
        Err(TryRecvError::Empty) => ctx.request_repaint_after(POLL_INTERVAL),
        Err(TryRecvError::Disconnected) => {
            state.pending = None;
            state.show_note("Dissecting the packets stopped unexpectedly.", true);
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
}

/// When the main view's cursor moves into a packet, select that packet (and
/// note the field under the cursor), scrolling the list only when the user
/// is not working in it.
fn follow_main_selection(state: &mut PacketsState, app: &ViewerApp) {
    let current = (app.cursor, app.anchor);
    if state.last_main_selection == Some(current) {
        return;
    }
    state.last_main_selection = Some(current);
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
}

/// The layers of the viewer's packet holding document offset `position`:
/// the selected packet's dissection when it is current, otherwise that
/// packet dissected afresh. `None` when the viewer holds no such packet.
pub(crate) fn layers_at(app: &mut ViewerApp, position: usize) -> Option<PacketLayers> {
    let state = &app.bench.panels.packets;
    if state.foreign_document {
        return None;
    }
    let index = state.packet_at(position)?;
    let packet = state.set.as_ref()?.packets.get(index)?.clone();
    let version = app.document.version();
    if let Some(detail) = &state.detail
        && detail.index == index
        && detail.version == version
        && detail.link_choice == state.link_choice
        && detail.raw_generation == state.raw_generation
        && detail.tshark_generation == state.tshark.generation
    {
        return Some(PacketLayers::from_dissection(packet.offset, packet.len, &detail.dissection));
    }
    let link = state.link_choice.apply(packet.link);
    let raw = state.raw.clone();
    let unchanged = state.built.is_some_and(|built| built.version == version);
    let bytes = app.document.read_range(packet.offset, packet.len.min(PACKET_READ_LIMIT));
    let mut dissection = packets::dissect_with(&bytes, link, &raw);
    if unchanged {
        dissection = tshark_view::merged(&app.bench.panels.packets, index, dissection);
    }
    Some(PacketLayers::from_dissection(packet.offset, packet.len, &dissection))
}

/// Note the main view's selection as one the panel made, so it is not
/// followed back.
pub(crate) fn remember_main_selection(state: &mut PacketsState, app: &ViewerApp) {
    state.last_main_selection = Some((app.cursor, app.anchor));
}

/// Select document bytes in the main view and bring them into view.
pub(crate) fn select_in_document(state: &mut PacketsState, app: &mut ViewerApp, start: usize, len: usize, title: String) {
    let finding = Finding::new("packet", "packets", Category::Protocol, start, len.max(1)).title(title);
    app.select_pattern(&finding);
    remember_main_selection(state, app);
}

fn poll_protocol_wait(state: &mut PacketsState, app: &mut ViewerApp, ctx: &egui::Context) {
    if !state.awaiting_protocol {
        return;
    }
    analysis_tools::poll_protocol(app);
    if app.bench.tools.protocol.is_some() {
        state.awaiting_protocol = false;
        state.note = None;
        load_from_protocol(state, app);
    } else if !app.bench.tools.protocol_pending() {
        state.awaiting_protocol = false;
        state.show_note("The protocol analysis stopped without a result.", true);
    } else {
        ctx.request_repaint_after(POLL_INTERVAL);
    }
}

fn poll_captures(state: &mut PacketsState, ctx: &egui::Context) {
    let Some(receiver) = &state.captures_pending else { return };
    match receiver.try_recv() {
        Ok(captures) => {
            state.captures = captures;
            state.captures_pending = None;
        }
        Err(TryRecvError::Empty) => ctx.request_repaint_after(POLL_INTERVAL),
        Err(TryRecvError::Disconnected) => state.captures_pending = None,
    }
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
    poll_dissection(state, &ctx);
    poll_captures(state, &ctx);
    poll_protocol_wait(state, app, &ctx);
    tshark_view::poll(state, app, &ctx);
    if let Some(set) = state.incoming.take() {
        start_dissection(state, app, set);
    }
    follow_document(state, app, &ctx);
    follow_main_selection(state, app);
    refresh_filter(state);
    tshark_view::decode_automatically(state, app);
    refresh_detail(state, app);

    state.pane_height = ui.available_height();
    egui::ScrollArea::vertical().id_salt("packets-panel").auto_shrink([false, false]).show(ui, |ui| show_body(state, app, ui));
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
        let searching = state.captures_pending.is_some();
        if ui.add_enabled(!searching, egui::Button::new("Find captures")).on_hover_text("Look for captures inside the document: pcap, pcapng, snoop, Network Monitor 2.x and ERF, and any of them compressed with gzip").clicked() {
            start_capture_search(state, app);
        }
        ui.menu_button("From the selection", |ui| {
            if !has_selection {
                ui.label(RichText::new("Select some bytes in the view first.").color(theme::TEXT_DIM));
            }
            if ui.add_enabled(has_selection, egui::Button::new("Selection as one packet")).clicked() {
                add_selection(state, app);
                ui.close();
            }
            if ui.add_enabled(has_selection, egui::Button::new(format!("Split by row width ({stride} B)"))).clicked() {
                split_selection_by_length(state, app, stride);
                ui.close();
            }
            ui.separator();
            ui.horizontal(|ui| {
                ui.add(egui::DragValue::new(&mut state.split_length).range(1..=1_048_576).suffix(" B"));
                if ui.add_enabled(has_selection, egui::Button::new("Split by length")).clicked() {
                    let length = state.split_length;
                    split_selection_by_length(state, app, length);
                    ui.close();
                }
            });
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut state.delimiter_text).hint_text("hex, e.g. 0D0A").desired_width(110.0));
                if ui.add_enabled(has_selection, egui::Button::new("Split by delimiter")).clicked() {
                    split_selection_by_delimiter(state, app);
                    ui.close();
                }
            });
            ui.checkbox(&mut state.marker_starts_packet, "The delimiter starts each packet (a sync word)")
                .on_hover_text("Keep the bytes at the start of each packet instead of dropping them between packets");
        });
        view::start_row_unless_fits(ui, view::combo_width(ui));
        egui::ComboBox::from_id_salt("packets-link").selected_text(state.link_choice.label()).show_ui(ui, |ui| {
            for choice in LinkChoice::ALL {
                if ui.selectable_value(&mut state.link_choice, choice, choice.label()).changed() {
                    redo = true;
                }
            }
        });
        view::start_row_unless_fits(ui, view::combo_width(ui));
        show_frame_decoding(state, app, ui);
    });
    if redo {
        state.raw_generation += 1;
        redissect(state, app);
    }
}

/// The "Decode frames as" choice: detection, each protocol, the field
/// guesses and the templates.
fn show_frame_decoding(state: &mut PacketsState, app: &ViewerApp, ui: &mut Ui) {
    let detection_allowed = app.preferences.detect_frame_protocols;
    let detected_label = detection_label(state.frame_detection);
    let mut chosen = None;
    egui::ComboBox::from_id_salt("packets-raw-template").selected_text(frame_decoding_label(state, detection_allowed)).show_ui(ui, |ui| {
        let detecting = matches!(state.frame_choice, FrameChoice::Detect) || (detection_allowed && state.frame_choice == FrameChoice::Default);
        let detect_label = if detection_allowed { detected_label.as_str() } else { "Detect now" };
        if ui.selectable_label(detecting, detect_label).on_hover_text("Find out which protocol the frames are from a sample of them, and decode them as it").clicked() {
            chosen = Some(FrameChoice::Detect);
        }
        for protocol in FrameProtocol::ALL {
            if ui.selectable_label(state.frame_choice == FrameChoice::Protocol(protocol), protocol.label()).clicked() {
                chosen = Some(FrameChoice::Protocol(protocol));
            }
        }
        ui.separator();
        let raw_chosen = !detecting && matches!(state.frame_choice, FrameChoice::Default | FrameChoice::Raw);
        if ui.selectable_label(raw_chosen && state.raw.template.is_none(), FIELD_GUESSES).on_hover_text("The fields the protocol analysis guessed").clicked() {
            chosen = Some(FrameChoice::Raw);
        }
        if let Some(source) = state.suggested_template.clone()
            && ui.selectable_label(raw_chosen && state.raw_label == PROTOCOL_TEMPLATE, PROTOCOL_TEMPLATE).clicked()
        {
            choose_template(state, PROTOCOL_TEMPLATE, &source);
        }
        for (name, source) in available_templates() {
            let label = format!("Template: {name}");
            if ui.selectable_label(raw_chosen && state.raw_label == label, &label).clicked() {
                choose_template(state, &label, &source);
            }
        }
    });
    if let Some(choice) = chosen {
        state.choose_frame_decoding(choice);
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
fn choose_template(state: &mut PacketsState, label: &str, source: &str) {
    match Template::parse(source) {
        Ok(template) => {
            state.choose_frame_decoding(FrameChoice::Raw);
            state.raw.template = Some(template);
            state.raw_label = label.to_string();
        }
        Err(error) => state.show_note(format!("The template could not be read: {error}"), true),
    }
}

/// The built-in templates and the user's, as (name, source).
fn available_templates() -> Vec<(String, String)> {
    let mut all: Vec<(String, String)> = templates::builtin_templates().into_iter().map(|(name, source)| (name.to_string(), source.to_string())).collect();
    if let Some(dir) = templates::default_dir() {
        for (name, result) in templates::load_dir(&dir) {
            if result.is_ok()
                && let Ok(source) = std::fs::read_to_string(dir.join(format!("{name}.tpl")))
            {
                all.push((name, source));
            }
        }
    }
    all
}

fn show_captures(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    if state.captures_pending.is_some() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new("Looking for captures…").color(theme::TEXT_DIM));
        });
        return;
    }
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
            if ui.small_button(capture.describe()).on_hover_text(hint).clicked() {
                chosen = Some(capture.offset);
            }
        }
    });
    if let Some(offset) = chosen {
        load_capture(state, app, offset);
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
                state.foreign_document = false;
                let snapshot = Snapshot { version: app.document.version(), document_len: app.document.len() };
                refresh_from_document(state, app, snapshot);
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
            |ui, (state, app): &mut (PacketsState, ViewerApp)| show_packets(state, app, ui),
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

    fn load_capture_into(harness: &mut PanelHarness, at: usize) {
        let (state, app) = harness.state_mut();
        let bytes = app.document.read_range(at, 4096);
        state.load(sources::from_capture(&bytes, at).expect("a capture"));
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
        harness.get_by_label("Find captures").click();
        settle(&mut harness);
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
        harness.get_by_label_contains("snoop (gzip) at 0x0").click();
        settle(&mut harness);
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
        {
            let (state, app) = harness.state_mut();
            state.selected = BTreeSet::from([1]);
            state.focus = Some(1);
            view::delete_selected_packets(state, app);
        }
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
        harness.get_by_label("XOR column").click();
        settle(&mut harness);
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
        harness.get_by_label("XOR column").click();
        settle(&mut harness);
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
            grid::delete_columns(state, app);
        }
        settle(&mut harness);
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
}
