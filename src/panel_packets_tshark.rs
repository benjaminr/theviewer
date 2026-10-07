//! Decoding the packet viewer's packets with Wireshark's tshark.
//!
//! Only when tshark is installed, and only when the user clicks "Decode with
//! tshark" or has turned on "Use tshark when installed" in Settings, the shown
//! packets (or the one in detail) are written to a temporary pcap file with
//! their own link type and handed to tshark, always with `-n`, on a
//! background thread that can be cancelled and is stopped after a time limit.
//! Its layers are merged into ours ([`crate::packets::tshark_layers`]):
//! where our dissector stops, or for every layer when the user asks. Where
//! ours found no addresses (frames of a link type we read only as raw
//! bytes), the list's Source, Destination and flow come from tshark, with a
//! note in the packet's detail saying so. The results belong to one reading of the packets and are dropped when the
//! packets are read again, after an edit to the document for example.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, RichText, Ui};

use crate::api::packet_sets::{TsharkPacket, TsharkResult, TsharkUse};
use crate::app::ViewerApp;
use crate::bus::{JobHandle, Payload};
use crate::bus::topics::{FramesDefined, ProtocolIdentified};
use crate::packets::tshark::{self, RunLimits};
use crate::packets::tshark_layers::{self, TsharkLayers, TsharkMode};
use crate::packets::{self, Dissection, ExportPacket, LinkKind, RawFrames};
use crate::panel_packets::{LinkChoice, POLL_INTERVAL, PacketBytes, PacketRow, PacketsState};
use crate::theme;

/// Most packets handed to tshark at once.
pub const MAX_TSHARK_PACKETS: usize = 5_000;
/// tshark is stopped after this long.
const TSHARK_TIMEOUT: Duration = Duration::from_secs(120);
/// tshark is stopped once it has written this much.
const TSHARK_OUTPUT_LIMIT: usize = 512 * 1024 * 1024;
/// About how many protocols tshark dissects, for the hint shown when it is
/// not installed.
const TSHARK_PROTOCOLS: &str = "3,000";

/// tshark's part of the packet viewer.
#[derive(Default)]
pub struct TsharkState {
    /// The tshark found for a path setting, so the disk is searched once.
    found: Option<(String, Option<PathBuf>)>,
    /// Whether tshark's layers fill our gaps or replace ours.
    pub(crate) mode: TsharkMode,
    job: Option<Job>,
    /// tshark's layers per packet, for one reading of the packets.
    pub(crate) decodes: Option<Decodes>,
    /// Counts changes to `decodes` and `mode`, so the detail is merged again.
    pub(crate) generation: u64,
    pub(crate) error: Option<String>,
    /// The reading of the packets that was decoded automatically, so it is
    /// decoded once.
    auto_decoded: Option<u64>,
}

/// tshark's layers for packets of one reading of the packet set.
pub(crate) struct Decodes {
    set_generation: u64,
    packets: HashMap<usize, TsharkLayers>,
}

struct Job {
    /// The job's id, for `jobs.cancel`.
    id: String,
    receiver: Receiver<Result<Finished, String>>,
    done: Arc<AtomicUsize>,
    total: usize,
    set_generation: u64,
}

/// What a finished run gives back.
pub(crate) struct Finished {
    pub packets: HashMap<usize, TsharkLayers>,
    rows: Vec<(usize, PacketRow)>,
    pub warning: Option<String>,
}

/// One packet to decode.
pub(crate) struct Request {
    pub index: usize,
    pub bytes: Vec<u8>,
    pub original_len: usize,
    pub timestamp: Option<f64>,
    /// The tcpdump.org LINKTYPE number tshark is told.
    pub link_type: u32,
    /// The link type our dissector uses.
    pub link: LinkKind,
}

/// What is said when tshark cannot be found.
pub const NOT_FOUND: &str = "tshark was not found. Install Wireshark, or set where tshark is in Settings.";

impl TsharkState {
    /// Where tshark is, for the path set in Settings (empty: look for it).
    pub fn program(&mut self, preferred_path: &str) -> Option<PathBuf> {
        if self.found.as_ref().is_none_or(|(path, _)| path != preferred_path) {
            let preferred = (!preferred_path.trim().is_empty()).then(|| PathBuf::from(preferred_path.trim()));
            self.found = Some((preferred_path.to_string(), tshark::find_tshark(preferred.as_deref())));
        }
        self.found.as_ref().and_then(|(_, found)| found.clone())
    }

    pub fn is_busy(&self) -> bool {
        self.job.is_some()
    }

    /// tshark's layers for packet `index` of the reading `set_generation`.
    fn layers_for(&self, set_generation: u64, index: usize) -> Option<&TsharkLayers> {
        self.decodes.as_ref().filter(|decodes| decodes.set_generation == set_generation).and_then(|decodes| decodes.packets.get(&index))
    }

    /// How many packets of the reading `set_generation` tshark decoded.
    pub fn decoded_count(&self, set_generation: u64) -> usize {
        self.decodes.as_ref().filter(|decodes| decodes.set_generation == set_generation).map_or(0, |decodes| decodes.packets.len())
    }
}

/// Our dissection of packet `index` with tshark's layers merged in, when
/// tshark decoded that packet of the current reading.
pub fn merged(state: &PacketsState, index: usize, dissection: Dissection) -> Dissection {
    match state.tshark.layers_for(state.set_generation, index) {
        Some(layers) => tshark_layers::merge(dissection, layers, state.tshark.mode),
        None => dissection,
    }
}

/// The packets to decode: `indices`, or the shown ones, at most
/// [`MAX_TSHARK_PACKETS`].
fn requests(state: &PacketsState, indices: Option<Vec<usize>>) -> Vec<Request> {
    let Some(set) = &state.set else { return Vec::new() };
    let indices: Vec<usize> = indices.unwrap_or_else(|| state.visible.clone()).into_iter().take(MAX_TSHARK_PACKETS).collect();
    indices
        .into_iter()
        .filter_map(|index| {
            let packet = set.packets.get(index)?;
            let link = state.rows.get(index).map_or_else(|| state.link_choice.apply(packet.link), |row| row.link);
            let link_type = if state.link_choice == LinkChoice::Auto { packet.link_type } else { link.pcap_link_type() };
            Some(Request { index, bytes: state.bytes.packet(index).to_vec(), original_len: packet.len, timestamp: packet.timestamp, link_type, link })
        })
        .collect()
}

/// What `packets.tshark_decode` does in the window for the set the panel
/// shows: decode packets `indices` (the shown ones when `None`) with
/// tshark's layers merged as `mode` says, and return the job's id.
/// `finished` is also handed tshark's layers when the run ends well, so the
/// API's set can filter on them too.
pub fn start_for(app: &mut ViewerApp, indices: Option<Vec<usize>>, mode: TsharkMode, finished: Option<OnFinished>) -> String {
    let mut state = std::mem::take(&mut app.bench.panels.packets);
    if state.tshark.mode != mode {
        state.tshark.mode = mode;
        remerge_rows(&mut state);
    }
    let job = start_with(&mut state, app, indices, finished);
    app.bench.panels.packets = state;
    job
}

/// Start decoding with tshark: packets `indices`, or the shown packets.
/// Returns the job's id; when tshark is missing or there is nothing to
/// decode, the job has already failed and the panel says why.
fn start(state: &mut PacketsState, app: &mut ViewerApp, indices: Option<Vec<usize>>) -> String {
    start_with(state, app, indices, None)
}

/// What else is told of tshark's layers, by packet index, when a run ends well.
pub type OnFinished = Box<dyn FnOnce(&HashMap<usize, TsharkLayers>) + Send>;

fn start_with(state: &mut PacketsState, app: &mut ViewerApp, indices: Option<Vec<usize>>, on_finished: Option<OnFinished>) -> String {
    let job = app.start_job("tshark", "Decoding with tshark");
    let id = job.id().to_string();
    let Some(program) = state.tshark.program(&app.preferences.tshark_path) else {
        state.tshark.error = Some(NOT_FOUND.to_string());
        job.finish(false, NOT_FOUND);
        return id;
    };
    if let Some(running) = state.tshark.job.take() {
        app.bus.jobs_mut().cancel(&running.id);
    }
    let requests = requests(state, indices);
    if requests.is_empty() {
        state.tshark.error = Some("No packets to decode.".to_string());
        job.finish(false, "no packets to decode");
        return id;
    }
    let (sender, receiver) = mpsc::channel();
    let done = Arc::new(AtomicUsize::new(0));
    let total = requests.len();
    let (raw, mode) = (state.raw.clone(), state.tshark.mode);
    let thread_done = Arc::clone(&done);
    thread::spawn(move || {
        let finished = run(&program, requests, &raw, mode, &job, &thread_done);
        match &finished {
            Ok(finished) => {
                if let Some(on_finished) = on_finished {
                    on_finished(&finished.packets);
                }
                job.finish_with(true, format!("{} packets decoded", finished.packets.len()), serde_json::to_value(finished.result()).ok());
            }
            Err(error) => job.finish(false, error.clone()),
        }
        let _ = sender.send(finished);
    });
    state.tshark.error = None;
    state.tshark.job = Some(Job { id: id.clone(), receiver, done, total, set_generation: state.set_generation });
    id
}

impl Finished {
    /// The job's result: the protocols tshark named in each packet.
    pub fn result(&self) -> TsharkResult {
        let mut packets: Vec<TsharkPacket> = self.packets.iter().map(|(&index, layers)| TsharkPacket { index: index as u64, protocols: layers.protocols.clone() }).collect();
        packets.sort_by_key(|packet| packet.index);
        TsharkResult { packets, warning: self.warning.clone() }
    }
}

/// Run tshark once per link type and merge its layers into ours.
pub(crate) fn run(program: &std::path::Path, requests: Vec<Request>, raw: &RawFrames, mode: TsharkMode, job: &JobHandle, done: &AtomicUsize) -> Result<Finished, String> {
    let cancel = job.cancel_flag();
    let total = requests.len() as u64;
    let mut by_link_type: BTreeMap<u32, Vec<&Request>> = BTreeMap::new();
    for request in &requests {
        by_link_type.entry(request.link_type).or_default().push(request);
    }
    let limits = RunLimits { timeout: TSHARK_TIMEOUT, max_output_bytes: TSHARK_OUTPUT_LIMIT, max_packets: MAX_TSHARK_PACKETS };
    let mut finished = Finished { packets: HashMap::new(), rows: Vec::new(), warning: None };
    for (link_type, group) in by_link_type {
        let export: Vec<ExportPacket> = group.iter().map(|request| ExportPacket { bytes: &request.bytes, original_len: request.original_len, timestamp: request.timestamp, link: request.link }).collect();
        let mut position = 0;
        let outcome = tshark::decode_packets(program, &export, link_type, &limits, &cancel, |decoded| {
            if let Some(request) = group.get(position)
                && decoded.captured_len == request.bytes.len()
            {
                let layers = tshark_layers::to_layers(&decoded, request.bytes.len());
                let ours = packets::dissect_with(&request.bytes, request.link, raw);
                finished.rows.push((request.index, PacketRow::from(tshark_layers::merge(ours, &layers, mode))));
                finished.packets.insert(request.index, layers);
            }
            position += 1;
            let so_far = done.fetch_add(1, Ordering::Relaxed) + 1;
            job.progress(so_far as u64, Some(total));
        });
        match outcome {
            Ok(outcome) => finished.warning = finished.warning.or(outcome.warning),
            Err(error) if finished.packets.is_empty() => return Err(error.to_string()),
            Err(error) => finished.warning = Some(error.to_string()),
        }
    }
    Ok(finished)
}

/// Take a finished run's results, if they still describe the packets shown.
pub fn poll(state: &mut PacketsState, app: &ViewerApp, ctx: &egui::Context) {
    let Some(job) = &state.tshark.job else { return };
    let finished = match job.receiver.try_recv() {
        Ok(finished) => finished,
        Err(TryRecvError::Empty) => {
            ctx.request_repaint_after(POLL_INTERVAL);
            return;
        }
        Err(TryRecvError::Disconnected) => Err("Decoding with tshark stopped unexpectedly.".to_string()),
    };
    let set_generation = job.set_generation;
    state.tshark.job = None;
    match finished {
        Err(error) => state.tshark.error = Some(error),
        Ok(_) if set_generation != state.set_generation => {}
        Ok(finished) => {
            state.tshark.error = finished.warning.map(|warning| format!("tshark: {warning}"));
            for (index, row) in finished.rows {
                if let Some(slot) = state.rows.get_mut(index) {
                    *slot = row;
                }
            }
            let decodes = state.tshark.decodes.get_or_insert_with(|| Decodes { set_generation, packets: HashMap::new() });
            if decodes.set_generation != set_generation {
                *decodes = Decodes { set_generation, packets: HashMap::new() };
            }
            decodes.packets.extend(finished.packets);
            state.tshark.generation += 1;
            state.rows_changed();
            publish_protocols(state, app);
        }
    }
}

/// Publish the protocol tshark named most often as the innermost layer of
/// the packets it decoded.
fn publish_protocols(state: &PacketsState, app: &ViewerApp) {
    let (Some(decodes), Some(set)) = (&state.tshark.decodes, &state.set) else { return };
    let mut counts: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (&index, layers) in &decodes.packets {
        if let Some(innermost) = layers.protocols.last() {
            counts.entry(innermost.as_str()).or_default().push(index);
        }
    }
    let Some((protocol, mut indices)) = counts.into_iter().max_by_key(|(_, indices)| indices.len()) else { return };
    indices.sort_unstable();
    let frames = FramesDefined::new(indices.iter().filter_map(|&index| set.packets.get(index)).map(|packet| (packet.offset, packet.len)), String::new()).frames;
    let start = frames.iter().map(|frame| frame.start).min().unwrap_or(0);
    let end = frames.iter().map(|frame| frame.start + frame.len).max().unwrap_or(start);
    let identified = ProtocolIdentified {
        protocol: protocol.to_string(),
        how: format!("tshark named it the innermost protocol of {} of the {} packets it decoded", indices.len(), decodes.packets.len()),
        frames,
    };
    app.bus.publish(app.draft("tool:tshark", Payload::ProtocolIdentified(identified)).span(start, end - start));
}

/// Merge again after the user chose between filling gaps and everything.
fn remerge_rows(state: &mut PacketsState) {
    let Some(decodes) = state.tshark.decodes.as_ref().filter(|decodes| decodes.set_generation == state.set_generation) else { return };
    let bytes: Arc<PacketBytes> = Arc::clone(&state.bytes);
    for (&index, layers) in &decodes.packets {
        let Some(row) = state.rows.get(index) else { continue };
        let ours = packets::dissect_with(bytes.packet(index), row.link, &state.raw);
        state.rows[index] = PacketRow::from(tshark_layers::merge(ours, layers, state.tshark.mode));
    }
    state.tshark.generation += 1;
    state.rows_changed();
}

/// Decode new packets automatically when the user turned that on.
pub fn decode_automatically(state: &mut PacketsState, app: &mut ViewerApp) {
    let wanted = app.preferences.use_tshark && state.set.is_some() && !state.rows.is_empty() && !state.is_reading();
    if !wanted || state.tshark.job.is_some() || state.tshark.auto_decoded == Some(state.set_generation) {
        return;
    }
    if state.tshark.program(&app.preferences.tshark_path).is_none() {
        return;
    }
    state.tshark.auto_decoded = Some(state.set_generation);
    start(state, app, None);
}

/// The tshark controls: decode, cancel, progress and the choice of how much
/// tshark decodes.
pub fn show_controls(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    let available = state.tshark.program(&app.preferences.tshark_path).is_some();
    ui.horizontal_wrapped(|ui| {
        if let Some(job) = &state.tshark.job {
            ui.spinner();
            ui.label(RichText::new(format!("Decoding with tshark… {} of {}", job.done.load(Ordering::Relaxed).min(job.total), job.total)).color(theme::TEXT_DIM));
            if ui.small_button("Cancel").clicked() {
                let _ = app.perform("jobs.cancel", serde_json::json!({ "job": job.id }));
            }
            return;
        }
        let shown = state.visible.len().min(MAX_TSHARK_PACKETS);
        let button = ui
            .add_enabled(available && shown > 0, egui::Button::new("Decode with tshark"))
            .on_hover_text(format!("Have Wireshark's tshark decode the {shown} shown packets (run locally with -n: no name lookups) and show the protocols ours does not"))
            .on_disabled_hover_text(if available { "No packets are shown".to_string() } else { format!("Install Wireshark (tshark) to decode {TSHARK_PROTOCOLS} more protocols") });
        if button.clicked() {
            ask_to_decode(state, app, None);
        }
        let mut everything = state.tshark.mode == TsharkMode::Everything;
        if ui.add_enabled(available, egui::Checkbox::new(&mut everything, "Use tshark for everything")).on_hover_text("Show tshark's layers in place of ours for the packets it decoded").changed() {
            state.tshark.mode = if everything { TsharkMode::Everything } else { TsharkMode::FillGaps };
            remerge_rows(state);
        }
        let decoded = state.tshark.decoded_count(state.set_generation);
        if decoded > 0 {
            ui.label(RichText::new(format!("{decoded} packets decoded by tshark · filter with proto:NAME")).small().color(theme::TEXT_DIM));
        }
    });
    if let Some(error) = &state.tshark.error {
        ui.add(egui::Label::new(RichText::new(error).small().color(theme::DANGER)).wrap());
    }
}

/// Ask, as `packets.tshark_decode` once the panel is drawn, for the shown
/// packets (by index when a filter hides some), or only packet `only`, to
/// be decoded with tshark, its layers merged as the panel merges them now.
pub(crate) fn ask_to_decode(state: &mut PacketsState, app: &mut ViewerApp, only: Option<usize>) {
    let Some(set) = crate::panel_packets::api_set_id(state, app) else { return };
    let mut params = serde_json::json!({ "set": set, "mode": TsharkUse::of(state.tshark.mode) });
    let indices: Option<Vec<usize>> = match only {
        Some(index) => Some(vec![index]),
        None if state.visible.len() != state.rows.len() => Some(state.visible.iter().copied().take(MAX_TSHARK_PACKETS).collect()),
        None => None,
    };
    if let Some(indices) = indices {
        params["indices"] = serde_json::json!(indices);
    }
    app.perform_later("packets.tshark_decode", params);
}

/// Whether tshark can be offered for one packet in the detail view.
pub fn can_decode_one(state: &mut PacketsState, app: &ViewerApp) -> bool {
    state.tshark.job.is_none() && state.tshark.program(&app.preferences.tshark_path).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::sources;

    #[test]
    fn the_tshark_path_is_looked_up_once_per_setting() {
        let mut state = TsharkState::default();
        assert_eq!(state.program("/no/such/tshark"), None);
        assert_eq!(state.found.as_ref().map(|(path, _)| path.as_str()), Some("/no/such/tshark"));
        state.found = Some(("/no/such/tshark".to_string(), Some(PathBuf::from("/remembered"))));
        assert_eq!(state.program("/no/such/tshark"), Some(PathBuf::from("/remembered")), "not searched again");
    }

    #[test]
    fn packets_keep_their_captures_link_type_for_tshark_unless_one_is_chosen() {
        let mut state = PacketsState::default();
        let mut set = sources::single(0, 4, LinkKind::Unknown).unwrap();
        set.packets[0] = set.packets[0].clone().with_link_type(105);
        state.set = Some(set);
        state.visible = vec![0];
        assert_eq!(requests(&state, None)[0].link_type, 105, "an 802.11 frame stays 802.11");
        state.link_choice = LinkChoice::Ethernet;
        assert_eq!(requests(&state, Some(vec![0]))[0].link_type, packets::LINKTYPE_ETHERNET);
    }

    #[test]
    fn a_raw_frame_tshark_decoded_shows_tshark_s_addresses_in_the_list() {
        use crate::packets::{Endpoint, Flow, Transport};
        let mut state = PacketsState::default();
        let address = |last: u8| std::net::IpAddr::from([192, 0, 2, last]);
        let flow = Flow { transport: Transport::Udp, source: Endpoint { address: address(1), port: Some(5000) }, destination: Endpoint { address: address(2), port: Some(53) }, tcp_sequence: None };
        let layers = TsharkLayers { flow: Some(flow), ..TsharkLayers::default() };
        state.tshark.decodes = Some(Decodes { set_generation: 0, packets: HashMap::from([(0, layers)]) });
        let row = PacketRow::from(merged(&state, 0, packets::dissect(b"opaque frame", LinkKind::Unknown)));
        assert_eq!((row.summary.source.as_str(), row.summary.destination.as_str()), ("192.0.2.1", "192.0.2.2"));
        assert_eq!(row.flow.map(|flow| flow.destination.port), Some(Some(53)));
    }

    #[test]
    fn results_for_an_older_reading_of_the_packets_are_not_merged() {
        let mut state = PacketsState::default();
        let mut layers = TsharkLayers::default();
        layers.protocols.push("dhcp".to_string());
        state.tshark.decodes = Some(Decodes { set_generation: 1, packets: HashMap::from([(0, layers)]) });
        state.set_generation = 1;
        assert_eq!(merged(&state, 0, Dissection::default()).tshark_protocols, vec!["dhcp".to_string()]);
        state.set_generation = 2;
        assert!(merged(&state, 0, Dissection::default()).tshark_protocols.is_empty());
    }
}
