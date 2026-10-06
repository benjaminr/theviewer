//! Running our packet code, and tshark, over every capture in the corpus.
//!
//! Each file is read with our capture readers and every packet (up to
//! [`MAX_PACKETS_PER_FILE`]) is dissected, filtered, summarised into flows,
//! exported again and placed in the Reference tab's stack; the whole file is
//! also scanned by the detectors. Every step runs with panics caught and
//! recorded with the file, the step and the packet. When tshark is installed
//! the same packets are decoded by it and compared with ours.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::compare::{self, Carrier, TopAgreement};
use crate::packets::sources::{self, CaptureFormat};
use crate::packets::tshark::{self, RunLimits, TsharkPacket};
use crate::packets::tshark_layers::{self, TsharkMode};
use crate::packets::{self, Dissection, ExportPacket, LinkKind, PacketSet};
use crate::panel_packets::PacketLayers;
use crate::plugin::{Registry, ScanContext};
use crate::reference::{self, FormatReference, Transport};

/// Most packets of one file read, dissected and compared.
pub const MAX_PACKETS_PER_FILE: usize = 2_000;
/// Most bytes of a file the detectors scan.
const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;
/// Packets whose Reference stack is built.
const REFERENCE_PACKETS: usize = 200;
/// A file whose own processing takes longer is listed as slow.
pub const SLOW_FILE: Duration = Duration::from_secs(5);
/// A file is abandoned (and listed) after this long.
pub const FILE_TIME_LIMIT: Duration = Duration::from_secs(180);
const TSHARK_LIMITS: RunLimits = RunLimits { timeout: Duration::from_secs(90), max_output_bytes: 768 * 1024 * 1024, max_packets: MAX_PACKETS_PER_FILE };
/// A filter that exercises several kinds of term.
const SAMPLE_FILTER: &str = "udp port:53 len>20 proto:dns hex:0001";

/// Something that went wrong with one file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub file: String,
    /// "open", "dissect", "scan", "reference", "export", "flows", "tshark",
    /// "tshark-layers", "timeout" or "slow".
    pub stage: String,
    /// The packet, from 1, when the failure belongs to one.
    pub packet: Option<usize>,
    pub detail: String,
}

/// How often each kind of agreement and disagreement was seen.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Comparisons {
    pub compared_packets: usize,
    /// Packets whose captured length differed between us and tshark, so
    /// they were not compared.
    pub misaligned: usize,
    pub top_agree: usize,
    pub top_not_compared: usize,
    /// tshark's innermost protocol where it decodes further than we do.
    pub we_stop_earlier: BTreeMap<String, usize>,
    /// (our innermost layer, tshark's innermost protocol) where they differ.
    pub top_differs: BTreeMap<(String, String), usize>,
    /// (our layer, tshark protocols) → layer tallies.
    pub layers: BTreeMap<(String, String), LayerTally>,
    /// (our layer, our field, tshark filter) → field tallies.
    pub fields: BTreeMap<(String, String, String), FieldTally>,
    /// tshark filter name → coverage.
    pub protocols: BTreeMap<String, ProtocolTally>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LayerTally {
    pub compared: usize,
    pub offset_differs: usize,
    pub len_differs: usize,
    pub example: Option<Example>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldTally {
    pub compared: usize,
    pub differs: usize,
    pub example: Option<Example>,
}

/// Where a disagreement was first seen, with both sides' `(offset, len)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Example {
    pub file: String,
    pub packet: usize,
    pub ours: (usize, usize),
    pub theirs: (usize, usize),
}

/// What is known about one tshark protocol across the corpus.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtocolTally {
    pub packets: usize,
    pub files: BTreeSet<String>,
    /// Packets where one of our layers covered it.
    pub decoded_by_us: usize,
    /// Whether the reference notes are found by its filter name or long name.
    pub reference_named: bool,
    /// Packets where it sat right above UDP or TCP.
    pub over_port: usize,
    /// …and the reference notes for one of the ports name it.
    pub port_named: usize,
    /// …and guessing by the lower port with notes would name it.
    pub port_guess_right: usize,
    pub over_ethertype: usize,
    pub ethertype_named: usize,
    pub over_ip_protocol: usize,
    pub ip_protocol_named: usize,
}

impl Comparisons {
    /// Add another file's tallies to these.
    pub fn absorb(&mut self, other: Comparisons) {
        self.compared_packets += other.compared_packets;
        self.misaligned += other.misaligned;
        self.top_agree += other.top_agree;
        self.top_not_compared += other.top_not_compared;
        for (key, count) in other.we_stop_earlier {
            *self.we_stop_earlier.entry(key).or_default() += count;
        }
        for (key, count) in other.top_differs {
            *self.top_differs.entry(key).or_default() += count;
        }
        for (key, tally) in other.layers {
            let kept = self.layers.entry(key).or_default();
            kept.compared += tally.compared;
            kept.offset_differs += tally.offset_differs;
            kept.len_differs += tally.len_differs;
            kept.example = kept.example.take().or(tally.example);
        }
        for (key, tally) in other.fields {
            let kept = self.fields.entry(key).or_default();
            kept.compared += tally.compared;
            kept.differs += tally.differs;
            kept.example = kept.example.take().or(tally.example);
        }
        for (key, tally) in other.protocols {
            let kept = self.protocols.entry(key).or_default();
            kept.packets += tally.packets;
            kept.files.extend(tally.files);
            kept.decoded_by_us += tally.decoded_by_us;
            kept.reference_named |= tally.reference_named;
            kept.over_port += tally.over_port;
            kept.port_named += tally.port_named;
            kept.port_guess_right += tally.port_guess_right;
            kept.over_ethertype += tally.over_ethertype;
            kept.ethertype_named += tally.ethertype_named;
            kept.over_ip_protocol += tally.over_ip_protocol;
            kept.ip_protocol_named += tally.ip_protocol_named;
        }
    }

    /// Add one packet compared with tshark.
    pub fn add_packet(&mut self, file: &str, number: usize, ours: &Dissection, theirs: &TsharkPacket) {
        self.compared_packets += 1;
        let comparison = compare::compare(ours, theirs);
        match comparison.top {
            Some(TopAgreement::Agree) => self.top_agree += 1,
            Some(TopAgreement::WeStopEarlier { theirs }) => *self.we_stop_earlier.entry(theirs).or_default() += 1,
            Some(TopAgreement::Differs { ours, theirs }) => *self.top_differs.entry((ours, theirs)).or_default() += 1,
            Some(TopAgreement::NotCompared) | None => self.top_not_compared += 1,
        }
        for check in &comparison.layers {
            let tshark = check.tshark.clone().unwrap_or_else(|| "(none)".to_string());
            let tally = self.layers.entry((check.ours.to_string(), tshark)).or_default();
            tally.compared += 1;
            tally.offset_differs += usize::from(!check.offset_agrees());
            tally.len_differs += usize::from(!check.len_agrees());
            if (!check.offset_agrees() || !check.len_agrees()) && tally.example.is_none() {
                tally.example = Some(Example { file: file.to_string(), packet: number, ours: check.ours_span, theirs: check.theirs_span });
            }
        }
        for check in &comparison.fields {
            let tally = self.fields.entry((check.layer.to_string(), check.field.to_string(), check.filter.to_string())).or_default();
            tally.compared += 1;
            if !check.agrees() {
                tally.differs += 1;
                if tally.example.is_none() {
                    tally.example = Some(Example { file: file.to_string(), packet: number, ours: check.ours, theirs: check.theirs });
                }
            }
        }
        let carriers = compare::carriers(theirs);
        let titles: BTreeMap<&str, &str> = theirs.layers.iter().map(|layer| (layer.name.as_str(), layer.title.as_str())).collect();
        let distinct: BTreeSet<&String> = theirs.protocols.iter().filter(|name| !tshark_pseudo(name)).collect();
        for name in distinct {
            let tally = self.protocols.entry(name.clone()).or_default();
            tally.packets += 1;
            tally.files.insert(file.to_string());
            tally.decoded_by_us += usize::from(comparison.decoded_by_us.contains(name));
            if !tally.reference_named {
                let long_name = titles.get(name.as_str()).map(|title| title.split(", ").next().unwrap_or_default()).unwrap_or_default();
                tally.reference_named = notes_for(name).is_some() || (!long_name.is_empty() && reference::lookup(long_name).is_some());
            }
            for (_, carrier) in carriers.iter().filter(|(carried, _)| carried == name) {
                record_carrier(tally, name, *carrier);
            }
        }
    }
}

/// Names in tshark's stack that are not protocols of their own.
fn tshark_pseudo(name: &str) -> bool {
    name == "ethertype" || name.starts_with("_ws.")
}

/// Whether reference notes describe the tshark protocol `name`.
fn names_protocol(notes: &FormatReference, name: &str) -> bool {
    notes.id.eq_ignore_ascii_case(name) || notes.keys.iter().any(|key| key.eq_ignore_ascii_case(name)) || notes_for(name).is_some_and(|found| found.id == notes.id)
}

/// The reference notes for a tshark protocol: by its filter name, else by
/// the name of our layer that covers it (tshark's `ip` is our IPv4 layer).
fn notes_for(name: &str) -> Option<&'static FormatReference> {
    reference::lookup(name).or_else(|| compare::LAYER_MAP.iter().find(|mapping| mapping.tshark.contains(&name)).and_then(|mapping| reference::lookup(mapping.ours)))
}

fn record_carrier(tally: &mut ProtocolTally, name: &str, carrier: Carrier) {
    let library = reference::library();
    match carrier {
        Carrier::Port { tcp, ports } => {
            let transport = if tcp { Transport::Tcp } else { Transport::Udp };
            tally.over_port += 1;
            let named = ports.iter().any(|&port| library.by_port(transport, port).iter().any(|notes| names_protocol(notes, name)));
            tally.port_named += usize::from(named);
            let mut by_preference = ports;
            by_preference.sort_unstable();
            let guess = by_preference.iter().find_map(|&port| library.by_port(transport, port).first().copied());
            tally.port_guess_right += usize::from(guess.is_some_and(|notes| names_protocol(notes, name)));
        }
        Carrier::EtherType(ether_type) => {
            tally.over_ethertype += 1;
            tally.ethertype_named += usize::from(library.by_ethertype(ether_type).iter().any(|notes| names_protocol(notes, name)));
        }
        Carrier::IpProtocol(number) => {
            tally.over_ip_protocol += 1;
            tally.ip_protocol_named += usize::from(library.by_ip_protocol(number).iter().any(|notes| names_protocol(notes, name)));
        }
    }
}

/// What happened to one capture.
#[derive(Clone, Debug, Default)]
pub struct FileResult {
    pub file: String,
    pub size: usize,
    /// "pcap", "pcapng", or a guess at what else it is.
    pub format: String,
    /// Packets we read, or why the file could not be opened.
    pub opened: Option<Result<usize, String>>,
    /// Packets per pcap LINKTYPE number, of those we read.
    pub link_types: BTreeMap<u32, usize>,
    /// Packets tshark dissected, or why it did not.
    pub tshark: Option<Result<usize, String>>,
    /// tshark's outermost protocol for the first packet, when we could not
    /// open the file, to say what it holds.
    pub tshark_link: Option<String>,
    pub elapsed: Duration,
    pub failures: Vec<Failure>,
    pub comparisons: Comparisons,
}

// ---------------------------------------------------------------------------
// Panics
// ---------------------------------------------------------------------------

/// A panic seen while working on a file.
#[derive(Clone, Debug)]
struct PanicRecord {
    file: String,
    stage: String,
    packet: Option<usize>,
    message: String,
}

static PANICS: Mutex<Vec<PanicRecord>> = Mutex::new(Vec::new());

thread_local! {
    /// The file, step and packet the current thread is working on.
    static WORKING_ON: RefCell<(String, String, Option<usize>)> = const { RefCell::new((String::new(), String::new(), None)) };
}

fn working_on(file: &str, stage: &str, packet: Option<usize>) {
    WORKING_ON.with(|current| *current.borrow_mut() = (file.to_string(), stage.to_string(), packet));
}

/// Record every panic, including ones the detectors catch themselves, with
/// what the thread was working on, instead of printing it.
pub fn install_panic_recorder() {
    std::panic::set_hook(Box::new(|info| {
        let message = info.payload().downcast_ref::<&str>().map(|text| text.to_string()).or_else(|| info.payload().downcast_ref::<String>().cloned()).unwrap_or_else(|| "panic".to_string());
        let location = info.location().map(|at| format!(" at {}:{}", at.file(), at.line())).unwrap_or_default();
        let (file, stage, packet) = WORKING_ON.with(|current| current.borrow().clone());
        if let Ok(mut panics) = PANICS.lock() {
            panics.push(PanicRecord { file, stage, packet, message: format!("{message}{location}") });
        }
    }));
}

fn panics_for(file: &str) -> Vec<Failure> {
    let Ok(mut panics) = PANICS.lock() else { return Vec::new() };
    let (mine, others): (Vec<PanicRecord>, Vec<PanicRecord>) = panics.drain(..).partition(|record| record.file == file);
    *panics = others;
    mine.into_iter().map(|record| Failure { file: record.file, stage: record.stage, packet: record.packet, detail: format!("panic: {}", record.message) }).collect()
}

fn guarded<T>(work: impl FnOnce() -> T) -> Option<T> {
    catch_unwind(AssertUnwindSafe(work)).ok()
}

// ---------------------------------------------------------------------------
// One file
// ---------------------------------------------------------------------------

/// What a file that is not pcap or pcapng appears to be, from its first bytes.
pub fn describe_other_format(bytes: &[u8]) -> String {
    const KNOWN: [(&[u8], &str); 9] = [
        (b"snoop\0\0\0", "snoop"),
        (b"GMBU", "Microsoft Network Monitor 2"),
        (b"RTSS", "Microsoft Network Monitor 1"),
        (b"XCP\0", "NetXRay / Sniffer for Windows"),
        (b"TRSNIFF data", "Sniffer (DOS)"),
        (&[0xA1, 0xB2, 0xCD, 0x34], "pcap with Kuznetsov's extended records"),
        (&[0x34, 0xCD, 0xB2, 0xA1], "pcap with Kuznetsov's extended records"),
        (&[0x1F, 0x8B], "gzip"),
        (b"\x0a\x0d\x0d\x0a", "pcapng with an unknown byte order"),
    ];
    if let Some((_, name)) = KNOWN.iter().find(|(magic, _)| bytes.starts_with(magic)) {
        return name.to_string();
    }
    let text_like = bytes.iter().take(256).all(|&byte| byte == b'\n' || byte == b'\r' || byte == b'\t' || (0x20..0x7F).contains(&byte));
    if text_like && !bytes.is_empty() {
        return "text".to_string();
    }
    format!("unknown (starts {})", packets::hex_preview(bytes, 4))
}

/// Our side of one file: the packets read and their dissections.
struct OurSide {
    set: Option<PacketSet>,
    dissections: Vec<Dissection>,
}

/// Read, dissect and exercise one capture with our code.
fn run_ours(file: &str, bytes: &[u8], registry: &Registry, result: &mut FileResult) -> OurSide {
    let mut side = OurSide { set: None, dissections: Vec::new() };
    working_on(file, "open", None);
    result.format = match sources::capture_format(bytes) {
        Some(CaptureFormat::Pcap) => "pcap".to_string(),
        Some(CaptureFormat::PcapNg) => "pcapng".to_string(),
        None => describe_other_format(bytes),
    };
    let opened = guarded(|| sources::from_capture(bytes, 0));
    match opened {
        Some(Ok(set)) => {
            result.opened = Some(Ok(set.len()));
            side.set = Some(set);
        }
        Some(Err(error)) => result.opened = Some(Err(error.to_string())),
        None => result.opened = Some(Err("panicked while reading the capture".to_string())),
    }
    let findings = scan(file, bytes, registry);
    let Some(set) = &side.set else { return side };
    let filter = packets::parse_filter(SAMPLE_FILTER).unwrap_or_default();
    for (index, packet) in set.packets.iter().take(MAX_PACKETS_PER_FILE).enumerate() {
        *result.link_types.entry(packet.link_type).or_default() += 1;
        let data = bytes.get(packet.offset..packet.end()).unwrap_or_default();
        working_on(file, "dissect", Some(index + 1));
        let Some(dissection) = guarded(|| packets::dissect(data, packet.link)) else {
            side.dissections.push(Dissection::default());
            continue;
        };
        working_on(file, "filter", Some(index + 1));
        let no_tshark_protocols: [String; 0] = [];
        guarded(|| {
            filter.matches(&packets::FilterSubject {
                protocols: &dissection.protocols,
                tshark_protocols: &no_tshark_protocols,
                flow: dissection.flow.as_ref(),
                summary: &dissection.summary,
                bytes: data,
                len: packet.len,
            })
        });
        if index < REFERENCE_PACKETS {
            working_on(file, "reference", Some(index + 1));
            let layers = PacketLayers::from_dissection(packet.offset, packet.len, &dissection);
            for layer in &dissection.layers {
                guarded(|| crate::panel_reference::build_stack(reference::library(), &findings, Some(&layers), packet.offset + layer.offset));
            }
        }
        side.dissections.push(dissection);
    }
    exercise_flows(file, bytes, set, &side.dissections);
    export_round_trip(file, bytes, set, result);
    side
}

/// Scan the start of the file with every detector.
fn scan(file: &str, bytes: &[u8], registry: &Registry) -> Vec<crate::plugin::Finding> {
    working_on(file, "scan", None);
    let window = &bytes[..bytes.len().min(MAX_SCAN_BYTES)];
    let mut findings = Vec::new();
    for (start, end) in crate::explain::scan_windows(window.len()) {
        let context = ScanContext { base: start, document_len: bytes.len(), strides: Vec::new() };
        if let Some(found) = guarded(|| registry.scan(&window[start..end], &context)) {
            findings.extend(found);
        }
    }
    findings
}

fn exercise_flows(file: &str, bytes: &[u8], set: &PacketSet, dissections: &[Dissection]) {
    working_on(file, "flows", None);
    guarded(|| {
        let flows = || dissections.iter().zip(&set.packets).map(|(dissection, packet)| (dissection.flow.as_ref(), packet.len));
        let conversations = packets::conversations(flows());
        packets::endpoints(flows());
        if let Some(first) = conversations.first() {
            let items = dissections.iter().zip(&set.packets).enumerate().filter_map(|(index, (dissection, packet))| {
                let flow = dissection.flow.as_ref()?;
                let (start, len) = dissection.payload?;
                let data = bytes.get(packet.offset..packet.end())?;
                Some((index, flow, data.get(start..(start + len).min(data.len())).unwrap_or_default()))
            });
            packets::follow_stream(&first.key, items);
        }
    });
}

/// Write the packets out as pcap and read them back: the count must match.
fn export_round_trip(file: &str, bytes: &[u8], set: &PacketSet, result: &mut FileResult) {
    working_on(file, "export", None);
    let Some(first) = set.packets.first() else { return };
    let same_link: Vec<ExportPacket> = set
        .packets
        .iter()
        .take(MAX_PACKETS_PER_FILE)
        .filter(|packet| packet.link_type == first.link_type)
        .map(|packet| ExportPacket { bytes: bytes.get(packet.offset..packet.end()).unwrap_or_default(), original_len: packet.len, timestamp: packet.timestamp, link: packet.link })
        .collect();
    let Some(written) = guarded(|| packets::write_pcap_as(&same_link, first.link_type)) else { return };
    match written.map(|file_bytes| sources::from_capture(&file_bytes, 0).map(|read| read.len())) {
        Ok(Ok(count)) if count == same_link.len() => {}
        Ok(Ok(count)) => result.failures.push(Failure { file: file.to_string(), stage: "export".to_string(), packet: None, detail: format!("{} packets written, {count} read back", same_link.len()) }),
        Ok(Err(error)) => result.failures.push(Failure { file: file.to_string(), stage: "export".to_string(), packet: None, detail: format!("the exported file could not be read back: {error}") }),
        Err(error) => result.failures.push(Failure { file: file.to_string(), stage: "export".to_string(), packet: None, detail: error.to_string() }),
    }
}

/// tshark's side of one file, compared packet by packet with ours.
fn run_tshark(file: &str, path: &Path, tshark: &Path, ours: &OurSide, result: &mut FileResult) {
    let cancel = AtomicBool::new(false);
    let mut decoded: Vec<TsharkPacket> = Vec::new();
    let outcome = tshark::decode_file(tshark, path, &TSHARK_LIMITS, &cancel, |packet| decoded.push(packet));
    result.tshark = Some(match &outcome {
        Ok(_) => Ok(decoded.len()),
        Err(error) => Err(error.to_string()),
    });
    if let Err(error) = &outcome
        && decoded.is_empty()
    {
        result.failures.push(Failure { file: file.to_string(), stage: "tshark".to_string(), packet: None, detail: error.to_string() });
        return;
    }
    let Some(set) = &ours.set else {
        result.tshark_link = decoded.first().and_then(|packet| packet.protocols.first().cloned());
        return;
    };
    for (index, theirs) in decoded.iter().enumerate() {
        let (Some(packet), Some(dissection)) = (set.packets.get(index), ours.dissections.get(index)) else { break };
        if theirs.captured_len != packet.len {
            result.comparisons.misaligned += 1;
            continue;
        }
        working_on(file, "tshark-layers", Some(index + 1));
        guarded(|| {
            let layers = tshark_layers::to_layers(theirs, packet.len);
            tshark_layers::merge(dissection.clone(), &layers, TsharkMode::FillGaps);
            tshark_layers::merge(dissection.clone(), &layers, TsharkMode::Everything);
        });
        if matches!(dissection.link, LinkKind::Ethernet | LinkKind::RawIp) {
            result.comparisons.add_packet(file, index + 1, dissection, theirs);
        } else {
            // Frames we cannot read still count towards coverage.
            result.comparisons.add_packet(file, index + 1, &Dissection::default(), theirs);
        }
    }
}

/// Everything for one file, on a thread of its own so a hang can be
/// abandoned after [`FILE_TIME_LIMIT`].
pub fn run_file(path: &Path, registry: &Registry, tshark: Option<&Path>) -> FileResult {
    let file = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let (sender, receiver) = mpsc::channel();
    let path_owned: PathBuf = path.to_path_buf();
    let registry = registry.clone();
    let tshark = tshark.map(Path::to_path_buf);
    let name = file.clone();
    thread::spawn(move || {
        let mut result = FileResult { file: name.clone(), ..FileResult::default() };
        let bytes = match std::fs::read(&path_owned) {
            Ok(bytes) => bytes,
            Err(error) => {
                result.opened = Some(Err(error.to_string()));
                let _ = sender.send(result);
                return;
            }
        };
        result.size = bytes.len();
        let started = Instant::now();
        let ours = run_ours(&name, &bytes, &registry, &mut result);
        result.elapsed = started.elapsed();
        if let Some(tshark) = &tshark {
            run_tshark(&name, &path_owned, tshark, &ours, &mut result);
        }
        working_on("", "", None);
        let _ = sender.send(result);
    });
    let mut result = match receiver.recv_timeout(FILE_TIME_LIMIT) {
        Ok(result) => result,
        Err(_) => FileResult {
            file: file.clone(),
            failures: vec![Failure { file: file.clone(), stage: "timeout".to_string(), packet: None, detail: format!("not finished after {} s", FILE_TIME_LIMIT.as_secs()) }],
            ..FileResult::default()
        },
    };
    if result.elapsed > SLOW_FILE {
        result.failures.push(Failure { file: file.clone(), stage: "slow".to_string(), packet: None, detail: format!("{:.1} s for our own processing", result.elapsed.as_secs_f64()) });
    }
    result.failures.extend(panics_for(&file));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_capture_formats_are_named_from_their_first_bytes() {
        assert_eq!(describe_other_format(b"snoop\0\0\0\0\0\0\x02"), "snoop");
        assert_eq!(describe_other_format(b"GMBU\x00\x02"), "Microsoft Network Monitor 2");
        assert_eq!(describe_other_format(b"# a text log\n"), "text");
        assert_eq!(describe_other_format(&[0xDE, 0xAD, 0xBE, 0xEF, 0, 1]), "unknown (starts de ad be ef …)");
    }

    #[test]
    fn a_hand_made_capture_is_read_dissected_and_exported_without_failures() {
        let builder = etherparse::PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]).ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).udp(4000, 9999);
        let mut frame = Vec::new();
        builder.write(&mut frame, b"hello").unwrap();
        let file = packets::write_pcap(&[ExportPacket { bytes: &frame, original_len: frame.len(), timestamp: Some(1.0), link: LinkKind::Ethernet }]).unwrap();
        let path = std::env::temp_dir().join(format!("theviewer-corpus-run-{}.pcap", std::process::id()));
        std::fs::write(&path, &file).unwrap();
        let result = run_file(&path, &crate::app::build_registry(), None);
        std::fs::remove_file(&path).ok();
        assert_eq!(result.format, "pcap");
        assert_eq!(result.opened, Some(Ok(1)));
        assert_eq!(result.link_types, BTreeMap::from([(packets::LINKTYPE_ETHERNET, 1)]));
        assert!(result.failures.is_empty(), "{:?}", result.failures);
    }

    #[test]
    fn coverage_counts_each_tshark_protocol_once_per_packet_with_what_names_it() {
        use crate::packets::tshark::{TsharkField, TsharkProtocol};
        let field = |name: &str, position: usize, size: usize, value: &str| TsharkField { name: name.into(), position: Some(position), size, value: value.into(), ..TsharkField::default() };
        let theirs = TsharkPacket {
            number: 1,
            captured_len: 300,
            protocols: ["eth", "ethertype", "ip", "udp", "dhcp"].map(String::from).to_vec(),
            layers: vec![
                TsharkProtocol { name: "eth".into(), position: Some(0), size: 14, fields: vec![field("eth.type", 12, 2, "0800")], ..TsharkProtocol::default() },
                TsharkProtocol { name: "ip".into(), position: Some(14), size: 20, fields: vec![field("ip.proto", 23, 1, "11")], ..TsharkProtocol::default() },
                TsharkProtocol { name: "udp".into(), position: Some(34), size: 8, fields: vec![field("udp.srcport", 34, 2, "0044"), field("udp.dstport", 36, 2, "0043")], ..TsharkProtocol::default() },
                TsharkProtocol { name: "dhcp".into(), position: Some(42), size: 258, ..TsharkProtocol::default() },
            ],
            notes: Vec::new(),
        };
        let mut comparisons = Comparisons::default();
        comparisons.add_packet("a.pcap", 1, &Dissection::default(), &theirs);
        comparisons.add_packet("b.pcap", 1, &Dissection::default(), &theirs);
        let dhcp = &comparisons.protocols["dhcp"];
        assert_eq!((dhcp.packets, dhcp.files.len(), dhcp.decoded_by_us, dhcp.over_port), (2, 2, 0, 2));
        assert!(!comparisons.protocols.contains_key("ethertype"));
        assert_eq!(comparisons.top_not_compared, 2);
        let mut total = Comparisons::default();
        total.absorb(comparisons.clone());
        total.absorb(comparisons);
        assert_eq!(total.protocols["dhcp"].packets, 4);
        assert_eq!(total.protocols["dhcp"].files.len(), 2);
    }
}
