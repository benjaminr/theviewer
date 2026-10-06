//! Wireshark's command-line dissector, tshark, run as a separate program.
//!
//! tshark knows thousands of protocols this viewer does not. When it is
//! installed (and only when the user asks for it), a capture file is handed
//! to it and its per-packet dissection is read back into our own types:
//! [`TsharkPacket`]s holding the protocol stack and a tree of fields with
//! their byte positions. [`super::tshark_layers`] turns those into the
//! viewer's layers.
//!
//! tshark is always run with `-n`, so it resolves no names (no DNS lookups),
//! reads only the file given with `-r`, and is stopped after a time limit,
//! when its output passes a size cap, or when the caller cancels.
//!
//! Its output is read as PDML (`-T pdml`) rather than JSON. PDML gives every
//! field its filter name, display text, value and its position and size in
//! the frame as attributes, keeps fields in order, and lets repeated fields
//! (several `dhcp.option.type`, say) appear more than once. tshark's JSON
//! writes repeated fields as duplicate object keys, which JSON parsers fold
//! into one, and keeps positions in separate `_raw` arrays only with `-x`.
//! PDML also arrives one `<packet>` element at a time, so packets are parsed
//! as they stream in and memory stays bounded.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};
use std::{fmt, io};

use super::export::{ExportPacket, write_pcap_as};

/// The program's name on Unix-like systems and on Windows.
const PROGRAM_NAMES: [&str; 2] = ["tshark", "tshark.exe"];

/// Places Wireshark installs tshark that may not be on the `PATH`.
const COMMON_LOCATIONS: [&str; 7] = [
    "/opt/homebrew/bin/tshark",
    "/usr/local/bin/tshark",
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/usr/bin/tshark",
    "/usr/sbin/tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
];

/// How long to wait for more output before checking the clock and the
/// cancel flag again.
const POLL: Duration = Duration::from_millis(50);
/// Bytes read from tshark's standard output at a time.
const READ_CHUNK: usize = 64 * 1024;
/// Most bytes of tshark's error output kept for an error message.
const MAX_ERROR_TEXT: usize = 4096;
/// Expert-info severities from "warning" up are kept as notes; "chat" and
/// "note" (such as "connection establish request") are left out.
const EXPERT_WARNING: u64 = 0x0060_0000;

/// Where tshark is: `preferred` when it names a program, else the first
/// `tshark` on the `PATH`, else one of the usual install locations.
pub fn find_tshark(preferred: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = preferred.filter(|path| !path.as_os_str().is_empty()) {
        return path.is_file().then(|| path.to_path_buf());
    }
    let on_path = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .flat_map(|dir| PROGRAM_NAMES.map(|name| dir.join(name)));
    on_path.chain(COMMON_LOCATIONS.iter().map(PathBuf::from)).find(|path| path.is_file())
}

/// Bounds on one run of tshark.
#[derive(Clone, Copy, Debug)]
pub struct RunLimits {
    /// The run is stopped after this long.
    pub timeout: Duration,
    /// The run is stopped once tshark has written this many bytes.
    pub max_output_bytes: usize,
    /// Most packets read from the capture (tshark's `-c`).
    pub max_packets: usize,
}

impl Default for RunLimits {
    fn default() -> Self {
        RunLimits { timeout: Duration::from_secs(120), max_output_bytes: 512 * 1024 * 1024, max_packets: 10_000 }
    }
}

/// Why tshark gave no dissection.
#[derive(Debug)]
pub enum TsharkError {
    /// The program could not be started.
    Start { program: PathBuf, error: io::Error },
    /// tshark stopped with an error and dissected nothing.
    Failed { status: String, message: String },
    TimedOut { after: Duration, packets: usize },
    OutputTooLarge { limit: usize, packets: usize },
    Cancelled,
    /// The packets could not be written out for tshark to read.
    TemporaryFile(String),
}

impl fmt::Display for TsharkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TsharkError::Start { program, error } => write!(f, "tshark could not be started from {}: {error}", program.display()),
            TsharkError::Failed { status, message } if message.is_empty() => write!(f, "tshark stopped ({status}) without dissecting any packets"),
            TsharkError::Failed { status, message } => write!(f, "tshark stopped ({status}): {message}"),
            TsharkError::TimedOut { after, packets } => write!(f, "tshark was stopped after {} s, having dissected {packets} packets", after.as_secs()),
            TsharkError::OutputTooLarge { limit, packets } => write!(f, "tshark was stopped once its output passed {limit} bytes, having dissected {packets} packets"),
            TsharkError::Cancelled => write!(f, "Decoding with tshark was cancelled"),
            TsharkError::TemporaryFile(reason) => write!(f, "The packets could not be written out for tshark: {reason}"),
        }
    }
}

impl std::error::Error for TsharkError {}

/// How a finished run went.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunOutcome {
    /// Packets dissected and handed to the caller.
    pub packets: usize,
    /// tshark's complaint when it exited with an error after dissecting some
    /// packets, such as a capture that was cut short.
    pub warning: Option<String>,
}

/// Run tshark on `capture` and hand each packet's dissection to `on_packet`
/// as it arrives. Stops early when `cancel` is set, after the time limit or
/// past the output cap; packets already handed over stay valid.
pub fn decode_file(tshark: &Path, capture: &Path, limits: &RunLimits, cancel: &AtomicBool, mut on_packet: impl FnMut(TsharkPacket)) -> Result<RunOutcome, TsharkError> {
    let mut child = Command::new(tshark)
        // -n: no name resolution of any kind, so nothing is looked up on the network.
        .arg("-n")
        .arg("-r")
        .arg(capture)
        .args(["-T", "pdml", "-c", &limits.max_packets.max(1).to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| TsharkError::Start { program: tshark.to_path_buf(), error })?;
    let errors = spawn_error_reader(&mut child);
    let chunks = spawn_output_reader(&mut child);

    let started = Instant::now();
    let mut pending = String::new();
    let mut undecoded_tail: Vec<u8> = Vec::new();
    let mut written = 0usize;
    let mut packets = 0usize;
    let stop = |child: &mut Child, error: TsharkError| {
        let _ = child.kill();
        let _ = child.wait();
        Err(error)
    };
    loop {
        if cancel.load(Ordering::Relaxed) {
            return stop(&mut child, TsharkError::Cancelled);
        }
        if started.elapsed() > limits.timeout {
            return stop(&mut child, TsharkError::TimedOut { after: limits.timeout, packets });
        }
        match chunks.recv_timeout(POLL) {
            Ok(chunk) => {
                written += chunk.len();
                if written > limits.max_output_bytes {
                    return stop(&mut child, TsharkError::OutputTooLarge { limit: limits.max_output_bytes, packets });
                }
                undecoded_tail.extend_from_slice(&chunk);
                append_utf8(&mut undecoded_tail, &mut pending);
                for text in take_packet_elements(&mut pending) {
                    packets += 1;
                    on_packet(parse_pdml_packet(&text).unwrap_or_else(|problem| TsharkPacket::unreadable(packets, problem)));
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = child.wait().map_err(|error| TsharkError::Start { program: tshark.to_path_buf(), error })?;
    let message = errors.join().unwrap_or_default();
    if status.success() {
        return Ok(RunOutcome { packets, warning: None });
    }
    let status = status.code().map_or_else(|| "killed".to_string(), |code| format!("exit status {code}"));
    if packets == 0 {
        return Err(TsharkError::Failed { status, message });
    }
    Ok(RunOutcome { packets, warning: Some(if message.is_empty() { status } else { message }) })
}

/// Decode packets that share one link type (a tcpdump.org LINKTYPE number):
/// they are written to a temporary pcap file, which is removed afterwards,
/// and tshark's dissection of each is handed to `on_packet` in order.
pub fn decode_packets(
    tshark: &Path,
    packets: &[ExportPacket<'_>],
    link_type: u32,
    limits: &RunLimits,
    cancel: &AtomicBool,
    on_packet: impl FnMut(TsharkPacket),
) -> Result<RunOutcome, TsharkError> {
    let file = write_pcap_as(packets, link_type).map_err(|error| TsharkError::TemporaryFile(error.to_string()))?;
    let path = temporary_capture_path();
    std::fs::write(&path, file).map_err(|error| TsharkError::TemporaryFile(format!("{}: {error}", path.display())))?;
    let outcome = decode_file(tshark, &path, limits, cancel, on_packet);
    let _ = std::fs::remove_file(&path);
    outcome
}

/// A capture file name of our own in the system's temporary directory.
fn temporary_capture_path() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let number = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("theviewer-tshark-{}-{number}.pcap", std::process::id()))
}

/// Read standard output in chunks on a thread, so the caller can keep an eye
/// on the clock while waiting.
fn spawn_output_reader(child: &mut Child) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    if let Some(mut stdout) = child.stdout.take() {
        thread::spawn(move || {
            let mut buffer = vec![0u8; READ_CHUNK];
            while let Ok(read) = stdout.read(&mut buffer) {
                if read == 0 || sender.send(buffer[..read].to_vec()).is_err() {
                    break;
                }
            }
        });
    }
    receiver
}

/// Collect the start of standard error on a thread (so tshark never blocks
/// writing it), returning it trimmed to one paragraph.
fn spawn_error_reader(child: &mut Child) -> thread::JoinHandle<String> {
    let stderr = child.stderr.take();
    thread::spawn(move || {
        let Some(mut stderr) = stderr else { return String::new() };
        let mut kept = Vec::new();
        let mut buffer = [0u8; 4096];
        while let Ok(read) = stderr.read(&mut buffer) {
            if read == 0 {
                break;
            }
            if kept.len() < MAX_ERROR_TEXT {
                kept.extend_from_slice(&buffer[..read.min(MAX_ERROR_TEXT - kept.len())]);
            }
        }
        String::from_utf8_lossy(&kept).split_whitespace().collect::<Vec<_>>().join(" ")
    })
}

/// Move the complete UTF-8 characters at the front of `bytes` onto `text`,
/// leaving a character split across two reads for the next call.
fn append_utf8(bytes: &mut Vec<u8>, text: &mut String) {
    let valid = match std::str::from_utf8(bytes) {
        Ok(_) => bytes.len(),
        Err(error) if error.error_len().is_none() => error.valid_up_to(),
        // Not UTF-8 at all: keep going with replacement characters.
        Err(_) => {
            text.push_str(&String::from_utf8_lossy(bytes));
            bytes.clear();
            return;
        }
    };
    text.push_str(std::str::from_utf8(&bytes[..valid]).unwrap_or_default());
    bytes.drain(..valid);
}

/// Remove every complete `<packet>…</packet>` element from the front of
/// `pending` and return them; whatever follows the last one stays.
pub fn take_packet_elements(pending: &mut String) -> Vec<String> {
    const OPEN: &str = "<packet>";
    const CLOSE: &str = "</packet>";
    let mut elements = Vec::new();
    let mut consumed = 0;
    while let Some(start) = pending[consumed..].find(OPEN).map(|at| consumed + at) {
        let Some(end) = pending[start..].find(CLOSE).map(|at| start + at + CLOSE.len()) else {
            consumed = start;
            break;
        };
        elements.push(pending[start..end].to_string());
        consumed = end;
    }
    if elements.is_empty() && !pending.contains(OPEN) {
        // Only the document's preamble so far; nothing to keep but a
        // possible partial "<packet" at the very end.
        let keep_from = pending.len().saturating_sub(OPEN.len());
        let keep_from = (keep_from..=pending.len()).find(|&at| pending.is_char_boundary(at)).unwrap_or(pending.len());
        pending.drain(..keep_from);
        return elements;
    }
    pending.drain(..consumed);
    elements
}

// ---------------------------------------------------------------------------
// What tshark reports
// ---------------------------------------------------------------------------

/// One packet as tshark dissected it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TsharkPacket {
    /// tshark's frame number, from 1.
    pub number: usize,
    /// Bytes captured.
    pub captured_len: usize,
    /// The protocol stack by filter name, outermost first, as tshark lists
    /// it (`eth`, `ethertype`, `ip`, `udp`, `dhcp`).
    pub protocols: Vec<String>,
    /// The protocols dissected, outermost first, without tshark's own
    /// pseudo-protocols (`geninfo`, `frame` and `_ws.*`).
    pub layers: Vec<TsharkProtocol>,
    /// Expert warnings and errors, and malformed-packet reports.
    pub notes: Vec<String>,
}

impl TsharkPacket {
    fn unreadable(number: usize, problem: String) -> TsharkPacket {
        TsharkPacket { number, notes: vec![format!("tshark's dissection of this packet could not be read: {problem}")], ..TsharkPacket::default() }
    }

    /// The innermost protocol tshark named, leaving out undissected data.
    pub fn top_protocol(&self) -> Option<&str> {
        self.protocols.iter().rev().map(String::as_str).find(|name| !is_data_protocol(name))
    }
}

/// Whether a tshark protocol name stands for bytes it did not dissect, or
/// for a step in the stack rather than a header (such as `ethertype`).
pub fn is_data_protocol(name: &str) -> bool {
    matches!(name, "data" | "ethertype" | "media" | "_ws.malformed" | "_ws.short" | "_ws.unreassembled")
}

/// One protocol of a packet.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TsharkProtocol {
    /// Filter name, such as `ip` or `dhcp`.
    pub name: String,
    /// tshark's one-line description, such as "User Datagram Protocol, Src Port: 68, Dst Port: 67".
    pub title: String,
    /// Position and size within the data tshark dissected it from.
    pub position: Option<usize>,
    pub size: usize,
    pub fields: Vec<TsharkField>,
}

/// One field of a protocol.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TsharkField {
    /// Filter name, such as `ip.ttl`; empty for text-only items.
    pub name: String,
    /// The line tshark shows, such as "Time to Live: 64".
    pub display: String,
    /// The value as text, such as "64".
    pub show: String,
    /// The bytes as hex, such as "40".
    pub value: String,
    pub position: Option<usize>,
    pub size: usize,
    pub children: Vec<TsharkField>,
}

/// Parse one `<packet>` element of PDML.
pub fn parse_pdml_packet(xml: &str) -> Result<TsharkPacket, String> {
    let document = roxmltree::Document::parse(xml).map_err(|error| error.to_string())?;
    let root = document.root_element();
    if !root.has_tag_name("packet") {
        return Err(format!("expected a <packet> element, found <{}>", root.tag_name().name()));
    }
    let mut packet = TsharkPacket::default();
    for proto in root.children().filter(|node| node.has_tag_name("proto")) {
        let name = proto.attribute("name").unwrap_or_default();
        match name {
            "geninfo" => {
                for field in proto.children().filter(|node| node.has_tag_name("field")) {
                    let show = || field.attribute("show").and_then(|text| text.parse::<usize>().ok());
                    match field.attribute("name") {
                        Some("num") => packet.number = show().unwrap_or_default(),
                        Some("caplen") => packet.captured_len = show().unwrap_or_default(),
                        _ => {}
                    }
                }
            }
            "frame" => {
                let stack = proto.descendants().find(|node| node.attribute("name") == Some("frame.protocols"));
                if let Some(stack) = stack.and_then(|node| node.attribute("show")) {
                    packet.protocols = stack.split(':').filter(|name| !name.is_empty()).map(str::to_string).collect();
                }
                collect_notes(proto, &mut packet.notes);
            }
            _ if name.starts_with("_ws.") => {
                if name == "_ws.malformed" {
                    packet.notes.push(proto.attribute("showname").unwrap_or("Malformed packet").to_string());
                } else {
                    collect_notes(proto, &mut packet.notes);
                }
            }
            "fake-field-wrapper" => collect_notes(proto, &mut packet.notes),
            _ => {
                collect_notes(proto, &mut packet.notes);
                packet.layers.push(TsharkProtocol {
                    name: name.to_string(),
                    title: proto.attribute("showname").unwrap_or(name).to_string(),
                    position: number(proto, "pos"),
                    size: number(proto, "size").unwrap_or_default(),
                    fields: parse_fields(proto),
                });
            }
        }
    }
    Ok(packet)
}

fn number(node: roxmltree::Node<'_, '_>, attribute: &str) -> Option<usize> {
    node.attribute(attribute).and_then(|text| text.parse().ok())
}

/// The `<field>` children of `parent`, leaving out hidden fields and
/// tshark's own `_ws.*` items.
fn parse_fields(parent: roxmltree::Node<'_, '_>) -> Vec<TsharkField> {
    parent
        .children()
        .filter(|node| node.has_tag_name("field"))
        .filter(|node| node.attribute("hide") != Some("yes"))
        .filter(|node| !node.attribute("name").unwrap_or_default().starts_with("_ws."))
        .map(|node| {
            let show = node.attribute("show").unwrap_or_default().to_string();
            TsharkField {
                name: node.attribute("name").unwrap_or_default().to_string(),
                display: node.attribute("showname").map_or_else(|| show.clone(), str::to_string),
                show,
                value: node.attribute("value").unwrap_or_default().to_string(),
                position: number(node, "pos"),
                size: number(node, "size").unwrap_or_default(),
                children: parse_fields(node),
            }
        })
        .collect()
}

/// Expert messages of warning severity or worse anywhere under `node`.
fn collect_notes(node: roxmltree::Node<'_, '_>, notes: &mut Vec<String>) {
    for expert in node.descendants().filter(|n| n.attribute("name") == Some("_ws.expert")) {
        let child_show = |name: &str| expert.children().find(|n| n.attribute("name") == Some(name)).and_then(|n| n.attribute("show"));
        let severity = child_show("_ws.expert.severity").and_then(|text| text.parse::<u64>().ok());
        if severity.is_some_and(|severity| severity < EXPERT_WARNING) {
            continue;
        }
        let message = child_show("_ws.expert.message").or_else(|| expert.attribute("showname")).unwrap_or("Expert information");
        if !notes.iter().any(|known| known == message) {
            notes.push(message.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small hand-written packet in PDML's shape: tshark's own pseudo
    /// protocols, an outer header, a protocol with nested and hidden fields,
    /// a generated field without bytes, and an expert warning.
    const PACKET: &str = r#"<packet>
  <proto name="geninfo" pos="0" showname="General information" size="30">
    <field name="num" pos="0" show="7" showname="Number" value="7" size="30"/>
    <field name="caplen" pos="0" show="30" showname="Captured Length" value="1e" size="30"/>
  </proto>
  <proto name="frame" showname="Frame 7" size="30" pos="0">
    <field name="frame.protocols" showname="Protocols in frame: outer:widget" size="0" pos="0" show="outer:widget"/>
  </proto>
  <proto name="outer" showname="Outer Header, Kind: 2" size="4" pos="0">
    <field name="outer.kind" showname="Kind: 2" size="2" pos="0" show="2" value="0002"/>
    <field name="outer.len" showname="Length: 26" size="2" pos="2" show="26" value="001a"/>
  </proto>
  <proto name="widget" showname="Widget Protocol (Hello)" size="26" pos="4">
    <field name="widget.flags" showname="Flags: 0x81" size="1" pos="4" show="0x81" value="81">
      <field name="widget.flags.urgent" showname="1... .... = Urgent: Set" size="1" pos="4" show="True" value="1"/>
      <field name="widget.flags.copy" showname="Copy" hide="yes" size="1" pos="4" show="1" value="1"/>
    </field>
    <field name="widget.count" showname="Count: 3" size="0" pos="5" show="3"/>
    <field name="_ws.expert" showname="Expert Info (Warning/Protocol): Odd count" size="0" pos="5">
      <field name="_ws.expert.message" showname="Message: Odd count" hide="yes" size="0" pos="0" show="Odd count"/>
      <field name="_ws.expert.severity" showname="Severity level: Warning" size="0" pos="0" show="6291456"/>
    </field>
    <field name="_ws.expert" showname="Expert Info (Chat/Sequence): Hello" size="0" pos="5">
      <field name="_ws.expert.message" showname="Message: Hello" hide="yes" size="0" pos="0" show="Hello"/>
      <field name="_ws.expert.severity" showname="Severity level: Chat" size="0" pos="0" show="2097152"/>
    </field>
  </proto>
  <proto name="_ws.malformed" showname="[Malformed Packet: Widget]" size="0" pos="30"/>
</packet>"#;

    #[test]
    fn a_pdml_packet_gives_its_stack_its_protocols_and_their_fields() {
        let packet = parse_pdml_packet(PACKET).expect("a packet");
        assert_eq!((packet.number, packet.captured_len), (7, 30));
        assert_eq!(packet.protocols, vec!["outer", "widget"]);
        let names: Vec<&str> = packet.layers.iter().map(|layer| layer.name.as_str()).collect();
        assert_eq!(names, vec!["outer", "widget"], "geninfo, frame and _ws.* are not layers");
        let widget = &packet.layers[1];
        assert_eq!((widget.position, widget.size, widget.title.as_str()), (Some(4), 26, "Widget Protocol (Hello)"));
        let flags = &widget.fields[0];
        assert_eq!((flags.name.as_str(), flags.display.as_str(), flags.value.as_str()), ("widget.flags", "Flags: 0x81", "81"));
        assert_eq!(flags.children.len(), 1, "hidden fields are left out");
        assert_eq!(widget.fields.len(), 2, "expert items are notes, not fields");
        assert_eq!(packet.notes, vec!["Odd count".to_string(), "[Malformed Packet: Widget]".to_string()], "chat-level expert info is left out");
        assert_eq!(packet.top_protocol(), Some("widget"));
    }

    #[test]
    fn broken_pdml_is_reported_rather_than_parsed() {
        assert!(parse_pdml_packet("<packet><proto name=\"x\"").is_err());
        assert!(parse_pdml_packet("<pdml/>").unwrap_err().contains("<packet>"));
    }

    #[test]
    fn packets_are_taken_from_streamed_output_as_each_one_completes() {
        let mut pending = String::from("<?xml version=\"1.0\"?>\n<pdml>\n<packet><proto name=\"a\"/></packet>\n<packet><proto na");
        let first = take_packet_elements(&mut pending);
        assert_eq!(first, vec!["<packet><proto name=\"a\"/></packet>".to_string()]);
        assert_eq!(pending, "<packet><proto na");
        pending.push_str("me=\"b\"/></packet>\n</pdml>\n");
        let second = take_packet_elements(&mut pending);
        assert_eq!(second, vec!["<packet><proto name=\"b\"/></packet>".to_string()]);
        assert!(take_packet_elements(&mut pending).is_empty());
        assert!(pending.len() <= "<packet>".len(), "the closing tags are dropped: {pending:?}");
    }

    #[test]
    fn a_character_split_between_two_reads_is_joined_before_parsing() {
        let text = "Größe";
        let bytes = text.as_bytes();
        // "Gr" and the first of the two bytes of "ö".
        let mut tail = bytes[..3].to_vec();
        let mut out = String::new();
        append_utf8(&mut tail, &mut out);
        assert_eq!(out, "Gr");
        tail.extend_from_slice(&bytes[3..]);
        append_utf8(&mut tail, &mut out);
        assert_eq!(out, text);
        assert!(tail.is_empty());
    }

    #[test]
    fn a_chosen_tshark_that_does_not_exist_is_not_found() {
        assert_eq!(find_tshark(Some(Path::new("/no/such/dir/tshark"))), None);
    }

    #[test]
    fn a_missing_program_is_a_clear_error() {
        let cancel = AtomicBool::new(false);
        let error = decode_file(Path::new("/no/such/dir/tshark"), Path::new("capture.pcap"), &RunLimits::default(), &cancel, |_| {}).unwrap_err();
        assert!(matches!(error, TsharkError::Start { .. }));
        assert!(error.to_string().contains("could not be started"), "{error}");
    }
}
