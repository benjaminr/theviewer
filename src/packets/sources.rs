//! Where packets come from: the protocol analysis's messages, captures inside
//! the document (pcap and pcapng, and the older formats in [`snoop`] and
//! [`netmon`]), a range
//! cut into records, a single range, or a cluster of aligned messages. Each
//! source is a pure function returning a [`PacketSet`] whose offsets are
//! document offsets.

use std::fmt;

use pcap_parser::pcapng::Block;

use super::split::{self, BytePattern, LengthField, PatternMode};
use super::{LinkKind, Packet, PacketSet};
use crate::parsers::guarded;
use crate::protocol::{self, Framing, Message};

pub mod netmon;
pub mod snoop;

/// Size of a classic pcap file header and of each record header.
const PCAP_FILE_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;
/// Where packet data starts inside a pcapng enhanced packet block and a simple
/// packet block.
const PCAPNG_ENHANCED_DATA_OFFSET: usize = 28;
const PCAPNG_SIMPLE_DATA_OFFSET: usize = 12;
/// The four magic numbers of classic pcap: micro- and nanosecond timestamps,
/// in either byte order.
const PCAP_MAGICS: [[u8; 4]; 4] = [[0xD4, 0xC3, 0xB2, 0xA1], [0xA1, 0xB2, 0xC3, 0xD4], [0x4D, 0x3C, 0xB2, 0xA1], [0xA1, 0xB2, 0x3C, 0x4D]];
/// A pcapng section header block's type, the same in either byte order.
const PCAPNG_SECTION_MAGIC: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];
/// The byte-order magic inside a section header, as stored little and big endian.
const PCAPNG_BYTE_ORDER_LE: [u8; 4] = [0x4D, 0x3C, 0x2B, 0x1A];
const PCAPNG_BYTE_ORDER_BE: [u8; 4] = [0x1A, 0x2B, 0x3C, 0x4D];
/// Timestamp units per second when an interface does not say.
const DEFAULT_PCAPNG_UNITS_PER_SECOND: u64 = 1_000_000;
const MICROSECONDS: f64 = 1e6;
const NANOSECONDS: f64 = 1e9;
/// Most captures `find_captures` reports.
pub const MAX_CAPTURES: usize = 64;

/// Why a source produced no packets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// The range to split holds no bytes.
    EmptyRange,
    /// A record length of zero was asked for.
    ZeroRecordLength,
    /// The delimiter is empty.
    EmptyDelimiter,
    /// The delimiter never occurs in the range.
    DelimiterNotFound { delimiter: String },
    /// The bytes do not start with a pcap or pcapng header.
    NotACapture { offset: usize },
    /// The capture's header was read, but no packet record could be.
    NoPacketsInCapture { offset: usize },
    /// The capture's header names a format we know but cannot read, for the
    /// reason given.
    UnreadableCapture { offset: usize, format: &'static str, reason: String },
    /// There were no messages to take packets from.
    NoMessages,
    /// A splitting rule found no frame, for the reason given.
    NoFrames { reason: String },
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceError::EmptyRange => write!(f, "The range holds no bytes; select some first."),
            SourceError::ZeroRecordLength => write!(f, "The record length must be at least 1 byte."),
            SourceError::EmptyDelimiter => write!(f, "Give the delimiter as hex bytes, such as 0D0A."),
            SourceError::DelimiterNotFound { delimiter } => write!(f, "The delimiter {delimiter} does not occur in the range."),
            SourceError::NotACapture { offset } => write!(f, "There is no pcap or pcapng header at {offset:#x}."),
            SourceError::NoPacketsInCapture { offset } => write!(f, "The capture at {offset:#x} has a header but no readable packet records."),
            SourceError::UnreadableCapture { offset, format, reason } => write!(f, "The {format} capture at {offset:#x} cannot be read: {reason}."),
            SourceError::NoMessages => write!(f, "There are no messages to take packets from."),
            SourceError::NoFrames { reason } => write!(f, "No frames: {reason}."),
        }
    }
}

impl std::error::Error for SourceError {}

// ---------------------------------------------------------------------------
// Messages, clusters and ranges
// ---------------------------------------------------------------------------

/// One packet per protocol message. `base` is the document offset the
/// messages' offsets are counted from.
pub fn from_messages(messages: &[Message], base: usize, name: &str) -> Result<PacketSet, SourceError> {
    if messages.is_empty() {
        return Err(SourceError::NoMessages);
    }
    let mut set = PacketSet::new(name, format!("{} messages split by the protocol framing", messages.len()));
    for (index, message) in messages.iter().enumerate() {
        let packet = Packet::new(base.saturating_add(message.offset), message.len, LinkKind::Unknown, format!("message {index}"));
        if !set.push(packet) {
            break;
        }
    }
    Ok(set)
}

/// One packet per member of an alignment cluster. `offsets` and `lengths`
/// describe every aligned message; `members` index into them.
pub fn from_cluster(offsets: &[usize], lengths: &[usize], members: &[usize], name: &str) -> Result<PacketSet, SourceError> {
    let mut set = PacketSet::new(name, format!("{} messages of one type from the message alignment", members.len()));
    for &member in members {
        let (Some(&offset), Some(&len)) = (offsets.get(member), lengths.get(member)) else { continue };
        if !set.push(Packet::new(offset, len, LinkKind::Unknown, format!("message {member}"))) {
            break;
        }
    }
    if set.is_empty() {
        return Err(SourceError::NoMessages);
    }
    Ok(set)
}

/// A single range as one packet.
pub fn single(offset: usize, len: usize, link: LinkKind) -> Result<PacketSet, SourceError> {
    if len == 0 {
        return Err(SourceError::EmptyRange);
    }
    let mut set = PacketSet::new(format!("range at {offset:#x}"), format!("{len} bytes added by hand"));
    set.push(Packet::new(offset, len, link, format!("range {offset:#x}")));
    Ok(set)
}

/// The range `start..start + len` cut into records of `record_len` bytes; a
/// shorter last record is kept.
pub fn split_fixed(start: usize, len: usize, record_len: usize, link: LinkKind) -> Result<PacketSet, SourceError> {
    if len == 0 {
        return Err(SourceError::EmptyRange);
    }
    if record_len == 0 {
        return Err(SourceError::ZeroRecordLength);
    }
    let mut set = PacketSet::new(format!("{record_len}-byte records at {start:#x}"), format!("{len} bytes cut every {record_len} bytes"));
    set.recipe = Recipe::Records { start, len, record_len, link };
    let mut at = 0;
    let mut index = 0;
    while at < len {
        let packet_len = record_len.min(len - at);
        if !set.push(Packet::new(start + at, packet_len, link, format!("record {index}"))) {
            break;
        }
        at += record_len;
        index += 1;
    }
    Ok(set)
}

/// How a delimiter relates to the packets around it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MarkerMode {
    /// The delimiter separates packets and belongs to neither.
    #[default]
    Separator,
    /// The marker (a sync word) starts every packet and is kept in it.
    StartsPacket,
}

/// Cut `bytes` (which sit at document offset `base`) at every occurrence of
/// `marker`. Empty pieces between adjacent separators are skipped.
pub fn split_by_marker(bytes: &[u8], base: usize, marker: &[u8], mode: MarkerMode, link: LinkKind) -> Result<PacketSet, SourceError> {
    if bytes.is_empty() {
        return Err(SourceError::EmptyRange);
    }
    if marker.is_empty() {
        return Err(SourceError::EmptyDelimiter);
    }
    let hits = occurrences(bytes, marker);
    let shown = super::hex_preview(marker, marker.len());
    if hits.is_empty() {
        return Err(SourceError::DelimiterNotFound { delimiter: shown });
    }
    let description = match mode {
        MarkerMode::Separator => format!("{} bytes cut at each {shown}", bytes.len()),
        MarkerMode::StartsPacket => format!("{} bytes cut before each {shown}", bytes.len()),
    };
    let mut set = PacketSet::new(format!("split at {shown}"), description);
    set.recipe = Recipe::Marker { start: base, len: bytes.len(), marker: marker.to_vec(), mode, link };
    let pieces = match mode {
        MarkerMode::Separator => separated_pieces(&hits, marker.len(), bytes.len()),
        MarkerMode::StartsPacket => started_pieces(&hits, bytes.len()),
    };
    for (index, (start, end)) in pieces.into_iter().enumerate() {
        if !set.push(Packet::new(base + start, end - start, link, format!("piece {index}"))) {
            break;
        }
    }
    Ok(set)
}

/// Non-overlapping positions of `needle` in `haystack`.
fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut at = 0;
    while at + needle.len() <= haystack.len() {
        if &haystack[at..at + needle.len()] == needle {
            hits.push(at);
            at += needle.len();
        } else {
            at += 1;
        }
    }
    hits
}

/// The non-empty stretches between separators, as `(start, end)`.
fn separated_pieces(hits: &[usize], marker_len: usize, total: usize) -> Vec<(usize, usize)> {
    let mut pieces = Vec::new();
    let mut start = 0;
    for &hit in hits {
        if hit > start {
            pieces.push((start, hit));
        }
        start = hit + marker_len;
    }
    if start < total {
        pieces.push((start, total));
    }
    pieces
}

/// Pieces that each start at a marker; bytes before the first marker form
/// their own piece.
fn started_pieces(hits: &[usize], total: usize) -> Vec<(usize, usize)> {
    let mut starts: Vec<usize> = hits.to_vec();
    if starts.first() != Some(&0) {
        starts.insert(0, 0);
    }
    let mut pieces = Vec::new();
    for (index, &start) in starts.iter().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(total);
        pieces.push((start, end));
    }
    pieces
}

// ---------------------------------------------------------------------------
// Finding the packets again after an edit
// ---------------------------------------------------------------------------

/// How a set's packets were found, so they can be found again once the
/// document has been edited: inserting or deleting bytes moves packets, and
/// overwriting a length or a delimiter changes where they split.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Recipe {
    /// The packets were placed by hand (a range, or a cluster of messages)
    /// and stay where they are.
    #[default]
    Fixed,
    /// A pcap or pcapng capture whose header is at `offset`.
    Capture { offset: usize },
    /// A range split with a protocol framing.
    Framing { start: usize, len: usize, framing: Framing },
    /// A range cut into records of one length.
    Records { start: usize, len: usize, record_len: usize, link: LinkKind },
    /// A range cut at a delimiter or sync word.
    Marker { start: usize, len: usize, marker: Vec<u8>, mode: MarkerMode, link: LinkKind },
    /// A range cut into frames by a length field inside each.
    LengthField { start: usize, len: usize, field: LengthField, link: LinkKind },
    /// A range cut at every match of a pattern (which may hold wildcards).
    Pattern { start: usize, len: usize, pattern: BytePattern, mode: PatternMode, link: LinkKind },
}

impl Recipe {
    /// The document range to read again, after the document grew by `growth`
    /// bytes (negative when it shrank), or `None` for packets placed by hand.
    /// A capture is read to the end of the document, at most `read_limit`
    /// bytes; a split range grows and shrinks with the document.
    pub fn range(&self, growth: i64, document_len: usize, read_limit: usize) -> Option<(usize, usize)> {
        let grown = |start: usize, len: usize| {
            let len = (len as i64 + growth).max(0) as usize;
            let start = start.min(document_len);
            (start, len.min(document_len - start))
        };
        match self {
            Recipe::Fixed => None,
            Recipe::Capture { offset } => {
                let offset = (*offset).min(document_len);
                Some((offset, (document_len - offset).min(read_limit)))
            }
            Recipe::Framing { start, len, .. }
            | Recipe::Records { start, len, .. }
            | Recipe::Marker { start, len, .. }
            | Recipe::LengthField { start, len, .. }
            | Recipe::Pattern { start, len, .. } => Some(grown(*start, *len)),
        }
    }

    /// Find the packets again in `bytes`, which are the document range
    /// `range` returned, starting at document offset `start`.
    pub fn rebuild(&self, bytes: &[u8], start: usize) -> Result<PacketSet, SourceError> {
        match self {
            Recipe::Fixed => Err(SourceError::NoMessages),
            Recipe::Capture { .. } => from_capture(bytes, start),
            Recipe::Framing { framing, .. } => from_framing(bytes, start, framing),
            Recipe::Records { record_len, link, .. } => split_fixed(start, bytes.len(), *record_len, *link),
            Recipe::Marker { marker, mode, link, .. } => split_by_marker(bytes, start, marker, *mode, *link),
            Recipe::LengthField { field, link, .. } => split::split_by_length_field(bytes, start, field, *link),
            Recipe::Pattern { pattern, mode, link, .. } => split::split_by_pattern(bytes, start, pattern, *mode, *link),
        }
    }
}

/// `bytes` (at document offset `start`) split with `framing`, one packet per
/// message.
pub fn from_framing(bytes: &[u8], start: usize, framing: &Framing) -> Result<PacketSet, SourceError> {
    let messages = protocol::split(bytes, framing, super::MAX_PACKETS + 1);
    let mut set = from_messages(&messages, start, &format!("messages at {start:#x}"))?;
    set.description = format!("{} messages, {}", messages.len(), framing.describe());
    set.recipe = Recipe::Framing { start, len: bytes.len(), framing: framing.clone() };
    Ok(set)
}

// ---------------------------------------------------------------------------
// Captures
// ---------------------------------------------------------------------------

/// Which capture container a file uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureFormat {
    Pcap,
    PcapNg,
    /// Sun snoop (RFC 1761).
    Snoop,
    /// Microsoft Network Monitor 2.x.
    NetMon,
}

impl CaptureFormat {
    pub fn label(self) -> &'static str {
        match self {
            CaptureFormat::Pcap => "pcap",
            CaptureFormat::PcapNg => "pcapng",
            CaptureFormat::Snoop => "snoop",
            CaptureFormat::NetMon => "Network Monitor",
        }
    }
}

/// A capture found inside the document.
#[derive(Clone, Debug, PartialEq)]
pub struct CaptureLocation {
    /// Document offset of the capture's file header.
    pub offset: usize,
    pub format: CaptureFormat,
    /// The link type of the first interface.
    pub link: LinkKind,
    pub packets: usize,
    /// Bytes from the header to the end of the last readable record.
    pub len: usize,
}

impl CaptureLocation {
    pub fn describe(&self) -> String {
        format!("{} at {:#x} · {} · {} packets", self.format.label(), self.offset, self.link.label(), self.packets)
    }
}

/// Which capture format `bytes` starts with, if any.
pub fn capture_format(bytes: &[u8]) -> Option<CaptureFormat> {
    let start = bytes.get(..4)?;
    if PCAP_MAGICS.iter().any(|magic| magic == start) {
        return Some(CaptureFormat::Pcap);
    }
    if snoop::looks_like(bytes) {
        return Some(CaptureFormat::Snoop);
    }
    if netmon::looks_like(bytes) {
        return Some(CaptureFormat::NetMon);
    }
    let byte_order = bytes.get(8..12)?;
    (start == PCAPNG_SECTION_MAGIC && (byte_order == PCAPNG_BYTE_ORDER_LE || byte_order == PCAPNG_BYTE_ORDER_BE)).then_some(CaptureFormat::PcapNg)
}

/// The packets of the capture that starts at `bytes[0]`,
/// which sits at document offset `base`.
pub fn from_capture(bytes: &[u8], base: usize) -> Result<PacketSet, SourceError> {
    let (mut set, _) = read_capture(bytes, base)?;
    set.recipe = Recipe::Capture { offset: base };
    Ok(set)
}

/// The packets and the number of bytes the capture spans.
fn read_capture(bytes: &[u8], base: usize) -> Result<(PacketSet, usize), SourceError> {
    let (set, extent) = match capture_format(bytes) {
        Some(CaptureFormat::Pcap) => read_pcap(bytes, base)?,
        Some(CaptureFormat::PcapNg) => read_pcapng(bytes, base),
        Some(CaptureFormat::Snoop) => snoop::read(bytes, base)?,
        Some(CaptureFormat::NetMon) => netmon::read(bytes, base)?,
        None => return Err(SourceError::NotACapture { offset: base }),
    };
    if set.is_empty() {
        return Err(SourceError::NoPacketsInCapture { offset: base });
    }
    Ok((set, extent))
}

/// One classic pcap record header, read without borrowing the data.
struct PcapRecord {
    seconds: u32,
    fraction: u32,
    caplen: usize,
    available: usize,
}

fn read_pcap(bytes: &[u8], base: usize) -> Result<(PacketSet, usize), SourceError> {
    let header = guarded(|| pcap_parser::parse_pcap_header(bytes).ok().map(|(_, header)| header)).ok_or(SourceError::NotACapture { offset: base })?;
    let big_endian = header.is_bigendian();
    let fraction_units = if header.is_nanosecond_precision() { NANOSECONDS } else { MICROSECONDS };
    let link_type = header.network.0 as u32;
    let link = LinkKind::from_pcap_link_type(link_type);
    let mut set = PacketSet::new(format!("pcap capture at {base:#x}"), format!("pcap capture, link type {link_type} ({})", link.label()));
    let mut at = PCAP_FILE_HEADER_LEN;
    while at < bytes.len() {
        let rest = &bytes[at..];
        let record = guarded(|| {
            let parsed = if big_endian { pcap_parser::parse_pcap_frame_be(rest) } else { pcap_parser::parse_pcap_frame(rest) };
            parsed.ok().map(|(_, block)| PcapRecord {
                seconds: block.ts_sec,
                fraction: block.ts_usec,
                caplen: block.caplen as usize,
                available: block.data.len(),
            })
        });
        let Some(record) = record else { break };
        let timestamp = record.seconds as f64 + record.fraction as f64 / fraction_units;
        let packet = Packet::new(base + at + PCAP_RECORD_HEADER_LEN, record.caplen.min(record.available), link, format!("pcap record {}", set.len() + 1))
            .with_timestamp(Some(timestamp))
            .with_link_type(link_type)
            .with_record(base + at, (PCAP_RECORD_HEADER_LEN + record.caplen).min(bytes.len() - at));
        if !set.push(packet) {
            break;
        }
        at += PCAP_RECORD_HEADER_LEN + record.caplen;
    }
    Ok((set, at.min(bytes.len())))
}

/// What an interface description block says about its packets.
#[derive(Clone, Copy, Debug)]
struct Interface {
    link: LinkKind,
    link_type: u32,
    units_per_second: u64,
    offset_seconds: i64,
}

/// The parts of a pcapng block the packet list needs.
enum BlockFacts {
    Section,
    Interface(Interface),
    Packet { interface: usize, ticks: Option<u64>, data_offset: usize, len: usize },
    Other,
}

fn block_facts(block: &Block<'_>) -> BlockFacts {
    match block {
        Block::SectionHeader(_) => BlockFacts::Section,
        Block::InterfaceDescription(interface) => BlockFacts::Interface(Interface {
            link: LinkKind::from_pcap_link_type(interface.linktype.0 as u32),
            link_type: interface.linktype.0 as u32,
            units_per_second: interface.ts_resolution().filter(|units| *units > 0).unwrap_or(DEFAULT_PCAPNG_UNITS_PER_SECOND),
            offset_seconds: interface.if_tsoffset,
        }),
        Block::EnhancedPacket(packet) => BlockFacts::Packet {
            interface: packet.if_id as usize,
            ticks: Some((u64::from(packet.ts_high) << 32) | u64::from(packet.ts_low)),
            data_offset: PCAPNG_ENHANCED_DATA_OFFSET,
            len: (packet.caplen as usize).min(packet.data.len()),
        },
        Block::SimplePacket(packet) => BlockFacts::Packet {
            interface: 0,
            ticks: None,
            data_offset: PCAPNG_SIMPLE_DATA_OFFSET,
            len: (packet.origlen as usize).min(packet.data.len()),
        },
        _ => BlockFacts::Other,
    }
}

fn read_pcapng(bytes: &[u8], base: usize) -> (PacketSet, usize) {
    let mut set = PacketSet::new(format!("pcapng capture at {base:#x}"), "pcapng capture".to_string());
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut big_endian = false;
    let mut at = 0;
    while at < bytes.len() {
        let rest = &bytes[at..];
        if rest.starts_with(&PCAPNG_SECTION_MAGIC) {
            big_endian = rest.get(8..12) == Some(&PCAPNG_BYTE_ORDER_BE[..]);
        }
        let parsed = guarded(|| {
            let result = if big_endian { pcap_parser::pcapng::parse_block_be(rest) } else { pcap_parser::pcapng::parse_block_le(rest) };
            result.ok().map(|(remaining, block)| (rest.len() - remaining.len(), block_facts(&block)))
        });
        let Some((consumed, facts)) = parsed else { break };
        if consumed == 0 {
            break;
        }
        match facts {
            BlockFacts::Section => interfaces.clear(),
            BlockFacts::Interface(interface) => interfaces.push(interface),
            BlockFacts::Packet { interface, ticks, data_offset, len } => {
                let described = interfaces.get(interface).copied();
                let link = described.map_or(LinkKind::Ethernet, |i| i.link);
                let link_type = described.map_or(super::LINKTYPE_ETHERNET, |i| i.link_type);
                let timestamp = ticks.map(|ticks| match described {
                    Some(i) => ticks as f64 / i.units_per_second as f64 + i.offset_seconds as f64,
                    None => ticks as f64 / DEFAULT_PCAPNG_UNITS_PER_SECOND as f64,
                });
                let packet = Packet::new(base + at + data_offset, len, link, format!("pcapng packet {}", set.len() + 1))
                    .with_timestamp(timestamp)
                    .with_link_type(link_type)
                    .with_record(base + at, consumed);
                if !set.push(packet) {
                    break;
                }
            }
            BlockFacts::Other => {}
        }
        at += consumed;
    }
    if let Some(first) = interfaces.first() {
        set.description = format!("pcapng capture, {} interface{} ({} first)", interfaces.len(), if interfaces.len() == 1 { "" } else { "s" }, first.link.label());
    }
    (set, at.min(bytes.len()))
}

/// Every capture whose header lies in `bytes` (which sit at
/// document offset `base`), at most [`MAX_CAPTURES`]. A capture is reported
/// only when at least one packet record can be read.
pub fn find_captures(bytes: &[u8], base: usize) -> Vec<CaptureLocation> {
    let mut found = Vec::new();
    let mut at = 0;
    while at + 4 <= bytes.len() && found.len() < MAX_CAPTURES {
        let format = match bytes[at] {
            0xD4 | 0xA1 | 0x4D | 0x0A | b's' | b'G' => capture_format(&bytes[at..]),
            _ => None,
        };
        let Some(format) = format else {
            at += 1;
            continue;
        };
        match read_capture(&bytes[at..], base + at) {
            Ok((set, extent)) => {
                let link = set.packets.first().map_or(LinkKind::Unknown, |p| p.link);
                found.push(CaptureLocation { offset: base + at, format, link, packets: set.len(), len: extent });
                at += extent.max(1);
            }
            Err(_) => at += 1,
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A little-endian microsecond pcap with the given packets and timestamps.
    fn pcap_file(link_type: u32, packets: &[(&[u8], u32, u32)]) -> Vec<u8> {
        let mut file = Vec::new();
        file.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
        file.extend_from_slice(&2u16.to_le_bytes());
        file.extend_from_slice(&4u16.to_le_bytes());
        file.extend_from_slice(&0i32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&65_535u32.to_le_bytes());
        file.extend_from_slice(&link_type.to_le_bytes());
        for (data, seconds, micros) in packets {
            file.extend_from_slice(&seconds.to_le_bytes());
            file.extend_from_slice(&micros.to_le_bytes());
            file.extend_from_slice(&(data.len() as u32).to_le_bytes());
            file.extend_from_slice(&(data.len() as u32).to_le_bytes());
            file.extend_from_slice(data);
        }
        file
    }

    /// A little-endian pcapng with one Ethernet interface (nanosecond
    /// resolution) and enhanced packet blocks.
    fn pcapng_file(packets: &[(&[u8], u64)]) -> Vec<u8> {
        let mut file = Vec::new();
        // Section header: type, length 28, byte order, version 1.0, section length -1, length.
        file.extend_from_slice(&PCAPNG_SECTION_MAGIC);
        file.extend_from_slice(&28u32.to_le_bytes());
        file.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&(-1i64).to_le_bytes());
        file.extend_from_slice(&28u32.to_le_bytes());
        // Interface description with an if_tsresol option of 9 (nanoseconds).
        let mut options = Vec::new();
        options.extend_from_slice(&9u16.to_le_bytes());
        options.extend_from_slice(&1u16.to_le_bytes());
        options.extend_from_slice(&[9, 0, 0, 0]);
        options.extend_from_slice(&[0, 0, 0, 0]);
        let idb_len = 20 + options.len() as u32;
        file.extend_from_slice(&1u32.to_le_bytes());
        file.extend_from_slice(&idb_len.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&options);
        file.extend_from_slice(&idb_len.to_le_bytes());
        for (data, nanoseconds) in packets {
            let padded = data.len().div_ceil(4) * 4;
            let block_len = (32 + padded) as u32;
            file.extend_from_slice(&6u32.to_le_bytes());
            file.extend_from_slice(&block_len.to_le_bytes());
            file.extend_from_slice(&0u32.to_le_bytes());
            file.extend_from_slice(&((nanoseconds >> 32) as u32).to_le_bytes());
            file.extend_from_slice(&(*nanoseconds as u32).to_le_bytes());
            file.extend_from_slice(&(data.len() as u32).to_le_bytes());
            file.extend_from_slice(&(data.len() as u32).to_le_bytes());
            file.extend_from_slice(data);
            file.resize(file.len() + padded - data.len(), 0);
            file.extend_from_slice(&block_len.to_le_bytes());
        }
        file
    }

    #[test]
    fn a_pcap_inside_a_document_yields_its_packets_with_timestamps_and_document_offsets() {
        let capture = pcap_file(1, &[(b"first packet", 100, 250_000), (b"second", 101, 0)]);
        let mut document = vec![0x55u8; 40];
        document.extend_from_slice(&capture);
        let set = from_capture(&document[40..], 40).expect("a capture");
        assert_eq!(set.len(), 2);
        let first = &set.packets[0];
        assert_eq!(first.link, LinkKind::Ethernet);
        assert_eq!(&document[first.offset..first.end()], b"first packet");
        assert_eq!(first.timestamp, Some(100.25));
        assert_eq!(first.record, Some((40 + 24, 16 + 12)), "the record header goes with the packet when it is deleted");
        assert_eq!(&document[set.packets[1].offset..set.packets[1].end()], b"second");
    }

    #[test]
    fn a_pcapng_capture_uses_the_interface_link_type_and_timestamp_resolution() {
        let file = pcapng_file(&[(b"abcde", 1_500_000_000), (b"xyz", 2_000_000_000)]);
        let set = from_capture(&file, 0).expect("a capture");
        assert_eq!(set.len(), 2);
        assert_eq!(&file[set.packets[0].offset..set.packets[0].end()], b"abcde");
        assert_eq!(set.packets[0].link, LinkKind::Ethernet);
        assert!((set.packets[0].timestamp.unwrap() - 1.5).abs() < 1e-9);
        assert!((set.packets[1].timestamp.unwrap() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn captures_are_found_anywhere_in_the_document_and_garbage_is_ignored() {
        let mut document = vec![0xD4u8, 0xC3, 0xB2, 0xA1, 0, 0];
        document.extend(std::iter::repeat_n(7u8, 100));
        let pcap_at = document.len();
        document.extend_from_slice(&pcap_file(101, &[(b"\x45packet", 1, 0)]));
        document.extend(std::iter::repeat_n(9u8, 33));
        let pcapng_at = document.len();
        document.extend_from_slice(&pcapng_file(&[(b"frame", 5)]));
        let found = find_captures(&document, 1000);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].offset, 1000 + pcap_at);
        assert_eq!(found[0].format, CaptureFormat::Pcap);
        assert_eq!(found[0].link, LinkKind::RawIp);
        assert_eq!(found[1].offset, 1000 + pcapng_at);
        assert_eq!(found[1].format, CaptureFormat::PcapNg);
        assert_eq!(found[1].packets, 1);
    }

    #[test]
    fn a_snoop_capture_inside_a_document_is_found_and_read_at_its_offset() {
        let mut document = b"snoop\0\0\0 is only a header here".to_vec();
        let at = document.len();
        document.extend_from_slice(&snoop::tests::snoop_file(4, &[(b"frame one", 7, 0), (b"frame two", 8, 0)]));
        document.extend_from_slice(b"trailing bytes");
        let found = find_captures(&document, 0);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!((found[0].offset, found[0].format, found[0].link, found[0].packets), (at, CaptureFormat::Snoop, LinkKind::Ethernet, 2));
        let set = from_capture(&document[at..], at).expect("a capture");
        assert_eq!(&document[set.packets[1].offset..set.packets[1].end()], b"frame two");
        assert_eq!(set.recipe, Recipe::Capture { offset: at });
    }

    #[test]
    fn a_network_monitor_capture_inside_a_document_is_found_and_read_at_its_offset() {
        let mut document = b"GMBU\x00\x02 but too short to be a capture".to_vec();
        let at = document.len();
        let frames = [netmon::tests::TestFrame { data: b"frame one", offset_micros: 0, media_type: 1 }, netmon::tests::TestFrame { data: b"frame two", offset_micros: 10, media_type: 1 }];
        document.extend_from_slice(&netmon::tests::netmon_file(0x01, &frames));
        let capture_end = document.len();
        document.extend_from_slice(b"trailing bytes");
        let found = find_captures(&document, 0);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!((found[0].offset, found[0].format, found[0].link, found[0].packets, found[0].len), (at, CaptureFormat::NetMon, LinkKind::Ethernet, 2, capture_end - at));
        let set = from_capture(&document[at..], at).expect("a capture");
        assert_eq!(&document[set.packets[1].offset..set.packets[1].end()], b"frame two");
    }

    #[test]
    fn a_truncated_capture_keeps_the_complete_records_and_a_header_alone_is_an_error() {
        let mut capture = pcap_file(1, &[(b"whole", 1, 0), (b"cut short", 2, 0)]);
        capture.truncate(capture.len() - 3);
        let set = from_capture(&capture, 0).expect("the first record");
        assert_eq!(set.len(), 1);
        let header_only = pcap_file(1, &[]);
        assert_eq!(from_capture(&header_only, 0), Err(SourceError::NoPacketsInCapture { offset: 0 }));
        assert_eq!(from_capture(b"not a capture at all", 9), Err(SourceError::NotACapture { offset: 9 }));
    }

    #[test]
    fn splitting_by_length_keeps_a_short_last_record() {
        let set = split_fixed(100, 25, 10, LinkKind::Unknown).expect("records");
        let ranges: Vec<(usize, usize)> = set.packets.iter().map(|p| (p.offset, p.len)).collect();
        assert_eq!(ranges, vec![(100, 10), (110, 10), (120, 5)]);
        assert_eq!(split_fixed(0, 10, 0, LinkKind::Unknown), Err(SourceError::ZeroRecordLength));
        assert_eq!(split_fixed(0, 0, 4, LinkKind::Unknown), Err(SourceError::EmptyRange));
    }

    #[test]
    fn splitting_by_length_stops_at_the_packet_cap() {
        let set = split_fixed(0, super::super::MAX_PACKETS * 2, 1, LinkKind::Unknown).expect("records");
        assert_eq!(set.len(), super::super::MAX_PACKETS);
        assert!(set.capped);
    }

    #[test]
    fn splitting_by_a_delimiter_drops_it_and_skips_empty_pieces() {
        let bytes = b"one\r\ntwo\r\n\r\nthree";
        let set = split_by_marker(bytes, 10, b"\r\n", MarkerMode::Separator, LinkKind::Unknown).expect("pieces");
        let pieces: Vec<&[u8]> = set.packets.iter().map(|p| &bytes[p.offset - 10..p.end() - 10]).collect();
        assert_eq!(pieces, vec![&b"one"[..], b"two", b"three"]);
    }

    #[test]
    fn splitting_at_a_sync_word_keeps_it_at_the_start_of_each_packet() {
        let bytes = b"xx\xAA\x55abc\xAA\x55de";
        let set = split_by_marker(bytes, 0, &[0xAA, 0x55], MarkerMode::StartsPacket, LinkKind::Unknown).expect("pieces");
        let pieces: Vec<&[u8]> = set.packets.iter().map(|p| &bytes[p.offset..p.end()]).collect();
        assert_eq!(pieces, vec![&b"xx"[..], b"\xAA\x55abc", b"\xAA\x55de"]);
        assert!(matches!(split_by_marker(bytes, 0, b"zz", MarkerMode::Separator, LinkKind::Unknown), Err(SourceError::DelimiterNotFound { .. })));
        assert_eq!(split_by_marker(bytes, 0, b"", MarkerMode::Separator, LinkKind::Unknown), Err(SourceError::EmptyDelimiter));
    }

    #[test]
    fn messages_and_cluster_members_become_packets_at_document_offsets() {
        let messages = [Message { offset: 0, len: 4 }, Message { offset: 4, len: 6 }];
        let set = from_messages(&messages, 0x100, "framing").expect("packets");
        assert_eq!(set.packets[1].offset, 0x104);
        assert_eq!(set.packets[1].len, 6);
        assert_eq!(from_messages(&[], 0, "x"), Err(SourceError::NoMessages));

        let cluster = from_cluster(&[10, 20, 30], &[3, 4, 5], &[2, 0, 9], "type 0").expect("members");
        let ranges: Vec<(usize, usize)> = cluster.packets.iter().map(|p| (p.offset, p.len)).collect();
        assert_eq!(ranges, vec![(30, 5), (10, 3)], "unknown members are skipped");
    }

    #[test]
    fn a_split_range_grows_with_the_document_and_splits_again() {
        let set = split_fixed(10, 20, 10, LinkKind::Unknown).expect("records");
        assert_eq!(set.recipe.range(5, 100, usize::MAX), Some((10, 25)));
        assert_eq!(set.recipe.range(-30, 100, usize::MAX), Some((10, 0)));
        let bytes = vec![0u8; 25];
        let again = set.recipe.rebuild(&bytes, 10).expect("records");
        assert_eq!(again.len(), 3);
        assert_eq!(again.recipe, Recipe::Records { start: 10, len: 25, record_len: 10, link: LinkKind::Unknown });
        assert_eq!(Recipe::Fixed.range(5, 100, usize::MAX), None);
    }

    #[test]
    fn a_capture_is_read_again_from_its_header_to_the_end_of_the_document() {
        let capture = pcap_file(1, &[(b"one", 1, 0), (b"two", 2, 0)]);
        let set = from_capture(&capture, 0).expect("a capture");
        assert_eq!(set.recipe, Recipe::Capture { offset: 0 });
        assert_eq!(set.recipe.range(0, capture.len(), 16), Some((0, 16)), "limited");
        let mut edited = capture.clone();
        edited.truncate(24 + 16 + 3);
        assert_eq!(set.recipe.rebuild(&edited, 0).expect("still readable").len(), 1);
    }

    #[test]
    fn framed_messages_are_split_again_with_the_same_framing() {
        let recipe = Recipe::Framing { start: 4, len: 8, framing: Framing::Delimiter { bytes: vec![b';'] } };
        let set = recipe.rebuild(b"ab;cd;ef;gh", 4).expect("messages");
        let ranges: Vec<(usize, usize)> = set.packets.iter().map(|p| (p.offset, p.len)).collect();
        assert_eq!(ranges, vec![(4, 2), (7, 2), (10, 2), (13, 2)]);
    }

    #[test]
    fn a_single_range_is_one_packet() {
        let set = single(5, 9, LinkKind::RawIp).expect("a packet");
        assert_eq!(set.packets, vec![Packet::new(5, 9, LinkKind::RawIp, "range 0x5")]);
        assert_eq!(single(5, 0, LinkKind::RawIp), Err(SourceError::EmptyRange));
    }
}
