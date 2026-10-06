//! Endace ERF (Extensible Record Format) captures, from Endace's published
//! description of the record types.
//!
//! An ERF file is nothing but records, with no file header and so no magic
//! number. Each record has a 16-byte header: a 64-bit little-endian
//! timestamp (seconds in the upper 32 bits, a binary fraction in the lower),
//! a type byte whose top bit says extension headers follow, a flags byte,
//! and three big-endian 16-bit numbers: the record length, a loss counter
//! and the length on the wire. Extension headers are 8 bytes each, the top
//! bit of each one's first byte saying whether another follows. Ethernet
//! records then have two bytes (an offset and a pad) before the frame.
//!
//! Without a magic number, a file is taken to be ERF only when several
//! records in a row are of known types, chain exactly, and carry plausible
//! timestamps close to each other.

use super::super::{LINKTYPE_ETHERNET, LINKTYPE_IPV4, LINKTYPE_IPV6, LinkKind, Packet, PacketSet};
use super::SourceError;
use crate::parsers::{u16be, u64le};

pub const ERF_RECORD_HEADER_LEN: usize = 16;
const EXTENSION_HEADER_LEN: usize = 8;
/// The two bytes before an Ethernet frame.
const ETHERNET_PAD_LEN: usize = 2;
/// The type byte's top bit: extension headers follow the record header.
const EXTENSION_FLAG: u8 = 0x80;
const TYPE_MASK: u8 = 0x7F;
/// Most extension headers followed before a record is called malformed.
const MAX_EXTENSION_HEADERS: usize = 16;
/// The LINKTYPE for whole ERF records, which tshark decodes itself.
pub const LINKTYPE_ERF: u32 = 197;

/// Records that must read cleanly, one after another, before bytes are
/// called ERF; a shorter file must be all such records.
const RECORDS_TO_RECOGNISE: usize = 3;
/// Timestamps before 1995 or after 2100 are not believed.
const EARLIEST_SECONDS: u64 = 788_918_400;
const LATEST_SECONDS: u64 = 4_102_444_800;
/// Neighbouring records further apart than this are not believed.
const LARGEST_GAP_SECONDS: u64 = 86_400;
const FRACTION_UNITS: f64 = 4_294_967_296.0;

/// ERF record types, from Endace's list.
const TYPE_HDLC_POS: u8 = 1;
const TYPE_ETH: u8 = 2;
const TYPE_COLOR_ETH: u8 = 11;
const TYPE_DSM_COLOR_ETH: u8 = 16;
const TYPE_COLOR_HASH_ETH: u8 = 20;
const TYPE_IPV4: u8 = 22;
const TYPE_IPV6: u8 = 23;
const TYPE_META: u8 = 27;
const TYPE_PAD: u8 = 48;

/// Endace's name for a record type, or `None` for numbers not assigned.
pub fn type_name(record_type: u8) -> Option<&'static str> {
    let name = match record_type {
        TYPE_HDLC_POS => "HDLC (packet over SONET)",
        TYPE_ETH => "Ethernet",
        3 => "ATM cell",
        4 => "AAL5 frame",
        5 => "multichannel HDLC",
        6 => "multichannel raw",
        7 => "multichannel ATM",
        8 => "multichannel raw link",
        9 => "multichannel AAL5",
        10 => "coloured HDLC",
        TYPE_COLOR_ETH => "coloured Ethernet",
        12 => "multichannel AAL2",
        13 => "IP counter",
        14 => "TCP flow counter",
        15 => "DSM coloured HDLC",
        TYPE_DSM_COLOR_ETH => "DSM coloured Ethernet",
        17 => "coloured multichannel HDLC",
        18 => "AAL2 frame",
        19 => "coloured hashed HDLC",
        TYPE_COLOR_HASH_ETH => "coloured hashed Ethernet",
        21 => "InfiniBand",
        TYPE_IPV4 => "IPv4",
        TYPE_IPV6 => "IPv6",
        24 => "raw link",
        25 => "InfiniBand link",
        TYPE_META => "provenance metadata",
        TYPE_PAD => "padding",
        _ => return None,
    };
    Some(name)
}

fn is_ethernet(record_type: u8) -> bool {
    matches!(record_type, TYPE_ETH | TYPE_COLOR_ETH | TYPE_DSM_COLOR_ETH | TYPE_COLOR_HASH_ETH)
}

/// One record header, checked to fit inside the bytes it was read from.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Record {
    record_type: u8,
    seconds: u64,
    fraction: u64,
    /// The whole record.
    len: usize,
    wire_len: usize,
    /// Bytes from the record's start to its packet.
    data_offset: usize,
}

impl Record {
    fn at(bytes: &[u8], at: usize) -> Option<Record> {
        let timestamp = u64le(bytes, at)?;
        let type_byte = *bytes.get(at + 8)?;
        let record_type = type_byte & TYPE_MASK;
        type_name(record_type)?;
        let len = usize::from(u16be(bytes, at + 10)?);
        let wire_len = usize::from(u16be(bytes, at + 14)?);
        let mut data_offset = ERF_RECORD_HEADER_LEN;
        if type_byte & EXTENSION_FLAG != 0 {
            data_offset += extension_headers_len(bytes, at + ERF_RECORD_HEADER_LEN)?;
        }
        if is_ethernet(record_type) {
            data_offset += ETHERNET_PAD_LEN;
        }
        let fits = len >= data_offset && at.checked_add(len).is_some_and(|end| end <= bytes.len());
        fits.then_some(Record { record_type, seconds: timestamp >> 32, fraction: timestamp & 0xFFFF_FFFF, len, wire_len, data_offset })
    }

    fn timestamp(&self) -> f64 {
        self.seconds as f64 + self.fraction as f64 / FRACTION_UNITS
    }

    /// The packet's bytes: what the record holds, but no more than the wire
    /// length (the rest is alignment padding).
    fn captured_len(&self) -> usize {
        (self.len - self.data_offset).min(self.wire_len)
    }

    fn plausible_time(&self) -> bool {
        (EARLIEST_SECONDS..LATEST_SECONDS).contains(&self.seconds)
    }
}

/// The bytes of the extension headers starting at `at`.
fn extension_headers_len(bytes: &[u8], at: usize) -> Option<usize> {
    for count in 1..=MAX_EXTENSION_HEADERS {
        let header_start = at + (count - 1) * EXTENSION_HEADER_LEN;
        let first = *bytes.get(header_start)?;
        if first & EXTENSION_FLAG == 0 {
            return Some(count * EXTENSION_HEADER_LEN);
        }
    }
    None
}

/// Whether `bytes` start with ERF records: [`RECORDS_TO_RECOGNISE`] in a
/// row (or every record of a shorter file) of known types, chaining
/// exactly, with believable timestamps no more than a day apart.
pub fn looks_like(bytes: &[u8]) -> bool {
    let mut at = 0;
    let mut previous: Option<u64> = None;
    for _ in 0..RECORDS_TO_RECOGNISE {
        let Some(record) = Record::at(bytes, at) else { return false };
        let close_to_previous = previous.is_none_or(|seconds| seconds.abs_diff(record.seconds) <= LARGEST_GAP_SECONDS);
        if record.len == 0 || !record.plausible_time() || !close_to_previous {
            return false;
        }
        previous = Some(record.seconds);
        at += record.len;
        if at == bytes.len() {
            return true;
        }
    }
    true
}

/// The LINKTYPE number and our link kind for a record type, and whether the
/// packet is the frame inside the record. Types without a LINKTYPE of their
/// own keep the whole record, for tshark's ERF dissector.
fn link_for(record_type: u8) -> (LinkKind, u32, bool) {
    match record_type {
        _ if is_ethernet(record_type) => (LinkKind::Ethernet, LINKTYPE_ETHERNET, true),
        TYPE_IPV4 => (LinkKind::RawIp, LINKTYPE_IPV4, true),
        TYPE_IPV6 => (LinkKind::RawIp, LINKTYPE_IPV6, true),
        _ => (LinkKind::Unknown, LINKTYPE_ERF, false),
    }
}

/// The packets of the ERF records at `bytes[0]` (document offset `base`)
/// and the number of bytes they span. Padding records are skipped.
pub fn read(bytes: &[u8], base: usize) -> Result<(PacketSet, usize), SourceError> {
    if !looks_like(bytes) {
        return Err(SourceError::NotACapture { offset: base });
    }
    let mut set = PacketSet::new(format!("ERF records at {base:#x}"), "Endace ERF records".to_string());
    let mut kinds: Vec<&'static str> = Vec::new();
    let mut at = 0;
    while let Some(record) = Record::at(bytes, at).filter(|record| record.len > 0) {
        if record.record_type != TYPE_PAD {
            let name = type_name(record.record_type).unwrap_or_default();
            if !kinds.contains(&name) {
                kinds.push(name);
            }
            let (link, link_type, frame_only) = link_for(record.record_type);
            let (offset, len) = if frame_only { (at + record.data_offset, record.captured_len()) } else { (at, record.len) };
            let packet = Packet::new(base + offset, len, link, format!("ERF record {} ({name})", set.len() + 1))
                .with_timestamp(Some(record.timestamp()))
                .with_link_type(link_type)
                .with_record(base + at, record.len);
            if !set.push(packet) {
                break;
            }
        }
        at += record.len;
    }
    set.description = format!("Endace ERF records: {}", kinds.join(", "));
    Ok((set, at))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One record: its type, seconds, the bytes after the header (the pad
    /// included for Ethernet), the wire length, and extension headers.
    pub(crate) fn erf_record(record_type: u8, seconds: u32, body: &[u8], wire_len: u16, extensions: usize) -> Vec<u8> {
        let mut record = ((u64::from(seconds) << 32) | 0x8000_0000).to_le_bytes().to_vec();
        record.push(if extensions > 0 { record_type | EXTENSION_FLAG } else { record_type });
        record.push(0x04);
        let len = ERF_RECORD_HEADER_LEN + extensions * EXTENSION_HEADER_LEN + body.len();
        record.extend_from_slice(&(len as u16).to_be_bytes());
        record.extend_from_slice(&0u16.to_be_bytes());
        record.extend_from_slice(&wire_len.to_be_bytes());
        for index in 0..extensions {
            let more = if index + 1 < extensions { EXTENSION_FLAG } else { 0 };
            record.extend_from_slice(&[more | 0x01, 0, 0, 0, 0, 0, 0, 0]);
        }
        record.extend_from_slice(body);
        record
    }

    /// An Ethernet record holding `frame` and four bytes of alignment padding.
    pub(crate) fn ethernet_record(seconds: u32, frame: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0];
        body.extend_from_slice(frame);
        body.extend_from_slice(&[0; 4]);
        erf_record(TYPE_ETH, seconds, &body, frame.len() as u16, 0)
    }

    const NOW: u32 = 1_700_000_000;

    #[test]
    fn ethernet_records_yield_their_frames_without_pad_or_padding() {
        let mut file = ethernet_record(NOW, b"first frame");
        file.extend(ethernet_record(NOW + 1, b"second"));
        file.extend(erf_record(TYPE_PAD, NOW + 1, &[0; 8], 0, 0));
        file.extend(ethernet_record(NOW + 2, b"third"));
        let (set, extent) = read(&file, 0).expect("records");
        assert_eq!(extent, file.len());
        assert_eq!(set.len(), 3, "the padding record is skipped");
        let first = &set.packets[0];
        assert_eq!(&file[first.offset..first.end()], b"first frame");
        assert_eq!((first.link, first.link_type), (LinkKind::Ethernet, LINKTYPE_ETHERNET));
        assert_eq!(first.timestamp, Some(f64::from(NOW) + 0.5));
        assert_eq!(first.record, Some((0, 16 + 2 + 11 + 4)));
        assert_eq!(&file[set.packets[2].offset..set.packets[2].end()], b"third");
    }

    #[test]
    fn ip_records_are_raw_ip_and_extension_headers_are_skipped() {
        let mut file = erf_record(TYPE_IPV4, NOW, b"\x45 ipv4", 7, 2);
        file.extend(erf_record(TYPE_IPV6, NOW, b"\x60 ipv6", 7, 0));
        let (set, _) = read(&file, 0).expect("records");
        assert_eq!(&file[set.packets[0].offset..set.packets[0].end()], b"\x45 ipv4");
        assert_eq!((set.packets[0].link, set.packets[0].link_type), (LinkKind::RawIp, LINKTYPE_IPV4));
        assert_eq!(set.packets[1].link_type, LINKTYPE_IPV6);
    }

    #[test]
    fn records_of_other_types_are_kept_whole_for_tshark() {
        let file = erf_record(TYPE_HDLC_POS, NOW, b"\xFF\x03\x00\x21 ppp", 8, 0);
        let (set, _) = read(&file, 0x10).expect("a record");
        assert_eq!((set.packets[0].offset, set.packets[0].len), (0x10, file.len()));
        assert_eq!((set.packets[0].link, set.packets[0].link_type), (LinkKind::Unknown, LINKTYPE_ERF));
        assert!(set.description.contains("HDLC"), "{}", set.description);
    }

    #[test]
    fn bytes_are_called_erf_only_when_several_records_chain_with_believable_times() {
        let mut file = ethernet_record(NOW, b"one");
        file.extend(ethernet_record(NOW, b"two"));
        file.extend(ethernet_record(NOW, b"three"));
        file.extend(b"anything after the third record");
        assert!(looks_like(&file));
        let single = ethernet_record(NOW, b"a whole file of one record");
        assert!(looks_like(&single));

        let mut far_apart = ethernet_record(NOW, b"one");
        far_apart.extend(ethernet_record(NOW + 200_000, b"two"));
        assert!(!looks_like(&far_apart), "a day apart at most");
        assert!(!looks_like(&ethernet_record(1_000, b"1970")), "too early");
        let mut unknown_type = ethernet_record(NOW, b"one");
        unknown_type[8] = 99;
        assert!(!looks_like(&unknown_type));
        assert!(!looks_like(&[0u8; 64]), "zeros are not ERF");
        assert!(!looks_like(b"plain text that is long enough to hold several record headers"));
        assert_eq!(read(b"not erf", 4), Err(SourceError::NotACapture { offset: 4 }));
    }

    #[test]
    fn truncated_or_malformed_records_end_the_capture_without_panicking() {
        let mut file = ethernet_record(NOW, b"one");
        file.extend(ethernet_record(NOW, b"two"));
        file.extend(ethernet_record(NOW, b"three"));
        file.extend(ethernet_record(NOW, b"four"));
        let cut = file.len() - 3;
        let (set, extent) = read(&file[..cut], 0).expect("the whole records");
        assert_eq!(set.len(), 3);
        assert_eq!(extent, cut + 3 - ethernet_record(NOW, b"four").len());
        for cut in 0..file.len() {
            let _ = read(&file[..cut], 0);
        }
        let mut endless_extensions = erf_record(TYPE_ETH, NOW, &[0x81; 200], 4, 0);
        endless_extensions[8] |= EXTENSION_FLAG;
        assert!(!looks_like(&endless_extensions));
    }
}
