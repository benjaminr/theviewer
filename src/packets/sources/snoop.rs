//! Sun snoop captures, as described in RFC 1761.
//!
//! A 16-byte file header (the identification "snoop\0\0\0", a version
//! number and a datalink type) is followed by packet records. Each record
//! has a 24-byte header (original length, included length, record length,
//! cumulative drops, timestamp seconds and microseconds), the included bytes
//! of the packet, and padding up to the record length. Every number is
//! big-endian.

use super::super::{LINKTYPE_ETHERNET, LINKTYPE_FDDI, LINKTYPE_IEEE802_5, LinkKind, Packet, PacketSet};
use super::SourceError;
use crate::parsers::u32be;

/// The identification at the start of every snoop file.
pub const SNOOP_MAGIC: &[u8; 8] = b"snoop\0\0\0";
/// The only version RFC 1761 describes.
const SNOOP_VERSION: u32 = 2;
pub const SNOOP_FILE_HEADER_LEN: usize = 16;
const SNOOP_RECORD_HEADER_LEN: usize = 24;
const MICROSECONDS: f64 = 1e6;

/// RFC 1761's datalink types the viewer can name a LINKTYPE for.
const DATALINK_IEEE_802_3: u32 = 0;
const DATALINK_IEEE_802_5: u32 = 2;
const DATALINK_ETHERNET: u32 = 4;
const DATALINK_FDDI: u32 = 8;

/// Whether `bytes` start with a snoop file header.
pub fn looks_like(bytes: &[u8]) -> bool {
    bytes.starts_with(SNOOP_MAGIC)
}

/// RFC 1761's name for a datalink type.
pub fn datalink_name(datalink: u32) -> String {
    match datalink {
        0 => "IEEE 802.3".to_string(),
        1 => "IEEE 802.4 token bus".to_string(),
        2 => "IEEE 802.5 token ring".to_string(),
        3 => "IEEE 802.6 metro net".to_string(),
        4 => "Ethernet".to_string(),
        5 => "HDLC".to_string(),
        6 => "character synchronous".to_string(),
        7 => "IBM channel-to-channel".to_string(),
        8 => "FDDI".to_string(),
        9 => "other".to_string(),
        other => format!("datalink type {other}"),
    }
}

/// The LINKTYPE number and our link kind for a snoop datalink type. Types
/// without a LINKTYPE are kept as frames of unknown format.
fn link_for(datalink: u32) -> (LinkKind, u32) {
    match datalink {
        DATALINK_IEEE_802_3 | DATALINK_ETHERNET => (LinkKind::Ethernet, LINKTYPE_ETHERNET),
        DATALINK_IEEE_802_5 => (LinkKind::Unknown, LINKTYPE_IEEE802_5),
        DATALINK_FDDI => (LinkKind::Unknown, LINKTYPE_FDDI),
        _ => (LinkKind::Unknown, LinkKind::Unknown.pcap_link_type()),
    }
}

/// The packets of the snoop capture at `bytes[0]` (document offset `base`)
/// and the number of bytes it spans.
pub fn read(bytes: &[u8], base: usize) -> Result<(PacketSet, usize), SourceError> {
    if !looks_like(bytes) {
        return Err(SourceError::NotACapture { offset: base });
    }
    let unreadable = |reason: String| SourceError::UnreadableCapture { offset: base, format: "snoop", reason };
    let (Some(version), Some(datalink)) = (u32be(bytes, 8), u32be(bytes, 12)) else {
        return Err(unreadable("the 16-byte file header is cut short".to_string()));
    };
    if version != SNOOP_VERSION {
        return Err(unreadable(format!("version {version} is not the version 2 of RFC 1761")));
    }
    let (link, link_type) = link_for(datalink);
    let mut set = PacketSet::new(format!("snoop capture at {base:#x}"), format!("snoop capture, {} ({})", datalink_name(datalink), link.label()));
    let mut at = SNOOP_FILE_HEADER_LEN;
    while let Some(record) = Record::at(bytes, at) {
        let packet = Packet::new(base + at + SNOOP_RECORD_HEADER_LEN, record.included, link, format!("snoop record {}", set.len() + 1))
            .with_timestamp(Some(record.seconds as f64 + record.microseconds as f64 / MICROSECONDS))
            .with_link_type(link_type)
            .with_record(base + at, record.len);
        if !set.push(packet) {
            break;
        }
        at += record.len;
    }
    Ok((set, at))
}

/// One record header, checked to fit inside `bytes`.
struct Record {
    included: usize,
    /// The whole record: header, packet and padding.
    len: usize,
    seconds: u32,
    microseconds: u32,
}

impl Record {
    fn at(bytes: &[u8], at: usize) -> Option<Record> {
        let field = |index: usize| u32be(bytes, at + index * 4).map(|value| value as usize);
        let (included, len) = (field(1)?, field(2)?);
        let (seconds, microseconds) = (u32be(bytes, at + 16)?, u32be(bytes, at + 20)?);
        let fits = len >= SNOOP_RECORD_HEADER_LEN && included <= len - SNOOP_RECORD_HEADER_LEN && at.checked_add(len).is_some_and(|end| end <= bytes.len());
        fits.then_some(Record { included, len, seconds, microseconds })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A snoop file with the given datalink type and packets, each padded to
    /// a multiple of four bytes as Sun's tools write them.
    pub(crate) fn snoop_file(datalink: u32, packets: &[(&[u8], u32, u32)]) -> Vec<u8> {
        let mut file = SNOOP_MAGIC.to_vec();
        file.extend_from_slice(&SNOOP_VERSION.to_be_bytes());
        file.extend_from_slice(&datalink.to_be_bytes());
        for (data, seconds, microseconds) in packets {
            let record_len = SNOOP_RECORD_HEADER_LEN + data.len().div_ceil(4) * 4;
            file.extend_from_slice(&(data.len() as u32).to_be_bytes());
            file.extend_from_slice(&(data.len() as u32).to_be_bytes());
            file.extend_from_slice(&(record_len as u32).to_be_bytes());
            file.extend_from_slice(&0u32.to_be_bytes());
            file.extend_from_slice(&seconds.to_be_bytes());
            file.extend_from_slice(&microseconds.to_be_bytes());
            file.extend_from_slice(data);
            file.resize(file.len() + record_len - SNOOP_RECORD_HEADER_LEN - data.len(), 0);
        }
        file
    }

    #[test]
    fn a_snoop_capture_yields_its_packets_without_the_padding() {
        let file = snoop_file(DATALINK_ETHERNET, &[(b"first frame", 1_000, 500_000), (b"second", 1_001, 0)]);
        let (set, extent) = read(&file, 0).expect("a capture");
        assert_eq!(extent, file.len());
        assert_eq!(set.len(), 2);
        let first = &set.packets[0];
        assert_eq!(&file[first.offset..first.end()], b"first frame");
        assert_eq!((first.link, first.link_type), (LinkKind::Ethernet, LINKTYPE_ETHERNET));
        assert_eq!(first.timestamp, Some(1_000.5));
        assert_eq!(first.record, Some((16, 24 + 12)), "the record keeps its padding");
        assert_eq!(&file[set.packets[1].offset..set.packets[1].end()], b"second");
    }

    #[test]
    fn token_ring_and_fddi_keep_their_link_type_for_tshark() {
        let (set, _) = read(&snoop_file(DATALINK_FDDI, &[(b"ring", 1, 0)]), 0).expect("a capture");
        assert_eq!((set.packets[0].link, set.packets[0].link_type), (LinkKind::Unknown, LINKTYPE_FDDI));
        let (set, _) = read(&snoop_file(DATALINK_IEEE_802_5, &[(b"ring", 1, 0)]), 0).expect("a capture");
        assert_eq!(set.packets[0].link_type, LINKTYPE_IEEE802_5);
    }

    #[test]
    fn a_truncated_snoop_capture_keeps_its_whole_records() {
        let mut file = snoop_file(DATALINK_ETHERNET, &[(b"whole", 1, 0), (b"cut short", 2, 0)]);
        file.truncate(file.len() - 5);
        let (set, extent) = read(&file, 0).expect("the first record");
        assert_eq!(set.len(), 1);
        assert_eq!(extent, 16 + 24 + 8);
        for cut in 0..file.len() {
            let _ = read(&file[..cut], 0);
        }
    }

    #[test]
    fn a_record_claiming_more_bytes_than_its_length_ends_the_capture() {
        let mut file = snoop_file(DATALINK_ETHERNET, &[(b"good", 1, 0), (b"liar", 2, 0)]);
        let second = 16 + 24 + 4;
        file[second + 4..second + 8].copy_from_slice(&100u32.to_be_bytes());
        let (set, _) = read(&file, 0).expect("the first record");
        assert_eq!(set.len(), 1);
        let mut short_record = snoop_file(DATALINK_ETHERNET, &[(b"good", 1, 0)]);
        short_record[16 + 8..16 + 12].copy_from_slice(&4u32.to_be_bytes());
        assert_eq!(read(&short_record, 0).expect("a header").0.len(), 0, "a record shorter than its own header is not read");
    }

    #[test]
    fn a_wrong_version_or_short_header_is_explained() {
        let mut file = snoop_file(DATALINK_ETHERNET, &[(b"x", 1, 0)]);
        file[8..12].copy_from_slice(&7u32.to_be_bytes());
        let error = read(&file, 0x40).unwrap_err();
        assert!(error.to_string().contains("version 7"), "{error}");
        assert!(read(&SNOOP_MAGIC[..], 0).unwrap_err().to_string().contains("cut short"));
        assert_eq!(read(b"not snoop at all", 3).unwrap_err(), SourceError::NotACapture { offset: 3 });
    }
}
