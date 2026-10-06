//! Writing packets out as a classic pcap file that Wireshark and tcpdump open.
//!
//! The file uses microsecond timestamps in little-endian byte order. Packets
//! without a timestamp are given one a millisecond after the packet before,
//! so the order is kept.

use std::fmt;

use super::LinkKind;

const PCAP_MAGIC_MICROSECONDS: u32 = 0xA1B2_C3D4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
/// The largest packet the file says it may hold.
const PCAP_SNAPLEN: u32 = 262_144;
/// Gap between packets that have no timestamp of their own.
const SYNTHETIC_STEP_SECONDS: f64 = 0.001;
const MICROSECONDS_PER_SECOND: f64 = 1e6;

/// One packet to write.
#[derive(Clone, Copy, Debug)]
pub struct ExportPacket<'a> {
    /// The bytes captured.
    pub bytes: &'a [u8],
    /// The packet's length on the wire, at least `bytes.len()`.
    pub original_len: usize,
    pub timestamp: Option<f64>,
    pub link: LinkKind,
}

/// Why packets could not be written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportError {
    NoPackets,
    /// A pcap file has one link type; these packets have several.
    MixedLinkTypes { kinds: Vec<&'static str> },
    /// A packet is larger than a pcap record can describe.
    PacketTooLarge { index: usize, len: usize },
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportError::NoPackets => write!(f, "There are no packets to export."),
            ExportError::MixedLinkTypes { kinds } => write!(
                f,
                "A pcap file holds one link type, but these packets are {}. Choose one link type above, or filter to one kind, before exporting.",
                kinds.join(" and ")
            ),
            ExportError::PacketTooLarge { index, len } => write!(f, "Packet {} is {len} bytes, more than a pcap record can hold.", index + 1),
        }
    }
}

impl std::error::Error for ExportError {}

/// The packets as a classic pcap file.
pub fn write_pcap(packets: &[ExportPacket<'_>]) -> Result<Vec<u8>, ExportError> {
    let first = packets.first().ok_or(ExportError::NoPackets)?;
    let mut kinds: Vec<&'static str> = Vec::new();
    for packet in packets {
        if !kinds.contains(&packet.link.label()) {
            kinds.push(packet.link.label());
        }
    }
    if kinds.len() > 1 {
        return Err(ExportError::MixedLinkTypes { kinds });
    }
    let total: usize = packets.iter().map(|p| p.bytes.len() + 16).sum();
    let mut file = Vec::with_capacity(24 + total);
    file.extend_from_slice(&PCAP_MAGIC_MICROSECONDS.to_le_bytes());
    file.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    file.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    file.extend_from_slice(&0i32.to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&PCAP_SNAPLEN.to_le_bytes());
    file.extend_from_slice(&first.link.pcap_link_type().to_le_bytes());
    let mut previous: Option<f64> = None;
    for (index, packet) in packets.iter().enumerate() {
        let captured = u32::try_from(packet.bytes.len()).map_err(|_| ExportError::PacketTooLarge { index, len: packet.bytes.len() })?;
        let original = u32::try_from(packet.original_len.max(packet.bytes.len())).unwrap_or(u32::MAX);
        let timestamp = packet.timestamp.unwrap_or_else(|| previous.map_or(0.0, |t| t + SYNTHETIC_STEP_SECONDS));
        previous = Some(timestamp);
        let (seconds, microseconds) = split_timestamp(timestamp);
        file.extend_from_slice(&seconds.to_le_bytes());
        file.extend_from_slice(&microseconds.to_le_bytes());
        file.extend_from_slice(&captured.to_le_bytes());
        file.extend_from_slice(&original.to_le_bytes());
        file.extend_from_slice(packet.bytes);
    }
    Ok(file)
}

/// Whole seconds and microseconds, rounded to the nearest microsecond and
/// kept within what a pcap record can hold.
fn split_timestamp(timestamp: f64) -> (u32, u32) {
    let clamped = if timestamp.is_finite() { timestamp.clamp(0.0, u32::MAX as f64) } else { 0.0 };
    let total_microseconds = (clamped * MICROSECONDS_PER_SECOND).round() as u64;
    let seconds = (total_microseconds / 1_000_000).min(u32::MAX as u64) as u32;
    (seconds, (total_microseconds % 1_000_000) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::sources::from_capture;

    #[test]
    fn exported_packets_read_back_identically_with_their_timestamps() {
        let payloads: [&[u8]; 3] = [b"\x45first", b"second packet", b""];
        let timestamps = [Some(1_700_000_000.25), Some(1_700_000_000.500_001), Some(1_700_000_001.0)];
        let packets: Vec<ExportPacket> = payloads
            .iter()
            .zip(timestamps)
            .map(|(bytes, timestamp)| ExportPacket { bytes, original_len: bytes.len(), timestamp, link: LinkKind::RawIp })
            .collect();
        let file = write_pcap(&packets).expect("a pcap file");
        let read = from_capture(&file, 0).expect("readable");
        assert_eq!(read.len(), 3);
        for ((packet, payload), timestamp) in read.packets.iter().zip(payloads).zip(timestamps) {
            assert_eq!(&file[packet.offset..packet.end()], payload);
            assert_eq!(packet.link, LinkKind::RawIp);
            assert!((packet.timestamp.unwrap() - timestamp.unwrap()).abs() < 1e-6, "{:?} vs {timestamp:?}", packet.timestamp);
        }
    }

    #[test]
    fn packets_without_timestamps_get_increasing_ones_and_unknown_frames_use_user0() {
        let packets = [
            ExportPacket { bytes: b"a", original_len: 1, timestamp: None, link: LinkKind::Unknown },
            ExportPacket { bytes: b"b", original_len: 1, timestamp: None, link: LinkKind::Unknown },
            ExportPacket { bytes: b"c", original_len: 1, timestamp: Some(10.0), link: LinkKind::Unknown },
            ExportPacket { bytes: b"d", original_len: 1, timestamp: None, link: LinkKind::Unknown },
        ];
        let file = write_pcap(&packets).unwrap();
        assert_eq!(u32::from_le_bytes(file[20..24].try_into().unwrap()), 147);
        let times: Vec<f64> = from_capture(&file, 0).unwrap().packets.iter().map(|p| p.timestamp.unwrap()).collect();
        let expected = [0.0, 0.001, 10.0, 10.001];
        assert_eq!(times.len(), expected.len());
        for (time, expected) in times.iter().zip(expected) {
            assert!((time - expected).abs() < 1e-9, "{times:?}");
        }
    }

    #[test]
    fn mixed_link_types_and_empty_sets_are_refused_with_a_reason() {
        let mixed = [
            ExportPacket { bytes: b"a", original_len: 1, timestamp: None, link: LinkKind::Ethernet },
            ExportPacket { bytes: b"b", original_len: 1, timestamp: None, link: LinkKind::RawIp },
        ];
        let error = write_pcap(&mixed).unwrap_err();
        assert!(error.to_string().contains("Ethernet and Raw IP"), "{error}");
        assert_eq!(write_pcap(&[]), Err(ExportError::NoPackets));
    }

    #[test]
    fn timestamps_round_to_the_nearest_microsecond_and_stay_in_range() {
        assert_eq!(split_timestamp(1.999_999_9), (2, 0));
        assert_eq!(split_timestamp(-5.0), (0, 0));
        assert_eq!(split_timestamp(f64::NAN), (0, 0));
        assert_eq!(split_timestamp(3.000_001), (3, 1));
    }
}
