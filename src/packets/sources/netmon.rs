//! Microsoft Network Monitor 2.x captures, from Microsoft's published
//! description of the capture file format.
//!
//! A 72-byte little-endian header (the signature "GMBU", a BCD version, the
//! network's media type, the capture's start time as a SYSTEMTIME, and the
//! offset and length of the frame table and other optional tables) is
//! followed by the frames, and the frame table, an array of 32-bit frame
//! offsets, usually comes last. Each frame starts with a 16-byte header (the
//! time since the capture started in microseconds, the length on the wire
//! and the length captured) and the captured bytes. From version 2.1 a
//! frame's own media type follows its bytes; from 2.2 a process index, and
//! from 2.3 the frame's UTC time and a time zone index.

use super::super::{LINKTYPE_ETHERNET, LINKTYPE_FDDI, LINKTYPE_IEEE802_5, LinkKind, Packet, PacketSet};
use super::SourceError;
use crate::numeric::days_from_civil;
use crate::parsers::{u16le, u32le, u64le};

pub const NETMON_MAGIC: &[u8; 4] = b"GMBU";
pub const NETMON_HEADER_LEN: usize = 72;
const FRAME_HEADER_LEN: usize = 16;
/// Where the frame table's offset and length sit in the header.
const FRAME_TABLE_FIELD: usize = 24;
/// Where the start time sits in the header.
const START_TIME_FIELD: usize = 8;
/// Bytes after a frame's data: its media type (2.1), a process index (2.2),
/// and its UTC time and time zone index (2.3).
const MEDIA_TYPE_LEN: usize = 2;
const PROCESS_INDEX_LEN: usize = 4;
const UTC_TIME_LEN: usize = 8;
const TIME_ZONE_INDEX_LEN: usize = 1;
const MICROSECONDS: f64 = 1e6;
/// FILETIME counts 100 ns ticks from 1601-01-01.
const FILETIME_TICKS_PER_SECOND: f64 = 1e7;
const FILETIME_EPOCH_UNIX_SECONDS: f64 = -11_644_473_600.0;

/// Network Monitor's media types the viewer can name a LINKTYPE for.
const MEDIA_ETHERNET: u16 = 1;
const MEDIA_TOKEN_RING: u16 = 2;
const MEDIA_FDDI: u16 = 3;

/// Whether `bytes` start with a Network Monitor 2.x header.
pub fn looks_like(bytes: &[u8]) -> bool {
    bytes.starts_with(NETMON_MAGIC) && bytes.get(5) == Some(&0x02)
}

/// Network Monitor's name for a media type, including the pseudo-frames it
/// stores among the packets.
pub fn media_type_name(media_type: u16) -> String {
    match media_type {
        1 => "Ethernet".to_string(),
        2 => "token ring".to_string(),
        3 => "FDDI".to_string(),
        4 => "ATM".to_string(),
        5 => "IEEE 1394".to_string(),
        6 => "802.11 with Network Monitor's radio header".to_string(),
        0xFFE0 => "NetEvent (event tracing record)".to_string(),
        0xFFFB => "network information (extended)".to_string(),
        0xFFFC => "payload header".to_string(),
        0xFFFD => "network information".to_string(),
        0xFFFE => "DNS cache".to_string(),
        0xFFFF => "capture filter".to_string(),
        other => format!("media type {other:#06x}"),
    }
}

/// The LINKTYPE number and our link kind for a media type. Media without a
/// LINKTYPE, and Network Monitor's own pseudo-frames, are kept as frames of
/// unknown format.
fn link_for(media_type: u16) -> (LinkKind, u32) {
    match media_type {
        MEDIA_ETHERNET => (LinkKind::Ethernet, LINKTYPE_ETHERNET),
        MEDIA_TOKEN_RING => (LinkKind::Unknown, LINKTYPE_IEEE802_5),
        MEDIA_FDDI => (LinkKind::Unknown, LINKTYPE_FDDI),
        _ => (LinkKind::Unknown, LinkKind::Unknown.pcap_link_type()),
    }
}

/// A version held as two BCD bytes, such as 2.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

impl Version {
    fn from_bcd(major: u8, minor: u8) -> Version {
        let decimal = |bcd: u8| (bcd >> 4) * 10 + (bcd & 0x0F);
        Version { major: decimal(major), minor: decimal(minor) }
    }

    /// Bytes each frame carries after its data.
    fn trailer_len(self) -> usize {
        match self.minor {
            0 => 0,
            1 => MEDIA_TYPE_LEN,
            2 => MEDIA_TYPE_LEN + PROCESS_INDEX_LEN,
            _ => MEDIA_TYPE_LEN + PROCESS_INDEX_LEN + UTC_TIME_LEN + TIME_ZONE_INDEX_LEN,
        }
    }
}

/// What the header says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: Version,
    pub media_type: u16,
    /// The capture's start, in seconds since the Unix epoch, read as UTC
    /// (Network Monitor wrote the capturing machine's local time).
    pub start: Option<i64>,
    pub frame_table_offset: usize,
    pub frame_table_len: usize,
}

impl Header {
    pub fn read(bytes: &[u8]) -> Option<Header> {
        if !looks_like(bytes) || bytes.len() < NETMON_HEADER_LEN {
            return None;
        }
        Some(Header {
            version: Version::from_bcd(bytes[5], bytes[4]),
            media_type: u16le(bytes, 6)?,
            start: system_time(&bytes[START_TIME_FIELD..START_TIME_FIELD + 16]),
            frame_table_offset: u32le(bytes, FRAME_TABLE_FIELD)? as usize,
            frame_table_len: u32le(bytes, FRAME_TABLE_FIELD + 4)? as usize,
        })
    }
}

/// A SYSTEMTIME (year, month, day of week, day, hour, minute, second and
/// millisecond as 16-bit numbers) as whole seconds since the Unix epoch.
fn system_time(bytes: &[u8]) -> Option<i64> {
    let part = |index: usize| u16le(bytes, index * 2).map(u32::from);
    let (year, month, day) = (part(0)?, part(1)?, part(3)?);
    let (hour, minute, second) = (part(4)?, part(5)?, part(6)?);
    let valid = (1..=12).contains(&month) && (1..=31).contains(&day) && hour < 24 && minute < 60 && second < 60;
    valid.then(|| days_from_civil(i64::from(year), month, day) * 86_400 + i64::from(hour * 3600 + minute * 60 + second))
}

/// The packets of the Network Monitor capture at `bytes[0]` (document offset
/// `base`) and the number of bytes it spans.
pub fn read(bytes: &[u8], base: usize) -> Result<(PacketSet, usize), SourceError> {
    if !looks_like(bytes) {
        return Err(SourceError::NotACapture { offset: base });
    }
    let unreadable = |reason: String| SourceError::UnreadableCapture { offset: base, format: "Network Monitor", reason };
    let header = Header::read(bytes).ok_or_else(|| unreadable(format!("the {NETMON_HEADER_LEN}-byte file header is cut short")))?;
    let table_end = header.frame_table_offset.checked_add(header.frame_table_len).filter(|&end| end <= bytes.len() && header.frame_table_offset >= NETMON_HEADER_LEN);
    let Some(table_end) = table_end else {
        return Err(unreadable(format!(
            "its frame table ({} bytes at {:#x}) lies outside the {} bytes read, so the frames cannot be found",
            header.frame_table_len,
            header.frame_table_offset,
            bytes.len()
        )));
    };
    let (default_link, default_link_type) = link_for(header.media_type);
    let version = header.version;
    let mut set = PacketSet::new(
        format!("Network Monitor capture at {base:#x}"),
        format!("Network Monitor {}.{} capture, {} ({})", version.major, version.minor, media_type_name(header.media_type), default_link.label()),
    );
    let mut extent = table_end;
    let (entries, _) = bytes[header.frame_table_offset..table_end].as_chunks::<4>();
    for (index, entry) in entries.iter().enumerate() {
        let frame_offset = u32::from_le_bytes(*entry) as usize;
        let Some(frame) = Frame::at(bytes, frame_offset, version) else { continue };
        let (link, link_type) = frame.media_type.map_or((default_link, default_link_type), link_for);
        let timestamp = frame.utc.or_else(|| header.start.map(|start| start as f64 + frame.offset_micros as f64 / MICROSECONDS));
        let origin = match frame.media_type.filter(|&media| media != header.media_type) {
            Some(media) => format!("Network Monitor frame {} ({})", index + 1, media_type_name(media)),
            None => format!("Network Monitor frame {}", index + 1),
        };
        let packet = Packet::new(base + frame_offset + FRAME_HEADER_LEN, frame.captured, link, origin)
            .with_timestamp(timestamp)
            .with_link_type(link_type)
            .with_record(base + frame_offset, frame.len);
        extent = extent.max(frame_offset + frame.len);
        if !set.push(packet) {
            break;
        }
    }
    Ok((set, extent))
}

/// One frame, checked to fit inside `bytes`.
struct Frame {
    offset_micros: u64,
    captured: usize,
    /// The header, data and whatever of the trailer is present.
    len: usize,
    /// The frame's own media type, from version 2.1.
    media_type: Option<u16>,
    /// The frame's UTC time in seconds, from version 2.3.
    utc: Option<f64>,
}

impl Frame {
    fn at(bytes: &[u8], at: usize, version: Version) -> Option<Frame> {
        if at < NETMON_HEADER_LEN {
            return None;
        }
        let offset_micros = u64le(bytes, at)?;
        let captured = u32le(bytes, at + 12)? as usize;
        let data_end = at.checked_add(FRAME_HEADER_LEN)?.checked_add(captured).filter(|&end| end <= bytes.len())?;
        let trailer = version.trailer_len();
        let media_type = (trailer >= MEDIA_TYPE_LEN).then(|| u16le(bytes, data_end)).flatten();
        let has_utc = trailer >= MEDIA_TYPE_LEN + PROCESS_INDEX_LEN + UTC_TIME_LEN;
        let utc_ticks = if has_utc { u64le(bytes, data_end + MEDIA_TYPE_LEN + PROCESS_INDEX_LEN) } else { None };
        let utc = utc_ticks.filter(|&ticks| ticks > 0).map(|ticks| ticks as f64 / FILETIME_TICKS_PER_SECOND + FILETIME_EPOCH_UNIX_SECONDS);
        let len = FRAME_HEADER_LEN + captured + trailer.min(bytes.len() - data_end);
        Some(Frame { offset_micros, captured, len, media_type, utc })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One frame for [`netmon_file`]: its data, the microseconds since the
    /// capture started, and its own media type (written from version 2.1).
    pub(crate) struct TestFrame<'a> {
        pub data: &'a [u8],
        pub offset_micros: u64,
        pub media_type: u16,
    }

    /// A Network Monitor file of version 2.`minor`, Ethernet, started at
    /// 2005-07-03 08:54:05 (Unix 1120380845), with the frame table last.
    pub(crate) fn netmon_file(minor: u8, frames: &[TestFrame]) -> Vec<u8> {
        let mut file = NETMON_MAGIC.to_vec();
        file.extend_from_slice(&[minor, 0x02]);
        file.extend_from_slice(&MEDIA_ETHERNET.to_le_bytes());
        for part in [2005u16, 7, 0, 3, 8, 54, 5, 539] {
            file.extend_from_slice(&part.to_le_bytes());
        }
        file.resize(NETMON_HEADER_LEN, 0);
        let version = Version::from_bcd(0x02, minor);
        let mut offsets = Vec::new();
        for frame in frames {
            offsets.push(file.len() as u32);
            file.extend_from_slice(&frame.offset_micros.to_le_bytes());
            file.extend_from_slice(&(frame.data.len() as u32).to_le_bytes());
            file.extend_from_slice(&(frame.data.len() as u32).to_le_bytes());
            file.extend_from_slice(frame.data);
            if version.trailer_len() >= MEDIA_TYPE_LEN {
                file.extend_from_slice(&frame.media_type.to_le_bytes());
            }
            if version.trailer_len() > MEDIA_TYPE_LEN {
                file.extend_from_slice(&u32::MAX.to_le_bytes());
            }
            if version.trailer_len() > MEDIA_TYPE_LEN + PROCESS_INDEX_LEN {
                let utc_seconds = 1_600_000_000 + frame.offset_micros / 1_000_000;
                file.extend_from_slice(&((utc_seconds + 11_644_473_600) * 10_000_000).to_le_bytes());
                file.push(15);
            }
        }
        let table_offset = file.len() as u32;
        for offset in &offsets {
            file.extend_from_slice(&offset.to_le_bytes());
        }
        file[FRAME_TABLE_FIELD..FRAME_TABLE_FIELD + 4].copy_from_slice(&table_offset.to_le_bytes());
        file[FRAME_TABLE_FIELD + 4..FRAME_TABLE_FIELD + 8].copy_from_slice(&((offsets.len() * 4) as u32).to_le_bytes());
        file
    }

    #[test]
    fn a_version_2_0_capture_dates_its_frames_from_the_header_start_time() {
        let frames = [TestFrame { data: b"first frame", offset_micros: 0, media_type: 0 }, TestFrame { data: b"second", offset_micros: 1_500_000, media_type: 0 }];
        let file = netmon_file(0x00, &frames);
        let (set, extent) = read(&file, 0).expect("a capture");
        assert_eq!(extent, file.len());
        assert_eq!(set.len(), 2);
        let first = &set.packets[0];
        assert_eq!(&file[first.offset..first.end()], b"first frame");
        assert_eq!((first.link, first.link_type), (LinkKind::Ethernet, LINKTYPE_ETHERNET));
        assert_eq!(first.timestamp, Some(1_120_380_845.0));
        assert_eq!(set.packets[1].timestamp, Some(1_120_380_846.5));
        assert_eq!(first.record, Some((NETMON_HEADER_LEN, FRAME_HEADER_LEN + 11)));
        assert!(set.description.contains("2.0"), "{}", set.description);
    }

    #[test]
    fn a_version_2_3_capture_uses_each_frames_media_type_and_utc_time() {
        let frames = [TestFrame { data: b"filter text", offset_micros: 0, media_type: 0xFFFF }, TestFrame { data: b"ring frame", offset_micros: 2_000_000, media_type: MEDIA_TOKEN_RING }];
        let file = netmon_file(0x03, &frames);
        let (set, _) = read(&file, 0x1000).expect("a capture");
        let filter = &set.packets[0];
        assert_eq!((filter.link, filter.link_type), (LinkKind::Unknown, LinkKind::Unknown.pcap_link_type()));
        assert!(filter.origin.contains("capture filter"), "{}", filter.origin);
        assert_eq!(filter.record.map(|(_, len)| len), Some(FRAME_HEADER_LEN + 11 + 15), "the trailer goes with the frame");
        let ring = &set.packets[1];
        assert_eq!(&file[ring.offset - 0x1000..ring.end() - 0x1000], b"ring frame");
        assert_eq!(ring.link_type, LINKTYPE_IEEE802_5);
        assert_eq!(ring.timestamp, Some(1_600_000_002.0));
    }

    #[test]
    fn frames_outside_the_file_are_skipped_and_cut_files_do_not_panic() {
        let frames = [TestFrame { data: b"kept", offset_micros: 0, media_type: 1 }, TestFrame { data: b"lost", offset_micros: 0, media_type: 1 }];
        let mut file = netmon_file(0x01, &frames);
        let table = u32le(&file, FRAME_TABLE_FIELD).unwrap() as usize;
        file[table + 4..table + 8].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        let (set, _) = read(&file, 0).expect("the first frame");
        assert_eq!(set.len(), 1);
        for cut in 0..file.len() {
            let _ = read(&file[..cut], 0);
        }
    }

    #[test]
    fn a_frame_table_past_the_end_or_a_short_header_is_explained() {
        let file = netmon_file(0x00, &[TestFrame { data: b"x", offset_micros: 0, media_type: 1 }]);
        let without_table = &file[..file.len() - 4];
        let error = read(without_table, 0).unwrap_err();
        assert!(error.to_string().contains("frame table"), "{error}");
        assert!(read(&file[..20], 0).unwrap_err().to_string().contains("cut short"));
        assert_eq!(read(b"GMBU\x00\x01 version one", 0).unwrap_err(), SourceError::NotACapture { offset: 0 });
    }
}
