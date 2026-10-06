//! Capture files other than pcap and pcapng, as findings: Sun snoop,
//! Microsoft Network Monitor 2.x, Endace ERF and gzip-compressed captures.
//! The packets are read with the packet viewer's own readers
//! ([`crate::packets::sources`]), so the findings and the Packets panel
//! agree on what a capture holds.

use super::MAX_EXTENT;
use super::protocol::summarise_packet;
use crate::packets::PacketSet;
use crate::packets::sources::{self, erf, gzip, netmon, snoop};
use crate::parsers::u32be;
use crate::plugin::{Category, Field, Finding, Parser};

const SOURCE: &str = "parsers.captures";
/// Finding ids of every capture whose packets are ranges of the document,
/// pcap and pcapng included, for the panels that read them.
pub const CAPTURE_FINDING_IDS: [&str; 5] = ["pcap", "pcapng", "snoop", "netmon", "erf"];
/// The finding id of a gzip-compressed capture.
pub const GZIP_CAPTURE_FINDING_ID: &str = "gzip-capture";
/// Packets summarised in a finding; the rest are only counted.
const DISSECTED_PACKETS: usize = 50;

/// The packets of `set` as fields, the first [`DISSECTED_PACKETS`] of them
/// summarised. `bytes` sit at document offset `base`.
fn packet_fields(set: &PacketSet, bytes: &[u8], base: usize) -> Vec<Field> {
    set.packets
        .iter()
        .take(DISSECTED_PACKETS)
        .enumerate()
        .map(|(index, packet)| {
            let (offset, len) = packet.removal_range();
            let data = bytes.get(packet.offset - base..packet.end() - base).unwrap_or_default();
            Field::new(format!("packet {}", index + 1), offset, len, format!("{} bytes: {}", packet.len, summarise_packet(packet.link_type, data)))
        })
        .collect()
}

/// The span of the packets field: from the first packet's record to the end
/// of the capture.
fn packets_field(set: &PacketSet, bytes: &[u8], base: usize, extent: usize) -> Field {
    let start = set.packets.first().map_or(base, |packet| packet.removal_range().0);
    Field::new("packets", start, (base + extent).saturating_sub(start), format!("{} packets", set.len())).with_children(packet_fields(set, bytes, base))
}

/// The capture at `bytes[0]` read with the packet viewer's readers, its
/// extent kept within [`MAX_EXTENT`].
fn read(bytes: &[u8], base: usize) -> Option<(PacketSet, usize)> {
    let window = &bytes[..bytes.len().min(MAX_EXTENT)];
    sources::read_capture(window, base).ok()
}

// ---------------------------------------------------------------------------
// snoop
// ---------------------------------------------------------------------------

pub struct SnoopParser;

impl Parser for SnoopParser {
    fn id(&self) -> &str {
        "snoop"
    }

    fn name(&self) -> &str {
        "snoop capture"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        snoop::looks_like(bytes)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        let (set, extent) = read(bytes, base)?;
        let datalink = u32be(bytes, 12)?;
        let fields = vec![
            Field::new("file header", base, snoop::SNOOP_FILE_HEADER_LEN, snoop::datalink_name(datalink)).with_children(vec![
                Field::new("identification", base, 8, "snoop"),
                Field::new("version", base + 8, 4, u32be(bytes, 8)?.to_string()),
                Field::new("datalink type", base + 12, 4, format!("{datalink} ({})", snoop::datalink_name(datalink))),
            ]),
            packets_field(&set, bytes, base, extent),
        ];
        Some(
            Finding::new("snoop", SOURCE, Category::Protocol, base, extent)
                .title("snoop capture")
                .detail(format!("snoop, {}, {} packets", snoop::datalink_name(datalink), set.len()))
                .confidence(1.0)
                .fields(fields),
        )
    }
}

// ---------------------------------------------------------------------------
// Network Monitor
// ---------------------------------------------------------------------------

pub struct NetMonParser;

impl Parser for NetMonParser {
    fn id(&self) -> &str {
        "netmon"
    }

    fn name(&self) -> &str {
        "Network Monitor capture"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        netmon::looks_like(bytes)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        let header = netmon::Header::read(bytes)?;
        let (set, extent) = read(bytes, base)?;
        let version = format!("{}.{}", header.version.major, header.version.minor);
        let media = netmon::media_type_name(header.media_type);
        let frames = header.frame_table_len / 4;
        let mut fields = vec![
            Field::new("file header", base, netmon::NETMON_HEADER_LEN, format!("version {version}, {media}")).with_children(vec![
                Field::new("signature", base, 4, "GMBU"),
                Field::new("version", base + 4, 2, version.clone()),
                Field::new("media type", base + 6, 2, format!("{} ({media})", header.media_type)),
                Field::new("start time", base + 8, 16, header.start.map_or_else(|| "not a valid date".to_string(), |seconds| format!("{seconds} s after 1970 (local time)"))),
                Field::new("frame table", base + 24, 8, format!("{frames} frames at {:#x}", header.frame_table_offset)),
            ]),
            packets_field(&set, bytes, base, header.frame_table_offset.min(extent)),
        ];
        fields.push(Field::new("frame table", base + header.frame_table_offset, header.frame_table_len, format!("{frames} frame offsets")));
        Some(
            Finding::new("netmon", SOURCE, Category::Protocol, base, extent)
                .title("Network Monitor capture")
                .detail(format!("Network Monitor {version}, {media}, {} packets", set.len()))
                .confidence(1.0)
                .fields(fields),
        )
    }
}

// ---------------------------------------------------------------------------
// ERF
// ---------------------------------------------------------------------------

/// ERF has no magic number, so it is only claimed at the very start of the
/// document, and only when several records in a row read cleanly.
pub struct ErfParser;

impl Parser for ErfParser {
    fn id(&self) -> &str {
        "erf"
    }

    fn name(&self) -> &str {
        "ERF records"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        erf::looks_like(bytes)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if base != 0 {
            return None;
        }
        let (set, extent) = read(bytes, base)?;
        let complete = extent == bytes.len();
        Some(
            Finding::new("erf", SOURCE, Category::Protocol, base, extent)
                .title("ERF records")
                .detail(format!("{}, {} packets{}", set.description, set.len(), if complete { "" } else { ", followed by other bytes" }))
                .confidence(if complete { 0.9 } else { 0.6 })
                .fields(vec![packets_field(&set, bytes, base, extent)]),
        )
    }
}

// ---------------------------------------------------------------------------
// gzip-compressed captures
// ---------------------------------------------------------------------------

/// A capture compressed whole with gzip. Its packets are not ranges of the
/// document, so the finding covers the gzip stream and says what is inside.
pub struct GzipCaptureParser;

impl Parser for GzipCaptureParser {
    fn id(&self) -> &str {
        GZIP_CAPTURE_FINDING_ID
    }

    fn name(&self) -> &str {
        "gzip-compressed capture"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        gzip::looks_like(bytes)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        let capture = gzip::gunzip(bytes, base).ok()?;
        let (set, _) = sources::read_capture(&capture.data, 0).ok()?;
        let label = capture.format.label();
        let cut = if capture.truncated { ", cut short" } else { "" };
        Some(
            Finding::new(GZIP_CAPTURE_FINDING_ID, SOURCE, Category::Protocol, base, capture.compressed_len)
                .title(format!("gzip-compressed {label} capture"))
                .detail(format!("{label} compressed with gzip, {} packets in {} bytes{cut}; decompress it to see the packets", set.len(), capture.data.len()))
                .confidence(0.9)
                .fields(vec![Field::new("gzip stream", base, capture.compressed_len, format!("{label} capture, {} bytes decompressed", capture.data.len()))]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::{self, Codec};
    use crate::packets::sources::{erf, netmon, snoop};
    use etherparse::PacketBuilder;

    fn udp_frame() -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12]).ipv4([192, 168, 1, 5], [10, 0, 0, 2], 64).udp(5353, 53);
        let mut frame = Vec::new();
        builder.write(&mut frame, b"hello").unwrap();
        frame
    }

    #[test]
    fn a_snoop_capture_is_a_finding_with_its_header_and_summarised_packets() {
        let frame = udp_frame();
        let file = snoop::tests::snoop_file(4, &[(&frame, 1, 0)]);
        assert!(SnoopParser.looks_like(&file));
        let finding = SnoopParser.parse(&file, 0x200).expect("snoop");
        assert_eq!((finding.start, finding.len), (0x200, file.len()));
        assert_eq!(finding.detail, "snoop, Ethernet, 1 packets");
        assert_eq!(finding.fields[0].children[2].name, "datalink type");
        let packet = &finding.fields[1].children[0];
        assert_eq!(packet.offset, 0x200 + 16, "the packet field covers its record");
        assert!(packet.value.contains("192.168.1.5:5353 → 10.0.0.2:53 UDP"), "{}", packet.value);
    }

    #[test]
    fn a_network_monitor_capture_is_a_finding_with_its_frame_table() {
        let frame = udp_frame();
        let file = netmon::tests::netmon_file(0x00, &[netmon::tests::TestFrame { data: &frame, offset_micros: 0, media_type: 1 }]);
        let finding = NetMonParser.parse(&file, 0).expect("Network Monitor");
        assert_eq!(finding.len, file.len());
        assert_eq!(finding.detail, "Network Monitor 2.0, Ethernet, 1 packets");
        let names: Vec<&str> = finding.fields.iter().map(|field| field.name.as_str()).collect();
        assert_eq!(names, vec!["file header", "packets", "frame table"]);
        assert!(finding.fields[1].children[0].value.contains("UDP"), "{}", finding.fields[1].children[0].value);
    }

    #[test]
    fn erf_records_are_a_finding_only_at_the_start_of_the_document() {
        let frame = udp_frame();
        let mut file = erf::tests::ethernet_record(1_700_000_000, &frame);
        file.extend(erf::tests::ethernet_record(1_700_000_001, &frame));
        assert!(ErfParser.looks_like(&file));
        let finding = ErfParser.parse(&file, 0).expect("ERF");
        assert_eq!((finding.len, finding.confidence), (file.len(), 0.9));
        assert!(finding.detail.contains("Ethernet, 2 packets"), "{}", finding.detail);
        assert!(ErfParser.parse(&file, 0x40).is_none());
    }

    #[test]
    fn a_gzip_compressed_capture_is_a_finding_over_the_compressed_stream() {
        let frame = udp_frame();
        let compressed = compress::compress(Codec::Gzip, &snoop::tests::snoop_file(4, &[(&frame, 1, 0)])).unwrap();
        let mut window = compressed.clone();
        window.extend_from_slice(b"more bytes");
        let finding = GzipCaptureParser.parse(&window, 0x10).expect("a compressed capture");
        assert_eq!((finding.id.as_str(), finding.start, finding.len), (GZIP_CAPTURE_FINDING_ID, 0x10, compressed.len()));
        assert_eq!(finding.title, "gzip-compressed snoop capture");
        let plain = compress::compress(Codec::Gzip, b"not a capture").unwrap();
        assert!(GzipCaptureParser.parse(&plain, 0).is_none());
    }

    #[test]
    fn the_capture_parsers_run_where_their_formats_appear_in_a_scan() {
        let frame = udp_frame();
        let mut document = vec![0x33u8; 50];
        document.extend_from_slice(&snoop::tests::snoop_file(4, &[(&frame, 1, 0)]));
        document.extend_from_slice(&[0x44; 30]);
        let netmon_at = document.len();
        document.extend_from_slice(&netmon::tests::netmon_file(0x01, &[netmon::tests::TestFrame { data: &frame, offset_micros: 0, media_type: 1 }]));
        let registry = crate::app::build_registry();
        let context = crate::plugin::ScanContext { base: 0, document_len: document.len(), strides: Vec::new() };
        let findings = registry.scan(&document, &context);
        let start_of = |id: &str| findings.iter().find(|finding| finding.id == id).map(|finding| finding.start);
        assert_eq!(start_of("snoop"), Some(50), "{findings:?}");
        assert_eq!(start_of("netmon"), Some(netmon_at));
    }
}
