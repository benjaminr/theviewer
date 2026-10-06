//! RTP and RTCP (RFC 3550): media packets and their control reports over
//! UDP. Neither has a fixed port; RTP is recognised by what the rest of the
//! set says ([`super::SetHints`]), RTCP also by its strict layout.

use crate::plugin::Field;

use super::{AppLayer, u16_at, u32_at};

pub(super) const RTP_HEADER_LEN: usize = 12;
const RTP_VERSION: u8 = 2;
const CSRC_LEN: usize = 4;
const PADDING_BIT: u8 = 0x20;
const EXTENSION_BIT: u8 = 0x10;
const MARKER_BIT: u8 = 0x80;
/// Payload types 72 to 76 (with the marker bit, bytes 200 to 204) would
/// collide with RTCP's packet types, so RTP never uses them (RFC 5761).
const RTCP_COLLIDING_PAYLOAD_TYPES: std::ops::RangeInclusive<u8> = 72..=76;
/// RTCP packet types from sender report (200) to extended report (207).
const RTCP_PACKET_TYPES: std::ops::RangeInclusive<u8> = 200..=207;
const RTCP_SENDER_REPORT: u8 = 200;
const RTCP_RECEIVER_REPORT: u8 = 201;
const RTCP_HEADER_LEN: usize = 4;
const RTCP_REPORT_BLOCK_LEN: usize = 24;
/// The sender information of a sender report: NTP and RTP timestamps and
/// the packet and octet counts.
const RTCP_SENDER_INFO_LEN: usize = 20;
/// Most RTCP packets read from one compound packet.
const RTCP_MAX_PACKETS: usize = 16;
/// Bytes of a payload shown as hex.
const PAYLOAD_PREVIEW_BYTES: usize = 16;

/// The static payload types of RFC 3551, named as Wireshark's packet list
/// names them.
fn payload_type_name(payload_type: u8) -> String {
    let name = match payload_type {
        0 => "ITU-T G.711 PCMU",
        3 => "GSM 06.10",
        4 => "ITU-T G.723",
        5 | 6 => "DVI4",
        7 => "LPC",
        8 => "ITU-T G.711 PCMA",
        9 => "ITU-T G.722",
        10 | 11 => "L16",
        12 => "QCELP",
        13 => "Comfort noise (CN)",
        14 => "MPEG-I/II Audio",
        15 => "ITU-T G.728",
        18 => "ITU-T G.729",
        25 => "CelB",
        26 => "JPEG",
        28 => "nv",
        31 => "ITU-T H.261",
        32 => "MPEG-I/II Video",
        33 => "MPEG-II transport streams",
        34 => "ITU-T H.263",
        96..=127 => return format!("DynamicRTP-Type-{payload_type}"),
        _ => return format!("Unassigned ({payload_type})"),
    };
    name.to_string()
}

fn rtcp_type_name(packet_type: u8) -> &'static str {
    match packet_type {
        RTCP_SENDER_REPORT => "Sender Report",
        RTCP_RECEIVER_REPORT => "Receiver Report",
        202 => "Source description",
        203 => "Goodbye",
        204 => "Application specific",
        205 => "Generic RTP Feedback",
        206 => "Payload-specific Feedback",
        207 => "Extended report (RFC 3611)",
        _ => "Unknown",
    }
}

/// The payload type, sequence number and SSRC of what could be an RTP
/// header: version 2, a payload type RTCP cannot be mistaken for, and room
/// for its contributing sources.
pub(super) fn plausible_header(payload: &[u8]) -> Option<(u8, u16, u32)> {
    if payload.len() < RTP_HEADER_LEN || payload[0] >> 6 != RTP_VERSION {
        return None;
    }
    let payload_type = payload[1] & !MARKER_BIT;
    let csrc_count = (payload[0] & 0x0F) as usize;
    if RTCP_COLLIDING_PAYLOAD_TYPES.contains(&payload_type) || payload.len() < RTP_HEADER_LEN + csrc_count * CSRC_LEN {
        return None;
    }
    Some((payload_type, u16_at(payload, 2)?, u32_at(payload, 8)?))
}

/// Whether the second byte names an RTCP packet, as on a port that carries
/// RTP and RTCP together (RFC 5761).
pub(super) fn looks_like_rtcp_type(payload: &[u8]) -> bool {
    payload.get(1).is_some_and(|byte| RTCP_PACKET_TYPES.contains(byte))
}

/// An RTP packet, or `None` when the header does not hold together.
pub fn dissect_rtp(payload: &[u8]) -> Option<AppLayer> {
    let (payload_type, sequence, ssrc) = plausible_header(payload)?;
    let first = payload[0];
    let csrc_count = (first & 0x0F) as usize;
    let marker = payload[1] & MARKER_BIT != 0;
    let timestamp = u32_at(payload, 4)?;
    let mut fields = vec![
        Field::new("Version", 0, 1, RTP_VERSION.to_string()),
        Field::new("Padding", 0, 1, (first & PADDING_BIT != 0).to_string()),
        Field::new("Extension", 0, 1, (first & EXTENSION_BIT != 0).to_string()),
        Field::new("CSRC count", 0, 1, csrc_count.to_string()),
        Field::new("Marker", 1, 1, marker.to_string()),
        Field::new("Payload type", 1, 1, format!("{payload_type} ({})", payload_type_name(payload_type))),
        Field::new("Sequence number", 2, 2, sequence.to_string()),
        Field::new("Timestamp", 4, 4, timestamp.to_string()),
        Field::new("SSRC", 8, 4, format!("{ssrc:#010x}")),
    ];
    let mut at = RTP_HEADER_LEN;
    for _ in 0..csrc_count {
        fields.push(Field::new("CSRC", at, CSRC_LEN, format!("{:#010x}", u32_at(payload, at)?)));
        at += CSRC_LEN;
    }
    if first & EXTENSION_BIT != 0 {
        let profile = u16_at(payload, at)?;
        let words = u16_at(payload, at + 2)? as usize;
        let len = 4 + words * 4;
        payload.get(at..at + len)?;
        fields.push(Field::new("Header extension", at, len, format!("profile {profile:#06x}, {words} words")));
        at += len;
    }
    let mut end = payload.len();
    if first & PADDING_BIT != 0 {
        let padding = *payload.last()? as usize;
        if padding == 0 || at + padding > payload.len() {
            return None;
        }
        end -= padding;
        fields.push(Field::new("Padding bytes", end, padding, padding.to_string()));
    }
    if end > at {
        fields.push(Field::new("Payload", at, end - at, format!("{} bytes: {}", end - at, super::super::hex_preview(&payload[at..end], PAYLOAD_PREVIEW_BYTES))));
    }
    let mark = if marker { ", Mark" } else { "" };
    let info = format!("PT={}, SSRC={ssrc:#010X}, Seq={sequence}, Time={timestamp}{mark}", payload_type_name(payload_type));
    Some(AppLayer { name: "RTP", key: "rtp", len: payload.len(), fields, info })
}

/// A compound RTCP packet, or `None` unless every packet in it is version
/// 2 with a known type and their lengths add up to the payload exactly.
pub fn dissect_rtcp(payload: &[u8]) -> Option<AppLayer> {
    let mut fields = Vec::new();
    let mut names = Vec::new();
    let mut at = 0;
    while at < payload.len() {
        if names.len() == RTCP_MAX_PACKETS {
            return None;
        }
        let first = *payload.get(at)?;
        let packet_type = *payload.get(at + 1)?;
        if first >> 6 != RTP_VERSION || !RTCP_PACKET_TYPES.contains(&packet_type) {
            return None;
        }
        let len = (u16_at(payload, at + 2)? as usize + 1) * 4;
        let packet = payload.get(at..at + len)?;
        fields.push(rtcp_packet(packet, at));
        names.push(rtcp_type_name(packet_type));
        at += len;
    }
    if names.is_empty() {
        return None;
    }
    Some(AppLayer { name: "RTCP", key: "rtcp", len: payload.len(), fields, info: names.join(", ") })
}

/// One packet of a compound RTCP packet, starting at `base` in the payload.
fn rtcp_packet(packet: &[u8], base: usize) -> Field {
    let count = (packet[0] & 0x1F) as usize;
    let packet_type = packet[1];
    let words = u16_at(packet, 2).unwrap_or_default();
    let mut children = vec![
        Field::new("Reception report count", base, 1, count.to_string()),
        Field::new("Packet type", base + 1, 1, format!("{packet_type} ({})", rtcp_type_name(packet_type))),
        Field::new("Length", base + 2, 2, format!("{words} ({} bytes)", packet.len())),
    ];
    if let Some(ssrc) = u32_at(packet, RTCP_HEADER_LEN) {
        children.push(Field::new("Sender SSRC", base + 4, 4, format!("{ssrc:#010x}")));
    }
    let mut at = RTCP_HEADER_LEN + 4;
    if packet_type == RTCP_SENDER_REPORT && packet.len() >= at + RTCP_SENDER_INFO_LEN {
        let seconds = u32_at(packet, at).unwrap_or_default();
        let fraction = u32_at(packet, at + 4).unwrap_or_default();
        children.push(Field::new("NTP timestamp", base + at, 8, format!("{seconds}.{:06} s since 1900", (fraction as u64 * 1_000_000) >> 32)));
        children.push(Field::new("RTP timestamp", base + at + 8, 4, u32_at(packet, at + 8).unwrap_or_default().to_string()));
        children.push(Field::new("Sender's packet count", base + at + 12, 4, u32_at(packet, at + 12).unwrap_or_default().to_string()));
        children.push(Field::new("Sender's octet count", base + at + 16, 4, u32_at(packet, at + 16).unwrap_or_default().to_string()));
        at += RTCP_SENDER_INFO_LEN;
    }
    if matches!(packet_type, RTCP_SENDER_REPORT | RTCP_RECEIVER_REPORT) {
        for index in 0..count {
            let Some(block) = packet.get(at..at + RTCP_REPORT_BLOCK_LEN) else { break };
            children.push(report_block(block, base + at, index));
            at += RTCP_REPORT_BLOCK_LEN;
        }
    }
    Field::new(rtcp_type_name(packet_type), base, packet.len(), format!("{} bytes", packet.len())).with_children(children)
}

/// A report block about one source received.
fn report_block(block: &[u8], at: usize, index: usize) -> Field {
    let number = |offset: usize| u32_at(block, offset).unwrap_or_default();
    let lost = number(4) & 0x00FF_FFFF;
    let fraction = block[4];
    Field::new(format!("Report block {index}"), at, RTCP_REPORT_BLOCK_LEN, format!("SSRC {:#010x}, {lost} lost", number(0))).with_children(vec![
        Field::new("SSRC", at, 4, format!("{:#010x}", number(0))),
        Field::new("Fraction lost", at + 4, 1, format!("{fraction} / 256")),
        Field::new("Cumulative packets lost", at + 5, 3, lost.to_string()),
        Field::new("Highest sequence number received", at + 8, 4, number(8).to_string()),
        Field::new("Interarrival jitter", at + 12, 4, number(12).to_string()),
        Field::new("Last SR timestamp", at + 16, 4, format!("{:#010x}", number(16))),
        Field::new("Delay since last SR", at + 20, 4, format!("{:.3} s", number(20) as f64 / 65_536.0)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtp(payload_type: u8, sequence: u16, marker: bool) -> Vec<u8> {
        let mut packet = vec![0x80, payload_type | if marker { MARKER_BIT } else { 0 }];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&160u32.to_be_bytes());
        packet.extend_from_slice(&0x1234_ABCDu32.to_be_bytes());
        packet.extend_from_slice(&[0xFF; 160]);
        packet
    }

    #[test]
    fn an_rtp_packet_names_its_codec_source_sequence_and_time() {
        let layer = dissect_rtp(&rtp(0, 4321, true)).expect("RTP");
        assert_eq!(layer.info, "PT=ITU-T G.711 PCMU, SSRC=0x1234ABCD, Seq=4321, Time=160, Mark");
        let payload = layer.fields.iter().find(|f| f.name == "Payload").expect("payload");
        assert_eq!((payload.offset, payload.len), (12, 160));
        assert_eq!(dissect_rtp(&rtp(96, 1, false)).expect("RTP").info, "PT=DynamicRTP-Type-96, SSRC=0x1234ABCD, Seq=1, Time=160");
    }

    #[test]
    fn rtp_headers_that_do_not_hold_together_are_rejected() {
        assert!(dissect_rtp(&[0x80, 0, 0, 1]).is_none(), "shorter than a header");
        let mut version_one = rtp(0, 1, false);
        version_one[0] = 0x40;
        assert!(dissect_rtp(&version_one).is_none());
        assert!(dissect_rtp(&rtp(72, 1, true)).is_none(), "an RTCP sender report, not RTP");
        let mut too_many_sources = rtp(0, 1, false)[..16].to_vec();
        too_many_sources[0] = 0x8F;
        assert!(dissect_rtp(&too_many_sources).is_none());
        let mut bad_padding = rtp(0, 1, false);
        bad_padding[0] |= PADDING_BIT;
        *bad_padding.last_mut().expect("bytes") = 250;
        assert!(dissect_rtp(&bad_padding).is_none());
    }

    #[test]
    fn a_compound_rtcp_packet_lists_its_reports_and_must_add_up_exactly() {
        // A sender report with one report block, then a source description.
        let mut compound = vec![0x81, 200, 0, 12];
        compound.extend_from_slice(&0x1234_ABCDu32.to_be_bytes());
        compound.extend_from_slice(&[0; 20]);
        compound.extend_from_slice(&0x5555_0001u32.to_be_bytes());
        compound.extend_from_slice(&[0x10, 0, 0, 3]);
        compound.extend_from_slice(&[0; 16]);
        compound.extend_from_slice(&[0x81, 202, 0, 1, 0x12, 0x34, 0xAB, 0xCD]);
        let layer = dissect_rtcp(&compound).expect("RTCP");
        assert_eq!(layer.info, "Sender Report, Source description");
        let block = &layer.fields[0].children.iter().find(|f| f.name == "Report block 0").expect("a report block").children;
        assert_eq!(block[2].value, "3");
        assert!(dissect_rtcp(&compound[..compound.len() - 4]).is_none(), "the last packet is cut short");
        let mut extra = compound.clone();
        extra.push(0);
        assert!(dissect_rtcp(&extra).is_none(), "a stray byte after the last packet");
        assert!(dissect_rtcp(&rtp(0, 1, false)).is_none());
    }

    #[test]
    fn arbitrary_bytes_never_make_the_rtp_or_rtcp_parsers_panic() {
        let mut state = 0x7F4A_7C15u32;
        for round in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let len = (state % 64) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|index| (state >> (index % 24)) as u8).collect();
            if let Some(first) = bytes.first_mut() {
                *first = 0x80 | (*first & 0x3F);
            }
            if round % 2 == 0 && bytes.len() > 1 {
                bytes[1] = 200 + (state % 8) as u8;
            }
            let _ = dissect_rtp(&bytes);
            let _ = dissect_rtcp(&bytes);
        }
    }
}
