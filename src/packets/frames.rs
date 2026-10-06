//! Frames of unknown format that are a protocol we can dissect: what to
//! decode them as, and finding that out from the frames themselves.
//!
//! Frames split from a file, or taken from the protocol tool's message
//! framing, carry no link type and no ports, so nothing says they are DNS
//! messages or Modbus/TCP frames. [`FrameProtocol`] names a decoder to read
//! each frame with from its first byte, and [`detect_frame_protocol`] tries
//! every decoder on a sample of the frames and names the one that reads
//! nearly all of them in full. It is conservative: a decoder that reads only
//! a prefix of each frame, or only some of the frames, is not taken, and
//! detecting nothing is better than detecting the wrong protocol.

use super::application::{self, AppLayer};
use super::dissect::looks_like_ip;

/// Most frames tried, spread evenly through the set.
pub const DETECTION_SAMPLE: usize = 64;
/// Share of the sampled frames a decoder must read for the set to be taken
/// as that protocol.
const MIN_AGREEMENT: f64 = 0.8;
/// Fewest frames a decoder must read, unless the set holds only one.
const MIN_AGREEING_FRAMES: usize = 2;
/// Share of a frame the decoded layers must cover for the frame to count.
const MIN_FRAME_COVERAGE: f64 = 0.9;

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_TAG_LEN: usize = 4;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;
const ARP_ETHERNET_IPV4: [u8; 6] = [0, 1, 8, 0, 6, 4];
const ARP_LEN: usize = 28;
/// The bit of a MAC address's first byte marking a group address, which a
/// source address never is.
const MAC_GROUP_BIT: u8 = 0x01;

const DNS_OPCODE_MAX: u16 = 6;
const DNS_Z_BIT: u16 = 0x0040;
const NTP_MAX_STRATUM: u8 = 16;
const NTP_POLL_RANGE: std::ops::RangeInclusive<i8> = -6..=17;
const NTP_PRECISION_RANGE: std::ops::RangeInclusive<i8> = -32..=0;
const MQTT_PUBLISH: u8 = 3;
/// MQTT packet types whose fixed-header flags must be 0b0010.
const MQTT_FLAGGED_TYPES: [u8; 3] = [6, 8, 10];
const MQTT_LAST_TYPE: u8 = 15;
const DHCP_MAGIC_COOKIE_AT: usize = 236;
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const TFTP_READ_REQUEST: u16 = 1;
const TFTP_WRITE_REQUEST: u16 = 2;
/// Share of RTP frames that must share one synchronisation source.
const RTP_MIN_SHARED_SSRC: f64 = 0.5;

/// What a frame of unknown format is decoded as, from its first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameProtocol {
    Ethernet,
    RawIp,
    Dns,
    /// DNS messages each after a two-byte length, as on TCP.
    DnsOverTcp,
    Snmp,
    Ntp,
    ModbusTcp,
    Mqtt,
    Tls,
    Dhcp,
    Tftp,
    /// TPKT, with the COTP TPDU inside and any S7comm header in it.
    Tpkt,
    /// The NetBIOS session service, with the SMB header inside.
    Nbss,
    Rtp,
    Rtcp,
    Http,
}

impl FrameProtocol {
    /// Every protocol, most specific first: when two read a set equally
    /// well, the earlier is taken.
    pub const ALL: [FrameProtocol; 16] = [
        FrameProtocol::Ethernet,
        FrameProtocol::RawIp,
        FrameProtocol::Tpkt,
        FrameProtocol::Nbss,
        FrameProtocol::ModbusTcp,
        FrameProtocol::Tls,
        FrameProtocol::Snmp,
        FrameProtocol::Dhcp,
        FrameProtocol::Rtcp,
        FrameProtocol::Http,
        FrameProtocol::Ntp,
        FrameProtocol::Dns,
        FrameProtocol::DnsOverTcp,
        FrameProtocol::Mqtt,
        FrameProtocol::Tftp,
        FrameProtocol::Rtp,
    ];

    /// The name shown, as the protocol's layer is named.
    pub fn label(self) -> &'static str {
        match self {
            FrameProtocol::Ethernet => "Ethernet",
            FrameProtocol::RawIp => "Raw IP",
            FrameProtocol::Dns => "DNS",
            FrameProtocol::DnsOverTcp => "DNS with a length prefix",
            FrameProtocol::Snmp => "SNMP",
            FrameProtocol::Ntp => "NTP",
            FrameProtocol::ModbusTcp => "Modbus/TCP",
            FrameProtocol::Mqtt => "MQTT",
            FrameProtocol::Tls => "TLS",
            FrameProtocol::Dhcp => "DHCP",
            FrameProtocol::Tftp => "TFTP",
            FrameProtocol::Tpkt => "TPKT",
            FrameProtocol::Nbss => "NetBIOS Session Service",
            FrameProtocol::Rtp => "RTP",
            FrameProtocol::Rtcp => "RTCP",
            FrameProtocol::Http => "HTTP",
        }
    }

    /// The filter's name for the protocol, which a decoded frame lists.
    pub fn key(self) -> &'static str {
        match self {
            FrameProtocol::Ethernet => "eth",
            FrameProtocol::RawIp => "ip",
            FrameProtocol::Dns | FrameProtocol::DnsOverTcp => "dns",
            FrameProtocol::Snmp => "snmp",
            FrameProtocol::Ntp => "ntp",
            FrameProtocol::ModbusTcp => "modbus",
            FrameProtocol::Mqtt => "mqtt",
            FrameProtocol::Tls => "tls",
            FrameProtocol::Dhcp => "dhcp",
            FrameProtocol::Tftp => "tftp",
            FrameProtocol::Tpkt => "tpkt",
            FrameProtocol::Nbss => "nbss",
            FrameProtocol::Rtp => "rtp",
            FrameProtocol::Rtcp => "rtcp",
            FrameProtocol::Http => "http",
        }
    }

    /// Whether the frame starts a link layer rather than a message.
    pub fn is_link_layer(self) -> bool {
        matches!(self, FrameProtocol::Ethernet | FrameProtocol::RawIp)
    }

    /// Protocols whose header is short or loose enough that one frame
    /// proves little; they are detected only across several.
    fn needs_several_frames(self) -> bool {
        matches!(self, FrameProtocol::Mqtt | FrameProtocol::Ntp | FrameProtocol::Tftp | FrameProtocol::Rtp)
    }
}

/// A protocol found for a set of frames, and how many sampled frames it
/// read in full.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Detection {
    pub protocol: FrameProtocol,
    pub matched: usize,
    pub sampled: usize,
}

/// Up to [`DETECTION_SAMPLE`] frames spread evenly through `frames`.
fn sample<'a>(frames: &[&'a [u8]]) -> Vec<&'a [u8]> {
    if frames.len() <= DETECTION_SAMPLE {
        return frames.to_vec();
    }
    (0..DETECTION_SAMPLE).map(|index| frames[index * frames.len() / DETECTION_SAMPLE]).collect()
}

/// The protocol nearly every frame of the set reads as in full, if one
/// does: at least [`MIN_AGREEMENT`] of the sampled frames and at least two
/// of them, or a single frame read to its last byte by a decoder with a
/// strict enough header. `None` when no protocol is clearly right.
pub fn detect_frame_protocol(frames: &[&[u8]]) -> Option<Detection> {
    let sampled = sample(frames);
    if sampled.is_empty() {
        return None;
    }
    let single = sampled.len() == 1;
    let mut best: Option<(Detection, f64)> = None;
    for protocol in FrameProtocol::ALL {
        if single && protocol.needs_several_frames() {
            continue;
        }
        let coverages: Vec<f64> = sampled.iter().filter_map(|frame| frame_coverage(protocol, frame)).filter(|&coverage| coverage >= MIN_FRAME_COVERAGE).collect();
        let matched = coverages.len();
        let agrees = if single { coverages.first() == Some(&1.0) } else { matched >= MIN_AGREEING_FRAMES && matched as f64 >= MIN_AGREEMENT * sampled.len() as f64 };
        if !agrees || !set_holds_together(protocol, &sampled) {
            continue;
        }
        let mean_coverage = coverages.iter().sum::<f64>() / matched as f64;
        let better = best.is_none_or(|(known, known_coverage)| matched > known.matched || (matched == known.matched && mean_coverage > known_coverage));
        if better {
            best = Some((Detection { protocol, matched, sampled: sampled.len() }, mean_coverage));
        }
    }
    best.map(|(detection, _)| detection)
}

/// The share of `frame` that `protocol` reads, or `None` when it does not
/// read the frame or the frame lacks the protocol's tell-tale values.
fn frame_coverage(protocol: FrameProtocol, frame: &[u8]) -> Option<f64> {
    if frame.is_empty() {
        return None;
    }
    match protocol {
        FrameProtocol::Ethernet => looks_like_ethernet(frame).then_some(1.0),
        FrameProtocol::RawIp => looks_like_ip(frame).then_some(1.0),
        _ => {
            let layers = application::dissect_frame_as(protocol, frame);
            if layers.is_empty() || !frame_is_plausible(protocol, frame, &layers) {
                return None;
            }
            let covered: usize = layers.iter().map(|layer| layer.len).sum();
            Some(covered.min(frame.len()) as f64 / frame.len() as f64)
        }
    }
}

/// An Ethernet II header from a unicast source, with any VLAN tags, then an
/// IP packet whose header holds together or an Ethernet ARP packet.
fn looks_like_ethernet(frame: &[u8]) -> bool {
    if frame.len() < ETHERNET_HEADER_LEN || frame[6] & MAC_GROUP_BIT != 0 {
        return false;
    }
    let mut at = 12;
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    while matches!(ether_type, ETHERTYPE_VLAN | ETHERTYPE_QINQ) {
        at += VLAN_TAG_LEN;
        let Some(next) = frame.get(at..at + 2) else { return false };
        ether_type = u16::from_be_bytes([next[0], next[1]]);
    }
    let payload = &frame[at + 2..];
    match ether_type {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => looks_like_ip(payload),
        ETHERTYPE_ARP => payload.len() >= ARP_LEN && payload.starts_with(&ARP_ETHERNET_IPV4),
        _ => false,
    }
}

/// Values the decoders accept but real traffic of the protocol never
/// sends, which rule a frame out during detection; a frame decoded on the
/// user's say-so is read whatever they are.
fn frame_is_plausible(protocol: FrameProtocol, frame: &[u8], layers: &[AppLayer]) -> bool {
    match protocol {
        FrameProtocol::Dns => dns_header_is_plausible(frame),
        FrameProtocol::DnsOverTcp => frame.get(2..).is_some_and(dns_header_is_plausible),
        FrameProtocol::Ntp => {
            let [_, stratum, poll, precision] = [frame[0], frame[1], frame[2], frame[3]];
            stratum <= NTP_MAX_STRATUM && NTP_POLL_RANGE.contains(&(poll as i8)) && NTP_PRECISION_RANGE.contains(&(precision as i8))
        }
        FrameProtocol::Mqtt => {
            let (kind, flags) = (frame[0] >> 4, frame[0] & 0x0F);
            match kind {
                MQTT_PUBLISH => (flags >> 1) & 0x03 != 0x03,
                kind if MQTT_FLAGGED_TYPES.contains(&kind) => flags == 0b0010,
                kind => kind < MQTT_LAST_TYPE && flags == 0,
            }
        }
        FrameProtocol::Snmp => !layers[0].info.starts_with("Malformed"),
        FrameProtocol::Dhcp => frame.get(DHCP_MAGIC_COOKIE_AT..DHCP_MAGIC_COOKIE_AT + 4) == Some(&DHCP_MAGIC_COOKIE[..]),
        _ => true,
    }
}

/// A DNS header with a known opcode, the reserved bit clear, and at least
/// one question or record.
fn dns_header_is_plausible(message: &[u8]) -> bool {
    let Some(header) = message.get(..12) else { return false };
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let opcode = (flags >> 11) & 0x0F;
    let records: u32 = (0..4).map(|index| u16::from_be_bytes([header[4 + index * 2], header[5 + index * 2]]) as u32).sum();
    opcode <= DNS_OPCODE_MAX && flags & DNS_Z_BIT == 0 && records > 0
}

/// What the set as a whole must show for protocols whose single frames
/// prove little: a TFTP transfer opens with a request, and RTP frames
/// mostly come from one synchronisation source.
fn set_holds_together(protocol: FrameProtocol, frames: &[&[u8]]) -> bool {
    match protocol {
        FrameProtocol::Tftp => frames.iter().any(|frame| {
            let opcode = frame.get(..2).map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
            matches!(opcode, Some(TFTP_READ_REQUEST | TFTP_WRITE_REQUEST)) && !application::dissect_frame_as(FrameProtocol::Tftp, frame).is_empty()
        }),
        FrameProtocol::Rtp => {
            let sources: Vec<[u8; 4]> = frames.iter().filter_map(|frame| frame.get(8..12)).map(|bytes| [bytes[0], bytes[1], bytes[2], bytes[3]]).collect();
            let most_shared = sources.iter().map(|source| sources.iter().filter(|other| *other == source).count()).max().unwrap_or(0);
            most_shared as f64 >= RTP_MIN_SHARED_SSRC * frames.len() as f64
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use super::*;

    fn detected(frames: &[Vec<u8>]) -> Option<FrameProtocol> {
        let slices: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        detect_frame_protocol(&slices).map(|detection| detection.protocol)
    }

    fn dns_query(id: u16, name: &[u8]) -> Vec<u8> {
        let mut message = id.to_be_bytes().to_vec();
        message.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split(|&byte| byte == b'.') {
            message.push(label.len() as u8);
            message.extend_from_slice(label);
        }
        message.extend_from_slice(&[0, 0, 1, 0, 1]);
        message
    }

    fn modbus_read(transaction: u16, register: u16) -> Vec<u8> {
        let mut frame = transaction.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0, 0, 0, 6, 1, 3]);
        frame.extend_from_slice(&register.to_be_bytes());
        frame.extend_from_slice(&[0, 2]);
        frame
    }

    fn modbus_read_response(transaction: u16) -> Vec<u8> {
        let mut frame = transaction.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0, 0, 0, 7, 1, 3, 4, 0, 1, 0, 2]);
        frame
    }

    fn mqtt_publish(topic: &[u8], message: &[u8]) -> Vec<u8> {
        let mut body = (topic.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(topic);
        body.extend_from_slice(message);
        let mut frame = vec![0x30, body.len() as u8];
        frame.extend(body);
        frame
    }

    fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut bytes = vec![tag, content.len() as u8];
        bytes.extend_from_slice(content);
        bytes
    }

    fn snmp_get(request_id: u8) -> Vec<u8> {
        let oid = ber(0x06, &[0x2B, 6, 1, 2, 1, 1, 1, 0]);
        let binding = ber(0x30, &[oid, ber(0x05, &[])].concat());
        let bindings = ber(0x30, &binding);
        let pdu = ber(0xA0, &[ber(0x02, &[request_id]), ber(0x02, &[0]), ber(0x02, &[0]), bindings].concat());
        ber(0x30, &[ber(0x02, &[1]), ber(0x04, b"public"), pdu].concat())
    }

    fn ntp_client(seconds: u32) -> Vec<u8> {
        let mut packet = vec![0x23, 0, 6, 0xEC];
        packet.resize(40, 0);
        packet.extend_from_slice(&seconds.to_be_bytes());
        packet.extend_from_slice(&[0; 4]);
        packet
    }

    fn ethernet_udp(source_port: u16, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]).ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64).udp(source_port, 9000);
        let mut packet = Vec::new();
        builder.write(&mut packet, payload).expect("a packet");
        packet
    }

    /// Bytes from a xorshift generator, the same every run.
    fn noise(len: usize, mut state: u32) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    #[test]
    fn a_set_of_dns_messages_is_detected_as_dns() {
        let frames: Vec<Vec<u8>> = (0..10).map(|index| dns_query(index, b"host.example.com")).collect();
        let slices: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
        let detection = detect_frame_protocol(&slices).expect("a detection");
        assert_eq!(detection, Detection { protocol: FrameProtocol::Dns, matched: 10, sampled: 10 });
    }

    #[test]
    fn length_prefixed_dns_messages_are_told_apart_from_bare_ones() {
        let frames: Vec<Vec<u8>> = (0..4)
            .map(|index| {
                let message = dns_query(index, b"example.org");
                [(message.len() as u16).to_be_bytes().to_vec(), message].concat()
            })
            .collect();
        assert_eq!(detected(&frames), Some(FrameProtocol::DnsOverTcp));
    }

    #[test]
    fn modbus_tcp_requests_and_responses_are_detected_by_their_mbap_header() {
        let frames: Vec<Vec<u8>> = (0..6).flat_map(|index| [modbus_read(index, 100 + index), modbus_read_response(index)]).collect();
        assert_eq!(detected(&frames), Some(FrameProtocol::ModbusTcp));
    }

    #[test]
    fn mqtt_snmp_and_ntp_sets_are_each_detected() {
        let mqtt: Vec<Vec<u8>> = (0..5).map(|index| mqtt_publish(b"plant/line1/temp", format!("{}", 20 + index).as_bytes())).collect();
        assert_eq!(detected(&mqtt), Some(FrameProtocol::Mqtt));
        let snmp: Vec<Vec<u8>> = (1..6).map(snmp_get).collect();
        assert_eq!(detected(&snmp), Some(FrameProtocol::Snmp));
        let ntp: Vec<Vec<u8>> = (0..5).map(|index| ntp_client(0xE000_0000 + index)).collect();
        assert_eq!(detected(&ntp), Some(FrameProtocol::Ntp));
    }

    #[test]
    fn ethernet_frames_and_raw_ip_packets_are_detected_by_their_headers() {
        let ethernet: Vec<Vec<u8>> = (0..4).map(|index| ethernet_udp(4000 + index, b"reading")).collect();
        assert_eq!(detected(&ethernet), Some(FrameProtocol::Ethernet));
        let raw_ip: Vec<Vec<u8>> = ethernet.iter().map(|frame| frame[ETHERNET_HEADER_LEN..].to_vec()).collect();
        assert_eq!(detected(&raw_ip), Some(FrameProtocol::RawIp));
    }

    #[test]
    fn random_frames_and_a_mix_of_protocols_detect_nothing() {
        let random: Vec<Vec<u8>> = (0..40).map(|index| noise(20 + index * 3, 0x9E37_79B9 ^ index as u32)).collect();
        assert_eq!(detected(&random), None);
        let zeros: Vec<Vec<u8>> = (0..10).map(|_| vec![0; 48]).collect();
        assert_eq!(detected(&zeros), None, "all-zero records are not empty DNS headers");
        let mixed = vec![dns_query(1, b"a.example"), modbus_read(1, 1), mqtt_publish(b"t", b"x"), snmp_get(1), ntp_client(1), dns_query(2, b"b.example")];
        assert_eq!(detected(&mixed), None, "no protocol reads 80% of the frames");
    }

    #[test]
    fn a_single_frame_is_detected_only_when_read_to_its_last_byte() {
        assert_eq!(detected(&[dns_query(7, b"example.com")]), Some(FrameProtocol::Dns));
        let mut padded = dns_query(7, b"example.com");
        padded.extend_from_slice(&[0xEE; 4]);
        assert_eq!(detected(&[padded]), None, "four bytes left over");
        assert_eq!(detected(&[mqtt_publish(b"a/b", b"1")]), None, "one MQTT frame proves too little");
    }

    #[test]
    fn a_frame_mostly_left_over_does_not_count() {
        // A Modbus header claiming 2 bytes after the unit, in a long frame.
        let frames: Vec<Vec<u8>> = (0..5).map(|index| [vec![0, index, 0, 0, 0, 2, 1, 3], vec![0x55; 200]].concat()).collect();
        assert_eq!(detected(&frames), None);
    }
}
