//! What a packet set says about its flows that a single packet cannot: the
//! ports a TFTP transfer moved to after its request to port 69, and the UDP
//! endpoints carrying RTP and RTCP, as SDP or RTSP announced them or as a
//! run of agreeing RTP headers shows.
//!
//! The hints are learned in one pass over the set before its packets are
//! dissected one by one ([`SetHints::learn`]), and consulted when a payload
//! travels on no well-known port.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use super::super::LinkKind;
use super::super::dissect::dissect;
use super::super::flows::{Flow, Transport};
use super::signalling::{Announced, announced_media};
use super::{rtp, tftp};

const PORT_TFTP: u16 = 69;
/// Most TFTP transfers, and most media endpoints, remembered.
const MAX_TFTP_TRANSFERS: usize = 4096;
const MAX_MEDIA_ENDPOINTS: usize = 4096;
/// Most UDP flows followed while looking for RTP.
const MAX_RTP_CANDIDATES: usize = 16_384;
/// RTP picks its ports from the dynamic range in practice; lower ports are
/// left to the protocols registered on them.
const LOWEST_RTP_PORT: u16 = 1024;
/// A flow is taken for RTP without signalling only after this many packets
/// in a row kept one source, one payload type and sequence numbers that rise
/// by small steps...
const RTP_MIN_AGREEING: u32 = 8;
/// ...and when at least this share of its packets (in tenths) agreed.
const RTP_MIN_AGREEING_TENTHS: u32 = 9;
/// The largest step between consecutive sequence numbers still taken as
/// the same stream (a few packets lost or reordered).
const RTP_MAX_SEQUENCE_STEP: u16 = 4;

/// What the RTP headers of one direction of a UDP flow have shown so far.
#[derive(Clone, Copy, Debug, Default)]
struct RtpCandidate {
    /// The payload type, sequence number and SSRC of the last header.
    last: Option<(u8, u16, u32)>,
    /// Packets that continued the stream of the one before them.
    agreeing: u32,
    packets: u32,
}

impl RtpCandidate {
    fn add(&mut self, header: Option<(u8, u16, u32)>) {
        self.packets += 1;
        if let (Some((last_type, last_sequence, last_ssrc)), Some((payload_type, sequence, ssrc))) = (self.last, header) {
            let step = sequence.wrapping_sub(last_sequence);
            if payload_type == last_type && ssrc == last_ssrc && (1..=RTP_MAX_SEQUENCE_STEP).contains(&step) {
                self.agreeing += 1;
            }
        }
        self.last = header;
    }

    fn is_rtp(&self) -> bool {
        self.agreeing >= RTP_MIN_AGREEING && self.agreeing * 10 >= self.packets.saturating_sub(1) * RTP_MIN_AGREEING_TENTHS
    }
}

/// Flows identified by other packets of the set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetHints {
    /// TFTP transfers: the client's address and port, and the server's
    /// address, from read and write requests sent to port 69. The rest of
    /// a transfer runs between that client port and a port the server chose.
    tftp_transfers: HashSet<(SocketAddr, IpAddr)>,
    /// UDP endpoints that send or receive RTP.
    rtp: HashSet<SocketAddr>,
    /// UDP endpoints that send or receive RTCP.
    rtcp: HashSet<SocketAddr>,
}

/// A flow's source and destination as socket addresses, for TCP and UDP.
fn socket_addresses(flow: &Flow) -> Option<(SocketAddr, SocketAddr)> {
    let source = SocketAddr::new(flow.source.address, flow.source.port?);
    let destination = SocketAddr::new(flow.destination.address, flow.destination.port?);
    Some((source, destination))
}

impl SetHints {
    /// Learn the hints from every packet of a set, given as its bytes and
    /// what its first byte is.
    pub fn learn<'a>(packets: impl IntoIterator<Item = (&'a [u8], LinkKind)>) -> SetHints {
        let mut hints = SetHints::default();
        let mut candidates: HashMap<(SocketAddr, SocketAddr), RtpCandidate> = HashMap::new();
        for (bytes, link) in packets {
            let dissection = dissect(bytes, link);
            let (Some(flow), Some((at, len))) = (dissection.flow, dissection.payload) else { continue };
            let Some(payload) = bytes.get(at..at + len) else { continue };
            hints.learn_from(&flow, payload);
            follow_rtp_candidate(&mut candidates, &flow, payload);
        }
        for ((_, destination), candidate) in candidates {
            if candidate.is_rtp() && hints.rtp.len() < MAX_MEDIA_ENDPOINTS {
                hints.rtp.insert(destination);
            }
        }
        hints
    }

    /// Learn what one packet's flow and payload say.
    fn learn_from(&mut self, flow: &Flow, payload: &[u8]) {
        let Some((source, destination)) = socket_addresses(flow) else { return };
        if flow.transport == Transport::Udp && destination.port() == PORT_TFTP && self.tftp_transfers.len() < MAX_TFTP_TRANSFERS && tftp::is_request(payload) {
            self.tftp_transfers.insert((source, destination.ip()));
        }
        for announced in announced_media(payload, source.ip(), destination.ip()) {
            if self.rtp.len() + self.rtcp.len() >= MAX_MEDIA_ENDPOINTS {
                break;
            }
            match announced {
                Announced::Rtp(endpoint) => self.rtp.insert(endpoint),
                Announced::Rtcp(endpoint) => self.rtcp.insert(endpoint),
            };
        }
    }

    /// Whether `flow` belongs to a TFTP transfer a request in the set began.
    pub fn is_tftp(&self, flow: &Flow) -> bool {
        let Some((source, destination)) = socket_addresses(flow) else { return false };
        flow.transport == Transport::Udp && (self.tftp_transfers.contains(&(source, destination.ip())) || self.tftp_transfers.contains(&(destination, source.ip())))
    }

    /// Whether `flow` is UDP to or from an endpoint that carries RTP.
    pub fn is_rtp(&self, flow: &Flow) -> bool {
        Self::touches(&self.rtp, flow)
    }

    /// Whether `flow` is UDP to or from an endpoint that carries RTCP.
    pub fn is_rtcp(&self, flow: &Flow) -> bool {
        Self::touches(&self.rtcp, flow)
    }

    fn touches(endpoints: &HashSet<SocketAddr>, flow: &Flow) -> bool {
        let Some((source, destination)) = socket_addresses(flow) else { return false };
        flow.transport == Transport::Udp && (endpoints.contains(&source) || endpoints.contains(&destination))
    }

    pub fn is_empty(&self) -> bool {
        self.tftp_transfers.is_empty() && self.rtp.is_empty() && self.rtcp.is_empty()
    }
}

/// Add a UDP packet between two dynamic ports to what its direction of the
/// flow has shown about RTP.
fn follow_rtp_candidate(candidates: &mut HashMap<(SocketAddr, SocketAddr), RtpCandidate>, flow: &Flow, payload: &[u8]) {
    let Some((source, destination)) = socket_addresses(flow) else { return };
    if flow.transport != Transport::Udp || source.port() < LOWEST_RTP_PORT || destination.port() < LOWEST_RTP_PORT {
        return;
    }
    let known = candidates.contains_key(&(source, destination));
    if !known && candidates.len() >= MAX_RTP_CANDIDATES {
        return;
    }
    candidates.entry((source, destination)).or_default().add(rtp::plausible_header(payload));
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use super::*;

    const CLIENT: [u8; 4] = [10, 0, 0, 2];
    const SERVER: [u8; 4] = [10, 0, 0, 1];

    fn udp(source: ([u8; 4], u16), destination: ([u8; 4], u16), payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ipv4(source.0, destination.0, 64).udp(source.1, destination.1);
        let mut packet = Vec::new();
        builder.write(&mut packet, payload).expect("a packet");
        packet
    }

    fn flow_of(packet: &[u8]) -> Flow {
        dissect(packet, LinkKind::RawIp).flow.expect("a flow")
    }

    #[test]
    fn a_read_request_to_port_69_marks_the_transfer_on_the_ports_that_follow() {
        let request = udp((CLIENT, 50000), (SERVER, PORT_TFTP), b"\x00\x01boot.img\x00octet\x00");
        let data = udp((SERVER, 61000), (CLIENT, 50000), b"\x00\x03\x00\x01data");
        let ack = udp((CLIENT, 50000), (SERVER, 61000), b"\x00\x04\x00\x01");
        let unrelated = udp((CLIENT, 50001), (SERVER, 61000), b"\x00\x04\x00\x01");
        let hints = SetHints::learn([&request, &data, &ack, &unrelated].map(|packet| (packet.as_slice(), LinkKind::RawIp)));
        assert!(hints.is_tftp(&flow_of(&data)));
        assert!(hints.is_tftp(&flow_of(&ack)));
        assert!(!hints.is_tftp(&flow_of(&unrelated)), "another client port is another conversation");
    }

    fn rtp_packet(sequence: u16, ssrc: u32) -> Vec<u8> {
        let mut header = vec![0x80, 0];
        header.extend_from_slice(&sequence.to_be_bytes());
        header.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
        header.extend_from_slice(&ssrc.to_be_bytes());
        header.extend_from_slice(&[0xD5; 160]);
        udp((CLIENT, 40000), (SERVER, 30000), &header)
    }

    fn learn(packets: &[Vec<u8>]) -> SetHints {
        SetHints::learn(packets.iter().map(|packet| (packet.as_slice(), LinkKind::RawIp)))
    }

    #[test]
    fn a_run_of_agreeing_rtp_headers_marks_the_flow_and_a_short_or_jumbled_one_does_not() {
        let stream: Vec<Vec<u8>> = (100..120).map(|sequence| rtp_packet(sequence, 0xCAFE)).collect();
        let hints = learn(&stream);
        assert!(hints.is_rtp(&flow_of(&stream[0])));
        let reply = udp((SERVER, 30000), (CLIENT, 40000), b"anything");
        assert!(hints.is_rtp(&flow_of(&reply)), "the endpoint's other direction too");

        assert!(!learn(&stream[..5]).is_rtp(&flow_of(&stream[0])), "too few packets to be sure");
        let jumbled: Vec<Vec<u8>> = (0..20u16).map(|index| rtp_packet(index.wrapping_mul(7919), 0xCAFE + u32::from(index % 3))).collect();
        assert!(!learn(&jumbled).is_rtp(&flow_of(&jumbled[0])));
        let low_port: Vec<Vec<u8>> = (0..20).map(|sequence| udp((CLIENT, 40000), (SERVER, 53), &rtp_packet(sequence, 1)[28..])).collect();
        assert!(learn(&low_port).is_empty(), "registered ports are left to their own protocols");
    }

    #[test]
    fn sdp_in_a_sip_message_marks_the_announced_rtp_and_rtcp_endpoints() {
        let invite = udp((CLIENT, 5060), (SERVER, 5060), b"INVITE sip:b@x SIP/2.0\r\n\r\nv=0\r\nc=IN IP4 10.0.0.2\r\nm=audio 7078 RTP/AVP 0\r\n");
        let hints = learn(&[invite]);
        let media = udp((SERVER, 9000), (CLIENT, 7078), &rtp_packet(1, 1)[28..]);
        let control = udp((SERVER, 9001), (CLIENT, 7079), &[0x80, 201, 0, 1, 0, 0, 0, 1]);
        assert!(hints.is_rtp(&flow_of(&media)));
        assert!(hints.is_rtcp(&flow_of(&control)));
        assert!(!hints.is_rtp(&flow_of(&control)));
    }

    #[test]
    fn a_set_without_requests_teaches_nothing() {
        let data = udp((SERVER, 61000), (CLIENT, 50000), b"\x00\x03\x00\x01data");
        let not_a_request = udp((CLIENT, 50000), (SERVER, PORT_TFTP), b"\x00\x03\x00\x01");
        let hints = SetHints::learn([&data, &not_a_request].map(|packet| (packet.as_slice(), LinkKind::RawIp)));
        assert!(hints.is_empty());
        assert!(SetHints::learn([(&b"\x01\x02"[..], LinkKind::Unknown)]).is_empty());
    }
}
