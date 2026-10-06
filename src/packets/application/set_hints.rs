//! What a packet set says about its flows that a single packet cannot: the
//! ports a TFTP transfer moved to after its request to port 69.
//!
//! The hints are learned in one pass over the set before its packets are
//! dissected one by one ([`SetHints::learn`]), and consulted when a payload
//! travels on no well-known port.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use super::super::LinkKind;
use super::super::dissect::dissect;
use super::super::flows::{Flow, Transport};
use super::tftp;

const PORT_TFTP: u16 = 69;
/// Most TFTP transfers remembered.
const MAX_TFTP_TRANSFERS: usize = 4096;

/// Flows identified by other packets of the set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetHints {
    /// TFTP transfers: the client's address and port, and the server's
    /// address, from read and write requests sent to port 69. The rest of
    /// a transfer runs between that client port and a port the server chose.
    tftp_transfers: HashSet<(SocketAddr, IpAddr)>,
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
        for (bytes, link) in packets {
            let dissection = dissect(bytes, link);
            let (Some(flow), Some((at, len))) = (dissection.flow, dissection.payload) else { continue };
            let Some(payload) = bytes.get(at..at + len) else { continue };
            hints.learn_from(&flow, payload);
        }
        hints
    }

    /// Learn what one packet's flow and payload say.
    fn learn_from(&mut self, flow: &Flow, payload: &[u8]) {
        let Some((source, destination)) = socket_addresses(flow) else { return };
        if flow.transport == Transport::Udp && destination.port() == PORT_TFTP && self.tftp_transfers.len() < MAX_TFTP_TRANSFERS && tftp::is_request(payload) {
            self.tftp_transfers.insert((source, destination.ip()));
        }
    }

    /// Whether `flow` belongs to a TFTP transfer a request in the set began.
    pub fn is_tftp(&self, flow: &Flow) -> bool {
        let Some((source, destination)) = socket_addresses(flow) else { return false };
        flow.transport == Transport::Udp && (self.tftp_transfers.contains(&(source, destination.ip())) || self.tftp_transfers.contains(&(destination, source.ip())))
    }

    pub fn is_empty(&self) -> bool {
        self.tftp_transfers.is_empty()
    }
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

    #[test]
    fn a_set_without_requests_teaches_nothing() {
        let data = udp((SERVER, 61000), (CLIENT, 50000), b"\x00\x03\x00\x01data");
        let not_a_request = udp((CLIENT, 50000), (SERVER, PORT_TFTP), b"\x00\x03\x00\x01");
        let hints = SetHints::learn([&data, &not_a_request].map(|packet| (packet.as_slice(), LinkKind::RawIp)));
        assert!(hints.is_empty());
        assert!(SetHints::learn([(&b"\x01\x02"[..], LinkKind::Unknown)]).is_empty());
    }
}
