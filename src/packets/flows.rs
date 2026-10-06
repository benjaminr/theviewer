//! Conversations, endpoints and streams: what the packets say about who
//! talked to whom.
//!
//! A [`Flow`] is one packet's addresses, ports and transport. Packets of a
//! conversation share a [`ConversationKey`], which orders the two endpoints so
//! that both directions land together.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

/// Most bytes a followed stream collects.
pub const STREAM_LIMIT: usize = 16 * 1024 * 1024;
/// Most bytes of a followed stream rendered as text per segment.
const SEGMENT_TEXT_LIMIT: usize = 64 * 1024;

/// The transport a flow uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    /// Any other IP protocol, by number.
    Other(u8),
}

impl Transport {
    pub fn label(self) -> String {
        match self {
            Transport::Tcp => "TCP".to_string(),
            Transport::Udp => "UDP".to_string(),
            Transport::Icmp => "ICMP".to_string(),
            Transport::Other(number) => format!("IP protocol {number}"),
        }
    }

    /// Whether the transport has ports.
    pub fn has_ports(self) -> bool {
        matches!(self, Transport::Tcp | Transport::Udp)
    }
}

/// An address and, for TCP and UDP, a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: Option<u16>,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.address, self.port) {
            (IpAddr::V6(address), Some(port)) => write!(f, "[{address}]:{port}"),
            (address, Some(port)) => write!(f, "{address}:{port}"),
            (address, None) => write!(f, "{address}"),
        }
    }
}

/// One packet's place in a conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Flow {
    pub transport: Transport,
    pub source: Endpoint,
    pub destination: Endpoint,
    /// The TCP sequence number, used to drop retransmitted segments.
    pub tcp_sequence: Option<u32>,
}

impl Flow {
    /// The conversation this packet belongs to, the same in both directions.
    pub fn key(&self) -> ConversationKey {
        let (a, b) = if self.source <= self.destination { (self.source, self.destination) } else { (self.destination, self.source) };
        ConversationKey { transport: self.transport, a, b }
    }

    /// Whether the packet travels from the key's `a` to its `b`.
    pub fn is_a_to_b(&self, key: &ConversationKey) -> bool {
        self.source == key.a
    }
}

/// Identifies a conversation: the transport and its two endpoints, ordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConversationKey {
    pub transport: Transport,
    pub a: Endpoint,
    pub b: Endpoint,
}

impl ConversationKey {
    /// A filter (in the [`super::filter`] language) that keeps this
    /// conversation's packets.
    pub fn filter_text(&self) -> String {
        let mut terms = vec![match self.transport {
            Transport::Tcp => "tcp".to_string(),
            Transport::Udp => "udp".to_string(),
            Transport::Icmp => "icmp".to_string(),
            Transport::Other(_) => "ip".to_string(),
        }];
        terms.push(format!("ip:{}", self.a.address));
        if self.b.address != self.a.address {
            terms.push(format!("ip:{}", self.b.address));
        }
        for port in [self.a.port, self.b.port].into_iter().flatten() {
            let term = format!("port:{port}");
            if !terms.contains(&term) {
                terms.push(term);
            }
        }
        terms.join(" ")
    }
}

impl fmt::Display for ConversationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ⇄ {}", self.transport.label(), self.a, self.b)
    }
}

/// Packet and byte counts for one conversation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conversation {
    pub key: ConversationKey,
    pub packets: usize,
    pub bytes: usize,
    pub packets_a_to_b: usize,
    pub bytes_a_to_b: usize,
    /// Index of the conversation's first packet.
    pub first_packet: usize,
}

impl Conversation {
    pub fn packets_b_to_a(&self) -> usize {
        self.packets - self.packets_a_to_b
    }

    pub fn bytes_b_to_a(&self) -> usize {
        self.bytes - self.bytes_a_to_b
    }
}

/// Group packets into conversations, in order of each one's first packet.
/// Each item is a packet's flow (if it has addresses) and its length.
pub fn conversations<'a>(packets: impl IntoIterator<Item = (Option<&'a Flow>, usize)>) -> Vec<Conversation> {
    let mut by_key: HashMap<ConversationKey, usize> = HashMap::new();
    let mut found: Vec<Conversation> = Vec::new();
    for (index, (flow, len)) in packets.into_iter().enumerate() {
        let Some(flow) = flow else { continue };
        let key = flow.key();
        let position = *by_key.entry(key).or_insert_with(|| {
            found.push(Conversation { key, packets: 0, bytes: 0, packets_a_to_b: 0, bytes_a_to_b: 0, first_packet: index });
            found.len() - 1
        });
        let conversation = &mut found[position];
        conversation.packets += 1;
        conversation.bytes += len;
        if flow.is_a_to_b(&key) {
            conversation.packets_a_to_b += 1;
            conversation.bytes_a_to_b += len;
        }
    }
    found
}

/// Packet and byte counts for one address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointStats {
    pub address: IpAddr,
    pub packets_sent: usize,
    pub bytes_sent: usize,
    pub packets_received: usize,
    pub bytes_received: usize,
}

/// Packet and byte counts per address, busiest first.
pub fn endpoints<'a>(packets: impl IntoIterator<Item = (Option<&'a Flow>, usize)>) -> Vec<EndpointStats> {
    let mut by_address: HashMap<IpAddr, EndpointStats> = HashMap::new();
    let blank = |address| EndpointStats { address, packets_sent: 0, bytes_sent: 0, packets_received: 0, bytes_received: 0 };
    for (flow, len) in packets {
        let Some(flow) = flow else { continue };
        let sender = by_address.entry(flow.source.address).or_insert_with(|| blank(flow.source.address));
        sender.packets_sent += 1;
        sender.bytes_sent += len;
        let receiver = by_address.entry(flow.destination.address).or_insert_with(|| blank(flow.destination.address));
        receiver.packets_received += 1;
        receiver.bytes_received += len;
    }
    let mut list: Vec<EndpointStats> = by_address.into_values().collect();
    list.sort_by(|x, y| (y.bytes_sent + y.bytes_received).cmp(&(x.bytes_sent + x.bytes_received)).then(x.address.cmp(&y.address)));
    list
}

/// One packet's payload within a followed stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamSegment {
    /// Index of the packet the bytes came from.
    pub packet: usize,
    /// True when the bytes travel from the key's `a` to its `b`.
    pub a_to_b: bool,
    /// Where the bytes sit in [`Stream::bytes`].
    pub start: usize,
    pub len: usize,
}

/// The payloads of one conversation, both directions, in capture order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub key: ConversationKey,
    pub bytes: Vec<u8>,
    pub segments: Vec<StreamSegment>,
    /// Retransmitted TCP segments left out.
    pub retransmissions: usize,
    /// Set when the stream reached [`STREAM_LIMIT`].
    pub truncated: bool,
}

impl Stream {
    /// The stream as text, each segment headed by its direction. Bytes that
    /// are not printable text are shown as `.`.
    pub fn marked_text(&self) -> String {
        let mut text = String::new();
        for segment in &self.segments {
            let (from, to) = if segment.a_to_b { (self.key.a, self.key.b) } else { (self.key.b, self.key.a) };
            let arrow = if segment.a_to_b { "→" } else { "←" };
            text.push_str(&format!("{arrow} {from} to {to}, packet {}, {} bytes\n", segment.packet + 1, segment.len));
            let bytes = &self.bytes[segment.start..segment.start + segment.len];
            let shown = &bytes[..bytes.len().min(SEGMENT_TEXT_LIMIT)];
            text.extend(shown.iter().map(|&byte| printable(byte)));
            if bytes.len() > shown.len() {
                text.push('…');
            }
            if !text.ends_with('\n') {
                text.push('\n');
            }
        }
        text
    }
}

fn printable(byte: u8) -> char {
    match byte {
        b'\n' | b'\t' => byte as char,
        b'\r' => '\r',
        0x20..=0x7E => byte as char,
        _ => '.',
    }
}

/// Collect the payloads of the conversation `key`, in capture order. Each
/// item is a packet's index, its flow and its payload. A TCP segment with the
/// same direction, sequence number and length as an earlier one is a
/// retransmission and is left out.
pub fn follow_stream<'a>(key: &ConversationKey, packets: impl IntoIterator<Item = (usize, &'a Flow, &'a [u8])>) -> Stream {
    let mut stream = Stream { key: *key, bytes: Vec::new(), segments: Vec::new(), retransmissions: 0, truncated: false };
    let mut seen_segments: HashSet<(bool, u32, usize)> = HashSet::new();
    for (index, flow, payload) in packets {
        if flow.key() != *key || payload.is_empty() {
            continue;
        }
        let a_to_b = flow.is_a_to_b(key);
        if let Some(sequence) = flow.tcp_sequence
            && !seen_segments.insert((a_to_b, sequence, payload.len()))
        {
            stream.retransmissions += 1;
            continue;
        }
        let room = STREAM_LIMIT - stream.bytes.len();
        let taken = &payload[..payload.len().min(room)];
        stream.segments.push(StreamSegment { packet: index, a_to_b, start: stream.bytes.len(), len: taken.len() });
        stream.bytes.extend_from_slice(taken);
        if taken.len() < payload.len() {
            stream.truncated = true;
            break;
        }
    }
    stream
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(address: &str, port: u16) -> Endpoint {
        Endpoint { address: address.parse().unwrap(), port: Some(port) }
    }

    fn tcp(from: Endpoint, to: Endpoint, sequence: u32) -> Flow {
        Flow { transport: Transport::Tcp, source: from, destination: to, tcp_sequence: Some(sequence) }
    }

    #[test]
    fn both_directions_of_a_conversation_are_counted_together() {
        let client = endpoint("10.0.0.2", 51000);
        let server = endpoint("10.0.0.1", 80);
        let other = endpoint("10.0.0.9", 53);
        let flows = [tcp(client, server, 1), tcp(server, client, 7), tcp(client, server, 2), Flow { transport: Transport::Udp, ..tcp(client, other, 0) }];
        let lengths = [60, 1500, 54, 80];
        let found = conversations(flows.iter().map(Some).zip(lengths));
        assert_eq!(found.len(), 2);
        let web = &found[0];
        assert_eq!(web.packets, 3);
        assert_eq!(web.bytes, 60 + 1500 + 54);
        assert_eq!(web.key.a, server, "the lower endpoint comes first");
        assert_eq!(web.packets_a_to_b, 1);
        assert_eq!(web.bytes_b_to_a(), 114);
        assert_eq!(found[1].first_packet, 3);
        assert_eq!(found[1].key.transport, Transport::Udp);
    }

    #[test]
    fn endpoints_count_what_each_address_sent_and_received() {
        let a = endpoint("192.168.1.1", 1);
        let b = endpoint("192.168.1.2", 2);
        let flows = [tcp(a, b, 0), tcp(b, a, 0), tcp(a, b, 1)];
        let list = endpoints(flows.iter().map(Some).zip([100, 10, 100]));
        assert_eq!(list.len(), 2);
        let first = &list[0];
        assert_eq!(first.address, a.address);
        assert_eq!((first.packets_sent, first.bytes_sent, first.packets_received, first.bytes_received), (2, 200, 1, 10));
    }

    #[test]
    fn a_followed_stream_keeps_capture_order_marks_direction_and_drops_retransmissions() {
        let client = endpoint("10.0.0.2", 40000);
        let server = endpoint("10.0.0.1", 80);
        let stranger = endpoint("10.0.0.3", 80);
        let request = tcp(client, server, 100);
        let response = tcp(server, client, 500);
        let retransmitted = tcp(client, server, 100);
        let unrelated = tcp(stranger, client, 9);
        let more = tcp(server, client, 508);
        let packets: Vec<(usize, &Flow, &[u8])> = vec![
            (0, &request, b"GET / HTTP/1.1\r\n\r\n"),
            (1, &response, b"HTTP/1.1"),
            (2, &retransmitted, b"GET / HTTP/1.1\r\n\r\n"),
            (3, &unrelated, b"noise"),
            (4, &more, b" 200 OK\r\n"),
        ];
        let stream = follow_stream(&request.key(), packets);
        assert_eq!(stream.bytes, b"GET / HTTP/1.1\r\n\r\nHTTP/1.1 200 OK\r\n");
        let order: Vec<(usize, bool)> = stream.segments.iter().map(|s| (s.packet, s.a_to_b)).collect();
        let client_is_a = request.is_a_to_b(&request.key());
        assert_eq!(order, vec![(0, client_is_a), (1, !client_is_a), (4, !client_is_a)]);
        assert_eq!(stream.retransmissions, 1);
        let text = stream.marked_text();
        assert!(text.contains("10.0.0.2:40000 to 10.0.0.1:80, packet 1"), "{text}");
        assert!(text.contains("10.0.0.1:80 to 10.0.0.2:40000, packet 2"), "{text}");
    }

    #[test]
    fn a_conversation_becomes_a_filter_naming_both_ends() {
        let key = tcp(endpoint("10.0.0.2", 40000), endpoint("10.0.0.1", 80), 0).key();
        assert_eq!(key.filter_text(), "tcp ip:10.0.0.1 ip:10.0.0.2 port:80 port:40000");
    }
}
