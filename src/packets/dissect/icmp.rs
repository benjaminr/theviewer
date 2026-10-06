//! ICMP (RFC 792) and ICMPv6 (RFC 4443, with neighbour discovery from
//! RFC 4861). The layer covers the whole message. Echo messages show their
//! identifier and sequence number; error messages quote the start of the
//! packet that caused them, shown as nested "(quoted)" layers; neighbour
//! discovery messages show their target addresses and options.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};

use super::{DATA_PREVIEW_BYTES, IP_PROTOCOL_TCP, IP_PROTOCOL_UDP, Walk, ip_protocol_name, ipv4_header_fields, ipv6_header_fields, mac};
use crate::packets::flows::{Endpoint, Flow, Transport};
use crate::packets::hex_preview;
use crate::plugin::Field;

const ICMP_HEADER_LEN: usize = 8;
const IPV6_ADDRESS_LEN: usize = 16;
/// Neighbour discovery options are counted in units of 8 bytes.
const ND_OPTION_UNIT: usize = 8;
/// Most neighbour discovery options read from one message.
const MAX_ND_OPTIONS: usize = 32;
/// Bytes of a quoted TCP header shown: the ports and the sequence number.
const QUOTED_TCP_LEN: usize = 8;
const UDP_HEADER_LEN: usize = 8;

/// What follows the first four bytes of an ICMP message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Body {
    /// An identifier and sequence number, then data echoed back.
    Echo,
    /// Four type-specific bytes, then the start of the offending packet.
    Error,
    /// An ICMPv6 neighbour discovery message: fixed fields that end at
    /// `options_at` bytes into the message, then options.
    NeighbourDiscovery { options_at: usize },
    /// Four bytes and data this dissector does not read.
    Other,
}

fn body_of(icmp_type: u8, version6: bool) -> Body {
    match (version6, icmp_type) {
        (false, 0 | 8) | (true, 128 | 129) => Body::Echo,
        (false, 3 | 4 | 5 | 11 | 12) | (true, 1..=4) => Body::Error,
        (true, 133) => Body::NeighbourDiscovery { options_at: 8 },
        (true, 134) => Body::NeighbourDiscovery { options_at: 16 },
        (true, 135 | 136) => Body::NeighbourDiscovery { options_at: 24 },
        (true, 137) => Body::NeighbourDiscovery { options_at: 40 },
        _ => Body::Other,
    }
}

pub(super) fn icmp_type_name(icmp_type: u8, version6: bool) -> &'static str {
    match (version6, icmp_type) {
        (false, 0) => "Echo (ping) reply",
        (false, 3) => "Destination unreachable",
        (false, 4) => "Source quench",
        (false, 5) => "Redirect",
        (false, 8) => "Echo (ping) request",
        (false, 11) => "Time exceeded",
        (false, 12) => "Parameter problem",
        (false, 13) => "Timestamp request",
        (false, 14) => "Timestamp reply",
        (true, 1) => "Destination unreachable",
        (true, 2) => "Packet too big",
        (true, 3) => "Time exceeded",
        (true, 4) => "Parameter problem",
        (true, 128) => "Echo (ping) request",
        (true, 129) => "Echo (ping) reply",
        (true, 130) => "Multicast listener query",
        (true, 131) => "Multicast listener report",
        (true, 132) => "Multicast listener done",
        (true, 133) => "Router solicitation",
        (true, 134) => "Router advertisement",
        (true, 135) => "Neighbour solicitation",
        (true, 136) => "Neighbour advertisement",
        (true, 137) => "Redirect",
        (true, 143) => "Multicast listener report v2",
        _ => "Other",
    }
}

/// What the code means, for the error types whose codes are named.
fn code_name(icmp_type: u8, code: u8, version6: bool) -> Option<&'static str> {
    Some(match (version6, icmp_type, code) {
        (false, 3, 0) => "Network unreachable",
        (false, 3, 1) => "Host unreachable",
        (false, 3, 2) => "Protocol unreachable",
        (false, 3, 3) => "Port unreachable",
        (false, 3, 4) => "Fragmentation needed",
        (false, 3, 9 | 10 | 13) => "Administratively prohibited",
        (false, 11, 0) => "Time to live exceeded in transit",
        (false, 11, 1) => "Fragment reassembly time exceeded",
        (true, 1, 0) => "No route to destination",
        (true, 1, 1) => "Administratively prohibited",
        (true, 1, 3) => "Address unreachable",
        (true, 1, 4) => "Port unreachable",
        (true, 3, 0) => "Hop limit exceeded in transit",
        (true, 3, 1) => "Fragment reassembly time exceeded",
        _ => return None,
    })
}

fn neighbour_option_name(option_type: u8) -> &'static str {
    match option_type {
        1 => "Source link-layer address",
        2 => "Target link-layer address",
        3 => "Prefix information",
        4 => "Redirected header",
        5 => "MTU",
        14 => "Nonce",
        25 => "Recursive DNS server",
        31 => "DNS search list",
        _ => "Unknown",
    }
}

fn ipv6_address(bytes: &[u8]) -> Ipv6Addr {
    let mut octets = [0u8; IPV6_ADDRESS_LEN];
    octets.copy_from_slice(&bytes[..IPV6_ADDRESS_LEN]);
    Ipv6Addr::from(octets)
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

impl Walk<'_> {
    pub(super) fn icmp(&mut self, source: IpAddr, destination: IpAddr, at: usize, end: usize, version6: bool) {
        let name = if version6 { "ICMPv6" } else { "ICMP" };
        let bytes = self.bytes;
        let Some(header) = bytes.get(at..at + ICMP_HEADER_LEN).filter(|_| at + ICMP_HEADER_LEN <= end) else {
            self.malformed(at, name, format!("The {name} header is cut short"));
            return;
        };
        let (icmp_type, code) = (header[0], header[1]);
        let type_name = icmp_type_name(icmp_type, version6);
        let code_text = match code_name(icmp_type, code, version6) {
            Some(meaning) => format!("{code} ({meaning})"),
            None => code.to_string(),
        };
        let mut fields = vec![
            Field::new("Type", at, 1, format!("{icmp_type} ({type_name})")),
            Field::new("Code", at + 1, 1, code_text),
            Field::new("Checksum", at + 2, 2, format!("{:#06x}", u16::from_be_bytes([header[2], header[3]]))),
        ];
        let body = body_of(icmp_type, version6);
        let mut info = match code_name(icmp_type, code, version6) {
            Some(meaning) => format!("{type_name} ({meaning})"),
            None => type_name.to_string(),
        };
        match body {
            Body::Echo => {
                let identifier = u16::from_be_bytes([header[4], header[5]]);
                let sequence = u16::from_be_bytes([header[6], header[7]]);
                fields.push(Field::new("Identifier", at + 4, 2, format!("{identifier:#06x}")));
                fields.push(Field::new("Sequence number", at + 6, 2, sequence.to_string()));
                info = format!("{type_name} id={identifier:#06x}, seq={sequence}");
            }
            Body::Error => fields.push(Field::new("Rest of header", at + 4, 4, error_rest_of_header(header, version6))),
            Body::NeighbourDiscovery { options_at } => {
                let (nd_fields, nd_info) = self.neighbour_discovery(icmp_type, at, end, options_at);
                fields.extend(nd_fields);
                if let Some(nd_info) = nd_info {
                    info = format!("{type_name} {nd_info}");
                }
            }
            Body::Other => fields.push(Field::new("Rest of header", at + 4, 4, hex_preview(&header[4..], 4))),
        }
        let protocol_name = if version6 { "Internet Control Message Protocol v6" } else { "Internet Control Message Protocol" };
        self.push_layer(protocol_name, at, end - at, fields);
        self.out.protocols.push(if version6 { "icmpv6" } else { "icmp" });
        self.out.flow = Some(Flow {
            transport: Transport::Icmp,
            source: Endpoint { address: source, port: None },
            destination: Endpoint { address: destination, port: None },
            tcp_sequence: None,
        });
        self.out.payload = Some((at + ICMP_HEADER_LEN, end - at - ICMP_HEADER_LEN));
        match body {
            Body::Error => {
                if let Some(quoted) = self.quoted_packet(at + ICMP_HEADER_LEN, end) {
                    info = format!("{info} for {quoted}");
                }
            }
            Body::NeighbourDiscovery { .. } => {}
            Body::Echo | Body::Other => self.data_layer(at + ICMP_HEADER_LEN, end, "ICMP data"),
        }
        self.set_top(name, info);
    }

    /// The fixed fields and options of a neighbour discovery message at
    /// `at`, and a few words for the packet list.
    fn neighbour_discovery(&mut self, icmp_type: u8, at: usize, end: usize, options_at: usize) -> (Vec<Field>, Option<String>) {
        let bytes = self.bytes;
        let mut fields = Vec::new();
        if at + options_at > end {
            self.out.notes.push(format!("The {} message needs {options_at} bytes but has {}", icmp_type_name(icmp_type, true), end - at));
            fields.push(Field::new("Rest of header", at + 4, 4, hex_preview(&bytes[at + 4..at + 8], 4)));
            return (fields, None);
        }
        let mut info = None;
        match icmp_type {
            134 => {
                let lifetime = u16::from_be_bytes([bytes[at + 6], bytes[at + 7]]);
                fields.push(Field::new("Rest of header", at + 4, 4, format!("hop limit {}, flags {:#04x}, router lifetime {lifetime} s", bytes[at + 4], bytes[at + 5])));
                fields.push(Field::new("Reachable time", at + 8, 4, format!("{} ms", u32_at(bytes, at + 8))));
                fields.push(Field::new("Retransmission timer", at + 12, 4, format!("{} ms", u32_at(bytes, at + 12))));
            }
            135..=137 => {
                let rest = if icmp_type == 136 {
                    let flags = bytes[at + 4];
                    let names: Vec<&str> = [(0x80, "router"), (0x40, "solicited"), (0x20, "override")].into_iter().filter(|(bit, _)| flags & bit != 0).map(|(_, name)| name).collect();
                    format!("flags {flags:#04x} ({})", if names.is_empty() { "none".to_string() } else { names.join(", ") })
                } else {
                    "reserved".to_string()
                };
                fields.push(Field::new("Rest of header", at + 4, 4, rest));
                let target = ipv6_address(&bytes[at + 8..]);
                fields.push(Field::new("Target address", at + 8, IPV6_ADDRESS_LEN, target.to_string()));
                info = Some(target.to_string());
                if icmp_type == 137 {
                    let redirected = ipv6_address(&bytes[at + 24..]);
                    fields.push(Field::new("Destination address", at + 24, IPV6_ADDRESS_LEN, redirected.to_string()));
                    info = Some(format!("to {target} for {redirected}"));
                }
            }
            _ => fields.push(Field::new("Rest of header", at + 4, 4, "reserved".to_string())),
        }
        fields.extend(self.neighbour_options(at + options_at, end));
        (fields, info)
    }

    /// Neighbour discovery options from `at` to `end`: a type, a length in
    /// units of 8 bytes and a value (RFC 4861 §4.6).
    fn neighbour_options(&mut self, mut at: usize, end: usize) -> Vec<Field> {
        let bytes = self.bytes;
        let mut fields = Vec::new();
        for _ in 0..MAX_ND_OPTIONS {
            if at + 2 > end {
                break;
            }
            let (option_type, units) = (bytes[at], bytes[at + 1] as usize);
            let len = units * ND_OPTION_UNIT;
            if len == 0 || at + len > end {
                self.out.notes.push(format!("A neighbour discovery option at +{at} has a length of {len} bytes, which does not fit the message"));
                fields.push(Field::new("Option (malformed)", at, end - at, hex_preview(&bytes[at..end], DATA_PREVIEW_BYTES)));
                return fields;
            }
            let value = &bytes[at + 2..at + len];
            let shown = match option_type {
                1 | 2 if value.len() >= 6 => mac([value[0], value[1], value[2], value[3], value[4], value[5]]),
                3 if value.len() >= 30 => {
                    let prefix = ipv6_address(&value[14..]);
                    format!("{prefix}/{}, valid {} s, preferred {} s", value[0], u32_at(value, 2), u32_at(value, 6))
                }
                5 if value.len() >= 6 => u32_at(value, 2).to_string(),
                _ => hex_preview(value, DATA_PREVIEW_BYTES),
            };
            fields.push(Field::new(format!("Option {option_type} ({})", neighbour_option_name(option_type)), at, len, shown));
            at += len;
        }
        fields
    }

    /// The start of the packet an ICMP error quotes, from `at` to `end`: its
    /// IP header and transport ports as "(quoted)" layers, the rest as data.
    /// Returns the quoted packet's addresses and ports, for the summary.
    fn quoted_packet(&mut self, at: usize, end: usize) -> Option<String> {
        let bytes = self.bytes;
        let quoted = &bytes[at.min(end)..end];
        let (protocol, transport_at, addresses) = match quoted.first().map(|byte| byte >> 4) {
            Some(4) => {
                let header = Ipv4HeaderSlice::from_slice(quoted).ok()?;
                let (fields, _) = ipv4_header_fields(bytes, at, &header);
                let header_len = header.slice().len();
                self.push_layer("IPv4 (quoted)", at, header_len, fields);
                (header.protocol().0, at + header_len, (IpAddr::V4(header.source_addr()), IpAddr::V4(header.destination_addr())))
            }
            Some(6) => {
                let header = Ipv6HeaderSlice::from_slice(quoted).ok()?;
                self.push_layer("IPv6 (quoted)", at, super::IPV6_HEADER_LEN, ipv6_header_fields(at, &header));
                (header.next_header().0, at + super::IPV6_HEADER_LEN, (IpAddr::V6(header.source_addr()), IpAddr::V6(header.destination_addr())))
            }
            _ => {
                self.data_layer(at, end, "ICMP data");
                return None;
            }
        };
        let (source, destination) = addresses;
        let mut summary = format!("{source} → {destination} {}", ip_protocol_name(protocol));
        let mut data_at = transport_at;
        if matches!(protocol, IP_PROTOCOL_TCP | IP_PROTOCOL_UDP) && transport_at + 4 <= end {
            let source_port = u16::from_be_bytes([bytes[transport_at], bytes[transport_at + 1]]);
            let destination_port = u16::from_be_bytes([bytes[transport_at + 2], bytes[transport_at + 3]]);
            let mut fields = vec![Field::new("Source port", transport_at, 2, source_port.to_string()), Field::new("Destination port", transport_at + 2, 2, destination_port.to_string())];
            let (name, wanted) = if protocol == IP_PROTOCOL_TCP { ("TCP (quoted)", QUOTED_TCP_LEN) } else { ("UDP (quoted)", UDP_HEADER_LEN) };
            let len = wanted.min(end - transport_at);
            if len == wanted {
                if protocol == IP_PROTOCOL_TCP {
                    fields.push(Field::new("Sequence number", transport_at + 4, 4, u32_at(bytes, transport_at + 4).to_string()));
                } else {
                    fields.push(Field::new("Length", transport_at + 4, 2, u16::from_be_bytes([bytes[transport_at + 4], bytes[transport_at + 5]]).to_string()));
                    fields.push(Field::new("Checksum", transport_at + 6, 2, format!("{:#06x}", u16::from_be_bytes([bytes[transport_at + 6], bytes[transport_at + 7]]))));
                }
            }
            self.push_layer(name, transport_at, len, fields);
            summary = format!("{summary} {source_port} → {destination_port}");
            data_at = transport_at + len;
        }
        self.data_layer(data_at.min(end), end, "ICMP data");
        Some(summary)
    }
}

/// The four bytes after an error message's checksum, which hold an MTU, a
/// gateway or a pointer for some types and are unused for the rest.
fn error_rest_of_header(header: &[u8], version6: bool) -> String {
    let (icmp_type, code) = (header[0], header[1]);
    match (version6, icmp_type, code) {
        (false, 3, 4) => format!("next-hop MTU {}", u16::from_be_bytes([header[6], header[7]])),
        (false, 5, _) => format!("gateway {}", Ipv4Addr::new(header[4], header[5], header[6], header[7])),
        (false, 12, _) => format!("pointer {}", header[4]),
        (true, 2, _) => format!("MTU {}", u32_at(header, 4)),
        (true, 4, _) => format!("pointer {}", u32_at(header, 4)),
        _ => "unused".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use super::super::{Dissection, Layer, dissect};
    use crate::packets::LinkKind;

    const HOST: [u8; 4] = [10, 0, 0, 2];
    const SERVER: [u8; 4] = [10, 0, 0, 1];
    const ROUTER: [u8; 4] = [10, 0, 0, 254];
    const LINK_LOCAL_A: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const LINK_LOCAL_B: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    fn layer<'a>(dissection: &'a Dissection, name: &str) -> &'a Layer {
        dissection.layers.iter().find(|layer| layer.name == name).unwrap_or_else(|| panic!("no layer {name} in {:?}", dissection.layers.iter().map(|l| &l.name).collect::<Vec<_>>()))
    }

    fn value<'a>(layer: &'a Layer, name: &str) -> &'a str {
        layer.fields.iter().find(|field| field.name == name).map(|field| field.value.as_str()).unwrap_or_else(|| panic!("no field {name} in {}", layer.name))
    }

    /// An IPv4 packet carrying the ICMP message `icmp`.
    fn ipv4_icmp(source: [u8; 4], destination: [u8; 4], icmp: &[u8]) -> Vec<u8> {
        let mut header = etherparse::Ipv4Header::new(icmp.len() as u16, 64, etherparse::IpNumber::ICMP, source, destination).expect("a header");
        header.header_checksum = header.calc_header_checksum();
        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(icmp);
        packet
    }

    /// An IPv6 packet carrying the ICMPv6 message `icmp`.
    fn ipv6_icmp(icmp: &[u8]) -> Vec<u8> {
        let header = etherparse::Ipv6Header {
            payload_length: icmp.len() as u16,
            next_header: etherparse::IpNumber::IPV6_ICMP,
            hop_limit: 255,
            source: LINK_LOCAL_A,
            destination: LINK_LOCAL_B,
            ..etherparse::Ipv6Header::default()
        };
        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(icmp);
        packet
    }

    #[test]
    fn an_echo_request_covers_the_whole_message_with_its_data_inside() {
        let builder = PacketBuilder::ipv4(HOST, SERVER, 64).icmpv4_echo_request(0x1234, 7);
        let mut packet = Vec::new();
        builder.write(&mut packet, b"abcdefgh").unwrap();
        let dissection = dissect(&packet, LinkKind::RawIp);
        let icmp = layer(&dissection, "Internet Control Message Protocol");
        assert_eq!((icmp.offset, icmp.len), (20, 16), "the layer covers the header and the echoed data");
        let data = layer(&dissection, "ICMP data");
        assert_eq!((data.offset, data.len), (28, 8));
        assert_eq!(dissection.summary.info, "Echo (ping) request id=0x1234, seq=7");
    }

    #[test]
    fn a_port_unreachable_shows_the_quoted_ip_header_and_ports_of_the_packet_that_caused_it() {
        let original = {
            let builder = PacketBuilder::ipv4(HOST, SERVER, 64).udp(40000, 53);
            let mut packet = Vec::new();
            builder.write(&mut packet, b"query").unwrap();
            packet
        };
        let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&original[..28]);
        let dissection = dissect(&ipv4_icmp(SERVER, HOST, &icmp), LinkKind::RawIp);
        let names: Vec<&str> = dissection.layers.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["Internet Protocol version 4", "Internet Control Message Protocol", "IPv4 (quoted)", "UDP (quoted)"]);
        let message = layer(&dissection, "Internet Control Message Protocol");
        assert_eq!((message.offset, message.len), (20, 36));
        assert_eq!(value(message, "Code"), "3 (Port unreachable)");
        let quoted_ip = layer(&dissection, "IPv4 (quoted)");
        assert_eq!((quoted_ip.offset, quoted_ip.len), (28, 20));
        assert_eq!(value(quoted_ip, "Destination address"), "10.0.0.1");
        let quoted_udp = layer(&dissection, "UDP (quoted)");
        assert_eq!((quoted_udp.offset, quoted_udp.len), (48, 8));
        assert_eq!(value(quoted_udp, "Destination port"), "53");
        assert_eq!(dissection.summary.info, "Destination unreachable (Port unreachable) for 10.0.0.2 → 10.0.0.1 UDP 40000 → 53");
        assert_eq!(dissection.flow.map(|flow| flow.source.address.to_string()), Some("10.0.0.1".to_string()), "the flow is the ICMP message's own");
        assert!(!dissection.has_protocol("udp"), "the quoted header is not this packet's transport");
        assert_eq!(crate::reference::lookup("IPv4 (quoted)").map(|notes| notes.id.as_str()), Some("ipv4"));
        assert_eq!(crate::reference::lookup("UDP (quoted)").map(|notes| notes.id.as_str()), Some("udp"));
    }

    #[test]
    fn a_time_exceeded_quoting_only_part_of_a_tcp_header_shows_what_is_there() {
        let original = {
            let builder = PacketBuilder::ipv4(HOST, SERVER, 1).tcp(50000, 443, 77, 1024);
            let mut packet = Vec::new();
            builder.write(&mut packet, &[]).unwrap();
            packet
        };
        let mut icmp = vec![11, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&original[..26]);
        let dissection = dissect(&ipv4_icmp(ROUTER, HOST, &icmp), LinkKind::RawIp);
        let quoted_tcp = layer(&dissection, "TCP (quoted)");
        assert_eq!((quoted_tcp.offset, quoted_tcp.len), (48, 6), "only six bytes of the TCP header were quoted");
        assert_eq!(value(quoted_tcp, "Source port"), "50000");
        assert!(dissection.summary.info.starts_with("Time exceeded (Time to live exceeded in transit) for 10.0.0.2 → 10.0.0.1 TCP"), "{}", dissection.summary.info);
    }

    #[test]
    fn a_neighbour_solicitation_shows_its_target_and_options() {
        let mut icmp = vec![135, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&LINK_LOCAL_B);
        icmp.extend_from_slice(&[1, 1, 0x02, 0, 0, 0, 0, 0x01]);
        let dissection = dissect(&ipv6_icmp(&icmp), LinkKind::RawIp);
        let message = layer(&dissection, "Internet Control Message Protocol v6");
        assert_eq!((message.offset, message.len), (40, 32));
        assert_eq!(value(message, "Target address"), "fe80::2");
        assert_eq!(value(message, "Option 1 (Source link-layer address)"), "02:00:00:00:00:01");
        assert_eq!(dissection.summary.info, "Neighbour solicitation fe80::2");
        assert_eq!(dissection.layers.len(), 2, "the options belong to the message, not to a data layer");
        assert!(dissection.notes.is_empty(), "{:?}", dissection.notes);
    }

    #[test]
    fn a_router_advertisement_reads_its_prefix_and_a_bad_option_length_is_noted() {
        let mut icmp = vec![134, 0, 0, 0, 64, 0, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&[3, 4, 64, 0xC0, 0, 0x27, 0x8D, 0, 0, 0x09, 0x3A, 0x80, 0, 0, 0, 0]);
        icmp.extend_from_slice(&[0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        icmp.extend_from_slice(&[5, 1, 0, 0, 0, 0, 0x05, 0xDC]);
        let dissection = dissect(&ipv6_icmp(&icmp), LinkKind::RawIp);
        let message = layer(&dissection, "Internet Control Message Protocol v6");
        assert_eq!(message.len, icmp.len());
        assert_eq!(value(message, "Option 3 (Prefix information)"), "2001:db8::/64, valid 2592000 s, preferred 604800 s");
        assert_eq!(value(message, "Option 5 (MTU)"), "1500");
        assert!(value(message, "Rest of header").contains("router lifetime 1800 s"));

        let mut broken = icmp.clone();
        broken[16 + 1] = 0;
        let dissection = dissect(&ipv6_icmp(&broken), LinkKind::RawIp);
        assert!(dissection.notes.iter().any(|note| note.contains("neighbour discovery option")), "{:?}", dissection.notes);
    }

    #[test]
    fn an_icmpv6_packet_too_big_gives_the_mtu_and_quotes_the_ipv6_header() {
        let original = {
            let builder = PacketBuilder::ipv6(LINK_LOCAL_A, LINK_LOCAL_B, 64).udp(5000, 6000);
            let mut packet = Vec::new();
            builder.write(&mut packet, &[0; 32]).unwrap();
            packet
        };
        let mut icmp = vec![2, 0, 0, 0, 0, 0, 0x05, 0x00];
        icmp.extend_from_slice(&original);
        let dissection = dissect(&ipv6_icmp(&icmp), LinkKind::RawIp);
        assert_eq!(value(layer(&dissection, "Internet Control Message Protocol v6"), "Rest of header"), "MTU 1280");
        let quoted = layer(&dissection, "IPv6 (quoted)");
        assert_eq!((quoted.offset, quoted.len), (48, 40));
        let data = layer(&dissection, "ICMP data");
        assert_eq!((data.offset, data.len), (96, 32), "the quoted UDP payload");
    }
}
