//! Comparing our dissection of a packet with tshark's.
//!
//! [`LAYER_MAP`] and [`FIELD_MAP`] say which tshark protocols and fields
//! (by filter name) cover the same bytes as our layers and fields. They are
//! written by hand for the protocols we dissect. A packet's comparison says
//! whether both name the same innermost protocol, whether each of our layers
//! starts and ends where tshark's does, and the same for each mapped field.

use std::collections::BTreeSet;

use crate::packets::tshark::{TsharkField, TsharkPacket, TsharkProtocol, is_data_protocol};
use crate::packets::tshark_layers::is_undecoded;
use crate::packets::{Dissection, Layer};

/// Our layer and the tshark protocols that cover the same bytes.
#[derive(Clone, Copy, Debug)]
pub struct LayerMapping {
    /// Our layer's name.
    pub ours: &'static str,
    /// tshark filter names: any one of them (DNS is `mdns` on port 5353), or
    /// all of them in a row when `spans_all` is set.
    pub tshark: &'static [&'static str],
    /// Our layer covers several tshark protocols one after another (our
    /// Modbus/TCP layer is tshark's `mbtcp` header and its `modbus` PDU).
    pub spans_all: bool,
}

const fn layer(ours: &'static str, tshark: &'static [&'static str]) -> LayerMapping {
    LayerMapping { ours, tshark, spans_all: false }
}

pub const LAYER_MAP: [LayerMapping; 35] = [
    // tshark names the cooked header of a netlink device `netlink`.
    layer("Linux cooked capture", &["sll", "netlink"]),
    layer("Linux cooked capture v2", &["sll", "netlink"]),
    layer("BSD loopback", &["null"]),
    layer("Point-to-Point Protocol", &["ppp"]),
    layer("LCP", &["lcp"]),
    layer("IPCP", &["ipcp"]),
    layer("IPV6CP", &["ipv6cp"]),
    layer("Cisco HDLC", &["chdlc"]),
    layer("Radiotap", &["radiotap"]),
    layer("IEEE 802.11", &["wlan"]),
    // tshark's management body is `wlan.mgt`, but its protocol stack ends
    // at `wlan`, so that counts as the same innermost protocol.
    layer("IEEE 802.11 (management)", &["wlan.mgt", "wlan"]),
    layer("LLC", &["llc"]),
    layer("Ethernet II", &["eth"]),
    layer("802.1Q VLAN", &["vlan"]),
    layer("Address Resolution Protocol", &["arp"]),
    layer("Internet Protocol version 4", &["ip"]),
    layer("Internet Protocol version 6", &["ipv6"]),
    layer("Transmission Control Protocol", &["tcp"]),
    layer("User Datagram Protocol", &["udp"]),
    layer("Internet Control Message Protocol", &["icmp"]),
    layer("Internet Control Message Protocol v6", &["icmpv6"]),
    layer("DNS", &["dns", "mdns", "llmnr"]),
    layer("HTTP", &["http"]),
    layer("NTP", &["ntp"]),
    LayerMapping { ours: "Modbus/TCP", tshark: &["mbtcp", "modbus"], spans_all: true },
    layer("MQTT", &["mqtt"]),
    layer("SNMP", &["snmp"]),
    layer("DHCP", &["dhcp"]),
    layer("NetBIOS Session Service", &["nbss"]),
    layer("SMB", &["smb"]),
    layer("SMB2", &["smb2"]),
    layer("TPKT", &["tpkt"]),
    layer("COTP", &["cotp"]),
    layer("S7comm", &["s7comm"]),
    layer("TFTP", &["tftp"]),
];

/// `(our layer, our field, tshark filter name)` for fields both sides name.
pub const FIELD_MAP: [(&str, &str, &str); 118] = [
    ("Linux cooked capture", "Packet type", "sll.pkttype"),
    ("Linux cooked capture", "ARPHRD type", "sll.hatype"),
    ("Linux cooked capture", "Link-layer address length", "sll.halen"),
    ("Linux cooked capture", "Protocol", "sll.etype"),
    ("Linux cooked capture v2", "Protocol", "sll.etype"),
    ("Linux cooked capture v2", "Reserved", "sll.reserved"),
    ("Linux cooked capture v2", "Interface index", "sll.ifindex"),
    ("Linux cooked capture v2", "ARPHRD type", "sll.hatype"),
    ("Linux cooked capture v2", "Packet type", "sll.pkttype"),
    ("Linux cooked capture v2", "Link-layer address length", "sll.halen"),
    ("BSD loopback", "Family", "null.family"),
    ("Point-to-Point Protocol", "Address", "ppp.address"),
    ("Point-to-Point Protocol", "Control", "ppp.control"),
    ("Point-to-Point Protocol", "Protocol", "ppp.protocol"),
    ("LCP", "Code", "ppp.code"),
    ("LCP", "Identifier", "ppp.identifier"),
    ("LCP", "Length", "ppp.length"),
    ("Radiotap", "Header revision", "radiotap.version"),
    ("Radiotap", "Header length", "radiotap.length"),
    ("Radiotap", "Present flags", "radiotap.present"),
    ("IEEE 802.11", "Frame Control", "wlan.fc"),
    ("IEEE 802.11", "Duration/ID", "wlan.duration"),
    ("IEEE 802.11", "Address 1", "wlan.ra"),
    ("IEEE 802.11", "Address 2", "wlan.ta"),
    ("IEEE 802.11", "FCS", "wlan.fcs"),
    ("LLC", "DSAP", "llc.dsap"),
    ("LLC", "SSAP", "llc.ssap"),
    ("LLC", "Control", "llc.control"),
    ("LLC", "OUI", "llc.oui"),
    ("Ethernet II", "Destination", "eth.dst"),
    ("Ethernet II", "Source", "eth.src"),
    ("Ethernet II", "Type", "eth.type"),
    ("802.1Q VLAN", "Priority", "vlan.priority"),
    ("802.1Q VLAN", "VLAN ID", "vlan.id"),
    ("802.1Q VLAN", "Type", "vlan.etype"),
    ("Address Resolution Protocol", "Hardware type", "arp.hw.type"),
    ("Address Resolution Protocol", "Protocol type", "arp.proto.type"),
    ("Address Resolution Protocol", "Hardware size", "arp.hw.size"),
    ("Address Resolution Protocol", "Protocol size", "arp.proto.size"),
    ("Address Resolution Protocol", "Opcode", "arp.opcode"),
    ("Address Resolution Protocol", "Sender hardware address", "arp.src.hw_mac"),
    ("Address Resolution Protocol", "Sender protocol address", "arp.src.proto_ipv4"),
    ("Address Resolution Protocol", "Target hardware address", "arp.dst.hw_mac"),
    ("Address Resolution Protocol", "Target protocol address", "arp.dst.proto_ipv4"),
    ("Internet Protocol version 4", "Version and header length", "ip.version"),
    ("Internet Protocol version 4", "Differentiated services", "ip.dsfield"),
    ("Internet Protocol version 4", "Total length", "ip.len"),
    ("Internet Protocol version 4", "Identification", "ip.id"),
    ("Internet Protocol version 4", "Flags and fragment offset", "ip.frag_offset"),
    ("Internet Protocol version 4", "Time to live", "ip.ttl"),
    ("Internet Protocol version 4", "Protocol", "ip.proto"),
    ("Internet Protocol version 4", "Header checksum", "ip.checksum"),
    ("Internet Protocol version 4", "Source address", "ip.src"),
    ("Internet Protocol version 4", "Destination address", "ip.dst"),
    ("Internet Protocol version 6", "Payload length", "ipv6.plen"),
    ("Internet Protocol version 6", "Next header", "ipv6.nxt"),
    ("Internet Protocol version 6", "Hop limit", "ipv6.hlim"),
    ("Internet Protocol version 6", "Source address", "ipv6.src"),
    ("Internet Protocol version 6", "Destination address", "ipv6.dst"),
    ("Transmission Control Protocol", "Source port", "tcp.srcport"),
    ("Transmission Control Protocol", "Destination port", "tcp.dstport"),
    ("Transmission Control Protocol", "Sequence number", "tcp.seq"),
    ("Transmission Control Protocol", "Acknowledgement number", "tcp.ack"),
    ("Transmission Control Protocol", "Header length", "tcp.hdr_len"),
    ("Transmission Control Protocol", "Flags", "tcp.flags"),
    ("Transmission Control Protocol", "Window", "tcp.window_size_value"),
    ("Transmission Control Protocol", "Checksum", "tcp.checksum"),
    ("Transmission Control Protocol", "Urgent pointer", "tcp.urgent_pointer"),
    ("Transmission Control Protocol", "Options", "tcp.options"),
    ("User Datagram Protocol", "Source port", "udp.srcport"),
    ("User Datagram Protocol", "Destination port", "udp.dstport"),
    ("User Datagram Protocol", "Length", "udp.length"),
    ("User Datagram Protocol", "Checksum", "udp.checksum"),
    ("Internet Control Message Protocol", "Type", "icmp.type"),
    ("Internet Control Message Protocol", "Code", "icmp.code"),
    ("Internet Control Message Protocol", "Checksum", "icmp.checksum"),
    ("Internet Control Message Protocol", "Identifier", "icmp.ident"),
    ("Internet Control Message Protocol", "Sequence number", "icmp.seq"),
    ("Internet Control Message Protocol v6", "Type", "icmpv6.type"),
    ("Internet Control Message Protocol v6", "Code", "icmpv6.code"),
    ("Internet Control Message Protocol v6", "Checksum", "icmpv6.checksum"),
    ("Internet Control Message Protocol v6", "Identifier", "icmpv6.echo.identifier"),
    ("Internet Control Message Protocol v6", "Sequence number", "icmpv6.echo.sequence_number"),
    ("Internet Control Message Protocol v6", "Target address", "icmpv6.nd.ns.target_address"),
    ("DNS", "Transaction ID", "dns.id"),
    ("DNS", "Flags", "dns.flags"),
    ("DNS", "Questions", "dns.count.queries"),
    ("DNS", "Answer records", "dns.count.answers"),
    ("DNS", "Authority records", "dns.count.auth_rr"),
    ("DNS", "Additional records", "dns.count.add_rr"),
    ("NTP", "Flags", "ntp.flags"),
    ("NTP", "Stratum", "ntp.stratum"),
    ("NTP", "Reference ID", "ntp.refid"),
    ("NTP", "Transmit timestamp", "ntp.xmt"),
    ("Modbus/TCP", "Transaction ID", "mbtcp.trans_id"),
    ("Modbus/TCP", "Unit ID", "mbtcp.unit_id"),
    ("Modbus/TCP", "Function code", "modbus.func_code"),
    ("MQTT", "Topic", "mqtt.topic"),
    ("SNMP", "version", "snmp.version"),
    ("SNMP", "community", "snmp.community"),
    ("SNMP", "PDU", "snmp.data"),
    ("DHCP", "Message type", "dhcp.type"),
    ("DHCP", "Transaction ID", "dhcp.id"),
    ("DHCP", "Magic cookie", "dhcp.cookie"),
    ("NetBIOS Session Service", "Message type", "nbss.type"),
    ("SMB", "Command", "smb.cmd"),
    ("SMB", "Multiplex ID", "smb.mid"),
    ("SMB2", "Command", "smb2.cmd"),
    ("SMB2", "Message ID", "smb2.msg_id"),
    ("SMB2", "Session ID", "smb2.sesid"),
    ("SMB2", "Tree ID", "smb2.tid"),
    ("TPKT", "Length", "tpkt.length"),
    ("COTP", "Length indicator", "cotp.li"),
    ("COTP", "PDU type", "cotp.type"),
    ("S7comm", "ROSCTR", "s7comm.header.rosctr"),
    ("S7comm", "PDU reference", "s7comm.header.pduref"),
    ("TFTP", "Opcode", "tftp.opcode"),
    ("TFTP", "Block", "tftp.block"),
];

/// The mapping for one of our layers, if we compare it.
pub fn mapping_for(layer_name: &str) -> Option<&'static LayerMapping> {
    LAYER_MAP.iter().find(|mapping| mapping.ours == layer_name)
}

/// Whether the innermost protocols agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TopAgreement {
    Agree,
    /// tshark decodes further than we do: our innermost layer is in its
    /// stack, and it names `theirs` inside it.
    WeStopEarlier { theirs: String },
    /// We name a protocol tshark does not see there.
    Differs { ours: String, theirs: String },
    /// Nothing of ours to compare (a frame of unknown format, say).
    NotCompared,
}

/// One of our layers set against tshark's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerCheck {
    pub ours: &'static str,
    /// The tshark protocol paired with it, or `None` when tshark has none.
    pub tshark: Option<String>,
    /// Our `(offset, len)` and tshark's.
    pub ours_span: (usize, usize),
    pub theirs_span: (usize, usize),
}

impl LayerCheck {
    pub fn offset_agrees(&self) -> bool {
        self.ours_span.0 == self.theirs_span.0
    }

    pub fn len_agrees(&self) -> bool {
        self.ours_span.1 == self.theirs_span.1
    }
}

/// One of our fields set against tshark's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldCheck {
    pub layer: &'static str,
    pub field: &'static str,
    pub filter: &'static str,
    /// Our `(offset, len)` and tshark's.
    pub ours: (usize, usize),
    pub theirs: (usize, usize),
}

impl FieldCheck {
    pub fn agrees(&self) -> bool {
        self.ours == self.theirs
    }
}

/// Everything compared in one packet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketComparison {
    pub top: Option<TopAgreement>,
    pub layers: Vec<LayerCheck>,
    pub fields: Vec<FieldCheck>,
    /// tshark protocols (by filter name) that one of our layers covers.
    pub decoded_by_us: BTreeSet<String>,
}

/// Compare our dissection of a packet with tshark's.
pub fn compare(ours: &Dissection, theirs: &TsharkPacket) -> PacketComparison {
    let mut comparison = PacketComparison::default();
    let mut cursor = 0;
    let mut innermost: Option<&'static LayerMapping> = None;
    for layer in ours.layers.iter().filter(|layer| !is_undecoded(layer)) {
        let Some(mapping) = mapping_for(&layer.name) else { continue };
        innermost = Some(mapping);
        let paired = pair_layer(mapping, &theirs.layers, cursor);
        let Some((first, last)) = paired else {
            comparison.layers.push(LayerCheck { ours: mapping.ours, tshark: None, ours_span: (layer.offset, layer.len), theirs_span: (0, 0) });
            continue;
        };
        cursor = last + 1;
        let span: Vec<&TsharkProtocol> = theirs.layers[first..=last].iter().collect();
        let start = span[0].position.unwrap_or_default();
        let end = span.iter().map(|protocol| protocol.position.unwrap_or_default() + protocol.size).max().unwrap_or(start);
        comparison.layers.push(LayerCheck {
            ours: mapping.ours,
            tshark: Some(span.iter().map(|protocol| protocol.name.as_str()).collect::<Vec<_>>().join("+")),
            ours_span: (layer.offset, layer.len),
            theirs_span: (start, end - start),
        });
        comparison.decoded_by_us.extend(span.iter().map(|protocol| protocol.name.clone()));
        comparison.fields.extend(compare_fields(mapping.ours, layer, &span));
    }
    comparison.top = Some(top_agreement(innermost, theirs));
    comparison
}

/// The tshark protocols, from index `from`, that match our layer: the
/// first with one of the mapping's names, and for a spanning mapping the
/// ones after it that also belong. Returns the first and last index.
fn pair_layer(mapping: &LayerMapping, protocols: &[TsharkProtocol], from: usize) -> Option<(usize, usize)> {
    let first = (from..protocols.len()).find(|&index| mapping.tshark.contains(&protocols[index].name.as_str()) && protocols[index].position.is_some())?;
    let mut last = first;
    if mapping.spans_all {
        while protocols.get(last + 1).is_some_and(|next| mapping.tshark.contains(&next.name.as_str())) {
            last += 1;
        }
    }
    Some((first, last))
}

fn top_agreement(innermost: Option<&'static LayerMapping>, theirs: &TsharkPacket) -> TopAgreement {
    let (Some(mapping), Some(their_top)) = (innermost, theirs.top_protocol()) else { return TopAgreement::NotCompared };
    if mapping.tshark.contains(&their_top) {
        return TopAgreement::Agree;
    }
    if theirs.protocols.iter().any(|name| mapping.tshark.contains(&name.as_str())) {
        return TopAgreement::WeStopEarlier { theirs: their_top.to_string() };
    }
    TopAgreement::Differs { ours: mapping.ours.to_string(), theirs: their_top.to_string() }
}

fn compare_fields(layer_name: &'static str, layer: &Layer, span: &[&TsharkProtocol]) -> Vec<FieldCheck> {
    let mut checks = Vec::new();
    for &(_, field_name, filter) in FIELD_MAP.iter().filter(|(mapped_layer, _, _)| *mapped_layer == layer_name) {
        let Some(ours) = layer.fields.iter().find(|field| field.name == field_name) else { continue };
        let Some(theirs) = span.iter().find_map(|protocol| find_field(&protocol.fields, filter)) else { continue };
        checks.push(FieldCheck { layer: layer_name, field: field_name, filter, ours: (ours.offset, ours.len), theirs: (theirs.position.unwrap_or_default(), theirs.size) });
    }
    checks
}

/// The first field named `filter` that has bytes, searching depth first.
fn find_field<'a>(fields: &'a [TsharkField], filter: &str) -> Option<&'a TsharkField> {
    fields.iter().find_map(|field| if field.name == filter && field.position.is_some() && field.size > 0 { Some(field) } else { find_field(&field.children, filter) })
}

/// How a tshark protocol was reached from the layer below it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// Over UDP or TCP between these ports.
    Port { tcp: bool, ports: [u16; 2] },
    EtherType(u16),
    IpProtocol(u8),
}

/// For each protocol tshark found right above UDP, TCP, an EtherType or an
/// IP header, how it got there: `(filter name, carrier)`.
pub fn carriers(packet: &TsharkPacket) -> Vec<(String, Carrier)> {
    let mut found = Vec::new();
    let mut pending: Option<Carrier> = None;
    for protocol in &packet.layers {
        if let Some(carrier) = pending.take()
            && !is_data_protocol(&protocol.name)
        {
            found.push((protocol.name.clone(), carrier));
        }
        let value = |filter: &str| find_field(&protocol.fields, filter).and_then(|field| u32::from_str_radix(&field.value, 16).ok());
        pending = match protocol.name.as_str() {
            "udp" | "tcp" => {
                let prefix = protocol.name.as_str();
                match (value(&format!("{prefix}.srcport")), value(&format!("{prefix}.dstport"))) {
                    (Some(source), Some(destination)) => Some(Carrier::Port { tcp: prefix == "tcp", ports: [source as u16, destination as u16] }),
                    _ => None,
                }
            }
            "eth" => value("eth.type").map(|ether_type| Carrier::EtherType(ether_type as u16)),
            "vlan" => value("vlan.etype").map(|ether_type| Carrier::EtherType(ether_type as u16)),
            "ip" => value("ip.proto").map(|number| Carrier::IpProtocol(number as u8)),
            "ipv6" => value("ipv6.nxt").map(|number| Carrier::IpProtocol(number as u8)),
            _ => None,
        };
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::{LinkKind, dissect};

    fn field(name: &str, position: usize, size: usize, value: &str) -> TsharkField {
        TsharkField { name: name.to_string(), position: Some(position), size, value: value.to_string(), ..TsharkField::default() }
    }

    fn protocol(name: &str, position: usize, size: usize, fields: Vec<TsharkField>) -> TsharkProtocol {
        TsharkProtocol { name: name.to_string(), title: String::new(), position: Some(position), size, fields }
    }

    /// Ethernet, IPv4, UDP from port 40000 to 53 and a DNS query.
    fn dns_frame() -> Vec<u8> {
        let mut query = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(b"\x01a\x00\x00\x01\x00\x01");
        let builder = etherparse::PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]).ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).udp(40000, 53);
        let mut frame = Vec::new();
        builder.write(&mut frame, &query).unwrap();
        frame
    }

    fn tshark_dns(dns_name: &str, ttl_position: usize) -> TsharkPacket {
        TsharkPacket {
            number: 1,
            captured_len: 61,
            protocols: ["eth", "ethertype", "ip", "udp", dns_name].map(String::from).to_vec(),
            layers: vec![
                protocol("eth", 0, 14, vec![field("eth.dst", 0, 6, ""), field("eth.type", 12, 2, "0800")]),
                protocol("ip", 14, 20, vec![field("ip.ttl", ttl_position, 1, "40"), field("ip.proto", 23, 1, "11")]),
                protocol("udp", 34, 8, vec![field("udp.srcport", 34, 2, "9c40"), field("udp.dstport", 36, 2, "0035")]),
                protocol(dns_name, 42, 19, vec![field("dns.id", 42, 2, "abcd")]),
            ],
            notes: Vec::new(),
        }
    }

    #[test]
    fn matching_dissections_agree_layer_by_layer_and_field_by_field() {
        let ours = dissect(&dns_frame(), LinkKind::Ethernet);
        let comparison = compare(&ours, &tshark_dns("dns", 22));
        assert_eq!(comparison.top, Some(TopAgreement::Agree));
        let layers: Vec<(&str, bool, bool)> = comparison.layers.iter().map(|check| (check.ours, check.offset_agrees(), check.len_agrees())).collect();
        assert_eq!(layers, vec![("Ethernet II", true, true), ("Internet Protocol version 4", true, true), ("User Datagram Protocol", true, true), ("DNS", true, true)]);
        assert!(comparison.fields.iter().all(FieldCheck::agrees), "{:?}", comparison.fields);
        assert!(comparison.fields.iter().any(|check| check.filter == "dns.id"));
        assert_eq!(comparison.decoded_by_us, ["dns", "eth", "ip", "udp"].map(String::from).into_iter().collect());
    }

    #[test]
    fn a_field_in_a_different_place_is_a_mismatch() {
        let ours = dissect(&dns_frame(), LinkKind::Ethernet);
        let comparison = compare(&ours, &tshark_dns("dns", 21));
        let ttl = comparison.fields.iter().find(|check| check.filter == "ip.ttl").expect("compared");
        assert!(!ttl.agrees());
        assert_eq!((ttl.ours, ttl.theirs), ((22, 1), (21, 1)));
    }

    #[test]
    fn tshark_going_further_or_elsewhere_is_told_apart() {
        let ours = dissect(&dns_frame(), LinkKind::Ethernet);
        let mut further = tshark_dns("dns", 22);
        further.protocols.push("dnsextra".to_string());
        assert_eq!(compare(&ours, &further).top, Some(TopAgreement::WeStopEarlier { theirs: "dnsextra".to_string() }));
        let elsewhere = tshark_dns("bootp", 22);
        assert_eq!(compare(&ours, &elsewhere).top, Some(TopAgreement::Differs { ours: "DNS".to_string(), theirs: "bootp".to_string() }));
    }

    #[test]
    fn the_protocol_above_a_port_ethertype_or_ip_header_is_noted_with_how_it_was_reached() {
        let found = carriers(&tshark_dns("dns", 22));
        assert_eq!(
            found,
            vec![
                ("ip".to_string(), Carrier::EtherType(0x0800)),
                ("udp".to_string(), Carrier::IpProtocol(17)),
                ("dns".to_string(), Carrier::Port { tcp: false, ports: [40000, 53] }),
            ]
        );
    }

    #[test]
    fn every_mapped_field_belongs_to_a_mapped_layer() {
        for (layer_name, field, _) in FIELD_MAP {
            assert!(mapping_for(layer_name).is_some(), "{layer_name} / {field}");
        }
    }
}
