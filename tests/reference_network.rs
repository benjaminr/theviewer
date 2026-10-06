//! The reference notes cover what the packet dissector and the protocol
//! parsers show: every layer of common traffic, and the fields in it.

use etherparse::PacketBuilder;
use theviewer::packets::LinkKind;
use theviewer::packets::dissect::{Dissection, RawFrames, dissect, dissect_with};
use theviewer::packets::SetHints;
use theviewer::packets::filter::wireshark_values;
use theviewer::plugin::Field;
use theviewer::reference;

const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const SERVER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0xFE];
const CLIENT_IPV4: [u8; 4] = [10, 0, 0, 2];
const SERVER_IPV4: [u8; 4] = [10, 0, 0, 1];
const CLIENT_IPV6: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const SERVER_IPV6: [u8; 16] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const ETHERTYPE_ARP: u16 = 0x0806;

/// Layers that hold bytes no parser claimed; they have no format to explain.
const GENERIC_LAYERS: [&str; 6] = ["Data", "Padding", "Payload", "Trailing data", "ICMP data", "Fragment"];

/// Fields whose children are named by the traffic itself, such as HTTP
/// header names, rather than by the dissector.
const FIELDS_WITH_FREE_NAMED_CHILDREN: [&str; 1] = ["Headers"];

/// An etherparse builder that has reached its UDP header.
type UdpBuilder = etherparse::PacketBuilderStep<etherparse::UdpHeader>;

fn build(builder: UdpBuilder, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).expect("a packet");
    packet
}

fn dns_query() -> Vec<u8> {
    let mut message = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    message.extend_from_slice(b"\x07example\x03com\x00");
    message.extend_from_slice(&[0, 1, 0, 1]);
    message
}

fn dns_response() -> Vec<u8> {
    let mut message = dns_query();
    message[2] = 0x81;
    message[3] = 0x80;
    message[7] = 1;
    message.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
    message
}

fn ethernet_ipv4_udp_dns() -> Vec<u8> {
    build(PacketBuilder::ethernet2(CLIENT_MAC, SERVER_MAC).ipv4(CLIENT_IPV4, SERVER_IPV4, 64).udp(53, 40000), &dns_response())
}

fn vlan_tagged_dns() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(CLIENT_MAC, SERVER_MAC)
        .single_vlan(etherparse::VlanId::try_new(42).expect("a VLAN ID"))
        .ipv4(CLIENT_IPV4, SERVER_IPV4, 64)
        .udp(40000, 53);
    build(builder, &dns_query())
}

fn ethernet_ipv6_tcp_http() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(CLIENT_MAC, SERVER_MAC).ipv6(CLIENT_IPV6, SERVER_IPV6, 64).tcp(49152, 80, 1000, 64240).psh().ack(2000);
    let mut packet = Vec::new();
    builder.write(&mut packet, b"GET /status HTTP/1.1\r\nHost: plc.local\r\nContent-Length: 2\r\n\r\nok").expect("a packet");
    packet
}

fn ipv4_tcp(destination_port: u16, payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ipv4(CLIENT_IPV4, SERVER_IPV4, 64).tcp(40000, destination_port, 1, 1024).syn();
    let mut packet = Vec::new();
    builder.write(&mut packet, payload).expect("a packet");
    packet
}

fn arp_request() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0xFF; 6]);
    packet.extend_from_slice(&CLIENT_MAC);
    packet.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    packet.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    packet.extend_from_slice(&CLIENT_MAC);
    packet.extend_from_slice(&CLIENT_IPV4);
    packet.extend_from_slice(&[0; 6]);
    packet.extend_from_slice(&SERVER_IPV4);
    packet.resize(60, 0);
    packet
}

fn icmp_echo_request() -> Vec<u8> {
    let builder = PacketBuilder::ipv4(CLIENT_IPV4, SERVER_IPV4, 64).icmpv4_echo_request(0x1234, 7);
    let mut packet = Vec::new();
    builder.write(&mut packet, b"ping").expect("a packet");
    packet
}

fn icmpv6_echo_request() -> Vec<u8> {
    let builder = PacketBuilder::ipv6(CLIENT_IPV6, SERVER_IPV6, 64).icmpv6_echo_request(0x1234, 7);
    let mut packet = Vec::new();
    builder.write(&mut packet, b"ping").expect("a packet");
    packet
}

fn ntp_client_request() -> Vec<u8> {
    let mut ntp = vec![0u8; 48];
    ntp[0] = 0x23;
    build(PacketBuilder::ipv4(CLIENT_IPV4, SERVER_IPV4, 64).udp(123, 123), &ntp)
}

fn modbus_read_request() -> Vec<u8> {
    ipv4_tcp(502, &[0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x01, 0x04, 0x00, 0x00, 0x00, 0x02])
}

fn mqtt_publish() -> Vec<u8> {
    let mut mqtt = vec![0x32, 0, 0, 5];
    mqtt.extend_from_slice(b"a/b/c");
    mqtt.extend_from_slice(&[0, 9]);
    mqtt.extend_from_slice(b"on");
    mqtt[1] = (mqtt.len() - 2) as u8;
    ipv4_tcp(1883, &mqtt)
}

/// A BER element with a short-form length.
fn ber(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut element = vec![tag, content.len() as u8];
    element.extend_from_slice(content);
    element
}

fn snmp_get_request() -> Vec<u8> {
    let binding = ber(0x30, &[ber(0x06, &[0x2B, 6, 1, 2, 1, 1, 5, 0]), ber(0x05, &[])].concat());
    let pdu = ber(0xA0, &[ber(0x02, &[1]), ber(0x02, &[0]), ber(0x02, &[0]), ber(0x30, &binding)].concat());
    let message = ber(0x30, &[ber(0x02, &[1]), ber(0x04, b"public"), pdu].concat());
    build(PacketBuilder::ipv4(CLIENT_IPV4, SERVER_IPV4, 64).udp(40000, 161), &message)
}

fn dhcp_offer() -> Vec<u8> {
    let mut message = vec![0u8; 236];
    message[..4].copy_from_slice(&[2, 1, 6, 0]);
    message[4..8].copy_from_slice(&0x3D1Du32.to_be_bytes());
    message[16..20].copy_from_slice(&CLIENT_IPV4);
    message[28..34].copy_from_slice(&CLIENT_MAC);
    message.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    message.extend_from_slice(&[53, 1, 2, 54, 4, 10, 0, 0, 1, 51, 4, 0, 0, 0x0E, 0x10, 1, 4, 255, 255, 255, 0, 255, 0, 0, 0]);
    build(PacketBuilder::ipv4(SERVER_IPV4, [255, 255, 255, 255], 64).udp(67, 68), &message)
}

/// An SMB2 Negotiate request behind the four-byte framing of port 445.
fn smb2_negotiate() -> Vec<u8> {
    let mut smb2 = vec![0u8; 64];
    smb2[..4].copy_from_slice(b"\xFESMB");
    smb2[4] = 64;
    smb2.extend_from_slice(&[0x24, 0, 1, 0, 1, 0, 0, 0, 0x7F, 0, 0, 0]);
    smb2.extend_from_slice(&[0; 16]);
    smb2.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x02]);
    let mut payload = vec![0, 0, 0, smb2.len() as u8];
    payload.extend_from_slice(&smb2);
    ipv4_tcp(445, &payload)
}

/// A COTP connection request to rack 0, slot 2 of an S7 controller, and the
/// S7comm setup communication job that follows the connection.
fn s7_connection_and_setup() -> (Vec<u8>, Vec<u8>) {
    let request = [3, 0, 0, 22, 17, 0xE0, 0, 0, 0, 1, 0, 0xC0, 1, 0x0A, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2];
    let setup = [3, 0, 0, 25, 2, 0xF0, 0x80, 0x32, 1, 0, 0, 0, 1, 0, 8, 0, 0, 0xF0, 0, 0, 1, 0, 1, 0x03, 0xC0];
    (ipv4_tcp(102, &request), ipv4_tcp(102, &setup))
}

/// A TFTP read request, and the server's first data block from a port of
/// its own choosing.
fn tftp_read_and_data() -> (Vec<u8>, Vec<u8>) {
    let request = build(PacketBuilder::ipv4(CLIENT_IPV4, SERVER_IPV4, 64).udp(50000, 69), b"\x00\x01config.txt\x00netascii\x00");
    let data = build(PacketBuilder::ipv4(SERVER_IPV4, CLIENT_IPV4, 64).udp(61000, 50000), b"\x00\x03\x00\x01hostname plc\r\n");
    (request, data)
}

fn dns_over_tcp() -> Vec<u8> {
    let query = dns_query();
    let mut payload = (query.len() as u16).to_be_bytes().to_vec();
    payload.extend_from_slice(&query);
    ipv4_tcp(53, &payload)
}

/// A SIP INVITE whose SDP offers audio on port 7078, a G.711 packet sent
/// there, and a receiver report sent to the RTCP port above it.
fn sip_rtp_and_rtcp() -> [Vec<u8>; 3] {
    let invite = b"INVITE sip:plc@10.0.0.1 SIP/2.0\r\nContent-Type: application/sdp\r\n\r\nv=0\r\nc=IN IP4 10.0.0.2\r\nm=audio 7078 RTP/AVP 0\r\n";
    let mut media = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 160, 0x12, 0x34, 0x56, 0x78];
    media.extend_from_slice(&[0xD5; 160]);
    let report = [0x80, 201, 0, 1, 0x9A, 0xBC, 0xDE, 0xF0];
    [
        build(PacketBuilder::ipv4(CLIENT_IPV4, SERVER_IPV4, 64).udp(5060, 5060), invite),
        build(PacketBuilder::ipv4(SERVER_IPV4, CLIENT_IPV4, 64).udp(9000, 7078), &media),
        build(PacketBuilder::ipv4(SERVER_IPV4, CLIENT_IPV4, 64).udp(9001, 7079), &report),
    ]
}

/// The media and the report of [`sip_rtp_and_rtcp`], dissected with what the
/// INVITE announced.
fn rtp_and_rtcp_in_their_set() -> (Dissection, Dissection) {
    let packets = sip_rtp_and_rtcp();
    let hints = SetHints::learn(packets.iter().map(|packet| (packet.as_slice(), LinkKind::RawIp)));
    let raw = RawFrames { hints, ..RawFrames::default() };
    (dissect_with(&packets[1], LinkKind::RawIp, &raw), dissect_with(&packets[2], LinkKind::RawIp, &raw))
}

/// The TFTP data block dissected with what its read request taught.
fn tftp_data_in_its_set() -> Dissection {
    let (request, data) = tftp_read_and_data();
    let hints = SetHints::learn([(request.as_slice(), LinkKind::RawIp), (data.as_slice(), LinkKind::RawIp)]);
    dissect_with(&data, LinkKind::RawIp, &RawFrames { hints, ..RawFrames::default() })
}

/// Common traffic, dissected.
fn sample_dissections() -> Vec<(&'static str, Dissection)> {
    vec![
        ("Ethernet/IPv4/UDP/DNS", dissect(&ethernet_ipv4_udp_dns(), LinkKind::Ethernet)),
        ("Ethernet/VLAN/IPv4/UDP/DNS", dissect(&vlan_tagged_dns(), LinkKind::Ethernet)),
        ("Ethernet/IPv6/TCP/HTTP", dissect(&ethernet_ipv6_tcp_http(), LinkKind::Ethernet)),
        ("Ethernet/ARP", dissect(&arp_request(), LinkKind::Ethernet)),
        ("IPv4/ICMP", dissect(&icmp_echo_request(), LinkKind::RawIp)),
        ("IPv6/ICMPv6", dissect(&icmpv6_echo_request(), LinkKind::RawIp)),
        ("IPv4/UDP/NTP", dissect(&ntp_client_request(), LinkKind::RawIp)),
        ("IPv4/TCP/Modbus", dissect(&modbus_read_request(), LinkKind::RawIp)),
        ("IPv4/TCP/MQTT", dissect(&mqtt_publish(), LinkKind::RawIp)),
        ("IPv4/TCP/DNS", dissect(&dns_over_tcp(), LinkKind::RawIp)),
        ("IPv4/UDP/SNMP", dissect(&snmp_get_request(), LinkKind::RawIp)),
        ("IPv4/UDP/DHCP", dissect(&dhcp_offer(), LinkKind::RawIp)),
        ("IPv4/TCP/NBSS/SMB2", dissect(&smb2_negotiate(), LinkKind::RawIp)),
        ("IPv4/TCP/TPKT/COTP", dissect(&s7_connection_and_setup().0, LinkKind::RawIp)),
        ("IPv4/TCP/TPKT/COTP/S7comm", dissect(&s7_connection_and_setup().1, LinkKind::RawIp)),
        ("IPv4/UDP/TFTP", dissect(&tftp_read_and_data().0, LinkKind::RawIp)),
        ("IPv4/UDP/TFTP data", tftp_data_in_its_set()),
        ("IPv4/UDP/RTP", rtp_and_rtcp_in_their_set().0),
        ("IPv4/UDP/RTCP", rtp_and_rtcp_in_their_set().1),
    ]
}

/// Names of fields (and their dissector-named children) that have no note.
fn fields_without_notes(entry: &reference::FormatReference, fields: &[Field], missing: &mut Vec<String>) {
    for field in fields {
        if entry.field(&field.name).is_none() {
            missing.push(field.name.clone());
        }
        if !FIELDS_WITH_FREE_NAMED_CHILDREN.contains(&field.name.as_str()) {
            fields_without_notes(entry, &field.children, missing);
        }
    }
}

#[test]
fn every_layer_of_common_traffic_has_reference_notes_explaining_each_field() {
    let mut expected_layers = std::collections::BTreeSet::new();
    for (traffic, dissection) in sample_dissections() {
        assert!(dissection.notes.is_empty(), "{traffic}: the sample should dissect cleanly: {:?}", dissection.notes);
        for layer in &dissection.layers {
            if GENERIC_LAYERS.contains(&layer.name.as_str()) {
                continue;
            }
            expected_layers.insert(layer.name.clone());
            let entry = reference::lookup(&layer.name).unwrap_or_else(|| panic!("{traffic}: no reference notes for layer '{}'", layer.name));
            let mut missing = Vec::new();
            fields_without_notes(entry, &layer.fields, &mut missing);
            assert!(missing.is_empty(), "{traffic}: layer '{}' ({}) has fields without notes: {missing:?}", layer.name, entry.id);
        }
    }
    for layer in [
        "Ethernet II",
        "802.1Q VLAN",
        "Address Resolution Protocol",
        "Internet Protocol version 4",
        "Internet Protocol version 6",
        "Transmission Control Protocol",
        "User Datagram Protocol",
        "Internet Control Message Protocol",
        "Internet Control Message Protocol v6",
        "DNS",
        "HTTP",
        "NTP",
        "Modbus/TCP",
        "MQTT",
        "SNMP",
        "DHCP",
        "NetBIOS Session Service",
        "SMB2",
        "TPKT",
        "COTP",
        "S7comm",
        "TFTP",
        "RTP",
        "RTCP",
    ] {
        assert!(expected_layers.contains(layer), "the sample traffic should include a '{layer}' layer, found {expected_layers:?}");
    }
}

#[test]
fn wireshark_field_names_reach_the_fields_of_the_newer_dissectors_through_the_notes() {
    let snmp = dissect(&snmp_get_request(), LinkKind::RawIp);
    assert_eq!(wireshark_values(&snmp, "snmp.community"), ["public"]);
    assert_eq!(wireshark_values(&snmp, "snmp.version"), ["1 (SNMPv2c)"]);
    let dhcp = dissect(&dhcp_offer(), LinkKind::RawIp);
    assert_eq!(wireshark_values(&dhcp, "dhcp.ip.your"), ["10.0.0.2"]);
    assert_eq!(dhcp.summary.info, "DHCP Offer - Transaction ID 0x3d1d");
    let smb2 = dissect(&smb2_negotiate(), LinkKind::RawIp);
    assert_eq!(wireshark_values(&smb2, "smb2.cmd"), ["0 (Negotiate Protocol)"]);
    assert_eq!(smb2.summary.info, "SMB2 Negotiate Protocol Request");
    let s7 = dissect(&s7_connection_and_setup().1, LinkKind::RawIp);
    assert_eq!(wireshark_values(&s7, "s7comm.header.rosctr"), ["1 (Job)"]);
    assert_eq!(wireshark_values(&s7, "tpkt.length"), ["25"]);
    assert_eq!(s7.summary.info, "ROSCTR:[Job       ] Function:[Setup communication]");
    assert_eq!(wireshark_values(&tftp_data_in_its_set(), "tftp.block"), ["1"]);
    let (rtp, rtcp) = rtp_and_rtcp_in_their_set();
    assert_eq!(wireshark_values(&rtp, "rtp.ssrc"), ["0x12345678"]);
    assert_eq!(rtp.summary.info, "PT=ITU-T G.711 PCMU, SSRC=0x12345678, Seq=1, Time=160");
    assert_eq!(wireshark_values(&rtcp, "rtcp.pt"), ["201 (Receiver Report)"]);
}

#[test]
fn layers_the_samples_do_not_reach_and_malformed_layers_still_find_their_notes() {
    for (layer, id) in [
        ("IPv6 hop-by-hop options", "ipv6-extension"),
        ("IPv6 routing header", "ipv6-extension"),
        ("IPv6 destination options", "ipv6-extension"),
        ("IPv6 extension (malformed)", "ipv6-extension"),
        ("IPv6 fragment header", "ipv6-fragment"),
        ("IPv6 fragment (malformed)", "ipv6-fragment"),
        ("Ethernet II (malformed)", "ethernet"),
        ("ARP (malformed)", "arp"),
        ("IPv4 (malformed)", "ipv4"),
        ("IPv6 (malformed)", "ipv6"),
        ("TCP (malformed)", "tcp"),
        ("UDP (malformed)", "udp"),
        ("ICMP (malformed)", "icmp"),
        ("ICMPv6 (malformed)", "icmpv6"),
    ] {
        assert_eq!(reference::lookup(layer).map(|entry| entry.id.as_str()), Some(id), "{layer}");
    }
}

#[test]
fn protocol_findings_and_capture_signatures_find_their_notes() {
    for (key, id) in [
        ("pcap", "pcap"),
        ("pcapng", "pcapng"),
        ("tls-record", "tls-record"),
        ("http", "http"),
        ("ssh-banner", "ssh-banner"),
        ("dns", "dns"),
        ("signature:capture/pcap-le", "pcap"),
        ("signature:capture/pcapng", "pcapng"),
        ("signature:application/vnd.tcpdump.pcap", "pcap"),
        ("signature:application/vnd.tcpdump.pcapng", "pcapng"),
        ("signature:protocol/tls-client-hello", "tls-record"),
        ("signature:protocol/http-response", "http"),
        ("signature:protocol/ssh-banner", "ssh-banner"),
    ] {
        assert_eq!(reference::lookup(key).map(|entry| entry.id.as_str()), Some(id), "{key}");
    }
    let pcap = reference::lookup("pcap").expect("pcap notes");
    for field in ["file header", "magic", "snaplen", "link type", "packets", "packet 12"] {
        assert!(pcap.field(field).is_some(), "pcap field '{field}' has no note");
    }
    let tls = reference::lookup("tls-record").expect("TLS notes");
    for field in ["ClientHello", "ServerHello", "Alert", "ApplicationData", "ChangeCipherSpec"] {
        assert!(tls.field(field).is_some(), "TLS record '{field}' has no note");
    }
}
