//! The infrastructure reference notes (link layer, tunnels, routing,
//! addressing and network services) load, cite their sources and name
//! payloads the dissector leaves undecoded by layer, port, EtherType and IP
//! protocol number.

use etherparse::PacketBuilder;
use theviewer::packets::LinkKind;
use theviewer::packets::dissect::dissect;
use theviewer::reference::{self, Library, Transport, library};

const INFRASTRUCTURE_NOTES: &str = include_str!("../reference/network-infrastructure.toml");

const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const SERVER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0xFE];
const CLIENT_IPV4: [u8; 4] = [10, 0, 0, 2];
const SERVER_IPV4: [u8; 4] = [10, 0, 0, 1];

/// IP protocols the dissector shows as an undecoded data layer, with the
/// note each should open.
const UNDECODED_IP_PROTOCOLS: [(u8, &str); 13] = [
    (2, "igmp"),
    (4, "ipip"),
    (41, "6in4"),
    (47, "gre"),
    (50, "esp"),
    (51, "ah"),
    (88, "eigrp"),
    (89, "ospf"),
    (103, "pim"),
    (112, "vrrp"),
    (115, "l2tp"),
    (132, "sctp"),
    (137, "mpls"),
];

/// EtherTypes the dissector names but does not decode, with their notes.
const UNDECODED_ETHERTYPES: [(u16, &str); 6] = [(0x88CC, "lldp"), (0x88F7, "ptp"), (0x8863, "pppoe"), (0x8864, "pppoe"), (0x8809, "lacp"), (0x888E, "eapol")];

fn infrastructure_entries() -> Library {
    Library::parse(&[("network-infrastructure.toml", INFRASTRUCTURE_NOTES)]).expect("the infrastructure notes parse on their own")
}

fn ipv4_packet_with_protocol(protocol: u8) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(CLIENT_MAC, SERVER_MAC).ipv4(CLIENT_IPV4, SERVER_IPV4, 64);
    let payload = [0xA5u8; 24];
    let mut packet = Vec::new();
    builder.write(&mut packet, etherparse::IpNumber(protocol), &payload).expect("a packet");
    packet
}

fn ethernet_frame(ether_type: u16) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E]);
    frame.extend_from_slice(&CLIENT_MAC);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(&[0u8; 46]);
    frame
}

#[test]
fn the_embedded_library_loads_with_the_infrastructure_notes() {
    let library = library();
    for entry in infrastructure_entries().entries() {
        assert!(library.by_id(&entry.id).is_some(), "'{}' should be in the embedded library", entry.id);
    }
}

#[test]
fn every_infrastructure_note_explains_its_layout_and_cites_a_source() {
    let notes = infrastructure_entries();
    assert!(notes.entries().len() >= 40, "expected a broad set of notes, found {}", notes.entries().len());
    for entry in notes.entries() {
        assert!(!entry.organisation.trim().is_empty(), "{} has no organisation", entry.id);
        assert!(!entry.specs.is_empty(), "{} cites no specification", entry.id);
        for spec in &entry.specs {
            assert!(spec.url.starts_with("https://"), "{}: {}", entry.id, spec.url);
            if let Some(number) = spec.rfc {
                assert_eq!(spec.document, format!("RFC {number}"), "{}: the citation should name its RFC", entry.id);
                assert!(spec.url.ends_with(&format!("/rfc{number}")), "{}: {} should link RFC {number}", entry.id, spec.url);
            }
        }
        assert!(entry.group.is_some(), "{} should be listed under a group when browsing", entry.id);
    }
}

#[test]
fn each_note_is_found_by_its_own_id() {
    for entry in infrastructure_entries().entries() {
        let found = reference::lookup(&entry.id).unwrap_or_else(|| panic!("'{}' should be found by its id", entry.id));
        assert_eq!(found.id, entry.id);
    }
}

#[test]
fn undissected_payloads_are_named_by_their_port() {
    let library = library();
    let expectations = [
        (Transport::Udp, 67, "dhcp"),
        (Transport::Udp, 68, "dhcp"),
        (Transport::Udp, 547, "dhcpv6"),
        (Transport::Udp, 4789, "vxlan"),
        (Transport::Udp, 6081, "geneve"),
        (Transport::Udp, 2152, "gtp-u"),
        (Transport::Udp, 500, "ikev2"),
        (Transport::Udp, 1194, "openvpn"),
        (Transport::Udp, 161, "snmp"),
        (Transport::Udp, 514, "syslog"),
        (Transport::Udp, 69, "tftp"),
        (Transport::Udp, 3478, "stun"),
        (Transport::Udp, 137, "nbns"),
        (Transport::Udp, 1900, "ssdp"),
        (Transport::Tcp, 179, "bgp"),
        (Transport::Udp, 443, "quic"),
    ];
    for (transport, port, id) in expectations {
        let entries = library.by_port(transport, port);
        assert!(entries.iter().any(|entry| entry.id == id), "{}/{port} should name '{id}', found {:?}", transport.name(), entries.iter().map(|entry| &entry.id).collect::<Vec<_>>());
    }
}

#[test]
fn undissected_frames_are_named_by_their_ethertype() {
    let library = library();
    for (ether_type, id) in UNDECODED_ETHERTYPES.into_iter().chain([(0x8847, "mpls"), (0x0842, "wake-on-lan")]) {
        let entries = library.by_ethertype(ether_type);
        assert!(entries.iter().any(|entry| entry.id == id), "EtherType {ether_type:#06x} should name '{id}'");
    }
}

#[test]
fn undissected_ip_payloads_are_named_by_their_protocol_number() {
    let library = library();
    for (protocol, id) in UNDECODED_IP_PROTOCOLS {
        let entries = library.by_ip_protocol(protocol);
        assert!(entries.iter().any(|entry| entry.id == id), "IP protocol {protocol} should name '{id}'");
    }
}

#[test]
fn the_dissectors_undecoded_ip_layers_open_their_notes() {
    for (protocol, id) in UNDECODED_IP_PROTOCOLS {
        let dissection = dissect(&ipv4_packet_with_protocol(protocol), LinkKind::Ethernet);
        let layer = dissection.layers.last().expect("a layer for the payload");
        let entry = reference::lookup(&layer.name).unwrap_or_else(|| panic!("layer '{}' (IP protocol {protocol}) should have notes", layer.name));
        assert_eq!(entry.id, id, "layer '{}'", layer.name);
    }
}

#[test]
fn ethertypes_the_dissector_names_open_their_notes() {
    for (ether_type, id) in UNDECODED_ETHERTYPES {
        let dissection = dissect(&ethernet_frame(ether_type), LinkKind::Ethernet);
        let type_field = dissection.layers[0].fields.iter().find(|field| field.name == "Type").expect("an EtherType field");
        let name = type_field.value.split_once('(').and_then(|(_, rest)| rest.strip_suffix(')')).expect("the EtherType's name in brackets");
        if name == "unknown" {
            continue;
        }
        let entry = reference::lookup(name).unwrap_or_else(|| panic!("EtherType name '{name}' should have notes"));
        assert_eq!(entry.id, id, "EtherType name '{name}'");
    }
}

#[test]
fn layers_shown_only_as_data_still_explain_themselves() {
    for (layer, note) in [("Netlink", "netlink"), ("IPX", "ipx"), ("IP protocol 33", "dccp"), ("IP protocol 46", "rsvp"), ("IP protocol 136", "udp-lite")] {
        let entry = theviewer::reference::lookup(layer).unwrap_or_else(|| panic!("{layer} has no notes"));
        assert_eq!(entry.id, note, "{layer}");
        assert!(entry.field("Data").is_some(), "{layer}'s undecoded body is explained");
    }
    let sctp = theviewer::reference::lookup("SCTP").unwrap();
    assert!(sctp.field("Data").is_some_and(|data| data.meaning.contains("does not decode")));
    assert!(sctp.field("Bytes").is_some(), "the remains of a malformed layer are explained too");
    assert!(sctp.field("No such field").is_none());
}
