//! Link layers other than Ethernet, read from their public descriptions:
//! Linux cooked captures (tcpdump.org's LINKTYPE_LINUX_SLL and SLL2 pages),
//! BSD and OpenBSD loopback (LINKTYPE_NULL and LINKTYPE_LOOP), PPP (RFC 1661)
//! with or without HDLC-like framing (RFC 1662) and Cisco HDLC, IEEE 802.11
//! frames (IEEE 802.11-2020 §9.2), the radiotap header (radiotap.org) and
//! IEEE 802.2 LLC with SNAP (RFC 1042).

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{DATA_PREVIEW_BYTES, Walk, ether_type_name, mac};
use crate::packets::hex_preview;
use crate::plugin::Field;

const SLL_HEADER_LEN: usize = 16;
const SLL2_HEADER_LEN: usize = 20;
/// Bytes kept of the sender's link-layer address in a cooked header.
const SLL_ADDRESS_LEN: usize = 8;
/// Cooked-header protocol values below this are not EtherTypes.
const MIN_ETHER_TYPE: u16 = 0x0600;
/// Cooked-header protocol value saying an 802.2 LLC header follows.
const SLL_PROTOCOL_LLC: u16 = 0x0004;
/// Linux ARPHRD_ device types whose cooked protocol field means something
/// other than an EtherType.
const ARPHRD_IEEE80211: u16 = 801;
const ARPHRD_IEEE80211_RADIOTAP: u16 = 803;
const ARPHRD_NETLINK: u16 = 824;

const LOOPBACK_HEADER_LEN: usize = 4;
/// BSD AF_ values: IPv4 is 2 everywhere; IPv6 is 24, 28 or 30 depending on
/// the system that wrote the capture.
const AF_INET: u32 = 2;
const AF_INET6_VALUES: [u32; 3] = [24, 28, 30];

const PPP_ADDRESS_ALL_STATIONS: u8 = 0xFF;
const PPP_CONTROL_UNNUMBERED: u8 = 0x03;
const PPP_IPV4: u16 = 0x0021;
const PPP_IPV6: u16 = 0x0057;
const PPP_LCP: u16 = 0xC021;
const PPP_IPCP: u16 = 0x8021;
const PPP_IPV6CP: u16 = 0x8057;
/// The first byte of a Cisco HDLC frame: unicast or multicast address.
const CISCO_HDLC_ADDRESSES: [u8; 2] = [0x0F, 0x8F];
const CISCO_HDLC_HEADER_LEN: usize = 4;
/// An LCP or NCP packet: code, identifier and length.
const CONTROL_PACKET_HEADER_LEN: usize = 4;
/// Most options read from one LCP or NCP packet, or one 802.11 frame.
const MAX_OPTIONS: usize = 64;

const IEEE80211_MIN_LEN: usize = 10;
const IEEE80211_FCS_LEN: usize = 4;
const IEEE80211_TYPE_MANAGEMENT: u8 = 0;
const IEEE80211_TYPE_CONTROL: u8 = 1;
const IEEE80211_TYPE_DATA: u8 = 2;
const IEEE80211_FLAG_TO_DS: u8 = 0x01;
const IEEE80211_FLAG_FROM_DS: u8 = 0x02;
const IEEE80211_FLAG_PROTECTED: u8 = 0x40;
const IEEE80211_FLAG_ORDER: u8 = 0x80;
/// Data subtypes with this bit carry a QoS Control field.
const IEEE80211_SUBTYPE_QOS: u8 = 0x08;
/// Data subtypes with this bit carry no data (null function frames).
const IEEE80211_SUBTYPE_NO_DATA: u8 = 0x04;
/// In the QoS Control field: the body is an aggregate of several frames.
const IEEE80211_QOS_AMSDU: u8 = 0x80;
/// In the fourth byte of a protected frame's security header: an extended
/// IV follows, so the header is CCMP's or TKIP's 8 bytes, not WEP's 4.
const IEEE80211_EXTENDED_IV: u8 = 0x20;

const RADIOTAP_MIN_LEN: usize = 8;
/// In a radiotap present word: another present word follows.
const RADIOTAP_PRESENT_EXTENDED: u32 = 1 << 31;
/// Most present words followed.
const MAX_RADIOTAP_PRESENT_WORDS: usize = 8;
/// In the radiotap Flags field: the 802.11 frame ends with its FCS.
const RADIOTAP_FLAG_FCS: u8 = 0x10;
/// In the radiotap Flags field: padding follows the 802.11 header, up to a
/// multiple of four bytes.
const RADIOTAP_FLAG_DATA_PAD: u8 = 0x20;

const LLC_SNAP_SAP: u8 = 0xAA;
const LLC_UNNUMBERED_INFORMATION: u8 = 0x03;
const LLC_SNAP_LEN: usize = 8;
/// SNAP organisation codes whose protocol ID is an EtherType: zero, and
/// Apple's for AppleTalk ARP and others bridged the same way.
const SNAP_ETHER_TYPE_OUIS: [u32; 2] = [0x000000, 0x0000F8];

fn u16_be(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn u16_le(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// A link-layer address: colon-separated hex, as MAC addresses are written.
fn link_address(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn sll_packet_type_name(packet_type: u16) -> &'static str {
    match packet_type {
        0 => "unicast to us",
        1 => "broadcast",
        2 => "multicast",
        3 => "unicast to another host",
        4 => "sent by us",
        _ => "other",
    }
}

fn arphrd_name(device_type: u16) -> &'static str {
    match device_type {
        1 => "Ethernet",
        280 => "CAN",
        512 => "PPP",
        772 => "loopback",
        776 => "IPv6 in IPv4",
        778 => "IP over GRE",
        ARPHRD_IEEE80211 => "IEEE 802.11",
        ARPHRD_IEEE80211_RADIOTAP => "IEEE 802.11 with radiotap",
        ARPHRD_NETLINK => "netlink",
        65534 => "none",
        _ => "other",
    }
}

fn ppp_protocol_name(protocol: u16) -> &'static str {
    match protocol {
        PPP_IPV4 => "IPv4",
        PPP_IPV6 => "IPv6",
        0x002B => "IPX",
        0x0031 => "Bridging",
        0x003D => "Multilink",
        0x00FD => "Compressed datagram",
        PPP_LCP => "LCP",
        PPP_IPCP => "IPCP",
        PPP_IPV6CP => "IPV6CP",
        0x80FD => "CCP",
        0xC023 => "PAP",
        0xC025 => "Link quality report",
        0xC223 => "CHAP",
        0xC227 => "EAP",
        _ => "unknown",
    }
}

fn control_code_name(code: u8) -> &'static str {
    match code {
        1 => "Configuration Request",
        2 => "Configuration Ack",
        3 => "Configuration Nak",
        4 => "Configuration Reject",
        5 => "Termination Request",
        6 => "Termination Ack",
        7 => "Code Reject",
        8 => "Protocol Reject",
        9 => "Echo Request",
        10 => "Echo Reply",
        11 => "Discard Request",
        _ => "Other",
    }
}

/// The name of a configuration option of LCP, IPCP or IPV6CP.
fn control_option_name(protocol: u16, option: u8) -> &'static str {
    match (protocol, option) {
        (PPP_LCP, 1) => "Maximum receive unit",
        (PPP_LCP, 2) => "Async control character map",
        (PPP_LCP, 3) => "Authentication protocol",
        (PPP_LCP, 4) => "Quality protocol",
        (PPP_LCP, 5) => "Magic number",
        (PPP_LCP, 7) => "Protocol field compression",
        (PPP_LCP, 8) => "Address and control field compression",
        (PPP_IPCP, 2) => "IP compression protocol",
        (PPP_IPCP, 3) => "IP address",
        (PPP_IPCP, 129) => "Primary DNS server",
        (PPP_IPCP, 131) => "Secondary DNS server",
        (PPP_IPV6CP, 1) => "Interface identifier",
        _ => "Unknown",
    }
}

fn sap_name(sap: u8) -> &'static str {
    match sap & 0xFE {
        0x00 => "null",
        0x06 => "IP",
        0x42 => "Spanning Tree",
        LLC_SNAP_SAP => "SNAP",
        0xE0 => "NetWare",
        0xF0 => "NetBIOS",
        0xFE => "ISO network layer",
        _ => "other",
    }
}

fn ieee80211_subtype_name(frame_type: u8, subtype: u8) -> &'static str {
    match (frame_type, subtype) {
        (IEEE80211_TYPE_MANAGEMENT, 0) => "Association request",
        (IEEE80211_TYPE_MANAGEMENT, 1) => "Association response",
        (IEEE80211_TYPE_MANAGEMENT, 2) => "Reassociation request",
        (IEEE80211_TYPE_MANAGEMENT, 3) => "Reassociation response",
        (IEEE80211_TYPE_MANAGEMENT, 4) => "Probe request",
        (IEEE80211_TYPE_MANAGEMENT, 5) => "Probe response",
        (IEEE80211_TYPE_MANAGEMENT, 8) => "Beacon frame",
        (IEEE80211_TYPE_MANAGEMENT, 9) => "ATIM",
        (IEEE80211_TYPE_MANAGEMENT, 10) => "Disassociation",
        (IEEE80211_TYPE_MANAGEMENT, 11) => "Authentication",
        (IEEE80211_TYPE_MANAGEMENT, 12) => "Deauthentication",
        (IEEE80211_TYPE_MANAGEMENT, 13) => "Action",
        (IEEE80211_TYPE_MANAGEMENT, 14) => "Action no ack",
        (IEEE80211_TYPE_CONTROL, 8) => "Block ack request",
        (IEEE80211_TYPE_CONTROL, 9) => "Block ack",
        (IEEE80211_TYPE_CONTROL, 10) => "Power-save poll",
        (IEEE80211_TYPE_CONTROL, 11) => "Request to send",
        (IEEE80211_TYPE_CONTROL, 12) => "Clear to send",
        (IEEE80211_TYPE_CONTROL, 13) => "Acknowledgement",
        (IEEE80211_TYPE_CONTROL, 14) => "CF-End",
        (IEEE80211_TYPE_CONTROL, 15) => "CF-End + CF-Ack",
        (IEEE80211_TYPE_DATA, 0) => "Data",
        (IEEE80211_TYPE_DATA, 4) => "Null function",
        (IEEE80211_TYPE_DATA, 8) => "QoS Data",
        (IEEE80211_TYPE_DATA, 12) => "QoS Null function",
        (IEEE80211_TYPE_DATA, _) => "Data (other subtype)",
        (IEEE80211_TYPE_MANAGEMENT, _) => "Management (other subtype)",
        (IEEE80211_TYPE_CONTROL, _) => "Control (other subtype)",
        _ => "Extension frame",
    }
}

fn element_name(id: u8) -> &'static str {
    match id {
        0 => "SSID",
        1 => "Supported rates",
        3 => "DS parameter set",
        5 => "Traffic indication map",
        7 => "Country",
        42 => "ERP information",
        45 => "HT capabilities",
        48 => "RSN",
        50 => "Extended supported rates",
        61 => "HT operation",
        127 => "Extended capabilities",
        191 => "VHT capabilities",
        221 => "Vendor specific",
        _ => "Other",
    }
}

/// The length of a management frame's fixed fields, before its information
/// elements; `None` when the body has no elements (an action frame, say).
fn management_fixed_len(subtype: u8) -> Option<usize> {
    match subtype {
        0 => Some(4),
        1 | 3 | 11 => Some(6),
        2 => Some(10),
        4 => Some(0),
        5 | 8 => Some(12),
        10 | 12 => Some(2),
        _ => None,
    }
}

/// The length of an 802.11 header, from its frame control bytes.
fn ieee80211_header_len(frame_type: u8, subtype: u8, flags: u8) -> usize {
    let order = flags & IEEE80211_FLAG_ORDER != 0;
    match frame_type {
        IEEE80211_TYPE_MANAGEMENT => 24 + if order { 4 } else { 0 },
        IEEE80211_TYPE_CONTROL => match subtype {
            12 | 13 => 10,
            _ => 16,
        },
        IEEE80211_TYPE_DATA => {
            let four_addresses = flags & (IEEE80211_FLAG_TO_DS | IEEE80211_FLAG_FROM_DS) == IEEE80211_FLAG_TO_DS | IEEE80211_FLAG_FROM_DS;
            let qos = subtype & IEEE80211_SUBTYPE_QOS != 0;
            24 + if four_addresses { 6 } else { 0 } + if qos { 2 } else { 0 } + if qos && order { 4 } else { 0 }
        }
        _ => IEEE80211_MIN_LEN,
    }
}

impl Walk<'_> {
    // -- Linux cooked capture ----------------------------------------------

    pub(super) fn linux_sll(&mut self) {
        let bytes = self.bytes;
        if bytes.len() < SLL_HEADER_LEN {
            self.malformed(0, "Linux cooked capture", format!("Only {} bytes, shorter than a Linux cooked capture header ({SLL_HEADER_LEN} bytes)", bytes.len()));
            return;
        }
        let packet_type = u16_be(bytes, 0);
        let device_type = u16_be(bytes, 2);
        let address_len = u16_be(bytes, 4) as usize;
        let protocol = u16_be(bytes, 14);
        let address = &bytes[6..6 + address_len.min(SLL_ADDRESS_LEN)];
        self.push_layer(
            "Linux cooked capture",
            0,
            SLL_HEADER_LEN,
            vec![
                Field::new("Packet type", 0, 2, format!("{packet_type} ({})", sll_packet_type_name(packet_type))),
                Field::new("ARPHRD type", 2, 2, format!("{device_type} ({})", arphrd_name(device_type))),
                Field::new("Link-layer address length", 4, 2, address_len.to_string()),
                Field::new("Link-layer address", 6, SLL_ADDRESS_LEN, link_address(address)),
                Field::new("Protocol", 14, 2, format!("{protocol:#06x} ({})", ether_type_name(protocol))),
            ],
        );
        self.cooked_payload(protocol, device_type, address, SLL_HEADER_LEN);
    }

    pub(super) fn linux_sll2(&mut self) {
        let bytes = self.bytes;
        if bytes.len() < SLL2_HEADER_LEN {
            self.malformed(0, "Linux cooked capture v2", format!("Only {} bytes, shorter than a Linux cooked capture v2 header ({SLL2_HEADER_LEN} bytes)", bytes.len()));
            return;
        }
        let protocol = u16_be(bytes, 0);
        let interface = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let device_type = u16_be(bytes, 8);
        let packet_type = bytes[10] as u16;
        let address_len = bytes[11] as usize;
        let address = &bytes[12..12 + address_len.min(SLL_ADDRESS_LEN)];
        self.push_layer(
            "Linux cooked capture v2",
            0,
            SLL2_HEADER_LEN,
            vec![
                Field::new("Protocol", 0, 2, format!("{protocol:#06x} ({})", ether_type_name(protocol))),
                Field::new("Reserved", 2, 2, format!("{:#06x}", u16_be(bytes, 2))),
                Field::new("Interface index", 4, 4, interface.to_string()),
                Field::new("ARPHRD type", 8, 2, format!("{device_type} ({})", arphrd_name(device_type))),
                Field::new("Packet type", 10, 1, format!("{packet_type} ({})", sll_packet_type_name(packet_type))),
                Field::new("Link-layer address length", 11, 1, address_len.to_string()),
                Field::new("Link-layer address", 12, SLL_ADDRESS_LEN, link_address(address)),
            ],
        );
        self.cooked_payload(protocol, device_type, address, SLL2_HEADER_LEN);
    }

    /// What follows a cooked header: chosen by the device type for 802.11
    /// and netlink devices, else by the protocol, usually an EtherType.
    fn cooked_payload(&mut self, protocol: u16, device_type: u16, address: &[u8], at: usize) {
        self.out.protocols.push("sll");
        self.out.summary.source = link_address(address);
        self.set_top("SLL", format!("Protocol {protocol:#06x} ({})", ether_type_name(protocol)));
        let end = self.bytes.len();
        match device_type {
            ARPHRD_IEEE80211 => self.ieee80211(at, end, 0),
            ARPHRD_IEEE80211_RADIOTAP => self.radiotap(at),
            ARPHRD_NETLINK => self.data_layer(at, end, "Netlink"),
            _ if protocol == SLL_PROTOCOL_LLC => self.llc(at, end),
            _ if protocol >= MIN_ETHER_TYPE => self.ether_type_payload(protocol, at, end, "SLL"),
            _ => self.data_layer(at, end, "Data"),
        }
    }

    // -- BSD loopback ------------------------------------------------------

    /// BSD loopback: a 4-byte protocol family, big-endian for OpenBSD's
    /// LOOP and in the capturing machine's order for NULL.
    pub(super) fn bsd_loopback(&mut self, always_big_endian: bool) {
        let bytes = self.bytes;
        let Some(&[a, b, c, d]) = bytes.get(..LOOPBACK_HEADER_LEN).and_then(|s| <&[u8; 4]>::try_from(s).ok()) else {
            self.malformed(0, "BSD loopback", format!("Only {} bytes, shorter than a loopback header ({LOOPBACK_HEADER_LEN} bytes)", bytes.len()));
            return;
        };
        // Families are small numbers, so a little-endian value starts with
        // a non-zero byte and a big-endian one with zeros.
        let big_endian = always_big_endian || (a == 0 && b == 0);
        let family = if big_endian { u32::from_be_bytes([a, b, c, d]) } else { u32::from_le_bytes([a, b, c, d]) };
        let family_name = match family {
            AF_INET => "IPv4",
            other if AF_INET6_VALUES.contains(&other) => "IPv6",
            7 => "OSI",
            23 => "IPX",
            _ => "unknown",
        };
        self.push_layer("BSD loopback", 0, LOOPBACK_HEADER_LEN, vec![Field::new("Family", 0, LOOPBACK_HEADER_LEN, format!("{family} ({family_name})"))]);
        self.out.protocols.push("null");
        self.set_top("Loopback", format!("Family {family} ({family_name})"));
        match family_name {
            "IPv4" | "IPv6" => {
                let ip_end = self.ip(LOOPBACK_HEADER_LEN).min(bytes.len());
                self.padding(ip_end, bytes.len());
            }
            _ => self.data_layer(LOOPBACK_HEADER_LEN, bytes.len(), "Data"),
        }
    }

    // -- PPP -----------------------------------------------------------------

    /// A PPP frame from LINKTYPE_PPP_HDLC: PPP in HDLC-like framing, or a
    /// Cisco HDLC frame, told apart by the first byte.
    pub(super) fn ppp_hdlc(&mut self) {
        match self.bytes.first() {
            Some(address) if CISCO_HDLC_ADDRESSES.contains(address) => self.cisco_hdlc(),
            _ => self.ppp(),
        }
    }

    /// A PPP frame (RFC 1661 §2), with the HDLC address and control bytes
    /// when they are there (RFC 1662 §3.1).
    pub(super) fn ppp(&mut self) {
        let bytes = self.bytes;
        let mut fields = Vec::new();
        let mut at = 0;
        if bytes.starts_with(&[PPP_ADDRESS_ALL_STATIONS, PPP_CONTROL_UNNUMBERED]) {
            fields.push(Field::new("Address", 0, 1, format!("{PPP_ADDRESS_ALL_STATIONS:#04x} (all stations)")));
            fields.push(Field::new("Control", 1, 1, format!("{PPP_CONTROL_UNNUMBERED:#04x} (unnumbered information)")));
            at = 2;
        }
        // A protocol's first byte is even and its last odd, so an odd first
        // byte is a protocol compressed to one byte.
        let (protocol, protocol_len) = match bytes.get(at) {
            Some(&first) if first & 1 == 1 => (first as u16, 1),
            Some(_) if at + 2 <= bytes.len() => (u16_be(bytes, at), 2),
            _ => {
                self.malformed(0, "PPP", "The PPP frame is cut short before its protocol field".to_string());
                return;
            }
        };
        fields.push(Field::new("Protocol", at, protocol_len, format!("{protocol:#06x} ({})", ppp_protocol_name(protocol))));
        at += protocol_len;
        self.push_layer("Point-to-Point Protocol", 0, at, fields);
        self.out.protocols.push("ppp");
        self.set_top("PPP", format!("Protocol {protocol:#06x} ({})", ppp_protocol_name(protocol)));
        let end = bytes.len();
        match protocol {
            PPP_IPV4 | PPP_IPV6 => {
                let ip_end = self.ip(at).min(end);
                self.padding(ip_end, end);
            }
            PPP_LCP | PPP_IPCP | PPP_IPV6CP => self.ppp_control(protocol, at, end),
            _ => self.data_layer(at, end, ppp_protocol_name(protocol)),
        }
    }

    /// An LCP, IPCP or IPV6CP packet (RFC 1661 §5): code, identifier,
    /// length, then configuration options or data.
    fn ppp_control(&mut self, protocol: u16, at: usize, end: usize) {
        let bytes = self.bytes;
        let name = ppp_protocol_name(protocol);
        if at + CONTROL_PACKET_HEADER_LEN > end {
            self.malformed(at, name, format!("The {name} packet is cut short"));
            return;
        }
        let (code, identifier) = (bytes[at], bytes[at + 1]);
        let length = u16_be(bytes, at + 2) as usize;
        let packet_end = if length >= CONTROL_PACKET_HEADER_LEN { (at + length).min(end) } else { end };
        let mut fields = vec![
            Field::new("Code", at, 1, format!("{code} ({})", control_code_name(code))),
            Field::new("Identifier", at + 1, 1, identifier.to_string()),
            Field::new("Length", at + 2, 2, length.to_string()),
        ];
        let body_at = at + CONTROL_PACKET_HEADER_LEN;
        if body_at < packet_end {
            let body = &bytes[body_at..packet_end];
            let field = match code {
                1..=4 => control_options_field(protocol, bytes, body_at, packet_end),
                9 | 10 if body.len() >= 4 => Field::new("Magic number", body_at, 4, format!("{:#010x}", u32::from_be_bytes([body[0], body[1], body[2], body[3]]))),
                _ => Field::new("Data", body_at, body.len(), hex_preview(body, DATA_PREVIEW_BYTES)),
            };
            fields.push(field);
        }
        self.push_layer(name, at, packet_end - at, fields);
        self.out.protocols.push(match protocol {
            PPP_LCP => "lcp",
            PPP_IPCP => "ipcp",
            _ => "ipv6cp",
        });
        self.set_top(name, format!("{} (id {identifier})", control_code_name(code)));
        self.padding(packet_end, end);
    }

    /// A Cisco HDLC frame: address, control and an EtherType.
    fn cisco_hdlc(&mut self) {
        let bytes = self.bytes;
        if bytes.len() < CISCO_HDLC_HEADER_LEN {
            self.malformed(0, "Cisco HDLC", "The Cisco HDLC header is cut short".to_string());
            return;
        }
        let protocol = u16_be(bytes, 2);
        self.push_layer(
            "Cisco HDLC",
            0,
            CISCO_HDLC_HEADER_LEN,
            vec![
                Field::new("Address", 0, 1, format!("{:#04x} ({})", bytes[0], if bytes[0] == CISCO_HDLC_ADDRESSES[0] { "unicast" } else { "multicast" })),
                Field::new("Control", 1, 1, format!("{:#04x}", bytes[1])),
                Field::new("Protocol", 2, 2, format!("{protocol:#06x} ({})", ether_type_name(protocol))),
            ],
        );
        self.out.protocols.push("chdlc");
        self.ether_type_payload(protocol, CISCO_HDLC_HEADER_LEN, bytes.len(), "Cisco HDLC");
    }

    // -- IEEE 802.11 -------------------------------------------------------

    /// An 802.11 frame from `at` to `end`. `radiotap_flags` are the Flags
    /// of the radiotap header before it (zero without one): they say
    /// whether the frame ends with its frame check sequence and whether
    /// its header is padded to a multiple of four bytes.
    pub(super) fn ieee80211(&mut self, at: usize, end: usize, radiotap_flags: u8) {
        let bytes = self.bytes;
        if at + IEEE80211_MIN_LEN > end {
            self.malformed(at, "IEEE 802.11", format!("Only {} bytes, shorter than the shortest 802.11 frame ({IEEE80211_MIN_LEN} bytes)", end.saturating_sub(at)));
            return;
        }
        let has_fcs = radiotap_flags & RADIOTAP_FLAG_FCS != 0 && at + IEEE80211_MIN_LEN + IEEE80211_FCS_LEN <= end;
        let frame_end = if has_fcs { end - IEEE80211_FCS_LEN } else { end };
        let (control, flags) = (bytes[at], bytes[at + 1]);
        let frame_type = (control >> 2) & 0x03;
        let subtype = control >> 4;
        let subtype_name = ieee80211_subtype_name(frame_type, subtype);
        let header_len = ieee80211_header_len(frame_type, subtype, flags);
        if at + header_len > frame_end {
            self.malformed(at, "IEEE 802.11", format!("The 802.11 {subtype_name} header needs {header_len} bytes but only {} are left", frame_end - at));
            return;
        }
        let to_ds = flags & IEEE80211_FLAG_TO_DS != 0;
        let from_ds = flags & IEEE80211_FLAG_FROM_DS != 0;
        let address = |offset: usize| mac([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3], bytes[offset + 4], bytes[offset + 5]]);
        let mut fields = vec![
            Field::new("Frame Control", at, 2, format!("{:#06x} ({subtype_name}, flags {flags:#04x})", u16_be(bytes, at))),
            Field::new("Duration/ID", at + 2, 2, u16_le(bytes, at + 2).to_string()),
        ];
        // Who sent the frame and who it is for, for the packet list.
        let (mut source, mut destination) = (String::new(), address(at + 4));
        if header_len >= 16 {
            source = address(at + 10);
        }
        let receiver_role = if frame_type == IEEE80211_TYPE_DATA && !to_ds { "receiver, destination" } else { "receiver" };
        fields.push(Field::new("Address 1", at + 4, 6, format!("{} ({receiver_role})", address(at + 4))));
        if header_len >= 16 {
            let transmitter_role = if frame_type == IEEE80211_TYPE_DATA && !from_ds || frame_type == IEEE80211_TYPE_MANAGEMENT { "transmitter, source" } else { "transmitter" };
            fields.push(Field::new("Address 2", at + 10, 6, format!("{} ({transmitter_role})", address(at + 10))));
        }
        if header_len >= 24 {
            let role = match (frame_type == IEEE80211_TYPE_DATA, to_ds, from_ds) {
                (true, true, false) | (true, true, true) => "destination",
                (true, false, true) => "source",
                _ => "BSS ID",
            };
            match role {
                "destination" => destination = address(at + 16),
                "source" => source = address(at + 16),
                _ => {}
            }
            fields.push(Field::new("Address 3", at + 16, 6, format!("{} ({role})", address(at + 16))));
            let sequence_control = u16_le(bytes, at + 22);
            fields.push(Field::new("Sequence Control", at + 22, 2, format!("sequence {}, fragment {}", sequence_control >> 4, sequence_control & 0x0F)));
        }
        let mut cursor = at + 24;
        let is_data = frame_type == IEEE80211_TYPE_DATA;
        if is_data && to_ds && from_ds {
            source = address(cursor);
            fields.push(Field::new("Address 4", cursor, 6, format!("{} (source)", address(cursor))));
            cursor += 6;
        }
        let mut aggregate = false;
        if is_data && subtype & IEEE80211_SUBTYPE_QOS != 0 {
            aggregate = bytes[cursor] & IEEE80211_QOS_AMSDU != 0;
            fields.push(Field::new("QoS Control", cursor, 2, format!("{:#06x} (priority {})", u16_le(bytes, cursor), bytes[cursor] & 0x07)));
            cursor += 2;
        }
        if cursor + 4 <= at + header_len {
            fields.push(Field::new("HT Control", cursor, 4, format!("{:#010x}", u32_le(bytes, cursor))));
        }
        let mut body_at = at + header_len;
        if radiotap_flags & RADIOTAP_FLAG_DATA_PAD != 0 {
            body_at = (at + header_len.next_multiple_of(4)).min(frame_end);
        }
        let protected = flags & IEEE80211_FLAG_PROTECTED != 0 && frame_type != IEEE80211_TYPE_CONTROL;
        if protected && body_at + 4 <= frame_end {
            let security_len = if bytes[body_at + 3] & IEEE80211_EXTENDED_IV != 0 { 8 } else { 4 };
            let security_len = security_len.min(frame_end - body_at);
            fields.push(Field::new("Security header", body_at, security_len, hex_preview(&bytes[body_at..body_at + security_len], security_len)));
            body_at += security_len;
        }
        if has_fcs {
            fields.push(Field::new("FCS", frame_end, IEEE80211_FCS_LEN, format!("{:#010x}", u32_le(bytes, frame_end))));
        }
        self.push_layer("IEEE 802.11", at, body_at - at, fields);
        self.out.protocols.push("wlan");
        self.out.summary.source = source;
        self.out.summary.destination = destination;
        self.set_top("802.11", subtype_name);
        if body_at >= frame_end {
            return;
        }
        if protected {
            self.data_layer(body_at, frame_end, "Encrypted data");
            self.set_top("802.11", format!("{subtype_name}, protected"));
            return;
        }
        match frame_type {
            IEEE80211_TYPE_MANAGEMENT => self.ieee80211_management(subtype, subtype_name, body_at, frame_end),
            IEEE80211_TYPE_DATA if subtype & IEEE80211_SUBTYPE_NO_DATA == 0 && !aggregate && bytes[body_at..frame_end].starts_with(&[LLC_SNAP_SAP, LLC_SNAP_SAP]) => self.llc(body_at, frame_end),
            _ => self.data_layer(body_at, frame_end, "Data"),
        }
    }

    /// The body of a management frame: fixed fields, then information
    /// elements, each an id, a length and a value.
    fn ieee80211_management(&mut self, subtype: u8, subtype_name: &str, at: usize, end: usize) {
        let bytes = self.bytes;
        let mut fields = Vec::new();
        let elements_at = management_fixed_len(subtype).map(|len| at + len).filter(|&elements_at| elements_at <= end);
        let fixed_end = elements_at.unwrap_or(end);
        if fixed_end > at {
            fields.push(Field::new("Fixed parameters", at, fixed_end - at, hex_preview(&bytes[at..fixed_end], DATA_PREVIEW_BYTES)));
        }
        let mut info = subtype_name.to_string();
        if let Some(mut cursor) = elements_at {
            for _ in 0..MAX_OPTIONS {
                if cursor + 2 > end {
                    break;
                }
                let (id, len) = (bytes[cursor], bytes[cursor + 1] as usize);
                if cursor + 2 + len > end {
                    self.out.notes.push(format!("An 802.11 information element at +{cursor} runs past the end of the frame"));
                    break;
                }
                let value = &bytes[cursor + 2..cursor + 2 + len];
                let shown = match id {
                    0 => {
                        let ssid = String::from_utf8_lossy(value).into_owned();
                        info = format!("{subtype_name}, SSID \"{ssid}\"");
                        format!("\"{ssid}\"")
                    }
                    1 | 50 => value.iter().map(|rate| format!("{}", f64::from(rate & 0x7F) / 2.0)).collect::<Vec<_>>().join(", ") + " Mb/s",
                    3 if len == 1 => format!("channel {}", value[0]),
                    _ => hex_preview(value, DATA_PREVIEW_BYTES),
                };
                fields.push(Field::new(format!("Information element {id} ({})", element_name(id)), cursor, 2 + len, shown));
                cursor += 2 + len;
            }
        }
        self.push_layer("IEEE 802.11 (management)", at, end - at, fields);
        self.out.protocols.push("wlan.mgt");
        self.set_top("802.11", info);
    }

    // -- Radiotap ------------------------------------------------------------

    /// A radiotap header at `at`, then the 802.11 frame it describes.
    pub(super) fn radiotap(&mut self, at: usize) {
        let bytes = self.bytes;
        if at + RADIOTAP_MIN_LEN > bytes.len() {
            self.malformed(at, "Radiotap", format!("Only {} bytes, shorter than a radiotap header ({RADIOTAP_MIN_LEN} bytes)", bytes.len().saturating_sub(at)));
            return;
        }
        let len = u16_le(bytes, at + 2) as usize;
        if len < RADIOTAP_MIN_LEN || at + len > bytes.len() {
            self.malformed(at, "Radiotap", format!("The radiotap header says it is {len} bytes, which does not fit the frame"));
            return;
        }
        let header_end = at + len;
        let present = u32_le(bytes, at + 4);
        // Further present words follow while the extension bit is set.
        let mut words_end = at + 8;
        let mut word = present;
        for _ in 1..MAX_RADIOTAP_PRESENT_WORDS {
            if word & RADIOTAP_PRESENT_EXTENDED == 0 || words_end + 4 > header_end {
                break;
            }
            word = u32_le(bytes, words_end);
            words_end += 4;
        }
        let mut fields = vec![
            Field::new("Header revision", at, 1, bytes[at].to_string()),
            Field::new("Header length", at + 2, 2, len.to_string()),
            Field::new("Present flags", at + 4, words_end - at - 4, format!("{present:#010x}")),
        ];
        let (radio_fields, flags) = radiotap_fields(bytes, at, words_end, header_end, present);
        fields.extend(radio_fields);
        self.push_layer("Radiotap", at, len, fields);
        self.out.protocols.push("radiotap");
        self.set_top("Radiotap", format!("Radiotap header, {len} bytes"));
        let flags = flags.unwrap_or_default();
        self.ieee80211(header_end, bytes.len(), flags);
    }

    // -- LLC -----------------------------------------------------------------

    /// An IEEE 802.2 LLC header from `at`, with a SNAP header when both
    /// SAPs are 0xAA, then what it carries, up to `end`.
    pub(super) fn llc(&mut self, at: usize, end: usize) {
        let bytes = self.bytes;
        if at + 3 > end {
            self.malformed(at, "LLC", "The LLC header is cut short".to_string());
            return;
        }
        let (dsap, ssap, control) = (bytes[at], bytes[at + 1], bytes[at + 2]);
        // Unnumbered frames have a 1-byte control field; information and
        // supervisory frames a 2-byte one.
        let control_len = if control & 0x03 == 0x03 { 1 } else { 2 };
        if at + 2 + control_len > end {
            self.malformed(at, "LLC", "The LLC control field is cut short".to_string());
            return;
        }
        let mut fields = vec![
            Field::new("DSAP", at, 1, format!("{dsap:#04x} ({})", sap_name(dsap))),
            Field::new("SSAP", at + 1, 1, format!("{ssap:#04x} ({})", sap_name(ssap))),
            Field::new("Control", at + 2, control_len, format!("{control:#04x}")),
        ];
        self.out.protocols.push("llc");
        let is_snap = dsap == LLC_SNAP_SAP && ssap == LLC_SNAP_SAP && control == LLC_UNNUMBERED_INFORMATION && at + LLC_SNAP_LEN <= end;
        if !is_snap {
            let len = 2 + control_len;
            self.push_layer("LLC", at, len, fields);
            self.set_top("LLC", format!("DSAP {dsap:#04x} ({}), SSAP {ssap:#04x} ({})", sap_name(dsap), sap_name(ssap)));
            self.data_layer(at + len, end, "Data");
            return;
        }
        let organisation = u32::from_be_bytes([0, bytes[at + 3], bytes[at + 4], bytes[at + 5]]);
        let protocol = u16_be(bytes, at + 6);
        fields.push(Field::new("OUI", at + 3, 3, format!("{organisation:06x}")));
        let carries_ether_type = SNAP_ETHER_TYPE_OUIS.contains(&organisation);
        let protocol_text = if carries_ether_type { format!("{protocol:#06x} ({})", ether_type_name(protocol)) } else { format!("{protocol:#06x}") };
        fields.push(Field::new("PID", at + 6, 2, protocol_text));
        self.push_layer("LLC", at, LLC_SNAP_LEN, fields);
        if carries_ether_type {
            self.ether_type_payload(protocol, at + LLC_SNAP_LEN, end, "LLC");
        } else {
            self.set_top("LLC", format!("SNAP, organisation {organisation:06x}, protocol {protocol:#06x}"));
            self.data_layer(at + LLC_SNAP_LEN, end, "Data");
        }
    }
}

/// The radiotap fields this dissector names (present bits 0 to 5), which
/// start at `fields_at` and are each aligned to their own size counted
/// from the header's start at `header_at`. Returns them, and the Flags
/// value when it is present.
fn radiotap_fields(bytes: &[u8], header_at: usize, fields_at: usize, header_end: usize, present: u32) -> (Vec<Field>, Option<u8>) {
    // (bit, name, alignment, size)
    const KNOWN: [(u32, &str, usize, usize); 6] = [(0, "TSFT", 8, 8), (1, "Flags", 1, 1), (2, "Rate", 1, 1), (3, "Channel", 2, 4), (4, "FHSS", 1, 2), (5, "Antenna signal", 1, 1)];
    let mut fields = Vec::new();
    let mut flags = None;
    let mut at = fields_at;
    for (bit, name, alignment, size) in KNOWN {
        if present & (1 << bit) == 0 {
            continue;
        }
        let from_start = at - header_at;
        at = header_at + from_start.next_multiple_of(alignment);
        if at + size > header_end {
            break;
        }
        let value = match bit {
            0 => format!("{} µs", u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or_default())),
            1 => {
                flags = Some(bytes[at]);
                format!("{:#04x}{}", bytes[at], if bytes[at] & RADIOTAP_FLAG_FCS != 0 { " (frame ends with its FCS)" } else { "" })
            }
            2 => format!("{} Mb/s", f64::from(bytes[at]) / 2.0),
            3 => format!("{} MHz, flags {:#06x}", u16_le(bytes, at), u16_le(bytes, at + 2)),
            5 => format!("{} dBm", bytes[at] as i8),
            _ => hex_preview(&bytes[at..at + size], size),
        };
        // FHSS has no note of its own; it is read only to step past it.
        if bit != 4 {
            fields.push(Field::new(name, at, size, value));
        }
        at += size;
    }
    (fields, flags)
}

/// The configuration options of an LCP, IPCP or IPV6CP packet from `start`
/// to `end`, as one field with a child per option.
fn control_options_field(protocol: u16, bytes: &[u8], start: usize, end: usize) -> Field {
    let mut options = Vec::new();
    let mut at = start;
    for _ in 0..MAX_OPTIONS {
        if at + 2 > end {
            break;
        }
        let (option, len) = (bytes[at], bytes[at + 1] as usize);
        if len < 2 || at + len > end {
            break;
        }
        let value = &bytes[at + 2..at + len];
        let shown = match (protocol, option, value.len()) {
            (PPP_IPCP, 3 | 129 | 131, 4) => Ipv4Addr::new(value[0], value[1], value[2], value[3]).to_string(),
            (PPP_LCP, 1, 2) => u16_be(value, 0).to_string(),
            (PPP_LCP, 3, 2..) => format!("{:#06x} ({})", u16_be(value, 0), ppp_protocol_name(u16_be(value, 0))),
            (PPP_IPV6CP, 1, 8) => {
                let mut octets = [0u8; 16];
                octets[0] = 0xFE;
                octets[1] = 0x80;
                octets[8..].copy_from_slice(value);
                format!("{} ({})", hex_preview(value, 8), Ipv6Addr::from(octets))
            }
            _ if value.is_empty() => "present".to_string(),
            _ => hex_preview(value, DATA_PREVIEW_BYTES),
        };
        options.push(Field::new(format!("Option {option} ({})", control_option_name(protocol, option)), at, len, shown));
        at += len;
    }
    let count = options.len();
    Field::new("Options", start, end - start, format!("{count} option{}", if count == 1 { "" } else { "s" })).with_children(options)
}

#[cfg(test)]
mod tests {
    use super::super::{ETHERTYPE_ARP, ETHERTYPE_IPV4, dissect};
    use super::*;
    use crate::packets::LinkKind;

    /// An IPv4/UDP packet from 10.0.0.2:4000 to 10.0.0.1:9999 holding "hi".
    fn ipv4_udp() -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).udp(4000, 9999);
        let mut packet = Vec::new();
        builder.write(&mut packet, b"hi").expect("a packet");
        packet
    }

    fn names(dissection: &crate::packets::Dissection) -> Vec<&str> {
        dissection.layers.iter().map(|layer| layer.name.as_str()).collect()
    }

    fn span(dissection: &crate::packets::Dissection, name: &str) -> (usize, usize) {
        let layer = dissection.layers.iter().find(|layer| layer.name == name).unwrap_or_else(|| panic!("no layer {name} in {:?}", names(dissection)));
        (layer.offset, layer.len)
    }

    fn field_value<'a>(dissection: &'a crate::packets::Dissection, layer: &str, field: &str) -> &'a str {
        let layer = dissection.layers.iter().find(|candidate| candidate.name == layer).expect("the layer");
        layer.fields.iter().find(|candidate| candidate.name == field).map(|found| found.value.as_str()).unwrap_or_else(|| panic!("no field {field}"))
    }

    #[test]
    fn a_linux_cooked_capture_names_the_sender_and_carries_ip() {
        let mut packet = vec![0, 4, 0, 1, 0, 6, 0x02, 0, 0, 0, 0, 0x01, 0, 0];
        packet.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        packet.extend_from_slice(&ipv4_udp());
        let dissection = dissect(&packet, LinkKind::LinuxSll);
        assert_eq!(names(&dissection), ["Linux cooked capture", "Internet Protocol version 4", "User Datagram Protocol", "Payload"]);
        assert_eq!(span(&dissection, "Linux cooked capture"), (0, 16));
        assert_eq!(field_value(&dissection, "Linux cooked capture", "Packet type"), "4 (sent by us)");
        assert_eq!(dissection.summary.source, "10.0.0.2", "the IP source takes over from the link-layer address");
        assert_eq!(dissection.summary.protocol, "UDP");
        assert!(dissection.has_protocol("sll"));
        assert_eq!(dissection.ether_type, Some(ETHERTYPE_IPV4));
    }

    #[test]
    fn a_linux_cooked_capture_v2_carries_arp_and_says_which_interface_saw_it() {
        let mut packet = ETHERTYPE_ARP.to_be_bytes().to_vec();
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 3, 0, 1, 1, 6, 0x02, 0, 0, 0, 0, 0x01, 0, 0]);
        packet.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        packet.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01, 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1]);
        let dissection = dissect(&packet, LinkKind::LinuxSll2);
        assert_eq!(names(&dissection), ["Linux cooked capture v2", "Address Resolution Protocol"]);
        assert_eq!(span(&dissection, "Linux cooked capture v2"), (0, 20));
        assert_eq!(field_value(&dissection, "Linux cooked capture v2", "Interface index"), "3");
        assert_eq!(dissection.summary.info, "Who has 10.0.0.1? Tell 10.0.0.2");
    }

    #[test]
    fn bsd_loopback_reads_the_family_in_either_byte_order_and_openbsd_loopback_big_endian() {
        let mut little = vec![2, 0, 0, 0];
        little.extend_from_slice(&ipv4_udp());
        let dissection = dissect(&little, LinkKind::BsdLoopback);
        assert_eq!(names(&dissection)[..2], ["BSD loopback", "Internet Protocol version 4"]);
        assert_eq!(field_value(&dissection, "BSD loopback", "Family"), "2 (IPv4)");

        let ipv6 = {
            let builder = etherparse::PacketBuilder::ipv6([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 64).udp(1, 2);
            let mut packet = Vec::new();
            builder.write(&mut packet, b"x").unwrap();
            packet
        };
        let mut big = vec![0, 0, 0, 30];
        big.extend_from_slice(&ipv6);
        assert_eq!(dissect(&big, LinkKind::BsdLoopback).summary.protocol, "UDP", "a big-endian NULL header from a Mac is read too");
        let loop_frame = dissect(&big, LinkKind::OpenBsdLoopback);
        assert_eq!(field_value(&loop_frame, "BSD loopback", "Family"), "30 (IPv6)");
        assert_eq!(loop_frame.layers[1].name, "Internet Protocol version 6");
    }

    #[test]
    fn a_ppp_frame_carries_ip_with_or_without_the_hdlc_address_and_control_bytes() {
        let mut bare = PPP_IPV4.to_be_bytes().to_vec();
        bare.extend_from_slice(&ipv4_udp());
        let dissection = dissect(&bare, LinkKind::Ppp);
        assert_eq!(span(&dissection, "Point-to-Point Protocol"), (0, 2));
        assert_eq!(dissection.summary.protocol, "UDP");

        let mut framed = vec![0xFF, 0x03];
        framed.extend_from_slice(&bare);
        let dissection = dissect(&framed, LinkKind::PppHdlc);
        assert_eq!(span(&dissection, "Point-to-Point Protocol"), (0, 4));
        assert_eq!(field_value(&dissection, "Point-to-Point Protocol", "Protocol"), "0x0021 (IPv4)");
        assert_eq!(span(&dissection, "Internet Protocol version 4").0, 4);
    }

    #[test]
    fn an_lcp_configuration_request_lists_its_options() {
        let frame = [0xFF, 0x03, 0xC0, 0x21, 1, 7, 0, 14, 1, 4, 0x05, 0xDC, 5, 6, 0x12, 0x34, 0x56, 0x78];
        let dissection = dissect(&frame, LinkKind::Ppp);
        assert_eq!(names(&dissection), ["Point-to-Point Protocol", "LCP"]);
        assert_eq!(span(&dissection, "LCP"), (4, 14));
        assert_eq!(dissection.summary.info, "Configuration Request (id 7)");
        let options = &dissection.layers[1].fields[3];
        assert_eq!(options.children.len(), 2);
        assert_eq!((options.children[0].name.as_str(), options.children[0].value.as_str()), ("Option 1 (Maximum receive unit)", "1500"));
    }

    #[test]
    fn a_cisco_hdlc_frame_carries_an_ether_type() {
        let mut frame = vec![0x0F, 0x00, 0x08, 0x00];
        frame.extend_from_slice(&ipv4_udp());
        let dissection = dissect(&frame, LinkKind::PppHdlc);
        assert_eq!(names(&dissection)[..2], ["Cisco HDLC", "Internet Protocol version 4"]);
    }

    /// An 802.11 data frame from a station to its access point, holding
    /// an LLC/SNAP header and an IPv4 packet.
    fn wlan_data_to_access_point() -> Vec<u8> {
        let mut frame = vec![0x08, 0x01, 0x2C, 0x00];
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0xAA]); // BSS ID
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // the station
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0xFE]); // the destination
        frame.extend_from_slice(&[0x10, 0x00]);
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0, 0, 0, 0x08, 0x00]);
        frame.extend_from_slice(&ipv4_udp());
        frame
    }

    #[test]
    fn an_802_11_data_frame_with_llc_snap_continues_into_ip() {
        let frame = wlan_data_to_access_point();
        let dissection = dissect(&frame, LinkKind::Ieee80211);
        assert_eq!(names(&dissection), ["IEEE 802.11", "LLC", "Internet Protocol version 4", "User Datagram Protocol", "Payload"]);
        assert_eq!(span(&dissection, "IEEE 802.11"), (0, 24));
        assert_eq!(span(&dissection, "LLC"), (24, 8));
        assert_eq!(field_value(&dissection, "IEEE 802.11", "Address 3"), "02:00:00:00:00:fe (destination)");
        assert_eq!(field_value(&dissection, "LLC", "PID"), "0x0800 (IPv4)");
        assert_eq!(field_value(&dissection, "IEEE 802.11", "Sequence Control"), "sequence 1, fragment 0");
        assert!(dissection.has_protocol("wlan") && dissection.has_protocol("llc"));
    }

    #[test]
    fn an_802_11_beacon_lists_its_information_elements_and_an_ack_is_ten_bytes() {
        let mut beacon = vec![0x80, 0x00, 0, 0];
        beacon.extend_from_slice(&[0xFF; 6]);
        beacon.extend_from_slice(&[0x02, 0, 0, 0, 0, 0xAA]);
        beacon.extend_from_slice(&[0x02, 0, 0, 0, 0, 0xAA]);
        beacon.extend_from_slice(&[0, 0]);
        beacon.extend_from_slice(&[0; 8]);
        beacon.extend_from_slice(&[0x64, 0, 0x01, 0x04]);
        beacon.extend_from_slice(&[0, 4]);
        beacon.extend_from_slice(b"home");
        beacon.extend_from_slice(&[1, 2, 0x82, 0x84]);
        let dissection = dissect(&beacon, LinkKind::Ieee80211);
        assert_eq!(names(&dissection), ["IEEE 802.11", "IEEE 802.11 (management)"]);
        assert_eq!(span(&dissection, "IEEE 802.11 (management)"), (24, beacon.len() - 24));
        assert_eq!(field_value(&dissection, "IEEE 802.11 (management)", "Information element 0 (SSID)"), "\"home\"");
        assert_eq!(field_value(&dissection, "IEEE 802.11 (management)", "Information element 1 (Supported rates)"), "1, 2 Mb/s");
        assert_eq!(dissection.summary.info, "Beacon frame, SSID \"home\"");

        let ack = [0xD4, 0x00, 0, 0, 0x02, 0, 0, 0, 0, 0x01];
        let dissection = dissect(&ack, LinkKind::Ieee80211);
        assert_eq!(span(&dissection, "IEEE 802.11"), (0, 10));
        assert_eq!(dissection.summary.info, "Acknowledgement");
    }

    #[test]
    fn a_protected_802_11_frame_keeps_its_security_header_and_leaves_the_rest_encrypted() {
        let mut frame = wlan_data_to_access_point();
        frame[1] |= IEEE80211_FLAG_PROTECTED;
        frame.splice(24..24, [0x01, 0x00, 0x00, 0x20, 0, 0, 0, 0]);
        let dissection = dissect(&frame, LinkKind::Ieee80211);
        assert_eq!(names(&dissection), ["IEEE 802.11", "Encrypted data"]);
        assert_eq!(span(&dissection, "IEEE 802.11"), (0, 32));
    }

    #[test]
    fn a_radiotap_header_is_skipped_by_its_length_and_its_fcs_flag_trims_the_frame() {
        // Present: TSFT, flags, rate, channel and antenna signal.
        let mut frame = vec![0, 0, 0, 0, 0x2F, 0, 0, 0];
        frame.extend_from_slice(&1_000u64.to_le_bytes());
        frame.extend_from_slice(&[RADIOTAP_FLAG_FCS, 0x0C]);
        frame.extend_from_slice(&2412u16.to_le_bytes());
        frame.extend_from_slice(&0x00A0u16.to_le_bytes());
        frame.push(0xC4);
        let header_len = frame.len() as u16;
        frame[2..4].copy_from_slice(&header_len.to_le_bytes());
        frame.extend_from_slice(&wlan_data_to_access_point());
        frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let dissection = dissect(&frame, LinkKind::Radiotap);
        assert_eq!(names(&dissection)[..3], ["Radiotap", "IEEE 802.11", "LLC"]);
        assert_eq!(span(&dissection, "Radiotap"), (0, header_len as usize));
        assert_eq!(span(&dissection, "IEEE 802.11").0, header_len as usize);
        assert_eq!(field_value(&dissection, "Radiotap", "Channel"), "2412 MHz, flags 0x00a0");
        assert_eq!(field_value(&dissection, "Radiotap", "Antenna signal"), "-60 dBm");
        assert_eq!(field_value(&dissection, "Radiotap", "Rate"), "6 Mb/s");
        assert_eq!(field_value(&dissection, "IEEE 802.11", "FCS"), "0xefbeadde");
        assert!(!dissection.layers.iter().any(|layer| layer.name == "Padding"), "the FCS is not taken for padding: {:?}", names(&dissection));
        assert_eq!(dissection.summary.protocol, "UDP");
    }

    #[test]
    fn a_radiotap_data_pad_flag_moves_the_802_11_body_to_a_four_byte_boundary() {
        let mut frame = vec![0, 0, 9, 0, 0x02, 0, 0, 0, RADIOTAP_FLAG_DATA_PAD];
        // A QoS data frame: a 26-byte header, padded to 28.
        let mut wlan = wlan_data_to_access_point();
        wlan[0] = 0x88;
        wlan.splice(24..24, [0x00, 0x00, 0xEE, 0xEE]);
        frame.extend_from_slice(&wlan);
        let dissection = dissect(&frame, LinkKind::Radiotap);
        assert_eq!(span(&dissection, "IEEE 802.11"), (9, 28));
        assert_eq!(span(&dissection, "LLC").0, 9 + 28);
        assert_eq!(dissection.summary.protocol, "UDP");
    }

    #[test]
    fn a_novell_raw_802_3_frame_is_ipx_without_an_llc_header() {
        let mut frame = vec![0xFF; 6];
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        frame.extend_from_slice(&30u16.to_be_bytes());
        frame.extend_from_slice(&[0xFF, 0xFF, 0, 30]);
        frame.extend_from_slice(&[0; 26]);
        let dissection = dissect(&frame, LinkKind::Ethernet);
        assert_eq!(names(&dissection), ["Ethernet II", "IPX"]);
    }

    #[test]
    fn an_ieee_802_3_frame_with_llc_and_padding_is_read_by_its_length() {
        let mut frame = vec![0x01, 0x80, 0xC2, 0, 0, 0, 0x02, 0, 0, 0, 0, 0x01];
        frame.extend_from_slice(&38u16.to_be_bytes());
        frame.extend_from_slice(&[0x42, 0x42, 0x03]);
        frame.extend_from_slice(&[0; 35]);
        frame.extend_from_slice(&[0; 8]);
        let dissection = dissect(&frame, LinkKind::Ethernet);
        assert_eq!(names(&dissection), ["Ethernet II", "LLC", "Data", "Padding"]);
        assert_eq!(span(&dissection, "LLC"), (14, 3));
        assert_eq!(span(&dissection, "Padding"), (52, 8));
        assert_eq!(field_value(&dissection, "Ethernet II", "Type"), "0x0026 (length 38, IEEE 802.3)");
        assert_eq!(dissection.summary.info, "DSAP 0x42 (Spanning Tree), SSAP 0x42 (Spanning Tree)");
    }

    #[test]
    fn every_new_link_layer_finds_its_reference_notes() {
        for name in ["Linux cooked capture", "Linux cooked capture v2", "BSD loopback", "Point-to-Point Protocol", "LCP", "IPCP", "IPV6CP", "IEEE 802.11", "IEEE 802.11 (management)", "Radiotap", "LLC"] {
            assert!(crate::reference::lookup(name).is_some(), "no notes for {name}");
        }
    }
}
