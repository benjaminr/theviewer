//! Dissection: a packet's bytes as a stack of layers, each a list of fields,
//! and a one-line summary for the packet list.
//!
//! Ethernet, IPv4, IPv6, TCP and UDP headers are read with `etherparse`;
//! ARP and IPv6 extension headers are small enough to read directly, as are
//! ICMP and ICMPv6 ([`icmp`]) and the other link layers a capture may use,
//! from Linux cooked captures to 802.11 and radiotap ([`link`]);
//! application protocols are chosen by port ([`super::application`]).
//! Frames of unknown format are decoded as a protocol chosen for them
//! ([`super::frames`]), else with a template, or with the field guesses of
//! the protocol analysis. Every offset is relative to the packet's first
//! byte.

use std::net::{IpAddr, Ipv4Addr};

use etherparse::{Ethernet2HeaderSlice, Ipv4HeaderSlice, Ipv6HeaderSlice, SingleVlanHeaderSlice, TcpHeaderSlice, UdpHeaderSlice};

use super::application::{self, AppLayer, SetHints};
use super::flows::{Endpoint, Flow, Transport};
use super::frames::FrameProtocol;
use super::{LinkKind, hex_preview};
use crate::plugin::Field;
use crate::protocol::MessageField;
use crate::templates::Template;

mod icmp;
mod link;

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_TAG_LEN: usize = 4;
/// Most stacked VLAN tags read.
const MAX_VLAN_TAGS: usize = 3;
const IPV6_HEADER_LEN: usize = 40;
/// Most IPv6 extension headers followed.
const MAX_IPV6_EXTENSIONS: usize = 8;
const ARP_FIXED_LEN: usize = 8;
/// Bytes of a data field shown as hex.
const DATA_PREVIEW_BYTES: usize = 24;
/// Leaf values of a template decode shown in the packet's info, enough for
/// the fields of a typical frame header and its type to be seen (and found
/// by a text filter).
const TEMPLATE_INFO_VALUES: usize = 12;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;
const ETHERTYPE_QINQ_OLD: u16 = 0x9100;

const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;
const IP_PROTOCOL_ICMPV6: u8 = 58;
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_DESTINATION_OPTIONS: u8 = 60;
const IPV6_NO_NEXT_HEADER: u8 = 59;
const IPV6_FRAGMENT_HEADER_LEN: usize = 8;
const IPV6_OPTION_PAD1: u8 = 0;
const IPV6_OPTION_PADN: u8 = 1;
const IPV6_OPTION_ROUTER_ALERT: u8 = 5;
const IPV6_OPTION_JUMBO_PAYLOAD: u8 = 0xC2;
/// The largest value of an Ethernet type field that is an IEEE 802.3
/// length rather than an EtherType.
const MAX_IEEE802_3_LENGTH: u16 = 1500;
/// An IPX header's unused checksum, which starts Novell's "raw" 802.3
/// frames where an LLC header would otherwise be.
const NOVELL_RAW_IPX_CHECKSUM: [u8; 2] = [0xFF, 0xFF];

/// One protocol layer of a packet.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct Layer {
    pub name: String,
    /// Where the layer starts in the packet.
    pub offset: usize,
    pub len: usize,
    /// Fields with offsets relative to the packet's first byte.
    pub fields: Vec<Field>,
}

/// The packet list's columns for one packet.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct Summary {
    pub source: String,
    pub destination: String,
    /// The highest layer understood, such as "DNS" or "TCP".
    pub protocol: String,
    pub info: String,
}

/// Everything learned from one packet.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Dissection {
    pub layers: Vec<Layer>,
    pub summary: Summary,
    /// Lower-case names of every layer, for the filter: "eth", "ip", "ipv4",
    /// "tcp", "dns", "data" and so on.
    pub protocols: Vec<&'static str>,
    /// Addresses and ports, for IP packets.
    pub flow: Option<Flow>,
    /// The transport payload as `(offset, len)`, for following streams.
    pub payload: Option<(usize, usize)>,
    /// The EtherType of what follows the Ethernet header and any VLAN tags.
    pub ether_type: Option<u16>,
    /// The link type actually used, after auto-detection.
    pub link: LinkKind,
    /// Problems met, such as truncation or a bad checksum.
    pub notes: Vec<String>,
    /// Indices of the layers decoded by tshark rather than by us
    /// ([`super::tshark_layers::merge`]).
    pub tshark_layers: Vec<usize>,
    /// Wireshark's filter names for those layers and their fields, in the
    /// same order as `tshark_layers`.
    pub tshark_names: Vec<WiresharkNames>,
    /// Every protocol tshark named in the packet, by filter name.
    pub tshark_protocols: Vec<String>,
}

impl Dissection {
    pub fn has_protocol(&self, name: &str) -> bool {
        self.protocols.iter().any(|protocol| protocol.eq_ignore_ascii_case(name))
    }

    /// Whether layer `index` was decoded by tshark.
    pub fn is_from_tshark(&self, index: usize) -> bool {
        self.tshark_layers.contains(&index)
    }

    /// Wireshark's filter names for layer `index`, when tshark decoded it.
    pub fn wireshark_names(&self, index: usize) -> Option<&WiresharkNames> {
        self.tshark_layers.iter().position(|&layer| layer == index).and_then(|at| self.tshark_names.get(at))
    }
}

/// Wireshark's display-filter names for a layer tshark decoded: the
/// protocol's (such as `dhcp`) and each field's (such as `dhcp.id`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WiresharkNames {
    pub protocol: String,
    /// `(path, filter name)`: the path gives the field's index in the
    /// layer's fields, then in that field's children, and so on.
    pub fields: Vec<(Vec<usize>, String)>,
}

impl WiresharkNames {
    /// The filter name of the field at `path`.
    pub fn field(&self, path: &[usize]) -> Option<&str> {
        self.fields.iter().find(|(at, _)| at == path).map(|(_, name)| name.as_str())
    }
}

/// How to decode what a packet does not say about itself: frames of unknown
/// format, and flows the rest of the set identified.
#[derive(Clone, Debug, Default)]
pub struct RawFrames {
    /// The protocol each frame is decoded as, from its first byte; frames
    /// it does not read fall back to the template or the field guesses.
    pub decode_as: Option<FrameProtocol>,
    /// Applied to each frame when set.
    pub template: Option<Template>,
    /// Header fields found by the protocol analysis, used without a template.
    pub guesses: Vec<MessageField>,
    /// Flows identified by other packets of the set, such as the ports a
    /// TFTP transfer moved to.
    pub hints: SetHints,
}

/// Dissect a packet whose first byte is described by `link`.
pub fn dissect(bytes: &[u8], link: LinkKind) -> Dissection {
    dissect_with(bytes, link, &RawFrames::default())
}

/// Dissect a packet, decoding frames of unknown format as `raw` says.
pub fn dissect_with(bytes: &[u8], link: LinkKind, raw: &RawFrames) -> Dissection {
    let resolved = match raw.decode_as.filter(|_| link == LinkKind::Unknown) {
        Some(FrameProtocol::Ethernet) if bytes.len() >= ETHERNET_HEADER_LEN => LinkKind::Ethernet,
        Some(FrameProtocol::RawIp) if matches!(bytes.first().map(|byte| byte >> 4), Some(4 | 6)) => LinkKind::RawIp,
        Some(_) => LinkKind::Unknown,
        None => resolve_link(bytes, link),
    };
    let mut walk = Walk { bytes, out: Dissection { link: resolved, ..Dissection::default() }, hints: &raw.hints };
    match resolved {
        LinkKind::Ethernet => walk.ethernet(),
        LinkKind::RawIp => {
            walk.ip(0);
        }
        LinkKind::LinuxSll => walk.linux_sll(),
        LinkKind::LinuxSll2 => walk.linux_sll2(),
        LinkKind::BsdLoopback => walk.bsd_loopback(false),
        LinkKind::OpenBsdLoopback => walk.bsd_loopback(true),
        LinkKind::Ppp => walk.ppp(),
        LinkKind::PppHdlc => walk.ppp_hdlc(),
        LinkKind::Ieee80211 => walk.ieee80211(0, bytes.len(), 0),
        LinkKind::Radiotap => walk.radiotap(0),
        LinkKind::Unknown => walk.raw_frame(raw),
    }
    walk.finish()
}

/// `Unknown` frames that start with a believable IP header are read as IP.
pub fn resolve_link(bytes: &[u8], link: LinkKind) -> LinkKind {
    if link == LinkKind::Unknown && looks_like_ip(bytes) { LinkKind::RawIp } else { link }
}

/// Whether `bytes` start with an IPv4 header whose checksum is right and
/// whose length fits, or an IPv6 header whose length fits and whose next
/// header is a common one.
pub fn looks_like_ip(bytes: &[u8]) -> bool {
    match bytes.first().map(|byte| byte >> 4) {
        Some(4) => Ipv4HeaderSlice::from_slice(bytes).is_ok_and(|header| {
            let total = header.total_len() as usize;
            total >= header.slice().len() && total <= bytes.len() && header.to_header().calc_header_checksum() == header.header_checksum()
        }),
        Some(6) => Ipv6HeaderSlice::from_slice(bytes).is_ok_and(|header| {
            let payload = header.payload_length() as usize;
            let common_next = [IP_PROTOCOL_TCP, IP_PROTOCOL_UDP, IP_PROTOCOL_ICMPV6, IPV6_HOP_BY_HOP, IPV6_ROUTING, IPV6_FRAGMENT, IPV6_DESTINATION_OPTIONS];
            payload > 0 && IPV6_HEADER_LEN + payload <= bytes.len() && common_next.contains(&header.next_header().0) && header.hop_limit() > 0
        }),
        _ => false,
    }
}

fn mac(bytes: [u8; 6]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn ether_type_name(ether_type: u16) -> &'static str {
    match ether_type {
        ETHERTYPE_IPV4 => "IPv4",
        ETHERTYPE_IPV6 => "IPv6",
        ETHERTYPE_ARP => "ARP",
        ETHERTYPE_VLAN => "802.1Q VLAN",
        ETHERTYPE_QINQ | ETHERTYPE_QINQ_OLD => "802.1ad QinQ",
        0x88CC => "LLDP",
        0x8892 => "PROFINET",
        0x88A4 => "EtherCAT",
        0x88F7 => "PTP",
        0x8863 | 0x8864 => "PPPoE",
        _ => "unknown",
    }
}

fn ip_protocol_name(protocol: u8) -> String {
    match protocol {
        IP_PROTOCOL_ICMP => "ICMP".to_string(),
        2 => "IGMP".to_string(),
        IP_PROTOCOL_TCP => "TCP".to_string(),
        IP_PROTOCOL_UDP => "UDP".to_string(),
        41 => "IPv6 in IPv4".to_string(),
        47 => "GRE".to_string(),
        50 => "ESP".to_string(),
        51 => "AH".to_string(),
        IP_PROTOCOL_ICMPV6 => "ICMPv6".to_string(),
        89 => "OSPF".to_string(),
        132 => "SCTP".to_string(),
        other => format!("IP protocol {other}"),
    }
}

fn tcp_flag_names(header: &TcpHeaderSlice<'_>) -> Vec<&'static str> {
    let flags = [
        (header.cwr(), "CWR"),
        (header.ece(), "ECE"),
        (header.urg(), "URG"),
        (header.ack(), "ACK"),
        (header.psh(), "PSH"),
        (header.rst(), "RST"),
        (header.syn(), "SYN"),
        (header.fin(), "FIN"),
    ];
    flags.into_iter().filter(|(set, _)| *set).map(|(_, name)| name).collect()
}

fn shift_fields(fields: &mut [Field], by: usize) {
    for field in fields {
        field.offset += by;
        shift_fields(&mut field.children, by);
    }
}

/// The fields of the IPv4 header at `at`, and a note when its checksum is
/// wrong.
fn ipv4_header_fields(bytes: &[u8], at: usize, header: &Ipv4HeaderSlice<'_>) -> (Vec<Field>, Option<String>) {
    let header_len = header.slice().len();
    let stored_checksum = header.header_checksum();
    let computed_checksum = header.to_header().calc_header_checksum();
    let (checksum, problem) = if stored_checksum == computed_checksum {
        (format!("{stored_checksum:#06x} (correct)"), None)
    } else {
        (
            format!("{stored_checksum:#06x} (incorrect, should be {computed_checksum:#06x})"),
            Some(format!("The IPv4 header checksum is {stored_checksum:#06x}; it should be {computed_checksum:#06x}")),
        )
    };
    let protocol = header.protocol().0;
    let flags = format!(
        "{}{}fragment offset {}",
        if header.dont_fragment() { "don't fragment, " } else { "" },
        if header.more_fragments() { "more fragments, " } else { "" },
        header.fragments_offset().value()
    );
    let mut fields = vec![
        Field::new("Version and header length", at, 1, format!("version 4, {header_len} bytes")),
        Field::new("Differentiated services", at + 1, 1, format!("{:#04x}", bytes[at + 1])),
        Field::new("Total length", at + 2, 2, header.total_len().to_string()),
        Field::new("Identification", at + 4, 2, format!("{:#06x}", header.identification())),
        Field::new("Flags and fragment offset", at + 6, 2, flags),
        Field::new("Time to live", at + 8, 1, header.ttl().to_string()),
        Field::new("Protocol", at + 9, 1, format!("{protocol} ({})", ip_protocol_name(protocol))),
        Field::new("Header checksum", at + 10, 2, checksum),
        Field::new("Source address", at + 12, 4, header.source_addr().to_string()),
        Field::new("Destination address", at + 16, 4, header.destination_addr().to_string()),
    ];
    if header_len > 20 {
        fields.push(Field::new("Options", at + 20, header_len - 20, hex_preview(header.options(), DATA_PREVIEW_BYTES)));
    }
    (fields, problem)
}

/// The fields of the fixed IPv6 header at `at`.
fn ipv6_header_fields(at: usize, header: &Ipv6HeaderSlice<'_>) -> Vec<Field> {
    let next = header.next_header().0;
    vec![
        Field::new("Version, traffic class and flow label", at, 4, format!("version 6, class {:#04x}, flow {:#07x}", header.traffic_class(), header.flow_label().value())),
        Field::new("Payload length", at + 4, 2, header.payload_length().to_string()),
        Field::new("Next header", at + 6, 1, format!("{next} ({})", ip_protocol_name(next))),
        Field::new("Hop limit", at + 7, 1, header.hop_limit().to_string()),
        Field::new("Source address", at + 8, 16, header.source_addr().to_string()),
        Field::new("Destination address", at + 24, 16, header.destination_addr().to_string()),
    ]
}

/// The options of a hop-by-hop or destination options header, from `start`
/// to `end`, each a type, a length and a value (RFC 8200 §4.2), as one
/// field with a child per option.
fn ipv6_options_field(bytes: &[u8], start: usize, end: usize) -> Field {
    let mut options = Vec::new();
    let mut at = start;
    while at < end {
        let option_type = bytes[at];
        let len = if option_type == IPV6_OPTION_PAD1 { 1 } else { bytes.get(at + 1).map_or(1, |&data_len| 2 + data_len as usize).min(end - at) };
        let name = match option_type {
            IPV6_OPTION_PAD1 => "Pad1".to_string(),
            IPV6_OPTION_PADN => "PadN".to_string(),
            IPV6_OPTION_ROUTER_ALERT => "Router alert".to_string(),
            IPV6_OPTION_JUMBO_PAYLOAD => "Jumbo payload".to_string(),
            other => format!("Option {other:#04x}"),
        };
        let value = if len > 2 { hex_preview(&bytes[at + 2..at + len], DATA_PREVIEW_BYTES) } else { format!("{len} bytes") };
        options.push(Field::new(name, at, len, value));
        at += len;
    }
    let count = options.len();
    Field::new("Options", start, end - start, format!("{count} option{}", if count == 1 { "" } else { "s" })).with_children(options)
}

/// Where a chain of IPv6 extension headers ends, and what follows it.
struct ExtensionChain {
    end: usize,
    outcome: ChainOutcome,
}

enum ChainOutcome {
    /// The upper-layer protocol starts at the chain's end.
    Upper { protocol: u8 },
    /// The packet is one fragment of a larger one.
    Fragment { protocol: u8, offset: usize },
    /// An extension header could not be read.
    Malformed,
}

/// The dissection in progress.
struct Walk<'a> {
    bytes: &'a [u8],
    out: Dissection,
    hints: &'a SetHints,
}

impl Walk<'_> {
    fn push_layer(&mut self, name: impl Into<String>, offset: usize, len: usize, fields: Vec<Field>) {
        self.out.layers.push(Layer { name: name.into(), offset, len, fields });
    }

    fn set_top(&mut self, protocol: impl Into<String>, info: impl Into<String>) {
        self.out.summary.protocol = protocol.into();
        self.out.summary.info = info.into();
    }

    /// A layer that could not be read: its bytes, and why.
    fn malformed(&mut self, at: usize, name: &str, why: String) {
        let at = at.min(self.bytes.len());
        let rest = &self.bytes[at..];
        self.push_layer(format!("{name} (malformed)"), at, rest.len(), vec![Field::new("Bytes", at, rest.len(), hex_preview(rest, DATA_PREVIEW_BYTES))]);
        if self.out.summary.protocol.is_empty() {
            self.out.summary.protocol = name.to_string();
        }
        self.out.summary.info = why.clone();
        self.out.notes.push(why);
    }

    /// Bytes no parser claimed, as one field.
    fn data_layer(&mut self, start: usize, end: usize, name: &str) {
        if start >= end {
            return;
        }
        let data = &self.bytes[start..end];
        self.push_layer(name, start, data.len(), vec![Field::new("Data", start, data.len(), format!("{} bytes: {}", data.len(), hex_preview(data, DATA_PREVIEW_BYTES)))]);
        self.out.protocols.push("data");
    }

    fn finish(mut self) -> Dissection {
        if self.out.summary.protocol.is_empty() {
            self.out.summary.protocol = "Data".to_string();
        }
        if self.out.summary.info.is_empty() {
            self.out.summary.info = format!("{} bytes", self.bytes.len());
        }
        self.out
    }

    // -- Link layer --------------------------------------------------------

    fn ethernet(&mut self) {
        let Ok(header) = Ethernet2HeaderSlice::from_slice(self.bytes) else {
            self.malformed(0, "Ethernet II", format!("Only {} bytes, shorter than an Ethernet header ({ETHERNET_HEADER_LEN} bytes)", self.bytes.len()));
            return;
        };
        let source = mac(header.source());
        let destination = mac(header.destination());
        let ether_type = header.ether_type().0;
        // Values up to 1500 are not an EtherType but the length of the IEEE
        // 802.3 frame's LLC payload.
        let is_length = ether_type <= MAX_IEEE802_3_LENGTH;
        let type_value = if is_length { format!("{ether_type:#06x} (length {ether_type}, IEEE 802.3)") } else { format!("{ether_type:#06x} ({})", ether_type_name(ether_type)) };
        self.push_layer(
            "Ethernet II",
            0,
            ETHERNET_HEADER_LEN,
            vec![Field::new("Destination", 0, 6, destination.clone()), Field::new("Source", 6, 6, source.clone()), Field::new("Type", 12, 2, type_value)],
        );
        self.out.protocols.push("eth");
        self.out.summary.source = source;
        self.out.summary.destination = destination;
        if is_length {
            let llc_end = (ETHERNET_HEADER_LEN + ether_type as usize).min(self.bytes.len());
            self.set_top("Ethernet", format!("IEEE 802.3, length {ether_type}"));
            if self.bytes[ETHERNET_HEADER_LEN..llc_end].starts_with(&NOVELL_RAW_IPX_CHECKSUM) {
                // Novell's "raw" 802.3: IPX straight after the length, no LLC.
                self.data_layer(ETHERNET_HEADER_LEN, llc_end, "IPX");
            } else {
                self.llc(ETHERNET_HEADER_LEN, llc_end);
            }
            self.padding(llc_end, self.bytes.len());
            return;
        }
        self.ether_type_payload(ether_type, ETHERNET_HEADER_LEN, self.bytes.len(), "Ethernet");
    }

    /// What follows an EtherType at `at`: any VLAN tags, then IPv4, IPv6,
    /// ARP or data, up to `end`. `carrier` names the layer holding the
    /// EtherType, for the summary when nothing inside it is understood.
    fn ether_type_payload(&mut self, mut ether_type: u16, mut at: usize, end: usize, carrier: &str) {
        for _ in 0..MAX_VLAN_TAGS {
            if !matches!(ether_type, ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_QINQ_OLD) {
                break;
            }
            let Ok(tag) = SingleVlanHeaderSlice::from_slice(&self.bytes[at.min(end)..end]) else {
                self.malformed(at, "802.1Q VLAN", "The VLAN tag is cut short".to_string());
                return;
            };
            ether_type = tag.ether_type().0;
            self.push_layer(
                "802.1Q VLAN",
                at,
                VLAN_TAG_LEN,
                vec![
                    Field::new("Priority", at, 1, tag.priority_code_point().value().to_string()),
                    Field::new("VLAN ID", at, 2, tag.vlan_identifier().value().to_string()),
                    Field::new("Type", at + 2, 2, format!("{ether_type:#06x} ({})", ether_type_name(ether_type))),
                ],
            );
            self.out.protocols.push("vlan");
            at += VLAN_TAG_LEN;
        }
        self.out.ether_type = Some(ether_type);
        self.set_top(carrier, format!("EtherType {ether_type:#06x} ({})", ether_type_name(ether_type)));
        match ether_type {
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => {
                let ip_end = self.ip(at).min(end);
                self.padding(ip_end, end);
            }
            ETHERTYPE_ARP => self.arp(at, end),
            _ => self.data_layer(at, end, "Data"),
        }
    }

    /// Bytes from `start` to `end` after the network packet, such as
    /// Ethernet padding.
    fn padding(&mut self, start: usize, end: usize) {
        if start < end {
            let len = end - start;
            self.push_layer("Padding", start, len, vec![Field::new("Padding", start, len, hex_preview(&self.bytes[start..end], DATA_PREVIEW_BYTES))]);
        }
    }

    fn arp(&mut self, at: usize, end: usize) {
        let bytes = self.bytes;
        let Some(fixed) = bytes.get(at..at + ARP_FIXED_LEN) else {
            self.malformed(at, "ARP", "The ARP header is cut short".to_string());
            return;
        };
        let hardware_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let protocol_type = u16::from_be_bytes([fixed[2], fixed[3]]);
        let (hardware_len, protocol_len) = (fixed[4] as usize, fixed[5] as usize);
        let operation = u16::from_be_bytes([fixed[6], fixed[7]]);
        let total = ARP_FIXED_LEN + 2 * (hardware_len + protocol_len);
        if at + total > bytes.len() {
            self.malformed(at, "ARP", format!("The ARP packet needs {total} bytes but only {} are left", bytes.len() - at));
            return;
        }
        let address = |offset: usize, len: usize| -> String {
            let value = &bytes[offset..offset + len];
            match len {
                4 => Ipv4Addr::new(value[0], value[1], value[2], value[3]).to_string(),
                6 => mac([value[0], value[1], value[2], value[3], value[4], value[5]]),
                _ => hex_preview(value, len),
            }
        };
        let sender_hardware = at + ARP_FIXED_LEN;
        let sender_protocol = sender_hardware + hardware_len;
        let target_hardware = sender_protocol + protocol_len;
        let target_protocol = target_hardware + hardware_len;
        let operation_name = match operation {
            1 => "request",
            2 => "reply",
            _ => "other",
        };
        self.push_layer(
            "Address Resolution Protocol",
            at,
            total,
            vec![
                Field::new("Hardware type", at, 2, hardware_type.to_string()),
                Field::new("Protocol type", at + 2, 2, format!("{protocol_type:#06x}")),
                Field::new("Hardware size", at + 4, 1, hardware_len.to_string()),
                Field::new("Protocol size", at + 5, 1, protocol_len.to_string()),
                Field::new("Opcode", at + 6, 2, format!("{operation} ({operation_name})")),
                Field::new("Sender hardware address", sender_hardware, hardware_len, address(sender_hardware, hardware_len)),
                Field::new("Sender protocol address", sender_protocol, protocol_len, address(sender_protocol, protocol_len)),
                Field::new("Target hardware address", target_hardware, hardware_len, address(target_hardware, hardware_len)),
                Field::new("Target protocol address", target_protocol, protocol_len, address(target_protocol, protocol_len)),
            ],
        );
        self.out.protocols.push("arp");
        let sender = address(sender_protocol, protocol_len);
        let target = address(target_protocol, protocol_len);
        let info = match operation {
            1 => format!("Who has {target}? Tell {sender}"),
            2 => format!("{sender} is at {}", address(sender_hardware, hardware_len)),
            _ => format!("ARP operation {operation}"),
        };
        self.set_top("ARP", info);
        self.padding(at + total, end);
    }

    // -- Network layer -----------------------------------------------------

    /// Read an IPv4 or IPv6 packet at `at`. Returns where it ends.
    fn ip(&mut self, at: usize) -> usize {
        match self.bytes.get(at).map(|byte| byte >> 4) {
            Some(4) => self.ipv4(at),
            Some(6) => self.ipv6(at),
            _ => {
                self.malformed(at, "IP", "The bytes do not start an IPv4 or IPv6 header".to_string());
                self.bytes.len()
            }
        }
    }

    fn ipv4(&mut self, at: usize) -> usize {
        let bytes = self.bytes;
        let header = match Ipv4HeaderSlice::from_slice(&bytes[at..]) {
            Ok(header) => header,
            Err(error) => {
                self.malformed(at, "IPv4", format!("The IPv4 header could not be read: {error}"));
                return bytes.len();
            }
        };
        let header_len = header.slice().len();
        let total = header.total_len() as usize;
        let end = if total >= header_len { (at + total).min(bytes.len()) } else { bytes.len() };
        if at + total > bytes.len() {
            self.out.notes.push(format!("The IPv4 total length is {total} bytes but only {} were captured", bytes.len() - at));
        }
        let (fields, checksum_problem) = ipv4_header_fields(bytes, at, &header);
        self.out.notes.extend(checksum_problem);
        let protocol = header.protocol().0;
        let fragment_offset = header.fragments_offset().value() as usize * 8;
        let source = header.source_addr();
        let destination = header.destination_addr();
        self.push_layer("Internet Protocol version 4", at, header_len, fields);
        self.out.protocols.extend(["ip", "ipv4"]);
        self.out.summary.source = source.to_string();
        self.out.summary.destination = destination.to_string();
        self.set_top("IPv4", format!("{} packet", ip_protocol_name(protocol)));
        let payload_at = at + header_len;
        if fragment_offset != 0 || header.more_fragments() {
            self.fragment("IPv4", protocol, fragment_offset, payload_at, end);
            return end;
        }
        self.transport(protocol, IpAddr::V4(source), IpAddr::V4(destination), payload_at, end);
        end
    }

    /// The data of one fragment of a fragmented packet. Only the first
    /// fragment holds the transport header, and even there the rest of the
    /// transport message is missing, so nothing inside is decoded.
    fn fragment(&mut self, version: &str, protocol: u8, offset: usize, at: usize, end: usize) {
        self.data_layer(at, end, "Fragment");
        let protocol_name = ip_protocol_name(protocol);
        if offset == 0 {
            self.set_top(version, format!("Fragmented {protocol_name} packet, first fragment"));
            self.out.notes.push(format!(
                "This is the first fragment of a fragmented {version} packet; its {protocol_name} header is not decoded because the rest of the {protocol_name} message is in later fragments"
            ));
        } else {
            self.set_top(version, format!("Fragmented {protocol_name} packet, offset {offset}"));
        }
    }

    fn ipv6(&mut self, at: usize) -> usize {
        let bytes = self.bytes;
        let header = match Ipv6HeaderSlice::from_slice(&bytes[at..]) {
            Ok(header) => header,
            Err(error) => {
                self.malformed(at, "IPv6", format!("The IPv6 header could not be read: {error}"));
                return bytes.len();
            }
        };
        let payload_len = header.payload_length() as usize;
        let end = if payload_len == 0 { bytes.len() } else { (at + IPV6_HEADER_LEN + payload_len).min(bytes.len()) };
        if at + IPV6_HEADER_LEN + payload_len > bytes.len() {
            self.out.notes.push(format!("The IPv6 payload length is {payload_len} bytes but only {} were captured", bytes.len() - at - IPV6_HEADER_LEN));
        }
        let source = header.source_addr();
        let destination = header.destination_addr();
        let next = header.next_header().0;
        let ipv6_layer = self.out.layers.len();
        self.push_layer("Internet Protocol version 6", at, IPV6_HEADER_LEN, ipv6_header_fields(at, &header));
        self.out.protocols.extend(["ip", "ipv6"]);
        self.out.summary.source = source.to_string();
        self.out.summary.destination = destination.to_string();
        self.set_top("IPv6", format!("{} packet", ip_protocol_name(next)));
        let chain = self.ipv6_extensions(next, at + IPV6_HEADER_LEN, end);
        // The IPv6 layer spans its extension headers too, as Wireshark's does;
        // each extension header is also a layer of its own inside it.
        self.out.layers[ipv6_layer].len = chain.end - at;
        match chain.outcome {
            ChainOutcome::Upper { protocol } if chain.end <= end && protocol != IPV6_NO_NEXT_HEADER => {
                self.transport(protocol, IpAddr::V6(source), IpAddr::V6(destination), chain.end, end);
            }
            ChainOutcome::Fragment { protocol, offset } => self.fragment("IPv6", protocol, offset, chain.end, end),
            ChainOutcome::Upper { .. } | ChainOutcome::Malformed => {}
        }
        end
    }

    /// Follow the IPv6 extension headers from `at`, the first being `next`,
    /// each as a layer of its own.
    fn ipv6_extensions(&mut self, mut next: u8, mut at: usize, end: usize) -> ExtensionChain {
        let bytes = self.bytes;
        for _ in 0..MAX_IPV6_EXTENSIONS {
            match next {
                IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DESTINATION_OPTIONS => {
                    let Some(&[following, units]) = bytes.get(at..at + 2).and_then(|s| <&[u8; 2]>::try_from(s).ok()) else {
                        self.malformed(at, "IPv6 extension", "An IPv6 extension header is cut short".to_string());
                        return ExtensionChain { end: at, outcome: ChainOutcome::Malformed };
                    };
                    let len = (units as usize + 1) * 8;
                    if at + len > end {
                        self.malformed(at, "IPv6 extension", format!("An IPv6 extension header of {len} bytes runs past the end of the packet"));
                        return ExtensionChain { end: at, outcome: ChainOutcome::Malformed };
                    }
                    let mut fields = vec![Field::new("Next header", at, 1, format!("{following} ({})", ip_protocol_name(following))), Field::new("Length", at + 1, 1, format!("{len} bytes"))];
                    let name = match next {
                        IPV6_HOP_BY_HOP => {
                            fields.push(ipv6_options_field(bytes, at + 2, at + len));
                            "IPv6 hop-by-hop options"
                        }
                        IPV6_ROUTING => {
                            fields.push(Field::new("Routing type", at + 2, 1, bytes[at + 2].to_string()));
                            fields.push(Field::new("Segments left", at + 3, 1, bytes[at + 3].to_string()));
                            if len > 4 {
                                fields.push(Field::new("Type-specific data", at + 4, len - 4, hex_preview(&bytes[at + 4..at + len], DATA_PREVIEW_BYTES)));
                            }
                            "IPv6 routing header"
                        }
                        _ => {
                            fields.push(ipv6_options_field(bytes, at + 2, at + len));
                            "IPv6 destination options"
                        }
                    };
                    self.push_layer(name, at, len, fields);
                    next = following;
                    at += len;
                }
                IPV6_FRAGMENT => {
                    let Some(fragment) = bytes.get(at..at + IPV6_FRAGMENT_HEADER_LEN).filter(|_| at + IPV6_FRAGMENT_HEADER_LEN <= end) else {
                        self.malformed(at, "IPv6 fragment", "The IPv6 fragment header is cut short".to_string());
                        return ExtensionChain { end: at, outcome: ChainOutcome::Malformed };
                    };
                    let offset_and_flag = u16::from_be_bytes([fragment[2], fragment[3]]);
                    let offset = (offset_and_flag >> 3) as usize * 8;
                    let more_fragments = offset_and_flag & 1 == 1;
                    let following = fragment[0];
                    let identification = u32::from_be_bytes([fragment[4], fragment[5], fragment[6], fragment[7]]);
                    self.push_layer(
                        "IPv6 fragment header",
                        at,
                        IPV6_FRAGMENT_HEADER_LEN,
                        vec![
                            Field::new("Next header", at, 1, format!("{following} ({})", ip_protocol_name(following))),
                            Field::new("Fragment offset", at + 2, 2, format!("{offset}{}", if more_fragments { ", more fragments" } else { ", last fragment" })),
                            Field::new("Identification", at + 4, 4, format!("{identification:#010x}")),
                        ],
                    );
                    at += IPV6_FRAGMENT_HEADER_LEN;
                    if offset != 0 || more_fragments {
                        return ExtensionChain { end: at, outcome: ChainOutcome::Fragment { protocol: following, offset } };
                    }
                    next = following;
                }
                _ => break,
            }
        }
        ExtensionChain { end: at, outcome: ChainOutcome::Upper { protocol: next } }
    }

    // -- Transport layer ---------------------------------------------------

    fn transport(&mut self, protocol: u8, source: IpAddr, destination: IpAddr, at: usize, end: usize) {
        match protocol {
            IP_PROTOCOL_TCP => self.tcp(source, destination, at, end),
            IP_PROTOCOL_UDP => self.udp(source, destination, at, end),
            IP_PROTOCOL_ICMP => self.icmp(source, destination, at, end, false),
            IP_PROTOCOL_ICMPV6 => self.icmp(source, destination, at, end, true),
            other => {
                self.out.flow = Some(Flow {
                    transport: Transport::Other(other),
                    source: Endpoint { address: source, port: None },
                    destination: Endpoint { address: destination, port: None },
                    tcp_sequence: None,
                });
                self.out.payload = Some((at, end.saturating_sub(at)));
                self.data_layer(at, end, &ip_protocol_name(other));
                self.set_top(ip_protocol_name(other), format!("{} bytes of {}", end.saturating_sub(at), ip_protocol_name(other)));
            }
        }
    }

    fn tcp(&mut self, source: IpAddr, destination: IpAddr, at: usize, end: usize) {
        let header = match TcpHeaderSlice::from_slice(&self.bytes[at..end]) {
            Ok(header) => header,
            Err(error) => {
                self.malformed(at, "TCP", format!("The TCP header could not be read: {error}"));
                return;
            }
        };
        let header_len = header.slice().len();
        let (source_port, destination_port) = (header.source_port(), header.destination_port());
        let sequence = header.sequence_number();
        let acknowledgement = header.acknowledgment_number();
        let flags = tcp_flag_names(&header).join(", ");
        let flag_bits = u16::from_be_bytes([self.bytes[at + 12], self.bytes[at + 13]]) & 0x01FF;
        let mut fields = vec![
            Field::new("Source port", at, 2, source_port.to_string()),
            Field::new("Destination port", at + 2, 2, destination_port.to_string()),
            Field::new("Sequence number", at + 4, 4, sequence.to_string()),
            Field::new("Acknowledgement number", at + 8, 4, acknowledgement.to_string()),
            Field::new("Header length", at + 12, 1, format!("{header_len} bytes")),
            Field::new("Flags", at + 12, 2, format!("{flag_bits:#05x} ({flags})")),
            Field::new("Window", at + 14, 2, header.window_size().to_string()),
            Field::new("Checksum", at + 16, 2, format!("{:#06x}", header.checksum())),
            Field::new("Urgent pointer", at + 18, 2, header.urgent_pointer().to_string()),
        ];
        if header_len > 20 {
            fields.push(Field::new("Options", at + 20, header_len - 20, hex_preview(header.options(), DATA_PREVIEW_BYTES)));
        }
        self.push_layer("Transmission Control Protocol", at, header_len, fields);
        self.out.protocols.push("tcp");
        self.out.flow = Some(Flow {
            transport: Transport::Tcp,
            source: Endpoint { address: source, port: Some(source_port) },
            destination: Endpoint { address: destination, port: Some(destination_port) },
            tcp_sequence: Some(sequence),
        });
        let payload_at = at + header_len;
        let payload_len = end - payload_at;
        self.out.payload = Some((payload_at, payload_len));
        let acknowledgement_text = if header.ack() { format!(" Ack={acknowledgement}") } else { String::new() };
        self.set_top(
            "TCP",
            format!("{source_port} → {destination_port} [{flags}] Seq={sequence}{acknowledgement_text} Win={} Len={payload_len}", header.window_size()),
        );
        self.application(payload_at, end);
    }

    fn udp(&mut self, source: IpAddr, destination: IpAddr, at: usize, end: usize) {
        let header = match UdpHeaderSlice::from_slice(&self.bytes[at..end]) {
            Ok(header) => header,
            Err(error) => {
                self.malformed(at, "UDP", format!("The UDP header could not be read: {error}"));
                return;
            }
        };
        let header_len = header.slice().len();
        let (source_port, destination_port) = (header.source_port(), header.destination_port());
        let length = header.length() as usize;
        let udp_end = if length >= header_len { (at + length).min(end) } else { end };
        self.push_layer(
            "User Datagram Protocol",
            at,
            header_len,
            vec![
                Field::new("Source port", at, 2, source_port.to_string()),
                Field::new("Destination port", at + 2, 2, destination_port.to_string()),
                Field::new("Length", at + 4, 2, length.to_string()),
                Field::new("Checksum", at + 6, 2, format!("{:#06x}", header.checksum())),
            ],
        );
        self.out.protocols.push("udp");
        self.out.flow = Some(Flow {
            transport: Transport::Udp,
            source: Endpoint { address: source, port: Some(source_port) },
            destination: Endpoint { address: destination, port: Some(destination_port) },
            tcp_sequence: None,
        });
        let payload_at = at + header_len;
        self.out.payload = Some((payload_at, udp_end - payload_at));
        self.set_top("UDP", format!("{source_port} → {destination_port} Len={}", udp_end - payload_at));
        self.application(payload_at, udp_end);
    }

    // -- Application layer -------------------------------------------------

    fn application(&mut self, start: usize, end: usize) {
        let Some(flow) = self.out.flow.filter(|_| start < end) else { return };
        let payload = &self.bytes[start..end];
        let layers = application::dissect_application(&flow, payload, self.hints);
        if layers.is_empty() {
            self.data_layer(start, end, "Payload");
            return;
        }
        self.application_layers(layers, start, end);
    }

    /// Application layers parsed from the bytes `start..end`, each starting
    /// where the one before it ends, then whatever they left over.
    fn application_layers(&mut self, layers: Vec<AppLayer>, start: usize, end: usize) {
        let mut at = start;
        for AppLayer { name, key, len, mut fields, info } in layers {
            shift_fields(&mut fields, start);
            let len = len.min(end - at);
            self.push_layer(name, at, len, fields);
            if !self.out.protocols.contains(&key) {
                self.out.protocols.push(key);
            }
            self.set_top(name, info);
            at += len;
        }
        self.data_layer(at, end, "Trailing data");
    }

    // -- Frames of unknown format ------------------------------------------

    fn raw_frame(&mut self, raw: &RawFrames) {
        if let Some(protocol) = raw.decode_as {
            if self.decoded_frame(protocol) {
                return;
            }
            let instead = if raw.template.is_some() { "the template" } else { "the field guesses" };
            self.out.notes.push(format!("This frame does not decode as {}, so it is shown with {instead} instead", protocol.label()));
        }
        match &raw.template {
            Some(template) => self.template_frame(template),
            None => self.guessed_frame(&raw.guesses),
        }
    }

    /// The whole frame read as `protocol` from its first byte, layer after
    /// layer as a transport payload is read. Returns false, adding
    /// nothing, when the frame is not that protocol.
    fn decoded_frame(&mut self, protocol: FrameProtocol) -> bool {
        let layers = application::dissect_frame_as(protocol, self.bytes);
        if layers.is_empty() {
            return false;
        }
        self.application_layers(layers, 0, self.bytes.len());
        true
    }

    fn template_frame(&mut self, template: &Template) {
        let applied = template.apply(self.bytes, 0);
        let len = applied.finding.len.min(self.bytes.len());
        let fields = applied.finding.fields.into_iter().next().map(single_element_children).unwrap_or_default();
        let mut values = Vec::new();
        for field in &fields {
            leaf_values(field, &mut values);
        }
        let info = if values.is_empty() { hex_preview(self.bytes, DATA_PREVIEW_BYTES) } else { values.join("  ") };
        self.push_layer(format!("{} (template)", template.name()), 0, len, fields);
        self.out.protocols.push("template");
        self.out.notes.extend(applied.warnings);
        self.set_top(template.name().to_string(), info);
        self.data_layer(len, self.bytes.len(), "Trailing data");
    }

    fn guessed_frame(&mut self, guesses: &[MessageField]) {
        let len = self.bytes.len();
        let fields: Vec<Field> = guesses.iter().filter_map(|guess| guessed_field(self.bytes, guess)).collect();
        let fields = if fields.is_empty() { vec![Field::new("Data", 0, len, format!("{len} bytes: {}", hex_preview(self.bytes, DATA_PREVIEW_BYTES)))] } else { fields };
        self.push_layer("Data", 0, len, fields);
        self.out.protocols.push("data");
        self.set_top("Data", hex_preview(self.bytes, DATA_PREVIEW_BYTES));
    }
}

/// A template decoded as `Root[until_end]` wraps everything in an array;
/// with one element, show that element's fields directly.
fn single_element_children(root: Field) -> Vec<Field> {
    match root.children.as_slice() {
        [only] if !only.children.is_empty() => only.children.clone(),
        [] => vec![root],
        _ => root.children,
    }
}

/// Up to [`TEMPLATE_INFO_VALUES`] `name=value` pairs from the leaves.
fn leaf_values(field: &Field, out: &mut Vec<String>) {
    if out.len() >= TEMPLATE_INFO_VALUES {
        return;
    }
    if field.children.is_empty() {
        out.push(format!("{}={}", field.name, field.value));
        return;
    }
    for child in &field.children {
        leaf_values(child, out);
    }
}

/// A field from the protocol analysis placed in this frame, if it fits.
fn guessed_field(bytes: &[u8], guess: &MessageField) -> Option<Field> {
    let (start, len) = if guess.from_end {
        (bytes.len().checked_sub(guess.start)?, guess.len)
    } else if guess.len == 0 {
        (guess.start, bytes.len().checked_sub(guess.start)?)
    } else {
        (guess.start, guess.len)
    };
    let value = bytes.get(start..start.checked_add(len)?)?;
    let detail = if guess.detail.is_empty() { String::new() } else { format!(" ({})", guess.detail) };
    Some(Field::new(guess.kind.clone(), start, len, format!("{}{detail}", hex_preview(value, DATA_PREVIEW_BYTES))))
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use super::*;

    const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const ROUTER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0xFE];
    const CLIENT_IP: [u8; 4] = [10, 0, 0, 2];
    const SERVER_IP: [u8; 4] = [10, 0, 0, 1];

    fn dns_query_payload() -> Vec<u8> {
        let mut message = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(b"\x07example\x03com\x00");
        message.extend_from_slice(&[0, 1, 0, 1]);
        message
    }

    fn ethernet_udp(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2(CLIENT_MAC, ROUTER_MAC).ipv4(CLIENT_IP, SERVER_IP, 64).udp(source_port, destination_port);
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, payload).expect("a packet");
        packet
    }

    fn ethernet_tcp(payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2(CLIENT_MAC, ROUTER_MAC).ipv4(CLIENT_IP, SERVER_IP, 64).tcp(49152, 80, 1000, 64240).psh().ack(2000);
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, payload).expect("a packet");
        packet
    }

    fn layer<'a>(dissection: &'a Dissection, name: &str) -> &'a Layer {
        dissection.layers.iter().find(|l| l.name == name).unwrap_or_else(|| panic!("no layer {name} in {:?}", dissection.layers.iter().map(|l| &l.name).collect::<Vec<_>>()))
    }

    fn field<'a>(layer: &'a Layer, name: &str) -> &'a Field {
        layer.fields.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no field {name} in {}", layer.name))
    }

    #[test]
    fn an_ethernet_dns_query_is_dissected_layer_by_layer_with_a_summary() {
        let payload = dns_query_payload();
        let packet = ethernet_udp(53_000, 53, &payload);
        let dissection = dissect(&packet, LinkKind::Ethernet);
        let names: Vec<&str> = dissection.layers.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, vec!["Ethernet II", "Internet Protocol version 4", "User Datagram Protocol", "DNS"]);

        let ethernet = layer(&dissection, "Ethernet II");
        assert_eq!(field(ethernet, "Source").value, "02:00:00:00:00:01");
        assert_eq!(field(ethernet, "Type").value, "0x0800 (IPv4)");
        let ip = layer(&dissection, "Internet Protocol version 4");
        assert_eq!((ip.offset, ip.len), (14, 20));
        assert_eq!(field(ip, "Source address").value, "10.0.0.2");
        assert!(field(ip, "Header checksum").value.ends_with("(correct)"));
        assert_eq!(field(ip, "Protocol").value, "17 (UDP)");
        let udp = layer(&dissection, "User Datagram Protocol");
        assert_eq!((udp.offset, udp.len), (34, 8));
        assert_eq!(field(udp, "Destination port").value, "53");
        assert_eq!(field(udp, "Length").value, (8 + payload.len()).to_string());
        let dns = layer(&dissection, "DNS");
        assert_eq!(dns.offset, 42);
        let transaction = field(dns, "Transaction ID");
        assert_eq!((transaction.offset, transaction.value.as_str()), (42, "0xabcd"));

        assert_eq!(
            dissection.summary,
            Summary {
                source: "10.0.0.2".to_string(),
                destination: "10.0.0.1".to_string(),
                protocol: "DNS".to_string(),
                info: "Standard query 0xabcd A example.com".to_string()
            }
        );
        assert_eq!(dissection.protocols, vec!["eth", "ip", "ipv4", "udp", "dns"]);
        assert_eq!(dissection.payload, Some((42, payload.len())));
        let flow = dissection.flow.expect("a flow");
        assert_eq!(flow.transport, Transport::Udp);
        assert_eq!(flow.destination.port, Some(53));
        assert!(dissection.notes.is_empty(), "{:?}", dissection.notes);
    }

    #[test]
    fn a_tcp_http_request_shows_flags_sequence_and_the_request_line() {
        let packet = ethernet_tcp(b"GET /status HTTP/1.1\r\nHost: plc.local\r\n\r\n");
        let dissection = dissect(&packet, LinkKind::Ethernet);
        let tcp = layer(&dissection, "Transmission Control Protocol");
        assert_eq!(field(tcp, "Sequence number").value, "1000");
        assert!(field(tcp, "Flags").value.contains("ACK, PSH"), "{}", field(tcp, "Flags").value);
        let http = layer(&dissection, "HTTP");
        assert_eq!(field(http, "Request line").value, "GET /status HTTP/1.1");
        assert_eq!(dissection.summary.protocol, "HTTP");
        assert_eq!(dissection.summary.info, "GET /status HTTP/1.1");
        assert_eq!(dissection.flow.and_then(|f| f.tcp_sequence), Some(1000));
    }

    #[test]
    fn an_ntp_packet_over_udp_is_recognised_by_port() {
        let mut ntp = vec![0u8; 48];
        ntp[0] = 0x24; // version 4, server
        ntp[1] = 2;
        let packet = ethernet_udp(123, 123, &ntp);
        let dissection = dissect(&packet, LinkKind::Ethernet);
        assert_eq!(dissection.summary.protocol, "NTP");
        assert_eq!(dissection.summary.info, "NTP version 4, server, stratum 2");
        assert!(dissection.has_protocol("ntp"));
    }

    #[test]
    fn a_modbus_request_and_an_mqtt_publish_are_recognised_by_port() {
        let modbus = [0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0x01, 0x04, 0x00, 0x00, 0x00, 0x02];
        let builder = PacketBuilder::ipv4(CLIENT_IP, SERVER_IP, 64).tcp(40000, 502, 1, 1024);
        let mut packet = Vec::new();
        builder.write(&mut packet, &modbus).unwrap();
        let dissection = dissect(&packet, LinkKind::RawIp);
        assert_eq!(dissection.summary.protocol, "Modbus/TCP");
        assert!(dissection.summary.info.contains("Read Input Registers"), "{}", dissection.summary.info);

        let mut mqtt = vec![0x30, 0];
        mqtt.extend_from_slice(&[0, 5]);
        mqtt.extend_from_slice(b"a/b/c");
        mqtt.extend_from_slice(b"on");
        mqtt[1] = (mqtt.len() - 2) as u8;
        let builder = PacketBuilder::ipv4(CLIENT_IP, SERVER_IP, 64).tcp(40001, 1883, 1, 1024);
        let mut packet = Vec::new();
        builder.write(&mut packet, &mqtt).unwrap();
        let dissection = dissect(&packet, LinkKind::RawIp);
        assert_eq!(dissection.summary.info, "Publish Message (QoS 0) [a/b/c]");
    }

    #[test]
    fn a_raw_ip_packet_starts_at_the_ip_header_and_unknown_frames_that_look_like_ip_are_detected() {
        let builder = PacketBuilder::ipv6([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 64).udp(5353, 5353);
        let mut packet = Vec::new();
        builder.write(&mut packet, &dns_query_payload()).unwrap();
        let dissection = dissect(&packet, LinkKind::RawIp);
        assert_eq!(dissection.layers[0].name, "Internet Protocol version 6");
        assert_eq!(dissection.summary.source, "fe80::1");
        assert_eq!(dissection.summary.protocol, "DNS");

        let ipv4 = ethernet_udp(1000, 2000, b"hello")[ETHERNET_HEADER_LEN..].to_vec();
        let detected = dissect(&ipv4, LinkKind::Unknown);
        assert_eq!(detected.link, LinkKind::RawIp);
        assert_eq!(detected.summary.protocol, "UDP");
        let mut corrupted = ipv4.clone();
        corrupted[10] ^= 0xFF;
        assert_eq!(dissect(&corrupted, LinkKind::Unknown).link, LinkKind::Unknown, "a bad checksum is not taken for IP");
    }

    #[test]
    fn an_arp_request_asks_who_has_the_target() {
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0xFF; 6]);
        packet.extend_from_slice(&CLIENT_MAC);
        packet.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        packet.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        packet.extend_from_slice(&CLIENT_MAC);
        packet.extend_from_slice(&CLIENT_IP);
        packet.extend_from_slice(&[0; 6]);
        packet.extend_from_slice(&SERVER_IP);
        packet.resize(60, 0);
        let dissection = dissect(&packet, LinkKind::Ethernet);
        assert_eq!(dissection.summary.protocol, "ARP");
        assert_eq!(dissection.summary.info, "Who has 10.0.0.1? Tell 10.0.0.2");
        assert_eq!(dissection.layers.last().map(|l| l.name.as_str()), Some("Padding"));
    }

    #[test]
    fn an_icmp_echo_request_shows_its_identifier_and_sequence() {
        let builder = PacketBuilder::ipv4(CLIENT_IP, SERVER_IP, 64).icmpv4_echo_request(0x1234, 7);
        let mut packet = Vec::new();
        builder.write(&mut packet, b"ping").unwrap();
        let dissection = dissect(&packet, LinkKind::RawIp);
        assert_eq!(dissection.summary.protocol, "ICMP");
        assert_eq!(dissection.summary.info, "Echo (ping) request id=0x1234, seq=7");
        assert_eq!(dissection.flow.map(|f| f.transport), Some(Transport::Icmp));
    }

    #[test]
    fn a_truncated_packet_is_explained_rather_than_failing() {
        let packet = ethernet_tcp(b"GET / HTTP/1.1\r\n\r\n");
        let truncated = &packet[..40];
        let dissection = dissect(truncated, LinkKind::Ethernet);
        assert!(dissection.layers.iter().any(|l| l.name.contains("malformed")), "{:?}", dissection.layers);
        assert!(!dissection.notes.is_empty());
        let tiny = dissect(&[1, 2, 3], LinkKind::Ethernet);
        assert!(tiny.summary.info.contains("shorter than an Ethernet header"));
    }

    #[test]
    fn raw_frames_use_the_template_when_one_is_chosen_and_the_field_guesses_otherwise() {
        let frame = [0xAA, 0x55, 0x02, 0x00, 0x07, 0xDE, 0xAD];
        let template = Template::parse("struct Frame { sync: u16be  kind: u8  sequence: u16be  body: bytes[2] }").expect("a template");
        let raw = RawFrames { template: Some(template), ..RawFrames::default() };
        let dissection = dissect_with(&frame, LinkKind::Unknown, &raw);
        assert_eq!(dissection.layers[0].name, "Frame (template)");
        let names: Vec<&str> = dissection.layers[0].fields.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"sequence"), "{names:?}");
        assert!(dissection.summary.info.contains("kind="), "{}", dissection.summary.info);

        let guesses = vec![
            MessageField { start: 0, len: 2, kind: "constant".to_string(), detail: String::new(), values: vec![], from_end: false },
            MessageField { start: 3, len: 2, kind: "sequence number u16 BE".to_string(), detail: "counts up".to_string(), values: vec![], from_end: false },
            MessageField { start: 2, len: 2, kind: "checksum".to_string(), detail: String::new(), values: vec![], from_end: true },
            MessageField { start: 40, len: 2, kind: "beyond".to_string(), detail: String::new(), values: vec![], from_end: false },
        ];
        let dissection = dissect_with(&frame, LinkKind::Unknown, &RawFrames { guesses, ..RawFrames::default() });
        let data = layer(&dissection, "Data");
        assert_eq!(data.fields.len(), 3, "the field beyond the frame is left out");
        let checksum = field(data, "checksum");
        assert_eq!((checksum.offset, checksum.len), (5, 2));
        assert_eq!(field(data, "sequence number u16 BE").value, "00 07 (counts up)");
    }

    #[test]
    fn frames_decoded_as_a_protocol_read_like_that_protocol_on_its_port() {
        let message = dns_query_payload();
        let mut frame = message.clone();
        frame.extend_from_slice(&[0xEE, 0xEE]);
        let raw = RawFrames { decode_as: Some(FrameProtocol::Dns), ..RawFrames::default() };
        let decoded = dissect_with(&frame, LinkKind::Unknown, &raw);
        let names: Vec<&str> = decoded.layers.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["DNS", "Trailing data"]);
        let on_port = dissect(&ethernet_udp(53_000, 53, &message), LinkKind::Ethernet);
        assert_eq!(decoded.summary.protocol, on_port.summary.protocol);
        assert_eq!(decoded.summary.info, on_port.summary.info);
        assert_eq!(decoded.protocols, ["dns", "data"]);
        assert_eq!(field(layer(&decoded, "DNS"), "Transaction ID").offset, 0);
        assert!(decoded.notes.is_empty(), "{:?}", decoded.notes);
    }

    #[test]
    fn a_chosen_protocol_overrides_the_template_and_the_raw_ip_guess() {
        let template = Template::parse("struct Frame { a: u8 }").expect("a template");
        let raw = RawFrames { decode_as: Some(FrameProtocol::Dns), template: Some(template), ..RawFrames::default() };
        assert_eq!(dissect_with(&dns_query_payload(), LinkKind::Unknown, &raw).summary.protocol, "DNS");
        let ip_packet = ethernet_udp(1000, 2000, b"hello")[ETHERNET_HEADER_LEN..].to_vec();
        let as_ethernet = dissect_with(&ip_packet, LinkKind::Unknown, &RawFrames { decode_as: Some(FrameProtocol::Ethernet), ..RawFrames::default() });
        assert_eq!(as_ethernet.link, LinkKind::Ethernet, "the user's choice beats the raw IP guess");
        let frame = ethernet_udp(1000, 2000, b"hello");
        let ethernet = dissect_with(&frame, LinkKind::Unknown, &RawFrames { decode_as: Some(FrameProtocol::Ethernet), ..RawFrames::default() });
        assert_eq!(ethernet.summary.protocol, "UDP");
        assert_eq!(dissect_with(&frame, LinkKind::Ethernet, &raw).summary.protocol, "UDP", "a capture's own link type is kept");
    }

    #[test]
    fn a_frame_the_chosen_decoder_rejects_falls_back_with_a_note() {
        let frame = [0xFF, 0x01, 0x02];
        let raw = RawFrames { decode_as: Some(FrameProtocol::ModbusTcp), ..RawFrames::default() };
        let dissection = dissect_with(&frame, LinkKind::Unknown, &raw);
        assert_eq!(dissection.layers[0].name, "Data");
        assert_eq!(dissection.notes, ["This frame does not decode as Modbus/TCP, so it is shown with the field guesses instead"]);
        let short = dissect_with(&frame, LinkKind::Unknown, &RawFrames { decode_as: Some(FrameProtocol::Ethernet), ..RawFrames::default() });
        assert_eq!(short.link, LinkKind::Unknown);
        assert!(short.notes[0].contains("Ethernet"), "{:?}", short.notes);
    }

    #[test]
    fn arbitrary_bytes_never_make_the_dissector_panic() {
        let mut state = 0x1234_5678u32;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        let template = Template::parse("struct T { a: u8  n: u8  body: bytes[n] }").ok();
        let raw = RawFrames { template, ..RawFrames::default() };
        let decoders: Vec<RawFrames> = FrameProtocol::ALL.iter().map(|&protocol| RawFrames { decode_as: Some(protocol), ..RawFrames::default() }).collect();
        for round in 0..3000 {
            let len = (next() % 200) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if round % 3 == 0 && bytes.len() > 20 {
                bytes[0] = 0x45;
            }
            if round % 5 == 0 && bytes.len() > 14 {
                bytes[12] = 0x08;
                bytes[13] = 0x00;
            }
            for link in LinkKind::ALL {
                let _ = dissect(&bytes, link);
                let _ = dissect_with(&bytes, link, &raw);
            }
            for decoder in &decoders {
                let _ = dissect_with(&bytes, LinkKind::Unknown, decoder);
            }
        }
    }

    /// A raw IPv6 packet whose payload is `payload`, starting with the
    /// header `next_header` names.
    fn ipv6_packet(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let header = etherparse::Ipv6Header {
            payload_length: payload.len() as u16,
            next_header: etherparse::IpNumber(next_header),
            hop_limit: 64,
            source: [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16],
            ..etherparse::Ipv6Header::default()
        };
        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(payload);
        packet
    }

    /// A UDP header from port 546 to 547 and `data`, with no checksum.
    fn udp_datagram(data: &[u8]) -> Vec<u8> {
        let mut datagram = vec![0x02, 0x22, 0x02, 0x23];
        datagram.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        datagram.extend_from_slice(&[0, 0]);
        datagram.extend_from_slice(data);
        datagram
    }

    #[test]
    fn the_ipv6_layer_spans_its_extension_headers_which_are_also_layers_of_their_own() {
        // Hop-by-hop options holding a router alert and two bytes of padding.
        let mut payload = vec![IP_PROTOCOL_UDP, 0, IPV6_OPTION_ROUTER_ALERT, 2, 0, 0, IPV6_OPTION_PADN, 0];
        payload.extend_from_slice(&udp_datagram(b"solicit"));
        let packet = ipv6_packet(IPV6_HOP_BY_HOP, &payload);
        let dissection = dissect(&packet, LinkKind::RawIp);
        let ipv6 = layer(&dissection, "Internet Protocol version 6");
        assert_eq!((ipv6.offset, ipv6.len), (0, 48), "the fixed header and the hop-by-hop options");
        let options = layer(&dissection, "IPv6 hop-by-hop options");
        assert_eq!((options.offset, options.len), (40, 8));
        assert_eq!(field(options, "Next header").value, "17 (UDP)");
        let children: Vec<&str> = field(options, "Options").children.iter().map(|option| option.name.as_str()).collect();
        assert_eq!(children, ["Router alert", "PadN"]);
        let udp = layer(&dissection, "User Datagram Protocol");
        assert_eq!(udp.offset, 48);
        assert_eq!(crate::reference::lookup(&options.name).map(|notes| notes.id.as_str()), Some("ipv6-extension"));
    }

    #[test]
    fn a_routing_header_then_destination_options_are_followed_to_the_transport() {
        let mut payload = vec![IPV6_DESTINATION_OPTIONS, 0, 0, 1, 0, 0, 0, 0];
        payload.extend_from_slice(&[IP_PROTOCOL_UDP, 0, IPV6_OPTION_PADN, 4, 0, 0, 0, 0]);
        payload.extend_from_slice(&udp_datagram(b"x"));
        let dissection = dissect(&ipv6_packet(IPV6_ROUTING, &payload), LinkKind::RawIp);
        assert_eq!(layer(&dissection, "Internet Protocol version 6").len, 56);
        assert_eq!(field(layer(&dissection, "IPv6 routing header"), "Segments left").value, "1");
        assert_eq!(layer(&dissection, "IPv6 destination options").offset, 48);
        assert_eq!(dissection.summary.protocol, "UDP");
    }

    #[test]
    fn an_extension_header_longer_than_the_packet_is_malformed_and_stops_the_chain() {
        let payload = [IP_PROTOCOL_UDP, 4, 0, 0, 0, 0, 0, 0];
        let dissection = dissect(&ipv6_packet(IPV6_HOP_BY_HOP, &payload), LinkKind::RawIp);
        assert_eq!(layer(&dissection, "Internet Protocol version 6").len, 40);
        assert!(dissection.layers.iter().any(|l| l.name == "IPv6 extension (malformed)"));
        assert!(!dissection.has_protocol("udp"));
    }

    #[test]
    fn the_first_fragment_of_an_ipv6_packet_is_left_as_fragment_data_until_reassembly() {
        let mut payload = vec![IP_PROTOCOL_UDP, 0, 0, 1, 0x12, 0x34, 0x56, 0x78];
        payload.extend_from_slice(&udp_datagram(&[0; 40])[..24]);
        let dissection = dissect(&ipv6_packet(IPV6_FRAGMENT, &payload), LinkKind::RawIp);
        let names: Vec<&str> = dissection.layers.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["Internet Protocol version 6", "IPv6 fragment header", "Fragment"]);
        assert_eq!(layer(&dissection, "Internet Protocol version 6").len, 48);
        let header = layer(&dissection, "IPv6 fragment header");
        assert_eq!(field(header, "Fragment offset").value, "0, more fragments");
        assert_eq!(field(header, "Identification").value, "0x12345678");
        assert_eq!(dissection.summary.protocol, "IPv6");
        assert_eq!(dissection.summary.info, "Fragmented UDP packet, first fragment");
        assert!(dissection.notes.iter().any(|note| note.contains("first fragment")), "{:?}", dissection.notes);
        assert!(dissection.flow.is_none());
    }

    #[test]
    fn the_first_fragment_of_an_ipv4_datagram_does_not_decode_its_udp_header() {
        let builder = PacketBuilder::ipv4(CLIENT_IP, SERVER_IP, 64).udp(5000, 53);
        let mut packet = Vec::new();
        builder.write(&mut packet, &[0xAB; 64]).unwrap();
        // Set "more fragments" and keep the header checksum right.
        packet[6] |= 0x20;
        let checksum = Ipv4HeaderSlice::from_slice(&packet).unwrap().to_header().calc_header_checksum();
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        let dissection = dissect(&packet, LinkKind::RawIp);
        let names: Vec<&str> = dissection.layers.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["Internet Protocol version 4", "Fragment"]);
        assert_eq!((layer(&dissection, "Fragment").offset, layer(&dissection, "Fragment").len), (20, 72));
        assert_eq!(dissection.summary.protocol, "IPv4");
        assert_eq!(dissection.summary.info, "Fragmented UDP packet, first fragment");
        assert!(!dissection.has_protocol("udp"));
        assert_eq!(dissection.notes.len(), 1, "{:?}", dissection.notes);

        // A later fragment says where its data belongs, without a note.
        packet[6] = 0x00;
        packet[7] = 0x09;
        let checksum = Ipv4HeaderSlice::from_slice(&packet).unwrap().to_header().calc_header_checksum();
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        let later = dissect(&packet, LinkKind::RawIp);
        assert_eq!(later.summary.info, "Fragmented UDP packet, offset 72");
        assert!(later.notes.is_empty(), "{:?}", later.notes);
    }
}
