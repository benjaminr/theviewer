//! Packets taken from the document, and what can be learned from them.
//!
//! A [`Packet`] is a range of the document with an optional timestamp and a
//! link type saying what its first byte is: an Ethernet, Linux cooked,
//! loopback, PPP, 802.11 or radiotap header, an IP header, or an
//! application frame of unknown format. Packets are gathered into a
//! [`PacketSet`] from one of several sources ([`sources`]): the messages of
//! the protocol analysis, a pcap or pcapng capture inside the document, a
//! range cut into fixed-length records, at a delimiter or pattern, or by a
//! length field inside each frame ([`split`]), a single range, or a cluster
//! from the message alignment. [`grid`] lays packets out one per row, so the
//! same field lines up across them, and edits whole columns at once.
//!
//! Each packet can be dissected into layers ([`dissect`]), summarised into
//! conversations and endpoints and followed as a stream ([`flows`]), matched
//! against a small filter language ([`filter`]), and written back out as a
//! classic pcap file ([`export`]). When Wireshark's tshark is installed and
//! the user asks for it, packets can also be decoded by it ([`tshark`]) and
//! its layers merged into ours ([`tshark_layers`]).
//!
//! Everything here is pure and bounded: no input makes it panic, and every
//! loop has a cap.

pub mod application;
pub mod dissect;
pub mod edit;
pub mod export;
pub mod filter;
pub mod flows;
pub mod grid;
pub mod sources;
pub mod split;
pub mod tshark;
pub mod tshark_layers;

pub use dissect::{Dissection, Layer, RawFrames, Summary, dissect, dissect_with};
pub use export::{ExportError, ExportPacket, write_pcap, write_pcap_as};
pub use filter::{Filter, FilterError, FilterSubject, parse_filter};
pub use flows::{Conversation, ConversationKey, Endpoint, EndpointStats, Flow, Stream, Transport, conversations, endpoints, follow_stream};
pub use sources::{CaptureLocation, SourceError};

/// Most packets a set holds; sources stop adding once it is reached.
pub const MAX_PACKETS: usize = 200_000;

/// pcap link-layer header type numbers (from tcpdump.org's LINKTYPE list).
pub const LINKTYPE_NULL: u32 = 0;
pub const LINKTYPE_ETHERNET: u32 = 1;
/// IEEE 802.5 token ring and FDDI, which older capture formats record.
pub const LINKTYPE_IEEE802_5: u32 = 6;
pub const LINKTYPE_PPP: u32 = 9;
pub const LINKTYPE_FDDI: u32 = 10;
/// The numbers some systems wrote for raw IP before `LINKTYPE_RAW_IP` was
/// assigned: 12 on most, 14 on OpenBSD.
pub const LINKTYPE_RAW_IP_OLD: u32 = 12;
pub const LINKTYPE_RAW_IP_OPENBSD: u32 = 14;
pub const LINKTYPE_PPP_HDLC: u32 = 50;
pub const LINKTYPE_RAW_IP: u32 = 101;
pub const LINKTYPE_IEEE802_11: u32 = 105;
pub const LINKTYPE_LOOP: u32 = 108;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_IEEE802_11_RADIOTAP: u32 = 127;
/// The first of the link types reserved for private use; Wireshark lets the
/// user say which dissector to apply to it.
pub const LINKTYPE_USER0: u32 = 147;
/// Raw IPv4 and raw IPv6, which some captures use instead of `LINKTYPE_RAW_IP`.
pub const LINKTYPE_IPV4: u32 = 228;
pub const LINKTYPE_IPV6: u32 = 229;
pub const LINKTYPE_LINUX_SLL2: u32 = 276;

/// What a packet's first byte is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum LinkKind {
    /// An Ethernet II header.
    Ethernet,
    /// An IPv4 or IPv6 header.
    RawIp,
    /// A Linux cooked capture header (SLL, 16 bytes).
    LinuxSll,
    /// A Linux cooked capture v2 header (SLL2, 20 bytes).
    LinuxSll2,
    /// BSD loopback: a 4-byte protocol family in the capturing machine's
    /// byte order.
    BsdLoopback,
    /// OpenBSD loopback: the same family, always big-endian.
    OpenBsdLoopback,
    /// A PPP frame, with or without the HDLC address and control bytes.
    Ppp,
    /// A PPP frame in HDLC-like framing (or a Cisco HDLC frame), without
    /// flags or frame check sequence.
    PppHdlc,
    /// An IEEE 802.11 frame.
    Ieee80211,
    /// A radiotap header followed by an IEEE 802.11 frame.
    Radiotap,
    /// An application frame of unknown format, such as a serial message.
    #[default]
    Unknown,
}

impl LinkKind {
    pub const ALL: [LinkKind; 11] = [
        LinkKind::Ethernet,
        LinkKind::RawIp,
        LinkKind::LinuxSll,
        LinkKind::LinuxSll2,
        LinkKind::BsdLoopback,
        LinkKind::OpenBsdLoopback,
        LinkKind::Ppp,
        LinkKind::PppHdlc,
        LinkKind::Ieee80211,
        LinkKind::Radiotap,
        LinkKind::Unknown,
    ];

    pub fn label(self) -> &'static str {
        match self {
            LinkKind::Ethernet => "Ethernet",
            LinkKind::RawIp => "Raw IP",
            LinkKind::LinuxSll => "Linux cooked capture",
            LinkKind::LinuxSll2 => "Linux cooked capture v2",
            LinkKind::BsdLoopback => "BSD loopback",
            LinkKind::OpenBsdLoopback => "OpenBSD loopback",
            LinkKind::Ppp => "PPP",
            LinkKind::PppHdlc => "PPP in HDLC framing",
            LinkKind::Ieee80211 => "IEEE 802.11",
            LinkKind::Radiotap => "802.11 with radiotap",
            LinkKind::Unknown => "Raw frames",
        }
    }

    /// The pcap link type written for packets of this kind.
    pub fn pcap_link_type(self) -> u32 {
        match self {
            LinkKind::Ethernet => LINKTYPE_ETHERNET,
            LinkKind::RawIp => LINKTYPE_RAW_IP,
            LinkKind::LinuxSll => LINKTYPE_LINUX_SLL,
            LinkKind::LinuxSll2 => LINKTYPE_LINUX_SLL2,
            LinkKind::BsdLoopback => LINKTYPE_NULL,
            LinkKind::OpenBsdLoopback => LINKTYPE_LOOP,
            LinkKind::Ppp => LINKTYPE_PPP,
            LinkKind::PppHdlc => LINKTYPE_PPP_HDLC,
            LinkKind::Ieee80211 => LINKTYPE_IEEE802_11,
            LinkKind::Radiotap => LINKTYPE_IEEE802_11_RADIOTAP,
            LinkKind::Unknown => LINKTYPE_USER0,
        }
    }

    /// The kind for a pcap link type; link types the dissector does not
    /// read are treated as frames of unknown format.
    pub fn from_pcap_link_type(link_type: u32) -> LinkKind {
        match link_type {
            LINKTYPE_ETHERNET => LinkKind::Ethernet,
            LINKTYPE_RAW_IP | LINKTYPE_RAW_IP_OLD | LINKTYPE_RAW_IP_OPENBSD | LINKTYPE_IPV4 | LINKTYPE_IPV6 => LinkKind::RawIp,
            LINKTYPE_LINUX_SLL => LinkKind::LinuxSll,
            LINKTYPE_LINUX_SLL2 => LinkKind::LinuxSll2,
            LINKTYPE_NULL => LinkKind::BsdLoopback,
            LINKTYPE_LOOP => LinkKind::OpenBsdLoopback,
            LINKTYPE_PPP => LinkKind::Ppp,
            LINKTYPE_PPP_HDLC => LinkKind::PppHdlc,
            LINKTYPE_IEEE802_11 => LinkKind::Ieee80211,
            LINKTYPE_IEEE802_11_RADIOTAP => LinkKind::Radiotap,
            _ => LinkKind::Unknown,
        }
    }
}

/// One packet: a range of the document.
#[derive(Clone, Debug, PartialEq)]
pub struct Packet {
    /// Document offset of the packet's first byte.
    pub offset: usize,
    pub len: usize,
    /// Seconds since the Unix epoch (or since the capture started), if known.
    pub timestamp: Option<f64>,
    pub link: LinkKind,
    /// The tcpdump.org LINKTYPE number of the packet's first byte: its
    /// capture's own (which may be one the viewer reads as frames of unknown
    /// format, such as 802.11), else the number for `link`.
    pub link_type: u32,
    /// Where the packet came from, such as "pcap record 12" or "message 5".
    pub origin: String,
    /// The whole container record holding the packet (a pcap record header
    /// and data, or a pcapng block), as `(offset, len)`. Deleting the packet
    /// removes this, so the capture stays readable.
    pub record: Option<(usize, usize)>,
}

impl Packet {
    pub fn new(offset: usize, len: usize, link: LinkKind, origin: impl Into<String>) -> Self {
        Packet { offset, len, timestamp: None, link, link_type: link.pcap_link_type(), origin: origin.into(), record: None }
    }

    /// The packet as its capture labelled it, by LINKTYPE number.
    pub fn with_link_type(mut self, link_type: u32) -> Self {
        self.link_type = link_type;
        self
    }

    pub fn with_record(mut self, offset: usize, len: usize) -> Self {
        self.record = Some((offset, len));
        self
    }

    /// The bytes to remove when the packet is deleted: its container record
    /// if it has one, else the packet itself.
    pub fn removal_range(&self) -> (usize, usize) {
        self.record.unwrap_or((self.offset, self.len))
    }

    pub fn with_timestamp(mut self, timestamp: Option<f64>) -> Self {
        self.timestamp = timestamp;
        self
    }

    pub fn end(&self) -> usize {
        self.offset.saturating_add(self.len)
    }
}

/// Packets from one source.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PacketSet {
    pub packets: Vec<Packet>,
    /// Short name of the source, such as "pcap capture at 0x1000".
    pub name: String,
    /// A sentence about how the packets were found.
    pub description: String,
    /// Set when the source had more packets than [`MAX_PACKETS`].
    pub capped: bool,
    /// How to find the packets again after the document is edited.
    pub recipe: sources::Recipe,
}

impl PacketSet {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        PacketSet { packets: Vec::new(), name: name.into(), description: description.into(), capped: false, recipe: sources::Recipe::default() }
    }

    /// Add a packet. Returns false, and marks the set as capped, once the set
    /// is full; the caller should stop looking for more.
    pub fn push(&mut self, packet: Packet) -> bool {
        if self.packets.len() >= MAX_PACKETS {
            self.capped = true;
            return false;
        }
        self.packets.push(packet);
        true
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// A note for the user when packets were left out.
    pub fn cap_note(&self) -> Option<String> {
        self.capped.then(|| format!("Only the first {MAX_PACKETS} packets are listed; the rest of the source was left out."))
    }
}

/// Bytes as space-separated hex pairs, at most `max` of them, with an
/// ellipsis when there are more.
pub fn hex_preview(bytes: &[u8], max: usize) -> String {
    let mut text: Vec<String> = bytes.iter().take(max).map(|byte| format!("{byte:02x}")).collect();
    if bytes.len() > max {
        text.push("…".to_string());
    }
    text.join(" ")
}

/// Parse hex such as `DEADBEEF`, `de ad be ef` or `0xDEADBEEF`.
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let trimmed = text.trim();
    let without_prefix = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    let digits: String = without_prefix.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.is_empty() {
        return Err("no hex digits given".to_string());
    }
    if let Some(bad) = digits.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("'{bad}' is not a hex digit"));
    }
    if !digits.len().is_multiple_of(2) {
        return Err(format!("'{digits}' has an odd number of hex digits; each byte needs two"));
    }
    let bytes = (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).expect("checked to be hex digits"))
        .collect();
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_stops_accepting_packets_at_the_cap_and_says_so() {
        let mut set = PacketSet::new("test", "");
        for index in 0..MAX_PACKETS {
            assert!(set.push(Packet::new(index, 1, LinkKind::Unknown, "")));
        }
        assert!(set.cap_note().is_none());
        assert!(!set.push(Packet::new(0, 1, LinkKind::Unknown, "")));
        assert_eq!(set.len(), MAX_PACKETS);
        assert!(set.cap_note().expect("a note").contains("200000"));
    }

    #[test]
    fn link_kinds_map_to_and_from_pcap_link_types() {
        for kind in LinkKind::ALL {
            assert_eq!(LinkKind::from_pcap_link_type(kind.pcap_link_type()), kind);
        }
        assert_eq!(LinkKind::from_pcap_link_type(LINKTYPE_IPV6), LinkKind::RawIp);
        assert_eq!(LinkKind::from_pcap_link_type(LINKTYPE_RAW_IP_OLD), LinkKind::RawIp);
        assert_eq!(LinkKind::from_pcap_link_type(113), LinkKind::LinuxSll);
        assert_eq!(LinkKind::from_pcap_link_type(105), LinkKind::Ieee80211);
        assert_eq!(LinkKind::from_pcap_link_type(189), LinkKind::Unknown, "USB is not read");
    }

    #[test]
    fn hex_is_parsed_with_spaces_and_prefix_and_bad_input_is_explained() {
        assert_eq!(parse_hex("DEADBEEF"), Ok(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(parse_hex("0x0d 0a"), Ok(vec![0x0D, 0x0A]));
        assert!(parse_hex("abc").unwrap_err().contains("odd"));
        assert!(parse_hex("zz").unwrap_err().contains("'z'"));
        assert!(parse_hex("").is_err());
    }
}
