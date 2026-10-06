//! Frames of unknown format that are a protocol we can dissect.
//!
//! Frames split from a file, or taken from the protocol tool's message
//! framing, carry no link type and no ports, so nothing says they are DNS
//! messages or Modbus/TCP frames. [`FrameProtocol`] names a decoder to read
//! each frame with from its first byte.

/// What a frame of unknown format is decoded as, from its first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameProtocol {
    Ethernet,
    RawIp,
    Dns,
    /// DNS messages each after a two-byte length, as on TCP.
    DnsOverTcp,
    Snmp,
    Ntp,
    ModbusTcp,
    Mqtt,
    Tls,
    Dhcp,
    Tftp,
    /// TPKT, with the COTP TPDU inside and any S7comm header in it.
    Tpkt,
    /// The NetBIOS session service, with the SMB header inside.
    Nbss,
    Rtp,
    Rtcp,
    Http,
}

impl FrameProtocol {
    /// Every protocol, most specific first.
    pub const ALL: [FrameProtocol; 16] = [
        FrameProtocol::Ethernet,
        FrameProtocol::RawIp,
        FrameProtocol::Tpkt,
        FrameProtocol::Nbss,
        FrameProtocol::ModbusTcp,
        FrameProtocol::Tls,
        FrameProtocol::Snmp,
        FrameProtocol::Dhcp,
        FrameProtocol::Rtcp,
        FrameProtocol::Http,
        FrameProtocol::Ntp,
        FrameProtocol::Dns,
        FrameProtocol::DnsOverTcp,
        FrameProtocol::Mqtt,
        FrameProtocol::Tftp,
        FrameProtocol::Rtp,
    ];

    /// The name shown, as the protocol's layer is named.
    pub fn label(self) -> &'static str {
        match self {
            FrameProtocol::Ethernet => "Ethernet",
            FrameProtocol::RawIp => "Raw IP",
            FrameProtocol::Dns => "DNS",
            FrameProtocol::DnsOverTcp => "DNS with a length prefix",
            FrameProtocol::Snmp => "SNMP",
            FrameProtocol::Ntp => "NTP",
            FrameProtocol::ModbusTcp => "Modbus/TCP",
            FrameProtocol::Mqtt => "MQTT",
            FrameProtocol::Tls => "TLS",
            FrameProtocol::Dhcp => "DHCP",
            FrameProtocol::Tftp => "TFTP",
            FrameProtocol::Tpkt => "TPKT",
            FrameProtocol::Nbss => "NetBIOS Session Service",
            FrameProtocol::Rtp => "RTP",
            FrameProtocol::Rtcp => "RTCP",
            FrameProtocol::Http => "HTTP",
        }
    }

    /// The filter's name for the protocol, which a decoded frame lists.
    pub fn key(self) -> &'static str {
        match self {
            FrameProtocol::Ethernet => "eth",
            FrameProtocol::RawIp => "ip",
            FrameProtocol::Dns | FrameProtocol::DnsOverTcp => "dns",
            FrameProtocol::Snmp => "snmp",
            FrameProtocol::Ntp => "ntp",
            FrameProtocol::ModbusTcp => "modbus",
            FrameProtocol::Mqtt => "mqtt",
            FrameProtocol::Tls => "tls",
            FrameProtocol::Dhcp => "dhcp",
            FrameProtocol::Tftp => "tftp",
            FrameProtocol::Tpkt => "tpkt",
            FrameProtocol::Nbss => "nbss",
            FrameProtocol::Rtp => "rtp",
            FrameProtocol::Rtcp => "rtcp",
            FrameProtocol::Http => "http",
        }
    }

    /// Whether the frame starts a link layer rather than a message.
    pub fn is_link_layer(self) -> bool {
        matches!(self, FrameProtocol::Ethernet | FrameProtocol::RawIp)
    }
}

