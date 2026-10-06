//! A small filter language for the packet list.
//!
//! A filter is a list of space-separated terms, all of which must match:
//!
//! | Term | Matches packets that |
//! | --- | --- |
//! | `tcp`, `dns`, `arp`… | contain that protocol |
//! | `proto:dhcp` | contain that protocol, by our name or tshark's filter name |
//! | `port:53` | use port 53 at either end |
//! | `ip:10.0.0.2` | come from or go to that address |
//! | `len>100` (also `<`, `>=`, `<=`, `=`) | have that many bytes |
//! | `hex:DEADBEEF` | contain those bytes |
//! | anything else | mention the text in their summary (ignoring case) |

use std::fmt;
use std::net::IpAddr;

use super::dissect::Summary;
use super::flows::Flow;

/// Protocol names the filter knows; any other bare word is free text.
pub const PROTOCOL_NAMES: [&str; 18] =
    ["eth", "vlan", "arp", "ip", "ipv4", "ipv6", "icmp", "icmpv6", "tcp", "udp", "dns", "http", "ntp", "modbus", "mqtt", "data", "template", "payload"];

/// How a length is compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Comparison {
    Less,
    LessOrEqual,
    Equal,
    GreaterOrEqual,
    Greater,
}

impl Comparison {
    fn holds(self, value: usize, limit: usize) -> bool {
        match self {
            Comparison::Less => value < limit,
            Comparison::LessOrEqual => value <= limit,
            Comparison::Equal => value == limit,
            Comparison::GreaterOrEqual => value >= limit,
            Comparison::Greater => value > limit,
        }
    }
}

/// One term of a filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    Protocol(String),
    /// Any protocol name, ours or one tshark decoded.
    AnyProtocol(String),
    Port(u16),
    Address(IpAddr),
    Length(Comparison, usize),
    Bytes(Vec<u8>),
    /// Lower-case text looked for in the summary.
    Text(String),
}

/// Why a filter could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterError {
    /// The term at fault.
    pub term: String,
    pub reason: String,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'{}': {}", self.term, self.reason)
    }
}

impl std::error::Error for FilterError {}

/// A parsed filter. The empty filter matches everything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    pub terms: Vec<Term>,
}

/// What a filter looks at in one packet.
#[derive(Clone, Copy, Debug)]
pub struct FilterSubject<'a> {
    pub protocols: &'a [&'static str],
    /// Protocols tshark named, when the packet was decoded with it.
    pub tshark_protocols: &'a [String],
    pub flow: Option<&'a Flow>,
    pub summary: &'a Summary,
    /// The packet's bytes as read (possibly fewer than `len`).
    pub bytes: &'a [u8],
    pub len: usize,
}

impl Filter {
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    /// Whether every term matches the packet.
    pub fn matches(&self, subject: &FilterSubject<'_>) -> bool {
        self.terms.iter().all(|term| term_matches(term, subject))
    }
}

fn term_matches(term: &Term, subject: &FilterSubject<'_>) -> bool {
    match term {
        Term::Protocol(name) => subject.protocols.iter().any(|protocol| protocol == name),
        Term::AnyProtocol(name) => subject.protocols.iter().any(|protocol| protocol == name) || subject.tshark_protocols.iter().any(|protocol| protocol.eq_ignore_ascii_case(name)),
        Term::Port(port) => subject.flow.is_some_and(|flow| flow.source.port == Some(*port) || flow.destination.port == Some(*port)),
        Term::Address(address) => {
            let in_flow = subject.flow.is_some_and(|flow| flow.source.address == *address || flow.destination.address == *address);
            let text = address.to_string();
            in_flow || subject.summary.source == text || subject.summary.destination == text
        }
        Term::Length(comparison, limit) => comparison.holds(subject.len, *limit),
        Term::Bytes(needle) => !needle.is_empty() && subject.bytes.windows(needle.len()).any(|window| window == needle.as_slice()),
        Term::Text(text) => {
            let summary = subject.summary;
            [&summary.info, &summary.protocol, &summary.source, &summary.destination].iter().any(|field| field.to_lowercase().contains(text))
        }
    }
}

/// Parse a filter, explaining the first term that cannot be read.
pub fn parse_filter(text: &str) -> Result<Filter, FilterError> {
    let terms = text.split_whitespace().map(parse_term).collect::<Result<Vec<Term>, FilterError>>()?;
    Ok(Filter { terms })
}

fn error(term: &str, reason: impl Into<String>) -> FilterError {
    FilterError { term: term.to_string(), reason: reason.into() }
}

fn parse_term(term: &str) -> Result<Term, FilterError> {
    let lower = term.to_lowercase();
    if let Some(rest) = lower.strip_prefix("len") {
        return parse_length(term, rest);
    }
    if let Some((key, value)) = term.split_once(':')
        && !key.is_empty()
        && key.chars().all(|c| c.is_ascii_alphabetic())
    {
        return match key.to_lowercase().as_str() {
            "port" => value.parse::<u16>().map(Term::Port).map_err(|_| error(term, "a port is a number from 0 to 65535, such as port:53")),
            "ip" => value.parse::<IpAddr>().map(Term::Address).map_err(|_| error(term, "give an IPv4 or IPv6 address, such as ip:10.0.0.2")),
            "hex" => super::parse_hex(value).map(Term::Bytes).map_err(|reason| error(term, reason)),
            "proto" if !value.is_empty() => Ok(Term::AnyProtocol(value.to_lowercase())),
            "proto" => Err(error(term, "name a protocol, such as proto:dhcp")),
            other => Err(error(term, format!("'{other}:' is not a filter; use port:, ip:, proto:, hex: or len>"))),
        };
    }
    if PROTOCOL_NAMES.contains(&lower.as_str()) {
        return Ok(Term::Protocol(if lower == "payload" { "data".to_string() } else { lower }));
    }
    Ok(Term::Text(lower))
}

fn parse_length(term: &str, rest: &str) -> Result<Term, FilterError> {
    let operators = [(">=", Comparison::GreaterOrEqual), ("<=", Comparison::LessOrEqual), (">", Comparison::Greater), ("<", Comparison::Less), ("=", Comparison::Equal)];
    let Some((comparison, number)) = operators.iter().find_map(|(symbol, comparison)| rest.strip_prefix(symbol).map(|number| (*comparison, number))) else {
        // A word such as "length" that happens to start with "len" is free text.
        if rest.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
            return Ok(Term::Text(term.to_lowercase()));
        }
        return Err(error(term, "compare the length with >, <, >=, <= or =, such as len>100"));
    };
    number.parse::<usize>().map(|limit| Term::Length(comparison, limit)).map_err(|_| error(term, format!("'{number}' is not a whole number of bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::flows::{Endpoint, Transport};

    struct Example {
        protocols: Vec<&'static str>,
        tshark_protocols: Vec<String>,
        flow: Option<Flow>,
        summary: Summary,
        bytes: Vec<u8>,
    }

    impl Example {
        fn subject(&self) -> FilterSubject<'_> {
            FilterSubject {
                protocols: &self.protocols,
                tshark_protocols: &self.tshark_protocols,
                flow: self.flow.as_ref(),
                summary: &self.summary,
                bytes: &self.bytes,
                len: self.bytes.len(),
            }
        }
    }

    fn dns_packet() -> Example {
        Example {
            protocols: vec!["eth", "ip", "ipv4", "udp", "dns"],
            tshark_protocols: Vec::new(),
            flow: Some(Flow {
                transport: Transport::Udp,
                source: Endpoint { address: "10.0.0.2".parse().unwrap(), port: Some(40000) },
                destination: Endpoint { address: "10.0.0.1".parse().unwrap(), port: Some(53) },
                tcp_sequence: None,
            }),
            summary: Summary { source: "10.0.0.2".into(), destination: "10.0.0.1".into(), protocol: "DNS".into(), info: "Standard query 0xabcd A example.com".into() },
            bytes: [vec![0u8; 50], vec![0xDE, 0xAD, 0xBE, 0xEF], vec![0u8; 20]].concat(),
        }
    }

    fn matches(filter: &str, example: &Example) -> bool {
        parse_filter(filter).expect("a valid filter").matches(&example.subject())
    }

    #[test]
    fn protocol_and_port_terms_must_all_match() {
        let packet = dns_packet();
        assert!(matches("udp port:53", &packet));
        assert!(matches("DNS", &packet));
        assert!(!matches("tcp port:53", &packet));
        assert!(!matches("udp port:80", &packet));
        assert!(matches("", &packet), "the empty filter keeps everything");
    }

    #[test]
    fn length_comparisons_use_the_packet_length() {
        let packet = dns_packet();
        assert_eq!(packet.bytes.len(), 74);
        assert!(matches("len>60", &packet));
        assert!(!matches("len<60", &packet));
        assert!(matches("len>=74 len<=74 len=74", &packet));
    }

    #[test]
    fn hex_address_and_text_terms_look_inside_the_packet() {
        let packet = dns_packet();
        assert!(matches("hex:DEADBEEF", &packet));
        assert!(matches("hex:dead", &packet), "hex digits in either case");
        assert!(!matches("hex:CAFE", &packet));
        assert!(matches("ip:10.0.0.1", &packet));
        assert!(!matches("ip:10.0.0.3", &packet));
        assert!(matches("example.com", &packet));
        assert!(matches("QUERY", &packet), "text ignores case");
        assert!(!matches("response", &packet));
    }

    #[test]
    fn proto_matches_our_protocols_and_the_ones_tshark_decoded() {
        let mut packet = dns_packet();
        assert!(matches("proto:udp", &packet));
        assert!(!matches("proto:dhcp", &packet));
        packet.tshark_protocols = vec!["eth".to_string(), "ip".to_string(), "udp".to_string(), "dhcp".to_string()];
        assert!(matches("proto:DHCP", &packet));
        assert!(!matches("proto:snmp", &packet));
    }

    #[test]
    fn mistakes_are_explained_with_the_term_at_fault() {
        let cases = [("proto:", "name a protocol"), ("port:http", "port"), ("ip:10.0.0", "address"), ("hex:ABC", "odd"), ("len>lots", "whole number"), ("len!5", "compare"), ("size:5", "not a filter")];
        for (filter, expected) in cases {
            let error = parse_filter(&format!("udp {filter}")).expect_err(filter);
            assert_eq!(error.term, filter);
            assert!(error.to_string().contains(expected), "{filter}: {error}");
        }
        assert_eq!(parse_filter("length").map(|f| f.terms), Ok(vec![Term::Text("length".to_string())]));
    }
}
