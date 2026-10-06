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
//! | `ip.ttl==64` (also `!=`, `<`, `<=`, `>`, `>=`, `~` for "contains") | have a field, by its Wireshark name, with that value |
//! | `dns.qry.name` | have that field at all |
//! | anything else | mention the text in their summary (ignoring case) |
//!
//! Wireshark field names reach our own fields through the reference notes,
//! which give each field its Wireshark name, and tshark's fields directly
//! when a packet was decoded with tshark.

use std::fmt;
use std::net::IpAddr;

use super::dissect::{Dissection, Summary};
use super::flows::Flow;
use crate::plugin::Field;
use crate::reference;

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

/// How a field's value is tested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldTest {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
    Contains,
}

/// Operators of field terms, longest first so `>=` is not read as `>`.
const FIELD_OPERATORS: [(&str, FieldTest); 7] = [
    ("==", FieldTest::Equal),
    ("!=", FieldTest::NotEqual),
    (">=", FieldTest::GreaterOrEqual),
    ("<=", FieldTest::LessOrEqual),
    (">", FieldTest::Greater),
    ("<", FieldTest::Less),
    ("~", FieldTest::Contains),
];

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
    /// A field by its Wireshark display-filter name, such as `ip.ttl`, and
    /// the test its value must pass (none: the field need only be there).
    Field { name: String, test: Option<(FieldTest, String)> },
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

/// Gives the values of a field by its Wireshark name, such as `ip.ttl`.
pub type FieldValues<'a> = dyn Fn(&str) -> Vec<String> + 'a;

/// What a filter looks at in one packet.
#[derive(Clone, Copy)]
pub struct FilterSubject<'a> {
    pub protocols: &'a [&'static str],
    /// Protocols tshark named, when the packet was decoded with it.
    pub tshark_protocols: &'a [String],
    pub flow: Option<&'a Flow>,
    pub summary: &'a Summary,
    /// The packet's bytes as read (possibly fewer than `len`).
    pub bytes: &'a [u8],
    pub len: usize,
    /// The values of a field, by its Wireshark name, for field terms; see
    /// [`wireshark_values`]. Without it field terms match nothing.
    pub fields: Option<&'a FieldValues<'a>>,
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
        Term::Field { name, test } => {
            let values = subject.fields.map(|values_of| values_of(name)).unwrap_or_default();
            match test {
                None => !values.is_empty(),
                Some((FieldTest::NotEqual, wanted)) => !values.is_empty() && !values.iter().any(|value| value_equals(value, wanted)),
                Some((test, wanted)) => values.iter().any(|value| value_passes(value, *test, wanted)),
            }
        }
        Term::Text(text) => {
            let summary = subject.summary;
            [&summary.info, &summary.protocol, &summary.source, &summary.destination].iter().any(|field| field.to_lowercase().contains(text))
        }
    }
}

fn value_passes(value: &str, test: FieldTest, wanted: &str) -> bool {
    match test {
        FieldTest::Equal => value_equals(value, wanted),
        FieldTest::NotEqual => !value_equals(value, wanted),
        FieldTest::Contains => value.to_lowercase().contains(&wanted.to_lowercase()),
        ordering => match (leading_number(value), leading_number(wanted)) {
            (Some(value), Some(wanted)) => match ordering {
                FieldTest::Less => value < wanted,
                FieldTest::LessOrEqual => value <= wanted,
                FieldTest::Greater => value > wanted,
                _ => value >= wanted,
            },
            _ => false,
        },
    }
}

/// Values are shown with extra words ("6 (TCP)", "0x0800 IPv4"), so a value
/// equals what was asked for when the whole of it does, its first word does,
/// or the two are the same number written in decimal or hex.
fn value_equals(value: &str, wanted: &str) -> bool {
    let first_word = value.split([' ', '(', ',']).next().unwrap_or("");
    value.eq_ignore_ascii_case(wanted)
        || first_word.eq_ignore_ascii_case(wanted)
        || leading_number(value).is_some_and(|number| leading_number(wanted) == Some(number))
}

/// The number a value starts with, in decimal or `0x` hex.
fn leading_number(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        let digits: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
        return u64::from_str_radix(&digits, 16).ok();
    }
    let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
    let rest = &text[digits.len()..];
    // "10.0.0.1" and "3.5" are not numbers to compare.
    if rest.starts_with('.') {
        return None;
    }
    digits.parse().ok()
}

/// Every value in `dissection` of the field Wireshark calls `name`: from
/// tshark's layers by the names tshark gave them, and from ours by the names
/// the reference notes give our fields.
pub fn wireshark_values(dissection: &Dissection, name: &str) -> Vec<String> {
    let mut values = Vec::new();
    for (index, layer) in dissection.layers.iter().enumerate() {
        match dissection.wireshark_names(index) {
            Some(names) => collect_tshark_values(&layer.fields, &mut Vec::new(), names, name, &mut values),
            None => {
                let Some(notes) = reference::lookup(&layer.name) else { continue };
                collect_noted_values(&layer.fields, notes, name, &mut values);
            }
        }
    }
    values
}

fn collect_tshark_values(fields: &[Field], path: &mut Vec<usize>, names: &super::dissect::WiresharkNames, name: &str, values: &mut Vec<String>) {
    for (index, field) in fields.iter().enumerate() {
        path.push(index);
        if names.field(path).is_some_and(|field_name| field_name.eq_ignore_ascii_case(name)) {
            values.push(field.value.clone());
        }
        collect_tshark_values(&field.children, path, names, name, values);
        path.pop();
    }
}

fn collect_noted_values(fields: &[Field], notes: &reference::FormatReference, name: &str, values: &mut Vec<String>) {
    for field in fields {
        if notes.field(&field.name).and_then(|note| note.wireshark.as_deref()).is_some_and(|field_name| field_name.eq_ignore_ascii_case(name)) {
            values.push(field.value.clone());
        }
        collect_noted_values(&field.children, notes, name, values);
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
    if let Some(field) = parse_field(term)? {
        return Ok(field);
    }
    Ok(Term::Text(lower))
}

/// A Wireshark field term such as `ip.ttl>=64` or `dns.qry.name`, if the
/// term is one. A dotted word without an operator is a field only when it
/// starts with a protocol the notes know, so "example.com" stays text.
fn parse_field(term: &str) -> Result<Option<Term>, FilterError> {
    let operator = FIELD_OPERATORS.iter().filter_map(|&(symbol, test)| term.find(symbol).map(|at| (at, symbol, test))).min_by_key(|&(at, symbol, _)| (at, std::cmp::Reverse(symbol.len())));
    let name = operator.map_or(term, |(at, _, _)| &term[..at]).to_lowercase();
    let looks_like_field = name.contains('.')
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && name.split('.').all(|part| !part.is_empty());
    if !looks_like_field {
        return Ok(None);
    }
    let protocol = name.split('.').next().unwrap_or_default();
    match operator {
        None if reference::library().by_wireshark(protocol).is_none() => Ok(None),
        None => Ok(Some(Term::Field { name, test: None })),
        Some((at, symbol, test)) => {
            let wanted = term[at + symbol.len()..].trim_matches('"');
            if wanted.is_empty() {
                return Err(error(term, format!("give a value after {symbol}, such as ip.ttl==64")));
            }
            let ordering = matches!(test, FieldTest::Less | FieldTest::LessOrEqual | FieldTest::Greater | FieldTest::GreaterOrEqual);
            if ordering && leading_number(wanted).is_none() {
                return Err(error(term, format!("{symbol} compares numbers; '{wanted}' is not one")));
            }
            Ok(Some(Term::Field { name, test: Some((test, wanted.to_string())) }))
        }
    }
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
                fields: None,
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

    #[test]
    fn wireshark_field_names_filter_on_our_own_fields_through_the_notes() {
        use crate::packets::{LinkKind, dissect};
        // An IPv4/UDP datagram with a TTL of 64 to port 53.
        let mut packet = vec![0x45, 0, 0, 36, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1];
        packet.extend_from_slice(&[0x9c, 0x40, 0, 53, 0, 16, 0, 0]);
        packet.extend_from_slice(b"anything");
        let dissection = dissect(&packet, LinkKind::RawIp);
        let values = |name: &str| wireshark_values(&dissection, name);
        let example = dns_packet();
        let subject = FilterSubject { fields: Some(&values), ..example.subject() };
        let holds = |filter: &str| parse_filter(filter).expect(filter).matches(&subject);
        assert!(holds("ip.ttl==64"), "{:?}", values("ip.ttl"));
        assert!(holds("ip.ttl>=60 ip.ttl<65 udp.dstport==53"));
        assert!(!holds("ip.ttl==63"));
        assert!(holds("ip.ttl!=63"));
        assert!(holds("ip.src==10.0.0.2"));
        assert!(holds("ip.ttl"), "a bare field name asks only that the field is there");
        assert!(!holds("tcp.srcport"), "no TCP here");
    }

    #[test]
    fn field_terms_are_told_apart_from_text_and_explained_when_wrong() {
        assert_eq!(parse_filter("ip.ttl>=64").unwrap().terms, vec![Term::Field { name: "ip.ttl".into(), test: Some((FieldTest::GreaterOrEqual, "64".into())) }]);
        assert_eq!(parse_filter("dns.qry.name~example").unwrap().terms, vec![Term::Field { name: "dns.qry.name".into(), test: Some((FieldTest::Contains, "example".into())) }]);
        assert_eq!(parse_filter("example.com").unwrap().terms, vec![Term::Text("example.com".into())], "not a protocol the notes know");
        assert_eq!(parse_filter("10.0.0.1").unwrap().terms, vec![Term::Text("10.0.0.1".into())]);
        assert!(parse_filter("ip.ttl==").unwrap_err().to_string().contains("give a value"));
        assert!(parse_filter("ip.ttl>lots").unwrap_err().to_string().contains("compares numbers"));
    }

    #[test]
    fn values_match_by_whole_text_first_word_or_number() {
        assert!(value_equals("6 (TCP)", "6"));
        assert!(value_equals("0x0800 (IPv4)", "2048"));
        assert!(value_equals("example.com", "EXAMPLE.COM"));
        assert!(!value_equals("10.0.0.1", "10"));
        assert!(value_passes("1500 bytes", FieldTest::Greater, "1000"));
        assert!(value_passes("Standard query", FieldTest::Contains, "QUERY"));
    }
}
