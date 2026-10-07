//! A small filter language for the packet list.
//!
//! A filter is an expression of terms. Terms side by side must all match,
//! as do terms joined by `and` (or `&&`); `or` (or `||`) keeps packets that
//! match either side, `not` (or `!`) turns a term or a bracketed group
//! round, and brackets group: `dns and not (ip.src==10.0.0.1 or len>200)`.
//!
//! | Term | Matches packets that |
//! | --- | --- |
//! | `tcp`, `dns`, `arp`… | contain that protocol |
//! | `proto:dhcp` | contain that protocol, by our name or tshark's filter name |
//! | `port:53` | use port 53 at either end |
//! | `ip:10.0.0.2` | come from or go to that address |
//! | `len>100` (also `<`, `>=`, `<=`, `==`, `!=`) | have that many bytes |
//! | `hex:DEADBEEF` | contain those bytes |
//! | `ip.ttl==64` (also `!=`, `<`, `<=`, `>`, `>=`, `~` for "contains") | have a field, by its Wireshark name, with that value |
//! | `template.type==60`, or `type==60` | have a field of the set's template with that value |
//! | `dns.qry.name` | have that field at all |
//! | `"standard query"`, or any other word | mention the text in their summary (ignoring case) |
//!
//! Wireshark field names reach our own fields through the reference notes,
//! which give each field its Wireshark name, and tshark's fields directly
//! when a packet was decoded with tshark. A few names are worked out from
//! other fields, as Wireshark has them: `tcp.port`, `udp.port` and
//! `ip.addr` (either end), the bits of `dns.flags`, the parts of an HTTP
//! request or status line, and `http.` followed by any header's name.
//!
//! A value matches a field's when the two are the same text, the field's
//! first word, the name or number in its brackets ("TXT (16)" is both `TXT`
//! and `16`) or the same number written in decimal or hex.
//!
//! [`parse_filter`] reads a filter; [`Filter::resolve`] then checks its
//! field names against those a set has ([`KnownFields`]), so a mistyped
//! name is an error that suggests the names it was close to, rather than a
//! filter that quietly keeps nothing.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use super::dissect::{Dissection, Summary, WiresharkNames};
use super::flows::Flow;
use crate::plugin::Field;
use crate::reference;

/// Protocol names the filter knows; any other bare word is free text.
pub const PROTOCOL_NAMES: [&str; 18] =
    ["eth", "vlan", "arp", "ip", "ipv4", "ipv6", "icmp", "icmpv6", "tcp", "udp", "dns", "http", "ntp", "modbus", "mqtt", "data", "template", "payload"];

/// What template fields are called in a filter: `template.<name>`.
pub const TEMPLATE_PREFIX: &str = "template.";

/// Names worked out from other fields ([`derived_values`]), as Wireshark
/// names them.
const DERIVED_NAMES: [&str; 22] = [
    "tcp.port",
    "udp.port",
    "ip.addr",
    "ipv6.addr",
    "dns.flags.response",
    "dns.flags.opcode",
    "dns.flags.authoritative",
    "dns.flags.truncated",
    "dns.flags.recdesired",
    "dns.flags.recavail",
    "dns.flags.z",
    "dns.flags.authenticated",
    "dns.flags.checkdisable",
    "dns.flags.rcode",
    "http.request",
    "http.response",
    "http.request.method",
    "http.request.uri",
    "http.request.version",
    "http.response.code",
    "http.response.phrase",
    "http.response.version",
];

/// Most close names an unknown field's error suggests.
const MAX_SUGGESTIONS: usize = 5;

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

impl FieldTest {
    fn is_ordering(self) -> bool {
        matches!(self, FieldTest::Less | FieldTest::LessOrEqual | FieldTest::Greater | FieldTest::GreaterOrEqual)
    }
}

/// Comparison operators, longest first so `>=` is not read as `>`; a single
/// `=` is taken for `==`.
const COMPARISONS: [(&str, FieldTest); 8] = [
    ("==", FieldTest::Equal),
    ("!=", FieldTest::NotEqual),
    (">=", FieldTest::GreaterOrEqual),
    ("<=", FieldTest::LessOrEqual),
    (">", FieldTest::Greater),
    ("<", FieldTest::Less),
    ("~", FieldTest::Contains),
    ("=", FieldTest::Equal),
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
    /// A field by its Wireshark display-filter name, such as `ip.ttl`, or
    /// a template field as `template.<name>`, and the test its value must
    /// pass (none: the field need only be there).
    Field { name: String, test: Option<(FieldTest, String)> },
    /// Lower-case text looked for in the summary.
    Text(String),
}

/// A filter's terms, combined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expression {
    Term(Term),
    Not(Box<Expression>),
    /// Every part must match.
    All(Vec<Expression>),
    /// Some part must match.
    Any(Vec<Expression>),
}

impl Expression {
    fn matches(&self, subject: &FilterSubject<'_>) -> bool {
        match self {
            Expression::Term(term) => term_matches(term, subject),
            Expression::Not(inner) => !inner.matches(subject),
            Expression::All(parts) => parts.iter().all(|part| part.matches(subject)),
            Expression::Any(parts) => parts.iter().any(|part| part.matches(subject)),
        }
    }

    fn terms<'a>(&'a self, out: &mut Vec<&'a Term>) {
        match self {
            Expression::Term(term) => out.push(term),
            Expression::Not(inner) => inner.terms(out),
            Expression::All(parts) | Expression::Any(parts) => parts.iter().for_each(|part| part.terms(out)),
        }
    }

    /// The same expression with every field term passed through `resolve`.
    fn map_fields(self, resolve: &mut impl FnMut(String, Option<(FieldTest, String)>) -> Result<Term, FilterError>) -> Result<Expression, FilterError> {
        Ok(match self {
            Expression::Term(Term::Field { name, test }) => Expression::Term(resolve(name, test)?),
            Expression::Term(term) => Expression::Term(term),
            Expression::Not(inner) => Expression::Not(Box::new(inner.map_fields(resolve)?)),
            Expression::All(parts) => Expression::All(parts.into_iter().map(|part| part.map_fields(resolve)).collect::<Result<_, _>>()?),
            Expression::Any(parts) => Expression::Any(parts.into_iter().map(|part| part.map_fields(resolve)).collect::<Result<_, _>>()?),
        })
    }
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
    pub expression: Option<Expression>,
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
        self.expression.is_none()
    }

    /// Whether the packet passes the filter.
    pub fn matches(&self, subject: &FilterSubject<'_>) -> bool {
        self.expression.as_ref().is_none_or(|expression| expression.matches(subject))
    }

    /// Every term, in the order written.
    pub fn terms(&self) -> Vec<&Term> {
        let mut terms = Vec::new();
        if let Some(expression) = &self.expression {
            expression.terms(&mut terms);
        }
        terms
    }

    /// Whether some term asks for a field, so packets must be dissected
    /// with their fields to be filtered.
    pub fn asks_for_fields(&self) -> bool {
        self.terms().iter().any(|term| matches!(term, Term::Field { .. }))
    }

    /// Check every field name against `known`: a bare name (`type==60`)
    /// becomes the template field it names, and a name the set cannot have
    /// is an error that lists the close names it does have.
    pub fn resolve(self, known: &KnownFields) -> Result<Filter, FilterError> {
        let Some(expression) = self.expression else { return Ok(self) };
        let expression = expression.map_fields(&mut |name, test| {
            let shown = shown_term(&name, test.as_ref());
            let name = known.field_name(&name).map_err(|reason| error(&shown, reason))?;
            Ok(Term::Field { name, test })
        })?;
        Ok(Filter { expression: Some(expression) })
    }
}

/// A field term as it was written, for errors.
fn shown_term(name: &str, test: Option<&(FieldTest, String)>) -> String {
    match test {
        None => name.to_string(),
        Some((test, value)) => {
            let symbol = COMPARISONS.iter().find(|(_, candidate)| candidate == test).map_or("==", |(symbol, _)| symbol);
            format!("{name}{symbol}{value}")
        }
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
        ordering => match (value_number(value), leading_number(wanted)) {
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

/// Values are shown with extra words ("6 (TCP)", "0x0800 IPv4", "TXT (16)"),
/// so a value equals what was asked for when the whole of it does, its
/// first word does, what is in its brackets does, or the two are the same
/// number written in decimal or hex. `true` and `false` are 1 and 0.
fn value_equals(value: &str, wanted: &str) -> bool {
    let wanted = match wanted.to_ascii_lowercase().as_str() {
        "true" => "1",
        "false" => "0",
        _ => wanted,
    };
    let first_word = value.split([' ', '(', ',']).next().unwrap_or("");
    let wanted_number = leading_number(wanted).filter(|_| is_number(wanted));
    value.eq_ignore_ascii_case(wanted)
        || first_word.eq_ignore_ascii_case(wanted)
        || bracketed(value).any(|inner| inner.eq_ignore_ascii_case(wanted))
        || wanted_number.is_some_and(|number| leading_number(value) == Some(number) || bracketed(value).any(|inner| is_number(inner) && leading_number(inner) == Some(number)))
}

/// What a value holds in brackets: "TXT (16)" holds 16, and "60 (0x3C)
/// (unlock)" holds 0x3C and unlock.
fn bracketed(value: &str) -> impl Iterator<Item = &str> {
    value.split('(').skip(1).filter_map(|part| part.split_once(')').map(|(inner, _)| inner.trim()))
}

/// The number a value stands for: the one it starts with, or else the
/// first in its brackets.
fn value_number(value: &str) -> Option<u64> {
    leading_number(value).or_else(|| bracketed(value).find(|inner| is_number(inner)).and_then(leading_number))
}

/// Whether the whole of `text` is one number.
fn is_number(text: &str) -> bool {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()),
        None => !text.is_empty() && text.chars().all(|c| c.is_ascii_digit()),
    }
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

// ---------------------------------------------------------------------------
// Field values
// ---------------------------------------------------------------------------

/// One value of a field, and where its bytes are in the packet when it has
/// bytes of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldMatch {
    pub value: String,
    /// `(offset, len)` from the packet's first byte.
    pub span: Option<(usize, usize)>,
}

/// Every value in `dissection` of the field Wireshark calls `name`: from
/// tshark's layers by the names tshark gave them, from ours by the names
/// the reference notes give our fields, from the template's fields for
/// `template.<name>`, and otherwise worked out from other fields.
pub fn wireshark_values(dissection: &Dissection, name: &str) -> Vec<String> {
    field_matches(dissection, name).into_iter().map(|found| found.value).collect()
}

/// [`wireshark_values`] with where each value's bytes are.
pub fn field_matches(dissection: &Dissection, name: &str) -> Vec<FieldMatch> {
    let name = name.trim().to_lowercase();
    if let Some(path) = name.strip_prefix(TEMPLATE_PREFIX) {
        return template_matches(dissection, path);
    }
    let mut found = named_matches(dissection, &name);
    // tshark gives a flag as words ("Message is a query"), so the number
    // worked out from the flags word is offered as well.
    if found.is_empty() || DERIVED_NAMES.contains(&name.as_str()) {
        found.extend(derived_matches(dissection, &name));
    }
    found
}

/// Values of a field named by tshark or by the notes.
fn named_matches(dissection: &Dissection, name: &str) -> Vec<FieldMatch> {
    let mut found = Vec::new();
    for (index, layer) in dissection.layers.iter().enumerate() {
        match dissection.wireshark_names(index) {
            Some(names) => collect_tshark(&layer.fields, &mut Vec::new(), names, name, &mut found),
            None => {
                let Some(notes) = reference::lookup(&layer.name) else { continue };
                collect_noted(&layer.fields, notes, name, &mut found);
            }
        }
    }
    found
}

fn matched(field: &Field) -> FieldMatch {
    FieldMatch { value: field.value.clone(), span: Some((field.offset, field.len)) }
}

fn collect_tshark(fields: &[Field], path: &mut Vec<usize>, names: &WiresharkNames, name: &str, found: &mut Vec<FieldMatch>) {
    for (index, field) in fields.iter().enumerate() {
        path.push(index);
        if names.field(path).is_some_and(|field_name| field_name.eq_ignore_ascii_case(name)) {
            found.push(matched(field));
        }
        collect_tshark(&field.children, path, names, name, found);
        path.pop();
    }
}

fn collect_noted(fields: &[Field], notes: &reference::FormatReference, name: &str, found: &mut Vec<FieldMatch>) {
    for field in fields {
        if notes.field(&field.name).and_then(|note| note.wireshark.as_deref()).is_some_and(|field_name| field_name.eq_ignore_ascii_case(name)) {
            found.push(matched(field));
        }
        collect_noted(&field.children, notes, name, found);
    }
}

/// The layer a template decoded, by the name the dissector gives it.
fn is_template_layer(name: &str) -> bool {
    name.ends_with("(template)")
}

/// Values of the template field at `path`: a leaf's name (`type`) or its
/// dotted path from the record (`header.type`), without regard to case.
fn template_matches(dissection: &Dissection, path: &str) -> Vec<FieldMatch> {
    let mut found = Vec::new();
    for layer in dissection.layers.iter().filter(|layer| is_template_layer(&layer.name)) {
        visit_template_fields(&layer.fields, "", &mut |dotted, field| {
            let leaf = dotted.rsplit('.').next().unwrap_or(dotted);
            if dotted.eq_ignore_ascii_case(path) || leaf.eq_ignore_ascii_case(path) {
                found.push(matched(field));
            }
        });
    }
    found
}

/// Call `visit` with every template field and its dotted path.
fn visit_template_fields(fields: &[Field], prefix: &str, visit: &mut impl FnMut(&str, &Field)) {
    for field in fields {
        let dotted = if prefix.is_empty() { field.name.clone() } else { format!("{prefix}.{}", field.name) };
        visit(&dotted, field);
        visit_template_fields(&field.children, &dotted, visit);
    }
}

/// Values worked out from other fields, as Wireshark has them.
fn derived_matches(dissection: &Dissection, name: &str) -> Vec<FieldMatch> {
    let either = |first: &str, second: &str| [named_matches(dissection, first), named_matches(dissection, second)].concat();
    match name {
        "tcp.port" => either("tcp.srcport", "tcp.dstport"),
        "udp.port" => either("udp.srcport", "udp.dstport"),
        "ip.addr" => either("ip.src", "ip.dst"),
        "ipv6.addr" => either("ipv6.src", "ipv6.dst"),
        _ if name.starts_with("dns.flags.") => dns_flag(dissection, &name["dns.flags.".len()..]),
        "http.request" => named_matches(dissection, "http.request.line"),
        "http.response" => named_matches(dissection, "http.response.line"),
        "http.request.method" => line_part(dissection, "http.request.line", 0),
        "http.request.uri" => line_part(dissection, "http.request.line", 1),
        "http.request.version" => line_part(dissection, "http.request.line", 2),
        "http.response.version" => line_part(dissection, "http.response.line", 0),
        "http.response.code" => line_part(dissection, "http.response.line", 1),
        "http.response.phrase" => line_part(dissection, "http.response.line", 2),
        _ if name.starts_with("http.") => http_header(dissection, &name["http.".len()..]),
        _ => Vec::new(),
    }
}

/// A bit (or bits) of the DNS flags word, as a number.
fn dns_flag(dissection: &Dissection, flag: &str) -> Vec<FieldMatch> {
    let (shift, mask) = match flag {
        "response" => (15, 1),
        "opcode" => (11, 0xF),
        "authoritative" => (10, 1),
        "truncated" => (9, 1),
        "recdesired" => (8, 1),
        "recavail" => (7, 1),
        "z" => (6, 1),
        "authenticated" => (5, 1),
        "checkdisable" => (4, 1),
        "rcode" => (0, 0xF),
        _ => return Vec::new(),
    };
    named_matches(dissection, "dns.flags")
        .into_iter()
        .filter_map(|flags| Some(FieldMatch { value: ((leading_number(&flags.value)? >> shift) & mask).to_string(), span: flags.span }))
        .collect()
}

/// Word `part` of an HTTP request or status line; the status line's
/// phrase is everything after the code.
fn line_part(dissection: &Dissection, line: &str, part: usize) -> Vec<FieldMatch> {
    named_matches(dissection, line)
        .into_iter()
        .filter_map(|found| {
            let mut words = found.value.splitn(3, ' ');
            let value = words.nth(part)?.to_string();
            Some(FieldMatch { value, span: found.span })
        })
        .collect()
}

/// An HTTP header of ours by Wireshark's way of naming headers: lower case,
/// with `_` for `-` (`http.content_encoding`, `http.user_agent`).
fn http_header(dissection: &Dissection, wanted: &str) -> Vec<FieldMatch> {
    let mut found = Vec::new();
    for (index, layer) in dissection.layers.iter().enumerate() {
        if dissection.is_from_tshark(index) || layer.name != "HTTP" {
            continue;
        }
        for headers in layer.fields.iter().filter(|field| field.name == "Headers") {
            for header in &headers.children {
                if header.name.to_lowercase().replace('-', "_") == wanted {
                    found.push(matched(header));
                }
            }
        }
    }
    found
}

/// A packet's value of a field as a key to sort by: its first value, as a
/// number when it is one ("17", "0x3c (unlock)", "TXT (16)") and as text
/// otherwise. Numbers come before text, and packets without the field last.
pub fn sort_key(values: &[String]) -> SortKey {
    let Some(value) = values.first() else { return SortKey::Missing };
    let first_word = value.split([' ', '(', ',']).next().unwrap_or("");
    let number = if is_number(first_word) { leading_number(first_word) } else { bracketed(value).find(|inner| is_number(inner)).and_then(leading_number) };
    match number {
        Some(number) => SortKey::Number(number),
        None => SortKey::Text(value.to_lowercase()),
    }
}

/// See [`sort_key`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SortKey {
    Number(u64),
    Text(String),
    Missing,
}

// ---------------------------------------------------------------------------
// Known field names
// ---------------------------------------------------------------------------

/// The field names a set's packets can have, beyond the ones every set
/// has (those the reference notes give and those worked out from them).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KnownFields {
    /// The template's fields, by leaf name and by dotted path.
    pub template: BTreeSet<String>,
    /// Names tshark gave the fields of the packets it decoded.
    pub tshark: BTreeSet<String>,
    /// Protocols tshark decoded, whose fields are taken on trust.
    pub tshark_protocols: BTreeSet<String>,
}

impl KnownFields {
    /// What `dissections` hold: their template fields and the fields tshark named.
    pub fn of<'a>(dissections: impl IntoIterator<Item = &'a Dissection>) -> KnownFields {
        let mut known = KnownFields::default();
        for dissection in dissections {
            known.add(dissection);
        }
        known
    }

    pub fn add(&mut self, dissection: &Dissection) {
        for (index, layer) in dissection.layers.iter().enumerate() {
            if let Some(names) = dissection.wireshark_names(index) {
                self.tshark.extend(names.fields.iter().map(|(_, name)| name.to_lowercase()));
                self.tshark_protocols.insert(names.protocol.to_lowercase());
            } else if is_template_layer(&layer.name) {
                visit_template_fields(&layer.fields, "", &mut |dotted, _| {
                    let dotted = dotted.to_lowercase();
                    if let Some(leaf) = dotted.rsplit('.').next() {
                        self.template.insert(leaf.to_string());
                    }
                    self.template.insert(dotted);
                });
            }
        }
        self.tshark_protocols.extend(dissection.tshark_protocols.iter().map(|protocol| protocol.to_lowercase()));
    }

    /// The name a field means (a bare name is the template's field), or
    /// why it means none.
    pub fn field_name(&self, name: &str) -> Result<String, String> {
        let name = name.trim().to_lowercase();
        let name = name.as_str();
        if let Some(path) = name.strip_prefix(TEMPLATE_PREFIX) {
            if self.template.contains(path) {
                return Ok(name.to_string());
            }
            if self.template.is_empty() {
                return Err("the packets have no template fields; choose a template with Decode as (packets.decode_as) first".to_string());
            }
            return Err(format!("the template has no field '{path}'{}", suggest(path, self.template.iter().map(String::as_str))));
        }
        if !name.contains('.') {
            if self.template.contains(name) {
                return Ok(format!("{TEMPLATE_PREFIX}{name}"));
            }
            let close = suggest(name, self.template.iter().map(String::as_str).chain(["len"]));
            let hint = if self.template.is_empty() { "; a template's fields are named template.<name> once a template decodes the packets" } else { "" };
            return Err(format!("'{name}' is not a field{close}{hint}"));
        }
        if self.is_known(name) {
            return Ok(name.to_string());
        }
        let wireshark = known_wireshark_names();
        let names = wireshark.iter().map(String::as_str).chain(DERIVED_NAMES).chain(self.tshark.iter().map(String::as_str)).chain(self.template.iter().map(String::as_str));
        Err(format!("there is no field called '{name}'{}", suggest(name, names)))
    }

    fn is_known(&self, name: &str) -> bool {
        let protocol = name.split('.').next().unwrap_or_default();
        DERIVED_NAMES.contains(&name)
            || name.starts_with("http.")
            || self.tshark.contains(name)
            || self.tshark_protocols.contains(protocol)
            || known_wireshark_names().iter().any(|known| known == name)
    }
}

/// Every Wireshark field name the reference notes give, lower case.
fn known_wireshark_names() -> Vec<String> {
    let mut names = Vec::new();
    for entry in reference::library().entries() {
        names.extend(entry.wireshark.iter().map(|name| name.to_lowercase()));
        names.extend(entry.fields.iter().filter_map(|field| field.wireshark.as_ref()).map(|name| name.to_lowercase()));
    }
    names
}

/// "; did you mean …?" with the names closest to `wanted`, or nothing when
/// none is close.
fn suggest<'a>(wanted: &str, names: impl IntoIterator<Item = &'a str>) -> String {
    let wanted = wanted.to_lowercase();
    let wanted_leaf = wanted.rsplit('.').next().unwrap_or(&wanted).to_string();
    let mut scored: Vec<(usize, &str)> = names
        .into_iter()
        .filter_map(|name| {
            let distance = edit_distance(&wanted, name);
            let leaf = name.rsplit('.').next().unwrap_or(name);
            let shares_leaf = wanted_leaf.len() >= 3 && (leaf.contains(&wanted_leaf) || wanted_leaf.contains(leaf) && leaf.len() >= 3);
            let close = distance <= (wanted.len() / 3).max(2);
            (close || shares_leaf).then_some((if close { distance } else { distance + wanted.len() }, name))
        })
        .collect();
    scored.sort();
    scored.dedup_by(|a, b| a.1 == b.1);
    let close: Vec<&str> = scored.into_iter().take(MAX_SUGGESTIONS).map(|(_, name)| name).collect();
    if close.is_empty() { String::new() } else { format!("; did you mean {}?", close.join(", ")) }
}

/// Levenshtein distance between two short names.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (i, &left) in a.iter().enumerate() {
        let mut current = vec![i + 1];
        for (j, &right) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(left != right);
            current.push(substitution.min(previous[j + 1] + 1).min(current[j] + 1));
        }
        previous = current;
    }
    previous[b.len()]
}

// ---------------------------------------------------------------------------
// Reading a filter
// ---------------------------------------------------------------------------

/// A piece of a filter's text, with where it is.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    /// Text in double quotes.
    Quoted(String),
    Compare(FieldTest),
    And,
    Or,
    Not,
    Open,
    Close,
}

/// Cut `text` into tokens, each with its byte range.
fn tokenise(text: &str) -> Result<Vec<(Token, usize, usize)>, FilterError> {
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let Some(first) = rest.chars().next() else { break };
        if first.is_whitespace() {
            at += first.len_utf8();
            continue;
        }
        let (token, len) = if first == '(' {
            (Token::Open, 1)
        } else if first == ')' {
            (Token::Close, 1)
        } else if rest.starts_with("&&") {
            (Token::And, 2)
        } else if rest.starts_with("||") {
            (Token::Or, 2)
        } else if let Some((symbol, test)) = COMPARISONS.iter().find(|(symbol, _)| rest.starts_with(symbol)) {
            (Token::Compare(*test), symbol.len())
        } else if first == '!' {
            (Token::Not, 1)
        } else if first == '"' {
            let (quoted, len) = read_quoted(rest).ok_or_else(|| error(rest, "a quoted text has no closing \""))?;
            (Token::Quoted(quoted), len)
        } else {
            let len = word_len(rest);
            let word = &rest[..len];
            let token = match word.to_ascii_lowercase().as_str() {
                "and" => Token::And,
                "or" => Token::Or,
                "not" => Token::Not,
                _ => Token::Word(word.to_string()),
            };
            (token, len)
        };
        tokens.push((token, at, at + len));
        at += len;
    }
    Ok(tokens)
}

/// How long the word at the start of `text` is: up to a space, a bracket,
/// or an operator.
fn word_len(text: &str) -> usize {
    let mut len = 0;
    for (at, c) in text.char_indices() {
        let rest = &text[at..];
        let operator = rest.starts_with("&&") || rest.starts_with("||") || COMPARISONS.iter().any(|(symbol, _)| rest.starts_with(symbol));
        if c.is_whitespace() || c == '(' || c == ')' || c == '"' || (at > 0 && operator) || (at == 0 && operator && c != '!') {
            break;
        }
        len = at + c.len_utf8();
    }
    len.max(text.chars().next().map_or(0, char::len_utf8))
}

/// The text inside the quotes at the start of `text` (with `\"` and `\\`
/// for a quote and a backslash), and how many bytes the quoted text took.
fn read_quoted(text: &str) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut escaped = false;
    for (at, c) in text.char_indices().skip(1) {
        match c {
            _ if escaped => {
                out.push(c);
                escaped = false;
            }
            '\\' => escaped = true,
            '"' => return Some((out, at + 1)),
            _ => out.push(c),
        }
    }
    None
}

/// Reads tokens into an expression.
struct Parser<'a> {
    text: &'a str,
    tokens: Vec<(Token, usize, usize)>,
    position: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position).map(|(token, _, _)| token)
    }

    /// The text of tokens `from..to`.
    fn source(&self, from: usize, to: usize) -> &str {
        let start = self.tokens.get(from).map_or(self.text.len(), |token| token.1);
        let end = to.checked_sub(1).and_then(|last| self.tokens.get(last)).map_or(start, |token| token.2);
        self.text.get(start..end.max(start)).unwrap_or_default()
    }

    fn any(&mut self) -> Result<Expression, FilterError> {
        let mut parts = vec![self.all()?];
        while self.peek() == Some(&Token::Or) {
            self.position += 1;
            if self.ends_group() {
                return Err(error(self.text, "'or' needs a term after it"));
            }
            parts.push(self.all()?);
        }
        Ok(if parts.len() == 1 { parts.remove(0) } else { Expression::Any(parts) })
    }

    fn ends_group(&self) -> bool {
        matches!(self.peek(), None | Some(Token::Close) | Some(Token::Or) | Some(Token::And))
    }

    fn all(&mut self) -> Result<Expression, FilterError> {
        let mut parts = vec![self.unary()?];
        loop {
            match self.peek() {
                Some(Token::And) => {
                    self.position += 1;
                    if self.ends_group() {
                        return Err(error(self.text, "'and' needs a term after it"));
                    }
                }
                None | Some(Token::Or) | Some(Token::Close) => break,
                // Terms side by side must all match.
                Some(_) => {}
            }
            parts.push(self.unary()?);
        }
        Ok(if parts.len() == 1 { parts.remove(0) } else { Expression::All(parts) })
    }

    fn unary(&mut self) -> Result<Expression, FilterError> {
        if self.peek() == Some(&Token::Not) {
            self.position += 1;
            if self.ends_group() {
                return Err(error(self.text, "'not' needs a term after it"));
            }
            return Ok(Expression::Not(Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expression, FilterError> {
        let start = self.position;
        let Some((token, _, _)) = self.tokens.get(self.position).cloned() else {
            return Err(error(self.text, "the filter ends where a term was expected"));
        };
        self.position += 1;
        match token {
            Token::Open => {
                if self.peek() == Some(&Token::Close) {
                    return Err(error("()", "the brackets are empty"));
                }
                let inner = self.any()?;
                if self.peek() != Some(&Token::Close) {
                    return Err(error(self.source(start, self.position), "a '(' is not closed"));
                }
                self.position += 1;
                Ok(inner)
            }
            Token::Close => Err(error(")", "this ')' has no '(' before it")),
            Token::Quoted(text) => Ok(Expression::Term(Term::Text(text.to_lowercase()))),
            Token::Word(word) => match self.peek().cloned() {
                Some(Token::Compare(test)) => {
                    self.position += 1;
                    let value = match self.tokens.get(self.position).map(|(token, _, _)| token.clone()) {
                        Some(Token::Word(value)) | Some(Token::Quoted(value)) => {
                            self.position += 1;
                            value
                        }
                        _ => return Err(error(self.source(start, self.position), "give a value after the comparison, such as ip.ttl==64")),
                    };
                    comparison(self.source(start, self.position), &word, test, &value)
                }
                _ => word_term(&word).map(Expression::Term),
            },
            Token::Compare(_) => Err(error(self.source(start, self.position), "a comparison needs a field before it, such as ip.ttl==64")),
            Token::And | Token::Or | Token::Not => Err(error(self.source(start, self.position), "'and', 'or' and 'not' go between or before terms")),
        }
    }
}

/// Parse a filter, explaining the first term that cannot be read. Field
/// names are not checked: see [`Filter::resolve`].
pub fn parse_filter(text: &str) -> Result<Filter, FilterError> {
    let tokens = tokenise(text)?;
    if tokens.is_empty() {
        return Ok(Filter::default());
    }
    let mut parser = Parser { text, tokens, position: 0 };
    let expression = parser.any()?;
    if parser.position < parser.tokens.len() {
        let (_, start, end) = parser.tokens[parser.position];
        return Err(error(&text[start..end], "this ')' has no '(' before it"));
    }
    Ok(Filter { expression: Some(expression) })
}

/// [`parse_filter`], then [`Filter::resolve`] against `known`.
pub fn parse_filter_for(text: &str, known: &KnownFields) -> Result<Filter, FilterError> {
    parse_filter(text)?.resolve(known)
}

fn error(term: &str, reason: impl Into<String>) -> FilterError {
    FilterError { term: term.trim().to_string(), reason: reason.into() }
}

/// A term written as `name OP value`.
fn comparison(shown: &str, name: &str, test: FieldTest, value: &str) -> Result<Expression, FilterError> {
    let lower = name.to_lowercase();
    if lower == "len" || lower == "frame.len" {
        let limit = value.parse::<usize>().map_err(|_| error(shown, format!("len counts bytes: '{value}' is not a whole number")))?;
        let length = |comparison| Ok(Expression::Term(Term::Length(comparison, limit)));
        return match test {
            FieldTest::Less => length(Comparison::Less),
            FieldTest::LessOrEqual => length(Comparison::LessOrEqual),
            FieldTest::Equal => length(Comparison::Equal),
            FieldTest::GreaterOrEqual => length(Comparison::GreaterOrEqual),
            FieldTest::Greater => length(Comparison::Greater),
            FieldTest::NotEqual => Ok(Expression::Not(Box::new(Expression::Term(Term::Length(Comparison::Equal, limit))))),
            FieldTest::Contains => Err(error(shown, "compare the length with ==, !=, >, <, >= or <=, such as len>100")),
        };
    }
    let looks_like_name = lower.starts_with(|c: char| c.is_ascii_alphabetic())
        && lower.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && lower.split('.').all(|part| !part.is_empty());
    if !looks_like_name {
        return Err(error(shown, format!("'{name}' is not a field name; fields are named such as ip.ttl, dns.qry.name or template.type")));
    }
    if PROTOCOL_NAMES.contains(&lower.as_str()) && !lower.contains('.') {
        return Err(error(shown, format!("'{name}' is a protocol, not a field; name one of its fields, such as {lower}.len")));
    }
    if test.is_ordering() && leading_number(value).is_none() {
        let symbol = COMPARISONS.iter().find(|(_, candidate)| *candidate == test).map_or("", |(symbol, _)| symbol);
        return Err(error(shown, format!("{symbol} compares numbers; '{value}' is not one")));
    }
    Ok(Expression::Term(Term::Field { name: lower, test: Some((test, value.to_string())) }))
}

/// A term written as one word.
fn word_term(term: &str) -> Result<Term, FilterError> {
    let lower = term.to_lowercase();
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
            other => Err(error(term, format!("'{other}:' is not a filter; use port:, ip:, proto:, hex:, a field such as ip.ttl==64, or len>100"))),
        };
    }
    if PROTOCOL_NAMES.contains(&lower.as_str()) {
        return Ok(Term::Protocol(if lower == "payload" { "data".to_string() } else { lower }));
    }
    // A dotted word is a field asked to be there only when it starts with a
    // protocol the notes know, or names a template field, so "example.com"
    // stays text.
    let looks_like_field = lower.contains('.')
        && lower.starts_with(|c: char| c.is_ascii_alphabetic())
        && lower.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && lower.split('.').all(|part| !part.is_empty());
    let protocol = lower.split('.').next().unwrap_or_default();
    if looks_like_field && (protocol == "template" || reference::library().by_wireshark(protocol).is_some()) {
        return Ok(Term::Field { name: lower, test: None });
    }
    Ok(Term::Text(lower))
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

    /// A DNS query for `name` of `record_type` over UDP, as raw IP, dissected.
    fn dns_query(record_type: u16, flags: u16) -> Dissection {
        let mut message = vec![0xAB, 0xCD];
        message.extend(flags.to_be_bytes());
        message.extend([0, 1, 0, 0, 0, 0, 0, 0]);
        message.extend(b"\x04abcd\x07example\x03com\x00");
        message.extend(record_type.to_be_bytes());
        message.extend([0, 1]);
        let builder = etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).udp(40000, 53);
        let mut packet = Vec::new();
        builder.write(&mut packet, &message).unwrap();
        crate::packets::dissect(&packet, crate::packets::LinkKind::RawIp)
    }

    /// Whether `filter`, checked against what `dissection` holds, keeps it.
    fn keeps(filter: &str, dissection: &Dissection) -> bool {
        let known = KnownFields::of([dissection]);
        let filter = parse_filter_for(filter, &known).unwrap_or_else(|error| panic!("{filter}: {error}"));
        let values = |name: &str| wireshark_values(dissection, name);
        let no_tshark: [String; 0] = [];
        let subject = FilterSubject {
            protocols: &dissection.protocols,
            tshark_protocols: &no_tshark,
            flow: dissection.flow.as_ref(),
            summary: &dissection.summary,
            bytes: &[],
            len: 0,
            fields: Some(&values),
        };
        filter.matches(&subject)
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
        assert!(matches("len > 60 and len == 74", &packet), "spaces around the operator are allowed");
        assert!(matches("len!=75", &packet));
        assert!(!matches("len!=74", &packet));
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
        assert!(matches("\"standard query\"", &packet), "quoted words are one text");
        assert!(!matches("\"query standard\"", &packet));
    }

    #[test]
    fn and_or_not_and_brackets_combine_terms_as_wireshark_does() {
        let packet = dns_packet();
        assert!(matches("udp && dns", &packet));
        assert!(matches("udp and dns", &packet));
        assert!(!matches("tcp && dns", &packet));
        assert!(matches("tcp || dns", &packet));
        assert!(matches("tcp or dns", &packet));
        assert!(!matches("not dns", &packet));
        assert!(!matches("!dns", &packet));
        assert!(matches("not response", &packet), "not turns the free-text word round, rather than looking for 'not'");
        assert!(matches("!(tcp or port:80) and (dns)", &packet));
        assert!(matches("tcp or udp port:53", &packet), "side by side binds tighter than or");
        assert!(!matches("(tcp or udp) port:80", &packet));
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
        let cases = [
            ("proto:", "name a protocol"),
            ("port:http", "port"),
            ("ip:10.0.0", "address"),
            ("hex:ABC", "odd"),
            ("len>lots", "whole number"),
            ("len~5", "compare the length"),
            ("size:5", "not a filter"),
            ("ip.ttl==", "give a value"),
            ("(udp", "not closed"),
            ("udp)", "no '('"),
            ("udp and", "needs a term"),
            ("== 5", "needs a field"),
            ("\"open", "closing"),
        ];
        for (filter, expected) in cases {
            let error = parse_filter(filter).expect_err(filter);
            assert!(error.to_string().contains(expected), "{filter}: {error}");
        }
        assert_eq!(parse_filter("udp port:http").unwrap_err().term, "port:http");
        assert_eq!(parse_filter("length").map(|f| f.terms().into_iter().cloned().collect::<Vec<_>>()), Ok(vec![Term::Text("length".to_string())]));
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
        assert!(holds("udp.port==53 and udp.port==40000"), "udp.port is either end");
        assert!(!holds("tcp.port==53"));
        assert!(holds("ip.addr==10.0.0.1 && ip.addr==10.0.0.2"));
    }

    #[test]
    fn dns_flags_bits_and_numeric_record_types_can_be_filtered_on() {
        let query = dns_query(16, 0x0100);
        let response = dns_query(16, 0x8180);
        assert!(keeps("dns.flags.response==0", &query));
        assert!(!keeps("dns.flags.response==0", &response));
        assert!(keeps("dns.flags.response==1 && dns.flags.recavail==1", &response));
        assert!(keeps("dns.flags.response==false", &query));
        assert!(keeps("dns.qry.type==16", &query), "TXT is type 16");
        assert!(keeps("dns.qry.type==TXT", &query));
        assert!(keeps("dns.qry.type>=16 && dns.qry.type<17", &query));
        assert!(!keeps("dns.qry.type==1", &query));
        assert!(!keeps("dns.qry.type==A", &query));
    }

    #[test]
    fn a_flag_tshark_gives_in_words_is_still_found_by_its_number() {
        use crate::packets::dissect::Layer;
        let flags = Field::new("Flags", 44, 2, "0x0100 Standard query").with_children(vec![Field::new("Response", 44, 2, "Message is a query")]);
        let dissection = Dissection {
            layers: vec![Layer { name: "Domain Name System (query)".into(), offset: 42, len: 12, fields: vec![flags] }],
            tshark_layers: vec![0],
            tshark_names: vec![WiresharkNames { protocol: "dns".into(), fields: vec![(vec![0], "dns.flags".into()), (vec![0, 0], "dns.flags.response".into())] }],
            tshark_protocols: vec!["dns".into()],
            ..Dissection::default()
        };
        assert!(keeps("dns.flags.response==0", &dissection));
        assert!(keeps("dns.flags.response~query", &dissection), "tshark's words still match");
        assert!(!keeps("dns.flags.response==1", &dissection));
    }

    #[test]
    fn an_unknown_field_is_an_error_naming_the_close_ones() {
        let query = dns_query(1, 0x0100);
        let known = KnownFields::of([&query]);
        let error = parse_filter_for("dns.qry.nmae==example.com", &known).unwrap_err();
        assert_eq!(error.term, "dns.qry.nmae==example.com");
        assert!(error.reason.contains("dns.qry.name"), "{error}");
        let error = parse_filter_for("udp and frob.x==1", &known).unwrap_err();
        assert!(error.reason.contains("no field called 'frob.x'"), "{error}");
        let error = parse_filter_for("kind==60", &known).unwrap_err();
        assert!(error.reason.contains("not a field") && error.reason.contains("template"), "{error}");
        assert!(parse_filter_for("dns.qry.name~example and tcp.port==80 and http.user_agent~curl", &known).is_ok(), "known, derived and header names pass");
    }

    #[test]
    fn template_fields_filter_by_template_name_or_bare_name() {
        let template = crate::templates::Template::parse("struct Frame { sync: u16be  kind: u8 display hex enum { 0x3c = \"unlock\" }  seq: u8 }").unwrap();
        let raw = crate::packets::RawFrames { template: Some(template), ..crate::packets::RawFrames::default() };
        let unlock = crate::packets::dissect_with(&[0xA5, 0x5A, 0x3C, 7], crate::packets::LinkKind::Unknown, &raw);
        let poll = crate::packets::dissect_with(&[0xA5, 0x5A, 0x01, 8], crate::packets::LinkKind::Unknown, &raw);
        let known = KnownFields::of([&unlock, &poll]);
        assert!(known.template.contains("kind"), "{known:?}");
        let both = |filter: &str| (keeps(filter, &unlock), keeps(filter, &poll));
        assert_eq!(both("template.kind==60"), (true, false));
        assert_eq!(both("kind==0x3c"), (true, false), "a bare name is the template's field");
        assert_eq!(both("kind==unlock"), (true, false), "an enum's label: {:?}", wireshark_values(&unlock, "template.kind"));
        assert_eq!(both("template.seq>7"), (false, true));
        let error = parse_filter_for("template.knd==1", &known).unwrap_err();
        assert!(error.reason.contains("kind"), "{error}");
    }

    #[test]
    fn field_terms_are_told_apart_from_text_and_explained_when_wrong() {
        let field = |name: &str, test: FieldTest, value: &str| Some(Expression::Term(Term::Field { name: name.into(), test: Some((test, value.into())) }));
        assert_eq!(parse_filter("ip.ttl>=64").unwrap().expression, field("ip.ttl", FieldTest::GreaterOrEqual, "64"));
        assert_eq!(parse_filter("dns.qry.name ~ example").unwrap().expression, field("dns.qry.name", FieldTest::Contains, "example"));
        assert_eq!(parse_filter("example.com").unwrap().expression, Some(Expression::Term(Term::Text("example.com".into()))), "not a protocol the notes know");
        assert_eq!(parse_filter("10.0.0.1").unwrap().expression, Some(Expression::Term(Term::Text("10.0.0.1".into()))));
        assert!(parse_filter("ip.ttl>lots").unwrap_err().to_string().contains("compares numbers"));
    }

    #[test]
    fn values_match_by_whole_text_first_word_bracketed_part_or_number() {
        assert!(value_equals("6 (TCP)", "6"));
        assert!(value_equals("6 (TCP)", "tcp"));
        assert!(value_equals("0x0800 (IPv4)", "2048"));
        assert!(value_equals("TXT (16)", "16"));
        assert!(value_equals("TXT (16)", "0x10"));
        assert!(value_equals("60 (0x3C) (unlock)", "unlock"));
        assert!(value_equals("60 (0x3C) (unlock)", "0x3c"));
        assert!(value_equals("example.com", "EXAMPLE.COM"));
        assert!(!value_equals("10.0.0.1", "10"));
        assert!(value_passes("1500 bytes", FieldTest::Greater, "1000"));
        assert!(value_passes("TXT (16)", FieldTest::Less, "17"));
        assert!(value_passes("Standard query", FieldTest::Contains, "QUERY"));
    }

    #[test]
    fn values_sort_as_numbers_before_text_and_missing_last() {
        let key = |value: &str| sort_key(&[value.to_string()]);
        assert!(key("9") < key("10"));
        assert!(key("0x0a") > key("9"));
        assert!(key("TXT (16)") > key("A (1)"));
        assert!(key("10") < key("abc"));
        assert!(key("10.0.0.9") < key("10.0.0.10") || key("10.0.0.9") > key("10.0.0.10"), "addresses compare as text");
        assert!(key("zzz") < sort_key(&[]));
    }
}
