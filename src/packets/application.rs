//! Small, defensive parsers for application protocols carried over TCP and
//! UDP: DNS, HTTP, NTP, Modbus/TCP and MQTT.
//!
//! Each parser takes a transport payload and returns an [`AppLayer`] whose
//! field offsets are relative to the payload's first byte, or `None` when the
//! bytes do not look like that protocol. None of them can panic, and every
//! loop is bounded.

use crate::patterns::format_unix_seconds;
use crate::plugin::Field;

use super::flows::Transport;

/// Well-known ports.
const PORT_HTTP: u16 = 80;
const PORT_HTTP_ALTERNATIVES: [u16; 3] = [8000, 8008, 8080];
const PORT_DNS: u16 = 53;
const PORT_MDNS: u16 = 5353;
const PORT_NTP: u16 = 123;
const PORT_MODBUS: u16 = 502;
const PORT_MQTT: u16 = 1883;

/// A parsed application layer.
#[derive(Clone, Debug, PartialEq)]
pub struct AppLayer {
    /// Display name, such as "DNS".
    pub name: &'static str,
    /// Lower-case name used by the filter, such as "dns".
    pub key: &'static str,
    /// Bytes of the payload the layer covers.
    pub len: usize,
    /// Fields with offsets relative to the payload.
    pub fields: Vec<Field>,
    /// One line for the packet list.
    pub info: String,
}

/// Parse `payload` by the ports it travels between, falling back to content
/// sniffing for HTTP on any TCP port.
pub fn dissect_application(transport: Transport, source_port: u16, destination_port: u16, payload: &[u8]) -> Option<AppLayer> {
    if payload.is_empty() {
        return None;
    }
    let uses = |port: u16| source_port == port || destination_port == port;
    let parsed = match transport {
        Transport::Udp if uses(PORT_DNS) || uses(PORT_MDNS) => dissect_dns(payload),
        Transport::Tcp if uses(PORT_DNS) => dissect_dns_over_tcp(payload),
        Transport::Udp if uses(PORT_NTP) => dissect_ntp(payload),
        Transport::Tcp if uses(PORT_MODBUS) => dissect_modbus(payload, destination_port == PORT_MODBUS),
        Transport::Tcp if uses(PORT_MQTT) => dissect_mqtt(payload),
        Transport::Tcp if uses(PORT_HTTP) || PORT_HTTP_ALTERNATIVES.iter().any(|&port| uses(port)) => dissect_http(payload),
        _ => None,
    };
    parsed.or_else(|| if transport == Transport::Tcp { dissect_http(payload) } else { None })
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn shift_fields(fields: &mut [Field], by: usize) {
    for field in fields {
        field.offset += by;
        shift_fields(&mut field.children, by);
    }
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

const DNS_HEADER_LEN: usize = 12;
/// Most questions and records listed per section.
const DNS_MAX_RECORDS: usize = 32;
/// Most compression pointers followed in one name.
const DNS_MAX_POINTER_HOPS: usize = 16;
/// Most labels in one name.
const DNS_MAX_LABELS: usize = 128;
const DNS_RESPONSE_BIT: u16 = 0x8000;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_NS: u16 = 2;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_SOA: u16 = 6;
const DNS_TYPE_PTR: u16 = 12;
const DNS_TYPE_MX: u16 = 15;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_SRV: u16 = 33;
const DNS_TYPE_OPT: u16 = 41;
/// The DNSSEC OK bit of an OPT record's flags.
const EDNS_DNSSEC_OK: u16 = 0x8000;

fn dns_type_name(record_type: u16) -> String {
    match record_type {
        DNS_TYPE_A => "A".to_string(),
        DNS_TYPE_NS => "NS".to_string(),
        DNS_TYPE_CNAME => "CNAME".to_string(),
        DNS_TYPE_SOA => "SOA".to_string(),
        DNS_TYPE_PTR => "PTR".to_string(),
        DNS_TYPE_MX => "MX".to_string(),
        DNS_TYPE_TXT => "TXT".to_string(),
        DNS_TYPE_AAAA => "AAAA".to_string(),
        DNS_TYPE_SRV => "SRV".to_string(),
        DNS_TYPE_OPT => "OPT".to_string(),
        46 => "RRSIG".to_string(),
        47 => "NSEC".to_string(),
        48 => "DNSKEY".to_string(),
        64 => "SVCB".to_string(),
        65 => "HTTPS".to_string(),
        255 => "ANY".to_string(),
        other => format!("type {other}"),
    }
}

/// Read a possibly compressed name at `start`. Returns the name and how many
/// bytes it takes up at `start` (a pointer counts as its two bytes).
pub fn read_dns_name(message: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut at = start;
    let mut consumed: Option<usize> = None;
    let mut hops = 0;
    loop {
        let len = *message.get(at)? as usize;
        if len == 0 {
            let used = consumed.unwrap_or_else(|| at + 1 - start);
            let name = if labels.is_empty() { "<root>".to_string() } else { labels.join(".") };
            return Some((name, used));
        }
        if len & 0xC0 == 0xC0 {
            let pointer = ((len & 0x3F) << 8) | *message.get(at + 1)? as usize;
            consumed.get_or_insert_with(|| at + 2 - start);
            hops += 1;
            if hops > DNS_MAX_POINTER_HOPS {
                return None;
            }
            at = pointer;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let label = message.get(at + 1..at + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        if labels.len() > DNS_MAX_LABELS {
            return None;
        }
        at += 1 + len;
    }
}

/// A DNS message carried over TCP, after its two-byte length.
fn dissect_dns_over_tcp(payload: &[u8]) -> Option<AppLayer> {
    let declared = u16_at(payload, 0)? as usize;
    let message = payload.get(2..(2 + declared).min(payload.len()))?;
    let mut layer = dissect_dns(message)?;
    shift_fields(&mut layer.fields, 2);
    layer.fields.insert(0, Field::new("Length", 0, 2, declared.to_string()));
    layer.len += 2;
    Some(layer)
}

/// A DNS message: the header, the questions, and the answer, authority and
/// additional records (an EDNS OPT pseudo-record among them).
pub fn dissect_dns(message: &[u8]) -> Option<AppLayer> {
    if message.len() < DNS_HEADER_LEN {
        return None;
    }
    let id = u16_at(message, 0)?;
    let flags = u16_at(message, 2)?;
    let counts: Vec<u16> = (0..4).map(|i| u16_at(message, 4 + i * 2).unwrap_or(0)).collect();
    let is_response = flags & DNS_RESPONSE_BIT != 0;
    let opcode = (flags >> 11) & 0x0F;
    let rcode = flags & 0x0F;
    let mut fields = vec![
        Field::new("Transaction ID", 0, 2, format!("{id:#06x}")),
        Field::new("Flags", 2, 2, format!("{flags:#06x} ({}, opcode {opcode}, rcode {rcode})", if is_response { "response" } else { "query" })),
        Field::new("Questions", 4, 2, counts[0].to_string()),
        Field::new("Answer records", 6, 2, counts[1].to_string()),
        Field::new("Authority records", 8, 2, counts[2].to_string()),
        Field::new("Additional records", 10, 2, counts[3].to_string()),
    ];
    let mut at = DNS_HEADER_LEN;
    let mut questions = Vec::new();
    let mut summary_parts = Vec::new();
    for index in 0..(counts[0] as usize).min(DNS_MAX_RECORDS) {
        let (name, name_len) = read_dns_name(message, at)?;
        let record_type = u16_at(message, at + name_len)?;
        let class = u16_at(message, at + name_len + 2)?;
        let len = name_len + 4;
        summary_parts.push(format!("{} {name}", dns_type_name(record_type)));
        questions.push(
            Field::new(format!("Question {index}"), at, len, format!("{name} {} class {class}", dns_type_name(record_type))).with_children(vec![
                Field::new("Name", at, name_len, name.clone()),
                Field::new("Type", at + name_len, 2, dns_type_name(record_type)),
                Field::new("Class", at + name_len + 2, 2, class.to_string()),
            ]),
        );
        at += len;
    }
    if !questions.is_empty() {
        fields.push(Field::new("Question section", DNS_HEADER_LEN, at - DNS_HEADER_LEN, format!("{} questions", questions.len())).with_children(questions));
    }
    for (section, count) in [(DnsSection::Answer, counts[1]), (DnsSection::Authority, counts[2]), (DnsSection::Additional, counts[3])] {
        let section_start = at;
        let mut records = Vec::new();
        for index in 0..(count as usize).min(DNS_MAX_RECORDS) {
            let Some((record, len, description)) = dns_record(message, at, section, index) else { break };
            // The packet list names the questions and answers, as Wireshark does.
            if section == DnsSection::Answer {
                summary_parts.push(description);
            }
            records.push(record);
            at += len;
        }
        let read_all = records.len() == count as usize;
        if !records.is_empty() {
            fields.push(Field::new(format!("{} section", section.label()), section_start, at - section_start, format!("{} {}", records.len(), section.plural())).with_children(records));
        }
        if !read_all {
            // Records follow one another, so nothing after an unreadable one
            // (or past the cap) can be found.
            break;
        }
    }
    let kind = if is_response { "Standard query response" } else { "Standard query" };
    let info = format!("{kind} {id:#06x} {}", summary_parts.join(" ")).trim_end().to_string();
    Some(AppLayer { name: "DNS", key: "dns", len: at.max(DNS_HEADER_LEN), fields, info })
}

/// The three sections of resource records after the questions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DnsSection {
    Answer,
    Authority,
    Additional,
}

impl DnsSection {
    fn label(self) -> &'static str {
        match self {
            DnsSection::Answer => "Answer",
            DnsSection::Authority => "Authority",
            DnsSection::Additional => "Additional",
        }
    }

    fn plural(self) -> &'static str {
        match self {
            DnsSection::Answer => "answers",
            DnsSection::Authority => "authority records",
            DnsSection::Additional => "additional records",
        }
    }
}

/// A name inside record data, or a placeholder when it cannot be read.
fn dns_name_or_placeholder(message: &[u8], at: usize) -> String {
    read_dns_name(message, at).map(|(name, _)| name).unwrap_or_else(|| "(unreadable name)".to_string())
}

/// The character strings of a TXT record, each a length byte and its text.
fn dns_text_strings(data: &[u8]) -> String {
    let mut strings = Vec::new();
    let mut at = 0;
    while let Some(&len) = data.get(at) {
        let Some(text) = data.get(at + 1..at + 1 + len as usize) else { break };
        strings.push(format!("\"{}\"", String::from_utf8_lossy(text)));
        at += 1 + len as usize;
    }
    strings.join(" ")
}

/// A record's data in words, by its type.
fn dns_record_value(message: &[u8], record_type: u16, data_at: usize, data: &[u8]) -> String {
    let number = |at: usize| u16_at(data, at).unwrap_or_default();
    match (record_type, data.len()) {
        (DNS_TYPE_A, 4) => std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
        (DNS_TYPE_AAAA, 16) => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(data);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        (DNS_TYPE_NS | DNS_TYPE_CNAME | DNS_TYPE_PTR, _) => dns_name_or_placeholder(message, data_at),
        (DNS_TYPE_MX, 3..) => format!("{} {}", number(0), dns_name_or_placeholder(message, data_at + 2)),
        (DNS_TYPE_SRV, 7..) => format!("{} {} {} {}", number(0), number(2), number(4), dns_name_or_placeholder(message, data_at + 6)),
        (DNS_TYPE_SOA, _) => dns_soa_value(message, data_at),
        (DNS_TYPE_TXT, _) => dns_text_strings(data),
        (_, len) => format!("{len} bytes"),
    }
}

/// An SOA record's primary server, responsible mailbox and serial number.
fn dns_soa_value(message: &[u8], data_at: usize) -> String {
    let Some((primary, primary_len)) = read_dns_name(message, data_at) else { return "(unreadable name)".to_string() };
    let Some((mailbox, mailbox_len)) = read_dns_name(message, data_at + primary_len) else { return primary };
    match u32_at(message, data_at + primary_len + mailbox_len) {
        Some(serial) => format!("{primary} {mailbox} serial {serial}"),
        None => format!("{primary} {mailbox}"),
    }
}

/// One resource record: its field, its length and a short description.
fn dns_record(message: &[u8], at: usize, section: DnsSection, index: usize) -> Option<(Field, usize, String)> {
    let (name, name_len) = read_dns_name(message, at)?;
    let fixed = at + name_len;
    let record_type = u16_at(message, fixed)?;
    let class = u16_at(message, fixed + 2)?;
    let ttl = u32_at(message, fixed + 4)?;
    let data_len = u16_at(message, fixed + 8)? as usize;
    let data_at = fixed + 10;
    let data = message.get(data_at..data_at + data_len)?;
    let len = name_len + 10 + data_len;
    let label = format!("{} {index}", section.label());
    if record_type == DNS_TYPE_OPT {
        let record = OptRecord { at, name_len, payload_size: class, ttl, data_at, data };
        let (field, description) = record.field(label, name);
        return Some((field, len, description));
    }
    let value = dns_record_value(message, record_type, data_at, data);
    let description = format!("{} {value}", dns_type_name(record_type));
    let field = Field::new(label, at, len, format!("{name} {description} TTL {ttl}")).with_children(vec![
        Field::new("Name", at, name_len, name),
        Field::new("Type", fixed, 2, dns_type_name(record_type)),
        Field::new("Class", fixed + 2, 2, class.to_string()),
        Field::new("Time to live", fixed + 4, 4, format!("{ttl} s")),
        Field::new("Data length", fixed + 8, 2, data_len.to_string()),
        Field::new("Data", data_at, data_len, value),
    ]);
    Some((field, len, description))
}

fn edns_option_name(code: u16) -> String {
    match code {
        3 => "NSID".to_string(),
        8 => "Client subnet".to_string(),
        10 => "Cookie".to_string(),
        11 => "TCP keepalive".to_string(),
        12 => "Padding".to_string(),
        15 => "Extended DNS error".to_string(),
        other => format!("option {other}"),
    }
}

/// An EDNS OPT pseudo-record (RFC 6891): its class holds the sender's UDP
/// payload size and its time to live the extended RCODE, the EDNS version
/// and the flags; its data is a list of options.
struct OptRecord<'a> {
    /// Where the record (its name) starts in the message.
    at: usize,
    name_len: usize,
    payload_size: u16,
    ttl: u32,
    data_at: usize,
    data: &'a [u8],
}

impl OptRecord<'_> {
    /// The record's field and a short description.
    fn field(&self, label: String, name: String) -> (Field, String) {
        let fixed = self.at + self.name_len;
        let [extended_rcode, version, flags_high, flags_low] = self.ttl.to_be_bytes();
        let flags = u16::from_be_bytes([flags_high, flags_low]);
        let dnssec_ok = flags & EDNS_DNSSEC_OK != 0;
        let (options, options_len) = self.options();
        let mut children = vec![
            Field::new("Name", self.at, self.name_len, name.clone()),
            Field::new("Type", fixed, 2, dns_type_name(DNS_TYPE_OPT)),
            Field::new("UDP payload size", fixed + 2, 2, self.payload_size.to_string()),
            Field::new("Extended RCODE", fixed + 4, 1, extended_rcode.to_string()),
            Field::new("EDNS version", fixed + 5, 1, version.to_string()),
            Field::new("EDNS flags", fixed + 6, 2, format!("{flags:#06x}{}", if dnssec_ok { " (DNSSEC OK)" } else { "" })),
            Field::new("Data length", fixed + 8, 2, self.data.len().to_string()),
        ];
        if !options.is_empty() {
            children.push(Field::new("Options", self.data_at, options_len, format!("{} options", options.len())).with_children(options));
        }
        let description = format!("OPT udp {}{}", self.payload_size, if dnssec_ok { " DO" } else { "" });
        let field = Field::new(label, self.at, self.name_len + 10 + self.data.len(), format!("{name} {description}, version {version}")).with_children(children);
        (field, description)
    }

    /// The options, each a code, a length and its value, and the bytes they
    /// take up.
    fn options(&self) -> (Vec<Field>, usize) {
        let mut options = Vec::new();
        let mut at = 0;
        while options.len() < DNS_MAX_RECORDS {
            let (Some(code), Some(len)) = (u16_at(self.data, at), u16_at(self.data, at + 2)) else { break };
            let len = len as usize;
            let Some(value) = self.data.get(at + 4..at + 4 + len) else { break };
            let start = self.data_at + at;
            let preview = super::hex_preview(value, 16);
            options.push(Field::new(format!("Option {}", options.len()), start, 4 + len, format!("{} ({len} bytes) {preview}", edns_option_name(code))).with_children(vec![
                Field::new("Option code", start, 2, format!("{code} ({})", edns_option_name(code))),
                Field::new("Option length", start + 2, 2, len.to_string()),
                Field::new("Option data", start + 4, len, preview),
            ]));
            at += 4 + len;
        }
        (options, at)
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/// Request methods of RFC 9110 and the WebDAV and UPnP extensions met on
/// the wire.
const HTTP_METHODS: [&str; 22] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH",
    "NOTIFY", "M-SEARCH", "SUBSCRIBE", "UNSUBSCRIBE",
];
const HTTP_VERSIONS: [&str; 2] = ["HTTP/1.0", "HTTP/1.1"];
/// Most header lines listed.
const HTTP_MAX_HEADERS: usize = 100;
/// Longest line considered part of an HTTP head.
const HTTP_MAX_LINE: usize = 8 * 1024;

/// Whether `line` is an HTTP/1.x request line ("GET /index.html HTTP/1.1")
/// or status line ("HTTP/1.1 200 OK"). RTSP and SIP, which look alike, give
/// other versions and are left alone.
fn is_http_start_line(line: &str) -> bool {
    if let Some(rest) = HTTP_VERSIONS.iter().find_map(|version| line.strip_prefix(version)) {
        let Some(status) = rest.strip_prefix(' ') else { return false };
        let code = status.get(..3).unwrap_or_default();
        let after = &status[code.len()..];
        return code.bytes().all(|byte| byte.is_ascii_digit()) && code.len() == 3 && (after.is_empty() || after.starts_with(' '));
    }
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else { return false };
    HTTP_METHODS.contains(&method) && !target.is_empty() && target.bytes().all(|byte| byte.is_ascii_graphic()) && HTTP_VERSIONS.contains(&version)
}

/// The next line from `at`: its text without the line ending, and where the
/// following line starts.
fn next_line(payload: &[u8], at: usize) -> Option<(String, usize)> {
    let rest = payload.get(at..)?;
    let end = rest.iter().take(HTTP_MAX_LINE).position(|&b| b == b'\n')?;
    let line = rest[..end].strip_suffix(b"\r").unwrap_or(&rest[..end]);
    Some((String::from_utf8_lossy(line).into_owned(), at + end + 1))
}

/// An HTTP/1 request or response head: the first line and the headers. The
/// payload must start with a whole request or status line, so the middle
/// of a body, or a request line cut short, is not taken for HTTP.
pub fn dissect_http(payload: &[u8]) -> Option<AppLayer> {
    let (first, mut at) = next_line(payload, 0)?;
    if !is_http_start_line(&first) {
        return None;
    }
    let is_response = first.starts_with("HTTP/");
    let mut fields = vec![Field::new(if is_response { "Status line" } else { "Request line" }, 0, at, first.clone())];
    let mut headers = Vec::new();
    let headers_start = at;
    while headers.len() < HTTP_MAX_HEADERS {
        let Some((line, next)) = next_line(payload, at) else { break };
        if line.is_empty() {
            at = next;
            break;
        }
        let (name, value) = line.split_once(':').map_or((line.as_str(), ""), |(n, v)| (n, v.trim()));
        headers.push(Field::new(name.to_string(), at, next - at, value.to_string()));
        at = next;
    }
    if !headers.is_empty() {
        fields.push(Field::new("Headers", headers_start, at - headers_start, format!("{} headers", headers.len())).with_children(headers));
    }
    if at < payload.len() {
        fields.push(Field::new("Body", at, payload.len() - at, format!("{} bytes", payload.len() - at)));
    }
    Some(AppLayer { name: "HTTP", key: "http", len: payload.len(), fields, info: first })
}

// ---------------------------------------------------------------------------
// NTP
// ---------------------------------------------------------------------------

const NTP_PACKET_LEN: usize = 48;
/// Seconds from the NTP epoch (1900) to the Unix epoch (1970).
const NTP_TO_UNIX_SECONDS: u64 = 2_208_988_800;
const NTP_FRACTION_SCALE: f64 = 4_294_967_296.0;
const NTP_MODE_CONTROL: u8 = 6;

fn ntp_mode_name(mode: u8) -> &'static str {
    match mode {
        1 => "symmetric active",
        2 => "symmetric passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "control",
        7 => "private",
        _ => "reserved",
    }
}

/// An NTP timestamp (seconds since 1900, 32.32 fixed point) as UTC text.
fn ntp_timestamp(bytes: &[u8], at: usize) -> String {
    let (Some(seconds), Some(fraction)) = (u32_at(bytes, at), u32_at(bytes, at + 4)) else { return String::new() };
    if seconds == 0 && fraction == 0 {
        return "(not set)".to_string();
    }
    let fraction = fraction as f64 / NTP_FRACTION_SCALE;
    match (seconds as u64).checked_sub(NTP_TO_UNIX_SECONDS) {
        Some(unix) => format!("{} +{fraction:.6} s", format_unix_seconds(unix)),
        None => format!("{seconds}.{:06} s since 1900", (fraction * 1e6) as u64),
    }
}

/// An NTP packet: mode, stratum and the four timestamps.
pub fn dissect_ntp(payload: &[u8]) -> Option<AppLayer> {
    if payload.len() < NTP_PACKET_LEN {
        return None;
    }
    let flags = payload[0];
    let leap = flags >> 6;
    let version = (flags >> 3) & 0x07;
    let mode = flags & 0x07;
    if !(1..=4).contains(&version) || mode == 0 {
        return None;
    }
    let stratum = payload[1];
    let poll = payload[2] as i8;
    let precision = payload[3] as i8;
    let fixed_16_16 = |at: usize| u32_at(payload, at).map_or(0.0, |value| value as f64 / 65_536.0);
    let reference_id = match stratum {
        0 | 1 => String::from_utf8_lossy(&payload[12..16]).trim_end_matches('\0').to_string(),
        _ => std::net::Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]).to_string(),
    };
    let mut fields = vec![
        Field::new("Flags", 0, 1, format!("leap {leap}, version {version}, mode {mode} ({})", ntp_mode_name(mode))),
        Field::new("Stratum", 1, 1, stratum.to_string()),
        Field::new("Poll interval", 2, 1, format!("2^{poll} s")),
        Field::new("Precision", 3, 1, format!("2^{precision} s")),
        Field::new("Root delay", 4, 4, format!("{:.6} s", fixed_16_16(4))),
        Field::new("Root dispersion", 8, 4, format!("{:.6} s", fixed_16_16(8))),
        Field::new("Reference ID", 12, 4, reference_id),
        Field::new("Reference timestamp", 16, 8, ntp_timestamp(payload, 16)),
        Field::new("Origin timestamp", 24, 8, ntp_timestamp(payload, 24)),
        Field::new("Receive timestamp", 32, 8, ntp_timestamp(payload, 32)),
        Field::new("Transmit timestamp", 40, 8, ntp_timestamp(payload, 40)),
    ];
    let mut len = NTP_PACKET_LEN;
    // Control (6) and private (7) messages share only the first byte with
    // the time packet; what follows their 48 bytes is not an extension.
    if mode < NTP_MODE_CONTROL {
        len = ntp_extensions_and_mac(payload, &mut fields);
    }
    let info = format!("NTP version {version}, {}, stratum {stratum}", ntp_mode_name(mode));
    Some(AppLayer { name: "NTP", key: "ntp", len, fields, info })
}

/// Lengths of what may follow the 48-byte packet as a MAC alone: a 4-byte
/// key ID of zero (a crypto-NAK), or a key ID and a 16-byte (MD5) or 20-byte
/// (SHA-1) digest.
const NTP_MAC_LENGTHS: [usize; 3] = [4, 20, 24];
/// The longest MAC; anything longer after the packet starts with extensions.
const NTP_LONGEST_MAC: usize = 24;
/// The shortest extension field allowed (RFC 7822): a 4-byte header and
/// 12 bytes of value.
const NTP_MIN_EXTENSION_LEN: usize = 16;
/// Most extension fields listed.
const NTP_MAX_EXTENSIONS: usize = 16;
const NTP_KEY_ID_LEN: usize = 4;

/// The extension fields (RFC 7822) and message authentication code (RFC
/// 5905) after the 48-byte packet, added to `fields`. Returns where the NTP
/// message ends.
fn ntp_extensions_and_mac(payload: &[u8], fields: &mut Vec<Field>) -> usize {
    let mut at = NTP_PACKET_LEN;
    let mut extensions = Vec::new();
    while extensions.len() < NTP_MAX_EXTENSIONS && payload.len() - at > NTP_LONGEST_MAC {
        let (Some(field_type), Some(len)) = (u16_at(payload, at), u16_at(payload, at + 2)) else { break };
        let len = len as usize;
        if len < NTP_MIN_EXTENSION_LEN || !len.is_multiple_of(4) || at + len > payload.len() {
            break;
        }
        extensions.push(Field::new(format!("Extension field {}", extensions.len()), at, len, format!("type {field_type:#06x}, {len} bytes")).with_children(vec![
            Field::new("Field type", at, 2, format!("{field_type:#06x}")),
            Field::new("Length", at + 2, 2, len.to_string()),
            Field::new("Value", at + 4, len - 4, super::hex_preview(&payload[at + 4..at + len], 16)),
        ]));
        at += len;
    }
    if !extensions.is_empty() {
        fields.push(Field::new("Extension fields", NTP_PACKET_LEN, at - NTP_PACKET_LEN, format!("{} extension fields", extensions.len())).with_children(extensions));
    }
    let rest = payload.len() - at;
    if NTP_MAC_LENGTHS.contains(&rest) {
        let key_id = u32_at(payload, at).unwrap_or_default();
        let mut mac = vec![Field::new("Key ID", at, NTP_KEY_ID_LEN, key_id.to_string())];
        let digest = &payload[at + NTP_KEY_ID_LEN..];
        let description = if digest.is_empty() {
            "crypto-NAK".to_string()
        } else {
            mac.push(Field::new("Message digest", at + NTP_KEY_ID_LEN, digest.len(), super::hex_preview(digest, 20)));
            format!("key {key_id}, {}-byte digest", digest.len())
        };
        fields.push(Field::new("Message authentication code", at, rest, description).with_children(mac));
        at += rest;
    }
    at
}

// ---------------------------------------------------------------------------
// Modbus/TCP
// ---------------------------------------------------------------------------

const MBAP_HEADER_LEN: usize = 7;
const MODBUS_EXCEPTION_BIT: u8 = 0x80;
/// The MBAP length counts the unit ID, the function code and the data; a
/// Modbus PDU is at most 253 bytes.
const MODBUS_MAX_LENGTH: u16 = 254;

fn modbus_function_name(code: u8) -> &'static str {
    match code & !MODBUS_EXCEPTION_BIT {
        1 => "Read Coils",
        2 => "Read Discrete Inputs",
        3 => "Read Holding Registers",
        4 => "Read Input Registers",
        5 => "Write Single Coil",
        6 => "Write Single Register",
        8 => "Diagnostics",
        15 => "Write Multiple Coils",
        16 => "Write Multiple Registers",
        23 => "Read/Write Multiple Registers",
        43 => "Encapsulated Interface Transport",
        _ => "Unknown function",
    }
}

/// A Modbus/TCP ADU: the MBAP header and the function code. `is_request`
/// says whether it travels to the server's port.
pub fn dissect_modbus(payload: &[u8], is_request: bool) -> Option<AppLayer> {
    let transaction = u16_at(payload, 0)?;
    let protocol = u16_at(payload, 2)?;
    let length = u16_at(payload, 4)?;
    let unit = *payload.get(6)?;
    let function = *payload.get(MBAP_HEADER_LEN)?;
    if protocol != 0 || !(2..=MODBUS_MAX_LENGTH).contains(&length) {
        return None;
    }
    let end = (6 + length as usize).min(payload.len());
    let is_exception = function & MODBUS_EXCEPTION_BIT != 0;
    let mut fields = vec![
        Field::new("Transaction ID", 0, 2, transaction.to_string()),
        Field::new("Protocol ID", 2, 2, protocol.to_string()),
        Field::new("Length", 4, 2, length.to_string()),
        Field::new("Unit ID", 6, 1, unit.to_string()),
        Field::new("Function code", 7, 1, format!("{} ({})", function & !MODBUS_EXCEPTION_BIT, modbus_function_name(function))),
    ];
    let data_at = MBAP_HEADER_LEN + 1;
    if is_exception {
        if let Some(&code) = payload.get(data_at) {
            fields.push(Field::new("Exception code", data_at, 1, code.to_string()));
        }
    } else if is_request && (1..=4).contains(&function) && end >= data_at + 4 {
        fields.push(Field::new("Reference number", data_at, 2, u16_at(payload, data_at)?.to_string()));
        fields.push(Field::new("Quantity", data_at + 2, 2, u16_at(payload, data_at + 2)?.to_string()));
    } else if end > data_at {
        fields.push(Field::new("Data", data_at, end - data_at, super::hex_preview(&payload[data_at..end], 16)));
    }
    let direction = if is_request { "Query" } else { "Response" };
    let exception = if is_exception { " (exception)" } else { "" };
    let info = format!("{direction}: trans {transaction}; unit {unit}; func {}: {}{exception}", function & !MODBUS_EXCEPTION_BIT, modbus_function_name(function));
    Some(AppLayer { name: "Modbus/TCP", key: "modbus", len: end, fields, info })
}

// ---------------------------------------------------------------------------
// MQTT
// ---------------------------------------------------------------------------

/// Most bytes of the remaining-length varint.
const MQTT_MAX_LENGTH_BYTES: usize = 4;
const MQTT_PUBLISH: u8 = 3;
const MQTT_CONNECT: u8 = 1;

fn mqtt_type_name(kind: u8) -> &'static str {
    match kind {
        1 => "Connect Command",
        2 => "Connect Ack",
        3 => "Publish Message",
        4 => "Publish Ack",
        5 => "Publish Received",
        6 => "Publish Release",
        7 => "Publish Complete",
        8 => "Subscribe Request",
        9 => "Subscribe Ack",
        10 => "Unsubscribe Request",
        11 => "Unsubscribe Ack",
        12 => "Ping Request",
        13 => "Ping Response",
        14 => "Disconnect Req",
        15 => "Auth Exchange",
        _ => "Reserved",
    }
}

/// The variable-length "remaining length" after the first byte: its value
/// and how many bytes it takes.
fn mqtt_remaining_length(payload: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    for index in 0..MQTT_MAX_LENGTH_BYTES {
        let byte = *payload.get(1 + index)?;
        value |= ((byte & 0x7F) as usize) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

/// A UTF-8 string with a two-byte length prefix: the text and bytes used.
fn mqtt_string(payload: &[u8], at: usize) -> Option<(String, usize)> {
    let len = u16_at(payload, at)? as usize;
    let text = payload.get(at + 2..at + 2 + len)?;
    Some((String::from_utf8_lossy(text).into_owned(), 2 + len))
}

/// An MQTT control packet: the fixed header, and the topic of a publish.
pub fn dissect_mqtt(payload: &[u8]) -> Option<AppLayer> {
    let first = *payload.first()?;
    let kind = first >> 4;
    if kind == 0 {
        return None;
    }
    let (remaining, length_bytes) = mqtt_remaining_length(payload)?;
    let header_len = 1 + length_bytes;
    let end = header_len.checked_add(remaining)?;
    if end > payload.len() {
        return None;
    }
    let flags = first & 0x0F;
    let mut fields = vec![
        Field::new("Header flags", 0, 1, format!("{first:#04x} ({}, flags {flags:#x})", mqtt_type_name(kind))),
        Field::new("Remaining length", 1, length_bytes, remaining.to_string()),
    ];
    let mut info = mqtt_type_name(kind).to_string();
    match kind {
        MQTT_PUBLISH => {
            let qos = (flags >> 1) & 0x03;
            let (topic, topic_len) = mqtt_string(payload, header_len)?;
            fields.push(Field::new("Topic", header_len, topic_len, topic.clone()));
            let mut at = header_len + topic_len;
            if qos > 0 {
                fields.push(Field::new("Message identifier", at, 2, u16_at(payload, at)?.to_string()));
                at += 2;
            }
            if end > at {
                fields.push(Field::new("Message", at, end - at, String::from_utf8_lossy(&payload[at..end.min(at + 64)]).into_owned()));
            }
            info = format!("{info} (QoS {qos}) [{topic}]");
        }
        MQTT_CONNECT => {
            if let Some((protocol, protocol_len)) = mqtt_string(payload, header_len) {
                fields.push(Field::new("Protocol name", header_len, protocol_len, protocol));
                if let Some(&level) = payload.get(header_len + protocol_len) {
                    fields.push(Field::new("Protocol level", header_len + protocol_len, 1, level.to_string()));
                }
            }
        }
        _ => {
            if end > header_len {
                fields.push(Field::new("Body", header_len, end - header_len, super::hex_preview(&payload[header_len..end], 16)));
            }
        }
    }
    Some(AppLayer { name: "MQTT", key: "mqtt", len: end, fields, info })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DNS query for `name`, type A, with transaction ID 0x1234.
    fn dns_query(name: &str) -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            message.push(label.len() as u8);
            message.extend_from_slice(label.as_bytes());
        }
        message.extend_from_slice(&[0, 0, 1, 0, 1]);
        message
    }

    fn field<'a>(layer: &'a AppLayer, name: &str) -> &'a Field {
        layer.fields.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no field {name} in {:?}", layer.fields))
    }

    #[test]
    fn a_dns_query_names_its_question_and_transaction() {
        let message = dns_query("example.com");
        let layer = dissect_dns(&message).expect("DNS");
        assert_eq!(layer.info, "Standard query 0x1234 A example.com");
        assert_eq!(field(&layer, "Transaction ID").value, "0x1234");
        let question = &field(&layer, "Question section").children[0];
        assert_eq!(question.children[0].value, "example.com");
        assert_eq!((question.offset, question.len), (12, 17));
        assert_eq!(layer.len, message.len());
    }

    #[test]
    fn a_dns_response_follows_compression_pointers_to_its_answer() {
        let mut message = dns_query("example.com");
        message[2] = 0x81;
        message[3] = 0x80;
        message[7] = 1;
        // Answer: pointer to the question name at 12, type A, class IN, TTL 60, 4 bytes.
        message.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let layer = dissect_dns(&message).expect("DNS");
        assert_eq!(layer.info, "Standard query response 0x1234 A example.com A 93.184.216.34");
        let answer = &field(&layer, "Answer section").children[0];
        assert_eq!(answer.children[0].value, "example.com");
    }

    #[test]
    fn a_dns_response_lists_its_authority_and_additional_records_and_the_edns_opt_record() {
        let mut message = dns_query("example.com");
        message[2] = 0x81;
        message[3] = 0x80;
        message[7] = 1; // one answer
        message[9] = 1; // one authority record
        message[11] = 2; // two additional records
        message.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        // Authority: example.com NS ns1.example.com (ns1 + pointer to example.com).
        message.extend_from_slice(&[0xC0, 12, 0, 2, 0, 1, 0, 0, 0x0E, 0x10, 0, 6, 3, b'n', b's', b'1', 0xC0, 12]);
        let ns_name_at = message.len() - 6;
        // Additional: ns1.example.com A 192.0.2.53.
        message.extend_from_slice(&[0xC0, ns_name_at as u8, 0, 1, 0, 1, 0, 0, 0x0E, 0x10, 0, 4, 192, 0, 2, 53]);
        // Additional: OPT, root name, payload size 1232, DO set, a cookie option.
        message.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 12, 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let layer = dissect_dns(&message).expect("DNS");
        assert_eq!(layer.len, message.len(), "the layer covers every section");
        assert_eq!(layer.info, "Standard query response 0x1234 A example.com A 93.184.216.34");
        let authority = &field(&layer, "Authority section").children[0];
        assert_eq!(authority.name, "Authority 0");
        assert_eq!(authority.children[5].value, "ns1.example.com");
        let additional = &field(&layer, "Additional section").children;
        assert_eq!(additional.len(), 2);
        assert_eq!(additional[0].children[5].value, "192.0.2.53");
        let opt = &additional[1];
        let child = |name: &str| opt.children.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no {name} in {opt:?}"));
        assert_eq!(child("UDP payload size").value, "1232");
        assert!(child("EDNS flags").value.contains("DNSSEC OK"));
        let cookie = &child("Options").children[0];
        assert!(cookie.value.starts_with("Cookie (8 bytes)"), "{}", cookie.value);
        assert_eq!(cookie.offset + cookie.len, message.len());
    }

    #[test]
    fn a_dns_record_cut_short_ends_the_message_without_losing_the_sections_before_it() {
        let mut message = dns_query("example.com");
        message[2] = 0x81;
        message[7] = 1;
        message[9] = 1;
        message.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let answers_end = message.len();
        message.extend_from_slice(&[0xC0, 12, 0, 2, 0, 1, 0, 0]);
        let layer = dissect_dns(&message).expect("DNS");
        assert_eq!(layer.len, answers_end);
        assert!(layer.fields.iter().all(|f| f.name != "Authority section"));
    }

    #[test]
    fn a_dns_name_that_points_at_itself_is_rejected_rather_than_looping() {
        let message = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1];
        assert!(dissect_dns(&message).is_none());
        assert!(dissect_dns(&[0; 5]).is_none());
    }

    #[test]
    fn an_http_request_lists_its_request_line_and_headers() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let layer = dissect_http(payload).expect("HTTP");
        assert_eq!(layer.info, "GET /index.html HTTP/1.1");
        let headers = &field(&layer, "Headers").children;
        assert_eq!(headers.len(), 2);
        assert_eq!((headers[0].name.as_str(), headers[0].value.as_str()), ("Host", "example.com"));
        assert!(dissect_http(b"GETTING warmer").is_none());
    }

    #[test]
    fn look_alike_protocols_and_the_middle_of_a_stream_are_not_taken_for_http() {
        for payload in [
            &b"OPTIONS rtsp://10.0.0.1:554/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n"[..],
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n",
            b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP host\r\n\r\n",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            b"GET /a-request-line-cut-short-by-the-segment HTTP/1.",
            b"GET /index.html\r\n\r\n",
            b"FETCH /index.html HTTP/1.1\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1\r\n",
            b"<html><body>GET / HTTP/1.1\r\n</body></html>",
            b"ttp-equiv=\"refresh\" content=\"0\">\r\nHTTP/1.1 200 OK\r\n",
        ] {
            assert!(dissect_http(payload).is_none(), "{}", String::from_utf8_lossy(payload));
            assert_eq!(dissect_application(Transport::Tcp, 40000, 80, payload), None);
        }
        assert!(dissect_http(b"HTTP/1.0 404\r\n\r\n").is_some(), "a reason phrase may be left out");
        assert!(dissect_http(b"PROPFIND /dav/ HTTP/1.1\r\nDepth: 1\r\n\r\n").is_some());
    }

    #[test]
    fn an_http_response_keeps_its_body_as_a_field() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let layer = dissect_http(payload).expect("HTTP");
        assert_eq!(layer.info, "HTTP/1.1 200 OK");
        let body = field(&layer, "Body");
        assert_eq!(&payload[body.offset..body.offset + body.len], b"hello");
    }

    #[test]
    fn an_ntp_client_request_shows_its_mode_and_transmit_time() {
        let mut packet = vec![0u8; NTP_PACKET_LEN];
        packet[0] = 0x23; // leap 0, version 4, mode 3
        // Transmit timestamp: 2024-01-01 00:00:00 UTC.
        let seconds = (1_704_067_200u64 + NTP_TO_UNIX_SECONDS) as u32;
        packet[40..44].copy_from_slice(&seconds.to_be_bytes());
        let layer = dissect_ntp(&packet).expect("NTP");
        assert_eq!(layer.info, "NTP version 4, client, stratum 0");
        assert!(field(&layer, "Transmit timestamp").value.starts_with("2024-01-01 00:00:00 UTC"));
        assert_eq!(field(&layer, "Origin timestamp").value, "(not set)");
        assert!(dissect_ntp(&packet[..20]).is_none());
    }

    #[test]
    fn an_ntp_packet_includes_its_extension_fields_and_message_authentication_code() {
        let mut packet = vec![0u8; NTP_PACKET_LEN];
        packet[0] = 0x24; // version 4, server
        // An extension field: type 0x0104 (unique identifier), 36 bytes.
        packet.extend_from_slice(&[0x01, 0x04, 0, 36]);
        packet.extend_from_slice(&[0xAB; 32]);
        // A MAC: key ID 7 and an MD5 digest.
        packet.extend_from_slice(&7u32.to_be_bytes());
        packet.extend_from_slice(&[0x5A; 16]);
        let layer = dissect_ntp(&packet).expect("NTP");
        assert_eq!(layer.len, packet.len());
        let extension = &field(&layer, "Extension fields").children[0];
        assert_eq!((extension.offset, extension.len), (48, 36));
        assert_eq!(extension.children[0].value, "0x0104");
        let mac = field(&layer, "Message authentication code");
        assert_eq!((mac.offset, mac.len), (84, 20));
        assert_eq!(mac.children[0].value, "7");
    }

    #[test]
    fn an_ntp_packet_with_only_a_mac_or_with_stray_bytes_after_it_is_read_carefully() {
        let mut packet = vec![0u8; NTP_PACKET_LEN];
        packet[0] = 0x1B; // version 3, client
        packet.extend_from_slice(&[0, 0, 0, 1]);
        packet.extend_from_slice(&[0x11; 20]);
        let layer = dissect_ntp(&packet).expect("NTP");
        assert_eq!(field(&layer, "Message authentication code").value, "key 1, 20-byte digest");
        assert_eq!(layer.len, 72);
        // Seven bytes fit neither an extension nor a MAC: the message ends at 48.
        let mut odd = vec![0u8; NTP_PACKET_LEN];
        odd[0] = 0x23;
        odd.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(dissect_ntp(&odd).expect("NTP").len, NTP_PACKET_LEN);
        // An extension claiming more bytes than there are is not listed.
        let mut overlong = vec![0u8; NTP_PACKET_LEN];
        overlong[0] = 0x23;
        overlong.extend_from_slice(&[0x01, 0x04, 0x01, 0x00]);
        overlong.extend_from_slice(&[0; 28]);
        let layer = dissect_ntp(&overlong).expect("NTP");
        assert!(layer.fields.iter().all(|f| f.name != "Extension fields"));
        assert_eq!(layer.len, NTP_PACKET_LEN);
    }

    #[test]
    fn a_modbus_read_request_names_the_function_and_registers() {
        let payload = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6B, 0x00, 0x03];
        let layer = dissect_modbus(&payload, true).expect("Modbus");
        assert_eq!(layer.info, "Query: trans 1; unit 17; func 3: Read Holding Registers");
        assert_eq!(field(&layer, "Reference number").value, "107");
        assert_eq!(field(&layer, "Quantity").value, "3");
        let mut wrong_protocol = payload;
        wrong_protocol[3] = 1;
        assert!(dissect_modbus(&wrong_protocol, true).is_none());
    }

    #[test]
    fn a_modbus_exception_response_reports_its_code() {
        let payload = [0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x02];
        let layer = dissect_modbus(&payload, false).expect("Modbus");
        assert!(layer.info.ends_with("(exception)"), "{}", layer.info);
        assert_eq!(field(&layer, "Exception code").value, "2");
    }

    #[test]
    fn an_mqtt_publish_names_its_topic_and_quality_of_service() {
        let mut payload = vec![0x32, 0];
        payload.extend_from_slice(&[0, 9]);
        payload.extend_from_slice(b"home/temp");
        payload.extend_from_slice(&[0, 7]);
        payload.extend_from_slice(b"21.5");
        payload[1] = (payload.len() - 2) as u8;
        let layer = dissect_mqtt(&payload).expect("MQTT");
        assert_eq!(layer.info, "Publish Message (QoS 1) [home/temp]");
        assert_eq!(field(&layer, "Message identifier").value, "7");
        assert_eq!(field(&layer, "Message").value, "21.5");
    }

    #[test]
    fn an_mqtt_remaining_length_spans_several_bytes_and_overruns_are_rejected() {
        let mut payload = vec![0xC0, 0x80, 0x01];
        payload.extend(std::iter::repeat_n(0u8, 128));
        let layer = dissect_mqtt(&payload).expect("MQTT");
        assert_eq!(field(&layer, "Remaining length").value, "128");
        assert_eq!(layer.len, 131);
        assert!(dissect_mqtt(&[0x30, 0x7F, 0, 0]).is_none(), "claims more bytes than there are");
        assert!(dissect_mqtt(&[0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]).is_none(), "a varint longer than four bytes");
    }

    #[test]
    fn arbitrary_payloads_never_make_an_application_parser_panic() {
        let mut state = 0x9E37_79B9u32;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        for round in 0..20_000 {
            let len = (next() % 120) as usize;
            let mut payload: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            // Bias some rounds towards DNS compression pointers and plausible headers.
            if round % 2 == 0 && len > 14 {
                payload[12] = 0xC0 | (next() as u8 & 0x3F);
                payload[5] = 1;
            }
            let _ = dissect_dns(&payload);
            let _ = dissect_dns_over_tcp(&payload);
            let _ = dissect_http(&payload);
            let _ = dissect_ntp(&payload);
            let _ = dissect_modbus(&payload, round % 3 == 0);
            let _ = dissect_mqtt(&payload);
        }
    }

    #[test]
    fn ports_choose_the_parser_and_http_is_sniffed_on_any_tcp_port() {
        let query = dns_query("a.b");
        assert_eq!(dissect_application(Transport::Udp, 40000, 53, &query).map(|l| l.key), Some("dns"));
        assert_eq!(dissect_application(Transport::Tcp, 40000, 9999, b"GET / HTTP/1.1\r\n\r\n").map(|l| l.key), Some("http"));
        assert_eq!(dissect_application(Transport::Udp, 1, 2, &query), None);
        let mut over_tcp = (query.len() as u16).to_be_bytes().to_vec();
        over_tcp.extend_from_slice(&query);
        let layer = dissect_application(Transport::Tcp, 53, 40000, &over_tcp).expect("DNS over TCP");
        assert_eq!(layer.fields[0].name, "Length");
        assert_eq!(layer.fields[1].offset, 2);
    }
}
