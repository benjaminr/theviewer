//! Packet captures (pcap, pcapng) via pcap-parser and etherparse, plus
//! heuristics for protocol traffic that has no container: TLS records, HTTP
//! messages, SSH banners and DNS messages.

use etherparse::{LinkSlice, NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::pcapng::Block;

use super::{MAX_CHILDREN, MAX_EXTENT, guarded, text_preview, u16be, u32be, u32le};
use crate::plugin::{Category, Detector, Field, Finding, Parser, ScanContext};

const SOURCE: &str = "parsers.protocol";
/// Packets dissected in detail; the rest are only counted.
const DISSECTED_PACKETS: usize = 50;
/// Packets counted before giving up on a huge capture.
const MAX_PACKETS: usize = 100_000;

fn link_type_name(link_type: u32) -> String {
    match link_type {
        0 => "BSD loopback".to_string(),
        1 => "Ethernet".to_string(),
        101 => "raw IP".to_string(),
        105 => "IEEE 802.11".to_string(),
        113 => "Linux cooked (SLL)".to_string(),
        127 => "802.11 radiotap".to_string(),
        228 => "raw IPv4".to_string(),
        229 => "raw IPv6".to_string(),
        276 => "Linux cooked v2".to_string(),
        other => format!("link type {other}"),
    }
}

/// One-line summary of a packet's addresses and transport.
fn summarise_packet(link_type: u32, data: &[u8]) -> String {
    let sliced = match link_type {
        1 => SlicedPacket::from_ethernet(data),
        101 | 228 | 229 => SlicedPacket::from_ip(data),
        _ => return format!("{} bytes", data.len()),
    };
    let Ok(packet) = sliced else {
        return format!("{} bytes, undecodable", data.len());
    };
    let (source, destination) = match &packet.net {
        Some(NetSlice::Ipv4(ip)) => (ip.header().source_addr().to_string(), ip.header().destination_addr().to_string()),
        Some(NetSlice::Ipv6(ip)) => (ip.header().source_addr().to_string(), ip.header().destination_addr().to_string()),
        Some(NetSlice::Arp(_)) => return "ARP".to_string(),
        _ => match &packet.link {
            Some(LinkSlice::Ethernet2(eth)) => return format!("Ethernet type {:?}", eth.ether_type()),
            _ => return format!("{} bytes", data.len()),
        },
    };
    match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let mut flags = Vec::new();
            if tcp.syn() {
                flags.push("SYN");
            }
            if tcp.ack() {
                flags.push("ACK");
            }
            if tcp.fin() {
                flags.push("FIN");
            }
            if tcp.rst() {
                flags.push("RST");
            }
            if tcp.psh() {
                flags.push("PSH");
            }
            format!("{source}:{} → {destination}:{} TCP [{}]", tcp.source_port(), tcp.destination_port(), flags.join(","))
        }
        Some(TransportSlice::Udp(udp)) => format!("{source}:{} → {destination}:{} UDP", udp.source_port(), udp.destination_port()),
        Some(TransportSlice::Icmpv4(_)) => format!("{source} → {destination} ICMP"),
        Some(TransportSlice::Icmpv6(_)) => format!("{source} → {destination} ICMPv6"),
        _ => format!("{source} → {destination}"),
    }
}

// ---------------------------------------------------------------------------
// pcap
// ---------------------------------------------------------------------------

pub struct PcapParser;

const PCAP_MAGICS: [[u8; 4]; 4] = [[0xD4, 0xC3, 0xB2, 0xA1], [0xA1, 0xB2, 0xC3, 0xD4], [0x4D, 0x3C, 0xB2, 0xA1], [0xA1, 0xB2, 0x3C, 0x4D]];

impl Parser for PcapParser {
    fn id(&self) -> &str {
        "pcap"
    }

    fn name(&self) -> &str {
        "pcap capture"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        PCAP_MAGICS.iter().any(|magic| bytes.starts_with(magic))
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) || bytes.len() < 24 {
            return None;
        }
        let (_, header) = guarded(|| pcap_parser::parse_pcap_header(bytes).ok())?;
        let big_endian = header.is_bigendian();
        let link_type = header.network.0 as u32;
        let mut packets = Vec::new();
        let mut count = 0usize;
        let mut at = 24;
        let mut complete = false;
        while count < MAX_PACKETS && at < MAX_EXTENT {
            if at >= bytes.len() {
                complete = true;
                break;
            }
            let frame = if big_endian { pcap_parser::parse_pcap_frame_be(&bytes[at..]) } else { pcap_parser::parse_pcap_frame(&bytes[at..]) };
            let Ok((_, block)) = frame else { break };
            let len = 16 + block.caplen as usize;
            if count < DISSECTED_PACKETS {
                packets.push(Field::new(
                    format!("packet {}", count + 1),
                    base + at,
                    len,
                    format!("t={}.{:06} caplen {}: {}", block.ts_sec, block.ts_usec, block.caplen, summarise_packet(link_type, block.data)),
                ));
            }
            count += 1;
            at += len;
        }
        if count == 0 {
            return None;
        }
        let extent = at.min(bytes.len());
        let fields = vec![
            Field::new("file header", base, 24, link_type_name(link_type)).with_children(vec![
                Field::new("magic", base, 4, if big_endian { "big endian" } else { "little endian" }),
                Field::new("snaplen", base + 16, 4, header.snaplen.to_string()),
                Field::new("link type", base + 20, 4, link_type_name(link_type)),
            ]),
            Field::new("packets", base + 24, extent - 24, format!("{count} packets")).with_children(packets),
        ];
        Some(
            Finding::new("pcap", SOURCE, Category::Protocol, base, extent)
                .title("pcap capture")
                .detail(format!("pcap, {}, {count} packets{}", link_type_name(link_type), if complete { "" } else { ", truncated" }))
                .confidence(if complete { 1.0 } else { 0.8 })
                .fields(fields),
        )
    }
}

// ---------------------------------------------------------------------------
// pcapng
// ---------------------------------------------------------------------------

pub struct PcapNgParser;

impl Parser for PcapNgParser {
    fn id(&self) -> &str {
        "pcapng"
    }

    fn name(&self) -> &str {
        "pcapng capture"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(&[0x0A, 0x0D, 0x0D, 0x0A]) && (bytes.get(8..12) == Some(&[0x4D, 0x3C, 0x2B, 0x1A]) || bytes.get(8..12) == Some(&[0x1A, 0x2B, 0x3C, 0x4D]))
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let big_endian = bytes.get(8..12) == Some(&[0x1A, 0x2B, 0x3C, 0x4D]);
        let mut fields = Vec::new();
        let mut link_type = 1u32;
        let mut count = 0usize;
        let mut at = 0;
        let mut complete = false;
        while at < bytes.len() && fields.len() < MAX_CHILDREN && at < MAX_EXTENT {
            let result = guarded(|| {
                let parsed = if big_endian { pcap_parser::pcapng::parse_block_be(&bytes[at..]) } else { pcap_parser::pcapng::parse_block_le(&bytes[at..]) };
                let current_link = link_type;
                parsed.ok().map(|(rest, block)| (bytes.len() - at - rest.len(), describe_block(&block, &mut link_type, &mut count, current_link)))
            });
            let Some((len, description)) = result else { break };
            if len == 0 {
                break;
            }
            if fields.len() < DISSECTED_PACKETS + 8 {
                fields.push(Field::new(description.0, base + at, len, description.1));
            }
            at += len;
            if at >= bytes.len() {
                complete = true;
            }
        }
        if fields.is_empty() {
            return None;
        }
        let extent = at.min(bytes.len());
        Some(
            Finding::new("pcapng", SOURCE, Category::Protocol, base, extent)
                .title("pcapng capture")
                .detail(format!("pcapng, {}, {count} packets{}", link_type_name(link_type), if complete { "" } else { ", truncated" }))
                .confidence(if complete { 1.0 } else { 0.8 })
                .fields(fields),
        )
    }
}

/// Name and value for one pcapng block, updating the interface link type and
/// packet count as it goes.
fn describe_block(block: &Block<'_>, link_type: &mut u32, count: &mut usize, current_link: u32) -> (String, String) {
    match block {
        Block::SectionHeader(section) => ("section header".to_string(), format!("version {}.{}", section.major_version, section.minor_version)),
        Block::InterfaceDescription(interface) => {
            *link_type = interface.linktype.0 as u32;
            ("interface description".to_string(), format!("{}, snaplen {}", link_type_name(*link_type), interface.snaplen))
        }
        Block::EnhancedPacket(packet) => {
            *count += 1;
            (format!("packet {count}"), format!("caplen {}: {}", packet.caplen, summarise_packet(current_link, packet.data)))
        }
        Block::SimplePacket(packet) => {
            *count += 1;
            (format!("packet {count}"), format!("{} bytes: {}", packet.data.len(), summarise_packet(current_link, packet.data)))
        }
        Block::NameResolution(_) => ("name resolution".to_string(), String::new()),
        Block::InterfaceStatistics(_) => ("interface statistics".to_string(), String::new()),
        _ => ("block".to_string(), String::new()),
    }
}

// ---------------------------------------------------------------------------
// Protocol heuristics
// ---------------------------------------------------------------------------

pub struct ProtocolHeuristics;

impl Detector for ProtocolHeuristics {
    fn id(&self) -> &str {
        "protocol.heuristics"
    }

    fn name(&self) -> &str {
        "Protocol heuristics"
    }

    fn categories(&self) -> Vec<Category> {
        vec![Category::Protocol]
    }

    fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut at = 0;
        while at + 8 <= window.len() && findings.len() < MAX_CHILDREN {
            let hit = match window[at] {
                0x16 => tls_records(window, at),
                b'G' | b'P' | b'H' | b'D' | b'O' => http_message(window, at),
                b'S' => ssh_banner(window, at),
                _ => None,
            }
            .or_else(|| if window[at + 4] == 0 && window[at + 5] == 1 { dns_message(window, at) } else { None });
            match hit {
                Some(finding) => {
                    let len = finding.len.max(1);
                    findings.push(finding.into_document(context.base));
                    at += len;
                }
                None => at += 1,
            }
        }
        findings
    }
}

/// A finding built with window-relative offsets; shifted to document offsets
/// once accepted.
struct Local(Finding);

impl Local {
    fn into_document(mut self, base: usize) -> Finding {
        self.0.start += base;
        for field in &mut self.0.fields {
            field.offset += base;
            for child in &mut field.children {
                child.offset += base;
            }
        }
        self.0
    }
}

impl std::ops::Deref for Local {
    type Target = Finding;
    fn deref(&self) -> &Finding {
        &self.0
    }
}

fn tls_record_len(window: &[u8], at: usize) -> Option<(u8, usize)> {
    let content = *window.get(at)?;
    if !matches!(content, 0x14..=0x17) || *window.get(at + 1)? != 0x03 || !matches!(*window.get(at + 2)?, 0x00..=0x04) {
        return None;
    }
    let len = u16be(window, at + 3)? as usize;
    (len > 0 && len <= 16_384 && at + 5 + len <= window.len()).then_some((content, len))
}

fn tls_handshake_name(kind: u8) -> &'static str {
    match kind {
        1 => "ClientHello",
        2 => "ServerHello",
        4 => "NewSessionTicket",
        8 => "EncryptedExtensions",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished",
        _ => "handshake",
    }
}

/// A run of TLS records starting with a handshake record.
fn tls_records(window: &[u8], at: usize) -> Option<Local> {
    let (content, len) = tls_record_len(window, at)?;
    if content != 0x16 {
        return None;
    }
    let handshake = *window.get(at + 5)?;
    if !matches!(handshake, 1 | 2 | 4 | 8 | 11..=16 | 20) {
        return None;
    }
    let handshake_len = ((*window.get(at + 6)? as usize) << 16) | ((*window.get(at + 7)? as usize) << 8) | *window.get(at + 8)? as usize;
    if handshake_len + 4 > len {
        return None;
    }
    let mut records = vec![Field::new(tls_handshake_name(handshake), at, 5 + len, format!("{} bytes", len))];
    let mut end = at + 5 + len;
    while let Some((next_content, next_len)) = tls_record_len(window, end) {
        if records.len() >= 64 {
            break;
        }
        let name = match next_content {
            0x14 => "ChangeCipherSpec",
            0x15 => "Alert",
            0x16 => tls_handshake_name(*window.get(end + 5).unwrap_or(&0)),
            _ => "ApplicationData",
        };
        records.push(Field::new(name, end, 5 + next_len, format!("{next_len} bytes")));
        end += 5 + next_len;
    }
    let version = match window[at + 2] {
        1 => "TLS 1.0",
        2 => "TLS 1.1",
        3 => "TLS 1.2/1.3",
        _ => "SSL 3.0",
    };
    let confidence = if records.len() >= 2 { 0.8 } else { 0.6 };
    Some(Local(
        Finding::new("tls-record", SOURCE, Category::Protocol, at, end - at)
            .title("TLS records")
            .detail(format!("{version} {} and {} more record(s)", tls_handshake_name(handshake), records.len() - 1))
            .confidence(confidence)
            .fields(records),
    ))
}

const HTTP_METHODS: [&[u8]; 7] = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH "];
const HTTP_MAX_HEADERS: usize = 16 * 1024;

fn http_message(window: &[u8], at: usize) -> Option<Local> {
    let slice = &window[at..];
    let is_request = HTTP_METHODS.iter().any(|method| slice.starts_with(method));
    let is_response = slice.starts_with(b"HTTP/1.");
    if !is_request && !is_response {
        return None;
    }
    let limit = slice.len().min(HTTP_MAX_HEADERS);
    let line_end = slice[..limit].windows(2).position(|pair| pair == b"\r\n")?;
    let line = &slice[..line_end];
    if !line.iter().all(|&b| (0x20..0x7F).contains(&b)) || line.len() < 12 {
        return None;
    }
    let line_text = String::from_utf8_lossy(line).to_string();
    if is_request && !line_text.contains(" HTTP/1.") {
        return None;
    }
    if is_response && !line_text.as_bytes().get(9..12).is_some_and(|code| code.iter().all(u8::is_ascii_digit)) {
        return None;
    }
    // Header block: printable lines until an empty one.
    let mut cursor = line_end + 2;
    let mut header_count = 0;
    let mut content_length: Option<usize> = None;
    let mut fields = vec![Field::new(if is_request { "request line" } else { "status line" }, at, line_end, line_text.clone())];
    loop {
        let rest = &slice[cursor..slice.len().min(HTTP_MAX_HEADERS)];
        let end = rest.windows(2).position(|pair| pair == b"\r\n")?;
        if end == 0 {
            cursor += 2;
            break;
        }
        let header = &rest[..end];
        if !header.iter().all(|&b| (0x20..0x7F).contains(&b) || b == b'\t') || !header.contains(&b':') {
            return None;
        }
        let text = String::from_utf8_lossy(header).to_string();
        if let Some(value) = text.strip_prefix("Content-Length:").or_else(|| text.strip_prefix("content-length:")) {
            content_length = value.trim().parse().ok();
        }
        if header_count < 64 {
            fields.push(Field::new("header", at + cursor, end, text));
        }
        header_count += 1;
        cursor += end + 2;
    }
    let mut end = cursor;
    if let Some(body) = content_length
        && body <= slice.len() - cursor
        && body <= MAX_EXTENT
    {
        fields.push(Field::new("body", at + cursor, body, format!("{body} bytes")));
        end += body;
    }
    let title = if is_request { format!("HTTP request {}", line_text.split(' ').take(2).collect::<Vec<_>>().join(" ")) } else { format!("HTTP response {}", &line_text[9..line_text.len().min(12)]) };
    Some(Local(
        Finding::new("http", SOURCE, Category::Protocol, at, end)
            .title(title)
            .detail(format!("{line_text}, {header_count} headers"))
            .confidence(0.9)
            .fields(fields),
    ))
}

fn ssh_banner(window: &[u8], at: usize) -> Option<Local> {
    let slice = &window[at..];
    if !(slice.starts_with(b"SSH-2.0-") || slice.starts_with(b"SSH-1.99-")) {
        return None;
    }
    let limit = slice.len().min(255);
    let end = slice[..limit].iter().position(|&b| b == b'\n')?;
    let line = &slice[..end];
    if !line.iter().all(|&b| (0x20..0x7F).contains(&b) || b == b'\r') {
        return None;
    }
    Some(Local(
        Finding::new("ssh-banner", SOURCE, Category::Protocol, at, end + 1)
            .title("SSH banner")
            .detail(text_preview(line, 80))
            .confidence(0.9),
    ))
}

fn dns_message(window: &[u8], at: usize) -> Option<Local> {
    let slice = window.get(at..)?;
    if slice.len() < 17 {
        return None;
    }
    let flags = u16be(slice, 2)?;
    let opcode = (flags >> 11) & 0xF;
    let questions = u16be(slice, 4)?;
    let answers = u16be(slice, 6)?;
    let authority = u16be(slice, 8)?;
    let additional = u16be(slice, 10)?;
    if opcode != 0 || questions != 1 || answers > 50 || authority > 50 || additional > 50 {
        return None;
    }
    // Question name: labels of 1..=63 printable bytes, total ≤ 255, then 0.
    let mut cursor = 12;
    let mut labels = Vec::new();
    loop {
        let len = *slice.get(cursor)? as usize;
        cursor += 1;
        if len == 0 {
            break;
        }
        if len > 63 || cursor + len > slice.len() || cursor > 255 + 12 {
            return None;
        }
        let label = &slice[cursor..cursor + len];
        if !label.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_string());
        cursor += len;
    }
    if labels.is_empty() {
        return None;
    }
    let qtype = u16be(slice, cursor)?;
    let qclass = u16be(slice, cursor + 2)?;
    if !matches!(qtype, 1 | 2 | 5 | 6 | 12 | 15 | 16 | 28 | 33 | 35 | 43 | 46 | 48 | 65 | 255) || !matches!(qclass, 1 | 255) {
        return None;
    }
    cursor += 4;
    let qtype_name = match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        255 => "ANY",
        _ => "other",
    };
    let is_response = flags & 0x8000 != 0;
    let name = labels.join(".");
    let fields = vec![
        Field::new("header", at, 12, format!("id {:#06x}, {}", u16be(slice, 0)?, if is_response { "response" } else { "query" })),
        Field::new("question", at + 12, cursor - 12, format!("{name} {qtype_name}")),
    ];
    // Without walking answers we cannot know the exact extent; claim the
    // header and question, which is what we verified.
    let confidence = if answers > 0 && is_response { 0.7 } else { 0.6 };
    Some(Local(
        Finding::new("dns", SOURCE, Category::Protocol, at, cursor)
            .title(if is_response { "DNS response" } else { "DNS query" })
            .detail(format!("{name} {qtype_name}, {answers} answers"))
            .confidence(confidence)
            .fields(fields),
    ))
}

// Keep these helpers referenced for the byte-order variants the detectors use.
#[allow(dead_code)]
fn _unused(bytes: &[u8]) -> Option<u32> {
    u32be(bytes, 0).or_else(|| u32le(bytes, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    fn one_packet_pcap() -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12]).ipv4([192, 168, 1, 5], [10, 0, 0, 2], 64).udp(5353, 53);
        let payload = b"hello";
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, payload).unwrap();
        let mut pcap = Vec::new();
        pcap.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
        pcap.extend_from_slice(&2u16.to_le_bytes());
        pcap.extend_from_slice(&4u16.to_le_bytes());
        pcap.extend_from_slice(&0i32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&65535u32.to_le_bytes());
        pcap.extend_from_slice(&1u32.to_le_bytes());
        pcap.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        pcap.extend_from_slice(&123u32.to_le_bytes());
        pcap.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&packet);
        pcap
    }

    #[test]
    fn pcap_with_one_udp_packet_is_dissected() {
        let bytes = one_packet_pcap();
        assert!(PcapParser.looks_like(&bytes));
        let finding = PcapParser.parse(&bytes, 2000).expect("pcap");
        assert_eq!(finding.len, bytes.len());
        assert_eq!(finding.confidence, 1.0);
        assert!(finding.detail.contains("Ethernet, 1 packets"), "{}", finding.detail);
        let packet = &finding.fields[1].children[0];
        assert_eq!(packet.offset, 2024);
        assert!(packet.value.contains("192.168.1.5:5353 → 10.0.0.2:53 UDP"), "{}", packet.value);
    }

    #[test]
    fn heuristics_find_http_tls_ssh_and_dns() {
        let mut window = vec![0u8; 64];
        let http_at = window.len();
        window.extend_from_slice(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nabcd");
        window.extend_from_slice(&[0u8; 32]);
        let tls_at = window.len();
        // Handshake record carrying a 6-byte ClientHello body, then an alert record.
        window.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x0A, 0x01, 0x00, 0x00, 0x06, 1, 2, 3, 4, 5, 6]);
        window.extend_from_slice(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
        window.extend_from_slice(&[0u8; 32]);
        let ssh_at = window.len();
        window.extend_from_slice(b"SSH-2.0-OpenSSH_9.6\r\n");
        window.extend_from_slice(&[0u8; 32]);
        let dns_at = window.len();
        window.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7]);
        window.extend_from_slice(b"example");
        window.extend_from_slice(&[3]);
        window.extend_from_slice(b"com");
        window.extend_from_slice(&[0, 0, 1, 0, 1]);
        window.extend_from_slice(&[0u8; 32]);

        let findings = ProtocolHeuristics.scan(&window, &ScanContext { base: 100, document_len: window.len(), strides: vec![] });
        let find = |id: &str| findings.iter().find(|f| f.id == id).unwrap_or_else(|| panic!("{id} in {findings:?}"));
        let http = find("http");
        assert_eq!(http.start, 100 + http_at);
        assert!(http.title.starts_with("HTTP request GET /index.html"), "{}", http.title);
        assert_eq!(http.fields.last().unwrap().name, "body");
        let tls = find("tls-record");
        assert_eq!(tls.start, 100 + tls_at);
        assert_eq!(tls.len, 15 + 7);
        assert_eq!(tls.fields.len(), 2);
        assert!(tls.confidence >= 0.8);
        assert_eq!(find("ssh-banner").start, 100 + ssh_at);
        let dns = find("dns");
        assert_eq!(dns.start, 100 + dns_at);
        assert!(dns.detail.starts_with("example.com A"), "{}", dns.detail);
    }
}
