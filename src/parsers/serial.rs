//! Schemaless serialisation checks: protobuf wire format, MessagePack, CBOR,
//! JSON and XML text, and UTF-8 text runs. Each format is both a parser (for
//! the cursor) and feeds the window detector.

use super::{MAX_CHILDREN, MAX_EXTENT, hex_preview, text_preview};
use crate::plugin::{Category, Detector, Field, Finding, Parser, ScanContext};

const SOURCE: &str = "parsers.serial";
/// Smallest serialised value worth reporting from a window scan.
const MIN_SCAN_LEN: usize = 16;
/// Longest JSON or XML document the walkers will check.
const MAX_TEXT_SCAN: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Protobuf
// ---------------------------------------------------------------------------

fn read_varint(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *bytes.get(at + index)?;
        value |= ((byte & 0x7F) as u64) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

/// One protobuf field as walked from the wire.
struct WireField {
    offset: usize,
    len: usize,
    number: u64,
    wire_type: u8,
    value: String,
    children: Vec<Field>,
}

fn walk_protobuf(bytes: &[u8], base: usize, depth: usize) -> Option<Vec<WireField>> {
    let mut fields = Vec::new();
    let mut at = 0;
    while at < bytes.len() && fields.len() < MAX_CHILDREN {
        let (tag, tag_len) = read_varint(bytes, at)?;
        let wire_type = (tag & 7) as u8;
        let number = tag >> 3;
        if number == 0 || number > 536_870_911 {
            return None;
        }
        let value_at = at + tag_len;
        let (value, len, children) = match wire_type {
            0 => {
                let (value, len) = read_varint(bytes, value_at)?;
                (value.to_string(), len, Vec::new())
            }
            1 => {
                let raw = bytes.get(value_at..value_at + 8)?;
                (format!("{} / {}", u64::from_le_bytes(raw.try_into().ok()?), f64::from_le_bytes(raw.try_into().ok()?)), 8, Vec::new())
            }
            5 => {
                let raw = bytes.get(value_at..value_at + 4)?;
                (format!("{} / {}", u32::from_le_bytes(raw.try_into().ok()?), f32::from_le_bytes(raw.try_into().ok()?)), 4, Vec::new())
            }
            2 => {
                let (length, length_len) = read_varint(bytes, value_at)?;
                let length = length as usize;
                let data = bytes.get(value_at + length_len..value_at + length_len + length)?;
                let nested = if depth < 4 && length >= 2 { walk_protobuf(data, base + value_at + length_len, depth + 1) } else { None };
                let (text, children) = match nested {
                    Some(inner) if inner.len() >= 2 => (format!("message with {} fields", inner.len()), inner.into_iter().map(to_field).collect()),
                    _ => (
                        if std::str::from_utf8(data).is_ok_and(|s| s.chars().all(|c| !c.is_control() || c.is_whitespace())) {
                            format!("\"{}\"", text_preview(data, 48))
                        } else {
                            format!("{length} bytes: {}", hex_preview(data, 12))
                        },
                        Vec::new(),
                    ),
                };
                (text, length_len + length, children)
            }
            _ => return None,
        };
        fields.push(WireField { offset: base + at, len: tag_len + len, number, wire_type, value, children });
        at = value_at + len;
    }
    (at == bytes.len()).then_some(fields)
}

fn to_field(field: WireField) -> Field {
    let kind = match field.wire_type {
        0 => "varint",
        1 => "64-bit",
        2 => "bytes",
        _ => "32-bit",
    };
    Field::new(format!("field {} ({kind})", field.number), field.offset, field.len, field.value).with_children(field.children)
}

/// Confidence for a protobuf walk: more fields, ascending numbers and textual
/// payloads all make a real message more likely than a lucky byte run.
fn protobuf_confidence(fields: &[WireField]) -> f32 {
    let mut confidence: f32 = 0.4;
    let ascending = fields.windows(2).all(|pair| pair[0].number <= pair[1].number);
    if fields.len() >= 4 && ascending {
        confidence += 0.2;
    }
    if fields.iter().any(|f| f.value.starts_with('"') || f.value.starts_with("message with")) {
        confidence += 0.1;
    }
    if fields.iter().all(|f| f.number <= 1000) {
        confidence += 0.05;
    }
    confidence.min(0.75)
}

pub struct ProtobufParser;

impl Parser for ProtobufParser {
    fn id(&self) -> &str {
        "serial.protobuf"
    }

    fn name(&self) -> &str {
        "Protocol Buffers message"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        // A field number 1..=15 with a plausible wire type.
        bytes.first().is_some_and(|&b| b < 0x80 && b >> 3 >= 1 && matches!(b & 7, 0 | 1 | 2 | 5))
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        // Take the longest prefix that walks cleanly, trying message ends at
        // every field boundary from the start of the slice.
        let fields = longest_protobuf_prefix(bytes, base)?;
        if fields.len() < 3 {
            return None;
        }
        let len = fields.last().map(|f| f.offset + f.len - base).unwrap_or(0);
        let confidence = protobuf_confidence(&fields);
        let count = fields.len();
        Some(
            Finding::new("protobuf", SOURCE, Category::Encoding, base, len)
                .title("Protocol Buffers message")
                .detail(format!("{count} fields, {len} bytes"))
                .confidence(confidence)
                .fields(fields.into_iter().map(to_field).collect()),
        )
    }
}

fn longest_protobuf_prefix(bytes: &[u8], base: usize) -> Option<Vec<WireField>> {
    let mut best: Option<Vec<WireField>> = None;
    let mut at = 0;
    let mut fields = Vec::new();
    while at < bytes.len().min(MAX_EXTENT) && fields.len() < MAX_CHILDREN {
        let Some(one) = walk_one_field(bytes, at, base) else { break };
        at += one.len;
        fields.push(one);
        if fields.len() >= 3 {
            best = Some(fields.iter().map(clone_wire).collect());
        }
    }
    best
}

fn clone_wire(field: &WireField) -> WireField {
    WireField { offset: field.offset, len: field.len, number: field.number, wire_type: field.wire_type, value: field.value.clone(), children: field.children.clone() }
}

fn walk_one_field(bytes: &[u8], at: usize, base: usize) -> Option<WireField> {
    let (tag, tag_len) = read_varint(bytes, at)?;
    let wire_type = (tag & 7) as u8;
    let end = match wire_type {
        0 => at + tag_len + read_varint(bytes, at + tag_len)?.1,
        1 => at + tag_len + 8,
        5 => at + tag_len + 4,
        2 => {
            let (length, length_len) = read_varint(bytes, at + tag_len)?;
            // The length is untrusted: a huge value must not wrap the sum.
            usize::try_from(length).ok()?.checked_add(at + tag_len + length_len)?
        }
        _ => return None,
    };
    if end > bytes.len() {
        return None;
    }
    let mut walked = walk_protobuf(&bytes[at..end], base + at, 0)?;
    (walked.len() == 1).then(|| walked.remove(0))
}

// ---------------------------------------------------------------------------
// MessagePack
// ---------------------------------------------------------------------------

/// Size of the MessagePack value at `bytes[at]`, with a field for it.
fn msgpack_value(bytes: &[u8], at: usize, base: usize, depth: usize) -> Option<(usize, Field)> {
    let marker = *bytes.get(at)?;
    let be16 = |o: usize| bytes.get(o..o + 2).map(|b| u16::from_be_bytes([b[0], b[1]]) as usize);
    let be32 = |o: usize| bytes.get(o..o + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize);
    let leaf = |len: usize, name: &str, value: String| Some((len, Field::new(name, base + at, len, value)));
    let text = |header: usize, len: usize| -> Option<(usize, Field)> {
        let data = bytes.get(at + header..at + header + len)?;
        let value = std::str::from_utf8(data).ok()?;
        Some((header + len, Field::new("str", base + at, header + len, text_preview(value.as_bytes(), 48))))
    };
    let container = |header: usize, count: usize, is_map: bool| -> Option<(usize, Field)> {
        if depth > 16 || count > MAX_CHILDREN {
            return None;
        }
        let mut cursor = at + header;
        let mut children = Vec::new();
        for _ in 0..count {
            if is_map {
                let (key_len, key) = msgpack_value(bytes, cursor, base, depth + 1)?;
                cursor += key_len;
                let (value_len, mut value) = msgpack_value(bytes, cursor, base, depth + 1)?;
                value.name = format!("{} = {}", key.value, value.name);
                cursor += value_len;
                children.push(value);
            } else {
                let (len, value) = msgpack_value(bytes, cursor, base, depth + 1)?;
                cursor += len;
                children.push(value);
            }
        }
        let name = if is_map { "map" } else { "array" };
        Some((cursor - at, Field::new(name, base + at, cursor - at, format!("{count} items")).with_children(children)))
    };
    match marker {
        0x00..=0x7F => leaf(1, "uint", marker.to_string()),
        0x80..=0x8F => container(1, (marker & 0x0F) as usize, true),
        0x90..=0x9F => container(1, (marker & 0x0F) as usize, false),
        0xA0..=0xBF => text(1, (marker & 0x1F) as usize),
        0xC0 => leaf(1, "nil", String::new()),
        0xC2 => leaf(1, "bool", "false".to_string()),
        0xC3 => leaf(1, "bool", "true".to_string()),
        0xC4 => leaf(2 + *bytes.get(at + 1)? as usize, "bin", String::new()),
        0xC5 => leaf(3 + be16(at + 1)?, "bin", String::new()),
        0xC6 => leaf(5 + be32(at + 1)?, "bin", String::new()),
        0xCA => leaf(5, "f32", f32::from_be_bytes(bytes.get(at + 1..at + 5)?.try_into().ok()?).to_string()),
        0xCB => leaf(9, "f64", f64::from_be_bytes(bytes.get(at + 1..at + 9)?.try_into().ok()?).to_string()),
        0xCC => leaf(2, "uint", bytes.get(at + 1)?.to_string()),
        0xCD => leaf(3, "uint", be16(at + 1)?.to_string()),
        0xCE => leaf(5, "uint", be32(at + 1)?.to_string()),
        0xCF => leaf(9, "uint", u64::from_be_bytes(bytes.get(at + 1..at + 9)?.try_into().ok()?).to_string()),
        0xD0 => leaf(2, "int", (*bytes.get(at + 1)? as i8).to_string()),
        0xD1 => leaf(3, "int", (be16(at + 1)? as u16 as i16).to_string()),
        0xD2 => leaf(5, "int", (be32(at + 1)? as u32 as i32).to_string()),
        0xD3 => leaf(9, "int", i64::from_be_bytes(bytes.get(at + 1..at + 9)?.try_into().ok()?).to_string()),
        0xD4..=0xD8 => leaf(2 + (1usize << (marker - 0xD4)), "ext", String::new()),
        0xD9 => text(2, *bytes.get(at + 1)? as usize),
        0xDA => text(3, be16(at + 1)?),
        0xDB => text(5, be32(at + 1)?),
        0xDC => container(3, be16(at + 1)?, false),
        0xDD => container(5, be32(at + 1)?, false),
        0xDE => container(3, be16(at + 1)?, true),
        0xDF => container(5, be32(at + 1)?, true),
        0xE0..=0xFF => leaf(1, "int", (marker as i8).to_string()),
        _ => None,
    }
    .filter(|(len, _)| at + len <= bytes.len())
}

pub struct MessagePackParser;

impl Parser for MessagePackParser {
    fn id(&self) -> &str {
        "serial.msgpack"
    }

    fn name(&self) -> &str {
        "MessagePack value"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.first().is_some_and(|&b| matches!(b, 0x80..=0x9F | 0xDC..=0xDF))
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let (len, root) = msgpack_value(bytes, 0, base, 0)?;
        if root.children.len() < 2 || len < MIN_SCAN_LEN {
            return None;
        }
        Some(
            Finding::new("msgpack", SOURCE, Category::Encoding, base, len)
                .title("MessagePack value")
                .detail(format!("{} with {} items, {len} bytes", root.name, root.children.len()))
                .confidence(0.6)
                .fields(vec![root]),
        )
    }
}

// ---------------------------------------------------------------------------
// CBOR
// ---------------------------------------------------------------------------

/// Decode a CBOR argument (additional information) at `bytes[at]`.
fn cbor_argument(bytes: &[u8], at: usize) -> Option<(u8, u64, usize)> {
    let initial = *bytes.get(at)?;
    let major = initial >> 5;
    let info = initial & 0x1F;
    let (value, len) = match info {
        0..=23 => (info as u64, 1),
        24 => (*bytes.get(at + 1)? as u64, 2),
        25 => (u16::from_be_bytes(bytes.get(at + 1..at + 3)?.try_into().ok()?) as u64, 3),
        26 => (u32::from_be_bytes(bytes.get(at + 1..at + 5)?.try_into().ok()?) as u64, 5),
        27 => (u64::from_be_bytes(bytes.get(at + 1..at + 9)?.try_into().ok()?), 9),
        31 => (u64::MAX, 1), // indefinite length
        _ => return None,
    };
    Some((major, value, len))
}

fn cbor_value(bytes: &[u8], at: usize, base: usize, depth: usize) -> Option<(usize, Field)> {
    let (major, argument, header) = cbor_argument(bytes, at)?;
    if argument == u64::MAX {
        return None; // indefinite lengths are rare and hard to bound
    }
    let leaf = |len: usize, name: &str, value: String| Some((len, Field::new(name, base + at, len, value)));
    match major {
        0 => leaf(header, "uint", argument.to_string()),
        1 => leaf(header, "int", (-1i128 - argument as i128).to_string()),
        2 | 3 => {
            let len = header + argument as usize;
            let data = bytes.get(at + header..at + len)?;
            if major == 3 {
                let text = std::str::from_utf8(data).ok()?;
                leaf(len, "text", text_preview(text.as_bytes(), 48))
            } else {
                leaf(len, "bytes", hex_preview(data, 12))
            }
        }
        4 | 5 => {
            let count = argument as usize;
            if depth > 16 || count > MAX_CHILDREN {
                return None;
            }
            let mut cursor = at + header;
            let mut children = Vec::new();
            for _ in 0..count {
                if major == 5 {
                    let (key_len, key) = cbor_value(bytes, cursor, base, depth + 1)?;
                    cursor += key_len;
                    let (value_len, mut value) = cbor_value(bytes, cursor, base, depth + 1)?;
                    value.name = format!("{} = {}", key.value, value.name);
                    cursor += value_len;
                    children.push(value);
                } else {
                    let (len, value) = cbor_value(bytes, cursor, base, depth + 1)?;
                    cursor += len;
                    children.push(value);
                }
            }
            let name = if major == 5 { "map" } else { "array" };
            Some((cursor - at, Field::new(name, base + at, cursor - at, format!("{count} items")).with_children(children)))
        }
        6 => {
            let (inner_len, mut inner) = cbor_value(bytes, at + header, base, depth + 1)?;
            inner.name = format!("tag {argument} {}", inner.name);
            inner.offset = base + at;
            inner.len += header;
            Some((header + inner_len, inner))
        }
        7 => match bytes.get(at)? & 0x1F {
            20 => leaf(1, "bool", "false".to_string()),
            21 => leaf(1, "bool", "true".to_string()),
            22 => leaf(1, "null", String::new()),
            23 => leaf(1, "undefined", String::new()),
            25 => leaf(3, "f16", String::new()),
            26 => leaf(5, "f32", f32::from_be_bytes(bytes.get(at + 1..at + 5)?.try_into().ok()?).to_string()),
            27 => leaf(9, "f64", f64::from_be_bytes(bytes.get(at + 1..at + 9)?.try_into().ok()?).to_string()),
            _ => None,
        },
        _ => None,
    }
    .filter(|(len, _)| at + len <= bytes.len())
}

pub struct CborParser;

impl Parser for CborParser {
    fn id(&self) -> &str {
        "serial.cbor"
    }

    fn name(&self) -> &str {
        "CBOR value"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(&[0xD9, 0xD9, 0xF7]) || bytes.first().is_some_and(|&b| matches!(b >> 5, 4 | 5) && b & 0x1F != 31)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let self_described = bytes.starts_with(&[0xD9, 0xD9, 0xF7]);
        let (len, root) = cbor_value(bytes, 0, base, 0)?;
        if (root.children.len() < 2 && !self_described) || len < MIN_SCAN_LEN {
            return None;
        }
        Some(
            Finding::new("cbor", SOURCE, Category::Encoding, base, len)
                .title("CBOR value")
                .detail(format!("{} with {} items, {len} bytes", root.name, root.children.len()))
                .confidence(if self_described { 0.9 } else { 0.6 })
                .fields(vec![root]),
        )
    }
}

// ---------------------------------------------------------------------------
// JSON and XML
// ---------------------------------------------------------------------------

/// Length of a balanced JSON value starting at `bytes[0]`, or None.
fn json_value_len(bytes: &[u8]) -> Option<usize> {
    let limit = bytes.len().min(MAX_TEXT_SCAN);
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut at = 0;
    while at < limit {
        let byte = bytes[at];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            } else if byte < 0x20 {
                return None;
            }
        } else {
            match byte {
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(at + 1);
                    }
                }
                b'"' => in_string = true,
                b' ' | b'\t' | b'\r' | b'\n' | b',' | b':' | b'-' | b'+' | b'.' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => {}
                _ => return None,
            }
        }
        at += 1;
    }
    None
}

/// Deepest nesting of JSON values walked into fields.
const MAX_JSON_DEPTH: usize = 32;

/// `at` moved past any JSON white space.
fn skip_json_space(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n')) {
        at += 1;
    }
    at
}

/// Where the JSON string opening at `bytes[at]` ends, after its closing quote.
fn json_string_end(bytes: &[u8], at: usize) -> Option<usize> {
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate().skip(at + 1) {
        match byte {
            _ if escaped => escaped = false,
            b'\\' => escaped = true,
            b'"' => return Some(index + 1),
            _ => {}
        }
    }
    None
}

/// The JSON value at `bytes[at]` as a field named `name`, and where it
/// ends: an object's members are its children by key, an array's elements
/// its children named `item`, and a string's span leaves out its quotes.
fn json_value(bytes: &[u8], at: usize, base: usize, name: &str, depth: usize) -> Option<(usize, Field)> {
    let text = |from: usize, to: usize| String::from_utf8_lossy(&bytes[from..to]).into_owned();
    match *bytes.get(at)? {
        b'"' => {
            let end = json_string_end(bytes, at)?;
            Some((end, Field::new(name, base + at + 1, end - at - 2, text(at + 1, end - 1))))
        }
        open @ (b'{' | b'[') if depth < MAX_JSON_DEPTH => {
            let close = if open == b'{' { b'}' } else { b']' };
            let mut children = Vec::new();
            let mut position = skip_json_space(bytes, at + 1);
            if bytes.get(position) != Some(&close) {
                loop {
                    let (member, value_at) = if open == b'{' {
                        if bytes.get(position) != Some(&b'"') {
                            return None;
                        }
                        let key_end = json_string_end(bytes, position)?;
                        let colon = skip_json_space(bytes, key_end);
                        if bytes.get(colon) != Some(&b':') {
                            return None;
                        }
                        (text(position + 1, key_end - 1), skip_json_space(bytes, colon + 1))
                    } else {
                        ("item".to_string(), position)
                    };
                    let (end, child) = json_value(bytes, value_at, base, &member, depth + 1)?;
                    children.push(child);
                    position = skip_json_space(bytes, end);
                    match bytes.get(position) {
                        Some(b',') => position = skip_json_space(bytes, position + 1),
                        Some(&byte) if byte == close => break,
                        _ => return None,
                    }
                }
            }
            let end = position + 1;
            let summary = if open == b'{' { format!("{} members", children.len()) } else { format!("{} items", children.len()) };
            Some((end, Field::new(name, base + at, end - at, summary).with_children(children)))
        }
        _ => {
            let end = (at..bytes.len()).find(|&index| matches!(bytes[index], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')).unwrap_or(bytes.len());
            (end > at).then(|| (end, Field::new(name, base + at, end - at, text(at, end))))
        }
    }
}

pub struct JsonParser;

impl Parser for JsonParser {
    fn id(&self) -> &str {
        "serial.json"
    }

    fn name(&self) -> &str {
        "JSON document"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        matches!(bytes.first(), Some(b'{') | Some(b'['))
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let len = json_value_len(bytes)?;
        if len < MIN_SCAN_LEN || !bytes[..len].contains(&b'"') {
            return None;
        }
        let text = std::str::from_utf8(&bytes[..len]).ok()?;
        let confidence = if len >= 64 { 0.9 } else { 0.7 };
        let fields = json_value(&bytes[..len], 0, base, "value", 0).map(|(_, root)| root.children).unwrap_or_default();
        Some(
            Finding::new("json", SOURCE, Category::Encoding, base, len)
                .title("JSON document")
                .detail(format!("{len} bytes: {}", text_preview(text.as_bytes(), 60)))
                .confidence(confidence)
                .fields(fields),
        )
    }
}

/// Length of a balanced XML fragment starting at `bytes[0]`, or None.
fn xml_len(bytes: &[u8]) -> Option<usize> {
    let limit = bytes.len().min(MAX_TEXT_SCAN);
    let mut depth = 0usize;
    let mut at = 0;
    let mut opened = 0;
    while at < limit {
        if bytes[at] != b'<' {
            if bytes[at] < 0x20 && !matches!(bytes[at], b'\t' | b'\n' | b'\r') {
                return None;
            }
            at += 1;
            continue;
        }
        let end = bytes[at..limit].iter().position(|&b| b == b'>')? + at;
        let tag = &bytes[at + 1..end];
        if tag.is_empty() || !tag.iter().all(|&b| b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b >= 0x80) {
            return None;
        }
        match tag[0] {
            b'?' | b'!' => {}
            b'/' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(end + 1);
                }
            }
            _ => {
                if tag.last() != Some(&b'/') {
                    depth += 1;
                    opened += 1;
                }
            }
        }
        at = end + 1;
        if depth == 0 && opened > 0 {
            return Some(at);
        }
    }
    None
}

pub struct XmlParser;

impl Parser for XmlParser {
    fn id(&self) -> &str {
        "serial.xml"
    }

    fn name(&self) -> &str {
        "XML document"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"<?xml") || (bytes.first() == Some(&b'<') && bytes.get(1).is_some_and(|b| b.is_ascii_alphabetic()))
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        if !self.looks_like(bytes) {
            return None;
        }
        let len = xml_len(bytes)?;
        if len < 32 {
            return None;
        }
        let text = std::str::from_utf8(&bytes[..len]).ok()?;
        let confidence = if bytes.starts_with(b"<?xml") { 0.95 } else { 0.7 };
        Some(
            Finding::new("xml", SOURCE, Category::Encoding, base, len)
                .title("XML document")
                .detail(format!("{len} bytes: {}", text_preview(text.as_bytes(), 60)))
                .confidence(confidence),
        )
    }
}

// ---------------------------------------------------------------------------
// Window detector
// ---------------------------------------------------------------------------

pub struct SerialisationDetector;

/// Valid UTF-8 run with at least one multi-byte character, printable only.
/// Leading bytes of common file formats.
const FILE_MAGICS: [&[u8]; 12] = [
    b"\x89PNG",
    b"\x7fELF",
    b"PK\x03\x04",
    b"%PDF",
    b"\xff\xd8\xff",
    b"GIF8",
    b"\x1f\x8b\x08",
    b"RIFF",
    b"\xca\xfe\xba\xbe",
    b"\xcf\xfa\xed\xfe",
    b"BZh",
    b"\xfd7zXZ",
];

fn starts_with_file_magic(bytes: &[u8]) -> bool {
    FILE_MAGICS.iter().any(|magic| bytes.starts_with(magic))
}

/// Start of the printable ASCII that runs directly into `at`, not reaching
/// back before `floor`.
fn ascii_lead_in(window: &[u8], at: usize, floor: usize) -> usize {
    let mut start = at;
    while start > floor && (0x20..0x7F).contains(&window[start - 1]) {
        start -= 1;
    }
    start
}

/// Bytes well-formed as MessagePack, CBOR or protobuf turn up in random data
/// surprisingly often, because nearly every byte is a valid header. Without a
/// self-describing tag such a finding needs real size before it is trusted.
fn demote_schemaless(finding: Finding) -> Finding {
    const TRUSTED_LEN: usize = 32;
    const TRUSTED_LEAVES: usize = 8;
    let schemaless = matches!(finding.id.as_str(), "msgpack" | "cbor" | "protobuf");
    let self_describing = finding.detail.contains("self-describe");
    if !schemaless || self_describing {
        return finding;
    }
    // Real messages hold many small values; random bytes that happen to be
    // well-formed are usually one or two values with a long payload.
    let mut leaves = Vec::new();
    collect_leaves(&finding.fields, &mut leaves);
    let largest_leaf = leaves.iter().copied().max().unwrap_or(finding.len);
    let structured = leaves.len() >= TRUSTED_LEAVES && largest_leaf * 2 <= finding.len;
    if finding.len >= TRUSTED_LEN && structured {
        finding
    } else {
        let confidence = finding.confidence.min(0.4);
        finding.confidence(confidence)
    }
}

/// Lengths of the fields with no children.
fn collect_leaves(fields: &[crate::plugin::Field], leaves: &mut Vec<usize>) {
    for field in fields {
        if field.children.is_empty() {
            leaves.push(field.len);
        } else {
            collect_leaves(&field.children, leaves);
        }
    }
}

fn utf8_run(window: &[u8], at: usize) -> Option<usize> {
    let mut end = at;
    let mut multibyte = false;
    let limit = window.len().min(at + MAX_TEXT_SCAN);
    while end < limit {
        let byte = window[end];
        let width = if byte < 0x80 {
            if byte < 0x20 && !matches!(byte, b'\t' | b'\n' | b'\r') || byte == 0x7F {
                break;
            }
            1
        } else if byte & 0xE0 == 0xC0 {
            2
        } else if byte & 0xF0 == 0xE0 {
            3
        } else if byte & 0xF8 == 0xF0 {
            4
        } else {
            break;
        };
        let Some(chunk) = window.get(end..end + width) else { break };
        if width > 1 {
            let Ok(text) = std::str::from_utf8(chunk) else { break };
            if text.chars().any(|c| c.is_control()) {
                break;
            }
            multibyte = true;
        }
        end += width;
    }
    (multibyte && end - at >= MIN_SCAN_LEN).then_some(end - at)
}

impl Detector for SerialisationDetector {
    fn id(&self) -> &str {
        "serial.scan"
    }

    fn name(&self) -> &str {
        "Serialisation formats"
    }

    fn categories(&self) -> Vec<Category> {
        vec![Category::Encoding, Category::Text]
    }

    fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding> {
        let json = JsonParser;
        let xml = XmlParser;
        let msgpack = MessagePackParser;
        let cbor = CborParser;
        let protobuf = ProtobufParser;
        let mut findings: Vec<Finding> = Vec::new();
        let mut at = 0;
        let mut last_end = 0;
        while at < window.len() && findings.len() < MAX_CHILDREN {
            let slice = &window[at..];
            let base = context.base + at;
            // Bytes that start a well-known file format belong to it, even
            // when they also happen to be well-formed CBOR or MessagePack
            // (0x89, the first byte of PNG, is a CBOR array of nine items).
            if starts_with_file_magic(slice) {
                at += 1;
                continue;
            }
            let hit = match window[at] {
                b'{' | b'[' => json.parse(slice, base),
                b'<' => xml.parse(slice, base),
                0xD9 if slice.starts_with(&[0xD9, 0xD9, 0xF7]) => cbor.parse(slice, base),
                0x80..=0x9F | 0xDC..=0xDF => msgpack.parse(slice, base).or_else(|| cbor.parse(slice, base)),
                0xA0..=0xBF => cbor.parse(slice, base),
                b if b >= 0xC2 => utf8_run(window, at).map(|len| {
                    // The run was found at its first multi-byte character;
                    // pull the start back over the ASCII that leads into it.
                    let start = ascii_lead_in(window, at, last_end);
                    let len = len + (at - start);
                    let text = String::from_utf8_lossy(&window[start..start + len]).to_string();
                    Finding::new("utf8-text", SOURCE, Category::Text, context.base + start, len)
                        .title("UTF-8 text")
                        .detail(format!("{len} bytes: {}", text.chars().take(60).collect::<String>()))
                        .confidence(0.8)
                }),
                0x08 | 0x0A | 0x10 | 0x12 | 0x18 | 0x1A | 0x20 | 0x22 => {
                    // Protobuf is only reported when it is clearly structured.
                    protobuf.parse(slice, base).filter(|f| f.confidence >= 0.6 && f.len >= MIN_SCAN_LEN)
                }
                _ => None,
            };
            match hit {
                Some(finding) => {
                    let finding = demote_schemaless(finding);
                    let end = finding.end() - context.base;
                    at = end.max(at + 1);
                    last_end = at;
                    findings.push(finding);
                }
                None => at += 1,
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_huge_protobuf_length_is_rejected_instead_of_wrapping() {
        // Field 2 claims a length near u64::MAX, which used to wrap the end offset.
        let bytes = [0x08, 0x01, 0x08, 0x01, 0x12, 0xF3, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        for start in 0..bytes.len() {
            let _ = ProtobufParser.parse(&bytes[start..], 0);
            let _ = walk_one_field(&bytes, start, 0);
        }
    }

    #[test]
    fn protobuf_messages_walk_into_fields() {
        // field 1 varint 150, field 2 string "testing", field 3 fixed32, field 4 nested {1: 1}
        let mut message = vec![0x08, 0x96, 0x01, 0x12, 0x07];
        message.extend_from_slice(b"testing");
        message.extend_from_slice(&[0x1D, 1, 0, 0, 0, 0x22, 0x02, 0x08, 0x01]);
        let finding = ProtobufParser.parse(&message, 10).expect("protobuf");
        assert_eq!(finding.len, message.len());
        assert_eq!(finding.fields.len(), 4);
        assert_eq!(finding.fields[0].value, "150");
        assert_eq!(finding.fields[1].value, "\"testing\"");
        assert_eq!(finding.fields[1].offset, 13);
        assert!(finding.confidence >= 0.6, "{}", finding.confidence);
    }

    #[test]
    fn messagepack_and_cbor_maps_are_walked() {
        // msgpack: {"name": "theviewer", "count": 3, "tags": ["a", "b"]}
        let msgpack = [
            0x83, 0xA4, b'n', b'a', b'm', b'e', 0xA9, b't', b'h', b'e', b'v', b'i', b'e', b'w', b'e', b'r', 0xA5, b'c', b'o', b'u', b'n', b't', 0x03, 0xA4, b't', b'a', b'g', b's', 0x92, 0xA1, b'a', 0xA1, b'b',
        ];
        let finding = MessagePackParser.parse(&msgpack, 0).expect("msgpack");
        assert_eq!(finding.len, msgpack.len());
        let root = &finding.fields[0];
        assert_eq!(root.children.len(), 3);
        assert!(root.children[0].name.starts_with("name = str"), "{}", root.children[0].name);

        // cbor: [1, "two", {"three": 3}, true, 4.5]
        let cbor = [0x85, 0x01, 0x63, b't', b'w', b'o', 0xA1, 0x65, b't', b'h', b'r', b'e', b'e', 0x03, 0xF5, 0xFB, 0x40, 0x12, 0, 0, 0, 0, 0, 0];
        let finding = CborParser.parse(&cbor, 100).expect("cbor");
        assert_eq!(finding.len, cbor.len());
        let root = &finding.fields[0];
        assert_eq!(root.children.len(), 5);
        assert_eq!(root.children[4].value, "4.5");
        assert_eq!(root.children[2].offset, 106);
    }

    #[test]
    fn json_and_xml_documents_are_bounded() {
        let json = br#"{"name": "theviewer", "items": [1, 2, 3], "nested": {"ok": true}} trailing"#;
        let finding = JsonParser.parse(json, 0).expect("json");
        assert_eq!(finding.len, json.len() - " trailing".len());
        assert!(JsonParser.parse(b"{not json", 0).is_none());

        let xml = b"<?xml version=\"1.0\"?><root><item id=\"1\">text</item><empty/></root>tail";
        let finding = XmlParser.parse(xml, 0).expect("xml");
        assert_eq!(finding.len, xml.len() - 4);
        assert!(finding.confidence > 0.9);
    }

    #[test]
    fn a_json_documents_members_are_fields_a_structure_anchor_can_name() {
        let json = br#"{"stage": 2, "payload_b64": "SGVsbG8=", "cfg": {"port": 8443, "hosts": ["a.example", "b.example"]}}"#;
        let finding = JsonParser.parse(json, 100).expect("json");
        let names: Vec<&str> = finding.fields.iter().map(|field| field.name.as_str()).collect();
        assert_eq!(names, ["stage", "payload_b64", "cfg"]);
        let payload = &finding.fields[1];
        let at = json.windows(8).position(|window| window == b"SGVsbG8=").unwrap();
        assert_eq!((payload.offset, payload.len, payload.value.as_str()), (100 + at, 8, "SGVsbG8="), "the value's span leaves out its quotes");
        assert_eq!(finding.fields[0].value, "2");
        let cfg = &finding.fields[2];
        assert_eq!((cfg.children[0].name.as_str(), cfg.children[0].value.as_str()), ("port", "8443"));
        let hosts = &cfg.children[1];
        assert_eq!(hosts.children.iter().map(|host| host.value.as_str()).collect::<Vec<_>>(), ["a.example", "b.example"]);
        let named = crate::journal::provenance::named_fields(&finding);
        assert!(named.iter().any(|(name, field)| name == "cfg.port" && field.value == "8443"), "{:?}", named.iter().map(|(name, _)| name).collect::<Vec<_>>());
    }

    #[test]
    fn file_signatures_are_not_mistaken_for_serialised_values() {
        let mut window = b"\x89PNG\r\n\x1a\n".to_vec();
        window.extend_from_slice(&[0u8; 64]);
        let findings = SerialisationDetector.scan(&window, &ScanContext { base: 0, document_len: window.len(), strides: vec![] });
        assert!(findings.iter().all(|f| f.start != 0), "{findings:?}");
    }

    #[test]
    fn detector_finds_utf8_text_and_documents_in_a_window() {
        let mut window = vec![0u8; 32];
        let text_at = window.len();
        window.extend_from_slice("naïve café résumé — sixteen+ bytes".as_bytes());
        window.extend_from_slice(&[0u8; 32]);
        let json_at = window.len();
        window.extend_from_slice(br#"{"key": "value", "list": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]}"#);
        window.extend_from_slice(&[0u8; 32]);
        let findings = SerialisationDetector.scan(&window, &ScanContext { base: 0, document_len: window.len(), strides: vec![] });
        assert!(findings.iter().any(|f| f.id == "utf8-text" && f.start == text_at), "{findings:?}");
        assert!(findings.iter().any(|f| f.id == "json" && f.start == json_at), "{findings:?}");
    }
}
