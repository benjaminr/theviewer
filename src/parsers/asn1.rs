//! ASN.1 DER structures: a hand-written TLV walker (for exact offsets) with
//! der-parser validating the whole object, and x509-parser for certificates.

use der_parser::der::parse_der;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::{MAX_EXTENT, guarded, hex_preview, text_preview};
use crate::plugin::{Category, Field, Finding, Parser};

const SOURCE: &str = "parsers.asn1";
const MAX_DEPTH: usize = 12;
const MAX_NODE_CHILDREN: usize = 200;
/// Generic DER objects shorter than this are not worth reporting.
const MIN_GENERIC_LEN: usize = 8;

/// Tag, header length, content length for the TLV at `bytes[0]`.
fn der_header(bytes: &[u8]) -> Option<(u8, bool, usize, usize)> {
    let tag_byte = *bytes.first()?;
    let constructed = tag_byte & 0x20 != 0;
    if tag_byte & 0x1F == 0x1F {
        return None; // multi-byte tags are rare in practice; skip them
    }
    let first = *bytes.get(1)?;
    let (header_len, content_len) = if first < 0x80 {
        (2, first as usize)
    } else {
        let count = (first & 0x7F) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | *bytes.get(2 + i)? as usize;
        }
        // DER requires the shortest encoding.
        if (count == 1 && len < 0x80) || (count > 1 && len >> (8 * (count - 1)) == 0) {
            return None;
        }
        (2 + count, len)
    };
    (header_len + content_len <= bytes.len()).then_some((tag_byte, constructed, header_len, content_len))
}

fn tag_name(tag: u8) -> String {
    match tag & 0xDF {
        0x01 => "BOOLEAN".to_string(),
        0x02 => "INTEGER".to_string(),
        0x03 => "BIT STRING".to_string(),
        0x04 => "OCTET STRING".to_string(),
        0x05 => "NULL".to_string(),
        0x06 => "OBJECT IDENTIFIER".to_string(),
        0x0A => "ENUMERATED".to_string(),
        0x0C => "UTF8String".to_string(),
        0x10 => "SEQUENCE".to_string(),
        0x11 => "SET".to_string(),
        0x13 => "PrintableString".to_string(),
        0x14 => "T61String".to_string(),
        0x16 => "IA5String".to_string(),
        0x17 => "UTCTime".to_string(),
        0x18 => "GeneralizedTime".to_string(),
        0x1E => "BMPString".to_string(),
        _ if tag & 0xC0 == 0x80 => format!("[{}]", tag & 0x1F),
        _ if tag & 0xC0 == 0x40 => format!("APPLICATION [{}]", tag & 0x1F),
        _ => format!("tag {tag:#04x}"),
    }
}

fn decode_oid(content: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut value: u64 = 0;
    for (index, &byte) in content.iter().enumerate() {
        value = (value << 7) | (byte & 0x7F) as u64;
        if byte & 0x80 == 0 {
            if parts.is_empty() && index < 8 {
                let first = (value / 40).min(2);
                parts.push(first.to_string());
                parts.push((value - first * 40).to_string());
            } else {
                parts.push(value.to_string());
            }
            value = 0;
        }
    }
    parts.join(".")
}

fn primitive_value(tag: u8, content: &[u8]) -> String {
    match tag & 0xDF {
        0x01 => if content.first().copied().unwrap_or(0) != 0 { "TRUE" } else { "FALSE" }.to_string(),
        0x02 | 0x0A => {
            if content.len() <= 8 {
                let mut value: i64 = if content.first().is_some_and(|b| b & 0x80 != 0) { -1 } else { 0 };
                for &byte in content {
                    value = (value << 8) | byte as i64;
                }
                value.to_string()
            } else {
                format!("{} bytes: {}", content.len(), hex_preview(content, 12))
            }
        }
        0x05 => String::new(),
        0x06 => decode_oid(content),
        0x0C | 0x13 | 0x14 | 0x16 | 0x17 | 0x18 => text_preview(content, 64),
        0x03 => format!("{} bits", content.len().saturating_sub(1) * 8 - content.first().copied().unwrap_or(0) as usize),
        _ => hex_preview(content, 16),
    }
}

/// Walk one TLV at `bytes[0]` (document offset `base`) into a field.
fn walk(bytes: &[u8], base: usize, depth: usize) -> Option<(Field, usize)> {
    let (tag, constructed, header_len, content_len) = der_header(bytes)?;
    let total = header_len + content_len;
    let content = &bytes[header_len..total];
    let name = tag_name(tag);
    let mut field = Field::new(name, base, total, String::new());
    if constructed && depth < MAX_DEPTH {
        let mut at = 0;
        while at < content.len() && field.children.len() < MAX_NODE_CHILDREN {
            let (child, len) = walk(&content[at..], base + header_len + at, depth + 1)?;
            field.children.push(child);
            at += len;
        }
        field.value = format!("{} items", field.children.len());
    } else if constructed {
        field.value = format!("{content_len} bytes");
    } else {
        field.value = primitive_value(tag, content);
    }
    Some((field, total))
}

pub struct DerParser;

impl Parser for DerParser {
    fn id(&self) -> &str {
        "der"
    }

    fn name(&self) -> &str {
        "ASN.1 DER"
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        bytes.first() == Some(&0x30) && der_header(bytes).is_some_and(|(_, _, header, content)| header + content >= MIN_GENERIC_LEN)
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        let (_, _, header_len, content_len) = der_header(bytes)?;
        let total = (header_len + content_len).min(MAX_EXTENT);
        let object = &bytes[..total];
        if let Some(certificate) = guarded(|| describe_certificate(object, base)) {
            return Some(certificate);
        }
        // Validate with der-parser before trusting our own walk.
        guarded(|| parse_der(object).ok())?;
        let (root, _) = walk(object, base, 0)?;
        if root.children.len() < 2 {
            return None;
        }
        let items = root.children.len();
        Some(
            Finding::new("der", SOURCE, Category::Structure, base, total)
                .title("ASN.1 DER structure")
                .detail(format!("SEQUENCE of {items} items, {total} bytes"))
                .confidence(0.5)
                .fields(vec![root]),
        )
    }
}

fn describe_certificate(object: &[u8], base: usize) -> Option<Finding> {
    let (rest, certificate) = X509Certificate::from_der(object).ok()?;
    let used = object.len() - rest.len();
    let registry = x509_parser::objects::oid_registry();
    let algorithm = x509_parser::objects::oid2sn(&certificate.signature_algorithm.algorithm, registry)
        .map(str::to_string)
        .unwrap_or_else(|_| certificate.signature_algorithm.algorithm.to_id_string());
    let validity = certificate.validity();
    let not_before = validity.not_before.to_rfc2822().unwrap_or_else(|_| validity.not_before.timestamp().to_string());
    let not_after = validity.not_after.to_rfc2822().unwrap_or_else(|_| validity.not_after.timestamp().to_string());
    let subject = certificate.subject().to_string();
    let issuer = certificate.issuer().to_string();
    let mut names = Vec::new();
    if let Ok(Some(san)) = certificate.subject_alternative_name() {
        for name in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                names.push(dns.to_string());
            }
        }
    }
    let (structure, _) = walk(object, base, 0)?;
    let mut summary = Field::new("certificate", base, used, subject.clone()).with_children(vec![
        Field::new("version", base, 0, format!("{:?}", certificate.version())),
        Field::new("serial", base, 0, certificate.raw_serial_as_string()),
        Field::new("signature algorithm", base, 0, algorithm.clone()),
        Field::new("issuer", base, 0, issuer.clone()),
        Field::new("subject", base, 0, subject.clone()),
        Field::new("not before", base, 0, not_before.clone()),
        Field::new("not after", base, 0, not_after.clone()),
    ]);
    if !names.is_empty() {
        summary.children.push(Field::new("subject alternative names", base, 0, names.join(", ")));
    }
    Some(
        Finding::new("x509", SOURCE, Category::Structure, base, used)
            .title("X.509 certificate")
            .detail(format!("{subject}, issued by {issuer}, {algorithm}, valid {not_before} to {not_after}", ))
            .confidence(1.0)
            .fields(vec![summary, structure]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_sequence_of_integers(values: &[i64]) -> Vec<u8> {
        let mut content = Vec::new();
        for &value in values {
            let bytes = value.to_be_bytes();
            let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
            let mut body = bytes[first..].to_vec();
            if body[0] & 0x80 != 0 {
                body.insert(0, 0);
            }
            content.push(0x02);
            content.push(body.len() as u8);
            content.extend_from_slice(&body);
        }
        let mut out = vec![0x30, content.len() as u8];
        out.extend_from_slice(&content);
        out
    }

    #[test]
    fn walks_a_sequence_of_integers_with_offsets() {
        let bytes = der_sequence_of_integers(&[1, 300, 65_537, 42, 7]);
        assert!(DerParser.looks_like(&bytes));
        let finding = DerParser.parse(&bytes, 50).expect("der");
        assert_eq!(finding.len, bytes.len());
        assert_eq!(finding.confidence, 0.5);
        let root = &finding.fields[0];
        assert_eq!(root.name, "SEQUENCE");
        assert_eq!(root.children.len(), 5);
        assert_eq!(root.children[1].value, "300");
        assert_eq!(root.children[0].offset, 52);
        assert_eq!(root.children[1].offset, 55);
    }

    #[test]
    fn oids_and_strings_are_decoded() {
        // SEQUENCE { OID 1.2.840.113549, UTF8String "hi" }
        let bytes = [0x30, 0x0C, 0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x0C, 0x02, b'h', b'i'];
        let finding = DerParser.parse(&bytes, 0).expect("der");
        let root = &finding.fields[0];
        assert_eq!(root.children[0].value, "1.2.840.113549");
        assert_eq!(root.children[1].value, "hi");
    }

    #[test]
    fn short_or_invalid_objects_are_rejected() {
        assert!(!DerParser.looks_like(&[0x30, 0x02, 0x02, 0x01]));
        assert!(DerParser.parse(&[0x30, 0x10, 0x02, 0x01, 0x05], 0).is_none());
        // Non-minimal length encoding is not DER.
        assert!(der_header(&[0x30, 0x81, 0x05, 0, 0, 0, 0, 0]).is_none());
    }
}
