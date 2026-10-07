//! Finds cryptographic keys and certificates in arbitrary bytes.
//!
//! Four kinds of evidence are searched for:
//!
//! * PEM blocks (`-----BEGIN …-----` to `-----END …-----`), whose Base64
//!   body is decoded and described where possible;
//! * DER structures that parse as X.509 certificates, SubjectPublicKeyInfo
//!   public keys, or PKCS#1, PKCS#8, SEC1 and DSA private keys;
//! * OpenSSH public keys (`ssh-rsa AAAA…`) and private keys
//!   (`openssh-key-v1`);
//! * raw symmetric key candidates: 16, 24 or 32 random-looking bytes with
//!   structured, low-entropy bytes on both sides, as when an AES key sits in
//!   a configuration structure. These are guesses and carry low confidence.
//!
//! Descriptions never contain key material beyond a short hex prefix.

use aho_corasick::AhoCorasick;
use der_parser::ber::{BerObject, BerObjectContent, Class};
use der_parser::der::parse_der;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::parsers::guarded;
use crate::text::truncate_chars;

/// Most bytes scanned; longer input is truncated.
pub const MAX_SCAN_BYTES: usize = 64 * 1024 * 1024;
/// Most bytes searched for raw symmetric key candidates (the slowest search).
pub const MAX_RAW_KEY_SCAN_BYTES: usize = 16 * 1024 * 1024;
/// Scan positions handled per chunk.
const CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// Bytes past a chunk's end that an object starting in the chunk may use;
/// also the largest DER object or PEM block recognised.
const MAX_OBJECT_LEN: usize = 64 * 1024;
/// Most findings returned.
pub const MAX_FINDINGS: usize = 2000;
/// Most raw key candidates returned.
const MAX_RAW_CANDIDATES: usize = 200;
/// Smallest DER object considered (an Ed25519 public key is 44 bytes).
const MIN_DER_LEN: usize = 40;
/// Longest PEM label accepted.
const MAX_PEM_LABEL: usize = 64;
/// Longest Base64 token read for an SSH public key.
const MAX_SSH_TOKEN: usize = 16 * 1024;
/// Hex digits of key material shown in descriptions.
const PREFIX_BYTES: usize = 4;
/// Bytes either side of a raw key candidate that must look structured.
const RAW_KEY_CONTEXT: usize = 32;
/// Fewest context bytes accepted at the edges of the data.
const MIN_RAW_KEY_CONTEXT: usize = 8;
/// Raw key lengths tried, longest first.
const RAW_KEY_LENGTHS: [usize; 3] = [32, 24, 16];

const PEM_BEGIN: &[u8] = b"-----BEGIN ";
const PEM_DASHES: &[u8] = b"-----";
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
const SSH_PUBLIC_PREFIXES: [&[u8]; 5] = [b"ssh-rsa AAAA", b"ssh-ed25519 AAAA", b"ssh-dss AAAA", b"ecdsa-sha2-nistp", b"ssh-ed448 AAAA"];

/// What was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    Certificate,
    PrivateKey,
    PublicKey,
    /// A PEM block of some other type (certificate request, DH parameters…).
    OtherPem,
    /// Random-looking bytes of a symmetric key's length amid structure.
    RawKeyCandidate,
}

impl KeyKind {
    pub fn label(self) -> &'static str {
        match self {
            KeyKind::Certificate => "certificate",
            KeyKind::PrivateKey => "private key",
            KeyKind::PublicKey => "public key",
            KeyKind::OtherPem => "PEM block",
            KeyKind::RawKeyCandidate => "raw key?",
        }
    }
}

/// How the object is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyFormat {
    Pem,
    Der,
    OpenSsh,
    Raw,
}

impl KeyFormat {
    pub fn label(self) -> &'static str {
        match self {
            KeyFormat::Pem => "PEM",
            KeyFormat::Der => "DER",
            KeyFormat::OpenSsh => "OpenSSH",
            KeyFormat::Raw => "raw",
        }
    }
}

/// One key, certificate or candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyFinding {
    /// Absolute offset of the first byte.
    pub offset: usize,
    pub len: usize,
    pub kind: KeyKind,
    pub format: KeyFormat,
    /// Algorithm, size, subject and similar; at most a short hex prefix of
    /// any key material.
    pub detail: String,
    /// 0 to 1.
    pub confidence: f32,
}

impl KeyFinding {
    pub fn end(&self) -> usize {
        self.offset + self.len
    }
}

/// Find keys and certificates in `bytes`, which start at absolute offset
/// `base`. Scans at most [`MAX_SCAN_BYTES`] in overlapping chunks and returns
/// at most [`MAX_FINDINGS`] findings in offset order. Never panics.
pub fn find_keys(bytes: &[u8], base: usize) -> Vec<KeyFinding> {
    let bytes = &bytes[..bytes.len().min(MAX_SCAN_BYTES)];
    let Ok(markers) = AhoCorasick::new(marker_patterns()) else { return Vec::new() };
    let mut findings = Vec::new();
    let mut chunk_start = 0;
    while chunk_start < bytes.len() && findings.len() < MAX_FINDINGS {
        let scan_end = (chunk_start + CHUNK_SIZE).min(bytes.len());
        let window_end = (scan_end + MAX_OBJECT_LEN).min(bytes.len());
        let window = &bytes[chunk_start..window_end];
        let starts_before = scan_end - chunk_start;
        scan_markers(&markers, window, starts_before, base + chunk_start, &mut findings);
        scan_der(window, starts_before, base + chunk_start, &mut findings);
        chunk_start = scan_end;
    }
    let raw_limit = bytes.len().min(MAX_RAW_KEY_SCAN_BYTES);
    findings.extend(find_raw_key_candidates(&bytes[..raw_limit], base));
    let mut findings = drop_contained(findings);
    findings.truncate(MAX_FINDINGS);
    findings
}

/// `bytes` as hex, at most `max_bytes` of it, with an ellipsis if cut short.
pub fn short_hex(bytes: &[u8], max_bytes: usize) -> String {
    let hex: String = bytes.iter().take(max_bytes).map(|byte| format!("{byte:02x}")).collect();
    if bytes.len() > max_bytes { format!("{hex}…") } else { hex }
}

/// Describe a DER object (which must start at `object[0]`) if it is a
/// certificate or a key: its kind, a description and its length in bytes.
pub fn classify_der(object: &[u8]) -> Option<(KeyKind, String, usize)> {
    let (header_len, content_len) = der_header(object)?;
    let total = header_len + content_len;
    let object = &object[..total];
    guarded(|| describe_certificate(object))
        .or_else(|| guarded(|| describe_public_key_info(object)))
        .or_else(|| guarded(|| describe_der_sequence(object)))
        .map(|(kind, detail)| (kind, detail, total))
}

// ---------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------

/// Header and content lengths of the DER TLV at `bytes[0]`, if it is
/// well-formed and fits in `bytes`.
fn der_header(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.get(1)?;
    let (header_len, content_len) = if first < 0x80 {
        (2, first as usize)
    } else {
        let count = (first & 0x7F) as usize;
        if count == 0 || count > 3 {
            return None;
        }
        let length = bytes.get(2..2 + count)?.iter().fold(0usize, |length, &byte| (length << 8) | byte as usize);
        // DER requires the shortest length encoding.
        if length < 0x80 || (count > 1 && length >> (8 * (count - 1)) == 0) {
            return None;
        }
        (2 + count, length)
    };
    (header_len + content_len <= bytes.len()).then_some((header_len, content_len))
}

/// Whether a SEQUENCE could be a certificate or key: long enough, and its
/// first child is an INTEGER or SEQUENCE that fits inside it.
fn plausible_der_sequence(bytes: &[u8]) -> Option<usize> {
    if bytes.first() != Some(&0x30) {
        return None;
    }
    let (header_len, content_len) = der_header(bytes)?;
    let total = header_len + content_len;
    if !(MIN_DER_LEN..=MAX_OBJECT_LEN).contains(&total) {
        return None;
    }
    let content = &bytes[header_len..total];
    if !matches!(content.first(), Some(0x02 | 0x30)) {
        return None;
    }
    let (child_header, child_content) = der_header(content)?;
    (child_header + child_content <= content.len()).then_some(total)
}

fn scan_der(window: &[u8], starts_before: usize, base: usize, findings: &mut Vec<KeyFinding>) {
    let mut position = 0;
    while position < starts_before && findings.len() < MAX_FINDINGS {
        let Some(total) = plausible_der_sequence(&window[position..]) else {
            position += 1;
            continue;
        };
        match classify_der(&window[position..position + total]) {
            Some((kind, detail, len)) => {
                let confidence = if kind == KeyKind::Certificate { 0.95 } else { 0.85 };
                findings.push(KeyFinding { offset: base + position, len, kind, format: KeyFormat::Der, detail, confidence });
                position += len;
            }
            None => position += 1,
        }
    }
}

fn describe_certificate(object: &[u8]) -> Option<(KeyKind, String)> {
    let (_, certificate) = X509Certificate::from_der(object).ok()?;
    let subject = truncate_chars(&certificate.subject().to_string(), 80);
    let key = describe_spki(certificate.public_key());
    Some((KeyKind::Certificate, format!("X.509 certificate for {subject}, {key} key")))
}

fn describe_public_key_info(object: &[u8]) -> Option<(KeyKind, String)> {
    let (rest, info) = SubjectPublicKeyInfo::from_der(object).ok()?;
    if !rest.is_empty() {
        return None;
    }
    Some((KeyKind::PublicKey, format!("{} public key (SubjectPublicKeyInfo)", describe_spki(&info))))
}

/// "RSA 2048-bit", "EC P-256" and so on.
fn describe_spki(info: &SubjectPublicKeyInfo) -> String {
    let oid = info.algorithm.algorithm.to_id_string();
    let name = algorithm_name(&oid);
    let curve = info
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok())
        .map(|oid| curve_name(&oid.to_id_string()).to_string());
    if let Some(curve) = curve {
        return format!("{name} {curve}");
    }
    match info.parsed() {
        Ok(PublicKey::Unknown(_)) | Err(_) => fixed_key_size(name).map_or(name.to_string(), |bits| format!("{name} {bits}-bit")),
        Ok(key) => format!("{name} {}-bit", key.key_size()),
    }
}

/// PKCS#1, PKCS#8, SEC1 and DSA structures, recognised by their shape.
fn describe_der_sequence(object: &[u8]) -> Option<(KeyKind, String)> {
    let (rest, parsed) = parse_der(object).ok()?;
    if !rest.is_empty() {
        return None;
    }
    let items = parsed.as_sequence().ok()?;
    describe_pkcs1_private(items)
        .or_else(|| describe_pkcs8(items))
        .or_else(|| describe_encrypted_pkcs8(items))
        .or_else(|| describe_sec1(items))
        .or_else(|| describe_dsa_private(items))
        .or_else(|| describe_pkcs1_public(items))
}

fn integer<'a>(object: &BerObject<'a>) -> Option<&'a [u8]> {
    match object.content {
        BerObjectContent::Integer(value) => Some(value),
        _ => None,
    }
}

/// Bits in an unsigned big-endian integer, ignoring leading zero bytes.
fn integer_bits(value: &[u8]) -> usize {
    let trimmed: &[u8] = match value.iter().position(|&byte| byte != 0) {
        Some(first) => &value[first..],
        None => return 0,
    };
    trimmed.len() * 8 - trimmed[0].leading_zeros() as usize
}

fn small_integer(object: &BerObject) -> Option<u64> {
    let value = integer(object)?;
    (integer_bits(value) <= 32).then(|| value.iter().fold(0u64, |acc, &byte| (acc << 8) | byte as u64))
}

/// RSAPrivateKey: version 0 and eight more INTEGERs (n, e, d, p, q, …).
fn describe_pkcs1_private(items: &[BerObject]) -> Option<(KeyKind, String)> {
    if items.len() != 9 || items.iter().any(|item| integer(item).is_none()) || small_integer(&items[0]) != Some(0) {
        return None;
    }
    let bits = integer_bits(integer(&items[1])?);
    Some((KeyKind::PrivateKey, format!("RSA {bits}-bit private key (PKCS#1)")))
}

/// RSAPublicKey: a modulus of at least 512 bits and a small odd exponent.
fn describe_pkcs1_public(items: &[BerObject]) -> Option<(KeyKind, String)> {
    if items.len() != 2 {
        return None;
    }
    let bits = integer_bits(integer(&items[0])?);
    let exponent = small_integer(&items[1])?;
    (bits >= 512 && exponent % 2 == 1 && exponent >= 3).then(|| (KeyKind::PublicKey, format!("RSA {bits}-bit public key (PKCS#1), exponent {exponent}")))
}

/// PrivateKeyInfo: version, AlgorithmIdentifier, OCTET STRING key.
fn describe_pkcs8(items: &[BerObject]) -> Option<(KeyKind, String)> {
    if items.len() < 3 || !matches!(small_integer(&items[0]), Some(0 | 1)) {
        return None;
    }
    let algorithm = items[1].as_sequence().ok()?;
    let oid = algorithm.first()?.as_oid().ok()?.to_id_string();
    let BerObjectContent::OctetString(inner) = items[2].content else { return None };
    let name = algorithm_name(&oid);
    let curve = algorithm.get(1).and_then(|parameter| parameter.as_oid().ok()).map(|oid| curve_name(&oid.to_id_string()).to_string());
    let size = match (name, curve) {
        (_, Some(curve)) => format!(" {curve}"),
        ("RSA", None) => describe_der_sequence(inner)
            .and_then(|(_, detail)| detail.split_whitespace().nth(1).map(|bits| format!(" {bits}")))
            .unwrap_or_default(),
        (_, None) => fixed_key_size(name).map(|bits| format!(" {bits}-bit")).unwrap_or_default(),
    };
    Some((KeyKind::PrivateKey, format!("{name}{size} private key (PKCS#8)")))
}

/// EncryptedPrivateKeyInfo: AlgorithmIdentifier (PBES2 and the like) and the
/// encrypted OCTET STRING.
fn describe_encrypted_pkcs8(items: &[BerObject]) -> Option<(KeyKind, String)> {
    if items.len() != 2 {
        return None;
    }
    let algorithm = items[0].as_sequence().ok()?;
    let oid = algorithm.first()?.as_oid().ok()?.to_id_string();
    let BerObjectContent::OctetString(_) = items[1].content else { return None };
    let scheme = match oid.as_str() {
        "1.2.840.113549.1.5.13" => "PBES2",
        "1.2.840.113549.1.5.3" => "PBE with MD5 and DES",
        "1.2.840.113549.1.5.10" => "PBE with SHA-1 and DES",
        _ if oid.starts_with("1.2.840.113549.1.12.1.") => "PKCS#12 PBE",
        _ => return None,
    };
    Some((KeyKind::PrivateKey, format!("encrypted private key (PKCS#8, {scheme})")))
}

/// ECPrivateKey: version 1, the private value, optional curve and public key.
fn describe_sec1(items: &[BerObject]) -> Option<(KeyKind, String)> {
    if items.len() < 2 || small_integer(&items[0]) != Some(1) {
        return None;
    }
    let BerObjectContent::OctetString(private) = items[1].content else { return None };
    if !(16..=72).contains(&private.len()) {
        return None;
    }
    let curve = items[2..]
        .iter()
        .find_map(|item| explicit_oid(item, SEC1_PARAMETERS_TAG))
        .map(|oid| format!(" {}", curve_name(&oid)))
        .unwrap_or_else(|| format!(" {}-bit", private.len() * 8));
    Some((KeyKind::PrivateKey, format!("EC{curve} private key (SEC1)")))
}

/// Context tag of the curve parameters in an ECPrivateKey.
const SEC1_PARAMETERS_TAG: u32 = 0;

/// The OBJECT IDENTIFIER inside an explicit context-specific tag `[number]`.
/// der-parser leaves such tags unparsed, so their contents are parsed here.
fn explicit_oid(object: &BerObject, number: u32) -> Option<String> {
    let BerObjectContent::Unknown(any) = &object.content else { return None };
    if any.header.class() != Class::ContextSpecific || any.header.tag().0 != number {
        return None;
    }
    let (_, inner) = parse_der(any.data).ok()?;
    inner.as_oid().ok().map(|oid| oid.to_id_string())
}

/// OpenSSL's DSA private key: version 0 and five INTEGERs (p, q, g, y, x).
fn describe_dsa_private(items: &[BerObject]) -> Option<(KeyKind, String)> {
    if items.len() != 6 || items.iter().any(|item| integer(item).is_none()) || small_integer(&items[0]) != Some(0) {
        return None;
    }
    let bits = integer_bits(integer(&items[1])?);
    Some((KeyKind::PrivateKey, format!("DSA {bits}-bit private key")))
}

fn algorithm_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.113549.1.1.10" => "RSA-PSS",
        "1.2.840.10045.2.1" => "EC",
        "1.2.840.10040.4.1" => "DSA",
        "1.3.101.110" => "X25519",
        "1.3.101.111" => "X448",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        _ => "unknown-algorithm",
    }
}

fn curve_name(oid: &str) -> &str {
    match oid {
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        "1.3.132.0.10" => "secp256k1",
        "1.2.840.10045.3.1.1" => "P-192",
        "1.3.132.0.33" => "P-224",
        _ => oid,
    }
}

/// Key sizes implied by the algorithm alone.
fn fixed_key_size(name: &str) -> Option<usize> {
    match name {
        "X25519" | "Ed25519" => Some(256),
        "X448" => Some(448),
        "Ed448" => Some(456),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// PEM and OpenSSH
// ---------------------------------------------------------------------------

/// Patterns for the marker search; the order matters to [`scan_markers`].
fn marker_patterns() -> Vec<&'static [u8]> {
    let mut patterns = vec![PEM_BEGIN, OPENSSH_MAGIC];
    patterns.extend(SSH_PUBLIC_PREFIXES);
    patterns
}

fn scan_markers(markers: &AhoCorasick, window: &[u8], starts_before: usize, base: usize, findings: &mut Vec<KeyFinding>) {
    let mut resume = 0;
    for found in markers.find_iter(window) {
        let position = found.start();
        if position >= starts_before || findings.len() >= MAX_FINDINGS {
            break;
        }
        if position < resume {
            continue;
        }
        let rest = &window[position..];
        let finding = match found.pattern().as_usize() {
            0 => guarded(|| parse_pem(rest)),
            1 => guarded(|| parse_openssh_private(rest)).map(|(detail, len)| (KeyKind::PrivateKey, KeyFormat::OpenSsh, detail, len, 0.9)),
            _ => guarded(|| parse_ssh_public_line(rest)).map(|(detail, len)| (KeyKind::PublicKey, KeyFormat::OpenSsh, detail, len, 0.9)),
        };
        if let Some((kind, format, detail, len, confidence)) = finding {
            findings.push(KeyFinding { offset: base + position, len, kind, format, detail, confidence });
            resume = position + len;
        }
    }
}

/// A PEM block at `bytes[0]`: kind, format, description, length, confidence.
fn parse_pem(bytes: &[u8]) -> Option<(KeyKind, KeyFormat, String, usize, f32)> {
    let bytes = &bytes[..bytes.len().min(MAX_OBJECT_LEN)];
    let label_start = PEM_BEGIN.len();
    let label_len = find(&bytes[label_start..bytes.len().min(label_start + MAX_PEM_LABEL + PEM_DASHES.len())], PEM_DASHES)?;
    let label = std::str::from_utf8(&bytes[label_start..label_start + label_len]).ok()?;
    if label.is_empty() || !label.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b' ') {
        return None;
    }
    let body_start = label_start + label_len + PEM_DASHES.len();
    let end_marker = format!("-----END {label}-----");
    let body_len = find(&bytes[body_start..], end_marker.as_bytes())?;
    let body = &bytes[body_start..body_start + body_len];
    let total = body_start + body_len + end_marker.len();
    let encrypted = find(body, b"Proc-Type: 4,ENCRYPTED").is_some();
    let decoded = decode_base64(strip_pem_headers(body));
    let (kind, detail) = describe_pem_contents(label, &decoded, encrypted);
    Some((kind, KeyFormat::Pem, detail, total, 0.95))
}

/// The Base64 part of a PEM body: everything after any "Name: value" header
/// lines, which end at the first blank line.
fn strip_pem_headers(body: &[u8]) -> &[u8] {
    if find(&body[..body.len().min(256)], b":").is_none() {
        return body;
    }
    find(body, b"\n\n").or_else(|| find(body, b"\r\n\r\n")).map_or(body, |blank| &body[blank..])
}

fn describe_pem_contents(label: &str, decoded: &[u8], encrypted: bool) -> (KeyKind, String) {
    let encrypted_note = if encrypted { ", encrypted" } else { "" };
    if label == "OPENSSH PRIVATE KEY"
        && let Some((detail, _)) = parse_openssh_private(decoded)
    {
        return (KeyKind::PrivateKey, format!("PEM {label}: {detail}"));
    }
    if let Some((kind, detail, _)) = classify_der(decoded) {
        return (kind, format!("PEM {label}: {detail}{encrypted_note}"));
    }
    let kind = if label.contains("CERTIFICATE") && !label.contains("REQUEST") {
        KeyKind::Certificate
    } else if label.contains("PRIVATE KEY") {
        KeyKind::PrivateKey
    } else if label.contains("PUBLIC KEY") {
        KeyKind::PublicKey
    } else {
        KeyKind::OtherPem
    };
    (kind, format!("PEM {label}, {} bytes decoded{encrypted_note}", decoded.len()))
}

/// An SSH wire-format string at `bytes[*position]`, advancing past it.
fn read_ssh_string<'a>(bytes: &'a [u8], position: &mut usize) -> Option<&'a [u8]> {
    let length_bytes: [u8; 4] = bytes.get(*position..*position + 4)?.try_into().ok()?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    let start = *position + 4;
    let value = bytes.get(start..start.checked_add(length)?)?;
    *position = start + length;
    Some(value)
}

/// Algorithm and size of an SSH public key blob, e.g. "ssh-rsa 2048-bit".
fn describe_ssh_public_blob(blob: &[u8]) -> Option<String> {
    let mut position = 0;
    let name = std::str::from_utf8(read_ssh_string(blob, &mut position)?).ok()?.to_string();
    let size = match name.as_str() {
        "ssh-rsa" => {
            let _exponent = read_ssh_string(blob, &mut position)?;
            format!("{}-bit", integer_bits(read_ssh_string(blob, &mut position)?))
        }
        "ssh-dss" => format!("{}-bit", integer_bits(read_ssh_string(blob, &mut position)?)),
        "ssh-ed25519" => format!("{}-bit", read_ssh_string(blob, &mut position)?.len() * 8),
        _ if name.starts_with("ecdsa-sha2-") => std::str::from_utf8(read_ssh_string(blob, &mut position)?).ok()?.to_string(),
        _ if name.starts_with("sk-") || name == "ssh-ed448" => String::new(),
        _ => return None,
    };
    Some(if size.is_empty() { name } else { format!("{name} {size}") })
}

/// An `openssh-key-v1` private key at `bytes[0]`: description and length.
fn parse_openssh_private(bytes: &[u8]) -> Option<(String, usize)> {
    let mut position = OPENSSH_MAGIC.len();
    if bytes.get(..position)? != OPENSSH_MAGIC {
        return None;
    }
    let cipher = std::str::from_utf8(read_ssh_string(bytes, &mut position)?).ok()?.to_string();
    let _kdf = read_ssh_string(bytes, &mut position)?;
    let _kdf_options = read_ssh_string(bytes, &mut position)?;
    let key_count = u32::from_be_bytes(bytes.get(position..position + 4)?.try_into().ok()?);
    position += 4;
    if key_count == 0 || key_count > 16 {
        return None;
    }
    let public = read_ssh_string(bytes, &mut position)?;
    let algorithm = describe_ssh_public_blob(public).unwrap_or_else(|| "unknown type".to_string());
    for _ in 1..key_count {
        read_ssh_string(bytes, &mut position)?;
    }
    // The private section (encrypted unless the cipher is "none") is skipped.
    read_ssh_string(bytes, &mut position)?;
    let protection = if cipher == "none" { "unencrypted".to_string() } else { format!("encrypted with {cipher}") };
    Some((format!("OpenSSH private key, {algorithm}, {protection}"), position))
}

/// An OpenSSH public key line (`ssh-rsa AAAA… comment`): description and
/// length up to the end of the Base64 token.
fn parse_ssh_public_line(bytes: &[u8]) -> Option<(String, usize)> {
    let space = bytes.iter().take(64).position(|&byte| byte == b' ')?;
    let token_start = space + 1;
    let token_len = bytes[token_start..]
        .iter()
        .take(MAX_SSH_TOKEN)
        .position(|&byte| !(byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'='))
        .unwrap_or_else(|| (bytes.len() - token_start).min(MAX_SSH_TOKEN));
    let blob = decode_base64(&bytes[token_start..token_start + token_len]);
    let described = describe_ssh_public_blob(&blob)?;
    let declared = std::str::from_utf8(&bytes[..space]).ok()?;
    if !described.starts_with(declared) {
        return None;
    }
    Some((format!("OpenSSH public key, {described}"), token_start + token_len))
}

/// Decode standard Base64, skipping whitespace and stopping at padding or
/// any other character.
fn decode_base64(text: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;
    for &character in text {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => break,
        };
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    decoded
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Raw symmetric key candidates
// ---------------------------------------------------------------------------

/// Number of distinct values in `bytes`.
fn distinct_count(bytes: &[u8]) -> usize {
    let mut seen = [0u64; 4];
    let mut distinct = 0;
    for &byte in bytes {
        let (word, bit) = (byte as usize / 64, byte as usize % 64);
        if seen[word] & (1 << bit) == 0 {
            seen[word] |= 1 << bit;
            distinct += 1;
        }
    }
    distinct
}

/// Whether context bytes look structured: few distinct values for their length.
fn is_structured_context(context: &[u8]) -> bool {
    context.len() >= MIN_RAW_KEY_CONTEXT && distinct_count(context) * 8 <= context.len() * 3
}

/// Fewest distinct values a random-looking key of `len` bytes must have
/// (random data averages 15.5 of 16, 23 of 24, 30 of 32).
fn min_distinct_for(len: usize) -> usize {
    len * 13 / 16
}

fn is_random_looking(window: &[u8]) -> bool {
    let printable = window.iter().filter(|&&byte| (0x20..0x7F).contains(&byte)).count();
    distinct_count(window) >= min_distinct_for(window.len()) && printable * 10 < window.len() * 9
}

/// A candidate before clustering: start, length, score.
struct RawCandidate {
    start: usize,
    len: usize,
    score: i64,
}

fn raw_candidate_at(bytes: &[u8], start: usize) -> Option<RawCandidate> {
    let before = &bytes[start.saturating_sub(RAW_KEY_CONTEXT)..start];
    if !is_structured_context(before) {
        return None;
    }
    RAW_KEY_LENGTHS.iter().find_map(|&len| {
        let window = bytes.get(start..start + len)?;
        let after = &bytes[start + len..(start + len + RAW_KEY_CONTEXT).min(bytes.len())];
        (is_random_looking(window) && is_structured_context(after)).then(|| RawCandidate {
            start,
            len,
            score: distinct_count(window) as i64 - distinct_count(before) as i64 - distinct_count(after) as i64,
        })
    })
}

/// Random-looking 16/24/32-byte windows surrounded by structured bytes.
/// Neighbouring positions of one key all qualify; the best-scoring one of
/// each overlapping cluster is kept.
fn find_raw_key_candidates(bytes: &[u8], base: usize) -> Vec<KeyFinding> {
    let mut findings = Vec::new();
    let mut cluster: Option<RawCandidate> = None;
    let mut cluster_end = 0;
    for start in 0..bytes.len() {
        if findings.len() >= MAX_RAW_CANDIDATES {
            break;
        }
        if let Some(best) = &cluster
            && start >= cluster_end
        {
            findings.push(raw_finding(bytes, base, best));
            cluster = None;
        }
        let Some(candidate) = raw_candidate_at(bytes, start) else { continue };
        cluster_end = cluster_end.max(candidate.start + candidate.len);
        if cluster.as_ref().is_none_or(|best| candidate.score > best.score) {
            cluster = Some(candidate);
        }
    }
    if let Some(best) = &cluster
        && findings.len() < MAX_RAW_CANDIDATES
    {
        findings.push(raw_finding(bytes, base, best));
    }
    findings
}

fn raw_finding(bytes: &[u8], base: usize, candidate: &RawCandidate) -> KeyFinding {
    let window = &bytes[candidate.start..candidate.start + candidate.len];
    let cipher = match candidate.len {
        32 => "AES-256 or ChaCha20",
        24 => "AES-192 or 3DES",
        _ => "AES-128",
    };
    KeyFinding {
        offset: base + candidate.start,
        len: candidate.len,
        kind: KeyKind::RawKeyCandidate,
        format: KeyFormat::Raw,
        detail: format!(
            "{} random-looking bytes amid structured data, possibly a {cipher} key ({})",
            candidate.len,
            short_hex(window, PREFIX_BYTES)
        ),
        confidence: 0.25,
    }
}

/// Sort by offset and drop findings that lie wholly inside an earlier one
/// (a certificate's public key, or a raw candidate inside a DER key).
fn drop_contained(mut findings: Vec<KeyFinding>) -> Vec<KeyFinding> {
    findings.sort_by(|a, b| a.offset.cmp(&b.offset).then(b.len.cmp(&a.len)));
    let mut kept: Vec<KeyFinding> = Vec::with_capacity(findings.len());
    let mut container_end = 0;
    for finding in findings {
        if finding.end() <= container_end {
            continue;
        }
        container_end = container_end.max(finding.end());
        kept.push(finding);
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed EC P-256 certificate for "CN=theviewer test", as DER.
    const TEST_CERTIFICATE_HEX: &str = concat!(
        "308201873082012da00302010202144cc7b75a91319968d3fcc6952e52ead08034a2ee300a06082a8648ce3d04030230",
        "193117301506035504030c0e7468657669657765722074657374301e170d3236313030353230353233365a170d333631",
        "3030323230353233365a30193117301506035504030c0e74686576696577657220746573743059301306072a8648ce3d",
        "020106082a8648ce3d030107034200041f17ce0bb917c04d89237f037912f70126a78ebf2428d753c936feb06d094600",
        "df5890b46f6b440323e464cd140e9c7944cbd98e3a48017d206a73b652ad9bbaa3533051301d0603551d0e04160414ca",
        "02af8b719b01c18a2ae80a409459f9442b2f2d301f0603551d23041830168014ca02af8b719b01c18a2ae80a409459f9",
        "442b2f2d300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022011a323fc6e78a035",
        "1d0d591c6248c2c0ab75fa2e661f2049d89bf1bb6f83e4c00221008967ebe3b900a03a5b187b0095097733bfce0d7094",
        "6b81285921c5f363754b0f",
    );

    fn from_hex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
    }

    fn encode_base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut text = String::new();
        for chunk in bytes.chunks(3) {
            let value = chunk.iter().enumerate().fold(0u32, |acc, (i, &byte)| acc | (byte as u32) << (16 - 8 * i));
            for i in 0..4 {
                if i <= chunk.len() {
                    text.push(ALPHABET[(value >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    text.push('=');
                }
            }
        }
        text
    }

    fn noise(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed.max(1);
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }

    /// A DER TLV with the given tag and content.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            len @ 0..0x80 => out.push(len as u8),
            len @ 0x80..0x100 => out.extend([0x81, len as u8]),
            len => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    fn sequence(items: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &items.concat())
    }

    /// A positive INTEGER of `bits` bits with pseudo-random contents.
    fn big_integer(bits: usize, seed: u32) -> Vec<u8> {
        let mut value = noise(bits / 8, seed);
        value[0] |= 0x80;
        value.insert(0, 0);
        tlv(0x02, &value)
    }

    fn rsa_pkcs1_private_key(bits: usize) -> Vec<u8> {
        let mut items = vec![tlv(0x02, &[0]), big_integer(bits, 1), tlv(0x02, &[1, 0, 1])];
        items.extend((2..8).map(|seed| big_integer(bits / 2, seed)));
        sequence(&items)
    }

    fn structured_padding(len: usize) -> Vec<u8> {
        (0..len).map(|i| if i % 8 == 0 { 0x01 } else { 0x00 }).collect()
    }

    #[test]
    fn embedded_der_certificate_is_found_with_subject_and_key() {
        let mut data = structured_padding(300);
        data.extend(from_hex(TEST_CERTIFICATE_HEX));
        data.extend(structured_padding(300));
        let findings = find_keys(&data, 0x1000);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let certificate = &findings[0];
        assert_eq!(certificate.kind, KeyKind::Certificate);
        assert_eq!(certificate.offset, 0x1000 + 300);
        assert_eq!(certificate.len, 395);
        assert!(certificate.detail.contains("theviewer test"), "{}", certificate.detail);
        assert!(certificate.detail.contains("EC P-256"), "{}", certificate.detail);
    }

    #[test]
    fn pem_certificate_is_reported_with_its_type() {
        let body = encode_base64(&from_hex(TEST_CERTIFICATE_HEX));
        let lines: Vec<&str> = body.as_bytes().chunks(64).map(|line| std::str::from_utf8(line).unwrap()).collect();
        let pem = format!("config\n-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\nmore", lines.join("\n"));
        let findings = find_keys(pem.as_bytes(), 0);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].format, KeyFormat::Pem);
        assert_eq!(findings[0].kind, KeyKind::Certificate);
        assert_eq!(findings[0].offset, 7);
        assert!(findings[0].detail.starts_with("PEM CERTIFICATE"));
        assert_eq!(&pem.as_bytes()[findings[0].end() - 5..findings[0].end()], b"-----");
    }

    #[test]
    fn pkcs1_rsa_private_key_reports_its_size() {
        let key = rsa_pkcs1_private_key(1024);
        let (kind, detail, len) = classify_der(&key).unwrap();
        assert_eq!(kind, KeyKind::PrivateKey);
        assert_eq!(len, key.len());
        assert_eq!(detail, "RSA 1024-bit private key (PKCS#1)");
    }

    #[test]
    fn pkcs8_wrapped_keys_report_algorithm_and_size() {
        let rsa_oid = tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
        let rsa = sequence(&[tlv(0x02, &[0]), sequence(&[rsa_oid, tlv(0x05, &[])]), tlv(0x04, &rsa_pkcs1_private_key(2048))]);
        assert_eq!(classify_der(&rsa).unwrap().1, "RSA 2048-bit private key (PKCS#8)");

        let ed25519_oid = tlv(0x06, &[0x2b, 0x65, 0x70]);
        let ed25519 = sequence(&[tlv(0x02, &[0]), sequence(&[ed25519_oid]), tlv(0x04, &tlv(0x04, &noise(32, 9)))]);
        assert_eq!(classify_der(&ed25519).unwrap().1, "Ed25519 256-bit private key (PKCS#8)");
    }

    #[test]
    fn sec1_ec_private_key_names_its_curve() {
        let p256_oid = tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
        let key = sequence(&[tlv(0x02, &[1]), tlv(0x04, &noise(32, 6)), tlv(0xa0, &p256_oid)]);
        assert_eq!(classify_der(&key).unwrap().1, "EC P-256 private key (SEC1)");
    }

    #[test]
    fn subject_public_key_info_is_recognised() {
        let ed25519_oid = tlv(0x06, &[0x2b, 0x65, 0x70]);
        let mut bit_string = vec![0];
        bit_string.extend(noise(32, 4));
        let spki = sequence(&[sequence(&[ed25519_oid]), tlv(0x03, &bit_string)]);
        let (kind, detail, _) = classify_der(&spki).unwrap();
        assert_eq!(kind, KeyKind::PublicKey);
        assert_eq!(detail, "Ed25519 256-bit public key (SubjectPublicKeyInfo)");
    }

    #[test]
    fn ssh_public_key_line_reports_type_and_size() {
        let mut blob = Vec::new();
        for part in [b"ssh-ed25519".to_vec(), noise(32, 2)] {
            blob.extend((part.len() as u32).to_be_bytes());
            blob.extend(part);
        }
        let line = format!("# keys\nssh-ed25519 {} user@host\n", encode_base64(&blob));
        let findings = find_keys(line.as_bytes(), 0);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].detail, "OpenSSH public key, ssh-ed25519 256-bit");
        assert_eq!(findings[0].offset, 7);
    }

    #[test]
    fn openssh_private_key_reports_cipher_and_type() {
        let mut blob = Vec::new();
        for part in [b"ssh-ed25519".to_vec(), noise(32, 2)] {
            blob.extend((part.len() as u32).to_be_bytes());
            blob.extend(part);
        }
        let mut key = OPENSSH_MAGIC.to_vec();
        for part in [b"aes256-ctr".to_vec(), b"bcrypt".to_vec(), vec![0; 4]] {
            key.extend((part.len() as u32).to_be_bytes());
            key.extend(part);
        }
        key.extend(1u32.to_be_bytes());
        key.extend((blob.len() as u32).to_be_bytes());
        key.extend(&blob);
        key.extend(16u32.to_be_bytes());
        key.extend(noise(16, 3));
        let (detail, len) = parse_openssh_private(&key).unwrap();
        assert_eq!(detail, "OpenSSH private key, ssh-ed25519 256-bit, encrypted with aes256-ctr");
        assert_eq!(len, key.len());
    }

    #[test]
    fn random_key_amid_structure_is_a_low_confidence_candidate() {
        let mut data = structured_padding(200);
        let key = noise(32, 77);
        data.extend(&key);
        data.extend(structured_padding(200));
        let findings = find_keys(&data, 0);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let candidate = &findings[0];
        assert_eq!(candidate.kind, KeyKind::RawKeyCandidate);
        assert_eq!((candidate.offset, candidate.len), (200, 32));
        assert!(candidate.confidence < 0.5);
        let full_hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(!candidate.detail.contains(&full_hex), "key material must not be shown in full");
    }

    #[test]
    fn random_data_and_text_yield_no_findings() {
        assert!(find_keys(&noise(1 << 20, 5), 0).is_empty());
        let text = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(200);
        assert!(find_keys(&text, 0).is_empty());
    }

    #[test]
    fn truncated_and_corrupt_inputs_never_panic() {
        let certificate = from_hex(TEST_CERTIFICATE_HEX);
        for cut in 0..certificate.len() {
            let _ = find_keys(&certificate[..cut], 0);
        }
        let _ = find_keys(b"-----BEGIN ", 0);
        let _ = find_keys(b"-----BEGIN X-----\n!!!!\n-----END X-----", 0);
        let _ = find_keys(b"ssh-rsa AAAA", 0);
        let _ = find_keys(OPENSSH_MAGIC, 0);
        let _ = find_keys(&[0x30, 0x83, 0xff, 0xff, 0xff, 0x02], 0);
    }
}
