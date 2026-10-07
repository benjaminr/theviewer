//! Recursive extraction into a browsable tree, like `binwalk -e`.
//!
//! Starting from a file, every embedded container and compressed stream is
//! pulled out as a child node, and each child is searched in turn: a zip
//! inside a gzip inside a firmware image becomes three levels of tree.
//! Everything is bounded by [`Limits`], and malformed input never panics.

use std::sync::Arc;

use crate::compress::{self, Codec};

/// Bounds on how much work an unpack may do.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Deepest nesting explored below the root.
    pub max_depth: usize,
    /// Most nodes in the whole tree, root included.
    pub max_nodes: usize,
    /// Most extracted bytes across the whole tree.
    pub max_total_bytes: usize,
    /// Most bytes a single extracted node may hold.
    pub max_node_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_depth: 6, max_nodes: 2000, max_total_bytes: 512 * 1024 * 1024, max_node_bytes: 256 * 1024 * 1024 }
    }
}

/// One file, entry or stream in the tree.
#[derive(Clone, Debug)]
pub struct Node {
    pub name: String,
    /// What it is: "file", "zip entry", "tar entry", "gzip stream", …
    pub kind: String,
    /// Offset of this node's source bytes in its parent's data.
    pub source_offset: usize,
    /// Length of those source bytes (header and compressed data included).
    pub source_len: usize,
    /// The node's own bytes, decompressed where that applies.
    pub data: Arc<Vec<u8>>,
    pub children: Vec<Node>,
    /// Why exploration stopped early here, or a problem with this node.
    pub note: Option<String>,
    /// Compression method, when the node was decompressed ("deflate", "gzip", …).
    pub method: Option<String>,
}

impl Node {
    /// The node reached by following child indices from this one.
    pub fn find(&self, path: &[usize]) -> Option<&Node> {
        let mut node = self;
        for &index in path {
            node = node.children.get(index)?;
        }
        Some(node)
    }

    /// Nodes in this subtree, this one included.
    pub fn count(&self) -> usize {
        1 + self.children.iter().map(Node::count).sum::<usize>()
    }

    /// One line, e.g. "zip entry config.txt, 500 B (deflate 3.2×)".
    pub fn summary(&self) -> String {
        let mut text = format!("{} {}, {}", self.kind, self.name, compress::human_bytes(self.data.len()));
        if let Some(method) = &self.method {
            let ratio = self.data.len() as f64 / self.source_len.max(1) as f64;
            text.push_str(&format!(" ({method} {ratio:.1}×)"));
        }
        if let Some(note) = &self.note {
            text.push_str(&format!(" — {note}"));
        }
        text
    }
}

/// Running totals checked against the limits.
struct Budget {
    nodes: usize,
    bytes: usize,
}

/// What one unpacking works within: its limits, and the password tried on
/// encrypted archive entries.
struct Settings<'a> {
    limits: &'a Limits,
    password: Option<&'a [u8]>,
}

/// Unpack `bytes` (called `name`) recursively.
pub fn unpack(bytes: Arc<Vec<u8>>, name: &str, limits: &Limits) -> Node {
    unpack_with_password(bytes, name, limits, None)
}

/// Unpack `bytes` recursively, decrypting ZipCrypto entries with `password`.
/// Without one, an encrypted entry is listed with a note and no content.
pub fn unpack_with_password(bytes: Arc<Vec<u8>>, name: &str, limits: &Limits, password: Option<&[u8]>) -> Node {
    let settings = Settings { limits, password };
    let mut root = Node {
        name: name.to_string(),
        kind: "file".to_string(),
        source_offset: 0,
        source_len: bytes.len(),
        data: bytes,
        children: Vec::new(),
        note: None,
        method: None,
    };
    let mut budget = Budget { nodes: 1, bytes: 0 };
    expand(&mut root, 0, &settings, &mut budget);
    root
}

fn expand(node: &mut Node, depth: usize, settings: &Settings, budget: &mut Budget) {
    let limits = settings.limits;
    // Decompression is capped by what is left of the total, so a small archive
    // of highly compressible entries cannot allocate far beyond the limit.
    let mut bytes_left = limits.max_total_bytes.saturating_sub(budget.bytes);
    let found = find_children(&node.data, settings, &mut bytes_left);
    if bytes_left == 0 {
        node.note = Some("stopped: size limit reached".to_string());
    }
    if found.is_empty() {
        return;
    }
    if depth >= limits.max_depth {
        node.note = Some("stopped: depth limit reached".to_string());
        return;
    }
    for mut child in found {
        if !admit(node, &child, limits, budget) {
            break;
        }
        descend(&mut child, depth + 1, settings, budget);
        node.children.push(child);
    }
}

/// Count `child` against the limits. Returns false, with a note on `parent`,
/// once a limit is reached.
fn admit(parent: &mut Node, child: &Node, limits: &Limits, budget: &mut Budget) -> bool {
    if budget.nodes >= limits.max_nodes {
        parent.note = Some("stopped: node limit reached".to_string());
        return false;
    }
    if budget.bytes + child.data.len() > limits.max_total_bytes {
        parent.note = Some("stopped: size limit reached".to_string());
        return false;
    }
    budget.nodes += 1;
    budget.bytes += child.data.len();
    true
}

/// Look inside a newly found node. Most are searched for containers and
/// streams; an embedded filesystem arrives as a folder that already holds its
/// files, so each of those is counted and searched instead.
fn descend(node: &mut Node, depth: usize, settings: &Settings, budget: &mut Budget) {
    if node.children.is_empty() {
        expand(node, depth, settings, budget);
        return;
    }
    let files = std::mem::take(&mut node.children);
    for mut child in files {
        if !admit(node, &child, settings.limits, budget) {
            break;
        }
        if depth < settings.limits.max_depth {
            descend(&mut child, depth + 1, settings, budget);
        }
        node.children.push(child);
    }
}

/// Containers and streams directly inside `data`, sorted by offset. Streams
/// that sit inside a zip or tar entry are left for that entry's own pass.
///
/// Extracted bytes are taken from `bytes_left`; once it runs out, no more
/// children are extracted.
fn find_children(data: &[u8], settings: &Settings, bytes_left: &mut usize) -> Vec<Node> {
    let limits = settings.limits;
    // Filesystems first: their compressed blocks and stored files must not be
    // reported again as loose streams or archive entries.
    let mut children = crate::embedfs::filesystem_nodes(data, limits, bytes_left);
    let in_filesystem = |offset: usize| {
        children.iter().any(|fs| offset >= fs.source_offset && offset < fs.source_offset + fs.source_len)
    };
    let archived: Vec<Node> = zip_entries(data, settings, bytes_left)
        .into_iter()
        .chain(tar_entries(data, limits, bytes_left))
        .filter(|entry| !in_filesystem(entry.source_offset))
        .collect();
    children.extend(archived);
    let claimed: Vec<(usize, usize)> = children.iter().map(|c| (c.source_offset, c.source_offset + c.source_len)).collect();
    for stream in compress::scan_streams(data, 0) {
        if claimed.iter().any(|&(start, end)| stream.start >= start && stream.start < end) {
            continue;
        }
        if let Some(child) = stream_node(data, &stream, limits, bytes_left) {
            children.push(child);
        }
    }
    children.sort_by_key(|child| child.source_offset);
    children
}

/// The most one child may extract: the per-node limit, or what is left of the
/// total. `None` once nothing is left.
fn node_cap(limits: &Limits, bytes_left: usize) -> Option<usize> {
    (bytes_left > 0).then(|| limits.max_node_bytes.min(bytes_left))
}

/// Charge an extracted child's bytes to the allowance.
fn charge(node: Node, bytes_left: &mut usize) -> Node {
    *bytes_left = bytes_left.saturating_sub(node.data.len());
    node
}

fn stream_node(data: &[u8], stream: &compress::Stream, limits: &Limits, bytes_left: &mut usize) -> Option<Node> {
    let cap = node_cap(limits, *bytes_left)?;
    let input = data.get(stream.start..)?;
    let decoded = compress::decompress(stream.codec, input, cap).ok()?;
    let note = if decoded.truncated {
        Some("stopped: node size limit reached".to_string())
    } else if !decoded.complete {
        Some("stream is incomplete".to_string())
    } else {
        None
    };
    let source_len = decoded.consumed.max(stream.compressed_len).min(input.len());
    Some(charge(Node {
        name: format!("{}@{:#x}", stream.codec.label(), stream.start),
        kind: format!("{} stream", stream.codec.label()),
        source_offset: stream.start,
        source_len,
        data: Arc::new(decoded.data),
        children: Vec::new(),
        note,
        method: Some(stream.codec.label().to_string()),
    }, bytes_left))
}

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_CENTRAL: &[u8] = b"PK\x01\x02";
const ZIP_LOCAL_HEADER_LEN: usize = 30;
const ZIP_CENTRAL_HEADER_LEN: usize = 46;
const MAX_ENTRIES: usize = 4096;
/// General-purpose flag: the entry is encrypted.
const ZIP_FLAG_ENCRYPTED: usize = 0x0001;
/// General-purpose flag: sizes and CRC follow the data in a descriptor.
const ZIP_FLAG_DESCRIPTOR: usize = 0x0008;
const ZIP_METHOD_STORED: usize = 0;
const ZIP_METHOD_DEFLATE: usize = 8;
/// WinZip AES: the real method is in an extra field, the data AES-encrypted.
const ZIP_METHOD_AES: usize = 99;

fn u16le(data: &[u8], at: usize) -> Option<usize> {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
}

fn u32le(data: &[u8], at: usize) -> Option<usize> {
    data.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
}

/// Every position of `needle` in `data`.
fn positions(data: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(offset) = data.get(at..).and_then(|rest| rest.windows(needle.len()).position(|w| w == needle)) {
        found.push(at + offset);
        at += offset + 1;
        if found.len() >= MAX_ENTRIES {
            break;
        }
    }
    found
}

/// What the central directory records of one entry: used when a local
/// header defers its sizes and CRC to a data descriptor.
struct CentralRecord {
    name: Vec<u8>,
    crc: usize,
    compressed: usize,
    uncompressed: usize,
}

fn central_records(data: &[u8]) -> Vec<CentralRecord> {
    positions(data, ZIP_CENTRAL)
        .into_iter()
        .filter_map(|at| {
            let name_len = u16le(data, at + 28)?;
            let name = data.get(at + ZIP_CENTRAL_HEADER_LEN..at + ZIP_CENTRAL_HEADER_LEN + name_len)?;
            Some(CentralRecord { name: name.to_vec(), crc: u32le(data, at + 16)?, compressed: u32le(data, at + 20)?, uncompressed: u32le(data, at + 24)? })
        })
        .collect()
}

fn zip_entries(data: &[u8], settings: &Settings, bytes_left: &mut usize) -> Vec<Node> {
    let locals = positions(data, ZIP_LOCAL);
    if locals.is_empty() {
        return Vec::new();
    }
    let central = central_records(data);
    locals.into_iter().filter_map(|at| zip_entry(data, at, &central, settings, bytes_left)).collect()
}

/// A local header's facts, with sizes and CRC taken from the central
/// directory when the header defers them to a data descriptor.
struct LocalHeader {
    flags: usize,
    method: usize,
    /// DOS modification time, whose high byte checks a ZipCrypto password
    /// when the entry has a data descriptor.
    time: usize,
    crc: usize,
    compressed: usize,
    uncompressed: usize,
    data_start: usize,
}

impl LocalHeader {
    fn encrypted(&self) -> bool {
        self.flags & ZIP_FLAG_ENCRYPTED != 0 || self.method == ZIP_METHOD_AES
    }

    /// The byte a ZipCrypto header ends with when the password is right.
    fn check_byte(&self) -> u8 {
        if self.flags & ZIP_FLAG_DESCRIPTOR != 0 { (self.time >> 8) as u8 } else { (self.crc >> 24) as u8 }
    }
}

fn zip_entry(data: &[u8], at: usize, central: &[CentralRecord], settings: &Settings, bytes_left: &mut usize) -> Option<Node> {
    let cap = node_cap(settings.limits, *bytes_left)?;
    let name_len = u16le(data, at + 26)?;
    let extra_len = u16le(data, at + 28)?;
    let name_bytes = data.get(at + ZIP_LOCAL_HEADER_LEN..at + ZIP_LOCAL_HEADER_LEN + name_len)?;
    let name = String::from_utf8_lossy(name_bytes).into_owned();
    if name.is_empty() || name.ends_with('/') {
        return None; // Directories hold no data.
    }
    let mut header = LocalHeader {
        flags: u16le(data, at + 6)?,
        method: u16le(data, at + 8)?,
        time: u16le(data, at + 10)?,
        crc: u32le(data, at + 14)?,
        compressed: u32le(data, at + 18)?,
        uncompressed: u32le(data, at + 22)?,
        data_start: at + ZIP_LOCAL_HEADER_LEN + name_len + extra_len,
    };
    if header.flags & ZIP_FLAG_DESCRIPTOR != 0
        && header.compressed == 0
        && let Some(record) = central.iter().find(|record| record.name == name_bytes)
    {
        header.crc = record.crc;
        header.compressed = record.compressed;
        header.uncompressed = record.uncompressed;
    }
    let rest = data.get(header.data_start..)?;
    let member = if header.encrypted() {
        encrypted_member(&header, rest, settings.password, cap)
    } else {
        decode_member(header.method, header.compressed, header.uncompressed, rest, cap)
    };
    Some(charge(Node {
        name,
        kind: "zip entry".to_string(),
        source_offset: at,
        source_len: header.data_start - at + member.consumed,
        data: Arc::new(member.bytes),
        children: Vec::new(),
        note: member.note,
        method: member.method,
    }, bytes_left))
}

/// What came of one entry's data.
struct Member {
    bytes: Vec<u8>,
    /// Bytes of the entry's stored data used.
    consumed: usize,
    method: Option<String>,
    note: Option<String>,
}

impl Member {
    /// An entry left without content, with why.
    fn empty(consumed: usize, method: Option<String>, note: String) -> Self {
        Member { bytes: Vec::new(), consumed, method, note: Some(note) }
    }
}

/// Decompress an entry's stored data, `rest` running from its start to the
/// end of the scanned bytes. A stream that does not inflate is still an
/// entry, with the error as its note.
fn decode_member(method: usize, compressed: usize, uncompressed: usize, rest: &[u8], cap: usize) -> Member {
    match method {
        ZIP_METHOD_STORED => {
            let len = if compressed > 0 { compressed } else { uncompressed };
            let stored = &rest[..len.min(cap).min(rest.len())];
            Member { bytes: stored.to_vec(), consumed: stored.len(), method: None, note: None }
        }
        ZIP_METHOD_DEFLATE => {
            // Inflate tells us exactly where the deflate data ends, which also
            // covers descriptor entries the central directory did not list.
            let input = if compressed > 0 { rest.get(..compressed).unwrap_or(rest) } else { rest };
            match compress::decompress(Codec::Deflate, input, cap) {
                Ok(decoded) => {
                    let note = decoded.truncated.then(|| "stopped: node size limit reached".to_string());
                    Member { bytes: decoded.data, consumed: decoded.consumed, method: Some("deflate".to_string()), note }
                }
                Err(error) => Member::empty(compressed.min(rest.len()), Some("deflate".to_string()), format!("could not inflate: {error}")),
            }
        }
        other => {
            let raw = &rest[..compressed.min(rest.len()).min(cap)];
            Member { bytes: raw.to_vec(), consumed: raw.len(), method: None, note: Some(format!("unsupported compression method {other}")) }
        }
    }
}

/// An encrypted entry: decrypted when it is ZipCrypto and `password` fits,
/// otherwise listed with a note and no content, never with its ciphertext
/// standing in for the file.
fn encrypted_member(header: &LocalHeader, rest: &[u8], password: Option<&[u8]>, cap: usize) -> Member {
    let stored = &rest[..header.compressed.min(rest.len())];
    if header.method == ZIP_METHOD_AES {
        return Member::empty(stored.len(), None, "encrypted (AES): not decrypted".to_string());
    }
    let Some(password) = password else {
        return Member::empty(stored.len(), None, "encrypted (ZipCrypto): unpack with a password to decrypt".to_string());
    };
    if stored.len() < zipcrypto::HEADER_LEN {
        return Member::empty(stored.len(), None, "encrypted (ZipCrypto): the encryption header is cut short".to_string());
    }
    let plain = zipcrypto::decrypt(password, stored);
    if plain[zipcrypto::HEADER_LEN - 1] != header.check_byte() {
        return Member::empty(stored.len(), None, "encrypted (ZipCrypto): the password does not fit".to_string());
    }
    let payload = &plain[zipcrypto::HEADER_LEN..];
    let mut member = decode_member(header.method, payload.len(), header.uncompressed, payload, cap);
    member.consumed = stored.len();
    if member.note.is_none() {
        let fits = crc32fast::hash(&member.bytes) as usize == header.crc;
        member.note = Some(if fits { "decrypted (ZipCrypto)" } else { "decrypted (ZipCrypto), but the CRC does not match: the password may be wrong" }.to_string());
    }
    member
}

/// The traditional PKWARE stream cipher ("ZipCrypto"): three 32-bit keys
/// stirred by each plaintext byte, with a 12-byte header before the data
/// whose last byte checks the password.
mod zipcrypto {
    pub const HEADER_LEN: usize = 12;

    struct Keys([u32; 3]);

    impl Keys {
        fn new(password: &[u8]) -> Self {
            let mut keys = Keys([0x1234_5678, 0x2345_6789, 0x3456_7890]);
            for &byte in password {
                keys.update(byte);
            }
            keys
        }

        fn update(&mut self, plain: u8) {
            let [k0, k1, k2] = &mut self.0;
            *k0 = crc32_byte(*k0, plain);
            *k1 = k1.wrapping_add(*k0 & 0xFF).wrapping_mul(134_775_813).wrapping_add(1);
            *k2 = crc32_byte(*k2, (*k1 >> 24) as u8);
        }

        fn stream_byte(&self) -> u8 {
            let temp = (self.0[2] | 2) & 0xFFFF;
            (temp.wrapping_mul(temp ^ 1) >> 8) as u8
        }
    }

    /// One step of the CRC-32 the keys are stirred with.
    fn crc32_byte(crc: u32, byte: u8) -> u32 {
        let mut value = (crc ^ byte as u32) & 0xFF;
        for _ in 0..8 {
            value = if value & 1 != 0 { (value >> 1) ^ 0xEDB8_8320 } else { value >> 1 };
        }
        value ^ (crc >> 8)
    }

    /// Decrypt `cipher` (encryption header included) with `password`.
    pub fn decrypt(password: &[u8], cipher: &[u8]) -> Vec<u8> {
        let mut keys = Keys::new(password);
        cipher
            .iter()
            .map(|&byte| {
                let plain = byte ^ keys.stream_byte();
                keys.update(plain);
                plain
            })
            .collect()
    }

    /// Encrypt `plain` (encryption header included) with `password`.
    #[cfg(test)]
    pub fn encrypt(password: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut keys = Keys::new(password);
        plain
            .iter()
            .map(|&byte| {
                let cipher = byte ^ keys.stream_byte();
                keys.update(byte);
                cipher
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// TAR (ustar)
// ---------------------------------------------------------------------------

const TAR_BLOCK: usize = 512;

/// A ustar header at `at` whose checksum is valid.
fn is_tar_header(data: &[u8], at: usize) -> bool {
    let Some(header) = data.get(at..at + TAR_BLOCK) else { return false };
    if &header[257..262] != b"ustar" {
        return false;
    }
    let Some(stored) = parse_octal(&header[148..156]) else { return false };
    let sum: usize = header.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { b' ' as usize } else { b as usize }).sum();
    sum == stored
}

fn parse_octal(field: &[u8]) -> Option<usize> {
    let text: String = field.iter().take_while(|&&b| b != 0).map(|&b| b as char).collect();
    let text = text.trim();
    if text.is_empty() {
        return Some(0);
    }
    usize::from_str_radix(text, 8).ok()
}

fn tar_entries(data: &[u8], limits: &Limits, bytes_left: &mut usize) -> Vec<Node> {
    let mut entries = Vec::new();
    let mut search = 0;
    // Find the first header of each archive, then walk its entries.
    while let Some(magic) = data.get(search..).and_then(|rest| rest.windows(5).position(|w| w == b"ustar")) {
        let magic_at = search + magic;
        search = magic_at + 1;
        let Some(start) = magic_at.checked_sub(257) else { continue };
        if !is_tar_header(data, start) {
            continue;
        }
        let end = walk_tar(data, start, limits, bytes_left, &mut entries);
        search = end.max(search);
        if entries.len() >= MAX_ENTRIES {
            break;
        }
    }
    entries
}

/// Walk entries from the header at `start`; returns where the archive ends.
fn walk_tar(data: &[u8], start: usize, limits: &Limits, bytes_left: &mut usize, entries: &mut Vec<Node>) -> usize {
    let mut at = start;
    while is_tar_header(data, at) && entries.len() < MAX_ENTRIES {
        let header = &data[at..at + TAR_BLOCK];
        let Some(size) = parse_octal(&header[124..136]) else { break };
        let name: String = header[..100].iter().take_while(|&&b| b != 0).map(|&b| b as char).collect();
        let typeflag = header[156];
        let content_start = at + TAR_BLOCK;
        let content_end = content_start.saturating_add(size).min(data.len());
        if matches!(typeflag, b'0' | 0)
            && !name.is_empty()
            && let Some(cap) = node_cap(limits, *bytes_left)
        {
            let take = (content_end - content_start).min(cap);
            entries.push(charge(Node {
                name,
                kind: "tar entry".to_string(),
                source_offset: at,
                source_len: content_end - at,
                data: Arc::new(data[content_start..content_start + take].to_vec()),
                children: Vec::new(),
                note: (take < size).then(|| "stopped: node size limit reached".to_string()),
                method: None,
            }, bytes_left));
        }
        let padded = size.div_ceil(TAR_BLOCK) * TAR_BLOCK;
        match content_start.checked_add(padded) {
            Some(next) if next > at => at = next,
            _ => break,
        }
    }
    at
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A ZipCrypto-encrypted local entry, as PKWARE's tools write one: a
    /// 12-byte header ending in the CRC's high byte, then the encrypted data.
    pub fn encrypted_entry(name: &str, content: &[u8], deflate: bool, password: &[u8]) -> Vec<u8> {
        let crc = crc32fast::hash(content);
        let payload = if deflate { compress::compress(Codec::Deflate, content).unwrap() } else { content.to_vec() };
        let mut plain = b"random head".to_vec();
        plain.push((crc >> 24) as u8);
        plain.extend_from_slice(&payload);
        let cipher = zipcrypto::encrypt(password, &plain);
        let mut out = Vec::new();
        out.extend_from_slice(ZIP_LOCAL);
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&(ZIP_FLAG_ENCRYPTED as u16).to_le_bytes());
        out.extend_from_slice(&(if deflate { ZIP_METHOD_DEFLATE as u16 } else { ZIP_METHOD_STORED as u16 }).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(cipher.len() as u32).to_le_bytes());
        out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&cipher);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(lines: usize) -> Vec<u8> {
        (0..lines).flat_map(|i| format!("line {i:04} of some very compressible text\n").into_bytes()).collect()
    }

    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x2545_F491u32;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }

    /// A zip entry: local header, data and, when `descriptor`, sizes left
    /// zero in the header with a data descriptor after the data.
    fn zip_local(name: &str, content: &[u8], deflate: bool, descriptor: bool) -> (Vec<u8>, usize, u32) {
        let crc = crc32fast::hash(content);
        let payload = if deflate { compress::compress(Codec::Deflate, content).unwrap() } else { content.to_vec() };
        let mut out = Vec::new();
        out.extend_from_slice(ZIP_LOCAL);
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&(if descriptor { 0x08u16 } else { 0 }).to_le_bytes());
        out.extend_from_slice(&(if deflate { 8u16 } else { 0 }).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        let (crc_field, comp, uncomp) = if descriptor { (0, 0, 0) } else { (crc, payload.len() as u32, content.len() as u32) };
        out.extend_from_slice(&crc_field.to_le_bytes());
        out.extend_from_slice(&comp.to_le_bytes());
        out.extend_from_slice(&uncomp.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&payload);
        if descriptor {
            out.extend_from_slice(b"PK\x07\x08");
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        }
        (out, payload.len(), crc)
    }

    fn central(name: &str, comp: usize, uncomp: usize, crc: u32, local_offset: usize, deflate: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ZIP_CENTRAL);
        out.extend_from_slice(&[20, 0, 20, 0, 0x08, 0]);
        out.extend_from_slice(&(if deflate { 8u16 } else { 0 }).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(comp as u32).to_le_bytes());
        out.extend_from_slice(&(uncomp as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&(local_offset as u32).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out
    }

    fn tar_with(name: &str, content: &[u8]) -> Vec<u8> {
        let mut header = vec![0u8; TAR_BLOCK];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].copy_from_slice(b"        ");
        let sum: usize = header.iter().map(|&b| b as usize).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let mut out = header;
        out.extend_from_slice(content);
        out.resize(out.len().div_ceil(TAR_BLOCK) * TAR_BLOCK, 0);
        out.extend_from_slice(&[0u8; TAR_BLOCK * 2]);
        out
    }

    #[test]
    fn zip_entries_are_extracted_and_nested_gzip_is_unpacked() {
        let inner_text = text(200);
        let gzipped = compress::compress(Codec::Gzip, &inner_text).unwrap();
        let (stored, _, _) = zip_local("readme.txt", b"plain stored content", false, false);
        let (deflated, _, _) = zip_local("data.gz", &gzipped, true, false);
        let mut file = noise(100);
        file.extend_from_slice(&stored);
        file.extend_from_slice(&deflated);
        let root = unpack(Arc::new(file), "archive.bin", &Limits::default());
        let names: Vec<&str> = root.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["readme.txt", "data.gz"], "{root:#?}");
        assert_eq!(root.children[0].data.as_slice(), b"plain stored content");
        assert_eq!(root.children[0].source_offset, 100);
        let gz = &root.children[1];
        assert_eq!(gz.data.as_slice(), gzipped.as_slice());
        assert_eq!(gz.method.as_deref(), Some("deflate"));
        assert_eq!(gz.children.len(), 1, "gzip inside the deflated entry");
        assert_eq!(gz.children[0].kind, "gzip stream");
        assert_eq!(gz.children[0].data.as_slice(), inner_text.as_slice());
        assert_eq!(root.count(), 4);
        assert!(root.find(&[1, 0]).unwrap().summary().starts_with("gzip stream gzip@0x0"));
        assert!(gz.summary().contains("deflate"), "{}", gz.summary());
    }

    #[test]
    fn data_descriptor_entries_use_the_central_directory() {
        let content = text(50);
        let (local, comp, crc) = zip_local("log.txt", &content, true, true);
        let (stored_local, _, stored_crc) = zip_local("raw.bin", b"stored with descriptor", false, true);
        let mut file = local.clone();
        let stored_at = file.len();
        file.extend_from_slice(&stored_local);
        file.extend_from_slice(&central("log.txt", comp, content.len(), crc, 0, true));
        file.extend_from_slice(&central("raw.bin", 22, 22, stored_crc, stored_at, false));
        let root = unpack(Arc::new(file), "descriptor.zip", &Limits::default());
        assert_eq!(root.children.len(), 2, "{root:#?}");
        assert_eq!(root.children[0].data.as_slice(), content.as_slice());
        assert_eq!(root.children[1].data.as_slice(), b"stored with descriptor");
    }

    #[test]
    fn tar_entries_and_loose_streams_are_found() {
        let content = b"hello from inside a tar archive\n".repeat(10);
        let mut file = vec![0u8; 1024];
        let tar_at = file.len();
        file.extend_from_slice(&tar_with("hello.txt", &content));
        let gzip_at = file.len();
        let inner = text(100);
        file.extend_from_slice(&compress::compress(Codec::Gzip, &inner).unwrap());
        file.extend_from_slice(&noise(500));
        let root = unpack(Arc::new(file), "mixed", &Limits::default());
        assert_eq!(root.children.len(), 2, "{root:#?}");
        assert_eq!((root.children[0].kind.as_str(), root.children[0].source_offset), ("tar entry", tar_at));
        assert_eq!(root.children[0].data.as_slice(), content.as_slice());
        assert_eq!((root.children[1].kind.as_str(), root.children[1].source_offset), ("gzip stream", gzip_at));
        assert_eq!(root.children[1].data.as_slice(), inner.as_slice());
    }

    #[test]
    fn noise_has_no_children() {
        let root = unpack(Arc::new(noise(64 * 1024)), "noise", &Limits::default());
        assert!(root.children.is_empty());
        assert!(root.note.is_none());
    }

    #[test]
    fn the_total_size_limit_caps_decompression_not_just_the_kept_children() {
        // Ten streams that each inflate to 64 KiB, with room for only 100 KiB.
        let mut many = Vec::new();
        for _ in 0..10 {
            many.extend_from_slice(&compress::compress(Codec::Gzip, &vec![b'A'; 64 * 1024]).unwrap());
        }
        let small = Limits { max_total_bytes: 100 * 1024, ..Limits::default() };
        let root = unpack(Arc::new(many), "many", &small);
        let extracted: usize = root.children.iter().map(|child| child.data.len()).sum();
        assert!(extracted <= small.max_total_bytes, "extracted {extracted} bytes");
        assert_eq!(root.note.as_deref(), Some("stopped: size limit reached"));
    }

    #[test]
    fn depth_and_node_limits_are_respected() {
        // gzip of gzip of gzip of text: three levels.
        let mut nested = text(100);
        for _ in 0..3 {
            nested = compress::compress(Codec::Gzip, &nested).unwrap();
        }
        let shallow = Limits { max_depth: 1, ..Limits::default() };
        let root = unpack(Arc::new(nested.clone()), "nested", &shallow);
        assert_eq!(root.children.len(), 1);
        assert!(root.children[0].children.is_empty());
        assert_eq!(root.children[0].note.as_deref(), Some("stopped: depth limit reached"));
        let deep = unpack(Arc::new(nested), "nested", &Limits::default());
        assert_eq!(deep.count(), 4);

        let mut many = Vec::new();
        for i in 0..10 {
            many.extend_from_slice(&compress::compress(Codec::Gzip, format!("stream number {i} ").repeat(20).as_bytes()).unwrap());
        }
        let few = Limits { max_nodes: 4, ..Limits::default() };
        let root = unpack(Arc::new(many), "many", &few);
        assert_eq!(root.count(), 4);
        assert_eq!(root.note.as_deref(), Some("stopped: node limit reached"));
    }

    #[test]
    fn malformed_headers_do_not_panic() {
        let mut junk = noise(4096);
        for at in [0usize, 100, 2000, 4000] {
            junk[at..at + 4].copy_from_slice(ZIP_LOCAL);
        }
        junk[257 + 1024..262 + 1024].copy_from_slice(b"ustar");
        let mut truncated = ZIP_LOCAL.to_vec();
        truncated.extend_from_slice(&[0xFF; 10]);
        for input in [junk, truncated, b"PK".to_vec(), Vec::new()] {
            let _ = unpack(Arc::new(input), "junk", &Limits::default());
        }
    }

    const PASSWORD: &[u8] = b"Kestrel!Moor42";

    fn encrypted_archive() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n".to_vec();
        let csv = text(40);
        let mut archive = test_support::encrypted_entry("Q3_specs.pdf", &pdf, false, PASSWORD);
        archive.extend(test_support::encrypted_entry("board_rev3.png", &noise(300), true, PASSWORD));
        archive.extend(test_support::encrypted_entry("ledger.csv", &csv, true, PASSWORD));
        (archive, pdf, csv)
    }

    #[test]
    fn every_member_of_an_encrypted_zip_is_listed_as_encrypted_and_none_shows_ciphertext_as_its_content() {
        let (archive, _, _) = encrypted_archive();
        let root = unpack(Arc::new(archive), "backup_0912.zip", &Limits::default());
        let names: Vec<&str> = root.children.iter().map(|child| child.name.as_str()).collect();
        assert_eq!(names, ["Q3_specs.pdf", "board_rev3.png", "ledger.csv"], "{root:#?}");
        for member in &root.children {
            assert!(member.data.is_empty(), "{} presents {} bytes", member.name, member.data.len());
            assert!(member.note.as_deref().is_some_and(|note| note.starts_with("encrypted (ZipCrypto)")), "{member:#?}");
            assert!(member.summary().contains("encrypted (ZipCrypto)"));
        }
    }

    #[test]
    fn the_right_password_decrypts_stored_and_deflated_members() {
        let (archive, pdf, csv) = encrypted_archive();
        let root = unpack_with_password(Arc::new(archive), "backup_0912.zip", &Limits::default(), Some(PASSWORD));
        assert_eq!(root.children.len(), 3, "{root:#?}");
        assert_eq!(root.children[0].data.as_slice(), pdf.as_slice());
        assert_eq!(root.children[2].data.as_slice(), csv.as_slice());
        assert_eq!(root.children[2].method.as_deref(), Some("deflate"));
        assert!(root.children.iter().all(|member| member.note.as_deref() == Some("decrypted (ZipCrypto)")), "{root:#?}");
    }

    #[test]
    fn a_wrong_password_leaves_members_encrypted_rather_than_showing_garbage() {
        let (archive, _, _) = encrypted_archive();
        let root = unpack_with_password(Arc::new(archive), "backup_0912.zip", &Limits::default(), Some(b"hunter2"));
        assert_eq!(root.children.len(), 3, "{root:#?}");
        for member in &root.children {
            let note = member.note.as_deref().unwrap_or_default();
            assert!(member.data.is_empty() || note.contains("CRC does not match"), "{member:#?}");
            assert!(note.contains("ZipCrypto") && note != "decrypted (ZipCrypto)", "{note}");
        }
    }

    #[test]
    fn an_aes_member_is_listed_as_encrypted_with_no_content() {
        let (mut stored, _, _) = zip_local("secret.txt", b"not really aes", false, false);
        stored[8..10].copy_from_slice(&99u16.to_le_bytes());
        let root = unpack(Arc::new(stored), "aes.zip", &Limits::default());
        assert_eq!(root.children.len(), 1);
        assert!(root.children[0].data.is_empty());
        assert_eq!(root.children[0].note.as_deref(), Some("encrypted (AES): not decrypted"));
    }

    #[test]
    fn a_deflated_member_that_does_not_inflate_is_kept_with_its_error() {
        let (mut broken, _, _) = zip_local("broken.txt", &text(50), true, false);
        let data_at = ZIP_LOCAL_HEADER_LEN + "broken.txt".len();
        broken[data_at] = 0xFF; // An invalid block type.
        let root = unpack(Arc::new(broken), "broken.zip", &Limits::default());
        assert_eq!(root.children.len(), 1, "{root:#?}");
        let member = &root.children[0];
        assert_eq!(member.name, "broken.txt");
        assert!(member.data.is_empty());
        assert!(member.note.as_deref().is_some_and(|note| note.starts_with("could not inflate")), "{member:#?}");
    }
}
