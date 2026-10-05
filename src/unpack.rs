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

/// Unpack `bytes` (called `name`) recursively.
pub fn unpack(bytes: Arc<Vec<u8>>, name: &str, limits: &Limits) -> Node {
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
    expand(&mut root, 0, limits, &mut budget);
    root
}

fn expand(node: &mut Node, depth: usize, limits: &Limits, budget: &mut Budget) {
    // Decompression is capped by what is left of the total, so a small archive
    // of highly compressible entries cannot allocate far beyond the limit.
    let mut bytes_left = limits.max_total_bytes.saturating_sub(budget.bytes);
    let found = find_children(&node.data, limits, &mut bytes_left);
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
        descend(&mut child, depth + 1, limits, budget);
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
fn descend(node: &mut Node, depth: usize, limits: &Limits, budget: &mut Budget) {
    if node.children.is_empty() {
        expand(node, depth, limits, budget);
        return;
    }
    let files = std::mem::take(&mut node.children);
    for mut child in files {
        if !admit(node, &child, limits, budget) {
            break;
        }
        if depth < limits.max_depth {
            descend(&mut child, depth + 1, limits, budget);
        }
        node.children.push(child);
    }
}

/// Containers and streams directly inside `data`, sorted by offset. Streams
/// that sit inside a zip or tar entry are left for that entry's own pass.
///
/// Extracted bytes are taken from `bytes_left`; once it runs out, no more
/// children are extracted.
fn find_children(data: &[u8], limits: &Limits, bytes_left: &mut usize) -> Vec<Node> {
    // Filesystems first: their compressed blocks and stored files must not be
    // reported again as loose streams or archive entries.
    let mut children = crate::embedfs::filesystem_nodes(data, limits, bytes_left);
    let in_filesystem = |offset: usize| {
        children.iter().any(|fs| offset >= fs.source_offset && offset < fs.source_offset + fs.source_len)
    };
    let archived: Vec<Node> = zip_entries(data, limits, bytes_left)
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

/// Sizes recorded in the central directory, keyed by file name: used when a
/// local header defers its sizes to a data descriptor.
fn central_sizes(data: &[u8]) -> Vec<(Vec<u8>, usize, usize)> {
    positions(data, ZIP_CENTRAL)
        .into_iter()
        .filter_map(|at| {
            let compressed = u32le(data, at + 20)?;
            let uncompressed = u32le(data, at + 24)?;
            let name_len = u16le(data, at + 28)?;
            let name = data.get(at + ZIP_CENTRAL_HEADER_LEN..at + ZIP_CENTRAL_HEADER_LEN + name_len)?;
            Some((name.to_vec(), compressed, uncompressed))
        })
        .collect()
}

fn zip_entries(data: &[u8], limits: &Limits, bytes_left: &mut usize) -> Vec<Node> {
    let locals = positions(data, ZIP_LOCAL);
    if locals.is_empty() {
        return Vec::new();
    }
    let central = central_sizes(data);
    locals.into_iter().filter_map(|at| zip_entry(data, at, &central, limits, bytes_left)).collect()
}

fn zip_entry(data: &[u8], at: usize, central: &[(Vec<u8>, usize, usize)], limits: &Limits, bytes_left: &mut usize) -> Option<Node> {
    let cap = node_cap(limits, *bytes_left)?;
    let flags = u16le(data, at + 6)?;
    let method = u16le(data, at + 8)?;
    let mut compressed = u32le(data, at + 18)?;
    let mut uncompressed = u32le(data, at + 22)?;
    let name_len = u16le(data, at + 26)?;
    let extra_len = u16le(data, at + 28)?;
    let name_bytes = data.get(at + ZIP_LOCAL_HEADER_LEN..at + ZIP_LOCAL_HEADER_LEN + name_len)?;
    let name = String::from_utf8_lossy(name_bytes).into_owned();
    if name.is_empty() || name.ends_with('/') {
        return None; // Directories hold no data.
    }
    let data_start = at + ZIP_LOCAL_HEADER_LEN + name_len + extra_len;
    let has_descriptor = flags & 0x08 != 0;
    if has_descriptor
        && compressed == 0
        && let Some((_, c, u)) = central.iter().find(|(n, _, _)| n == name_bytes)
    {
        compressed = *c;
        uncompressed = *u;
    }
    let rest = data.get(data_start..)?;
    let (bytes, consumed, method_name, note) = match method {
        0 => {
            let len = if compressed > 0 { compressed } else { uncompressed };
            let stored = rest.get(..len.min(cap))?;
            (stored.to_vec(), stored.len(), None, None)
        }
        8 => {
            // Inflate tells us exactly where the deflate data ends, which also
            // covers descriptor entries the central directory did not list.
            let input = if compressed > 0 { rest.get(..compressed).unwrap_or(rest) } else { rest };
            let decoded = compress::decompress(Codec::Deflate, input, cap).ok()?;
            let note = decoded.truncated.then(|| "stopped: node size limit reached".to_string());
            (decoded.data, decoded.consumed, Some("deflate".to_string()), note)
        }
        other => {
            let raw = rest.get(..compressed.min(rest.len()).min(cap))?;
            (raw.to_vec(), raw.len(), None, Some(format!("unsupported compression method {other}")))
        }
    };
    Some(charge(Node {
        name,
        kind: "zip entry".to_string(),
        source_offset: at,
        source_len: data_start - at + consumed,
        data: Arc::new(bytes),
        children: Vec::new(),
        note,
        method: method_name,
    }, bytes_left))
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
}
