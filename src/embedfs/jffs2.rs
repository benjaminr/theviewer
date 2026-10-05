//! A JFFS2 reader (little-endian). JFFS2 has no tables: the image is a log of
//! nodes, each starting with the magic 0x1985. Directory entry nodes name an
//! inode inside a parent; inode nodes carry a piece of a file's data at an
//! offset. The newest version of each wins, so files are rebuilt by applying
//! their data nodes in version order.
//!
//! Data compressed with zlib, rtime, "zero" or none is decoded; rubin,
//! dynrubin, LZO and LZMA nodes are reported as unsupported.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use super::{Allowance, Entry, EntryKind, Filesystem, FsKind, MAX_DIRECTORY_DEPTH, join_path, le_u16, le_u32, slice_at, take_content};
use crate::compress::{self, Codec};

/// 0x1985, little-endian.
pub(super) const MAGIC: &[u8] = &[0x85, 0x19];
const MAGIC_VALUE: u16 = 0x1985;
const COMMON_HEADER_LEN: usize = 12;
const DIRENT_HEADER_LEN: usize = 40;
const INODE_HEADER_LEN: usize = 68;
/// Nodes are padded to 4-byte boundaries.
const NODE_ALIGNMENT: usize = 4;
/// Node type values, with the "accurate" bit set (cleared means obsolete).
const NODE_DIRENT: u16 = 0xE001;
const NODE_INODE: u16 = 0xE002;
const NODE_CLEANMARKER: u16 = 0x2003;
const NODE_PADDING: u16 = 0x2004;
const NODE_SUMMARY: u16 = 0x2006;
const NODE_XATTR: u16 = 0xE008;
const NODE_XREF: u16 = 0xE009;
const KNOWN_NODE_TYPES: [u16; 7] = [NODE_DIRENT, NODE_INODE, NODE_CLEANMARKER, NODE_PADDING, NODE_SUMMARY, NODE_XATTR, NODE_XREF];
/// The inode number of the root directory.
const ROOT_INODE: u32 = 1;
/// Most nodes read from one image.
const MAX_NODES: usize = 500_000;
/// Stop walking after this many bytes without a valid node (larger than any
/// common erase block, so erased blocks inside the image are crossed).
const MAX_GAP: usize = 256 * 1024;
/// Largest node accepted (a 4 KiB page of data plus headers, generously).
const MAX_NODE_LEN: usize = 64 * 1024;
/// Directory entry types (as in `dirent.d_type`).
const DT_DIRECTORY: u8 = 4;
const DT_SYMLINK: u8 = 10;

/// JFFS2 data compressors.
mod compressor {
    pub const NONE: u8 = 0;
    pub const ZERO: u8 = 1;
    pub const RTIME: u8 = 2;
    pub const RUBIN_MIPS: u8 = 3;
    pub const COPY: u8 = 4;
    pub const DYNRUBIN: u8 = 5;
    pub const ZLIB: u8 = 6;
    pub const LZO: u8 = 7;
    pub const LZMA: u8 = 8;
}

fn compressor_label(id: u8) -> &'static str {
    match id {
        compressor::NONE | compressor::COPY => "none",
        compressor::ZERO => "zero",
        compressor::RTIME => "rtime",
        compressor::RUBIN_MIPS => "rubin",
        compressor::DYNRUBIN => "dynrubin",
        compressor::ZLIB => "zlib",
        compressor::LZO => "lzo",
        compressor::LZMA => "lzma",
        _ => "unknown",
    }
}

/// JFFS2's CRC-32: the reflected 0xEDB88320 polynomial with a zero seed and
/// no final inversion (Linux `crc32(0, …)`), which is the bitwise complement
/// of a standard CRC-32 seeded with all ones.
pub(crate) fn jffs2_crc(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new_with_initial(u32::MAX);
    hasher.update(bytes);
    !hasher.finalize()
}

/// A node header at `at` with a valid magic, known type and header CRC;
/// returns its type and total length.
fn node_header(image: &[u8], at: usize) -> Option<(u16, usize)> {
    if le_u16(image, at)? != MAGIC_VALUE {
        return None;
    }
    let node_type = le_u16(image, at + 2)?;
    let total_len = le_u32(image, at + 4)? as usize;
    let stored_crc = le_u32(image, at + 8)?;
    if jffs2_crc(slice_at(image, at, 8)?) != stored_crc {
        return None;
    }
    let known = KNOWN_NODE_TYPES.iter().any(|&known| known == node_type || known & !ACCURATE_BIT == node_type);
    (known && (COMMON_HEADER_LEN..=MAX_NODE_LEN).contains(&total_len)).then_some((node_type, total_len))
}

/// Cleared in a node's type when the node has been made obsolete.
const ACCURATE_BIT: u16 = 0x2000;

/// A directory entry: `name` in directory `parent` is inode `inode`.
#[derive(Clone, Debug)]
struct Dirent {
    parent: u32,
    version: u32,
    /// Zero when the entry records a deletion.
    inode: u32,
    entry_type: u8,
    name: String,
    at: usize,
}

/// One piece of a file's data.
#[derive(Clone, Debug)]
struct DataNode {
    version: u32,
    inode_size: u32,
    offset: u32,
    compressed_len: u32,
    decompressed_len: u32,
    compressor: u8,
    data_at: usize,
    at: usize,
}

fn parse_dirent(image: &[u8], at: usize) -> Option<Dirent> {
    let name_len = *image.get(at + 28)? as usize;
    let raw_name = slice_at(image, at + DIRENT_HEADER_LEN, name_len)?;
    Some(Dirent {
        parent: le_u32(image, at + 12)?,
        version: le_u32(image, at + 16)?,
        inode: le_u32(image, at + 20)?,
        entry_type: *image.get(at + 29)?,
        name: super::clean_name(raw_name)?,
        at,
    })
}

fn parse_data_node(image: &[u8], at: usize, total_len: usize) -> Option<(u32, DataNode)> {
    let node = DataNode {
        version: le_u32(image, at + 16)?,
        inode_size: le_u32(image, at + 28)?,
        offset: le_u32(image, at + 44)?,
        compressed_len: le_u32(image, at + 48)?,
        decompressed_len: le_u32(image, at + 52)?,
        compressor: *image.get(at + 56)?,
        data_at: at + INODE_HEADER_LEN,
        at,
    };
    let fits = INODE_HEADER_LEN.checked_add(node.compressed_len as usize).is_some_and(|end| end <= total_len);
    fits.then(|| (le_u32(image, at + 12).unwrap_or(0), node))
}

/// Every live node in the image, grouped, and where the image ends.
#[derive(Default)]
struct NodeLog {
    dirents: Vec<Dirent>,
    data: HashMap<u32, Vec<DataNode>>,
    end: usize,
    node_count: usize,
}

/// Walk the node log from the start of `image`.
fn collect_nodes(image: &[u8]) -> NodeLog {
    let mut log = NodeLog::default();
    let mut at = 0;
    let mut last_node_end = 0;
    while at + COMMON_HEADER_LEN <= image.len() && log.node_count < MAX_NODES {
        let Some((node_type, total_len)) = node_header(image, at) else {
            if at - last_node_end > MAX_GAP {
                break;
            }
            at += NODE_ALIGNMENT;
            continue;
        };
        log.node_count += 1;
        match node_type {
            NODE_DIRENT => log.dirents.extend(parse_dirent(image, at)),
            NODE_INODE => {
                if let Some((inode, node)) = parse_data_node(image, at, total_len) {
                    log.data.entry(inode).or_default().push(node);
                }
            }
            _ => {} // Obsolete, padding, clean markers, summaries, attributes.
        }
        last_node_end = (at + total_len).min(image.len());
        at += total_len.next_multiple_of(NODE_ALIGNMENT);
    }
    log.end = last_node_end;
    log
}

/// Read the JFFS2 image at the start of `image` (at `base` in the scanned
/// data).
pub(super) fn read(image: &[u8], base: usize, allowance: &mut Allowance) -> Result<Filesystem, String> {
    if node_header(image, 0).is_none() {
        return Err("not a JFFS2 node".to_string());
    }
    let log = collect_nodes(image);
    if log.dirents.is_empty() && log.data.is_empty() {
        return Err("no directory or inode nodes".to_string());
    }
    let mut builder = TreeBuilder { image, base, log: &log, entries: Vec::new(), max_entries: allowance.max_entries(), problems: Vec::new(), visited: HashSet::new() };
    let children = builder.live_children();
    builder.walk(&children, ROOT_INODE, "", 0, allowance);
    let description = format!("JFFS2, {} nodes, {} KiB", log.node_count, log.end / 1024);
    let note = (!builder.problems.is_empty()).then(|| builder.problems.join("; "));
    Ok(Filesystem { kind: FsKind::Jffs2, offset: base, len: log.end, description, entries: builder.entries, note })
}

struct TreeBuilder<'a> {
    image: &'a [u8],
    base: usize,
    log: &'a NodeLog,
    entries: Vec<Entry>,
    max_entries: usize,
    problems: Vec<String>,
    visited: HashSet<u32>,
}

impl TreeBuilder<'_> {
    /// The newest entry for each (parent, name), without deletions, grouped
    /// by parent and sorted by name.
    fn live_children(&self) -> HashMap<u32, Vec<Dirent>> {
        let mut newest: BTreeMap<(u32, String), &Dirent> = BTreeMap::new();
        for dirent in &self.log.dirents {
            let key = (dirent.parent, dirent.name.clone());
            if newest.get(&key).is_none_or(|existing| existing.version < dirent.version) {
                newest.insert(key, dirent);
            }
        }
        let mut children: HashMap<u32, Vec<Dirent>> = HashMap::new();
        for dirent in newest.into_values().filter(|dirent| dirent.inode != 0) {
            children.entry(dirent.parent).or_default().push(dirent.clone());
        }
        children
    }

    fn walk(&mut self, children: &HashMap<u32, Vec<Dirent>>, directory: u32, path: &str, depth: usize, allowance: &mut Allowance) {
        if depth > MAX_DIRECTORY_DEPTH || !self.visited.insert(directory) {
            return;
        }
        for dirent in children.get(&directory).map(Vec::as_slice).unwrap_or_default() {
            if self.entries.len() >= self.max_entries {
                self.problems.push(format!("stopped after {} entries", self.max_entries));
                return;
            }
            let child_path = join_path(path, &dirent.name);
            if dirent.entry_type == DT_DIRECTORY {
                self.entries.push(Entry::directory(child_path.clone(), self.base + dirent.at));
                self.walk(children, dirent.inode, &child_path, depth + 1, allowance);
            } else {
                let kind = if dirent.entry_type == DT_SYMLINK { EntryKind::Symlink } else { EntryKind::File };
                let entry = self.rebuild_file(child_path, dirent.inode, kind, allowance);
                self.entries.push(entry);
            }
        }
    }

    /// Rebuild an inode's content by applying its data nodes oldest first.
    fn rebuild_file(&mut self, path: String, inode: u32, kind: EntryKind, allowance: &mut Allowance) -> Entry {
        let mut nodes: Vec<&DataNode> = self.log.data.get(&inode).map(|nodes| nodes.iter().collect()).unwrap_or_default();
        nodes.sort_by_key(|node| node.version);
        let declared = nodes.last().map_or(0, |node| node.inode_size as usize);
        let cap = allowance.cap().unwrap_or(0);
        let wanted = declared.min(cap);
        let mut content = vec![0u8; 0];
        let mut unsupported = HashSet::new();
        let mut damaged = 0;
        for node in &nodes {
            match self.decode(node) {
                Ok(piece) => apply_piece(&mut content, node.offset as usize, &piece, wanted),
                Err(DecodeError::Unsupported(name)) => {
                    unsupported.insert(name);
                }
                Err(DecodeError::Damaged) => damaged += 1,
            }
        }
        content.resize(wanted, 0);
        let mut problem = Vec::new();
        if !unsupported.is_empty() {
            let mut names: Vec<&str> = unsupported.into_iter().collect();
            names.sort_unstable();
            problem.push(format!("unsupported compression: {}", names.join(", ")));
        }
        if damaged > 0 {
            problem.push(format!("{damaged} damaged data nodes skipped"));
        }
        let methods: HashSet<&str> = nodes.iter().map(|node| compressor_label(node.compressor)).filter(|&label| label != "none").collect();
        let mut method: Vec<&str> = methods.into_iter().collect();
        method.sort_unstable();
        let (data, limit_note) = take_content(content, declared as u64, allowance);
        let first_at = nodes.iter().map(|node| node.at).min().unwrap_or(0);
        let last_end = nodes.iter().map(|node| node.data_at + node.compressed_len as usize).max().unwrap_or(first_at);
        Entry {
            path,
            kind,
            declared_size: declared as u64,
            data: Arc::new(data),
            source_offset: self.base + first_at,
            source_len: last_end.saturating_sub(first_at),
            method: (!method.is_empty()).then(|| method.join("+")),
            note: if problem.is_empty() { limit_note } else { Some(problem.join("; ")) },
        }
    }

    fn decode(&self, node: &DataNode) -> Result<Vec<u8>, DecodeError> {
        let output_len = node.decompressed_len as usize;
        if output_len > MAX_NODE_LEN {
            return Err(DecodeError::Damaged);
        }
        let input = slice_at(self.image, node.data_at, node.compressed_len as usize).ok_or(DecodeError::Damaged)?;
        match node.compressor {
            compressor::NONE | compressor::COPY => Ok(input[..output_len.min(input.len())].to_vec()),
            compressor::ZERO => Ok(vec![0; output_len]),
            compressor::ZLIB => compress::decompress(Codec::Zlib, input, output_len).map(|decoded| decoded.data).map_err(|_| DecodeError::Damaged),
            compressor::RTIME => Ok(rtime_decompress(input, output_len)),
            other => Err(DecodeError::Unsupported(compressor_label(other))),
        }
    }
}

enum DecodeError {
    Unsupported(&'static str),
    Damaged,
}

/// Write `piece` at `offset` into `content`, never past `limit` bytes.
fn apply_piece(content: &mut Vec<u8>, offset: usize, piece: &[u8], limit: usize) {
    if offset >= limit {
        return;
    }
    let end = offset.saturating_add(piece.len()).min(limit);
    if content.len() < end {
        content.resize(end, 0);
    }
    content[offset..end].copy_from_slice(&piece[..end - offset]);
}

/// JFFS2's "rtime" compressor: each literal byte is followed by a repeat
/// count copying from just after where that byte value last appeared.
fn rtime_decompress(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_len);
    let mut last_position = [0usize; 256];
    let mut pairs = input.as_chunks::<2>().0.iter();
    while output.len() < output_len {
        let Some(&[value, repeat]) = pairs.next() else { break };
        output.push(value);
        let start = last_position[value as usize];
        last_position[value as usize] = output.len();
        for source in start..start + repeat as usize {
            if output.len() >= output_len || source >= output.len() {
                break;
            }
            output.push(output[source]);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unpack::Limits;

    /// The Linux bitwise CRC-32 with a zero seed, to check [`jffs2_crc`].
    fn reference_crc(bytes: &[u8]) -> u32 {
        let mut crc = 0u32;
        for &byte in bytes {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
        crc
    }

    fn finish_node(mut node: Vec<u8>, node_type: u16) -> Vec<u8> {
        let total = node.len() as u32;
        node[0..2].copy_from_slice(&MAGIC_VALUE.to_le_bytes());
        node[2..4].copy_from_slice(&node_type.to_le_bytes());
        node[4..8].copy_from_slice(&total.to_le_bytes());
        let crc = jffs2_crc(&node[..8]);
        node[8..12].copy_from_slice(&crc.to_le_bytes());
        node.resize(node.len().next_multiple_of(NODE_ALIGNMENT), 0xFF);
        node
    }

    fn dirent(parent: u32, inode: u32, version: u32, name: &str, entry_type: u8) -> Vec<u8> {
        let mut node = vec![0u8; DIRENT_HEADER_LEN];
        node[12..16].copy_from_slice(&parent.to_le_bytes());
        node[16..20].copy_from_slice(&version.to_le_bytes());
        node[20..24].copy_from_slice(&inode.to_le_bytes());
        node[28] = name.len() as u8;
        node[29] = entry_type;
        node.extend_from_slice(name.as_bytes());
        finish_node(node, NODE_DIRENT)
    }

    fn data_node(inode: u32, version: u32, file_size: u32, offset: u32, content: &[u8], compressor_id: u8) -> Vec<u8> {
        let payload = match compressor_id {
            compressor::ZLIB => compress::compress(Codec::Zlib, content).unwrap(),
            _ => content.to_vec(),
        };
        let mut node = vec![0u8; INODE_HEADER_LEN];
        node[12..16].copy_from_slice(&inode.to_le_bytes());
        node[16..20].copy_from_slice(&version.to_le_bytes());
        node[28..32].copy_from_slice(&file_size.to_le_bytes());
        node[44..48].copy_from_slice(&offset.to_le_bytes());
        node[48..52].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        node[52..56].copy_from_slice(&(content.len() as u32).to_le_bytes());
        node[56] = compressor_id;
        node.extend_from_slice(&payload);
        finish_node(node, NODE_INODE)
    }

    fn sample_image() -> Vec<u8> {
        let mut image = Vec::new();
        image.extend(finish_node(vec![0u8; COMMON_HEADER_LEN], NODE_CLEANMARKER));
        image.extend(dirent(ROOT_INODE, 2, 1, "etc", DT_DIRECTORY));
        image.extend(dirent(2, 3, 2, "hostname", 8));
        image.extend(data_node(3, 1, 9, 0, b"old-name\n", compressor::NONE));
        // A newer version rewrites the file in two zlib pieces.
        image.extend(data_node(3, 2, 12, 0, b"router", compressor::ZLIB));
        image.extend(data_node(3, 3, 12, 6, b"-one\n\n", compressor::ZLIB));
        image.extend(dirent(ROOT_INODE, 4, 3, "deleted.txt", 8));
        image.extend(dirent(ROOT_INODE, 0, 4, "deleted.txt", 8));
        image.extend(dirent(ROOT_INODE, 5, 5, "packed.bin", 8));
        image.extend(data_node(5, 1, 4, 0, b"abcd", compressor::LZO));
        image.extend(vec![0xFF; 4096]); // Erased space.
        image
    }

    #[test]
    fn crc_matches_the_linux_definition() {
        for sample in [&b""[..], b"123456789", &[0x85, 0x19, 0x01, 0xE0, 0x2C, 0, 0, 0]] {
            assert_eq!(jffs2_crc(sample), reference_crc(sample));
        }
    }

    #[test]
    fn files_are_rebuilt_from_their_newest_nodes_and_deletions_are_honoured() {
        let image = sample_image();
        let mut left = usize::MAX;
        let filesystem = read(&image, 0, &mut Allowance::new(&Limits::default(), &mut left)).unwrap();
        let paths: Vec<&str> = filesystem.entries.iter().map(|entry| entry.path.as_str()).collect();
        assert_eq!(paths, ["etc", "etc/hostname", "packed.bin"]);
        let hostname = &filesystem.entries[1];
        assert_eq!(hostname.data.as_slice(), b"router-one\n\n");
        assert_eq!(hostname.method.as_deref(), Some("zlib"));
        let packed = &filesystem.entries[2];
        assert_eq!(packed.note.as_deref(), Some("unsupported compression: lzo"));
        assert_eq!(filesystem.len, image.len() - 4096, "the image ends at its last node");
    }

    #[test]
    fn rtime_round_trips_a_repeating_sequence() {
        // "ab" then "ab" again: 'a' (repeat 0), 'b' (repeat 0), 'a' (repeat 1 copies 'b').
        let decoded = rtime_decompress(&[b'a', 0, b'b', 0, b'a', 1], 4);
        assert_eq!(decoded, b"abab");
        // Back-references start at position 0, so a first repeat copies the byte itself.
        assert_eq!(rtime_decompress(&[b'x', 255], 10), b"xxxxxxxxxx");
        assert!(rtime_decompress(b"x", 10).is_empty(), "a lone literal without its count is ignored");
        assert_eq!(rtime_decompress(&[b'x', 0, b'x', 200], 5), b"xxxxx");
    }

    #[test]
    fn damaged_logs_do_not_panic_and_noise_is_not_jffs2() {
        let image = sample_image();
        let noise = super::super::test_support::noise(image.len(), 11);
        for step in 2..30 {
            let mut damaged = image.clone();
            for index in (COMMON_HEADER_LEN..damaged.len()).step_by(step) {
                damaged[index] ^= noise[index];
            }
            let mut left = 1 << 20;
            let _ = read(&damaged, 0, &mut Allowance::new(&Limits::default(), &mut left));
        }
        let mut left = usize::MAX;
        assert!(read(&noise, 0, &mut Allowance::new(&Limits::default(), &mut left)).is_err());
    }
}
