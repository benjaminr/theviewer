//! A minimal SquashFS 4.0 (little-endian) reader: superblock, inode table,
//! directory table and fragment table; regular files, directories, symlinks
//! and special files. Extended attributes, the export table and the ID table
//! are not needed for listing and are ignored.

use std::collections::HashSet;
use std::sync::Arc;

use super::{Allowance, Entry, EntryKind, EntryRecord, Filesystem, FsKind, MAX_DIRECTORY_DEPTH, join_path, le_u16, le_u32, le_u64, slice_at, take_content};
use crate::compress::{self, Codec};

pub(super) const MAGIC: &[u8] = b"hsqs";
const SUPERBLOCK_LEN: usize = 96;
const SUPPORTED_MAJOR: u16 = 4;
/// Smallest and largest block sizes the format allows (4 KiB to 1 MiB).
const MIN_BLOCK_LOG: u16 = 12;
const MAX_BLOCK_LOG: u16 = 20;
/// Uncompressed size of a full metadata block.
const METADATA_BLOCK_LEN: usize = 8192;
/// Metadata block header bit: the block is stored uncompressed.
const METADATA_UNCOMPRESSED: u16 = 0x8000;
const METADATA_SIZE_MASK: u16 = 0x7FFF;
/// Data block size bit: the block is stored uncompressed.
const DATA_UNCOMPRESSED: u32 = 1 << 24;
const DATA_SIZE_MASK: u32 = DATA_UNCOMPRESSED - 1;
/// Fragment index meaning "this file has no tail fragment".
const NO_FRAGMENT: u32 = 0xFFFF_FFFF;
/// Table start meaning "this table is absent".
const ABSENT_TABLE: u64 = u64::MAX;
const FRAGMENT_ENTRY_LEN: usize = 16;
/// Most decompressed metadata (inodes or directories) held for one image.
const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;
/// Most fragment entries read.
const MAX_FRAGMENTS: u32 = 1 << 20;
/// Directory listings: at most 256 entries per header, 256-byte names.
const MAX_DIRECTORY_RUN: u32 = 256;
const DIRECTORY_HEADER_LEN: usize = 12;
const DIRECTORY_ENTRY_LEN: usize = 8;
/// A directory's recorded size includes 3 bytes for "." and "..".
const DIRECTORY_SIZE_BIAS: u32 = 3;

/// Inode type numbers.
mod inode_type {
    pub const DIRECTORY: u16 = 1;
    pub const FILE: u16 = 2;
    pub const SYMLINK: u16 = 3;
    pub const LAST_BASIC_SPECIAL: u16 = 7;
    pub const EXTENDED_DIRECTORY: u16 = 8;
    pub const EXTENDED_FILE: u16 = 9;
    pub const EXTENDED_SYMLINK: u16 = 10;
    pub const LAST_EXTENDED_SPECIAL: u16 = 14;
}
/// Every inode starts with type, mode, uid, gid, mtime and inode number.
const INODE_HEADER_LEN: usize = 16;

/// The compressors a SquashFS image can declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Compression {
    Gzip,
    Lzma,
    Lzo,
    Xz,
    Lz4,
    Zstd,
}

impl Compression {
    fn from_id(id: u16) -> Option<Compression> {
        Some(match id {
            1 => Compression::Gzip,
            2 => Compression::Lzma,
            3 => Compression::Lzo,
            4 => Compression::Xz,
            5 => Compression::Lz4,
            6 => Compression::Zstd,
            _ => return None,
        })
    }

    fn label(self) -> &'static str {
        match self {
            Compression::Gzip => "gzip",
            Compression::Lzma => "lzma",
            Compression::Lzo => "lzo",
            Compression::Xz => "xz",
            Compression::Lz4 => "lz4",
            Compression::Zstd => "zstd",
        }
    }

    /// Decompress one block into at most `max_out` bytes.
    fn decompress(self, input: &[u8], max_out: usize) -> Result<Vec<u8>, String> {
        let codec = match self {
            // SquashFS "gzip" blocks are zlib streams.
            Compression::Gzip => Codec::Zlib,
            Compression::Lzma => Codec::Lzma,
            Compression::Xz => Codec::Xz,
            Compression::Zstd => Codec::Zstd,
            // Raw LZ4 blocks, not frames; the output buffer is `max_out`
            // (at most one 1 MiB block).
            Compression::Lz4 => return lz4_flex::block::decompress(input, max_out).map_err(|error| format!("lz4 block: {error}")),
            Compression::Lzo => return Err("LZO compression is not supported".to_string()),
        };
        compress::decompress(codec, input, max_out).map(|decoded| decoded.data).map_err(|error| format!("{} block: {error}", self.label()))
    }
}

/// The fields of the superblock this reader uses.
#[derive(Clone, Debug)]
struct Superblock {
    inode_count: u32,
    block_size: u32,
    fragment_count: u32,
    compression: Compression,
    version: (u16, u16),
    root_inode: u64,
    bytes_used: u64,
    inode_table: u64,
    directory_table: u64,
    fragment_table: u64,
    other_tables: [u64; 3],
}

fn parse_superblock(image: &[u8]) -> Result<Superblock, String> {
    let field16 = |at| le_u16(image, at).ok_or("superblock is truncated");
    let field32 = |at| le_u32(image, at).ok_or("superblock is truncated");
    let field64 = |at| le_u64(image, at).ok_or("superblock is truncated");
    if image.get(..MAGIC.len()) != Some(MAGIC) || image.len() < SUPERBLOCK_LEN {
        return Err("not a SquashFS superblock".to_string());
    }
    let version = (field16(28)?, field16(30)?);
    if version.0 != SUPPORTED_MAJOR {
        return Err(format!("SquashFS version {}.{} is not supported", version.0, version.1));
    }
    let block_size = field32(12)?;
    let block_log = field16(22)?;
    if !(MIN_BLOCK_LOG..=MAX_BLOCK_LOG).contains(&block_log) || block_size != 1 << block_log {
        return Err(format!("implausible block size {block_size} (log {block_log})"));
    }
    let compression_id = field16(20)?;
    let compression = Compression::from_id(compression_id).ok_or(format!("unknown compression id {compression_id}"))?;
    let superblock = Superblock {
        inode_count: field32(4)?,
        block_size,
        fragment_count: field32(16)?,
        compression,
        version,
        root_inode: field64(32)?,
        bytes_used: field64(40)?,
        inode_table: field64(64)?,
        directory_table: field64(72)?,
        fragment_table: field64(80)?,
        other_tables: [field64(48)?, field64(56)?, field64(88)?],
    };
    let ordered = SUPERBLOCK_LEN as u64 <= superblock.inode_table
        && superblock.inode_table < superblock.directory_table
        && superblock.directory_table < superblock.bytes_used;
    if !ordered {
        return Err("table offsets are out of order".to_string());
    }
    Ok(superblock)
}

/// A metadata table decompressed into one buffer, with where each on-disk
/// block landed so that inode and directory references can be resolved.
#[derive(Default)]
struct MetadataTable {
    bytes: Vec<u8>,
    /// (block offset from the table start, position in `bytes`), ascending.
    blocks: Vec<(u64, usize)>,
}

impl MetadataTable {
    /// Position in `bytes` of `offset` within the block starting `block`
    /// bytes after the table start.
    fn position(&self, block: u64, offset: usize) -> Option<usize> {
        let index = self.blocks.binary_search_by_key(&block, |&(start, _)| start).ok()?;
        let position = self.blocks[index].1.checked_add(offset)?;
        (position < self.bytes.len()).then_some(position)
    }
}

/// Decode one metadata block at `at`; returns its bytes and on-disk length.
fn read_metadata_block(image: &[u8], at: usize, compression: Compression) -> Result<(Vec<u8>, usize), String> {
    let header = le_u16(image, at).ok_or("metadata block header is beyond the image")?;
    let stored = (header & METADATA_SIZE_MASK) as usize;
    if stored == 0 || stored > METADATA_BLOCK_LEN {
        return Err(format!("metadata block at {at:#x} has implausible size {stored}"));
    }
    let payload = slice_at(image, at + 2, stored).ok_or("metadata block runs past the image")?;
    let bytes = if header & METADATA_UNCOMPRESSED != 0 { payload.to_vec() } else { compression.decompress(payload, METADATA_BLOCK_LEN)? };
    Ok((bytes, 2 + stored))
}

/// Decode consecutive metadata blocks in `start..end`. Stops at the first
/// bad block, returning what was read and why it stopped.
fn read_metadata_table(image: &[u8], start: usize, end: usize, compression: Compression) -> (MetadataTable, Option<String>) {
    let mut table = MetadataTable::default();
    let mut at = start;
    while at + 2 <= end.min(image.len()) {
        if table.bytes.len() >= MAX_METADATA_BYTES {
            return (table, Some("metadata table is larger than the reader allows".to_string()));
        }
        match read_metadata_block(image, at, compression) {
            Ok((bytes, consumed)) => {
                table.blocks.push(((at - start) as u64, table.bytes.len()));
                table.bytes.extend_from_slice(&bytes);
                at += consumed;
            }
            Err(error) => return (table, Some(error)),
        }
    }
    (table, None)
}

#[derive(Clone, Copy, Debug)]
struct FragmentEntry {
    start: u64,
    size: u32,
}

/// The fragment table: a list of pointers to metadata blocks of entries.
fn read_fragment_table(image: &[u8], superblock: &Superblock) -> Result<Vec<FragmentEntry>, String> {
    if superblock.fragment_count == 0 || superblock.fragment_table == ABSENT_TABLE {
        return Ok(Vec::new());
    }
    let count = superblock.fragment_count.min(MAX_FRAGMENTS) as usize;
    let entries_per_block = METADATA_BLOCK_LEN / FRAGMENT_ENTRY_LEN;
    let lookup_at = usize::try_from(superblock.fragment_table).map_err(|_| "fragment table is beyond the image")?;
    let mut fragments = Vec::new();
    for block_index in 0..count.div_ceil(entries_per_block) {
        let pointer = le_u64(image, lookup_at + block_index * 8).ok_or("fragment table is beyond the image")?;
        let pointer = usize::try_from(pointer).map_err(|_| "fragment block is beyond the image")?;
        let (bytes, _) = read_metadata_block(image, pointer, superblock.compression)?;
        for chunk in bytes.as_chunks::<FRAGMENT_ENTRY_LEN>().0 {
            if fragments.len() >= count {
                break;
            }
            fragments.push(FragmentEntry { start: le_u64(chunk, 0).unwrap_or(0), size: le_u32(chunk, 8).unwrap_or(0) });
        }
    }
    Ok(fragments)
}

/// What a parsed inode describes.
#[derive(Clone, Debug)]
enum Inode {
    Directory { start_block: u32, offset: u16, listing_len: usize },
    File(FileInode),
    Symlink { target: Vec<u8> },
    Special,
}

#[derive(Clone, Debug)]
struct FileInode {
    blocks_start: u64,
    fragment: u32,
    fragment_offset: u32,
    size: u64,
    /// Position of the block size list in the inode table.
    block_list_at: usize,
    block_count: usize,
}

/// Parse the inode at `at` in the decompressed inode table.
fn parse_inode(table: &[u8], at: usize, block_size: u32) -> Result<Inode, String> {
    let truncated = || format!("inode at {at:#x} is truncated");
    let kind = le_u16(table, at).ok_or_else(truncated)?;
    let body = at + INODE_HEADER_LEN;
    let field16 = |offset: usize| le_u16(table, body + offset).ok_or_else(truncated);
    let field32 = |offset: usize| le_u32(table, body + offset).ok_or_else(truncated);
    let field64 = |offset: usize| le_u64(table, body + offset).ok_or_else(truncated);
    match kind {
        inode_type::DIRECTORY => Ok(Inode::Directory {
            start_block: field32(0)?,
            offset: field16(10)?,
            listing_len: (field16(8)? as u32).saturating_sub(DIRECTORY_SIZE_BIAS) as usize,
        }),
        inode_type::EXTENDED_DIRECTORY => Ok(Inode::Directory {
            start_block: field32(8)?,
            offset: field16(18)?,
            listing_len: field32(4)?.saturating_sub(DIRECTORY_SIZE_BIAS) as usize,
        }),
        inode_type::FILE => {
            let (blocks_start, fragment, fragment_offset, size) = (field32(0)? as u64, field32(4)?, field32(8)?, field32(12)? as u64);
            file_inode(table, blocks_start, fragment, fragment_offset, size, body + 16, block_size)
        }
        inode_type::EXTENDED_FILE => {
            let (blocks_start, size, fragment, fragment_offset) = (field64(0)?, field64(8)?, field32(28)?, field32(32)?);
            file_inode(table, blocks_start, fragment, fragment_offset, size, body + 40, block_size)
        }
        inode_type::SYMLINK | inode_type::EXTENDED_SYMLINK => {
            let target_len = field32(4)? as usize;
            let target = slice_at(table, body + 8, target_len).ok_or_else(truncated)?;
            Ok(Inode::Symlink { target: target.to_vec() })
        }
        kind if kind <= inode_type::LAST_BASIC_SPECIAL || (inode_type::EXTENDED_SYMLINK..=inode_type::LAST_EXTENDED_SPECIAL).contains(&kind) => Ok(Inode::Special),
        other => Err(format!("unknown inode type {other} at {at:#x}")),
    }
}

fn file_inode(table: &[u8], blocks_start: u64, fragment: u32, fragment_offset: u32, size: u64, block_list_at: usize, block_size: u32) -> Result<Inode, String> {
    let block_size = block_size as u64;
    let block_count = if fragment == NO_FRAGMENT { size.div_ceil(block_size) } else { size / block_size };
    // Every block needs a 4-byte size in the table, which bounds the count.
    let available = (table.len().saturating_sub(block_list_at) / 4) as u64;
    if block_count > available {
        return Err(format!("file inode lists {block_count} blocks but the inode table holds at most {available}"));
    }
    Ok(Inode::File(FileInode { blocks_start, fragment, fragment_offset, size, block_list_at, block_count: block_count as usize }))
}

/// One name in a directory listing and the inode it refers to.
struct DirectoryEntry {
    name: String,
    inode_block: u64,
    inode_offset: usize,
}

/// Read a directory listing of `len` bytes from `at` in the directory table.
fn read_listing(table: &[u8], at: usize, len: usize) -> Result<Vec<DirectoryEntry>, String> {
    let end = at.saturating_add(len).min(table.len());
    let mut entries = Vec::new();
    let mut cursor = at;
    while cursor + DIRECTORY_HEADER_LEN <= end {
        let count = le_u32(table, cursor).unwrap_or(0) + 1;
        let inode_block = le_u32(table, cursor + 4).unwrap_or(0) as u64;
        if count > MAX_DIRECTORY_RUN {
            return Err(format!("directory header at {cursor:#x} claims {count} entries"));
        }
        cursor += DIRECTORY_HEADER_LEN;
        for _ in 0..count {
            let truncated = || format!("directory entry at {cursor:#x} is truncated");
            let inode_offset = le_u16(table, cursor).ok_or_else(truncated)? as usize;
            let name_len = le_u16(table, cursor + 6).ok_or_else(truncated)? as usize + 1;
            let raw_name = slice_at(table, cursor + DIRECTORY_ENTRY_LEN, name_len).ok_or_else(truncated)?;
            cursor += DIRECTORY_ENTRY_LEN + name_len;
            if let Some(name) = super::clean_name(raw_name) {
                entries.push(DirectoryEntry { name, inode_block, inode_offset });
            }
        }
    }
    Ok(entries)
}

/// Everything needed to walk one image.
struct Reader<'a> {
    image: &'a [u8],
    base: usize,
    superblock: Superblock,
    inodes: MetadataTable,
    directories: MetadataTable,
    fragments: Vec<FragmentEntry>,
    /// The most recently decoded fragment block, as files sharing a fragment
    /// are usually listed together.
    fragment_cache: Option<(u32, Vec<u8>)>,
    entries: Vec<Entry>,
    max_entries: usize,
    visited: HashSet<usize>,
    problems: Vec<String>,
}

/// Read the SquashFS image at the start of `image` (at `base` in the scanned
/// data).
pub(super) fn read(image: &[u8], base: usize, allowance: &mut Allowance) -> Result<Filesystem, String> {
    let superblock = parse_superblock(image)?;
    let len = usize::try_from(superblock.bytes_used).unwrap_or(usize::MAX).min(image.len());
    let image = &image[..len];
    let mut problems = Vec::new();
    if (len as u64) < superblock.bytes_used {
        problems.push(format!("image is truncated: {} of {} bytes present", len, superblock.bytes_used));
    }
    let inode_start = superblock.inode_table as usize;
    let directory_start = superblock.directory_table as usize;
    let directory_end = superblock
        .other_tables
        .iter()
        .chain([&superblock.fragment_table])
        .filter(|&&table| table > superblock.directory_table && table != ABSENT_TABLE)
        .map(|&table| usize::try_from(table).unwrap_or(usize::MAX))
        .min()
        .unwrap_or(len);
    let (inodes, inode_problem) = read_metadata_table(image, inode_start, directory_start, superblock.compression);
    let (directories, directory_problem) = read_metadata_table(image, directory_start, directory_end, superblock.compression);
    if inodes.bytes.is_empty() {
        return Err(inode_problem.unwrap_or_else(|| "inode table is empty".to_string()));
    }
    problems.extend(inode_problem);
    problems.extend(directory_problem);
    let fragments = read_fragment_table(image, &superblock).unwrap_or_else(|error| {
        problems.push(error);
        Vec::new()
    });
    let mut reader = Reader {
        image,
        base,
        superblock,
        inodes,
        directories,
        fragments,
        fragment_cache: None,
        entries: Vec::new(),
        max_entries: allowance.max_entries(),
        visited: HashSet::new(),
        problems,
    };
    reader.walk_root(allowance)?;
    let superblock = &reader.superblock;
    let description = format!(
        "SquashFS {}.{}, {}, {} KiB blocks, {} inodes",
        superblock.version.0,
        superblock.version.1,
        superblock.compression.label(),
        superblock.block_size / 1024,
        superblock.inode_count
    );
    let note = (!reader.problems.is_empty()).then(|| reader.problems.join("; "));
    Ok(Filesystem { kind: FsKind::SquashFs, offset: base, len, description, entries: reader.entries, note })
}

impl Reader<'_> {
    /// Position of an inode reference (block offset in the high bits, offset
    /// within the block in the low 16).
    fn inode_position(&self, block: u64, offset: usize) -> Option<usize> {
        self.inodes.position(block, offset)
    }

    fn walk_root(&mut self, allowance: &mut Allowance) -> Result<(), String> {
        let root = self.superblock.root_inode;
        let position = self.inode_position(root >> 16, (root & 0xFFFF) as usize).ok_or("root inode reference is outside the inode table")?;
        match parse_inode(&self.inodes.bytes, position, self.superblock.block_size)? {
            Inode::Directory { start_block, offset, listing_len } => {
                self.visited.insert(position);
                self.walk_directory(start_block, offset, listing_len, "", 0, allowance);
                Ok(())
            }
            _ => Err("root inode is not a directory".to_string()),
        }
    }

    fn walk_directory(&mut self, start_block: u32, offset: u16, listing_len: usize, path: &str, depth: usize, allowance: &mut Allowance) {
        let Some(at) = self.directories.position(start_block as u64, offset as usize) else {
            if listing_len > 0 {
                self.problems.push(format!("listing of '{path}' is outside the directory table"));
            }
            return;
        };
        let listing = match read_listing(&self.directories.bytes, at, listing_len) {
            Ok(listing) => listing,
            Err(error) => {
                self.problems.push(error);
                return;
            }
        };
        for item in listing {
            if self.entries.len() >= self.max_entries {
                self.problems.push(format!("stopped after {} entries", self.max_entries));
                return;
            }
            self.visit(item, path, depth, allowance);
        }
    }

    fn visit(&mut self, item: DirectoryEntry, parent: &str, depth: usize, allowance: &mut Allowance) {
        let path = join_path(parent, &item.name);
        let Some(position) = self.inode_position(item.inode_block, item.inode_offset) else {
            self.problems.push(format!("inode of '{path}' is outside the inode table"));
            return;
        };
        let inode = match parse_inode(&self.inodes.bytes, position, self.superblock.block_size) {
            Ok(inode) => inode,
            Err(error) => {
                self.problems.push(format!("{path}: {error}"));
                return;
            }
        };
        match inode {
            Inode::Directory { start_block, offset, listing_len } => {
                self.entries.push(Entry::directory(path.clone(), self.base));
                if depth < MAX_DIRECTORY_DEPTH && self.visited.insert(position) {
                    self.walk_directory(start_block, offset, listing_len, &path, depth + 1, allowance);
                }
            }
            Inode::File(file) => {
                let entry = self.read_file(path, &file, allowance);
                self.entries.push(entry);
            }
            Inode::Symlink { target } => {
                let (data, note) = take_content(target, 0, allowance);
                self.entries.push(Entry { path, kind: EntryKind::Symlink, declared_size: data.len() as u64, data: Arc::new(data), source_offset: self.base, source_len: 0, method: None, note, record: EntryRecord::default() });
            }
            Inode::Special => {
                self.entries.push(Entry { path, kind: EntryKind::Special, declared_size: 0, data: Arc::new(Vec::new()), source_offset: self.base, source_len: 0, method: None, note: None, record: EntryRecord::default() });
            }
        }
    }

    /// Extract a regular file: its full blocks, then its tail fragment.
    fn read_file(&mut self, path: String, file: &FileInode, allowance: &mut Allowance) -> Entry {
        let block_size = self.superblock.block_size as usize;
        let cap = allowance.cap().unwrap_or(0);
        let wanted = usize::try_from(file.size).unwrap_or(usize::MAX).min(cap);
        let mut content = Vec::new();
        let mut problem = None;
        let mut compressed = false;
        let mut at = usize::try_from(file.blocks_start).unwrap_or(usize::MAX);
        let source_offset = at;
        for index in 0..file.block_count {
            if content.len() >= wanted {
                break;
            }
            let raw = le_u32(&self.inodes.bytes, file.block_list_at + index * 4).unwrap_or(0);
            let stored = (raw & DATA_SIZE_MASK) as usize;
            let expected = block_size.min(wanted - content.len());
            if stored == 0 {
                content.resize(content.len() + expected, 0); // A sparse block.
                continue;
            }
            let Some(input) = slice_at(self.image, at, stored) else {
                problem = Some(format!("data block {index} is beyond the image"));
                break;
            };
            at += stored;
            let block = if raw & DATA_UNCOMPRESSED != 0 {
                Ok(input.to_vec())
            } else {
                compressed = true;
                self.superblock.compression.decompress(input, block_size)
            };
            match block {
                Ok(block) => content.extend_from_slice(&block[..expected.min(block.len())]),
                Err(error) => {
                    problem = Some(error);
                    break;
                }
            }
        }
        if problem.is_none() && file.fragment != NO_FRAGMENT && content.len() < wanted {
            match self.fragment_bytes(file.fragment) {
                Ok(block) => {
                    let start = file.fragment_offset as usize;
                    let tail = wanted - content.len();
                    match slice_at(&block, start, tail) {
                        Some(bytes) => content.extend_from_slice(bytes),
                        None => problem = Some("tail runs past its fragment block".to_string()),
                    }
                }
                Err(error) => problem = Some(error),
            }
        }
        let (data, limit_note) = take_content(content, file.size, allowance);
        Entry {
            path,
            kind: EntryKind::File,
            declared_size: file.size,
            data: Arc::new(data),
            source_offset: self.base + source_offset.min(self.image.len()),
            source_len: at.saturating_sub(source_offset),
            method: compressed.then(|| self.superblock.compression.label().to_string()),
            note: problem.or(limit_note),
            record: EntryRecord::default(),
        }
    }

    /// The decompressed fragment block `index`, cached.
    fn fragment_bytes(&mut self, index: u32) -> Result<Vec<u8>, String> {
        if let Some((cached, bytes)) = &self.fragment_cache
            && *cached == index
        {
            return Ok(bytes.clone());
        }
        let fragment = *self.fragments.get(index as usize).ok_or(format!("fragment {index} is not in the fragment table"))?;
        let stored = (fragment.size & DATA_SIZE_MASK) as usize;
        let start = usize::try_from(fragment.start).map_err(|_| "fragment block is beyond the image")?;
        let input = slice_at(self.image, start, stored).ok_or(format!("fragment block {index} is beyond the image"))?;
        let bytes = if fragment.size & DATA_UNCOMPRESSED != 0 {
            input.to_vec()
        } else {
            self.superblock.compression.decompress(input, self.superblock.block_size as usize)?
        };
        self.fragment_cache = Some((index, bytes.clone()));
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unpack::Limits;

    const BLOCK_SIZE: u32 = 4096;

    /// Builds a tiny SquashFS 4.0 image by hand: superblock, data blocks, a
    /// fragment block, one inode metadata block, one directory metadata block
    /// and a fragment table. Metadata is stored uncompressed; data blocks are
    /// zlib ("gzip") compressed or stored, as the test chooses.
    struct ImageBuilder {
        image: Vec<u8>,
        inodes: Vec<u8>,
        directories: Vec<u8>,
        fragment_entries: Vec<(u64, u32)>,
        next_inode_number: u32,
        compress_metadata: bool,
    }

    impl ImageBuilder {
        fn new() -> Self {
            ImageBuilder { image: vec![0; SUPERBLOCK_LEN], inodes: Vec::new(), directories: Vec::new(), fragment_entries: Vec::new(), next_inode_number: 1, compress_metadata: false }
        }

        fn inode_header(&mut self, kind: u16) -> u16 {
            let offset = self.inodes.len() as u16;
            self.inodes.extend_from_slice(&kind.to_le_bytes());
            self.inodes.extend_from_slice(&0o644u16.to_le_bytes());
            self.inodes.extend_from_slice(&[0; 8]); // uid, gid, mtime
            self.inodes.extend_from_slice(&self.next_inode_number.to_le_bytes());
            self.next_inode_number += 1;
            offset
        }

        /// A file stored in full blocks, each zlib-compressed when `compress`.
        fn add_block_file(&mut self, content: &[u8], compress: bool) -> u16 {
            let start = self.image.len() as u32;
            let mut sizes = Vec::new();
            for block in content.chunks(BLOCK_SIZE as usize) {
                if compress {
                    let packed = compress::compress(Codec::Zlib, block).unwrap();
                    sizes.push(packed.len() as u32);
                    self.image.extend_from_slice(&packed);
                } else {
                    sizes.push(block.len() as u32 | DATA_UNCOMPRESSED);
                    self.image.extend_from_slice(block);
                }
            }
            let offset = self.inode_header(inode_type::FILE);
            for value in [start, NO_FRAGMENT, 0, content.len() as u32].into_iter().chain(sizes) {
                self.inodes.extend_from_slice(&value.to_le_bytes());
            }
            offset
        }

        /// A file held entirely in its own uncompressed fragment block.
        fn add_fragment_file(&mut self, content: &[u8]) -> u16 {
            let fragment_index = self.fragment_entries.len() as u32;
            self.fragment_entries.push((self.image.len() as u64, content.len() as u32 | DATA_UNCOMPRESSED));
            self.image.extend_from_slice(content);
            let offset = self.inode_header(inode_type::FILE);
            for value in [0, fragment_index, 0, content.len() as u32] {
                self.inodes.extend_from_slice(&value.to_le_bytes());
            }
            offset
        }

        fn add_symlink(&mut self, target: &str) -> u16 {
            let offset = self.inode_header(inode_type::SYMLINK);
            self.inodes.extend_from_slice(&1u32.to_le_bytes());
            self.inodes.extend_from_slice(&(target.len() as u32).to_le_bytes());
            self.inodes.extend_from_slice(target.as_bytes());
            offset
        }

        /// A directory listing `(name, inode offset, type)`; returns its inode.
        fn add_directory(&mut self, children: &[(&str, u16, u16)]) -> u16 {
            let listing_at = self.directories.len() as u16;
            if !children.is_empty() {
                self.directories.extend_from_slice(&(children.len() as u32 - 1).to_le_bytes());
                self.directories.extend_from_slice(&0u32.to_le_bytes()); // inode block 0
                self.directories.extend_from_slice(&1u32.to_le_bytes());
                for (name, inode_offset, kind) in children {
                    self.directories.extend_from_slice(&inode_offset.to_le_bytes());
                    self.directories.extend_from_slice(&0i16.to_le_bytes());
                    self.directories.extend_from_slice(&kind.to_le_bytes());
                    self.directories.extend_from_slice(&(name.len() as u16 - 1).to_le_bytes());
                    self.directories.extend_from_slice(name.as_bytes());
                }
            }
            let listing_len = self.directories.len() as u16 - listing_at;
            let offset = self.inode_header(inode_type::DIRECTORY);
            self.inodes.extend_from_slice(&0u32.to_le_bytes()); // directory block 0
            self.inodes.extend_from_slice(&2u32.to_le_bytes());
            self.inodes.extend_from_slice(&(listing_len + DIRECTORY_SIZE_BIAS as u16).to_le_bytes());
            self.inodes.extend_from_slice(&listing_at.to_le_bytes());
            self.inodes.extend_from_slice(&0u32.to_le_bytes());
            offset
        }

        fn metadata_block(&self, payload: &[u8]) -> Vec<u8> {
            let (stored, header) = if self.compress_metadata {
                let packed = compress::compress(Codec::Zlib, payload).unwrap();
                let header = packed.len() as u16;
                (packed, header)
            } else {
                (payload.to_vec(), payload.len() as u16 | METADATA_UNCOMPRESSED)
            };
            let mut block = header.to_le_bytes().to_vec();
            block.extend_from_slice(&stored);
            block
        }

        fn finish(mut self, root: u16) -> Vec<u8> {
            let inode_table = self.image.len() as u64;
            let block = self.metadata_block(&self.inodes);
            self.image.extend_from_slice(&block);
            let directory_table = self.image.len() as u64;
            let block = self.metadata_block(&self.directories);
            self.image.extend_from_slice(&block);
            let mut fragment_table = ABSENT_TABLE;
            if !self.fragment_entries.is_empty() {
                let mut entries = Vec::new();
                for (start, size) in &self.fragment_entries {
                    entries.extend_from_slice(&start.to_le_bytes());
                    entries.extend_from_slice(&size.to_le_bytes());
                    entries.extend_from_slice(&0u32.to_le_bytes());
                }
                let block_at = self.image.len() as u64;
                let block = self.metadata_block(&entries);
                self.image.extend_from_slice(&block);
                fragment_table = self.image.len() as u64;
                self.image.extend_from_slice(&block_at.to_le_bytes());
            }
            let bytes_used = self.image.len() as u64;
            let sb = &mut self.image[..SUPERBLOCK_LEN];
            sb[..4].copy_from_slice(MAGIC);
            sb[4..8].copy_from_slice(&(self.next_inode_number - 1).to_le_bytes());
            sb[12..16].copy_from_slice(&BLOCK_SIZE.to_le_bytes());
            sb[16..20].copy_from_slice(&(self.fragment_entries.len() as u32).to_le_bytes());
            sb[20..22].copy_from_slice(&1u16.to_le_bytes()); // gzip
            sb[22..24].copy_from_slice(&12u16.to_le_bytes());
            sb[28..30].copy_from_slice(&4u16.to_le_bytes());
            sb[32..40].copy_from_slice(&(root as u64).to_le_bytes());
            sb[40..48].copy_from_slice(&bytes_used.to_le_bytes());
            for (at, value) in [(48, ABSENT_TABLE), (56, ABSENT_TABLE), (64, inode_table), (72, directory_table), (80, fragment_table), (88, ABSENT_TABLE)] {
                sb[at..at + 8].copy_from_slice(&value.to_le_bytes());
            }
            self.image
        }
    }

    fn sample_image() -> (Vec<u8>, Vec<u8>) {
        sample_image_with(false)
    }

    fn sample_image_with(compress_metadata: bool) -> (Vec<u8>, Vec<u8>) {
        let big: Vec<u8> = (0..10_000u32).flat_map(|i| format!("{i:05}\n").into_bytes()).collect();
        let mut builder = ImageBuilder::new();
        builder.compress_metadata = compress_metadata;
        let readme = builder.add_block_file(&big, true);
        let config = builder.add_fragment_file(b"key=value\n");
        let raw = builder.add_block_file(b"stored bytes", false);
        let link = builder.add_symlink("/bin/busybox");
        let etc = builder.add_directory(&[("config", config, 2), ("raw.bin", raw, 2)]);
        let root = builder.add_directory(&[("README", readme, 2), ("etc", etc, 1), ("sh", link, 3)]);
        (builder.finish(root), big)
    }

    fn read_all(image: &[u8]) -> Filesystem {
        let mut left = usize::MAX;
        read(image, 0, &mut Allowance::new(&Limits::default(), &mut left)).unwrap()
    }

    #[test]
    fn files_directories_and_links_are_listed_with_their_contents() {
        let (image, big) = sample_image();
        let filesystem = read_all(&image);
        assert!(filesystem.note.is_none(), "{:?}", filesystem.note);
        assert_eq!(filesystem.len, image.len());
        let paths: Vec<&str> = filesystem.entries.iter().map(|entry| entry.path.as_str()).collect();
        assert_eq!(paths, ["README", "etc", "etc/config", "etc/raw.bin", "sh"]);
        let find = |path: &str| filesystem.entries.iter().find(|entry| entry.path == path).unwrap();
        assert_eq!(find("README").data.as_slice(), big.as_slice());
        assert_eq!(find("README").method.as_deref(), Some("gzip"));
        assert_eq!(find("etc/config").data.as_slice(), b"key=value\n");
        assert_eq!(find("etc/raw.bin").data.as_slice(), b"stored bytes");
        assert_eq!(find("sh").kind, EntryKind::Symlink);
        assert_eq!(find("sh").data.as_slice(), b"/bin/busybox");
        assert_eq!(filesystem.file_count(), 3);
        assert!(filesystem.description.starts_with("SquashFS 4.0, gzip"), "{}", filesystem.description);
    }

    #[test]
    fn compressed_metadata_blocks_are_decoded() {
        let (image, big) = sample_image_with(true);
        let filesystem = read_all(&image);
        assert!(filesystem.note.is_none(), "{:?}", filesystem.note);
        assert_eq!(filesystem.entries.len(), 5);
        assert_eq!(filesystem.entries[0].data.as_slice(), big.as_slice());
        assert_eq!(filesystem.entries[2].data.as_slice(), b"key=value\n");
    }

    #[test]
    fn lz4_and_xz_blocks_decode_and_lzo_is_reported() {
        let block = b"firmware block contents, firmware block contents".repeat(20);
        let lz4 = lz4_flex::block::compress(&block);
        assert_eq!(Compression::Lz4.decompress(&lz4, 4096).unwrap(), block);
        assert!(Compression::Lz4.decompress(&lz4, 16).is_err(), "output larger than a block is refused");
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut block.as_slice(), &mut xz).unwrap();
        assert_eq!(Compression::Xz.decompress(&xz, 4096).unwrap(), block);
        assert!(Compression::Lzo.decompress(&lz4, 4096).unwrap_err().contains("not supported"));
    }

    #[test]
    fn an_image_inside_other_data_is_found_by_the_scanner() {
        let (image, _) = sample_image();
        let mut data = super::super::test_support::noise(3000, 3);
        data.extend_from_slice(&image);
        data.extend_from_slice(&[0xFF; 500]);
        let mut left = usize::MAX;
        let found = super::super::find_filesystems(&data, &Limits::default(), &mut left);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].kind, found[0].offset, found[0].len), (FsKind::SquashFs, 3000, image.len()));
    }

    #[test]
    fn extraction_respects_the_byte_allowance() {
        let (image, _) = sample_image();
        let mut left = 1000;
        let filesystem = read(&image, 0, &mut Allowance::new(&Limits::default(), &mut left)).unwrap();
        let extracted: usize = filesystem.entries.iter().map(|entry| entry.data.len()).sum();
        assert_eq!(extracted, 1000);
        assert_eq!(left, 0);
        let readme = &filesystem.entries[0];
        assert_eq!(readme.note.as_deref(), Some(super::super::NOTE_NODE_LIMIT));
    }

    #[test]
    fn corrupt_and_truncated_images_do_not_panic() {
        let (image, _) = sample_image();
        for cut in [0, 10, 95, 96, 200, image.len() / 2, image.len() - 1] {
            let mut left = usize::MAX;
            let _ = read(&image[..cut], 0, &mut Allowance::new(&Limits::default(), &mut left));
        }
        let noise = super::super::test_support::noise(image.len(), 9);
        for seed in 0..64usize {
            let mut damaged = image.clone();
            for (index, byte) in noise.iter().enumerate().skip(SUPERBLOCK_LEN).step_by(7 + seed) {
                damaged[index] ^= *byte;
            }
            let mut left = 1 << 20;
            let _ = read(&damaged, 0, &mut Allowance::new(&Limits::default(), &mut left));
        }
    }

    #[test]
    fn unsupported_versions_and_block_sizes_are_rejected() {
        let (mut image, _) = sample_image();
        image[28] = 3;
        assert!(read_all_result(&image).unwrap_err().contains("version 3"));
        let (mut image, _) = sample_image();
        image[22] = 30;
        assert!(read_all_result(&image).is_err());
    }

    fn read_all_result(image: &[u8]) -> Result<Filesystem, String> {
        let mut left = usize::MAX;
        read(image, 0, &mut Allowance::new(&Limits::default(), &mut left))
    }
}
