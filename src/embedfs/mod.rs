//! Embedded filesystem images found inside firmware and disk images:
//! SquashFS, CramFS, JFFS2, UBI and FAT.
//!
//! Each format has its own reader that turns an image into a flat list of
//! [`Entry`] values (directories, files, symlinks, volumes) with their paths.
//! [`filesystem_nodes`] turns those lists into [`unpack::Node`] trees so the
//! Unpacked view can show a filesystem as a folder of files.
//!
//! Images are untrusted: every offset and length is checked before use,
//! counts are capped, and extracted bytes are taken from the same allowance
//! that `unpack` uses for its own children, so a hostile image can neither
//! panic nor allocate without bound.

mod cramfs;
pub mod fat;
mod jffs2;
mod squashfs;
mod ubi;

use std::sync::Arc;

use aho_corasick::AhoCorasick;

use crate::unpack::{self, Limits, Node};

/// Most entries listed from one filesystem.
pub const MAX_ENTRIES: usize = 4096;
/// Most filesystems reported from one scan.
pub const MAX_FILESYSTEMS: usize = 64;
/// Deepest directory nesting followed inside an image.
const MAX_DIRECTORY_DEPTH: usize = 64;
/// Note on an entry whose bytes were cut at the per-node limit.
const NOTE_NODE_LIMIT: &str = "stopped: node size limit reached";
/// Note on an entry left empty because the total allowance ran out.
const NOTE_SIZE_LIMIT: &str = "stopped: size limit reached";

/// The filesystem formats this module reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FsKind {
    SquashFs,
    CramFs,
    Jffs2,
    Ubi,
    Fat,
}

impl FsKind {
    pub fn label(self) -> &'static str {
        match self {
            FsKind::SquashFs => "SquashFS",
            FsKind::CramFs => "CramFS",
            FsKind::Jffs2 => "JFFS2",
            FsKind::Ubi => "UBI",
            FsKind::Fat => "FAT",
        }
    }
}

/// What an [`Entry`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    /// A symbolic link; its data holds the target path.
    Symlink,
    /// A device node, FIFO or socket: listed, but holds no data.
    Special,
    /// A UBI volume; its data holds the volume's logical erase blocks in order.
    Volume,
}

impl EntryKind {
    /// Whether the entry carries extractable content.
    pub fn has_content(self) -> bool {
        matches!(self, EntryKind::File | EntryKind::Volume)
    }
}

/// What a directory entry records beyond its content. FAT keeps times and
/// leaves deleted entries behind; the other formats leave this empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EntryRecord {
    /// The entry was deleted; any content was recovered, as its note says.
    pub deleted: bool,
    /// Local wall-clock times, such as "2026-09-12 08:14:54" (FAT keeps no zone).
    pub created: Option<String>,
    pub modified: Option<String>,
    /// The first cluster the directory entry names.
    pub first_cluster: Option<u32>,
    /// Offset in the scanned data of the entry's 32-byte directory entry.
    pub entry_offset: Option<usize>,
    /// Where a file's content lies in the scanned data: (offset, length) of
    /// each run of contiguous clusters, the last cut to the file's size; a
    /// deleted file's are its size read on from its first cluster.
    pub ranges: Vec<(usize, usize)>,
    /// For a deleted file: whether the clusters it was recovered from are
    /// all still free, as the contiguous assumption needs.
    pub clusters_free: Option<bool>,
}

/// One directory, file, link or volume inside a filesystem image.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Path from the filesystem root, components joined with '/'.
    pub path: String,
    pub kind: EntryKind,
    /// Size the image declares, which may exceed `data` when extraction was
    /// capped or failed.
    pub declared_size: u64,
    /// Extracted content (empty for directories and special files).
    pub data: Arc<Vec<u8>>,
    /// Offset in the scanned data of the entry's first stored byte (best
    /// effort: the first data block, node or inode).
    pub source_offset: usize,
    /// Bytes the entry occupies in the image, where known.
    pub source_len: usize,
    /// Compression the content was stored with, when it was decompressed.
    pub method: Option<String>,
    /// A problem with this entry, or why extraction stopped early.
    pub note: Option<String>,
    pub record: EntryRecord,
}

impl Entry {
    /// The last path component.
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    fn directory(path: String, source_offset: usize) -> Entry {
        Entry {
            path,
            kind: EntryKind::Directory,
            declared_size: 0,
            data: Arc::new(Vec::new()),
            source_offset,
            source_len: 0,
            method: None,
            note: None,
            record: EntryRecord::default(),
        }
    }
}

/// A filesystem image found in the scanned data.
#[derive(Clone, Debug)]
pub struct Filesystem {
    pub kind: FsKind,
    /// Offset of the image's first byte in the scanned data.
    pub offset: usize,
    /// Bytes the image occupies.
    pub len: usize,
    /// One line, e.g. "SquashFS 4.0, xz, 128 KiB blocks".
    pub description: String,
    pub entries: Vec<Entry>,
    /// A problem with the image as a whole, e.g. an unsupported compressor.
    pub note: Option<String>,
}

impl Filesystem {
    /// Entries with content: files and volumes.
    pub fn files(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|entry| entry.kind.has_content())
    }

    pub fn file_count(&self) -> usize {
        self.files().count()
    }
}

// ---------------------------------------------------------------------------
// Byte allowance
// ---------------------------------------------------------------------------

/// The extraction allowance shared with `unpack`: the same rules as its
/// private `node_cap` and `charge`, duplicated here because those are private.
pub(crate) struct Allowance<'a> {
    limits: &'a Limits,
    bytes_left: &'a mut usize,
}

impl<'a> Allowance<'a> {
    pub(crate) fn new(limits: &'a Limits, bytes_left: &'a mut usize) -> Self {
        Allowance { limits, bytes_left }
    }

    /// The most one entry may extract: the per-node limit, or what is left of
    /// the total. `None` once nothing is left.
    pub(crate) fn cap(&self) -> Option<usize> {
        (*self.bytes_left > 0).then(|| self.limits.max_node_bytes.min(*self.bytes_left))
    }

    /// Charge an extracted entry's bytes to the allowance.
    pub(crate) fn charge(&mut self, len: usize) {
        *self.bytes_left = self.bytes_left.saturating_sub(len);
    }

    /// Most entries one filesystem may list.
    pub(crate) fn max_entries(&self) -> usize {
        MAX_ENTRIES.min(self.limits.max_nodes)
    }
}

/// Take up to `cap` bytes of `content` for an entry, charging the allowance;
/// returns the kept bytes and a note when they were cut or skipped.
pub(crate) fn take_content(mut content: Vec<u8>, declared: u64, allowance: &mut Allowance) -> (Vec<u8>, Option<String>) {
    let Some(cap) = allowance.cap() else {
        return (Vec::new(), Some(NOTE_SIZE_LIMIT.to_string()));
    };
    let mut note = None;
    if content.len() > cap {
        content.truncate(cap);
    }
    if (content.len() as u64) < declared && content.len() == cap {
        note = Some(NOTE_NODE_LIMIT.to_string());
    }
    allowance.charge(content.len());
    (content, note)
}

// ---------------------------------------------------------------------------
// Little helpers shared by the readers
// ---------------------------------------------------------------------------

pub(crate) fn le_u16(data: &[u8], at: usize) -> Option<u16> {
    let bytes = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(crate) fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn le_u64(data: &[u8], at: usize) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

pub(crate) fn be_u32(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn be_u64(data: &[u8], at: usize) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(8)?)?;
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

/// A slice of `len` bytes at `at`, or `None` when it would leave `data`.
pub(crate) fn slice_at(data: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    data.get(at..at.checked_add(len)?)
}

/// A directory entry name made safe for a '/'-joined path: lossy UTF-8,
/// trailing NULs dropped, '/' replaced. `None` for empty, "." and "..".
pub(crate) fn clean_name(raw: &[u8]) -> Option<String> {
    let last = raw.iter().rposition(|&byte| byte != 0)?;
    let trimmed = &raw[..=last];
    let name = String::from_utf8_lossy(trimmed).replace('/', "_");
    (!matches!(name.as_str(), "" | "." | "..")).then_some(name)
}

/// `parent/name`, or just `name` at the root.
pub(crate) fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() { name.to_string() } else { format!("{parent}/{name}") }
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Magic numbers that start a candidate image, with the format they belong to.
const MAGICS: [(&[u8], FsKind); 4] = [
    (squashfs::MAGIC, FsKind::SquashFs),
    (cramfs::MAGIC, FsKind::CramFs),
    (jffs2::MAGIC, FsKind::Jffs2),
    (ubi::MAGIC, FsKind::Ubi),
];

/// Where an image of each kind might start: each magic number found, and
/// each sector boundary holding a FAT boot sector, which has no magic of its
/// own. In offset order.
fn candidates(data: &[u8]) -> Vec<(usize, FsKind)> {
    let patterns: Vec<&[u8]> = MAGICS.iter().map(|(magic, _)| *magic).collect();
    let Ok(matcher) = AhoCorasick::new(patterns) else { return Vec::new() };
    let mut found: Vec<(usize, FsKind)> = matcher.find_overlapping_iter(data).map(|candidate| (candidate.start(), MAGICS[candidate.pattern().as_usize()].1)).collect();
    found.extend((0..data.len()).step_by(fat::SCAN_ALIGNMENT).filter(|&offset| fat::geometry(&data[offset..]).is_ok()).map(|offset| (offset, FsKind::Fat)));
    found.sort_by_key(|&(offset, _)| offset);
    found
}

/// Every filesystem image in `data`, in offset order. Images do not overlap:
/// scanning resumes after the end of each one found, so a filesystem inside
/// another (say, SquashFS in a UBI volume) is found when that volume is
/// itself scanned. A FAT volume is found at any 512-byte boundary, which
/// covers a partition of a whole disk image.
///
/// File contents are taken from `bytes_left` exactly as `unpack` charges its
/// own children; once it runs out, entries are still listed but left empty.
pub fn find_filesystems(data: &[u8], limits: &Limits, bytes_left: &mut usize) -> Vec<Filesystem> {
    let mut allowance = Allowance::new(limits, bytes_left);
    let mut found = Vec::new();
    let mut resume_at = 0;
    for (offset, kind) in candidates(data) {
        if offset < resume_at {
            continue;
        }
        let image = &data[offset..];
        let parsed = match kind {
            FsKind::SquashFs => squashfs::read(image, offset, &mut allowance),
            FsKind::CramFs => cramfs::read(image, offset, &mut allowance),
            FsKind::Jffs2 => jffs2::read(image, offset, &mut allowance),
            FsKind::Ubi => ubi::read(image, offset, &mut allowance),
            FsKind::Fat => fat::read(image, offset, &mut allowance),
        };
        if let Ok(filesystem) = parsed {
            resume_at = offset + filesystem.len.max(1);
            found.push(filesystem);
            if found.len() >= MAX_FILESYSTEMS {
                break;
            }
        }
    }
    found
}

/// Filesystems in `data` as unpack nodes: one folder per image, holding its
/// directories, files, links and volumes.
///
/// Bytes are charged to `bytes_left` as `unpack::find_children` does for zip
/// and tar entries. Each returned node's own `data` is empty (the content
/// lives in its descendants), so recursing into it does not find the same
/// image again. Child `source_offset`s are offsets in `data`.
pub fn filesystem_nodes(data: &[u8], limits: &Limits, bytes_left: &mut usize) -> Vec<unpack::Node> {
    find_filesystems(data, limits, bytes_left).iter().map(filesystem_node).collect()
}

/// One filesystem as a folder node with its entries arranged by path.
pub fn filesystem_node(filesystem: &Filesystem) -> Node {
    let label = filesystem.kind.label();
    let mut root = folder_node(format!("{label}@{:#x}", filesystem.offset), format!("{label} filesystem"), filesystem.offset);
    root.source_len = filesystem.len;
    root.note = filesystem.note.clone();
    for entry in &filesystem.entries {
        insert_entry(&mut root, entry, filesystem.kind);
    }
    root
}

fn folder_node(name: String, kind: String, source_offset: usize) -> Node {
    Node {
        name,
        kind,
        source_offset,
        source_len: 0,
        data: Arc::new(Vec::new()),
        children: Vec::new(),
        note: None,
        method: None,
    }
}

/// Place `entry` under `root`, creating any missing parent folders.
fn insert_entry(root: &mut Node, entry: &Entry, kind: FsKind) {
    let components: Vec<&str> = entry.path.split('/').filter(|part| !part.is_empty()).collect();
    let Some((leaf, parents)) = components.split_last() else { return };
    let mut folder = root;
    for parent in parents {
        folder = child_folder(folder, parent, entry.source_offset);
    }
    if entry.kind == EntryKind::Directory {
        let node = child_folder(folder, leaf, entry.source_offset);
        node.note = entry.note.clone();
        return;
    }
    folder.children.push(Node {
        name: leaf.to_string(),
        kind: entry_kind_label(entry.kind, kind),
        source_offset: entry.source_offset,
        source_len: entry.source_len,
        data: Arc::clone(&entry.data),
        children: Vec::new(),
        note: entry.note.clone(),
        method: entry.method.clone(),
    });
}

/// The folder called `name` directly under `parent`, created when missing.
fn child_folder<'a>(parent: &'a mut Node, name: &str, source_offset: usize) -> &'a mut Node {
    let existing = parent.children.iter().position(|child| child.kind == FOLDER_KIND && child.name == name);
    let index = match existing {
        Some(index) => index,
        None => {
            parent.children.push(folder_node(name.to_string(), FOLDER_KIND.to_string(), source_offset));
            parent.children.len() - 1
        }
    };
    &mut parent.children[index]
}

/// Node kind of a directory inside a filesystem.
const FOLDER_KIND: &str = "directory";

fn entry_kind_label(entry: EntryKind, filesystem: FsKind) -> String {
    match entry {
        EntryKind::File => format!("{} file", filesystem.label()),
        EntryKind::Directory => FOLDER_KIND.to_string(),
        EntryKind::Symlink => "symlink".to_string(),
        EntryKind::Special => "special file".to_string(),
        EntryKind::Volume => "UBI volume".to_string(),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    /// A CramFS image holding `files` (name and content) at its root, for
    /// tests outside this module.
    pub fn cramfs_image(files: &[(&str, &[u8])]) -> Vec<u8> {
        use super::cramfs::tests::{Item, build_image};
        let items: Vec<Item> = files.iter().map(|&(name, content)| Item::File(name, content)).collect();
        build_image(&items)
    }

    /// A disk image: an MBR whose one partition, at sector 63, holds a
    /// FAT16 volume with a live note and a deleted photo (with its long name),
    /// for tests outside this module. Returns the disk and the photo.
    pub fn fat_disk() -> (Vec<u8>, Vec<u8>) {
        use super::fat::tests::{Item, build_volume};
        let photo: Vec<u8> = (0..3000u32).map(|i| (i * 13 % 251) as u8).collect();
        let volume = build_volume(8192, 1, &[
            Item::file(b"NOTES   TXT", None, b"pw on the yellow note\n"),
            Item::file(b"IMG_20~1JPG", Some("IMG_20260912_0814.jpg"), &photo).deleted(),
        ]);
        let mut disk = vec![0u8; 63 * 512];
        disk[446 + 4] = 0x06;
        disk[446 + 8..446 + 12].copy_from_slice(&63u32.to_le_bytes());
        disk[446 + 12..446 + 16].copy_from_slice(&8192u32.to_le_bytes());
        disk[510..512].copy_from_slice(&[0x55, 0xAA]);
        disk.extend(volume);
        (disk, photo)
    }

    /// Deterministic pseudo-random bytes (xorshift).
    pub fn noise(len: usize, seed: u32) -> Vec<u8> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, content: &[u8]) -> Entry {
        Entry {
            path: path.to_string(),
            kind: EntryKind::File,
            declared_size: content.len() as u64,
            data: Arc::new(content.to_vec()),
            source_offset: 0,
            source_len: content.len(),
            method: None,
            note: None,
            record: EntryRecord::default(),
        }
    }

    #[test]
    fn filesystem_node_arranges_entries_into_folders() {
        let filesystem = Filesystem {
            kind: FsKind::CramFs,
            offset: 0x40,
            len: 100,
            description: String::new(),
            entries: vec![Entry::directory("etc".to_string(), 0), file("etc/passwd", b"root"), file("etc/init.d/rcS", b"#!/bin/sh"), file("README", b"hi")],
            note: None,
        };
        let root = filesystem_node(&filesystem);
        assert_eq!(root.name, "CramFS@0x40");
        assert_eq!(root.kind, "CramFS filesystem");
        assert!(root.data.is_empty());
        let names: Vec<&str> = root.children.iter().map(|child| child.name.as_str()).collect();
        assert_eq!(names, ["etc", "README"]);
        let etc = &root.children[0];
        assert_eq!(etc.kind, "directory");
        assert_eq!(etc.children.len(), 2, "{etc:#?}");
        assert_eq!(etc.children[1].children[0].data.as_slice(), b"#!/bin/sh");
        assert_eq!(etc.children[0].kind, "CramFS file");
    }

    #[test]
    fn allowance_matches_the_unpack_rules() {
        let limits = Limits { max_node_bytes: 10, ..Limits::default() };
        let mut left = 15;
        let mut allowance = Allowance::new(&limits, &mut left);
        let (first, note) = take_content(vec![1; 20], 20, &mut allowance);
        assert_eq!((first.len(), note.as_deref()), (10, Some(NOTE_NODE_LIMIT)));
        let (second, _) = take_content(vec![1; 20], 20, &mut allowance);
        assert_eq!(second.len(), 5);
        let (third, note) = take_content(vec![1; 20], 20, &mut allowance);
        assert_eq!((third.len(), note.as_deref()), (0, Some(NOTE_SIZE_LIMIT)));
        assert_eq!(left, 0);
    }

    #[test]
    fn unsafe_names_are_cleaned_or_rejected() {
        assert_eq!(clean_name(b"a/b\0\0").as_deref(), Some("a_b"));
        assert_eq!(clean_name(b".."), None);
        assert_eq!(clean_name(b"\0\0"), None);
    }

    #[test]
    fn a_fat_volume_is_found_inside_an_mbr_partition() {
        let (disk, photo) = test_support::fat_disk();
        let mut left = usize::MAX;
        let found = find_filesystems(&disk, &Limits::default(), &mut left);
        assert_eq!(found.len(), 1, "the MBR itself is no volume");
        assert_eq!((found[0].kind, found[0].offset, found[0].len), (FsKind::Fat, 63 * 512, 8192 * 512));
        let deleted = found[0].entries.iter().find(|entry| entry.record.deleted).expect("the deleted photo");
        assert_eq!(deleted.path, "IMG_20260912_0814.jpg");
        assert_eq!(deleted.data.as_slice(), photo.as_slice());
        let root = filesystem_node(&found[0]);
        assert_eq!(root.name, "FAT@0x7e00");
        assert_eq!(root.children[1].note.as_deref(), Some(fat::NOTE_RECOVERED), "the unpacked tree says the file was recovered");
    }

    #[test]
    fn noise_and_stray_magics_find_no_filesystem() {
        let mut data = test_support::noise(256 * 1024, 7);
        for (index, (magic, _)) in MAGICS.iter().enumerate() {
            let at = 1000 + index * 5000;
            data[at..at + magic.len()].copy_from_slice(magic);
        }
        let mut left = usize::MAX;
        assert!(find_filesystems(&data, &Limits::default(), &mut left).is_empty());
        assert!(find_filesystems(&[], &Limits::default(), &mut left).is_empty());
    }
}
