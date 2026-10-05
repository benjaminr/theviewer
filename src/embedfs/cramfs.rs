//! A CramFS reader (little-endian, zlib): a superblock, then a tree of
//! 12-byte inodes, with each file stored as a table of block end pointers
//! followed by zlib-compressed 4 KiB pages.

use std::collections::HashSet;
use std::sync::Arc;

use super::{Allowance, Entry, EntryKind, Filesystem, FsKind, MAX_DIRECTORY_DEPTH, join_path, le_u32, slice_at, take_content};
use crate::compress::{self, Codec};

/// 0x28cd3d45, little-endian.
pub(super) const MAGIC: &[u8] = &[0x45, 0x3D, 0xCD, 0x28];
const SIGNATURE: &[u8] = b"Compressed ROMFS";
const SIGNATURE_AT: usize = 16;
const NAME_AT: usize = 48;
const NAME_LEN: usize = 16;
const ROOT_INODE_AT: usize = 64;
const INODE_LEN: usize = 12;
const SUPERBLOCK_LEN: usize = ROOT_INODE_AT + INODE_LEN;
/// Files are compressed in pages of this size.
const PAGE_SIZE: usize = 4096;
/// Flags this reader understands; any other bit means a newer format.
const KNOWN_FLAGS: u32 = 0x0000_07FF;
/// Block pointers carry flag bits instead of plain end offsets.
const FLAG_EXTENDED_BLOCK_POINTERS: u32 = 0x0000_0800;

/// File type bits of an inode's mode.
mod mode {
    pub const TYPE_MASK: u32 = 0o170_000;
    pub const DIRECTORY: u32 = 0o040_000;
    pub const REGULAR: u32 = 0o100_000;
    pub const SYMLINK: u32 = 0o120_000;
}

/// One decoded 12-byte inode.
#[derive(Clone, Copy, Debug)]
struct Inode {
    mode: u32,
    size: usize,
    /// Byte length of the name that follows the inode.
    name_len: usize,
    /// Byte offset of the inode's data (a directory's children, a file's
    /// block pointers).
    offset: usize,
}

fn parse_inode(image: &[u8], at: usize) -> Option<Inode> {
    let words = [le_u32(image, at)?, le_u32(image, at + 4)?, le_u32(image, at + 8)?];
    Some(Inode {
        mode: words[0] & 0xFFFF,
        size: (words[1] & 0x00FF_FFFF) as usize,
        name_len: ((words[2] & 0x3F) * 4) as usize,
        offset: ((words[2] >> 6) * 4) as usize,
    })
}

/// Read the CramFS image at the start of `image` (at `base` in the scanned
/// data).
pub(super) fn read(image: &[u8], base: usize, allowance: &mut Allowance) -> Result<Filesystem, String> {
    if image.get(..MAGIC.len()) != Some(MAGIC) || slice_at(image, SIGNATURE_AT, SIGNATURE.len()) != Some(SIGNATURE) {
        return Err("not a CramFS superblock".to_string());
    }
    let declared_len = le_u32(image, 4).ok_or("superblock is truncated")? as usize;
    let flags = le_u32(image, 8).ok_or("superblock is truncated")?;
    if flags & !KNOWN_FLAGS & !FLAG_EXTENDED_BLOCK_POINTERS != 0 {
        return Err(format!("unknown CramFS flags {flags:#x}"));
    }
    if declared_len < SUPERBLOCK_LEN {
        return Err(format!("implausible image size {declared_len}"));
    }
    let len = declared_len.min(image.len());
    let image = &image[..len];
    let root = parse_inode(image, ROOT_INODE_AT).ok_or("root inode is truncated")?;
    if root.mode & mode::TYPE_MASK != mode::DIRECTORY {
        return Err("root inode is not a directory".to_string());
    }
    let mut problems = Vec::new();
    if len < declared_len {
        problems.push(format!("image is truncated: {len} of {declared_len} bytes present"));
    }
    if flags & FLAG_EXTENDED_BLOCK_POINTERS != 0 {
        problems.push("extended block pointers are not supported: files are listed without content".to_string());
    }
    let mut walker = Walker {
        image,
        base,
        extended_pointers: flags & FLAG_EXTENDED_BLOCK_POINTERS != 0,
        entries: Vec::new(),
        max_entries: allowance.max_entries(),
        visited: HashSet::new(),
        problems,
    };
    walker.walk_directory(root, "", 0, allowance);
    let volume_name = super::clean_name(slice_at(image, NAME_AT, NAME_LEN).unwrap_or_default()).unwrap_or_default();
    let description = format!("CramFS \"{volume_name}\", zlib, {} KiB", len / 1024);
    let note = (!walker.problems.is_empty()).then(|| walker.problems.join("; "));
    Ok(Filesystem { kind: FsKind::CramFs, offset: base, len, description, entries: walker.entries, note })
}

struct Walker<'a> {
    image: &'a [u8],
    base: usize,
    extended_pointers: bool,
    entries: Vec<Entry>,
    max_entries: usize,
    visited: HashSet<usize>,
    problems: Vec<String>,
}

impl Walker<'_> {
    fn walk_directory(&mut self, directory: Inode, path: &str, depth: usize, allowance: &mut Allowance) {
        if depth > MAX_DIRECTORY_DEPTH || !self.visited.insert(directory.offset) {
            return;
        }
        let end = directory.offset.saturating_add(directory.size).min(self.image.len());
        let mut at = directory.offset;
        while at + INODE_LEN <= end {
            if self.entries.len() >= self.max_entries {
                self.problems.push(format!("stopped after {} entries", self.max_entries));
                return;
            }
            let Some(inode) = parse_inode(self.image, at) else { return };
            let name_at = at + INODE_LEN;
            at = name_at + inode.name_len;
            if inode.name_len == 0 {
                self.problems.push(format!("entry at {:#x} has no name", name_at - INODE_LEN));
                return;
            }
            let Some(name) = slice_at(self.image, name_at, inode.name_len).and_then(super::clean_name) else { continue };
            self.visit(inode, join_path(path, &name), name_at - INODE_LEN, depth, allowance);
        }
    }

    fn visit(&mut self, inode: Inode, path: String, inode_at: usize, depth: usize, allowance: &mut Allowance) {
        match inode.mode & mode::TYPE_MASK {
            mode::DIRECTORY => {
                self.entries.push(Entry::directory(path.clone(), self.base + inode_at));
                self.walk_directory(inode, &path, depth + 1, allowance);
            }
            kind @ (mode::REGULAR | mode::SYMLINK) => {
                let entry_kind = if kind == mode::REGULAR { EntryKind::File } else { EntryKind::Symlink };
                let entry = self.read_file(path, inode, entry_kind, allowance);
                self.entries.push(entry);
            }
            _ => self.entries.push(Entry {
                path,
                kind: EntryKind::Special,
                declared_size: 0,
                data: Arc::new(Vec::new()),
                source_offset: self.base + inode_at,
                source_len: INODE_LEN,
                method: None,
                note: None,
            }),
        }
    }

    /// Extract a file or link target: block pointers, then zlib pages.
    fn read_file(&mut self, path: String, inode: Inode, kind: EntryKind, allowance: &mut Allowance) -> Entry {
        let cap = allowance.cap().unwrap_or(0);
        let (content, problem) = if self.extended_pointers { (Vec::new(), None) } else { self.decode_pages(inode, cap) };
        let (data, limit_note) = take_content(content, inode.size as u64, allowance);
        let pages = inode.size.div_ceil(PAGE_SIZE);
        let source_end = le_u32(self.image, inode.offset + pages.saturating_sub(1) * 4).map_or(inode.offset, |end| end as usize);
        Entry {
            path,
            kind,
            declared_size: inode.size as u64,
            data: Arc::new(data),
            source_offset: self.base + inode.offset,
            source_len: source_end.saturating_sub(inode.offset),
            method: (inode.size > 0).then(|| "zlib".to_string()),
            note: problem.or(limit_note),
        }
    }

    /// Decompress up to `cap` bytes of the pages of `inode`.
    fn decode_pages(&self, inode: Inode, cap: usize) -> (Vec<u8>, Option<String>) {
        let wanted = inode.size.min(cap);
        let pages = inode.size.div_ceil(PAGE_SIZE);
        let mut content = Vec::new();
        let mut start = inode.offset.saturating_add(pages * 4);
        for page in 0..pages {
            if content.len() >= wanted {
                break;
            }
            let expected = PAGE_SIZE.min(wanted - content.len());
            let Some(end) = le_u32(self.image, inode.offset + page * 4).map(|end| end as usize) else {
                return (content, Some("block pointers run past the image".to_string()));
            };
            if end == start {
                content.resize(content.len() + expected, 0); // A hole.
                continue;
            }
            let Some(input) = (end > start).then(|| self.image.get(start..end)).flatten() else {
                return (content, Some(format!("page {page} has an invalid extent {start:#x}..{end:#x}")));
            };
            match compress::decompress(Codec::Zlib, input, PAGE_SIZE) {
                Ok(decoded) => content.extend_from_slice(&decoded.data[..expected.min(decoded.data.len())]),
                Err(error) => return (content, Some(format!("page {page}: {error}"))),
            }
            start = end;
        }
        (content, None)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::unpack::Limits;

    /// A file or directory to place in a test image.
    pub enum Item<'a> {
        File(&'a str, &'a [u8]),
        Link(&'a str, &'a str),
        Directory(&'a str, Vec<Item<'a>>),
    }

    fn inode_bytes(mode: u32, size: usize, name_len: usize, offset: usize) -> [u8; INODE_LEN] {
        let mut bytes = [0u8; INODE_LEN];
        bytes[0..4].copy_from_slice(&mode.to_le_bytes());
        bytes[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&((name_len / 4) as u32 | ((offset / 4) as u32) << 6).to_le_bytes());
        bytes
    }

    impl Item<'_> {
        fn padded_name(&self) -> Vec<u8> {
            let (Item::File(name, _) | Item::Link(name, _) | Item::Directory(name, _)) = self;
            let mut bytes = name.as_bytes().to_vec();
            bytes.resize(name.len().div_ceil(4) * 4, 0);
            bytes
        }
    }

    /// Lay out a directory's children (inodes then their data) at the end of
    /// `image`; returns the offset and size of the child inode list.
    fn write_directory(image: &mut Vec<u8>, items: &[Item]) -> (usize, usize) {
        let list_at = image.len();
        let mut slots = Vec::new();
        for item in items {
            slots.push(image.len());
            image.extend_from_slice(&[0; INODE_LEN]);
            image.extend_from_slice(&item.padded_name());
        }
        let list_len = image.len() - list_at;
        for (item, slot) in items.iter().zip(slots) {
            let (mode, size, offset) = match item {
                Item::File(_, content) => (mode::REGULAR | 0o644, content.len(), write_pages(image, content)),
                Item::Link(_, target) => (mode::SYMLINK | 0o777, target.len(), write_pages(image, target.as_bytes())),
                Item::Directory(_, children) => {
                    let (at, len) = write_directory(image, children);
                    (mode::DIRECTORY | 0o755, len, at)
                }
            };
            image[slot..slot + INODE_LEN].copy_from_slice(&inode_bytes(mode, size, item.padded_name().len(), offset));
        }
        (list_at, list_len)
    }

    /// Block pointers then zlib pages; returns where the pointers start.
    fn write_pages(image: &mut Vec<u8>, content: &[u8]) -> usize {
        let pointers_at = image.len();
        let pages: Vec<Vec<u8>> = content.chunks(PAGE_SIZE).map(|page| compress::compress(Codec::Zlib, page).unwrap()).collect();
        image.resize(pointers_at + pages.len() * 4, 0);
        for (index, page) in pages.iter().enumerate() {
            image.extend_from_slice(page);
            let end = image.len() as u32;
            image[pointers_at + index * 4..pointers_at + index * 4 + 4].copy_from_slice(&end.to_le_bytes());
        }
        while !image.len().is_multiple_of(4) {
            image.push(0);
        }
        pointers_at
    }

    pub fn build_image(items: &[Item]) -> Vec<u8> {
        let mut image = vec![0u8; SUPERBLOCK_LEN];
        let (root_at, root_len) = write_directory(&mut image, items);
        let total = image.len() as u32;
        image[0..4].copy_from_slice(MAGIC);
        image[4..8].copy_from_slice(&total.to_le_bytes());
        image[8..12].copy_from_slice(&3u32.to_le_bytes()); // fsid v2, sorted dirs
        image[SIGNATURE_AT..SIGNATURE_AT + SIGNATURE.len()].copy_from_slice(SIGNATURE);
        image[NAME_AT..NAME_AT + 6].copy_from_slice(b"rootfs");
        image[ROOT_INODE_AT..SUPERBLOCK_LEN].copy_from_slice(&inode_bytes(mode::DIRECTORY | 0o755, root_len, 0, root_at));
        image
    }

    fn sample() -> (Vec<u8>, Vec<u8>) {
        let big: Vec<u8> = (0..3000u32).flat_map(|i| format!("{i:04} ").into_bytes()).collect();
        let image = build_image(&[
            Item::Directory("bin", vec![Item::Link("sh", "busybox"), Item::File("busybox", &big)]),
            Item::File("version", b"1.2.3\n"),
            Item::File("empty", b""),
        ]);
        (image, big)
    }

    #[test]
    fn files_directories_and_links_are_extracted() {
        let (image, big) = sample();
        let mut left = usize::MAX;
        let filesystem = read(&image, 0, &mut Allowance::new(&Limits::default(), &mut left)).unwrap();
        assert!(filesystem.note.is_none(), "{:?}", filesystem.note);
        let paths: Vec<&str> = filesystem.entries.iter().map(|entry| entry.path.as_str()).collect();
        assert_eq!(paths, ["bin", "bin/sh", "bin/busybox", "version", "empty"]);
        let find = |path: &str| filesystem.entries.iter().find(|entry| entry.path == path).unwrap();
        assert_eq!(find("bin/busybox").data.as_slice(), big.as_slice());
        assert_eq!(find("bin/sh").kind, EntryKind::Symlink);
        assert_eq!(find("bin/sh").data.as_slice(), b"busybox");
        assert_eq!(find("version").data.as_slice(), b"1.2.3\n");
        assert!(find("empty").data.is_empty());
        assert!(filesystem.description.contains("rootfs"));
    }

    #[test]
    fn unpacking_finds_a_compressed_file_inside_a_filesystem_and_extracts_it() {
        let log = b"boot log line\n".repeat(200);
        let gzipped = crate::compress::compress(crate::compress::Codec::Gzip, &log).unwrap();
        let image = build_image(&[Item::Directory("var", vec![Item::File("boot.log.gz", &gzipped)])]);
        let mut data = vec![0x11u8; 512];
        data.extend_from_slice(&image);
        let root = crate::unpack::unpack(std::sync::Arc::new(data), "firmware", &Limits::default());
        let filesystem = root.children.iter().find(|child| child.kind.contains("CramFS")).expect("the filesystem");
        let var = filesystem.children.iter().find(|child| child.name.ends_with("var")).expect("its folder");
        let file = var.children.iter().find(|child| child.name.ends_with("boot.log.gz")).expect("the file");
        let stream = file.children.first().expect("the gzip stream inside the file was unpacked too");
        assert_eq!(stream.data.as_slice(), log.as_slice());
        assert!(root.children.iter().all(|child| !child.kind.contains("gzip")), "the stream is not also listed loose");
    }

    #[test]
    fn the_scanner_finds_an_image_after_other_data_and_charges_the_allowance() {
        let (image, big) = sample();
        let mut data = vec![0xAAu8; 4096];
        data.extend_from_slice(&image);
        let mut left = 10_000;
        let found = super::super::find_filesystems(&data, &Limits::default(), &mut left);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].kind, found[0].offset, found[0].len), (FsKind::CramFs, 4096, image.len()));
        let extracted: usize = found[0].entries.iter().map(|entry| entry.data.len()).sum();
        assert_eq!(left, 10_000 - extracted);
        assert!(extracted <= 10_000 && big.len() > 10_000);
    }

    #[test]
    fn damaged_images_do_not_panic() {
        let (image, _) = sample();
        let noise = super::super::test_support::noise(image.len(), 5);
        for cut in [4, 20, 76, image.len() / 2] {
            let mut left = usize::MAX;
            let _ = read(&image[..cut], 0, &mut Allowance::new(&Limits::default(), &mut left));
        }
        for step in 3..40 {
            let mut damaged = image.clone();
            for index in (SUPERBLOCK_LEN..damaged.len()).step_by(step) {
                damaged[index] ^= noise[index];
            }
            let mut left = 1 << 20;
            let _ = read(&damaged, 0, &mut Allowance::new(&Limits::default(), &mut left));
        }
    }
}
