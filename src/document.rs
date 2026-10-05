//! Editable byte document backed by a piece table.
//!
//! The original file is memory-mapped and never copied. Edits append to a
//! separate "added" buffer and the document is described as an ordered list of
//! pieces that point into either backing store. This keeps inserts and deletes
//! cheap even on multi-gigabyte files, and reads of any window stay a handful
//! of `memcpy` calls.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use memmap2::Mmap;

/// Where a piece's bytes live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Original,
    Added,
}

/// A contiguous run of bytes in one of the backing stores.
#[derive(Clone, Copy, Debug)]
struct Piece {
    source: Source,
    start: usize,
    len: usize,
}

/// The immutable original contents of the file. Cheap to clone so that
/// background analysis can read it while the UI keeps editing.
#[derive(Clone)]
pub enum Backing {
    Mapped(Arc<Mmap>),
    Owned(Arc<Vec<u8>>),
}

impl Backing {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Backing::Mapped(map) => &map[..],
            Backing::Owned(bytes) => bytes,
        }
    }
}

/// One reversible edit: at `pos`, `removed` was replaced by `inserted`.
#[derive(Clone, Debug)]
struct EditRecord {
    pos: usize,
    removed: Vec<u8>,
    inserted: Vec<u8>,
}

impl EditRecord {
    fn inverse(&self) -> EditRecord {
        EditRecord {
            pos: self.pos,
            removed: self.inserted.clone(),
            inserted: self.removed.clone(),
        }
    }
}

pub struct Document {
    original: Backing,
    added: Vec<u8>,
    pieces: Vec<Piece>,
    /// `prefix[i]` is the document offset at which `pieces[i]` begins.
    /// Has one extra trailing entry equal to the total length.
    prefix: Vec<usize>,
    prefix_dirty: bool,
    len: usize,
    path: Option<PathBuf>,
    undo_stack: Vec<EditRecord>,
    redo_stack: Vec<EditRecord>,
    /// Incremented on every mutation so caches can detect staleness.
    version: u64,
}

impl Default for Document {
    fn default() -> Self {
        Self::from_bytes(Vec::new())
    }
}

impl Document {
    /// Build a document from an in-memory buffer.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        let pieces = if len == 0 {
            Vec::new()
        } else {
            vec![Piece { source: Source::Original, start: 0, len }]
        };
        Document {
            original: Backing::Owned(Arc::new(bytes)),
            added: Vec::new(),
            pieces,
            prefix: Vec::new(),
            prefix_dirty: true,
            len,
            path: None,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            version: 0,
        }
    }

    /// Memory-map a file from disk.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let len = file.metadata()?.len() as usize;
        let backing = if len == 0 {
            Backing::Owned(Arc::new(Vec::new()))
        } else {
            // SAFETY: we never write through the mapping, and we accept that
            // external modification of the file while mapped is undefined.
            let map = unsafe { Mmap::map(&file) }.context("memory-mapping file")?;
            Backing::Mapped(Arc::new(map))
        };
        let pieces = if len == 0 {
            Vec::new()
        } else {
            vec![Piece { source: Source::Original, start: 0, len }]
        };
        Ok(Document {
            original: backing,
            added: Vec::new(),
            pieces,
            prefix: Vec::new(),
            prefix_dirty: true,
            len,
            path: Some(path.to_path_buf()),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            version: 0,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// A shareable handle to the original (on-disk) bytes.
    pub fn original(&self) -> Backing {
        self.original.clone()
    }

    pub fn is_modified(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    // ----------------------------------------------------------------------
    // Reading
    // ----------------------------------------------------------------------

    fn piece_bytes(&self, piece: &Piece) -> &[u8] {
        let store = match piece.source {
            Source::Original => self.original.as_slice(),
            Source::Added => &self.added,
        };
        &store[piece.start..piece.start + piece.len]
    }

    fn ensure_prefix(&mut self) {
        if !self.prefix_dirty {
            return;
        }
        self.prefix.clear();
        self.prefix.reserve(self.pieces.len() + 1);
        let mut acc = 0;
        for piece in &self.pieces {
            self.prefix.push(acc);
            acc += piece.len;
        }
        self.prefix.push(acc);
        self.prefix_dirty = false;
    }

    /// Index of the piece containing document offset `pos`.
    /// Requires `pos < len` and a fresh prefix table.
    fn piece_index_for(&self, pos: usize) -> usize {
        debug_assert!(!self.prefix_dirty);
        // partition_point gives the first prefix > pos; the piece is one before.
        self.prefix.partition_point(|&start| start <= pos) - 1
    }

    /// Copy bytes starting at `offset` into `out`. Bytes beyond the end of the
    /// document are zero-filled. Returns how many bytes were real data.
    pub fn read_into(&mut self, offset: usize, out: &mut [u8]) -> usize {
        self.ensure_prefix();
        if offset >= self.len || out.is_empty() {
            out.fill(0);
            return 0;
        }
        let wanted = out.len().min(self.len - offset);
        let mut written = 0;
        let mut index = self.piece_index_for(offset);
        let mut pos_in_piece = offset - self.prefix[index];
        while written < wanted {
            let piece = &self.pieces[index];
            let available = piece.len - pos_in_piece;
            let take = available.min(wanted - written);
            let src = &self.piece_bytes(piece)[pos_in_piece..pos_in_piece + take];
            out[written..written + take].copy_from_slice(src);
            written += take;
            index += 1;
            pos_in_piece = 0;
        }
        out[written..].fill(0);
        written
    }

    /// Copy a range out into a fresh vector (clamped to the document).
    pub fn read_range(&mut self, offset: usize, len: usize) -> Vec<u8> {
        if offset >= self.len {
            return Vec::new();
        }
        let len = len.min(self.len - offset);
        let mut out = vec![0u8; len];
        self.read_into(offset, &mut out);
        out
    }

    pub fn byte_at(&mut self, offset: usize) -> Option<u8> {
        if offset >= self.len {
            return None;
        }
        let mut one = [0u8; 1];
        self.read_into(offset, &mut one);
        Some(one[0])
    }

    // ----------------------------------------------------------------------
    // Low-level piece surgery (no undo bookkeeping)
    // ----------------------------------------------------------------------

    /// Split the piece list so that a piece boundary exists exactly at `pos`.
    /// Returns the index of the first piece starting at `pos`.
    fn split_at(&mut self, pos: usize) -> usize {
        self.ensure_prefix();
        if pos >= self.len {
            return self.pieces.len();
        }
        let index = self.piece_index_for(pos);
        let piece_start = self.prefix[index];
        if piece_start == pos {
            return index;
        }
        let piece = self.pieces[index];
        let head_len = pos - piece_start;
        let head = Piece { len: head_len, ..piece };
        let tail = Piece {
            source: piece.source,
            start: piece.start + head_len,
            len: piece.len - head_len,
        };
        self.pieces[index] = head;
        self.pieces.insert(index + 1, tail);
        self.prefix_dirty = true;
        index + 1
    }

    fn raw_insert(&mut self, pos: usize, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let pos = pos.min(self.len);
        let index = self.split_at(pos);
        let start = self.added.len();
        self.added.extend_from_slice(bytes);

        // Coalesce with a preceding piece that ends exactly where we append.
        if index > 0 {
            let prev = &mut self.pieces[index - 1];
            if prev.source == Source::Added && prev.start + prev.len == start {
                prev.len += bytes.len();
                self.len += bytes.len();
                self.prefix_dirty = true;
                return;
            }
        }
        self.pieces.insert(
            index,
            Piece { source: Source::Added, start, len: bytes.len() },
        );
        self.len += bytes.len();
        self.prefix_dirty = true;
    }

    fn raw_delete(&mut self, pos: usize, len: usize) {
        if len == 0 || pos >= self.len {
            return;
        }
        let end = (pos + len).min(self.len);
        let first = self.split_at(pos);
        let last = self.split_at(end);
        self.pieces.drain(first..last);
        self.len -= end - pos;
        self.prefix_dirty = true;
    }

    fn apply(&mut self, record: &EditRecord) {
        self.raw_delete(record.pos, record.removed.len());
        self.raw_insert(record.pos, &record.inserted);
        self.version += 1;
    }

    fn commit(&mut self, record: EditRecord) {
        self.apply(&record);
        self.undo_stack.push(record);
        self.redo_stack.clear();
    }

    // ----------------------------------------------------------------------
    // Public editing API (all undoable)
    // ----------------------------------------------------------------------

    pub fn insert(&mut self, pos: usize, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let pos = pos.min(self.len);
        self.commit(EditRecord { pos, removed: Vec::new(), inserted: bytes.to_vec() });
    }

    pub fn delete(&mut self, pos: usize, len: usize) {
        let removed = self.read_range(pos, len);
        if removed.is_empty() {
            return;
        }
        self.commit(EditRecord { pos, removed, inserted: Vec::new() });
    }

    /// Replace bytes in place without changing the document length, growing
    /// the document only if the write runs past the end.
    pub fn overwrite(&mut self, pos: usize, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let pos = pos.min(self.len);
        let removed = self.read_range(pos, bytes.len());
        if removed == bytes {
            return;
        }
        self.commit(EditRecord { pos, removed, inserted: bytes.to_vec() });
    }

    /// Overwrite one byte, folding the change into the previous edit when that
    /// edit put a single byte at the same position. Typing the two hex digits
    /// of a byte therefore becomes one undo step.
    pub fn overwrite_byte_coalescing(&mut self, pos: usize, byte: u8) {
        let folds = self
            .undo_stack
            .last()
            .is_some_and(|last| last.pos == pos && last.inserted.len() == 1);
        if folds {
            let previous = self.undo_stack.pop().expect("checked above");
            self.apply(&previous.inverse());
            self.commit(EditRecord { pos, removed: previous.removed, inserted: vec![byte] });
        } else {
            self.overwrite(pos, &[byte]);
        }
    }

    /// Replace `len` bytes at `pos` with `bytes` (lengths may differ).
    pub fn replace(&mut self, pos: usize, len: usize, bytes: &[u8]) {
        let pos = pos.min(self.len);
        let removed = self.read_range(pos, len);
        if removed.is_empty() && bytes.is_empty() {
            return;
        }
        self.commit(EditRecord { pos, removed, inserted: bytes.to_vec() });
    }

    pub fn undo(&mut self) -> Option<usize> {
        let record = self.undo_stack.pop()?;
        let inverse = record.inverse();
        self.apply(&inverse);
        let pos = record.pos;
        self.redo_stack.push(record);
        Some(pos)
    }

    pub fn redo(&mut self) -> Option<usize> {
        let record = self.redo_stack.pop()?;
        self.apply(&record);
        let pos = record.pos;
        self.undo_stack.push(record);
        Some(pos)
    }

    // ----------------------------------------------------------------------
    // Saving
    // ----------------------------------------------------------------------

    /// Stream the document to `path`. Writes to a sibling temporary file first
    /// so the mapped original is never truncated underneath us.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        let temp_path = temp_sibling(path);
        {
            let file = File::create(&temp_path)
                .with_context(|| format!("creating {}", temp_path.display()))?;
            let mut writer = BufWriter::with_capacity(1 << 20, file);
            for piece in &self.pieces {
                writer.write_all(self.piece_bytes(piece))?;
            }
            writer.flush()?;
        }
        std::fs::rename(&temp_path, path)
            .with_context(|| format!("renaming into place at {}", path.display()))?;
        Ok(())
    }
}

fn temp_sibling(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".to_string());
    let unique = std::process::id();
    path.with_file_name(format!(".{file_name}.{unique}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(bytes: &[u8]) -> Document {
        Document::from_bytes(bytes.to_vec())
    }

    #[test]
    fn reads_back_original_bytes_unchanged() {
        let mut document = doc(b"hello world");
        assert_eq!(document.read_range(0, 11), b"hello world");
        assert_eq!(document.read_range(6, 100), b"world");
        assert_eq!(document.byte_at(4), Some(b'o'));
        assert_eq!(document.byte_at(11), None);
    }

    #[test]
    fn insert_in_middle_shifts_following_bytes() {
        let mut document = doc(b"abcd");
        document.insert(2, b"XY");
        assert_eq!(document.read_range(0, 10), b"abXYcd");
        assert_eq!(document.len(), 6);
    }

    #[test]
    fn delete_across_piece_boundaries_removes_exact_range() {
        let mut document = doc(b"abcdef");
        document.insert(3, b"123");
        assert_eq!(document.read_range(0, 20), b"abc123def");
        document.delete(2, 5);
        assert_eq!(document.read_range(0, 20), b"abef");
    }

    #[test]
    fn overwrite_keeps_length_and_undo_restores() {
        let mut document = doc(b"abcdef");
        document.overwrite(1, b"ZZ");
        assert_eq!(document.read_range(0, 10), b"aZZdef");
        assert_eq!(document.len(), 6);
        document.undo();
        assert_eq!(document.read_range(0, 10), b"abcdef");
        document.redo();
        assert_eq!(document.read_range(0, 10), b"aZZdef");
    }

    #[test]
    fn coalesced_nibble_edits_undo_as_one_step() {
        let mut document = doc(b"abc");
        document.overwrite(1, &[0xF0]);
        document.overwrite_byte_coalescing(1, 0xF1);
        assert_eq!(document.read_range(0, 3), [b'a', 0xF1, b'c']);
        document.undo();
        assert_eq!(document.read_range(0, 3), b"abc");
        assert!(!document.can_undo());

        // Folding also applies to a byte that was just inserted.
        document.insert(3, &[0xA0]);
        document.overwrite_byte_coalescing(3, 0xA5);
        assert_eq!(document.read_range(0, 4), [b'a', b'b', b'c', 0xA5]);
        document.undo();
        assert_eq!(document.read_range(0, 4), b"abc");
    }

    #[test]
    fn overwrite_past_end_extends_document() {
        let mut document = doc(b"ab");
        document.overwrite(1, b"xyz");
        assert_eq!(document.read_range(0, 10), b"axyz");
    }

    #[test]
    fn consecutive_inserts_coalesce_into_one_piece() {
        let mut document = doc(b"");
        for byte in b"typing" {
            let at = document.len();
            document.insert(at, &[*byte]);
        }
        assert_eq!(document.read_range(0, 10), b"typing");
        assert_eq!(document.pieces.len(), 1);
    }

    #[test]
    fn read_into_zero_fills_beyond_end() {
        let mut document = doc(b"abc");
        let mut buffer = [0xFFu8; 6];
        let real = document.read_into(1, &mut buffer);
        assert_eq!(real, 2);
        assert_eq!(&buffer, b"bc\0\0\0\0");
    }

    #[test]
    fn save_round_trips_edits() {
        let mut document = doc(b"the quick brown fox");
        document.delete(4, 6);
        document.insert(4, b"slow ");
        let dir = std::env::temp_dir();
        let path = dir.join(format!("theviewer-test-{}.bin", std::process::id()));
        document.save_to(&path).unwrap();
        let written = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(written, b"the slow brown fox");
    }
}
