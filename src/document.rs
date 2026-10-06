//! Editable byte document backed by a piece table.
//!
//! The original file is memory-mapped and never copied. Edits append to a
//! separate "added" buffer and the document is described as an ordered list of
//! pieces that point into either backing store. This keeps inserts and deletes
//! cheap even on multi-gigabyte files, and reads of any window stay a handful
//! of `memcpy` calls.
//!
//! Every change is also noted in a bounded edit log (positions and lengths,
//! not bytes), from which the workspace bus publishes `document.edited` and
//! carries what is known about unchanged regions through the edit.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use memmap2::Mmap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Most changes the edit log remembers. Older ones are forgotten, and
/// offsets from before them can no longer be mapped forward.
const EDIT_LOG_LIMIT: usize = 4096;

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

/// One change to the bytes as the edit log records it: at `at`, `removed`
/// bytes were replaced by `inserted` bytes, which made version `version`.
/// Undo and redo are changes too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Edit {
    /// The document version this change made.
    pub version: u64,
    /// Offset of the change.
    pub at: usize,
    /// Bytes taken out at `at`.
    pub removed: usize,
    /// Bytes put in at `at`.
    pub inserted: usize,
}

impl Edit {
    /// Where the span `[start, start + len)` lies after this change, or
    /// `None` when the change touched it. A change that ends where the span
    /// starts (an insert there, say) moves it; one that starts where it ends
    /// leaves it be.
    pub fn map_span(&self, start: usize, len: usize) -> Option<(usize, usize)> {
        let end = start + len;
        if self.at + self.removed <= start && (self.at < start || self.removed == 0) {
            let moved = (start + self.inserted).checked_sub(self.removed)?;
            return Some((moved, len));
        }
        if self.at >= end && (len > 0 || self.at > start) {
            return Some((start, len));
        }
        None
    }
}

/// Map a span described at `from_version` through `edits` (in version
/// order), to where it lies after the last of them. `None` when an edit
/// touched it, or when `edits` does not carry on from `from_version` (some
/// changes in between are unknown).
pub fn map_span_through(edits: &[Edit], from_version: u64, start: usize, len: usize) -> Option<(usize, usize)> {
    let mut span = (start, len);
    let later = edits.iter().filter(|edit| edit.version > from_version);
    for (expected, edit) in (from_version + 1..).zip(later) {
        if edit.version != expected {
            return None;
        }
        span = edit.map_span(span.0, span.1)?;
    }
    Some(span)
}

/// Everything one undo or redo reverses or repeats: usually one edit, or
/// every edit made inside a group.
type UndoStep = Vec<EditRecord>;

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
    undo_stack: Vec<UndoStep>,
    redo_stack: Vec<UndoStep>,
    /// Edits made since [`Document::begin_group`], undone together.
    open_group: Option<UndoStep>,
    /// How many groups are open; the step is recorded when the last closes.
    group_depth: usize,
    /// Incremented on every mutation so caches can detect staleness.
    version: u64,
    /// The latest changes, oldest first, at most [`EDIT_LOG_LIMIT`].
    edit_log: VecDeque<Edit>,
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
            open_group: None,
            group_depth: 0,
            version: 0,
            edit_log: VecDeque::new(),
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
            open_group: None,
            group_depth: 0,
            version: 0,
            edit_log: VecDeque::new(),
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

    /// The changes made after `version`, oldest first; `None` when the edit
    /// log no longer reaches back that far.
    pub fn edits_since(&self, version: u64) -> Option<Vec<Edit>> {
        if version >= self.version {
            return Some(Vec::new());
        }
        let oldest = self.edit_log.front()?.version;
        if oldest > version + 1 {
            return None;
        }
        Some(self.edit_log.iter().filter(|edit| edit.version > version).copied().collect())
    }

    /// Where the span `[start, start + len)` described at `version` lies
    /// now, or `None` when an edit since touched it or is forgotten.
    pub fn map_span(&self, version: u64, start: usize, len: usize) -> Option<(usize, usize)> {
        map_span_through(&self.edits_since(version)?, version, start, len)
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
        if self.edit_log.len() == EDIT_LOG_LIMIT {
            self.edit_log.pop_front();
        }
        self.edit_log.push_back(Edit { version: self.version, at: record.pos, removed: record.removed.len(), inserted: record.inserted.len() });
    }

    fn commit(&mut self, record: EditRecord) {
        self.apply(&record);
        match &mut self.open_group {
            Some(group) => group.push(record),
            None => self.undo_stack.push(vec![record]),
        }
        self.redo_stack.clear();
    }

    /// Start a group: every edit until the matching [`Document::end_group`]
    /// becomes one undo step. Groups may nest; the outermost decides.
    pub fn begin_group(&mut self) {
        self.group_depth += 1;
        self.open_group.get_or_insert_with(Vec::new);
    }

    /// Close a group opened by [`Document::begin_group`].
    pub fn end_group(&mut self) {
        self.group_depth = self.group_depth.saturating_sub(1);
        if self.group_depth == 0
            && let Some(group) = self.open_group.take()
            && !group.is_empty()
        {
            self.undo_stack.push(group);
        }
    }

    /// Run `edits` as one undo step.
    pub fn grouped<R>(&mut self, edits: impl FnOnce(&mut Document) -> R) -> R {
        self.begin_group();
        let result = edits(self);
        self.end_group();
        result
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
        let folds = self.open_group.is_none()
            && self
                .undo_stack
                .last()
                .is_some_and(|last| matches!(last.as_slice(), [only] if only.pos == pos && only.inserted.len() == 1));
        if folds {
            let mut step = self.undo_stack.pop().expect("checked above");
            let previous = step.pop().expect("a step of one edit");
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

    /// Undo the last step (one edit or a whole group). Returns where the
    /// earliest of its edits was.
    pub fn undo(&mut self) -> Option<usize> {
        let step = self.undo_stack.pop()?;
        for record in step.iter().rev() {
            self.apply(&record.inverse());
        }
        let pos = step.iter().map(|record| record.pos).min();
        self.redo_stack.push(step);
        pos
    }

    /// Redo the last undone step. Returns where the earliest of its edits was.
    pub fn redo(&mut self) -> Option<usize> {
        let step = self.redo_stack.pop()?;
        for record in &step {
            self.apply(record);
        }
        let pos = step.iter().map(|record| record.pos).min();
        self.undo_stack.push(step);
        pos
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
    fn edits_made_in_a_group_undo_and_redo_as_one_step() {
        let mut document = doc(b"abcdef");
        document.grouped(|document| {
            document.delete(1, 2);
            document.insert(3, b"XY");
            document.overwrite(0, b"Z");
        });
        assert_eq!(document.read_range(0, 10), b"ZdeXYf");
        assert_eq!(document.undo(), Some(0));
        assert_eq!(document.read_range(0, 10), b"abcdef");
        assert!(!document.can_undo());
        document.redo();
        assert_eq!(document.read_range(0, 10), b"ZdeXYf");
    }

    #[test]
    fn an_empty_group_leaves_no_undo_step() {
        let mut document = doc(b"abc");
        document.begin_group();
        document.end_group();
        assert!(!document.can_undo());
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
    fn every_change_including_undo_is_logged_with_the_version_it_made() {
        let mut document = doc(b"abcdef");
        document.insert(2, b"XY");
        document.delete(0, 1);
        document.undo();
        let edits = document.edits_since(0).unwrap();
        assert_eq!(
            edits,
            [
                Edit { version: 1, at: 2, removed: 0, inserted: 2 },
                Edit { version: 2, at: 0, removed: 1, inserted: 0 },
                Edit { version: 3, at: 0, removed: 0, inserted: 1 },
            ]
        );
        assert_eq!(document.edits_since(2).unwrap().len(), 1);
        assert!(document.edits_since(3).unwrap().is_empty());
    }

    #[test]
    fn a_span_after_an_insert_moves_and_one_the_edit_touches_is_lost() {
        let mut document = doc(&[0u8; 0x10000]);
        document.insert(0x100, &[1, 2, 3, 4]);
        assert_eq!(document.map_span(0, 0x9000, 16), Some((0x9004, 16)), "a finding after the insert moves with it");
        assert_eq!(document.map_span(0, 0x10, 16), Some((0x10, 16)), "one before it stays");
        assert_eq!(document.map_span(0, 0xF8, 16), None, "one the insert lands inside is touched");
        assert_eq!(document.map_span(0, 0x100, 4), Some((0x104, 4)), "an insert where the span starts pushes it along");
        assert_eq!(document.map_span(0, 0xFC, 4), Some((0xFC, 4)), "an insert where the span ends leaves it be");
        document.overwrite(0x2000, b"zz");
        assert_eq!(document.map_span(0, 0x9000, 16), Some((0x9004, 16)), "an overwrite elsewhere changes nothing");
        assert_eq!(document.map_span(0, 0x1FFC, 8), None, "an overwrite inside the span touches it");
        document.delete(0, 0x10);
        assert_eq!(document.map_span(1, 0x9004, 16), Some((0x8FF4, 16)), "mapped from a later version");
    }

    #[test]
    fn spans_cannot_be_mapped_across_forgotten_edits() {
        let mut document = doc(&[0u8; 64]);
        for round in 0..EDIT_LOG_LIMIT + 2 {
            document.overwrite(63, &[1 + (round % 2) as u8]);
        }
        assert_eq!(document.edits_since(0), None, "the oldest changes are forgotten");
        assert_eq!(document.map_span(0, 0, 4), None);
        let recent = document.version() - 3;
        assert_eq!(document.map_span(recent, 0, 4), Some((0, 4)));
        assert_eq!(map_span_through(&[Edit { version: 5, at: 100, removed: 0, inserted: 1 }], 3, 0, 4), None, "version 4 is missing");
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
