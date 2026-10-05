//! Comparing two documents in a way that understands inserted and deleted
//! bytes, not just flipped ones.
//!
//! Both documents are cut into content-defined chunks with a gear rolling
//! hash, so an insertion only disturbs the chunk it lands in. Chunks whose
//! hash is unique in both documents become anchors; the longest increasing
//! subsequence of anchors keeps them in order. Each anchor is then extended
//! byte by byte in both directions, and the gaps between matches are
//! classified as inserts, deletes or replacements. Memory use is bounded by
//! the chunk table (hashes only), so multi-gigabyte documents are fine.

use std::collections::HashMap;

use crate::document::Document;

/// One step of the edit script turning document A into document B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiffOp {
    Equal { a: usize, b: usize, len: usize },
    Replace { a: usize, a_len: usize, b: usize, b_len: usize },
    Insert { b: usize, len: usize },
    Delete { a: usize, len: usize },
}

/// Bounds on the work a diff may do.
#[derive(Clone, Copy, Debug)]
pub struct DiffLimits {
    /// Stop (and report `truncated`) after this many operations.
    pub max_ops: usize,
    /// Equal-length gaps up to this size are compared byte by byte.
    pub byte_compare_gap: usize,
}

impl Default for DiffLimits {
    fn default() -> Self {
        DiffLimits { max_ops: 200_000, byte_compare_gap: 64 * 1024 }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiffResult {
    pub ops: Vec<DiffOp>,
    pub equal_bytes: usize,
    pub changed_bytes: usize,
    pub truncated: bool,
}

/// Compare `a` with `b`.
pub fn diff(a: &mut Document, b: &mut Document, limits: DiffLimits) -> DiffResult {
    let average = average_chunk_len(a.len().max(b.len()));
    let chunks_a = chunk_document(a, average);
    let chunks_b = chunk_document(b, average);
    let anchors = ordered_anchors(&chunks_a, &chunks_b);

    let mut builder = Builder::new(limits);
    let (mut a_pos, mut b_pos) = (0usize, 0usize);
    for &(index_a, index_b) in &anchors {
        let (chunk_a, chunk_b) = (chunks_a[index_a], chunks_b[index_b]);
        // Skip anchors already covered by an earlier extension.
        if chunk_a.offset < a_pos || chunk_b.offset < b_pos {
            continue;
        }
        // Extend the anchor backwards as far as the previous match allows.
        let back = common_suffix(a, b, a_pos, chunk_a.offset, b_pos, chunk_b.offset);
        let match_a = chunk_a.offset - back;
        let match_b = chunk_b.offset - back;
        // And forwards past the chunk.
        let forward = common_prefix(a, b, chunk_a.offset, chunk_b.offset);
        builder.gap(a, b, a_pos, match_a, b_pos, match_b);
        builder.equal(match_a, match_b, back + forward);
        a_pos = match_a + back + forward;
        b_pos = match_b + back + forward;
        if builder.full() {
            break;
        }
    }
    if !builder.full() {
        // Trailing bytes: extend from the last match, then classify the rest.
        let forward = common_prefix(a, b, a_pos, b_pos);
        builder.equal(a_pos, b_pos, forward);
        a_pos += forward;
        b_pos += forward;
        let back = common_suffix(a, b, a_pos, a.len(), b_pos, b.len());
        builder.gap(a, b, a_pos, a.len() - back, b_pos, b.len() - back);
        builder.equal(a.len() - back, b.len() - back, back);
    }
    builder.finish()
}

// ---------------------------------------------------------------------------
// Content-defined chunking
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Chunk {
    offset: usize,
    hash: u64,
}

/// Most chunks per document; the average size grows to stay under it.
const MAX_CHUNKS: usize = 1 << 20;
const READ_BLOCK: usize = 1 << 20;

fn average_chunk_len(len: usize) -> usize {
    (len / MAX_CHUNKS).next_power_of_two().max(64)
}

const fn gear_table() -> [u64; 256] {
    // SplitMix64, so the table is fixed and needs no runtime set-up.
    let mut table = [0u64; 256];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut index = 0;
    while index < 256 {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        table[index] = z ^ (z >> 31);
        index += 1;
    }
    table
}

const GEAR: [u64; 256] = gear_table();

/// Cut the document into chunks whose boundaries depend on content, reading
/// it in blocks so memory stays bounded.
fn chunk_document(document: &mut Document, average: usize) -> Vec<Chunk> {
    let mask = (average as u64).next_power_of_two() - 1;
    let min_len = (average / 4).max(16);
    let max_len = average * 4;
    let mut chunks = Vec::new();
    let mut block = vec![0u8; READ_BLOCK];
    let (mut rolling, mut content) = (0u64, FNV_OFFSET);
    let mut chunk_start = 0usize;
    let mut offset = 0usize;
    while offset < document.len() {
        let read = document.read_into(offset, &mut block);
        for (index, &byte) in block[..read].iter().enumerate() {
            rolling = (rolling << 1).wrapping_add(GEAR[byte as usize]);
            content = (content ^ byte as u64).wrapping_mul(FNV_PRIME);
            let position = offset + index + 1;
            let len = position - chunk_start;
            if (len >= min_len && rolling & mask == 0) || len >= max_len {
                chunks.push(Chunk { offset: chunk_start, hash: content ^ len as u64 });
                chunk_start = position;
                rolling = 0;
                content = FNV_OFFSET;
            }
        }
        offset += read.max(1);
    }
    if chunk_start < document.len() {
        chunks.push(Chunk { offset: chunk_start, hash: content ^ (document.len() - chunk_start) as u64 });
    }
    chunks
}

const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

/// Pairs of chunk indices (A, B) whose hash is unique in both documents,
/// reduced to the longest run that is increasing in both.
fn ordered_anchors(chunks_a: &[Chunk], chunks_b: &[Chunk]) -> Vec<(usize, usize)> {
    let mut seen: HashMap<u64, (u32, u32, usize, usize)> = HashMap::new();
    for (index, chunk) in chunks_a.iter().enumerate() {
        let entry = seen.entry(chunk.hash).or_insert((0, 0, index, 0));
        entry.0 += 1;
    }
    for (index, chunk) in chunks_b.iter().enumerate() {
        if let Some(entry) = seen.get_mut(&chunk.hash) {
            entry.1 += 1;
            entry.3 = index;
        }
    }
    let mut pairs: Vec<(usize, usize)> = seen
        .values()
        .filter(|&&(count_a, count_b, _, _)| count_a == 1 && count_b == 1)
        .map(|&(_, _, index_a, index_b)| (index_a, index_b))
        .collect();
    pairs.sort_unstable();
    longest_increasing(&pairs)
}

/// Longest subsequence of `pairs` (already sorted by A) increasing in B.
fn longest_increasing(pairs: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut tails: Vec<usize> = Vec::new(); // index into pairs of the smallest tail per length
    let mut previous: Vec<Option<usize>> = vec![None; pairs.len()];
    for (index, &(_, b)) in pairs.iter().enumerate() {
        let position = tails.partition_point(|&tail| pairs[tail].1 < b);
        previous[index] = position.checked_sub(1).map(|p| tails[p]);
        if position == tails.len() {
            tails.push(index);
        } else {
            tails[position] = index;
        }
    }
    let mut result = Vec::with_capacity(tails.len());
    let mut cursor = tails.last().copied();
    while let Some(index) = cursor {
        result.push(pairs[index]);
        cursor = previous[index];
    }
    result.reverse();
    result
}

// ---------------------------------------------------------------------------
// Byte-wise extension
// ---------------------------------------------------------------------------

const COMPARE_BLOCK: usize = 4096;

/// Length of the common run starting at `a_start` / `b_start`.
fn common_prefix(a: &mut Document, b: &mut Document, a_start: usize, b_start: usize) -> usize {
    let limit = a.len().saturating_sub(a_start).min(b.len().saturating_sub(b_start));
    let mut matched = 0;
    let (mut block_a, mut block_b) = (vec![0u8; COMPARE_BLOCK], vec![0u8; COMPARE_BLOCK]);
    while matched < limit {
        let len = COMPARE_BLOCK.min(limit - matched);
        a.read_into(a_start + matched, &mut block_a[..len]);
        b.read_into(b_start + matched, &mut block_b[..len]);
        match block_a[..len].iter().zip(&block_b[..len]).position(|(x, y)| x != y) {
            Some(mismatch) => return matched + mismatch,
            None => matched += len,
        }
    }
    matched
}

/// Length of the common run ending at `a_end` / `b_end`, not reaching back
/// before `a_floor` / `b_floor`.
fn common_suffix(a: &mut Document, b: &mut Document, a_floor: usize, a_end: usize, b_floor: usize, b_end: usize) -> usize {
    let limit = a_end.saturating_sub(a_floor).min(b_end.saturating_sub(b_floor));
    let mut matched = 0;
    let (mut block_a, mut block_b) = (vec![0u8; COMPARE_BLOCK], vec![0u8; COMPARE_BLOCK]);
    while matched < limit {
        let len = COMPARE_BLOCK.min(limit - matched);
        a.read_into(a_end - matched - len, &mut block_a[..len]);
        b.read_into(b_end - matched - len, &mut block_b[..len]);
        match block_a[..len].iter().rev().zip(block_b[..len].iter().rev()).position(|(x, y)| x != y) {
            Some(mismatch) => return matched + mismatch,
            None => matched += len,
        }
    }
    matched
}

// ---------------------------------------------------------------------------
// Building the edit script
// ---------------------------------------------------------------------------

struct Builder {
    limits: DiffLimits,
    result: DiffResult,
}

impl Builder {
    fn new(limits: DiffLimits) -> Self {
        Builder { limits, result: DiffResult::default() }
    }

    fn full(&self) -> bool {
        self.result.truncated
    }

    fn push(&mut self, op: DiffOp) {
        if self.result.ops.len() >= self.limits.max_ops {
            self.result.truncated = true;
            return;
        }
        // Merge with the previous operation when they continue each other.
        if let Some(last) = self.result.ops.last_mut() {
            match (last, op) {
                (DiffOp::Equal { a, len, .. }, DiffOp::Equal { a: next_a, len: more, .. }) if *a + *len == next_a => {
                    *len += more;
                    return;
                }
                (DiffOp::Replace { a, a_len, b, b_len }, DiffOp::Replace { a: next_a, a_len: more_a, b: next_b, b_len: more_b })
                    if *a + *a_len == next_a && *b + *b_len == next_b =>
                {
                    *a_len += more_a;
                    *b_len += more_b;
                    return;
                }
                _ => {}
            }
        }
        self.result.ops.push(op);
    }

    fn equal(&mut self, a: usize, b: usize, len: usize) {
        if len > 0 {
            self.result.equal_bytes += len;
            self.push(DiffOp::Equal { a, b, len });
        }
    }

    /// Classify the bytes between two matches.
    fn gap(&mut self, a_doc: &mut Document, b_doc: &mut Document, a_start: usize, a_end: usize, b_start: usize, b_end: usize) {
        let (a_len, b_len) = (a_end.saturating_sub(a_start), b_end.saturating_sub(b_start));
        match (a_len, b_len) {
            (0, 0) => {}
            (0, len) => {
                self.result.changed_bytes += len;
                self.push(DiffOp::Insert { b: b_start, len });
            }
            (len, 0) => {
                self.result.changed_bytes += len;
                self.push(DiffOp::Delete { a: a_start, len });
            }
            (a_len, b_len) if a_len == b_len && a_len <= self.limits.byte_compare_gap => {
                let left = a_doc.read_range(a_start, a_len);
                let right = b_doc.read_range(b_start, b_len);
                self.compare_equal_length(&left, &right, a_start, b_start);
            }
            (a_len, b_len) => {
                self.result.changed_bytes += a_len.max(b_len);
                self.push(DiffOp::Replace { a: a_start, a_len, b: b_start, b_len });
            }
        }
    }

    /// Split an equal-length gap into runs of equal and changed bytes.
    /// Equal runs shorter than four bytes are folded into the change, which
    /// keeps a scattered edit as one readable block.
    fn compare_equal_length(&mut self, left: &[u8], right: &[u8], a_start: usize, b_start: usize) {
        const MIN_EQUAL_RUN: usize = 4;
        let mut index = 0;
        while index < left.len() {
            let same = left[index..].iter().zip(&right[index..]).take_while(|(x, y)| x == y).count();
            if same >= MIN_EQUAL_RUN || index + same == left.len() {
                self.equal(a_start + index, b_start + index, same);
                index += same;
                continue;
            }
            // A change, absorbing short equal runs inside it.
            let mut end = index + same.max(1);
            while end < left.len() {
                let run = left[end..].iter().zip(&right[end..]).take_while(|(x, y)| x == y).count();
                if run >= MIN_EQUAL_RUN {
                    break;
                }
                end += run.max(1);
            }
            let len = end - index;
            self.result.changed_bytes += len;
            self.push(DiffOp::Replace { a: a_start + index, a_len: len, b: b_start + index, b_len: len });
            index = end;
        }
    }

    fn finish(self) -> DiffResult {
        self.result
    }
}

// ---------------------------------------------------------------------------
// Aligned scrolling
// ---------------------------------------------------------------------------

/// The offset in B that corresponds to `a_offset` in A.
pub fn aligned_offset(ops: &[DiffOp], a_offset: usize) -> Option<usize> {
    let mut b_cursor = 0usize;
    for op in ops {
        match *op {
            DiffOp::Equal { a, b, len } => {
                if (a..a + len).contains(&a_offset) {
                    return Some(b + (a_offset - a));
                }
                b_cursor = b + len;
            }
            DiffOp::Replace { a, a_len, b, b_len } => {
                if (a..a + a_len).contains(&a_offset) {
                    return Some(b + (a_offset - a).min(b_len.saturating_sub(1)));
                }
                b_cursor = b + b_len;
            }
            DiffOp::Insert { b, len } => b_cursor = b + len,
            DiffOp::Delete { a, len } => {
                if (a..a + len).contains(&a_offset) {
                    return Some(b_cursor);
                }
            }
        }
    }
    None
}

/// The offset in A that corresponds to `b_offset` in B.
pub fn aligned_offset_b_to_a(ops: &[DiffOp], b_offset: usize) -> Option<usize> {
    let mut a_cursor = 0usize;
    for op in ops {
        match *op {
            DiffOp::Equal { a, b, len } => {
                if (b..b + len).contains(&b_offset) {
                    return Some(a + (b_offset - b));
                }
                a_cursor = a + len;
            }
            DiffOp::Replace { a, a_len, b, b_len } => {
                if (b..b + b_len).contains(&b_offset) {
                    return Some(a + (b_offset - b).min(a_len.saturating_sub(1)));
                }
                a_cursor = a + a_len;
            }
            DiffOp::Delete { a, len } => a_cursor = a + len,
            DiffOp::Insert { b, len } => {
                if (b..b + len).contains(&b_offset) {
                    return Some(a_cursor);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }

    fn run(a: &[u8], b: &[u8]) -> DiffResult {
        let mut doc_a = Document::from_bytes(a.to_vec());
        let mut doc_b = Document::from_bytes(b.to_vec());
        diff(&mut doc_a, &mut doc_b, DiffLimits::default())
    }

    #[test]
    fn identical_documents_are_one_equal_run() {
        let data = noise(10_000, 1);
        let result = run(&data, &data);
        assert_eq!(result.ops, vec![DiffOp::Equal { a: 0, b: 0, len: 10_000 }]);
        assert_eq!((result.equal_bytes, result.changed_bytes), (10_000, 0));
    }

    #[test]
    fn a_single_flipped_byte_is_a_one_byte_replacement() {
        let a = noise(10_000, 2);
        let mut b = a.clone();
        b[5000] ^= 0xFF;
        let result = run(&a, &b);
        assert_eq!(
            result.ops,
            vec![
                DiffOp::Equal { a: 0, b: 0, len: 5000 },
                DiffOp::Replace { a: 5000, a_len: 1, b: 5000, b_len: 1 },
                DiffOp::Equal { a: 5001, b: 5001, len: 4999 },
            ]
        );
    }

    #[test]
    fn an_insertion_is_found_with_exact_offsets() {
        let a = noise(64 * 1024, 3);
        let inserted = noise(100, 99);
        let at = 30_000;
        let mut b = a[..at].to_vec();
        b.extend_from_slice(&inserted);
        b.extend_from_slice(&a[at..]);
        let result = run(&a, &b);
        // Ambiguity is only possible if inserted bytes happen to repeat their
        // neighbours; this seed avoids that.
        assert_eq!(
            result.ops,
            vec![
                DiffOp::Equal { a: 0, b: 0, len: at },
                DiffOp::Insert { b: at, len: 100 },
                DiffOp::Equal { a: at, b: at + 100, len: a.len() - at },
            ]
        );
        assert_eq!(aligned_offset(&result.ops, at + 10), Some(at + 110));
        assert_eq!(aligned_offset(&result.ops, 10), Some(10));
        assert_eq!(aligned_offset_b_to_a(&result.ops, at + 50), Some(at));
        assert_eq!(aligned_offset_b_to_a(&result.ops, at + 150), Some(at + 50));
    }

    #[test]
    fn a_deleted_block_is_a_delete() {
        let a = noise(40_000, 4);
        let mut b = a[..10_000].to_vec();
        b.extend_from_slice(&a[12_000..]);
        let result = run(&a, &b);
        assert_eq!(
            result.ops,
            vec![
                DiffOp::Equal { a: 0, b: 0, len: 10_000 },
                DiffOp::Delete { a: 10_000, len: 2000 },
                DiffOp::Equal { a: 12_000, b: 10_000, len: 28_000 },
            ]
        );
        assert_eq!(aligned_offset(&result.ops, 11_000), Some(10_000));
    }

    #[test]
    fn a_moved_block_shows_as_a_delete_and_an_insert() {
        let a = noise(40_000, 5);
        let block = a[5000..8000].to_vec();
        let mut b = a[..5000].to_vec();
        b.extend_from_slice(&a[8000..30_000]);
        b.extend_from_slice(&block);
        b.extend_from_slice(&a[30_000..]);
        let result = run(&a, &b);
        let deleted: usize = result.ops.iter().map(|op| match op { DiffOp::Delete { len, .. } => *len, DiffOp::Replace { a_len, .. } => *a_len, _ => 0 }).sum();
        let inserted: usize = result.ops.iter().map(|op| match op { DiffOp::Insert { len, .. } => *len, DiffOp::Replace { b_len, .. } => *b_len, _ => 0 }).sum();
        assert_eq!((deleted, inserted), (3000, 3000), "{:?}", result.ops);
        assert_eq!(result.equal_bytes, 37_000);
    }

    #[test]
    fn repeated_content_and_size_changes_are_handled() {
        // Zero padding has no unique chunks; extension still matches it.
        let mut a = vec![0u8; 20_000];
        a.extend_from_slice(&noise(5000, 6));
        let mut b = a.clone();
        b.extend_from_slice(b"tail");
        let result = run(&a, &b);
        assert_eq!(result.ops.last(), Some(&DiffOp::Insert { b: a.len(), len: 4 }));
        assert_eq!(result.equal_bytes, a.len());
        // Empty documents.
        assert!(run(&[], &[]).ops.is_empty());
        assert_eq!(run(&[], b"abc").ops, vec![DiffOp::Insert { b: 0, len: 3 }]);
    }

    #[test]
    fn the_op_limit_truncates() {
        let a = noise(20_000, 7);
        let mut b = a.clone();
        for k in (0..b.len()).step_by(100) {
            b[k] ^= 1;
        }
        let mut doc_a = Document::from_bytes(a);
        let mut doc_b = Document::from_bytes(b);
        let result = diff(&mut doc_a, &mut doc_b, DiffLimits { max_ops: 10, ..DiffLimits::default() });
        assert!(result.truncated);
        assert_eq!(result.ops.len(), 10);
    }
}
