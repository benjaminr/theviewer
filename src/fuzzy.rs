//! Fuzzy hashing and shared-fragment matching.
//!
//! Two ways of asking "how much of this file is in that one":
//!
//! * **ssdeep-compatible fuzzy hashes** (context-triggered piecewise hashing,
//!   CTPH). A rolling hash over a seven-byte window decides where pieces end;
//!   each piece is summarised by one base64 character of an FNV-style hash.
//!   Two signatures are kept, at block sizes `b` and `2b`, and written as
//!   `b:first:second`. The output and the 0–100 comparison score follow
//!   ssdeep 2.14 (`fuzzy_hash_buf` and `fuzzy_compare`).
//! * **Shared fragments**: the aligned blocks of one file are indexed and
//!   every offset of another file is checked against them with a rolling
//!   hash, so a chunk copied to a different (even unaligned) position is
//!   still found. Every candidate is confirmed byte for byte.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// ssdeep constants
// ---------------------------------------------------------------------------

/// Bytes in the rolling hash's window.
const ROLLING_WINDOW: usize = 7;
/// Smallest block size; block size `i` is `MIN_BLOCK_SIZE << i`.
const MIN_BLOCK_SIZE: u64 = 3;
/// Most characters in one signature.
const SPAMSUM_LENGTH: usize = 64;
/// Number of block sizes tracked at once.
const NUM_BLOCK_HASHES: usize = 31;
/// FNV prime used by the piece hash.
const HASH_PRIME: u32 = 0x0100_0193;
/// Starting value of the piece hash.
const HASH_INIT: u32 = 0x2802_1967;
/// The signature alphabet.
const BASE64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// Runs of identical characters longer than this are cut before comparing.
const MAX_REPEATED_CHARACTERS: usize = 3;
/// The best possible similarity score.
pub const MAX_SCORE: u32 = 100;

fn block_size_at(index: usize) -> u64 {
    MIN_BLOCK_SIZE << index
}

fn base64_char(hash: u32) -> u8 {
    BASE64_ALPHABET[(hash % 64) as usize]
}

fn piece_hash(byte: u8, hash: u32) -> u32 {
    hash.wrapping_mul(HASH_PRIME) ^ u32::from(byte)
}

// ---------------------------------------------------------------------------
// Rolling hash
// ---------------------------------------------------------------------------

/// The Adler-like rolling hash ssdeep uses to find piece boundaries.
#[derive(Default)]
struct RollingHash {
    window: [u8; ROLLING_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    count: usize,
}

impl RollingHash {
    fn push(&mut self, byte: u8) {
        let value = u32::from(byte);
        let slot = self.count % ROLLING_WINDOW;
        self.h2 = self.h2.wrapping_sub(self.h1).wrapping_add(ROLLING_WINDOW as u32 * value);
        self.h1 = self.h1.wrapping_add(value).wrapping_sub(u32::from(self.window[slot]));
        self.window[slot] = byte;
        self.count = self.count.wrapping_add(1);
        self.h3 = (self.h3 << 5) ^ value;
    }

    fn sum(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// The signature being built at one block size.
#[derive(Clone)]
struct BlockHash {
    /// Hash of the current piece.
    hash: u32,
    /// Hash of the current piece for the truncated (half-length) signature.
    half_hash: u32,
    /// Characters so far; the slot at `length` holds the latest character
    /// once the signature is full.
    digest: [u8; SPAMSUM_LENGTH],
    length: usize,
    /// Latest character of the truncated signature, or 0 for none.
    half_digest: u8,
}

impl BlockHash {
    fn new() -> Self {
        BlockHash { hash: HASH_INIT, half_hash: HASH_INIT, digest: [0; SPAMSUM_LENGTH], length: 0, half_digest: 0 }
    }
}

/// The state of ssdeep's single-pass engine (fuzzy.c, version 2.14).
struct FuzzyState {
    blocks: Vec<BlockHash>,
    /// Block sizes below this index can no longer be chosen and are dropped.
    first: usize,
    /// Block sizes from this index on have not started yet.
    end: usize,
    total_size: u64,
    roll: RollingHash,
    /// Hash of the piece after the last block size, once every size is in use.
    last_hash: Option<u32>,
}

impl FuzzyState {
    fn new(total_size: u64) -> Self {
        let mut blocks = Vec::with_capacity(NUM_BLOCK_HASHES);
        blocks.push(BlockHash::new());
        FuzzyState { blocks, first: 0, end: 1, total_size, roll: RollingHash::default(), last_hash: None }
    }

    /// Start the next block size, copying the running piece hashes.
    fn try_fork(&mut self) {
        let previous = &self.blocks[self.end - 1];
        if self.end < NUM_BLOCK_HASHES {
            let mut next = BlockHash::new();
            next.hash = previous.hash;
            next.half_hash = previous.half_hash;
            self.blocks.push(next);
            self.end += 1;
        } else if self.last_hash.is_none() {
            self.last_hash = Some(previous.hash);
        }
    }

    /// Drop the smallest block size once a larger one is certain to be used.
    fn try_reduce(&mut self) {
        if self.end - self.first < 2 {
            return;
        }
        if block_size_at(self.first).saturating_mul(SPAMSUM_LENGTH as u64) >= self.total_size {
            return;
        }
        if self.blocks[self.first + 1].length < SPAMSUM_LENGTH / 2 {
            return;
        }
        self.first += 1;
    }

    fn step(&mut self, byte: u8) {
        self.roll.push(byte);
        let rolling = u64::from(self.roll.sum());
        for block in &mut self.blocks[self.first..self.end] {
            block.hash = piece_hash(byte, block.hash);
            block.half_hash = piece_hash(byte, block.half_hash);
        }
        if let Some(last) = self.last_hash.as_mut() {
            *last = piece_hash(byte, *last);
        }
        let mut index = self.first;
        while index < self.end {
            let size = block_size_at(index);
            if rolling % size != size - 1 {
                break;
            }
            if self.blocks[index].length == 0 {
                self.try_fork();
            }
            let block = &mut self.blocks[index];
            block.digest[block.length] = base64_char(block.hash);
            block.half_digest = base64_char(block.half_hash);
            if block.length < SPAMSUM_LENGTH - 1 {
                block.length += 1;
                block.hash = HASH_INIT;
                if block.length < SPAMSUM_LENGTH / 2 {
                    block.half_hash = HASH_INIT;
                    block.half_digest = 0;
                }
            } else {
                self.try_reduce();
            }
            index += 1;
        }
    }

    fn digest(&self) -> FuzzyHash {
        let rolling = self.roll.sum();
        let mut index = self.first;
        while block_size_at(index).saturating_mul(SPAMSUM_LENGTH as u64) < self.total_size && index < NUM_BLOCK_HASHES - 1 {
            index += 1;
        }
        while index >= self.end {
            index -= 1;
        }
        while index > self.first && self.blocks[index].length < SPAMSUM_LENGTH / 2 {
            index -= 1;
        }

        let block = &self.blocks[index];
        let mut first = block.digest[..block.length].to_vec();
        if rolling != 0 {
            first.push(base64_char(block.hash));
        } else if block.length == SPAMSUM_LENGTH - 1 && block.digest[block.length] != 0 {
            first.push(block.digest[block.length]);
        }

        let mut second = Vec::new();
        if index + 1 < self.end {
            let next = &self.blocks[index + 1];
            let kept = next.length.min(SPAMSUM_LENGTH / 2 - 1);
            second.extend_from_slice(&next.digest[..kept]);
            if rolling != 0 {
                second.push(base64_char(next.half_hash));
            } else if next.half_digest != 0 {
                second.push(next.half_digest);
            }
        } else if rolling != 0 {
            let hash = if index == 0 { block.hash } else { self.last_hash.unwrap_or(block.hash) };
            second.push(base64_char(hash));
        }

        FuzzyHash {
            block_size: block_size_at(index),
            first: String::from_utf8_lossy(&first).into_owned(),
            second: String::from_utf8_lossy(&second).into_owned(),
        }
    }
}

/// An ssdeep fuzzy hash: `block_size:first:second`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FuzzyHash {
    pub block_size: u64,
    /// Signature at `block_size`, up to 64 characters.
    pub first: String,
    /// Signature at twice `block_size`, up to 32 characters.
    pub second: String,
}

impl fmt::Display for FuzzyHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}:{}", self.block_size, self.first, self.second)
    }
}

/// Why a fuzzy hash's text could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FuzzyHashParseError {
    /// Not three parts separated by colons.
    WrongShape(String),
    /// The block size is not a number ssdeep could produce.
    BadBlockSize(String),
    /// A signature holds a character outside the base64 alphabet.
    BadCharacter(char),
    /// A signature is longer than ssdeep ever writes.
    TooLong(usize),
}

impl fmt::Display for FuzzyHashParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzyHashParseError::WrongShape(text) => write!(formatter, "'{text}' is not a fuzzy hash; expected blocksize:signature:signature"),
            FuzzyHashParseError::BadBlockSize(text) => write!(formatter, "'{text}' is not a valid ssdeep block size (3, 6, 12, …)"),
            FuzzyHashParseError::BadCharacter(character) => write!(formatter, "'{character}' cannot appear in a fuzzy hash signature"),
            FuzzyHashParseError::TooLong(length) => write!(formatter, "a signature of {length} characters is longer than ssdeep writes ({SPAMSUM_LENGTH})"),
        }
    }
}

impl std::error::Error for FuzzyHashParseError {}

impl FromStr for FuzzyHash {
    type Err = FuzzyHashParseError;

    /// Read `blocksize:first:second`. A `,"filename"` suffix, as the ssdeep
    /// command line prints it, is ignored.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let wrong_shape = || FuzzyHashParseError::WrongShape(text.to_string());
        let mut parts = text.splitn(3, ':');
        let (Some(size_text), Some(first), Some(rest)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(wrong_shape());
        };
        let second = rest.split(',').next().unwrap_or("");
        let block_size: u64 = size_text.parse().map_err(|_| FuzzyHashParseError::BadBlockSize(size_text.to_string()))?;
        let is_valid_size = (0..NUM_BLOCK_HASHES).any(|index| block_size_at(index) == block_size);
        if !is_valid_size {
            return Err(FuzzyHashParseError::BadBlockSize(size_text.to_string()));
        }
        for signature in [first, second] {
            if signature.len() > SPAMSUM_LENGTH {
                return Err(FuzzyHashParseError::TooLong(signature.len()));
            }
            if let Some(bad) = signature.chars().find(|c| !c.is_ascii() || !BASE64_ALPHABET.contains(&(*c as u8))) {
                return Err(FuzzyHashParseError::BadCharacter(bad));
            }
        }
        Ok(FuzzyHash { block_size, first: first.to_string(), second: second.to_string() })
    }
}

/// The ssdeep fuzzy hash of `data`, as `ssdeep` would print it for a file
/// holding exactly these bytes.
pub fn fuzzy_hash(data: &[u8]) -> FuzzyHash {
    let mut state = FuzzyState::new(data.len() as u64);
    for &byte in data {
        state.step(byte);
    }
    state.digest()
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

/// Similarity of two fuzzy hashes, 0 (nothing in common) to 100 (identical
/// or nearly so), as `ssdeep -d` and `fuzzy_compare` report it.
pub fn compare(a: &FuzzyHash, b: &FuzzyHash) -> u32 {
    let (size_a, size_b) = (a.block_size, b.block_size);
    let comparable = size_a == size_b || size_a.checked_mul(2) == Some(size_b) || size_b.checked_mul(2) == Some(size_a);
    if !comparable {
        return 0;
    }
    let a_first = without_long_runs(a.first.as_bytes());
    let a_second = without_long_runs(a.second.as_bytes());
    let b_first = without_long_runs(b.first.as_bytes());
    let b_second = without_long_runs(b.second.as_bytes());

    if size_a == size_b && a_first == b_first && a_second == b_second {
        return MAX_SCORE;
    }
    if size_a == size_b {
        let first_score = score_signatures(&a_first, &b_first, size_a);
        let second_score = score_signatures(&a_second, &b_second, size_a.saturating_mul(2));
        first_score.max(second_score)
    } else if size_a.checked_mul(2) == Some(size_b) {
        score_signatures(&b_first, &a_second, size_b)
    } else {
        score_signatures(&a_first, &b_second, size_a)
    }
}

/// Compare two fuzzy hashes given as text.
pub fn compare_text(a: &str, b: &str) -> Result<u32, FuzzyHashParseError> {
    Ok(compare(&a.parse()?, &b.parse()?))
}

/// Keep at most three of any run of the same character.
fn without_long_runs(signature: &[u8]) -> Vec<u8> {
    let mut kept: Vec<u8> = Vec::with_capacity(signature.len());
    for &character in signature {
        let run = kept.iter().rev().take_while(|&&previous| previous == character).count();
        if run < MAX_REPEATED_CHARACTERS {
            kept.push(character);
        }
    }
    kept
}

/// ssdeep's `score_strings`: edit distance scaled to 0–100, zero unless the
/// signatures share a run of seven characters, and capped for small blocks
/// so that tiny inputs cannot claim a high match.
fn score_signatures(a: &[u8], b: &[u8], block_size: u64) -> u32 {
    if a.len() > SPAMSUM_LENGTH || b.len() > SPAMSUM_LENGTH {
        return 0;
    }
    if !has_common_substring(a, b) {
        return 0;
    }
    let distance = edit_distance(a, b) as u64;
    let scaled = distance * SPAMSUM_LENGTH as u64 / (a.len() + b.len()) as u64;
    let percent = 100 * scaled / SPAMSUM_LENGTH as u64;
    if percent >= u64::from(MAX_SCORE) {
        return 0;
    }
    let score = u64::from(MAX_SCORE) - percent;
    let cap = (block_size / MIN_BLOCK_SIZE).saturating_mul(a.len().min(b.len()) as u64);
    score.min(cap) as u32
}

/// Whether the signatures share any run of [`ROLLING_WINDOW`] characters.
fn has_common_substring(a: &[u8], b: &[u8]) -> bool {
    if a.len() < ROLLING_WINDOW || b.len() < ROLLING_WINDOW {
        return false;
    }
    a.windows(ROLLING_WINDOW).any(|window| b.windows(ROLLING_WINDOW).any(|other| other == window))
}

/// Edit distance with insertions and deletions costing 1 and a substitution
/// costing 2, as ssdeep's `edit_distn`.
fn edit_distance(a: &[u8], b: &[u8]) -> usize {
    const INSERT_COST: usize = 1;
    const REMOVE_COST: usize = 1;
    const REPLACE_COST: usize = 2;
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0; b.len() + 1];
    for (i, &left) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, &right) in b.iter().enumerate() {
            let replace = previous[j] + if left == right { 0 } else { REPLACE_COST };
            let remove = previous[j + 1] + REMOVE_COST;
            let insert = current[j] + INSERT_COST;
            current[j + 1] = replace.min(remove).min(insert);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

// ---------------------------------------------------------------------------
// Shared fragments
// ---------------------------------------------------------------------------

/// Default block size for fragment matching: one disk sector.
pub const DEFAULT_FRAGMENT_BLOCK: usize = 512;
/// Most offsets remembered for blocks with identical contents.
const MAX_OFFSETS_PER_BLOCK: usize = 8;
/// Most block matches collected before merging, to bound time and memory on
/// highly repetitive data.
const MAX_BLOCK_MATCHES: usize = 200_000;
/// Multiplier of the polynomial rolling hash (odd, so no bits are lost).
const ROLLING_MULTIPLIER: u64 = 0x0000_0100_0000_01B3;
/// Bits in the quick-rejection filter (a power of two).
const FILTER_BITS: usize = 1 << 20;

/// Why blocks could not be indexed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FragmentError {
    /// A block size of zero.
    ZeroBlockSize,
}

impl fmt::Display for FragmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FragmentError::ZeroBlockSize => write!(formatter, "the fragment block size must be at least one byte"),
        }
    }
}

impl std::error::Error for FragmentError {}

/// A run of bytes found in both files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedFragment {
    /// Where the run starts in the indexed file (always block aligned).
    pub offset_here: usize,
    /// Where the same bytes start in the other file.
    pub offset_there: usize,
    /// Length in bytes, a whole number of blocks.
    pub len: usize,
}

/// The aligned blocks of one file, ready to be looked for in others.
pub struct BlockIndex<'a> {
    data: &'a [u8],
    block_size: usize,
    /// Rolling hash of a block to the offsets of blocks with that hash.
    blocks: HashMap<u64, Vec<usize>>,
    /// One bit per hash bucket, to skip most lookups cheaply.
    filter: Vec<u64>,
    /// `ROLLING_MULTIPLIER` to the power `block_size`, for removing a byte.
    outgoing_factor: u64,
}

impl<'a> BlockIndex<'a> {
    /// Index every aligned block of `data` except trivial ones (every byte
    /// the same, such as zero or 0xFF fill). A partial block at the end is
    /// left out.
    pub fn new(data: &'a [u8], block_size: usize) -> Result<Self, FragmentError> {
        if block_size == 0 {
            return Err(FragmentError::ZeroBlockSize);
        }
        let mut blocks: HashMap<u64, Vec<usize>> = HashMap::new();
        let mut filter = vec![0u64; FILTER_BITS / 64];
        for (index, block) in data.chunks_exact(block_size).enumerate() {
            if is_trivial_block(block) {
                continue;
            }
            let hash = rolling_hash_of(block);
            let offsets = blocks.entry(hash).or_default();
            if offsets.len() < MAX_OFFSETS_PER_BLOCK {
                offsets.push(index * block_size);
            }
            set_filter_bit(&mut filter, hash);
        }
        let outgoing_factor = (0..block_size).fold(1u64, |power, _| power.wrapping_mul(ROLLING_MULTIPLIER));
        Ok(BlockIndex { data, block_size, blocks, filter, outgoing_factor })
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Number of distinct non-trivial blocks indexed.
    pub fn indexed_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Every run of indexed blocks that also occurs in `other`, at any
    /// offset there. Adjacent blocks found next to each other in `other` are
    /// merged into one fragment. Sorted by offset in the indexed file.
    pub fn find_in(&self, other: &[u8]) -> Vec<SharedFragment> {
        let matches = self.block_matches(other);
        merge_block_matches(matches, self.block_size)
    }

    /// Pairs of (offset here, offset there) of identical blocks.
    fn block_matches(&self, other: &[u8]) -> Vec<(usize, usize)> {
        let size = self.block_size;
        let mut matches = Vec::new();
        if self.blocks.is_empty() || other.len() < size {
            return matches;
        }
        let mut hash = rolling_hash_of(&other[..size]);
        let mut start = 0;
        loop {
            if filter_has(&self.filter, hash) {
                self.collect_matches_at(other, start, hash, &mut matches);
                if matches.len() >= MAX_BLOCK_MATCHES {
                    break;
                }
            }
            let next = start + size;
            if next >= other.len() {
                break;
            }
            hash = hash
                .wrapping_mul(ROLLING_MULTIPLIER)
                .wrapping_sub(u64::from(other[start]).wrapping_mul(self.outgoing_factor))
                .wrapping_add(u64::from(other[next]));
            start += 1;
        }
        matches
    }

    fn collect_matches_at(&self, other: &[u8], start: usize, hash: u64, matches: &mut Vec<(usize, usize)>) {
        let Some(offsets) = self.blocks.get(&hash) else { return };
        let window = &other[start..start + self.block_size];
        for &offset in offsets {
            if &self.data[offset..offset + self.block_size] == window {
                matches.push((offset, start));
            }
        }
    }
}

/// Every byte of the block is the same.
fn is_trivial_block(block: &[u8]) -> bool {
    block.iter().all(|&byte| byte == block[0])
}

fn rolling_hash_of(block: &[u8]) -> u64 {
    block.iter().fold(0u64, |hash, &byte| hash.wrapping_mul(ROLLING_MULTIPLIER).wrapping_add(u64::from(byte)))
}

fn filter_slot(hash: u64) -> (usize, u64) {
    // The high bits are the best mixed by the multiplication.
    let bit = (hash >> 40) as usize % FILTER_BITS;
    (bit / 64, 1u64 << (bit % 64))
}

fn set_filter_bit(filter: &mut [u64], hash: u64) {
    let (word, mask) = filter_slot(hash);
    filter[word] |= mask;
}

fn filter_has(filter: &[u64], hash: u64) -> bool {
    let (word, mask) = filter_slot(hash);
    filter[word] & mask != 0
}

/// Join block matches that continue each other in both files.
fn merge_block_matches(mut matches: Vec<(usize, usize)>, block_size: usize) -> Vec<SharedFragment> {
    // Group by diagonal (the shift between the files), then by position.
    matches.sort_by_key(|&(here, there)| (there as i128 - here as i128, here));
    let mut fragments: Vec<SharedFragment> = Vec::new();
    for (here, there) in matches {
        if let Some(last) = fragments.last_mut()
            && last.offset_here + last.len == here
            && last.offset_there + last.len == there
        {
            last.len += block_size;
            continue;
        }
        fragments.push(SharedFragment { offset_here: here, offset_there: there, len: block_size });
    }
    fragments.sort_by_key(|fragment| (fragment.offset_here, fragment.offset_there));
    fragments
}

/// Shared fragments between `here` and `other`, indexing `here` in blocks of
/// `block_size` bytes.
pub fn shared_fragments(here: &[u8], other: &[u8], block_size: usize) -> Result<Vec<SharedFragment>, FragmentError> {
    Ok(BlockIndex::new(here, block_size)?.find_in(other))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes the reference values below were computed from: a 32-bit
    /// linear congruential generator, taking bits 16..24 of each state.
    fn lcg_bytes(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (state >> 16) as u8
            })
            .collect()
    }

    /// Reference hashes computed with an independent ssdeep implementation
    /// (ppdeep), which agrees with the ssdeep command line.
    #[test]
    fn hashes_match_reference_ssdeep_values() {
        let cases: &[(usize, &str)] = &[
            (0, "3::"),
            (1, "3:s:s"),
            (7, "3:5gIn:+I"),
            (100, "3:5gId8IfbB3vaQayyjaOCn/HnNyAZEn:+2VlywyjaBNyv"),
            (1000, "24:qZi8XAcC+BNPiILGFioWEmsijJ7rxu0U7fHZnrh/pQ:q8MAcCqliIwRsJxO7f5rk"),
            (4096, "96:vhBjfok5rzZlBkbS+DoYf+iSOZoSfx2mX0hcMwgzYJw:3j1HPBaS+DoYdb6S52hhcWzYJw"),
            (10_000, "192:3j1HPBaS+DoYdb6S52hhcWzYJ/tQsvzV6R94Nm2BLZSG1TiHGfZsmL2:3jfgDoAOJhPzYV9xPXBNSsTIsZLL2"),
            (65_536, "1536:3ju9hDO9upE3F7dZJyURgJ8WZI/5XFbIZ5:3oDeuq3FXJy9rehVbW5"),
            (100_000, "1536:3ju9hDO9upE3F7dZJyURgJ8WZI/5XFbIZVBCZ1gMHp8hWA3YOI6m:3oDeuq3FXJy9rehVbWV0lGhWA3YOY"),
            (1_000_000, "24576:3O7obeKS5aNn4XKh1r4GSMYTxu+iJFLwEcLR7SRZ:3EobeKoaNjLvQALwEqR7SRZ"),
        ];
        for &(len, expected) in cases {
            assert_eq!(fuzzy_hash(&lcg_bytes(len, 42)).to_string(), expected, "{len} bytes");
        }
    }

    #[test]
    fn hashes_of_repetitive_inputs_match_reference_ssdeep_values() {
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(1000);
        assert_eq!(fuzzy_hash(&text).to_string(), format!("12:Fg{}J:F1", "6".repeat(61)));
        assert_eq!(fuzzy_hash(&vec![0u8; 50_000]).to_string(), "3::");
        let ramp: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
        assert_eq!(fuzzy_hash(&ramp).to_string(), format!("192:z{}7:H", "n".repeat(62)));
    }

    /// Compares with the `ssdeep` command line when it is installed.
    #[test]
    fn hashes_agree_with_the_ssdeep_command_line_when_installed() {
        let Ok(output) = std::process::Command::new("ssdeep").arg("-V").output() else {
            eprintln!("ssdeep is not installed; skipping");
            return;
        };
        if !output.status.success() {
            return;
        }
        let directory = std::env::temp_dir().join(format!("theviewer-fuzzy-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        for len in [0usize, 100, 5000, 300_000] {
            let data = lcg_bytes(len, 7);
            let path = directory.join(format!("sample-{len}.bin"));
            std::fs::write(&path, &data).unwrap();
            let output = std::process::Command::new("ssdeep").arg("-s").arg("-b").arg(&path).output().unwrap();
            let text = String::from_utf8_lossy(&output.stdout);
            // The first line is a header, "ssdeep,1.1--blocksize:hash:hash,filename".
            let line = text.lines().find(|line| !line.starts_with("ssdeep,") && line.contains(',')).expect("an ssdeep result line");
            let reference: FuzzyHash = line.parse().unwrap();
            assert_eq!(fuzzy_hash(&data), reference, "{len} bytes");
        }
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn identical_data_scores_one_hundred() {
        let data = lcg_bytes(50_000, 1);
        let hash = fuzzy_hash(&data);
        assert_eq!(compare(&hash, &hash), 100);
        assert_eq!(compare_text(&hash.to_string(), &hash.to_string()), Ok(100));
    }

    #[test]
    fn a_small_edit_still_scores_high() {
        let original = lcg_bytes(50_000, 1);
        let mut edited = original.clone();
        edited[25_000..25_100].fill(0x41);
        let score = compare(&fuzzy_hash(&original), &fuzzy_hash(&edited));
        assert!(score >= 80, "score {score}");
    }

    #[test]
    fn appending_data_keeps_a_meaningful_score_across_block_sizes() {
        let original = lcg_bytes(40_000, 3);
        let mut longer = original.clone();
        longer.extend(lcg_bytes(40_000, 4));
        let (a, b) = (fuzzy_hash(&original), fuzzy_hash(&longer));
        assert_eq!(b.block_size, a.block_size * 2, "{a} / {b}");
        let score = compare(&a, &b);
        assert!(score > 0, "score {score}");
    }

    #[test]
    fn unrelated_data_scores_zero() {
        let a = fuzzy_hash(&lcg_bytes(50_000, 1));
        let b = fuzzy_hash(&lcg_bytes(50_000, 2));
        assert_eq!(compare(&a, &b), 0);
    }

    #[test]
    fn hashes_with_incompatible_block_sizes_score_zero() {
        assert_eq!(compare_text("3:abcdefghij:abc", "12:abcdefghij:abc"), Ok(0));
    }

    #[test]
    fn hash_text_round_trips_and_rejects_nonsense() {
        let hash = fuzzy_hash(&lcg_bytes(3000, 9));
        assert_eq!(hash.to_string().parse::<FuzzyHash>(), Ok(hash.clone()));
        let with_name: FuzzyHash = format!("{hash},\"/tmp/file\"").parse().unwrap();
        assert_eq!(with_name, hash);
        assert!(matches!("nonsense".parse::<FuzzyHash>(), Err(FuzzyHashParseError::WrongShape(_))));
        assert!(matches!("5:abc:def".parse::<FuzzyHash>(), Err(FuzzyHashParseError::BadBlockSize(_))));
        assert!(matches!("3:ab!:def".parse::<FuzzyHash>(), Err(FuzzyHashParseError::BadCharacter('!'))));
    }

    #[test]
    fn long_runs_of_one_character_are_cut_to_three() {
        assert_eq!(without_long_runs(b"AAAAABBBCDDDD"), b"AAABBBCDDD".to_vec());
    }

    #[test]
    fn edit_distance_counts_a_substitution_as_two() {
        assert_eq!(edit_distance(b"abcdef", b"abcdef"), 0);
        assert_eq!(edit_distance(b"abcdef", b"abXdef"), 2);
        assert_eq!(edit_distance(b"abcdef", b"abdef"), 1);
        assert_eq!(edit_distance(b"", b"abc"), 3);
    }

    #[test]
    fn shared_chunk_is_found_at_different_offsets() {
        let chunk = lcg_bytes(8192, 77);
        let mut here = lcg_bytes(40_000, 10);
        let mut there = lcg_bytes(30_000, 11);
        let (at_here, at_there) = (4096, 12_345);
        here[at_here..at_here + chunk.len()].copy_from_slice(&chunk);
        there[at_there..at_there + chunk.len()].copy_from_slice(&chunk);

        let fragments = shared_fragments(&here, &there, DEFAULT_FRAGMENT_BLOCK).unwrap();
        assert_eq!(fragments, vec![SharedFragment { offset_here: at_here, offset_there: at_there, len: 8192 }]);
    }

    #[test]
    fn an_unaligned_chunk_is_found_as_its_whole_aligned_blocks() {
        let chunk = lcg_bytes(8192, 78);
        let mut here = lcg_bytes(40_000, 12);
        let there_prefix = lcg_bytes(777, 13);
        here[1000..1000 + chunk.len()].copy_from_slice(&chunk);
        let mut there = there_prefix;
        there.extend_from_slice(&chunk);

        let fragments = shared_fragments(&here, &there, DEFAULT_FRAGMENT_BLOCK).unwrap();
        // Blocks 1024..9216 of `here` lie wholly inside the chunk.
        assert_eq!(fragments, vec![SharedFragment { offset_here: 1024, offset_there: 777 + 24, len: 8192 - 512 }]);
    }

    #[test]
    fn zero_and_ff_fill_is_not_reported_as_shared() {
        let mut here = vec![0u8; 8192];
        here.extend(vec![0xFF; 8192]);
        let there = here.clone();
        assert!(shared_fragments(&here, &there, DEFAULT_FRAGMENT_BLOCK).unwrap().is_empty());
    }

    #[test]
    fn unrelated_files_share_nothing_and_odd_inputs_do_not_panic() {
        let here = lcg_bytes(20_000, 20);
        let there = lcg_bytes(20_000, 21);
        assert!(shared_fragments(&here, &there, 512).unwrap().is_empty());
        assert!(shared_fragments(&here, &[], 512).unwrap().is_empty());
        assert!(shared_fragments(&[], &there, 512).unwrap().is_empty());
        assert!(shared_fragments(&here[..100], &there, 512).unwrap().is_empty());
        assert_eq!(shared_fragments(&here, &there, 0), Err(FragmentError::ZeroBlockSize));
    }

    #[test]
    fn one_index_serves_several_other_files() {
        let here = lcg_bytes(16_384, 30);
        let index = BlockIndex::new(&here, 4096).unwrap();
        assert_eq!(index.indexed_blocks(), 4);
        let mut first = lcg_bytes(10_000, 31);
        first.extend_from_slice(&here[4096..8192]);
        let second = here[8192..].to_vec();
        assert_eq!(index.find_in(&first), vec![SharedFragment { offset_here: 4096, offset_there: 10_000, len: 4096 }]);
        assert_eq!(index.find_in(&second), vec![SharedFragment { offset_here: 8192, offset_there: 0, len: 8192 }]);
    }
}
