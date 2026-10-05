//! Repeated-block detection: the tell-tale of ECB-mode encryption.
//!
//! A block cipher in ECB mode encrypts equal plaintext blocks to equal
//! ciphertext blocks, so encrypted data with any repetition in its plaintext
//! (padding, headers, flat image areas) shows the same high-entropy 8- or
//! 16-byte block many times over. CBC, CTR, stream ciphers and compression
//! leave essentially no repeats: two random 16-byte blocks are equal by chance
//! with probability 2^-128.
//!
//! Low-entropy blocks (zero fill, text, counters) repeat naturally in plain
//! data, so only blocks that look random on their own are counted.

use std::collections::HashMap;

/// Block sizes examined: 8 (DES, 3DES, Blowfish) and 16 (AES and most others).
pub const BLOCK_SIZES: [usize; 2] = [8, 16];
/// Most bytes analysed; longer input is truncated.
pub const MAX_ANALYSED_BYTES: usize = 16 * 1024 * 1024;
/// Width of one region of the repeat map, unless the input is so long that
/// more than [`MAX_REGIONS`] regions would be needed.
pub const REGION_SIZE: usize = 4 * 1024;
/// Most regions in the repeat map.
pub const MAX_REGIONS: usize = 4096;
/// Most repeated blocks listed.
const TOP_REPEATS: usize = 20;
/// Most offsets kept for one repeated block.
const MAX_OFFSETS_PER_BLOCK: usize = 32;
/// Fewer high-entropy blocks than this are too few to judge.
const MIN_ELIGIBLE_BLOCKS: usize = 16;
/// Repeat ratio at or above which ECB is the likely explanation.
const ECB_RATIO: f64 = 0.01;
/// Fewest repeated blocks that count as more than coincidence or duplication.
const ECB_MIN_REPEATS: usize = 3;
/// A 16-byte layout is preferred when its repeat ratio is at least this share
/// of the 8-byte one (16-byte repeats always show as 8-byte repeats too).
const SIXTEEN_PREFERENCE: f64 = 0.8;

/// One repeated block value and where it occurs.
#[derive(Clone, Debug, PartialEq)]
pub struct RepeatedBlock {
    pub bytes: Vec<u8>,
    /// Total occurrences in the analysed range.
    pub count: usize,
    /// Absolute offsets of the first occurrences (at most 32).
    pub offsets: Vec<usize>,
}

/// Repetition measured for one block size and alignment.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LayoutScore {
    pub block_size: usize,
    /// Offset of the first block from the start of the range (0..block_size).
    pub alignment: usize,
    /// High-entropy blocks counted.
    pub eligible_blocks: usize,
    /// Eligible blocks equal to an earlier eligible block.
    pub repeated_blocks: usize,
}

impl LayoutScore {
    /// Share of eligible blocks that repeat an earlier one (0 to 1).
    pub fn repeat_ratio(&self) -> f64 {
        if self.eligible_blocks == 0 {
            return 0.0;
        }
        self.repeated_blocks as f64 / self.eligible_blocks as f64
    }
}

/// Repetition within one window of the range, for drawing as a strip.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RegionRepeat {
    /// Absolute offset of the region.
    pub offset: usize,
    pub len: usize,
    pub eligible_blocks: usize,
    /// Eligible blocks whose value occurs more than once anywhere in the range.
    pub repeated_blocks: usize,
}

impl RegionRepeat {
    /// Share of the region's high-entropy blocks that repeat, or `None` when
    /// the region has no high-entropy blocks at all.
    pub fn repeat_ratio(&self) -> Option<f32> {
        (self.eligible_blocks > 0).then(|| self.repeated_blocks as f32 / self.eligible_blocks as f32)
    }
}

/// What the repetition suggests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockVerdict {
    /// Many repeated high-entropy blocks of this size.
    LikelyEcb { block_size: usize },
    /// A few repeats: ECB with little plaintext repetition, or duplicated data.
    PossiblyEcb { block_size: usize },
    /// High-entropy data without repeats.
    NoRepetition,
    /// Too little high-entropy data to say.
    TooLittleData,
}

impl BlockVerdict {
    /// A sentence for the user.
    pub fn label(&self) -> String {
        match self {
            BlockVerdict::LikelyEcb { block_size } => format!("likely ECB-encrypted with a {block_size}-byte block cipher"),
            BlockVerdict::PossiblyEcb { block_size } => {
                format!("a few repeated {block_size}-byte blocks: ECB with little repetition in the plaintext, or duplicated data")
            }
            BlockVerdict::NoRepetition => "no repetition: CBC/CTR/stream or compressed".to_string(),
            BlockVerdict::TooLittleData => "too little high-entropy data to judge".to_string(),
        }
    }
}

/// Full result of [`analyse`].
#[derive(Clone, Debug, PartialEq)]
pub struct BlockReport {
    /// Absolute offset of the analysed range.
    pub start: usize,
    /// Bytes analysed (after truncation to [`MAX_ANALYSED_BYTES`]).
    pub analysed_len: usize,
    /// The layout with the most repetition.
    pub best: LayoutScore,
    /// Every block size and alignment tried.
    pub layouts: Vec<LayoutScore>,
    /// Most repeated blocks in the best layout, most frequent first.
    pub top_repeats: Vec<RepeatedBlock>,
    /// Repeat ratio along the range in the best layout.
    pub regions: Vec<RegionRepeat>,
    pub verdict: BlockVerdict,
}

/// Look for repeated high-entropy blocks in `bytes`, which start at absolute
/// offset `start`. Never panics; analyses at most [`MAX_ANALYSED_BYTES`].
pub fn analyse(bytes: &[u8], start: usize) -> BlockReport {
    let bytes = &bytes[..bytes.len().min(MAX_ANALYSED_BYTES)];
    let layouts: Vec<LayoutScore> = BLOCK_SIZES
        .iter()
        .flat_map(|&block_size| (0..block_size).map(move |alignment| (block_size, alignment)))
        .map(|(block_size, alignment)| score_layout(bytes, block_size, alignment))
        .collect();
    let best = choose_best_layout(&layouts);
    let counts = count_blocks(bytes, best.block_size, best.alignment);
    BlockReport {
        start,
        analysed_len: bytes.len(),
        top_repeats: top_repeats(bytes, start, best, &counts),
        regions: region_map(bytes, start, best, &counts),
        verdict: verdict_for(best),
        best,
        layouts,
    }
}

/// Whether a block looks random enough to be ciphertext: most of its bytes
/// distinct and not entirely printable text.
pub fn is_high_entropy_block(block: &[u8]) -> bool {
    if block.is_empty() {
        return false;
    }
    let mut seen = [false; 256];
    let mut distinct = 0;
    for &byte in block {
        if !seen[byte as usize] {
            seen[byte as usize] = true;
            distinct += 1;
        }
    }
    let all_printable = block.iter().all(|&byte| (0x20..0x7F).contains(&byte) || byte == b'\n' || byte == b'\r' || byte == b'\t');
    distinct * 4 >= block.len() * 3 && !all_printable
}

/// A block's bytes packed into a hashable key (blocks are at most 16 bytes).
fn block_key(block: &[u8]) -> u128 {
    block.iter().fold(0u128, |key, &byte| (key << 8) | byte as u128)
}

/// Iterate over the whole blocks of one layout as (offset in `bytes`, block).
fn blocks_of(bytes: &[u8], block_size: usize, alignment: usize) -> impl Iterator<Item = (usize, &[u8])> {
    let aligned = bytes.get(alignment..).unwrap_or(&[]);
    aligned.chunks_exact(block_size).enumerate().map(move |(index, block)| (alignment + index * block_size, block))
}

/// Occurrences of every high-entropy block value in one layout.
fn count_blocks(bytes: &[u8], block_size: usize, alignment: usize) -> HashMap<u128, usize> {
    let mut counts = HashMap::new();
    for (_, block) in blocks_of(bytes, block_size, alignment) {
        if is_high_entropy_block(block) {
            *counts.entry(block_key(block)).or_insert(0) += 1;
        }
    }
    counts
}

fn score_layout(bytes: &[u8], block_size: usize, alignment: usize) -> LayoutScore {
    let counts = count_blocks(bytes, block_size, alignment);
    let eligible_blocks: usize = counts.values().sum();
    LayoutScore { block_size, alignment, eligible_blocks, repeated_blocks: eligible_blocks - counts.len() }
}

/// The 8- or 16-byte layout with the highest repeat ratio, preferring 16
/// bytes when it explains nearly as much repetition.
fn choose_best_layout(layouts: &[LayoutScore]) -> LayoutScore {
    let best_of_size = |size: usize| {
        layouts
            .iter()
            .filter(|layout| layout.block_size == size)
            .copied()
            .max_by(|a, b| a.repeat_ratio().total_cmp(&b.repeat_ratio()).then(b.alignment.cmp(&a.alignment)))
            .unwrap_or(LayoutScore { block_size: size, alignment: 0, eligible_blocks: 0, repeated_blocks: 0 })
    };
    let eight = best_of_size(8);
    let sixteen = best_of_size(16);
    if sixteen.repeated_blocks > 0 && sixteen.repeat_ratio() >= eight.repeat_ratio() * SIXTEEN_PREFERENCE {
        sixteen
    } else if eight.repeated_blocks > 0 {
        eight
    } else {
        sixteen
    }
}

fn verdict_for(best: LayoutScore) -> BlockVerdict {
    if best.eligible_blocks < MIN_ELIGIBLE_BLOCKS {
        BlockVerdict::TooLittleData
    } else if best.repeated_blocks >= ECB_MIN_REPEATS && best.repeat_ratio() >= ECB_RATIO {
        BlockVerdict::LikelyEcb { block_size: best.block_size }
    } else if best.repeated_blocks > 0 {
        BlockVerdict::PossiblyEcb { block_size: best.block_size }
    } else {
        BlockVerdict::NoRepetition
    }
}

fn top_repeats(bytes: &[u8], start: usize, layout: LayoutScore, counts: &HashMap<u128, usize>) -> Vec<RepeatedBlock> {
    let mut repeated: Vec<(u128, usize)> = counts.iter().filter(|&(_, &count)| count > 1).map(|(&key, &count)| (key, count)).collect();
    repeated.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    repeated.truncate(TOP_REPEATS);
    let mut found: Vec<RepeatedBlock> =
        repeated.iter().map(|&(_, count)| RepeatedBlock { bytes: Vec::new(), count, offsets: Vec::new() }).collect();
    let index_of: HashMap<u128, usize> = repeated.iter().enumerate().map(|(index, &(key, _))| (key, index)).collect();
    for (offset, block) in blocks_of(bytes, layout.block_size, layout.alignment) {
        let Some(&index) = index_of.get(&block_key(block)) else { continue };
        let entry = &mut found[index];
        if entry.bytes.is_empty() {
            entry.bytes = block.to_vec();
        }
        if entry.offsets.len() < MAX_OFFSETS_PER_BLOCK {
            entry.offsets.push(start + offset);
        }
    }
    found
}

/// Region width for a range of `len` bytes.
fn region_size_for(len: usize) -> usize {
    REGION_SIZE.max(len.div_ceil(MAX_REGIONS))
}

fn region_map(bytes: &[u8], start: usize, layout: LayoutScore, counts: &HashMap<u128, usize>) -> Vec<RegionRepeat> {
    let region_size = region_size_for(bytes.len());
    let mut regions: Vec<RegionRepeat> = (0..bytes.len().div_ceil(region_size))
        .map(|index| {
            let offset = index * region_size;
            RegionRepeat { offset: start + offset, len: region_size.min(bytes.len() - offset), eligible_blocks: 0, repeated_blocks: 0 }
        })
        .collect();
    for (offset, block) in blocks_of(bytes, layout.block_size, layout.alignment) {
        if !is_high_entropy_block(block) {
            continue;
        }
        let region = &mut regions[offset / region_size];
        region.eligible_blocks += 1;
        if counts.get(&block_key(block)).is_some_and(|&count| count > 1) {
            region.repeated_blocks += 1;
        }
    }
    regions
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes (xorshift).
    fn noise(len: usize, seed: u32) -> Vec<u8> {
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

    /// ECB-like data: a stream of 16-byte blocks drawn from a small set.
    fn ecb_like(blocks: usize, block_size: usize, distinct: usize) -> Vec<u8> {
        let palette = noise(block_size * distinct, 7);
        let choices = noise(blocks, 99);
        let mut data = Vec::new();
        for &choice in &choices {
            let index = choice as usize % distinct;
            data.extend_from_slice(&palette[index * block_size..(index + 1) * block_size]);
        }
        data
    }

    #[test]
    fn ecb_like_sixteen_byte_blocks_are_flagged_as_ecb() {
        let report = analyse(&ecb_like(2000, 16, 40), 0);
        assert_eq!(report.verdict, BlockVerdict::LikelyEcb { block_size: 16 });
        assert_eq!(report.best.alignment, 0);
        assert!(report.best.repeat_ratio() > 0.9);
        assert!(report.top_repeats[0].count > 10);
    }

    #[test]
    fn eight_byte_cipher_blocks_are_told_apart_from_sixteen() {
        let report = analyse(&ecb_like(4000, 8, 30), 0);
        assert_eq!(report.verdict, BlockVerdict::LikelyEcb { block_size: 8 });
    }

    #[test]
    fn misaligned_ecb_data_is_found_at_its_alignment() {
        let mut data = vec![0u8; 5];
        data.extend(ecb_like(1000, 16, 20));
        let report = analyse(&data, 0x100);
        assert_eq!(report.best.alignment, 5);
        let first = &report.top_repeats[0];
        assert!(first.offsets.iter().all(|offset| (offset - 0x100 - 5) % 16 == 0));
    }

    #[test]
    fn random_data_shows_no_repetition() {
        let report = analyse(&noise(256 * 1024, 3), 0);
        assert_eq!(report.verdict, BlockVerdict::NoRepetition);
        assert!(report.top_repeats.is_empty());
    }

    #[test]
    fn zero_fill_and_text_are_not_mistaken_for_ecb() {
        let mut data = vec![0u8; 64 * 1024];
        data.extend(b"the quick brown fox jumps over the lazy dog ".repeat(500));
        let report = analyse(&data, 0);
        assert_eq!(report.verdict, BlockVerdict::TooLittleData);
    }

    #[test]
    fn region_map_marks_where_the_repeats_are() {
        let mut data = noise(8 * 1024, 5);
        data.extend(ecb_like(512, 16, 8));
        let report = analyse(&data, 0);
        let first = report.regions[0].repeat_ratio().unwrap_or(0.0);
        let last = report.regions.last().and_then(|region| region.repeat_ratio()).unwrap_or(0.0);
        assert!(first < 0.01, "random region ratio {first}");
        assert!(last > 0.9, "ECB region ratio {last}");
    }

    #[test]
    fn tiny_and_empty_inputs_never_panic() {
        for len in 0..40 {
            let report = analyse(&noise(len, 11), 0);
            assert_eq!(report.verdict, BlockVerdict::TooLittleData);
        }
    }
}
