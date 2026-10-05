//! Self-similarity dot plots: the data compared against itself.
//!
//! The range is cut into `N` equal blocks and cell `(row, col)` of an `N × N`
//! grid holds how alike block `row` and block `col` are, from 0 (nothing in
//! common) to 1 (the same). The diagonal is always 1. Content that repeats
//! shows up as lines parallel to the diagonal, and long runs of one kind of
//! data (padding, tables, text) as bright squares.
//!
//! Two measures are offered:
//! * [`SimilarityMode::KGrams`]: the estimated Jaccard similarity of the sets
//!   of 6-byte substrings (a one-permutation MinHash sketch per block). Blind
//!   to alignment, so repeats at any offset are found.
//! * [`SimilarityMode::Histogram`]: the cosine similarity of byte histograms,
//!   which groups blocks of the same *kind* of data even when the bytes differ.
//!
//! Large blocks are sampled (evenly spaced slices), so tens of megabytes
//! take a fraction of a second; sketches and rows are computed in parallel.

use rayon::prelude::*;

/// Most blocks along each side of the grid.
pub const MAX_CELLS: usize = 512;
/// Fewest bytes per block; smaller files get fewer cells.
pub const MIN_BLOCK_BYTES: usize = 32;
/// Fewest cells along a side for the plot to mean anything.
const MIN_CELLS: usize = 2;
/// Length of the substrings hashed in k-gram mode.
const K_GRAM_BYTES: usize = 6;
/// Bins in each MinHash sketch; a power of two so the bin is the top bits.
const SKETCH_BINS: usize = 64;
/// log2 of [`SKETCH_BINS`].
const SKETCH_BIN_BITS: u32 = 6;
/// Marker for a sketch bin that saw no k-gram.
const EMPTY_BIN: u32 = u32::MAX;
/// Bytes of each block actually examined; larger blocks are sampled.
const SAMPLE_BYTES_PER_BLOCK: usize = 16 * 1024;
/// Length of each contiguous slice taken when a block is sampled.
const SAMPLE_SLICE_BYTES: usize = 1024;
/// Distinct byte values, the length of a histogram.
const BYTE_VALUES: usize = 256;

/// How two blocks are compared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SimilarityMode {
    /// Shared 6-byte substrings (MinHash estimate of Jaccard similarity).
    #[default]
    KGrams,
    /// Cosine similarity of byte-value histograms.
    Histogram,
}

impl SimilarityMode {
    pub const ALL: [SimilarityMode; 2] = [SimilarityMode::KGrams, SimilarityMode::Histogram];

    pub fn label(self) -> &'static str {
        match self {
            SimilarityMode::KGrams => "Shared substrings",
            SimilarityMode::Histogram => "Byte histograms",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            SimilarityMode::KGrams => "Fraction of 6-byte substrings two blocks share; repeats show as diagonals",
            SimilarityMode::Histogram => "How alike the byte-value distributions are; groups blocks of the same kind of data",
        }
    }
}

/// A finished self-similarity grid.
#[derive(Clone, Debug, PartialEq)]
pub struct DotPlot {
    /// Document offset of the first block.
    pub start: usize,
    /// Bytes covered.
    pub len: usize,
    /// Blocks along each side; zero when the range was too short.
    pub cells: usize,
    /// Bytes per block (the last block may be shorter).
    pub block_size: usize,
    pub mode: SimilarityMode,
    /// Row-major `cells × cells` similarities in 0..=1.
    pub values: Vec<f32>,
}

impl DotPlot {
    /// Similarity of blocks `row` and `col`, or zero outside the grid.
    pub fn value(&self, row: usize, col: usize) -> f32 {
        if row >= self.cells || col >= self.cells {
            return 0.0;
        }
        self.values[row * self.cells + col]
    }

    /// Document offsets of the first byte of block `row` and of block `col`,
    /// or `None` outside the grid.
    pub fn cell_offsets(&self, row: usize, col: usize) -> Option<(usize, usize)> {
        if row >= self.cells || col >= self.cells {
            return None;
        }
        Some((self.block_offset(row), self.block_offset(col)))
    }

    /// Document offset of the first byte of block `index`.
    pub fn block_offset(&self, index: usize) -> usize {
        self.start + index * self.block_size
    }

    pub fn is_empty(&self) -> bool {
        self.cells == 0
    }
}

/// Blocks per side and bytes per block for a range of `len` bytes, or `None`
/// when the range is too short to plot.
pub fn grid_layout(len: usize) -> Option<(usize, usize)> {
    let wanted = (len / MIN_BLOCK_BYTES).min(MAX_CELLS);
    if wanted < MIN_CELLS {
        return None;
    }
    let block_size = len.div_ceil(wanted);
    let cells = len.div_ceil(block_size);
    (cells >= MIN_CELLS).then_some((cells, block_size))
}

/// Compare every block of `bytes` (which start at document offset `base`)
/// with every other. Safe on any input; a range too short to plot returns a
/// plot with zero cells.
pub fn compute(bytes: &[u8], base: usize, mode: SimilarityMode) -> DotPlot {
    let Some((cells, block_size)) = grid_layout(bytes.len()) else {
        return DotPlot { start: base, len: bytes.len(), cells: 0, block_size: 0, mode, values: Vec::new() };
    };
    let blocks: Vec<&[u8]> = bytes.chunks(block_size).collect();
    let values = match mode {
        SimilarityMode::KGrams => {
            let sketches: Vec<Sketch> = blocks.par_iter().map(|block| Sketch::of(block)).collect();
            similarity_grid(&sketches, Sketch::similarity)
        }
        SimilarityMode::Histogram => {
            let histograms: Vec<Histogram> = blocks.par_iter().map(|block| Histogram::of(block)).collect();
            similarity_grid(&histograms, Histogram::similarity)
        }
    };
    DotPlot { start: base, len: bytes.len(), cells, block_size, mode, values }
}

/// Fill a row-major grid by comparing every pair of block summaries.
fn similarity_grid<T: Sync>(summaries: &[T], similarity: impl Fn(&T, &T) -> f32 + Sync) -> Vec<f32> {
    summaries
        .par_iter()
        .flat_map_iter(|row| summaries.iter().map(|col| similarity(row, col).clamp(0.0, 1.0)).collect::<Vec<f32>>())
        .collect()
}

/// The parts of a block that are examined: all of it when small, otherwise
/// evenly spaced slices totalling [`SAMPLE_BYTES_PER_BLOCK`].
fn sampled_slices(block: &[u8]) -> Vec<&[u8]> {
    if block.len() <= SAMPLE_BYTES_PER_BLOCK {
        return vec![block];
    }
    let slices = SAMPLE_BYTES_PER_BLOCK / SAMPLE_SLICE_BYTES;
    let spacing = block.len() / slices;
    (0..slices)
        .map(|index| {
            let start = index * spacing;
            &block[start..(start + SAMPLE_SLICE_BYTES).min(block.len())]
        })
        .collect()
}

/// The SplitMix64 finaliser: spreads the bits of a k-gram evenly.
fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

/// One-permutation MinHash: each k-gram hash goes to the bin named by its top
/// bits, and each bin keeps the smallest value it has seen.
struct Sketch {
    bins: [u32; SKETCH_BINS],
}

impl Sketch {
    fn of(block: &[u8]) -> Sketch {
        let mut bins = [EMPTY_BIN; SKETCH_BINS];
        let mask = (1u64 << (8 * K_GRAM_BYTES)) - 1;
        for slice in sampled_slices(block) {
            let mut window = 0u64;
            for (index, &byte) in slice.iter().enumerate() {
                window = ((window << 8) | u64::from(byte)) & mask;
                if index + 1 < K_GRAM_BYTES {
                    continue;
                }
                let hash = mix(window);
                let bin = (hash >> (u64::BITS - SKETCH_BIN_BITS)) as usize;
                bins[bin] = bins[bin].min(hash as u32);
            }
        }
        Sketch { bins }
    }

    /// Fraction of bins used by either sketch in which both hold the same minimum.
    fn similarity(&self, other: &Sketch) -> f32 {
        let mut used = 0u32;
        let mut agreeing = 0u32;
        for (&a, &b) in self.bins.iter().zip(&other.bins) {
            if a == EMPTY_BIN && b == EMPTY_BIN {
                continue;
            }
            used += 1;
            if a == b {
                agreeing += 1;
            }
        }
        if used == 0 { 0.0 } else { agreeing as f32 / used as f32 }
    }
}

/// A byte histogram scaled to unit length, so a dot product is a cosine.
struct Histogram {
    unit: [f32; BYTE_VALUES],
}

impl Histogram {
    fn of(block: &[u8]) -> Histogram {
        let mut counts = [0f32; BYTE_VALUES];
        for slice in sampled_slices(block) {
            for &byte in slice {
                counts[usize::from(byte)] += 1.0;
            }
        }
        let length = counts.iter().map(|count| count * count).sum::<f32>().sqrt();
        if length > 0.0 {
            counts.iter_mut().for_each(|count| *count /= length);
        }
        Histogram { unit: counts }
    }

    fn similarity(&self, other: &Histogram) -> f32 {
        self.unit.iter().zip(&other.unit).map(|(a, b)| a * b).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn a_repeated_section_appears_as_an_off_diagonal_line() {
        let segment = 8 * 1024;
        let repeated = noise(segment, 1);
        let data = [repeated.clone(), noise(segment, 2), repeated, noise(segment, 3)].concat();
        let plot = compute(&data, 0, SimilarityMode::KGrams);
        assert_eq!(plot.cells, MAX_CELLS);
        let blocks_per_segment = segment / plot.block_size;
        for row in (0..blocks_per_segment).step_by(17) {
            assert!(plot.value(row, row + 2 * blocks_per_segment) > 0.9, "repeat at row {row}");
            assert!(plot.value(row, row + blocks_per_segment) < 0.1, "unrelated at row {row}");
        }
    }

    #[test]
    fn every_block_is_identical_to_itself() {
        let plot = compute(&noise(20_000, 4), 0, SimilarityMode::KGrams);
        for index in 0..plot.cells {
            assert_eq!(plot.value(index, index), 1.0);
        }
    }

    #[test]
    fn a_zero_filled_region_forms_a_bright_square() {
        let data = [noise(16 * 1024, 5), vec![0u8; 16 * 1024]].concat();
        let plot = compute(&data, 0, SimilarityMode::KGrams);
        let last = plot.cells - 1;
        let middle = plot.cells / 2 + 4;
        assert_eq!(plot.value(middle, last), 1.0);
        assert!(plot.value(0, last) < 0.1);
    }

    #[test]
    fn histogram_mode_groups_text_apart_from_padding() {
        let text = b"the quick brown fox jumps over the lazy dog ".repeat(400);
        let data = [text.clone(), vec![0u8; text.len()], text].concat();
        let plot = compute(&data, 0, SimilarityMode::Histogram);
        let third = plot.cells / 3;
        assert!(plot.value(1, 2 * third + 2) > 0.8, "text with text");
        assert!(plot.value(1, third + 2) < 0.1, "text with zeros");
    }

    #[test]
    fn clicked_cells_map_to_the_start_of_both_blocks() {
        let plot = compute(&noise(64 * 1024, 6), 0x1000, SimilarityMode::KGrams);
        assert_eq!(plot.block_size, 128);
        assert_eq!(plot.cell_offsets(2, 5), Some((0x1000 + 256, 0x1000 + 640)));
        assert_eq!(plot.cell_offsets(plot.cells, 0), None);
        assert_eq!(plot.value(plot.cells, 0), 0.0);
    }

    #[test]
    fn empty_and_tiny_ranges_produce_an_empty_plot() {
        assert!(compute(&[], 0, SimilarityMode::KGrams).is_empty());
        assert!(compute(&[1, 2, 3], 0, SimilarityMode::Histogram).is_empty());
        let small = compute(&noise(100, 7), 0, SimilarityMode::KGrams);
        assert_eq!(small.cells, 3);
        assert_eq!(small.values.len(), 9);
    }

    #[test]
    fn a_large_range_is_sampled_and_stays_within_bounds() {
        let data = noise(24 * 1024 * 1024, 8);
        let plot = compute(&data, 0, SimilarityMode::KGrams);
        assert_eq!(plot.cells, MAX_CELLS);
        assert!(plot.block_size > SAMPLE_BYTES_PER_BLOCK);
        assert!(plot.values.iter().all(|value| (0.0..=1.0).contains(value)));
    }
}
