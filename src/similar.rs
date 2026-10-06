//! "Find more like this": rank the parts of a file that resemble a selection.
//!
//! The selection is measured as a whole and, when it spans several blocks,
//! block by block. Every block of the file is then scored by its similarity
//! to the closest of those references, as `1 / (1 + distance)` on normalised
//! [features](crate::features), so identical blocks score 1 and a block one
//! z-score away everywhere scores 0.5. Blocks above a threshold are merged
//! into regions and ranked. The selection itself is never reported.
//!
//! Scoring is the costly part and runs once ([`score_blocks`]); regions for
//! any threshold come cheaply from the scores ([`matching_regions`]).

use std::fmt;

use rayon::prelude::*;

use crate::features::{self, FeatureOptions, FeatureVector, FeatureWeights, Features, Normaliser};

/// Default similarity a block needs to count as a match.
pub const DEFAULT_THRESHOLD: f32 = 0.6;
/// Most reference blocks taken from a long selection.
pub const MAX_REFERENCES: usize = 64;
/// Most regions returned.
pub const MAX_REGIONS: usize = 1000;
/// Block size used when the selection is at least this long.
const PREFERRED_BLOCK_SIZE: usize = features::DEFAULT_BLOCK_SIZE;
/// Block sizes are rounded down to a multiple of this.
const BLOCK_ALIGNMENT: usize = 16;

/// Settings for [`score_blocks`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SimilarOptions {
    /// 0 compares statistics only, 1 compares the coarse histogram only.
    pub histogram_weight: f32,
    /// Most blocks scored; the block size grows for very large files.
    pub max_blocks: usize,
}

impl Default for SimilarOptions {
    fn default() -> Self {
        SimilarOptions { histogram_weight: 0.5, max_blocks: features::MAX_BLOCKS }
    }
}

impl SimilarOptions {
    fn weights(&self) -> FeatureWeights {
        let histogram = self.histogram_weight.clamp(0.0, 1.0);
        FeatureWeights { statistics: 1.0 - histogram, histogram }
    }
}

/// Why a similarity search could not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimilarError {
    /// Nothing is selected.
    EmptySelection,
    /// The selection lies (partly) beyond the data analysed.
    SelectionOutOfRange { start: usize, len: usize, data_len: usize },
}

impl fmt::Display for SimilarError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimilarError::EmptySelection => write!(formatter, "select some bytes first: the search looks for data like the selection"),
            SimilarError::SelectionOutOfRange { start, len, data_len } => write!(
                formatter,
                "the selection {start:#x}..{:#x} lies beyond the {data_len} bytes analysed; select a range inside them",
                start + len
            ),
        }
    }
}

impl std::error::Error for SimilarError {}

/// Every block's similarity to the selection.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SimilarityScores {
    /// Bytes analysed.
    pub scanned_len: usize,
    /// Block size used (close to the selection's length, at most 1 KiB).
    pub block_size: usize,
    /// The selection as `(start, len)`.
    pub selection: (usize, usize),
    /// Features of the whole selection.
    pub selection_features: Features,
    /// `(offset, len, score)` per block; blocks overlapping the selection are left out.
    pub blocks: Vec<(usize, usize, f32)>,
}

/// A run of neighbouring matching blocks.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SimilarRegion {
    pub start: usize,
    pub len: usize,
    /// Mean similarity of the region's blocks (0 to 1).
    pub score: f32,
    /// Best similarity of any of its blocks.
    pub best: f32,
    pub blocks: usize,
}

impl SimilarRegion {
    /// One past the last byte.
    pub fn end(&self) -> usize {
        self.start + self.len
    }
}

/// The block size for a selection of `selection_len` bytes: the selection's
/// own length (so blocks are measured on equal footing), at most 1 KiB.
pub fn block_size_for(selection_len: usize) -> usize {
    let size = selection_len.min(PREFERRED_BLOCK_SIZE);
    (size - size % BLOCK_ALIGNMENT).max(features::MIN_BLOCK_SIZE)
}

/// Score every block of `data` by similarity to `data[start..start + len]`.
pub fn score_blocks(data: &[u8], selection: (usize, usize), options: &SimilarOptions) -> Result<SimilarityScores, SimilarError> {
    let (start, len) = selection;
    if len == 0 {
        return Err(SimilarError::EmptySelection);
    }
    let end = start.checked_add(len).filter(|&end| end <= data.len()).ok_or(SimilarError::SelectionOutOfRange { start, len, data_len: data.len() })?;
    let feature_options = FeatureOptions { block_size: block_size_for(len), max_blocks: options.max_blocks };
    let series = features::compute_features(data, &feature_options);
    let normaliser = Normaliser::fit(&series.vectors());

    let selected = &data[start..end];
    let selection_features = features::measure(selected);
    let references = reference_vectors(selected, series.block_size, &selection_features, &normaliser);
    let weights = options.weights();

    let blocks = series
        .blocks
        .par_iter()
        .filter(|block| block.end() <= start || block.offset >= end)
        .map(|block| {
            let vector = normaliser.apply(&block.features.vector());
            let nearest = references.iter().map(|reference| features::distance(reference, &vector, weights)).fold(f32::INFINITY, f32::min);
            (block.offset, block.len, 1.0 / (1.0 + nearest))
        })
        .collect();
    Ok(SimilarityScores { scanned_len: data.len(), block_size: series.block_size, selection, selection_features, blocks })
}

/// Normalised vectors for the whole selection and for each block-sized
/// piece of it (evenly sampled to at most [`MAX_REFERENCES`]).
fn reference_vectors(selected: &[u8], block_size: usize, whole: &Features, normaliser: &Normaliser) -> Vec<FeatureVector> {
    let mut references = vec![normaliser.apply(&whole.vector())];
    let pieces: Vec<&[u8]> = selected.chunks(block_size).filter(|piece| piece.len() * 2 >= block_size).collect();
    if pieces.len() > 1 {
        let step = pieces.len().div_ceil(MAX_REFERENCES);
        references.extend(pieces.iter().step_by(step).map(|piece| normaliser.apply(&features::measure(piece).vector())));
    }
    references
}

/// Merge neighbouring blocks scoring at least `threshold` into regions,
/// best first (by mean score, then size), at most [`MAX_REGIONS`].
pub fn matching_regions(scores: &SimilarityScores, threshold: f32) -> Vec<SimilarRegion> {
    let mut regions: Vec<SimilarRegion> = Vec::new();
    for &(offset, len, score) in scores.blocks.iter().filter(|block| block.2 >= threshold) {
        match regions.last_mut() {
            Some(region) if region.end() == offset => {
                region.score = (region.score * region.blocks as f32 + score) / (region.blocks + 1) as f32;
                region.best = region.best.max(score);
                region.len += len;
                region.blocks += 1;
            }
            _ => regions.push(SimilarRegion { start: offset, len, score, best: score, blocks: 1 }),
        }
    }
    regions.sort_by(|a, b| b.score.total_cmp(&a.score).then(b.len.cmp(&a.len)).then(a.start.cmp(&b.start)));
    regions.truncate(MAX_REGIONS);
    regions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::test_data::*;

    struct Layout {
        data: Vec<u8>,
        text: Vec<(usize, usize)>,
        tables: Vec<(usize, usize)>,
    }

    /// text | table | random | text | table | zeros | table | text
    fn layout() -> Layout {
        let mut layout = Layout { data: Vec::new(), text: Vec::new(), tables: Vec::new() };
        let add = |layout: &mut Layout, part: Vec<u8>, kind: Option<bool>| {
            let range = (layout.data.len(), layout.data.len() + part.len());
            match kind {
                Some(true) => layout.tables.push(range),
                Some(false) => layout.text.push(range),
                None => {}
            }
            layout.data.extend(part);
        };
        add(&mut layout, prose(6_000, 1), Some(false));
        add(&mut layout, records(6_400, 32, 2), Some(true));
        add(&mut layout, random_bytes(5_000, 3), None);
        add(&mut layout, prose(7_000, 4), Some(false));
        add(&mut layout, records(5_120, 32, 5), Some(true));
        add(&mut layout, vec![0; 4_000], None);
        add(&mut layout, records(7_200, 32, 6), Some(true));
        add(&mut layout, prose(5_000, 7), Some(false));
        layout
    }

    fn overlaps(region: &SimilarRegion, range: (usize, usize)) -> bool {
        region.start < range.1 && range.0 < region.end()
    }

    #[test]
    fn selecting_one_table_finds_the_other_tables_and_not_the_text() {
        let layout = layout();
        let (table_start, table_end) = layout.tables[0];
        let scores = score_blocks(&layout.data, (table_start, table_end - table_start), &SimilarOptions::default()).expect("valid selection");
        let regions = matching_regions(&scores, DEFAULT_THRESHOLD);
        for &table in &layout.tables[1..] {
            assert!(regions.iter().any(|region| overlaps(region, table)), "table at {table:?} not found in {regions:?}");
        }
        for &text in &layout.text {
            let inner = (text.0 + 1024, text.1 - 1024);
            assert!(!regions.iter().any(|region| overlaps(region, inner)), "text at {text:?} matched: {regions:?}");
        }
        assert!(!regions.iter().any(|region| overlaps(region, (table_start, table_end))), "the selection itself was reported");
    }

    #[test]
    fn a_short_selection_uses_blocks_of_its_own_size() {
        assert_eq!(block_size_for(200), 192);
        assert_eq!(block_size_for(10), features::MIN_BLOCK_SIZE);
        assert_eq!(block_size_for(1 << 20), PREFERRED_BLOCK_SIZE);
        let layout = layout();
        let (start, _) = layout.text[1];
        let scores = score_blocks(&layout.data, (start + 100, 512), &SimilarOptions::default()).expect("valid selection");
        assert_eq!(scores.block_size, 512);
        let regions = matching_regions(&scores, DEFAULT_THRESHOLD);
        assert!(regions.iter().any(|region| overlaps(region, layout.text[0])));
        assert!(!regions.iter().any(|region| layout.tables.iter().any(|&table| overlaps(region, (table.0 + 600, table.1 - 600)))));
    }

    #[test]
    fn regions_are_ranked_best_first_and_the_threshold_filters_them() {
        let layout = layout();
        let (start, end) = layout.tables[0];
        let scores = score_blocks(&layout.data, (start, end - start), &SimilarOptions::default()).expect("valid selection");
        let regions = matching_regions(&scores, 0.0);
        assert!(regions.windows(2).all(|pair| pair[0].score >= pair[1].score));
        assert!(matching_regions(&scores, 1.01).is_empty());
    }

    #[test]
    fn an_empty_or_out_of_range_selection_is_an_explicit_error() {
        let data = random_bytes(4096, 9);
        assert_eq!(score_blocks(&data, (0, 0), &SimilarOptions::default()), Err(SimilarError::EmptySelection));
        let error = score_blocks(&data, (4000, 200), &SimilarOptions::default()).expect_err("beyond the end");
        assert!(error.to_string().contains("beyond"));
        assert!(score_blocks(&data, (usize::MAX, 2), &SimilarOptions::default()).is_err());
    }
}
