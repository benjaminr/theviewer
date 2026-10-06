//! Automatic segmentation of a file into homogeneous regions.
//!
//! 1. **Coarse change points.** Block [features](crate::features) are
//!    normalised to z-scores and split by binary segmentation: the split that
//!    most reduces the within-segment squared deviation is taken while the
//!    reduction beats a penalty scaled to the noise between neighbouring
//!    blocks. Splits are taken strongest first and capped at [`MAX_SEGMENTS`].
//! 2. **Byte-level refinement.** Each boundary is moved, within one block
//!    either side, to the byte where a window to its left and a window to its
//!    right differ most in byte kinds and coarse histogram, then snapped to a
//!    16-byte boundary when one is within a few bytes.
//! 3. **Types.** Segments are clustered agglomeratively on their mean
//!    features (at most [`MAX_TYPES`] types), adjacent segments of
//!    the same type are merged, and each type is named after the dominant
//!    [`fragments::classify`] class of its segments and given a colour.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use eframe::egui::Color32;

use crate::features::{self, BlockFeatures, FeatureOptions, FeatureSeries, FeatureVector, FeatureWeights, Features, Normaliser};
use crate::fragments::{self, BlockClass};
use crate::plugin::Category;

/// Most segments found by the change-point pass, before merging.
pub const MAX_SEGMENTS: usize = 256;
/// Most segment types.
pub const MAX_TYPES: usize = 8;
/// Segments whose mean features are closer than this (root mean square
/// z-score difference) share a type.
const TYPE_DISTANCE: f32 = 0.6;
/// Multiplier on the change-point penalty, which is otherwise the expected
/// largest gain from splitting pure noise.
const PENALTY_SAFETY: f64 = 1.5;
/// Smallest noise variance assumed, in squared z-score units, so very clean
/// data does not split on rounding differences.
const MIN_NOISE_VARIANCE: f64 = 0.01;
/// Largest window either side of a candidate boundary in the byte-level refinement.
const REFINE_WINDOW: usize = 1024;
/// Refined boundaries are at least this fraction of a block apart (and away
/// from the ends of the data), so no sliver segments appear.
const MIN_SEGMENT_FRACTION: usize = 4;
/// Boundaries within this many bytes of a 16-byte boundary snap to it.
const SNAP_DISTANCE: usize = 4;
/// Alignment boundaries snap to.
const SNAP_ALIGNMENT: usize = 16;
/// Bytes classified per sample when naming a segment.
const CLASSIFY_SAMPLE: usize = fragments::DEFAULT_BLOCK_SIZE;
/// Samples classified per segment: start, middle and end.
const CLASSIFY_SAMPLES: usize = 3;
/// Colours used when a type's natural colour is already taken.
const SPARE_COLOURS: [Color32; 6] = [
    Color32::from_rgb(120, 220, 200),
    Color32::from_rgb(240, 160, 220),
    Color32::from_rgb(160, 230, 110),
    Color32::from_rgb(255, 210, 150),
    Color32::from_rgb(150, 170, 255),
    Color32::from_rgb(210, 120, 90),
];

/// Settings for [`segment_file`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SegmentOptions {
    /// How blocks are cut for the coarse pass.
    pub features: FeatureOptions,
}

/// One homogeneous stretch of the file.
#[derive(Clone, Debug, PartialEq)]
pub struct Segment {
    /// File offset of the first byte.
    pub start: usize,
    /// Bytes in the segment.
    pub len: usize,
    /// Index into [`Segmentation::types`].
    pub type_id: usize,
    /// The type's label, such as "Text" or "Table / records".
    pub label: String,
    /// Mean features of the segment's blocks.
    pub mean: Features,
    /// Why the segment has its type and where its start boundary came from.
    pub reason: String,
}

impl Segment {
    /// One past the last byte.
    pub fn end(&self) -> usize {
        self.start + self.len
    }
}

/// A kind of segment shared by similar segments.
#[derive(Clone, Debug, PartialEq)]
pub struct SegmentType {
    pub id: usize,
    pub label: String,
    /// The block class the label comes from.
    pub class: BlockClass,
    /// Findings category matching the class, for pinning segments.
    pub category: Category,
    pub colour: Color32,
    /// Segments of this type.
    pub count: usize,
    /// Bytes in segments of this type.
    pub total_bytes: usize,
}

/// The result of [`segment_file`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Segmentation {
    /// Bytes analysed.
    pub scanned_len: usize,
    /// Block size of the coarse pass.
    pub block_size: usize,
    /// Segments in file order, covering the whole data without gaps.
    pub segments: Vec<Segment>,
    /// Types in order of first appearance.
    pub types: Vec<SegmentType>,
}

/// Split `data` into homogeneous segments and group them into types.
pub fn segment_file(data: &[u8], options: &SegmentOptions) -> Segmentation {
    if data.is_empty() {
        return Segmentation::default();
    }
    let series = features::compute_features(data, &options.features);
    let normaliser = Normaliser::fit(&series.vectors());
    let normalised: Vec<FeatureVector> = series.blocks.iter().map(|block| normaliser.apply(&block.features.vector())).collect();

    let coarse = coarse_change_points(&normalised);
    let block_offsets: Vec<usize> = coarse.iter().map(|&index| series.blocks[index].offset).collect();
    let boundaries = refine_boundaries(data, &block_offsets, series.block_size);
    let ranges = ranges_from_boundaries(&boundaries, data.len());

    let means: Vec<Features> = ranges.iter().map(|&(start, end)| range_mean(data, &series, start, end)).collect();
    let mean_vectors: Vec<FeatureVector> = means.iter().map(|mean| normaliser.apply(&mean.vector())).collect();
    let lengths: Vec<usize> = ranges.iter().map(|&(start, end)| end - start).collect();
    let clusters = cluster(&mean_vectors, &lengths);
    let merged = merge_adjacent(&ranges, &clusters);

    build_segmentation(data, &series, merged)
}

// ---------------------------------------------------------------------------
// Coarse change points
// ---------------------------------------------------------------------------

/// Running sums that give any range's squared-deviation cost in O(features).
struct PrefixSums {
    sums: Vec<[f64; features::FEATURE_COUNT]>,
    squares: Vec<f64>,
}

impl PrefixSums {
    fn new(vectors: &[FeatureVector]) -> Self {
        let mut sums = vec![[0.0; features::FEATURE_COUNT]; vectors.len() + 1];
        let mut squares = vec![0.0; vectors.len() + 1];
        for (index, vector) in vectors.iter().enumerate() {
            let mut next = sums[index];
            for (total, &value) in next.iter_mut().zip(vector) {
                *total += f64::from(value);
            }
            sums[index + 1] = next;
            squares[index + 1] = squares[index] + vector.iter().map(|&value| f64::from(value).powi(2)).sum::<f64>();
        }
        PrefixSums { sums, squares }
    }

    /// Sum of squared deviations from the mean over blocks `start..end`.
    fn cost(&self, start: usize, end: usize) -> f64 {
        let count = (end - start) as f64;
        if count == 0.0 {
            return 0.0;
        }
        let sum_squared: f64 = self.sums[end].iter().zip(&self.sums[start]).map(|(high, low)| (high - low).powi(2)).sum();
        (self.squares[end] - self.squares[start] - sum_squared / count).max(0.0)
    }
}

/// A candidate split of blocks `start..end` at `split`, ordered by gain.
struct Candidate {
    start: usize,
    end: usize,
    split: usize,
    gain: f64,
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.gain.total_cmp(&other.gain) == Ordering::Equal
    }
}

impl Eq for Candidate {}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.gain.total_cmp(&other.gain)
    }
}

/// The best split of blocks `start..end`, if it has at least one block each side.
fn best_split(sums: &PrefixSums, start: usize, end: usize) -> Option<Candidate> {
    if end - start < 2 {
        return None;
    }
    let whole = sums.cost(start, end);
    (start + 1..end)
        .map(|split| Candidate { start, end, split, gain: whole - sums.cost(start, split) - sums.cost(split, end) })
        .max()
}

/// Block indices where a new segment starts (excluding 0), in order.
fn coarse_change_points(vectors: &[FeatureVector]) -> Vec<usize> {
    if vectors.len() < 2 {
        return Vec::new();
    }
    let sums = PrefixSums::new(vectors);
    let penalty = split_penalty(vectors);
    let mut queue: BinaryHeap<Candidate> = best_split(&sums, 0, vectors.len()).into_iter().collect();
    let mut change_points = Vec::new();
    while let Some(candidate) = queue.pop() {
        if candidate.gain <= penalty || change_points.len() + 1 >= MAX_SEGMENTS {
            break;
        }
        change_points.push(candidate.split);
        queue.extend(best_split(&sums, candidate.start, candidate.split));
        queue.extend(best_split(&sums, candidate.split, candidate.end));
    }
    change_points.sort_unstable();
    change_points
}

/// The gain a split must beat: about the largest gain splitting pure noise
/// would give, with noise variance estimated robustly from the differences
/// between neighbouring blocks (the median ignores the true change points).
fn split_penalty(vectors: &[FeatureVector]) -> f64 {
    let dimensions = features::FEATURE_COUNT as f64;
    let mut differences: Vec<f64> = vectors
        .windows(2)
        .map(|pair| pair[0].iter().zip(&pair[1]).map(|(a, b)| f64::from(a - b).powi(2)).sum::<f64>() / (2.0 * dimensions))
        .collect();
    differences.sort_by(f64::total_cmp);
    let noise_variance = differences.get(differences.len() / 2).copied().unwrap_or(0.0).max(MIN_NOISE_VARIANCE);
    let log_blocks = (vectors.len() as f64).ln().max(1.0);
    let noise_gain = dimensions + 2.0 * (2.0 * dimensions * log_blocks).sqrt() + 2.0 * log_blocks;
    PENALTY_SAFETY * noise_variance * noise_gain
}

// ---------------------------------------------------------------------------
// Byte-level refinement
// ---------------------------------------------------------------------------

/// Bins of the local measure: 16 high-nibble bins and 4 byte kinds.
const LOCAL_BINS: usize = features::HISTOGRAM_BINS + 4;

fn local_bins(byte: u8) -> [usize; 2] {
    let kind = if byte == 0 {
        0
    } else if features::is_printable(byte) {
        1
    } else if byte < 0x80 {
        2
    } else {
        3
    };
    [usize::from(byte >> 4), features::HISTOGRAM_BINS + kind]
}

/// Counts of the local bins in a window that slides one byte at a time.
struct WindowCounts {
    counts: [u32; LOCAL_BINS],
    len: u32,
}

impl WindowCounts {
    fn of(bytes: &[u8]) -> Self {
        let mut window = WindowCounts { counts: [0; LOCAL_BINS], len: 0 };
        bytes.iter().for_each(|&byte| window.add(byte));
        window
    }

    fn add(&mut self, byte: u8) {
        local_bins(byte).iter().for_each(|&bin| self.counts[bin] += 1);
        self.len += 1;
    }

    fn remove(&mut self, byte: u8) {
        local_bins(byte).iter().for_each(|&bin| self.counts[bin] -= 1);
        self.len -= 1;
    }

    /// L1 distance between the two windows' bin fractions (0 to 4).
    fn difference(&self, other: &WindowCounts) -> f32 {
        let (left, right) = (self.len.max(1) as f32, other.len.max(1) as f32);
        self.counts.iter().zip(&other.counts).map(|(&a, &b)| (a as f32 / left - b as f32 / right).abs()).sum()
    }
}

/// Move each coarse boundary (a byte offset on the block grid) to the byte
/// within one block where the data either side differs most.
fn refine_boundaries(data: &[u8], coarse: &[usize], block_size: usize) -> Vec<usize> {
    let window = block_size.min(REFINE_WINDOW);
    let min_gap = (block_size / MIN_SEGMENT_FRACTION).max(1);
    let mut refined: Vec<usize> = Vec::with_capacity(coarse.len());
    for (index, &boundary) in coarse.iter().enumerate() {
        let previous = refined.last().copied().unwrap_or(0);
        let next = coarse.get(index + 1).copied().unwrap_or(data.len());
        let low = boundary.saturating_sub(block_size).max(previous + min_gap);
        let high = (boundary + block_size).min(next.saturating_sub(1)).min(data.len().saturating_sub(min_gap));
        // Two coarse boundaries either side of one mixed block both find the
        // same edge; the second has no room left and is dropped.
        if low > high {
            continue;
        }
        let best = sharpest_edge(data, low, high, window);
        refined.push(snap_to_alignment(best, low, high));
    }
    refined
}

/// The offset in `low..=high` where windows of `window` bytes either side differ most.
fn sharpest_edge(data: &[u8], low: usize, high: usize, window: usize) -> usize {
    let mut left = WindowCounts::of(&data[low.saturating_sub(window)..low]);
    let mut right = WindowCounts::of(&data[low..(low + window).min(data.len())]);
    let (mut best_offset, mut best_score) = (low, left.difference(&right));
    for offset in low + 1..=high {
        // The byte at offset - 1 crosses from the right window to the left.
        let crossing = data[offset - 1];
        right.remove(crossing);
        left.add(crossing);
        if offset > window {
            left.remove(data[offset - 1 - window]);
        }
        if offset - 1 + window < data.len() {
            right.add(data[offset - 1 + window]);
        }
        let score = left.difference(&right);
        if score > best_score {
            (best_offset, best_score) = (offset, score);
        }
    }
    best_offset
}

/// Snap to the nearest multiple of [`SNAP_ALIGNMENT`] when it is within
/// [`SNAP_DISTANCE`] bytes and inside `low..=high`.
fn snap_to_alignment(offset: usize, low: usize, high: usize) -> usize {
    let below = offset - offset % SNAP_ALIGNMENT;
    let above = below + SNAP_ALIGNMENT;
    let nearest = if offset - below <= above - offset { below } else { above };
    if nearest.abs_diff(offset) <= SNAP_DISTANCE && (low..=high).contains(&nearest) { nearest } else { offset }
}

/// `(start, end)` of the segments between boundaries.
fn ranges_from_boundaries(boundaries: &[usize], len: usize) -> Vec<(usize, usize)> {
    let mut edges = Vec::with_capacity(boundaries.len() + 2);
    edges.push(0);
    edges.extend(boundaries.iter().copied().filter(|&offset| offset > 0 && offset < len));
    edges.push(len);
    edges.windows(2).filter(|pair| pair[1] > pair[0]).map(|pair| (pair[0], pair[1])).collect()
}

// ---------------------------------------------------------------------------
// Segment features and types
// ---------------------------------------------------------------------------

/// Mean features of the blocks lying wholly inside `start..end`, or the
/// features of the bytes themselves when no block fits inside.
fn range_mean(data: &[u8], series: &FeatureSeries, start: usize, end: usize) -> Features {
    let inside: Vec<&BlockFeatures> = series.blocks.iter().filter(|block| block.offset >= start && block.end() <= end).collect();
    if inside.is_empty() {
        return features::measure(&data[start..end]);
    }
    Features::weighted_mean(inside.iter().map(|block| (&block.features, block.len as f32)))
}

/// A group of segments being clustered: its byte-weighted centroid and size.
struct Cluster {
    centroid: FeatureVector,
    bytes: f32,
}

impl Cluster {
    fn absorb(&mut self, other: &Cluster) {
        let total = (self.bytes + other.bytes).max(f32::MIN_POSITIVE);
        for (value, &other_value) in self.centroid.iter_mut().zip(&other.centroid) {
            *value = (*value * self.bytes + other_value * other.bytes) / total;
        }
        self.bytes += other.bytes;
    }
}

/// Agglomerative clustering of segments by their mean feature vectors.
///
/// First the two closest clusters merge while their centroids are within
/// [`TYPE_DISTANCE`]. Then, while there are more than [`MAX_TYPES`], the pair
/// whose merge adds least squared deviation per byte (Ward's criterion,
/// weighted by bytes) merges, so small outliers join their nearest type
/// before two large, distinct types are forced together.
/// Returns a cluster id per segment, numbered by first appearance.
fn cluster(vectors: &[FeatureVector], bytes: &[usize]) -> Vec<usize> {
    let weights = FeatureWeights::default();
    let mut clusters: Vec<Cluster> = vectors.iter().zip(bytes).map(|(vector, &len)| Cluster { centroid: *vector, bytes: len as f32 }).collect();
    let mut owner: Vec<usize> = (0..vectors.len()).collect();
    let mut active: Vec<usize> = (0..vectors.len()).collect();
    let distance = |a: &Cluster, b: &Cluster| features::distance(&a.centroid, &b.centroid, weights);
    let ward_cost = |a: &Cluster, b: &Cluster| distance(a, b).powi(2) * a.bytes * b.bytes / (a.bytes + b.bytes).max(f32::MIN_POSITIVE);
    while active.len() > 1 {
        let Some((closest, a, b)) = cheapest_pair(&active, &clusters, distance) else { break };
        let (a, b) = if closest <= TYPE_DISTANCE {
            (a, b)
        } else if active.len() > MAX_TYPES {
            match cheapest_pair(&active, &clusters, ward_cost) {
                Some((_, a, b)) => (a, b),
                None => break,
            }
        } else {
            break;
        };
        let absorbed = std::mem::replace(&mut clusters[b], Cluster { centroid: [0.0; features::FEATURE_COUNT], bytes: 0.0 });
        clusters[a].absorb(&absorbed);
        owner.iter_mut().filter(|cluster| **cluster == b).for_each(|cluster| *cluster = a);
        active.retain(|&cluster| cluster != b);
    }
    renumber_by_first_appearance(&owner)
}

/// The active pair with the lowest `cost`, as `(cost, a, b)` with `a < b`.
fn cheapest_pair(active: &[usize], clusters: &[Cluster], cost: impl Fn(&Cluster, &Cluster) -> f32) -> Option<(f32, usize, usize)> {
    let mut best: Option<(f32, usize, usize)> = None;
    for (position, &a) in active.iter().enumerate() {
        for &b in &active[position + 1..] {
            let value = cost(&clusters[a], &clusters[b]);
            if best.is_none_or(|(lowest, _, _)| value < lowest) {
                best = Some((value, a.min(b), a.max(b)));
            }
        }
    }
    best
}

fn renumber_by_first_appearance(owner: &[usize]) -> Vec<usize> {
    let mut order: Vec<usize> = Vec::new();
    owner
        .iter()
        .map(|&cluster| match order.iter().position(|&seen| seen == cluster) {
            Some(id) => id,
            None => {
                order.push(cluster);
                order.len() - 1
            }
        })
        .collect()
}

/// Merge neighbouring ranges of the same cluster: `(start, end, cluster)`.
fn merge_adjacent(ranges: &[(usize, usize)], clusters: &[usize]) -> Vec<(usize, usize, usize)> {
    let mut merged: Vec<(usize, usize, usize)> = Vec::new();
    for (&(start, end), &cluster) in ranges.iter().zip(clusters) {
        match merged.last_mut() {
            Some(last) if last.2 == cluster && last.1 == start => last.1 = end,
            _ => merged.push((start, end, cluster)),
        }
    }
    merged
}

/// The class most of a range's samples get, with the reason given for it.
fn classify_range(data: &[u8], start: usize, end: usize) -> (BlockClass, String) {
    let len = end - start;
    let sample_len = len.min(CLASSIFY_SAMPLE);
    let span = len - sample_len;
    let mut votes: Vec<(BlockClass, usize, String)> = Vec::new();
    for sample in 0..CLASSIFY_SAMPLES {
        let offset = start + span * sample / (CLASSIFY_SAMPLES - 1).max(1);
        let (class, _, reason) = fragments::classify(&data[offset..offset + sample_len]);
        match votes.iter_mut().find(|(voted, _, _)| *voted == class) {
            Some(vote) => vote.1 += 1,
            None => votes.push((class, 1, reason)),
        }
    }
    // The earliest class wins a tie, so the result is deterministic.
    let winner = votes.iter().enumerate().max_by(|(ia, a), (ib, b)| a.1.cmp(&b.1).then(ib.cmp(ia))).map(|(index, _)| index).unwrap_or(0);
    let (class, _, reason) = votes.swap_remove(winner);
    (class, reason)
}

/// Mean zero-or-0xFF fraction above which a segment is padding.
const MEAN_PADDING_FRACTION: f32 = 0.9;
/// Mean printable fraction above which a segment is text.
const MEAN_TEXT_FRACTION: f32 = 0.85;
/// Mean entropy (bits per byte) above which a segment is compressed or random.
const MEAN_HIGH_ENTROPY: f32 = 7.5;
/// Mean period strength above which a segment is a table of records.
const MEAN_TABLE_STRENGTH: f32 = 0.3;

/// A class from a segment's mean block features, for segments whose sampled
/// blocks fit no [`fragments::classify`] rule on their own (rules judge
/// single blocks strictly; a segment's average is steadier).
fn class_from_mean(mean: &Features) -> Option<(BlockClass, String)> {
    let padding = mean.kinds.zero + mean.erased;
    if padding >= MEAN_PADDING_FRACTION {
        return Some((BlockClass::Padding, format!("on average {:.0}% of bytes are 0x00 or 0xFF", padding * 100.0)));
    }
    if mean.kinds.printable >= MEAN_TEXT_FRACTION {
        return Some((BlockClass::Text, format!("on average {:.0}% printable, entropy {:.2}", mean.kinds.printable * 100.0, mean.entropy)));
    }
    if mean.entropy >= MEAN_HIGH_ENTROPY {
        return Some((BlockClass::Random, format!("mean entropy {:.2} bits/byte and incompressible ({:.0}% after LZ4)", mean.entropy, mean.compressibility * 100.0)));
    }
    if mean.period > 0 && mean.period_strength >= MEAN_TABLE_STRENGTH {
        return Some((BlockClass::Table, format!("blocks repeat every {} bytes on average (strength {:.0}%)", mean.period, mean.period_strength * 100.0)));
    }
    None
}

/// The findings category whose colour suits a block class.
pub fn class_category(class: BlockClass) -> Category {
    match class {
        BlockClass::Padding => Category::Padding,
        BlockClass::Text => Category::Text,
        BlockClass::Markup => Category::Document,
        BlockClass::MachineCode => Category::Executable,
        BlockClass::Compressed => Category::Compressed,
        BlockClass::Random => Category::HighEntropy,
        BlockClass::Image => Category::Image,
        BlockClass::Audio => Category::FloatArray,
        BlockClass::Table => Category::Structure,
        BlockClass::Binary => Category::Custom,
    }
}

/// Name the types, assign colours and describe each segment.
fn build_segmentation(data: &[u8], series: &FeatureSeries, merged: Vec<(usize, usize, usize)>) -> Segmentation {
    let means: Vec<Features> = merged.iter().map(|&(start, end, _)| range_mean(data, series, start, end)).collect();
    let classified: Vec<(BlockClass, String)> = merged
        .iter()
        .zip(&means)
        .map(|(&(start, end, _), mean)| match classify_range(data, start, end) {
            (BlockClass::Binary, reason) => class_from_mean(mean).unwrap_or((BlockClass::Binary, reason)),
            decided => decided,
        })
        .collect();
    let type_count = merged.iter().map(|&(_, _, cluster)| cluster + 1).max().unwrap_or(0);
    let types = name_types(type_count, &merged, &classified);

    let mut segments = Vec::with_capacity(merged.len());
    for (index, &(start, end, cluster)) in merged.iter().enumerate() {
        let boundary = match index.checked_sub(1) {
            Some(previous) => describe_change(&means[previous], &means[index]),
            None => "starts the file".to_string(),
        };
        segments.push(Segment {
            start,
            len: end - start,
            type_id: cluster,
            label: types[cluster].label.clone(),
            mean: means[index],
            reason: format!("{}; {boundary}", classified[index].1),
        });
    }
    Segmentation { scanned_len: data.len(), block_size: series.block_size, segments, types }
}

/// One type per cluster, labelled by the class covering most of its bytes.
fn name_types(type_count: usize, merged: &[(usize, usize, usize)], classified: &[(BlockClass, String)]) -> Vec<SegmentType> {
    let mut types: Vec<SegmentType> = Vec::with_capacity(type_count);
    let mut used_colours: Vec<Color32> = Vec::new();
    for id in 0..type_count {
        let members: Vec<usize> = (0..merged.len()).filter(|&index| merged[index].2 == id).collect();
        let total_bytes = members.iter().map(|&index| merged[index].1 - merged[index].0).sum();
        let class = dominant_class(members.iter().map(|&index| (classified[index].0, merged[index].1 - merged[index].0)));
        let category = class_category(class);
        let same_class = types.iter().filter(|other| other.class == class).count();
        let label = if same_class == 0 { class.label().to_string() } else { format!("{} ({})", class.label(), same_class + 1) };
        let colour = pick_colour(category.colour(), &used_colours);
        used_colours.push(colour);
        types.push(SegmentType { id, label, class, category, colour, count: members.len(), total_bytes });
    }
    types
}

fn dominant_class(members: impl Iterator<Item = (BlockClass, usize)>) -> BlockClass {
    let mut bytes_per_class: Vec<(BlockClass, usize)> = Vec::new();
    for (class, bytes) in members {
        match bytes_per_class.iter_mut().find(|(seen, _)| *seen == class) {
            Some(entry) => entry.1 += bytes,
            None => bytes_per_class.push((class, bytes)),
        }
    }
    bytes_per_class.iter().max_by_key(|(_, bytes)| *bytes).map_or(BlockClass::Binary, |(class, _)| *class)
}

fn pick_colour(natural: Color32, used: &[Color32]) -> Color32 {
    if !used.contains(&natural) {
        return natural;
    }
    SPARE_COLOURS.iter().copied().find(|colour| !used.contains(colour)).unwrap_or(natural)
}

/// The statistic that changes most between two neighbouring segments, in words.
fn describe_change(before: &Features, after: &Features) -> String {
    let (before_vector, after_vector) = (before.vector(), after.vector());
    let largest = (0..features::STATISTIC_COUNT)
        .max_by(|&a, &b| (after_vector[a] - before_vector[a]).abs().total_cmp(&(after_vector[b] - before_vector[b]).abs()))
        .unwrap_or(0);
    let name = features::STATISTIC_NAMES[largest];
    match largest {
        0 => format!("starts where {name} changes from {:.2} to {:.2} bits/byte", before.entropy, after.entropy),
        7 => format!("starts where the {name} byte changes from {:.0} to {:.0}", before.mean, after.mean),
        8 => format!("starts where {name} changes from {:.1} to {:.1} bits", before.bigram_entropy, after.bigram_entropy),
        _ => format!("starts where {name} changes from {:.0}% to {:.0}%", before_vector[largest] * 100.0, after_vector[largest] * 100.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::test_data::*;

    /// [text | 64-byte records | gzip | zeros | random] with odd lengths.
    fn mixed_file() -> (Vec<u8>, Vec<usize>) {
        let parts = [prose(9_000, 1), records(10_000, 64, 2), gzip(9_500, 3), vec![0u8; 6_200], random_bytes(8_300, 4)];
        let mut data = Vec::new();
        let mut boundaries = Vec::new();
        for part in parts {
            if !data.is_empty() {
                boundaries.push(data.len());
            }
            data.extend_from_slice(&part);
        }
        (data, boundaries)
    }

    #[test]
    fn a_mixed_file_is_split_within_sixteen_bytes_of_each_true_boundary() {
        let (data, truth) = mixed_file();
        let result = segment_file(&data, &SegmentOptions::default());
        let found: Vec<usize> = result.segments.iter().skip(1).map(|segment| segment.start).collect();
        for &boundary in &truth {
            let nearest = found.iter().map(|&offset| offset.abs_diff(boundary)).min().unwrap_or(usize::MAX);
            assert!(nearest <= 16, "boundary {boundary}: nearest found is {nearest} away; found {found:?}");
        }
        // The start of a deflate stream (its Huffman tables) is measurably more
        // biased than the rest, so one extra split inside the gzip part is allowed.
        assert!(found.len() <= truth.len() + 1, "too many segments: {found:?}");
        assert_eq!(result.segments.iter().map(|segment| segment.len).sum::<usize>(), data.len());
    }

    #[test]
    fn segment_types_are_named_after_their_content() {
        let (data, truth) = mixed_file();
        let result = segment_file(&data, &SegmentOptions::default());
        let class_at = |offset: usize| {
            let segment = result.segments.iter().find(|segment| (segment.start..segment.end()).contains(&offset)).expect("segments cover the file");
            result.types[segment.type_id].class
        };
        assert_eq!(class_at(truth[0] / 2), BlockClass::Text);
        assert_eq!(class_at((truth[0] + truth[1]) / 2), BlockClass::Table);
        assert!(matches!(class_at((truth[1] + truth[2]) / 2), BlockClass::Compressed | BlockClass::Random));
        assert_eq!(class_at((truth[2] + truth[3]) / 2), BlockClass::Padding);
        assert!(matches!(class_at(data.len() - 100), BlockClass::Compressed | BlockClass::Random));
        assert!(result.types.len() <= MAX_TYPES);
        let counted: usize = result.types.iter().map(|segment_type| segment_type.count).sum();
        assert_eq!(counted, result.segments.len());
    }

    #[test]
    fn repeated_content_shares_one_type() {
        let mut data = prose(8_000, 5);
        data.extend(records(8_000, 32, 6));
        data.extend(prose(8_000, 7));
        let result = segment_file(&data, &SegmentOptions::default());
        assert_eq!(result.segments.len(), 3, "{:?}", result.segments.iter().map(|s| (s.start, s.len)).collect::<Vec<_>>());
        assert_eq!(result.segments[0].type_id, result.segments[2].type_id);
        assert_ne!(result.segments[0].type_id, result.segments[1].type_id);
        assert_eq!(result.types[result.segments[0].type_id].count, 2);
    }

    #[test]
    fn uniform_data_is_one_segment() {
        let data = random_bytes(50_000, 8);
        let result = segment_file(&data, &SegmentOptions::default());
        assert_eq!(result.segments.len(), 1);
        assert_eq!(result.types.len(), 1);
    }

    #[test]
    fn boundaries_near_sixteen_byte_alignment_snap_to_it() {
        assert_eq!(snap_to_alignment(4099, 3000, 5000), 4096);
        assert_eq!(snap_to_alignment(4108, 3000, 5000), 4112);
        assert_eq!(snap_to_alignment(4104, 3000, 5000), 4104);
        assert_eq!(snap_to_alignment(4099, 4097, 5000), 4099);
    }

    #[test]
    fn tiny_and_empty_input_never_panics() {
        assert!(segment_file(&[], &SegmentOptions::default()).segments.is_empty());
        for len in [1, 2, 63, 64, 100, 1500, 3000] {
            let data = random_bytes(len, len as u64);
            let result = segment_file(&data, &SegmentOptions::default());
            assert_eq!(result.segments.iter().map(|segment| segment.len).sum::<usize>(), len);
        }
    }
}
