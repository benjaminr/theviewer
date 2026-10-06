//! Feature vectors for fixed-size blocks of a file.
//!
//! Each block is summarised by a handful of explainable measures: entropy,
//! compressibility, the mix of byte kinds, the mean byte value, a coarse
//! 16-bin histogram, bigram entropy and the strongest short-lag
//! autocorrelation. Every measure is scaled to roughly 0 to 1 so blocks can
//! be compared as vectors, and a [`Normaliser`] turns those vectors into
//! per-feature z-scores fitted on the whole file. [`distance`] compares two
//! normalised vectors, optionally weighting the histogram against the other
//! statistics.
//!
//! The segmentation, similarity search and feature tracks all build on this
//! module. Everything is pure, bounded and safe on any input.

use rayon::prelude::*;

/// Block size used when the caller has no preference: 1 KiB.
pub const DEFAULT_BLOCK_SIZE: usize = 1024;
/// Smallest block size that gives meaningful statistics.
pub const MIN_BLOCK_SIZE: usize = 64;
/// Most blocks computed for one file; the block size doubles until the file fits.
pub const MAX_BLOCKS: usize = 65_536;
/// Bins of the coarse histogram: one per high nibble.
pub const HISTOGRAM_BINS: usize = 16;
/// Shortest period the autocorrelation looks for.
pub const MIN_PERIOD: usize = 2;
/// Longest period the per-block autocorrelation looks for.
pub const MAX_BLOCK_PERIOD: usize = 256;
/// Number of statistics in a [`FeatureVector`] before the histogram bins.
pub const STATISTIC_COUNT: usize = 10;
/// Length of a [`FeatureVector`].
pub const FEATURE_COUNT: usize = STATISTIC_COUNT + HISTOGRAM_BINS;
/// Names of the statistics, in [`FeatureVector`] order.
pub const STATISTIC_NAMES: [&str; STATISTIC_COUNT] = [
    "entropy",
    "compressibility",
    "printable",
    "zeros",
    "0xFF",
    "high bytes",
    "control bytes",
    "mean",
    "bigram entropy",
    "period strength",
];

/// Bytes from the start of a block used by the costlier measures
/// (compression, bigrams, autocorrelation) when blocks grow large.
const EXPENSIVE_SAMPLE: usize = 4096;
/// Bytes compared per lag by the autocorrelation.
const AUTOCORRELATION_SAMPLE: usize = 1024;
/// A period must fit this many times into the sample to be trusted.
const MIN_PERIOD_REPEATS: usize = 3;
/// A lag scoring at least this share of the best lag counts as "as good",
/// so the shortest such lag (the fundamental) is reported.
const FUNDAMENTAL_SHARE: f32 = 0.9;
/// Below this strength (best lag match rate minus the median) no period is reported.
pub const MIN_PERIOD_STRENGTH: f32 = 0.15;
/// Compressed-to-original ratios above this are clamped (tiny or random blocks).
const MAX_COMPRESSION_RATIO: f32 = 1.2;
/// Largest Shannon entropy of a byte, in bits.
const MAX_BYTE_ENTROPY: f32 = 8.0;
/// Largest Shannon entropy of a byte pair, in bits.
const MAX_BIGRAM_ENTROPY: f32 = 16.0;
/// Smallest spread used when normalising, in feature units (0 to 1), so a
/// feature that barely varies across the file does not amplify noise.
const MIN_SPREAD: f32 = 0.02;
/// Index of the first histogram bin in a [`FeatureVector`].
const HISTOGRAM_START: usize = STATISTIC_COUNT;

/// A block's features as a vector, each roughly 0 to 1 (see [`STATISTIC_NAMES`]
/// for the first [`STATISTIC_COUNT`] entries; the rest are histogram bins).
pub type FeatureVector = [f32; FEATURE_COUNT];

/// The four kinds of byte, as fractions that sum to 1.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct KindMix {
    /// 0x00.
    pub zero: f32,
    /// Printable ASCII, tab, line feed and carriage return.
    pub printable: f32,
    /// Other bytes below 0x80.
    pub control: f32,
    /// 0x80 and above.
    pub high: f32,
}

/// The measures of one range of bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Features {
    /// Shannon entropy in bits per byte (0 to 8).
    pub entropy: f32,
    /// LZ4 compressed size over original size (about 0 for repetitive data,
    /// about 1 for random data), clamped to 1.2.
    pub compressibility: f32,
    /// Fractions of zeros, printable, control and high bytes.
    pub kinds: KindMix,
    /// Fraction of bytes that are 0xFF (erased flash).
    pub erased: f32,
    /// Mean byte value (0 to 255).
    pub mean: f32,
    /// Fraction of bytes in each high-nibble bin.
    pub histogram: [f32; HISTOGRAM_BINS],
    /// Shannon entropy of consecutive byte pairs in bits (0 to 16).
    pub bigram_entropy: f32,
    /// The strongest short period in bytes, or 0 when none stands out.
    pub period: usize,
    /// Match rate at that period minus the median match rate (0 to 1).
    pub period_strength: f32,
}

impl Features {
    /// The features scaled to roughly 0 to 1, in [`FeatureVector`] order.
    pub fn vector(&self) -> FeatureVector {
        let mut vector = [0.0; FEATURE_COUNT];
        let statistics = [
            self.entropy / MAX_BYTE_ENTROPY,
            self.compressibility,
            self.kinds.printable,
            self.kinds.zero,
            self.erased,
            self.kinds.high,
            self.kinds.control,
            self.mean / f32::from(u8::MAX),
            self.bigram_entropy / MAX_BIGRAM_ENTROPY,
            self.period_strength,
        ];
        vector[..STATISTIC_COUNT].copy_from_slice(&statistics);
        vector[HISTOGRAM_START..].copy_from_slice(&self.histogram);
        vector
    }

    /// The weighted mean of several feature sets. The period is the one
    /// carrying the most weight. Returns the default when the weights sum to 0.
    pub fn weighted_mean<'a>(items: impl IntoIterator<Item = (&'a Features, f32)>) -> Features {
        let mut total = 0.0f32;
        let mut sum = Features::default();
        let mut period_weights: Vec<(usize, f32)> = Vec::new();
        for (features, weight) in items {
            if weight <= 0.0 {
                continue;
            }
            total += weight;
            sum.entropy += features.entropy * weight;
            sum.compressibility += features.compressibility * weight;
            sum.kinds.zero += features.kinds.zero * weight;
            sum.kinds.printable += features.kinds.printable * weight;
            sum.kinds.control += features.kinds.control * weight;
            sum.kinds.high += features.kinds.high * weight;
            sum.erased += features.erased * weight;
            sum.mean += features.mean * weight;
            for (bin, value) in sum.histogram.iter_mut().zip(features.histogram) {
                *bin += value * weight;
            }
            sum.bigram_entropy += features.bigram_entropy * weight;
            sum.period_strength += features.period_strength * weight;
            match period_weights.iter_mut().find(|(period, _)| *period == features.period) {
                Some((_, period_weight)) => *period_weight += weight,
                None => period_weights.push((features.period, weight)),
            }
        }
        if total <= 0.0 {
            return Features::default();
        }
        let scale = |value: f32| value / total;
        Features {
            entropy: scale(sum.entropy),
            compressibility: scale(sum.compressibility),
            kinds: KindMix {
                zero: scale(sum.kinds.zero),
                printable: scale(sum.kinds.printable),
                control: scale(sum.kinds.control),
                high: scale(sum.kinds.high),
            },
            erased: scale(sum.erased),
            mean: scale(sum.mean),
            histogram: sum.histogram.map(scale),
            bigram_entropy: scale(sum.bigram_entropy),
            period: period_weights.iter().max_by(|a, b| a.1.total_cmp(&b.1)).map_or(0, |(period, _)| *period),
            period_strength: scale(sum.period_strength),
        }
    }
}

/// The features of one block of the file.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BlockFeatures {
    /// File offset of the block's first byte.
    pub offset: usize,
    /// Bytes in the block.
    pub len: usize,
    pub features: Features,
}

impl BlockFeatures {
    /// One past the block's last byte.
    pub fn end(&self) -> usize {
        self.offset + self.len
    }
}

/// How to cut a file into blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureOptions {
    /// Requested block size in bytes, raised to at least [`MIN_BLOCK_SIZE`].
    pub block_size: usize,
    /// Most blocks to compute; the block size doubles until the file fits.
    pub max_blocks: usize,
}

impl Default for FeatureOptions {
    fn default() -> Self {
        FeatureOptions { block_size: DEFAULT_BLOCK_SIZE, max_blocks: MAX_BLOCKS }
    }
}

/// The features of every block of a file.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FeatureSeries {
    /// The block size actually used (see [`effective_block_size`]).
    pub block_size: usize,
    /// Blocks in file order. A final partial block shorter than half a block
    /// is folded into the block before it.
    pub blocks: Vec<BlockFeatures>,
}

impl FeatureSeries {
    /// Every block's [`FeatureVector`], in order.
    pub fn vectors(&self) -> Vec<FeatureVector> {
        self.blocks.iter().map(|block| block.features.vector()).collect()
    }

    /// Index of the block containing `offset`, if any.
    pub fn block_at(&self, offset: usize) -> Option<usize> {
        let index = self.blocks.partition_point(|block| block.end() <= offset);
        (index < self.blocks.len() && self.blocks[index].offset <= offset).then_some(index)
    }
}

/// The block size used for `len` bytes: `requested` (at least
/// [`MIN_BLOCK_SIZE`]), doubled until at most `max_blocks` blocks cover the data.
pub fn effective_block_size(len: usize, requested: usize, max_blocks: usize) -> usize {
    let max_blocks = max_blocks.max(1);
    let mut block_size = requested.max(MIN_BLOCK_SIZE);
    while len.div_ceil(block_size) > max_blocks {
        block_size = block_size.saturating_mul(2);
    }
    block_size
}

/// Compute the features of every block of `data`, in parallel.
pub fn compute_features(data: &[u8], options: &FeatureOptions) -> FeatureSeries {
    let block_size = effective_block_size(data.len(), options.block_size, options.max_blocks);
    let ranges = block_ranges(data.len(), block_size);
    let blocks = ranges
        .into_par_iter()
        .map(|(offset, len)| BlockFeatures { offset, len, features: measure(&data[offset..offset + len]) })
        .collect();
    FeatureSeries { block_size, blocks }
}

/// `(offset, len)` of each block, folding a short final remainder into the
/// block before it so no block is too small to measure.
fn block_ranges(len: usize, block_size: usize) -> Vec<(usize, usize)> {
    let mut ranges: Vec<(usize, usize)> = (0..len).step_by(block_size.max(1)).map(|offset| (offset, block_size.min(len - offset))).collect();
    if ranges.len() >= 2
        && let Some(&(_, last_len)) = ranges.last()
        && last_len < block_size / 2
    {
        ranges.pop();
        if let Some(previous) = ranges.last_mut() {
            previous.1 += last_len;
        }
    }
    ranges
}

/// Measure one range of bytes. Safe on any input, including an empty slice.
pub fn measure(bytes: &[u8]) -> Features {
    if bytes.is_empty() {
        return Features::default();
    }
    let mut histogram = [0u64; 256];
    for &byte in bytes {
        histogram[byte as usize] += 1;
    }
    let total = bytes.len() as f32;
    let fraction = |count: u64| count as f32 / total;
    let sample = &bytes[..bytes.len().min(EXPENSIVE_SAMPLE)];
    let peak = best_period(&sample[..sample.len().min(AUTOCORRELATION_SAMPLE)], MIN_PERIOD, MAX_BLOCK_PERIOD);
    Features {
        entropy: entropy_of_counts(&histogram, bytes.len()),
        compressibility: compression_ratio(sample),
        kinds: kind_mix(&histogram, bytes.len()),
        erased: fraction(histogram[0xFF]),
        mean: histogram.iter().enumerate().map(|(value, &count)| value as f32 * count as f32).sum::<f32>() / total,
        histogram: coarse_histogram(&histogram, bytes.len()),
        bigram_entropy: bigram_entropy(sample),
        period: peak.period,
        period_strength: peak.strength,
    }
}

/// Whether `byte` is printable ASCII or common whitespace.
pub fn is_printable(byte: u8) -> bool {
    (0x20..0x7F).contains(&byte) || matches!(byte, b'\t' | b'\n' | b'\r')
}

/// Shannon entropy (bits) of a histogram of `total` items.
fn entropy_of_counts(histogram: &[u64], total: usize) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    let entropy: f64 = histogram
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / total;
            -probability * probability.log2()
        })
        .sum();
    entropy as f32
}

fn kind_mix(histogram: &[u64; 256], total: usize) -> KindMix {
    let mut counts = [0u64; 4];
    for (value, &count) in histogram.iter().enumerate() {
        let byte = value as u8;
        let kind = if byte == 0 {
            0
        } else if is_printable(byte) {
            1
        } else if byte < 0x80 {
            2
        } else {
            3
        };
        counts[kind] += count;
    }
    let fraction = |count: u64| if total == 0 { 0.0 } else { count as f32 / total as f32 };
    KindMix { zero: fraction(counts[0]), printable: fraction(counts[1]), control: fraction(counts[2]), high: fraction(counts[3]) }
}

fn coarse_histogram(histogram: &[u64; 256], total: usize) -> [f32; HISTOGRAM_BINS] {
    let values_per_bin = 256 / HISTOGRAM_BINS;
    let mut bins = [0.0f32; HISTOGRAM_BINS];
    for (bin, counts) in bins.iter_mut().zip(histogram.chunks(values_per_bin)) {
        *bin = counts.iter().sum::<u64>() as f32 / total.max(1) as f32;
    }
    bins
}

/// LZ4 compressed size over original size, clamped to [`MAX_COMPRESSION_RATIO`].
fn compression_ratio(sample: &[u8]) -> f32 {
    if sample.is_empty() {
        return 0.0;
    }
    let compressed = lz4_flex::block::compress(sample);
    (compressed.len() as f32 / sample.len() as f32).min(MAX_COMPRESSION_RATIO)
}

/// Shannon entropy of consecutive byte pairs, counted by sorting.
fn bigram_entropy(sample: &[u8]) -> f32 {
    let mut pairs: Vec<u16> = sample.windows(2).map(|pair| u16::from_be_bytes([pair[0], pair[1]])).collect();
    if pairs.is_empty() {
        return 0.0;
    }
    pairs.sort_unstable();
    let total = pairs.len() as f64;
    let entropy: f64 = pairs
        .chunk_by(|a, b| a == b)
        .map(|run| {
            let probability = run.len() as f64 / total;
            -probability * probability.log2()
        })
        .sum();
    entropy as f32
}

/// The strongest repeating period of a sample.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PeriodPeak {
    /// Period in bytes, or 0 when none stands out (strength below [`MIN_PERIOD_STRENGTH`]).
    pub period: usize,
    /// Match rate at the period minus the median match rate over all lags.
    pub strength: f32,
}

/// Fraction of bytes equal to the byte `lag` positions later.
pub fn match_rate(sample: &[u8], lag: usize) -> f32 {
    let pairs = sample.len().saturating_sub(lag);
    if pairs == 0 {
        return 0.0;
    }
    let matches = sample[..pairs].iter().zip(&sample[lag..]).filter(|(a, b)| a == b).count();
    matches as f32 / pairs as f32
}

/// The shortest lag in `min_period..=max_period` whose exact-match rate is
/// nearly the best, and how far that best stands above the median lag. The
/// longest lag tried is also limited so the period repeats at least three
/// times in the sample.
pub fn best_period(sample: &[u8], min_period: usize, max_period: usize) -> PeriodPeak {
    let min_period = min_period.max(1);
    let max_period = max_period.min(sample.len() / MIN_PERIOD_REPEATS);
    if max_period < min_period {
        return PeriodPeak::default();
    }
    let scores: Vec<f32> = (min_period..=max_period).map(|lag| match_rate(sample, lag)).collect();
    let mut sorted = scores.clone();
    sorted.sort_by(f32::total_cmp);
    let median = sorted[sorted.len() / 2];
    let best = sorted[sorted.len() - 1];
    let strength = (best - median).max(0.0);
    if strength < MIN_PERIOD_STRENGTH {
        return PeriodPeak { period: 0, strength };
    }
    let fundamental = scores.iter().position(|&score| score >= best * FUNDAMENTAL_SHARE).unwrap_or(0);
    PeriodPeak { period: fundamental + min_period, strength }
}

/// Per-feature z-scores fitted on a set of vectors.
#[derive(Clone, Debug, PartialEq)]
pub struct Normaliser {
    mean: FeatureVector,
    spread: FeatureVector,
}

impl Default for Normaliser {
    /// The identity-like normaliser: zero mean, unit spread.
    fn default() -> Self {
        Normaliser { mean: [0.0; FEATURE_COUNT], spread: [1.0; FEATURE_COUNT] }
    }
}

impl Normaliser {
    /// Fit the mean and standard deviation of each feature. Spreads are
    /// floored so features that are nearly constant do not amplify noise.
    pub fn fit(vectors: &[FeatureVector]) -> Normaliser {
        if vectors.is_empty() {
            return Normaliser::default();
        }
        let count = vectors.len() as f64;
        let mut mean = [0.0f64; FEATURE_COUNT];
        for vector in vectors {
            for (total, &value) in mean.iter_mut().zip(vector) {
                *total += f64::from(value);
            }
        }
        mean.iter_mut().for_each(|total| *total /= count);
        let mut variance = [0.0f64; FEATURE_COUNT];
        for vector in vectors {
            for ((total, &value), &centre) in variance.iter_mut().zip(vector).zip(&mean) {
                *total += (f64::from(value) - centre).powi(2);
            }
        }
        Normaliser {
            mean: mean.map(|value| value as f32),
            spread: variance.map(|total| ((total / count).sqrt() as f32).max(MIN_SPREAD)),
        }
    }

    /// The z-scores of `vector`.
    pub fn apply(&self, vector: &FeatureVector) -> FeatureVector {
        let mut normalised = [0.0; FEATURE_COUNT];
        for (index, value) in normalised.iter_mut().enumerate() {
            *value = (vector[index] - self.mean[index]) / self.spread[index];
        }
        normalised
    }
}

/// How much the histogram counts against the other statistics in [`distance`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FeatureWeights {
    /// Weight of the statistics (entropy, kinds, period and so on).
    pub statistics: f32,
    /// Weight of the coarse histogram.
    pub histogram: f32,
}

impl Default for FeatureWeights {
    /// Equal weight to the statistics and the histogram.
    fn default() -> Self {
        FeatureWeights { statistics: 1.0, histogram: 1.0 }
    }
}

/// Distance between two normalised vectors: the root mean square difference
/// within the statistics and within the histogram, combined by weight. Two
/// identical vectors are 0 apart; one z-score of difference everywhere is 1.
pub fn distance(a: &FeatureVector, b: &FeatureVector, weights: FeatureWeights) -> f32 {
    let mean_square = |range: std::ops::Range<usize>| {
        let len = range.len().max(1) as f32;
        range.map(|index| (a[index] - b[index]).powi(2)).sum::<f32>() / len
    };
    let statistics_weight = weights.statistics.max(0.0);
    let histogram_weight = weights.histogram.max(0.0);
    let total_weight = statistics_weight + histogram_weight;
    if total_weight <= 0.0 {
        return 0.0;
    }
    let combined = statistics_weight * mean_square(0..STATISTIC_COUNT) + histogram_weight * mean_square(HISTOGRAM_START..FEATURE_COUNT);
    (combined / total_weight).sqrt()
}

#[cfg(test)]
pub(crate) mod test_data {
    //! Deterministic synthetic data shared by the structure-map tests.

    /// A simple linear congruential generator, so tests need no crate.
    pub struct Lcg(u64);

    impl Lcg {
        pub fn new(seed: u64) -> Self {
            Lcg(seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407))
        }

        pub fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }

        pub fn below(&mut self, limit: u32) -> u32 {
            self.next_u32() % limit.max(1)
        }
    }

    /// Uniformly random bytes.
    pub fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut generator = Lcg::new(seed);
        (0..len).map(|_| (generator.next_u32() >> 7) as u8).collect()
    }

    /// English-like prose made from a small vocabulary.
    pub fn prose(len: usize, seed: u64) -> Vec<u8> {
        const WORDS: [&str; 24] = [
            "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "while", "reading", "a", "binary", "file", "with", "many", "records",
            "and", "some", "text", "between", "them,", "then", "stops.", "again\n",
        ];
        let mut generator = Lcg::new(seed);
        let mut text = Vec::with_capacity(len + 16);
        while text.len() < len {
            text.extend_from_slice(WORDS[generator.below(WORDS.len() as u32) as usize].as_bytes());
            text.push(b' ');
        }
        text.truncate(len);
        text
    }

    /// Fixed-size little-endian records: a magic, a counter, a small value,
    /// a flags byte and zero padding up to `record_size` (at least 16).
    pub fn records(len: usize, record_size: usize, seed: u64) -> Vec<u8> {
        let mut generator = Lcg::new(seed);
        let mut data = Vec::with_capacity(len + record_size);
        let mut counter = generator.below(1000);
        while data.len() < len {
            let mut record = vec![0u8; record_size.max(16)];
            record[..4].copy_from_slice(b"REC\x01");
            record[4..8].copy_from_slice(&counter.to_le_bytes());
            record[8..10].copy_from_slice(&(generator.below(4000) as u16).to_le_bytes());
            record[10] = generator.below(4) as u8;
            record[12] = 0x80 | generator.below(16) as u8;
            data.extend_from_slice(&record[..record_size.max(16)]);
            counter += 1;
        }
        data.truncate(len);
        data
    }

    /// A gzip stream of varied prose, cut to `len` bytes.
    pub fn gzip(len: usize, seed: u64) -> Vec<u8> {
        use std::io::Write;
        let mut generator = Lcg::new(seed);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut output_len = 0;
        while output_len < len {
            let line: Vec<u8> = (0..200).map(|_| b'a' + generator.below(26) as u8).collect();
            encoder.write_all(&line).expect("writing to a Vec cannot fail");
            output_len = encoder.get_ref().len();
        }
        let mut data = encoder.finish().expect("finishing a Vec cannot fail");
        data.truncate(len);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::test_data::*;
    use super::*;

    #[test]
    fn padding_text_and_random_blocks_have_the_expected_measures() {
        let zeros = measure(&[0u8; 1024]);
        assert_eq!(zeros.entropy, 0.0);
        assert_eq!(zeros.kinds.zero, 1.0);
        assert!(zeros.compressibility < 0.1);

        let text = measure(&prose(1024, 1));
        assert!(text.kinds.printable > 0.99);
        assert!((3.0..5.0).contains(&text.entropy), "text entropy {}", text.entropy);

        let random = measure(&random_bytes(1024, 2));
        assert!(random.entropy > 7.5);
        assert!(random.compressibility > 0.95);
        assert!(random.kinds.high > 0.4);
        assert!(random.bigram_entropy > text.bigram_entropy);
    }

    #[test]
    fn a_record_block_reports_its_record_size_as_period() {
        for size in [24, 64] {
            let block = records(1024, size, 3);
            let features = measure(&block);
            assert_eq!(features.period, size, "records of {size} bytes");
            assert!(features.period_strength > MIN_PERIOD_STRENGTH);
        }
        assert_eq!(measure(&random_bytes(1024, 4)).period, 0);
    }

    #[test]
    fn block_size_doubles_until_the_file_fits_the_block_cap() {
        assert_eq!(effective_block_size(10_000, 1024, 65_536), 1024);
        assert_eq!(effective_block_size(10_000, 1024, 4), 4096);
        assert_eq!(effective_block_size(10, 1, 4), MIN_BLOCK_SIZE);
        let series = compute_features(&random_bytes(10_000, 5), &FeatureOptions { block_size: 1024, max_blocks: 4 });
        assert_eq!(series.block_size, 4096);
        assert!(series.blocks.len() <= 4);
        assert_eq!(series.blocks.last().map(BlockFeatures::end), Some(10_000));
    }

    #[test]
    fn a_short_final_remainder_is_folded_into_the_previous_block() {
        let series = compute_features(&random_bytes(1024 * 3 + 100, 6), &FeatureOptions::default());
        assert_eq!(series.blocks.len(), 3);
        assert_eq!(series.blocks[2].len, 1124);
        assert_eq!(series.block_at(3000), Some(2));
        assert_eq!(series.block_at(5000), None);
    }

    #[test]
    fn normalised_text_is_closer_to_text_than_to_random_data() {
        let blocks = [prose(1024, 7), prose(1024, 8), random_bytes(1024, 9), vec![0u8; 1024]];
        let vectors: Vec<FeatureVector> = blocks.iter().map(|block| measure(block).vector()).collect();
        let normaliser = Normaliser::fit(&vectors);
        let normalised: Vec<FeatureVector> = vectors.iter().map(|vector| normaliser.apply(vector)).collect();
        let weights = FeatureWeights::default();
        let text_to_text = distance(&normalised[0], &normalised[1], weights);
        let text_to_random = distance(&normalised[0], &normalised[2], weights);
        assert!(text_to_text < text_to_random / 4.0, "{text_to_text} vs {text_to_random}");
        assert_eq!(distance(&normalised[3], &normalised[3], weights), 0.0);
    }

    #[test]
    fn weighted_mean_averages_measures_and_keeps_the_heaviest_period() {
        let a = Features { entropy: 2.0, period: 24, ..Features::default() };
        let b = Features { entropy: 6.0, period: 64, ..Features::default() };
        let mean = Features::weighted_mean([(&a, 3.0), (&b, 1.0)]);
        assert!((mean.entropy - 3.0).abs() < 1e-6);
        assert_eq!(mean.period, 24);
        assert_eq!(Features::weighted_mean([]), Features::default());
    }

    #[test]
    fn measuring_odd_input_never_panics() {
        for len in [0, 1, 2, 3, 7, 63, 64, 65, 5000] {
            let data = random_bytes(len, len as u64);
            let features = measure(&data);
            assert!(features.entropy.is_finite());
            let series = compute_features(&data, &FeatureOptions { block_size: 0, max_blocks: 0 });
            assert_eq!(series.blocks.iter().map(|block| block.len).sum::<usize>(), len);
        }
    }
}
