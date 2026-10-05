//! Algorithms for discovering structure in raw bytes.
//!
//! Two complementary tools:
//!
//! * **Period scan** – an autocorrelation over byte lags. Data laid out in
//!   fixed-size records or image rows repeats every `P` bytes, so the
//!   similarity between `x[i]` and `x[i + P]` peaks at the row stride and its
//!   multiples. The peaks become candidate widths.
//! * **Entropy map** – Shannon entropy per block across the whole file, which
//!   separates headers, text, tables, code and compressed regions at a glance.

use rayon::prelude::*;

/// Result of scanning a window of bytes for repeating periods.
#[derive(Clone, Debug, Default)]
pub struct PeriodScan {
    /// Document offset the window started at.
    pub window_start: usize,
    /// Bytes examined.
    pub window_len: usize,
    /// Similarity score for every lag; index is the lag in bytes (index 0 is unused).
    pub scores: Vec<f32>,
    /// Baseline used for peak detection.
    pub baseline: f32,
    /// Peaks ranked best first.
    pub candidates: Vec<Candidate>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Candidate {
    /// Period in bytes.
    pub period: usize,
    /// Similarity at that lag, 0..1.
    pub score: f32,
    /// How far the score rises above the baseline, in robust standard deviations.
    pub prominence: f32,
    /// Bits of entropy removed per byte by knowing the column (position mod period).
    pub column_gain: f32,
    /// Smallest earlier candidate this period is a multiple of, if any.
    pub multiple_of: Option<usize>,
}

/// Similarity between bytes `lag` apart: half exact-match rate, half closeness
/// of values. Exact matches dominate for records with fixed fields; closeness
/// helps for images and slowly varying signals.
fn lag_similarity(data: &[u8], lag: usize) -> f32 {
    let pairs = data.len() - lag;
    if pairs == 0 {
        return 0.0;
    }
    let (matches, distance) = data[..pairs]
        .iter()
        .zip(&data[lag..])
        .fold((0u32, 0u64), |(matches, distance), (&a, &b)| {
            (matches + u32::from(a == b), distance + a.abs_diff(b) as u64)
        });
    let match_rate = matches as f32 / pairs as f32;
    let closeness = 1.0 - distance as f32 / (pairs as f32 * 255.0);
    0.5 * match_rate + 0.5 * closeness
}

/// Average Shannon entropy (bits) of the byte value at each column when the
/// data is folded at `period`, subtracted from the unfolded entropy. Positive
/// gain means columns are more predictable than the stream as a whole.
pub fn column_entropy_gain(data: &[u8], period: usize) -> f32 {
    if period == 0 || data.len() < period * 4 {
        return 0.0;
    }
    let rows = data.len() / period;
    let folded = &data[..rows * period];
    let mut counts = vec![0u32; period * 256];
    for row in folded.chunks_exact(period) {
        for (column, &byte) in row.iter().enumerate() {
            counts[column * 256 + byte as usize] += 1;
        }
    }
    let column_entropy: f32 = counts
        .as_chunks::<256>()
        .0
        .iter()
        .map(|histogram| entropy_of_counts(histogram, rows))
        .sum::<f32>()
        / period as f32;
    shannon_entropy(folded) - column_entropy
}

fn entropy_of_counts(histogram: &[u32], total: usize) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let total = total as f32;
    histogram
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f32 / total;
            -p * p.log2()
        })
        .sum()
}

/// Shannon entropy of a byte slice in bits per byte (0 to 8).
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut histogram = [0u32; 256];
    for &byte in data {
        histogram[byte as usize] += 1;
    }
    entropy_of_counts(&histogram, data.len())
}

/// Scan `data` for periods from 1 to `max_lag` bytes.
pub fn scan_periods(data: &[u8], window_start: usize, max_lag: usize) -> PeriodScan {
    let max_lag = max_lag.min(data.len().saturating_sub(16));
    if max_lag < 2 {
        return PeriodScan { window_start, window_len: data.len(), ..Default::default() };
    }
    let mut scores = vec![0.0f32; max_lag + 1];
    scores[1..]
        .par_iter_mut()
        .enumerate()
        .for_each(|(index, score)| *score = lag_similarity(data, index + 1));

    let (baseline, spread) = robust_stats(&scores[1..]);
    let mut candidates = find_peaks(&scores, baseline, spread);
    candidates.sort_by(|a, b| b.prominence.total_cmp(&a.prominence));
    candidates.truncate(12);
    for candidate in &mut candidates {
        candidate.column_gain = column_entropy_gain(data, candidate.period);
    }
    mark_multiples(&mut candidates);

    PeriodScan { window_start, window_len: data.len(), scores, baseline, candidates }
}

/// Median and median absolute deviation, scaled to approximate a standard deviation.
fn robust_stats(values: &[f32]) -> (f32, f32) {
    let mut sorted: Vec<f32> = values.to_vec();
    sorted.sort_by(f32::total_cmp);
    let median = sorted[sorted.len() / 2];
    let mut deviations: Vec<f32> = sorted.iter().map(|v| (v - median).abs()).collect();
    deviations.sort_by(f32::total_cmp);
    let mad = deviations[deviations.len() / 2];
    (median, (mad * 1.4826).max(1e-4))
}

fn find_peaks(scores: &[f32], baseline: f32, spread: f32) -> Vec<Candidate> {
    const MIN_PROMINENCE: f32 = 3.0;
    let mut peaks = Vec::new();
    for lag in 1..scores.len() {
        let score = scores[lag];
        let left = if lag > 1 { scores[lag - 1] } else { f32::NEG_INFINITY };
        let right = scores.get(lag + 1).copied().unwrap_or(f32::NEG_INFINITY);
        if score < left || score <= right {
            continue;
        }
        let prominence = (score - baseline) / spread;
        if prominence >= MIN_PROMINENCE {
            peaks.push(Candidate { period: lag, score, prominence, column_gain: 0.0, multiple_of: None });
        }
    }
    peaks
}

/// Flag candidates that are integer multiples of a smaller candidate scoring
/// at least about as well, and move fundamentals ahead of their multiples.
/// Autocorrelation peaks at every multiple of the true period, so the
/// smallest period among near-equal peaks is the one to show first.
fn mark_multiples(candidates: &mut Vec<Candidate>) {
    const NEAR_EQUAL: f32 = 0.98;
    for index in 0..candidates.len() {
        let current = candidates[index];
        let base = candidates
            .iter()
            .filter(|other| {
                other.period < current.period
                    && current.period.is_multiple_of(other.period)
                    && other.score >= current.score * NEAR_EQUAL
            })
            .map(|other| other.period)
            .min();
        candidates[index].multiple_of = base;
    }
    let (fundamentals, multiples): (Vec<Candidate>, Vec<Candidate>) =
        candidates.drain(..).partition(|candidate| candidate.multiple_of.is_none());
    candidates.extend(fundamentals);
    candidates.extend(multiples);
}

/// Entropy of consecutive blocks across a whole buffer, computed in parallel.
/// Returns one value per block in bits per byte.
pub fn entropy_map(data: &[u8], block_count: usize) -> Vec<f32> {
    if data.is_empty() || block_count == 0 {
        return Vec::new();
    }
    let block_size = data.len().div_ceil(block_count).max(1);
    // Very large blocks are sampled from their start so huge files stay quick.
    const MAX_SAMPLE: usize = 256 * 1024;
    data.par_chunks(block_size)
        .map(|block| shannon_entropy(&block[..block.len().min(MAX_SAMPLE)]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift(state: &mut u32) -> u8 {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        (*state >> 24) as u8
    }

    /// Records with two fixed header bytes, a counter, and a random payload.
    fn records(record_len: usize, count: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(record_len * count);
        let mut state = 0x9E37_79B9u32;
        for index in 0..count {
            for field in 0..record_len {
                let byte = match field {
                    0 => 0xAA,
                    1 => 0x55,
                    2 => (index & 0xFF) as u8,
                    _ => xorshift(&mut state),
                };
                data.push(byte);
            }
        }
        data
    }

    #[test]
    fn finds_the_record_length_of_structured_data() {
        let data = records(37, 2000);
        let scan = scan_periods(&data, 0, 256);
        let best = scan.candidates.first().expect("a candidate");
        assert_eq!(best.period, 37, "candidates: {:?}", scan.candidates);
        assert!(best.column_gain > 0.0);
    }

    #[test]
    fn multiples_of_the_fundamental_are_flagged() {
        let data = records(24, 3000);
        let scan = scan_periods(&data, 0, 128);
        let fundamental = scan.candidates.iter().find(|c| c.period == 24).expect("fundamental");
        assert_eq!(fundamental.multiple_of, None);
        let double = scan.candidates.iter().find(|c| c.period == 48).expect("second harmonic");
        assert_eq!(double.multiple_of, Some(24));
    }

    #[test]
    fn random_data_yields_no_confident_candidates() {
        let mut state = 0x1234_5678u32;
        let data: Vec<u8> = (0..65536).map(|_| xorshift(&mut state)).collect();
        let scan = scan_periods(&data, 0, 512);
        assert!(scan.candidates.len() <= 2, "candidates: {:?}", scan.candidates);
    }

    #[test]
    fn entropy_ranges_from_zero_to_eight_bits() {
        assert_eq!(shannon_entropy(&[7u8; 1000]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-4);
    }

    #[test]
    fn entropy_map_has_one_value_per_block() {
        let mut data = vec![0u8; 4096];
        data[2048..].iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
        let map = entropy_map(&data, 4);
        assert_eq!(map.len(), 4);
        assert_eq!(map[0], 0.0);
        assert!(map[3] > 7.9);
    }
}
