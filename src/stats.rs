//! Statistics for diagnosing unknown data: the `ent` measures, a plain-English
//! verdict, byte-pair counts, sliding entropy and compressibility, the most
//! repeated sequences, and a magnitude spectrum.
//!
//! Everything here is pure and safe on any input, including empty slices.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::io::Write;

use rayon::prelude::*;

/// The `ent` measures plus a few fractions that help classify data.
#[derive(Clone, Debug, PartialEq)]
pub struct ByteStats {
    pub len: usize,
    pub histogram: [u64; 256],
    /// Shannon entropy in bits per byte (0 to 8).
    pub entropy: f64,
    /// Chi-square statistic against a uniform byte distribution.
    pub chi_square: f64,
    /// Approximate upper-tail p-value for 255 degrees of freedom.
    pub chi_square_p: f64,
    /// Arithmetic mean of the byte values (127.5 for random data).
    pub mean: f64,
    /// Monte Carlo estimate of pi from 24-bit coordinate pairs.
    pub monte_carlo_pi: f64,
    pub pi_error_percent: f64,
    /// Serial correlation coefficient of consecutive bytes (0 for random data).
    pub serial_correlation: f64,
    pub printable_fraction: f64,
    pub zero_fraction: f64,
    /// Fraction of bytes at or above 0x80.
    pub high_fraction: f64,
    pub distinct_values: usize,
}

/// Compute the `ent` statistics (John Walker's definitions) and fractions.
pub fn byte_stats(bytes: &[u8]) -> ByteStats {
    let len = bytes.len();
    let mut histogram = [0u64; 256];
    for &byte in bytes {
        histogram[byte as usize] += 1;
    }
    let total = len as f64;
    let fraction = |count: u64| if len == 0 { 0.0 } else { count as f64 / total };

    let entropy = histogram
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum();
    let (chi_square, chi_square_p) = chi_square(&histogram, len);
    let mean = if len == 0 {
        0.0
    } else {
        histogram.iter().enumerate().map(|(value, &count)| value as f64 * count as f64).sum::<f64>() / total
    };
    let monte_carlo_pi = monte_carlo_pi(bytes);
    let pi_error_percent = if monte_carlo_pi == 0.0 {
        100.0
    } else {
        ((monte_carlo_pi - std::f64::consts::PI) / std::f64::consts::PI).abs() * 100.0
    };
    let printable: u64 = histogram
        .iter()
        .enumerate()
        .filter(|(value, _)| (0x20..0x7F).contains(value) || matches!(*value, 9 | 10 | 13))
        .map(|(_, &count)| count)
        .sum();
    let high: u64 = histogram[0x80..].iter().sum();

    ByteStats {
        len,
        histogram,
        entropy,
        chi_square,
        chi_square_p,
        mean,
        monte_carlo_pi,
        pi_error_percent,
        serial_correlation: serial_correlation(bytes),
        printable_fraction: fraction(printable),
        zero_fraction: fraction(histogram[0]),
        high_fraction: fraction(high),
        distinct_values: histogram.iter().filter(|&&count| count > 0).count(),
    }
}

/// Chi-square against uniform, and its upper-tail p-value.
///
/// The p-value uses the Wilson–Hilferty approximation: for `k` degrees of
/// freedom, `(x / k)^(1/3)` is close to normal with mean `1 - 2/(9k)` and
/// variance `2/(9k)`. With `k = 255` this is accurate to a few parts in a
/// thousand, plenty to tell "uniform" from "clearly not".
fn chi_square(histogram: &[u64; 256], len: usize) -> (f64, f64) {
    if len == 0 {
        return (0.0, 1.0);
    }
    let expected = len as f64 / 256.0;
    let statistic: f64 = histogram.iter().map(|&count| (count as f64 - expected).powi(2) / expected).sum();
    let k = 255.0;
    let z = ((statistic / k).cbrt() - (1.0 - 2.0 / (9.0 * k))) / (2.0 / (9.0 * k)).sqrt();
    let p = 0.5 * erfc(z / std::f64::consts::SQRT_2);
    (statistic, p.clamp(0.0, 1.0))
}

/// Complementary error function (Numerical Recipes' Chebyshev fit, relative
/// error below 1.2e-7).
fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let polynomial = -z * z - 1.265_512_23
        + t * (1.000_023_68
            + t * (0.374_091_96
                + t * (0.096_784_18
                    + t * (-0.186_288_06
                        + t * (0.278_868_07 + t * (-1.135_203_98 + t * (1.488_515_87 + t * (-0.822_152_23 + t * 0.170_872_77))))))));
    let result = t * polynomial.exp();
    if x >= 0.0 { result } else { 2.0 - result }
}

/// `ent`'s Monte Carlo pi: each 6 bytes give a 24-bit (x, y) point in a
/// square; the fraction inside the inscribed quarter circle estimates pi/4.
fn monte_carlo_pi(bytes: &[u8]) -> f64 {
    let radius = (256.0f64.powi(3) - 1.0).powi(2);
    let mut inside = 0u64;
    let mut tries = 0u64;
    for chunk in bytes.as_chunks::<6>().0 {
        let x = ((chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32) as f64;
        let y = ((chunk[3] as u32) << 16 | (chunk[4] as u32) << 8 | chunk[5] as u32) as f64;
        tries += 1;
        if x * x + y * y <= radius {
            inside += 1;
        }
    }
    if tries == 0 { 0.0 } else { 4.0 * inside as f64 / tries as f64 }
}

/// `ent`'s serial correlation coefficient: each byte against the next, with
/// the last wrapping to the first.
fn serial_correlation(bytes: &[u8]) -> f64 {
    let n = bytes.len() as f64;
    if bytes.len() < 2 {
        return 0.0;
    }
    let (mut sum_xy, mut sum_x, mut sum_x2) = (0.0f64, 0.0f64, 0.0f64);
    for (index, &byte) in bytes.iter().enumerate() {
        let x = byte as f64;
        let next = bytes[(index + 1) % bytes.len()] as f64;
        sum_xy += x * next;
        sum_x += x;
        sum_x2 += x * x;
    }
    let denominator = n * sum_x2 - sum_x * sum_x;
    if denominator.abs() < f64::EPSILON { 0.0 } else { (n * sum_xy - sum_x * sum_x) / denominator }
}

/// A short classification of the data with the reasoning behind it.
#[derive(Clone, Debug, PartialEq)]
pub struct Verdict {
    pub label: &'static str,
    pub explanation: String,
}

/// Classify data from its statistics. Heuristic: the explanation says why.
pub fn verdict(stats: &ByteStats) -> Verdict {
    let verdict = |label, explanation: String| Verdict { label, explanation };
    if stats.len == 0 {
        return verdict("Empty", "There are no bytes to measure.".to_string());
    }
    if stats.distinct_values == 1 {
        let value = stats.histogram.iter().position(|&count| count > 0).unwrap_or(0);
        return verdict("Constant fill", format!("Every byte is {value:#04x}: padding or erased storage."));
    }
    if stats.printable_fraction >= 0.95 {
        return verdict(
            "Text",
            format!("Looks like text because {:.0}% of bytes are printable characters, with entropy {:.2} bits per byte.", stats.printable_fraction * 100.0, stats.entropy),
        );
    }
    if stats.entropy >= 7.5 {
        return if stats.chi_square_p < 0.01 {
            verdict(
                "Compressed",
                format!(
                    "Looks compressed because entropy is high ({:.3} bits per byte) but the byte distribution is not uniform (chi-square p = {:.4}); compressors leave this kind of bias, good encryption does not.",
                    stats.entropy, stats.chi_square_p
                ),
            )
        } else {
            verdict(
                "Encrypted or random",
                format!(
                    "Looks encrypted or random because entropy is {:.3} bits per byte and the byte distribution passes a uniformity test (chi-square p = {:.3}). Well-compressed data can also look like this.",
                    stats.entropy, stats.chi_square_p
                ),
            )
        };
    }
    if stats.zero_fraction >= 0.4 {
        return verdict(
            "Sparse binary (many zeros)",
            format!("Looks like sparse binary data such as tables, headers or uninitialised space because {:.0}% of bytes are zero.", stats.zero_fraction * 100.0),
        );
    }
    if (5.0..=6.8).contains(&stats.entropy) && stats.printable_fraction < 0.6 && stats.zero_fraction < 0.3 {
        return verdict(
            "Machine code (likely)",
            format!(
                "Could be machine code because entropy is {:.2} bits per byte, typical of instruction streams, with few long text runs or zero fills; try the disassembler to confirm.",
                stats.entropy
            ),
        );
    }
    verdict(
        "Structured binary",
        format!(
            "Looks like structured binary data: entropy {:.2} bits per byte, {:.0}% printable, {:.0}% zeros, serial correlation {:.2}.",
            stats.entropy,
            stats.printable_fraction * 100.0,
            stats.zero_fraction * 100.0,
            stats.serial_correlation
        ),
    )
}

/// Counts of each consecutive byte pair; index `a * 256 + b`.
pub fn digraph_counts(bytes: &[u8]) -> Vec<u32> {
    let mut counts = vec![0u32; 65_536];
    for pair in bytes.windows(2) {
        let index = (pair[0] as usize) << 8 | pair[1] as usize;
        counts[index] = counts[index].saturating_add(1);
    }
    counts
}

/// Evenly spaced start offsets for at most `points` windows of `window` bytes.
fn sample_offsets(len: usize, window: usize, points: usize) -> Vec<usize> {
    if len == 0 || window == 0 || points == 0 {
        return Vec::new();
    }
    let last = len.saturating_sub(window);
    let count = points.min(last + 1);
    if count == 1 {
        return vec![0];
    }
    (0..count).map(|i| i * last / (count - 1)).collect()
}

/// Entropy of a sliding window, sampled at most `points` times across the data.
pub fn sliding_entropy(bytes: &[u8], window: usize, points: usize) -> Vec<(usize, f32)> {
    let window = window.max(1);
    sample_offsets(bytes.len(), window, points)
        .into_par_iter()
        .map(|offset| {
            let end = (offset + window).min(bytes.len());
            (offset, crate::analysis::shannon_entropy(&bytes[offset..end]))
        })
        .collect()
}

/// Deflate ratio (compressed / original) of sampled blocks: near 0 for
/// repetitive data, about 1 (or slightly more) for random data.
pub fn compressibility(bytes: &[u8], block: usize, points: usize) -> Vec<(usize, f32)> {
    let block = block.max(1);
    sample_offsets(bytes.len(), block, points)
        .into_par_iter()
        .map(|offset| {
            let end = (offset + block).min(bytes.len());
            let slice = &bytes[offset..end];
            let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
            let compressed = encoder.write_all(slice).and_then(|_| encoder.finish()).map(|out| out.len()).unwrap_or(slice.len());
            (offset, compressed as f32 / slice.len().max(1) as f32)
        })
        .collect()
}

/// A byte sequence that occurs many times.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repeat {
    pub bytes: Vec<u8>,
    pub count: usize,
    /// Offsets of the first occurrences, up to 16.
    pub first_offsets: Vec<usize>,
}

/// Most bytes examined by [`repeated_sequences`].
const REPEAT_SAMPLE: usize = 8 * 1024 * 1024;
/// Distinct hashes tracked per length before rare ones are dropped.
const REPEAT_TABLE_LIMIT: usize = 1 << 20;
/// Slots in the first-pass counting sketch (one byte each).
const SKETCH_SIZE: usize = 1 << 22;

/// Call `visit(hash, offset)` for every window of `len` bytes, with a
/// polynomial rolling hash.
fn for_each_window_hash(bytes: &[u8], len: usize, mut visit: impl FnMut(u64, usize)) {
    const BASE: u64 = 0x100_0000_01B3;
    let mut power = 1u64;
    for _ in 1..len {
        power = power.wrapping_mul(BASE);
    }
    let mut hash = 0u64;
    for &byte in &bytes[..len] {
        hash = hash.wrapping_mul(BASE).wrapping_add(byte as u64 + 1);
    }
    visit(hash, 0);
    for offset in 1..=bytes.len() - len {
        let outgoing = bytes[offset - 1] as u64 + 1;
        let incoming = bytes[offset + len - 1] as u64 + 1;
        hash = hash.wrapping_sub(outgoing.wrapping_mul(power)).wrapping_mul(BASE).wrapping_add(incoming);
        visit(hash, offset);
    }
}

/// The most repeated byte sequences of length `min_len..=max_len`, ranked by
/// bytes covered (count × length). Runs of one repeated byte (padding) are
/// ignored, and a sequence is dropped when a longer reported one contains it
/// with the same count. Looks at most the first 8 MiB.
pub fn repeated_sequences(bytes: &[u8], min_len: usize, max_len: usize, top: usize) -> Vec<Repeat> {
    let bytes = &bytes[..bytes.len().min(REPEAT_SAMPLE)];
    let min_len = min_len.max(2);
    let max_len = max_len.max(min_len).min(64);
    if bytes.len() < min_len * 2 || top == 0 {
        return Vec::new();
    }
    // Count windows of the shortest length once, then grow each frequent one
    // outwards while every occurrence still agrees. Longer repeats are made
    // of repeated short windows, so this finds them in a single pass instead
    // of one pass per length.
    let seeds = repeats_of_length(bytes, min_len, top * 8);
    let mut found: Vec<Repeat> = seeds.par_iter().map(|seed| extend_repeat(bytes, seed, max_len)).collect();
    found.extend(seeds.iter().map(Seed::to_repeat));
    found.sort_by(|a, b| (b.count * b.bytes.len()).cmp(&(a.count * a.bytes.len())).then(b.bytes.len().cmp(&a.bytes.len())));

    let mut kept: Vec<Repeat> = Vec::new();
    for candidate in found {
        let covered = kept.iter().any(|longer| {
            longer.bytes.len() > candidate.bytes.len()
                && longer.count >= candidate.count
                && longer.bytes.windows(candidate.bytes.len()).any(|w| w == candidate.bytes.as_slice())
        });
        let duplicate = kept.iter().any(|k| k.bytes == candidate.bytes);
        if !covered && !duplicate {
            kept.push(candidate);
        }
        if kept.len() >= top {
            break;
        }
    }
    kept
}

/// The table's keys are already well-mixed rolling hashes, so hashing them
/// again (SipHash, the default) is wasted work; pass them straight through.
#[derive(Default)]
struct PassThroughHasher(u64);

impl Hasher for PassThroughHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = self.0.rotate_left(8) ^ byte as u64;
        }
    }

    fn write_u64(&mut self, value: u64) {
        // Fold the high bits down: hashbrown picks buckets from the low bits.
        self.0 = value ^ (value >> 29);
    }
}

type HashTable = HashMap<u64, (u32, usize, usize), BuildHasherDefault<PassThroughHasher>>;

/// Grow a repeat right, then left, while every occurrence shares the next
/// byte, up to `max_len`.
fn extend_repeat(bytes: &[u8], seed: &Seed, max_len: usize) -> Repeat {
    let mut starts = seed.offsets.clone();
    let mut len = seed.pattern.len();
    while len < max_len {
        let Some(&first) = starts.first() else { break };
        let Some(&next) = bytes.get(first + len) else { break };
        if !starts.iter().all(|&o| bytes.get(o + len) == Some(&next)) {
            break;
        }
        len += 1;
    }
    while len < max_len && starts.iter().all(|&o| o > 0) {
        let previous = bytes[starts[0] - 1];
        if !starts.iter().all(|&o| bytes[o - 1] == previous) {
            break;
        }
        starts.iter_mut().for_each(|o| *o -= 1);
        len += 1;
    }
    let pattern = starts.first().map(|&o| bytes[o..o + len].to_vec()).unwrap_or_default();
    Repeat { count: starts.len(), first_offsets: starts.into_iter().take(16).collect(), bytes: pattern }
}

/// Count every window of `len` bytes by a rolling hash; return the most
/// frequent ones, verified against the real bytes.
fn repeats_of_length(bytes: &[u8], len: usize, keep: usize) -> Vec<Seed> {
    if bytes.len() < len {
        return Vec::new();
    }
    // First pass: a small counting sketch. Most windows in real data occur
    // once, and a window only needs a table entry once the sketch has seen
    // its hash before, which keeps the expensive table small.
    let mut sketch = vec![0u8; SKETCH_SIZE];
    for_each_window_hash(bytes, len, |hash, _| {
        let slot = &mut sketch[(hash >> 11) as usize & (SKETCH_SIZE - 1)];
        *slot = slot.saturating_add(1);
    });
    // hash -> (count, first offset, last counted offset)
    let mut table: HashTable = HashTable::with_capacity_and_hasher(1 << 14, Default::default());
    for_each_window_hash(bytes, len, |hash, offset| {
        if sketch[(hash >> 11) as usize & (SKETCH_SIZE - 1)] < 2 {
            return;
        }
        if let Some(entry) = table.get_mut(&hash) {
            // Count non-overlapping occurrences only.
            if offset >= entry.2 + len {
                entry.0 += 1;
                entry.2 = offset;
            }
        } else if table.len() < REPEAT_TABLE_LIMIT {
            table.insert(hash, (1, offset, offset));
        }
    });
    let mut frequent: Vec<(u64, u32, usize)> = table.into_iter().filter(|(_, e)| e.0 >= 2).map(|(h, e)| (h, e.0, e.1)).collect();
    frequent.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.1));
    let chosen: Vec<(u64, usize)> = frequent
        .into_iter()
        .filter(|&(_, _, first)| {
            let window = &bytes[first..first + len];
            window.iter().any(|&b| b != window[0])
        })
        .take(keep)
        .map(|(hash, _, first)| (hash, first))
        .collect();

    // One more pass collects every non-overlapping occurrence of the chosen
    // windows, checked against the real bytes in case of a hash collision.
    let mut positions: HashMap<u64, (usize, Vec<usize>), BuildHasherDefault<PassThroughHasher>> =
        chosen.iter().map(|&(hash, first)| (hash, (first, Vec::new()))).collect();
    for_each_window_hash(bytes, len, |hash, offset| {
        if let Some((first, offsets)) = positions.get_mut(&hash)
            && offsets.last().is_none_or(|&last| offset >= last + len)
            && bytes[offset..offset + len] == bytes[*first..*first + len]
        {
            offsets.push(offset);
        }
    });
    chosen
        .into_iter()
        .filter_map(|(hash, first)| {
            let (_, offsets) = positions.remove(&hash)?;
            (offsets.len() >= 2).then(|| Seed { pattern: bytes[first..first + len].to_vec(), offsets })
        })
        .collect()
}

/// A frequent window with every occurrence.
struct Seed {
    pattern: Vec<u8>,
    offsets: Vec<usize>,
}

impl Seed {
    fn to_repeat(&self) -> Repeat {
        Repeat { bytes: self.pattern.clone(), count: self.offsets.len(), first_offsets: self.offsets.iter().copied().take(16).collect() }
    }
}

/// Largest input the spectrum transforms.
const SPECTRUM_MAX_SAMPLES: usize = 1 << 20;

/// One-sided magnitude spectrum in decibels: mean removed, Hann window,
/// radix-2 FFT (zero-padded to a power of two), reduced to at most
/// `max_bins` points by taking the maximum per bucket.
pub fn spectrum(samples: &[f64], max_bins: usize) -> Vec<(f64, f64)> {
    let samples = &samples[..samples.len().min(SPECTRUM_MAX_SAMPLES)];
    if samples.len() < 2 || max_bins == 0 {
        return Vec::new();
    }
    let n = samples.len();
    let mean = samples.iter().sum::<f64>() / n as f64;
    let size = n.next_power_of_two();
    let mut real = vec![0.0f64; size];
    let mut imaginary = vec![0.0f64; size];
    for (index, &value) in samples.iter().enumerate() {
        let hann = 0.5 - 0.5 * (std::f64::consts::TAU * index as f64 / (n - 1) as f64).cos();
        real[index] = (value - mean) * hann;
    }
    fft(&mut real, &mut imaginary);
    let half = size / 2;
    let magnitudes: Vec<f64> = (0..=half).map(|k| (real[k].hypot(imaginary[k]) / n as f64).max(1e-12)).collect();
    let buckets = max_bins.min(magnitudes.len());
    (0..buckets)
        .map(|bucket| {
            let start = bucket * magnitudes.len() / buckets;
            let end = ((bucket + 1) * magnitudes.len() / buckets).max(start + 1);
            let (best_index, best) = magnitudes[start..end]
                .iter()
                .enumerate()
                .fold((0, 0.0f64), |acc, (i, &m)| if m > acc.1 { (i, m) } else { acc });
            let frequency = (start + best_index) as f64 / size as f64;
            (frequency, 20.0 * best.log10())
        })
        .collect()
}

/// In-place iterative radix-2 Cooley–Tukey FFT; length must be a power of two.
fn fft(real: &mut [f64], imaginary: &mut [f64]) {
    let n = real.len();
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;
        if i < j {
            real.swap(i, j);
            imaginary.swap(i, j);
        }
    }
    let mut length = 2;
    while length <= n {
        let angle = -std::f64::consts::TAU / length as f64;
        let (w_real, w_imaginary) = (angle.cos(), angle.sin());
        for start in (0..n).step_by(length) {
            let (mut u_real, mut u_imaginary) = (1.0f64, 0.0f64);
            for k in 0..length / 2 {
                let a = start + k;
                let b = a + length / 2;
                let t_real = real[b] * u_real - imaginary[b] * u_imaginary;
                let t_imaginary = real[b] * u_imaginary + imaginary[b] * u_real;
                real[b] = real[a] - t_real;
                imaginary[b] = imaginary[a] - t_imaginary;
                real[a] += t_real;
                imaginary[a] += t_imaginary;
                let next = u_real * w_real - u_imaginary * w_imaginary;
                u_imaginary = u_real * w_imaginary + u_imaginary * w_real;
                u_real = next;
            }
        }
        length <<= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize, mut state: u32) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }

    fn english(len: usize) -> Vec<u8> {
        let text = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, \
it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness. \
The quick brown fox jumps over the lazy dog while a binary viewer quietly counts every byte it can find. ";
        text.bytes().cycle().take(len).collect()
    }

    #[test]
    fn noise_measures_like_ent_reports_for_random_data() {
        let stats = byte_stats(&noise(256 * 1024, 0x1234_5678));
        assert!(stats.entropy > 7.99, "{}", stats.entropy);
        assert!((0.001..0.999).contains(&stats.chi_square_p), "{}", stats.chi_square_p);
        assert!(stats.serial_correlation.abs() < 0.01, "{}", stats.serial_correlation);
        assert!(stats.pi_error_percent < 1.0, "{}", stats.pi_error_percent);
        assert!((stats.mean - 127.5).abs() < 1.0);
        assert_eq!(verdict(&stats).label, "Encrypted or random");
    }

    #[test]
    fn text_zeros_and_empty_get_the_right_verdicts() {
        let stats = byte_stats(&english(64 * 1024));
        assert!((4.0..5.0).contains(&stats.entropy), "{}", stats.entropy);
        assert!(stats.printable_fraction > 0.95);
        assert_eq!(verdict(&stats).label, "Text");
        assert_eq!(verdict(&byte_stats(&[0u8; 4096])).label, "Constant fill");
        let empty = byte_stats(&[]);
        assert_eq!(verdict(&empty).label, "Empty");
        assert_eq!(empty.chi_square_p, 1.0);
    }

    /// Deflate output is high-entropy but measurably non-uniform: with this
    /// sample (varied text, about 30 KiB compressed) the chi-square p-value
    /// is far below 0.01, so it reads as compressed rather than random.
    #[test]
    fn deflated_text_reads_as_compressed() {
        let mut text = Vec::new();
        for i in 0..20_000u32 {
            text.extend_from_slice(format!("record {i:05} temperature={} status={} note=", (i * 37) % 101, ["ok", "warn", "fail"][(i % 3) as usize]).as_bytes());
            text.extend_from_slice(&english(((i * 7) % 40 + 10) as usize));
            text.push(b'\n');
        }
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&text).unwrap();
        let packed = encoder.finish().unwrap();
        let stats = byte_stats(&packed);
        assert!(stats.entropy > 7.5, "{}", stats.entropy);
        assert!(stats.chi_square_p < 0.01, "p = {}", stats.chi_square_p);
        assert_eq!(verdict(&stats).label, "Compressed");
    }

    #[test]
    fn digraphs_count_every_consecutive_pair() {
        let bytes = noise(10_000, 9);
        let counts = digraph_counts(&bytes);
        assert_eq!(counts.len(), 65_536);
        assert_eq!(counts.iter().map(|&c| c as usize).sum::<usize>(), bytes.len() - 1);
        assert_eq!(digraph_counts(&[]).iter().sum::<u32>(), 0);
    }

    #[test]
    fn sliding_entropy_and_compressibility_find_the_change() {
        let mut bytes = english(32 * 1024);
        bytes.extend(noise(32 * 1024, 3));
        let curve = sliding_entropy(&bytes, 1024, 64);
        assert!(curve.len() <= 64);
        let first_high = curve.iter().find(|(_, e)| *e > 7.0).map(|(o, _)| *o).unwrap();
        assert!((30 * 1024..=33 * 1024).contains(&first_high), "{first_high}");
        let zeros = compressibility(&[0u8; 65_536], 4096, 8);
        assert!(zeros.iter().all(|(_, r)| *r < 0.05));
        let random = compressibility(&noise(65_536, 5), 4096, 8);
        assert!(random.iter().all(|(_, r)| *r > 0.95));
        assert!(sliding_entropy(&[], 10, 10).is_empty() && compressibility(&[], 10, 10).is_empty());
    }

    #[test]
    fn a_planted_marker_is_the_top_repeat_and_padding_is_ignored() {
        let marker = b"\xDE\xAD\xBE\xEFMARKER!!";
        let mut bytes = Vec::new();
        let filler = noise(40 * 200, 11);
        for i in 0..40 {
            bytes.extend_from_slice(marker);
            bytes.extend_from_slice(&filler[i * 200..i * 200 + 200]);
        }
        bytes.extend(std::iter::repeat_n(0u8, 4096));
        let repeats = repeated_sequences(&bytes, 4, 16, 5);
        let top = repeats.first().expect("a repeat");
        assert_eq!(top.bytes.as_slice(), marker.as_slice());
        assert_eq!(top.count, 40);
        assert_eq!(top.first_offsets[..2], [0, 212]);
        assert!(repeats.iter().all(|r| r.bytes.iter().any(|&b| b != r.bytes[0])), "no padding runs");
        assert!(repeated_sequences(&[], 4, 16, 5).is_empty());
    }

    /// Timing check: `cargo test --release --lib repeat_timing -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn repeat_timing_on_eight_mebibytes() {
        let mut bytes = noise(8 * 1024 * 1024, 77);
        for i in (0..bytes.len() - 16).step_by(4096) {
            bytes[i..i + 12].copy_from_slice(b"\xCA\xFE\xBA\xBErecord!!");
        }
        let started = std::time::Instant::now();
        let repeats = repeated_sequences(&bytes, 4, 16, 10);
        eprintln!("repeated_sequences on 8 MiB: {:?}, top {:?}", started.elapsed(), repeats.first().map(|r| (r.bytes.len(), r.count)));
    }

    #[test]
    fn spectrum_peaks_at_the_sine_frequency() {
        let samples: Vec<f64> = (0..4096).map(|i| (i as f64 * std::f64::consts::TAU * 0.125).sin() + 3.0).collect();
        let bins = spectrum(&samples, 4096);
        let peak = bins.iter().fold((0.0, f64::MIN), |best, &(f, db)| if db > best.1 { (f, db) } else { best });
        assert!((peak.0 - 0.125).abs() <= 1.0 / 4096.0, "{peak:?}");
        assert!(spectrum(&[], 10).is_empty() && spectrum(&[1.0], 10).is_empty());
        assert!(spectrum(&samples, 100).len() <= 100);
    }
}
