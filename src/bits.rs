//! Bit-level structure: repeating bit periods, sync words and bit planes.
//!
//! Byte-oriented tools miss data framed in units that are not whole bytes:
//! a 10-bit sample stream, a 37-bit telemetry frame, a serial capture. Here
//! the data is treated as a stream of bits and compared with itself at every
//! bit lag (64 bits at a time, counting differences with `popcount`). Lags at
//! which the stream agrees with itself more than chance are candidate frame
//! lengths; the bits that never change within a frame are its sync word.
//!
//! Bit planes split each byte into its eight bits and show each bit position
//! as its own image, which exposes data hidden in low bits or flags packed
//! into high bits.

use rayon::prelude::*;

/// Most bits compared by the period scan (2 Mbit = 256 KiB of data).
pub const MAX_SCAN_BITS: usize = 2 * 1024 * 1024;
/// Most frames examined when looking for a sync word.
const MAX_SYNC_FRAMES: usize = 8192;
/// Longest sync word reported, in bits.
pub const MAX_SYNC_BITS: usize = 64;
/// A bit position counts as part of the sync word when it holds the same
/// value in at least this fraction of frames.
const SYNC_CONSISTENCY: f64 = 0.95;
/// Fewest frames needed before a sync word is believable.
const MIN_SYNC_FRAMES: usize = 4;
/// A period candidate must rise this many robust deviations above the baseline.
const MIN_PROMINENCE: f32 = 6.0;
/// And at least this far above the baseline in absolute agreement.
const MIN_EXCESS: f32 = 0.03;
/// Candidates returned by the period scan.
const MAX_CANDIDATES: usize = 12;
/// Bits in a storage word.
const WORD_BITS: usize = 64;

/// The order in which the bits of each byte enter the stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub enum BitOrder {
    /// Bit 7 of each byte first (most serial protocols and image formats).
    #[default]
    #[serde(rename = "msb")]
    MsbFirst,
    /// Bit 0 of each byte first (UARTs, many radio links).
    #[serde(rename = "lsb")]
    LsbFirst,
}

impl BitOrder {
    pub const ALL: [BitOrder; 2] = [BitOrder::MsbFirst, BitOrder::LsbFirst];

    pub fn label(self) -> &'static str {
        match self {
            BitOrder::MsbFirst => "MSB first",
            BitOrder::LsbFirst => "LSB first",
        }
    }
}

/// A packed stream of bits. Bit `i` of the stream is stored at bit
/// `63 - i % 64` of word `i / 64`, so the stream reads left to right within
/// each word, which keeps shifted reads simple.
#[derive(Clone, Debug, Default)]
pub struct BitStream {
    words: Vec<u64>,
    len_bits: usize,
}

impl BitStream {
    /// Build a stream from `bytes`, reading each byte in `order`.
    pub fn from_bytes(bytes: &[u8], order: BitOrder) -> Self {
        let mut words = vec![0u64; bytes.len().div_ceil(8)];
        for (index, &byte) in bytes.iter().enumerate() {
            let ordered = match order {
                BitOrder::MsbFirst => byte,
                BitOrder::LsbFirst => byte.reverse_bits(),
            };
            let shift = 56 - (index % 8) * 8;
            words[index / 8] |= u64::from(ordered) << shift;
        }
        BitStream { words, len_bits: bytes.len() * 8 }
    }

    /// Number of bits in the stream.
    pub fn len(&self) -> usize {
        self.len_bits
    }

    pub fn is_empty(&self) -> bool {
        self.len_bits == 0
    }

    /// The bit at `index`, or `false` past the end.
    pub fn bit(&self, index: usize) -> bool {
        if index >= self.len_bits {
            return false;
        }
        (self.words[index / WORD_BITS] >> (63 - index % WORD_BITS)) & 1 == 1
    }

    /// The 64 bits starting at `start`, first bit in the most significant
    /// position. Bits past the end read as zero.
    pub fn word_at(&self, start: usize) -> u64 {
        let word_index = start / WORD_BITS;
        let shift = start % WORD_BITS;
        let first = self.words.get(word_index).copied().unwrap_or(0);
        if shift == 0 {
            return first;
        }
        let second = self.words.get(word_index + 1).copied().unwrap_or(0);
        (first << shift) | (second >> (WORD_BITS - shift))
    }

    /// `count` bits (at most 64) starting at `start`, as an integer whose
    /// least significant bit is the last bit read.
    pub fn bits_at(&self, start: usize, count: usize) -> u64 {
        let count = count.min(WORD_BITS);
        if count == 0 {
            return 0;
        }
        self.word_at(start) >> (WORD_BITS - count)
    }
}

/// Fraction of bits that agree between the stream and itself shifted by
/// `lag` bits, over at most `MAX_SCAN_BITS` comparisons.
pub fn bit_agreement(stream: &BitStream, lag: usize) -> f32 {
    if lag == 0 || lag >= stream.len() {
        return 0.0;
    }
    let comparable = (stream.len() - lag).min(MAX_SCAN_BITS);
    let whole_words = comparable / WORD_BITS;
    let mut differences: u64 = 0;
    for word in 0..whole_words {
        let start = word * WORD_BITS;
        differences += u64::from((stream.word_at(start) ^ stream.word_at(start + lag)).count_ones());
    }
    let tail = comparable % WORD_BITS;
    if tail > 0 {
        let start = whole_words * WORD_BITS;
        let mask = !0u64 << (WORD_BITS - tail);
        differences += u64::from(((stream.word_at(start) ^ stream.word_at(start + lag)) & mask).count_ones());
    }
    1.0 - differences as f32 / comparable as f32
}

/// One repeating bit period.
#[derive(Clone, Debug, PartialEq)]
pub struct BitPeriod {
    /// Period in bits.
    pub period: usize,
    /// Fraction of bits equal to the bit one period later.
    pub agreement: f32,
    /// How far the agreement rises above the baseline, in robust deviations.
    pub prominence: f32,
    /// The smallest stronger-or-equal candidate this period is a multiple of.
    pub multiple_of: Option<usize>,
}

impl BitPeriod {
    /// Whether the period is a whole number of bytes (byte tools find these too).
    pub fn byte_aligned(&self) -> bool {
        self.period.is_multiple_of(8)
    }
}

/// The result of a bit period scan.
#[derive(Clone, Debug, Default)]
pub struct BitPeriodScan {
    pub order: BitOrder,
    /// Bits examined.
    pub bits: usize,
    /// Agreement at every lag; index is the lag in bits (index 0 unused).
    pub agreement: Vec<f32>,
    /// Median agreement, the level of "no structure".
    pub baseline: f32,
    /// Candidates, fundamentals before their multiples, strongest first.
    pub candidates: Vec<BitPeriod>,
}

/// Scan for bit periods from 2 to `max_period` bits in `bytes`.
pub fn scan_bit_periods(bytes: &[u8], order: BitOrder, max_period: usize) -> BitPeriodScan {
    let byte_limit = (MAX_SCAN_BITS + max_period * 2) / 8 + 8;
    let stream = BitStream::from_bytes(&bytes[..bytes.len().min(byte_limit)], order);
    let max_period = max_period.min(stream.len() / 4);
    if max_period < 2 {
        return BitPeriodScan { order, bits: stream.len(), ..Default::default() };
    }
    let mut agreement = vec![0.0f32; max_period + 1];
    agreement[1..].par_iter_mut().enumerate().for_each(|(index, slot)| *slot = bit_agreement(&stream, index + 1));

    let (baseline, deviation) = median_and_deviation(&agreement[2..]);
    let mut candidates: Vec<BitPeriod> = (2..=max_period)
        .filter(|&lag| is_local_peak(&agreement, lag))
        .filter_map(|lag| {
            let excess = agreement[lag] - baseline;
            let prominence = excess / deviation;
            (excess >= MIN_EXCESS && prominence >= MIN_PROMINENCE).then_some(BitPeriod {
                period: lag,
                agreement: agreement[lag],
                prominence,
                multiple_of: None,
            })
        })
        .collect();
    mark_multiples(&mut candidates);
    candidates.truncate(MAX_CANDIDATES);
    BitPeriodScan { order, bits: stream.len(), agreement, baseline, candidates }
}

/// A lag whose agreement is at least that of its neighbours.
fn is_local_peak(agreement: &[f32], lag: usize) -> bool {
    let here = agreement[lag];
    let before = if lag > 2 { agreement[lag - 1] } else { f32::MIN };
    let after = agreement.get(lag + 1).copied().unwrap_or(f32::MIN);
    here >= before && here >= after
}

/// Median, and median absolute deviation (floored so flat data cannot divide by zero).
fn median_and_deviation(values: &[f32]) -> (f32, f32) {
    const DEVIATION_FLOOR: f32 = 0.002;
    if values.is_empty() {
        return (0.0, DEVIATION_FLOOR);
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f32::total_cmp);
    let median = sorted[sorted.len() / 2];
    let mut deviations: Vec<f32> = sorted.iter().map(|v| (v - median).abs()).collect();
    deviations.sort_by(f32::total_cmp);
    (median, deviations[deviations.len() / 2].max(DEVIATION_FLOOR))
}

/// Order candidates strongest first, note which are multiples of a smaller
/// candidate that is nearly as strong, and list fundamentals first.
fn mark_multiples(candidates: &mut [BitPeriod]) {
    const NEARLY_AS_STRONG: f32 = 0.9;
    let snapshot: Vec<(usize, f32)> = candidates.iter().map(|c| (c.period, c.agreement - 0.5)).collect();
    for candidate in candidates.iter_mut() {
        let strength = candidate.agreement - 0.5;
        candidate.multiple_of = snapshot
            .iter()
            .filter(|&&(period, other)| period < candidate.period && candidate.period.is_multiple_of(period) && other >= strength * NEARLY_AS_STRONG)
            .map(|&(period, _)| period)
            .min();
    }
    candidates.sort_by(|a, b| a.multiple_of.is_some().cmp(&b.multiple_of.is_some()).then(b.agreement.total_cmp(&a.agreement)).then(a.period.cmp(&b.period)));
}

/// A run of bits that recurs once per frame.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncPattern {
    /// Bit offset of the first occurrence from the start of the data.
    pub bit_offset: usize,
    /// Frame length in bits.
    pub period: usize,
    /// Length of the sync word in bits.
    pub length: usize,
    /// The sync word, last bit in the least significant position.
    pub pattern: u64,
    /// Fraction of frames whose bits at the sync position match it exactly.
    pub match_fraction: f64,
    /// Frames examined.
    pub frames: usize,
}

impl SyncPattern {
    /// The sync word as a string of 0s and 1s.
    pub fn bits_text(&self) -> String {
        (0..self.length).rev().map(|shift| if (self.pattern >> shift) & 1 == 1 { '1' } else { '0' }).collect()
    }
}

/// Find the sync word of frames `period` bits long: the longest run of bit
/// positions (within the frame, wrapping round) that hold the same value in
/// nearly every frame, less any idle (a long stretch of one value, the
/// silence between bursts) at either end; a run that is all idle is no sync
/// word. Returns `None` without enough frames or a stable run.
pub fn find_sync(bytes: &[u8], order: BitOrder, period: usize) -> Option<SyncPattern> {
    if period < 2 {
        return None;
    }
    let byte_limit = (period * (MAX_SYNC_FRAMES + 1)).div_ceil(8);
    let stream = BitStream::from_bytes(&bytes[..bytes.len().min(byte_limit)], order);
    let frames = (stream.len() / period).min(MAX_SYNC_FRAMES);
    if frames < MIN_SYNC_FRAMES {
        return None;
    }
    let stable = stable_positions(&stream, period, frames);
    let (start, length) = circular_runs(&stable)
        .into_iter()
        .filter_map(|(start, length)| without_idle(&stable, start, length))
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))?;
    let length = length.min(MAX_SYNC_BITS);
    let pattern = stream.bits_at(start, length);
    let matching = (0..frames)
        .filter(|frame| {
            let position = start + frame * period;
            position + length <= stream.len() && stream.bits_at(position, length) == pattern
        })
        .count();
    Some(SyncPattern { bit_offset: start, period, length, pattern, match_fraction: matching as f64 / frames as f64, frames })
}

/// For each bit position within the frame, the value it holds in at least
/// `SYNC_CONSISTENCY` of the frames, if it holds one.
fn stable_positions(stream: &BitStream, period: usize, frames: usize) -> Vec<Option<bool>> {
    (0..period)
        .map(|phase| {
            let ones = (0..frames).filter(|frame| stream.bit(phase + frame * period)).count();
            let majority = ones.max(frames - ones);
            (majority as f64 >= frames as f64 * SYNC_CONSISTENCY).then_some(ones * 2 > frames)
        })
        .collect()
}

/// The runs of stable positions in a circular frame: (start, length). The
/// whole frame being stable means the data is constant, which has no sync word.
fn circular_runs(stable: &[Option<bool>]) -> Vec<(usize, usize)> {
    let len = stable.len();
    if len == 0 || stable.iter().all(Option::is_some) {
        return Vec::new();
    }
    // Start only where a run begins (previous position unstable), then walk round.
    (0..len)
        .filter(|&start| stable[start].is_some() && stable[(start + len - 1) % len].is_none())
        .map(|start| (start, (0..len).take_while(|step| stable[(start + step) % len].is_some()).count()))
        .collect()
}

/// The run of stable bits at `start` without the idle at its ends: a
/// stretch of one value at least `IDLE_BITS` long. `None` when nothing but
/// one value is left.
fn without_idle(stable: &[Option<bool>], start: usize, length: usize) -> Option<(usize, usize)> {
    const IDLE_BITS: usize = 8;
    let value = |step: usize| stable[(start + step) % stable.len()];
    let leading = (0..length).take_while(|&step| value(step) == value(0)).count();
    if leading == length {
        return None;
    }
    let trailing = (0..length).rev().take_while(|&step| value(step) == value(length - 1)).count();
    let cut_front = if leading >= IDLE_BITS { leading } else { 0 };
    let cut_back = if trailing >= IDLE_BITS { trailing } else { 0 };
    let kept = length - cut_front - cut_back;
    (kept > 1).then_some(((start + cut_front) % stable.len(), kept))
}

// ---------------------------------------------------------------------------
// Bit planes
// ---------------------------------------------------------------------------

/// Bit `bit` (0 = least significant) of every byte, as 0 or 255 so the
/// plane can be shown as a greyscale image.
pub fn bit_plane(bytes: &[u8], bit: u32) -> Vec<u8> {
    let bit = bit.min(7);
    bytes.iter().map(|&byte| if (byte >> bit) & 1 == 1 { 255 } else { 0 }).collect()
}

/// How much one bit plane says.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlaneScore {
    /// Bit position, 0 = least significant.
    pub bit: u32,
    /// Fraction of bytes with this bit set.
    pub ones_fraction: f64,
    /// Entropy of the bit on its own, 0..1 bits.
    pub entropy: f64,
    /// Information the left and upper neighbours give about the bit, 0..1
    /// bits: zero for a constant plane and for pure noise, high for planes
    /// with shapes in them.
    pub structure: f64,
}

impl PlaneScore {
    /// A short verdict for the user.
    pub fn verdict(&self) -> &'static str {
        const CONSTANT: f64 = 0.01;
        const STRUCTURED: f64 = 0.1;
        const FAINT: f64 = 0.02;
        if self.entropy < CONSTANT {
            "constant"
        } else if self.structure >= STRUCTURED {
            "structured"
        } else if self.structure >= FAINT {
            "faint structure"
        } else {
            "noise"
        }
    }
}

/// Score each of the eight bit planes of `bytes`, laid out `row_width`
/// bytes per row (0 means treat as one long row).
pub fn plane_scores(bytes: &[u8], row_width: usize) -> [PlaneScore; 8] {
    std::array::from_fn(|bit| score_plane(bytes, bit as u32, row_width))
}

fn score_plane(bytes: &[u8], bit: u32, row_width: usize) -> PlaneScore {
    let bit_of = |index: usize| (bytes[index] >> bit) & 1 == 1;
    let ones = bytes.iter().filter(|&&byte| (byte >> bit) & 1 == 1).count();
    let ones_fraction = if bytes.is_empty() { 0.0 } else { ones as f64 / bytes.len() as f64 };
    let entropy = binary_entropy(ones_fraction);

    // Counts of (context, bit) where the context is the left and upper bits.
    let mut counts = [[0u64; 2]; 4];
    let first = if row_width > 0 { row_width.max(1) } else { 1 };
    for index in first..bytes.len() {
        let left = bit_of(index - 1);
        let above = if row_width > 0 { bit_of(index - row_width) } else { false };
        let context = usize::from(left) * 2 + usize::from(above);
        counts[context][usize::from(bit_of(index))] += 1;
    }
    let total: u64 = counts.iter().flatten().sum();
    let conditional = if total == 0 {
        entropy
    } else {
        counts
            .iter()
            .map(|[zeros, ones]| {
                let in_context = zeros + ones;
                if in_context == 0 {
                    return 0.0;
                }
                in_context as f64 / total as f64 * binary_entropy(*ones as f64 / in_context as f64)
            })
            .sum()
    };
    PlaneScore { bit, ones_fraction, entropy, structure: (entropy - conditional).max(0.0) }
}

/// Entropy in bits of a coin that lands heads with probability `p`.
fn binary_entropy(p: f64) -> f64 {
    if p <= 0.0 || p >= 1.0 {
        return 0.0;
    }
    -(p * p.log2() + (1.0 - p) * (1.0 - p).log2())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic pseudo-random generator for test data.
    fn noise(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed;
        move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        }
    }

    /// Frames of `period` bits: a sync word then random payload, MSB first.
    fn framed_bits(period: usize, sync: u64, sync_bits: usize, frames: usize) -> Vec<u8> {
        let mut random = noise(7);
        let mut bits = Vec::with_capacity(period * frames);
        for _ in 0..frames {
            for shift in (0..sync_bits).rev() {
                bits.push((sync >> shift) & 1 == 1);
            }
            for _ in sync_bits..period {
                bits.push(random() & 1 == 1);
            }
        }
        pack_msb_first(&bits)
    }

    fn pack_msb_first(bits: &[bool]) -> Vec<u8> {
        bits.chunks(8).map(|chunk| chunk.iter().enumerate().fold(0u8, |byte, (index, &bit)| byte | (u8::from(bit) << (7 - index)))).collect()
    }

    #[test]
    fn stream_reads_bits_in_either_order() {
        let msb = BitStream::from_bytes(&[0b1000_0001, 0xFF], BitOrder::MsbFirst);
        assert!(msb.bit(0));
        assert!(!msb.bit(1));
        assert!(msb.bit(7));
        assert_eq!(msb.bits_at(4, 8), 0b0001_1111);
        let lsb = BitStream::from_bytes(&[0b0000_0010], BitOrder::LsbFirst);
        assert!(!lsb.bit(0));
        assert!(lsb.bit(1));
        assert!(!lsb.bit(100), "bits past the end read as zero");
    }

    #[test]
    fn a_37_bit_frame_with_a_sync_word_is_found_at_period_37() {
        let data = framed_bits(37, 0b1_0110_0111_0001, 13, 3000);
        let scan = scan_bit_periods(&data, BitOrder::MsbFirst, 200);
        let best = scan.candidates.first().expect("a period is found");
        assert_eq!(best.period, 37);
        assert!(!best.byte_aligned());
        assert!(scan.candidates.iter().filter(|c| c.period == 74).all(|c| c.multiple_of == Some(37)));
    }

    #[test]
    fn a_10_bit_frame_is_found_with_lsb_first_ordering() {
        // Each 10-bit frame starts with "11" then random bits, read LSB first.
        let msb_data = framed_bits(10, 0b11, 2, 20_000);
        let lsb_data: Vec<u8> = msb_data.iter().map(|byte| byte.reverse_bits()).collect();
        let scan = scan_bit_periods(&lsb_data, BitOrder::LsbFirst, 64);
        assert_eq!(scan.candidates.first().map(|c| c.period), Some(10));
    }

    #[test]
    fn random_data_has_no_bit_period() {
        let mut random = noise(99);
        let data: Vec<u8> = (0..50_000).map(|_| random() as u8).collect();
        let scan = scan_bit_periods(&data, BitOrder::MsbFirst, 128);
        assert!(scan.candidates.is_empty(), "found {:?}", scan.candidates.first());
    }

    #[test]
    fn the_sync_word_and_its_offset_are_reported() {
        let sync = 0b1_0110_0111_0001;
        let data = framed_bits(37, sync, 13, 500);
        let found = find_sync(&data, BitOrder::MsbFirst, 37).expect("sync found");
        assert_eq!(found.bit_offset, 0);
        assert!(found.length >= 13, "length {}", found.length);
        // Random payload bits may extend the run by chance, so check the start.
        assert_eq!(found.pattern >> (found.length - 13), sync);
        assert!(found.match_fraction > 0.9);
    }

    #[test]
    fn the_idle_between_bursts_is_not_the_sync_word() {
        // Each burst: 80 bits of silence, the sync word, then the payload.
        let sync = 0b1010_1010_1011_0010_1101;
        let mut random = noise(11);
        let mut bits = Vec::new();
        for _ in 0..400 {
            bits.extend([false; 80]);
            bits.extend((0..20).rev().map(|shift| (sync >> shift) & 1 == 1));
            bits.extend((0..40).map(|_| random() & 1 == 1));
        }
        let data = pack_msb_first(&bits);
        let found = find_sync(&data, BitOrder::MsbFirst, 140).expect("sync found");
        assert_eq!((found.bit_offset, found.pattern >> (found.length - 20)), (80, sync), "{found:?} {}", found.bits_text());
        for idle in [0u8, 0xFF] {
            let constant: Vec<u8> = data.iter().map(|byte| if idle == 0 { *byte } else { !byte }).collect();
            let found = find_sync(&constant, BitOrder::MsbFirst, 140).expect("sync found");
            assert!(found.bits_text().contains('0') && found.bits_text().contains('1'), "{}", found.bits_text());
        }
    }

    #[test]
    fn sync_search_rejects_short_or_empty_input() {
        assert_eq!(find_sync(&[], BitOrder::MsbFirst, 37), None);
        assert_eq!(find_sync(&[0xAA; 4], BitOrder::MsbFirst, 37), None);
        assert_eq!(find_sync(&[0u8; 1000], BitOrder::MsbFirst, 37), None, "constant data has no sync word");
    }

    #[test]
    fn bit_planes_are_0_or_255_per_byte() {
        assert_eq!(bit_plane(&[0b0000_0001, 0b0000_0010, 0xFF], 0), vec![255, 0, 255]);
        assert_eq!(bit_plane(&[0b1000_0000], 7), vec![255]);
    }

    #[test]
    fn plane_scores_tell_shapes_from_noise_and_constants() {
        // Bit 7: a square in the middle of a 64-wide image; bits 0..3 random; bit 5 always set.
        let mut random = noise(3);
        let width = 64;
        let data: Vec<u8> = (0..width * 64)
            .map(|index| {
                let (row, column) = (index / width, index % width);
                let square = (16..48).contains(&row) && (16..48).contains(&column);
                (u8::from(square) << 7) | 0b0010_0000 | (random() as u8 & 0x0F)
            })
            .collect();
        let scores = plane_scores(&data, width);
        assert_eq!(scores[7].verdict(), "structured");
        assert_eq!(scores[5].verdict(), "constant");
        assert_eq!(scores[0].verdict(), "noise");
        assert!(scores[7].structure > scores[0].structure);
    }

    #[test]
    fn empty_input_is_handled() {
        let scan = scan_bit_periods(&[], BitOrder::MsbFirst, 100);
        assert!(scan.candidates.is_empty());
        let scores = plane_scores(&[], 16);
        assert_eq!(scores[0].ones_fraction, 0.0);
    }
}
