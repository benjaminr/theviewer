//! Per-block file-type classification for carving headerless fragments.
//!
//! The data is cut into fixed blocks (4 KiB by default) and each block is
//! classified on its own from simple, explainable features: byte statistics
//! from [`crate::stats`], text and markup tests, 16-bit sample smoothness,
//! adjacent-byte smoothness, opcode frequencies and short-lag
//! autocorrelation. Rules are tried in a fixed order and the first that fits
//! wins, so the result is deterministic and every decision carries a reason.
//! Neighbouring blocks of the same class are then merged into runs.

use rayon::prelude::*;

use crate::compress;
use crate::stats::{self, ByteStats};

/// The default block size: one page, the usual unit of file-system storage.
pub const DEFAULT_BLOCK_SIZE: usize = 4096;
/// Smallest block size that gives meaningful statistics.
pub const MIN_BLOCK_SIZE: usize = 256;

/// What a block most likely holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockClass {
    /// One repeated value, or nearly all zeros or 0xFF.
    Padding,
    /// ASCII, UTF-8 or UTF-16 text.
    Text,
    /// XML, HTML or JSON.
    Markup,
    /// Instruction streams (x86, ARM, AArch64).
    MachineCode,
    /// High entropy with a detectably non-uniform byte distribution.
    Compressed,
    /// High entropy indistinguishable from uniform random bytes.
    Random,
    /// Raw pixels: neighbouring bytes change smoothly.
    Image,
    /// 16-bit little-endian PCM samples.
    Audio,
    /// Fixed-size records: bytes repeat at a short period.
    Table,
    /// None of the above with any confidence.
    Binary,
}

impl BlockClass {
    pub const ALL: [BlockClass; 10] = [
        BlockClass::Padding,
        BlockClass::Text,
        BlockClass::Markup,
        BlockClass::MachineCode,
        BlockClass::Compressed,
        BlockClass::Random,
        BlockClass::Image,
        BlockClass::Audio,
        BlockClass::Table,
        BlockClass::Binary,
    ];

    pub fn label(self) -> &'static str {
        match self {
            BlockClass::Padding => "Zeros / padding",
            BlockClass::Text => "Text",
            BlockClass::Markup => "Markup",
            BlockClass::MachineCode => "Machine code",
            BlockClass::Compressed => "Compressed",
            BlockClass::Random => "Encrypted / random",
            BlockClass::Image => "Raw image",
            BlockClass::Audio => "PCM audio",
            BlockClass::Table => "Table / records",
            BlockClass::Binary => "Other binary",
        }
    }
}

/// The classification of one block.
#[derive(Clone, Debug, PartialEq)]
pub struct BlockVerdict {
    pub offset: usize,
    pub len: usize,
    pub class: BlockClass,
    /// 0 to 1: how clearly the block met its rule.
    pub confidence: f32,
    /// Why, in a sentence with the measured values.
    pub reason: String,
}

/// Neighbouring blocks of the same class.
#[derive(Clone, Debug, PartialEq)]
pub struct Run {
    pub offset: usize,
    pub len: usize,
    pub class: BlockClass,
    pub blocks: usize,
    /// Mean confidence of the run's blocks.
    pub confidence: f32,
    /// The reason given for the run's first block.
    pub reason: String,
}

impl Run {
    pub fn end(&self) -> usize {
        self.offset + self.len
    }
}

/// Classify `data` in blocks of `block_size` bytes (raised to at least
/// [`MIN_BLOCK_SIZE`]); the last block may be shorter.
pub fn classify_blocks(data: &[u8], block_size: usize) -> Vec<BlockVerdict> {
    let block_size = block_size.max(MIN_BLOCK_SIZE);
    data.par_chunks(block_size)
        .enumerate()
        .map(|(index, block)| {
            let (class, confidence, reason) = classify(block);
            BlockVerdict { offset: index * block_size, len: block.len(), class, confidence, reason }
        })
        .collect()
}

/// Merge consecutive blocks of the same class.
pub fn merge_runs(blocks: &[BlockVerdict]) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    for block in blocks {
        match runs.last_mut() {
            Some(run) if run.class == block.class && run.end() == block.offset => {
                run.confidence = (run.confidence * run.blocks as f32 + block.confidence) / (run.blocks + 1) as f32;
                run.blocks += 1;
                run.len += block.len;
            }
            _ => runs.push(Run { offset: block.offset, len: block.len, class: block.class, blocks: 1, confidence: block.confidence, reason: block.reason.clone() }),
        }
    }
    runs
}

/// Classify one block: its class, confidence and reason.
pub fn classify(block: &[u8]) -> (BlockClass, f32, String) {
    if block.is_empty() {
        return (BlockClass::Padding, 1.0, "empty block".to_string());
    }
    let stats = stats::byte_stats(block);
    let rules: [Rule; 8] = [padding, utf16_text, text_or_markup, high_entropy, audio, machine_code, table, image];
    for rule in rules {
        if let Some(decision) = rule(block, &stats) {
            return (decision.class, decision.confidence.clamp(0.0, 1.0), decision.reason);
        }
    }
    let reason = format!(
        "no rule fits: entropy {:.2} bits/byte, {:.0}% printable, {:.0}% zeros",
        stats.entropy,
        stats.printable_fraction * 100.0,
        stats.zero_fraction * 100.0
    );
    (BlockClass::Binary, 0.3, reason)
}

/// One classification rule: a decision when the block fits, else `None`.
type Rule = fn(&[u8], &ByteStats) -> Option<Decision>;

struct Decision {
    class: BlockClass,
    confidence: f32,
    reason: String,
}

fn decide(class: BlockClass, confidence: f64, reason: String) -> Option<Decision> {
    Some(Decision { class, confidence: confidence as f32, reason })
}

/// How far `value` is past `threshold` towards `full`, as 0 to 1.
fn margin(value: f64, threshold: f64, full: f64) -> f64 {
    if full == threshold { 1.0 } else { ((value - threshold) / (full - threshold)).clamp(0.0, 1.0) }
}

// ---------------------------------------------------------------------------
// Padding
// ---------------------------------------------------------------------------

/// Fraction of bytes that must be 0x00 or 0xFF for "mostly padding".
const PADDING_FRACTION: f64 = 0.95;

fn padding(_block: &[u8], stats: &ByteStats) -> Option<Decision> {
    if stats.distinct_values == 1 {
        let value = stats.histogram.iter().position(|&count| count > 0).unwrap_or(0);
        return decide(BlockClass::Padding, 1.0, format!("every byte is {value:#04x}"));
    }
    let len = stats.len as f64;
    let zeros = stats.histogram[0x00] as f64 / len;
    let erased = stats.histogram[0xFF] as f64 / len;
    let (fraction, name) = if zeros >= erased { (zeros, "0x00") } else { (erased, "0xFF") };
    (fraction >= PADDING_FRACTION).then(|| Decision {
        class: BlockClass::Padding,
        confidence: (0.7 + 0.3 * margin(fraction, PADDING_FRACTION, 1.0)) as f32,
        reason: format!("{:.1}% of bytes are {name}", fraction * 100.0),
    })
}

// ---------------------------------------------------------------------------
// Text and markup
// ---------------------------------------------------------------------------

/// Fraction of printable characters (or UTF-16 units) needed for text.
const TEXT_PRINTABLE: f64 = 0.95;
/// Density of '<' and '>' that suggests tags.
const TAG_DENSITY: f64 = 0.02;
/// Density of JSON punctuation ({}[]":,) that suggests JSON.
const JSON_DENSITY: f64 = 0.08;
const JSON_QUOTE_DENSITY: f64 = 0.03;

fn is_printable_ascii(byte: u8) -> bool {
    (0x20..0x7F).contains(&byte) || matches!(byte, b'\t' | b'\n' | b'\r')
}

fn utf16_text(block: &[u8], _stats: &ByteStats) -> Option<Decision> {
    let units = block.len() / 2;
    if units < 16 {
        return None;
    }
    let pairs = block.as_chunks::<2>().0;
    let ascii_units = |high_first: bool| {
        pairs
            .iter()
            .filter(|pair| {
                let (low, high) = if high_first { (pair[1], pair[0]) } else { (pair[0], pair[1]) };
                high == 0 && is_printable_ascii(low)
            })
            .count() as f64
            / units as f64
    };
    let (little, big) = (ascii_units(false), ascii_units(true));
    let (fraction, order) = if little >= big { (little, "little-endian") } else { (big, "big-endian") };
    (fraction >= TEXT_PRINTABLE * 0.9).then(|| Decision {
        class: BlockClass::Text,
        confidence: (0.75 + 0.25 * margin(fraction, TEXT_PRINTABLE * 0.9, 1.0)) as f32,
        reason: format!("UTF-16 {order} text: {:.0}% of 16-bit units are printable ASCII", fraction * 100.0),
    })
}

/// UTF-8 validity, tolerating a character cut at either end of the block.
fn is_mostly_utf8(block: &[u8]) -> bool {
    let inner = trim_partial_utf8(block);
    std::str::from_utf8(inner).is_ok()
}

fn trim_partial_utf8(block: &[u8]) -> &[u8] {
    let is_continuation = |byte: u8| byte & 0xC0 == 0x80;
    let start = block.iter().take(3).take_while(|&&byte| is_continuation(byte)).count();
    let mut end = block.len();
    // Drop an incomplete sequence at the end: up to 3 bytes.
    for back in 1..=3.min(block.len().saturating_sub(start)) {
        let byte = block[block.len() - back];
        if byte & 0xC0 == 0xC0 {
            let needed = if byte >= 0xF0 { 4 } else if byte >= 0xE0 { 3 } else { 2 };
            if needed > back {
                end = block.len() - back;
            }
            break;
        }
        if !is_continuation(byte) {
            break;
        }
    }
    &block[start..end.max(start)]
}

fn text_or_markup(block: &[u8], stats: &ByteStats) -> Option<Decision> {
    let printable = stats.printable_fraction;
    let utf8 = stats.high_fraction > 0.0 && is_mostly_utf8(block);
    let text_fraction = if utf8 { printable + stats.high_fraction } else { printable };
    if text_fraction < TEXT_PRINTABLE {
        return None;
    }
    let encoding = if utf8 { "UTF-8" } else { "ASCII" };
    let count = |set: &[u8]| block.iter().filter(|byte| set.contains(byte)).count() as f64 / block.len() as f64;
    let tags = count(b"<>");
    let has_tag_syntax = [&b"</"[..], b"/>", b"<?xml", b"<!DOCTYPE", b"<html"].iter().any(|needle| block.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle)));
    if tags >= TAG_DENSITY && has_tag_syntax {
        return decide(BlockClass::Markup, 0.7 + 0.3 * margin(tags, TAG_DENSITY, 0.1), format!("{encoding} text with tags: {:.1}% of bytes are '<' or '>' and closing tags appear", tags * 100.0));
    }
    let json = count(b"{}[]\":,");
    let quotes = count(b"\"");
    if json >= JSON_DENSITY && quotes >= JSON_QUOTE_DENSITY {
        return decide(BlockClass::Markup, 0.6 + 0.3 * margin(json, JSON_DENSITY, 0.25), format!("{encoding} text dense with JSON punctuation ({:.0}% of bytes, {:.0}% quotes)", json * 100.0, quotes * 100.0));
    }
    decide(BlockClass::Text, 0.7 + 0.3 * margin(text_fraction, TEXT_PRINTABLE, 1.0), format!("{encoding} text: {:.1}% printable characters, entropy {:.2}", text_fraction * 100.0, stats.entropy))
}

// ---------------------------------------------------------------------------
// Compressed and random
// ---------------------------------------------------------------------------

/// Entropy above which data is compressed or random.
const HIGH_ENTROPY: f64 = 7.5;
/// Chi-square p-value below which the byte distribution is not uniform.
const NON_UNIFORM_P: f64 = 0.01;
/// How far below the entropy expected of random data a block may fall and
/// still be called random.
const RANDOM_ENTROPY_SLACK: f64 = 0.05;

/// The Shannon entropy expected of `len` uniformly random bytes: short
/// samples fall below 8 because not every value appears equally often
/// (Miller–Madow bias, 255 / (2 n ln 2)).
fn expected_random_entropy(len: usize) -> f64 {
    8.0 - 255.0 / (2.0 * len.max(1) as f64 * std::f64::consts::LN_2)
}

fn high_entropy(block: &[u8], stats: &ByteStats) -> Option<Decision> {
    if stats.entropy < HIGH_ENTROPY {
        return None;
    }
    if let Some(codec) = compress::detect_header(block) {
        return decide(BlockClass::Compressed, 0.9, format!("entropy {:.2} and the block starts with a {} header", stats.entropy, codec.label()));
    }
    let random_floor = expected_random_entropy(block.len()) - RANDOM_ENTROPY_SLACK;
    if stats.chi_square_p < NON_UNIFORM_P || stats.entropy < random_floor {
        let confidence = 0.6 + 0.3 * margin(stats.entropy, HIGH_ENTROPY, 8.0);
        return decide(
            BlockClass::Compressed,
            confidence,
            format!("entropy {:.2} is high but the byte distribution is not uniform (chi-square p = {:.4}): compressors leave this bias", stats.entropy, stats.chi_square_p),
        );
    }
    decide(
        BlockClass::Random,
        0.6 + 0.3 * margin(stats.chi_square_p, NON_UNIFORM_P, 0.5),
        format!(
            "entropy {:.3} (random data of this length gives {:.3}) and a uniform byte distribution (chi-square p = {:.3}); well-compressed data can look the same",
            stats.entropy,
            expected_random_entropy(block.len()),
            stats.chi_square_p
        ),
    )
}

// ---------------------------------------------------------------------------
// Audio
// ---------------------------------------------------------------------------

/// Mean sample magnitude below which a block is too quiet to judge.
const AUDIO_MIN_LEVEL: f64 = 256.0;
/// Mean step between samples, relative to the mean magnitude, below which
/// the signal is smooth (sampled sound changes little per sample).
const AUDIO_MAX_ROUGHNESS: f64 = 0.5;
/// Sound swings both ways about zero.
const AUDIO_SIGN_BALANCE: std::ops::RangeInclusive<f64> = 0.25..=0.75;

fn audio(block: &[u8], _stats: &ByteStats) -> Option<Decision> {
    let samples: Vec<f64> = block.as_chunks::<2>().0.iter().map(|pair| i16::from_le_bytes(*pair) as f64).collect();
    if samples.len() < 64 {
        return None;
    }
    let level = samples.iter().map(|sample| sample.abs()).sum::<f64>() / samples.len() as f64;
    if level < AUDIO_MIN_LEVEL {
        return None;
    }
    // Lag 1 for mono, lag 2 for interleaved stereo.
    let roughness = [1, 2].map(|lag| mean_step(&samples, lag) / level).into_iter().fold(f64::INFINITY, f64::min);
    let non_zero = samples.iter().filter(|&&sample| sample != 0.0).count().max(1) as f64;
    let positive = samples.iter().filter(|&&sample| sample > 0.0).count() as f64 / non_zero;
    if roughness > AUDIO_MAX_ROUGHNESS || !AUDIO_SIGN_BALANCE.contains(&positive) {
        return None;
    }
    decide(
        BlockClass::Audio,
        0.6 + 0.35 * (1.0 - roughness / AUDIO_MAX_ROUGHNESS),
        format!(
            "as 16-bit little-endian samples the signal is smooth (mean step {:.0}% of mean level {level:.0}) and swings both ways ({:.0}% positive)",
            roughness * 100.0,
            positive * 100.0
        ),
    )
}

fn mean_step(samples: &[f64], lag: usize) -> f64 {
    let steps = samples.len().saturating_sub(lag).max(1);
    samples.iter().zip(samples.iter().skip(lag)).map(|(a, b)| (a - b).abs()).sum::<f64>() / steps as f64
}

// ---------------------------------------------------------------------------
// Machine code
// ---------------------------------------------------------------------------

/// Instruction streams have moderate entropy.
const CODE_ENTROPY: std::ops::RangeInclusive<f64> = 4.5..=7.2;
const CODE_MAX_PRINTABLE: f64 = 0.65;
const CODE_MAX_ZEROS: f64 = 0.35;
/// The commonest x86 and x86-64 opcode, prefix and ModRM bytes: REX
/// prefixes, mov, lea, call, jcc, push/pop rbp, ret, test, xor, 0F escapes.
const X86_COMMON: [u8; 22] = [
    0x48, 0x89, 0x8B, 0xE8, 0xFF, 0x0F, 0x83, 0x85, 0x74, 0x75, 0xC3, 0x4C, 0x8D, 0x31, 0xC0, 0x24, 0x44, 0x45, 0x5D, 0x55, 0x41, 0x84,
];
/// Fraction of bytes from [`X86_COMMON`] that marks x86 (random data gives
/// 22/256, under 9%).
const X86_THRESHOLD: f64 = 0.22;
/// Fraction of 32-bit words with the ARM "always" condition (0xE in the top
/// nibble) that marks 32-bit ARM code (random data gives 1/16).
const ARM_THRESHOLD: f64 = 0.4;
/// Common top bytes of AArch64 instructions: add/sub immediate, ldr/str,
/// bl, b, mov/orr, stp/ldp, cbz/cbnz, b.cond, adrp.
const AARCH64_COMMON: [u8; 22] = [
    0x91, 0xD1, 0xF9, 0xB9, 0xF8, 0xB8, 0x94, 0x97, 0x14, 0x17, 0xAA, 0x2A, 0xA9, 0xA8, 0x29, 0x28, 0xB4, 0xB5, 0x34, 0x35, 0x54, 0x90,
];
const AARCH64_THRESHOLD: f64 = 0.4;

fn machine_code(block: &[u8], stats: &ByteStats) -> Option<Decision> {
    if !CODE_ENTROPY.contains(&stats.entropy) || stats.printable_fraction > CODE_MAX_PRINTABLE || stats.zero_fraction > CODE_MAX_ZEROS {
        return None;
    }
    let len = block.len() as f64;
    let x86 = X86_COMMON.iter().map(|&byte| stats.histogram[byte as usize]).sum::<u64>() as f64 / len;
    let words = block.as_chunks::<4>().0;
    let word_count = words.len().max(1) as f64;
    let arm = words.iter().filter(|word| word[3] & 0xF0 == 0xE0).count() as f64 / word_count;
    let aarch64 = words.iter().filter(|word| AARCH64_COMMON.contains(&word[3])).count() as f64 / word_count;
    let candidates = [
        ("x86", x86, X86_THRESHOLD, "of bytes are common x86 opcodes and prefixes"),
        ("32-bit ARM", arm, ARM_THRESHOLD, "of 32-bit words carry the ARM 'always' condition"),
        ("AArch64", aarch64, AARCH64_THRESHOLD, "of 32-bit words start with common AArch64 opcodes"),
    ];
    let (name, score, threshold, what) = candidates.into_iter().max_by(|a, b| (a.1 / a.2).total_cmp(&(b.1 / b.2)))?;
    (score >= threshold).then(|| Decision {
        class: BlockClass::MachineCode,
        confidence: (0.55 + 0.4 * margin(score, threshold, threshold * 2.0)) as f32,
        reason: format!("likely {name}: {:.0}% {what}, entropy {:.2}", score * 100.0, stats.entropy),
    })
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// Record sizes tried: 2 to 64 bytes.
const MIN_PERIOD: usize = 2;
const MAX_PERIOD: usize = 64;
/// Bytes compared per lag; enough to see a period without scanning it all.
const PERIOD_SAMPLE: usize = 2048;
/// A period must match this often, and stand this far above the typical lag.
const PERIOD_MIN_MATCH: f64 = 0.35;
const PERIOD_MIN_PROMINENCE: f64 = 0.2;

fn table(block: &[u8], stats: &ByteStats) -> Option<Decision> {
    let sample = &block[..block.len().min(PERIOD_SAMPLE)];
    if sample.len() < MAX_PERIOD * 4 {
        return None;
    }
    let scores: Vec<f64> = (MIN_PERIOD..=MAX_PERIOD)
        .map(|lag| sample.iter().zip(&sample[lag..]).filter(|(a, b)| a == b).count() as f64 / (sample.len() - lag) as f64)
        .collect();
    let mut sorted = scores.clone();
    sorted.sort_by(f64::total_cmp);
    let median = sorted[sorted.len() / 2];
    let best = sorted[sorted.len() - 1];
    // The fundamental period: the shortest lag nearly as good as the best.
    let period_index = scores.iter().position(|&score| score >= best * 0.9)?;
    let period = period_index + MIN_PERIOD;
    let prominence = best - median;
    (best >= PERIOD_MIN_MATCH && prominence >= PERIOD_MIN_PROMINENCE).then(|| Decision {
        class: BlockClass::Table,
        confidence: (0.55 + 0.4 * margin(prominence, PERIOD_MIN_PROMINENCE, 0.6)) as f32,
        reason: format!(
            "bytes repeat every {period} bytes ({:.0}% match against {:.0}% at a typical lag): fixed-size records; entropy {:.2}",
            scores[period_index] * 100.0,
            median * 100.0,
            stats.entropy
        ),
    })
}

// ---------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------

/// Pixel strides tried: grey (1), RGB (3) and RGBA (4) bytes per pixel.
const PIXEL_STRIDES: [usize; 3] = [1, 3, 4];
/// Mean difference to the same channel of the previous pixel below which
/// the bytes are smooth.
const IMAGE_MAX_STEP: f64 = 12.0;
/// Images vary: flat or two-tone blocks are left to other rules.
const IMAGE_MIN_ENTROPY: f64 = 3.0;
const IMAGE_MIN_DISTINCT: usize = 24;

fn image(block: &[u8], stats: &ByteStats) -> Option<Decision> {
    if stats.entropy < IMAGE_MIN_ENTROPY || stats.distinct_values < IMAGE_MIN_DISTINCT {
        return None;
    }
    let (stride, step) = PIXEL_STRIDES
        .iter()
        .map(|&stride| {
            let steps = block.len().saturating_sub(stride).max(1);
            let total: u64 = block.iter().zip(&block[stride.min(block.len())..]).map(|(&a, &b)| a.abs_diff(b) as u64).sum();
            (stride, total as f64 / steps as f64)
        })
        .min_by(|a, b| a.1.total_cmp(&b.1))?;
    let layout = match stride {
        1 => "1 byte per pixel (greyscale or indexed)",
        3 => "3 bytes per pixel (RGB)",
        _ => "4 bytes per pixel (RGBA)",
    };
    (step <= IMAGE_MAX_STEP).then(|| Decision {
        class: BlockClass::Image,
        confidence: (0.5 + 0.4 * (1.0 - step / IMAGE_MAX_STEP)) as f32,
        reason: format!("neighbouring bytes change smoothly at stride {stride} (mean step {step:.1}), as in raw pixels with {layout}; entropy {:.2}", stats.entropy),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn prose(len: usize) -> Vec<u8> {
        let words = ["the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "firmware", "partition", "image", "kernel"];
        let picks = noise(len, 5);
        let mut text = Vec::new();
        for pick in picks {
            text.extend_from_slice(words[pick as usize % words.len()].as_bytes());
            text.push(if pick % 13 == 0 { b'\n' } else { b' ' });
            if text.len() >= len {
                break;
            }
        }
        text.truncate(len);
        text
    }

    fn class_of(block: &[u8]) -> BlockClass {
        classify(block).0
    }

    #[test]
    fn padding_and_text_are_recognised() {
        assert_eq!(class_of(&[0u8; 4096]), BlockClass::Padding);
        let mut mostly_erased = vec![0xFFu8; 4096];
        mostly_erased[100..120].copy_from_slice(&[7; 20]);
        assert_eq!(class_of(&mostly_erased), BlockClass::Padding);
        assert_eq!(class_of(&prose(4096)), BlockClass::Text);
        let utf8 = "Größe, naïve café — ünïcödé ".repeat(200);
        let (class, _, reason) = classify(&utf8.as_bytes()[1..4001]);
        assert_eq!(class, BlockClass::Text, "{reason}");
        assert!(reason.contains("UTF-8"), "{reason}");
        let utf16: Vec<u8> = String::from_utf8(prose(2048)).unwrap().encode_utf16().flat_map(u16::to_le_bytes).collect();
        let (class, _, reason) = classify(&utf16);
        assert_eq!(class, BlockClass::Text);
        assert!(reason.contains("UTF-16 little-endian"), "{reason}");
    }

    #[test]
    fn xml_and_json_are_markup() {
        let xml: String = (0..200).map(|i| format!("<item id=\"{i}\"><name>part {i}</name></item>\n")).collect();
        assert_eq!(class_of(&xml.as_bytes()[..4096]), BlockClass::Markup);
        let json: String = (0..200).map(|i| format!("{{\"id\": {i}, \"name\": \"part {i}\", \"tags\": [\"a\", \"b\"]}},\n")).collect();
        assert_eq!(class_of(&json.as_bytes()[..4096]), BlockClass::Markup);
    }

    #[test]
    fn random_bytes_are_random_and_biased_high_entropy_is_compressed() {
        let (class, confidence, reason) = classify(&noise(4096, 1));
        assert_eq!(class, BlockClass::Random, "{reason}");
        assert!(confidence > 0.5);
        // High entropy, but some byte values are three times as common as others.
        let biased: Vec<u8> = noise(8192, 2).chunks(2).map(|pair| if pair[0] < 64 { pair[1] & 0x3F } else { pair[1] }).take(4096).collect();
        let (class, _, reason) = classify(&biased);
        assert_eq!(class, BlockClass::Compressed, "{reason}");
        let gzip = compress::compress(compress::Codec::Gzip, &noise(8192, 3)).unwrap();
        let (class, _, reason) = classify(&gzip[..4096]);
        assert_eq!(class, BlockClass::Compressed);
        assert!(reason.contains("gzip"), "{reason}");
    }

    #[test]
    fn a_sine_wave_is_audio() {
        let samples: Vec<u8> = (0..2048)
            .flat_map(|i| {
                let t = i as f64 / 44_100.0;
                let value = 9000.0 * (2.0 * std::f64::consts::PI * 440.0 * t).sin() + 2000.0 * (2.0 * std::f64::consts::PI * 1320.0 * t).sin();
                (value as i16).to_le_bytes()
            })
            .collect();
        let (class, _, reason) = classify(&samples);
        assert_eq!(class, BlockClass::Audio, "{reason}");
    }

    #[test]
    fn a_smooth_rgb_gradient_is_an_image() {
        let jitter = noise(4096, 4);
        let pixels: Vec<u8> = (0..4096 / 3 * 3)
            .map(|i| {
                let pixel = i / 3;
                let (x, y) = (pixel % 64, pixel / 64);
                let base = match i % 3 {
                    0 => 40 + x * 2,
                    1 => 60 + y * 3,
                    _ => 200 - x,
                };
                (base as u8).wrapping_add(jitter[i] % 3)
            })
            .collect();
        let (class, _, reason) = classify(&pixels);
        assert_eq!(class, BlockClass::Image, "{reason}");
        assert!(reason.contains("stride 3"), "{reason}");
    }

    #[test]
    fn fixed_size_records_are_a_table() {
        let mut records = Vec::new();
        let jitter = noise(4096, 6);
        for index in 0..256u32 {
            records.extend_from_slice(&index.to_le_bytes());
            records.extend_from_slice(&0x0001_0203u32.to_le_bytes());
            records.extend_from_slice(&[jitter[index as usize], jitter[index as usize + 1], 0x00, 0x80]);
            records.extend_from_slice(b"REC\0");
        }
        let (class, _, reason) = classify(&records);
        assert_eq!(class, BlockClass::Table, "{reason}");
        assert!(reason.contains("every 16 bytes"), "{reason}");
    }

    #[test]
    fn instruction_like_bytes_are_machine_code() {
        let picks = noise(8192, 8);
        let mut code = Vec::new();
        let mut index = 0;
        while code.len() < 4096 {
            let immediate = [picks[index], picks[index + 1], picks[index + 2] & 0x0F, 0x00];
            index = (index + 3) % 8000;
            match picks[index] % 9 {
                0 => code.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5]),
                1 => code.extend_from_slice(&[0x48, 0x8B, 0x45, immediate[0] | 0x80]),
                2 => code.extend(&[0xE8].into_iter().chain(immediate).collect::<Vec<u8>>()),
                3 => code.extend_from_slice(&[0x48, 0x83, 0xEC, immediate[0] & 0x78]),
                4 => code.extend_from_slice(&[0x0F, 0x85, immediate[0], immediate[1], 0x00, 0x00]),
                5 => code.extend_from_slice(&[0x31, 0xC0, 0x5D, 0xC3]),
                6 => code.extend_from_slice(&[0x74, immediate[0]]),
                7 => code.extend_from_slice(&[0x89, 0x7D, immediate[1], 0x8B, 0x55, immediate[2]]),
                _ => code.extend(&[0xFF, 0x15].into_iter().chain(immediate).collect::<Vec<u8>>()),
            }
        }
        code.truncate(4096);
        let (class, _, reason) = classify(&code);
        assert_eq!(class, BlockClass::MachineCode, "{reason}");
        assert!(reason.contains("x86"), "{reason}");
    }

    #[test]
    fn blocks_are_classified_in_order_and_merged_into_runs() {
        let mut data = vec![0u8; 8192];
        data.extend(prose(4096));
        data.extend(noise(8192, 9));
        data.extend(prose(100)); // A short final block.
        let blocks = classify_blocks(&data, DEFAULT_BLOCK_SIZE);
        assert_eq!(blocks.len(), 6);
        assert_eq!(blocks[5].len, 100);
        let runs = merge_runs(&blocks);
        let summary: Vec<(BlockClass, usize, usize)> = runs.iter().map(|run| (run.class, run.offset, run.blocks)).collect();
        assert_eq!(summary, [(BlockClass::Padding, 0, 2), (BlockClass::Text, 8192, 1), (BlockClass::Random, 12288, 2), (BlockClass::Text, 20480, 1)]);
        assert_eq!(runs.last().unwrap().end(), data.len());
        assert!(runs.iter().all(|run| !run.reason.is_empty() && run.confidence > 0.0));
    }

    #[test]
    fn classification_is_deterministic_and_safe_on_odd_input() {
        let data = noise(50_000, 10);
        assert_eq!(classify_blocks(&data, 1000), classify_blocks(&data, 1000));
        assert!(classify_blocks(&[], DEFAULT_BLOCK_SIZE).is_empty());
        for len in [1, 2, 3, 63, 255] {
            let _ = classify(&noise(len, 11));
            let _ = classify(&vec![0x80; len]);
        }
        assert_eq!(classify_blocks(&data, 1)[0].len, MIN_BLOCK_SIZE, "block size is raised to the minimum");
    }
}
