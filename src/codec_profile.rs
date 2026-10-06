//! Multi-codec compressibility profile.
//!
//! A sample of a region is compressed with several codecs that work in
//! different ways, and the pattern of their gains says what kind of data it
//! is:
//!
//! * LZ4 only finds repeated strings; it has no entropy coder.
//! * The order-1 coder (LZMA's literal coder on its own, from `lzma-rs`) only
//!   exploits a skewed byte distribution; it never finds repeats.
//! * Deflate (fast and best), zstd (fast) and bzip2 combine both, bzip2 with a
//!   block sort that suits text.
//!
//! Random or encrypted bytes gain nothing anywhere. Already compressed data
//! gains nothing or a few per cent, and its byte histogram is detectably
//! non-uniform. Lossy media payloads (Huffman-coded coefficients) gain a
//! little from entropy coding but have no repeats. Structured binary data and
//! text gain a lot, and which codec wins says why.
//!
//! Work is bounded: at most [`MAX_SAMPLE`] bytes per region are compressed,
//! taken as evenly spaced slices, and a whole-file profile looks at no more
//! than [`MAX_SEGMENTS`] segments of [`SEGMENT_SAMPLE`] bytes each.

use std::io::Write;

use rayon::prelude::*;

use crate::stats;

/// Most bytes of one region that are compressed.
pub const MAX_SAMPLE: usize = 256 * 1024;
/// Evenly spaced slices a large region's sample is built from.
pub const SAMPLE_SLICES: usize = 4;
/// Most segments a whole-file profile is cut into.
pub const MAX_SEGMENTS: usize = 64;
/// Bytes sampled from each segment of a whole-file profile.
pub const SEGMENT_SAMPLE: usize = 32 * 1024;
/// Fewer bytes than this say too little to judge.
pub const MIN_SAMPLE: usize = 64;

/// Gain (fraction of the input saved) below which a codec "gains nothing".
const NO_GAIN: f64 = 0.01;
/// Best gain below which data counts as already compressed.
const SMALL_GAIN: f64 = 0.05;
/// Best gain below which data without repeats may be lossy media.
const MEDIA_MAX_GAIN: f64 = 0.15;
/// LZ4 gain below which the data has no useful repeats.
const NO_REPEATS: f64 = 0.03;
/// Byte entropy (bits per byte) above which data without repeats looks coded.
const MEDIA_MIN_ENTROPY: f64 = 7.5;
/// Chi-square p-value below which the byte histogram is detectably not uniform.
const NON_UNIFORM_P: f64 = 0.001;
/// Best gain above which data is mostly repeats or padding.
const HIGHLY_REDUNDANT: f64 = 0.9;
/// Printable fraction above which structured data is described as text.
const TEXT_PRINTABLE: f64 = 0.9;
/// Share of 0xFF bytes followed by 0x00 that marks JPEG entropy-coded data.
const JPEG_STUFFING_SHARE: f64 = 0.5;
/// Fewest 0xFF bytes for the JPEG stuffing test to mean anything.
const JPEG_MIN_FF: usize = 16;
/// MPEG audio frame syncs per 2 KiB above which frames are present (random
/// data has about one).
const MPEG_SYNCS_PER_2K: f64 = 3.0;

/// One of the codecs a sample is compressed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Probe {
    DeflateFast,
    DeflateBest,
    Bzip2,
    Lz4,
    ZstdFast,
    /// LZMA's literal coder alone: an order-1 context model without matches.
    Order1,
}

impl Probe {
    pub const ALL: [Probe; 6] = [Probe::DeflateFast, Probe::DeflateBest, Probe::Bzip2, Probe::Lz4, Probe::ZstdFast, Probe::Order1];

    pub fn label(self) -> &'static str {
        match self {
            Probe::DeflateFast => "deflate -1",
            Probe::DeflateBest => "deflate -9",
            Probe::Bzip2 => "bzip2 -9",
            Probe::Lz4 => "LZ4",
            Probe::ZstdFast => "zstd fast",
            Probe::Order1 => "order-1 entropy",
        }
    }

    /// What the codec exploits, for tooltips.
    pub fn description(self) -> &'static str {
        match self {
            Probe::DeflateFast => "LZ77 matches plus Huffman coding, quick search",
            Probe::DeflateBest => "LZ77 matches plus Huffman coding, thorough search",
            Probe::Bzip2 => "Burrows-Wheeler block sort plus Huffman coding; strong on text",
            Probe::Lz4 => "LZ matches only, no entropy coding: measures repeats",
            Probe::ZstdFast => "LZ matches plus FSE entropy coding",
            Probe::Order1 => "LZMA literal coder without matches: measures byte skew only",
        }
    }
}

/// How well one codec did on the sample.
#[derive(Clone, Debug, PartialEq)]
pub struct CodecRatio {
    pub probe: Probe,
    /// Compressed size, or why the codec failed.
    pub compressed: Result<usize, String>,
}

impl CodecRatio {
    /// Compressed size over input size; above 1 means it grew.
    pub fn ratio(&self, input_len: usize) -> Option<f64> {
        let compressed = *self.compressed.as_ref().ok()?;
        (input_len > 0).then(|| compressed as f64 / input_len as f64)
    }

    /// Fraction of the input saved (negative when it grew).
    pub fn gain(&self, input_len: usize) -> Option<f64> {
        self.ratio(input_len).map(|ratio| 1.0 - ratio)
    }
}

/// What the profile says the data is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    TooSmall,
    EncryptedOrRandom,
    AlreadyCompressed,
    LossyMedia,
    Structured,
}

impl Verdict {
    pub const ALL: [Verdict; 5] = [Verdict::TooSmall, Verdict::EncryptedOrRandom, Verdict::AlreadyCompressed, Verdict::LossyMedia, Verdict::Structured];

    pub fn label(self) -> &'static str {
        match self {
            Verdict::TooSmall => "too small to judge",
            Verdict::EncryptedOrRandom => "encrypted or random",
            Verdict::AlreadyCompressed => "already compressed",
            Verdict::LossyMedia => "media (lossy codec data)",
            Verdict::Structured => "structured binary/text",
        }
    }
}

/// The ratios for one sample and what they mean.
#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
    pub sample_len: usize,
    pub ratios: Vec<CodecRatio>,
    pub verdict: Verdict,
    /// One sentence with the measured values behind the verdict.
    pub reason: String,
    /// Byte entropy of the sample, bits per byte.
    pub entropy: f64,
}

impl Profile {
    /// The codec that saved the most, with its gain.
    pub fn best(&self) -> Option<(Probe, f64)> {
        self.ratios
            .iter()
            .filter_map(|ratio| ratio.gain(self.sample_len).map(|gain| (ratio.probe, gain)))
            .max_by(|a, b| a.1.total_cmp(&b.1))
    }

    pub fn gain_of(&self, probe: Probe) -> Option<f64> {
        self.ratios.iter().find(|ratio| ratio.probe == probe)?.gain(self.sample_len)
    }
}

/// A profile of one segment of a document.
#[derive(Clone, Debug, PartialEq)]
pub struct SegmentProfile {
    pub offset: usize,
    pub len: usize,
    pub profile: Profile,
}

/// Byte ranges `(offset, len)` to sample from the region at `start` of
/// `len` bytes: the whole region when it fits in `budget`, otherwise
/// [`SAMPLE_SLICES`] evenly spaced slices that add up to `budget`.
pub fn sample_ranges(start: usize, len: usize, budget: usize) -> Vec<(usize, usize)> {
    if len <= budget {
        return vec![(start, len)];
    }
    let slice_len = budget / SAMPLE_SLICES;
    if slice_len == 0 {
        return vec![(start, budget)];
    }
    let spacing = (len - slice_len) / (SAMPLE_SLICES - 1).max(1);
    (0..SAMPLE_SLICES).map(|index| (start + index * spacing, slice_len)).collect()
}

/// Cut a document of `document_len` bytes into at most `max_segments`
/// segments of equal size (the last may be shorter), as `(offset, len)`.
pub fn segment_bounds(document_len: usize, max_segments: usize) -> Vec<(usize, usize)> {
    if document_len == 0 || max_segments == 0 {
        return Vec::new();
    }
    let segment_len = document_len.div_ceil(max_segments).max(MIN_SAMPLE);
    (0..document_len).step_by(segment_len).map(|offset| (offset, segment_len.min(document_len - offset))).collect()
}

/// Profile a region held in memory, sampling it if it is larger than
/// [`MAX_SAMPLE`].
pub fn profile_region(bytes: &[u8]) -> Profile {
    let sample: Vec<u8> = sample_ranges(0, bytes.len(), MAX_SAMPLE).into_iter().flat_map(|(offset, len)| bytes[offset..offset + len].iter().copied()).collect();
    profile_sample(&sample)
}

/// Profile samples already read from a document, one per segment, in
/// parallel. Each entry is `(offset, segment_len, sample)`.
pub fn profile_segments(segments: Vec<(usize, usize, Vec<u8>)>) -> Vec<SegmentProfile> {
    segments.into_par_iter().map(|(offset, len, sample)| SegmentProfile { offset, len, profile: profile_sample(&sample) }).collect()
}

/// Compress `sample` (truncated to [`MAX_SAMPLE`]) with every probe and
/// interpret the result.
pub fn profile_sample(sample: &[u8]) -> Profile {
    let sample = &sample[..sample.len().min(MAX_SAMPLE)];
    let byte_stats = stats::byte_stats(sample);
    if sample.len() < MIN_SAMPLE {
        return Profile {
            sample_len: sample.len(),
            ratios: Vec::new(),
            verdict: Verdict::TooSmall,
            reason: format!("only {} bytes; at least {MIN_SAMPLE} are needed", sample.len()),
            entropy: byte_stats.entropy,
        };
    }
    let ratios: Vec<CodecRatio> = Probe::ALL.par_iter().map(|&probe| CodecRatio { probe, compressed: compressed_len(probe, sample) }).collect();
    let mut profile = Profile { sample_len: sample.len(), ratios, verdict: Verdict::TooSmall, reason: String::new(), entropy: byte_stats.entropy };
    let (verdict, reason) = interpret(&profile, sample, &byte_stats);
    profile.verdict = verdict;
    profile.reason = reason;
    profile
}

/// Size of `data` compressed with `probe`. Codec panics count as failures.
fn compressed_len(probe: Probe, data: &[u8]) -> Result<usize, String> {
    let attempt = std::panic::catch_unwind(|| compress_with(probe, data));
    match attempt {
        Ok(result) => result.map(|bytes| bytes.len()),
        Err(_) => Err(format!("{} failed unexpectedly", probe.label())),
    }
}

fn compress_with(probe: Probe, data: &[u8]) -> Result<Vec<u8>, String> {
    let io_error = |error: std::io::Error| format!("{}: {error}", probe.label());
    match probe {
        Probe::DeflateFast | Probe::DeflateBest => {
            let level = if probe == Probe::DeflateFast { flate2::Compression::fast() } else { flate2::Compression::best() };
            let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), level);
            encoder.write_all(data).map_err(io_error)?;
            encoder.finish().map_err(io_error)
        }
        Probe::Bzip2 => {
            let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
            encoder.write_all(data).map_err(io_error)?;
            encoder.finish().map_err(io_error)
        }
        Probe::Lz4 => Ok(lz4_flex::block::compress(data)),
        Probe::ZstdFast => Ok(ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)),
        Probe::Order1 => {
            let mut output = Vec::new();
            lzma_rs::lzma_compress(&mut std::io::Cursor::new(data), &mut output).map_err(io_error)?;
            Ok(output)
        }
    }
}

/// Signs of lossy media in the raw bytes, if any: JPEG byte stuffing or
/// recurring MPEG audio frame syncs.
fn media_markers(sample: &[u8]) -> Option<String> {
    let ff_count = sample.iter().filter(|&&byte| byte == 0xFF).count();
    let stuffed = sample.windows(2).filter(|pair| pair[0] == 0xFF && pair[1] == 0x00).count();
    if ff_count >= JPEG_MIN_FF && stuffed as f64 / ff_count as f64 >= JPEG_STUFFING_SHARE {
        return Some(format!("{stuffed} of {ff_count} 0xFF bytes are followed by 0x00, as in JPEG entropy-coded data"));
    }
    let syncs = sample.windows(2).filter(|pair| pair[0] == 0xFF && pair[1] & 0xE0 == 0xE0).count();
    let syncs_per_2k = syncs as f64 * 2048.0 / sample.len().max(1) as f64;
    (syncs_per_2k >= MPEG_SYNCS_PER_2K).then(|| format!("{syncs_per_2k:.1} MPEG frame syncs per 2 KiB (random data has about 1)"))
}

fn percent(fraction: f64) -> String {
    format!("{:.1}%", fraction * 100.0)
}

/// Turn the gains and byte statistics into a verdict and reason.
fn interpret(profile: &Profile, sample: &[u8], byte_stats: &stats::ByteStats) -> (Verdict, String) {
    let Some((best_probe, best_gain)) = profile.best() else {
        return (Verdict::TooSmall, "no codec produced a result".to_string());
    };
    let lz_gain = profile.gain_of(Probe::Lz4).unwrap_or(0.0);
    let order1_gain = profile.gain_of(Probe::Order1).unwrap_or(0.0);
    let best = format!("best gain {} ({})", percent(best_gain), best_probe.label());

    if best_gain < MEDIA_MAX_GAIN
        && lz_gain < NO_REPEATS
        && let Some(markers) = media_markers(sample)
    {
        return (Verdict::LossyMedia, format!("{best} with no repeats (LZ4 {}); {markers}", percent(lz_gain)));
    }
    if best_gain < NO_GAIN {
        return if byte_stats.chi_square_p < NON_UNIFORM_P {
            (Verdict::AlreadyCompressed, format!("{best}, yet the byte histogram is not uniform (chi-square p = {:.2e}): the output of a compressor", byte_stats.chi_square_p))
        } else {
            (Verdict::EncryptedOrRandom, format!("{best}; bytes are uniform (entropy {:.3}, chi-square p = {:.2})", byte_stats.entropy, byte_stats.chi_square_p))
        };
    }
    if best_gain < SMALL_GAIN {
        return (Verdict::AlreadyCompressed, format!("{best}: only small gains remain (LZ4 {}), as in already compressed data", percent(lz_gain)));
    }
    if best_gain < MEDIA_MAX_GAIN && lz_gain < NO_REPEATS && byte_stats.entropy >= MEDIA_MIN_ENTROPY {
        return (
            Verdict::LossyMedia,
            format!("{best} from entropy coding alone (order-1 {}, LZ4 {}) at entropy {:.2}: skewed but repeat-free, typical of lossy codec payloads", percent(order1_gain), percent(lz_gain), byte_stats.entropy),
        );
    }
    (Verdict::Structured, structured_reason(&best, best_gain, lz_gain, order1_gain, byte_stats))
}

/// Why structured data compresses: repeats, byte skew, or both.
fn structured_reason(best: &str, best_gain: f64, lz_gain: f64, order1_gain: f64, byte_stats: &stats::ByteStats) -> String {
    let kind = if byte_stats.printable_fraction >= TEXT_PRINTABLE { "text" } else { "binary data" };
    let cause = if best_gain >= HIGHLY_REDUNDANT {
        "mostly repeats or padding".to_string()
    } else if lz_gain >= order1_gain {
        format!("LZ-friendly repeats (LZ4 alone {} vs order-1 {}), such as records or repeated strings", percent(lz_gain), percent(order1_gain))
    } else if lz_gain < NO_REPEATS {
        format!("entropy-coding gains without repeats (order-1 {} vs LZ4 {}), such as samples, tables of small numbers or a small alphabet", percent(order1_gain), percent(lz_gain))
    } else {
        format!("both repeats (LZ4 {}) and a skewed byte distribution (order-1 {})", percent(lz_gain), percent(order1_gain))
    };
    format!("{best}; {kind} with {cause}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes (xorshift64*).
    fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.max(1);
        (0..len)
            .map(|_| {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
            })
            .collect()
    }

    /// Text-like words chosen pseudo-randomly from a small vocabulary.
    fn word_soup(len: usize) -> Vec<u8> {
        const WORDS: [&str; 16] = ["sensor", "reading", "value", "alpha", "bravo", "charlie", "delta", "echo", "frame", "packet", "status", "error", "level", "port", "timer", "queue"];
        let choices = random_bytes(len / 4, 7);
        let mut text = Vec::new();
        for (index, choice) in choices.iter().enumerate() {
            text.extend_from_slice(WORDS[*choice as usize % WORDS.len()].as_bytes());
            text.push(if index % 11 == 10 { b'\n' } else { b' ' });
            text.extend_from_slice(format!("{}", choice).as_bytes());
            text.push(b' ');
            if text.len() >= len {
                break;
            }
        }
        text
    }

    #[test]
    fn random_bytes_are_judged_encrypted_or_random() {
        let profile = profile_region(&random_bytes(128 * 1024, 42));
        assert_eq!(profile.verdict, Verdict::EncryptedOrRandom, "{}", profile.reason);
        assert_eq!(profile.ratios.len(), Probe::ALL.len());
    }

    #[test]
    fn zlib_output_is_judged_already_compressed() {
        let compressed = crate::compress::compress(crate::compress::Codec::Zlib, &word_soup(1024 * 1024)).unwrap();
        let profile = profile_region(&compressed);
        assert_eq!(profile.verdict, Verdict::AlreadyCompressed, "{}", profile.reason);
    }

    #[test]
    fn repeated_records_give_a_large_lz_friendly_gain() {
        let mut records = Vec::new();
        for index in 0u32..4000 {
            records.extend_from_slice(b"REC1");
            records.extend_from_slice(&(index % 50).to_le_bytes());
            records.extend_from_slice(&[0x10, 0x20, 0x00, 0x00, 0xAA, 0x55, 0x00, 0x01]);
        }
        let profile = profile_region(&records);
        assert_eq!(profile.verdict, Verdict::Structured);
        let (_, best_gain) = profile.best().unwrap();
        assert!(best_gain > 0.8, "best gain {best_gain}");
        assert!(profile.gain_of(Probe::Lz4).unwrap() > 0.5);
    }

    #[test]
    fn text_is_described_as_text() {
        let profile = profile_region(&word_soup(64 * 1024));
        assert_eq!(profile.verdict, Verdict::Structured);
        assert!(profile.reason.contains("text"), "{}", profile.reason);
    }

    #[test]
    fn jpeg_like_stuffed_data_is_judged_lossy_media() {
        // High-entropy payload with every 0xFF stuffed with 0x00, as JPEG scans are.
        let mut scan = Vec::new();
        for byte in random_bytes(96 * 1024, 9) {
            scan.push(byte);
            if byte == 0xFF {
                scan.push(0x00);
            }
        }
        let profile = profile_region(&scan);
        assert_eq!(profile.verdict, Verdict::LossyMedia, "{}", profile.reason);
    }

    #[test]
    fn tiny_regions_are_too_small_to_judge() {
        assert_eq!(profile_region(&[1, 2, 3]).verdict, Verdict::TooSmall);
        assert_eq!(profile_region(&[]).verdict, Verdict::TooSmall);
    }

    #[test]
    fn large_regions_are_sampled_in_evenly_spaced_slices_within_budget() {
        let ranges = sample_ranges(1000, 10 * MAX_SAMPLE, MAX_SAMPLE);
        assert_eq!(ranges.len(), SAMPLE_SLICES);
        assert_eq!(ranges.iter().map(|range| range.1).sum::<usize>(), MAX_SAMPLE);
        let last = ranges.last().unwrap();
        assert_eq!(last.0 + last.1, 1000 + 10 * MAX_SAMPLE);
        assert_eq!(sample_ranges(5, 100, MAX_SAMPLE), vec![(5, 100)]);
    }

    #[test]
    fn segments_cover_the_whole_document_without_exceeding_the_limit() {
        let bounds = segment_bounds(1_000_003, MAX_SEGMENTS);
        assert!(bounds.len() <= MAX_SEGMENTS);
        assert_eq!(bounds.iter().map(|bound| bound.1).sum::<usize>(), 1_000_003);
        assert!(segment_bounds(0, MAX_SEGMENTS).is_empty());
    }

    #[test]
    fn a_whole_file_profile_tells_random_and_structured_segments_apart() {
        let mut document = word_soup(64 * 1024);
        document.truncate(64 * 1024);
        document.extend(random_bytes(64 * 1024, 3));
        let segments = segment_bounds(document.len(), 2)
            .into_iter()
            .map(|(offset, len)| (offset, len, document[offset..offset + len.min(SEGMENT_SAMPLE)].to_vec()))
            .collect();
        let profiles = profile_segments(segments);
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].profile.verdict, Verdict::Structured);
        assert_eq!(profiles[1].profile.verdict, Verdict::EncryptedOrRandom);
    }
}
