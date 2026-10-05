//! Correlation of byte fields with an outside value.
//!
//! Given several captures of the same kind of data and a number the person
//! knows for each (a temperature, a button state, a setting), this searches
//! every position for integer fields (1, 2 and 4 bytes, little- and
//! big-endian, signed and unsigned) and single bits whose values follow the
//! outside numbers. Each field is scored by Pearson correlation and fitted to
//! `field = scale · outside + offset`, so an encoded setting such as
//! "temperature × 10" is reported with scale 10.
//!
//! With few samples, chance correlations are common: three samples are the
//! minimum, and confidence grows with every file added.

use std::fmt;
use std::ops::Range;

/// Fewest samples a correlation can be computed from.
pub const MIN_SAMPLES: usize = 3;
/// Most samples compared at once, which bounds the time spent per field.
pub const MAX_SAMPLES: usize = 64;
/// Longest stretch of the files searched by default.
pub const DEFAULT_SEARCH_LEN: usize = 256 * 1024;
/// Longest stretch of the files that may be searched at all.
pub const MAX_SEARCH_LEN: usize = 4 * 1024 * 1024;
/// Fields scoring below this |r| are not reported.
pub const MIN_REPORTED_CORRELATION: f64 = 0.5;
/// Fields reported, best first.
pub const MAX_REPORTED_FIELDS: usize = 40;
/// Candidates kept while searching before the weakest are pruned.
const CANDIDATE_PRUNE_THRESHOLD: usize = 50_000;
/// Candidates kept after a prune: enough to survive de-duplication.
const CANDIDATES_AFTER_PRUNE: usize = 5_000;
/// Correlations closer than this are treated as tied.
const CORRELATION_TIE: f64 = 1e-9;
/// Relative tolerance for calling a linear fit exact.
const EXACT_FIT_TOLERANCE: f64 = 1e-6;
/// Integer widths searched, in bytes.
const WIDTHS: [usize; 3] = [1, 2, 4];

/// Why a correlation could not be computed.
#[derive(Debug, Clone, PartialEq)]
pub enum CorrelationError {
    /// Fewer than [`MIN_SAMPLES`] files were given.
    TooFewSamples(usize),
    /// More than [`MAX_SAMPLES`] files were given.
    TooManySamples(usize),
    /// The number of outside values does not match the number of files.
    ValueCountMismatch { files: usize, values: usize },
    /// An outside value is not a finite number.
    NotFinite { file: usize },
    /// Every outside value is the same, so nothing can follow it.
    ConstantOutsideValues,
    /// The search range lies beyond the end of the shortest file.
    RangeOutsideFiles { start: usize, common_len: usize },
}

impl fmt::Display for CorrelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CorrelationError::TooFewSamples(count) => write!(
                f,
                "Correlation needs at least {MIN_SAMPLES} files, each with an outside value; {count} given. \
                 Confidence grows with every file added."
            ),
            CorrelationError::TooManySamples(count) => {
                write!(f, "At most {MAX_SAMPLES} files can be correlated at once; {count} given.")
            }
            CorrelationError::ValueCountMismatch { files, values } => {
                write!(f, "{files} files but {values} outside values were given; there must be one per file.")
            }
            CorrelationError::NotFinite { file } => write!(f, "The outside value for file {} is not a number.", file + 1),
            CorrelationError::ConstantOutsideValues => {
                write!(f, "Every outside value is the same; give files taken at different values.")
            }
            CorrelationError::RangeOutsideFiles { start, common_len } => write!(
                f,
                "The search starts at 0x{start:X}, beyond the shortest file's {common_len} bytes."
            ),
        }
    }
}

impl std::error::Error for CorrelationError {}

/// How a field's bytes are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldEncoding {
    Integer { width: usize, signed: bool, big_endian: bool },
    /// One bit of a byte, 0 being the least significant.
    Bit { bit: u8 },
}

impl FieldEncoding {
    /// Bytes the field occupies.
    pub fn width(self) -> usize {
        match self {
            FieldEncoding::Integer { width, .. } => width,
            FieldEncoding::Bit { .. } => 1,
        }
    }

    /// A short name such as "u16 LE", "i8" or "bit 3".
    pub fn describe(self) -> String {
        match self {
            FieldEncoding::Integer { width, signed, big_endian } => {
                let kind = if signed { 'i' } else { 'u' };
                let bits = width * 8;
                if width == 1 {
                    format!("{kind}{bits}")
                } else {
                    format!("{kind}{bits} {}", if big_endian { "BE" } else { "LE" })
                }
            }
            FieldEncoding::Bit { bit } => format!("bit {bit}"),
        }
    }

    /// The field's value at the start of `bytes`, or `None` when too short.
    pub fn read(self, bytes: &[u8]) -> Option<f64> {
        match self {
            FieldEncoding::Bit { bit } => bytes.first().map(|byte| f64::from((byte >> bit) & 1)),
            FieldEncoding::Integer { width, signed, big_endian } => {
                let field = bytes.get(..width)?;
                Some(read_integer(field, signed, big_endian))
            }
        }
    }

    /// Simpler encodings first: narrower, unsigned, little-endian; bits last.
    fn simplicity_rank(self) -> (usize, bool, bool) {
        match self {
            FieldEncoding::Integer { width, signed, big_endian } => (width, signed, big_endian),
            FieldEncoding::Bit { .. } => (usize::MAX, false, false),
        }
    }
}

fn read_integer(field: &[u8], signed: bool, big_endian: bool) -> f64 {
    let fold = |value: u64, &byte: &u8| (value << 8) | u64::from(byte);
    let raw = if big_endian { field.iter().fold(0, fold) } else { field.iter().rev().fold(0, fold) };
    if !signed {
        return raw as f64;
    }
    let unused_bits = 64 - 8 * field.len() as u32;
    // Shift the sign bit to the top, then back with sign extension.
    (((raw << unused_bits) as i64) >> unused_bits) as f64
}

/// Every encoding searched at each position.
fn all_encodings() -> Vec<FieldEncoding> {
    let mut encodings = Vec::new();
    for width in WIDTHS {
        let orders: &[bool] = if width == 1 { &[false] } else { &[false, true] };
        for &big_endian in orders {
            for signed in [false, true] {
                encodings.push(FieldEncoding::Integer { width, signed, big_endian });
            }
        }
    }
    encodings.extend((0..8).map(|bit| FieldEncoding::Bit { bit }));
    encodings
}

/// How much the result can be trusted, from the number of samples alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Moderate,
    Good,
}

impl Confidence {
    pub fn for_samples(samples: usize) -> Confidence {
        match samples {
            0..=4 => Confidence::Low,
            5..=9 => Confidence::Moderate,
            _ => Confidence::Good,
        }
    }

    pub fn explanation(self) -> &'static str {
        match self {
            Confidence::Low => {
                "Few samples: unrelated fields can match closely by chance. Add more files to tell them apart."
            }
            Confidence::Moderate => "A handful of samples: strong matches are suggestive; more files make them convincing.",
            Confidence::Good => "Enough samples that a close match is unlikely to be chance.",
        }
    }
}

/// A field whose values follow the outside values.
#[derive(Debug, Clone, PartialEq)]
pub struct CorrelatedField {
    pub offset: usize,
    pub encoding: FieldEncoding,
    /// Pearson correlation with the outside values, −1 to 1.
    pub correlation: f64,
    /// Fitted `field = scale · outside + offset_term`.
    pub scale: f64,
    pub offset_term: f64,
    /// Every sample lies on the fitted line.
    pub exact_fit: bool,
    /// The field equals the outside value in every file.
    pub equals_outside: bool,
    /// The field's value in each file.
    pub values: Vec<f64>,
}

impl CorrelatedField {
    /// "0x0010 u16 LE: r = 1.000, field ≈ 10·x + 0 (exact)".
    pub fn summary(&self) -> String {
        let fit = if self.equals_outside {
            "equals the outside value".to_string()
        } else {
            let exact = if self.exact_fit { " (exact)" } else { "" };
            format!("field ≈ {}·x {} {}{exact}", format_number(self.scale), sign(self.offset_term), format_number(self.offset_term.abs()))
        };
        format!("0x{:04X} {}: r = {:.3}, {fit}", self.offset, self.encoding.describe(), self.correlation)
    }
}

fn sign(value: f64) -> char {
    if value < 0.0 { '−' } else { '+' }
}

/// Up to four significant decimals, without trailing zeros.
fn format_number(value: f64) -> String {
    let text = format!("{value:.4}");
    let trimmed = text.trim_end_matches('0').trim_end_matches('.');
    if trimmed == "-0" { "0".to_string() } else { trimmed.to_string() }
}

/// The result of a search.
#[derive(Debug, Clone, PartialEq)]
pub struct CorrelationReport {
    pub samples: usize,
    pub confidence: Confidence,
    /// Byte range searched, relative to the start of each file.
    pub searched: Range<usize>,
    pub fields: Vec<CorrelatedField>,
}

/// Search `range` (clamped to the shortest file and [`MAX_SEARCH_LEN`]) of
/// `files` for fields that follow `outside`, one value per file.
pub fn find_correlated_fields(
    files: &[&[u8]],
    outside: &[f64],
    range: Range<usize>,
) -> Result<CorrelationReport, CorrelationError> {
    validate(files, outside)?;
    let common_len = files.iter().map(|bytes| bytes.len()).min().unwrap_or(0);
    if range.start >= common_len {
        return Err(CorrelationError::RangeOutsideFiles { start: range.start, common_len });
    }
    let end = range.end.min(common_len).min(range.start.saturating_add(MAX_SEARCH_LEN));
    let searched = range.start..end.max(range.start);

    let outside_stats = Moments::of(outside);
    let encodings = all_encodings();
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut values = vec![0.0; files.len()];
    for offset in searched.clone() {
        for &encoding in &encodings {
            if offset + encoding.width() > common_len {
                continue;
            }
            for (value, bytes) in values.iter_mut().zip(files) {
                *value = encoding.read(&bytes[offset..]).unwrap_or(0.0);
            }
            if let Some(fit) = fit_line(outside, &outside_stats, &values)
                && fit.correlation.abs() >= MIN_REPORTED_CORRELATION
            {
                candidates.push(Candidate { offset, encoding, fit });
            }
        }
        if candidates.len() > CANDIDATE_PRUNE_THRESHOLD {
            rank(&mut candidates);
            candidates.truncate(CANDIDATES_AFTER_PRUNE);
        }
    }
    rank(&mut candidates);
    let fields = report_fields(files, outside, &candidates);
    Ok(CorrelationReport { samples: files.len(), confidence: Confidence::for_samples(files.len()), searched, fields })
}

fn validate(files: &[&[u8]], outside: &[f64]) -> Result<(), CorrelationError> {
    if files.len() != outside.len() {
        return Err(CorrelationError::ValueCountMismatch { files: files.len(), values: outside.len() });
    }
    if files.len() < MIN_SAMPLES {
        return Err(CorrelationError::TooFewSamples(files.len()));
    }
    if files.len() > MAX_SAMPLES {
        return Err(CorrelationError::TooManySamples(files.len()));
    }
    if let Some(file) = outside.iter().position(|value| !value.is_finite()) {
        return Err(CorrelationError::NotFinite { file });
    }
    if outside.iter().all(|&value| value == outside[0]) {
        return Err(CorrelationError::ConstantOutsideValues);
    }
    Ok(())
}

/// A field found while searching, before its values are gathered.
#[derive(Debug, Clone, Copy)]
struct Candidate {
    offset: usize,
    encoding: FieldEncoding,
    fit: LineFit,
}

/// Strongest correlation first; among ties, the reading that needs the
/// smallest offset term (an i8 of −5·x rather than a u8 of 256 − 5·x), then
/// the simplest encoding, then the lowest offset.
fn rank(candidates: &mut [Candidate]) {
    candidates.sort_by(|a, b| {
        let strength = |candidate: &Candidate| (candidate.fit.correlation.abs() / CORRELATION_TIE).round();
        let offset_size = |candidate: &Candidate| candidate.fit.offset_term.abs();
        strength(b)
            .total_cmp(&strength(a))
            .then_with(|| offset_size(a).total_cmp(&offset_size(b)))
            .then_with(|| a.encoding.simplicity_rank().cmp(&b.encoding.simplicity_rank()))
            .then_with(|| a.offset.cmp(&b.offset))
    });
}

/// Turn ranked candidates into reported fields, skipping any that overlap a
/// better one and read the same values (a u32 whose upper bytes are zero
/// repeats the u16 inside it, for instance).
fn report_fields(files: &[&[u8]], outside: &[f64], candidates: &[Candidate]) -> Vec<CorrelatedField> {
    let mut fields: Vec<CorrelatedField> = Vec::new();
    for candidate in candidates {
        if fields.len() == MAX_REPORTED_FIELDS {
            break;
        }
        let values: Vec<f64> =
            files.iter().map(|bytes| candidate.encoding.read(&bytes[candidate.offset..]).unwrap_or(0.0)).collect();
        let duplicate = fields.iter().any(|field| overlaps(field, candidate) && field.values == values);
        if duplicate {
            continue;
        }
        fields.push(describe_field(candidate, outside, values));
    }
    fields
}

fn overlaps(field: &CorrelatedField, candidate: &Candidate) -> bool {
    let field_end = field.offset + field.encoding.width();
    let candidate_end = candidate.offset + candidate.encoding.width();
    field.offset < candidate_end && candidate.offset < field_end
}

/// A field's correlation with the outside values and its least-squares line
/// `field = scale · outside + offset_term`.
#[derive(Debug, Clone, Copy)]
struct LineFit {
    correlation: f64,
    scale: f64,
    offset_term: f64,
}

/// Check how closely `values` lie on the candidate's line.
fn describe_field(candidate: &Candidate, outside: &[f64], values: Vec<f64>) -> CorrelatedField {
    let LineFit { correlation, scale, offset_term } = candidate.fit;
    let largest = values.iter().fold(1.0_f64, |largest, value| largest.max(value.abs()));
    let tolerance = EXACT_FIT_TOLERANCE * largest;
    let exact_fit = outside.iter().zip(&values).all(|(x, value)| (scale * x + offset_term - value).abs() <= tolerance);
    let equals_outside = outside.iter().zip(&values).all(|(x, value)| (x - value).abs() <= tolerance);
    CorrelatedField {
        offset: candidate.offset,
        encoding: candidate.encoding,
        correlation,
        scale,
        offset_term,
        exact_fit,
        equals_outside,
        values,
    }
}

/// Mean and (population) variance of a sample.
struct Moments {
    mean: f64,
    variance: f64,
}

impl Moments {
    fn of(values: &[f64]) -> Moments {
        let count = values.len().max(1) as f64;
        let mean = values.iter().sum::<f64>() / count;
        let variance = values.iter().map(|value| (value - mean).powi(2)).sum::<f64>() / count;
        Moments { mean, variance }
    }
}

fn covariance(xs: &[f64], x_stats: &Moments, ys: &[f64], y_stats: &Moments) -> f64 {
    let count = xs.len().max(1) as f64;
    xs.iter().zip(ys).map(|(x, y)| (x - x_stats.mean) * (y - y_stats.mean)).sum::<f64>() / count
}

/// Pearson correlation and least-squares line of `values` against
/// `outside`, or `None` when either never changes.
fn fit_line(outside: &[f64], outside_stats: &Moments, values: &[f64]) -> Option<LineFit> {
    let value_stats = Moments::of(values);
    if value_stats.variance <= 0.0 || outside_stats.variance <= 0.0 {
        return None;
    }
    let covariance = covariance(outside, outside_stats, values, &value_stats);
    let correlation = covariance / (outside_stats.variance.sqrt() * value_stats.variance.sqrt());
    let scale = covariance / outside_stats.variance;
    let offset_term = value_stats.mean - scale * outside_stats.mean;
    Some(LineFit { correlation: correlation.clamp(-1.0, 1.0), scale, offset_term })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPTURE_LEN: usize = 64;
    const TEMPERATURE_OFFSET: usize = 0x12;
    const BUTTON_OFFSET: usize = 0x20;
    const BUTTON_BIT: u8 = 3;

    /// Deterministic noise so unrelated bytes change between captures.
    fn noise(seed: usize, position: usize) -> u8 {
        ((seed * 7919 + position * 104_729) % 251) as u8
    }

    fn captures(temperatures: &[f64]) -> Vec<Vec<u8>> {
        temperatures
            .iter()
            .enumerate()
            .map(|(index, temperature)| {
                let mut bytes: Vec<u8> = (0..CAPTURE_LEN).map(|position| noise(index, position)).collect();
                let encoded = (temperature * 10.0).round() as u16;
                bytes[TEMPERATURE_OFFSET..TEMPERATURE_OFFSET + 2].copy_from_slice(&encoded.to_le_bytes());
                bytes
            })
            .collect()
    }

    fn search(files: &[Vec<u8>], outside: &[f64]) -> CorrelationReport {
        let slices: Vec<&[u8]> = files.iter().map(Vec::as_slice).collect();
        find_correlated_fields(&slices, outside, 0..usize::MAX).expect("valid input")
    }

    #[test]
    fn a_u16_le_field_holding_temperature_times_ten_ranks_first_with_scale_ten() {
        let temperatures = [21.5, 24.0, 19.0, 30.2, 26.7, 22.1];
        let report = search(&captures(&temperatures), &temperatures);
        let best = &report.fields[0];
        assert_eq!(best.offset, TEMPERATURE_OFFSET);
        assert_eq!(best.encoding, FieldEncoding::Integer { width: 2, signed: false, big_endian: false });
        assert!(best.correlation > 0.9999);
        assert!((best.scale - 10.0).abs() < 1e-6, "scale {}", best.scale);
        assert!(best.offset_term.abs() < 1e-6);
        assert!(best.exact_fit);
        assert_eq!(best.values, vec![215.0, 240.0, 190.0, 302.0, 267.0, 221.0]);
    }

    #[test]
    fn wider_fields_that_repeat_the_best_one_are_not_listed_again() {
        let temperatures = [21.5, 24.0, 19.0, 30.2, 26.7];
        let mut files = captures(&temperatures);
        for file in &mut files {
            // Zero the bytes above the temperature, so a u32 reads the same values.
            file[TEMPERATURE_OFFSET + 2..TEMPERATURE_OFFSET + 4].fill(0);
        }
        let report = search(&files, &temperatures);
        let best = &report.fields[0];
        assert_eq!(best.encoding, FieldEncoding::Integer { width: 2, signed: false, big_endian: false });
        let repeats = report.fields.iter().filter(|field| field.offset == TEMPERATURE_OFFSET && field.values == best.values).count();
        assert_eq!(repeats, 1);
    }

    #[test]
    fn a_button_bit_that_equals_the_button_state_is_found_exactly() {
        let pressed = [0.0, 1.0, 1.0, 0.0, 1.0, 0.0, 0.0, 1.0];
        let files: Vec<Vec<u8>> = pressed
            .iter()
            .enumerate()
            .map(|(index, &state)| {
                let mut bytes: Vec<u8> = (0..CAPTURE_LEN).map(|position| noise(index, position)).collect();
                bytes[BUTTON_OFFSET] = 0b1000_0001 | if state > 0.0 { 1 << BUTTON_BIT } else { 0 };
                bytes
            })
            .collect();
        let report = search(&files, &pressed);
        let button = report
            .fields
            .iter()
            .find(|field| field.offset == BUTTON_OFFSET && field.encoding == FieldEncoding::Bit { bit: BUTTON_BIT })
            .expect("button bit reported");
        assert!(button.equals_outside);
        assert_eq!(report.confidence, Confidence::Moderate);
    }

    #[test]
    fn a_decreasing_signed_field_reports_a_negative_scale() {
        let settings = [1.0, 2.0, 3.0, 4.0];
        let files: Vec<Vec<u8>> = settings
            .iter()
            .map(|setting| {
                let mut bytes = vec![0x55u8; 16];
                bytes[4] = (-5 * *setting as i8) as u8;
                bytes
            })
            .collect();
        let report = search(&files, &settings);
        let best = &report.fields[0];
        assert_eq!(best.offset, 4);
        assert_eq!(best.encoding, FieldEncoding::Integer { width: 1, signed: true, big_endian: false });
        assert!((best.correlation + 1.0).abs() < 1e-9);
        assert!((best.scale + 5.0).abs() < 1e-9);
        assert_eq!(report.confidence, Confidence::Low);
    }

    #[test]
    fn too_few_samples_are_refused_with_an_explanation() {
        let file = [1u8, 2, 3];
        let error = find_correlated_fields(&[&file, &file], &[1.0, 2.0], 0..3).unwrap_err();
        assert_eq!(error, CorrelationError::TooFewSamples(2));
        assert!(error.to_string().contains("at least 3"));
    }

    #[test]
    fn unusable_outside_values_are_refused() {
        let file = [1u8, 2, 3];
        let files: [&[u8]; 3] = [&file, &file, &file];
        assert_eq!(find_correlated_fields(&files, &[1.0, 1.0, 1.0], 0..3), Err(CorrelationError::ConstantOutsideValues));
        assert_eq!(find_correlated_fields(&files, &[1.0, f64::NAN, 2.0], 0..3), Err(CorrelationError::NotFinite { file: 1 }));
        assert_eq!(
            find_correlated_fields(&files, &[1.0, 2.0], 0..3),
            Err(CorrelationError::ValueCountMismatch { files: 3, values: 2 })
        );
        assert!(matches!(find_correlated_fields(&files, &[1.0, 2.0, 3.0], 5..9), Err(CorrelationError::RangeOutsideFiles { .. })));
    }

    #[test]
    fn identical_files_report_no_fields() {
        let file = vec![7u8; 32];
        let files = vec![file.clone(), file.clone(), file];
        let report = search(&files, &[1.0, 2.0, 3.0]);
        assert!(report.fields.is_empty());
    }

    #[test]
    fn signed_and_big_endian_reads_decode_correctly() {
        let bytes = [0xFF, 0xFE];
        let read = |signed, big_endian| FieldEncoding::Integer { width: 2, signed, big_endian }.read(&bytes).unwrap();
        assert_eq!(read(false, false), 65_279.0);
        assert_eq!(read(true, false), -257.0);
        assert_eq!(read(false, true), 65_534.0);
        assert_eq!(read(true, true), -2.0);
        assert_eq!(FieldEncoding::Bit { bit: 0 }.read(&[0x01]), Some(1.0));
        assert_eq!(FieldEncoding::Integer { width: 4, signed: false, big_endian: false }.read(&bytes), None);
    }
}
