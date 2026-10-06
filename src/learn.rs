//! Learning a file signature from samples of an unknown format.
//!
//! Given two or more files that share a format, compare their first bytes
//! position by position:
//!
//! * a position holding the same byte in every sample is **constant**;
//! * one where some bits never change is **masked** (a version byte that is
//!   1, 2 or 3 keeps its top six bits at zero);
//! * anything else is **variable**.
//!
//! The longest run of constant bytes near the start becomes the magic, with
//! further constant runs at fixed offsets as extra conditions. Variable
//! numbers in the header are then tested against the samples' lengths (a
//! field that always equals the file length, or the length minus the same
//! constant, gives the block's extent), against plausible timestamps and
//! against offsets that point inside the file.
//!
//! The result is a signature catalogue entry in the format of
//! `catalog/curated.toml`, a template draft in the template language (see
//! `docs/templates.md`) and a plain summary of what was found.

use std::fmt;
use std::fmt::Write as _;

use crate::numeric::{self, Interpretation, NumberKind};

/// Fewest samples a format can be learned from.
pub const MIN_SAMPLES: usize = 2;
/// Bytes at the start of each sample that are compared.
pub const HEADER_WINDOW: usize = 4096;
/// Length fields are looked for in this many leading bytes.
const LENGTH_SCAN_LIMIT: usize = 256;
/// Variable bytes this far past the last constant run still count as header.
const HEADER_SLACK: usize = 16;
/// The primary magic is looked for first among runs starting this early.
const PRIMARY_SEARCH_LIMIT: usize = 64;
/// Extra constant runs must start within this many bytes.
const EXTRA_MATCH_LIMIT: usize = 1024;
/// Longest single match written to the catalogue.
const MAX_MATCH_LEN: usize = 64;
/// Most constant runs used as conditions besides the primary magic.
const MAX_EXTRA_MATCHES: usize = 4;
/// Shortest extra constant run, with three or more samples and with two.
const MIN_EXTRA_RUN: usize = 2;
const MIN_EXTRA_RUN_FROM_TWO_SAMPLES: usize = 4;
/// Shortest primary magic.
const MIN_PRIMARY_RUN: usize = 2;
/// A partly constant byte joins the magic only with at least this many
/// fixed bits, seen across at least this many samples. With fewer samples
/// random bytes share bits by chance too often.
const MIN_MASKED_BITS: u32 = 4;
const MIN_SAMPLES_FOR_MASKS: usize = 3;
/// Timestamps need this many samples, for the same reason.
const MIN_SAMPLES_FOR_TIMESTAMPS: usize = 3;
/// Largest constant difference between a length field and the file length.
const MAX_LENGTH_ADJUSTMENT: i128 = 65_536;
/// Lowest plausibility a timestamp reading needs from [`numeric::rank_field`].
const TIMESTAMP_MIN_SCORE: f64 = 0.85;
/// Timestamps in learned headers must fall between 2000-01-01 and 2040-01-01.
const EARLIEST_LEARNED_TIMESTAMP: f64 = 946_684_800.0;
const LATEST_LEARNED_TIMESTAMP: f64 = 2_208_988_800.0;
/// Samples' timestamps must lie within ten years of each other; random
/// bytes read as dates spread across the whole window.
const MAX_TIMESTAMP_SPREAD_SECONDS: f64 = 10.0 * 365.25 * 86_400.0;
/// Lowest plausibility for typing a variable gap as a number.
const NUMBER_MIN_SCORE: f64 = 0.5;
/// A one-byte field whose values never exceed this looks like a version.
const SMALL_VALUE_LIMIT: u64 = 16;
/// Magic bytes used in the learned entry's id.
const ID_MAGIC_BYTES: usize = 8;
/// Column at which template comments start.
const TEMPLATE_COMMENT_COLUMN: usize = 40;
/// Ranges listed per kind in the summary.
const SUMMARY_MAX_RANGES: usize = 12;
/// Values listed for a field in the template's comments.
const LISTED_VALUES: usize = 5;

// ---------------------------------------------------------------------------
// Inputs and results
// ---------------------------------------------------------------------------

/// One sample file: its leading bytes (at least the header) and its full
/// length, which may be longer when only part of the file was read.
#[derive(Clone, Copy, Debug)]
pub struct Sample<'a> {
    pub bytes: &'a [u8],
    pub file_len: u64,
}

impl<'a> Sample<'a> {
    /// A sample holding the whole file.
    pub fn whole(bytes: &'a [u8]) -> Self {
        Sample { bytes, file_len: bytes.len() as u64 }
    }
}

/// How one header position behaves across the samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteClass {
    /// The same byte in every sample.
    Constant(u8),
    /// The bits set in `mask` always hold `value`; the others vary.
    Masked { mask: u8, value: u8 },
    /// No bit is the same in every sample.
    Variable,
}

impl ByteClass {
    /// Classify one position from its byte in each sample.
    fn of(column: impl Iterator<Item = u8>) -> Self {
        let (all_set, any_set) = column.fold((0xFF_u8, 0x00_u8), |(and, or), byte| (and & byte, or | byte));
        let fixed_bits = !(all_set ^ any_set);
        match fixed_bits {
            0xFF => ByteClass::Constant(all_set),
            0x00 => ByteClass::Variable,
            mask => ByteClass::Masked { mask, value: all_set & mask },
        }
    }
}

/// One condition of the learned signature: bytes at a fixed offset, with a
/// mask when some bits vary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MagicMatch {
    pub offset: usize,
    pub bytes: Vec<u8>,
    /// Same length as `bytes`; `None` when every bit matters.
    pub mask: Option<Vec<u8>>,
}

impl MagicMatch {
    fn end(&self) -> usize {
        self.offset + self.bytes.len()
    }
}

/// What a header field was recognised as.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FieldKind {
    /// `value + add` is the file length in every sample.
    Length { add: i64 },
    /// A plausible date in every sample.
    Timestamp(Interpretation),
    /// Always points past itself and inside the file.
    Offset,
}

impl FieldKind {
    /// Lower is preferred when candidates overlap.
    fn rank(&self) -> u8 {
        match self {
            FieldKind::Length { .. } => 0,
            FieldKind::Timestamp(_) => 1,
            FieldKind::Offset => 2,
        }
    }
}

/// A recognised numeric field in the header.
#[derive(Clone, Debug, PartialEq)]
pub struct HeaderField {
    pub offset: usize,
    /// 2, 4 or 8 bytes.
    pub width: usize,
    pub little_endian: bool,
    pub kind: FieldKind,
    /// The field's value in each sample.
    pub values: Vec<u64>,
}

impl HeaderField {
    fn end(&self) -> usize {
        self.offset + self.width
    }

    fn overlaps(&self, other: &HeaderField) -> bool {
        self.offset < other.end() && other.offset < self.end()
    }

    fn describe(&self) -> String {
        let order = if self.little_endian { "LE" } else { "BE" };
        let number = format!("u{} {order}", self.width * 8);
        match self.kind {
            FieldKind::Length { add: 0 } => format!("{number} equal to the file length in every sample"),
            FieldKind::Length { add } if add > 0 => format!("{number} equal to the file length − {add} in every sample"),
            FieldKind::Length { add } => format!("{number} equal to the file length + {} in every sample", -add),
            FieldKind::Timestamp(interpretation) => format!("{}, a plausible date in every sample", interpretation.label()),
            FieldKind::Offset => format!("{number}, always pointing inside the file"),
        }
    }
}

/// Everything learned from the samples.
#[derive(Clone, Debug)]
pub struct LearnedFormat {
    /// Catalogue id, `user/learned-<hex of the magic>`.
    pub id: String,
    pub name: String,
    pub sample_count: usize,
    /// Leading bytes compared in every sample.
    pub compared_len: usize,
    /// One class per compared position.
    pub classes: Vec<ByteClass>,
    /// The primary magic first, then any extra conditions.
    pub magic: Vec<MagicMatch>,
    pub fields: Vec<HeaderField>,
    /// A `[[signature]]` entry for a user catalogue file.
    pub catalogue_toml: String,
    /// A template describing the header.
    pub template: String,
    /// A plain description of what is constant and what varies.
    pub summary: String,
}

impl LearnedFormat {
    /// The field used for the signature's extent, if any.
    pub fn length_field(&self) -> Option<&HeaderField> {
        self.fields.iter().find(|field| matches!(field.kind, FieldKind::Length { .. }))
    }
}

/// Why nothing could be learned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LearnError {
    /// Fewer than [`MIN_SAMPLES`] samples.
    TooFewSamples(usize),
    /// The sample at this index has no bytes.
    EmptySample(usize),
    /// No run of at least two constant bytes (other than fill) is shared.
    NoCommonMagic { compared_len: usize },
}

impl fmt::Display for LearnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LearnError::TooFewSamples(count) => {
                write!(formatter, "learning a format needs at least {MIN_SAMPLES} samples, but {count} were given")
            }
            LearnError::EmptySample(index) => write!(formatter, "sample {} is empty", index + 1),
            LearnError::NoCommonMagic { compared_len } => write!(
                formatter,
                "the samples share no run of {MIN_PRIMARY_RUN} or more constant bytes in their first {compared_len} bytes, so there is no magic to match"
            ),
        }
    }
}

impl std::error::Error for LearnError {}

// ---------------------------------------------------------------------------
// Learning
// ---------------------------------------------------------------------------

/// Learn a signature, a template draft and a summary from `samples`.
pub fn learn_format(samples: &[Sample]) -> Result<LearnedFormat, LearnError> {
    if samples.len() < MIN_SAMPLES {
        return Err(LearnError::TooFewSamples(samples.len()));
    }
    if let Some(index) = samples.iter().position(|sample| sample.bytes.is_empty()) {
        return Err(LearnError::EmptySample(index));
    }
    let compared_len = samples.iter().map(|sample| sample.bytes.len()).min().unwrap_or(0).min(HEADER_WINDOW);
    let headers: Vec<&[u8]> = samples.iter().map(|sample| &sample.bytes[..compared_len]).collect();
    let classes = classify(&headers, compared_len);

    let fields = find_fields(samples, &headers, &classes);
    let in_field = covered_positions(&fields, compared_len);
    let magic = choose_magic(&classes, &in_field, samples.len()).ok_or(LearnError::NoCommonMagic { compared_len })?;

    let prefix = constant_prefix(&magic[0]);
    let id = format!("user/learned-{}", hex(&prefix[..prefix.len().min(ID_MAGIC_BYTES)]));
    let name = format!("Learned format {}", readable_magic(&prefix));
    let mut learned = LearnedFormat {
        id,
        name,
        sample_count: samples.len(),
        compared_len,
        classes,
        magic,
        fields,
        catalogue_toml: String::new(),
        template: String::new(),
        summary: String::new(),
    };
    learned.catalogue_toml = catalogue_entry(&learned);
    learned.template = template_draft(&learned, &headers);
    learned.summary = summary(&learned);
    Ok(learned)
}

/// Classify each of the first `len` positions across the headers.
fn classify(headers: &[&[u8]], len: usize) -> Vec<ByteClass> {
    (0..len).map(|position| ByteClass::of(headers.iter().map(|header| header[position]))).collect()
}

/// The leading bytes of a match that are fully significant.
fn constant_prefix(found: &MagicMatch) -> Vec<u8> {
    match &found.mask {
        None => found.bytes.clone(),
        Some(mask) => found.bytes.iter().zip(mask).take_while(|(_, mask)| **mask == 0xFF).map(|(byte, _)| *byte).collect(),
    }
}

// ---------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------

/// Read an unsigned number of `width` bytes at `offset`.
fn read_value(bytes: &[u8], offset: usize, width: usize, little_endian: bool) -> Option<u64> {
    let field = bytes.get(offset..offset.checked_add(width)?)?;
    let fold = |value: u64, byte: &u8| (value << 8) | u64::from(*byte);
    Some(if little_endian { field.iter().rev().fold(0, fold) } else { field.iter().fold(0, fold) })
}

/// Values of one field in every header, or `None` if any header is too short.
fn field_values(headers: &[&[u8]], offset: usize, width: usize, little_endian: bool) -> Option<Vec<u64>> {
    headers.iter().map(|header| read_value(header, offset, width, little_endian)).collect()
}

/// Find length, timestamp and offset fields, keeping the best of any that overlap.
///
/// Timestamps and offsets may not overlap the magic: a number read across
/// constant magic bytes and a few varying ones can look like a date by chance.
fn find_fields(samples: &[Sample], headers: &[&[u8]], classes: &[ByteClass]) -> Vec<HeaderField> {
    let mut candidates = find_length_fields(samples, headers, classes);
    let region_end = header_region_end(classes);
    let magic = primary_run(classes, &constant_runs(classes, &vec![false; classes.len()]));
    let clear_of_magic = |field: &HeaderField| magic.is_none_or(|(start, end)| field.end() <= start || field.offset >= end);
    candidates.extend(find_timestamp_fields(samples, headers, classes, region_end).into_iter().filter(clear_of_magic));
    candidates.extend(find_offset_fields(samples, headers, classes, region_end).into_iter().filter(clear_of_magic));
    resolve_overlaps(candidates)
}

/// Widths tried for fields, most common first.
const FIELD_WIDTHS: [usize; 3] = [4, 8, 2];

fn width_rank(width: usize) -> usize {
    FIELD_WIDTHS.iter().position(|&w| w == width).unwrap_or(FIELD_WIDTHS.len())
}

/// Every field whose bytes are not all constant (so it carries information).
fn varies(classes: &[ByteClass], offset: usize, width: usize) -> bool {
    classes[offset..offset + width].iter().any(|class| !matches!(class, ByteClass::Constant(_)))
}

/// Fields whose value differs from the file length by the same amount in
/// every sample. Needs samples of different lengths to mean anything.
fn find_length_fields(samples: &[Sample], headers: &[&[u8]], classes: &[ByteClass]) -> Vec<HeaderField> {
    let lengths: Vec<u64> = samples.iter().map(|sample| sample.file_len).collect();
    if lengths.iter().all(|&len| len == lengths[0]) {
        return Vec::new();
    }
    let limit = classes.len().min(LENGTH_SCAN_LIMIT);
    let mut found = Vec::new();
    for width in FIELD_WIDTHS {
        for offset in 0..=limit.saturating_sub(width) {
            if offset + width > limit || !varies(classes, offset, width) {
                continue;
            }
            for little_endian in [true, false] {
                let Some(values) = field_values(headers, offset, width, little_endian) else { continue };
                if let Some(add) = constant_length_difference(&values, &lengths) {
                    found.push(HeaderField { offset, width, little_endian, kind: FieldKind::Length { add }, values });
                    break;
                }
            }
        }
    }
    found
}

/// The `add` for which `value + add == file length` in every sample.
fn constant_length_difference(values: &[u64], lengths: &[u64]) -> Option<i64> {
    let difference = i128::from(lengths[0]) - i128::from(values[0]);
    if difference.abs() > MAX_LENGTH_ADJUSTMENT {
        return None;
    }
    let consistent = values.iter().zip(lengths).all(|(&value, &len)| i128::from(len) - i128::from(value) == difference);
    consistent.then_some(difference as i64)
}

/// Where the header probably ends: a little past the last run of two or
/// more constant bytes near the start. Timestamps and offsets are only
/// looked for before this, because random body bytes resemble them too often.
fn header_region_end(classes: &[ByteClass]) -> usize {
    let limit = classes.len().min(LENGTH_SCAN_LIMIT);
    let last_run_end = constant_runs(classes, &vec![false; classes.len()])
        .into_iter()
        .filter(|&(start, end)| start < limit && end - start >= MIN_PRIMARY_RUN)
        .map(|(_, end)| end)
        .max()
        .unwrap_or(0);
    (last_run_end + HEADER_SLACK).min(classes.len())
}

/// The headers laid end to end, as fixed-size records for [`numeric::rank_field`].
fn header_records(headers: &[&[u8]]) -> Vec<u8> {
    headers.concat()
}

fn is_timestamp_kind(kind: NumberKind) -> bool {
    matches!(
        kind,
        NumberKind::UnixSeconds | NumberKind::UnixMillis | NumberKind::FileTime | NumberKind::GpsSeconds | NumberKind::HfsSeconds | NumberKind::DosDateTime
    )
}

/// Aligned 4- and 8-byte fields that read best as recent dates.
fn find_timestamp_fields(samples: &[Sample], headers: &[&[u8]], classes: &[ByteClass], region_end: usize) -> Vec<HeaderField> {
    if samples.len() < MIN_SAMPLES_FOR_TIMESTAMPS {
        return Vec::new();
    }
    let records = header_records(headers);
    let record_len = classes.len();
    let mut found = Vec::new();
    for width in [4usize, 8] {
        for offset in (0..region_end).step_by(width) {
            if offset + width > region_end || !varies(classes, offset, width) {
                continue;
            }
            let Ok(ranked) = numeric::rank_field(&records, record_len, offset, width) else { continue };
            let Some(best) = ranked.first() else { continue };
            let interpretation = best.interpretation;
            if !is_timestamp_kind(interpretation.kind) || best.score < TIMESTAMP_MIN_SCORE {
                continue;
            }
            let dates: Option<Vec<f64>> = headers.iter().map(|header| interpretation.decode(&header[offset..offset + width])).collect();
            let Some(dates) = dates else { continue };
            let Some(values) = field_values(headers, offset, width, interpretation.little_endian) else { continue };
            if are_plausible_learned_dates(&dates) {
                found.push(HeaderField { offset, width, little_endian: interpretation.little_endian, kind: FieldKind::Timestamp(interpretation), values });
            }
        }
    }
    found
}

/// Every date is recent and the dates lie close together.
fn are_plausible_learned_dates(dates: &[f64]) -> bool {
    let all_recent = dates.iter().all(|seconds| (EARLIEST_LEARNED_TIMESTAMP..=LATEST_LEARNED_TIMESTAMP).contains(seconds));
    let (earliest, latest) = dates.iter().fold((f64::INFINITY, f64::NEG_INFINITY), |(low, high), &date| (low.min(date), high.max(date)));
    all_recent && latest - earliest <= MAX_TIMESTAMP_SPREAD_SECONDS
}

/// Aligned 4- and 8-byte fields that always point past themselves and
/// inside their file, and are not the same in every sample.
fn find_offset_fields(samples: &[Sample], headers: &[&[u8]], classes: &[ByteClass], region_end: usize) -> Vec<HeaderField> {
    let mut found = Vec::new();
    for width in [4usize, 8] {
        for offset in (0..region_end).step_by(width) {
            if offset + width > region_end || !varies(classes, offset, width) {
                continue;
            }
            for little_endian in [true, false] {
                let Some(values) = field_values(headers, offset, width, little_endian) else { continue };
                let points_inside = values
                    .iter()
                    .zip(samples)
                    .all(|(&value, sample)| value >= (offset + width) as u64 && value < sample.file_len);
                if points_inside && values.iter().any(|&value| value != values[0]) {
                    found.push(HeaderField { offset, width, little_endian, kind: FieldKind::Offset, values });
                    break;
                }
            }
        }
    }
    found
}

/// Keep the most convincing candidates that do not overlap: lengths before
/// timestamps before offsets, then common widths, then earlier offsets.
fn resolve_overlaps(mut candidates: Vec<HeaderField>) -> Vec<HeaderField> {
    candidates.sort_by_key(|field| (field.kind.rank(), width_rank(field.width), field.offset, !field.little_endian));
    let mut kept: Vec<HeaderField> = Vec::new();
    for candidate in candidates {
        if !kept.iter().any(|field| field.overlaps(&candidate)) {
            kept.push(candidate);
        }
    }
    kept.sort_by_key(|field| field.offset);
    kept
}

fn covered_positions(fields: &[HeaderField], len: usize) -> Vec<bool> {
    let mut covered = vec![false; len];
    for field in fields {
        for slot in covered.iter_mut().take(field.end()).skip(field.offset) {
            *slot = true;
        }
    }
    covered
}

// ---------------------------------------------------------------------------
// Magic
// ---------------------------------------------------------------------------

/// Maximal runs `(start, end)` of constant positions not in `excluded`.
fn constant_runs(classes: &[ByteClass], excluded: &[bool]) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut start: Option<usize> = None;
    for (position, class) in classes.iter().enumerate() {
        let constant = matches!(class, ByteClass::Constant(_)) && !excluded[position];
        match (constant, start) {
            (true, None) => start = Some(position),
            (false, Some(begin)) => {
                runs.push((begin, position));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(begin) = start {
        runs.push((begin, classes.len()));
    }
    runs
}

fn constant_byte(class: ByteClass) -> Option<u8> {
    match class {
        ByteClass::Constant(byte) => Some(byte),
        _ => None,
    }
}

/// A run of one repeated byte (zero or 0xFF fill, say) makes a poor magic.
fn is_fill(classes: &[ByteClass], (start, end): (usize, usize)) -> bool {
    let first = constant_byte(classes[start]);
    classes[start..end].iter().all(|&class| constant_byte(class) == first)
}

/// The run that makes the best magic: one at offset 0 if there is one,
/// else the longest starting near the start, else the longest anywhere.
/// Runs of fill and single bytes do not count.
fn primary_run(classes: &[ByteClass], runs: &[(usize, usize)]) -> Option<(usize, usize)> {
    let eligible: Vec<(usize, usize)> =
        runs.iter().copied().filter(|&(start, end)| end - start >= MIN_PRIMARY_RUN && !is_fill(classes, (start, end))).collect();
    let longest = |candidates: &mut dyn Iterator<Item = (usize, usize)>| {
        candidates.fold(None, |best: Option<(usize, usize)>, run| match best {
            Some(best) if best.1 - best.0 >= run.1 - run.0 => Some(best),
            _ => Some(run),
        })
    };
    eligible
        .iter()
        .copied()
        .find(|&(start, _)| start == 0)
        .or_else(|| longest(&mut eligible.iter().copied().filter(|&(start, _)| start < PRIMARY_SEARCH_LIMIT)))
        .or_else(|| longest(&mut eligible.iter().copied()))
}

/// The primary magic, extended over partly constant bytes, then the longest
/// other constant runs as extra conditions.
fn choose_magic(classes: &[ByteClass], excluded: &[bool], sample_count: usize) -> Option<Vec<MagicMatch>> {
    let runs = constant_runs(classes, excluded);
    let primary_run = primary_run(classes, &runs)?;
    let masks_allowed = sample_count >= MIN_SAMPLES_FOR_MASKS;
    let primary = extend_match(classes, excluded, primary_run.0, masks_allowed);
    let mut matches = vec![primary];

    let min_extra = if sample_count >= MIN_SAMPLES_FOR_MASKS { MIN_EXTRA_RUN } else { MIN_EXTRA_RUN_FROM_TWO_SAMPLES };
    let mut extras: Vec<(usize, usize)> = runs
        .into_iter()
        .filter(|&(start, end)| start < EXTRA_MATCH_LIMIT && end - start >= min_extra)
        .filter(|&(start, end)| start >= matches[0].end() || end <= matches[0].offset)
        .collect();
    extras.sort_by_key(|&(start, end)| (std::cmp::Reverse(end - start), start));
    for (start, end) in extras.into_iter().take(MAX_EXTRA_MATCHES) {
        let end = end.min(start + MAX_MATCH_LEN);
        let bytes = classes[start..end].iter().filter_map(|&class| constant_byte(class)).collect();
        matches.push(MagicMatch { offset: start, bytes, mask: None });
    }
    matches[1..].sort_by_key(|found| found.offset);
    Some(matches)
}

/// Grow a match from the constant byte at `start` over constant and
/// (when allowed) convincingly masked bytes, up to [`MAX_MATCH_LEN`].
fn extend_match(classes: &[ByteClass], excluded: &[bool], start: usize, masks_allowed: bool) -> MagicMatch {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for position in start..classes.len().min(start + MAX_MATCH_LEN) {
        if excluded[position] {
            break;
        }
        match classes[position] {
            ByteClass::Constant(byte) => {
                bytes.push(byte);
                mask.push(0xFF);
            }
            ByteClass::Masked { mask: bits, value } if masks_allowed && bits.count_ones() >= MIN_MASKED_BITS => {
                bytes.push(value);
                mask.push(bits);
            }
            _ => break,
        }
    }
    // A trailing masked byte is useful; a trailing run of them is not worth
    // more than the first, so nothing is trimmed.
    let mask = if mask.iter().all(|&bits| bits == 0xFF) { None } else { Some(mask) };
    MagicMatch { offset: start, bytes, mask }
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_printable_text(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&byte| (0x20..=0x7E).contains(&byte))
}

/// The magic as text when it reads as text, else as hex.
fn readable_magic(bytes: &[u8]) -> String {
    if bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || b" ._-+".contains(byte)) && !bytes.is_empty() {
        String::from_utf8_lossy(bytes).trim().to_string()
    } else {
        format!("0x{}", hex(bytes))
    }
}

/// A TOML basic string.
fn toml_string(text: &str) -> String {
    let mut quoted = String::from("\"");
    for character in text.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(quoted, "\\u{:04X}", c as u32);
            }
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// A template string literal: printable ASCII as is, everything else `\xNN`.
fn template_literal(bytes: &[u8]) -> String {
    let mut literal = String::from("\"");
    for &byte in bytes {
        match byte {
            b'"' => literal.push_str("\\\""),
            b'\\' => literal.push_str("\\\\"),
            0x20..=0x7E => literal.push(byte as char),
            _ => {
                let _ = write!(literal, "\\x{byte:02x}");
            }
        }
    }
    literal.push('"');
    literal
}

fn endian_name(little_endian: bool) -> &'static str {
    if little_endian { "little" } else { "big" }
}

/// `u32le`, `i16be`, `f64le`, or `u8` for a single byte.
fn template_type(interpretation: Interpretation) -> String {
    let bits = interpretation.width * 8;
    let stem = match interpretation.kind {
        NumberKind::Signed | NumberKind::FixedPoint => "i",
        NumberKind::Float => "f",
        _ => "u",
    };
    if interpretation.width == 1 {
        return format!("{stem}8");
    }
    format!("{stem}{bits}{}", if interpretation.little_endian { "le" } else { "be" })
}

fn unsigned_type(width: usize, little_endian: bool) -> String {
    template_type(Interpretation { kind: NumberKind::Unsigned, width, little_endian })
}

fn listed_values(values: &[u64]) -> String {
    let mut distinct: Vec<u64> = Vec::new();
    for &value in values {
        if !distinct.contains(&value) {
            distinct.push(value);
        }
    }
    let shown: Vec<String> = distinct.iter().take(LISTED_VALUES).map(u64::to_string).collect();
    let more = if distinct.len() > LISTED_VALUES { ", …" } else { "" };
    format!("{}{more}", shown.join(", "))
}

// ---------------------------------------------------------------------------
// Catalogue entry
// ---------------------------------------------------------------------------

fn catalogue_match(found: &MagicMatch) -> String {
    match &found.mask {
        None => format!("{{ offset = {}, bytes = \"{}\" }}", found.offset, hex(&found.bytes)),
        Some(mask) => format!("{{ offset = {}, bytes = \"{}\", mask = \"{}\" }}", found.offset, hex(&found.bytes), hex(mask)),
    }
}

/// A `[[signature]]` entry in the format of `catalog/curated.toml`.
fn catalogue_entry(learned: &LearnedFormat) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "# Learned by theviewer from {} samples. Rename it and pick a category as you learn more.", learned.sample_count);
    let _ = writeln!(text, "[[signature]]");
    let _ = writeln!(text, "id = {}", toml_string(&learned.id));
    let _ = writeln!(text, "name = {}", toml_string(&learned.name));
    let _ = writeln!(text, "category = \"Signature\"");
    if let Some(field) = learned.length_field()
        && let FieldKind::Length { add } = field.kind
    {
        let add_part = if add == 0 { String::new() } else { format!(", add = {add}") };
        let _ = writeln!(
            text,
            "extent = {{ kind = \"field\", offset = {}, size = {}, endian = \"{}\"{add_part} }}",
            field.offset,
            field.width,
            endian_name(field.little_endian)
        );
    }
    let matches: Vec<String> = learned.magic.iter().map(catalogue_match).collect();
    if let [single] = matches.as_slice() {
        let _ = writeln!(text, "magic = [{single}]");
    } else {
        let _ = writeln!(text, "magic = [{{ matches = [{}] }}]", matches.join(", "));
    }
    text
}

// ---------------------------------------------------------------------------
// Template draft
// ---------------------------------------------------------------------------

/// One field line of the template.
struct TemplateLine {
    declaration: String,
    comment: String,
}

impl TemplateLine {
    fn new(declaration: String, comment: impl Into<String>) -> Self {
        TemplateLine { declaration, comment: comment.into() }
    }
}

/// Field names already used, so each is unique.
#[derive(Default)]
struct Names {
    used: Vec<String>,
}

impl Names {
    /// `preferred` if still free, else `preferred_<offset>`.
    fn claim(&mut self, preferred: &str, offset: usize) -> String {
        let name = if self.used.iter().any(|used| used == preferred) { format!("{preferred}_{offset}") } else { preferred.to_string() };
        self.used.push(name.clone());
        name
    }
}

/// A template describing the header: constants with their expected values,
/// recognised fields, typed variable gaps, and the rest of the file when its
/// length is known.
fn template_draft(learned: &LearnedFormat, headers: &[&[u8]]) -> String {
    let compared = learned.compared_len;
    // Masked bytes inside a match are described as variable fields.
    let is_template_constant: Vec<bool> = (0..compared)
        .map(|position| {
            let in_magic = learned.magic.iter().any(|found| (found.offset..found.end()).contains(&position));
            in_magic && matches!(learned.classes[position], ByteClass::Constant(_))
        })
        .collect();
    let field_end = learned.fields.iter().map(HeaderField::end).max().unwrap_or(0);
    let magic_end = learned.magic.iter().map(MagicMatch::end).max().unwrap_or(0);
    let template_end = field_end.max(magic_end).min(compared);

    let records = header_records(headers);
    let mut names = Names::default();
    let mut lines = Vec::new();
    let mut position = 0;
    while position < template_end {
        if let Some(field) = learned.fields.iter().find(|field| field.offset == position) {
            lines.push(field_line(field, &mut names));
            position = field.end();
        } else if is_template_constant[position] {
            let end = run_end(position, template_end, |p| is_template_constant[p] && !starts_field(learned, p));
            let bytes: Vec<u8> = learned.classes[position..end].iter().filter_map(|&class| constant_byte(class)).collect();
            lines.push(constant_line(position, &bytes, &mut names));
            position = end;
        } else {
            let end = run_end(position, template_end, |p| !is_template_constant[p] && !starts_field(learned, p));
            lines.push(gap_line(position, end, &records, compared, headers, &mut names));
            position = end;
        }
    }
    let rest = rest_line(learned, template_end, &names);

    let mut text = String::new();
    let _ = writeln!(text, "// Learned from {} samples by comparing their first {} bytes.", learned.sample_count, compared);
    let _ = writeln!(text, "// Rename fields as you learn what they mean.");
    let _ = writeln!(text, "endian little");
    let _ = writeln!(text);
    let _ = writeln!(text, "struct Learned {{");
    for line in lines.iter().chain(rest.iter()) {
        let _ = writeln!(text, "    {:<width$} // {}", line.declaration, line.comment, width = TEMPLATE_COMMENT_COLUMN - 4);
    }
    let _ = writeln!(text, "}}");
    let _ = writeln!(text);
    let _ = writeln!(text, "root Learned");
    text
}

fn starts_field(learned: &LearnedFormat, position: usize) -> bool {
    learned.fields.iter().any(|field| field.offset == position)
}

/// First position at or after `start + 1` where `continues` fails, or `end`.
fn run_end(start: usize, end: usize, continues: impl Fn(usize) -> bool) -> usize {
    (start + 1..end).find(|&position| !continues(position)).unwrap_or(end)
}

fn field_line(field: &HeaderField, names: &mut Names) -> TemplateLine {
    let number = unsigned_type(field.width, field.little_endian);
    match field.kind {
        FieldKind::Length { add } => {
            let name = names.claim("length", field.offset);
            let relation = match add {
                0 => "the file length".to_string(),
                add if add > 0 => format!("the file length - {add}"),
                add => format!("the file length + {}", -add),
            };
            TemplateLine::new(format!("{name}: {number}"), format!("{relation} in every sample"))
        }
        FieldKind::Timestamp(interpretation) => {
            let name = names.claim("timestamp", field.offset);
            TemplateLine::new(format!("{name}: {number}"), format!("{} in every sample", interpretation.label()))
        }
        FieldKind::Offset => {
            let name = names.claim("offset", field.offset);
            TemplateLine::new(format!("{name}: {number} display hex"), "always points inside the file")
        }
    }
}

fn constant_line(offset: usize, bytes: &[u8], names: &mut Names) -> TemplateLine {
    let name = if offset == 0 { names.claim("magic", offset) } else { names.claim(&format!("constant_{offset}"), offset) };
    let kind = if is_printable_text(bytes) { "char" } else { "bytes" };
    TemplateLine::new(format!("{name}: {kind}[{}] = {}", bytes.len(), template_literal(bytes)), "the same in every sample")
}

/// Describe the variable bytes `start..end`: as a number when they are one
/// plausible number wide, else as unknown bytes.
fn gap_line(start: usize, end: usize, records: &[u8], record_len: usize, headers: &[&[u8]], names: &mut Names) -> TemplateLine {
    let width = end - start;
    if !matches!(width, 1 | 2 | 4 | 8) {
        let name = names.claim(&format!("unknown_{start}"), start);
        return TemplateLine::new(format!("{name}: bytes[{width}]"), "varies, no pattern found");
    }
    let values = field_values(headers, start, width, true).unwrap_or_default();
    if width == 1 && values.iter().all(|&value| value <= SMALL_VALUE_LIMIT) {
        let name = names.claim("version", start);
        return TemplateLine::new(format!("{name}: u8"), format!("varies: {}; small, version-like", listed_values(&values)));
    }
    let best = numeric::rank_field(records, record_len, start, width).ok().and_then(|ranked| ranked.into_iter().next());
    match best {
        Some(best) if best.score >= NUMBER_MIN_SCORE => {
            let name = names.claim(&format!("value_{start}"), start);
            TemplateLine::new(format!("{name}: {}", template_type(best.interpretation)), format!("best read as {}: {}", best.interpretation.label(), best.reason))
        }
        _ => {
            let name = names.claim(&format!("unknown_{start}"), start);
            TemplateLine::new(format!("{name}: bytes[{width}]"), "varies, no pattern found")
        }
    }
}

/// The rest of the file, sized from the length field when there is one.
fn rest_line(learned: &LearnedFormat, template_end: usize, names: &Names) -> Option<TemplateLine> {
    let field = learned.length_field()?;
    let FieldKind::Length { add } = field.kind else { return None };
    // The length field is always the first one claimed with that name.
    let name = names.used.iter().find(|name| name.starts_with("length"))?.clone();
    let adjustment = i128::from(add) - template_end as i128;
    let expression = match adjustment {
        0 => name,
        positive if positive > 0 => format!("{name} + {positive}"),
        negative => format!("{name} - {}", -negative),
    };
    Some(TemplateLine::new(format!("rest: bytes[{expression}]"), "everything after the header, sized by the length field"))
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClassKind {
    Constant,
    Masked,
    Variable,
}

/// How a position is reported. Bits shared by chance are common with few
/// samples, so only convincingly masked bytes count as partly constant.
fn class_kind(class: ByteClass, sample_count: usize) -> ClassKind {
    match class {
        ByteClass::Constant(_) => ClassKind::Constant,
        ByteClass::Masked { mask, .. } if sample_count >= MIN_SAMPLES_FOR_MASKS && mask.count_ones() >= MIN_MASKED_BITS => ClassKind::Masked,
        ByteClass::Masked { .. } | ByteClass::Variable => ClassKind::Variable,
    }
}

/// Runs of the same kind of class, as `(kind, start, end)`.
fn class_ranges(classes: &[ByteClass], sample_count: usize) -> Vec<(ClassKind, usize, usize)> {
    let mut ranges: Vec<(ClassKind, usize, usize)> = Vec::new();
    for (position, &class) in classes.iter().enumerate() {
        let kind = class_kind(class, sample_count);
        match ranges.last_mut() {
            Some(last) if last.0 == kind && last.2 == position => last.2 = position + 1,
            _ => ranges.push((kind, position, position + 1)),
        }
    }
    ranges
}

fn describe_range(start: usize, end: usize) -> String {
    if end - start == 1 { format!("0x{start:x}") } else { format!("0x{start:x}–0x{:x} ({} bytes)", end - 1, end - start) }
}

fn summarise_kind(text: &mut String, label: &str, ranges: &[(ClassKind, usize, usize)], kind: ClassKind, classes: &[ByteClass]) {
    let chosen: Vec<&(ClassKind, usize, usize)> = ranges.iter().filter(|range| range.0 == kind).collect();
    let total: usize = chosen.iter().map(|range| range.2 - range.1).sum();
    let _ = writeln!(text, "{label}: {total} bytes in {} ranges", chosen.len());
    for &&(_, start, end) in chosen.iter().take(SUMMARY_MAX_RANGES) {
        let detail = match kind {
            ClassKind::Constant => {
                let bytes: Vec<u8> = classes[start..end].iter().filter_map(|&class| constant_byte(class)).collect();
                if is_printable_text(&bytes) && bytes.len() > 1 { format!(" {}", template_literal(&bytes)) } else { format!(" {}", hex(&bytes[..bytes.len().min(16)])) }
            }
            ClassKind::Masked => match classes[start] {
                ByteClass::Masked { mask, value } if end - start == 1 => format!(" (bits {mask:02x} always {value:02x})"),
                _ => String::new(),
            },
            ClassKind::Variable => String::new(),
        };
        let _ = writeln!(text, "  {}{detail}", describe_range(start, end));
    }
    if chosen.len() > SUMMARY_MAX_RANGES {
        let _ = writeln!(text, "  … and {} more", chosen.len() - SUMMARY_MAX_RANGES);
    }
}

fn summary(learned: &LearnedFormat) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "Compared the first {} bytes of {} samples.", learned.compared_len, learned.sample_count);
    let ranges = class_ranges(&learned.classes, learned.sample_count);
    summarise_kind(&mut text, "Constant", &ranges, ClassKind::Constant, &learned.classes);
    summarise_kind(&mut text, "Partly constant", &ranges, ClassKind::Masked, &learned.classes);
    summarise_kind(&mut text, "Variable", &ranges, ClassKind::Variable, &learned.classes);

    let primary = &learned.magic[0];
    let masked = if primary.mask.is_some() { ", some bits masked" } else { "" };
    let _ = writeln!(text, "Magic: {} bytes at 0x{:x}{masked}.", primary.bytes.len(), primary.offset);
    if learned.magic.len() > 1 {
        let _ = writeln!(text, "Extra conditions: {} more constant runs at fixed offsets.", learned.magic.len() - 1);
    }
    if learned.fields.is_empty() {
        let _ = writeln!(text, "No length, timestamp or offset fields were recognised.");
    }
    for field in &learned.fields {
        let _ = writeln!(text, "Field at 0x{:x}: {}.", field.offset, field.describe());
    }
    match learned.length_field() {
        Some(field) => {
            let _ = writeln!(text, "The signature's extent comes from the length field at 0x{:x}.", field.offset);
        }
        None => {
            let _ = writeln!(text, "No length field was found, so a match covers only the magic.");
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Catalog;
    use crate::plugin::Field;
    use crate::templates::Template;

    /// Deterministic pseudo-random bytes (xorshift).
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

    /// A "QXF1" file: magic, version byte, u32 LE total length, random body.
    fn qxf_sample(version: u8, total_len: usize, seed: u64) -> Vec<u8> {
        let mut bytes = b"QXF1".to_vec();
        bytes.push(version);
        bytes.extend_from_slice(&(total_len as u32).to_le_bytes());
        bytes.extend(noise(total_len - bytes.len(), seed));
        bytes
    }

    fn qxf_samples() -> Vec<Vec<u8>> {
        [(1, 1200), (2, 1733), (3, 2048), (1, 999), (2, 3001)]
            .iter()
            .enumerate()
            .map(|(index, &(version, len))| qxf_sample(version, len, 100 + index as u64))
            .collect()
    }

    fn learn(samples: &[Vec<u8>]) -> LearnedFormat {
        let samples: Vec<Sample> = samples.iter().map(|bytes| Sample::whole(bytes)).collect();
        learn_format(&samples).expect("learned")
    }

    fn find_field<'a>(fields: &'a [Field], name: &str) -> &'a Field {
        fields.iter().find(|field| field.name == name).unwrap_or_else(|| panic!("no field '{name}' in {fields:?}"))
    }

    #[test]
    fn learned_catalogue_entry_matches_every_sample_with_its_full_length() {
        let samples = qxf_samples();
        let learned = learn(&samples);
        let catalog = Catalog::from_toml(&learned.catalogue_toml).unwrap_or_else(|error| panic!("{error}\n{}", learned.catalogue_toml));
        assert_eq!(catalog.len(), 1);
        for sample in &samples {
            let findings = catalog.scan(sample, 0);
            let hit = findings.iter().find(|finding| finding.start == 0).unwrap_or_else(|| panic!("no match:\n{}", learned.catalogue_toml));
            assert_eq!(hit.id, format!("signature:{}", learned.id));
            assert_eq!(hit.len, sample.len(), "extent from the length field");
            assert!(hit.confidence >= 0.8, "confidence {}", hit.confidence);
        }
    }

    #[test]
    fn learned_catalogue_entry_rejects_random_data() {
        let learned = learn(&qxf_samples());
        let catalog = Catalog::from_toml(&learned.catalogue_toml).unwrap();
        assert!(catalog.scan(&noise(256 * 1024, 0xABCDEF), 0).is_empty());
        // The right magic with a version outside the learned mask is rejected too.
        let mut wrong_version = qxf_sample(0x80, 500, 9);
        assert!(catalog.scan(&wrong_version, 0).is_empty(), "{}", learned.catalogue_toml);
        wrong_version[4] = 2;
        assert!(!catalog.scan(&wrong_version, 0).is_empty());
    }

    #[test]
    fn magic_is_the_constant_prefix_with_the_version_byte_masked() {
        let learned = learn(&qxf_samples());
        assert_eq!(learned.magic[0], MagicMatch { offset: 0, bytes: b"QXF1\x00".to_vec(), mask: Some(vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFC]) });
        assert_eq!(learned.id, "user/learned-51584631");
        assert_eq!(learned.classes[4], ByteClass::Masked { mask: 0xFC, value: 0 });
        assert!(learned.catalogue_toml.contains("extent = { kind = \"field\", offset = 5, size = 4, endian = \"little\" }"), "{}", learned.catalogue_toml);
    }

    #[test]
    fn the_length_field_is_found_and_its_high_zero_bytes_are_not_magic() {
        let learned = learn(&qxf_samples());
        let length = learned.length_field().expect("a length field");
        assert_eq!((length.offset, length.width, length.little_endian, length.kind), (5, 4, true, FieldKind::Length { add: 0 }));
        assert!(learned.magic.iter().all(|found| found.end() <= 5 || found.offset >= 9), "{:?}", learned.magic);
    }

    #[test]
    fn template_draft_parses_and_decodes_the_header() {
        let samples = qxf_samples();
        let learned = learn(&samples);
        let template = Template::parse(&learned.template).unwrap_or_else(|error| panic!("{error}\n{}", learned.template));
        for sample in &samples {
            let applied = template.apply(sample, 0);
            assert!(applied.warnings.is_empty(), "{:?}\n{}", applied.warnings, learned.template);
            assert!(!learned.template.contains("timestamp"), "random body bytes read as a date:\n{}", learned.template);
            let root = &applied.finding.fields[0];
            assert!(find_field(&root.children, "magic").value.contains("QXF1"));
            assert_eq!(find_field(&root.children, "version").value, sample[4].to_string());
            assert_eq!(find_field(&root.children, "length").value, sample.len().to_string());
            let rest = find_field(&root.children, "rest");
            assert_eq!(rest.offset + rest.len, sample.len());
        }
    }

    #[test]
    fn a_length_that_excludes_the_header_becomes_an_extent_with_an_addition() {
        // RIFF-like: magic, then a u32 BE size that leaves out the first 12 bytes.
        let samples: Vec<Vec<u8>> = [800usize, 1500, 2222]
            .iter()
            .enumerate()
            .map(|(index, &len)| {
                let mut bytes = b"ABCDWXYZ".to_vec();
                bytes.extend_from_slice(&(len as u32 - 12).to_be_bytes());
                bytes.extend(noise(len - 12, index as u64 + 7));
                bytes
            })
            .collect();
        let learned = learn(&samples);
        let length = learned.length_field().expect("a length field");
        assert_eq!((length.offset, length.little_endian, length.kind), (8, false, FieldKind::Length { add: 12 }));
        let catalog = Catalog::from_toml(&learned.catalogue_toml).unwrap();
        for sample in &samples {
            let hit = catalog.scan(sample, 0).into_iter().find(|finding| finding.start == 0).expect("match");
            assert_eq!(hit.len, sample.len());
        }
        let template = Template::parse(&learned.template).unwrap();
        assert!(template.apply(&samples[0], 0).warnings.is_empty(), "{}", learned.template);
    }

    #[test]
    fn timestamps_in_the_header_are_recognised() {
        let samples: Vec<Vec<u8>> = (0..5u32)
            .map(|index| {
                let mut bytes = b"TSHD\x00\x01\x00\x00".to_vec();
                bytes.extend_from_slice(&(1_650_000_000 + index * 86_400 * 37).to_le_bytes());
                bytes.extend_from_slice(b"\xAA\xBB\xCC\xDD");
                bytes.extend(noise(500, u64::from(index) + 50));
                bytes
            })
            .collect();
        let learned = learn(&samples);
        let timestamp = learned.fields.iter().find(|field| matches!(field.kind, FieldKind::Timestamp(_))).expect("a timestamp");
        assert_eq!((timestamp.offset, timestamp.width), (8, 4));
        assert!(learned.template.contains("timestamp: u32le"), "{}", learned.template);
        // The constant run after the timestamp is an extra condition.
        assert!(learned.magic.iter().any(|found| found.offset == 12 && found.bytes == b"\xAA\xBB\xCC\xDD"), "{:?}", learned.magic);
        assert!(Template::parse(&learned.template).is_ok());
    }

    #[test]
    fn a_magic_away_from_the_start_is_still_found() {
        let samples: Vec<Vec<u8>> = (0..3u64)
            .map(|seed| {
                let mut bytes = noise(64, seed * 2 + 1);
                bytes[20..26].copy_from_slice(b"MAGIC!");
                bytes
            })
            .collect();
        let learned = learn(&samples);
        assert_eq!(learned.magic[0].offset, 20, "{:?}", learned.fields);
        assert_eq!(learned.magic[0].bytes, b"MAGIC!".to_vec(), "{:?}", learned.fields);
        let catalog = Catalog::from_toml(&learned.catalogue_toml).unwrap();
        assert!(catalog.scan(&samples[1], 0).iter().any(|finding| finding.start == 0));
        assert!(Template::parse(&learned.template).is_ok(), "{}", learned.template);
    }

    #[test]
    fn summary_names_constant_and_variable_ranges() {
        let learned = learn(&qxf_samples());
        assert!(learned.summary.contains("0x0–0x3 (4 bytes) \"QXF1\""), "{}", learned.summary);
        assert!(learned.summary.contains("bits fc always 00"), "{}", learned.summary);
        assert!(learned.summary.contains("length field at 0x5"), "{}", learned.summary);
    }

    #[test]
    fn too_few_or_empty_samples_are_explained() {
        let one = qxf_sample(1, 100, 1);
        assert_eq!(learn_format(&[Sample::whole(&one)]).unwrap_err(), LearnError::TooFewSamples(1));
        assert_eq!(learn_format(&[Sample::whole(&one), Sample::whole(&[])]).unwrap_err(), LearnError::EmptySample(1));
    }

    #[test]
    fn unrelated_samples_have_no_common_magic() {
        let a = noise(4096, 1);
        let b = noise(4096, 2);
        let error = learn_format(&[Sample::whole(&a), Sample::whole(&b)]).unwrap_err();
        assert!(matches!(error, LearnError::NoCommonMagic { compared_len: 4096 }), "{error:?}");
        // Shared zero fill alone is not a magic either.
        let zeros = vec![0u8; 100];
        assert!(learn_format(&[Sample::whole(&zeros), Sample::whole(&zeros)]).is_err());
    }

    #[test]
    fn arbitrary_inputs_never_panic() {
        for seed in 0..40u64 {
            let count = 2 + (seed % 4) as usize;
            let samples: Vec<Vec<u8>> = (0..count)
                .map(|index| {
                    let len = 1 + (noise(2, seed * 10 + index as u64)[0] as usize * 7);
                    let mut bytes = noise(len, seed * 31 + index as u64);
                    if seed % 2 == 0 && len > 3 {
                        bytes[..3].copy_from_slice(b"\x01\x02\x03");
                    }
                    bytes
                })
                .collect();
            let views: Vec<Sample> = samples.iter().map(|bytes| Sample { bytes, file_len: bytes.len() as u64 * (seed % 3 + 1) }).collect();
            if let Ok(learned) = learn_format(&views) {
                assert!(Catalog::from_toml(&learned.catalogue_toml).is_ok(), "{}", learned.catalogue_toml);
                assert!(Template::parse(&learned.template).is_ok(), "{}", learned.template);
            }
        }
    }
}
