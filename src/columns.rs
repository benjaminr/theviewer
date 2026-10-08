//! Per-position field profiling for fixed-size records.
//!
//! Given bytes laid out as records of `record_len` bytes, every byte position
//! ("column") is profiled across the records, then adjacent columns are
//! grouped into likely fields: counters, timestamps, offsets, lengths, flags,
//! floats, text, constants and opaque bytes. The fields can be turned into a
//! template in the app's template language.

use crate::analysis::shannon_entropy;

/// What a single byte column looks like across the records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColumnKind {
    Constant,
    Counter,
    Monotonic,
    /// Few distinct values: flags, enums, types.
    LowCardinality,
    Text,
    Random,
    Mixed,
}

impl ColumnKind {
    pub fn label(self) -> &'static str {
        match self {
            ColumnKind::Constant => "constant",
            ColumnKind::Counter => "counter",
            ColumnKind::Monotonic => "monotonic",
            ColumnKind::LowCardinality => "few values",
            ColumnKind::Text => "text",
            ColumnKind::Random => "random",
            ColumnKind::Mixed => "mixed",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            ColumnKind::Constant => "the same value in every record",
            ColumnKind::Counter => "changes by the same step every record",
            ColumnKind::Monotonic => "never decreases from one record to the next",
            ColumnKind::LowCardinality => "only a few distinct values, like flags or a type",
            ColumnKind::Text => "printable ASCII in every record",
            ColumnKind::Random => "close to uniformly random",
            ColumnKind::Mixed => "varies without an obvious pattern",
        }
    }
}

/// Statistics of one byte position across the records.
#[derive(Clone, Debug, PartialEq)]
pub struct ColumnProfile {
    pub position: usize,
    pub kind: ColumnKind,
    /// Shannon entropy of the column's values, in bits.
    pub entropy: f32,
    pub distinct: usize,
    pub most_common: u8,
    pub most_common_fraction: f32,
    pub min: u8,
    pub max: u8,
    /// How often the value differs from the previous record's.
    pub changes_fraction: f32,
}

/// A likely field spanning one or more columns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldGuess {
    /// Named by where the field starts (`field_7`), so the name stays the
    /// same when another set of records makes the guess differ.
    pub name: String,
    pub start: usize,
    pub len: usize,
    /// Role, type and byte order, e.g. "counter u32 LE +1", "flags u16 LE",
    /// "text", "constant", "bytes".
    pub kind: String,
    /// Evidence, in words.
    pub detail: String,
}

/// Fraction of record pairs a pattern must hold for.
const AGREEMENT: f64 = 0.95;
/// Records examined when grouping columns into fields.
const MAX_GROUPED_RECORDS: usize = 4096;
/// Distinct values at or below which a column counts as low cardinality.
const LOW_CARDINALITY: usize = 8;
/// Records needed before a varying run is guessed to be text, a float or a
/// monotonic number: in fewer, such shapes turn up by chance.
const MIN_SHAPE_RECORDS: usize = 4;
/// How much more often a byte of a number may change than the byte below it.
const CHANGE_TOLERANCE: f32 = 0.05;

/// Records used to learn which byte positions are stable in a table.
const TABLE_SAMPLE_RECORDS: usize = 8;
/// Share of the stable positions a record must match to belong to the table.
const TABLE_MATCH_SHARE: f32 = 0.8;
/// Consecutive records that do not match before the table is taken to end.
const TABLE_END_RUN: usize = 3;

/// Broad kind of a byte (zero, text, control, high or 0xFF), the same split
/// the byte-class pixel format colours.
fn byte_kind(byte: u8) -> u8 {
    match byte {
        0x00 => 0,
        0xFF => 1,
        0x20..=0x7E => 2,
        0x01..=0x1F | 0x7F => 3,
        _ => 4,
    }
}

/// How many records, from the first, belong to one table.
///
/// Byte positions whose kind is the same in each of the first few records
/// (a constant, a text tag, a zero high byte) are the table's fingerprint.
/// The table ends where records stop matching it, so whatever follows (text,
/// an image, compressed data) does not drown out the real columns. With no
/// stable positions there is nothing to go on, and every record counts.
pub fn table_length(bytes: &[u8], record_len: usize, max_records: usize) -> usize {
    let records = record_count(bytes, record_len, max_records);
    let sample = records.min(TABLE_SAMPLE_RECORDS);
    if sample < 2 {
        return records;
    }
    let record = |index: usize| &bytes[index * record_len..(index + 1) * record_len];
    let stable: Vec<(usize, u8)> = (0..record_len)
        .filter_map(|position| {
            let kind = byte_kind(record(0)[position]);
            (1..sample).all(|r| byte_kind(record(r)[position]) == kind).then_some((position, kind))
        })
        .collect();
    if stable.is_empty() {
        return records;
    }
    let matches = |index: usize| {
        let matching = stable.iter().filter(|&&(position, kind)| byte_kind(record(index)[position]) == kind).count();
        matching as f32 >= stable.len() as f32 * TABLE_MATCH_SHARE
    };
    let mut misses = 0;
    for index in sample..records {
        if matches(index) {
            misses = 0;
        } else {
            misses += 1;
            if misses == TABLE_END_RUN {
                return index + 1 - TABLE_END_RUN;
            }
        }
    }
    records
}

/// Records available: at most `max_records` whole records.
fn record_count(bytes: &[u8], record_len: usize, max_records: usize) -> usize {
    if record_len == 0 {
        return 0;
    }
    (bytes.len() / record_len).min(max_records)
}

/// The column's value in each record.
fn column(bytes: &[u8], record_len: usize, records: usize, position: usize) -> Vec<u8> {
    (0..records).map(|r| bytes[r * record_len + position]).collect()
}

/// Profile every byte position over the first `max_records` records.
pub fn profile(bytes: &[u8], record_len: usize, max_records: usize) -> Vec<ColumnProfile> {
    let records = record_count(bytes, record_len, max_records);
    if records == 0 {
        return Vec::new();
    }
    (0..record_len).map(|position| profile_column(&column(bytes, record_len, records, position), position)).collect()
}

/// Profile one column from its value in each record, in record order.
pub fn profile_column(values: &[u8], position: usize) -> ColumnProfile {
    let mut histogram = [0usize; 256];
    for &value in values {
        histogram[value as usize] += 1;
    }
    let distinct = histogram.iter().filter(|&&c| c > 0).count();
    let (most_common, most_common_count) = histogram.iter().enumerate().max_by_key(|&(_, &c)| c).map(|(v, &c)| (v as u8, c)).unwrap_or((0, 0));
    let pairs = values.len().saturating_sub(1);
    let changes = values.windows(2).filter(|w| w[0] != w[1]).count();
    let changes_fraction = if pairs == 0 { 0.0 } else { changes as f32 / pairs as f32 };
    let entropy = shannon_entropy(values);
    ColumnProfile {
        position,
        kind: classify_column(values, distinct, entropy),
        entropy,
        distinct,
        most_common,
        most_common_fraction: most_common_count as f32 / values.len().max(1) as f32,
        min: values.iter().copied().min().unwrap_or(0),
        max: values.iter().copied().max().unwrap_or(0),
        changes_fraction,
    }
}

fn holds_for(pairs: usize, matching: usize) -> bool {
    pairs > 0 && matching as f64 >= pairs as f64 * AGREEMENT
}

fn classify_column(values: &[u8], distinct: usize, entropy: f32) -> ColumnKind {
    if distinct <= 1 {
        return ColumnKind::Constant;
    }
    let pairs = values.len().saturating_sub(1);
    let step = values[1].wrapping_sub(values[0]);
    let constant_step = values.windows(2).filter(|w| w[1].wrapping_sub(w[0]) == step).count();
    if step != 0 && holds_for(pairs, constant_step) {
        return ColumnKind::Counter;
    }
    if values.iter().all(|&v| (0x20..0x7F).contains(&v)) {
        return ColumnKind::Text;
    }
    let rising = values.windows(2).filter(|w| w[1] >= w[0]).count();
    if holds_for(pairs, rising) && values.windows(2).any(|w| w[1] > w[0]) {
        return ColumnKind::Monotonic;
    }
    if distinct <= LOW_CARDINALITY && distinct * 4 <= values.len() {
        return ColumnKind::LowCardinality;
    }
    let ideal = (values.len().min(256) as f32).log2();
    if ideal > 0.0 && entropy >= 0.8 * ideal {
        return ColumnKind::Random;
    }
    ColumnKind::Mixed
}

// ---------------------------------------------------------------------------
// Grouping columns into fields
// ---------------------------------------------------------------------------

/// Read a `width`-byte unsigned integer.
fn read_uint(bytes: &[u8], width: usize, big_endian: bool) -> u64 {
    let mut value = 0u64;
    for index in 0..width {
        let byte = if big_endian { bytes[index] } else { bytes[width - 1 - index] };
        value = (value << 8) | byte as u64;
    }
    value
}

/// A multi-byte column read as integers, one per record.
fn integers(bytes: &[u8], record_len: usize, records: usize, start: usize, width: usize, big_endian: bool) -> Vec<u64> {
    (0..records).map(|r| read_uint(&bytes[r * record_len + start..], width, big_endian)).collect()
}

fn endian_label(big_endian: bool) -> &'static str {
    if big_endian { "BE" } else { "LE" }
}

const UNIX_MIN: u64 = 946_684_800;
const UNIX_MAX: u64 = 2_208_988_800;

/// The step of a counter: the one change between records, which some
/// records repeat (a frame sent several times keeps its count), and
/// whether any did. Repeats need records enough to tell them from chance.
fn counter_step(values: &[u64]) -> Option<(i64, bool)> {
    const MOST_STEP: u64 = 1 << 20;
    let pairs = values.len().saturating_sub(1);
    let tolerate_repeats = values.len() >= MIN_SHAPE_RECORDS;
    let moves: Vec<i64> = values.windows(2).map(|w| w[1].wrapping_sub(w[0]) as i64).filter(|&step| step != 0).collect();
    let mut tally: Vec<(i64, usize)> = Vec::new();
    for &step in &moves {
        match tally.iter_mut().find(|(seen, _)| *seen == step) {
            Some((_, count)) => *count += 1,
            None => tally.push((step, 1)),
        }
    }
    let (step, regular) = tally.into_iter().max_by_key(|&(_, count)| count)?;
    // A counter mostly moves: one that stands still in most records is a
    // value that happens to change by the same amount now and then.
    let moves_enough = if tolerate_repeats { moves.len() * 3 >= pairs } else { moves.len() == pairs };
    let counts = regular >= 2 && step.unsigned_abs() <= MOST_STEP && holds_for(moves.len(), regular);
    (moves_enough && counts).then_some((step, moves.len() < pairs))
}

/// Classify a multi-byte integer field, if it has a recognisable role.
fn integer_role(values: &[u64], width: usize, big_endian: bool, records: usize, document_len: usize) -> Option<(String, String)> {
    let pairs = values.len().saturating_sub(1);
    if pairs == 0 || values.windows(2).all(|w| w[0] == w[1]) {
        return None;
    }
    let ty = format!("u{} {}", width * 8, endian_label(big_endian));
    let unix_times = width == 4 && values.iter().all(|v| (UNIX_MIN..UNIX_MAX).contains(v));
    if let Some((step, repeats)) = counter_step(values) {
        if repeats && unix_times {
            return Some((format!("timestamp {ty}"), "increasing values that read as Unix times".to_string()));
        }
        let detail = if repeats {
            format!("changes by {step:+} or stays the same from one record to the next")
        } else {
            format!("changes by {step:+} every record")
        };
        return Some((format!("counter {ty} {step:+}"), detail));
    }
    if records < MIN_SHAPE_RECORDS {
        return None;
    }
    let rising = values.windows(2).filter(|w| w[1] >= w[0]).count();
    // A clock read by several records in the same second stays put between
    // them; values that are all Unix times need only never go back.
    if holds_for(pairs, rising) && unix_times {
        return Some((format!("timestamp {ty}"), "increasing values that read as Unix times".to_string()));
    }
    if holds_for(pairs, rising) && values.windows(2).filter(|w| w[1] > w[0]).count() * 2 >= pairs {
        if values.iter().all(|&v| v > 0 && (v as usize) < document_len) {
            return Some((format!("offset {ty}"), "increasing values that point inside the file".to_string()));
        }
        return Some((format!("monotonic {ty}"), "never decreases from one record to the next".to_string()));
    }
    if values.iter().all(|&v| v as usize == records) {
        return Some((format!("length {ty}"), format!("equals the number of records ({records})")));
    }
    None
}

/// Whether the bytes a little-endian read treats as the high half are a
/// constant non-zero value: then the field is really narrower, next to a
/// constant.
fn high_half_suspicious(bytes: &[u8], record_len: usize, records: usize, start: usize, width: usize, big_endian: bool) -> bool {
    let half = width / 2;
    let high: Vec<usize> = if big_endian { (start..start + half).collect() } else { (start + half..start + width).collect() };
    let first: Vec<u8> = high.iter().map(|&p| bytes[p]).collect();
    let constant = (0..records).all(|r| high.iter().zip(&first).all(|(&p, &f)| bytes[r * record_len + p] == f));
    constant && first.iter().any(|&b| b != 0)
}

/// Whether the `width` columns at `start` vary as the bytes of one number:
/// the lowest byte changes, and no byte changes more often than the byte
/// below it. A type byte beside a counter, or a counter beside a tag, do not.
fn varies_as_one_number(profiles: &[ColumnProfile], start: usize, width: usize, big_endian: bool) -> bool {
    let mut by_significance: Vec<&ColumnProfile> = profiles[start..start + width].iter().collect();
    if big_endian {
        by_significance.reverse();
    }
    let lowest = by_significance[0];
    if matches!(lowest.kind, ColumnKind::Constant | ColumnKind::LowCardinality) {
        return false;
    }
    by_significance.windows(2).all(|pair| pair[1].changes_fraction <= pair[0].changes_fraction + CHANGE_TOLERANCE)
}

fn plausible_float(bits: u32) -> bool {
    let value = f32::from_bits(bits);
    value == 0.0 || (value.is_finite() && (1e-6..=1e9).contains(&value.abs()))
}

/// Merge columns into fields covering the record exactly once, in order.
pub fn group_fields(bytes: &[u8], record_len: usize, profiles: &[ColumnProfile], document_len: usize) -> Vec<FieldGuess> {
    let records = record_count(bytes, record_len, MAX_GROUPED_RECORDS);
    if records < 2 || profiles.len() != record_len {
        return if record_len == 0 { Vec::new() } else { vec![field(0, record_len, "bytes", "too few records to analyse")] };
    }
    let table = Table { bytes, record_len, records, profiles, document_len };
    let numbers = table.counters_and_times();
    let kind_at = |p: usize| profiles[p].kind;
    let mut fields: Vec<FieldGuess> = Vec::new();
    let mut position = 0;
    while position < record_len {
        // Other fields stop short of the next counter or time.
        let next_number = numbers.iter().find(|number| number.start + number.len > position);
        if let Some(number) = next_number.filter(|number| number.start == position) {
            position += number.len;
            fields.push(number.clone());
            continue;
        }
        let room = next_number.map_or(record_len, |number| number.start);
        if let Some(field) = table.integer_field(position, room) {
            position += field.len;
            fields.push(field);
            continue;
        }
        if let Some(field) = table.float_field(position, room) {
            position += field.len;
            fields.push(field);
            continue;
        }
        if kind_at(position) == ColumnKind::Text && records >= MIN_SHAPE_RECORDS {
            let end = (position..room).find(|&p| kind_at(p) != ColumnKind::Text).unwrap_or(room);
            if end - position >= 2 {
                fields.push(field(position, end - position, "text", "printable text that varies"));
                position = end;
                continue;
            }
        }
        if let Some(field) = flags_field(room, position, &kind_at) {
            position += field.len;
            fields.push(field);
            continue;
        }
        if kind_at(position) == ColumnKind::Constant {
            let end = (position..room).find(|&p| kind_at(p) != ColumnKind::Constant).unwrap_or(room);
            let value = &bytes[position..end];
            let detail = if value.iter().all(|b| (0x20..0x7F).contains(b)) && value.len() >= 2 {
                format!("text \"{}\"", String::from_utf8_lossy(value))
            } else {
                format!("hex {}", value.iter().map(|b| format!("{b:02x}")).collect::<String>())
            };
            fields.push(field(position, end - position, "constant", &detail));
            position = end;
            continue;
        }
        push_bytes(&mut fields, position);
        position += 1;
    }
    fields
}

/// A field guess, named by where it starts.
fn field(start: usize, len: usize, kind: &str, detail: &str) -> FieldGuess {
    FieldGuess { name: format!("field_{start}"), start, len, kind: kind.to_string(), detail: detail.to_string() }
}

/// The records being grouped, with each column's profile.
struct Table<'a> {
    bytes: &'a [u8],
    record_len: usize,
    records: usize,
    profiles: &'a [ColumnProfile],
    document_len: usize,
}

impl Table<'_> {
    /// Unix times, then counters, anywhere in the record, as fields that
    /// do not overlap: aligned ones first, then the rest at odd offsets. A
    /// counter takes in a constant high byte beside it.
    fn counters_and_times(&self) -> Vec<FieldGuess> {
        let mut found: Vec<FieldGuess> = Vec::new();
        for role in ["timestamp", "counter"] {
            for aligned in [true, false] {
                for start in 0..self.record_len {
                    for width in [4usize, 2] {
                        let overlaps = found.iter().any(|field| start < field.start + field.len && field.start < start + width);
                        if start + width > self.record_len || start.is_multiple_of(width) != aligned || overlaps {
                            continue;
                        }
                        if let Some(number) = self.number_in_role(start, width, role) {
                            found.push(number);
                            break;
                        }
                    }
                }
            }
        }
        found.sort_by_key(|field| field.start);
        found
    }

    /// The `width`-byte number at `start` when its role is `role`.
    fn number_in_role(&self, start: usize, width: usize, role: &str) -> Option<FieldGuess> {
        for big_endian in [false, true] {
            if !varies_as_one_number(self.profiles, start, width, big_endian) || self.low_byte_wraps_under_a_constant(start, width, big_endian) {
                continue;
            }
            let values = integers(self.bytes, self.record_len, self.records, start, width, big_endian);
            let found = integer_role(&values, width, big_endian, self.records, self.document_len);
            if let Some((kind, detail)) = found.filter(|(kind, _)| kind.starts_with(role)) {
                return Some(field(start, width, &kind, &detail));
            }
        }
        None
    }

    /// Whether the number at `start` has a low byte that wraps round under
    /// a constant byte: a byte counter beside a type or a tag, not a wider
    /// counter, whose next byte would have carried.
    fn low_byte_wraps_under_a_constant(&self, start: usize, width: usize, big_endian: bool) -> bool {
        let (low, next) = if big_endian { (start + width - 1, start + width - 2) } else { (start, start + 1) };
        if self.profiles[next].kind != ColumnKind::Constant {
            return false;
        }
        let lows = column(self.bytes, self.record_len, self.records, low);
        let rises = lows.windows(2).filter(|pair| pair[1] > pair[0]).count();
        let falls = lows.windows(2).filter(|pair| pair[1] < pair[0]).count();
        rises > 0 && falls > 0
    }

    /// An aligned integer field at `position` that ends by `room`.
    fn integer_field(&self, position: usize, room: usize) -> Option<FieldGuess> {
        let kind = self.profiles[position].kind;
        if kind == ColumnKind::Constant || kind == ColumnKind::Text {
            return None;
        }
        for width in [4usize, 8, 2] {
            if !position.is_multiple_of(width) || position + width > room {
                continue;
            }
            for big_endian in [false, true] {
                if high_half_suspicious(self.bytes, self.record_len, self.records, position, width, big_endian)
                    || !varies_as_one_number(self.profiles, position, width, big_endian)
                {
                    continue;
                }
                let values = integers(self.bytes, self.record_len, self.records, position, width, big_endian);
                if let Some((kind, detail)) = integer_role(&values, width, big_endian, self.records, self.document_len) {
                    return Some(field(position, width, &kind, &detail));
                }
            }
        }
        // A single byte that counts.
        if kind == ColumnKind::Counter {
            let values = integers(self.bytes, self.record_len, self.records, position, 1, false);
            let step = values[1].wrapping_sub(values[0]) as u8 as i8;
            return Some(field(position, 1, &format!("counter u8 {step:+}"), &format!("changes by {step:+} every record")));
        }
        None
    }

    /// A float at `position` that ends by `room`, its bytes varying alike:
    /// constant low bytes are a round mantissa and a constant top byte a
    /// value in a narrow range, but a constant byte between varying ones is
    /// not one float. There must be records enough that plausible values
    /// are not chance.
    fn float_field(&self, position: usize, room: usize) -> Option<FieldGuess> {
        if !position.is_multiple_of(4) || position + 4 > room || self.records < MIN_SHAPE_RECORDS {
            return None;
        }
        for big_endian in [false, true] {
            let mut by_significance: Vec<ColumnKind> = self.profiles[position..position + 4].iter().map(|column| column.kind).collect();
            if big_endian {
                by_significance.reverse();
            }
            // The top byte (sign and exponent) may stay put over varying
            // bytes; a constant middle byte over a varying low one is two fields.
            let top = by_significance.len() - 1;
            let constant_over_varying = (1..top).any(|index| {
                by_significance[index] == ColumnKind::Constant && by_significance[..index].iter().any(|&below| below != ColumnKind::Constant)
            });
            if constant_over_varying {
                continue;
            }
            let values = integers(self.bytes, self.record_len, self.records, position, 4, big_endian);
            let varies = values.windows(2).any(|w| w[0] != w[1]);
            let zeros = values.iter().filter(|&&v| v == 0).count();
            if varies && zeros * 2 < values.len() && values.iter().all(|&v| plausible_float(v as u32)) {
                let kind = format!("float f32 {}", endian_label(big_endian));
                return Some(field(position, 4, &kind, "a sensible floating-point value in every record"));
            }
        }
        None
    }
}

/// Extend the previous "bytes" field or start a new one.
fn push_bytes(fields: &mut Vec<FieldGuess>, position: usize) {
    if let Some(last) = fields.last_mut()
        && last.kind == "bytes"
        && last.start + last.len == position
    {
        last.len += 1;
        return;
    }
    fields.push(field(position, 1, "bytes", "no pattern found"));
}

const FLAGS_DETAIL: &str = "only a few distinct values, like flags or a type";

fn flags_field(room: usize, position: usize, kind_at: &dyn Fn(usize) -> ColumnKind) -> Option<FieldGuess> {
    let low = |p: usize| kind_at(p) == ColumnKind::LowCardinality;
    let constant = |p: usize| kind_at(p) == ColumnKind::Constant;
    if position.is_multiple_of(2) && position + 2 <= room {
        let (a, b) = (position, position + 1);
        if (low(a) && (low(b) || constant(b))) || (constant(a) && low(b)) {
            let big_endian = constant(a) && low(b);
            return Some(field(position, 2, &format!("flags u16 {}", endian_label(big_endian)), FLAGS_DETAIL));
        }
    }
    low(position).then(|| field(position, 1, "flags u8", FLAGS_DETAIL))
}

// ---------------------------------------------------------------------------
// Template output
// ---------------------------------------------------------------------------

/// The template type for a field kind: `u32`, `u16be`, `f32`, …
fn template_type(kind: &str) -> Option<String> {
    let mut words = kind.split_whitespace();
    let _role = words.next()?;
    let ty = words.next()?;
    if !ty.starts_with(['u', 'i', 'f']) || ty.len() < 2 || !ty[1..].chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let suffix = match words.next() {
        Some("BE") => "be",
        _ => "",
    };
    Some(format!("{ty}{suffix}"))
}

/// Escape bytes for a template string literal.
fn escape(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            b'"' => "\\\"".to_string(),
            b'\\' => "\\\\".to_string(),
            0x20..=0x7E => (b as char).to_string(),
            _ => format!("\\x{b:02X}"),
        })
        .collect()
}

/// Template source for one record, in the app's template language.
pub fn to_template(record_len: usize, fields: &[FieldGuess]) -> String {
    let mut lines = vec![
        format!("// Fields guessed from records of {record_len} bytes. Rename them as you learn what they mean."),
        "endian little".to_string(),
        String::new(),
        "struct Record {".to_string(),
    ];
    for field in fields {
        let role = field.kind.split_whitespace().next().unwrap_or("bytes");
        let name = &field.name;
        let declaration = match (role, template_type(&field.kind)) {
            (_, Some(ty)) if field.len <= 8 => format!("{name}: {ty}"),
            ("text", _) => format!("{name}: char[{}]", field.len),
            ("constant", _) => match field.detail.strip_prefix("hex ") {
                Some(hex) => {
                    let bytes: Vec<u8> = (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()).collect();
                    format!("{name}: bytes[{}] = \"{}\"", field.len, escape(&bytes))
                }
                None => match field.detail.strip_prefix("text \"").and_then(|t| t.strip_suffix('"')) {
                    Some(text) => format!("{name}: char[{}] = \"{}\"", field.len, escape(text.as_bytes())),
                    None => format!("{name}: bytes[{}]", field.len),
                },
            },
            _ => format!("{name}: bytes[{}]", field.len),
        };
        lines.push(format!("    {declaration:<40} // {}", field.detail));
    }
    lines.push("}".to_string());
    lines.push(String::new());
    lines.push("root Record[until_end]".to_string());
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_ends_where_its_records_stop_looking_alike() {
        let record_len = 16;
        let mut bytes = Vec::new();
        for i in 0..50u32 {
            bytes.extend_from_slice(&i.to_le_bytes());
            bytes.extend_from_slice(b"TAG:");
            bytes.extend_from_slice(&[0, 0, 0, 0, 1, 2, 3, (i * 7) as u8]);
        }
        let table_bytes = bytes.len();
        bytes.extend_from_slice(&b"log line: temperature 21.5C, link ok\n".repeat(20));
        assert_eq!(table_length(&bytes, record_len, 4096), table_bytes / record_len);
        assert_eq!(table_length(&bytes[..table_bytes], record_len, 4096), 50, "a table that fills the data");
    }
    use crate::templates::Template;

    fn xorshift(state: &mut u32) -> u8 {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        (*state >> 24) as u8
    }

    /// 24-byte records: "REC1", u32 LE counter, u16 LE flags in {1,2,8},
    /// 8 random bytes, 6 ASCII letters.
    fn records(count: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        let mut out = Vec::new();
        for index in 0..count as u32 {
            out.extend_from_slice(b"REC1");
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&[1u16, 2, 8][index as usize % 3].to_le_bytes());
            for _ in 0..8 {
                out.push(xorshift(&mut state));
            }
            for _ in 0..6 {
                out.push(b'a' + xorshift(&mut state) % 26);
            }
        }
        out
    }

    #[test]
    fn columns_are_profiled_by_kind() {
        let bytes = records(300);
        let profiles = profile(&bytes, 24, 4096);
        assert_eq!(profiles.len(), 24);
        let kind = |p: usize| profiles[p].kind;
        assert!((0..4).all(|p| kind(p) == ColumnKind::Constant));
        assert_eq!(kind(4), ColumnKind::Counter);
        assert_eq!(kind(5), ColumnKind::Monotonic, "high byte of a counter that passes 255 rises");
        assert_eq!(kind(8), ColumnKind::LowCardinality);
        assert_eq!(kind(9), ColumnKind::Constant);
        assert!((10..18).all(|p| kind(p) == ColumnKind::Random), "{:?}", (10..18).map(kind).collect::<Vec<_>>());
        assert!((18..24).all(|p| kind(p) == ColumnKind::Text));
        assert_eq!(profiles[8].distinct, 3);
        assert_eq!(profiles[0].most_common, b'R');
    }

    #[test]
    fn columns_group_into_fields_and_a_template() {
        let bytes = records(300);
        let profiles = profile(&bytes, 24, 4096);
        let fields = group_fields(&bytes, 24, &profiles, bytes.len());
        let summary: Vec<(usize, usize, &str)> = fields.iter().map(|f| (f.start, f.len, f.kind.as_str())).collect();
        assert_eq!(
            summary,
            vec![(0, 4, "constant"), (4, 4, "counter u32 LE +1"), (8, 2, "flags u16 LE"), (10, 8, "bytes"), (18, 6, "text")],
            "{fields:?}"
        );
        assert_eq!(fields.iter().map(|f| f.len).sum::<usize>(), 24);

        let source = to_template(24, &fields);
        let template = Template::parse(&source).unwrap_or_else(|e| panic!("{e}\n{source}"));
        let applied = template.apply(&bytes, 0);
        assert_eq!(applied.records.len(), 300, "{:?}", applied.warnings);
        assert_eq!(applied.records[57].value("field_4"), Some("57"), "{source}");
        assert!(applied.warnings.is_empty(), "{:?}", applied.warnings);
    }

    /// Nine-byte remote frames: AA 2D, a 3-byte serial, a button, a
    /// big-endian press counter and a sum. Each press is sent two or three
    /// times.
    fn remote_frames(repeated: bool, highest_first: bool) -> Vec<u8> {
        let mut presses: Vec<(u8, u16)> = [1u8, 4, 1, 2, 1, 1, 2, 4].iter().enumerate().map(|(index, &button)| (button, 0x1234 + index as u16)).collect();
        if highest_first {
            presses.reverse();
        }
        let mut bytes = Vec::new();
        for (index, (button, counter)) in presses.into_iter().enumerate() {
            let mut frame = vec![0xAA, 0x2D, 0x74, 0xB5, 0x27, button];
            frame.extend(counter.to_be_bytes());
            frame.push(frame.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte)));
            let copies = if repeated { 2 + index % 2 } else { 1 };
            for _ in 0..copies {
                bytes.extend(&frame);
            }
        }
        bytes
    }

    fn guessed(bytes: &[u8], record_len: usize) -> Vec<FieldGuess> {
        let profiles = profile(bytes, record_len, 4096);
        group_fields(bytes, record_len, &profiles, bytes.len())
    }

    fn field_at(fields: &[FieldGuess], start: usize) -> &FieldGuess {
        fields.iter().find(|field| field.start == start).unwrap_or_else(|| panic!("no field at {start}: {fields:?}"))
    }

    #[test]
    fn a_counter_sent_several_times_per_press_is_still_one_counter() {
        let fields = guessed(&remote_frames(true, false), 9);
        let counter = field_at(&fields, 6);
        assert_eq!((counter.len, counter.kind.as_str()), (2, "counter u16 BE +1"), "{fields:?}");
    }

    #[test]
    fn a_counter_listed_highest_first_keeps_its_constant_high_byte() {
        let fields = guessed(&remote_frames(false, true), 9);
        let counter = field_at(&fields, 6);
        assert_eq!((counter.len, counter.kind.as_str()), (2, "counter u16 BE -1"), "{fields:?}");
    }

    /// 25-byte telemetry frames of a bus: A5 5A, len, dst, src (three
    /// sensors in turn), seq, type 0x81, a u32 LE Unix time at the odd
    /// offset 7, readings and a CRC.
    fn telemetry() -> Vec<u8> {
        let mut state = 0x2545_F491u32;
        let mut time = 1_760_000_000u32;
        let mut seq = 0u8;
        let mut bytes = Vec::new();
        for cycle in 0..120u32 {
            for src in [0x10u8, 0x11, 0x12] {
                seq = seq.wrapping_add(1 + (cycle % 25 == 0 && src == 0x10) as u8);
                bytes.extend([0xA5, 0x5A, 0x14, 0x01, src, seq, 0x81]);
                bytes.extend(time.to_le_bytes());
                bytes.extend((200 + (xorshift(&mut state) % 50) as u16).to_le_bytes());
                bytes.extend((1013 + (xorshift(&mut state) % 7) as u16).to_le_bytes());
                bytes.extend([xorshift(&mut state) % 4, 0x80 | (xorshift(&mut state) % 2)]);
                bytes.extend([xorshift(&mut state), 0x05, 0, 0, 0, 0, xorshift(&mut state), xorshift(&mut state)]);
            }
            time += [1, 1, 1, 2][cycle as usize % 4];
        }
        bytes
    }

    #[test]
    fn a_unix_time_at_an_odd_offset_is_found() {
        let fields = guessed(&telemetry(), 25);
        let time = field_at(&fields, 7);
        assert_eq!((time.len, time.kind.as_str()), (4, "timestamp u32 LE"), "{fields:?}");
    }

    /// Unlock payloads: an access level, a 4-byte BCD PIN and a 9-byte
    /// technician id, from three tries.
    fn unlock_payloads(pins: [[u8; 4]; 3]) -> Vec<u8> {
        pins.iter()
            .flat_map(|pin| {
                let mut payload = vec![0x03];
                payload.extend(pin);
                payload.extend([0x34, 0x3E, 0x40, 0x51, 0x4C, 0x75, 0x2C, 0x30, 0x91]);
                payload
            })
            .collect()
    }

    #[test]
    fn a_few_records_do_not_make_a_float_or_text_across_a_constant_field() {
        for pins in [[[0x56, 0x79, 0x69, 0x21], [0x12, 0x34, 0x56, 0x78], [0x12, 0x34, 0x46, 0x78]], [[0x10, 0x27, 0x40, 0x33], [0x99, 0x01, 0x52, 0x84], [0x99, 0x01, 0x42, 0x84]]] {
            let fields = guessed(&unlock_payloads(pins), 14);
            let technician = field_at(&fields, 5);
            assert_eq!((technician.len, technician.kind.as_str()), (9, "constant"), "{fields:?}");
            assert!(fields.iter().all(|field| !field.kind.starts_with("float") && field.kind != "text"), "{fields:?}");
        }
    }

    #[test]
    fn a_field_is_named_by_where_it_is_not_by_what_it_is_guessed_to_be() {
        let original = guessed(&unlock_payloads([[0x56, 0x79, 0x69, 0x21], [0x12, 0x34, 0x56, 0x78], [0x12, 0x34, 0x46, 0x78]]), 14);
        let variant = guessed(&records(300), 24);
        assert_eq!(field_at(&original, 5).name, "field_5");
        assert_eq!(field_at(&variant, 4).name, "field_4");
        assert!(to_template(14, &original).contains("    field_5: bytes[9]"), "{}", to_template(14, &original));
    }

    #[test]
    fn degenerate_inputs_do_not_panic() {
        assert!(profile(&[], 0, 10).is_empty());
        assert!(profile(&[1, 2, 3], 8, 10).is_empty());
        let one = profile(&[1, 2, 3, 4], 4, 10);
        assert_eq!(one.len(), 4);
        let fields = group_fields(&[1, 2, 3, 4], 4, &one, 4);
        assert_eq!(fields.iter().map(|f| f.len).sum::<usize>(), 4);
        assert!(group_fields(&[], 0, &[], 0).is_empty());
        let noise: Vec<u8> = { let mut s = 7u32; (0..4096).map(|_| xorshift(&mut s)).collect() };
        for len in [1, 3, 7, 16, 33] {
            let profiles = profile(&noise, len, 4096);
            let fields = group_fields(&noise, len, &profiles, noise.len());
            assert_eq!(fields.iter().map(|f| f.len).sum::<usize>(), len);
            Template::parse(&to_template(len, &fields)).unwrap();
        }
    }
}
