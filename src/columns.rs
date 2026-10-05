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

fn profile_column(values: &[u8], position: usize) -> ColumnProfile {
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

/// Classify a multi-byte integer field, if it has a recognisable role.
fn integer_role(values: &[u64], width: usize, big_endian: bool, records: usize, document_len: usize) -> Option<(String, String)> {
    let pairs = values.len().saturating_sub(1);
    if pairs == 0 || values.windows(2).all(|w| w[0] == w[1]) {
        return None;
    }
    let ty = format!("u{} {}", width * 8, endian_label(big_endian));
    let step = values[1].wrapping_sub(values[0]) as i64;
    let constant_step = values.windows(2).filter(|w| w[1].wrapping_sub(w[0]) as i64 == step).count();
    if step != 0 && step.unsigned_abs() <= 1 << 20 && holds_for(pairs, constant_step) {
        return Some((format!("counter {ty} {step:+}"), format!("changes by {step:+} every record")));
    }
    let rising = values.windows(2).filter(|w| w[1] >= w[0]).count();
    if holds_for(pairs, rising) && values.windows(2).filter(|w| w[1] > w[0]).count() * 2 >= pairs {
        if width == 4 && values.iter().all(|v| (UNIX_MIN..UNIX_MAX).contains(v)) {
            return Some((format!("timestamp {ty}"), "increasing values that read as Unix times".to_string()));
        }
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

fn plausible_float(bits: u32) -> bool {
    let value = f32::from_bits(bits);
    value == 0.0 || (value.is_finite() && (1e-6..=1e9).contains(&value.abs()))
}

/// Merge columns into fields covering the record exactly once, in order.
pub fn group_fields(bytes: &[u8], record_len: usize, profiles: &[ColumnProfile], document_len: usize) -> Vec<FieldGuess> {
    let records = record_count(bytes, record_len, MAX_GROUPED_RECORDS);
    if records < 2 || profiles.len() != record_len {
        return if record_len == 0 {
            Vec::new()
        } else {
            vec![FieldGuess { start: 0, len: record_len, kind: "bytes".to_string(), detail: "too few records to analyse".to_string() }]
        };
    }
    let kind_at = |p: usize| profiles[p].kind;
    let mut fields: Vec<FieldGuess> = Vec::new();
    let mut position = 0;
    while position < record_len {
        if let Some(field) = integer_field(bytes, record_len, records, position, document_len, kind_at(position)) {
            position += field.len;
            fields.push(field);
            continue;
        }
        if let Some(field) = float_field(bytes, record_len, records, position) {
            position += field.len;
            fields.push(field);
            continue;
        }
        if kind_at(position) == ColumnKind::Text {
            let end = (position..record_len).find(|&p| kind_at(p) != ColumnKind::Text).unwrap_or(record_len);
            if end - position >= 2 {
                fields.push(FieldGuess { start: position, len: end - position, kind: "text".to_string(), detail: "printable text that varies".to_string() });
                position = end;
                continue;
            }
        }
        if let Some(field) = flags_field(record_len, position, &kind_at) {
            position += field.len;
            fields.push(field);
            continue;
        }
        if kind_at(position) == ColumnKind::Constant {
            let end = (position..record_len).find(|&p| kind_at(p) != ColumnKind::Constant).unwrap_or(record_len);
            let value = &bytes[position..end];
            let detail = if value.iter().all(|b| (0x20..0x7F).contains(b)) && value.len() >= 2 {
                format!("text \"{}\"", String::from_utf8_lossy(value))
            } else {
                format!("hex {}", value.iter().map(|b| format!("{b:02x}")).collect::<String>())
            };
            fields.push(FieldGuess { start: position, len: end - position, kind: "constant".to_string(), detail });
            position = end;
            continue;
        }
        push_bytes(&mut fields, position);
        position += 1;
    }
    fields
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
    fields.push(FieldGuess { start: position, len: 1, kind: "bytes".to_string(), detail: "no pattern found".to_string() });
}

fn integer_field(bytes: &[u8], record_len: usize, records: usize, position: usize, document_len: usize, kind: ColumnKind) -> Option<FieldGuess> {
    if kind == ColumnKind::Constant || kind == ColumnKind::Text {
        return None;
    }
    for width in [4usize, 8, 2] {
        if !position.is_multiple_of(width) || position + width > record_len {
            continue;
        }
        for big_endian in [false, true] {
            if high_half_suspicious(bytes, record_len, records, position, width, big_endian) {
                continue;
            }
            let values = integers(bytes, record_len, records, position, width, big_endian);
            if let Some((kind, detail)) = integer_role(&values, width, big_endian, records, document_len) {
                return Some(FieldGuess { start: position, len: width, kind, detail });
            }
        }
    }
    // A single byte that counts.
    if kind == ColumnKind::Counter {
        let values = integers(bytes, record_len, records, position, 1, false);
        let step = values[1].wrapping_sub(values[0]) as u8 as i8;
        return Some(FieldGuess { start: position, len: 1, kind: format!("counter u8 LE {step:+}"), detail: format!("changes by {step:+} every record") });
    }
    None
}

fn float_field(bytes: &[u8], record_len: usize, records: usize, position: usize) -> Option<FieldGuess> {
    if !position.is_multiple_of(4) || position + 4 > record_len {
        return None;
    }
    for big_endian in [false, true] {
        let values = integers(bytes, record_len, records, position, 4, big_endian);
        let varies = values.windows(2).any(|w| w[0] != w[1]);
        let zeros = values.iter().filter(|&&v| v == 0).count();
        if varies && zeros * 2 < values.len() && values.iter().all(|&v| plausible_float(v as u32)) {
            return Some(FieldGuess {
                start: position,
                len: 4,
                kind: format!("float f32 {}", endian_label(big_endian)),
                detail: "a sensible floating-point value in every record".to_string(),
            });
        }
    }
    None
}

fn flags_field(record_len: usize, position: usize, kind_at: &dyn Fn(usize) -> ColumnKind) -> Option<FieldGuess> {
    let low = |p: usize| kind_at(p) == ColumnKind::LowCardinality;
    let constant = |p: usize| kind_at(p) == ColumnKind::Constant;
    if position.is_multiple_of(2) && position + 2 <= record_len {
        let (a, b) = (position, position + 1);
        if (low(a) && (low(b) || constant(b))) || (constant(a) && low(b)) {
            let big_endian = constant(a) && low(b);
            return Some(FieldGuess {
                start: position,
                len: 2,
                kind: format!("flags u16 {}", endian_label(big_endian)),
                detail: "only a few distinct values, like flags or a type".to_string(),
            });
        }
    }
    low(position).then(|| FieldGuess { start: position, len: 1, kind: "flags u8".to_string(), detail: "only a few distinct values, like flags or a type".to_string() })
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
        let name = format!("{role}_{}", field.start);
        let declaration = match (role, template_type(&field.kind)) {
            (_, Some(ty)) if field.len <= 8 => format!("{name}: {ty}"),
            ("text", _) => format!("{name}: char[{}]", field.len),
            ("constant", _) => match field.detail.strip_prefix("hex ") {
                Some(hex) => {
                    let bytes: Vec<u8> = (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()).collect();
                    format!("{name}: bytes[{}] = \"{}\"", field.len, escape(&bytes))
                }
                None => match field.detail.strip_prefix("text \"").and_then(|t| t.strip_suffix('"')) {
                    Some(text) => format!("magic_{}: char[{}] = \"{}\"", field.start, field.len, escape(text.as_bytes())),
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
        assert_eq!(applied.records[57].value("counter_4"), Some("57"), "{source}");
        assert!(applied.warnings.is_empty(), "{:?}", applied.warnings);
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
