//! Protocol reverse engineering on a byte stream: captures, serial logs or a
//! file of messages.
//!
//! The analysis runs in three steps:
//!
//! 1. **Framing**: find how the stream is cut into messages (a sync word that
//!    starts each one, a delimiter between them, a length prefix, or a fixed
//!    size).
//! 2. **Splitting** with the best framing.
//! 3. **Field analysis**: align the messages at their start and classify the
//!    header positions (constants, message type, sequence number, length,
//!    timestamp) and a trailing checksum.
//!
//! Everything is pure and bounded; no input makes it panic.

use std::collections::HashMap;

use crate::analysis::{scan_periods, shannon_entropy};
use crate::checksums;

/// How a stream is cut into messages. In JSON the kind is named by `kind`
/// and bytes are hex strings.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Framing {
    /// Messages are separated by these bytes (which are not part of them).
    Delimiter {
        #[serde(with = "crate::ops::hex_bytes")]
        #[schemars(with = "String")]
        bytes: Vec<u8>,
    },
    /// A marker that starts every message.
    SyncWord {
        #[serde(with = "crate::ops::hex_bytes")]
        #[schemars(with = "String")]
        bytes: Vec<u8>,
    },
    /// A length field at `offset` gives each message's length:
    /// `message length = field value + adjustment`.
    LengthPrefixed { offset: usize, width: usize, big_endian: bool, adjustment: i64 },
    /// Every message is the same length.
    FixedSize { len: usize },
}

impl Framing {
    pub fn describe(&self) -> String {
        match self {
            Framing::Delimiter { bytes } => format!("messages separated by {}", show_bytes(bytes)),
            Framing::SyncWord { bytes } => format!("messages start with the sync word {}", show_bytes(bytes)),
            Framing::LengthPrefixed { offset, width, big_endian, adjustment } => {
                let adjustment = match adjustment {
                    0 => String::new(),
                    a if *a > 0 => format!(" + {a}"),
                    a => format!(" - {}", a.unsigned_abs()),
                };
                format!(
                    "length-prefixed: u{} {} at offset {offset}, message length = value{adjustment}",
                    width * 8,
                    if *big_endian { "BE" } else { "LE" }
                )
            }
            Framing::FixedSize { len } => format!("fixed-size messages of {len} bytes"),
        }
    }
}

/// Bytes as hex, or quoted when printable.
fn show_bytes(bytes: &[u8]) -> String {
    match bytes {
        b"\r\n" => "CR LF".to_string(),
        b"\n" => "LF".to_string(),
        _ if bytes.iter().all(|b| (0x21..0x7F).contains(b)) => format!("\"{}\"", String::from_utf8_lossy(bytes)),
        _ => bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "),
    }
}

/// A way to frame the stream, with how well it explains it.
#[derive(Clone, Debug, PartialEq)]
pub struct FramingCandidate {
    pub framing: Framing,
    /// Ranking score: coverage weighted by how convincing the evidence is.
    pub score: f64,
    pub messages: usize,
    /// Fraction of the input the framing explains.
    pub coverage: f64,
}

/// One message's place in the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub offset: usize,
    pub len: usize,
}

/// Most bytes examined when detecting framing.
const DETECT_LIMIT: usize = 4 * 1024 * 1024;
/// Most messages a length-prefix chain is followed for while detecting.
const CHAIN_LIMIT: usize = 200_000;
/// Longest plausible message.
const MAX_MESSAGE: usize = 64 * 1024;
/// Fewest messages a framing needs before it counts.
const MIN_MESSAGES: usize = 4;
/// How many times more often than chance a marker must occur.
const DELIMITER_RATIO: f64 = 3.0;
const SYNC_RATIO: f64 = 20.0;

/// Find likely framings, best first.
pub fn detect_framing(bytes: &[u8], max_candidates: usize) -> Vec<FramingCandidate> {
    let sample = &bytes[..bytes.len().min(DETECT_LIMIT)];
    if sample.len() < 16 {
        return Vec::new();
    }
    let mut candidates = Vec::new();
    candidates.extend(delimiter_candidates(sample));
    candidates.extend(sync_candidates(sample));
    candidates.extend(length_candidates(sample));
    candidates.extend(fixed_size_candidate(sample));
    candidates.retain(|c| c.messages >= MIN_MESSAGES && c.score > 0.0);
    candidates.sort_by(|a, b| b.score.total_cmp(&a.score));
    prefer_fixed_size(&mut candidates);
    let mut distinct: Vec<FramingCandidate> = Vec::new();
    for candidate in candidates {
        if !distinct.iter().any(|d| d.framing == candidate.framing) {
            distinct.push(candidate);
        }
        if distinct.len() >= max_candidates {
            break;
        }
    }
    distinct
}

/// When fixed-size framing explains nearly all of the data, it is the
/// simplest explanation: a length-prefix chain that also covers it is a
/// coincidence of header bytes (every fixed record has the same "length"),
/// so the fixed size goes first.
fn prefer_fixed_size(candidates: &mut Vec<FramingCandidate>) {
    const NEAR_COMPLETE: f64 = 0.95;
    let Some(index) = candidates
        .iter()
        .position(|c| matches!(c.framing, Framing::FixedSize { .. }) && c.coverage >= NEAR_COMPLETE)
    else {
        return;
    };
    // Only length-prefix chains are overruled; a delimiter or sync word that
    // explains the data is real structure, not a coincidence.
    let Some(first_chain) = candidates.iter().position(|c| matches!(c.framing, Framing::LengthPrefixed { .. })) else {
        return;
    };
    if first_chain < index {
        let fixed = candidates.remove(index);
        candidates.insert(first_chain, fixed);
    }
}

/// Positions where `needle` occurs, without overlaps.
fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut found = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return found;
    }
    let mut at = 0;
    while at + needle.len() <= haystack.len() {
        if haystack[at..].starts_with(needle) {
            found.push(at);
            at += needle.len();
        } else {
            at += 1;
        }
    }
    found
}

/// How much more often a marker of `len` bytes occurs than in uniform noise.
fn ratio_to_chance(count: usize, sample_len: usize, len: usize) -> f64 {
    let expected = sample_len as f64 / 256f64.powi(len as i32);
    count as f64 / expected.max(1e-9)
}

/// Entropy of the bytes at `position` across messages, normalised to 0..1 by
/// the most a column of that many values could have.
fn normalised_entropy(bytes: &[u8], messages: &[Message], position: usize) -> Option<f64> {
    let values: Vec<u8> = messages.iter().filter(|m| m.len > position).filter_map(|m| bytes.get(m.offset + position).copied()).collect();
    if values.len() < MIN_MESSAGES {
        return None;
    }
    let ideal = (values.len().min(256) as f64).log2();
    Some(if ideal <= 0.0 { 0.0 } else { (shannon_entropy(&values) as f64 / ideal).min(1.0) })
}

/// How structured the start of the messages looks: 1 when some early
/// position is constant, near 0 when every position looks random.
fn header_structure(bytes: &[u8], messages: &[Message], skip: &[usize]) -> f64 {
    let lowest = (0..8)
        .filter(|p| !skip.contains(p))
        .filter_map(|p| normalised_entropy(bytes, messages, p))
        .fold(1.0f64, f64::min);
    1.0 - lowest
}

fn candidate(framing: Framing, messages: &[Message], covered: usize, total: usize, confidence: f64) -> FramingCandidate {
    let coverage = (covered as f64 / total.max(1) as f64).min(1.0);
    FramingCandidate { framing, score: coverage * confidence.clamp(0.0, 1.0), messages: messages.len(), coverage }
}

fn delimiter_candidates(sample: &[u8]) -> Vec<FramingCandidate> {
    let delimiters: [&[u8]; 4] = [b"\r\n", b"\n", b"\0", b"\x7e"];
    let mut found = Vec::new();
    for delimiter in delimiters {
        let positions = occurrences(sample, delimiter);
        if positions.len() < MIN_MESSAGES || ratio_to_chance(positions.len(), sample.len(), delimiter.len()) < DELIMITER_RATIO {
            continue;
        }
        let framing = Framing::Delimiter { bytes: delimiter.to_vec() };
        let messages = split(sample, &framing, CHAIN_LIMIT);
        if messages.len() < MIN_MESSAGES {
            continue;
        }
        let covered = positions.last().map_or(0, |&p| p + delimiter.len());
        let body: usize = messages.iter().map(|m| m.len).sum();
        let printable = messages
            .iter()
            .flat_map(|m| &sample[m.offset..m.offset + m.len])
            .filter(|&&b| (0x20..0x7F).contains(&b) || b == b'\t')
            .count() as f64
            / body.max(1) as f64;
        // Text protocols are convincing when the messages are text; binary
        // ones when their headers have structure.
        let confidence = if printable >= 0.9 { 1.0 } else { 0.6 * header_structure(sample, &messages, &[]) };
        found.push(candidate(framing, &messages, covered, sample.len(), confidence));
    }
    found
}

fn sync_candidates(sample: &[u8]) -> Vec<FramingCandidate> {
    // Count every 1- to 4-byte sequence.
    let mut counts: Vec<(Vec<u8>, usize)> = Vec::new();
    for len in 1..=4usize {
        let mut table: HashMap<&[u8], usize> = HashMap::new();
        for window in sample.windows(len) {
            *table.entry(window).or_insert(0) += 1;
        }
        let threshold = (sample.len() as f64 / 256f64.powi(len as i32) * SYNC_RATIO).max(MIN_MESSAGES as f64);
        let mut frequent: Vec<(Vec<u8>, usize)> = table.into_iter().filter(|&(_, c)| c as f64 >= threshold).map(|(k, c)| (k.to_vec(), c)).collect();
        frequent.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        frequent.truncate(32);
        counts.extend(frequent);
    }
    // A sequence inside a longer frequent one that occurs about as often is
    // just part of that one.
    let keep: Vec<(Vec<u8>, usize)> = counts
        .iter()
        .filter(|(seq, count)| {
            !counts.iter().any(|(other, other_count)| {
                other.len() > seq.len() && other.windows(seq.len()).any(|w| w == seq.as_slice()) && *other_count as f64 >= *count as f64 * 0.9
            })
        })
        .cloned()
        .collect();

    // A marker extended by the byte that follows it (a type field, say) is
    // a special case of the shorter marker, which occurs more often.
    let keep: Vec<(Vec<u8>, usize)> = keep
        .iter()
        .filter(|(seq, count)| {
            !keep.iter().any(|(other, other_count)| other.len() < seq.len() && other.len() >= 2 && seq.starts_with(other) && *other_count as f64 >= *count as f64 * 1.3)
        })
        .cloned()
        .collect();
    let most_frequent = keep.iter().filter(|(seq, _)| seq.len() >= 2).map(|(_, c)| *c).max().unwrap_or(1).max(1);
    let mut found = Vec::new();
    for (sequence, count) in keep {
        if sequence.iter().all(|&b| b == sequence[0]) && sequence.len() > 1 {
            continue; // padding, not a marker
        }
        if [b"\r\n".as_slice(), b"\n"].contains(&sequence.as_slice()) {
            continue; // handled as delimiters
        }
        let framing = Framing::SyncWord { bytes: sequence.clone() };
        let messages = split(sample, &framing, CHAIN_LIMIT);
        if messages.len() < MIN_MESSAGES {
            continue;
        }
        let first = messages[0].offset;
        let covered = sample.len() - first;
        // The byte after the marker is usually a type or version: low entropy.
        let structure = header_structure(sample, &messages, &(0..sequence.len()).collect::<Vec<_>>());
        let lengths: Vec<f64> = messages.iter().map(|m| m.len as f64).collect();
        let mean = lengths.iter().sum::<f64>() / lengths.len() as f64;
        let tiny = messages.iter().filter(|m| m.len <= sequence.len() + 1).count() as f64 / messages.len() as f64;
        let marker_weight = match sequence.len() {
            1 => 0.6,
            2 => 0.9,
            _ => 1.0,
        };
        // The real marker starts every message, so it is the most frequent
        // multi-byte marker; rarer ones only start a few by coincidence.
        let frequency = (count as f64 / most_frequent as f64).min(1.0);
        let confidence = marker_weight * frequency * (0.5 + 0.5 * structure) * (1.0 - tiny) * if mean >= 3.0 { 1.0 } else { 0.3 };
        found.push(candidate(framing, &messages, covered, sample.len(), confidence));
    }
    found
}

/// Read a `width`-byte unsigned integer at `at`, if it fits.
fn read_uint(bytes: &[u8], at: usize, width: usize, big_endian: bool) -> Option<u64> {
    let slice = bytes.get(at..at.checked_add(width)?)?;
    let mut value = 0u64;
    for index in 0..width {
        let byte = if big_endian { slice[index] } else { slice[width - 1 - index] };
        value = (value << 8) | byte as u64;
    }
    Some(value)
}

/// Follow a length-prefix chain from the start. Returns the messages and how
/// far the chain got.
fn chain(bytes: &[u8], offset: usize, width: usize, big_endian: bool, adjustment: i64, limit: usize) -> (Vec<Message>, usize) {
    let mut messages = Vec::new();
    let mut position = 0usize;
    while messages.len() < limit {
        let Some(value) = read_uint(bytes, position + offset, width, big_endian) else { break };
        let len = value as i64 + adjustment;
        if len < (offset + width) as i64 || len as usize > MAX_MESSAGE || position + len as usize > bytes.len() {
            break;
        }
        messages.push(Message { offset: position, len: len as usize });
        position += len as usize;
    }
    (messages, position)
}

fn length_candidates(sample: &[u8]) -> Vec<FramingCandidate> {
    let mut found = Vec::new();
    for offset in 0..8usize {
        for width in [1usize, 2, 4] {
            for big_endian in [true, false] {
                if width == 1 && !big_endian {
                    continue;
                }
                for adjustment in -8i64..=8 {
                    let (messages, reached) = chain(sample, offset, width, big_endian, adjustment, CHAIN_LIMIT);
                    if messages.len() < MIN_MESSAGES || (reached as f64) < sample.len() as f64 * 0.5 {
                        continue;
                    }
                    // Random bytes also chain when every value is a valid
                    // length, so demand structure in the header. The field's
                    // own high byte counts: it is constant in real data.
                    let structure = header_structure(sample, &messages, &[]);
                    if structure < 0.4 {
                        continue;
                    }
                    let framing = Framing::LengthPrefixed { offset, width, big_endian, adjustment };
                    // Prefer simple framings: small offsets and adjustments,
                    // and the wider field when both split the stream alike.
                    let simplicity = 1.0 - (offset as f64 * 0.01) - (adjustment.unsigned_abs() as f64 * 0.005) + width as f64 * 0.001;
                    found.push(candidate(framing, &messages, reached, sample.len(), structure * simplicity));
                }
            }
        }
    }
    found.sort_by(|a, b| b.score.total_cmp(&a.score));
    found.truncate(4);
    found
}

fn fixed_size_candidate(sample: &[u8]) -> Option<FramingCandidate> {
    let window = &sample[..sample.len().min(1024 * 1024)];
    let scan = scan_periods(window, 0, 4096);
    let best = scan.candidates.iter().find(|c| c.multiple_of.is_none())?;
    let (period, column_gain) = smallest_equivalent_period(window, best.period, best.column_gain);
    // With few rows, a column's entropy is capped by the row count, so even
    // noise shows a "gain"; demand clearly more than that.
    let rows = window.len() / period.max(1);
    let bias = 8.0 - (rows.clamp(1, 256) as f32).log2();
    if period < 2 || rows < 16 || column_gain < bias + 0.75 {
        return None;
    }
    let framing = Framing::FixedSize { len: period };
    let messages = split(sample, &framing, CHAIN_LIMIT);
    let covered = messages.len() * period;
    let confidence = (column_gain as f64 / 4.0).min(0.9);
    Some(candidate(framing, &messages, covered, sample.len(), confidence))
}

/// Autocorrelation peaks at every multiple of the true record size. Step down
/// to the smallest divisor of `period` whose records are about as structured
/// (similar column entropy gain), since that is the real record.
fn smallest_equivalent_period(window: &[u8], period: usize, gain: f32) -> (usize, f32) {
    const SIMILAR: f32 = 0.85;
    let corrected = |p: usize, g: f32| g - noise_floor(window.len() / p.max(1));
    let target = corrected(period, gain);
    for divisor in 2..period {
        if !period.is_multiple_of(divisor) {
            continue;
        }
        let divisor_gain = crate::analysis::column_entropy_gain(window, divisor);
        if corrected(divisor, divisor_gain) >= target * SIMILAR {
            return (divisor, divisor_gain);
        }
    }
    (period, gain)
}

/// Apparent entropy gain of random columns with `rows` samples: with fewer
/// than 256 rows a byte column cannot show more than log2(rows) bits, so
/// even noise looks structured by the difference.
fn noise_floor(rows: usize) -> f32 {
    8.0 - (rows.clamp(1, 256) as f32).log2()
}

/// Cut the stream into messages with `framing`.
pub fn split(bytes: &[u8], framing: &Framing, max_messages: usize) -> Vec<Message> {
    let mut messages = Vec::new();
    match framing {
        Framing::Delimiter { bytes: delimiter } => {
            let mut start = 0;
            for at in occurrences(bytes, delimiter) {
                if at > start {
                    messages.push(Message { offset: start, len: at - start });
                }
                start = at + delimiter.len();
                if messages.len() >= max_messages {
                    return messages;
                }
            }
            if start < bytes.len() && messages.len() < max_messages {
                messages.push(Message { offset: start, len: bytes.len() - start });
            }
        }
        Framing::SyncWord { bytes: marker } => {
            let positions = occurrences(bytes, marker);
            for (index, &at) in positions.iter().enumerate().take(max_messages) {
                let end = positions.get(index + 1).copied().unwrap_or(bytes.len());
                messages.push(Message { offset: at, len: end - at });
            }
        }
        Framing::LengthPrefixed { offset, width, big_endian, adjustment } => {
            messages = chain(bytes, *offset, *width, *big_endian, *adjustment, max_messages).0;
        }
        Framing::FixedSize { len } => {
            if *len > 0 {
                messages = (0..bytes.len() / len).take(max_messages).map(|i| Message { offset: i * len, len: *len }).collect();
            }
        }
    }
    messages
}

// ---------------------------------------------------------------------------
// Field analysis
// ---------------------------------------------------------------------------

/// A field found by aligning the messages.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct MessageField {
    /// Offset within the message; counted from the end when `from_end`.
    pub start: usize,
    pub len: usize,
    /// "constant", "message type", "sequence number", "length", "timestamp",
    /// "checksum", "payload" or "variable"; numeric kinds carry their type,
    /// e.g. "length u16 LE".
    pub kind: String,
    pub detail: String,
    /// Distinct example values, up to 8.
    pub values: Vec<String>,
    /// True for a trailer: `start` is then the distance from the message end
    /// to the field's first byte (so a 2-byte checksum has start 2).
    pub from_end: bool,
}

/// Fraction of messages a field pattern must hold for.
const FIELD_AGREEMENT: f64 = 0.9;
const UNIX_MIN: u64 = 946_684_800;
const UNIX_MAX: u64 = 2_208_988_800;

fn holds(count: usize, total: usize) -> bool {
    total > 0 && count as f64 >= total as f64 * FIELD_AGREEMENT
}

/// A header integer's value in each message that is long enough for it.
fn field_values(bytes: &[u8], messages: &[Message], start: usize, width: usize, big_endian: bool) -> Vec<(usize, u64)> {
    messages
        .iter()
        .enumerate()
        .filter(|(_, m)| m.len >= start + width)
        .filter_map(|(i, m)| read_uint(bytes, m.offset + start, width, big_endian).map(|v| (i, v)))
        .collect()
}

fn type_name(width: usize, big_endian: bool) -> String {
    if width == 1 { "u8".to_string() } else { format!("u{} {}", width * 8, if big_endian { "BE" } else { "LE" }) }
}

fn examples(values: impl Iterator<Item = u64>, width: usize) -> Vec<String> {
    let mut seen: Vec<u64> = Vec::new();
    for value in values {
        if !seen.contains(&value) {
            seen.push(value);
        }
        if seen.len() >= 8 {
            break;
        }
    }
    seen.iter().map(|v| format!("{v:#0w$x}", w = width * 2 + 2)).collect()
}

/// A sequence number at `start`: +1 between consecutive messages.
fn sequence_field(bytes: &[u8], messages: &[Message], start: usize) -> Option<MessageField> {
    for width in [4usize, 2, 1] {
        for big_endian in [true, false] {
            if width == 1 && !big_endian {
                continue;
            }
            let values = field_values(bytes, messages, start, width, big_endian);
            if values.len() < MIN_MESSAGES {
                continue;
            }
            let mask = if width == 8 { u64::MAX } else { (1u64 << (width * 8)) - 1 };
            let steps = values.windows(2).filter(|w| w[1].0 == w[0].0 + 1).count();
            let ones = values.windows(2).filter(|w| w[1].0 == w[0].0 + 1 && w[1].1 == (w[0].1 + 1) & mask).count();
            if steps >= MIN_MESSAGES - 1 && holds(ones, steps) {
                return Some(MessageField {
                    start,
                    len: width,
                    kind: format!("sequence number {}", type_name(width, big_endian)),
                    detail: format!("increases by 1 from one message to the next ({} to {})", values[0].1, values[values.len() - 1].1),
                    values: examples(values.iter().map(|v| v.1), width),
                    from_end: false,
                });
            }
        }
    }
    None
}

/// A length at `start`: message length = value + a constant for most messages.
fn length_field(bytes: &[u8], messages: &[Message], start: usize) -> Option<(MessageField, i64)> {
    for width in [4usize, 2, 1] {
        for big_endian in [true, false] {
            if width == 1 && !big_endian {
                continue;
            }
            let values = field_values(bytes, messages, start, width, big_endian);
            if values.len() < MIN_MESSAGES || values.windows(2).all(|w| w[0].1 == w[1].1) {
                continue;
            }
            let mut differences: HashMap<i64, usize> = HashMap::new();
            for &(index, value) in &values {
                *differences.entry(messages[index].len as i64 - value as i64).or_insert(0) += 1;
            }
            let Some((&difference, &count)) = differences.iter().max_by_key(|&(_, c)| *c) else { continue };
            if (0..=64).contains(&difference) && holds(count, values.len()) {
                let detail = if difference == 0 { "the whole message length".to_string() } else { format!("message length = value + {difference}") };
                return Some((
                    MessageField {
                        start,
                        len: width,
                        kind: format!("length {}", type_name(width, big_endian)),
                        detail,
                        values: examples(values.iter().map(|v| v.1), width),
                        from_end: false,
                    },
                    difference,
                ));
            }
        }
    }
    None
}

/// A 4-byte Unix timestamp at `start` that never goes backwards.
fn timestamp_field(bytes: &[u8], messages: &[Message], start: usize) -> Option<MessageField> {
    for big_endian in [true, false] {
        let values = field_values(bytes, messages, start, 4, big_endian);
        if values.len() < MIN_MESSAGES {
            continue;
        }
        let plausible = values.iter().filter(|v| (UNIX_MIN..UNIX_MAX).contains(&v.1)).count();
        let rising = values.windows(2).filter(|w| w[1].1 >= w[0].1).count();
        let varies = values.windows(2).any(|w| w[1].1 != w[0].1);
        if varies && holds(plausible, values.len()) && holds(rising, values.len() - 1) {
            return Some(MessageField {
                start,
                len: 4,
                kind: format!("timestamp {}", type_name(4, big_endian)),
                detail: "Unix seconds that never go backwards".to_string(),
                values: examples(values.iter().map(|v| v.1), 4),
                from_end: false,
            });
        }
    }
    None
}

/// Byte statistics of one position across the messages that have it.
fn position_values(bytes: &[u8], messages: &[Message], position: usize) -> Vec<u8> {
    messages.iter().filter(|m| m.len > position).filter_map(|m| bytes.get(m.offset + position).copied()).collect()
}

/// A checksum algorithm: name, width in bytes, and how to compute it.
type ChecksumAlgorithm = (&'static str, usize, fn(&[u8]) -> u64);

/// The checksum algorithms tried on message trailers.
fn checksum_algorithms() -> Vec<ChecksumAlgorithm> {
    vec![
        ("CRC-32", 4, |b| checksums::crc32(b) as u64),
        ("Adler-32", 4, |b| checksums::adler32(b) as u64),
        ("sum32", 4, |b| checksums::sum32(b) as u64),
        ("CRC-16/CCITT", 2, |b| checksums::crc16_ccitt(b) as u64),
        ("CRC-16/ARC", 2, |b| checksums::crc16_arc(b) as u64),
        ("sum16", 2, |b| checksums::sum16(b) as u64),
        ("sum8", 1, |b| checksums::sum8(b) as u64),
        ("xor8", 1, |b| b.iter().fold(0u8, |acc, x| acc ^ x) as u64),
    ]
}

/// A checksum in the last bytes of each message over the bytes before it.
fn checksum_field(bytes: &[u8], messages: &[Message], body_starts: &[usize]) -> Option<MessageField> {
    let sample: Vec<&Message> = messages.iter().take(2000).collect();
    for (name, width, compute) in checksum_algorithms() {
        for big_endian in [true, false] {
            if width == 1 && !big_endian {
                continue;
            }
            for &body_start in body_starts {
                let usable: Vec<&&Message> = sample.iter().filter(|m| m.len > body_start + width).collect();
                if usable.len() < MIN_MESSAGES {
                    continue;
                }
                let matching = usable
                    .iter()
                    .filter(|m| {
                        let message = &bytes[m.offset..m.offset + m.len];
                        let body = &message[body_start..m.len - width];
                        read_uint(message, m.len - width, width, big_endian) == Some(compute(body))
                    })
                    .count();
                if holds(matching, usable.len()) {
                    let order = if width == 1 { String::new() } else if big_endian { " BE".to_string() } else { " LE".to_string() };
                    return Some(MessageField {
                        start: width,
                        len: width,
                        kind: format!("checksum ({name}{order} over {body_start}..n)"),
                        detail: format!("{name} of the message from byte {body_start} to just before the checksum, in {matching} of {} messages", usable.len()),
                        values: Vec::new(),
                        from_end: true,
                    });
                }
            }
        }
    }
    None
}

/// Classify the first `max_prefix` positions of the messages, plus a trailer.
pub fn analyse_fields(bytes: &[u8], messages: &[Message], max_prefix: usize) -> Vec<MessageField> {
    let messages: Vec<Message> = messages.iter().copied().filter(|m| m.offset.saturating_add(m.len) <= bytes.len()).collect();
    if messages.len() < MIN_MESSAGES {
        return Vec::new();
    }
    let total = messages.len();
    let mut fields: Vec<MessageField> = Vec::new();
    let mut length_found: Option<(usize, i64)> = None;
    let mut position = 0;
    while position < max_prefix {
        let values = position_values(bytes, &messages, position);
        if !holds(values.len(), total) {
            break;
        }
        let distinct: Vec<u8> = {
            let mut d = values.clone();
            d.sort_unstable();
            d.dedup();
            d
        };
        if distinct.len() == 1 {
            merge_or_push(&mut fields, position, "constant", values[0]);
            position += 1;
            continue;
        }
        if let Some(field) = sequence_field(bytes, &messages, position) {
            position += field.len;
            fields.push(field);
            continue;
        }
        if length_found.is_none()
            && let Some((field, difference)) = length_field(bytes, &messages, position)
        {
            length_found = Some((position + field.len, difference));
            position += field.len;
            fields.push(field);
            continue;
        }
        if let Some(field) = timestamp_field(bytes, &messages, position) {
            position += field.len;
            fields.push(field);
            continue;
        }
        if distinct.len() <= 16 && distinct.len() * 4 <= values.len() {
            let mut counts: Vec<(u8, usize)> = distinct.iter().map(|&v| (v, values.iter().filter(|&&x| x == v).count())).collect();
            counts.sort_by_key(|entry| std::cmp::Reverse(entry.1));
            fields.push(MessageField {
                start: position,
                len: 1,
                kind: "message type u8".to_string(),
                detail: format!("{} distinct values: {}", counts.len(), counts.iter().map(|(v, c)| format!("{v:#04x}×{c}")).collect::<Vec<_>>().join(", ")),
                values: counts.iter().take(8).map(|(v, _)| format!("{v:#04x}")).collect(),
                from_end: false,
            });
            position += 1;
            continue;
        }
        // Past the recognisable header: with a length field, the rest is payload.
        if length_found.is_some() {
            fields.push(MessageField {
                start: position,
                len: 0,
                kind: "payload".to_string(),
                detail: "variable length, given by the length field".to_string(),
                values: Vec::new(),
                from_end: false,
            });
            break;
        }
        merge_or_push(&mut fields, position, "variable", values[0]);
        position += 1;
    }

    let mut body_starts: Vec<usize> = vec![0, 1, 2, 3, 4];
    if let Some(first_variable) = fields.iter().find(|f| f.kind != "constant").map(|f| f.start) {
        body_starts.push(first_variable);
    }
    if let Some((after_length, _)) = length_found {
        body_starts.push(after_length);
    }
    body_starts.sort_unstable();
    body_starts.dedup();
    if let Some(field) = checksum_field(bytes, &messages, &body_starts) {
        fields.push(field);
    }
    fields
}

/// Extend the previous field of the same kind, or start one.
fn merge_or_push(fields: &mut Vec<MessageField>, position: usize, kind: &str, value: u8) {
    if let Some(last) = fields.last_mut()
        && last.kind == kind
        && last.start + last.len == position
    {
        last.len += 1;
        if kind == "constant" {
            last.values[0].push_str(&format!("{value:02x}"));
            last.detail = format!("always {}", last.values[0]);
        }
        return;
    }
    let (detail, values) = if kind == "constant" {
        (format!("always {value:02x}"), vec![format!("{value:02x}")])
    } else {
        ("varies between messages".to_string(), Vec::new())
    };
    fields.push(MessageField { start: position, len: 1, kind: kind.to_string(), detail, values, from_end: false });
}

// ---------------------------------------------------------------------------
// Whole report
// ---------------------------------------------------------------------------

/// Everything learned about a stream.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProtocolReport {
    pub framing: Option<FramingCandidate>,
    pub messages: Vec<Message>,
    pub fields: Vec<MessageField>,
    pub length_min: usize,
    pub length_max: usize,
    pub length_mean: f64,
    /// Messages per value of the message type field, if one was found.
    pub type_counts: Vec<(String, usize)>,
}

/// Most messages split out by `analyse`.
const MAX_MESSAGES: usize = 100_000;
/// Header positions examined by `analyse`.
const HEADER_POSITIONS: usize = 32;

/// Detect framing, split, and analyse the fields.
pub fn analyse(bytes: &[u8]) -> ProtocolReport {
    let Some(best) = detect_framing(bytes, 1).into_iter().next() else {
        return ProtocolReport::default();
    };
    let messages = split(bytes, &best.framing, MAX_MESSAGES);
    let fields = analyse_fields(bytes, &messages, HEADER_POSITIONS);
    let lengths = messages.iter().map(|m| m.len);
    let type_counts = fields
        .iter()
        .find(|f| f.kind.starts_with("message type"))
        .map(|field| {
            let mut counts: HashMap<u8, usize> = HashMap::new();
            for message in &messages {
                if message.len > field.start {
                    *counts.entry(bytes[message.offset + field.start]).or_insert(0) += 1;
                }
            }
            let mut counts: Vec<(String, usize)> = counts.into_iter().map(|(v, c)| (format!("{v:#04x}"), c)).collect();
            counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            counts
        })
        .unwrap_or_default();
    ProtocolReport {
        length_min: lengths.clone().min().unwrap_or(0),
        length_max: lengths.clone().max().unwrap_or(0),
        length_mean: if messages.is_empty() { 0.0 } else { lengths.sum::<usize>() as f64 / messages.len() as f64 },
        framing: Some(best),
        messages,
        fields,
        type_counts,
    }
}

/// The template type for a numeric field kind, e.g. "u16be".
fn template_type(kind: &str) -> Option<String> {
    let words: Vec<&str> = kind.split_whitespace().collect();
    let ty = words.iter().find(|w| w.starts_with('u') && w[1..].chars().all(|c| c.is_ascii_digit()) && w.len() > 1)?;
    let suffix = match words.iter().find(|w| **w == "BE" || **w == "LE") {
        Some(&"BE") => "be",
        Some(_) => "le",
        None => "",
    };
    Some(format!("{ty}{suffix}"))
}

/// A template for one message, if the layout is known well enough.
pub fn to_template(report: &ProtocolReport) -> Option<String> {
    if report.messages.is_empty() || report.fields.is_empty() {
        return None;
    }
    let fixed_len = matches!(report.framing.as_ref().map(|f| &f.framing), Some(Framing::FixedSize { .. })) || report.length_min == report.length_max;
    let header: Vec<&MessageField> = report.fields.iter().filter(|f| !f.from_end).collect();
    let trailer = report.fields.iter().find(|f| f.from_end);
    let trailer_len = trailer.map_or(0, |t| t.len);
    let length = header.iter().find(|f| f.kind.starts_with("length"));
    let mut lines = vec![
        "// Inferred from the message stream. Rename fields as you learn what they mean.".to_string(),
        "struct Message {".to_string(),
    ];
    let mut header_len = 0;
    for field in &header {
        if field.kind == "payload" {
            break;
        }
        let role = field.kind.split_whitespace().next().unwrap_or("field");
        let name = match role {
            "message" => "message_type".to_string(),
            "sequence" => "sequence".to_string(),
            other => format!("{other}_{}", field.start),
        };
        let declaration = match template_type(&field.kind) {
            Some(ty) if field.len <= 8 => format!("{name}: {ty}"),
            _ if field.kind == "constant" => {
                let hex = field.values.first().cloned().unwrap_or_default();
                let escaped: String = (0..hex.len() / 2).map(|i| format!("\\x{}", &hex[i * 2..i * 2 + 2])).collect();
                format!("{name}: bytes[{}] = \"{escaped}\"", field.len)
            }
            _ => format!("{name}: bytes[{}]", field.len),
        };
        lines.push(format!("    {declaration:<36} // {}", field.detail));
        header_len = field.start + field.len;
    }
    let payload = if let Some(length) = length {
        let role_name = format!("length_{}", length.start);
        let difference: i64 = length.detail.strip_prefix("message length = value + ").and_then(|d| d.parse().ok()).unwrap_or(0);
        let extra = difference - header_len as i64 - trailer_len as i64;
        match extra.cmp(&0) {
            std::cmp::Ordering::Equal => format!("bytes[{role_name}]"),
            std::cmp::Ordering::Greater => format!("bytes[{role_name} + {extra}]"),
            std::cmp::Ordering::Less => format!("bytes[{role_name} - {}]", extra.unsigned_abs()),
        }
    } else if fixed_len {
        format!("bytes[{}]", report.length_min.saturating_sub(header_len + trailer_len))
    } else {
        return None;
    };
    lines.push(format!("    {:<36} // the rest of the message", format!("payload: {payload}")));
    if let Some(trailer) = trailer {
        let algorithm_order = if trailer.kind.contains(" BE ") { "be" } else if trailer.kind.contains(" LE ") { "le" } else { "" };
        lines.push(format!("    {:<36} // {}", format!("checksum: u{}{algorithm_order}", trailer.len * 8), trailer.detail));
    }
    lines.push("}".to_string());
    lines.push(String::new());
    lines.push("root Message[until_end]".to_string());
    Some(lines.join("\n") + "\n")
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

    /// AA 55 | type u8 | seq u16 BE | payload length u16 LE | payload | CRC-16/CCITT BE over type..payload.
    fn binary_stream(count: usize) -> Vec<u8> {
        let mut state = 0xC0FF_EE11u32;
        let mut out = Vec::new();
        for sequence in 0..count as u16 {
            let kind = [1u8, 2, 3][(xorshift(&mut state) % 3) as usize];
            let payload_len = 4 + (xorshift(&mut state) as usize % 37);
            let mut body = vec![kind];
            body.extend_from_slice(&sequence.to_be_bytes());
            body.extend_from_slice(&(payload_len as u16).to_le_bytes());
            for _ in 0..payload_len {
                body.push(xorshift(&mut state));
            }
            let crc = checksums::crc16_ccitt(&body);
            out.extend_from_slice(&[0xAA, 0x55]);
            out.extend_from_slice(&body);
            out.extend_from_slice(&crc.to_be_bytes());
        }
        out
    }

    #[test]
    fn fixed_size_records_beat_coincidental_length_chains() {
        // 24-byte records whose first byte is constant: a length prefix of
        // "value - k" chains across them too, but fixed size is the answer.
        let mut state = 0x1234_5678u32;
        let mut stream = Vec::new();
        for index in 0..400u32 {
            stream.push(30u8);
            stream.extend_from_slice(&index.to_le_bytes());
            for _ in 0..19 {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                stream.push((state >> 24) as u8);
            }
        }
        let candidates = detect_framing(&stream, 6);
        assert_eq!(candidates.first().map(|c| c.framing.clone()), Some(Framing::FixedSize { len: 24 }), "{:?}", candidates.iter().map(|c| c.framing.describe()).collect::<Vec<_>>());
    }

    #[test]
    fn binary_protocol_framing_and_fields_are_found() {
        let stream = binary_stream(600);
        let candidates = detect_framing(&stream, 5);
        let best = candidates.first().expect("a framing");
        assert!(
            matches!(&best.framing, Framing::SyncWord { bytes } if bytes == &[0xAA, 0x55]) || matches!(best.framing, Framing::LengthPrefixed { .. }),
            "{candidates:?}"
        );
        assert!(best.coverage > 0.95, "{best:?}");

        let report = analyse(&stream);
        assert_eq!(report.messages.len(), 600);
        let kinds: Vec<&str> = report.fields.iter().map(|f| f.kind.as_str()).collect();
        let field = |prefix: &str| report.fields.iter().find(|f| f.kind.starts_with(prefix)).unwrap_or_else(|| panic!("{prefix} in {kinds:?}"));
        assert_eq!(field("constant").start, 0);
        let kind = field("message type");
        assert_eq!((kind.start, kind.values.len()), (2, 3));
        let sequence = field("sequence number");
        assert_eq!((sequence.start, sequence.len, sequence.kind.as_str()), (3, 2, "sequence number u16 BE"));
        let length = field("length");
        assert_eq!((length.start, length.len, length.kind.as_str()), (5, 2, "length u16 LE"));
        let checksum = field("checksum");
        assert!(checksum.from_end && checksum.len == 2 && checksum.kind.contains("CRC-16/CCITT BE over 2..n"), "{checksum:?}");
        assert_eq!(report.type_counts.len(), 3);
        assert_eq!(report.type_counts.iter().map(|t| t.1).sum::<usize>(), 600);

        let source = to_template(&report).expect("a template");
        let template = Template::parse(&source).unwrap_or_else(|e| panic!("{e}\n{source}"));
        let applied = template.apply(&stream, 0);
        assert_eq!(applied.records.len(), 600, "{:?}\n{source}", applied.warnings.iter().take(3).collect::<Vec<_>>());
        assert_eq!(applied.records[42].value("sequence"), Some("42"), "{source}");
    }

    #[test]
    fn text_lines_frame_on_crlf() {
        let mut stream = Vec::new();
        for i in 0..200 {
            let body = format!("GPGGA,{:06},{:.4},N,{:.4},W,1,08", 120000 + i, 4807.038 + i as f64 * 0.01, 1131.0 + i as f64 * 0.02);
            let checksum = body.bytes().fold(0u8, |a, b| a ^ b);
            stream.extend_from_slice(format!("${body}*{checksum:02X}\r\n").as_bytes());
        }
        let candidates = detect_framing(&stream, 5);
        let best = candidates.first().expect("a framing");
        assert_eq!(best.framing, Framing::Delimiter { bytes: b"\r\n".to_vec() }, "{candidates:?}");
        assert!((best.coverage - 1.0).abs() < 1e-9);
        let messages = split(&stream, &best.framing, 1000);
        assert_eq!(messages.len(), 200);
        assert_eq!(&stream[messages[0].offset..messages[0].offset + 6], b"$GPGGA");
        assert!(!stream[messages[0].offset..messages[0].offset + messages[0].len].ends_with(b"\r"));
    }

    #[test]
    fn length_prefixed_messages_without_a_sync_word() {
        let mut state = 0x5151_5151u32;
        let mut stream = Vec::new();
        for _ in 0..300 {
            let payload_len = 3 + xorshift(&mut state) as usize % 60;
            let total = (payload_len + 2) as u16;
            stream.extend_from_slice(&total.to_be_bytes());
            for _ in 0..payload_len {
                stream.push(xorshift(&mut state));
            }
        }
        let candidates = detect_framing(&stream, 5);
        let best = candidates.first().expect("a framing");
        assert_eq!(best.framing, Framing::LengthPrefixed { offset: 0, width: 2, big_endian: true, adjustment: 0 }, "{candidates:?}");
        assert!((best.coverage - 1.0).abs() < 1e-9);
        assert_eq!(split(&stream, &best.framing, 1000).len(), 300);
    }

    #[test]
    fn noise_has_no_convincing_framing() {
        let mut state = 0x2545_F491u32;
        let noise: Vec<u8> = (0..256 * 1024).map(|_| xorshift(&mut state)).collect();
        let candidates = detect_framing(&noise, 10);
        assert!(candidates.iter().all(|c| c.coverage <= 0.5), "{candidates:?}");
        let report = analyse(&noise);
        assert!(report.framing.is_none() || report.framing.as_ref().is_some_and(|f| f.coverage <= 0.5));
    }

    #[test]
    fn degenerate_inputs_do_not_panic() {
        assert!(detect_framing(&[], 5).is_empty());
        assert!(detect_framing(&[0xAA; 3], 5).is_empty());
        assert_eq!(analyse(&[]), ProtocolReport::default());
        assert!(analyse_fields(&[1, 2, 3], &[Message { offset: 2, len: 100 }], 32).is_empty());
        assert!(split(&[1, 2, 3], &Framing::FixedSize { len: 0 }, 10).is_empty());
        let zeros = vec![0u8; 4096];
        let _ = analyse(&zeros);
        let _ = to_template(&analyse(&zeros));
    }
}
