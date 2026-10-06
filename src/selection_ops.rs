//! Byte operations on any selection: one range, a column of every record, or
//! several ranges.
//!
//! Each operation is defined on the bytes of one selected range (with the
//! range's index, so a counter can number records). [`rebuild_span`] applies
//! it to every range inside a span of the document read in one piece, which
//! the app then writes back as one edit, so the whole operation is one undo
//! step however many ranges it touched. Everything here is pure: no document,
//! no UI.

use crate::compress::{self, Codec};
use crate::ops;

/// Most bytes a counter value is written across.
const MAX_COUNTER_BYTES: usize = 8;
/// Largest output a decompression of one range may produce.
const DECOMPRESS_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;

/// Byte ranges as `(start, len)`.
pub type Ranges = Vec<(usize, usize)>;

/// Something done to each selected range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Remove the bytes.
    Delete,
    /// Insert bytes before each range.
    InsertBefore(Vec<u8>),
    /// Insert bytes after each range.
    InsertAfter(Vec<u8>),
    /// Repeat a pattern over the bytes.
    Fill(Vec<u8>),
    /// Flip every bit.
    Invert,
    /// XOR with a key, repeated from the start of each range.
    Xor(Vec<u8>),
    /// Add a key byte by byte, wrapping, repeated from the start of each range.
    Add(Vec<u8>),
    /// Subtract a key byte by byte, wrapping.
    Subtract(Vec<u8>),
    /// Reverse the order of the bytes.
    Reverse,
    /// Reverse the bits within each byte.
    MirrorBits,
    /// Shift the range's bits; positive moves them towards the start.
    /// Vacated bits become zero.
    ShiftBits(i64),
    /// Rotate the range's bits; positive moves them towards the start and
    /// the bits shifted out come back in at the other end.
    RotateBits(i64),
    /// Reverse each group of this many bytes (2, 4 or 8): swap the byte
    /// order of the numbers in the range.
    SwapByteOrder(usize),
    /// Write `start + step × index` into each range, numbering records.
    Counter { start: u64, step: u64, little_endian: bool },
    /// Follow each range with a copy of itself.
    Duplicate,
    /// Replace each range with its compressed form.
    Compress(Codec),
    /// Replace each range with its decompressed contents.
    Decompress,
}

impl Operation {
    /// What the operation is called in the status bar and menus.
    pub fn label(&self) -> String {
        match self {
            Operation::Delete => "Deleted".to_string(),
            Operation::InsertBefore(bytes) => format!("Inserted {} bytes before", bytes.len()),
            Operation::InsertAfter(bytes) => format!("Inserted {} bytes after", bytes.len()),
            Operation::Fill(_) => "Filled".to_string(),
            Operation::Invert => "Inverted".to_string(),
            Operation::Xor(_) => "XORed".to_string(),
            Operation::Add(_) => "Added the key to".to_string(),
            Operation::Subtract(_) => "Subtracted the key from".to_string(),
            Operation::Reverse => "Reversed bytes".to_string(),
            Operation::MirrorBits => "Mirrored bits".to_string(),
            Operation::ShiftBits(amount) => format!("Shifted bits by {amount}"),
            Operation::RotateBits(amount) => format!("Rotated bits by {amount}"),
            Operation::SwapByteOrder(width) => format!("Swapped the byte order of {width}-byte values in"),
            Operation::Counter { .. } => "Numbered".to_string(),
            Operation::Duplicate => "Duplicated".to_string(),
            Operation::Compress(codec) => format!("Compressed with {}", codec.label()),
            Operation::Decompress => "Decompressed".to_string(),
        }
    }

    /// Whether each range keeps its length, so a column stays a column.
    pub fn keeps_length(&self) -> bool {
        !matches!(
            self,
            Operation::Delete
                | Operation::InsertBefore(_)
                | Operation::InsertAfter(_)
                | Operation::Duplicate
                | Operation::Compress(_)
                | Operation::Decompress
        )
    }
}

/// The new bytes for one selected range. `index` counts the ranges from the
/// first, so a counter numbers records.
pub fn transform_range(operation: &Operation, bytes: &[u8], index: usize) -> Result<Vec<u8>, String> {
    let mut out = bytes.to_vec();
    match operation {
        Operation::Delete => out.clear(),
        Operation::InsertBefore(insert) => out = [insert.as_slice(), bytes].concat(),
        Operation::InsertAfter(insert) => out.extend_from_slice(insert),
        Operation::Fill(pattern) => fill(&mut out, pattern)?,
        Operation::Invert => ops::invert_bits(&mut out),
        Operation::Xor(key) => combine_with_key(&mut out, key, |byte, key| byte ^ key)?,
        Operation::Add(key) => combine_with_key(&mut out, key, u8::wrapping_add)?,
        Operation::Subtract(key) => combine_with_key(&mut out, key, u8::wrapping_sub)?,
        Operation::Reverse => out.reverse(),
        Operation::MirrorBits => ops::reverse_bits_in_bytes(&mut out),
        Operation::ShiftBits(amount) => out = ops::shift_bits(bytes, *amount),
        Operation::RotateBits(amount) => out = rotate_bits(bytes, *amount),
        Operation::SwapByteOrder(width) => swap_byte_order(&mut out, *width)?,
        Operation::Counter { start, step, little_endian } => {
            let value = start.wrapping_add(step.wrapping_mul(index as u64));
            write_counter(&mut out, value, *little_endian);
        }
        Operation::Duplicate => out.extend_from_slice(bytes),
        Operation::Compress(codec) => out = compress::compress(*codec, bytes)?,
        Operation::Decompress => {
            let decoded = compress::probe(bytes, DECOMPRESS_OUTPUT_LIMIT).into_iter().next();
            out = decoded.ok_or_else(|| "The selected bytes do not decompress with any known codec".to_string())?.data;
        }
    }
    Ok(out)
}

/// Apply `operation` to every range in `span`, which holds the document's
/// bytes from `span_start`. `ranges` must be sorted, not overlapping and
/// inside the span. Returns the new span and where each range's new bytes
/// sit in the document.
pub fn rebuild_span(span: &[u8], span_start: usize, ranges: &[(usize, usize)], operation: &Operation) -> Result<(Vec<u8>, Ranges), String> {
    let mut out = Vec::with_capacity(span.len());
    let mut new_ranges = Vec::with_capacity(ranges.len());
    let mut copied_to = 0;
    for (index, &(start, len)) in ranges.iter().enumerate() {
        let relative = start.checked_sub(span_start).filter(|&at| at >= copied_to && at + len <= span.len()).ok_or_else(|| {
            format!("Range {start:#x}+{len} is outside the bytes read ({span_start:#x}+{}) or overlaps another", span.len())
        })?;
        out.extend_from_slice(&span[copied_to..relative]);
        let replaced = transform_range(operation, &span[relative..relative + len], index)?;
        new_ranges.push((span_start + out.len(), replaced.len()));
        out.extend_from_slice(&replaced);
        copied_to = relative + len;
    }
    out.extend_from_slice(&span[copied_to..]);
    Ok((out, new_ranges))
}

/// Where bytes moved to `cursor` land once `ranges` have been cut out: the
/// cursor shifted back by the bytes removed before it (a cursor inside a
/// range goes to that range's start).
pub fn moved_destination(cursor: usize, ranges: &[(usize, usize)]) -> usize {
    let mut removed_before = 0;
    for &(start, len) in ranges {
        if start + len <= cursor {
            removed_before += len;
        } else if start < cursor {
            return start - removed_before;
        }
    }
    cursor - removed_before
}

fn fill(out: &mut [u8], pattern: &[u8]) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("Fill needs at least one byte of pattern".to_string());
    }
    for (slot, &byte) in out.iter_mut().zip(pattern.iter().cycle()) {
        *slot = byte;
    }
    Ok(())
}

fn combine_with_key(out: &mut [u8], key: &[u8], combine: impl Fn(u8, u8) -> u8) -> Result<(), String> {
    if key.is_empty() {
        return Err("Type the key as hex bytes first, e.g. 5A or DEADBEEF".to_string());
    }
    for (slot, &key_byte) in out.iter_mut().zip(key.iter().cycle()) {
        *slot = combine(*slot, key_byte);
    }
    Ok(())
}

/// Rotate the bit stream of `bytes` by `amount` bits towards the start.
fn rotate_bits(bytes: &[u8], amount: i64) -> Vec<u8> {
    let total_bits = bytes.len() * 8;
    if total_bits == 0 {
        return Vec::new();
    }
    let shift = amount.rem_euclid(total_bits as i64) as usize;
    let bit = |index: usize| (bytes[index / 8] >> (7 - index % 8)) & 1;
    let mut out = vec![0u8; bytes.len()];
    for index in 0..total_bits {
        out[index / 8] |= bit((index + shift) % total_bits) << (7 - index % 8);
    }
    out
}

fn swap_byte_order(out: &mut [u8], width: usize) -> Result<(), String> {
    if !matches!(width, 2 | 4 | 8) {
        return Err(format!("Byte order can be swapped in groups of 2, 4 or 8 bytes, not {width}"));
    }
    for group in out.chunks_exact_mut(width) {
        group.reverse();
    }
    Ok(())
}

/// Write `value` across the range: its low bytes first from the start when
/// little endian, or its low bytes last at the end when big endian. Ranges
/// longer than eight bytes keep their other bytes.
fn write_counter(out: &mut [u8], value: u64, little_endian: bool) {
    let width = out.len().min(MAX_COUNTER_BYTES);
    if little_endian {
        out[..width].copy_from_slice(&value.to_le_bytes()[..width]);
    } else {
        let end = out.len();
        out[end - width..].copy_from_slice(&value.to_be_bytes()[MAX_COUNTER_BYTES - width..]);
    }
}

// ---------------------------------------------------------------------------
// Copying as text
// ---------------------------------------------------------------------------

/// Text forms the selected bytes can be copied as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyFormat {
    Hex,
    CArray,
    Base64,
}

impl CopyFormat {
    pub const ALL: [CopyFormat; 3] = [CopyFormat::Hex, CopyFormat::CArray, CopyFormat::Base64];

    pub fn label(self) -> &'static str {
        match self {
            CopyFormat::Hex => "Copy as hex",
            CopyFormat::CArray => "Copy as C array",
            CopyFormat::Base64 => "Copy as Base64",
        }
    }

    /// `bytes` written in this form.
    pub fn render(self, bytes: &[u8]) -> String {
        match self {
            CopyFormat::Hex => ops::to_hex_string(bytes),
            CopyFormat::CArray => c_array(bytes),
            CopyFormat::Base64 => base64(bytes),
        }
    }
}

/// A C array declaration, twelve bytes to a line.
fn c_array(bytes: &[u8]) -> String {
    const PER_LINE: usize = 12;
    let lines: Vec<String> = bytes
        .chunks(PER_LINE)
        .map(|line| format!("    {},", line.iter().map(|byte| format!("0x{byte:02x}")).collect::<Vec<_>>().join(", ")))
        .collect();
    format!("const unsigned char data[{}] = {{\n{}\n}};", bytes.len(), lines.join("\n"))
}

/// Standard Base64 with padding.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let bits = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        for position in 0..4 {
            if position <= chunk.len() {
                text.push(ALPHABET[(bits >> (18 - 6 * position) & 0x3F) as usize] as char);
            } else {
                text.push('=');
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(operation: Operation, bytes: &[u8]) -> Vec<u8> {
        transform_range(&operation, bytes, 0).unwrap()
    }

    #[test]
    fn delete_removes_and_insertions_add_around_the_range() {
        assert_eq!(apply(Operation::Delete, b"abc"), b"");
        assert_eq!(apply(Operation::InsertBefore(b"XY".to_vec()), b"abc"), b"XYabc");
        assert_eq!(apply(Operation::InsertAfter(b"XY".to_vec()), b"abc"), b"abcXY");
        assert_eq!(apply(Operation::Duplicate, b"ab"), b"abab");
    }

    #[test]
    fn fill_repeats_the_pattern_and_refuses_an_empty_one() {
        assert_eq!(apply(Operation::Fill(vec![1, 2]), &[0; 5]), vec![1, 2, 1, 2, 1]);
        assert!(transform_range(&Operation::Fill(Vec::new()), &[0; 2], 0).is_err());
    }

    #[test]
    fn invert_xor_add_and_subtract_combine_each_byte_with_a_repeating_key() {
        assert_eq!(apply(Operation::Invert, &[0x0F]), vec![0xF0]);
        assert_eq!(apply(Operation::Xor(vec![0xFF, 0x00]), &[0x12, 0x34, 0x56]), vec![0xED, 0x34, 0xA9]);
        assert_eq!(apply(Operation::Add(vec![1]), &[0xFF, 0x10]), vec![0x00, 0x11]);
        assert_eq!(apply(Operation::Subtract(vec![1]), &[0x00, 0x10]), vec![0xFF, 0x0F]);
        assert!(transform_range(&Operation::Xor(Vec::new()), &[1], 0).is_err(), "an empty key is an error");
    }

    #[test]
    fn reverse_and_mirror_reorder_bytes_and_bits() {
        assert_eq!(apply(Operation::Reverse, &[1, 2, 3]), vec![3, 2, 1]);
        assert_eq!(apply(Operation::MirrorBits, &[0b0000_0001]), vec![0b1000_0000]);
    }

    #[test]
    fn shifting_drops_bits_and_rotating_brings_them_round() {
        assert_eq!(apply(Operation::ShiftBits(4), &[0xAB, 0xCD]), vec![0xBC, 0xD0]);
        assert_eq!(apply(Operation::RotateBits(4), &[0xAB, 0xCD]), vec![0xBC, 0xDA]);
        assert_eq!(apply(Operation::RotateBits(-4), &[0xAB, 0xCD]), vec![0xDA, 0xBC]);
        assert_eq!(apply(Operation::RotateBits(16), &[0xAB, 0xCD]), vec![0xAB, 0xCD], "a full turn changes nothing");
    }

    #[test]
    fn swapping_byte_order_reverses_each_value_and_leaves_a_short_tail() {
        assert_eq!(apply(Operation::SwapByteOrder(2), &[1, 2, 3, 4, 5]), vec![2, 1, 4, 3, 5]);
        assert_eq!(apply(Operation::SwapByteOrder(4), &[1, 2, 3, 4]), vec![4, 3, 2, 1]);
        assert!(transform_range(&Operation::SwapByteOrder(3), &[1, 2, 3], 0).is_err());
    }

    #[test]
    fn a_counter_numbers_each_record_in_either_byte_order() {
        let little = Operation::Counter { start: 10, step: 2, little_endian: true };
        assert_eq!(transform_range(&little, &[0xEE; 4], 3).unwrap(), vec![16, 0, 0, 0]);
        let big = Operation::Counter { start: 0x0102, step: 1, little_endian: false };
        assert_eq!(transform_range(&big, &[0xEE; 2], 0).unwrap(), vec![0x01, 0x02]);
        assert_eq!(transform_range(&little, &[0xEE; 10], 0).unwrap()[8..], [0xEE, 0xEE], "bytes past eight are kept");
    }

    #[test]
    fn compressing_and_decompressing_round_trip() {
        let text = b"the same words again and again and again and again".repeat(4);
        let packed = apply(Operation::Compress(Codec::Zlib), &text);
        assert!(packed.len() < text.len());
        assert_eq!(apply(Operation::Decompress, &packed), text);
        assert!(transform_range(&Operation::Decompress, b"not compressed at all", 0).is_err());
    }

    #[test]
    fn an_operation_on_a_column_applies_to_each_record_and_reports_where_they_went() {
        // Three 4-byte records, the middle two bytes of each selected.
        let span = b"aBCdeFGhiJKl".to_vec();
        let ranges = [(101, 2), (105, 2), (109, 2)];
        let (filled, moved) = rebuild_span(&span, 100, &ranges, &Operation::Fill(vec![b'.'])).unwrap();
        assert_eq!(filled, b"a..de..hi..l");
        assert_eq!(moved, ranges);
        let (deleted, moved) = rebuild_span(&span, 100, &ranges, &Operation::Delete).unwrap();
        assert_eq!(deleted, b"adehil");
        assert_eq!(moved, vec![(101, 0), (103, 0), (105, 0)]);
        let (numbered, _) = rebuild_span(&span, 100, &ranges, &Operation::Counter { start: 0x30, step: 1, little_endian: true }).unwrap();
        assert_eq!(numbered, b"a0\0de1\0hi2\0l");
    }

    #[test]
    fn an_operation_on_several_ranges_applies_to_each_and_shifts_the_later_ones() {
        let span = b"0123456789".to_vec();
        let (out, moved) = rebuild_span(&span, 0, &[(1, 2), (6, 1)], &Operation::Duplicate).unwrap();
        assert_eq!(out, b"0121234566789");
        assert_eq!(moved, vec![(1, 4), (8, 2)]);
        let (inverted, _) = rebuild_span(&span, 0, &[(0, 1), (9, 1)], &Operation::Invert).unwrap();
        assert_eq!(inverted, [!b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', !b'9']);
    }

    #[test]
    fn ranges_outside_the_span_or_overlapping_are_refused() {
        assert!(rebuild_span(b"abc", 10, &[(9, 1)], &Operation::Invert).is_err());
        assert!(rebuild_span(b"abc", 10, &[(12, 2)], &Operation::Invert).is_err());
        assert!(rebuild_span(b"abcdef", 0, &[(0, 3), (2, 2)], &Operation::Invert).is_err());
    }

    #[test]
    fn moved_bytes_land_where_the_cursor_was_once_the_ranges_are_cut_out() {
        assert_eq!(moved_destination(100, &[(10, 5), (20, 5)]), 90);
        assert_eq!(moved_destination(5, &[(10, 5)]), 5);
        assert_eq!(moved_destination(12, &[(10, 5)]), 10, "inside a range: its start");
        assert_eq!(moved_destination(22, &[(10, 5), (20, 5)]), 15);
    }

    #[test]
    fn bytes_copy_as_hex_a_c_array_and_base64() {
        assert_eq!(CopyFormat::Hex.render(&[0xDE, 0xAD]), "DE AD");
        assert_eq!(CopyFormat::CArray.render(&[1, 2]), "const unsigned char data[2] = {\n    0x01, 0x02,\n};");
        assert_eq!(CopyFormat::Base64.render(b"Man"), "TWFu");
        assert_eq!(CopyFormat::Base64.render(b"Ma"), "TWE=");
        assert_eq!(CopyFormat::Base64.render(b"M"), "TQ==");
        assert_eq!(CopyFormat::Base64.render(b""), "");
    }
}
