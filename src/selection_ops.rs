//! Byte operations on any selection: one range, a column of every record, or
//! several ranges.
//!
//! Each operation is defined on the bytes of one selected range (with the
//! range's index, so a counter can number records). [`rebuild_span`] applies
//! it to every range inside a span of the document read in one piece, which
//! the app then writes back as one edit, so the whole operation is one undo
//! step however many ranges it touched. Everything here is pure: no document,
//! no UI.

use crate::ciphers::{Feedback, Transform};
use crate::compress::{self, Codec};
use crate::ops;

/// Most bytes a counter value is written across.
const MAX_COUNTER_BYTES: usize = 8;
/// Largest output a decompression of one range may produce.
const DECOMPRESS_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;

/// Byte ranges as `(start, len)`.
pub type Ranges = Vec<(usize, usize)>;

/// Something done to each selected range. In JSON it is tagged by `op`,
/// such as `{"op": "xor", "key": "5a"}`, with bytes as hex.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(into = "OperationJson", from = "OperationJson")]
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
    /// XOR each byte with a key that steps on: `start + step × i` for the
    /// byte `i` places into the range.
    RollingXor { start: u8, step: u8 },
    /// XOR each byte with the byte before it and a constant (see
    /// [`Feedback`]); the byte before the range's first counts as zero.
    XorPrevious { feedback: Feedback, key: u8 },
    /// XOR each byte with one constant, then add another, wrapping.
    XorThenAdd { xor: u8, add: u8 },
    /// Add one constant to each byte, wrapping, then XOR it with another.
    AddThenXor { add: u8, xor: u8 },
    /// Rotate the bits of each byte on its own, left by 1 to 7.
    RotateEachByte(u32),
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
    /// Rotate the range's bytes; positive moves them towards the start and
    /// the bytes moved out come back in at the other end.
    RotateBytes(i64),
    /// Reverse each group of this many bytes (2, 4 or 8): swap the byte
    /// order of the numbers in the range.
    SwapByteOrder(usize),
    /// Write `start + step × index` into each range, numbering records.
    Counter { start: u64, step: u64, little_endian: bool },
    /// Follow each range with a copy of itself.
    Duplicate,
    /// Replace each range with its compressed form, or its text encoding.
    Compress(Codec),
    /// Replace each range with its decompressed contents.
    Decompress,
    /// Replace each range with what it decodes to with this codec, a
    /// decompressor or a text encoding (base32, base64, sixbit…).
    DecodeAs(Codec),
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
            Operation::RollingXor { .. } => "Rolling-XORed".to_string(),
            Operation::XorPrevious { .. } => "XORed with the previous bytes".to_string(),
            Operation::XorThenAdd { .. } | Operation::AddThenXor { .. } => "XORed and added to".to_string(),
            Operation::RotateEachByte(bits) => format!("Rotated each byte left by {bits} in"),
            Operation::Reverse => "Reversed bytes".to_string(),
            Operation::MirrorBits => "Mirrored bits".to_string(),
            Operation::ShiftBits(amount) => format!("Shifted bits by {amount}"),
            Operation::RotateBits(amount) => format!("Rotated bits by {amount}"),
            Operation::RotateBytes(amount) => format!("Rotated bytes by {amount}"),
            Operation::SwapByteOrder(width) => format!("Swapped the byte order of {width}-byte values in"),
            Operation::Counter { .. } => "Numbered".to_string(),
            Operation::Duplicate => "Duplicated".to_string(),
            Operation::Compress(codec) if codec.text_encoding().is_some() => format!("Encoded as {}", codec.label()),
            Operation::Compress(codec) => format!("Compressed with {}", codec.label()),
            Operation::Decompress => "Decompressed".to_string(),
            Operation::DecodeAs(codec) => format!("Decoded {}", codec.label()),
        }
    }

    /// The operation's short name, as the undo history labels it ("XOR").
    pub fn name(&self) -> &'static str {
        match self {
            Operation::Delete => "Delete",
            Operation::InsertBefore(_) => "Insert before",
            Operation::InsertAfter(_) => "Insert after",
            Operation::Fill(_) => "Fill",
            Operation::Invert => "Invert",
            Operation::Xor(_) => "XOR",
            Operation::Add(_) => "Add",
            Operation::Subtract(_) => "Subtract",
            Operation::RollingXor { .. } => "Rolling XOR",
            Operation::XorPrevious { .. } => "XOR with previous",
            Operation::XorThenAdd { .. } => "XOR then add",
            Operation::AddThenXor { .. } => "Add then XOR",
            Operation::RotateEachByte(_) => "Rotate each byte",
            Operation::Reverse => "Reverse",
            Operation::MirrorBits => "Mirror bits",
            Operation::ShiftBits(_) => "Shift bits",
            Operation::RotateBits(_) => "Rotate bits",
            Operation::RotateBytes(_) => "Rotate bytes",
            Operation::SwapByteOrder(_) => "Swap byte order",
            Operation::Counter { .. } => "Number",
            Operation::Duplicate => "Duplicate",
            Operation::Compress(_) => "Compress",
            Operation::Decompress => "Decompress",
            Operation::DecodeAs(_) => "Decode",
        }
    }

    /// The operation applied to `target` (such as "128 selected bytes"),
    /// in plain words: "XOR 128 selected bytes with 5A".
    pub fn describe(&self, target: &str) -> String {
        let hex = |bytes: &[u8]| preview_hex(bytes);
        match self {
            Operation::Delete => format!("Delete {target}"),
            Operation::InsertBefore(bytes) => format!("Insert {} before {target}", hex(bytes)),
            Operation::InsertAfter(bytes) => format!("Insert {} after {target}", hex(bytes)),
            Operation::Fill(pattern) => format!("Fill {target} with {}", hex(pattern)),
            Operation::Invert => format!("Invert {target}"),
            Operation::Xor(key) => format!("XOR {target} with {}", hex(key)),
            Operation::Add(key) => format!("Add {} to {target}", hex(key)),
            Operation::Subtract(key) => format!("Subtract {} from {target}", hex(key)),
            Operation::RollingXor { start, step } => format!("XOR {target} with a rolling key from {start:02X} in steps of {step}"),
            Operation::XorPrevious { feedback, key } => {
                let previous = match feedback {
                    Feedback::Ciphertext => "input",
                    Feedback::Plaintext => "output",
                };
                format!("XOR each of {target} with the previous {previous} byte and {key:02X}")
            }
            Operation::XorThenAdd { xor, add } => format!("XOR {target} with {xor:02X}, then add {add:02X}"),
            Operation::AddThenXor { add, xor } => format!("Add {add:02X} to {target}, then XOR with {xor:02X}"),
            Operation::RotateEachByte(bits) => format!("Rotate each of {target} left by {bits} bits"),
            Operation::Reverse => format!("Reverse {target}"),
            Operation::MirrorBits => format!("Mirror the bits of {target}"),
            Operation::ShiftBits(amount) => format!("Shift the bits of {target} by {amount}"),
            Operation::RotateBits(amount) => format!("Rotate the bits of {target} by {amount}"),
            Operation::RotateBytes(amount) => format!("Rotate {target} by {amount} bytes"),
            Operation::SwapByteOrder(width) => format!("Swap the byte order of the {width}-byte values in {target}"),
            Operation::Counter { start, step, little_endian } => {
                let order = if *little_endian { "little-endian" } else { "big-endian" };
                format!("Number {target} from {start} in steps of {step}, {order}")
            }
            Operation::Duplicate => format!("Duplicate {target}"),
            Operation::Compress(codec) if codec.text_encoding().is_some() => format!("Encode {target} as {}", codec.label()),
            Operation::Compress(codec) => format!("Compress {target} with {}", codec.label()),
            Operation::Decompress => format!("Decompress {target}"),
            Operation::DecodeAs(codec) => format!("Decode {target} as {}", codec.label()),
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
                | Operation::DecodeAs(_)
        )
    }
}

/// How an [`Operation`] is written in JSON: every variant named, its values
/// named too, and bytes as hex strings.
#[derive(Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum OperationJson {
    /// Remove the bytes.
    Delete,
    /// Insert bytes before each range.
    InsertBefore {
        #[serde(with = "crate::ops::hex_bytes")]
        #[schemars(with = "String")]
        bytes: Vec<u8>,
    },
    /// Insert bytes after each range.
    InsertAfter {
        #[serde(with = "crate::ops::hex_bytes")]
        #[schemars(with = "String")]
        bytes: Vec<u8>,
    },
    /// Repeat a pattern over the bytes.
    Fill {
        #[serde(with = "crate::ops::hex_bytes")]
        #[schemars(with = "String")]
        pattern: Vec<u8>,
    },
    /// Flip every bit.
    Invert,
    /// XOR with a key, repeated from the start of each range.
    Xor {
        #[serde(with = "crate::ops::hex_bytes")]
        #[schemars(with = "String")]
        key: Vec<u8>,
    },
    /// Add a key byte by byte, wrapping, repeated from the start of each range.
    Add {
        #[serde(with = "crate::ops::hex_bytes")]
        #[schemars(with = "String")]
        key: Vec<u8>,
    },
    /// Subtract a key byte by byte, wrapping.
    Subtract {
        #[serde(with = "crate::ops::hex_bytes")]
        #[schemars(with = "String")]
        key: Vec<u8>,
    },
    /// XOR each byte with `start + step × i`, i counting from the range's start.
    RollingXor { start: u8, step: u8 },
    /// XOR each byte with the byte before it and `key`: the previous input
    /// byte ("ciphertext") or the previous output byte ("plaintext").
    XorPrevious { feedback: Feedback, key: u8 },
    /// XOR each byte with `xor`, then add `add`, wrapping.
    XorThenAdd { xor: u8, add: u8 },
    /// Add `add` to each byte, wrapping, then XOR with `xor`.
    AddThenXor { add: u8, xor: u8 },
    /// Rotate the bits of each byte left by `bits` (1 to 7).
    RotateEachByte { bits: u32 },
    /// Reverse the order of the bytes.
    Reverse,
    /// Reverse the bits within each byte.
    MirrorBits,
    /// Shift the range's bits; positive moves them towards the start.
    ShiftBits { amount: i64 },
    /// Rotate the range's bits; positive moves them towards the start.
    RotateBits { amount: i64 },
    /// Rotate the range's bytes; positive moves them towards the start.
    RotateBytes { amount: i64 },
    /// Swap the byte order of the 2, 4 or 8 byte numbers in the range.
    SwapByteOrder { width: usize },
    /// Write `start + step × index` into each range, numbering records.
    Counter { start: u64, step: u64, little_endian: bool },
    /// Follow each range with a copy of itself.
    Duplicate,
    /// Replace each range with its compressed form; a text encoding's
    /// codec (base32, base64, base64url, hex, sixbit, ais6) encodes it.
    Compress { codec: Codec },
    /// Replace each range with its decompressed contents: with the codec
    /// named (a decompressor or a text encoding, as codecs.list gives
    /// them), or else the first decompressor or text encoding that decodes it.
    Decompress {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        codec: Option<Codec>,
    },
}

impl From<Operation> for OperationJson {
    fn from(operation: Operation) -> Self {
        match operation {
            Operation::Delete => OperationJson::Delete,
            Operation::InsertBefore(bytes) => OperationJson::InsertBefore { bytes },
            Operation::InsertAfter(bytes) => OperationJson::InsertAfter { bytes },
            Operation::Fill(pattern) => OperationJson::Fill { pattern },
            Operation::Invert => OperationJson::Invert,
            Operation::Xor(key) => OperationJson::Xor { key },
            Operation::Add(key) => OperationJson::Add { key },
            Operation::Subtract(key) => OperationJson::Subtract { key },
            Operation::RollingXor { start, step } => OperationJson::RollingXor { start, step },
            Operation::XorPrevious { feedback, key } => OperationJson::XorPrevious { feedback, key },
            Operation::XorThenAdd { xor, add } => OperationJson::XorThenAdd { xor, add },
            Operation::AddThenXor { add, xor } => OperationJson::AddThenXor { add, xor },
            Operation::RotateEachByte(bits) => OperationJson::RotateEachByte { bits },
            Operation::Reverse => OperationJson::Reverse,
            Operation::MirrorBits => OperationJson::MirrorBits,
            Operation::ShiftBits(amount) => OperationJson::ShiftBits { amount },
            Operation::RotateBits(amount) => OperationJson::RotateBits { amount },
            Operation::RotateBytes(amount) => OperationJson::RotateBytes { amount },
            Operation::SwapByteOrder(width) => OperationJson::SwapByteOrder { width },
            Operation::Counter { start, step, little_endian } => OperationJson::Counter { start, step, little_endian },
            Operation::Duplicate => OperationJson::Duplicate,
            Operation::Compress(codec) => OperationJson::Compress { codec },
            Operation::Decompress => OperationJson::Decompress { codec: None },
            Operation::DecodeAs(codec) => OperationJson::Decompress { codec: Some(codec) },
        }
    }
}

impl From<OperationJson> for Operation {
    fn from(operation: OperationJson) -> Self {
        match operation {
            OperationJson::Delete => Operation::Delete,
            OperationJson::InsertBefore { bytes } => Operation::InsertBefore(bytes),
            OperationJson::InsertAfter { bytes } => Operation::InsertAfter(bytes),
            OperationJson::Fill { pattern } => Operation::Fill(pattern),
            OperationJson::Invert => Operation::Invert,
            OperationJson::Xor { key } => Operation::Xor(key),
            OperationJson::Add { key } => Operation::Add(key),
            OperationJson::Subtract { key } => Operation::Subtract(key),
            OperationJson::RollingXor { start, step } => Operation::RollingXor { start, step },
            OperationJson::XorPrevious { feedback, key } => Operation::XorPrevious { feedback, key },
            OperationJson::XorThenAdd { xor, add } => Operation::XorThenAdd { xor, add },
            OperationJson::AddThenXor { add, xor } => Operation::AddThenXor { add, xor },
            OperationJson::RotateEachByte { bits } => Operation::RotateEachByte(bits),
            OperationJson::Reverse => Operation::Reverse,
            OperationJson::MirrorBits => Operation::MirrorBits,
            OperationJson::ShiftBits { amount } => Operation::ShiftBits(amount),
            OperationJson::RotateBits { amount } => Operation::RotateBits(amount),
            OperationJson::RotateBytes { amount } => Operation::RotateBytes(amount),
            OperationJson::SwapByteOrder { width } => Operation::SwapByteOrder(width),
            OperationJson::Counter { start, step, little_endian } => Operation::Counter { start, step, little_endian },
            OperationJson::Duplicate => Operation::Duplicate,
            OperationJson::Compress { codec } => Operation::Compress(codec),
            OperationJson::Decompress { codec: None } => Operation::Decompress,
            OperationJson::Decompress { codec: Some(codec) } => Operation::DecodeAs(codec),
        }
    }
}

/// The operation that decodes as a cipher attack's transform does, so a
/// candidate can be applied to the bytes it was found in.
impl From<Transform> for Operation {
    fn from(transform: Transform) -> Self {
        match transform {
            Transform::RollingXor { start, step } => Operation::RollingXor { start, step },
            Transform::XorPrevious { feedback, key } => Operation::XorPrevious { feedback, key },
            Transform::Add { key } => Operation::Add(key),
            Transform::RotateLeft { bits } => Operation::RotateEachByte(bits),
            Transform::XorThenAdd { xor, add } => Operation::XorThenAdd { xor, add },
            Transform::AddThenXor { add, xor } => Operation::AddThenXor { add, xor },
            Transform::RepeatingXor { key } => Operation::Xor(key),
        }
    }
}

/// Most bytes [`preview_hex`] shows before it stops with an ellipsis.
const PREVIEW_BYTES: usize = 16;

/// Bytes as a short upper-case hex preview for messages: "DE AD BE EF",
/// cut off after 16 bytes with "… (40 bytes)".
pub fn preview_hex(bytes: &[u8]) -> String {
    if bytes.len() <= PREVIEW_BYTES {
        return ops::to_hex_string(bytes);
    }
    format!("{} … ({} bytes)", ops::to_hex_string(&bytes[..PREVIEW_BYTES]), bytes.len())
}

/// The new bytes for each of `ranges` of `document`, in order, as
/// [`transform_range`] makes them: what an operation would write, for
/// `transform.preview` and for an output other than in place.
pub fn transform_ranges(operation: &Operation, document: &mut crate::document::Document, ranges: &[(usize, usize)]) -> Result<Vec<Vec<u8>>, String> {
    ranges.iter().enumerate().map(|(index, &(start, len))| transform_range(operation, &document.read_range(start, len), index)).collect()
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
        Operation::RollingXor { start, step } => out = Transform::RollingXor { start: *start, step: *step }.apply(bytes),
        Operation::XorPrevious { feedback, key } => out = Transform::XorPrevious { feedback: *feedback, key: *key }.apply(bytes),
        Operation::XorThenAdd { xor, add } => out = Transform::XorThenAdd { xor: *xor, add: *add }.apply(bytes),
        Operation::AddThenXor { add, xor } => out = Transform::AddThenXor { add: *add, xor: *xor }.apply(bytes),
        Operation::RotateEachByte(bits) => {
            if !(1..8).contains(bits) {
                return Err(format!("Each byte can be rotated left by 1 to 7 bits, not {bits}"));
            }
            out = Transform::RotateLeft { bits: *bits }.apply(bytes);
        }
        Operation::Reverse => out.reverse(),
        Operation::MirrorBits => ops::reverse_bits_in_bytes(&mut out),
        Operation::ShiftBits(amount) => out = ops::shift_bits(bytes, *amount),
        Operation::RotateBits(amount) => out = rotate_bits(bytes, *amount),
        Operation::RotateBytes(amount) => {
            if !out.is_empty() {
                let turn = amount.rem_euclid(out.len() as i64) as usize;
                out.rotate_left(turn);
            }
        }
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
        Operation::DecodeAs(codec) => {
            out = compress::decompress(*codec, bytes, DECOMPRESS_OUTPUT_LIMIT).map_err(|reason| format!("The selected bytes do not decode as {}: {reason}", codec.label()))?.data;
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
    fn operations_are_written_as_json_tagged_by_name_with_bytes_as_hex() {
        let xor = serde_json::to_value(Operation::Xor(vec![0xDE, 0xAD])).unwrap();
        assert_eq!(xor, serde_json::json!({"op": "xor", "key": "dead"}));
        let shift = serde_json::to_value(Operation::ShiftBits(-3)).unwrap();
        assert_eq!(shift, serde_json::json!({"op": "shift_bits", "amount": -3}));
        let compress = serde_json::to_value(Operation::Compress(Codec::Zlib)).unwrap();
        assert_eq!(compress, serde_json::json!({"op": "compress", "codec": "zlib"}));
        for operation in [
            Operation::Invert,
            Operation::Fill(vec![0, 1]),
            Operation::Counter { start: 1, step: 2, little_endian: true },
            Operation::SwapByteOrder(4),
            Operation::Decompress,
            Operation::DecodeAs(Codec::Base32),
        ] {
            let json = serde_json::to_value(&operation).unwrap();
            assert_eq!(serde_json::from_value::<Operation>(json).unwrap(), operation);
        }
        let typed: Operation = serde_json::from_value(serde_json::json!({"op": "add", "key": "01 02"})).unwrap();
        assert_eq!(typed, Operation::Add(vec![1, 2]), "hex is read loosely, as typed in the app");
        assert!(serde_json::from_value::<Operation>(serde_json::json!({"op": "xor", "key": "xyz"})).is_err());
        assert!(serde_json::from_value::<Operation>(serde_json::json!({"op": "melt"})).is_err());
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
    fn rolling_and_chained_xors_undo_the_obfuscation_a_cipher_attack_names() {
        let plain = b"staged payload";
        let rolled: Vec<u8> = plain.iter().enumerate().map(|(i, byte)| byte ^ 0x51u8.wrapping_add(5u8.wrapping_mul(i as u8))).collect();
        assert_eq!(apply(Operation::RollingXor { start: 0x51, step: 5 }, &rolled), plain);
        let mut previous = 0u8;
        let chained: Vec<u8> = plain
            .iter()
            .map(|&byte| {
                previous = byte ^ previous ^ 0x5A;
                previous
            })
            .collect();
        assert_eq!(apply(Operation::XorPrevious { feedback: Feedback::Ciphertext, key: 0x5A }, &chained), plain);
        let mixed: Vec<u8> = plain.iter().map(|byte| byte.wrapping_sub(0x21) ^ 0xA5).collect();
        assert_eq!(apply(Operation::XorThenAdd { xor: 0xA5, add: 0x21 }, &mixed), plain);
        let added: Vec<u8> = plain.iter().map(|byte| (byte ^ 0x0F).wrapping_sub(0x10)).collect();
        assert_eq!(apply(Operation::AddThenXor { add: 0x10, xor: 0x0F }, &added), plain);
        let rotated: Vec<u8> = plain.iter().map(|byte| byte.rotate_right(3)).collect();
        assert_eq!(apply(Operation::RotateEachByte(3), &rotated), plain);
        assert!(transform_range(&Operation::RotateEachByte(8), plain, 0).is_err());
    }

    #[test]
    fn every_cipher_attack_transform_applies_as_the_operation_it_names() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        for transform in [
            Transform::RollingXor { start: 0x37, step: 3 },
            Transform::XorPrevious { feedback: Feedback::Plaintext, key: 9 },
            Transform::Add { key: vec![1, 2, 3] },
            Transform::RotateLeft { bits: 5 },
            Transform::XorThenAdd { xor: 0x11, add: 0x22 },
            Transform::AddThenXor { add: 0x33, xor: 0x44 },
            Transform::RepeatingXor { key: vec![0xDE, 0xAD] },
        ] {
            let operation = Operation::from(transform.clone());
            assert_eq!(apply(operation.clone(), &bytes), transform.apply(&bytes), "{}", transform.describe());
            let json = serde_json::to_value(&operation).unwrap();
            assert_eq!(serde_json::from_value::<Operation>(json).unwrap(), operation);
        }
        let rolling = serde_json::to_value(Operation::RollingXor { start: 0x51, step: 5 }).unwrap();
        assert_eq!(rolling, serde_json::json!({"op": "rolling_xor", "start": 0x51, "step": 5}));
        let previous = serde_json::to_value(Operation::XorPrevious { feedback: Feedback::Ciphertext, key: 1 }).unwrap();
        assert_eq!(previous, serde_json::json!({"op": "xor_previous", "feedback": "ciphertext", "key": 1}));
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
    fn rotating_bytes_moves_them_round_in_either_direction() {
        assert_eq!(apply(Operation::RotateBytes(1), &[1, 2, 3]), vec![2, 3, 1]);
        assert_eq!(apply(Operation::RotateBytes(-1), &[1, 2, 3]), vec![3, 1, 2]);
        assert_eq!(apply(Operation::RotateBytes(5), &[]), Vec::<u8>::new());
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
    fn a_transform_decodes_base32_and_six_bit_text_by_codec_id() {
        let decode: Operation = serde_json::from_value(serde_json::json!({"op": "decompress", "codec": "base32"})).unwrap();
        assert_eq!(decode, Operation::DecodeAs(Codec::Base32));
        assert_eq!(apply(decode, b"mzxw6ytboi"), b"foobar");
        assert_eq!(serde_json::to_value(Operation::Decompress).unwrap(), serde_json::json!({"op": "decompress"}), "unchanged without a codec");
        let encode: Operation = serde_json::from_value(serde_json::json!({"op": "compress", "codec": "sixbit"})).unwrap();
        let packed = apply(encode.clone(), b"JB22");
        assert_eq!(packed.len(), 3);
        assert_eq!(apply(Operation::DecodeAs(Codec::Sixbit), &packed), b"JB22");
        assert_eq!(encode.describe("4 selected bytes"), "Encode 4 selected bytes as DEC SIXBIT");
        assert!(transform_range(&Operation::DecodeAs(Codec::Base64), b"!!!!", 0).unwrap_err().contains("base64"));
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
