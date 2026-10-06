//! `bytes.*` and `bits.*`: reading the document's bytes and bits.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values::{self, ByteEncoding, NumberValue};
use super::workspace::{self, Workspace};
use super::ApiError;
use crate::bits::{BitOrder, BitStream};

/// Most bytes one hex dump shows: 1 MiB, about 5 MB of text.
const MAX_HEXDUMP_BYTES: usize = 1024 * 1024;
/// Most bits one `bits.read` returns as a string of 0s and 1s.
const MAX_BITS: u64 = 1024 * 1024;
/// Bits that still fit one integer value.
const MAX_VALUE_BITS: u64 = 64;

/// Parameters of `bytes.read`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the first byte.
    pub start: u64,
    /// Bytes to read, at most 16 MiB; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// How to write the bytes: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
}

/// The result of `bytes.read`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReadResult {
    /// Id of the document read.
    pub doc: String,
    /// Offset of the first byte.
    pub start: u64,
    /// Bytes read.
    pub len: u64,
    /// How `data` is written.
    pub encoding: ByteEncoding,
    /// The bytes, written as `encoding` says.
    pub data: String,
}

/// Parameters of `bytes.hexdump`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HexdumpParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the first byte.
    pub start: u64,
    /// Bytes to show, at most 1 MiB; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
}

/// The result of `bytes.hexdump`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HexdumpResult {
    /// Id of the document read.
    pub doc: String,
    /// Offset of the first byte.
    pub start: u64,
    /// Bytes shown.
    pub len: u64,
    /// Lines of an offset, 16 hex bytes and their ASCII.
    pub dump: String,
}

/// Parameters of `bits.read`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BitsParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Bit offset of the first bit: byte offset × 8 plus the bit within the byte, in `order`.
    pub bit_start: u64,
    /// Bits to read, at most 1048576.
    pub bit_len: u64,
    /// Which bit of each byte comes first: "msb" (the default) or "lsb".
    #[serde(default)]
    pub order: BitOrder,
}

/// The result of `bits.read`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BitsResult {
    /// Id of the document read.
    pub doc: String,
    /// Bit offset of the first bit.
    pub bit_start: u64,
    /// Bits read.
    pub bit_len: u64,
    /// Which bit of each byte came first.
    pub order: BitOrder,
    /// The bits as "0" and "1", first bit first.
    pub bits: String,
    /// The bits as an unsigned integer, first bit most significant, when there are at most 64.
    pub value: Option<NumberValue>,
}

pub fn read(workspace: &mut dyn Workspace, params: ReadParams) -> Result<ReadResult, ApiError> {
    let (doc, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (start, len) = values::span_within(document.len(), params.start, params.len)?;
    values::check_call_size(len)?;
    let bytes = document.read_range(start, len);
    Ok(ReadResult { doc, start: start as u64, len: len as u64, encoding: params.encoding, data: values::encode_bytes(&bytes, params.encoding) })
}

pub fn hexdump(workspace: &mut dyn Workspace, params: HexdumpParams) -> Result<HexdumpResult, ApiError> {
    let (doc, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (start, len) = values::span_within(document.len(), params.start, params.len)?;
    values::check_size(len, MAX_HEXDUMP_BYTES, "the hex dump")?;
    let bytes = document.read_range(start, len);
    Ok(HexdumpResult { doc, start: start as u64, len: len as u64, dump: crate::assistant::hex_dump(&bytes, start) })
}

pub fn read_bits(workspace: &mut dyn Workspace, params: BitsParams) -> Result<BitsResult, ApiError> {
    if params.bit_len > MAX_BITS {
        return Err(ApiError::too_large(format!("{} bits is over the limit of {MAX_BITS}; read fewer, or use bytes.read", params.bit_len)));
    }
    let (doc, document) = workspace::document(workspace, params.doc.as_deref())?;
    let document_bits = document.len() as u64 * 8;
    let bit_end = params.bit_start.saturating_add(params.bit_len);
    if bit_end > document_bits {
        return Err(ApiError::out_of_range(format!("bits {}..{bit_end} run past the end of the document ({document_bits} bits)", params.bit_start)));
    }
    let first_byte = (params.bit_start / 8) as usize;
    let last_byte = bit_end.div_ceil(8) as usize;
    let stream = BitStream::from_bytes(&document.read_range(first_byte, last_byte - first_byte), params.order);
    let skip = (params.bit_start % 8) as usize;
    let count = params.bit_len as usize;
    let bits: String = (skip..skip + count).map(|index| if stream.bit(index) { '1' } else { '0' }).collect();
    let value = (params.bit_len <= MAX_VALUE_BITS).then(|| NumberValue::integer(i128::from(stream.bits_at(skip, count))));
    Ok(BitsResult { doc, bit_start: params.bit_start, bit_len: params.bit_len, order: params.order, bits, value })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::{ErrorCode, call};

    #[test]
    fn bytes_are_read_as_hex_base64_or_text() {
        let mut workspace = workspace_with("a.bin", b"\x89PNG\r\n\x1a\nhello");
        let hex = call(&mut workspace, "bytes.read", json!({"start": 0, "len": 4})).unwrap();
        assert_eq!(hex["data"], "89504e47");
        let base64 = call(&mut workspace, "bytes.read", json!({"start": 0, "len": 4, "encoding": "base64"})).unwrap();
        assert_eq!(base64["data"], "iVBORw==");
        let text = call(&mut workspace, "bytes.read", json!({"start": 8, "encoding": "text"})).unwrap();
        assert_eq!((text["data"].as_str(), text["len"].as_u64()), (Some("hello"), Some(5)), "an omitted length reads to the end");
    }

    #[test]
    fn reading_past_the_end_is_out_of_range() {
        let mut workspace = workspace_with("a.bin", b"abcd");
        assert_eq!(call(&mut workspace, "bytes.read", json!({"start": 2, "len": 3})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "bytes.hexdump", json!({"start": 5})).unwrap_err().code, ErrorCode::OutOfRange);
    }

    #[test]
    fn a_hex_dump_shows_offsets_hex_and_ascii() {
        let mut workspace = workspace_with("a.bin", b"FWIM header");
        let dump = call(&mut workspace, "bytes.hexdump", json!({"start": 0, "len": 4})).unwrap();
        assert!(dump["dump"].as_str().unwrap().starts_with("00000000  46 57 49 4d"), "{dump}");
    }

    #[test]
    fn bits_are_read_in_either_order_from_any_bit() {
        let mut workspace = workspace_with("a.bin", &[0b1010_0000, 0b0000_0001]);
        let msb = call(&mut workspace, "bits.read", json!({"bit_start": 0, "bit_len": 4})).unwrap();
        assert_eq!((msb["bits"].as_str(), msb["value"].as_u64()), (Some("1010"), Some(0b1010)));
        let lsb = call(&mut workspace, "bits.read", json!({"bit_start": 8, "bit_len": 2, "order": "lsb"})).unwrap();
        assert_eq!(lsb["bits"], "10");
        let across = call(&mut workspace, "bits.read", json!({"bit_start": 6, "bit_len": 10})).unwrap();
        assert_eq!(across["bits"], "0000000001");
        assert_eq!(call(&mut workspace, "bits.read", json!({"bit_start": 10, "bit_len": 7})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "bits.read", json!({"bit_start": 0, "bit_len": 2_000_000})).unwrap_err().code, ErrorCode::TooLarge);
    }
}
