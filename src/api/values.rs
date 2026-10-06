//! How the API addresses documents and spans, and writes bytes, numbers and
//! pages of results in JSON.

use base64::Engine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{ApiError, MAX_CALL_BYTES};

/// Results a list method returns when no `limit` is given.
pub const DEFAULT_PAGE: usize = 100;
/// Most results one page may hold.
pub const MAX_PAGE: usize = 10_000;
/// The largest integer JSON numbers carry exactly; larger ones are strings.
const MAX_EXACT_JSON_INTEGER: i128 = 1 << 53;

/// Parameters of a method that takes none.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoParams {}

/// How bytes are written in JSON.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ByteEncoding {
    /// Compact lower-case hex, such as "89504e47".
    #[default]
    Hex,
    /// Standard base64 with padding.
    Base64,
    /// UTF-8 text; bytes that are not UTF-8 become U+FFFD replacement characters.
    Text,
}

/// `bytes` written as `encoding` says.
pub fn encode_bytes(bytes: &[u8], encoding: ByteEncoding) -> String {
    match encoding {
        ByteEncoding::Hex => crate::ops::to_compact_hex(bytes),
        ByteEncoding::Base64 => base64::engine::general_purpose::STANDARD.encode(bytes),
        ByteEncoding::Text => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Bytes given in JSON as `encoding` says.
pub fn decode_bytes(text: &str, encoding: ByteEncoding) -> Result<Vec<u8>, ApiError> {
    match encoding {
        ByteEncoding::Hex => crate::ops::parse_hex(text).ok_or_else(|| ApiError::invalid_params(format!("'{text}' is not hex bytes; write them like \"de ad be ef\""))),
        ByteEncoding::Base64 => base64::engine::general_purpose::STANDARD.decode(text.trim()).map_err(|error| ApiError::invalid_params(format!("the bytes are not valid base64: {error}"))),
        ByteEncoding::Text => Ok(text.as_bytes().to_vec()),
    }
}

/// A number in JSON: an integer when it fits a JSON number exactly, a float,
/// or a string of digits for integers beyond 2^53.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum NumberValue {
    Integer(i64),
    Float(f64),
    Text(String),
}

impl NumberValue {
    pub fn integer(value: i128) -> NumberValue {
        if value.abs() <= MAX_EXACT_JSON_INTEGER { NumberValue::Integer(value as i64) } else { NumberValue::Text(value.to_string()) }
    }
}

/// Check `start` and `len` (to the end when omitted) against a document of
/// `document_len` bytes and return the span as `(start, len)`.
pub fn span_within(document_len: usize, start: u64, len: Option<u64>) -> Result<(usize, usize), ApiError> {
    let start = usize::try_from(start).unwrap_or(usize::MAX);
    if start > document_len {
        return Err(ApiError::out_of_range(format!("offset {start:#x} is past the end of the document ({document_len} bytes)")));
    }
    let len = match len {
        Some(len) => usize::try_from(len).unwrap_or(usize::MAX),
        None => document_len - start,
    };
    if len > document_len - start {
        return Err(ApiError::out_of_range(format!(
            "{len} bytes from {start:#x} run past the end of the document ({document_len} bytes); read at most {}",
            document_len - start
        )));
    }
    Ok((start, len))
}

/// Refuse a call that would read or return more than `limit` bytes.
pub fn check_size(len: usize, limit: usize, what: &str) -> Result<(), ApiError> {
    if len > limit {
        return Err(ApiError::too_large(format!("{what} is {len} bytes, over the limit of {limit}; ask for a shorter span"))
            .with_data(serde_json::json!({ "limit": limit })));
    }
    Ok(())
}

/// Refuse a span over the per-call limit.
pub fn check_call_size(len: usize) -> Result<(), ApiError> {
    check_size(len, MAX_CALL_BYTES, "the span")
}

/// One page of `items`: from the position `next` names (the start when
/// omitted) up to `limit` of them, with the cursor of the page after, if any.
pub fn page<T>(items: Vec<T>, next: Option<&str>, limit: Option<usize>) -> Result<(Vec<T>, Option<String>), ApiError> {
    let from = match next {
        Some(cursor) => cursor.parse::<usize>().map_err(|_| ApiError::invalid_params(format!("'{cursor}' is not a cursor this method returned")))?,
        None => 0,
    };
    let limit = page_limit(limit)?;
    let total = items.len();
    let taken: Vec<T> = items.into_iter().skip(from).take(limit).collect();
    let after = from + taken.len();
    Ok((taken, (after < total).then(|| after.to_string())))
}

/// The page size asked for, checked.
pub fn page_limit(limit: Option<usize>) -> Result<usize, ApiError> {
    match limit {
        None => Ok(DEFAULT_PAGE),
        Some(0) => Err(ApiError::invalid_params("limit must be at least 1")),
        Some(limit) if limit > MAX_PAGE => Err(ApiError::invalid_params(format!("limit must be at most {MAX_PAGE}"))),
        Some(limit) => Ok(limit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ErrorCode;

    #[test]
    fn bytes_round_trip_through_every_encoding() {
        let bytes = b"\x89PNG\r\n";
        for encoding in [ByteEncoding::Hex, ByteEncoding::Base64] {
            assert_eq!(decode_bytes(&encode_bytes(bytes, encoding), encoding).unwrap(), bytes);
        }
        assert_eq!(encode_bytes(bytes, ByteEncoding::Hex), "89504e470d0a");
        assert_eq!(encode_bytes(b"ok\xff", ByteEncoding::Text), "ok\u{FFFD}", "bytes that are not UTF-8 are marked");
        assert_eq!(decode_bytes("zz", ByteEncoding::Hex).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn integers_beyond_two_to_the_fifty_three_are_strings() {
        assert_eq!(serde_json::to_value(NumberValue::integer(42)).unwrap(), serde_json::json!(42));
        assert_eq!(serde_json::to_value(NumberValue::integer(u64::MAX as i128)).unwrap(), serde_json::json!("18446744073709551615"));
    }

    #[test]
    fn spans_must_lie_inside_the_document() {
        assert_eq!(span_within(10, 2, None).unwrap(), (2, 8));
        assert_eq!(span_within(10, 10, Some(0)).unwrap(), (10, 0));
        assert_eq!(span_within(10, 11, None).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(span_within(10, 4, Some(7)).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(check_call_size(crate::api::MAX_CALL_BYTES + 1).unwrap_err().code, ErrorCode::TooLarge);
    }

    #[test]
    fn pages_follow_on_from_their_cursor() {
        let (first, next) = page((0..5).collect(), None, Some(2)).unwrap();
        assert_eq!((first, next.as_deref()), (vec![0, 1], Some("2")));
        let (last, next) = page((0..5).collect::<Vec<_>>(), Some("4"), Some(2)).unwrap();
        assert_eq!((last, next), (vec![4], None));
        assert_eq!(page(vec![1], Some("x"), None).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(page_limit(Some(0)).unwrap_err().code, ErrorCode::InvalidParams);
    }
}
