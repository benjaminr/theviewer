//! Then anchors: a value another anchor finds, transformed: an offset plus a
//! header's length, a sector number times the sector size, text as the hex
//! of its bytes.
//!
//! ```json
//! {"of": {"var": "serial"}, "then": [{"encode": "text_to_hex"}]}
//! {"of": {"structure": "mbr", "field": "partitions[0].lba", "part": "value"}, "then": [{"mul": 512}]}
//! ```
//!
//! The operations run in order, each on what the one before gave.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::ApiError;

/// One operation of a then anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Add a number: `{"add": 16}`.
    Add(i64),
    /// Take a number away: `{"sub": 4}`.
    Sub(i64),
    /// Multiply by a number: `{"mul": 512}`.
    Mul(i64),
    /// Keep the bits set in a mask: `{"and": 255}`.
    And(u64),
    /// Write text as the hex of its UTF-8 bytes, or hex as the text it
    /// spells: `{"encode": "text_to_hex"}`.
    Encode(Encoding),
    /// Read text as an integer, in decimal or 0x hex: `"int"`.
    Int,
    /// Part of a text (by characters) or a list: `{"slice": [start]}` to
    /// the end, `{"slice": [start, len]}`.
    Slice(Vec<usize>),
    /// The length of a text (in characters) or a list: `"len"`.
    Len,
}

/// How an `encode` writes a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// Text as the hex of its UTF-8 bytes: "NC5" is "4e4335".
    TextToHex,
    /// Hex as the UTF-8 text its bytes spell.
    HexToText,
}

impl Operation {
    /// "plus 16", "times 512", "as hex".
    pub fn describe(&self) -> String {
        match self {
            Operation::Add(number) => format!("plus {number}"),
            Operation::Sub(number) => format!("minus {number}"),
            Operation::Mul(number) => format!("times {number}"),
            Operation::And(mask) => format!("masked with {mask:#x}"),
            Operation::Encode(Encoding::TextToHex) => "as the hex of its text".to_string(),
            Operation::Encode(Encoding::HexToText) => "as the text its hex spells".to_string(),
            Operation::Int => "read as an integer".to_string(),
            Operation::Slice(bounds) => match bounds.as_slice() {
                [start] => format!("from character {start}"),
                [start, len] => format!("{len} from {start}"),
                _ => "sliced".to_string(),
            },
            Operation::Len => "its length".to_string(),
        }
    }

    /// `value` after this operation.
    pub fn apply(&self, value: Value) -> Result<Value, ApiError> {
        match self {
            Operation::Add(number) => arithmetic(&value, "add to", |held| held.checked_add(i128::from(*number))),
            Operation::Sub(number) => arithmetic(&value, "take from", |held| held.checked_sub(i128::from(*number))),
            Operation::Mul(number) => arithmetic(&value, "multiply", |held| held.checked_mul(i128::from(*number))),
            Operation::And(mask) => arithmetic(&value, "mask", |held| Some(held & i128::from(*mask))),
            Operation::Int => integer_of(&value).map(number_value).ok_or_else(|| ApiError::invalid_params(format!("{value} does not read as an integer"))),
            Operation::Encode(Encoding::TextToHex) => {
                let text = value.as_str().ok_or_else(|| ApiError::invalid_params(format!("{value} is not text, so it has no hex")))?;
                Ok(Value::String(crate::ops::to_compact_hex(text.as_bytes())))
            }
            Operation::Encode(Encoding::HexToText) => {
                let hex = value.as_str().ok_or_else(|| ApiError::invalid_params(format!("{value} is not hex")))?;
                let bytes = crate::api::values::decode_bytes(hex, crate::api::values::ByteEncoding::Hex)?;
                String::from_utf8(bytes).map(Value::String).map_err(|_| ApiError::invalid_params(format!("the bytes of {hex} are not UTF-8 text")))
            }
            Operation::Slice(bounds) => slice(value, bounds),
            Operation::Len => match &value {
                Value::String(text) => Ok(Value::from(text.chars().count())),
                Value::Array(items) => Ok(Value::from(items.len())),
                other => Err(ApiError::invalid_params(format!("{other} is neither text nor a list, so it has no length"))),
            },
        }
    }
}

/// `value` read as an integer and changed by `change`, which fails on
/// overflow.
fn arithmetic(value: &Value, verb: &str, change: impl FnOnce(i128) -> Option<i128>) -> Result<Value, ApiError> {
    let held = integer_of(value).ok_or_else(|| ApiError::invalid_params(format!("cannot {verb} {value}: it is not an integer")))?;
    let changed = change(held).ok_or_else(|| ApiError::out_of_range(format!("{held} overflows")))?;
    if changed > i128::from(u64::MAX) || changed < i128::from(i64::MIN) {
        return Err(ApiError::out_of_range(format!("{changed} is too large to give")));
    }
    Ok(number_value(changed))
}

/// An integer as JSON: unsigned when it is not negative.
fn number_value(number: i128) -> Value {
    match u64::try_from(number) {
        Ok(unsigned) => Value::from(unsigned),
        Err(_) => Value::from(number as i64),
    }
}

/// `value` as an integer: a whole number, or text in decimal or 0x hex.
fn integer_of(value: &Value) -> Option<i128> {
    match value {
        Value::Number(number) => number.as_u64().map(i128::from).or_else(|| number.as_i64().map(i128::from)),
        Value::String(text) => super::parse_integer(text).and_then(|number| number.as_u64().map(i128::from).or_else(|| number.as_i64().map(i128::from))),
        _ => None,
    }
}

fn slice(value: Value, bounds: &[usize]) -> Result<Value, ApiError> {
    let (start, len) = match bounds {
        [start] => (*start, None),
        [start, len] => (*start, Some(*len)),
        _ => return Err(ApiError::invalid_params("a slice is [start] or [start, len]")),
    };
    match value {
        Value::String(text) => {
            let count = text.chars().count();
            check_slice(start, len, count)?;
            Ok(Value::String(text.chars().skip(start).take(len.unwrap_or(usize::MAX)).collect()))
        }
        Value::Array(items) => {
            check_slice(start, len, items.len())?;
            Ok(Value::Array(items.into_iter().skip(start).take(len.unwrap_or(usize::MAX)).collect()))
        }
        other => Err(ApiError::invalid_params(format!("{other} is neither text nor a list, so it cannot be sliced"))),
    }
}

fn check_slice(start: usize, len: Option<usize>, count: usize) -> Result<(), ApiError> {
    let end = start.saturating_add(len.unwrap_or(0));
    if start > count || end > count {
        return Err(ApiError::out_of_range(format!("the slice runs past the end: it holds {count}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn apply_all(value: Value, operations: Value) -> Result<Value, ApiError> {
        let operations: Vec<Operation> = serde_json::from_value(operations).unwrap();
        operations.iter().try_fold(value, |value, operation| operation.apply(value))
    }

    #[test]
    fn an_offset_is_worked_out_from_another_with_arithmetic() {
        assert_eq!(apply_all(json!(2048), json!([{"mul": 512}])).unwrap(), json!(1_048_576));
        assert_eq!(apply_all(json!(1_156_096), json!([{"add": 16}])).unwrap(), json!(1_156_112));
        assert_eq!(apply_all(json!("0x40"), json!([{"sub": 4}, {"and": 15}])).unwrap(), json!(12));
        assert_eq!(apply_all(json!(3), json!([{"sub": 5}])).unwrap(), json!(-2), "a negative result is given as one");
        assert_eq!(apply_all(json!(u64::MAX), json!([{"add": 1}])).unwrap_err().code, crate::api::ErrorCode::OutOfRange);
    }

    #[test]
    fn a_serial_becomes_a_hex_key_and_back() {
        assert_eq!(apply_all(json!("NC500-8D98EE98"), json!([{"encode": "text_to_hex"}])).unwrap(), json!("4e433530302d3844393845453938"));
        assert_eq!(apply_all(json!("4e4335"), json!([{"encode": "hex_to_text"}])).unwrap(), json!("NC5"));
        assert!(apply_all(json!(12), json!([{"encode": "text_to_hex"}])).is_err());
    }

    #[test]
    fn text_is_read_as_a_number_sliced_and_measured() {
        assert_eq!(apply_all(json!("0x1F40"), json!(["int"])).unwrap(), json!(8000));
        assert_eq!(apply_all(json!("NC500-8D98EE98"), json!([{"slice": [6]}])).unwrap(), json!("8D98EE98"));
        assert_eq!(apply_all(json!("NC500-8D98EE98"), json!([{"slice": [0, 5]}, "len"])).unwrap(), json!(5));
        assert_eq!(apply_all(json!([1, 2, 3]), json!(["len"])).unwrap(), json!(3));
        assert_eq!(apply_all(json!("abc"), json!([{"slice": [2, 5]}])).unwrap_err().code, crate::api::ErrorCode::OutOfRange);
    }
}
