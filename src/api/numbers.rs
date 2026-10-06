//! `numbers.*`: reading bytes as numbers and timestamps.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values::{self, NumberValue};
use super::workspace::{self, Workspace};
use super::ApiError;
use crate::numeric::{self, Interpretation, NumberKind};

/// Field widths the interpretations cover.
const WIDTHS: [usize; 4] = [1, 2, 4, 8];

/// Parameters of `numbers.decode`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecodeParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the number's first byte.
    pub at: u64,
    /// Only this width in bytes: 1, 2, 4 or 8. Every width that fits when omitted.
    #[serde(default)]
    pub width: Option<usize>,
    /// Only this kind of number, such as "unsigned", "float" or "unix_seconds".
    #[serde(default)]
    pub kind: Option<NumberKind>,
    /// Only this byte order.
    #[serde(default)]
    pub little_endian: Option<bool>,
}

/// One way of reading the bytes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Decoding {
    pub interpretation: Interpretation,
    /// A short name such as "u32 LE" or "Unix seconds (u32 BE)".
    pub label: String,
    /// The value; timestamps are Unix seconds. Absent for NaN, infinities and impossible dates.
    pub value: Option<NumberValue>,
    /// The value as the app shows it, with dates written out.
    pub text: String,
}

/// The result of `numbers.decode`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DecodeResult {
    /// Offset of the number's first byte.
    pub at: u64,
    /// Every interpretation asked for that fits before the end of the document.
    pub decodings: Vec<Decoding>,
}

pub fn decode(workspace: &mut dyn Workspace, params: DecodeParams) -> Result<DecodeResult, ApiError> {
    if let Some(width) = params.width.filter(|width| !WIDTHS.contains(width)) {
        return Err(ApiError::invalid_params(format!("a width of {width} bytes is not supported; use 1, 2, 4 or 8")));
    }
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (at, available) = values::span_within(document.len(), params.at, None)?;
    if available == 0 {
        return Err(ApiError::out_of_range(format!("offset {at:#x} is the end of the document; there are no bytes to read")));
    }
    let bytes = document.read_range(at, available.min(8));
    let decodings = WIDTHS
        .into_iter()
        .filter(|&width| width <= bytes.len() && params.width.is_none_or(|wanted| wanted == width))
        .flat_map(numeric::interpretations)
        .filter(|interpretation| params.kind.is_none_or(|kind| kind == interpretation.kind))
        .filter(|interpretation| interpretation.width == 1 || params.little_endian.is_none_or(|order| order == interpretation.little_endian))
        .map(|interpretation| {
            let field = &bytes[..interpretation.width];
            Decoding { interpretation, label: interpretation.label(), value: exact_value(&interpretation, field), text: interpretation.display(field) }
        })
        .collect();
    Ok(DecodeResult { at: at as u64, decodings })
}

/// Integers exactly, as strings past 2^53; everything else as decoded.
fn exact_value(interpretation: &Interpretation, field: &[u8]) -> Option<NumberValue> {
    let raw = || {
        let fold = |value: u64, &byte: &u8| (value << 8) | u64::from(byte);
        if interpretation.little_endian { field.iter().rev().fold(0, fold) } else { field.iter().fold(0, fold) }
    };
    match interpretation.kind {
        NumberKind::Unsigned => Some(NumberValue::integer(i128::from(raw()))),
        NumberKind::Signed => {
            let unused = 64 - interpretation.width as u32 * 8;
            Some(NumberValue::integer(i128::from(((raw() << unused) as i64) >> unused)))
        }
        _ => interpretation.decode(field).map(NumberValue::Float),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::{ErrorCode, call};

    #[test]
    fn bytes_read_as_every_width_and_order_that_fits() {
        let mut workspace = workspace_with("a.bin", &[0x01, 0x00, 0x00, 0x00, 0xFF]);
        let decoded = call(&mut workspace, "numbers.decode", json!({"at": 0, "kind": "unsigned"})).unwrap();
        let labels: Vec<&str> = decoded["decodings"].as_array().unwrap().iter().map(|d| d["label"].as_str().unwrap()).collect();
        assert_eq!(labels, ["u8", "u16 LE", "u16 BE", "u32 LE", "u32 BE"], "eight-byte numbers do not fit");
        let u32_le = &decoded["decodings"][3];
        assert_eq!(u32_le["value"], 1);
        let signed = call(&mut workspace, "numbers.decode", json!({"at": 4, "width": 1, "kind": "signed"})).unwrap();
        assert_eq!(signed["decodings"][0]["value"], -1);
    }

    #[test]
    fn large_integers_are_strings_and_floats_are_numbers() {
        let mut workspace = workspace_with("a.bin", &[0xFF; 8]);
        let big = call(&mut workspace, "numbers.decode", json!({"at": 0, "width": 8, "kind": "unsigned", "little_endian": true})).unwrap();
        assert_eq!(big["decodings"][0]["value"], "18446744073709551615");
        let mut workspace = workspace_with("b.bin", &1.5f32.to_le_bytes());
        let float = call(&mut workspace, "numbers.decode", json!({"at": 0, "width": 4, "kind": "float", "little_endian": true})).unwrap();
        assert_eq!(float["decodings"][0]["value"], 1.5);
    }

    #[test]
    fn unsupported_widths_and_offsets_past_the_end_are_refused() {
        let mut workspace = workspace_with("a.bin", b"ab");
        assert_eq!(call(&mut workspace, "numbers.decode", json!({"at": 0, "width": 3})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "numbers.decode", json!({"at": 2})).unwrap_err().code, ErrorCode::OutOfRange);
    }
}
