//! Then anchors: a value another anchor finds, transformed: an offset plus a
//! header's length, a sector number times the sector size, text as the hex
//! of its bytes, the password after "password: " in a caption.
//!
//! ```json
//! {"of": {"var": "serial"}, "then": [{"encode": "text_to_hex"}]}
//! {"of": {"structure": "mbr", "field": "partitions[0].lba", "part": "value"}, "then": [{"mul": 512}]}
//! {"of": {"find": {"text": "ENDCRED"}}, "then": [{"sub": {"find": {"text": "CREDTBL"}, "part": "end"}}]}
//! ```
//!
//! The operations run in order, each on what the one before gave. The
//! number an arithmetic operation takes may be an anchor itself, written
//! bare as `of` is, which is resolved when the operation runs.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Anchor, ResolveContext};
use crate::api::ApiError;

/// One operation of a then anchor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Add a number or what an anchor finds: `{"add": 16}`.
    Add(Operand),
    /// Take a number away: `{"sub": 4}`.
    Sub(Operand),
    /// Multiply by a number: `{"mul": 512}`.
    Mul(Operand),
    /// Divide by a number, dropping any remainder: `{"div": 8}`.
    Div(Operand),
    /// The remainder after dividing by a number: `{"mod": 16}`.
    Mod(Operand),
    /// Keep the bits set in a mask: `{"and": 255}`.
    And(u64),
    /// Write text as the hex of its UTF-8 bytes, or hex as the text it
    /// spells: `{"encode": "text_to_hex"}`.
    Encode(Encoding),
    /// Read text as an integer, in decimal or 0x hex: `"int"`.
    Int,
    /// Write an integer as hex digits, without 0x, zero-padded to at least
    /// `width` digits: `{"hex": 2}` makes 10 "0a".
    Hex(usize),
    /// Part of a text (by characters) or a list: `{"slice": [start]}` to
    /// the end, `{"slice": [start, len]}`.
    Slice(Vec<usize>),
    /// The length of a text (in characters) or a list: `"len"`.
    Len,
    /// What a regex matches in a text: its first group when it has groups,
    /// else the whole match: `{"match": "password: (\\S+)"}`, or
    /// `{"match": {"regex": "(\\w+)=(\\w+)", "group": 2}}`.
    Match(Match),
    /// The text after the first occurrence of some text: `{"after": "password: "}`.
    After(String),
    /// The text before the first occurrence of some text: `{"before": ","}`.
    Before(String),
    /// A text cut at each separator: `{"split": [",", 1]}` gives the piece
    /// at that index (negative counts from the end), `{"split": ","}` every
    /// piece as a list.
    Split(Split),
    /// The value written into a text: `{"format": "FLAG{{{}}}"}`; `{}` or
    /// `{0}` is the value, `{1}` onwards what the anchors of `with` find,
    /// `{{` and `}}` braces: `{"format": {"text": "{0}-{1}", "with": [ANCHOR]}}`.
    Format(Format),
}

/// The number an arithmetic operation takes: a number, or an anchor (written
/// bare) whose value, read as an integer, is used.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Operand {
    Number(i64),
    Anchor(Box<Anchor>),
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

/// The regex of a `match`, and which group of it to give.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Match {
    /// The regex alone: its first group, or the whole match when it has none.
    Pattern(String),
    Group {
        regex: String,
        /// The group to give, counting from 1; 0 is the whole match.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<usize>,
    },
}

/// Where a `split` cuts, and which piece it gives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Split {
    /// `[separator, index]`: the piece at the index, negative from the end.
    Piece(String, i64),
    /// The separator alone: every piece, as a list.
    Pieces(String),
}

/// The text a `format` writes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Format {
    /// The text alone, with the value as `{}` or `{0}`.
    Text(String),
    With {
        text: String,
        /// The anchors whose values are `{1}`, `{2}` and on.
        with: Vec<Operand>,
    },
}

impl Operand {
    /// "16", or the anchor in words.
    pub fn describe(&self) -> String {
        match self {
            Operand::Number(number) => number.to_string(),
            Operand::Anchor(anchor) => format!("({})", anchor.describe()),
        }
    }

    /// The anchor this operand is, if it is one.
    pub fn anchor(&self) -> Option<&Anchor> {
        match self {
            Operand::Number(_) => None,
            Operand::Anchor(anchor) => Some(anchor),
        }
    }

    /// What the operand stands for when the operation runs.
    fn resolve(&self, context: &mut ResolveContext<'_>) -> Result<Value, ApiError> {
        match self {
            Operand::Number(number) => Ok(Value::from(*number)),
            Operand::Anchor(anchor) => anchor.resolve(context),
        }
    }

    /// The operand as an integer, for arithmetic.
    fn integer(&self, context: &mut ResolveContext<'_>) -> Result<i128, ApiError> {
        let value = self.resolve(context)?;
        integer_of(&value).ok_or_else(|| ApiError::invalid_params(format!("{} is {value}, which is not an integer", self.describe())))
    }

    fn renumbered(&self, renumber: &impl Fn(u64) -> Option<u64>) -> Option<Operand> {
        Some(match self {
            Operand::Number(number) => Operand::Number(*number),
            Operand::Anchor(anchor) => Operand::Anchor(Box::new(anchor.renumbered(renumber)?)),
        })
    }
}

impl Match {
    fn regex(&self) -> &str {
        match self {
            Match::Pattern(regex) | Match::Group { regex, .. } => regex,
        }
    }
}

impl Operation {
    /// "plus 16", "times 512", "as hex".
    pub fn describe(&self) -> String {
        match self {
            Operation::Add(operand) => format!("plus {}", operand.describe()),
            Operation::Sub(operand) => format!("minus {}", operand.describe()),
            Operation::Mul(operand) => format!("times {}", operand.describe()),
            Operation::Div(operand) => format!("divided by {}", operand.describe()),
            Operation::Mod(operand) => format!("modulo {}", operand.describe()),
            Operation::And(mask) => format!("masked with {mask:#x}"),
            Operation::Encode(Encoding::TextToHex) => "as the hex of its text".to_string(),
            Operation::Encode(Encoding::HexToText) => "as the text its hex spells".to_string(),
            Operation::Int => "read as an integer".to_string(),
            Operation::Hex(0) => "written in hex".to_string(),
            Operation::Hex(width) => format!("written in hex to {width} digits"),
            Operation::Slice(bounds) => match bounds.as_slice() {
                [start] => format!("from character {start}"),
                [start, len] => format!("{len} from {start}"),
                _ => "sliced".to_string(),
            },
            Operation::Len => "its length".to_string(),
            Operation::Match(found) => format!("what /{}/ matches", found.regex()),
            Operation::After(text) => format!("after '{text}'"),
            Operation::Before(text) => format!("before '{text}'"),
            Operation::Split(Split::Piece(separator, index)) => format!("piece {index} when split at '{separator}'"),
            Operation::Split(Split::Pieces(separator)) => format!("split at '{separator}'"),
            Operation::Format(Format::Text(text) | Format::With { text, .. }) => format!("written as '{text}'"),
        }
    }

    /// The anchors this operation takes as operands.
    pub fn operands(&self) -> Vec<&Anchor> {
        match self {
            Operation::Add(operand) | Operation::Sub(operand) | Operation::Mul(operand) | Operation::Div(operand) | Operation::Mod(operand) => operand.anchor().into_iter().collect(),
            Operation::Format(Format::With { with, .. }) => with.iter().filter_map(Operand::anchor).collect(),
            _ => Vec::new(),
        }
    }

    /// This operation with the steps its operands name changed as
    /// `renumber` says; `None` when one is not there to name.
    pub fn renumbered(&self, renumber: &impl Fn(u64) -> Option<u64>) -> Option<Operation> {
        Some(match self {
            Operation::Add(operand) => Operation::Add(operand.renumbered(renumber)?),
            Operation::Sub(operand) => Operation::Sub(operand.renumbered(renumber)?),
            Operation::Mul(operand) => Operation::Mul(operand.renumbered(renumber)?),
            Operation::Div(operand) => Operation::Div(operand.renumbered(renumber)?),
            Operation::Mod(operand) => Operation::Mod(operand.renumbered(renumber)?),
            Operation::Format(Format::With { text, with }) => {
                let with = with.iter().map(|operand| operand.renumbered(renumber)).collect::<Option<Vec<_>>>()?;
                Operation::Format(Format::With { text: text.clone(), with })
            }
            other => other.clone(),
        })
    }

    /// `value` after this operation; an operand that is an anchor is
    /// resolved in `context`.
    pub fn apply(&self, value: Value, context: &mut ResolveContext<'_>) -> Result<Value, ApiError> {
        match self {
            Operation::Add(operand) => {
                let number = operand.integer(context)?;
                arithmetic(&value, "add to", |held| held.checked_add(number))
            }
            Operation::Sub(operand) => {
                let number = operand.integer(context)?;
                arithmetic(&value, "take from", |held| held.checked_sub(number))
            }
            Operation::Mul(operand) => {
                let number = operand.integer(context)?;
                arithmetic(&value, "multiply", |held| held.checked_mul(number))
            }
            Operation::Div(operand) => {
                let number = nonzero(operand.integer(context)?, "divide")?;
                arithmetic(&value, "divide", |held| held.checked_div(number))
            }
            Operation::Mod(operand) => {
                let number = nonzero(operand.integer(context)?, "take the remainder of")?;
                arithmetic(&value, "take the remainder of", |held| held.checked_rem_euclid(number))
            }
            Operation::And(mask) => arithmetic(&value, "mask", |held| Some(held & i128::from(*mask))),
            Operation::Int => integer_of(&value).map(number_value).ok_or_else(|| ApiError::invalid_params(format!("{value} does not read as an integer"))),
            Operation::Hex(width) => {
                let number = integer_of(&value).ok_or_else(|| ApiError::invalid_params(format!("cannot write {value} in hex: it is not an integer")))?;
                if number < 0 {
                    return Err(ApiError::invalid_params(format!("cannot write {number} in hex: it is negative")));
                }
                Ok(Value::String(format!("{number:0width$x}")))
            }
            Operation::Encode(Encoding::TextToHex) => {
                let text = text_of(&value, "has no hex")?;
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
            Operation::Match(found) => matched(text_of(&value, "cannot be matched")?, found),
            Operation::After(marker) => {
                let text = text_of(&value, "has nothing after a text")?;
                let (_, after) = text.split_once(marker.as_str()).ok_or_else(|| ApiError::not_found(format!("'{marker}' does not occur in '{text}'")))?;
                Ok(Value::String(after.to_string()))
            }
            Operation::Before(marker) => {
                let text = text_of(&value, "has nothing before a text")?;
                let (before, _) = text.split_once(marker.as_str()).ok_or_else(|| ApiError::not_found(format!("'{marker}' does not occur in '{text}'")))?;
                Ok(Value::String(before.to_string()))
            }
            Operation::Split(split) => split_text(text_of(&value, "cannot be split")?, split),
            Operation::Format(Format::Text(text)) => format_text(text, &[value]),
            Operation::Format(Format::With { text, with }) => {
                let mut values = vec![value];
                for operand in with {
                    values.push(operand.resolve(context)?);
                }
                format_text(text, &values)
            }
        }
    }
}

/// `value` as text, or why it is not.
fn text_of<'a>(value: &'a Value, so: &str) -> Result<&'a str, ApiError> {
    value.as_str().ok_or_else(|| ApiError::invalid_params(format!("{value} is not text, so it {so}")))
}

fn nonzero(number: i128, verb: &str) -> Result<i128, ApiError> {
    if number == 0 {
        return Err(ApiError::invalid_params(format!("cannot {verb} by 0")));
    }
    Ok(number)
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

/// What `found`'s regex matches first in `text`: the group it asks for,
/// else the first group, else the whole match.
fn matched(text: &str, found: &Match) -> Result<Value, ApiError> {
    let pattern = found.regex();
    let regex = regex_lite::Regex::new(pattern).map_err(|error| ApiError::invalid_params(format!("the regex /{pattern}/ does not read: {error}")))?;
    let groups = regex.captures_len() - 1;
    let group = match found {
        Match::Group { group: Some(group), .. } => *group,
        _ => usize::from(groups > 0),
    };
    if group > groups {
        return Err(ApiError::invalid_params(format!("/{pattern}/ has {groups} group{}, so there is no group {group}", if groups == 1 { "" } else { "s" })));
    }
    let captures = regex.captures(text).ok_or_else(|| ApiError::not_found(format!("/{pattern}/ does not match '{text}'")))?;
    let piece = captures.get(group).ok_or_else(|| ApiError::not_found(format!("group {group} of /{pattern}/ took no part in matching '{text}'")))?;
    Ok(Value::String(piece.as_str().to_string()))
}

fn split_text(text: &str, split: &Split) -> Result<Value, ApiError> {
    let (separator, index) = match split {
        Split::Piece(separator, index) => (separator, Some(*index)),
        Split::Pieces(separator) => (separator, None),
    };
    if separator.is_empty() {
        return Err(ApiError::invalid_params("a split needs a separator that is not empty"));
    }
    let pieces: Vec<&str> = text.split(separator.as_str()).collect();
    let Some(index) = index else {
        return Ok(Value::Array(pieces.into_iter().map(|piece| Value::String(piece.to_string())).collect()));
    };
    let count = pieces.len() as i64;
    let at = if index < 0 { count + index } else { index };
    usize::try_from(at)
        .ok()
        .and_then(|at| pieces.get(at))
        .map(|piece| Value::String(piece.to_string()))
        .ok_or_else(|| ApiError::out_of_range(format!("'{text}' split at '{separator}' has {count} piece{}, so there is no piece {index}", if count == 1 { "" } else { "s" })))
}

/// `template` with each `{}` or `{n}` replaced by a value (`{}` the next
/// in turn, from the first), and `{{` and `}}` as braces.
fn format_text(template: &str, values: &[Value]) -> Result<Value, ApiError> {
    let invalid = |why: String| ApiError::invalid_params(format!("the format '{template}' {why}; write {{}} or {{0}} for the value, {{1}} onwards for what `with` finds, and {{{{ or }}}} for a brace"));
    let mut written = String::new();
    let mut next = 0;
    let mut characters = template.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '{' if characters.peek() == Some(&'{') => {
                characters.next();
                written.push('{');
            }
            '}' if characters.peek() == Some(&'}') => {
                characters.next();
                written.push('}');
            }
            '{' => {
                let mut inside = String::new();
                loop {
                    match characters.next() {
                        Some('}') => break,
                        Some(character) => inside.push(character),
                        None => return Err(invalid("has a { that is not closed".to_string())),
                    }
                }
                let index = if inside.is_empty() {
                    next += 1;
                    next - 1
                } else {
                    inside.trim().parse::<usize>().map_err(|_| invalid(format!("has {{{inside}}}, which is not a number")))?
                };
                let value = values.get(index).ok_or_else(|| invalid(format!("asks for value {index}, and there {}", if values.len() == 1 { "is only the one".to_string() } else { format!("are {}", values.len()) })))?;
                match value {
                    Value::String(text) => written.push_str(text),
                    other => written.push_str(&other.to_string()),
                }
            }
            '}' => return Err(invalid("has a } that opens nothing".to_string())),
            other => written.push(other),
        }
    }
    Ok(Value::String(written))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::super::RunSheets;
    use super::*;

    fn apply_all_on(contents: &[u8], value: Value, operations: Value) -> Result<Value, ApiError> {
        let operations: Vec<Operation> = serde_json::from_value(operations).unwrap();
        let mut workspace = crate::api::test_support::workspace_with("a.bin", contents);
        let sheets = RunSheets::on("doc-1");
        let none = BTreeMap::new();
        let mut context = ResolveContext { workspace: &mut workspace, doc: None, steps: &none, parameters: &BTreeMap::new(), sheets: &sheets, warnings: Vec::new() };
        let mut value = value;
        for operation in &operations {
            value = operation.apply(value, &mut context)?;
        }
        Ok(value)
    }

    fn apply_all(value: Value, operations: Value) -> Result<Value, ApiError> {
        apply_all_on(b"", value, operations)
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
    fn a_period_in_bits_becomes_bytes_and_an_offset_its_place_in_a_row() {
        assert_eq!(apply_all(json!(96), json!([{"div": 8}])).unwrap(), json!(12));
        assert_eq!(apply_all(json!(99), json!([{"div": 8}])).unwrap(), json!(12), "the remainder is dropped");
        assert_eq!(apply_all(json!(100), json!([{"mod": 48}])).unwrap(), json!(4));
        assert!(apply_all(json!(100), json!([{"div": 0}])).unwrap_err().message.contains("cannot divide by 0"));
    }

    #[test]
    fn the_length_between_two_markers_is_one_anchor_taken_from_another() {
        let contents = b"....CREDTBL\0rows rows rows ENDCRED....";
        let between = json!([{"sub": {"find": {"text": "CREDTBL"}, "part": "end"}}, {"sub": 1}]);
        let ended = apply_all_on(contents, json!(27), between).unwrap();
        assert_eq!(ended, json!(15), "ENDCRED at 27, less the end of CREDTBL (11) and its NUL");
        let missing = apply_all_on(contents, json!(27), json!([{"add": {"find": {"text": "NOPE"}}}])).unwrap_err();
        assert!(missing.message.contains("the 1st match of the text 'NOPE' did not resolve"), "{}", missing.message);
    }

    #[test]
    fn a_number_becomes_the_hex_a_preamble_is_written_in() {
        assert_eq!(apply_all(json!(0xaa), json!([{"hex": 2}])).unwrap(), json!("aa"));
        assert_eq!(apply_all(json!(10), json!([{"hex": 4}])).unwrap(), json!("000a"));
        assert_eq!(apply_all(json!("0x1F40"), json!([{"hex": 0}])).unwrap(), json!("1f40"));
        assert!(apply_all(json!(-1), json!([{"hex": 2}])).is_err());
    }

    #[test]
    fn a_password_is_taken_from_its_caption_without_counting_characters() {
        let caption = json!("reminder - backup.zip password: Kestrel!Moor42");
        assert_eq!(apply_all(caption.clone(), json!([{"match": "password: (\\S+)"}])).unwrap(), json!("Kestrel!Moor42"));
        assert_eq!(apply_all(caption.clone(), json!([{"after": "password: "}])).unwrap(), json!("Kestrel!Moor42"));
        assert_eq!(apply_all(caption.clone(), json!([{"before": " - "}])).unwrap(), json!("reminder"));
        assert_eq!(apply_all(caption.clone(), json!([{"match": {"regex": "(\\w+)\\.(zip)", "group": 2}}])).unwrap(), json!("zip"));
        assert_eq!(apply_all(caption.clone(), json!([{"match": "zip"}])).unwrap(), json!("zip"), "with no group, the whole match");
        assert!(apply_all(caption.clone(), json!([{"match": "secret: (\\S+)"}])).unwrap_err().message.contains("does not match"));
        assert!(apply_all(caption, json!([{"after": "pin: "}])).unwrap_err().message.contains("'pin: ' does not occur"));
    }

    #[test]
    fn a_field_of_a_csv_line_is_taken_by_its_place() {
        let line = json!("7,FLAG{deleted_not_forgotten_44cb},ok");
        assert_eq!(apply_all(line.clone(), json!([{"split": [",", 1]}])).unwrap(), json!("FLAG{deleted_not_forgotten_44cb}"));
        assert_eq!(apply_all(line.clone(), json!([{"split": [",", -1]}])).unwrap(), json!("ok"));
        assert_eq!(apply_all(line.clone(), json!([{"split": ","}, "len"])).unwrap(), json!(3));
        assert_eq!(apply_all(line, json!([{"split": [",", 3]}])).unwrap_err().code, crate::api::ErrorCode::OutOfRange);
    }

    #[test]
    fn values_are_written_into_text() {
        assert_eq!(apply_all(json!("54287072"), json!([{"format": "FLAG{{{}}}"}])).unwrap(), json!("FLAG{54287072}"));
        let joined = json!([{"format": {"text": "{0}-{1}", "with": [{"find": {"text": "B"}}]}}]);
        assert_eq!(apply_all_on(b"AB", json!(7), joined).unwrap(), json!("7-1"));
        assert!(apply_all(json!(1), json!([{"format": "{2}"}])).unwrap_err().message.contains("asks for value 2"));
        assert!(apply_all(json!(1), json!([{"format": "{"}])).is_err());
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

    #[test]
    fn an_unknown_operation_is_named_with_those_there_are() {
        let error = serde_json::from_value::<Operation>(json!({"regex": "x"})).unwrap_err().to_string();
        assert!(error.contains("unknown variant `regex`") && error.contains("`match`"), "{error}");
    }
}
