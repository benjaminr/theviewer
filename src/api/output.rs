//! The `output` parameter: where what a method produces goes.
//!
//! A method that produces bytes (a decode, a transform, a node unpacked,
//! some packets' fields) takes `output`, one of:
//!
//! | `output` | Where the bytes go | The result's `output` |
//! | --- | --- | --- |
//! | `"in_place"` | over the bytes they came from, as one undoable edit | `{version, len, ranges}` |
//! | `"new"`, `{"new": {"label", "name", "focus"}}` | a new sheet derived from the document read | `{doc, label?, len}` |
//! | `"return"`, `{"return": {"encoding"}}` | the result, as hex, base64 or text | `{len, encoding, data}` |
//! | `{"file": path}` | a file, which needs leave to edit | `{path, len}` |
//!
//! Each method declares the outputs it offers and its default
//! ([`super::Method::outputs`]), which `api.describe` lists; the journal
//! treats each call as its output says, so a call with `output: "new"`
//! makes a sheet, kept by recipes, and one in place is a byte edit. A
//! method works out its bytes and hands them to [`deliver`].

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::permissions::Caller;
use super::values::{self, ByteEncoding};
use super::workspace::{self, Workspace};
use super::{ApiError, ErrorCode, OutputKind};
use crate::selection::Selection;

/// Where a call's output goes, as its `output` parameter says.
#[derive(Clone, Debug, PartialEq)]
pub enum Output {
    /// Over the bytes it came from, as one undoable edit.
    InPlace,
    /// A new sheet, derived from the document read.
    New(NewSheet),
    /// Bytes in the result, written as `encoding` says (or as the call's
    /// own `encoding`, or hex).
    Return { encoding: Option<ByteEncoding> },
    /// A file, which needs leave to edit.
    File(String),
}

/// How to make the new sheet `output: {"new": …}` asks for.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewSheet {
    /// A short name for the sheet, such as "payload": its lineage keeps it,
    /// and a recipe made from the session names the sheet by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// What to call the new document; the method names it after where it
    /// came from when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Make the new sheet the document later calls that omit `doc` are
    /// about.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub focus: bool,
}

/// How to write the bytes `output: {"return": …}` returns.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReturnedBytes {
    /// hex, base64 or text; the call's own `encoding` (or hex) when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encoding: Option<ByteEncoding>,
}

/// The forms `output` is written in, for its JSON Schema.
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
#[allow(dead_code)]
enum OutputForm {
    /// "in_place", "new" or "return".
    Named(OutputName),
    /// {"new": {"label": "payload"}}, {"return": {"encoding": "text"}} or {"file": "/path/out.bin"}.
    Detailed(OutputDetail),
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(dead_code)]
enum OutputName {
    /// Over the bytes it came from, as one undoable edit.
    InPlace,
    /// A new sheet derived from the document read.
    New,
    /// Bytes in the result.
    Return,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[allow(dead_code)]
enum OutputDetail {
    /// A new sheet, with a label, name or focus.
    New(NewSheet),
    /// Bytes in the result, written as encoding says.
    Return(ReturnedBytes),
    /// The path of a file to write, which needs leave to edit.
    File(String),
}

impl Output {
    /// Where it goes.
    pub fn kind(&self) -> OutputKind {
        match self {
            Output::InPlace => OutputKind::InPlace,
            Output::New(_) => OutputKind::New,
            Output::Return { .. } => OutputKind::Return,
            Output::File(_) => OutputKind::File,
        }
    }

    /// The output `kind` names with nothing more said: a new sheet named by
    /// its method, bytes as the call's encoding says. A file needs its path,
    /// so it is never a default.
    fn plain(kind: OutputKind) -> Option<Output> {
        match kind {
            OutputKind::InPlace => Some(Output::InPlace),
            OutputKind::New => Some(Output::New(NewSheet::default())),
            OutputKind::Return => Some(Output::Return { encoding: None }),
            OutputKind::File => None,
        }
    }

    /// `output` as JSON gives it, or why it is not one.
    pub fn parse(value: &Value) -> Result<Output, String> {
        const FORMS: &str = "write output as \"in_place\", \"new\", \"return\", {\"new\": {\"label\": …}}, {\"return\": {\"encoding\": …}} or {\"file\": \"/path\"}";
        match value {
            Value::String(name) => match name.as_str() {
                "in_place" => Ok(Output::InPlace),
                "new" => Ok(Output::New(NewSheet::default())),
                "return" => Ok(Output::Return { encoding: None }),
                "file" => Err("a file output needs its path: {\"file\": \"/path/out.bin\"}".to_string()),
                other => Err(format!("'{other}' is not an output; {FORMS}")),
            },
            Value::Object(fields) if fields.len() == 1 => {
                let (name, detail) = fields.iter().next().expect("one field");
                match name.as_str() {
                    "new" => serde_json::from_value(detail.clone()).map(Output::New).map_err(|error| format!("output.new: {error}")),
                    "return" => serde_json::from_value::<ReturnedBytes>(detail.clone()).map(|bytes| Output::Return { encoding: bytes.encoding }).map_err(|error| format!("output.return: {error}")),
                    "file" => match detail.as_str() {
                        Some(path) if !path.is_empty() => Ok(Output::File(path.to_string())),
                        _ => Err("output.file is the path of the file to write, as a string".to_string()),
                    },
                    "in_place" => Ok(Output::InPlace),
                    other => Err(format!("'{other}' is not an output; {FORMS}")),
                }
            }
            _ => Err(FORMS.to_string()),
        }
    }

    /// The output as JSON writes it, in its shortest form.
    fn to_json(&self) -> Value {
        match self {
            Output::InPlace => json!("in_place"),
            Output::New(sheet) if *sheet == NewSheet::default() => json!("new"),
            Output::New(sheet) => json!({ "new": sheet }),
            Output::Return { encoding: None } => json!("return"),
            Output::Return { encoding: Some(encoding) } => json!({ "return": { "encoding": encoding } }),
            Output::File(path) => json!({ "file": path }),
        }
    }
}

impl<'de> Deserialize<'de> for Output {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Output::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Output {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(serializer)
    }
}

impl JsonSchema for Output {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("Output")
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        OutputForm::json_schema(generator)
    }
}

/// Where the JSON `output` sends a call's output, if it is one; the API
/// reads it to treat the call as its output says.
pub fn kind_of(value: &Value) -> Option<OutputKind> {
    Output::parse(value).ok().map(|output| output.kind())
}

/// The output a call of `method` asked for, or its default, checked
/// against the outputs the method offers.
pub fn chosen(method: &str, given: Option<Output>) -> Result<Output, ApiError> {
    let outputs = super::method(method).and_then(|method| method.outputs).ok_or_else(|| ApiError::invalid_params(format!("{method} takes no output")))?;
    let output = match given {
        Some(output) => output,
        None => Output::plain(outputs.default).expect("a default output needs nothing more said"),
    };
    if !outputs.allows(output.kind()) {
        let offered: Vec<&str> = outputs.allowed.iter().map(|kind| kind.name()).collect();
        return Err(ApiError::invalid_params(format!("{method} cannot send its output {}: it offers {}", described(output.kind()), offered.join(", "))));
    }
    Ok(output)
}

/// "in place", "to a new sheet"…, for messages.
fn described(kind: OutputKind) -> &'static str {
    match kind {
        OutputKind::InPlace => "in place",
        OutputKind::New => "to a new sheet",
        OutputKind::Return => "back in the result",
        OutputKind::File => "to a file",
    }
}

/// What a method produced, for [`deliver`]: its new bytes, piece by piece,
/// each with the span of the document read it replaces in place.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Produced {
    pub pieces: Vec<Piece>,
    /// What to call a new sheet when the call names none: "fw.bin › zlib@0x10".
    pub name: String,
    /// What an edit in place is called in the undo history: "Decode base32".
    pub action: String,
    /// How returned bytes are written when the output says nothing.
    pub encoding: ByteEncoding,
}

/// Some new bytes, and the span of the document read they replace in
/// place, as [start, len]; none where they came from no one span.
#[derive(Clone, Debug, PartialEq)]
pub struct Piece {
    pub replaces: Option<(usize, usize)>,
    pub bytes: Vec<u8>,
}

impl Produced {
    /// `bytes`, from no one span, for a new sheet called `name`.
    pub fn bytes(bytes: Vec<u8>, name: impl Into<String>) -> Self {
        Produced { pieces: vec![Piece { replaces: None, bytes }], name: name.into(), ..Produced::default() }
    }

    /// `bytes`, which replace `len` bytes at `start` in place.
    pub fn replacing(start: usize, len: usize, bytes: Vec<u8>, name: impl Into<String>, action: impl Into<String>) -> Self {
        Produced { pieces: vec![Piece { replaces: Some((start, len)), bytes }], name: name.into(), action: action.into(), ..Produced::default() }
    }

    /// Returned bytes are written as `encoding` unless the output says.
    pub fn encoded(mut self, encoding: ByteEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// Every piece's bytes, one after another.
    fn joined(&self) -> Vec<u8> {
        let mut joined = Vec::with_capacity(self.len());
        for piece in &self.pieces {
            joined.extend_from_slice(&piece.bytes);
        }
        joined
    }

    /// Bytes in every piece.
    pub fn len(&self) -> usize {
        self.pieces.iter().map(|piece| piece.bytes.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Where a call's output went, as its result gives it under `output`: the
/// one place later steps look.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Delivered {
    /// For `new`: the sheet made, such as "doc-5".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    /// For `new`: the label it was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Bytes delivered: the new sheet's length, the bytes written in place,
    /// returned or written to the file.
    pub len: u64,
    /// For `in_place`: the document's version after the edit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// For `in_place`: where the new bytes are now, as [start, len].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<(u64, u64)>>,
    /// For `return`: how `data` is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<ByteEncoding>,
    /// For `return`: the bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// For `file`: the file written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// The result of a method whose output is a new sheet by default: the
/// sheet made, as `documents.info` gives it, and where the output went.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Made {
    /// The sheet made, when the output was a new sheet.
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub document: Option<workspace::DocumentInfo>,
    /// Where the output went: {doc, label, len} for a new sheet, {len, encoding, data} returned, {path, len} to a file.
    pub output: Delivered,
}

impl Made {
    /// The result of a call whose output went where `delivered` says.
    pub fn of(workspace: &dyn Workspace, delivered: Delivered) -> Result<Made, ApiError> {
        let document = match &delivered.doc {
            Some(id) => Some(workspace::info(workspace, id)?),
            None => None,
        };
        Ok(Made { document, output: delivered })
    }
}

/// Send what a method `produced` from document `input` where `output`
/// says, for `caller`: edit `input` in place (each piece over the span it
/// replaces, as one undo step, selecting the new bytes), open a new sheet
/// derived from it, return the bytes, or write them to a file.
pub fn deliver(workspace: &mut dyn Workspace, caller: &Caller, input: &str, produced: Produced, output: &Output) -> Result<Delivered, ApiError> {
    match output {
        Output::InPlace => in_place(workspace, caller, input, produced),
        Output::New(sheet) => {
            let len = produced.len() as u64;
            let name = sheet.name.clone().unwrap_or(produced.name.clone());
            let doc = workspace.open_derived(input, produced.joined(), &name)?;
            Ok(Delivered { doc: Some(doc), label: sheet.label.clone(), len, ..Delivered::default() })
        }
        Output::Return { encoding } => {
            values::check_call_size(produced.len())?;
            let encoding = encoding.unwrap_or(produced.encoding);
            let data = values::encode_bytes(&produced.joined(), encoding);
            Ok(Delivered { len: produced.len() as u64, encoding: Some(encoding), data: Some(data), ..Delivered::default() })
        }
        Output::File(path) => {
            std::fs::write(path, produced.joined()).map_err(|error| ApiError::new(ErrorCode::Unavailable, format!("could not write {path}: {error}")))?;
            Ok(Delivered { len: produced.len() as u64, path: Some(path.clone()), ..Delivered::default() })
        }
    }
}

/// Write each piece over the span it replaces, from the last back, as one
/// undo step named for the method's action, and select the new bytes.
fn in_place(workspace: &mut dyn Workspace, caller: &Caller, input: &str, produced: Produced) -> Result<Delivered, ApiError> {
    let mut pieces = Vec::with_capacity(produced.pieces.len());
    for piece in produced.pieces {
        let Some(span) = piece.replaces else {
            return Err(ApiError::invalid_params("these bytes came from no one span of the document, so they cannot replace it in place; use output \"new\""));
        };
        pieces.push((span, piece.bytes));
    }
    pieces.sort_by_key(|((start, _), _)| *start);
    if pieces.windows(2).any(|pair| pair[0].0.0 + pair[0].0.1 > pair[1].0.0) {
        return Err(ApiError::invalid_params("the spans to replace overlap, so they cannot be replaced in place"));
    }
    let written: usize = pieces.iter().map(|(_, bytes)| bytes.len()).sum();
    let mut ranges = Vec::with_capacity(pieces.len());
    let mut shift: isize = 0;
    for &((start, len), ref bytes) in &pieces {
        ranges.push(((start as isize + shift) as usize, bytes.len()));
        shift += bytes.len() as isize - len as isize;
    }
    let action = if produced.action.is_empty() { "Replace in place".to_string() } else { produced.action };
    let (id, (), _) = super::edits::edit(workspace, caller, Some(input), None, &action, |document| {
        let len = document.len();
        if let Some(((start, span), _)) = pieces.iter().find(|((start, span), _)| start + span > len) {
            return Err(ApiError::out_of_range(format!("{start:#x}+{span} runs past the end of the document ({len} bytes)")));
        }
        for ((start, len), bytes) in pieces.iter().rev() {
            document.replace(*start, *len, bytes);
        }
        Ok(())
    })?;
    let changed: Vec<(usize, usize)> = ranges.iter().copied().filter(|&(_, len)| len > 0).collect();
    let selection = match changed.as_slice() {
        [] => None,
        [(start, len)] => Some(Selection::Range(*start, *len)),
        _ => Some(Selection::Ranges(changed.clone())),
    };
    let cursor = changed.last().map_or(ranges.first().map_or(0, |range| range.0), |&(start, len)| start + len);
    workspace.select(&id, cursor, selection, caller);
    let version = workspace::info(workspace, &id)?.version;
    Ok(Delivered {
        len: written as u64,
        version: Some(version),
        ranges: Some(ranges.into_iter().map(|(start, len)| (start as u64, len as u64)).collect()),
        ..Delivered::default()
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{NewSheet, Output};
    use crate::api::OutputKind;
    use crate::api::values::ByteEncoding;

    #[test]
    fn every_form_of_output_reads_and_writes_back_as_given() {
        for (given, expected) in [
            (json!("in_place"), Output::InPlace),
            (json!("new"), Output::New(NewSheet::default())),
            (json!({"new": {"label": "payload", "focus": true}}), Output::New(NewSheet { label: Some("payload".into()), name: None, focus: true })),
            (json!("return"), Output::Return { encoding: None }),
            (json!({"return": {"encoding": "text"}}), Output::Return { encoding: Some(ByteEncoding::Text) }),
            (json!({"file": "/tmp/out.bin"}), Output::File("/tmp/out.bin".into())),
        ] {
            let output: Output = serde_json::from_value(given.clone()).unwrap();
            assert_eq!(output, expected, "{given}");
            assert_eq!(serde_json::to_value(&output).unwrap(), given);
        }
        assert_eq!(super::kind_of(&json!({"new": {}})), Some(OutputKind::New));
    }

    mod through_the_api {
        use serde_json::{Value, json};

        use crate::api::test_support::{call, workspace_with};
        use crate::api::{ErrorCode, Workspace};

        fn read_all(workspace: &mut crate::api::HeadlessWorkspace, doc: &str) -> Value {
            call(workspace, "bytes.read", json!({"doc": doc, "start": 0})).unwrap()["data"].clone()
        }

        #[test]
        fn a_labelled_sheet_made_with_output_new_is_made_again_by_its_recipe_on_another_file() {
            let mut workspace = workspace_with("stage.bin", b"\x01\x02\x03\x04rest");
            let made = call(&mut workspace, "transform.apply", json!({"selection": {"range": [0, 4]}, "operation": {"op": "xor", "key": "ff"}, "output": {"new": {"label": "plain"}}})).unwrap();
            assert_eq!(made["output"], json!({"doc": "doc-2", "label": "plain", "len": 4}), "the one place a later step looks");
            assert_eq!(read_all(&mut workspace, "doc-1"), "0102030472657374", "the input is left as it was");
            assert_eq!(read_all(&mut workspace, "doc-2"), "fefdfcfb");
            let info = call(&mut workspace, "documents.info", json!({"doc": "doc-2"})).unwrap();
            assert_eq!((info["parent"].as_str(), info["label"].as_str(), info["made_by"]["method"].as_str()), (Some("doc-1"), Some("plain"), Some("transform.apply")));
            call(&mut workspace, "transform.apply", json!({"doc": "doc-2", "selection": {"range": [0, 2]}, "operation": {"op": "invert"}})).unwrap();

            let recipe = call(&mut workspace, "history.recipe", json!({"name": "Peel"})).unwrap();
            let steps = recipe["steps"].as_array().unwrap();
            assert_eq!((steps[0]["method"].as_str(), steps[0]["makes"].as_str()), (Some("transform.apply"), Some("plain")), "{recipe}");
            assert_eq!(steps[1]["params"]["doc"], json!({"$anchor": {"sheet": "plain"}}), "the later step names the sheet by its label");

            let mut other = workspace_with("other.bin", b"\x10\x20\x30\x40more");
            let report = call(&mut other, "recipes.run", json!({"recipe": recipe})).unwrap();
            assert!(report["stopped"].is_null(), "{report}");
            assert_eq!(read_all(&mut other, "doc-2"), "1020cfbf", "the sheet made again, then edited");
            assert_eq!(read_all(&mut other, "doc-1"), "102030406d6f7265", "the other file is left as it was");
        }

        #[test]
        fn bytes_returned_change_nothing_and_are_kept_among_the_reads() {
            let mut workspace = workspace_with("a.bin", b"hello");
            let steps_before = workspace.journal().entries().count();
            let returned = call(&mut workspace, "transform.apply", json!({"selection": {"range": [0, 5]}, "operation": {"op": "xor", "key": "20"}, "output": {"return": {"encoding": "text"}}})).unwrap();
            assert_eq!(returned["output"], json!({"len": 5, "encoding": "text", "data": "HELLO"}));
            assert!(returned.get("version").is_none(), "nothing was edited");
            assert_eq!(read_all(&mut workspace, "doc-1"), "68656c6c6f");
            assert_eq!(workspace.journal().entries().count(), steps_before, "a read, not a step");
            let encoded = call(&mut workspace, "transform.apply", json!({"selection": {"range": [0, 2]}, "operation": {"op": "invert"}, "output": "return", "encoding": "base64"})).unwrap();
            assert_eq!(encoded["output"]["data"], "l5o=", "the call's own encoding when the output names none");
        }

        #[test]
        fn an_edit_in_place_replaces_what_was_decoded_as_one_undo_step() {
            let mut packed = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut packed, b"hello, hello").unwrap();
            let packed = packed.finish().unwrap();
            let mut workspace = workspace_with("a.bin", &[b"head".as_slice(), &packed, b"tail"].concat());
            let decoded = call(&mut workspace, "codecs.decode", json!({"start": 4, "len": packed.len(), "codec": "zlib", "output": "in_place"})).unwrap();
            assert_eq!((decoded["output"]["ranges"].clone(), decoded["output"]["len"].as_u64()), (json!([[4, 12]]), Some(12)));
            assert!(decoded["output"]["version"].as_u64().is_some() && decoded.get("data").is_none());
            let text = call(&mut workspace, "bytes.read", json!({"start": 0, "encoding": "text"})).unwrap();
            assert_eq!(text["data"], "headhello, hellotail");
            let selected = call(&mut workspace, "selection.get", json!({})).unwrap();
            assert_eq!(selected["selection"], json!({"range": [4, 12]}), "what was decoded is selected");
            call(&mut workspace, "history.undo", json!({})).unwrap();
            assert_eq!(call(&mut workspace, "bytes.read", json!({"start": 4, "len": 1})).unwrap()["data"], "78", "one undo puts the stream back");
        }

        #[test]
        fn an_output_a_method_does_not_offer_is_refused_saying_which_it_does() {
            let mut workspace = workspace_with("a.bin", b"0123456789");
            let refused = call(&mut workspace, "documents.derive", json!({"start": 0, "len": 2, "output": "in_place"})).unwrap_err();
            assert_eq!(refused.code, ErrorCode::InvalidParams);
            assert!(refused.message.contains("offers new, file"), "{}", refused.message);
            let unreadable = call(&mut workspace, "transform.apply", json!({"operation": {"op": "invert"}, "output": "sideways"})).unwrap_err();
            assert!(unreadable.message.contains("not an output"), "{}", unreadable.message);
        }
    }

    #[test]
    fn an_output_that_is_not_one_says_how_to_write_one() {
        for (given, said) in [
            (json!("file"), "needs its path"),
            (json!("sideways"), "'sideways' is not an output"),
            (json!({"new": {"colour": "red"}}), "output.new"),
            (json!({"file": 3}), "path of the file"),
            (json!(7), "write output as"),
        ] {
            let error = Output::parse(&given).unwrap_err();
            assert!(error.contains(said), "{given}: {error}");
        }
    }
}
