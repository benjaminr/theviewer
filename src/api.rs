//! The data API: one table of methods over documents, bytes, bits,
//! selections, findings, structures, codecs, packets and analysis, each
//! declared once with its name, effect and JSON schemas.
//!
//! Every way in uses the same table: Ask's tools are generated from it, the
//! command line runs one method (`theviewer api bytes.read '{…}' FILE`), and
//! `api.describe` lists the table with its schemas. Rust callers use the typed
//! functions in each namespace module directly; JSON callers go through
//! [`call`], which checks the parameters against the method's types.
//!
//! Methods run against a [`Workspace`]: the window's open document, or a
//! [`HeadlessWorkspace`] of files opened from paths. See
//! `docs/design/shared-knowledge-and-api.md` for the design.
//!
//! Conventions every method follows:
//!
//! * Documents are named by id (`doc-1`), by path, or as `"current"`, which
//!   is also what an omitted `doc` means.
//! * Spans are `start` and `len` in bytes and must lie inside the document;
//!   an omitted `len` runs to the end.
//! * Bytes in JSON are hex strings unless `encoding` asks for `base64` or
//!   `text`.
//! * Integers larger than 2^53 are written as strings.
//! * List methods take `limit` and return `next`, an opaque cursor to pass
//!   back for the following page.
//! * One call reads or returns at most [`MAX_CALL_BYTES`].

pub mod analysis;
pub mod bytes;
pub mod codecs;
pub mod documents;
pub mod findings;
pub mod numbers;
pub mod packets;
pub mod reference;
pub mod search;
pub mod selection;
pub mod structure;
pub mod values;
pub mod workspace;

use std::fmt;

use schemars::{JsonSchema, Schema};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use workspace::{HeadlessWorkspace, Workspace};

/// The API version, which `api.version` returns. Within a major version
/// changes are additive only.
pub const API_VERSION: &str = "1.0";

/// Most bytes one call reads or returns: 16 MiB. Larger work will be a job.
pub const MAX_CALL_BYTES: usize = 16 * 1024 * 1024;

/// What calling a method does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Looks without changing anything.
    Read,
    /// Changes a document's bytes, as one undoable step.
    Edit,
    /// Changes what is shown or open, but no bytes.
    View,
    /// Starts long-running work and returns a job to follow.
    Job,
}

/// Whether a method's name, parameters and results are settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Stability {
    /// Changes only by addition within the major version.
    Stable,
    /// May change in any release.
    Experimental,
}

/// One method of the API, declared once.
pub struct Method {
    /// Dotted name, such as `bytes.read`.
    pub name: &'static str,
    /// One sentence on what the method does, for tool lists and the reference.
    pub summary: &'static str,
    pub effect: Effect,
    pub stability: Stability,
    /// JSON Schema of the parameters.
    pub params: fn() -> Schema,
    /// JSON Schema of the result.
    pub result: fn() -> Schema,
    /// Check the JSON parameters, run the method and return its JSON result.
    pub run: fn(&mut dyn Workspace, Value) -> Result<Value, ApiError>,
}

impl Method {
    /// The namespace, such as `bytes` for `bytes.read`.
    pub fn namespace(&self) -> &'static str {
        self.name.split_once('.').map_or(self.name, |(namespace, _)| namespace)
    }
}

/// Why a call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The parameters don't match the schema.
    InvalidParams,
    /// A span falls outside the document.
    OutOfRange,
    /// No such document, method or entry.
    NotFound,
    /// The document changed since `expect_version`.
    VersionConflict,
    /// The caller may not edit.
    ReadOnly,
    /// Over the per-call limit.
    TooLarge,
    /// A job was cancelled.
    Cancelled,
    /// A plugin raised an error or used up its budget.
    PluginFailed,
    /// Something needed is missing, such as tshark.
    Unavailable,
}

/// A failed call: a code to act on, a message saying what to do next, and
/// any details.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError { code, message: message.into(), data: None }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidParams, message)
    }

    pub fn out_of_range(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::OutOfRange, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    pub fn too_large(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::TooLarge, message)
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// The error as JSON, as the command line and Ask report it.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| Value::String(self.message.clone()))
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", serde_json::to_value(self.code).ok().and_then(|code| code.as_str().map(str::to_string)).unwrap_or_default(), self.message)
    }
}

impl std::error::Error for ApiError {}

/// The schema of a type, for the method table.
fn schema_of<T: JsonSchema>() -> Schema {
    schemars::schema_for!(T)
}

/// Run a typed method on JSON parameters: missing parameters count as `{}`,
/// and parameters that do not fit the method's type are `invalid_params`.
fn run_typed<P: DeserializeOwned, R: Serialize>(
    function: fn(&mut dyn Workspace, P) -> Result<R, ApiError>,
    workspace: &mut dyn Workspace,
    params: Value,
) -> Result<Value, ApiError> {
    let params = if params.is_null() { Value::Object(Default::default()) } else { params };
    let typed: P = serde_json::from_value(params).map_err(|error| ApiError::invalid_params(format!("{error}; see the method's params schema in api.describe")))?;
    let result = function(workspace, typed)?;
    serde_json::to_value(result).map_err(|error| ApiError::new(ErrorCode::InvalidParams, format!("the result could not be written as JSON: {error}")))
}

/// One row of the method table: name, effect, typed function, its params
/// and result types, and the summary.
macro_rules! method {
    ($name:literal, $effect:ident, $function:path, $params:ty, $result:ty, $summary:literal) => {
        Method {
            name: $name,
            summary: $summary,
            effect: Effect::$effect,
            stability: Stability::Stable,
            params: schema_of::<$params>,
            result: schema_of::<$result>,
            run: |workspace, params| run_typed($function, workspace, params),
        }
    };
}

/// Every method, by namespace.
pub static METHODS: &[Method] = &[
    method!("api.version", Read, version, values::NoParams, VersionResult, "The API version: 1.0. Changes within a major version only add methods, optional parameters and result fields."),
    method!("api.describe", Read, describe_method, values::NoParams, Description, "Every method with its summary, effect, stability and the JSON schemas of its parameters and result."),
    method!("documents.list", Read, documents::list, values::NoParams, documents::DocumentList, "The open documents, with their ids, names, paths, lengths and versions."),
    method!("documents.info", Read, documents::info, documents::InfoParams, workspace::DocumentInfo, "One document's id, name, path, length, version and whether it has unsaved edits."),
    method!("documents.open", View, documents::open, documents::OpenParams, workspace::DocumentInfo, "Open a file by path and make it the current document; a file already open is made current again."),
    method!("bytes.read", Read, bytes::read, bytes::ReadParams, bytes::ReadResult, "Read a span of bytes, as hex by default, or as base64 or text."),
    method!("bytes.hexdump", Read, bytes::hexdump, bytes::HexdumpParams, bytes::HexdumpResult, "A classic hex dump of a span, 16 bytes per line with an ASCII column, at most 1 MiB."),
    method!("bits.read", Read, bytes::read_bits, bytes::BitsParams, bytes::BitsResult, "Read a span of bits, most or least significant bit of each byte first, as a string of 0s and 1s and, up to 64 bits, as a number."),
    method!("search.find", Read, search::find, search::FindParams, search::FindResult, "The next (or previous) occurrence of hex bytes, text, UTF-16 text or an integer from an offset."),
    method!("search.find_all", Read, search::find_all, search::FindAllParams, search::FindAllResult, "Every occurrence of hex bytes, text, UTF-16 text or an integer in the document, a page at a time."),
    method!("search.count", Read, search::count, search::CountParams, search::CountResult, "How many times hex bytes, text, UTF-16 text or an integer occur in the document, up to a cap."),
    method!("numbers.decode", Read, numbers::decode, numbers::DecodeParams, numbers::DecodeResult, "Read the bytes at an offset as integers, floats, fixed-point numbers and timestamps of each width and byte order."),
    method!("selection.get", Read, selection::get_selection, selection::DocParams, selection::SelectionResult, "What is selected in a document: one range, several ranges or a column of every record."),
    method!("cursor.get", Read, selection::get_cursor, selection::DocParams, selection::CursorResult, "The cursor's offset in a document."),
    method!("findings.query", Read, findings::query, findings::QueryParams, findings::QueryResult, "Run the detectors over a span and list what they recognise (signatures, compressed streams, counters, timestamps, text, structures), filtered by category, confidence and producer."),
    method!("structure.parse", Read, structure::parse, structure::ParseParams, structure::ParseResult, "Parse the structure starting exactly at an offset (executables, images, archives, captures, ASN.1, filesystems) into a field tree, best match first."),
    method!("structure.parsers", Read, structure::parsers, values::NoParams, structure::ParsersResult, "The structure parsers available, built in and from plugins."),
    method!("templates.list", Read, structure::list_templates, values::NoParams, structure::TemplateList, "The binary templates available: the built-in ones and the user's own."),
    method!("templates.apply", Read, structure::apply_template, structure::ApplyParams, structure::ApplyResult, "Apply a binary template, by name or as source text, at an offset and return its field tree and records, without pinning it."),
    method!("codecs.list", Read, codecs::list, values::NoParams, codecs::CodecList, "The codecs available for decoding, built in and from plugins."),
    method!("codecs.detect", Read, codecs::detect, codecs::DetectParams, codecs::CodecList, "The codecs whose header starts at an offset."),
    method!("codecs.decode", Read, codecs::decode, codecs::DecodeParams, codecs::DecodeResult, "Decode (decompress) a span with a codec and return the output."),
    method!("codecs.probe", Read, codecs::probe, codecs::ProbeParams, codecs::ProbeResult, "Try every built-in decompressor at the start of a span, headerless ones included, and list those that decode."),
    method!("packets.dissect_bytes", Read, packets::dissect_bytes, packets::DissectParams, packets::DissectionResult, "Dissect one packet, from a span or from hex bytes, into protocol layers and fields, a summary and its flow."),
    method!("packets.detect_frames", Read, packets::detect_frames, packets::DetectFramesParams, packets::DetectFramesResult, "Find the protocol a set of frames of unknown format is, by trying every frame decoder on them."),
    method!("analysis.overview", Read, analysis::overview, analysis::OverviewParams, crate::headless::FileReport, "Map the whole document: a summary of what it is, its regions with offsets, likely record widths and confident findings."),
    method!("analysis.statistics", Read, analysis::statistics, analysis::SpanParams, analysis::StatisticsResult, "Measure a span: entropy, chi-square, serial correlation, printable, zero and high-byte fractions, distinct values and a verdict."),
    method!("analysis.segments", Read, analysis::segments, analysis::SegmentsParams, analysis::SegmentsResult, "Split the document into regions of one kind (text, tables, code, compressed, random, padding) and group them into types."),
    method!("analysis.compressibility", Read, analysis::compressibility, analysis::SpanParams, analysis::CompressibilityResult, "Compress a span with several codecs and report the ratios, with a verdict: encrypted or random, already compressed, lossy media or structured."),
    method!("analysis.text_encoding", Read, analysis::text_encoding, analysis::SpanParams, analysis::TextEncodingResult, "Identify the character encoding of a span of text, with previews and the likely language."),
    method!("analysis.processor", Read, analysis::processor, analysis::SpanParams, analysis::ProcessorResult, "Test whether a span is machine code, and for which processor, by disassembling samples for each architecture."),
    method!("reference.lookup", Read, reference::lookup, reference::LookupParams, reference::LookupResult, "The reference notes on a format or protocol, by id, finding id, layer name, port (udp/67) or number (port, IP protocol or EtherType): layout, field meanings and specifications."),
    method!("reference.search", Read, reference::search, reference::SearchParams, reference::SearchResult, "Reference entries whose notes mention every word of a query, or that a port or number names."),
];

/// The method called `name`.
pub fn method(name: &str) -> Option<&'static Method> {
    METHODS.iter().find(|method| method.name == name)
}

/// Run the method called `name` with JSON parameters.
pub fn call(workspace: &mut dyn Workspace, name: &str, params: Value) -> Result<Value, ApiError> {
    let method = method(name).ok_or_else(|| ApiError::not_found(format!("there is no method '{name}'; api.describe lists them")))?;
    (method.run)(workspace, params)
}

/// The result of `api.version`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VersionResult {
    /// Major and minor version, such as "1.0".
    pub version: String,
}

pub fn version(_workspace: &mut dyn Workspace, _params: values::NoParams) -> Result<VersionResult, ApiError> {
    Ok(VersionResult { version: API_VERSION.to_string() })
}

/// One method as `api.describe` lists it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MethodDescription {
    pub name: String,
    pub summary: String,
    pub effect: Effect,
    pub stability: Stability,
    /// JSON Schema of the parameters.
    pub params: Value,
    /// JSON Schema of the result.
    pub result: Value,
}

/// The whole method table, as `api.describe` returns it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Description {
    pub version: String,
    pub methods: Vec<MethodDescription>,
}

/// Every method with its schemas.
pub fn describe() -> Description {
    let methods = METHODS
        .iter()
        .map(|method| MethodDescription {
            name: method.name.to_string(),
            summary: method.summary.to_string(),
            effect: method.effect,
            stability: method.stability,
            params: (method.params)().to_value(),
            result: (method.result)().to_value(),
        })
        .collect();
    Description { version: API_VERSION.to_string(), methods }
}

fn describe_method(_workspace: &mut dyn Workspace, _params: values::NoParams) -> Result<Description, ApiError> {
    Ok(describe())
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Arc, LazyLock};

    use super::HeadlessWorkspace;
    use crate::document::Document;
    use crate::plugin::Registry;

    /// The app's registry, built once for all the API tests.
    static REGISTRY: LazyLock<Registry> = LazyLock::new(crate::app::build_registry);

    /// A workspace holding one document of `bytes`, called `name`.
    pub fn workspace_with(name: &str, bytes: &[u8]) -> HeadlessWorkspace {
        let mut workspace = HeadlessWorkspace::new(Arc::new(REGISTRY.clone()));
        workspace.add_document(name, Document::from_bytes(bytes.to_vec()));
        workspace
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::test_support::workspace_with;
    use super::*;

    #[test]
    fn every_method_has_a_unique_dotted_name_and_a_summary() {
        let mut names = std::collections::HashSet::new();
        for method in METHODS {
            assert!(names.insert(method.name), "{} is declared twice", method.name);
            assert!(method.name.contains('.') && method.name.chars().all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'), "{}", method.name);
            assert!(method.summary.ends_with('.'), "{} needs a one-sentence summary", method.name);
        }
    }

    #[test]
    fn every_schema_is_an_object_schema_that_closes_its_parameters() {
        for method in METHODS {
            let params = (method.params)().to_value();
            assert_eq!(params["type"], "object", "{} params", method.name);
            assert_eq!(params["additionalProperties"], false, "{} rejects unknown parameters", method.name);
            assert!((method.result)().to_value().is_object(), "{} result", method.name);
        }
    }

    /// Whether `value` fits `schema`, for the parts of JSON Schema the
    /// method table's schemas use. Returns where it does not fit.
    fn check_against(schema: &Value, value: &Value, root: &Value, path: &str) -> Result<(), String> {
        if schema == &Value::Bool(true) {
            return Ok(());
        }
        if let Some(reference) = schema["$ref"].as_str() {
            let name = reference.strip_prefix("#/$defs/").ok_or_else(|| format!("{path}: unexpected reference {reference}"))?;
            return check_against(&root["$defs"][name], value, root, path);
        }
        for key in ["anyOf", "oneOf"] {
            if let Some(options) = schema[key].as_array()
                && !options.iter().any(|option| check_against(option, value, root, path).is_ok())
            {
                return Err(format!("{path}: {value} fits none of the {key} options"));
            }
        }
        if let Some(options) = schema["enum"].as_array()
            && !options.contains(value)
        {
            return Err(format!("{path}: {value} is not one of {options:?}"));
        }
        if let Some(constant) = schema.get("const")
            && constant != value
        {
            return Err(format!("{path}: {value} is not {constant}"));
        }
        let types: Vec<&str> = match &schema["type"] {
            Value::String(name) => vec![name.as_str()],
            Value::Array(names) => names.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        let fits = |name: &str| match name {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => false,
        };
        if !types.is_empty() && !types.iter().any(|name| fits(name)) {
            return Err(format!("{path}: {value} is not {types:?}"));
        }
        if let Some(object) = value.as_object() {
            let properties = schema["properties"].as_object();
            for required in schema["required"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                if !object.contains_key(required) {
                    return Err(format!("{path}: '{required}' is missing"));
                }
            }
            for (key, item) in object {
                match properties.and_then(|properties| properties.get(key)) {
                    Some(property) => check_against(property, item, root, &format!("{path}.{key}"))?,
                    None if schema["additionalProperties"] == false => return Err(format!("{path}: '{key}' is not allowed")),
                    None => {}
                }
            }
        }
        if let Some(items) = value.as_array() {
            let prefix = schema["prefixItems"].as_array();
            for (index, item) in items.iter().enumerate() {
                let item_schema = prefix.and_then(|prefix| prefix.get(index)).unwrap_or(&schema["items"]);
                if !item_schema.is_null() {
                    check_against(item_schema, item, root, &format!("{path}[{index}]"))?;
                }
            }
        }
        Ok(())
    }

    fn fits_schema(schema: &Schema, value: &Value) -> Result<(), String> {
        let schema = schema.as_value();
        check_against(schema, value, schema, "")
    }

    #[test]
    fn every_method_accepts_an_example_and_answers_in_its_result_schema() {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &b"hello ".repeat(50)).unwrap();
        let mut bytes = encoder.finish().unwrap();
        bytes.extend(b"The quick brown fox jumps over the lazy dog. ".repeat(20));
        let path = std::env::temp_dir().join(format!("theviewer-api-examples-{}.bin", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let mut workspace = workspace_with("example.bin", &bytes);
        let examples = [
            ("api.version", json!({})),
            ("api.describe", json!({})),
            ("documents.list", json!({})),
            ("documents.info", json!({"doc": "current"})),
            ("documents.open", json!({"path": path.display().to_string()})),
            ("bytes.read", json!({"doc": "doc-1", "start": 0, "len": 8, "encoding": "base64"})),
            ("bytes.hexdump", json!({"start": 0, "len": 32})),
            ("bits.read", json!({"bit_start": 3, "bit_len": 12, "order": "lsb"})),
            ("search.find", json!({"query": "fox", "mode": "text"})),
            ("search.find_all", json!({"query": "6f 78", "mode": "hex", "limit": 5})),
            ("search.count", json!({"query": "the"})),
            ("numbers.decode", json!({"at": 0})),
            ("selection.get", json!({})),
            ("cursor.get", json!({})),
            ("findings.query", json!({"min_confidence": 0.0, "categories": ["compressed", "text"]})),
            ("structure.parse", json!({"at": 0})),
            ("structure.parsers", json!({})),
            ("templates.list", json!({})),
            ("templates.apply", json!({"name": "Fixed-size records", "limit": 2})),
            ("codecs.list", json!({})),
            ("codecs.detect", json!({"at": 0})),
            ("codecs.decode", json!({"start": 0, "codec": "zlib", "encoding": "text"})),
            ("codecs.probe", json!({"start": 0})),
            ("packets.dissect_bytes", json!({"start": 0, "len": 40, "link": "unknown"})),
            ("packets.detect_frames", json!({"frames": [{"start": 0, "len": 8}, {"start": 8, "len": 8}]})),
            ("analysis.overview", json!({"max_findings": 5})),
            ("analysis.statistics", json!({"start": 0, "len": 100})),
            ("analysis.segments", json!({"limit": 3})),
            ("analysis.compressibility", json!({})),
            ("analysis.text_encoding", json!({"start": 100})),
            ("analysis.processor", json!({})),
            ("reference.lookup", json!({"name": "zlib"})),
            ("reference.search", json!({"query": "compression", "limit": 3})),
        ];
        let named: std::collections::HashSet<&str> = examples.iter().map(|(name, _)| *name).collect();
        for method in METHODS {
            assert!(named.contains(method.name), "{} needs an example here", method.name);
        }
        for (name, params) in examples {
            let method = method(name).unwrap();
            fits_schema(&(method.params)(), &params).unwrap_or_else(|problem| panic!("{name} params: {problem}"));
            let result = call(&mut workspace, name, params).unwrap_or_else(|error| panic!("{name}: {error}"));
            fits_schema(&(method.result)(), &result).unwrap_or_else(|problem| panic!("{name} result: {problem}"));
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn the_schema_check_notices_values_that_do_not_fit() {
        let schema = (method("bytes.read").unwrap().params)();
        assert!(fits_schema(&schema, &json!({"start": 0})).is_ok());
        assert!(fits_schema(&schema, &json!({"len": 4})).is_err(), "start is required");
        assert!(fits_schema(&schema, &json!({"start": "0"})).is_err());
        assert!(fits_schema(&schema, &json!({"start": 0, "encoding": "rot13"})).is_err());
    }

    #[test]
    fn the_version_is_one_point_zero() {
        let mut workspace = workspace_with("a.bin", b"abc");
        assert_eq!(call(&mut workspace, "api.version", Value::Null).unwrap(), json!({"version": "1.0"}));
    }

    #[test]
    fn describe_lists_every_method_with_its_schemas() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let description = call(&mut workspace, "api.describe", json!({})).unwrap();
        let methods = description["methods"].as_array().unwrap();
        assert_eq!(methods.len(), METHODS.len());
        let read = methods.iter().find(|method| method["name"] == "bytes.read").unwrap();
        assert_eq!(read["effect"], "read");
        assert!(read["params"]["properties"]["start"].is_object());
    }

    #[test]
    fn an_unknown_method_is_not_found_and_bad_params_are_invalid() {
        let mut workspace = workspace_with("a.bin", b"abc");
        assert_eq!(call(&mut workspace, "bytes.melt", json!({})).unwrap_err().code, ErrorCode::NotFound);
        let error = call(&mut workspace, "bytes.read", json!({"start": "zero"})).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
        let error = call(&mut workspace, "bytes.read", json!({"start": 0, "len": 1, "colour": "red"})).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams, "unknown parameters are rejected");
    }

    #[test]
    fn errors_are_written_with_a_snake_case_code() {
        let error = ApiError::too_large("read less").with_data(json!({"limit": 1}));
        assert_eq!(error.to_json(), json!({"code": "too_large", "message": "read less", "data": {"limit": 1}}));
        assert_eq!(error.to_string(), "too_large: read less");
    }
}
