//! The data API: one table of methods over documents, bytes, bits,
//! selections, findings, structures, codecs, packets and analysis, each
//! declared once with its name, effect and JSON schemas.
//!
//! Every way in uses the same table: Ask's tools are generated from it, the
//! command line runs one method (`theviewer api bytes.read '{…}' FILE`), and
//! `docs/api.md` is written from [`describe`]. Rust callers use the typed
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
pub mod edits;
pub mod events;
pub mod findings;
pub mod numbers;
pub mod packets;
pub mod permissions;
pub mod reference;
pub mod search;
pub mod selection;
pub mod structure;
pub mod values;
pub mod workspace;

use std::fmt;
use std::sync::Arc;

use schemars::{JsonSchema, Schema};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use permissions::{Caller, Decision, HeldCall, Policy};
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
    /// Check the JSON parameters, run the method for the caller and return
    /// its JSON result.
    pub run: fn(&mut dyn Workspace, &Caller, Value) -> Result<Value, ApiError>,
}

impl Method {
    /// The namespace, such as `bytes` for `bytes.read`.
    pub fn namespace(&self) -> &'static str {
        namespace_of(self.name)
    }
}

/// The namespace of a dotted method name.
pub fn namespace_of(name: &str) -> &str {
    name.split_once('.').map_or(name, |(namespace, _)| namespace)
}

/// What runs a method a plugin registered.
pub type RunRegistered = dyn Fn(&mut dyn Workspace, &Caller, Value) -> Result<Value, ApiError> + Send + Sync;

/// A method added at run time, by a plugin's `theviewer.register_method`.
/// It joins the table for `api.describe`, Ask's tools and every other
/// client, and is always experimental.
pub struct RegisteredMethod {
    /// Dotted name, such as `acme.decode_frame`.
    pub name: String,
    pub summary: String,
    /// `read` or `edit`.
    pub effect: Effect,
    /// JSON Schema of the parameters.
    pub params: Value,
    /// JSON Schema of the result.
    pub result: Value,
    /// Who registered it, such as `plugin:acme.lua`.
    pub owner: String,
    pub run: Box<RunRegistered>,
}

impl fmt::Debug for RegisteredMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RegisteredMethod").field("name", &self.name).field("effect", &self.effect).field("owner", &self.owner).finish()
    }
}

/// A method found by name: one of the table's or one a plugin registered.
#[derive(Clone)]
pub enum MethodRef {
    Builtin(&'static Method),
    Registered(Arc<RegisteredMethod>),
}

impl MethodRef {
    pub fn name(&self) -> &str {
        match self {
            MethodRef::Builtin(method) => method.name,
            MethodRef::Registered(method) => &method.name,
        }
    }

    pub fn summary(&self) -> &str {
        match self {
            MethodRef::Builtin(method) => method.summary,
            MethodRef::Registered(method) => &method.summary,
        }
    }

    pub fn effect(&self) -> Effect {
        match self {
            MethodRef::Builtin(method) => method.effect,
            MethodRef::Registered(method) => method.effect,
        }
    }

    /// JSON Schema of the parameters.
    pub fn params_schema(&self) -> Value {
        match self {
            MethodRef::Builtin(method) => (method.params)().to_value(),
            MethodRef::Registered(method) => method.params.clone(),
        }
    }

    fn describe(&self) -> MethodDescription {
        match self {
            MethodRef::Builtin(method) => MethodDescription {
                name: method.name.to_string(),
                summary: method.summary.to_string(),
                effect: method.effect,
                stability: method.stability,
                params: (method.params)().to_value(),
                result: (method.result)().to_value(),
            },
            MethodRef::Registered(method) => MethodDescription {
                name: method.name.clone(),
                summary: method.summary.clone(),
                effect: method.effect,
                stability: Stability::Experimental,
                params: method.params.clone(),
                result: method.result.clone(),
            },
        }
    }

    fn run(&self, workspace: &mut dyn Workspace, caller: &Caller, params: Value) -> Result<Value, ApiError> {
        match self {
            MethodRef::Builtin(method) => (method.run)(workspace, caller, params),
            MethodRef::Registered(method) => (method.run)(workspace, caller, params),
        }
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

    pub fn version_conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::VersionConflict, message)
    }

    pub fn plugin_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PluginFailed, message)
    }

    /// Whether this is the error of a call that must be confirmed first.
    pub fn needs_confirmation(&self) -> bool {
        self.data.as_ref().is_some_and(|data| data["reason"] == permissions::NEEDS_CONFIRMATION)
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
    function: impl FnOnce(&mut dyn Workspace, P) -> Result<R, ApiError>,
    workspace: &mut dyn Workspace,
    params: Value,
) -> Result<Value, ApiError> {
    let params = if params.is_null() { Value::Object(Default::default()) } else { params };
    let typed: P = serde_json::from_value(params).map_err(|error| ApiError::invalid_params(format!("{error}; see the method's params schema in api.describe")))?;
    let result = function(workspace, typed)?;
    serde_json::to_value(result).map_err(|error| ApiError::new(ErrorCode::InvalidParams, format!("the result could not be written as JSON: {error}")))
}

/// One row of the method table: name, effect, typed function, its params
/// and result types, and the summary. Methods that act for their caller
/// (edits are labelled with it, facts published as it) are written
/// `caller fn`, and take the caller after the workspace.
macro_rules! method {
    ($name:literal, $effect:ident, caller $function:path, $params:ty, $result:ty, $summary:literal) => {
        Method {
            name: $name,
            summary: $summary,
            effect: Effect::$effect,
            stability: Stability::Stable,
            params: schema_of::<$params>,
            result: schema_of::<$result>,
            run: |workspace, caller, params| run_typed(|workspace, typed| $function(workspace, caller, typed), workspace, params),
        }
    };
    ($name:literal, $effect:ident, $function:path, $params:ty, $result:ty, $summary:literal) => {
        Method {
            name: $name,
            summary: $summary,
            effect: Effect::$effect,
            stability: Stability::Stable,
            params: schema_of::<$params>,
            result: schema_of::<$result>,
            run: |workspace, _caller, params| run_typed($function, workspace, params),
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
    method!("documents.new", View, documents::new, documents::NewParams, workspace::DocumentInfo, "Open a new, empty document and make it current; the window refuses while its document has unsaved edits."),
    method!("documents.save", Edit, documents::save, documents::SaveParams, workspace::DocumentInfo, "Save a document over its file, or to a path, with every edit made so far."),
    method!("bytes.read", Read, bytes::read, bytes::ReadParams, bytes::ReadResult, "Read a span of bytes, as hex by default, or as base64 or text."),
    method!("bytes.hexdump", Read, bytes::hexdump, bytes::HexdumpParams, bytes::HexdumpResult, "A classic hex dump of a span, 16 bytes per line with an ASCII column, at most 1 MiB."),
    method!("bytes.write", Edit, caller edits::write, edits::WriteParams, edits::EditResult, "Overwrite bytes in place with new ones, as one undoable step; the document keeps its length."),
    method!("bytes.insert", Edit, caller edits::insert, edits::InsertParams, edits::EditResult, "Insert bytes at an offset, as one undoable step; the bytes after it move along."),
    method!("bytes.delete", Edit, caller edits::delete, edits::DeleteParams, edits::EditResult, "Remove a span of bytes, as one undoable step; the bytes after it move back."),
    method!("bytes.replace", Edit, caller edits::replace, edits::ReplaceParams, edits::EditResult, "Replace a span of bytes with new bytes of any length, as one undoable step."),
    method!("bits.read", Read, bytes::read_bits, bytes::BitsParams, bytes::BitsResult, "Read a span of bits, most or least significant bit of each byte first, as a string of 0s and 1s and, up to 64 bits, as a number."),
    method!("bits.write", Edit, caller edits::write_bits, edits::BitsWriteParams, edits::EditResult, "Overwrite bits from any bit offset, most or least significant bit of each byte first, as one undoable step; the bits around them are kept."),
    method!("transform.apply", Edit, caller edits::apply_transform, edits::TransformParams, edits::EditResult, "Apply an operation (XOR, invert, shift bits, swap byte order, number, compress, decompress and more) to every range of a selection, as one undoable step, and select what it produced."),
    method!("transform.preview", Read, edits::preview_transform, edits::PreviewParams, edits::PreviewResult, "What transform.apply would write into each range of a selection, without changing anything."),
    method!("history.undo", Edit, caller edits::undo, edits::HistoryParams, edits::HistoryResult, "Undo the document's last step, whoever made it, and put the cursor where it was."),
    method!("history.redo", Edit, caller edits::redo, edits::HistoryParams, edits::HistoryResult, "Redo the last step undone, and put the cursor where it was."),
    method!("history.transaction", Edit, caller edits::transaction, edits::TransactionParams, edits::TransactionResult, "Run several calls on one document as one undoable step; when one fails, every change the others made is reversed."),
    method!("search.find", Read, search::find, search::FindParams, search::FindResult, "The next (or previous) occurrence of hex bytes, text, UTF-16 text or an integer from an offset."),
    method!("search.find_all", Read, search::find_all, search::FindAllParams, search::FindAllResult, "Every occurrence of hex bytes, text, UTF-16 text or an integer in the document, a page at a time."),
    method!("search.count", Read, search::count, search::CountParams, search::CountResult, "How many times hex bytes, text, UTF-16 text or an integer occur in the document, up to a cap."),
    method!("numbers.decode", Read, numbers::decode, numbers::DecodeParams, numbers::DecodeResult, "Read the bytes at an offset as integers, floats, fixed-point numbers and timestamps of each width and byte order."),
    method!("selection.get", Read, selection::get_selection, selection::DocParams, selection::SelectionResult, "What is selected in a document: one range, several ranges or a column of every record."),
    method!("cursor.get", Read, selection::get_cursor, selection::DocParams, selection::CursorResult, "The cursor's offset in a document."),
    method!("selection.set", View, caller selection::set_selection, selection::SetSelectionParams, selection::SelectionResult, "Select one range, several ranges or a column of every record in a document, or nothing."),
    method!("cursor.set", View, caller selection::set_cursor, selection::SetCursorParams, selection::CursorResult, "Move the cursor to an offset, selecting nothing."),
    method!("findings.query", Read, findings::query, findings::QueryParams, findings::QueryResult, "Run the detectors over a span and list what they recognise (signatures, compressed streams, counters, timestamps, text, structures), filtered by category, confidence and producer."),
    method!("findings.publish", Read, caller findings::publish, findings::PublishParams, findings::PublishResult, "Publish findings about a document on the bus as the caller's, for the views, Findings and every other tool to show; they replace the caller's earlier ones under the same key."),
    method!("findings.retract", Read, caller findings::retract, findings::RetractParams, findings::PublishResult, "Withdraw the findings the caller published under a key."),
    method!("structure.parse", Read, structure::parse, structure::ParseParams, structure::ParseResult, "Parse the structure starting exactly at an offset (executables, images, archives, captures, ASN.1, filesystems) into a field tree, best match first."),
    method!("structure.parsers", Read, structure::parsers, values::NoParams, structure::ParsersResult, "The structure parsers available, built in and from plugins."),
    method!("templates.list", Read, structure::list_templates, values::NoParams, structure::TemplateList, "The binary templates available: the built-in ones and the user's own."),
    method!("templates.apply", Read, structure::apply_template, structure::ApplyParams, structure::ApplyResult, "Apply a binary template, by name or as source text, at an offset and return its field tree and records; with pin, also show it as the template tool does."),
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
    method!("events.facts", Read, events::facts, events::FactsParams, events::FactsResult, "What the tools have learnt about a document and keep: the latest fact per topic, producer and key, by topic, producer or the bytes they cover, each marked stale when the document changed under it."),
    method!("events.poll", Read, events::poll, events::PollParams, events::PollResult, "The messages (facts and events) published after a cursor, oldest first, optionally of some topics only; pass back next to keep up."),
];

/// The method called `name` in the table.
pub fn method(name: &str) -> Option<&'static Method> {
    METHODS.iter().find(|method| method.name == name)
}

/// The method called `name`: the table's, or one a plugin registered in
/// `workspace`.
pub fn find(workspace: &dyn Workspace, name: &str) -> Result<MethodRef, ApiError> {
    if let Some(method) = method(name) {
        return Ok(MethodRef::Builtin(method));
    }
    workspace
        .registered_methods()
        .into_iter()
        .find(|method| method.name == name)
        .map(MethodRef::Registered)
        .ok_or_else(|| ApiError::not_found(format!("there is no method '{name}'; api.describe lists them")))
}

/// Every method: the table's, then those plugins registered in `workspace`.
pub fn all_methods(workspace: &dyn Workspace) -> Vec<MethodRef> {
    METHODS.iter().map(MethodRef::Builtin).chain(workspace.registered_methods().into_iter().map(MethodRef::Registered)).collect()
}

/// Run the method called `name` with JSON parameters for `caller`, once the
/// workspace allows it: a method that edits or changes the view, called by
/// anyone but the person at the keyboard, is checked against the caller's
/// policy. A call that must be confirmed fails here with a `read_only`
/// error for which [`ApiError::needs_confirmation`] holds; callers that can
/// wait for the person hold it instead (see [`Workspace::hold_for_confirmation`]).
pub fn call(workspace: &mut dyn Workspace, caller: &Caller, name: &str, params: Value) -> Result<Value, ApiError> {
    let method = find(workspace, name)?;
    match workspace.permission(caller, method.effect()) {
        Decision::Allowed => method.run(workspace, caller, params),
        Decision::Denied => Err(permissions::denied(caller, name)),
        Decision::NeedsConfirmation => Err(permissions::needs_confirmation(caller, name)),
    }
}

/// Run the method called `name` without checking the caller's permission:
/// for calls the person has just allowed, calls inside a call already
/// allowed (a transaction's), and plugin actions the person ran.
pub fn call_permitted(workspace: &mut dyn Workspace, caller: &Caller, name: &str, params: Value) -> Result<Value, ApiError> {
    find(workspace, name)?.run(workspace, caller, params)
}

/// Run `name` for `caller` if allowed, refuse it if denied, and otherwise
/// hold it for the person to decide on; `reply` gets the result in every
/// case, at once or once the person has decided. This is how callers that
/// cannot block (Ask's tool calls, plugins' handlers, MCP requests) ask.
pub fn call_or_hold(workspace: &mut dyn Workspace, caller: Caller, name: &str, params: Value, reply: permissions::ReplyTo) {
    let method = match find(workspace, name) {
        Ok(method) => method,
        Err(error) => return reply(workspace, Err(error)),
    };
    match workspace.permission(&caller, method.effect()) {
        Decision::Allowed => {
            let result = method.run(workspace, &caller, params);
            reply(workspace, result);
        }
        Decision::Denied => reply(workspace, Err(permissions::denied(&caller, name))),
        Decision::NeedsConfirmation => {
            let description = edits::describe_call(workspace, name, &params);
            let held = HeldCall { caller, method: name.to_string(), params, description, reply };
            if let Some(held) = workspace.hold_for_confirmation(held) {
                let error = permissions::needs_confirmation(&held.caller, name);
                (held.reply)(workspace, Err(error));
            }
        }
    }
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

/// One topic of the workspace bus as `api.describe` lists it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TopicDescription {
    /// Dotted name, such as `record_width.estimated`.
    pub name: String,
    /// Facts are kept (the latest per producer, document and key); events are not.
    pub kind: crate::bus::Kind,
    pub description: String,
    /// JSON Schema of the payload.
    pub payload: Value,
}

/// The whole method table, as `api.describe` returns it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Description {
    pub version: String,
    pub methods: Vec<MethodDescription>,
    /// The bus's topics, which `events.facts` and `events.poll` read.
    pub topics: Vec<TopicDescription>,
}

/// Every method in the table and every topic, with their schemas.
pub fn describe() -> Description {
    let methods: Vec<MethodRef> = METHODS.iter().map(MethodRef::Builtin).collect();
    describe_methods(&methods)
}

/// `methods` and every topic, with their schemas.
fn describe_methods(methods: &[MethodRef]) -> Description {
    let methods = methods.iter().map(MethodRef::describe).collect();
    let topics = crate::bus::topics::TOPICS
        .iter()
        .map(|topic| TopicDescription { name: topic.name.to_string(), kind: topic.kind, description: topic.description.to_string(), payload: (topic.payload)().to_value() })
        .collect();
    Description { version: API_VERSION.to_string(), methods, topics }
}

/// What `api.describe` returns: the table and the methods plugins
/// registered in this workspace.
fn describe_method(workspace: &mut dyn Workspace, _params: values::NoParams) -> Result<Description, ApiError> {
    Ok(describe_methods(&all_methods(workspace)))
}

/// The API reference, `docs/api.md`, written from the method table.
pub fn reference_markdown() -> String {
    let description = describe();
    let mut out = String::new();
    out.push_str("# theviewer data API, version ");
    out.push_str(&description.version);
    out.push_str("\n\n");
    out.push_str("<!-- Generated from the method table in src/api.rs by `cargo run --bin api_docs`. Do not edit by hand. -->\n\n");
    out.push_str(
        "Every method can be called from the command line (`theviewer api METHOD '{json params}' FILE`), \
Lua plugins call them as `theviewer.api.<namespace>.<method>{…}`, Ask uses the methods that read \
or edit as its tools, and `theviewer mcp FILE…` offers every method to MCP clients such as Claude \
Code as a tool named with underscores for dots (`bytes_read`), with resources for each document \
(`theviewer://doc/{id}`, its `bytes/{start}-{end}`, `findings` and `facts`) and the reference notes \
(`theviewer://reference/{id}`). Documents are named by id (`doc-1`), by path or as \
`\"current\"`, which an omitted `doc` also means. Spans are `start` and `len` in bytes; an omitted \
`len` runs to the end of the document. Bytes are hex strings unless `encoding` says `base64` or \
`text`. List methods take `limit` and return `next`, a cursor to pass back for the next page. One \
call reads or returns at most 16 MiB.\n\n",
    );
    out.push_str(
        "Methods whose effect is `edit` change the document. Each call is one undo step, labelled with \
what it did and who called it (\"XOR by mcp:claude-code\"), and published on `document.edited` as the \
caller's. Any edit takes `expect_version`: when the document has changed since, the call fails with \
`version_conflict` and changes nothing. `history.transaction` runs several calls as one step and \
reverses them all when one fails. In the app, an edit or view change from a plugin, Ask or another \
client is checked against that client's setting under Settings › Permissions (always allow, always \
ask, never allow; a new client is asked about): when it asks, a window shows the change for the \
person to allow once, always allow or deny. On the command line and through `theviewer mcp` every \
call is allowed: the files are the ones the person named. Methods \
plugins register join the table at run time; `api.describe` lists them as experimental.\n\n",
    );
    out.push_str("Errors are `{code, message, data}`, with these codes:\n\n| Code | Meaning |\n| --- | --- |\n");
    for (code, meaning) in [
        ("invalid_params", "The parameters don't match the schema"),
        ("out_of_range", "A span falls outside the document"),
        ("not_found", "No such document, method or entry"),
        ("version_conflict", "The document changed since `expect_version`"),
        ("read_only", "The caller may not edit"),
        ("too_large", "Over the per-call limit"),
        ("cancelled", "A job was cancelled"),
        ("plugin_failed", "A plugin raised an error or used up its budget"),
        ("unavailable", "Something needed is missing, such as tshark"),
    ] {
        out.push_str(&format!("| `{code}` | {meaning} |\n"));
    }
    out.push_str("\n## Methods\n\n| Method | Effect | Summary |\n| --- | --- | --- |\n");
    for method in &description.methods {
        let effect = serde_json::to_value(method.effect).ok().and_then(|value| value.as_str().map(str::to_string)).unwrap_or_default();
        out.push_str(&format!("| [`{}`](#{}) | {effect} | {} |\n", method.name, method.name.replace('.', ""), method.summary));
    }
    out.push_str("\nEach method's full JSON schemas are in `theviewer api --describe`.\n");
    for method in &description.methods {
        out.push_str(&format!("\n### {}\n\n{}\n\n", method.name, method.summary));
        out.push_str(&properties_table("Parameter", &method.params, "None."));
        out.push('\n');
        out.push_str(&properties_table("Result field", &method.result, "Nothing."));
    }
    out.push_str(
        "\n## Topics\n\nWhat tools, panels and plugins publish on the workspace bus. Facts are kept, the latest per \
producer, document and key, and count as stale once the document has changed since (unless the edits did not touch \
their span, which carries them forward); events are not kept. Every message has an envelope: `id`, `topic`, `kind`, \
`producer`, `document`, `version`, `span`, `confidence`, `key`, `caused_by` and the `payload` below.\n\n\
| Topic | Kind | Description |\n| --- | --- | --- |\n",
    );
    for topic in &description.topics {
        let kind = serde_json::to_value(topic.kind).ok().and_then(|value| value.as_str().map(str::to_string)).unwrap_or_default();
        out.push_str(&format!("| [`{}`](#{}) | {kind} | {} |\n", topic.name, topic.name.replace('.', ""), topic.description));
    }
    for topic in &description.topics {
        out.push_str(&format!("\n### {}\n\n{}\n\n", topic.name, topic.description));
        out.push_str(&properties_table("Payload field", &topic.payload, "None."));
    }
    out
}

/// A Markdown table of an object schema's properties: name, type, whether
/// required, and description.
fn properties_table(heading: &str, schema: &Value, when_empty: &str) -> String {
    let Some(properties) = schema["properties"].as_object().filter(|properties| !properties.is_empty()) else {
        return format!("{heading}s: {when_empty}\n");
    };
    let required: Vec<&str> = schema["required"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let mut out = format!("| {heading} | Type | Required | Description |\n| --- | --- | --- | --- |\n");
    for (name, property) in properties {
        let description = property["description"].as_str().or_else(|| referenced(property, schema)["description"].as_str()).unwrap_or_default();
        let required = if required.contains(&name.as_str()) { "yes" } else { "no" };
        out.push_str(&format!("| `{name}` | {} | {required} | {} |\n", type_label(property, schema), description.replace('\n', " ").replace('|', "\\|")));
    }
    out
}

/// The definition a `$ref` schema points to, or the schema itself.
fn referenced<'a>(schema: &'a Value, root: &'a Value) -> &'a Value {
    match schema["$ref"].as_str().and_then(|reference| reference.strip_prefix("#/$defs/")) {
        Some(name) => &root["$defs"][name],
        None => schema,
    }
}

/// The values an enumeration schema allows: an `enum`, or `oneOf` options
/// that are each a `const` or an `enum`.
fn enum_values(schema: &Value) -> Option<Vec<Value>> {
    if let Some(values) = schema["enum"].as_array() {
        return Some(values.clone());
    }
    let mut values = Vec::new();
    for option in schema["oneOf"].as_array()? {
        match (option.get("const"), option["enum"].as_array()) {
            (Some(constant), _) => values.push(constant.clone()),
            (None, Some(more)) => values.extend(more.iter().cloned()),
            (None, None) => return None,
        }
    }
    Some(values)
}

/// A short name for a schema's type, such as "integer", "array of string"
/// or `"hex" \| "base64"`, for the reference tables.
fn type_label(schema: &Value, root: &Value) -> String {
    if let Some(values) = enum_values(referenced(schema, root)) {
        return values.iter().map(|value| format!("`{value}`")).collect::<Vec<_>>().join(" \\| ");
    }
    if let Some(name) = schema["$ref"].as_str().and_then(|reference| reference.strip_prefix("#/$defs/")) {
        return name.to_string();
    }
    if let Some(options) = schema["anyOf"].as_array() {
        let labels: Vec<String> = options.iter().filter(|option| option["type"] != "null").map(|option| type_label(option, root)).collect();
        return labels.join(" or ");
    }
    let types: Vec<&str> = match &schema["type"] {
        Value::String(name) => vec![name.as_str()],
        Value::Array(names) => names.iter().filter_map(Value::as_str).filter(|name| *name != "null").collect(),
        _ => Vec::new(),
    };
    match types.as_slice() {
        ["array"] if schema.get("prefixItems").is_some() => "pair".to_string(),
        ["array"] => format!("array of {}", type_label(&schema["items"], root)),
        [] => "any".to_string(),
        names => names.join(" or "),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Arc, LazyLock};

    use serde_json::Value;

    use super::{ApiError, Caller, HeadlessWorkspace, Workspace};
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

    /// Call a method as the person at the keyboard would.
    pub fn call(workspace: &mut dyn Workspace, name: &str, params: Value) -> Result<Value, ApiError> {
        super::call(workspace, &Caller::Panel, name, params)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::test_support::{call, workspace_with};
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
        let saved = std::env::temp_dir().join(format!("theviewer-api-examples-saved-{}.bin", std::process::id()));
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
            ("events.facts", json!({"topic": "record_width.estimated", "span": {"start": 0, "len": 16}})),
            ("events.poll", json!({"cursor": 0, "topics": ["document.opened"], "limit": 10})),
            ("findings.publish", json!({"findings": [{"id": "x", "source": "test", "category": "custom", "start": 0, "len": 4, "title": "", "detail": "", "confidence": 1.0, "fields": []}]})),
            ("findings.retract", json!({})),
            ("transform.preview", json!({"selection": {"range": [0, 4]}, "operation": {"op": "invert"}})),
            ("bytes.write", json!({"start": 0, "data": "00"})),
            ("bytes.insert", json!({"at": 0, "data": "00"})),
            ("bytes.delete", json!({"start": 0, "len": 1})),
            ("bytes.replace", json!({"start": 0, "len": 1, "data": "ffff"})),
            ("bits.write", json!({"bit_start": 3, "bits": "101"})),
            ("transform.apply", json!({"selection": {"range": [0, 4]}, "operation": {"op": "xor", "key": "5a"}})),
            ("history.undo", json!({})),
            ("history.redo", json!({})),
            ("history.transaction", json!({"calls": [{"method": "cursor.set", "params": {"offset": 2}}, {"method": "bytes.delete", "params": {"start": 0, "len": 1}}]})),
            ("selection.set", json!({"selection": {"range": [1, 3]}})),
            ("cursor.set", json!({"offset": 5})),
            ("documents.save", json!({"path": saved.display().to_string()})),
            ("documents.new", json!({"name": "scratch"})),
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
        std::fs::remove_file(saved).ok();
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
        let topics = description["topics"].as_array().unwrap();
        assert_eq!(topics.len(), crate::bus::topics::TOPICS.len());
        let width = topics.iter().find(|topic| topic["name"] == "record_width.estimated").unwrap();
        assert_eq!(width["kind"], "fact");
        assert!(width["payload"]["properties"]["width"].is_object());
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

    #[test]
    fn the_reference_document_matches_the_method_table() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/api.md");
        let written = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            written == reference_markdown(),
            "docs/api.md is out of date with the method table; regenerate it with `cargo run --bin api_docs`"
        );
    }
}
