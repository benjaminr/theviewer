//! `documents.*`: which documents are open; opening, deriving, saving and
//! exporting them.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values::{self, ByteEncoding, NoParams};
use super::workspace::{self, DocumentInfo, Workspace};
use super::ApiError;
use super::permissions::Caller;
use crate::compress::{self, Codec};
use crate::selection_ops::{self, Operation};
use crate::sources::{self, SourceSpec};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("documents.list", Read, list, super::values::NoParams, DocumentList, "The open documents, with their ids, names, paths, lengths and versions."),
    method!("documents.info", Read, info, InfoParams, super::workspace::DocumentInfo, "One document's id, name, path, length, version and whether it has unsaved edits."),
    method!("documents.open", View, caller open, OpenParams, super::workspace::DocumentInfo, "Open a file by path, or an open document by id, and make it current; a file already open is made current again. In the window, a parent of the document shown is gone back to, closing what was derived from it; that, or opening another file, is refused while what it closes has unsaved edits, unless the person at the window discards them.").opens_document(false),
    method!("documents.new", View, caller new, NewParams, super::workspace::DocumentInfo, "Open a new, empty document and make it current; the window refuses while its document has unsaved edits, unless the person at the window discards them.").opens_document(false),
    method!("documents.save", Edit, save, SaveParams, super::workspace::DocumentInfo, "Save a document over its file, or to a path, with every edit made so far.").writes_file(crate::api::WritesFile::Always),
    method!("documents.derive", View, derive, DeriveParams, super::workspace::SheetMade, "Open bytes of a document (a span, several ranges one after another, or bytes given), or what a transform such as decompress or XOR makes of them, as a document of their own derived from it, and make it current; in the window, Back goes back to the parent. Returns the new document, and output.").makes_sheet(),
    method!("documents.export", Edit, export, ExportParams, ExportResult, "Write a span of a document (or several ranges one after another) to a file, or what decompresses at a span's start; the document is left as it is.").writes_file(crate::api::WritesFile::Always),
    method!("documents.open_source", View, caller open_source, OpenSourceParams, OpenSourceResult, "Open a file, URL, block device, serial port (serial:PORT@BAUD) or a process's memory region (pid:PID@ADDRESS) as a new document. The window reads a URL, device or region in the background and opens it when it arrives, and pid:PID lists a process's regions in the Live tab; headless, the bytes are read before the call returns.").opens_document(false),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("documents.list", json!({})),
        ("documents.info", json!({"doc": "current"})),
        ("documents.open", json!({"path": super::test_support::example_file().display().to_string()})),
        ("documents.save", json!({"path": super::test_support::example_save_path().display().to_string()})),
        ("documents.export", json!({"start": 0, "len": 40, "path": std::env::temp_dir().join(format!("theviewer-api-examples-export-{}.bin", std::process::id())).display().to_string(), "decompress": true})),
        ("documents.derive", json!({"start": 0, "len": 32, "name": "zlib stream", "transform": {"op": "decompress"}})),
        ("documents.open_source", json!({"uri": super::test_support::example_file().display().to_string()})),
        ("documents.new", json!({"name": "scratch"})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, params: &serde_json::Value) -> Option<String> {
    let description = match method {
        "documents.save" => match params.get("path").and_then(serde_json::Value::as_str) {
            Some(path) => format!("Save the document to {path}"),
            None => "Save the document over its file".to_string(),
        },
        "documents.new" => "Open a new, empty document in place of this one".to_string(),
        "documents.open_source" => format!("Open {}", params.get("uri")?.as_str()?),
        "documents.export" => {
            let path = params.get("path")?.as_str()?;
            if let Some(ranges) = params.get("ranges").and_then(serde_json::Value::as_array) {
                return Some(format!("Write {} ranges, one after another, to {path}", ranges.len()));
            }
            let start = params.get("start")?.as_u64()?;
            if params.get("decompress").and_then(serde_json::Value::as_bool) == Some(true) {
                format!("Write what decompresses at {start:#x} to {path}")
            } else {
                match params.get("len").and_then(serde_json::Value::as_u64) {
                    Some(len) => format!("Write {len} bytes from {start:#x} to {path}"),
                    None => format!("Write the bytes from {start:#x} to the end to {path}"),
                }
            }
        }
        "documents.derive" => {
            let params: DeriveParams = serde_json::from_value(params.clone()).ok()?;
            let what = match (&params.ranges, &params.data, params.start) {
                (Some(ranges), _, _) => format!("{} ranges", ranges.len()),
                (_, Some(_), _) => "the bytes given".to_string(),
                (_, _, Some(start)) => match params.len {
                    Some(len) => format!("{len} bytes from {start:#x}"),
                    None => format!("the bytes from {start:#x} to the end"),
                },
                _ => return None,
            };
            match &params.transform {
                Some(transform) => format!("Open {what}, after {}, as a document of their own", transform.name()),
                None => format!("Open {what} as a document of their own"),
            }
        }
        _ => return None,
    };
    Some(description)
}

/// The result of `documents.list`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DocumentList {
    pub documents: Vec<DocumentInfo>,
}

/// Parameters of `documents.info`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfoParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// Parameters of `documents.open`: a file by `path`, or an open document
/// by its id as `doc`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenParams {
    /// Path of the file to open.
    #[serde(default)]
    pub path: Option<String>,
    /// Id of an open document to make current, such as a parent the window
    /// derived the document shown from.
    #[serde(default)]
    pub doc: Option<String>,
    /// In the window, close documents with unsaved edits, losing them, as
    /// File › Open and Back do; only the person at the window may.
    #[serde(default)]
    pub discard_unsaved: bool,
}

/// Parameters of `documents.save`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Where to save; over the document's own file when omitted.
    #[serde(default)]
    pub path: Option<String>,
}

/// Parameters of `documents.new`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewParams {
    /// What to call the document ("untitled" by default).
    #[serde(default)]
    pub name: Option<String>,
    /// In the window, close documents with unsaved edits, losing them, as
    /// File › New does; only the person at the window may.
    #[serde(default)]
    pub discard_unsaved: bool,
}

/// Parameters of `documents.derive`: which bytes, given exactly one way
/// (`start` and `len`, `ranges` or `data`), and what to make of them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeriveParams {
    /// Document id, path or "current" (the default): the parent.
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the first byte to open.
    #[serde(default)]
    pub start: Option<u64>,
    /// Bytes to open from `start`; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Several spans as [start, len], opened one after another (a selection
    /// of several ranges, or several packets).
    #[serde(default)]
    pub ranges: Option<Vec<(u64, u64)>>,
    /// The bytes themselves, written as `encoding` says, when they are not
    /// in the document as they are (a reassembled stream, say).
    #[serde(default)]
    pub data: Option<String>,
    /// How `data` is written: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
    /// What to call the new document; the parent's name and the span when omitted.
    #[serde(default)]
    pub name: Option<String>,
    /// An operation to apply to each span first, such as {"op": "decompress"} or {"op": "xor", "key": "5a"}.
    #[serde(default)]
    pub transform: Option<Operation>,
}

/// The spans of bytes `params` names in document `id`, before any
/// transform, and a few words for them to name the document by.
fn derived_spans(workspace: &mut dyn Workspace, id: &str, params: &DeriveParams) -> Result<(Vec<Vec<u8>>, String), ApiError> {
    let (_, document) = workspace::document(workspace, Some(id))?;
    let document_len = document.len();
    match (params.start, &params.ranges, &params.data) {
        (Some(start), None, None) => {
            let (start, len) = values::span_within(document_len, start, params.len)?;
            Ok((vec![document.read_range(start, len)], format!("{start:#x}+{len}")))
        }
        (None, Some(ranges), None) if params.len.is_none() => {
            let mut spans = Vec::with_capacity(ranges.len());
            for &(start, len) in ranges {
                let (start, len) = values::span_within(document_len, start, Some(len))?;
                spans.push(document.read_range(start, len));
            }
            Ok((spans, format!("{} ranges", ranges.len())))
        }
        (None, None, Some(data)) if params.len.is_none() => {
            let bytes = values::decode_bytes(data, params.encoding)?;
            values::check_call_size(bytes.len())?;
            Ok((vec![bytes], "bytes".to_string()))
        }
        _ => Err(ApiError::invalid_params("give the bytes to open one way: start (and len), ranges, or data")),
    }
}

/// Parameters of `documents.export`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the first byte to write, or of the compressed stream; give
    /// this or `ranges`.
    #[serde(default)]
    pub start: Option<u64>,
    /// Bytes to write, or to read the compressed stream from (at most 64 MiB);
    /// to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Several spans as [start, len], written one after another (a selection
    /// of several ranges); in place of `start` and `len`.
    #[serde(default)]
    pub ranges: Option<Vec<(u64, u64)>>,
    /// The file to write.
    pub path: String,
    /// Write what the first codec that decodes at `start` makes of the bytes, instead of the bytes.
    #[serde(default)]
    pub decompress: bool,
}

/// How the bytes `documents.export` wrote were decompressed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExportedStream {
    pub codec: Codec,
    /// Input bytes the stream occupied.
    pub consumed: u64,
    /// Whether the stream ended cleanly.
    pub complete: bool,
    /// Whether the output was cut at 64 MiB.
    pub truncated: bool,
}

/// The result of `documents.export`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExportResult {
    /// The file written.
    pub path: String,
    /// Bytes written.
    pub written: u64,
    /// The codec and stream, when the bytes were decompressed.
    pub decompressed: Option<ExportedStream>,
}

/// Most bytes a decompressing export reads, and most it writes.
const EXPORT_DECOMPRESS_MAX: usize = 64 * 1024 * 1024;

pub fn export(workspace: &mut dyn Workspace, params: ExportParams) -> Result<ExportResult, ApiError> {
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let document_len = document.len();
    let start = match (params.start, &params.ranges) {
        (Some(start), None) => start,
        (None, Some(_)) if params.decompress => return Err(ApiError::invalid_params("decompress reads one stream: give its start (and len), not ranges")),
        (None, Some(ranges)) if params.len.is_none() => {
            let mut bytes = Vec::new();
            for &(start, len) in ranges {
                let (start, len) = values::span_within(document_len, start, Some(len))?;
                bytes.extend(document.read_range(start, len));
            }
            return write_export(params.path, bytes, None);
        }
        _ => return Err(ApiError::invalid_params("give the bytes to write one way: start (and len), or ranges")),
    };
    let (start, len) = values::span_within(document_len, start, params.len)?;
    let (bytes, decompressed) = if params.decompress {
        if start >= document_len {
            return Err(ApiError::invalid_params("nothing to decompress at the end of the document"));
        }
        let input = document.read_range(start, len.min(EXPORT_DECOMPRESS_MAX));
        let found = compress::probe(&input, EXPORT_DECOMPRESS_MAX).into_iter().next().ok_or_else(|| {
            ApiError::invalid_params(format!("nothing decodes at {start:#x} (tried gzip, zlib, bzip2, xz, zstd, LZ4, raw deflate and lzma)"))
        })?;
        let stream = ExportedStream { codec: found.codec, consumed: found.consumed as u64, complete: found.complete, truncated: found.truncated };
        (found.data, Some(stream))
    } else {
        (document.read_range(start, len), None)
    };
    write_export(params.path, bytes, decompressed)
}

/// Write the bytes `documents.export` gathered to `path`.
fn write_export(path: String, bytes: Vec<u8>, decompressed: Option<ExportedStream>) -> Result<ExportResult, ApiError> {
    std::fs::write(&path, &bytes).map_err(|error| ApiError::new(super::ErrorCode::Unavailable, format!("could not write {path}: {error}")))?;
    Ok(ExportResult { path, written: bytes.len() as u64, decompressed })
}

/// Parameters of `documents.open_source`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenSourceParams {
    /// A path, an http(s) URL, a block device (/dev/disk2), serial:PORT@BAUD, pid:PID or pid:PID@ADDRESS.
    pub uri: String,
}

/// The result of `documents.open_source`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenSourceResult {
    /// The document opened, when it opened before the call returned.
    pub document: Option<DocumentInfo>,
    /// Whether the window is still reading the bytes, and opens them when they arrive.
    pub reading: bool,
}

/// Most bytes read from a URL, device or process region.
const SOURCE_READ_LIMIT: usize = 512 * 1024 * 1024;

/// Read `spec` whole, for a workspace without a frame loop to wait in.
fn read_source_now(spec: SourceSpec) -> Result<Vec<u8>, ApiError> {
    let unavailable = |message: String| ApiError::new(super::ErrorCode::Unavailable, message);
    match spec {
        SourceSpec::Url(url) => sources::fetch_url(&url, SOURCE_READ_LIMIT).map_err(unavailable),
        SourceSpec::BlockDevice(path) => sources::read_block_device(&path, SOURCE_READ_LIMIT).map_err(unavailable),
        SourceSpec::ProcessRegion { pid, start } => {
            let region = sources::readable_region_at(pid, start).map_err(unavailable)?;
            sources::read_process_memory(pid, &region, SOURCE_READ_LIMIT).map_err(unavailable)
        }
        SourceSpec::Serial { .. } => Err(unavailable("serial captures run only in the window".to_string())),
        SourceSpec::Process { pid } => Err(ApiError::invalid_params(format!("give the memory region to read as pid:{pid}@ADDRESS; the window's Live tab lists them"))),
        SourceSpec::File(_) => Err(ApiError::invalid_params("a file is opened with documents.open")),
    }
}

pub fn open_source(workspace: &mut dyn Workspace, caller: &Caller, params: OpenSourceParams) -> Result<OpenSourceResult, ApiError> {
    let spec = SourceSpec::parse(&params.uri).map_err(ApiError::invalid_params)?;
    // The window opens a source in place of every document it shows, as
    // the Live tab always has; only the person may lose unsaved edits so.
    let unsaved = workspace.documents().iter().any(|info| info.modified);
    if let Some(app) = workspace.window() {
        may_discard(caller, unsaved)?;
        let before = app.document_id();
        app.open_live_source(&params.uri).map_err(|message| ApiError::new(super::ErrorCode::Unavailable, message))?;
        let (opened, reading) = (app.document_id(), app.source_loading());
        let document = if opened == before { None } else { Some(workspace::info(workspace, &opened)?) };
        return Ok(OpenSourceResult { document, reading });
    }
    let name = spec.describe();
    let id = match spec {
        SourceSpec::File(path) => workspace.open_path(&path)?,
        spec => {
            let bytes = read_source_now(spec)?;
            workspace.open_source_bytes(&name, bytes)?
        }
    };
    Ok(OpenSourceResult { document: Some(workspace::info(workspace, &id)?), reading: false })
}

pub fn derive(workspace: &mut dyn Workspace, params: DeriveParams) -> Result<workspace::SheetMade, ApiError> {
    let parent = workspace::resolve(workspace, params.doc.as_deref())?;
    let (spans, what) = derived_spans(workspace, &parent, &params)?;
    let mut bytes = Vec::with_capacity(spans.iter().map(Vec::len).sum());
    for (index, span) in spans.iter().enumerate() {
        match &params.transform {
            Some(transform) => {
                let changed = selection_ops::transform_range(transform, span, index).map_err(|message| ApiError::invalid_params(format!("{} failed: {message}", transform.name())))?;
                bytes.extend(changed);
            }
            None => bytes.extend_from_slice(span),
        }
    }
    let name = match params.name {
        Some(name) => name,
        None => format!("{} › {what}", workspace::info(workspace, &parent)?.name),
    };
    let id = workspace.open_derived(&parent, bytes, &name)?;
    workspace::SheetMade::of(workspace, &id)
}

pub fn save(workspace: &mut dyn Workspace, params: SaveParams) -> Result<DocumentInfo, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    workspace.save(&id, params.path.as_deref().map(Path::new))?;
    workspace::info(workspace, &id)
}

pub fn new(workspace: &mut dyn Workspace, caller: &Caller, params: NewParams) -> Result<DocumentInfo, ApiError> {
    let name = params.name.as_deref().unwrap_or("untitled");
    let id = if may_discard(caller, params.discard_unsaved)? { workspace.new_document_discarding(name)? } else { workspace.new_document(name)? };
    workspace::info(workspace, &id)
}

pub fn list(workspace: &mut dyn Workspace, _params: NoParams) -> Result<DocumentList, ApiError> {
    Ok(DocumentList { documents: workspace.documents() })
}

pub fn info(workspace: &mut dyn Workspace, params: InfoParams) -> Result<DocumentInfo, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    workspace::info(workspace, &id)
}

pub fn open(workspace: &mut dyn Workspace, caller: &Caller, params: OpenParams) -> Result<DocumentInfo, ApiError> {
    let discard = may_discard(caller, params.discard_unsaved)?;
    let id = match (params.path, params.doc) {
        (Some(path), None) if discard => workspace.open_path_discarding(Path::new(&path))?,
        (Some(path), None) => workspace.open_path(Path::new(&path))?,
        (None, Some(doc)) => {
            let id = workspace::resolve(workspace, Some(&doc))?;
            if discard { workspace.switch_to_discarding(&id)? } else { workspace.switch_to(&id)? }
            id
        }
        _ => return Err(ApiError::invalid_params("give the file to open as path, or an open document's id as doc, not both")),
    };
    workspace::info(workspace, &id)
}

/// The person's file actions in the window, each a `documents.*` step.
/// Like the File menu always has, they close what is shown even with
/// unsaved edits.
impl crate::app::ViewerApp {
    /// Open the file at `path` (dropped on the window, say) in place of
    /// what is shown.
    pub fn open_file(&mut self, path: &Path) {
        let _ = self.perform("documents.open", serde_json::json!({ "path": path.display().to_string(), "discard_unsaved": true }));
    }

    /// Open a new, empty document in place of what is shown.
    pub fn open_new_document(&mut self) {
        let _ = self.perform("documents.new", serde_json::json!({ "discard_unsaved": true }));
    }

    /// Go back to the document the one shown was derived from.
    pub fn go_back_to_parent(&mut self) {
        let Some(parent) = self.parents.last().map(|parent| parent.id.clone()) else {
            self.status = "Already at the top-level document".to_string();
            return;
        };
        let _ = self.perform("documents.open", serde_json::json!({ "doc": parent, "discard_unsaved": true }));
    }
}

/// Whether a call may discard unsaved edits: only the person at the window
/// may ask to, as the File menu and Back do.
fn may_discard(caller: &Caller, discard_unsaved: bool) -> Result<bool, ApiError> {
    if discard_unsaved && *caller != Caller::Panel {
        return Err(ApiError::new(super::ErrorCode::ReadOnly, "only the person at the window may discard unsaved edits; save them (documents.save) or undo them first"));
    }
    Ok(discard_unsaved)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::ErrorCode;
    use crate::api::test_support::call;

    #[test]
    fn the_open_documents_are_listed_with_their_lengths() {
        let mut workspace = workspace_with("fw.bin", b"0123456789");
        let listed = call(&mut workspace, "documents.list", json!({})).unwrap();
        assert_eq!(listed["documents"][0]["id"], "doc-1");
        assert_eq!(listed["documents"][0]["len"], 10);
        assert_eq!(listed["documents"][0]["current"], true);
        let info = call(&mut workspace, "documents.info", json!({"doc": "current"})).unwrap();
        assert_eq!(info["name"], "fw.bin");
        assert_eq!(call(&mut workspace, "documents.info", json!({"doc": "doc-7"})).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn opening_a_path_makes_it_the_current_document() {
        let path = std::env::temp_dir().join(format!("theviewer-api-documents-{}.bin", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        let mut workspace = workspace_with("first.bin", b"x");
        let opened = call(&mut workspace, "documents.open", json!({"path": path.display().to_string()})).unwrap();
        assert_eq!((opened["id"].as_str(), opened["len"].as_u64(), opened["current"].as_bool()), (Some("doc-2"), Some(3), Some(true)));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn saving_writes_the_edits_and_a_new_document_starts_empty() {
        let path = std::env::temp_dir().join(format!("theviewer-api-save-{}.bin", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        let mut workspace = workspace_with("first.bin", b"x");
        call(&mut workspace, "documents.open", json!({"path": path.display().to_string()})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        assert_eq!(call(&mut workspace, "documents.info", json!({})).unwrap()["modified"], true);
        let saved = call(&mut workspace, "documents.save", json!({})).unwrap();
        assert_eq!(saved["modified"], false);
        assert_eq!(std::fs::read(&path).unwrap(), b"Abc");
        assert_eq!(call(&mut workspace, "documents.save", json!({"doc": "doc-1"})).unwrap_err().code, ErrorCode::InvalidParams, "a document with no file needs a path");
        let fresh = call(&mut workspace, "documents.new", json!({"name": "scratch"})).unwrap();
        assert_eq!((fresh["name"].as_str(), fresh["len"].as_u64(), fresh["current"].as_bool()), (Some("scratch"), Some(0), Some(true)));
        std::fs::remove_file(path).ok();
    }

    fn bytes_of(workspace: &mut dyn crate::api::Workspace, doc: &str) -> String {
        call(workspace, "bytes.read", json!({"doc": doc, "start": 0, "encoding": "text"})).unwrap()["data"].as_str().unwrap().to_string()
    }

    #[test]
    fn deriving_opens_a_span_several_ranges_or_given_bytes_as_a_new_current_document() {
        let mut workspace = workspace_with("fw.bin", b"0123456789");
        let span = call(&mut workspace, "documents.derive", json!({"start": 2, "len": 3})).unwrap();
        assert_eq!((span["id"].as_str(), span["name"].as_str(), span["current"].as_bool()), (Some("doc-2"), Some("fw.bin › 0x2+3"), Some(true)));
        assert_eq!(bytes_of(&mut workspace, "doc-2"), "234");
        let ranges = call(&mut workspace, "documents.derive", json!({"doc": "doc-1", "ranges": [[8, 2], [0, 1]], "name": "ends"})).unwrap();
        assert_eq!(ranges["name"], "ends");
        assert_eq!(bytes_of(&mut workspace, "doc-3"), "890", "ranges are opened one after another, in the order given");
        call(&mut workspace, "documents.derive", json!({"doc": "doc-1", "data": "stream", "encoding": "text"})).unwrap();
        assert_eq!(bytes_of(&mut workspace, "doc-4"), "stream");
        let to_end = call(&mut workspace, "documents.derive", json!({"doc": "doc-1", "start": 7})).unwrap();
        assert_eq!(to_end["len"], 3, "an omitted len runs to the end");
        assert_eq!(bytes_of(&mut workspace, "doc-1"), "0123456789", "the parent is left as it was");
    }

    #[test]
    fn a_derived_sheet_remembers_its_parent_and_the_step_that_made_it() {
        let mut workspace = workspace_with("fw.bin", b"0123456789");
        let derived = call(&mut workspace, "documents.derive", json!({"start": 2, "len": 3})).unwrap();
        assert_eq!(derived["output"], json!({"doc": "doc-2", "len": 3}), "one place names the sheet made");
        let step = crate::api::Workspace::journal(&workspace).entries().last().unwrap().clone();
        assert_eq!((step.method.as_str(), step.doc.as_deref(), step.made.as_slice()), ("documents.derive", Some("doc-1"), ["doc-2".to_string()].as_slice()));
        let info = call(&mut workspace, "documents.info", json!({"doc": "doc-2"})).unwrap();
        assert_eq!(info["parent"], "doc-1");
        assert_eq!(info["made_by"], json!({"step": step.step, "method": "documents.derive", "params": {"start": 2, "len": 3}, "span": [[2, 3]]}));
        assert!(call(&mut workspace, "documents.info", json!({"doc": "doc-1"})).unwrap().get("parent").is_none(), "the file is a root");
    }

    #[test]
    fn deriving_with_a_transform_opens_what_it_makes_of_each_span() {
        let mut workspace = workspace_with("fw.bin", &crate::api::test_support::example_bytes());
        let decoded = call(&mut workspace, "documents.derive", json!({"start": 0, "len": 32, "transform": {"op": "decompress"}})).unwrap();
        assert_eq!(decoded["len"], 300);
        assert!(bytes_of(&mut workspace, "doc-2").starts_with("hello hello"));
        call(&mut workspace, "documents.derive", json!({"doc": "doc-1", "data": "0102", "transform": {"op": "xor", "key": "ff"}})).unwrap();
        assert_eq!(call(&mut workspace, "bytes.read", json!({"doc": "doc-3", "start": 0})).unwrap()["data"], "fefd");
    }

    #[test]
    fn deriving_is_refused_without_one_clear_source_or_outside_the_document() {
        let mut workspace = workspace_with("fw.bin", b"0123456789");
        let refused = |workspace: &mut crate::api::HeadlessWorkspace, params| call(workspace, "documents.derive", params).unwrap_err().code;
        assert_eq!(refused(&mut workspace, json!({})), ErrorCode::InvalidParams, "nothing to open");
        assert_eq!(refused(&mut workspace, json!({"start": 0, "data": "00"})), ErrorCode::InvalidParams, "two sources");
        assert_eq!(refused(&mut workspace, json!({"ranges": [[0, 1]], "len": 1})), ErrorCode::InvalidParams, "len belongs to start");
        assert_eq!(refused(&mut workspace, json!({"start": 8, "len": 3})), ErrorCode::OutOfRange);
        assert_eq!(refused(&mut workspace, json!({"ranges": [[0, 1], [20, 1]]})), ErrorCode::OutOfRange);
        assert_eq!(refused(&mut workspace, json!({"start": 0, "transform": {"op": "decompress"}})), ErrorCode::InvalidParams, "digits do not decompress");
        assert_eq!(refused(&mut workspace, json!({"doc": "doc-9", "start": 0})), ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "documents.list", json!({})).unwrap()["documents"].as_array().unwrap().len(), 1, "nothing was opened");
    }

    fn export_path(name: &str) -> String {
        std::env::temp_dir().join(format!("theviewer-export-{name}-{}.bin", std::process::id())).display().to_string()
    }

    #[test]
    fn exporting_writes_a_span_or_what_decompresses_at_its_start_and_leaves_the_document() {
        let mut workspace = workspace_with("fw.bin", &crate::api::test_support::example_bytes());
        let (raw, unpacked) = (export_path("raw"), export_path("unpacked"));
        let written = call(&mut workspace, "documents.export", json!({"start": 2, "len": 4, "path": raw})).unwrap();
        assert_eq!((written["written"].as_u64(), &written["decompressed"]), (Some(4), &serde_json::Value::Null));
        assert_eq!(std::fs::read(&raw).unwrap(), crate::api::test_support::example_bytes()[2..6]);
        let decompressed = call(&mut workspace, "documents.export", json!({"start": 0, "path": unpacked, "decompress": true})).unwrap();
        assert_eq!((decompressed["written"].as_u64(), decompressed["decompressed"]["codec"].as_str()), (Some(300), Some("zlib")));
        assert_eq!(std::fs::read(&unpacked).unwrap(), b"hello ".repeat(50));
        assert_eq!(call(&mut workspace, "documents.info", json!({})).unwrap()["modified"], false);
        std::fs::remove_file(raw).ok();
        std::fs::remove_file(unpacked).ok();
    }

    #[test]
    fn exporting_a_selection_of_several_ranges_writes_them_one_after_another() {
        let mut workspace = workspace_with("fw.bin", b"0123456789");
        let path = export_path("ranges");
        let written = call(&mut workspace, "documents.export", json!({"ranges": [[8, 2], [0, 3]], "path": path})).unwrap();
        assert_eq!(written["written"], 5);
        assert_eq!(std::fs::read(&path).unwrap(), b"89012", "in the order given");
        let refused = |workspace: &mut crate::api::HeadlessWorkspace, params| call(workspace, "documents.export", params).unwrap_err().code;
        assert_eq!(refused(&mut workspace, json!({"ranges": [[0, 1]], "start": 0, "path": path})), ErrorCode::InvalidParams, "one way only");
        assert_eq!(refused(&mut workspace, json!({"ranges": [[0, 1]], "len": 1, "path": path})), ErrorCode::InvalidParams, "len belongs to start");
        assert_eq!(refused(&mut workspace, json!({"ranges": [[0, 1]], "decompress": true, "path": path})), ErrorCode::InvalidParams);
        assert_eq!(refused(&mut workspace, json!({"ranges": [[0, 1], [9, 4]], "path": path})), ErrorCode::OutOfRange);
        assert_eq!(refused(&mut workspace, json!({"path": path})), ErrorCode::InvalidParams, "something to write");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn exporting_outside_the_document_what_does_not_decompress_or_to_nowhere_is_refused() {
        let mut workspace = workspace_with("fw.bin", b"plain text");
        let path = export_path("refused");
        let refused = |workspace: &mut crate::api::HeadlessWorkspace, params| call(workspace, "documents.export", params).unwrap_err().code;
        assert_eq!(refused(&mut workspace, json!({"start": 4, "len": 20, "path": path})), ErrorCode::OutOfRange);
        assert_eq!(refused(&mut workspace, json!({"start": 0, "path": path, "decompress": true})), ErrorCode::InvalidParams);
        assert_eq!(refused(&mut workspace, json!({"start": 10, "path": path, "decompress": true})), ErrorCode::InvalidParams, "nothing at the end");
        assert_eq!(refused(&mut workspace, json!({"start": 0, "path": "/no/such/dir/out.bin"})), ErrorCode::Unavailable);
        assert!(!std::path::Path::new(&path).exists(), "nothing was written");
    }

    #[test]
    fn a_source_opens_before_the_call_returns_without_a_window() {
        let path = std::env::temp_dir().join(format!("theviewer-open-source-{}.bin", std::process::id()));
        std::fs::write(&path, b"from a source").unwrap();
        let mut workspace = workspace_with("fw.bin", b"x");
        let opened = call(&mut workspace, "documents.open_source", json!({"uri": path.display().to_string()})).unwrap();
        assert_eq!((opened["document"]["id"].as_str(), opened["document"]["len"].as_u64(), opened["reading"].as_bool()), (Some("doc-2"), Some(13), Some(false)));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn a_source_that_cannot_be_read_without_a_window_is_refused() {
        let mut workspace = workspace_with("fw.bin", b"x");
        let refused = |workspace: &mut crate::api::HeadlessWorkspace, uri: &str| call(workspace, "documents.open_source", json!({"uri": uri})).unwrap_err().code;
        assert_eq!(refused(&mut workspace, "  "), ErrorCode::InvalidParams);
        assert_eq!(refused(&mut workspace, "pid:12"), ErrorCode::InvalidParams, "a process's regions are listed in the window");
        assert_eq!(refused(&mut workspace, "serial:/dev/cu.nothing"), ErrorCode::Unavailable);
        assert_eq!(refused(&mut workspace, "/no/such/file.bin"), ErrorCode::NotFound);
    }

    #[test]
    fn only_the_person_at_the_window_may_discard_unsaved_edits() {
        let mut workspace = workspace_with("fw.bin", b"0123");
        let client = crate::api::Caller::Mcp("claude-code".to_string());
        let refused = crate::api::call(&mut workspace, &client, "documents.new", json!({"discard_unsaved": true})).unwrap_err();
        assert_eq!(refused.code, ErrorCode::ReadOnly);
        assert_eq!(call(&mut workspace, "documents.new", json!({"discard_unsaved": true})).unwrap()["id"], "doc-2");
    }

    mod window {
        use serde_json::json;

        use crate::actions::take_performed;
        use crate::api::{Caller, ErrorCode, call};
        use crate::app::{Launch, ViewerApp};
        use crate::selection::Selection;

        fn app_with(bytes: &[u8]) -> ViewerApp {
            let mut app = ViewerApp::new(Launch::default());
            app.open_bytes(bytes.to_vec(), "test.bin".to_string());
            app.run_bus();
            take_performed();
            app
        }

        #[test]
        fn opening_the_selection_as_a_document_derives_it_through_the_api_and_back_returns() {
            let mut app = app_with(b"0123456789");
            let parent = app.document_id();
            app.set_selection(5, Some(Selection::Range(2, 3)));
            app.open_selection_as_document();
            assert_eq!(take_performed(), [("documents.derive".to_string(), json!({"start": 2, "len": 3, "name": "test.bin › selection"}))]);
            assert_eq!(app.document.read_range(0, 10), b"234");
            assert_eq!((app.display_name().as_str(), app.status.as_str()), ("test.bin › selection", "Opened test.bin › selection"));
            app.back_to_parent();
            assert_eq!((app.document_id(), app.document.len()), (parent, 10));
        }

        #[test]
        fn opening_several_selected_ranges_derives_them_one_after_another() {
            let mut app = app_with(b"0123456789");
            app.set_selection(0, Some(Selection::Ranges(vec![(0, 2), (6, 2)])));
            app.open_selection_as_document();
            assert_eq!(take_performed(), [("documents.derive".to_string(), json!({"ranges": [[0, 2], [6, 2]], "name": "test.bin › selection"}))]);
            assert_eq!(app.document.read_range(0, 10), b"0167");
        }

        fn temporary_file(name: &str, bytes: &[u8]) -> std::path::PathBuf {
            let path = std::env::temp_dir().join(format!("theviewer-files-{name}-{}.bin", std::process::id()));
            std::fs::write(&path, bytes).unwrap();
            path
        }

        #[test]
        fn opening_a_file_by_hand_replaces_what_is_shown_even_with_unsaved_edits() {
            let path = temporary_file("open", b"on disk");
            let mut app = app_with(b"edited");
            app.document.overwrite(0, b"E");
            app.open_file(&path);
            assert_eq!(take_performed(), [("documents.open".to_string(), json!({"path": path.display().to_string(), "discard_unsaved": true}))]);
            assert_eq!(app.document.read_range(0, 7), b"on disk");
            assert!(app.status.starts_with("Loaded theviewer-files-open"), "{}", app.status);
            app.document.overwrite(0, b"O");
            app.open_file(&path);
            assert_eq!(app.document.read_range(0, 7), b"on disk", "opening the file shown again reads it from disk again");
            std::fs::remove_file(path).ok();
        }

        #[test]
        fn a_file_that_will_not_open_says_why_on_the_status_bar() {
            let mut app = app_with(b"kept");
            app.open_file(std::path::Path::new("/no/such/file.bin"));
            assert!(app.status.starts_with("Failed to open /no/such/file.bin"), "{}", app.status);
            assert_eq!(app.document.read_range(0, 4), b"kept");
        }

        #[test]
        fn a_new_document_and_going_back_are_document_steps_that_close_unsaved_edits() {
            let mut app = app_with(b"outer");
            let outer = app.document_id();
            app.open_derived(b"inner".to_vec(), "inner".to_string());
            app.document.overwrite(0, b"I");
            take_performed();
            app.go_back_to_parent();
            assert_eq!(take_performed(), [("documents.open".to_string(), json!({"doc": outer, "discard_unsaved": true}))]);
            assert_eq!((app.document_id(), app.status.as_str()), (outer, "Back to test.bin"));
            app.go_back_to_parent();
            assert!(take_performed().is_empty(), "nothing to go back to");
            assert_eq!(app.status, "Already at the top-level document");
            app.document.overwrite(0, b"O");
            app.open_new_document();
            assert_eq!(take_performed(), [("documents.new".to_string(), json!({"discard_unsaved": true}))]);
            assert_eq!((app.document.len(), app.status.as_str()), (0, "New empty document"));
        }

        #[test]
        fn extracting_the_selection_or_its_decompressed_contents_is_a_documents_export_step() {
            let mut app = app_with(&crate::api::test_support::example_bytes());
            let (raw, unpacked) = (super::export_path("window-raw"), super::export_path("window-unpacked"));
            app.set_selection(8, Some(Selection::Range(4, 4)));
            app.export_bytes_to(std::path::Path::new(&raw));
            assert_eq!(take_performed(), [("documents.export".to_string(), json!({"start": 4, "len": 4, "path": raw}))]);
            assert_eq!(app.status, format!("Saved 4 B (selection from 0x4) to {raw}"));
            app.set_selection(0, None);
            app.export_decompressed_to(std::path::Path::new(&unpacked));
            let len = app.document.len();
            assert_eq!(take_performed(), [("documents.export".to_string(), json!({"start": 0, "len": len, "path": unpacked, "decompress": true}))]);
            assert!(app.status.starts_with("zlib at 0x0: "), "{}", app.status);
            assert!(app.status.ends_with(&format!("decompressed saved to {unpacked}")), "{}", app.status);
            assert_eq!(std::fs::read(&unpacked).unwrap(), b"hello ".repeat(50));
            std::fs::remove_file(raw).ok();
            std::fs::remove_file(unpacked).ok();
        }

        #[test]
        fn saving_by_hand_is_a_documents_save_step() {
            let path = temporary_file("save", b"abc");
            let mut app = app_with(b"x");
            app.open_file(&path);
            app.document.overwrite(0, b"A");
            take_performed();
            app.save();
            assert_eq!(take_performed(), [("documents.save".to_string(), json!({}))]);
            assert_eq!(std::fs::read(&path).unwrap(), b"Abc");
            std::fs::remove_file(path).ok();
        }

        #[test]
        fn the_window_records_where_a_derived_sheet_came_from_and_shows_it_as_before() {
            let mut app = app_with(b"outer");
            let outer = app.document_id();
            let derived = call(&mut app, &Caller::Panel, "documents.derive", json!({"start": 1, "len": 3})).unwrap();
            let inner = derived["output"]["doc"].as_str().unwrap().to_string();
            assert_eq!((app.document_id(), app.parents.len()), (inner.clone(), 1), "the sheet is shown with its parent waiting behind it, as ever");
            let info = call(&mut app, &Caller::Panel, "documents.info", json!({"doc": inner})).unwrap();
            assert_eq!((info["parent"].as_str(), info["made_by"]["method"].as_str()), (Some(outer.as_str()), Some("documents.derive")));
        }

        #[test]
        fn the_window_derives_only_from_the_document_shown() {
            let mut app = app_with(b"outer");
            let outer = app.document_id();
            call(&mut app, &Caller::Panel, "documents.derive", json!({"start": 1, "len": 3})).unwrap();
            let refused = call(&mut app, &Caller::Panel, "documents.derive", json!({"doc": outer, "start": 0})).unwrap_err();
            assert_eq!(refused.code, ErrorCode::InvalidParams);
            assert_eq!(app.document.read_range(0, 5), b"ute");
        }
    }
}
