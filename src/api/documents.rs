//! `documents.*`: which documents are open, and opening more.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values::{self, ByteEncoding, NoParams};
use super::workspace::{self, DocumentInfo, Workspace};
use super::ApiError;
use crate::selection_ops::{self, Operation};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("documents.list", Read, list, super::values::NoParams, DocumentList, "The open documents, with their ids, names, paths, lengths and versions."),
    method!("documents.info", Read, info, InfoParams, super::workspace::DocumentInfo, "One document's id, name, path, length, version and whether it has unsaved edits."),
    method!("documents.open", View, open, OpenParams, super::workspace::DocumentInfo, "Open a file by path, or an open document by id, and make it current; a file already open is made current again. In the window, a parent of the document shown is gone back to, closing what was derived from it."),
    method!("documents.new", View, new, NewParams, super::workspace::DocumentInfo, "Open a new, empty document and make it current; the window refuses while its document has unsaved edits."),
    method!("documents.save", Edit, save, SaveParams, super::workspace::DocumentInfo, "Save a document over its file, or to a path, with every edit made so far."),
    method!("documents.derive", View, derive, DeriveParams, super::workspace::DocumentInfo, "Open bytes of a document (a span, several ranges one after another, or bytes given), or what a transform such as decompress or XOR makes of them, as a document of their own derived from it, and make it current; in the window, Back goes back to the parent."),
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
        ("documents.derive", json!({"start": 0, "len": 32, "name": "zlib stream", "transform": {"op": "decompress"}})),
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

pub fn derive(workspace: &mut dyn Workspace, params: DeriveParams) -> Result<DocumentInfo, ApiError> {
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
    workspace::info(workspace, &id)
}

pub fn save(workspace: &mut dyn Workspace, params: SaveParams) -> Result<DocumentInfo, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    workspace.save(&id, params.path.as_deref().map(Path::new))?;
    workspace::info(workspace, &id)
}

pub fn new(workspace: &mut dyn Workspace, params: NewParams) -> Result<DocumentInfo, ApiError> {
    let id = workspace.new_document(params.name.as_deref().unwrap_or("untitled"))?;
    workspace::info(workspace, &id)
}

pub fn list(workspace: &mut dyn Workspace, _params: NoParams) -> Result<DocumentList, ApiError> {
    Ok(DocumentList { documents: workspace.documents() })
}

pub fn info(workspace: &mut dyn Workspace, params: InfoParams) -> Result<DocumentInfo, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    workspace::info(workspace, &id)
}

pub fn open(workspace: &mut dyn Workspace, params: OpenParams) -> Result<DocumentInfo, ApiError> {
    let id = match (params.path, params.doc) {
        (Some(path), None) => workspace.open_path(Path::new(&path))?,
        (None, Some(doc)) => {
            let id = workspace::resolve(workspace, Some(&doc))?;
            workspace.switch_to(&id)?;
            id
        }
        _ => return Err(ApiError::invalid_params("give the file to open as path, or an open document's id as doc, not both")),
    };
    workspace::info(workspace, &id)
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
