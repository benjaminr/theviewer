//! `diff.run`: the Diff tool's comparison of a document with another file
//! or another open document, finding inserted, deleted and changed regions
//! rather than flipped bytes.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary, ToolSpan};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller};
use crate::diff::{DiffLimits, DiffOp, DiffResult};
use crate::document::Document;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[method!(
    "diff.run",
    Job,
    caller run,
    DiffParams,
    JobStartedResult,
    "Start a comparison of a document with another file (path) or another open document (other) as a job: the regions replaced, only in the document and only in the other file (inserted, deleted and changed, not just flipped bytes), with the bytes equal and changed, are job.finished's result, and in the window they fill the Diff tab and are outlined on the views."
)];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("diff.run", json!({"path": super::tool_jobs::test_support::example_other_file()}))]
}

/// Most bytes of a document with unsaved edits copied for the comparison.
pub const DIFF_COPY_LIMIT: usize = 512 * 1024 * 1024;

/// Parameters of `diff.run`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// The file to compare it with; give this or `other`.
    #[serde(default)]
    pub path: Option<String>,
    /// An open document to compare it with, by id or path, such as a sheet
    /// derived from it; give this or `path`.
    #[serde(default)]
    pub other: Option<String>,
}

/// One region where the two differ.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DiffRegion {
    /// `a_len` bytes at `a` in the document stand where `b_len` bytes at `b` are in the other file.
    Replace { a: u64, a_len: u64, b: u64, b_len: u64 },
    /// `len` bytes at `b` are only in the other file.
    Insert { b: u64, len: u64 },
    /// `len` bytes at `a` are only in the document.
    Delete { a: u64, len: u64 },
}

/// What `diff.run`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DiffRunResult {
    /// The file compared with, when it was a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The open document compared with, when it was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other: Option<String>,
    pub equal_bytes: u64,
    pub changed_bytes: u64,
    /// Whether the comparison stopped at its limit of operations.
    pub truncated: bool,
    /// Where they differ, in document order.
    pub regions: Vec<DiffRegion>,
}

impl DiffRunResult {
    /// The comparison with `against` as an API caller collects it.
    pub fn of(against: &Against, result: &DiffResult) -> Self {
        let regions = result
            .ops
            .iter()
            .filter_map(|op| match *op {
                DiffOp::Equal { .. } => None,
                DiffOp::Replace { a, a_len, b, b_len } => Some(DiffRegion::Replace { a: a as u64, a_len: a_len as u64, b: b as u64, b_len: b_len as u64 }),
                DiffOp::Insert { b, len } => Some(DiffRegion::Insert { b: b as u64, len: len as u64 }),
                DiffOp::Delete { a, len } => Some(DiffRegion::Delete { a: a as u64, len: len as u64 }),
            })
            .collect();
        let (path, other) = match against {
            Against::File(path) => (Some(path.clone()), None),
            Against::Document(id) => (None, Some(id.clone())),
        };
        DiffRunResult { path, other, equal_bytes: result.equal_bytes as u64, changed_bytes: result.changed_bytes as u64, truncated: result.truncated, regions }
    }
}

/// What a document is compared with: a file, or another open document.
#[derive(Clone, Debug, PartialEq)]
pub enum Against {
    File(String),
    Document(String),
}

/// One side of a comparison: a file, or a copy of a document's bytes when
/// it has unsaved edits or no file.
enum Side {
    Path(PathBuf),
    Bytes(Vec<u8>),
}

impl Side {
    /// Open the side to compare.
    fn open(self) -> Result<Document, String> {
        match self {
            Side::Path(path) => Document::open(&path).map_err(|error| format!("{error:#}")),
            Side::Bytes(bytes) => Ok(Document::from_bytes(bytes)),
        }
    }

    /// The side of the open document `id`: its file when it has no unsaved
    /// edits, else a copy of its bytes.
    fn of(workspace: &mut dyn Workspace, id: &str) -> Result<Side, ApiError> {
        let (_, document) = workspace::document(workspace, Some(id))?;
        Ok(match document.path().filter(|_| !document.is_modified()) {
            Some(path) => Side::Path(path.to_path_buf()),
            None => Side::Bytes(document.read_range(0, DIFF_COPY_LIMIT)),
        })
    }
}

/// What a comparison ends with: the other file opened and the differences,
/// or why it could not be made.
pub type DiffOutcome = Result<(Document, DiffResult), String>;

/// Compare `own` with `other`.
fn compare(own: Side, other: Side) -> DiffOutcome {
    let mut a = own.open()?;
    let mut b = other.open()?;
    let result = crate::diff::diff(&mut a, &mut b, DiffLimits::default());
    Ok((b, result))
}

/// `diff.run`: compare on a thread, reading the other file there.
pub fn run(workspace: &mut dyn Workspace, caller: &Caller, params: DiffParams) -> Result<JobStartedResult, ApiError> {
    let (against, other) = match (&params.path, &params.other) {
        (Some(path), None) => {
            let file = PathBuf::from(path);
            if !file.is_file() {
                return Err(ApiError::not_found(format!("there is no file at {path}; give the path of a file to compare with")));
            }
            (Against::File(path.clone()), Side::Path(file))
        }
        (None, Some(other)) => {
            let other = workspace::resolve(workspace, Some(other))?;
            (Against::Document(other.clone()), Side::of(workspace, &other)?)
        }
        _ => return Err(ApiError::invalid_params("give what to compare with one way: a file's path, or an open document as other")),
    };
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let info = workspace::info(workspace, &id)?;
    let own = Side::of(workspace, &id)?;
    let span = ToolSpan { doc: id, version: info.version, start: 0, len: info.len as usize };
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(crate::analysis_tabs::await_diff);
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("diff", "Diff"),
        &span,
        deliver,
        move |_| compare(own, other),
        move |outcome| match outcome {
            Ok((_, result)) => Summary::of(format!("{} bytes equal, {} differ", result.equal_bytes, result.changed_bytes), DiffRunResult::of(&against, result)),
            Err(message) => Summary::failed(message.clone()),
        },
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn comparing_with_a_file_lists_the_regions_changed_and_inserted() {
        let other = std::env::temp_dir().join(format!("theviewer-diff-other-{}.bin", std::process::id()));
        let original: Vec<u8> = (0..20_000u32).map(|index| (index * 31 % 251) as u8).collect();
        let mut changed = original.clone();
        changed[5000..5010].copy_from_slice(b"0123456789");
        std::fs::write(&other, &changed).unwrap();
        let mut workspace = workspace_with("a.bin", &original);
        let status = run_job(&mut workspace, "diff.run", json!({"path": other.display().to_string()}));
        std::fs::remove_file(&other).ok();
        assert_eq!(status["state"], "finished", "{status}");
        let result = &status["result"];
        assert_eq!(result["changed_bytes"], 10, "{result}");
        assert_eq!(result["regions"][0], json!({"op": "replace", "a": 5000, "a_len": 10, "b": 5000, "b_len": 10}));
    }

    #[test]
    fn comparing_with_another_open_document_lists_where_they_differ() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        call(&mut workspace, "documents.derive", json!({"data": "0123XY6789", "encoding": "text"})).unwrap();
        let status = run_job(&mut workspace, "diff.run", json!({"doc": "doc-1", "other": "doc-2"}));
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["result"]["other"], "doc-2");
        assert_eq!(status["result"]["regions"][0], json!({"op": "replace", "a": 4, "a_len": 2, "b": 4, "b_len": 2}));
        assert_eq!(call(&mut workspace, "diff.run", json!({"other": "doc-2", "path": "/tmp/x"})).unwrap_err().code, ErrorCode::InvalidParams, "one way only");
    }

    #[test]
    fn two_firmware_sheets_compare_by_their_labels_without_a_file_being_written() {
        let older: Vec<u8> = (0..20_000u32).map(|index| (index * 31 % 251) as u8).collect();
        let mut newer = older.clone();
        newer[700..704].copy_from_slice(b"2.11");
        let mut workspace = workspace_with("update.bin", &[older.clone(), newer].concat());
        call(&mut workspace, "documents.derive", json!({"start": 0, "len": older.len(), "output": {"new": {"label": "2.1.0"}}})).unwrap();
        call(&mut workspace, "documents.derive", json!({"doc": "doc-1", "start": older.len(), "len": older.len(), "output": {"new": {"label": "2.1.1"}}})).unwrap();
        let status = run_job(&mut workspace, "diff.run", json!({"doc": {"$sheet": "2.1.0"}, "other": {"$sheet": "2.1.1"}}));
        assert_eq!(status["state"], "finished", "{status}");
        let result = &status["result"];
        assert_eq!((result["other"].as_str(), result.get("path")), (Some("doc-3"), None), "{result}");
        assert_eq!(result["regions"], json!([{"op": "replace", "a": 700, "a_len": 4, "b": 700, "b_len": 4}]));
    }

    #[test]
    fn comparing_with_a_file_that_is_not_there_is_refused() {
        let mut workspace = workspace_with("a.bin", b"abc");
        assert_eq!(call(&mut workspace, "diff.run", json!({"path": "/nowhere/at/all.bin"})).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "diff.run", json!({})).unwrap_err().code, ErrorCode::InvalidParams);
    }
}
