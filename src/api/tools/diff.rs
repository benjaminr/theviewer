//! `diff.run`: the Diff tool's comparison of a document with another file,
//! finding inserted, deleted and changed regions rather than flipped bytes.

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
    "Start a comparison of a document with another file as a job: the regions replaced, only in the document and only in the other file (inserted, deleted and changed, not just flipped bytes), with the bytes equal and changed, are job.finished's result, and in the window they fill the Diff tab and are outlined on the views."
)];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("diff.run", json!({"path": crate::api::test_support::example_file().display().to_string()}))]
}

/// Most bytes of a document with unsaved edits copied for the comparison.
pub const DIFF_COPY_LIMIT: usize = 512 * 1024 * 1024;

/// Parameters of `diff.run`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// The file to compare it with.
    pub path: String,
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
    /// The file compared with.
    pub path: String,
    pub equal_bytes: u64,
    pub changed_bytes: u64,
    /// Whether the comparison stopped at its limit of operations.
    pub truncated: bool,
    /// Where they differ, in document order.
    pub regions: Vec<DiffRegion>,
}

impl DiffRunResult {
    /// The comparison as an API caller collects it.
    pub fn of(path: &str, result: &DiffResult) -> Self {
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
        DiffRunResult { path: path.to_string(), equal_bytes: result.equal_bytes as u64, changed_bytes: result.changed_bytes as u64, truncated: result.truncated, regions }
    }
}

/// The document's side of a comparison: its file when it has no unsaved
/// edits, else a copy of its bytes.
enum OwnSide {
    Path(PathBuf),
    Bytes(Vec<u8>),
}

/// What a comparison ends with: the other file opened and the differences,
/// or why it could not be made.
pub type DiffOutcome = Result<(Document, DiffResult), String>;

/// Compare `own` with the file at `other`.
fn compare(own: OwnSide, other: &std::path::Path) -> DiffOutcome {
    let mut a = match own {
        OwnSide::Path(path) => Document::open(&path).map_err(|error| format!("{error:#}"))?,
        OwnSide::Bytes(bytes) => Document::from_bytes(bytes),
    };
    let mut b = Document::open(other).map_err(|error| format!("{error:#}"))?;
    let result = crate::diff::diff(&mut a, &mut b, DiffLimits::default());
    Ok((b, result))
}

/// `diff.run`: compare on a thread, reading the other file there.
pub fn run(workspace: &mut dyn Workspace, caller: &Caller, params: DiffParams) -> Result<JobStartedResult, ApiError> {
    let other = PathBuf::from(&params.path);
    if !other.is_file() {
        return Err(ApiError::not_found(format!("there is no file at {}; give the path of a file to compare with", params.path)));
    }
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let info = workspace::info(workspace, &id)?;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let own = match document.path().filter(|_| !document.is_modified()) {
        Some(path) => OwnSide::Path(path.to_path_buf()),
        None => OwnSide::Bytes(document.read_range(0, DIFF_COPY_LIMIT)),
    };
    let span = ToolSpan { doc: id, version: info.version, start: 0, len: info.len as usize };
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(crate::analysis_tabs::await_diff);
    let path = params.path;
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("diff", "Diff"),
        &span,
        deliver,
        move |_| compare(own, &other),
        move |outcome| match outcome {
            Ok((_, result)) => Summary::of(format!("{} bytes equal, {} differ", result.equal_bytes, result.changed_bytes), DiffRunResult::of(&path, result)),
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
    fn comparing_with_a_file_that_is_not_there_is_refused() {
        let mut workspace = workspace_with("a.bin", b"abc");
        assert_eq!(call(&mut workspace, "diff.run", json!({"path": "/nowhere/at/all.bin"})).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "diff.run", json!({})).unwrap_err().code, ErrorCode::InvalidParams);
    }
}
