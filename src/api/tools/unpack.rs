//! `unpack.*`: extracting archives and compressed streams recursively, like
//! binwalk -e, as a tree; opening or reading one of its nodes.

use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary, ToolSpan};
use crate::api::jobs::JobStartedResult;
use crate::api::values::{self, ByteEncoding};
use crate::api::workspace::{self, DocumentInfo, Workspace};
use crate::api::{ApiError, Caller, MAX_CALL_BYTES};
use crate::unpack::{Limits, Node};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("unpack.run", Job, caller run, UnpackParams, JobStartedResult, "Start extracting the archives and compressed streams in the document (its first 256 MiB) recursively, like binwalk -e, as a job: the tree of what was found, each node with its kind, size and where its bytes came from, is job.finished's result, and in the window it fills the Unpacked tab and the Size map."),
    method!("unpack.open", View, open, NodeParams, DocumentInfo, "Open one node of the unpacked tree (by its path of child indices, as unpack.run gave it) as a derived document."),
    method!("unpack.read", Read, read, ReadNodeParams, NodeBytes, "Read the bytes of one node of the unpacked tree, by its path of child indices, as hex by default, or as base64 or text."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("unpack.run", json!({})), ("unpack.read", json!({"path": [0], "len": 16})), ("unpack.open", json!({"path": [0]}))]
}

/// Parameters of `unpack.run`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnpackParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// Parameters of `unpack.open`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeParams {
    /// Document id, path or "current" (the default): the parent.
    #[serde(default)]
    pub doc: Option<String>,
    /// Child indices from the root, such as [0, 2]; [] is the document itself.
    pub path: Vec<usize>,
}

/// Parameters of `unpack.read`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadNodeParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Child indices from the root, such as [0, 2].
    pub path: Vec<usize>,
    /// First offset in the node's bytes (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes read, at most 16 MiB; to the end of the node when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
}

/// One node of the unpacked tree.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UnpackedNode {
    pub name: String,
    /// Such as "zip entry" or "gzip stream".
    pub kind: String,
    /// Where its bytes came from in its parent's, and how many.
    pub source_offset: u64,
    pub source_len: u64,
    /// Its own bytes, decompressed where that applies.
    pub len: u64,
    /// The compression undone, if any.
    pub method: Option<String>,
    /// Why exploring stopped here, or a problem with it.
    pub note: Option<String>,
    /// Child indices from the root, for unpack.open and unpack.read.
    pub path: Vec<usize>,
    pub children: Vec<UnpackedNode>,
}

impl UnpackedNode {
    pub fn of(node: &Node, path: Vec<usize>) -> Self {
        let children = node
            .children
            .iter()
            .enumerate()
            .map(|(index, child)| {
                let mut child_path = path.clone();
                child_path.push(index);
                UnpackedNode::of(child, child_path)
            })
            .collect();
        UnpackedNode {
            name: node.name.clone(),
            kind: node.kind.clone(),
            source_offset: node.source_offset as u64,
            source_len: node.source_len as u64,
            len: node.data.len() as u64,
            method: node.method.clone(),
            note: node.note.clone(),
            path,
            children,
        }
    }
}

/// The result of `unpack.read`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct NodeBytes {
    pub name: String,
    pub encoding: ByteEncoding,
    pub data: String,
    /// Bytes in the whole node.
    pub node_len: u64,
}

/// The document's bytes to unpack, as the window reads them.
fn document_bytes(workspace: &mut dyn Workspace, doc: Option<&str>) -> Result<(ToolSpan, String, Arc<Vec<u8>>), ApiError> {
    let id = workspace::resolve(workspace, doc)?;
    let info = workspace::info(workspace, &id)?;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let bytes = Arc::new(document.read_range(0, crate::workbench::ANALYSIS_READ_LIMIT));
    Ok((ToolSpan { doc: id, version: info.version, start: 0, len: bytes.len() }, info.name, bytes))
}

/// `unpack.run`: in the window, its own unpacking fills the tab; headless,
/// unpack on a thread.
pub fn run(workspace: &mut dyn Workspace, caller: &Caller, params: UnpackParams) -> Result<JobStartedResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    if let Some(app) = tool_jobs::window_showing(workspace, &id) {
        return Ok(JobStartedResult { job: app.unpack_as(&caller.producer()) });
    }
    let (span, name, bytes) = document_bytes(workspace, Some(&id))?;
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("unpack", "Unpack"),
        &span,
        None,
        move |_| crate::unpack::unpack(bytes, &name, &Limits::default()),
        tree_summary,
    ))
}

/// What a finished unpacking says: how many items, and the tree.
pub(crate) fn tree_summary(tree: &Node) -> Summary {
    Summary::of(format!("{} items", tree.count().saturating_sub(1)), UnpackedNode::of(tree, Vec::new()))
}

/// The tree of document `doc`: the one the window unpacked, else unpacked now.
fn tree_of(workspace: &mut dyn Workspace, doc: Option<&str>) -> Result<(String, Node), ApiError> {
    let id = workspace::resolve(workspace, doc)?;
    if let Some(tree) = tool_jobs::window_showing(workspace, &id).and_then(|app| app.bench.unpacked.clone()) {
        return Ok((id, tree));
    }
    let (_, name, bytes) = document_bytes(workspace, Some(&id))?;
    Ok((id, crate::unpack::unpack(bytes, &name, &Limits::default())))
}

/// The node at `path`, or why there is none.
fn node_at<'a>(tree: &'a Node, path: &[usize]) -> Result<&'a Node, ApiError> {
    tree.find(path).ok_or_else(|| ApiError::not_found(format!("the unpacked tree has no node at {path:?}; unpack.run lists them with their paths")))
}

pub fn open(workspace: &mut dyn Workspace, params: NodeParams) -> Result<DocumentInfo, ApiError> {
    let (id, tree) = tree_of(workspace, params.doc.as_deref())?;
    let node = node_at(&tree, &params.path)?;
    let name = format!("{} › {}", workspace::info(workspace, &id)?.name, node.name);
    let opened = workspace.open_derived(&id, node.data.to_vec(), &name)?;
    workspace::info(workspace, &opened)
}

pub fn read(workspace: &mut dyn Workspace, params: ReadNodeParams) -> Result<NodeBytes, ApiError> {
    let (_, tree) = tree_of(workspace, params.doc.as_deref())?;
    let node = node_at(&tree, &params.path)?;
    let (start, len) = values::span_within(node.data.len(), params.start, params.len)?;
    values::check_size(len, MAX_CALL_BYTES, "the read")?;
    Ok(NodeBytes { name: node.name.clone(), encoding: params.encoding, data: values::encode_bytes(&node.data[start..start + len], params.encoding), node_len: node.data.len() as u64 })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, example_bytes, workspace_with};

    #[test]
    fn a_zlib_stream_unpacks_into_a_node_that_can_be_read_and_opened() {
        let mut workspace = workspace_with("example.bin", &example_bytes());
        let status = run_job(&mut workspace, "unpack.run", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        let first = &status["result"]["children"][0];
        assert_eq!(first["path"], json!([0]), "{status}");
        assert_eq!(first["len"], 300, "the 'hello ' × 50 the stream holds");
        let read = call(&mut workspace, "unpack.read", json!({"path": [0], "len": 6, "encoding": "text"})).unwrap();
        assert_eq!(read["data"], "hello ");
        let opened = call(&mut workspace, "unpack.open", json!({"path": [0]})).unwrap();
        assert_eq!(opened["len"], 300);
        assert!(opened["name"].as_str().unwrap().starts_with("example.bin › "));
    }

    #[test]
    fn a_node_that_is_not_there_is_not_found() {
        let mut workspace = workspace_with("example.bin", &example_bytes());
        assert_eq!(call(&mut workspace, "unpack.open", json!({"path": [7, 1]})).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "unpack.read", json!({"path": [0], "start": 301})).unwrap_err().code, ErrorCode::OutOfRange);
    }
}
