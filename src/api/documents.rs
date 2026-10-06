//! `documents.*`: which documents are open, and opening more.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values::NoParams;
use super::workspace::{self, DocumentInfo, Workspace};
use super::ApiError;

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
}
