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

/// Parameters of `documents.open`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenParams {
    /// Path of the file to open.
    pub path: String,
}

pub fn list(workspace: &mut dyn Workspace, _params: NoParams) -> Result<DocumentList, ApiError> {
    Ok(DocumentList { documents: workspace.documents() })
}

pub fn info(workspace: &mut dyn Workspace, params: InfoParams) -> Result<DocumentInfo, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    workspace::info(workspace, &id)
}

pub fn open(workspace: &mut dyn Workspace, params: OpenParams) -> Result<DocumentInfo, ApiError> {
    let id = workspace.open_path(Path::new(&params.path))?;
    workspace::info(workspace, &id)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::{ErrorCode, call};

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
}
