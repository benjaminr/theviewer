//! `selection.*` and `cursor.*`: what is selected and where the cursor is.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::workspace::{self, Workspace};
use super::ApiError;
use crate::selection::{self, Selection};

/// Parameters that name just a document.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// The result of `selection.get`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SelectionResult {
    /// Id of the document.
    pub doc: String,
    /// The selection as the app holds it, or nothing when no bytes are selected.
    pub selection: Option<Selection>,
    /// Every selected range as [start, len], in document order.
    pub ranges: Vec<(u64, u64)>,
    /// Bytes selected in all.
    pub total_bytes: u64,
}

/// The result of `cursor.get`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CursorResult {
    /// Id of the document.
    pub doc: String,
    /// Offset of the byte at the cursor.
    pub offset: u64,
}

pub fn get_selection(workspace: &mut dyn Workspace, params: DocParams) -> Result<SelectionResult, ApiError> {
    let (doc, document) = workspace::document(workspace, params.doc.as_deref())?;
    let len = document.len();
    let selection = workspace.view(&doc).unwrap_or_default().selection;
    let ranges = selection.as_ref().map(|selection| selection.ranges(len)).unwrap_or_default();
    Ok(SelectionResult {
        total_bytes: selection::total_bytes(&ranges) as u64,
        ranges: ranges.into_iter().map(|(start, len)| (start as u64, len as u64)).collect(),
        selection,
        doc,
    })
}

pub fn get_cursor(workspace: &mut dyn Workspace, params: DocParams) -> Result<CursorResult, ApiError> {
    let doc = workspace::resolve(workspace, params.doc.as_deref())?;
    let offset = workspace.view(&doc).unwrap_or_default().cursor as u64;
    Ok(CursorResult { doc, offset })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::workspace::ViewState;
    use crate::api::call;
    use crate::selection::{ColumnSelection, Selection};

    #[test]
    fn the_selection_and_cursor_are_reported_as_the_app_holds_them() {
        let mut workspace = workspace_with("a.bin", &[0; 64]);
        let nothing = call(&mut workspace, "selection.get", json!({})).unwrap();
        assert_eq!((nothing["selection"].clone(), nothing["total_bytes"].as_u64()), (serde_json::Value::Null, Some(0)));

        let column = ColumnSelection { first_row_start: 0, stride: 16, column: 2, width: 2, rows: 3 };
        workspace.set_view("doc-1", ViewState { cursor: 0x21, selection: Some(Selection::Columns(column)), record_stride: Some(16) });
        let selected = call(&mut workspace, "selection.get", json!({"doc": "doc-1"})).unwrap();
        assert_eq!(selected["selection"]["columns"]["width"], 2);
        assert_eq!(selected["ranges"], json!([[2, 2], [18, 2], [34, 2]]));
        assert_eq!(selected["total_bytes"], 6);
        assert_eq!(call(&mut workspace, "cursor.get", json!({})).unwrap(), json!({"doc": "doc-1", "offset": 0x21}));
    }
}
