//! `selection.*` and `cursor.*`: what is selected and where the cursor is.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::edits::check_inside;
use super::permissions::Caller;
use super::values;
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

/// Parameters of `selection.set`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetSelectionParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// What to select: {"range": [start, len]}, {"ranges": [[start, len], …]}
    /// or {"columns": {…}}; null or omitted selects nothing.
    #[serde(default)]
    pub selection: Option<Selection>,
}

/// Parameters of `cursor.set`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetCursorParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset to put the cursor at; the document's length is just past the last byte.
    pub offset: u64,
}

pub fn set_selection(workspace: &mut dyn Workspace, caller: &Caller, params: SetSelectionParams) -> Result<SelectionResult, ApiError> {
    let (doc, document) = workspace::document(workspace, params.doc.as_deref())?;
    let len = document.len();
    let cursor = match &params.selection {
        Some(selected) => {
            check_inside(selected, len)?;
            selected.ranges(len).last().map_or(0, |&(start, range_len)| start + range_len)
        }
        None => workspace.view(&doc).unwrap_or_default().cursor.min(len),
    };
    workspace.select(&doc, cursor, params.selection, caller);
    get_selection(workspace, DocParams { doc: Some(doc) })
}

pub fn set_cursor(workspace: &mut dyn Workspace, caller: &Caller, params: SetCursorParams) -> Result<CursorResult, ApiError> {
    let (doc, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (offset, _) = values::span_within(document.len(), params.offset, Some(0))?;
    workspace.select(&doc, offset, None, caller);
    get_cursor(workspace, DocParams { doc: Some(doc) })
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
    use crate::api::test_support::call;
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

    #[test]
    fn a_client_selects_bytes_and_moves_the_cursor_and_says_so_on_the_bus() {
        let mut workspace = workspace_with("a.bin", &[0; 64]);
        let caller = crate::api::Caller::Mcp("claude-code".into());
        let selected = crate::api::call(&mut workspace, &caller, "selection.set", json!({"selection": {"ranges": [[0, 4], [8, 4]]}})).unwrap();
        assert_eq!(selected["total_bytes"], 8);
        let moved = crate::api::call(&mut workspace, &caller, "cursor.set", json!({"offset": 64})).unwrap();
        assert_eq!(moved["offset"], 64, "the cursor may sit just past the last byte");
        assert_eq!(call(&mut workspace, "selection.get", json!({})).unwrap()["selection"], serde_json::Value::Null, "moving the cursor selects nothing");
        let past = crate::api::call(&mut workspace, &caller, "selection.set", json!({"selection": {"range": [60, 8]}})).unwrap_err();
        assert_eq!(past.code, crate::api::ErrorCode::OutOfRange);
        let producers: Vec<String> = crate::api::Workspace::bus(&mut workspace)
            .recent()
            .filter(|message| message.topic() == crate::bus::Topic::SelectionChanged)
            .map(|message| message.producer().to_string())
            .collect();
        assert_eq!(producers, ["mcp:claude-code", "mcp:claude-code"]);
    }
}
