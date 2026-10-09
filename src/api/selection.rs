//! `selection.*` and `cursor.*`: what is selected and where the cursor is.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::edits::check_inside;
use super::permissions::Caller;
use super::values;
use super::workspace::{self, Workspace};
use super::ApiError;
use crate::selection::{self, Selection};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("selection.get", Read, get_selection, DocParams, SelectionResult, "What is selected in a document: one range, several ranges or a column of every record."),
    method!("cursor.get", Read, get_cursor, DocParams, CursorResult, "The cursor's offset in a document."),
    method!("selection.set", View, caller set_selection, SetSelectionParams, SelectionResult, "Select one range, several ranges or a column of every record in a document, or nothing.").reverses(crate::api::Reverse::Select).merges_repeats(),
    method!("cursor.set", View, caller set_cursor, SetCursorParams, CursorResult, "Move the cursor to an offset, selecting nothing.").reverses(crate::api::Reverse::MoveCursor).merges_repeats(),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("selection.get", json!({})),
        ("cursor.get", json!({})),
        ("selection.set", json!({"selection": {"range": [1, 3]}})),
        ("selection.set", json!({"selection": {"ranges": [[1, 3], [8, 2]]}, "cursor": 1})),
        ("cursor.set", json!({"offset": 5})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, params: &serde_json::Value) -> Option<String> {
    let description = match method {
        "selection.set" => {
            let selection: Option<Selection> = params.get("selection").cloned().and_then(|value| serde_json::from_value(value).ok()).flatten();
            match selection {
                Some(selected) => {
                    let ranges = selected.ranges(usize::MAX);
                    format!("Select {}", super::edits::target_phrase(&ranges, false))
                }
                None => "Select nothing".to_string(),
            }
        }
        "cursor.set" => format!("Move the cursor to {:#x}", params.get("offset")?.as_u64()?),
        _ => return None,
    };
    Some(description)
}

/// Parameters that name just a document.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocParams {
    /// Document id, path or "current" (left out: the caller's focus).
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
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// What to select: {"range": [start, len]}, {"ranges": [[start, len], …]}
    /// or {"columns": {…}}; null or omitted selects nothing.
    #[serde(default)]
    pub selection: Option<Selection>,
    /// Where the cursor goes: the start or end of one of the selected ranges, which is then the
    /// range Shift extends from its other end (a column's cursor is at its end); the end of the
    /// last range when omitted. With nothing selected, any offset; the cursor stays when omitted.
    #[serde(default)]
    pub cursor: Option<u64>,
}

/// Parameters of `cursor.set`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetCursorParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset to put the cursor at; the document's length is just past the last byte.
    pub offset: u64,
}

pub fn set_selection(workspace: &mut dyn Workspace, caller: &Caller, params: SetSelectionParams) -> Result<SelectionResult, ApiError> {
    let (doc, document) = workspace::document(workspace, params.doc.as_deref())?;
    let len = document.len();
    let cursor = match (&params.selection, params.cursor) {
        (Some(selected), cursor) => {
            check_inside(selected, len)?;
            cursor_in(selected, &selected.ranges(len), cursor)?
        }
        (None, Some(cursor)) => values::span_within(len, cursor, Some(0))?.0,
        (None, None) => workspace.view(&doc).unwrap_or_default().cursor.min(len),
    };
    workspace.select(&doc, cursor, params.selection, caller);
    get_selection(workspace, DocParams { doc: Some(doc) })
}

/// Where the cursor goes in `selected` (whose ranges are `ranges`): at
/// `cursor` when that is the start or end of one of the ranges (a column's
/// end), else refused; at the end of the last range when not given.
fn cursor_in(selected: &Selection, ranges: &[(usize, usize)], cursor: Option<u64>) -> Result<usize, ApiError> {
    let end = ranges.last().map_or(0, |&(start, len)| start + len);
    let Some(cursor) = cursor else { return Ok(end) };
    let cursor = usize::try_from(cursor).unwrap_or(usize::MAX);
    let at_an_end = match selected {
        Selection::Columns(_) => cursor == end,
        _ => ranges.iter().any(|&(start, len)| cursor == start || cursor == start + len),
    };
    if !at_an_end {
        return Err(ApiError::invalid_params(format!("the cursor {cursor:#x} must sit at the start or end of a selected range (a column's cursor at its end)")));
    }
    Ok(cursor)
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
        let adrift = crate::api::call(&mut workspace, &caller, "selection.set", json!({"selection": {"range": [8, 8]}, "cursor": 10})).unwrap_err();
        assert_eq!(adrift.code, crate::api::ErrorCode::InvalidParams, "the cursor must sit at an end of a range");
        let producers: Vec<String> = crate::api::Workspace::bus(&mut workspace)
            .recent()
            .filter(|message| message.topic() == crate::bus::Topic::SelectionChanged)
            .map(|message| message.producer().to_string())
            .collect();
        assert_eq!(producers, ["mcp:claude-code", "mcp:claude-code"]);
    }

    #[test]
    fn a_selection_may_put_the_cursor_at_the_start_of_a_range_to_extend_it_backwards() {
        let mut workspace = workspace_with("a.bin", &[0; 64]);
        call(&mut workspace, "selection.set", json!({"selection": {"ranges": [[0, 4], [8, 4]]}, "cursor": 0})).unwrap();
        assert_eq!(call(&mut workspace, "cursor.get", json!({})).unwrap()["offset"], 0);
        call(&mut workspace, "selection.set", json!({"selection": {"range": [8, 4]}})).unwrap();
        assert_eq!(call(&mut workspace, "cursor.get", json!({})).unwrap()["offset"], 12, "the end of the last range when not given");
        call(&mut workspace, "selection.set", json!({"selection": null, "cursor": 20})).unwrap();
        assert_eq!(call(&mut workspace, "cursor.get", json!({})).unwrap()["offset"], 20, "with nothing selected the cursor goes anywhere");
        let column = json!({"columns": {"first_row_start": 0, "stride": 16, "column": 2, "width": 2, "rows": 3}});
        let error = call(&mut workspace, "selection.set", json!({"selection": column, "cursor": 2})).unwrap_err();
        assert_eq!(error.code, crate::api::ErrorCode::InvalidParams, "a column's cursor is at its end");
        assert_eq!(call(&mut workspace, "selection.set", json!({"selection": null, "cursor": 65})).unwrap_err().code, crate::api::ErrorCode::OutOfRange);
    }
}
