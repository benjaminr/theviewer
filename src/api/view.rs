//! The view: `view.*` (the shape bytes are drawn in: width, origin and
//! padding), and what else the person changes about what is shown (panels,
//! layouts, bookmarks) when it matters for repeating an analysis.
//!
//! In the window these change the main view; a headless workspace keeps
//! them per document, so a recorded analysis replays the same way from the
//! command line. See `docs/design/ui-actions.md` for which view changes are
//! methods and which (zoom, scrolling, hovering) are not.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::workspace::{self, Workspace};
use super::{ApiError, ErrorCode};

/// Most pixels per row.
pub const MAX_WIDTH: usize = crate::app::MAX_WIDTH;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("view.get_shape", Read, get_shape, ShapeParams, ShapeResult, "The shape a document's bytes are drawn in: pixels per row, the offset of the first pixel, a bit shift and the bytes skipped after each row."),
    method!("view.set_shape", View, set_shape, SetShapeParams, ShapeResult, "Change the shape a document's bytes are drawn in (pixels per row, the first pixel's offset and bit, the padding after each row); what is not given stays as it is."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("view.set_shape", json!({"width": 48, "offset": 16, "row_padding": 2})), ("view.get_shape", json!({}))]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, params: &serde_json::Value) -> Option<String> {
    let description = match method {
        "view.set_shape" => {
            let params: SetShapeParams = serde_json::from_value(params.clone()).ok()?;
            let mut changes = Vec::new();
            if let Some(width) = params.width {
                changes.push(format!("{width} pixels per row"));
            }
            if let Some(offset) = params.offset {
                changes.push(format!("the first pixel at {offset:#x}"));
            }
            if let Some(bit) = params.bit_offset {
                changes.push(format!("shifted by {bit} bits"));
            }
            if let Some(padding) = params.row_padding {
                changes.push(format!("{padding} bytes skipped after each row"));
            }
            if changes.is_empty() { "Leave the view's shape as it is".to_string() } else { format!("Draw the bytes with {}", changes.join(", ")) }
        }
        _ => return None,
    };
    Some(description)
}

/// The shape a document's bytes are drawn in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ViewShape {
    /// Pixels per row.
    pub width: usize,
    /// Document offset of the first pixel.
    pub offset: u64,
    /// Extra bit shift (0 to 7) after `offset`.
    pub bit_offset: u32,
    /// Bytes skipped after each row's pixels.
    pub row_padding: usize,
}

impl Default for ViewShape {
    fn default() -> Self {
        ViewShape { width: crate::preferences::DEFAULT_WIDTH, offset: 0, bit_offset: 0, row_padding: 0 }
    }
}

/// Parameters of `view.get_shape`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapeParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// Parameters of `view.set_shape`: the parts to change.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetShapeParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Pixels per row, 1 to 16384.
    #[serde(default)]
    pub width: Option<usize>,
    /// Document offset of the first pixel; at most the document's length.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Extra bit shift after `offset`, 0 to 7.
    #[serde(default)]
    pub bit_offset: Option<u32>,
    /// Bytes skipped after each row's pixels.
    #[serde(default)]
    pub row_padding: Option<usize>,
}

/// The result of `view.get_shape` and `view.set_shape`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeResult {
    /// Id of the document.
    pub doc: String,
    /// The shape its bytes are drawn in now.
    pub shape: ViewShape,
}

pub fn get_shape(workspace: &mut dyn Workspace, params: ShapeParams) -> Result<ShapeResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let shape = workspace.shape(&id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
    Ok(ShapeResult { doc: id, shape })
}

pub fn set_shape(workspace: &mut dyn Workspace, params: SetShapeParams) -> Result<ShapeResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let len = workspace::info(workspace, &id)?.len;
    let mut shape = workspace.shape(&id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
    if let Some(width) = params.width {
        if !(1..=MAX_WIDTH).contains(&width) {
            return Err(ApiError::invalid_params(format!("a width of {width} pixels is outside 1 to {MAX_WIDTH}")));
        }
        shape.width = width;
    }
    if let Some(offset) = params.offset {
        if offset > len {
            return Err(ApiError::out_of_range(format!("offset {offset:#x} is past the end of the document ({len} bytes)")));
        }
        shape.offset = offset;
    }
    if let Some(bit_offset) = params.bit_offset {
        if bit_offset > 7 {
            return Err(ApiError::new(ErrorCode::InvalidParams, format!("a bit shift of {bit_offset} is more than 7; move the offset on by whole bytes instead")));
        }
        shape.bit_offset = bit_offset;
    }
    if let Some(row_padding) = params.row_padding {
        shape.row_padding = row_padding;
    }
    workspace.set_shape(&id, shape)?;
    get_shape(workspace, ShapeParams { doc: Some(id) })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::{call, workspace_with};
    use crate::api::{ErrorCode, Workspace};

    #[test]
    fn a_shape_change_keeps_what_it_does_not_mention_and_sets_the_record_stride() {
        let mut workspace = workspace_with("a.bin", &[0u8; 256]);
        call(&mut workspace, "view.set_shape", json!({"width": 48, "row_padding": 4})).unwrap();
        let shape = call(&mut workspace, "view.set_shape", json!({"offset": 16})).unwrap();
        assert_eq!(shape["shape"], json!({"width": 48, "offset": 16, "bit_offset": 0, "row_padding": 4}));
        assert_eq!(workspace.view("doc-1").unwrap().record_stride, Some(52), "columns and findings read records 52 bytes apart");
    }

    #[test]
    fn a_shape_outside_the_document_or_the_limits_is_refused() {
        let mut workspace = workspace_with("a.bin", &[0u8; 16]);
        assert_eq!(call(&mut workspace, "view.set_shape", json!({"offset": 17})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "view.set_shape", json!({"width": 0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "view.set_shape", json!({"bit_offset": 8})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "view.get_shape", json!({})).unwrap()["shape"]["offset"], 0, "nothing changed");
    }
}
