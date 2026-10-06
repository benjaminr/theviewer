//! The view: `view.*` (the shape bytes are drawn in: pixel format, width,
//! origin and padding), and what else the person changes about what is
//! shown (panels, layouts, bookmarks) when it matters for repeating an
//! analysis.
//!
//! In the window these change the main view; a headless workspace keeps
//! them per document, so a recorded analysis replays the same way from the
//! command line. See `docs/design/ui-actions.md` for which view changes are
//! methods and which (zoom, scrolling, hovering) are not.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::workspace::{self, Workspace};
use super::{ApiError, ErrorCode};
use crate::raster::PixelFormat;

/// Most pixels per row.
pub const MAX_WIDTH: usize = crate::app::MAX_WIDTH;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("view.get_shape", Read, get_shape, ShapeParams, ShapeResult, "The shape a document's bytes are drawn in: the pixel format, pixels per row, the offset of the first pixel, a bit shift and the bytes skipped after each row."),
    method!("view.set_shape", View, set_shape, SetShapeParams, ShapeResult, "Change the shape a document's bytes are drawn in (the pixel format, pixels per row, the first pixel's offset and bit, the padding after each row); what is not given stays as it is."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("view.set_shape", json!({"format": "rgb565", "width": 48, "offset": 16, "row_padding": 2})), ("view.get_shape", json!({}))]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, params: &serde_json::Value) -> Option<String> {
    let description = match method {
        "view.set_shape" => {
            let params: SetShapeParams = serde_json::from_value(params.clone()).ok()?;
            let mut changes = Vec::new();
            if let Some(format) = params.format {
                changes.push(format!("pixels as {}", format.label()));
            }
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
    /// How bytes are read as pixels.
    pub format: PixelFormat,
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
        ViewShape { format: PixelFormat::Gray8, width: crate::preferences::DEFAULT_WIDTH, offset: 0, bit_offset: 0, row_padding: 0 }
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
    /// How bytes are read as pixels, such as "gray8", "rgb565" or "bit1".
    #[serde(default)]
    pub format: Option<PixelFormat>,
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
    if let Some(format) = params.format {
        shape.format = format;
    }
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

/// Pixels per row and padding bytes that make one row of `format` pixels
/// `period` bytes long.
pub fn width_for_period(format: PixelFormat, period: usize) -> (usize, usize) {
    let bits = format.bits_per_pixel();
    if bits >= 8 {
        let bytes = bits / 8;
        let width = (period / bytes).clamp(1, MAX_WIDTH);
        (width, period.saturating_sub(width * bytes))
    } else {
        ((period * 8 / bits).clamp(1, MAX_WIDTH), 0)
    }
}

/// The person's changes to the view's shape in the window, each a
/// `view.set_shape` step. Zoom, scrolling and panning stay direct.
impl crate::app::ViewerApp {
    /// Move the view's origin to byte `offset` (a view offset, skipped
    /// bytes left out) and bit `bit_offset`; whether it moved.
    pub fn change_origin(&mut self, offset: usize, bit_offset: u32) -> bool {
        self.perform("view.set_shape", serde_json::json!({ "offset": offset, "bit_offset": bit_offset })).is_ok()
    }

    /// Read the bytes as `format` pixels.
    pub fn change_format(&mut self, format: PixelFormat) {
        let _ = self.perform("view.set_shape", serde_json::json!({ "format": format }));
    }

    /// Skip `row_padding` bytes after each row.
    pub fn change_row_padding(&mut self, row_padding: usize) {
        let _ = self.perform("view.set_shape", serde_json::json!({ "row_padding": row_padding }));
    }

    /// An image layout: `format` pixels, `width` to a row, nothing skipped.
    pub fn apply_image_layout(&mut self, format: PixelFormat, width: usize) {
        let _ = self.perform("view.set_shape", serde_json::json!({ "format": format, "width": width.clamp(1, MAX_WIDTH), "row_padding": 0 }));
    }
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
        assert_eq!(shape["shape"], json!({"format": "gray8", "width": 48, "offset": 16, "bit_offset": 0, "row_padding": 4}));
        assert_eq!(workspace.view("doc-1").unwrap().record_stride, Some(52), "columns and findings read records 52 bytes apart");
    }

    #[test]
    fn a_shape_outside_the_document_or_the_limits_is_refused() {
        let mut workspace = workspace_with("a.bin", &[0u8; 16]);
        assert_eq!(call(&mut workspace, "view.set_shape", json!({"offset": 17})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "view.set_shape", json!({"width": 0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "view.set_shape", json!({"bit_offset": 8})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "view.set_shape", json!({"format": "rgb9"})).unwrap_err().code, ErrorCode::InvalidParams);
        let shape = call(&mut workspace, "view.get_shape", json!({})).unwrap()["shape"].clone();
        assert_eq!((shape["offset"].as_u64(), shape["format"].as_str()), (Some(0), Some("gray8")), "nothing changed");
    }

    #[test]
    fn a_pixel_format_sets_how_many_bytes_a_row_reads() {
        let mut workspace = workspace_with("a.bin", &[0u8; 256]);
        let shape = call(&mut workspace, "view.set_shape", json!({"format": "rgb565", "width": 16, "row_padding": 2})).unwrap();
        assert_eq!(shape["shape"]["format"], "rgb565");
        assert_eq!(workspace.view("doc-1").unwrap().record_stride, Some(34), "16 two-byte pixels and 2 bytes of padding");
        call(&mut workspace, "view.set_shape", json!({"format": "bit1"})).unwrap();
        assert_eq!(workspace.view("doc-1").unwrap().record_stride, Some(4), "16 one-bit pixels are 2 bytes");
    }

    mod window {
        use serde_json::json;

        use crate::actions::take_performed;
        use crate::analysis::{Candidate, PeriodScan};
        use crate::api::{Caller, call};
        use crate::app::{Launch, ViewerApp};
        use crate::raster::PixelFormat;

        fn app_with(bytes: &[u8]) -> ViewerApp {
            let mut app = ViewerApp::new(Launch::default());
            app.open_bytes(bytes.to_vec(), "test.bin".to_string());
            app.run_bus();
            take_performed();
            app
        }

        fn performed_shape(params: serde_json::Value) -> Vec<(String, serde_json::Value)> {
            vec![("view.set_shape".to_string(), params)]
        }

        #[test]
        fn applying_a_period_sets_the_width_and_padding_as_one_view_step() {
            let mut app = app_with(&[0u8; 4096]);
            app.change_format(PixelFormat::Rgb8);
            take_performed();
            app.apply_period(100);
            assert_eq!(take_performed(), performed_shape(json!({"width": 33, "row_padding": 1})), "33 three-byte pixels and a byte over");
            assert_eq!((app.shape.width, app.shape.row_padding, app.status.as_str()), (33, 1, "Width set from a 100 byte period"));
        }

        #[test]
        fn guessing_the_image_shape_sets_the_format_width_and_padding_in_one_step() {
            let mut app = app_with(&[0u8; 4096]);
            let best = Candidate { period: 192, score: 1.0, prominence: 9.0, column_gain: 1.0, multiple_of: None };
            app.period_scan = Some(PeriodScan { window_start: 0, window_len: 4096, scores: Vec::new(), baseline: 0.0, candidates: vec![best] });
            app.guess_image_shape();
            assert_eq!(take_performed(), performed_shape(json!({"format": "rgba8", "width": 48, "row_padding": 0})));
            assert_eq!((app.shape.format, app.shape.width), (PixelFormat::Rgba8, 48));
            assert_eq!(app.status, "Guessed RGBA 32-bit at 192 bytes per row");
        }

        #[test]
        fn moving_the_origin_to_the_cursor_back_to_the_start_or_by_bits_are_view_steps() {
            let mut app = app_with(&[0u8; 256]);
            app.set_cursor(0x40, false);
            app.align_view_to_cursor();
            assert_eq!(take_performed(), performed_shape(json!({"offset": 0x40, "bit_offset": 0})));
            assert_eq!((app.shape.byte_offset, app.status.as_str()), (0x40, "View origin set to 0x40"));
            app.adjust_bit_offset(-1);
            assert_eq!(take_performed(), performed_shape(json!({"offset": 0x3F, "bit_offset": 7})), "a bit back crosses into the byte before");
            app.adjust_bit_offset(-1000);
            assert_eq!(take_performed(), performed_shape(json!({"offset": 0, "bit_offset": 0})), "the origin stops at the start");
            app.change_origin(3, 2);
            app.reset_origin();
            take_performed();
            assert_eq!((app.shape.byte_offset, app.shape.bit_offset), (0, 0));
        }

        #[test]
        fn the_toolbar_s_format_padding_and_image_layouts_are_view_steps() {
            let mut app = app_with(&[0u8; 256]);
            app.change_format(PixelFormat::Rgb565);
            app.change_row_padding(4);
            app.apply_image_layout(PixelFormat::Bit1Msb, 128);
            assert_eq!(
                take_performed(),
                [
                    ("view.set_shape".to_string(), json!({"format": "rgb565"})),
                    ("view.set_shape".to_string(), json!({"row_padding": 4})),
                    ("view.set_shape".to_string(), json!({"format": "bit1", "width": 128, "row_padding": 0})),
                ]
            );
            assert_eq!((app.shape.format, app.shape.width, app.shape.row_padding), (PixelFormat::Bit1Msb, 128, 0));
        }

        #[test]
        fn applying_the_settings_to_the_window_sets_their_format_and_width_as_a_view_step() {
            let mut app = app_with(&[0u8; 256]);
            app.preferences.format = "rgb8".to_string();
            app.preferences.width = 320;
            app.apply_preferences_to_window();
            assert_eq!(take_performed(), performed_shape(json!({"format": "rgb8", "width": 320})));
            assert_eq!((app.shape.format, app.shape.width), (PixelFormat::Rgb8, 320));
        }

        #[test]
        fn the_window_draws_its_bytes_in_the_pixel_format_set() {
            let mut app = ViewerApp::new(Launch::default());
            app.open_bytes(vec![0; 64], "test.bin".to_string());
            let shape = call(&mut app, &Caller::Panel, "view.set_shape", json!({"format": "rgba8", "width": 4})).unwrap();
            assert_eq!((app.shape.format, app.shape.width), (PixelFormat::Rgba8, 4));
            assert_eq!(shape["shape"]["format"], "rgba8");
        }
    }
}
