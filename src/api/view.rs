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
use crate::bookmarks::{Bookmark, Sidecar};
use crate::raster::PixelFormat;

/// Most pixels per row.
pub const MAX_WIDTH: usize = crate::app::MAX_WIDTH;
/// Most padding bytes after each row, as the toolbar allows; far more
/// would overflow a row's length in bits.
pub const MAX_ROW_PADDING: usize = MAX_WIDTH * 4;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("view.get_shape", Read, get_shape, ShapeParams, ShapeResult, "The shape a document's bytes are drawn in: the pixel format, pixels per row, the offset of the first pixel, a bit shift and the bytes skipped after each row."),
    method!("view.set_shape", View, set_shape, SetShapeParams, ShapeResult, "Change the shape a document's bytes are drawn in (the pixel format, pixels per row, the first pixel's offset and bit, the padding after each row); what is not given stays as it is.").reverses(crate::api::Reverse::Shape).merges_repeats(),
    method!("view.fold", View, fold, FoldParams, FoldsResult, "Skip ranges of a document in its views (the raster and the hex dump) without deleting them; a marker shows where each was.").reverses(crate::api::Reverse::Folds),
    method!("view.unfold", View, unfold, UnfoldParams, FoldsResult, "Show skipped bytes again: the skipped range starting at an offset, or all of them.").reverses(crate::api::Reverse::Folds),
    method!("bookmarks.list", Read, list_bookmarks, BookmarksParams, BookmarksResult, "A document's bookmarks, in offset order."),
    method!("bookmarks.add", View, add_bookmark, AddBookmarkParams, BookmarksResult, "Bookmark a byte or a span of a document with a name, replacing a bookmark at the same offset; the window keeps them beside the file.").reverses(crate::api::Reverse::AddBookmark),
    method!("bookmarks.remove", View, remove_bookmark, RemoveBookmarkParams, BookmarksResult, "Remove the bookmark at an offset.").reverses(crate::api::Reverse::RemoveBookmark),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("view.set_shape", json!({"format": "rgb565", "width": 48, "offset": 16, "row_padding": 2})),
        ("view.get_shape", json!({})),
        ("view.fold", json!({"ranges": [[16, 32], [100, 8]]})),
        ("view.unfold", json!({"start": 16})),
        ("bookmarks.add", json!({"start": 4, "len": 2, "name": "magic"})),
        ("bookmarks.list", json!({})),
        ("bookmarks.remove", json!({"start": 4})),
    ]
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
        "view.fold" => {
            let params: FoldParams = serde_json::from_value(params.clone()).ok()?;
            let ranges: Vec<(usize, usize)> = params.ranges.iter().map(|&(start, len)| (start as usize, len as usize)).collect();
            format!("Skip {} in the views", super::edits::target_phrase(&ranges, false))
        }
        "view.unfold" => match params.get("start").and_then(serde_json::Value::as_u64) {
            Some(start) => format!("Show the skipped bytes at {start:#x} again"),
            None => "Show every skipped range again".to_string(),
        },
        "bookmarks.add" => format!("Bookmark {:#x} as \"{}\"", params.get("start")?.as_u64()?, params.get("name")?.as_str()?),
        "bookmarks.remove" => format!("Remove the bookmark at {:#x}", params.get("start")?.as_u64()?),
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
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
}

/// Parameters of `view.set_shape`: the parts to change.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetShapeParams {
    /// Document id, path or "current" (left out: the caller's focus).
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
        if row_padding > MAX_ROW_PADDING {
            return Err(ApiError::invalid_params(format!("{row_padding} bytes of row padding is more than {MAX_ROW_PADDING}")));
        }
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

/// Parameters of `view.fold`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// The spans to skip, as [start, len]; they join spans already skipped that they touch.
    pub ranges: Vec<(u64, u64)>,
}

/// Parameters of `view.unfold`: `start` or `all`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnfoldParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// Where the skipped range to show again starts.
    #[serde(default)]
    pub start: Option<u64>,
    /// Show every skipped range again.
    #[serde(default)]
    pub all: bool,
}

/// The result of `view.fold` and `view.unfold`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FoldsResult {
    /// Id of the document.
    pub doc: String,
    /// Every span skipped now, as [start, len] in document order.
    pub folds: Vec<(u64, u64)>,
}

/// Parameters of `bookmarks.list`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BookmarksParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
}

/// Parameters of `bookmarks.add`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddBookmarkParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the bookmarked byte or span.
    pub start: u64,
    /// Bytes the bookmark covers; 0 marks just the offset.
    #[serde(default)]
    pub len: u64,
    /// What to call it.
    pub name: String,
}

/// Parameters of `bookmarks.remove`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoveBookmarkParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the bookmark to remove.
    pub start: u64,
}

/// One bookmark.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BookmarkInfo {
    /// Offset of the bookmarked byte or span.
    pub start: u64,
    /// Bytes it covers; 0 marks just the offset.
    pub len: u64,
    /// What it is called.
    pub name: String,
}

/// The result of the `bookmarks.*` methods.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BookmarksResult {
    /// Id of the document.
    pub doc: String,
    /// Its bookmarks now, in offset order.
    pub bookmarks: Vec<BookmarkInfo>,
}

fn folds_result(workspace: &dyn Workspace, id: String) -> Result<FoldsResult, ApiError> {
    let folds = workspace.folds(&id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
    Ok(FoldsResult { folds: folds.ranges().iter().map(|&(start, len)| (start as u64, len as u64)).collect(), doc: id })
}

pub fn fold(workspace: &mut dyn Workspace, params: FoldParams) -> Result<FoldsResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let len = workspace::info(workspace, &id)?.len as usize;
    if params.ranges.iter().all(|&(_, range_len)| range_len == 0) {
        return Err(ApiError::invalid_params("nothing to skip: give at least one span of one byte or more"));
    }
    let mut folds = workspace.folds(&id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
    for &(start, range_len) in &params.ranges {
        let (start, range_len) = super::values::span_within(len, start, Some(range_len))?;
        folds.fold(start, range_len);
    }
    workspace.set_folds(&id, folds)?;
    folds_result(workspace, id)
}

pub fn unfold(workspace: &mut dyn Workspace, params: UnfoldParams) -> Result<FoldsResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let mut folds = workspace.folds(&id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
    match (params.start, params.all) {
        (Some(start), false) => {
            if !folds.unfold(start as usize) {
                return Err(ApiError::not_found(format!("nothing skipped starts at {start:#x}; view.fold's result lists what is")));
            }
        }
        (None, true) => folds.clear(),
        _ => return Err(ApiError::invalid_params("give the start of one skipped range, or all: true, not both")),
    }
    workspace.set_folds(&id, folds)?;
    folds_result(workspace, id)
}

/// The bookmarks of document `id`, refused when it has none to show.
fn bookmarks_of(workspace: &dyn Workspace, id: &str) -> Result<Vec<Bookmark>, ApiError> {
    workspace.bookmarks(id).ok_or_else(|| ApiError::invalid_params(format!("{id} has no bookmarks here: it is not open")))
}

fn bookmarks_result(id: String, bookmarks: &[Bookmark]) -> BookmarksResult {
    let bookmarks = bookmarks.iter().map(|bookmark| BookmarkInfo { start: bookmark.offset as u64, len: bookmark.len as u64, name: bookmark.name.clone() }).collect();
    BookmarksResult { doc: id, bookmarks }
}

pub fn list_bookmarks(workspace: &mut dyn Workspace, params: BookmarksParams) -> Result<BookmarksResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let bookmarks = bookmarks_of(workspace, &id)?;
    Ok(bookmarks_result(id, &bookmarks))
}

pub fn add_bookmark(workspace: &mut dyn Workspace, params: AddBookmarkParams) -> Result<BookmarksResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let len = workspace::info(workspace, &id)?.len as usize;
    let (start, span) = super::values::span_within(len, params.start, Some(params.len))?;
    let mut sidecar = Sidecar { bookmarks: bookmarks_of(workspace, &id)?, shape: None };
    sidecar.set(Bookmark { offset: start, len: span, name: params.name, note: String::new() });
    workspace.set_bookmarks(&id, sidecar.bookmarks.clone())?;
    Ok(bookmarks_result(id, &sidecar.bookmarks))
}

pub fn remove_bookmark(workspace: &mut dyn Workspace, params: RemoveBookmarkParams) -> Result<BookmarksResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let mut sidecar = Sidecar { bookmarks: bookmarks_of(workspace, &id)?, shape: None };
    if !sidecar.remove(params.start as usize) {
        return Err(ApiError::not_found(format!("no bookmark starts at {:#x}; bookmarks.list shows them", params.start)));
    }
    workspace.set_bookmarks(&id, sidecar.bookmarks.clone())?;
    Ok(bookmarks_result(id, &sidecar.bookmarks))
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

    /// The person jumps to `offset` (a click on the file map or a curve):
    /// the cursor moves there as `cursor.set` and both panes show it.
    pub fn go_to_offset(&mut self, offset: usize) {
        if self.perform("cursor.set", serde_json::json!({ "offset": offset.min(self.document.len()) })).is_ok() {
            self.reveal_cursor_centred();
            self.reveal_cursor_in_hex(true);
        }
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
    fn row_padding_too_large_to_draw_is_refused() {
        let mut workspace = workspace_with("a.bin", &[0u8; 256]);
        let refused = call(&mut workspace, "view.set_shape", json!({"row_padding": (1u64 << 61) - 1})).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidParams);
        assert!(call(&mut workspace, "view.set_shape", json!({"row_padding": super::MAX_ROW_PADDING})).is_ok(), "the toolbar's largest padding is allowed");
    }

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

    #[test]
    fn skipped_ranges_join_when_they_touch_and_show_again_one_by_one_or_all_at_once() {
        let mut workspace = workspace_with("a.bin", &[0u8; 256]);
        call(&mut workspace, "view.fold", json!({"ranges": [[16, 16]]})).unwrap();
        let folded = call(&mut workspace, "view.fold", json!({"ranges": [[32, 8], [100, 4]]})).unwrap();
        assert_eq!(folded["folds"], json!([[16, 24], [100, 4]]));
        let shown = call(&mut workspace, "view.unfold", json!({"start": 16})).unwrap();
        assert_eq!(shown["folds"], json!([[100, 4]]));
        let none = call(&mut workspace, "view.unfold", json!({"all": true})).unwrap();
        assert_eq!(none["folds"], json!([]));
    }

    #[test]
    fn skipping_outside_the_document_nothing_or_an_unknown_range_is_refused() {
        let mut workspace = workspace_with("a.bin", &[0u8; 16]);
        assert_eq!(call(&mut workspace, "view.fold", json!({"ranges": [[8, 9]]})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "view.fold", json!({"ranges": []})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "view.unfold", json!({"start": 3})).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "view.unfold", json!({})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "view.unfold", json!({"start": 3, "all": true})).unwrap_err().code, ErrorCode::InvalidParams);
        assert!(workspace.folds("doc-1").unwrap().is_empty(), "nothing was skipped");
    }

    #[test]
    fn bookmarks_are_kept_per_document_in_offset_order_and_replace_one_at_the_same_offset() {
        let mut workspace = workspace_with("a.bin", &[0u8; 64]);
        call(&mut workspace, "bookmarks.add", json!({"start": 40, "name": "footer"})).unwrap();
        call(&mut workspace, "bookmarks.add", json!({"start": 4, "len": 2, "name": "magic"})).unwrap();
        let renamed = call(&mut workspace, "bookmarks.add", json!({"start": 40, "len": 8, "name": "trailer"})).unwrap();
        assert_eq!(renamed["bookmarks"], json!([{"start": 4, "len": 2, "name": "magic"}, {"start": 40, "len": 8, "name": "trailer"}]));
        let left = call(&mut workspace, "bookmarks.remove", json!({"start": 4})).unwrap();
        assert_eq!(left["bookmarks"].as_array().unwrap().len(), 1);
        workspace.add_document("b.bin", crate::document::Document::from_bytes(vec![0; 8]));
        assert_eq!(call(&mut workspace, "bookmarks.list", json!({})).unwrap()["bookmarks"], json!([]), "another document has its own");
        assert_eq!(call(&mut workspace, "bookmarks.list", json!({"doc": "doc-1"})).unwrap()["bookmarks"][0]["name"], "trailer");
    }

    #[test]
    fn a_bookmark_outside_the_document_or_one_not_there_is_refused() {
        let mut workspace = workspace_with("a.bin", &[0u8; 16]);
        assert_eq!(call(&mut workspace, "bookmarks.add", json!({"start": 12, "len": 5, "name": "x"})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "bookmarks.remove", json!({"start": 0})).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "bookmarks.add", json!({"start": 0})).unwrap_err().code, ErrorCode::InvalidParams, "a bookmark needs a name");
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

        #[test]
        fn skipping_the_selection_and_showing_it_again_are_fold_steps() {
            let mut app = app_with(&[0u8; 256]);
            app.set_selection(32, Some(crate::selection::Selection::Range(16, 16)));
            app.skip_selection();
            assert_eq!(take_performed(), [("view.fold".to_string(), json!({"ranges": [[16, 16]]}))]);
            assert_eq!((app.folds.ranges(), app.cursor), (&[(16, 16)][..], 32));
            assert_eq!(app.status, "Skipped 16 bytes in 1 places; click a marker to show them again");
            app.unfold(16);
            assert_eq!(take_performed(), [("view.unfold".to_string(), json!({"start": 16}))]);
            assert!(app.folds.is_empty());
            app.set_selection(8, Some(crate::selection::Selection::Ranges(vec![(0, 4), (4, 4)])));
            app.skip_selection();
            app.unfold_all();
            let performed = take_performed();
            assert_eq!(performed.last(), Some(&("view.unfold".to_string(), json!({"all": true}))));
            assert_eq!((app.folds.is_empty(), app.status.as_str()), (true, "Showing every skipped range again"));
        }

        #[test]
        fn a_click_on_the_file_map_or_a_curve_moves_the_cursor_as_the_person() {
            let mut app = app_with(&[0u8; 256]);
            app.go_to_offset(0x90);
            app.go_to_offset(9999);
            assert_eq!(take_performed(), [("cursor.set".to_string(), json!({"offset": 0x90})), ("cursor.set".to_string(), json!({"offset": 256}))], "past the end is the end");
            assert_eq!(app.cursor, 256);
        }

        #[test]
        fn bookmarking_removing_and_jumping_to_bookmarks_go_through_the_api() {
            let mut app = app_with(&[0u8; 256]);
            app.add_bookmark(0x20, 4, "header".to_string());
            app.add_bookmark(0x80, 0, "mark 0x80".to_string());
            assert_eq!(
                take_performed(),
                [
                    ("bookmarks.add".to_string(), json!({"start": 0x20, "len": 4, "name": "header"})),
                    ("bookmarks.add".to_string(), json!({"start": 0x80, "len": 0, "name": "mark 0x80"})),
                ]
            );
            assert_eq!(app.status, "Bookmarked mark 0x80 at 0x80");
            app.goto_bookmark(true);
            assert_eq!(take_performed(), [("selection.set".to_string(), json!({"selection": {"range": [0x20, 4]}}))], "a bookmarked span is selected");
            assert_eq!((app.selection(), app.status.as_str()), (Some((0x20, 4)), "Bookmark: header"));
            app.goto_bookmark(true);
            assert_eq!(take_performed(), [("cursor.set".to_string(), json!({"offset": 0x80}))]);
            assert_eq!(app.cursor, 0x80);
            app.remove_bookmark(0x20);
            assert_eq!(take_performed(), [("bookmarks.remove".to_string(), json!({"start": 0x20}))]);
            assert_eq!(app.bookmarks.bookmarks.len(), 1);
        }

        #[test]
        fn the_palette_s_view_file_and_bookmark_commands_are_method_calls() {
            let mut app = app_with(&[0u8; 256]);
            app.add_bookmark(0x10, 0, "mark".to_string());
            app.set_cursor(0x20, false);
            take_performed();
            let ctx = eframe::egui::Context::default();
            let expected = [
                ("view.origin_cursor", "view.set_shape"),
                ("view.origin_reset", "view.set_shape"),
                ("bookmark.next", "cursor.set"),
                ("plugins.reload", "plugins.reload"),
                ("file.new", "documents.new"),
            ];
            for (id, method) in expected {
                let command = crate::commands::commands().into_iter().find(|command| command.id == id).unwrap();
                (command.run)(&mut app, &ctx);
                let performed = take_performed();
                assert_eq!(performed.first().map(|(name, _)| name.as_str()), Some(method), "{id}");
            }
        }
    }
}
