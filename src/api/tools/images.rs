//! `images.find`: the Images tool's search for uncompressed bitmaps (fonts,
//! splash screens, framebuffers) in a span.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::Workspace;
use crate::api::{ApiError, Caller};
use crate::image_finder::ImageCandidate;
use crate::raster::PixelFormat;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[method!(
    "images.find",
    Job,
    caller find,
    FindImagesParams,
    JobStartedResult,
    "Start a search of a span (at most 64 MiB) for uncompressed images, trying 1-bit, 8-bit grey, RGB565, RGB and RGBA at widths from 16 to 2048 pixels, as a job: the regions whose rows resemble each other, best first, are job.finished's result (view.set_shape shows one), and in the window they fill Images."
)];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("images.find", json!({"start": 0}))]
}

/// Most bytes searched.
pub const IMAGE_SEARCH_LIMIT: usize = 64 * 1024 * 1024;

/// Parameters of `images.find`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindImagesParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset searched (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes searched, at most 64 MiB; to the end of the document (or 64 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
}

/// An image found.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ImageFound {
    /// Document offset of the first pixel, and the bytes of its rows.
    pub start: u64,
    pub len: u64,
    pub format: PixelFormat,
    pub width: usize,
    pub height: usize,
    /// How much more alike neighbouring pixels are than random ones, 0 to 1.
    pub score: f32,
    /// The image in words.
    pub description: String,
}

/// What `images.find`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ImagesFound {
    /// The images, best first.
    pub images: Vec<ImageFound>,
}

impl ImagesFound {
    fn of(candidates: &[ImageCandidate]) -> Self {
        ImagesFound {
            images: candidates
                .iter()
                .map(|candidate| ImageFound {
                    start: candidate.start as u64,
                    len: candidate.len as u64,
                    format: candidate.format,
                    width: candidate.width,
                    height: candidate.height,
                    score: candidate.score,
                    description: candidate.description(),
                })
                .collect(),
        }
    }
}

/// `images.find`: read the span now and search it on a thread.
pub fn find(workspace: &mut dyn Workspace, caller: &Caller, params: FindImagesParams) -> Result<JobStartedResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, IMAGE_SEARCH_LIMIT, "the span searched")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(crate::panel_image_finder::await_search);
    let start = span.start;
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("images", "Find images"),
        &span,
        deliver,
        move |_| crate::image_finder::find_images(&bytes, start),
        |candidates| Summary::of(format!("{} candidates", candidates.len()), ImagesFound::of(candidates)),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn a_smooth_grey_picture_among_noise_is_found_with_its_width() {
        let mut state = 0x2545_F491u32;
        let mut noise = |len: usize| -> Vec<u8> {
            (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    (state >> 24) as u8
                })
                .collect()
        };
        let picture: Vec<u8> = (0..120 * 80).map(|index| ((index % 120) + (index / 120)) as u8).collect();
        let bytes = [noise(4096), picture, noise(4096)].concat();
        let mut workspace = workspace_with("picture.bin", &bytes);
        let status = run_job(&mut workspace, "images.find", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        let images = status["result"]["images"].as_array().unwrap();
        assert!(images.iter().any(|image| image["width"] == 120 && image["start"].as_u64().is_some_and(|start| start.abs_diff(4096) < 120)), "{images:?}");
        assert_eq!(call(&mut workspace, "images.find", json!({"start": bytes.len() + 1})).unwrap_err().code, ErrorCode::OutOfRange);
    }
}
