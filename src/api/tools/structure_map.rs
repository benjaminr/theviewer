//! `structure_map.*`: segmenting the file into regions of one kind,
//! finding the parts like a span, and tracking features along the file, as
//! the Structure map tool does. Its pins are `findings.publish` calls.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller, values};
use crate::bus::JobHandle;
use crate::segments::{self, SegmentOptions, Segmentation};
use crate::similar::{self, SimilarError, SimilarOptions, SimilarityScores};
use crate::tracks::{self, FeatureTracks, TrackOptions};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("structure_map.segment", Job, caller segment, DocOnlyParams, JobStartedResult, "Start splitting the document into stretches of uniform character, grouped into types (text, tables, compressed, padding…), as a background job; the segments are job.finished's result, and in the window the Structure map shows them."),
    method!("structure_map.find_similar", Job, caller find_similar, FindSimilarParams, JobStartedResult, "Start finding every part of the document whose statistics resemble a span, as a background job; the regions at or above the threshold are job.finished's result, and in the window the Structure map lists them."),
    method!("structure_map.tracks", Job, caller compute_tracks, DocOnlyParams, JobStartedResult, "Start measuring entropy, compressibility, byte kinds and the local record width along the document, as a background job; the tracks are job.finished's result, and in the window the Structure map draws them."),
];

/// An example call of each of [`METHODS`].
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("structure_map.segment", json!({})),
        ("structure_map.find_similar", json!({"start": 0, "len": 64, "histogram_weight": 0.5, "threshold": 0.6})),
        ("structure_map.tracks", json!({})),
    ]
}

/// What a call to one of this module's methods would do, in plain words.
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

/// Largest prefix of the document the Structure map analyses.
pub const SCAN_LIMIT: usize = 256 * 1024 * 1024;

/// Parameters naming only a document.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocOnlyParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// Parameters of `structure_map.find_similar`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindSimilarParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// The span to find more like.
    pub start: u64,
    pub len: u64,
    /// 0 compares statistics only, 1 the coarse byte histogram only (0.5 by default).
    #[serde(default)]
    pub histogram_weight: Option<f32>,
    /// Similarity a region needs, 0 to 1 (0.6 by default).
    #[serde(default)]
    pub threshold: Option<f32>,
}

/// One kind of segment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SegmentTypeResult {
    pub id: usize,
    /// Such as "Text" or "Table / records".
    pub label: String,
    pub count: usize,
    pub total_bytes: usize,
}

/// One segment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SegmentResult {
    pub start: usize,
    pub len: usize,
    /// The id of its type in `types`.
    pub type_id: usize,
    pub label: String,
    /// Why it has its type and where its start boundary came from.
    pub reason: String,
}

/// What `structure_map.segment`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SegmentationResult {
    /// Bytes analysed, from the start of the document.
    pub scanned_len: usize,
    pub block_size: usize,
    pub types: Vec<SegmentTypeResult>,
    pub segments: Vec<SegmentResult>,
}

impl SegmentationResult {
    pub fn of(segmentation: &Segmentation) -> Self {
        SegmentationResult {
            scanned_len: segmentation.scanned_len,
            block_size: segmentation.block_size,
            types: segmentation.types.iter().map(|kind| SegmentTypeResult { id: kind.id, label: kind.label.clone(), count: kind.count, total_bytes: kind.total_bytes }).collect(),
            segments: segmentation
                .segments
                .iter()
                .map(|segment| SegmentResult { start: segment.start, len: segment.len, type_id: segment.type_id, label: segment.label.clone(), reason: segment.reason.clone() })
                .collect(),
        }
    }
}

/// One region like the span.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SimilarRegionResult {
    pub start: usize,
    pub len: usize,
    /// Mean similarity of its blocks, 0 to 1.
    pub score: f32,
    /// Best similarity of any of its blocks.
    pub best: f32,
    pub blocks: usize,
}

/// What `structure_map.find_similar`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SimilarResult {
    /// The span searched for, as [start, len].
    pub span: (usize, usize),
    pub block_size: usize,
    pub threshold: f32,
    /// Regions at or above the threshold, best first.
    pub regions: Vec<SimilarRegionResult>,
}

impl SimilarResult {
    pub fn of(scores: &SimilarityScores, threshold: f32) -> Self {
        let regions = similar::matching_regions(scores, threshold)
            .into_iter()
            .map(|region| SimilarRegionResult { start: region.start, len: region.len, score: region.score, best: region.best, blocks: region.blocks })
            .collect();
        SimilarResult { span: scores.selection, block_size: scores.block_size, threshold, regions }
    }
}

/// What `structure_map.tracks`'s job finishes with: one entry per point
/// in each series.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TracksResult {
    /// Bytes analysed, from the start of the document.
    pub scanned_len: usize,
    /// Offset where each point's stretch starts.
    pub offsets: Vec<usize>,
    /// Entropy in bits per byte, 0 to 8.
    pub entropy: Vec<f32>,
    /// Compressed size over original size.
    pub compressibility: Vec<f32>,
    /// Fractions of zero, printable, other low and high bytes.
    pub zero: Vec<f32>,
    pub printable: Vec<f32>,
    pub control: Vec<f32>,
    pub high: Vec<f32>,
    /// Best local record width in bytes, or 0 where nothing repeats.
    pub width: Vec<usize>,
    /// How strongly that width repeats, 0 to 1.
    pub width_strength: Vec<f32>,
}

impl TracksResult {
    pub fn of(tracks: &FeatureTracks) -> Self {
        TracksResult {
            scanned_len: tracks.scanned_len,
            offsets: tracks.offsets.clone(),
            entropy: tracks.entropy.clone(),
            compressibility: tracks.compressibility.clone(),
            zero: tracks.kinds.iter().map(|kinds| kinds.zero).collect(),
            printable: tracks.kinds.iter().map(|kinds| kinds.printable).collect(),
            control: tracks.kinds.iter().map(|kinds| kinds.control).collect(),
            high: tracks.kinds.iter().map(|kinds| kinds.high).collect(),
            width: tracks.width.clone(),
            width_strength: tracks.width_strength.clone(),
        }
    }
}

/// Segment `bytes` and finish `job` with the segments, unless it was
/// cancelled. Returns them when the job finished with them.
pub fn run_segmentation(bytes: &[u8], job: &JobHandle) -> Option<Segmentation> {
    let result = segments::segment_file(bytes, &SegmentOptions::default());
    if job.is_cancelled() {
        job.finish_cancelled();
        return None;
    }
    job.finish_with(true, format!("{} segments", result.segments.len()), serde_json::to_value(SegmentationResult::of(&result)).ok());
    Some(result)
}

/// Score `bytes`' blocks against `span` and finish `job` with the regions
/// at `threshold`, unless it was cancelled.
pub fn run_similar(bytes: &[u8], span: (usize, usize), histogram_weight: f32, threshold: f32, job: &JobHandle) -> Option<Result<SimilarityScores, SimilarError>> {
    let options = SimilarOptions { histogram_weight, ..SimilarOptions::default() };
    let result = similar::score_blocks(bytes, span, &options);
    if job.is_cancelled() {
        job.finish_cancelled();
        return None;
    }
    match &result {
        Ok(scores) => job.finish_with(true, "scored", serde_json::to_value(SimilarResult::of(scores, threshold)).ok()),
        Err(error) => job.finish(false, error.to_string()),
    }
    Some(result)
}

/// Measure the tracks of `bytes` and finish `job` with them, unless it was
/// cancelled.
pub fn run_tracks(bytes: &[u8], job: &JobHandle) -> Option<FeatureTracks> {
    let tracks = tracks::compute_tracks(bytes, &TrackOptions::default());
    if job.is_cancelled() {
        job.finish_cancelled();
        return None;
    }
    job.finish_with(true, "computed", serde_json::to_value(TracksResult::of(&tracks)).ok());
    Some(tracks)
}

/// The document `doc` names, its version and its analysed prefix.
fn scanned(workspace: &mut dyn Workspace, doc: Option<&str>) -> Result<(String, u64, Vec<u8>), ApiError> {
    let id = workspace::resolve(workspace, doc)?;
    let version = workspace::info(workspace, &id)?.version;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let bytes = document.read_range(0, document.len().min(SCAN_LIMIT));
    Ok((id, version, bytes))
}

/// Whether document `id` is the one the window shows.
fn shown_in_window(workspace: &mut dyn Workspace, id: &str) -> bool {
    workspace.window().is_some_and(|app| app.document_id() == id)
}

pub fn segment(workspace: &mut dyn Workspace, caller: &Caller, params: DocOnlyParams) -> Result<JobStartedResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    if shown_in_window(workspace, &id)
        && let Some(app) = workspace.window()
    {
        return Ok(JobStartedResult { job: crate::panel_structure_map::segment_as(app, &caller.producer()) });
    }
    let (id, version, bytes) = scanned(workspace, Some(&id))?;
    let job = workspace.bus().start_job("structure-map", "Segmenting the file", caller.producer(), Some((id, version)));
    let started = JobStartedResult { job: job.id().to_string() };
    std::thread::spawn(move || run_segmentation(&bytes, &job));
    Ok(started)
}

pub fn find_similar(workspace: &mut dyn Workspace, caller: &Caller, params: FindSimilarParams) -> Result<JobStartedResult, ApiError> {
    let histogram_weight = params.histogram_weight.unwrap_or_else(|| SimilarOptions::default().histogram_weight);
    let threshold = params.threshold.unwrap_or(similar::DEFAULT_THRESHOLD);
    for (name, value) in [("histogram_weight", histogram_weight), ("threshold", threshold)] {
        if !(0.0..=1.0).contains(&value) {
            return Err(ApiError::invalid_params(format!("{name} {value} is outside 0 to 1")));
        }
    }
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let span = values::span_within(document.len(), params.start, Some(params.len))?;
    if span.1 == 0 {
        return Err(ApiError::invalid_params("the span to find more like is empty; give its len"));
    }
    if span.0 + span.1 > SCAN_LIMIT {
        return Err(ApiError::out_of_range(format!("the span must lie within the first {SCAN_LIMIT} bytes, which are what is searched")));
    }
    if shown_in_window(workspace, &id)
        && let Some(app) = workspace.window()
    {
        return Ok(JobStartedResult { job: crate::panel_structure_map::find_similar_as(app, span, histogram_weight, threshold, &caller.producer()) });
    }
    let (id, version, bytes) = scanned(workspace, Some(&id))?;
    let job = workspace.bus().start_job("similar-blocks", "Finding blocks like the selection", caller.producer(), Some((id, version)));
    let started = JobStartedResult { job: job.id().to_string() };
    std::thread::spawn(move || run_similar(&bytes, span, histogram_weight, threshold, &job));
    Ok(started)
}

pub fn compute_tracks(workspace: &mut dyn Workspace, caller: &Caller, params: DocOnlyParams) -> Result<JobStartedResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    if shown_in_window(workspace, &id)
        && let Some(app) = workspace.window()
    {
        return Ok(JobStartedResult { job: crate::panel_structure_map::tracks_as(app, &caller.producer()) });
    }
    let (id, version, bytes) = scanned(workspace, Some(&id))?;
    let job = workspace.bus().start_job("feature-tracks", "Feature tracks", caller.producer(), Some((id, version)));
    let started = JobStartedResult { job: job.id().to_string() };
    std::thread::spawn(move || run_tracks(&bytes, &job));
    Ok(started)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};
    use crate::api::tools::finished_job as finished;

    /// Text, then zeros, then text again.
    fn text_zeros_text() -> Vec<u8> {
        let mut bytes = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
        bytes.extend(vec![0; 4500]);
        bytes.extend(b"The quick brown fox jumps over the lazy dog. ".repeat(100));
        bytes
    }

    #[test]
    fn segmenting_tells_text_from_padding() {
        let mut workspace = workspace_with("notes.bin", &text_zeros_text());
        let started = call(&mut workspace, "structure_map.segment", json!({})).unwrap();
        let status = finished(&mut workspace, &started);
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["producer"], "panel");
        let segments = status["result"]["segments"].as_array().unwrap();
        assert!(segments.len() >= 3, "{status}");
        assert_eq!(status["result"]["scanned_len"], text_zeros_text().len());
    }

    #[test]
    fn finding_more_like_a_span_finds_the_other_text() {
        let bytes = text_zeros_text();
        let mut workspace = workspace_with("notes.bin", &bytes);
        let started = call(&mut workspace, "structure_map.find_similar", json!({"start": 0, "len": 1024, "histogram_weight": 0.5, "threshold": 0.6})).unwrap();
        let status = finished(&mut workspace, &started);
        assert_eq!(status["state"], "finished", "{status}");
        let regions = status["result"]["regions"].as_array().unwrap();
        assert!(regions.iter().any(|region| region["start"].as_u64().unwrap() >= 9000), "{status}");
        assert!(regions.iter().all(|region| region["start"].as_u64().unwrap() < 4500 || region["start"].as_u64().unwrap() >= 9000), "the zeros are not like text: {status}");
    }

    #[test]
    fn tracks_measure_every_point_along_the_document() {
        let mut workspace = workspace_with("notes.bin", &text_zeros_text());
        let started = call(&mut workspace, "structure_map.tracks", json!({})).unwrap();
        let status = finished(&mut workspace, &started);
        assert_eq!(status["state"], "finished", "{status}");
        let points = status["result"]["offsets"].as_array().unwrap().len();
        assert!(points > 1);
        assert_eq!(status["result"]["entropy"].as_array().unwrap().len(), points);
        assert_eq!(status["result"]["width"].as_array().unwrap().len(), points);
    }

    #[test]
    fn an_empty_span_or_settings_outside_zero_to_one_are_refused() {
        let mut workspace = workspace_with("notes.bin", &text_zeros_text());
        assert_eq!(call(&mut workspace, "structure_map.find_similar", json!({"start": 0, "len": 0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "structure_map.find_similar", json!({"start": 0, "len": 8, "threshold": 2.0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "structure_map.find_similar", json!({"start": 0, "len": 1_000_000})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "structure_map.segment", json!({"doc": "doc-9"})).unwrap_err().code, ErrorCode::NotFound);
    }
}
