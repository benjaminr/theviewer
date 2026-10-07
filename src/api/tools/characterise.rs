//! `characterise.*`: the Characterise tool's compressibility profiles, of a
//! selection or sampled along the whole document, and its search for raw
//! media streams. Its text encoding is `analysis.text_encoding`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller};
use crate::codec_profile::Profile;
use crate::panel_characterise::{self, CompressionResult, StreamScan};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("characterise.profile_selection", Job, caller profile_selection, ProfileSpanParams, JobStartedResult, "Start compressing a sample of a span with deflate, bzip2, LZ4, zstd and an order-1 entropy coder as a job: the ratios and the verdict they give (encrypted or random, already compressed, lossy media or structured) are job.finished's result, and in the window they fill Characterise (analysis.compressibility is the quick read)."),
    method!("characterise.profile_file", Job, caller profile_file, ProfileFileParams, JobStartedResult, "Start profiling the compressibility of the whole document as a job, overall and for up to 64 segments sampled along it: the verdicts are job.finished's result, and in the window they fill Characterise with a strip of verdicts."),
    method!("characterise.streams", Job, caller streams, ProfileFileParams, JobStartedResult, "Start a search of the document (its first 256 MiB) for raw MP3/MP2 and AAC frames, H.264 and H.265 Annex B video and 16-bit PCM audio without a container as a job: the runs found are job.finished's result, and in the window they fill Characterise."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("characterise.profile_selection", json!({"start": 0, "len": 8})), ("characterise.profile_file", json!({})), ("characterise.streams", json!({}))]
}

/// Parameters of `characterise.profile_selection`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileSpanParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset of the span (0 by default).
    pub start: u64,
    /// Bytes in the span; a sample of at most 256 KiB is compressed, slices spread along it.
    pub len: u64,
}

/// Parameters of `characterise.profile_file` and `characterise.streams`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileFileParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// How well one codec compressed the sample.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CodecResult {
    /// Such as "deflate -9" or "zstd -19".
    pub codec: String,
    /// Compressed size, and that over the sample's, when it worked.
    pub compressed_len: Option<u64>,
    pub ratio: Option<f64>,
    /// Why it failed, when it did.
    pub error: Option<String>,
}

/// A compressibility profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompressibilityProfile {
    /// Such as "already compressed".
    pub verdict: String,
    /// The measured values behind it.
    pub reason: String,
    pub sample_len: u64,
    /// Bits per byte of the sample.
    pub entropy: f64,
    pub codecs: Vec<CodecResult>,
}

impl CompressibilityProfile {
    fn of(profile: &Profile) -> Self {
        CompressibilityProfile {
            verdict: profile.verdict.label().to_string(),
            reason: profile.reason.clone(),
            sample_len: profile.sample_len as u64,
            entropy: profile.entropy,
            codecs: profile
                .ratios
                .iter()
                .map(|ratio| CodecResult {
                    codec: ratio.probe.label().to_string(),
                    compressed_len: ratio.compressed.as_ref().ok().map(|&len| len as u64),
                    ratio: ratio.ratio(profile.sample_len),
                    error: ratio.compressed.as_ref().err().cloned(),
                })
                .collect(),
        }
    }
}

/// The verdict for one segment of the document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SegmentVerdict {
    pub offset: u64,
    pub len: u64,
    pub verdict: String,
    pub reason: String,
}

/// What the profiles' jobs finish with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Compressibility {
    /// What was profiled, such as "selection 0x100..0x900 (2 KiB)".
    pub scope: String,
    pub profile: CompressibilityProfile,
    /// Along the document, for a whole-document profile.
    pub segments: Vec<SegmentVerdict>,
}

impl Compressibility {
    fn of(result: &CompressionResult) -> Self {
        Compressibility {
            scope: result.scope.clone(),
            profile: CompressibilityProfile::of(&result.profile),
            segments: result
                .segments
                .iter()
                .map(|segment| SegmentVerdict { offset: segment.offset as u64, len: segment.len as u64, verdict: segment.profile.verdict.label().to_string(), reason: segment.profile.reason.clone() })
                .collect(),
        }
    }
}

/// A raw media stream found.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MediaStream {
    pub start: u64,
    pub len: u64,
    /// Such as "MPEG audio" or "H.264".
    pub kind: String,
    pub title: String,
    pub detail: String,
    /// The format it plays as without a container, if it does.
    pub playable_as: Option<String>,
}

/// What `characterise.streams`' job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MediaStreams {
    /// Bytes searched from the start.
    pub scanned_len: u64,
    pub streams: Vec<MediaStream>,
}

impl MediaStreams {
    fn of(scan: &StreamScan) -> Self {
        MediaStreams {
            scanned_len: scan.scanned_len as u64,
            streams: scan
                .runs
                .iter()
                .map(|run| MediaStream {
                    start: run.start as u64,
                    len: run.len as u64,
                    kind: run.kind.label().to_string(),
                    title: run.title.clone(),
                    detail: run.detail.clone(),
                    playable_as: run.playable_as.map(str::to_string).or_else(|| run.pcm.map(|_| "WAV".to_string())),
                })
                .collect(),
        }
    }
}

/// The document's key for stale results, and its length.
fn document_key(workspace: &mut dyn Workspace, doc: Option<&str>) -> Result<(tool_jobs::ToolSpan, panel_characterise::DocumentKey), ApiError> {
    let id = workspace::resolve(workspace, doc)?;
    let info = workspace::info(workspace, &id)?;
    let len = info.len as usize;
    Ok((tool_jobs::ToolSpan { doc: id, version: info.version, start: 0, len }, panel_characterise::DocumentKey { len, version: info.version }))
}

/// `characterise.profile_selection`: read the sample now and compress it on a thread.
pub fn profile_selection(workspace: &mut dyn Workspace, caller: &Caller, params: ProfileSpanParams) -> Result<JobStartedResult, ApiError> {
    let (_, key) = document_key(workspace, params.doc.as_deref())?;
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, Some(params.len), usize::MAX, "the span")?;
    let (_, document) = workspace::document(workspace, Some(&span.doc))?;
    let sample = panel_characterise::read_sample(document, span.start, span.len, crate::codec_profile::MAX_SAMPLE);
    let scope = panel_characterise::selection_scope(span.start, span.len);
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_characterise::await_compression);
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("compressibility", "Compressibility"),
        &span,
        deliver,
        move |_| CompressionResult { key, scope, profile: crate::codec_profile::profile_sample(&sample), segments: Vec::new() },
        |result| Summary::of(result.profile.verdict.label(), Compressibility::of(result)),
    ))
}

/// `characterise.profile_file`: read the samples now and compress them on a thread.
pub fn profile_file(workspace: &mut dyn Workspace, caller: &Caller, params: ProfileFileParams) -> Result<JobStartedResult, ApiError> {
    let (span, key) = document_key(workspace, params.doc.as_deref())?;
    let (_, document) = workspace::document(workspace, Some(&span.doc))?;
    let (overall, segments) = panel_characterise::whole_file_samples(document);
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_characterise::await_compression);
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("compressibility", "Compressibility"),
        &span,
        deliver,
        move |_| panel_characterise::profile_whole_file(key, &overall, segments),
        |result| Summary::of(result.profile.verdict.label(), Compressibility::of(result)),
    ))
}

/// `characterise.streams`: read the document now and search it on a thread.
pub fn streams(workspace: &mut dyn Workspace, caller: &Caller, params: ProfileFileParams) -> Result<JobStartedResult, ApiError> {
    let (_, key) = document_key(workspace, params.doc.as_deref())?;
    let span = tool_jobs::span(workspace, params.doc.as_deref(), 0, None, panel_characterise::STREAM_SCAN_LIMIT, "the document")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_characterise::await_streams);
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("media-streams", "Media streams"),
        &span,
        deliver,
        move |_| StreamScan { key, scanned_len: bytes.len(), runs: crate::elementary::find_streams(&bytes) },
        |scan| Summary::of(format!("{} streams", scan.runs.len()), MediaStreams::of(scan)),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn text_compresses_well_and_the_whole_file_is_profiled_along_its_length() {
        let mut workspace = workspace_with("notes.txt", &b"The quick brown fox jumps over the lazy dog. ".repeat(400));
        let selection = run_job(&mut workspace, "characterise.profile_selection", json!({"start": 0, "len": 9000}));
        assert_eq!(selection["state"], "finished", "{selection}");
        assert_eq!(selection["result"]["profile"]["verdict"], "structured binary/text", "{selection}");
        assert_eq!(selection["result"]["scope"], "selection 0x0..0x2328 (8.8 KiB)");
        let whole = run_job(&mut workspace, "characterise.profile_file", json!({}));
        assert!(!whole["result"]["segments"].as_array().unwrap().is_empty(), "{whole}");
        assert_eq!(call(&mut workspace, "characterise.profile_selection", json!({"start": 0, "len": 100_000})).unwrap_err().code, ErrorCode::OutOfRange);
    }

    #[test]
    fn a_document_without_media_has_no_streams() {
        let mut workspace = workspace_with("notes.txt", &b"no media here ".repeat(100));
        let status = run_job(&mut workspace, "characterise.streams", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["result"]["streams"], json!([]));
        assert_eq!(status["result"]["scanned_len"], 1400);
    }
}
