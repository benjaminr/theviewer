//! `analysis.*`: measuring and mapping the document, as the Report,
//! Statistics and Characterise tools do.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values;
use super::workspace::{self, Workspace};
use super::{ApiError, MAX_CALL_BYTES};
use crate::document::Document;
use crate::headless::{self, FileReport};

/// Largest prefix of the document the overview and segmentation read; they
/// run while the caller waits, so very large files are mapped from the start.
pub const WHOLE_FILE_READ_LIMIT: usize = 64 * 1024 * 1024;

/// Parameters of `analysis.overview`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OverviewParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Most findings to include (all of them, up to 2000, by default).
    #[serde(default)]
    pub max_findings: Option<usize>,
}

/// A span to measure. Spans longer than 16 MiB are measured over their first 16 MiB.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpanParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes in the span; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
}

/// The result of `analysis.statistics`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StatisticsResult {
    pub start: u64,
    /// Bytes measured.
    pub analysed: u64,
    /// What the bytes look like, such as "Text" or "Compressed or encrypted".
    pub verdict: String,
    /// Why, with the measurements behind it.
    pub explanation: String,
    /// Shannon entropy, 0 to 8 bits per byte.
    pub entropy: f64,
    pub chi_square: f64,
    /// Chi-square p-value against uniformly random bytes.
    pub chi_square_p: f64,
    pub mean: f64,
    /// Correlation of each byte with the next; 0 for random data.
    pub serial_correlation: f64,
    pub printable_fraction: f64,
    pub zero_fraction: f64,
    /// Fraction of bytes of 0x80 or more.
    pub high_fraction: f64,
    pub distinct_values: u64,
}

/// Parameters of `analysis.segments`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SegmentsParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Most segments to return (100 by default).
    #[serde(default)]
    pub limit: Option<usize>,
    /// The `next` cursor of the previous page.
    #[serde(default)]
    pub next: Option<String>,
}

/// One kind of region.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SegmentTypeResult {
    pub id: u64,
    /// Such as "Text" or "Table / records".
    pub label: String,
    /// Regions of this type.
    pub count: u64,
    pub total_bytes: u64,
}

/// One region of one kind.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SegmentResult {
    pub start: u64,
    pub len: u64,
    /// The id of its type in `types`.
    pub type_id: u64,
    pub label: String,
    /// Why it has its type and where its start boundary came from.
    pub reason: String,
}

/// The result of `analysis.segments`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SegmentsResult {
    /// Bytes segmented, from the start of the document.
    pub scanned_len: u64,
    pub types: Vec<SegmentTypeResult>,
    /// One page of the regions, in document order.
    pub segments: Vec<SegmentResult>,
    /// Pass back as `next` for more regions; absent after the last.
    pub next: Option<String>,
}

/// How well one codec compressed the span.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompressionRatio {
    /// Such as "deflate -9" or "order-1 entropy".
    pub codec: String,
    /// Compressed size as a fraction of the original; absent when the codec failed.
    pub ratio: Option<f64>,
}

/// The result of `analysis.compressibility`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompressibilityResult {
    /// Such as "encrypted or random" or "structured binary/text".
    pub verdict: String,
    /// The measurements behind the verdict.
    pub reason: String,
    /// Bytes sampled from the span.
    pub sample_len: u64,
    pub entropy: f64,
    pub ratios: Vec<CompressionRatio>,
}

/// One candidate encoding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EncodingCandidate {
    /// Such as "UTF-8" or "Shift-JIS".
    pub encoding: String,
    /// 0 to 1; 0 when the bytes are not valid in this encoding.
    pub confidence: f32,
    pub reason: String,
    /// The start of the decoded text.
    pub preview: String,
    pub has_bom: bool,
}

/// One candidate language.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LanguageCandidate {
    pub language: String,
    pub confidence: f32,
    pub reason: String,
}

/// The result of `analysis.text_encoding`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TextEncodingResult {
    pub sample_len: u64,
    /// Encodings, most likely first.
    pub encodings: Vec<EncodingCandidate>,
    /// Languages of the text in the best encoding, most likely first.
    pub languages: Vec<LanguageCandidate>,
}

/// One candidate processor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessorCandidate {
    /// Such as "ARM Thumb" or "x86-64".
    pub architecture: String,
    /// 0 to 1.
    pub confidence: f32,
    pub reason: String,
}

/// The result of `analysis.processor`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessorResult {
    /// One sentence on what was found.
    pub summary: String,
    /// Whether no architecture is convincing.
    pub looks_like_data: bool,
    /// Bytes disassembled per architecture.
    pub sampled_bytes: u64,
    /// Architectures, most likely first.
    pub candidates: Vec<ProcessorCandidate>,
}

/// The span's bytes, up to the per-call limit, and where they start.
fn span_bytes(workspace: &mut dyn Workspace, params: &SpanParams) -> Result<(usize, Vec<u8>), ApiError> {
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (start, len) = values::span_within(document.len(), params.start, params.len)?;
    Ok((start, document.read_range(start, len.min(MAX_CALL_BYTES))))
}

/// The start of the document, up to [`WHOLE_FILE_READ_LIMIT`].
fn whole_file(document: &mut Document) -> Vec<u8> {
    document.read_range(0, WHOLE_FILE_READ_LIMIT)
}

pub fn overview(workspace: &mut dyn Workspace, params: OverviewParams) -> Result<FileReport, ApiError> {
    let registry = workspace.registry();
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let name = workspace::info(workspace, &id)?.name;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let bytes = whole_file(document);
    let mut report = headless::analyse_bytes(&bytes, &name, &name, document.len(), &registry);
    if let Some(max) = params.max_findings {
        report.findings.truncate(max);
    }
    Ok(report)
}

pub fn statistics(workspace: &mut dyn Workspace, params: SpanParams) -> Result<StatisticsResult, ApiError> {
    let (start, bytes) = span_bytes(workspace, &params)?;
    let stats = crate::stats::byte_stats(&bytes);
    let verdict = crate::stats::verdict(&stats);
    Ok(StatisticsResult {
        start: start as u64,
        analysed: bytes.len() as u64,
        verdict: verdict.label.to_string(),
        explanation: verdict.explanation,
        entropy: stats.entropy,
        chi_square: stats.chi_square,
        chi_square_p: stats.chi_square_p,
        mean: stats.mean,
        serial_correlation: stats.serial_correlation,
        printable_fraction: stats.printable_fraction,
        zero_fraction: stats.zero_fraction,
        high_fraction: stats.high_fraction,
        distinct_values: stats.distinct_values as u64,
    })
}

pub fn segments(workspace: &mut dyn Workspace, params: SegmentsParams) -> Result<SegmentsResult, ApiError> {
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let bytes = whole_file(document);
    let segmentation = crate::segments::segment_file(&bytes, &crate::segments::SegmentOptions::default());
    let types = segmentation
        .types
        .iter()
        .map(|kind| SegmentTypeResult { id: kind.id as u64, label: kind.label.clone(), count: kind.count as u64, total_bytes: kind.total_bytes as u64 })
        .collect();
    let all: Vec<SegmentResult> = segmentation
        .segments
        .into_iter()
        .map(|segment| SegmentResult { start: segment.start as u64, len: segment.len as u64, type_id: segment.type_id as u64, label: segment.label, reason: segment.reason })
        .collect();
    let (segments, next) = values::page(all, params.next.as_deref(), params.limit)?;
    Ok(SegmentsResult { scanned_len: segmentation.scanned_len as u64, types, segments, next })
}

pub fn compressibility(workspace: &mut dyn Workspace, params: SpanParams) -> Result<CompressibilityResult, ApiError> {
    let (_, bytes) = span_bytes(workspace, &params)?;
    let profile = crate::codec_profile::profile_region(&bytes);
    let ratios = profile.ratios.iter().map(|ratio| CompressionRatio { codec: ratio.probe.label().to_string(), ratio: ratio.ratio(profile.sample_len) }).collect();
    Ok(CompressibilityResult { verdict: profile.verdict.label().to_string(), reason: profile.reason, sample_len: profile.sample_len as u64, entropy: profile.entropy, ratios })
}

pub fn text_encoding(workspace: &mut dyn Workspace, params: SpanParams) -> Result<TextEncodingResult, ApiError> {
    let (_, bytes) = span_bytes(workspace, &params)?;
    let report = crate::charset::characterise_text(&bytes);
    Ok(TextEncodingResult {
        sample_len: report.sample_len as u64,
        encodings: report
            .encodings
            .into_iter()
            .map(|guess| EncodingCandidate { encoding: guess.encoding.label().to_string(), confidence: guess.confidence, reason: guess.reason, preview: guess.preview, has_bom: guess.has_bom })
            .collect(),
        languages: report
            .languages
            .into_iter()
            .map(|guess| LanguageCandidate { language: guess.language.label().to_string(), confidence: guess.confidence, reason: guess.reason })
            .collect(),
    })
}

pub fn processor(workspace: &mut dyn Workspace, params: SpanParams) -> Result<ProcessorResult, ApiError> {
    let (start, bytes) = span_bytes(workspace, &params)?;
    let report = crate::cpu_detect::identify_architecture(&bytes, start);
    Ok(ProcessorResult {
        summary: report.summary,
        looks_like_data: report.looks_like_data,
        sampled_bytes: report.sampled_bytes as u64,
        candidates: report
            .candidates
            .into_iter()
            .map(|candidate| ProcessorCandidate { architecture: candidate.arch.label().to_string(), confidence: candidate.confidence, reason: candidate.reason })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::ErrorCode;
    use crate::api::test_support::call;

    fn text_then_zeros() -> Vec<u8> {
        let mut bytes = b"The quick brown fox jumps over the lazy dog. ".repeat(200);
        bytes.extend(vec![0; 8192]);
        bytes
    }

    #[test]
    fn the_overview_maps_the_document_and_names_it() {
        let mut workspace = workspace_with("notes.txt", &text_then_zeros());
        let report = call(&mut workspace, "analysis.overview", json!({"max_findings": 1})).unwrap();
        assert_eq!(report["file"], "notes.txt");
        assert!(!report["headline"].as_str().unwrap().is_empty());
        assert!(report["findings"].as_array().unwrap().len() <= 1);
    }

    #[test]
    fn statistics_measure_a_span_and_judge_it() {
        let mut workspace = workspace_with("notes.txt", &text_then_zeros());
        let text = call(&mut workspace, "analysis.statistics", json!({"start": 0, "len": 4000})).unwrap();
        assert_eq!(text["verdict"], "Text");
        assert_eq!(text["analysed"], 4000);
        let zeros = call(&mut workspace, "analysis.statistics", json!({"start": 9000})).unwrap();
        assert_eq!(zeros["distinct_values"], 1);
        assert_eq!(call(&mut workspace, "analysis.statistics", json!({"start": 1_000_000})).unwrap_err().code, ErrorCode::OutOfRange);
    }

    #[test]
    fn segments_split_text_from_padding() {
        let mut workspace = workspace_with("notes.txt", &text_then_zeros());
        let segmented = call(&mut workspace, "analysis.segments", json!({})).unwrap();
        assert!(segmented["segments"].as_array().unwrap().len() >= 2, "{segmented}");
        assert!(!segmented["types"].as_array().unwrap().is_empty());
    }

    #[test]
    fn compressibility_text_encoding_and_processor_report_on_a_span() {
        let mut workspace = workspace_with("notes.txt", &text_then_zeros());
        let compressed = call(&mut workspace, "analysis.compressibility", json!({"len": 4000})).unwrap();
        assert!(!compressed["ratios"].as_array().unwrap().is_empty());
        let encoding = call(&mut workspace, "analysis.text_encoding", json!({"len": 4000})).unwrap();
        assert!(encoding["encodings"][0]["encoding"].as_str().is_some(), "{encoding}");
        let processor = call(&mut workspace, "analysis.processor", json!({"len": 4000})).unwrap();
        assert!(!processor["summary"].as_str().unwrap().is_empty());
    }
}
