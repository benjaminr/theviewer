//! `analysis.*`: measuring and mapping the document, as the Report,
//! Statistics and Characterise tools do.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values;
use super::workspace::{self, Workspace};
use super::jobs::JobStartedResult;
use super::{ApiError, Caller, MAX_CALL_BYTES};
use crate::document::Document;
use crate::headless::{self, FileReport};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("analysis.overview", Read, overview, OverviewParams, crate::headless::FileReport, "Map the whole document: a summary of what it is, its regions with offsets, likely record widths and confident findings."),
    method!("analysis.overview_job", Job, caller overview_job, OverviewParams, super::jobs::JobStartedResult, "Start analysis.overview as a background job and return its id at once; the report arrives as job.finished's result and from jobs.status, for large files and clients that should not wait."),
    method!("analysis.statistics", Read, statistics, SpanParams, StatisticsResult, "Measure a span: entropy, chi-square, serial correlation, printable, zero and high-byte fractions, distinct values and a verdict."),
    method!("analysis.segments", Read, segments, SegmentsParams, SegmentsResult, "Split the document into regions of one kind (text, tables, code, compressed, random, padding) and group them into types."),
    method!("analysis.compressibility", Read, compressibility, SpanParams, CompressibilityResult, "Compress a span with several codecs and report the ratios, with a verdict: encrypted or random, already compressed, lossy media or structured."),
    method!("analysis.text_encoding", Read, text_encoding, SpanParams, TextEncodingResult, "Identify the character encoding of a span of text, with previews and the likely language."),
    method!("analysis.processor", Read, processor, SpanParams, ProcessorResult, "Test whether a span is machine code, and for which processor, by disassembling samples for each architecture."),
    method!("analysis.period_scan", Job, caller period_scan, PeriodScanParams, super::jobs::JobStartedResult, "Start a scan of a window of bytes for repeating periods (record widths) as a background job; the periods found, best first, are job.finished's result, and in the window they fill the structure chart and are published on record_width.estimated."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("analysis.overview", json!({"max_findings": 5})),
        ("analysis.overview_job", json!({"max_findings": 1})),
        ("analysis.statistics", json!({"start": 0, "len": 100})),
        ("analysis.segments", json!({"limit": 3})),
        ("analysis.compressibility", json!({})),
        ("analysis.text_encoding", json!({"start": 100})),
        ("analysis.processor", json!({})),
        ("analysis.period_scan", json!({"start": 0, "len": 512, "max_period": 64})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

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

/// Bytes `analysis.period_scan` reads when no length is given.
pub const PERIOD_SCAN_WINDOW: u64 = 192 * 1024;
/// Longest period `analysis.period_scan` looks for when none is given.
pub const DEFAULT_MAX_PERIOD: usize = 4096;
/// Longest period `analysis.period_scan` may be asked to look for.
pub const MOST_MAX_PERIOD: usize = 16384;

/// Parameters of `analysis.period_scan`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeriodScanParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset of the window scanned (0 by default; the window uses
    /// the view's origin).
    #[serde(default)]
    pub start: u64,
    /// Bytes scanned (192 KiB by default, at most 16 MiB).
    #[serde(default)]
    pub len: Option<u64>,
    /// Longest period looked for, 2 to 16384 (4096 by default).
    #[serde(default)]
    pub max_period: Option<usize>,
}

/// One period a scan found.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PeriodCandidate {
    /// Period in bytes.
    pub period: usize,
    /// How alike bytes this far apart are, 0 to 1.
    pub score: f32,
    /// How far the score rises above the rest, in robust standard deviations.
    pub prominence: f32,
    /// Bits of entropy per byte that knowing the column (offset modulo the period) removes.
    pub column_gain: f32,
    /// The smallest better period this one is a multiple of, if any.
    pub multiple_of: Option<usize>,
}

/// What `analysis.period_scan`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PeriodScanResult {
    /// First offset scanned.
    pub start: u64,
    /// Bytes scanned.
    pub len: u64,
    /// The periods found, best first.
    pub candidates: Vec<PeriodCandidate>,
}

impl PeriodScanResult {
    fn of(scan: &crate::analysis::PeriodScan) -> Self {
        let candidates = scan
            .candidates
            .iter()
            .map(|candidate| PeriodCandidate { period: candidate.period, score: candidate.score, prominence: candidate.prominence, column_gain: candidate.column_gain, multiple_of: candidate.multiple_of })
            .collect();
        PeriodScanResult { start: scan.window_start as u64, len: scan.window_len as u64, candidates }
    }
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

/// `analysis.overview` as a job: the bytes are read now, mapped on a
/// thread, and the report is the job's result.
pub fn overview_job(workspace: &mut dyn Workspace, caller: &Caller, params: OverviewParams) -> Result<JobStartedResult, ApiError> {
    let registry = workspace.registry();
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let info = workspace::info(workspace, &id)?;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let bytes = whole_file(document);
    let len = document.len();
    let job = workspace.bus().start_job("overview", "File overview", caller.producer(), Some((id, info.version)));
    let started = JobStartedResult::started(job.id().to_string());
    std::thread::spawn(move || {
        let mut report = headless::analyse_bytes(&bytes, &info.name, &info.name, len, &registry);
        if job.is_cancelled() {
            return job.finish_cancelled();
        }
        if let Some(max) = params.max_findings {
            report.findings.truncate(max);
        }
        job.finish_with(true, report.headline.clone(), serde_json::to_value(&report).ok());
    });
    Ok(started)
}

/// `analysis.period_scan`: read the window now and scan it on a thread as
/// a job. In the window, the window's own scan runs (see
/// `ViewerApp::scan_periods_from`), filling the structure chart.
pub fn period_scan(workspace: &mut dyn Workspace, caller: &Caller, params: PeriodScanParams) -> Result<JobStartedResult, ApiError> {
    let max_period = params.max_period.unwrap_or(DEFAULT_MAX_PERIOD);
    if !(2..=MOST_MAX_PERIOD).contains(&max_period) {
        return Err(ApiError::invalid_params(format!("a longest period of {max_period} is outside 2 to {MOST_MAX_PERIOD}")));
    }
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let version = workspace::info(workspace, &id)?.version;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let room = (document.len() as u64).saturating_sub(params.start);
    let (start, len) = values::span_within(document.len(), params.start, Some(params.len.unwrap_or(PERIOD_SCAN_WINDOW).min(room)))?;
    values::check_call_size(len)?;
    if let Some(app) = workspace.window()
        && app.document_id() == id
    {
        return Ok(JobStartedResult::started(app.scan_periods_from(start, len, max_period, &caller.producer())));
    }
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let bytes = document.read_range(start, len);
    let job = workspace.bus().start_job("period-scan", "Period scan", caller.producer(), Some((id, version)));
    let started = JobStartedResult::started(job.id().to_string());
    std::thread::spawn(move || run_period_scan(&bytes, start, max_period, &job));
    Ok(started)
}

/// Scan `bytes` (from document offset `start`) for periods up to
/// `max_period` and finish `job` with what was found, unless it was
/// cancelled meanwhile. Returns the scan when the job finished with it.
pub fn run_period_scan(bytes: &[u8], start: usize, max_period: usize, job: &crate::bus::JobHandle) -> Option<crate::analysis::PeriodScan> {
    let scan = crate::analysis::scan_periods(bytes, start, max_period);
    if job.is_cancelled() {
        job.finish_cancelled();
        return None;
    }
    let outcome = scan.candidates.first().map_or_else(|| "no repeating period".to_string(), |best| format!("best period {} bytes", best.period));
    job.finish_with(!scan.candidates.is_empty(), outcome, serde_json::to_value(PeriodScanResult::of(&scan)).ok());
    Some(scan)
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
    #[test]
    fn a_period_scan_job_finds_the_record_width() {
        use crate::api::Workspace;
        use serde_json::json;
        let records: Vec<u8> = (0..400u32).flat_map(|index| {
            let mut record = vec![0xA5, 0x5A, index as u8, (index >> 8) as u8];
            record.extend((0..44u8).map(|byte| byte.wrapping_mul(7)));
            record
        }).collect();
        let mut workspace = crate::api::test_support::workspace_with("records.bin", &records);
        let started = crate::api::test_support::call(&mut workspace, "analysis.period_scan", json!({"max_period": 256})).unwrap();
        let begun = std::time::Instant::now();
        let status = loop {
            workspace.bus().deliver_all();
            let status = crate::api::test_support::call(&mut workspace, "jobs.status", json!({"job": started["job"]})).unwrap();
            if status["state"] != "running" || begun.elapsed() > std::time::Duration::from_secs(20) {
                break status;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["producer"], "panel", "the job is its caller's");
        assert_eq!(status["result"]["candidates"][0]["period"], 48, "{status}");
        let refused = crate::api::test_support::call(&mut workspace, "analysis.period_scan", json!({"max_period": 1})).unwrap_err();
        assert_eq!(refused.code, crate::api::ErrorCode::InvalidParams);
    }

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
