//! `alignment.*`: clustering messages into probable types and aligning
//! each type byte by byte, as the Alignment tool does.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::alignment::{self, AlignmentOptions, AlignmentReport, ColumnClass};
use crate::analysis_tools::PROTOCOL_PRODUCER;
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller, values};
use crate::bus::JobHandle;
use crate::bus::topics::FramesDefined;
use crate::document::Document;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("alignment.run", Job, caller run, RunParams, JobStartedResult, "Start clustering messages into probable types and aligning each type byte by byte, marking columns as constant, counter, length or variable, as a background job; the messages are a span cut into rows, or else those the protocol analysis published on frames.defined. The clusters are job.finished's result, and in the window the Alignment tool shows them."),
];

/// An example call of each of [`METHODS`].
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("alignment.run", json!({"threshold": 0.5, "start": 0, "len": 64, "row_width": 16}))]
}

/// What a call to one of this module's methods would do, in plain words.
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

/// Most bytes read per message; longer messages are aligned on this prefix.
pub const READ_LIMIT: usize = 4096;

/// Parameters of `alignment.run`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Similarity, 0.1 to 0.95, above which clusters merge; higher splits
    /// more (0.5 by default).
    #[serde(default)]
    pub threshold: Option<f64>,
    /// Messages laid out one per row: the first row's offset. When omitted,
    /// the messages the protocol analysis published on frames.defined.
    #[serde(default)]
    pub start: Option<u64>,
    /// Bytes of rows; needed with `start`.
    #[serde(default)]
    pub len: Option<u64>,
    /// Bytes per row; needed with `start`.
    #[serde(default)]
    pub row_width: Option<usize>,
}

/// One column of a cluster's alignment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ColumnResult {
    /// "constant", "counter", "length" or "variable".
    pub class: String,
    /// The evidence, such as "step +2".
    pub detail: String,
}

/// A run of columns of one class.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FieldResult {
    pub class: String,
    pub start_column: usize,
    pub len: usize,
}

/// One probable message type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClusterResult {
    /// Indices into `messages` of every message of this type.
    pub members: Vec<usize>,
    pub columns: Vec<ColumnResult>,
    pub fields: Vec<FieldResult>,
    pub notes: Vec<String>,
}

/// What `alignment.run`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AlignmentResult {
    /// Where the messages came from.
    pub source: String,
    /// Each message as [start, len], in document offsets.
    pub messages: Vec<(usize, usize)>,
    /// Probable message types, largest first.
    pub clusters: Vec<ClusterResult>,
    pub notes: Vec<String>,
}

impl AlignmentResult {
    pub fn of(gathered: &Gathered, report: &AlignmentReport) -> Self {
        let label = |class: ColumnClass| class.label().to_string();
        AlignmentResult {
            source: gathered.source.clone(),
            messages: gathered.offsets.iter().copied().zip(gathered.lengths.iter().copied()).collect(),
            clusters: report
                .clusters
                .iter()
                .map(|cluster| ClusterResult {
                    members: cluster.members.clone(),
                    columns: cluster.columns.iter().map(|column| ColumnResult { class: label(column.class), detail: column.detail.clone() }).collect(),
                    fields: cluster.fields.iter().map(|field| FieldResult { class: label(field.class), start_column: field.start_column, len: field.len }).collect(),
                    notes: cluster.notes.clone(),
                })
                .collect(),
            notes: report.notes.clone(),
        }
    }
}

/// Messages gathered from a document: where each is, and its bytes.
pub struct Gathered {
    /// Where the messages came from, for display.
    pub source: String,
    pub offsets: Vec<usize>,
    /// Full length of each message (the bytes aligned may be fewer).
    pub lengths: Vec<usize>,
    pub bytes: Vec<Vec<u8>>,
}

/// Where the messages to align are.
pub enum MessageSource {
    /// The messages the protocol analysis published.
    Frames(FramesDefined),
    /// Rows of `row_width` bytes over `len` bytes from `start`.
    Rows { start: usize, len: usize, row_width: usize },
}

/// The messages `source` names in `document`.
pub fn gather(document: &mut Document, source: MessageSource) -> Result<Gathered, String> {
    match source {
        MessageSource::Frames(frames) => {
            let messages: Vec<_> = frames.frames.into_iter().take(alignment::MAX_CLUSTERED_MESSAGES).collect();
            let offsets = messages.iter().map(|frame| frame.start).collect();
            let lengths = messages.iter().map(|frame| frame.len).collect();
            let bytes = messages.iter().map(|frame| document.read_range(frame.start, frame.len.min(READ_LIMIT))).collect();
            Ok(Gathered { source: "protocol analysis".to_string(), offsets, lengths, bytes })
        }
        MessageSource::Rows { start, len, row_width } => {
            let stride = row_width.max(1);
            let rows = len.div_ceil(stride).min(alignment::MAX_CLUSTERED_MESSAGES);
            if rows < 2 {
                return Err(format!("The selection holds fewer than 2 rows of {stride} bytes."));
            }
            let bytes = document.read_range(start, len.min(rows * stride));
            let records = alignment::split_into_records(&bytes, stride);
            let offsets = (0..records.len()).map(|row| start + row * stride).collect();
            let lengths = records.iter().map(Vec::len).collect();
            Ok(Gathered { source: format!("selection rows of {stride} bytes"), offsets, lengths, bytes: records })
        }
    }
}

/// Cluster and align `gathered` and finish `job` with what was found.
pub fn run_alignment(gathered: &Gathered, threshold: f64, job: &JobHandle) -> AlignmentReport {
    let report = alignment::analyse(&gathered.bytes, &AlignmentOptions { threshold });
    job.finish_with(!report.clusters.is_empty(), format!("{} clusters", report.clusters.len()), serde_json::to_value(AlignmentResult::of(gathered, &report)).ok());
    report
}

/// Most and least cluster similarity the Alignment tool offers.
const THRESHOLDS: std::ops::RangeInclusive<f64> = 0.1..=0.95;

pub fn run(workspace: &mut dyn Workspace, caller: &Caller, params: RunParams) -> Result<JobStartedResult, ApiError> {
    let threshold = params.threshold.unwrap_or(alignment::DEFAULT_CLUSTER_THRESHOLD);
    if !THRESHOLDS.contains(&threshold) {
        return Err(ApiError::invalid_params(format!("a threshold of {threshold} is outside 0.1 to 0.95")));
    }
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let version = workspace::info(workspace, &id)?.version;
    let source = match (params.start, params.len, params.row_width) {
        (Some(start), Some(len), Some(row_width)) => {
            let (_, document) = workspace::document(workspace, Some(&id))?;
            let (start, len) = values::span_within(document.len(), start, Some(len))?;
            MessageSource::Rows { start, len, row_width }
        }
        (None, None, None) => {
            let frames = workspace.bus().latest_from::<FramesDefined>(&id, PROTOCOL_PRODUCER).map(|(_, frames)| frames.clone()).filter(|frames| !frames.frames.is_empty());
            MessageSource::Frames(frames.ok_or_else(|| ApiError::not_found("the protocol analysis has published no messages; run protocol.analyse first, or give start, len and row_width"))?)
        }
        _ => return Err(ApiError::invalid_params("give start, len and row_width together, or none of them to use the protocol analysis's messages")),
    };
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let gathered = gather(document, source).map_err(ApiError::invalid_params)?;
    if let Some(app) = workspace.window()
        && app.document_id() == id
    {
        return Ok(JobStartedResult::started(crate::panel_alignment::align_as(app, gathered, threshold, &caller.producer())));
    }
    let job = workspace.bus().start_job("alignment", "Message alignment", caller.producer(), Some((id, version)));
    let started = JobStartedResult::started(job.id().to_string());
    std::thread::spawn(move || run_alignment(&gathered, threshold, &job));
    Ok(started)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::PROTOCOL_PRODUCER;
    use crate::api::test_support::{call, workspace_with};
    use crate::api::tools::finished_job as finished;
    use crate::api::{ErrorCode, Workspace};
    use crate::bus::topics::FramesDefined;
    use crate::bus::{Draft, Payload};

    /// Two types of 16-byte message, alternating, each with a counter.
    fn messages() -> Vec<u8> {
        (0..20u8)
            .flat_map(|index| {
                let mut message = if index % 2 == 0 { vec![0xA5, 0x01] } else { vec![0x7E, 0x02, 0xFF, 0xFF] };
                message.push(index);
                message.resize(16, index % 2);
                message
            })
            .collect()
    }

    #[test]
    fn rows_of_messages_are_clustered_into_their_types() {
        let mut workspace = workspace_with("messages.bin", &messages());
        let started = call(&mut workspace, "alignment.run", json!({"start": 0, "len": 320, "row_width": 16})).unwrap();
        let status = finished(&mut workspace, &started);
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["result"]["messages"].as_array().unwrap().len(), 20);
        assert_eq!(status["result"]["clusters"].as_array().unwrap().len(), 2, "{status}");
    }

    #[test]
    fn without_a_span_the_protocol_analysis_s_messages_are_aligned() {
        let mut workspace = workspace_with("messages.bin", &messages());
        assert_eq!(call(&mut workspace, "alignment.run", json!({})).unwrap_err().code, ErrorCode::NotFound, "nothing published yet");
        let frames = FramesDefined::new((0..20).map(|index| (index * 16, 16)), "fixed-size messages of 16 bytes");
        workspace.bus().publish(Draft::new(PROTOCOL_PRODUCER, Payload::FramesDefined(frames)).about("doc-1", 0));
        let started = call(&mut workspace, "alignment.run", json!({"threshold": 0.5})).unwrap();
        let status = finished(&mut workspace, &started);
        assert_eq!(status["result"]["source"], "protocol analysis");
        assert_eq!(status["result"]["messages"][1], json!([16, 16]));
    }

    #[test]
    fn a_half_given_span_too_few_rows_or_a_threshold_out_of_range_is_refused() {
        let mut workspace = workspace_with("messages.bin", &messages());
        assert_eq!(call(&mut workspace, "alignment.run", json!({"start": 0, "len": 32})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "alignment.run", json!({"start": 0, "len": 16, "row_width": 16})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "alignment.run", json!({"threshold": 1.5, "start": 0, "len": 64, "row_width": 16})).unwrap_err().code, ErrorCode::InvalidParams);
    }
}
