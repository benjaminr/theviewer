//! `trigrams.count`: the Trigrams tool's count of every run of three bytes
//! in a span, as points in a 256 × 256 × 256 cube, each attributed to the
//! kinds of region it occurs in.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller};
use crate::bus::topics::RegionsMapped;
use crate::panel_trigram::{self, Counted, LabelInput, LabelSource};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[method!(
    "trigrams.count",
    Job,
    caller count,
    CountParams,
    JobStartedResult,
    "Start counting every run of three bytes in a span (sampled beyond 16 MiB) as a job, labelled by segments, by the report's regions or not at all, with a part of it to pick out: the points of the trigram cube, most common first, and the region types they belong to are job.finished's result, and in the window they fill Trigrams."
)];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("trigrams.count", json!({"start": 0, "labels": "segments", "highlight": [0, 8]}))]
}

/// What the points are labelled by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrigramLabels {
    /// The kinds of region the span segments into.
    #[default]
    Segments,
    /// The regions the report mapped (published on regions.mapped).
    ReportRegions,
    Nothing,
}

impl TrigramLabels {
    pub fn of(source: LabelSource) -> Self {
        match source {
            LabelSource::Segments => TrigramLabels::Segments,
            LabelSource::ReportRegions => TrigramLabels::ReportRegions,
            LabelSource::Nothing => TrigramLabels::Nothing,
        }
    }
}

/// Parameters of `trigrams.count`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CountParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    /// First offset counted (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes counted; to the end of the document when omitted. Beyond 16 MiB the span is sampled.
    #[serde(default)]
    pub len: Option<u64>,
    /// What the points are labelled by (segments by default).
    #[serde(default)]
    pub labels: TrigramLabels,
    /// A part of the span, as [start, len], whose trigrams are picked out from the rest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlight: Option<(u64, u64)>,
}

/// One cell of the cube.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TrigramCell {
    /// The cell along x, y and z.
    pub cell: [u8; 3],
    /// The first trigram seen in it, as hex, and its offset.
    pub exemplar: String,
    pub offset: u64,
    pub count: u64,
    /// Trigrams per region type (an index into region_types), most first.
    pub groups: Vec<(u8, u32)>,
    /// Trigrams from inside the highlight.
    pub in_highlight: u32,
}

/// A kind of region the points are attributed to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegionType {
    pub label: String,
    /// Its regions, as [start, len].
    pub spans: Vec<(u64, u64)>,
    pub bytes: u64,
}

/// What `trigrams.count`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TrigramCount {
    pub start: u64,
    pub len: u64,
    /// Bytes read; less than len when the span was sampled.
    pub bytes_read: u64,
    pub total_trigrams: u64,
    pub occupied_cells: usize,
    /// The cells kept, most common first.
    pub points: Vec<TrigramCell>,
    pub region_types: Vec<RegionType>,
}

impl TrigramCount {
    fn of(counted: &Counted) -> Self {
        let cloud = &counted.cloud;
        TrigramCount {
            start: cloud.start as u64,
            len: cloud.len as u64,
            bytes_read: cloud.bytes_read as u64,
            total_trigrams: cloud.total_trigrams,
            occupied_cells: cloud.occupied_cells,
            points: cloud
                .points
                .iter()
                .map(|point| TrigramCell {
                    cell: point.cell,
                    exemplar: crate::api::values::encode_bytes(&point.exemplar, Default::default()),
                    offset: point.offset as u64,
                    count: point.count,
                    groups: point.groups.clone(),
                    in_highlight: point.in_selection,
                })
                .collect(),
            region_types: counted
                .groups
                .iter()
                .map(|group| RegionType { label: group.label.clone(), spans: group.spans.iter().map(|&(start, len)| (start as u64, len as u64)).collect(), bytes: group.bytes as u64 })
                .collect(),
        }
    }
}

/// The regions the report mapped in document `doc`: the window's, else the
/// latest published on the bus.
fn report_regions(workspace: &mut dyn Workspace, doc: &str) -> Vec<crate::explain::Region> {
    if let Some(app) = tool_jobs::window_showing(workspace, doc) {
        return app.mapped_regions.to_vec();
    }
    let latest = workspace.bus().facts().filter(|fact| fact.draft.document.as_deref() == Some(doc)).filter_map(|fact| fact.payload_as::<RegionsMapped>().map(|mapped| mapped.regions.clone())).last();
    latest
        .unwrap_or_default()
        .into_iter()
        .map(|mapped| crate::explain::Region {
            start: mapped.start,
            len: mapped.len,
            kind: crate::explain::RegionKind::from_label(&mapped.kind),
            label: mapped.label,
            detail: mapped.detail,
            confident: mapped.confident,
        })
        .collect()
}

/// `trigrams.count`: read the span's samples now and count them on a
/// thread; in the window, Trigrams waits for the count.
pub fn count(workspace: &mut dyn Workspace, caller: &Caller, params: CountParams) -> Result<JobStartedResult, ApiError> {
    start_count(workspace, &caller.producer(), params, |workspace, doc| tool_jobs::window_showing(workspace, doc).map(panel_trigram::await_count))
}

/// Count as `trigrams.count` does, for `producer`, sending the count where
/// `deliver` says for the document counted: the method's way, and the
/// window's own recount after an edit.
pub(crate) fn start_count(
    workspace: &mut dyn Workspace,
    producer: &str,
    params: CountParams,
    deliver: impl FnOnce(&mut dyn Workspace, &str) -> Option<std::sync::mpsc::Sender<Counted>>,
) -> Result<JobStartedResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, usize::MAX, "the span counted")?;
    let highlight = match params.highlight {
        Some((start, len)) => {
            let (_, document) = workspace::document(workspace, Some(&span.doc))?;
            let (start, len) = crate::api::values::span_within(document.len(), start, Some(len))?;
            if start < span.start || start + len > span.start + span.len {
                return Err(ApiError::out_of_range(format!("the highlight {start:#x}+{len} is not inside the span counted")));
            }
            Some((start, len))
        }
        None => None,
    };
    let labels = match params.labels {
        TrigramLabels::Segments => {
            let (_, document) = workspace::document(workspace, Some(&span.doc))?;
            LabelInput::Bytes { start: span.start, bytes: document.read_range(span.start, span.len.min(panel_trigram::SEGMENT_LIMIT)) }
        }
        TrigramLabels::ReportRegions => LabelInput::Regions(report_regions(workspace, &span.doc)),
        TrigramLabels::Nothing => LabelInput::Nothing,
    };
    let (_, document) = workspace::document(workspace, Some(&span.doc))?;
    let windows = panel_trigram::sample(document, span.start, span.len);
    let deliver = deliver(workspace, &span.doc);
    let (start, len) = (span.start, span.len);
    Ok(tool_jobs::spawn(
        workspace,
        producer,
        ("trigrams", "Counting trigrams"),
        &span,
        deliver,
        move |job| panel_trigram::count(start, len, windows, labels, highlight, job),
        |counted| Summary::of(format!("{} groups", counted.groups.len()), TrigramCount::of(counted)),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn text_and_zeros_count_as_two_kinds_of_region() {
        let mut bytes = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
        bytes.extend(vec![0u8; 4500]);
        let mut workspace = workspace_with("mixed.bin", &bytes);
        let status = run_job(&mut workspace, "trigrams.count", json!({"highlight": [0, 45]}));
        assert_eq!(status["state"], "finished", "{status}");
        let result = &status["result"];
        assert_eq!(result["len"].as_u64(), Some(bytes.len() as u64));
        assert!(result["region_types"].as_array().unwrap().len() >= 2, "{}", result["region_types"]);
        let zeros = result["points"].as_array().unwrap().iter().find(|point| point["exemplar"] == "000000").expect("the zeros' cell");
        assert_eq!(zeros["in_highlight"], 0, "none of them in the text picked out");
        let unlabelled = run_job(&mut workspace, "trigrams.count", json!({"labels": "nothing"}));
        assert_eq!(unlabelled["result"]["region_types"], json!([]));
    }

    #[test]
    fn a_highlight_outside_the_span_is_refused() {
        let mut workspace = workspace_with("a.bin", &[1u8; 1000]);
        assert_eq!(call(&mut workspace, "trigrams.count", json!({"start": 500, "highlight": [0, 10]})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "trigrams.count", json!({"labels": "colours"})).unwrap_err().code, ErrorCode::InvalidParams);
    }
}
