//! `compare.*`: the Compare tool's analyses across files: which byte
//! positions vary and how, which fields follow a value known for each file,
//! and where a recording changes over time.

use std::path::PathBuf;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary, ToolSpan};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller, ErrorCode};
use crate::correlation::CorrelationReport;
use crate::panel_compare::{self, CompareInputs};
use crate::timeline::Timeline;
use crate::variation::{RegionKind, VariationReport};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("compare.variation", Job, caller variation, VariationParams, JobStartedResult, "Start comparing a document with other files byte position by byte position, each from its own start offset, as a job: the regions that are constant, vary (and how many values) or move one way through the files like a counter are job.finished's result, and in the window they fill Compare."),
    method!("compare.correlate", Job, caller correlate, CorrelateParams, JobStartedResult, "Start a search of a document and other files for fields whose values follow a number known for each file (a temperature, a setting), as a job: the fields, best fit first, with the fitted line, are job.finished's result, and in the window they fill Compare."),
    method!("compare.timeline", Job, caller timeline, CompareTimelineParams, JobStartedResult, "Start building the change timeline of the recording of a live source or watched file, as a job: where and how often it changed, snapshot by snapshot, is job.finished's result, and the window fills Compare with it; only the window records, so headless there is none."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    let other = crate::api::test_support::example_file().display().to_string();
    vec![
        ("compare.variation", json!({"start": 0, "files": [{"path": other, "start": 0}]})),
        ("compare.correlate", json!({"start": 0, "files": [{"path": other, "start": 0}, {"path": other, "start": 1}], "values": [1.0, 2.0, 3.0], "from": 0})),
        ("compare.timeline", json!({})),
    ]
}

/// A file compared with the document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareFileParam {
    pub path: String,
    /// Offset in this file that lines up with the others' starts (0 by default).
    #[serde(default)]
    pub start: usize,
}

/// Parameters of `compare.variation`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VariationParams {
    /// Document id, path or "current" (the default): the first file.
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset in the document that lines up with the files' starts (0 by default).
    #[serde(default)]
    pub start: usize,
    /// The other files, at most 31; the first 64 MiB of each is read.
    pub files: Vec<CompareFileParam>,
}

/// Parameters of `compare.correlate`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorrelateParams {
    /// Document id, path or "current" (the default): the first file.
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset in the document that lines up with the files' starts (0 by default).
    #[serde(default)]
    pub start: usize,
    /// The other files, at most 63.
    pub files: Vec<CompareFileParam>,
    /// The number known for each file, the document's first: one more than the files.
    pub values: Vec<f64>,
    /// Where the search starts, from each file's start (0 by default); 256 KiB are searched.
    #[serde(default)]
    pub from: usize,
}

/// Parameters of `compare.timeline`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareTimelineParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// A region of positions that behave alike across the files.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VariationRegion {
    /// Offsets from each file's start.
    pub start: u64,
    pub len: u64,
    /// "constant", "varies" or "trend".
    pub kind: String,
    /// The region in words, such as "varies 0x10–0x13 (3 distinct values, 0x00–0x7F)".
    pub label: String,
}

/// What `compare.variation`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Variation {
    pub file_count: usize,
    /// Length every file has after its start offset.
    pub common_len: u64,
    /// How much of that was summarised.
    pub analysed_len: u64,
    pub regions: Vec<VariationRegion>,
}

impl Variation {
    fn of(report: &VariationReport) -> Self {
        Variation {
            file_count: report.file_count,
            common_len: report.common_len as u64,
            analysed_len: report.analysed_len as u64,
            regions: report
                .regions
                .iter()
                .map(|region| VariationRegion {
                    start: region.start as u64,
                    len: region.len() as u64,
                    kind: match region.kind {
                        RegionKind::Constant => "constant",
                        RegionKind::Varies { .. } => "varies",
                        RegionKind::Trend { .. } => "trend",
                    }
                    .to_string(),
                    label: region.label(),
                })
                .collect(),
        }
    }
}

/// A field that follows the known values.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CorrelatedFieldFound {
    /// Offset from each file's start.
    pub offset: u64,
    /// How it is read, such as "u16 LE".
    pub encoding: String,
    /// Pearson correlation with the known values, −1 to 1.
    pub correlation: f64,
    /// The fit, field ≈ scale · value + offset_term.
    pub scale: f64,
    pub offset_term: f64,
    pub exact_fit: bool,
    /// Its value in each file, the document's first.
    pub values: Vec<f64>,
    /// The field in words.
    pub summary: String,
}

/// What `compare.correlate`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Correlation {
    pub samples: usize,
    /// How far a close match can be trusted with this many samples.
    pub confidence: String,
    /// The range searched, from each file's start.
    pub searched_start: u64,
    pub searched_end: u64,
    pub fields: Vec<CorrelatedFieldFound>,
}

impl Correlation {
    fn of(report: &CorrelationReport) -> Self {
        Correlation {
            samples: report.samples,
            confidence: report.confidence.explanation().to_string(),
            searched_start: report.searched.start as u64,
            searched_end: report.searched.end as u64,
            fields: report
                .fields
                .iter()
                .map(|field| CorrelatedFieldFound {
                    offset: field.offset as u64,
                    encoding: field.encoding.describe(),
                    correlation: field.correlation,
                    scale: field.scale,
                    offset_term: field.offset_term,
                    exact_fit: field.exact_fit,
                    values: field.values.clone(),
                    summary: field.summary(),
                })
                .collect(),
        }
    }
}

/// A stretch that changed often.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ActiveStretch {
    pub start: u64,
    pub len: u64,
    /// Snapshots in which it changed.
    pub changes: u32,
}

/// What `compare.timeline`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChangeTimeline {
    /// Snapshots recorded, and the first of those shown.
    pub total_snapshots: usize,
    pub first_index: usize,
    pub rows: usize,
    pub columns: usize,
    /// Byte positions per column, and in all.
    pub bucket: usize,
    pub width: usize,
    /// Snapshots in which each column changed.
    pub column_activity: Vec<u32>,
    /// The stretches that changed most often, most first.
    pub most_active: Vec<ActiveStretch>,
}

impl ChangeTimeline {
    fn of(built: &Timeline) -> Self {
        ChangeTimeline {
            total_snapshots: built.total_snapshots,
            first_index: built.first_index,
            rows: built.rows,
            columns: built.columns,
            bucket: built.bucket,
            width: built.width,
            column_activity: built.column_activity.clone(),
            most_active: built.most_active.iter().map(|span| ActiveStretch { start: span.start as u64, len: span.len as u64, changes: span.changes }).collect(),
        }
    }
}

/// The document's bytes, as the first file, and its span.
fn first_file(workspace: &mut dyn Workspace, doc: Option<&str>) -> Result<(ToolSpan, Arc<[u8]>), ApiError> {
    let id = workspace::resolve(workspace, doc)?;
    let info = workspace::info(workspace, &id)?;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let bytes: Arc<[u8]> = document.read_range(0, panel_compare::MAX_FILE_BYTES).into();
    Ok((ToolSpan { doc: id, version: info.version, start: 0, len: bytes.len() }, bytes))
}

/// The files to read, checked to be there.
fn other_files(files: &[CompareFileParam], most: usize) -> Result<Vec<(PathBuf, usize)>, ApiError> {
    if files.len() > most {
        return Err(ApiError::invalid_params(format!("{} files is more than the {most} that can be compared with a document", files.len())));
    }
    files
        .iter()
        .map(|file| {
            let path = PathBuf::from(&file.path);
            if path.is_file() { Ok((path, file.start)) } else { Err(ApiError::not_found(format!("there is no file at {}", file.path))) }
        })
        .collect()
}

/// Read `files` after the document's bytes, each with its start offset.
fn read_inputs(first: (Arc<[u8]>, usize), files: &[(PathBuf, usize)]) -> Result<CompareInputs, String> {
    let mut inputs = vec![first];
    for (path, start) in files {
        inputs.push((panel_compare::read_compare_file(path)?.bytes, *start));
    }
    Ok(inputs)
}

/// `compare.variation`: read the files and summarise them on a thread.
pub fn variation(workspace: &mut dyn Workspace, caller: &Caller, params: VariationParams) -> Result<JobStartedResult, ApiError> {
    if params.files.is_empty() {
        return Err(ApiError::invalid_params("give at least one file to compare the document with"));
    }
    let files = other_files(&params.files, crate::variation::MAX_FILES - 1)?;
    let (span, bytes) = first_file(workspace, params.doc.as_deref())?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_compare::await_variation);
    let start = params.start;
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("compare", "Compare files"),
        &span,
        deliver,
        move |_| panel_compare::summarise(read_inputs((bytes, start), &files)),
        |run| match &run.report {
            Ok(report) => Summary::of(format!("{} regions", report.regions.len()), Variation::of(report)),
            Err(message) => Summary::failed(message.clone()),
        },
    ))
}

/// `compare.correlate`: read the files and search them on a thread.
pub fn correlate(workspace: &mut dyn Workspace, caller: &Caller, params: CorrelateParams) -> Result<JobStartedResult, ApiError> {
    if params.values.len() != params.files.len() + 1 {
        return Err(ApiError::invalid_params(format!("give one value for the document and one for each of the {} files, {} in all, not {}", params.files.len(), params.files.len() + 1, params.values.len())));
    }
    if params.values.len() < crate::correlation::MIN_SAMPLES {
        return Err(ApiError::invalid_params(format!("at least {} files (the document among them) are needed", crate::correlation::MIN_SAMPLES)));
    }
    let files = other_files(&params.files, crate::correlation::MAX_SAMPLES - 1)?;
    let (span, bytes) = first_file(workspace, params.doc.as_deref())?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_compare::await_correlation);
    let (start, from, values) = (params.start, params.from, params.values);
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("correlate", "Find fields"),
        &span,
        deliver,
        move |_| read_inputs((bytes, start), &files).and_then(|inputs| panel_compare::correlate(&inputs, &values, from)),
        |found| match found {
            Ok(report) => Summary::of(format!("{} fields", report.fields.len()), Correlation::of(report)),
            Err(message) => Summary::failed(message.clone()),
        },
    ))
}

/// `compare.timeline`: collect the recording's changes now and build the
/// timeline on a thread. Only the window records; headless the job ends
/// without a timeline, saying so.
pub fn timeline(workspace: &mut dyn Workspace, caller: &Caller, params: CompareTimelineParams) -> Result<JobStartedResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let version = workspace::info(workspace, &id)?.version;
    let span = ToolSpan { doc: id, version, start: 0, len: 0 };
    let (changes, deliver) = match tool_jobs::window_showing(workspace, &span.doc) {
        Some(app) => {
            let changes = panel_compare::recorded_changes(app).map_err(|message| ApiError::new(ErrorCode::Unavailable, message))?;
            (Some(changes), Some(panel_compare::await_timeline(app)))
        }
        None => (None, None),
    };
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("timeline", "Change timeline"),
        &span,
        deliver,
        move |_| changes.map(|changes| crate::timeline::build_timeline(&changes, crate::timeline::MAX_COLUMNS)),
        |built: &Option<Timeline>| match built {
            Some(built) => Summary::of(format!("{} snapshots", built.rows), ChangeTimeline::of(built)),
            None => Summary::failed(NOTHING_RECORDED),
        },
    ))
}

/// Why there is no timeline headless.
const NOTHING_RECORDED: &str = "only the window records a live source or watched file; there is no recording here";

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    /// A capture holding a counter at 8 and a temperature (tenths) at 12.
    fn capture(counter: u32, temperature_tenths: u16) -> Vec<u8> {
        let mut bytes = b"HEAD".to_vec();
        bytes.extend([0u8; 4]);
        bytes.extend(counter.to_le_bytes());
        bytes.extend(temperature_tenths.to_le_bytes());
        bytes.extend([0xAA; 18]);
        bytes
    }

    fn files_of(captures: &[Vec<u8>], tag: &str) -> Vec<String> {
        captures
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let path = std::env::temp_dir().join(format!("theviewer-compare-{tag}-{}-{index}.bin", std::process::id()));
                std::fs::write(&path, bytes).unwrap();
                path.display().to_string()
            })
            .collect()
    }

    #[test]
    fn comparing_files_finds_the_constant_header_and_the_counter() {
        let others = files_of(&[capture(2, 200), capture(3, 210)], "variation");
        let mut workspace = workspace_with("first.bin", &capture(1, 190));
        let files: Vec<_> = others.iter().map(|path| json!({"path": path, "start": 0})).collect();
        let status = run_job(&mut workspace, "compare.variation", json!({"files": files}));
        others.iter().for_each(|path| drop(std::fs::remove_file(path)));
        assert_eq!(status["state"], "finished", "{status}");
        let regions = status["result"]["regions"].as_array().unwrap();
        assert_eq!((regions[0]["kind"].as_str(), regions[0]["start"].as_u64()), (Some("constant"), Some(0)), "{regions:?}");
        assert!(regions.iter().any(|region| region["kind"] == "trend" && region["start"] == 8), "{regions:?}");
    }

    #[test]
    fn a_field_following_the_temperature_is_found() {
        let others = files_of(&[capture(2, 200), capture(3, 215), capture(4, 230)], "correlate");
        let mut workspace = workspace_with("first.bin", &capture(1, 180));
        let files: Vec<_> = others.iter().map(|path| json!({"path": path})).collect();
        let status = run_job(&mut workspace, "compare.correlate", json!({"files": files, "values": [18.0, 20.0, 21.5, 23.0]}));
        others.iter().for_each(|path| drop(std::fs::remove_file(path)));
        assert_eq!(status["state"], "finished", "{status}");
        assert!(status["result"]["fields"].as_array().unwrap().iter().any(|field| field["offset"] == 12 && field["exact_fit"] == true), "{status}");
    }

    #[test]
    fn comparisons_without_files_values_or_a_recording_are_refused() {
        let mut workspace = workspace_with("first.bin", &capture(1, 180));
        let refuse = |workspace: &mut crate::api::HeadlessWorkspace, method, params| call(workspace, method, params).unwrap_err().code;
        assert_eq!(refuse(&mut workspace, "compare.variation", json!({"files": []})), ErrorCode::InvalidParams);
        assert_eq!(refuse(&mut workspace, "compare.variation", json!({"files": [{"path": "/no/such/file.bin"}]})), ErrorCode::NotFound);
        assert_eq!(refuse(&mut workspace, "compare.correlate", json!({"files": [{"path": "/a"}, {"path": "/b"}], "values": [1.0]})), ErrorCode::InvalidParams);
        let headless = run_job(&mut workspace, "compare.timeline", json!({}));
        assert_eq!(headless["state"], "failed", "nothing is recorded headless: {headless}");
        assert!(headless["outcome"].as_str().unwrap().contains("only the window records"));
    }
}
