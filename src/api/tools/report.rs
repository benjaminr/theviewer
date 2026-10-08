//! `report.*`: explaining the whole file in plain words and mapping its
//! regions, as the Report tool does.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller};
use crate::bus::JobHandle;
use crate::bus::topics::MappedRegion;
use crate::explain::{self, Region, Report};
use crate::plugin::Registry;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("report.run", Job, caller run, RunParams, JobStartedResult, "Start explaining the whole document in plain words and mapping its regions, as a background job; the report and regions are job.finished's result and are published on regions.mapped, and in the window the Report tool and the file map show them."),
];

/// An example call of each of [`METHODS`].
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("report.run", json!({}))]
}

/// What a call to one of this module's methods would do, in plain words.
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

/// Largest prefix of the document the report reads.
pub const REPORT_READ_LIMIT: usize = 256 * 1024 * 1024;
/// Who publishes the report's map of the file.
pub const REPORT_PRODUCER: &str = "tool:report";

/// Parameters of `report.run`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// One sentence of the report, about a span of the document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SentenceResult {
    pub text: String,
    pub start: usize,
    pub len: usize,
}

/// What `report.run`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReportResult {
    /// What the file is, in one sentence.
    pub headline: String,
    pub sentences: Vec<SentenceResult>,
    /// The file's regions, in document order.
    pub regions: Vec<MappedRegion>,
}

impl ReportResult {
    pub fn of(regions: &[Region], report: &Report) -> Self {
        ReportResult {
            headline: report.headline.clone(),
            sentences: report.sentences.iter().map(|sentence| SentenceResult { text: sentence.text.clone(), start: sentence.start, len: sentence.len }).collect(),
            regions: mapped_regions(regions),
        }
    }
}

/// The regions as `regions.mapped` publishes them.
pub fn mapped_regions(regions: &[Region]) -> Vec<MappedRegion> {
    regions
        .iter()
        .map(|region| MappedRegion {
            start: region.start,
            len: region.len,
            kind: region.kind.label().to_string(),
            label: region.label.clone(),
            detail: region.detail.clone(),
            confident: region.confident,
        })
        .collect()
}

/// Map and explain `bytes` (a file called `name`) and finish `job` with
/// the report, unless it was cancelled. Returns the regions and report
/// when the job finished with them.
pub fn run_report(bytes: &[u8], name: &str, registry: &Registry, job: &JobHandle) -> Option<(Vec<Region>, Report)> {
    let regions = explain::map_file(bytes, registry);
    if job.is_cancelled() {
        job.finish_cancelled();
        return None;
    }
    let report = explain::explain(bytes, name, &regions);
    if job.is_cancelled() {
        job.finish_cancelled();
        return None;
    }
    job.finish_with(true, format!("{} regions: {}", regions.len(), report.headline), serde_json::to_value(ReportResult::of(&regions, &report)).ok());
    Some((regions, report))
}

/// `report.run`: in the window the Report tool's own run starts (see
/// `ViewerApp::report_as`); elsewhere the same work runs on a thread and
/// publishes the regions when done.
pub fn run(workspace: &mut dyn Workspace, caller: &Caller, params: RunParams) -> Result<JobStartedResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let info = workspace::info(workspace, &id)?;
    if info.len == 0 {
        return Err(ApiError::invalid_params(format!("{} is empty; there is nothing to explain", info.name)));
    }
    if let Some(app) = workspace.window()
        && app.document_id() == id
    {
        return app.report_as(&caller.producer()).map(JobStartedResult::started).ok_or_else(|| ApiError::invalid_params("the report is already being worked out; wait for it to finish"));
    }
    let registry = workspace.registry();
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let bytes = document.read_range(0, REPORT_READ_LIMIT);
    let publisher = workspace.bus().publisher();
    let job = workspace.bus().start_job("report", "Report", caller.producer(), Some((id.clone(), info.version)));
    let started = JobStartedResult::started(job.id().to_string());
    std::thread::spawn(move || {
        if let Some((regions, _)) = run_report(&bytes, &info.name, &registry, &job) {
            let regions = mapped_regions(&regions);
            let end = regions.last().map_or(0, |region| region.start + region.len);
            let mapped = crate::bus::topics::RegionsMapped { regions };
            publisher.publish(crate::bus::Draft::new(REPORT_PRODUCER, crate::bus::Payload::RegionsMapped(mapped)).about(id, info.version).span(0, end));
        }
    });
    Ok(started)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::REPORT_PRODUCER;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};
    use crate::api::tools::finished_job as finished;

    #[test]
    fn the_report_explains_the_file_and_publishes_its_map() {
        let mut bytes = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
        bytes.extend(vec![0; 4096]);
        let mut workspace = workspace_with("notes.bin", &bytes);
        let started = call(&mut workspace, "report.run", json!({})).unwrap();
        let status = finished(&mut workspace, &started);
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["producer"], "panel");
        assert!(!status["result"]["headline"].as_str().unwrap().is_empty());
        assert!(!status["result"]["regions"].as_array().unwrap().is_empty());
        let mapped = call(&mut workspace, "events.facts", json!({"topic": "regions.mapped", "producer": REPORT_PRODUCER})).unwrap();
        assert_eq!(mapped["facts"].as_array().unwrap().len(), 1, "{mapped}");
    }

    #[test]
    fn an_empty_document_has_nothing_to_explain() {
        let mut workspace = workspace_with("empty.bin", b"");
        assert_eq!(call(&mut workspace, "report.run", json!({})).unwrap_err().code, ErrorCode::InvalidParams);
    }
}
