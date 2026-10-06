//! `jobs.*`: the background work tools and API callers started: what is
//! running, how far it has got, what it gave back, and cancelling it.
//!
//! A method whose effect is `job` returns `{job}` at once; its result
//! arrives as `job.finished`'s `result`, and `jobs.status` returns it once
//! the job has finished.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ApiError;
use super::values::NoParams;
use super::workspace::Workspace;
use crate::bus::JobStatus;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("jobs.list", Read, list, super::values::NoParams, JobList, "The background jobs tools and callers started (the last 100): what each does, who started it, whether it is running, how far it has got and how it ended."),
    method!("jobs.status", Read, status, JobParams, crate::bus::JobStatus, "One job's state, progress and outcome, and once it has finished, the result of a job a method started."),
    method!("jobs.cancel", Read, cancel, JobParams, crate::bus::JobStatus, "Ask a running job to stop; it ends as cancelled, without a result, as soon as it notices."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        // A job to follow.
        ("analysis.overview_job", json!({"max_findings": 1})),
        ("jobs.list", json!({})),
        ("jobs.status", json!({"job": "overview-1"})),
        ("jobs.cancel", json!({"job": "overview-1"})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

/// The result of `jobs.list`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobList {
    /// The jobs remembered (the last 100), oldest first.
    pub jobs: Vec<JobStatus>,
}

/// Parameters of `jobs.status` and `jobs.cancel`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobParams {
    /// The job's id, such as "report-3", as `job.started` or a job method gave it.
    pub job: String,
}

/// What a method whose effect is `job` returns at once.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobStartedResult {
    /// Follow it with jobs.status, or on job.progress and job.finished.
    pub job: String,
}

pub fn list(workspace: &mut dyn Workspace, _params: NoParams) -> Result<JobList, ApiError> {
    Ok(JobList { jobs: workspace.bus().jobs().list() })
}

pub fn status(workspace: &mut dyn Workspace, params: JobParams) -> Result<JobStatus, ApiError> {
    workspace.bus().jobs().status(&params.job).ok_or_else(|| unknown(&params.job))
}

pub fn cancel(workspace: &mut dyn Workspace, params: JobParams) -> Result<JobStatus, ApiError> {
    workspace.bus().jobs_mut().cancel(&params.job).ok_or_else(|| unknown(&params.job))
}

fn unknown(job: &str) -> ApiError {
    ApiError::not_found(format!("there is no job '{job}'; jobs.list shows the ones remembered"))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use serde_json::json;

    use crate::api::test_support::{call, workspace_with};
    use crate::api::{ErrorCode, Workspace};

    /// Ask for a job's status until it has ended.
    fn wait_for(workspace: &mut crate::api::HeadlessWorkspace, job: &str) -> serde_json::Value {
        let started = Instant::now();
        loop {
            let status = call(workspace, "jobs.status", json!({"job": job})).unwrap();
            if !matches!(status["state"].as_str(), Some("running" | "cancelling")) || started.elapsed() > Duration::from_secs(20) {
                return status;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn an_overview_started_as_a_job_gives_its_report_through_jobs_status() {
        let mut workspace = workspace_with("notes.txt", &b"The quick brown fox jumps over the lazy dog. ".repeat(200));
        let started = call(&mut workspace, "analysis.overview_job", json!({"max_findings": 1})).unwrap();
        let job = started["job"].as_str().unwrap().to_string();
        let listed = call(&mut workspace, "jobs.list", json!({})).unwrap();
        assert!(listed["jobs"].as_array().unwrap().iter().any(|listed| listed["job"] == job.as_str()));
        let status = wait_for(&mut workspace, &job);
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["result"]["file"], "notes.txt", "the report the overview would have returned");
        assert_eq!(status["producer"], "panel");
        let finished = call(&mut workspace, "events.poll", json!({"topics": ["job.finished"]})).unwrap();
        assert_eq!(finished["messages"][0]["payload"]["result"]["file"], "notes.txt", "and on job.finished");
    }

    #[test]
    fn a_cancelled_job_ends_as_cancelled_without_a_result() {
        let mut workspace = workspace_with("a.bin", &[0u8; 4096]);
        let handle = workspace.bus().start_job("test", "Waiting", "test", None);
        let cancelled = call(&mut workspace, "jobs.cancel", json!({"job": handle.id()})).unwrap();
        assert_eq!(cancelled["state"], "cancelling");
        assert!(handle.is_cancelled(), "the work sees the flag");
        handle.finish_with(true, "done anyway", Some(json!(1)));
        let status = call(&mut workspace, "jobs.status", json!({"job": handle.id()})).unwrap();
        assert_eq!(status["state"], "cancelled");
        assert_eq!(status["result"], serde_json::Value::Null);
        assert_eq!(call(&mut workspace, "jobs.status", json!({"job": "nope-1"})).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn progress_is_followed_in_the_job_s_status() {
        let mut workspace = workspace_with("a.bin", b"x");
        let handle = workspace.bus().start_job("test", "Counting", "test", None);
        handle.progress(50, Some(100));
        let status = call(&mut workspace, "jobs.status", json!({"job": handle.id()})).unwrap();
        assert_eq!((status["done"].as_u64(), status["total"].as_u64(), status["state"].as_str()), (Some(50), Some(100), Some("running")));
    }
}
