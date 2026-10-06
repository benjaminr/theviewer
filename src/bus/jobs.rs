//! Background jobs: each has an id, a handle the work keeps to report its
//! progress, notice it was cancelled and say how it ended, and a record in
//! the bus's registry that `jobs.list`, `jobs.status` and `jobs.cancel` read.
//!
//! Starting a job registers it and publishes `job.started`; the handle
//! publishes `job.progress` and `job.finished` from whatever thread does the
//! work. The registry follows the delivered messages, so a job's status is
//! what the bus has said about it. Cancelling sets the job's flag: the work
//! checks it where it can (between packets, say) and otherwise drops its
//! result when it ends, finishing as cancelled.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::topics::{JobFinished, JobProgress, JobStarted};
use super::{Draft, Payload, Publisher};

/// Most jobs the registry remembers; the oldest finished ones go first.
const REMEMBERED_JOBS: usize = 100;
/// Progress is published when it has moved on by at least this fraction.
const PROGRESS_STEP: f64 = 0.05;

/// Where a job is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Still working.
    Running,
    /// Asked to stop, and not yet stopped.
    Cancelling,
    /// Finished with a result.
    Finished,
    /// Finished without one.
    Failed,
    /// Stopped because it was cancelled.
    Cancelled,
}

/// One job, as `jobs.list` and `jobs.status` describe it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobStatus {
    /// Unique for the session, such as "report-3".
    pub job: String,
    /// What the job does, such as "Report".
    pub title: String,
    /// Who started it, such as `tool:report` or `mcp:claude-code`.
    pub producer: String,
    /// The document it works on, if one.
    pub document: Option<String>,
    pub state: JobState,
    /// Units of work done, when the job counts them.
    pub done: Option<u64>,
    /// Units of work in all, when known.
    pub total: Option<u64>,
    /// One line on what it found, or why it stopped, once it has.
    pub outcome: Option<String>,
    /// What a job started through the API gives back once finished: the
    /// result the method would have returned.
    pub result: Option<Value>,
}

/// What the work of a job holds: its id, its cancellation flag and a way to
/// say how it is going. Cloneable, and usable from any thread.
#[derive(Clone)]
pub struct JobHandle {
    id: String,
    title: String,
    producer: String,
    document: Option<(String, u64)>,
    cancel: Arc<AtomicBool>,
    publisher: Publisher,
    /// The fraction of the work last published as done.
    reported: Arc<std::sync::Mutex<f64>>,
}

impl JobHandle {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Whether someone asked the job to stop.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// The flag cancelling sets, for work that checks one of its own.
    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }

    /// Ask the job to stop.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    fn draft(&self, payload: Payload) -> Draft {
        let draft = Draft::new(self.producer.clone(), payload);
        match &self.document {
            Some((document, version)) => draft.about(document.clone(), *version),
            None => draft,
        }
    }

    /// Say that `done` of `total` units are done, when it has moved on
    /// enough since last said (or is complete).
    pub fn progress(&self, done: u64, total: Option<u64>) {
        if let Some(total) = total.filter(|&total| total > 0) {
            let fraction = done as f64 / total as f64;
            let Ok(mut reported) = self.reported.lock() else { return };
            if fraction - *reported < PROGRESS_STEP && done < total {
                return;
            }
            *reported = fraction;
        }
        self.publisher.publish(self.draft(Payload::JobProgress(JobProgress { job: self.id.clone(), done, total })));
    }

    /// Say the job ended: with a result (`ok`) or not, with a one-line
    /// outcome. A job that was cancelled says so instead.
    pub fn finish(&self, ok: bool, outcome: impl Into<String>) {
        self.finish_with(ok, outcome, None);
    }

    /// As [`JobHandle::finish`], with the result an API caller collects.
    pub fn finish_with(&self, ok: bool, outcome: impl Into<String>, result: Option<Value>) {
        let finished = if self.is_cancelled() {
            JobFinished { job: self.id.clone(), title: self.title.clone(), ok: false, outcome: "cancelled".to_string(), cancelled: true, result: None }
        } else {
            JobFinished { job: self.id.clone(), title: self.title.clone(), ok, outcome: outcome.into(), cancelled: false, result }
        };
        self.publisher.publish(self.draft(Payload::JobFinished(finished)));
    }

    /// Say the job stopped because it was cancelled.
    pub fn finish_cancelled(&self) {
        self.cancel();
        self.finish(false, "cancelled");
    }
}

struct JobRecord {
    status: JobStatus,
    cancel: Arc<AtomicBool>,
}

/// Every job started, newest last, with its cancellation flag.
#[derive(Default)]
pub struct JobRegistry {
    jobs: VecDeque<JobRecord>,
    started: u64,
}

impl JobRegistry {
    /// Register a new job of `kind` (such as `report`) and return its handle;
    /// the caller publishes `job.started` with [`JobHandle`]'s draft.
    pub(super) fn start(&mut self, kind: &str, title: &str, producer: String, document: Option<(String, u64)>, publisher: Publisher) -> (JobHandle, Draft) {
        self.started += 1;
        let id = format!("{kind}-{}", self.started);
        let cancel = Arc::new(AtomicBool::new(false));
        let status = JobStatus {
            job: id.clone(),
            title: title.to_string(),
            producer: producer.clone(),
            document: document.as_ref().map(|(document, _)| document.clone()),
            state: JobState::Running,
            done: None,
            total: None,
            outcome: None,
            result: None,
        };
        if self.jobs.len() == REMEMBERED_JOBS
            && let Some(oldest_done) = self.jobs.iter().position(|record| !matches!(record.status.state, JobState::Running | JobState::Cancelling))
        {
            self.jobs.remove(oldest_done);
        }
        self.jobs.push_back(JobRecord { status, cancel: Arc::clone(&cancel) });
        let handle = JobHandle { id: id.clone(), title: title.to_string(), producer, document, cancel, publisher, reported: Arc::default() };
        let started = handle.draft(Payload::JobStarted(JobStarted { job: id, title: title.to_string() }));
        (handle, started)
    }

    fn record_mut(&mut self, job: &str) -> Option<&mut JobRecord> {
        self.jobs.iter_mut().find(|record| record.status.job == job)
    }

    /// Follow a delivered `job.progress` or `job.finished`.
    pub(super) fn note(&mut self, payload: &Payload) {
        match payload {
            Payload::JobProgress(progress) => {
                if let Some(record) = self.record_mut(&progress.job) {
                    record.status.done = Some(progress.done);
                    record.status.total = progress.total;
                }
            }
            Payload::JobFinished(finished) => {
                if let Some(record) = self.record_mut(&finished.job) {
                    record.status.state = match (finished.cancelled, finished.ok) {
                        (true, _) => JobState::Cancelled,
                        (false, true) => JobState::Finished,
                        (false, false) => JobState::Failed,
                    };
                    record.status.outcome = Some(finished.outcome.clone());
                    record.status.result = finished.result.clone();
                }
            }
            _ => {}
        }
    }

    /// Every job remembered, oldest first.
    pub fn list(&self) -> Vec<JobStatus> {
        self.jobs.iter().map(|record| record.status.clone()).collect()
    }

    /// One job's status.
    pub fn status(&self, job: &str) -> Option<JobStatus> {
        self.jobs.iter().find(|record| record.status.job == job).map(|record| record.status.clone())
    }

    /// Ask a job to stop; its status, or `None` when there is no such job.
    /// A job that has ended is left as it was.
    pub fn cancel(&mut self, job: &str) -> Option<JobStatus> {
        let record = self.record_mut(job)?;
        if record.status.state == JobState::Running {
            record.cancel.store(true, Ordering::Relaxed);
            record.status.state = JobState::Cancelling;
        }
        Some(record.status.clone())
    }

    /// Whether a job started by `producer` is still running.
    pub fn running_from(&self, producer: &str) -> bool {
        self.jobs.iter().any(|record| record.status.producer == producer && matches!(record.status.state, JobState::Running | JobState::Cancelling))
    }
}
