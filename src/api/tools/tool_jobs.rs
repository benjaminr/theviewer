//! What the measuring tools' job methods share: the span a tool reads,
//! checked against the document and the tool's own limit, and the job that
//! runs the tool on a thread, finishes with its result as JSON and, in the
//! window, hands the tool's own result to its panel.

use std::sync::mpsc::Sender;

use serde_json::Value;

use crate::api::jobs::JobStartedResult;
use crate::api::values;
use crate::api::workspace::{self, Workspace};
use crate::api::ApiError;
use crate::app::ViewerApp;
use crate::bus::JobHandle;

/// The bytes a tool works on: a span of one document, at the version read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolSpan {
    /// Id of the document.
    pub doc: String,
    /// The document's version when the span was read.
    pub version: u64,
    pub start: usize,
    pub len: usize,
}

/// The span `start`, `len` of document `doc`, checked against the
/// document. An omitted `len` runs to the end of the document or to
/// `limit` bytes, whichever comes first; a longer one is refused, naming
/// `what` the tool reads.
pub(crate) fn span(workspace: &mut dyn Workspace, doc: Option<&str>, start: u64, len: Option<u64>, limit: usize, what: &str) -> Result<ToolSpan, ApiError> {
    let id = workspace::resolve(workspace, doc)?;
    let info = workspace::info(workspace, &id)?;
    let document_len = info.len as usize;
    let room = (document_len as u64).saturating_sub(start);
    let (start, len) = values::span_within(document_len, start, Some(len.unwrap_or_else(|| room.min(limit as u64))))?;
    values::check_size(len, limit, what)?;
    Ok(ToolSpan { doc: id, version: info.version, start, len })
}

/// The bytes of `span`.
pub(crate) fn read(workspace: &mut dyn Workspace, span: &ToolSpan) -> Result<Vec<u8>, ApiError> {
    let (_, document) = workspace::document(workspace, Some(&span.doc))?;
    Ok(document.read_range(span.start, span.len))
}

/// The window, when this workspace is the window and shows document `doc`:
/// where a tool's panel is filled.
pub(crate) fn window_showing<'a>(workspace: &'a mut dyn Workspace, doc: &str) -> Option<&'a mut ViewerApp> {
    workspace.window().filter(|app| app.document_id() == doc)
}

/// What a finished tool says about its result: one line for the job list,
/// and the result as an API caller collects it.
pub(crate) struct Summary {
    pub ok: bool,
    pub outcome: String,
    pub result: Value,
}

impl Summary {
    /// A result, with its one-line outcome.
    pub fn of(outcome: impl Into<String>, result: impl serde::Serialize) -> Summary {
        Summary { ok: true, outcome: outcome.into(), result: serde_json::to_value(result).unwrap_or(Value::Null) }
    }

    /// Work that could not be done, with why.
    pub fn failed(outcome: impl Into<String>) -> Summary {
        let outcome = outcome.into();
        Summary { ok: false, result: serde_json::json!({ "error": outcome }), outcome }
    }
}

/// Start a job of `kind` (titled `title`) for `producer` about `span`'s
/// document, run `work` on a thread and finish the job with what
/// `summarise` says of its result. When `deliver` is given (the panel's
/// channel, in the window), the result is sent there too, after the job
/// has finished.
pub(crate) fn spawn<T: Send + 'static>(
    workspace: &mut dyn Workspace,
    producer: &str,
    (kind, title): (&str, &str),
    span: &ToolSpan,
    deliver: Option<Sender<T>>,
    work: impl FnOnce(&JobHandle) -> T + Send + 'static,
    summarise: impl FnOnce(&T) -> Summary + Send + 'static,
) -> JobStartedResult {
    let job = workspace.bus().start_job(kind, title, producer, Some((span.doc.clone(), span.version)));
    let started = JobStartedResult { job: job.id().to_string() };
    std::thread::spawn(move || {
        let result = work(&job);
        if job.is_cancelled() {
            return job.finish_cancelled();
        }
        let summary = summarise(&result);
        job.finish_with(summary.ok, summary.outcome, Some(summary.result));
        if let Some(sender) = deliver {
            let _ = sender.send(result);
        }
    });
    started
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::time::{Duration, Instant};

    use serde_json::{Value, json};

    use crate::api::test_support::call;
    use crate::api::Workspace;

    /// How long a test waits for a job.
    const PATIENCE: Duration = Duration::from_secs(30);

    /// Call job method `method` with `params` as the person and wait for
    /// its job's status once it has ended.
    pub fn run_job(workspace: &mut dyn Workspace, method: &str, params: Value) -> Value {
        let started = call(workspace, method, params).unwrap_or_else(|error| panic!("{method}: {error}"));
        wait_for(workspace, started["job"].as_str().expect("a job method returns its job"))
    }

    /// The status of job `job` once it has ended.
    pub fn wait_for(workspace: &mut dyn Workspace, job: &str) -> Value {
        let begun = Instant::now();
        loop {
            workspace.bus().deliver_all();
            let status = call(workspace, "jobs.status", json!({"job": job})).unwrap();
            if !matches!(status["state"].as_str(), Some("running" | "cancelling")) || begun.elapsed() > PATIENCE {
                return status;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
