//! Running recorded steps again: a recipe on another file, "go back to step
//! N", and playback one step at a time.
//!
//! Every way of running steps goes through here: the History tab for "go
//! back to step N" and playback, and the recipe runner, `theviewer replay`
//! and `recipes.run`. Each step is called through the API as
//! `options.caller`, so it is journalled and labelled like any other call,
//! after its anchors are resolved.
//!
//! How a run goes ([`run`]):
//!
//! 1. **The run's document** is `options.doc`, or the current one. A step's
//!    `doc` that names the recorded document means the run's document: a
//!    step with no `doc` (when its method takes one), with `"current"`, or
//!    with the id the recipe's first step named. Any other id is kept as it
//!    is (a document an earlier step opened is best named by a step anchor,
//!    `{"step": 2, "path": "result.doc"}`). See [`super::recipe`].
//! 2. **Anchors** marked `{"$anchor": …}` in a step's params are resolved
//!    against the step's document, in the order [`super::anchors::anchors_in`]
//!    lists them, and each is reported in [`StepReport::anchors`].
//! 3. **The call** is made as `options.caller`, so its edits are labelled
//!    "… by recipe:NAME", through [`crate::api::call_as`]. Each step is
//!    checked against the policy of `options.checked_as`: whoever started
//!    the run (Ask, an MCP client, a plugin), or by default the run's own
//!    caller; a step it denies or would ask about is refused and stops the
//!    run. With no one to check against, the person allowed the whole run
//!    (they pressed Run after the preview, went back to a step, or allowed
//!    the held `recipes.run` whose description lists the steps), so each
//!    step runs without asking again.
//! 4. **Jobs** a step starts are waited for, and the finished job's result
//!    is kept beside the step's params and result, for later step anchors
//!    (`job.candidates[0].period`).
//! 5. **The first failure stops the run**: a step whose anchor does not
//!    resolve or whose call fails, with [`RunReport::stopped`] saying which
//!    and why.
//! 6. **The run's edits undo as one step** of the run's document, named
//!    "Recipe steps by recipe:NAME", whether it completed or stopped, so
//!    one Undo takes back everything it changed.
//!
//! A **preview** (`options.preview`) resolves and describes each step on
//! this file without calling anything. It goes on past a problem, marking
//! that step failed and the first such as where the run would stop. A step
//! anchor cannot be known until its step has run, so it is shown as
//! waiting for that step.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::anchors::{Anchor, ResolveContext, anchors_in, replace_at};
use super::recipe::{Recipe, RecipeStep};
use super::{FileIdentity, Outcome};
use crate::api::{self, ApiError, Caller, Consent, Effect, ErrorCode, MethodRef, Workspace, workspace};
use crate::bus::{JobState, JobStatus};

/// Longest a run waits for one step's job before giving up on it.
const JOB_WAIT_LIMIT: Duration = Duration::from_secs(10 * 60);
/// How often a run looks at a job it waits for.
const JOB_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// How to run steps.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayOptions {
    /// Who the steps are called as: `Caller::Recipe(name)` for a recipe,
    /// `Caller::Panel` when the person goes back to a step.
    pub caller: Caller,
    /// The values of the recipe's parameters, by name.
    pub parameters: BTreeMap<String, Value>,
    /// The document to run on, by id; the current one when `None`.
    pub doc: Option<String>,
    /// Stop after the step with this number (going back to step N).
    pub through_step: Option<u64>,
    /// Resolve anchors and describe each step without calling anything:
    /// the preview shown before a recipe changes a file.
    pub preview: bool,
    /// Whose policy each step is checked against: `caller`'s by default,
    /// or whoever started the run (Ask, an MCP client, a plugin), so a
    /// recipe run by them may do only what they may. A step the policy
    /// denies, or would ask about, is refused and stops the run. `None`
    /// when the whole run is allowed already: the person pressed Run after
    /// the preview, went back to a step, or allowed the run when asked.
    pub checked_as: Option<Caller>,
}

impl ReplayOptions {
    /// Options to run every step as `caller` on the current document,
    /// waiting for jobs, each step checked against `caller`'s policy.
    pub fn new(caller: Caller) -> Self {
        ReplayOptions { checked_as: Some(caller.clone()), caller, parameters: BTreeMap::new(), doc: None, through_step: None, preview: false }
    }

    /// Whether each step needs leave to run, and whose.
    pub fn consent(&self) -> Consent<'_> {
        self.checked_as.as_ref().map_or(Consent::Given, Consent::CheckedAs)
    }
}

/// An anchor of a step and what it resolved to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedAnchor {
    /// The parameter's path in the step's params, such as `start`.
    pub path: String,
    pub anchor: Anchor,
    pub value: Value,
    /// Why there is no value yet, in a preview: the step anchor's step has
    /// not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<String>,
}

/// What one step did (or, in a preview, would do).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StepReport {
    /// The step's number in the recipe or journal.
    pub step: u64,
    pub method: String,
    /// The parameters it was called with, anchors resolved.
    pub params: Value,
    /// What it did in plain words.
    pub description: String,
    /// Where each anchor resolved.
    #[serde(default)]
    pub anchors: Vec<ResolvedAnchor>,
    pub outcome: Outcome,
    /// What it returned; none in a preview or when it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The journal step the call was recorded as in this session (none
    /// when the run was itself inside a call, such as `recipes.run`, whose
    /// step it is part of).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_step: Option<u64>,
    /// The job the step started, as it finished, when the run waited for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<JobStatus>,
}

/// Why a run stopped before its last step.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Stopped {
    /// The step that failed, or whose anchor did not resolve.
    pub step: u64,
    pub error: ApiError,
}

/// What a run did, step by step: what `recipes.run` returns and `theviewer
/// replay` writes for each file.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunReport {
    /// Each step run (or previewed), in order.
    pub steps: Vec<StepReport>,
    /// Why the run stopped early, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<Stopped>,
    /// Things to know that did not stop it: a plugin missing or changed, a
    /// different API version, another file than the one recorded on.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl RunReport {
    /// Whether every step ran.
    pub fn completed(&self) -> bool {
        self.stopped.is_none()
    }

    /// The run in one line: "4 steps ran" or "Stopped at step 3 of 4
    /// (bytes.write): …".
    pub fn summary(&self) -> String {
        match &self.stopped {
            None => {
                let ran = self.steps.len();
                format!("{ran} step{} ran", if ran == 1 { "" } else { "s" })
            }
            Some(stopped) => {
                let method = self.steps.iter().find(|report| report.step == stopped.step).map_or(String::new(), |report| format!(" ({})", report.method));
                format!("Stopped at step {}{method}: {}", stopped.step, stopped.error.message)
            }
        }
    }
}

/// Run `steps` in order on `workspace` as `options` say, resolving each
/// step's anchors first and stopping at the first failure; see the module
/// documentation for the whole of it.
pub fn run(workspace: &mut dyn Workspace, steps: &[RecipeStep], options: &ReplayOptions) -> RunReport {
    let mut report = RunReport::default();
    let Some(first) = steps.first() else { return report };
    let run_doc = match workspace::resolve(workspace, options.doc.as_deref()) {
        Ok(doc) => doc,
        Err(error) => {
            report.stopped = Some(Stopped { step: first.step, error: ApiError::new(error.code, format!("there is no document to run on: {}", error.message)) });
            return report;
        }
    };
    let mut run = Run { options, run_doc, recorded_doc: recorded_document(steps), done: BTreeMap::new() };
    if !options.preview {
        run.open_undo_group(workspace);
    }
    for step in steps {
        if options.through_step.is_some_and(|through| step.step > through) {
            break;
        }
        let step_report = run.step(workspace, step);
        if let Outcome::Error(error) = &step_report.outcome
            && report.stopped.is_none()
        {
            report.stopped = Some(Stopped { step: step.step, error: error.clone() });
        }
        let failed = !step_report.outcome.is_ok();
        report.steps.push(step_report);
        if failed && !options.preview {
            break;
        }
    }
    if !options.preview {
        run.close_undo_group(workspace);
    }
    report
}

/// Run `recipe`'s steps as [`run`] does, after checking it can run here:
/// its parameters are given (defaults filled in, text read as the declared
/// type), and its warnings (API version, plugins, another file than it was
/// recorded on) are added to the report.
pub fn run_recipe(workspace: &mut dyn Workspace, recipe: &Recipe, options: &ReplayOptions) -> RunReport {
    let mut options = options.clone();
    let mut warnings = recipe.warnings(&workspace.journal().session().api_version, &workspace.journal().session().plugins);
    if let Some(recorded_on) = &recipe.recorded_on
        && let Ok(doc) = workspace::resolve(workspace, options.doc.as_deref())
        && !is_same_file(workspace, &doc, recorded_on)
    {
        warnings.push(format!("this is not the file the recipe was recorded on ({}, {} bytes); its anchors find their values here, but literal offsets may not fit", recorded_on.name, recorded_on.size));
    }
    let mut report = match recipe.parameter_values(&options.parameters) {
        Ok(values) => {
            options.parameters = values;
            run(workspace, &recipe.steps, &options)
        }
        Err(error) => {
            let step = recipe.steps.first().map_or(0, |step| step.step);
            RunReport { steps: Vec::new(), stopped: Some(Stopped { step, error }), warnings: Vec::new() }
        }
    };
    warnings.append(&mut report.warnings);
    warnings.extend(crate::recipes::unknown_methods(workspace, recipe));
    report.warnings = warnings;
    report
}

/// The document the recipe's steps were recorded on, as its first step
/// that names one names it.
fn recorded_document(steps: &[RecipeStep]) -> Option<String> {
    steps.iter().find_map(|step| step.params.get("doc").and_then(Value::as_str).filter(|doc| *doc != workspace::CURRENT).map(str::to_string))
}

/// Whether document `doc` is the file `identity` describes: the same size
/// and, when both were hashed, the same SHA-256. A document still as the
/// session first saw it is not hashed again.
fn is_same_file(workspace: &mut dyn Workspace, doc: &str, identity: &FileIdentity) -> bool {
    let Some(version) = workspace.version(doc) else { return false };
    let first_seen = workspace.journal().session().document(doc).filter(|first_seen| first_seen.version == version).map(|first_seen| first_seen.file());
    let Some(document) = workspace.document_mut(doc) else { return false };
    if document.len() as u64 != identity.size {
        return false;
    }
    let Some(recorded) = &identity.sha256 else { return true };
    let sha256 = match first_seen {
        Some(file) => file.sha256,
        None => super::document_sha256(document),
    };
    // Too large to hash: the size has to do.
    sha256.is_none_or(|sha256| sha256 == *recorded)
}

/// A run in progress: its options, its document, and what each step done
/// so far was given and returned.
struct Run<'a> {
    options: &'a ReplayOptions,
    run_doc: String,
    /// The id the recorded document had, which the run's stands in for.
    recorded_doc: Option<String>,
    /// Each step done, by number, as `{"params", "result", "job"?}`, `job`
    /// being the result of the job the step started, once finished.
    done: BTreeMap<u64, Value>,
}

impl Run<'_> {
    /// Resolve, describe and (unless previewing) call one step.
    fn step(&mut self, workspace: &mut dyn Workspace, step: &RecipeStep) -> StepReport {
        let mut report = StepReport {
            step: step.step,
            method: step.method.clone(),
            params: step.params.clone(),
            description: String::new(),
            anchors: Vec::new(),
            outcome: Outcome::Ok,
            result: None,
            journal_step: None,
            job: None,
        };
        let method = api::find(workspace, &step.method);
        let prepared = match &method {
            Ok(method) => self.prepare(workspace, method, &mut report),
            Err(error) => Err(error.clone()),
        };
        report.description = api::describe_call(workspace, &step.method, &report.params);
        if let Some(waiting) = report.anchors.iter().find_map(|anchor| anchor.pending.clone()) {
            report.description = format!("{} ({waiting})", report.description);
        }
        if let Err(error) = prepared {
            report.outcome = Outcome::Error(error);
            return report;
        }
        if self.options.preview {
            return report;
        }
        let before = workspace.journal().last_step();
        let outermost = workspace.journal().depth == 0;
        let called = api::call_as(workspace, &self.options.caller, &step.method, report.params.clone(), self.options.consent());
        let after = workspace.journal().last_step();
        report.journal_step = after.filter(|_| outermost && after != before);
        let starts_jobs = method.is_ok_and(|method| method.effect() == Effect::Job);
        let result = match called.and_then(|result| if starts_jobs { self.await_job(workspace, step, result, &mut report) } else { Ok(result) }) {
            Ok(result) => result,
            Err(error) => {
                report.outcome = Outcome::Error(error);
                return report;
            }
        };
        let mut done = serde_json::json!({ "params": report.params, "result": result });
        if let Some(job) = &report.job {
            done["job"] = job.result.clone().unwrap_or(Value::Null);
        }
        self.done.insert(step.step, done);
        report.result = Some(result);
        report
    }

    /// Put the run's document in the step's params and resolve its anchors
    /// into `report.params`, noting each in `report.anchors`.
    ///
    /// A step's `doc` that names the recorded document means the run's: a
    /// step with none (when its method takes one), with "current", or with
    /// the id the recipe's first step named. This is the one place that
    /// rule is kept.
    fn prepare(&self, workspace: &mut dyn Workspace, method: &MethodRef, report: &mut StepReport) -> Result<(), ApiError> {
        if report.params.is_null() {
            report.params = Value::Object(Default::default());
        }
        // The document first: the other anchors are found in it.
        if let Some(anchor) = report.params.get("doc").and_then(super::anchors::as_anchor) {
            self.resolve_into(workspace, report, "doc", &anchor, &self.run_doc.clone())?;
        }
        let takes_doc = method.takes_doc();
        if let Some(object) = report.params.as_object_mut() {
            let named = object.get("doc").and_then(Value::as_str);
            let means_run_doc = match named {
                None => takes_doc && !object.contains_key("doc"),
                Some(doc) => doc == workspace::CURRENT || self.recorded_doc.as_deref() == Some(doc),
            };
            if means_run_doc {
                object.insert("doc".to_string(), Value::String(self.run_doc.clone()));
            }
        }
        let step_doc = report.params.get("doc").and_then(Value::as_str).map_or_else(|| self.run_doc.clone(), str::to_string);
        for (path, anchor) in anchors_in(&report.params) {
            self.resolve_into(workspace, report, &path, &anchor, &step_doc)?;
        }
        Ok(())
    }

    /// Resolve `anchor` at `path` of `report.params` on document `doc`, and
    /// put its value there. In a preview, a step anchor is left marked and
    /// reported as waiting for its step.
    fn resolve_into(&self, workspace: &mut dyn Workspace, report: &mut StepReport, path: &str, anchor: &Anchor, doc: &str) -> Result<(), ApiError> {
        if self.options.preview
            && let Anchor::Step { step, .. } = anchor
            && !self.done.contains_key(step)
        {
            let pending = format!("found once step {step} has run");
            report.anchors.push(ResolvedAnchor { path: path.to_string(), anchor: anchor.clone(), value: Value::Null, pending: Some(pending) });
            return Ok(());
        }
        let mut context = ResolveContext { workspace, doc: Some(doc.to_string()), steps: &self.done, parameters: &self.options.parameters };
        let value = anchor.resolve(&mut context).map_err(|error| at_parameter(error, path))?;
        replace_at(&mut report.params, path, value.clone())?;
        report.anchors.push(ResolvedAnchor { path: path.to_string(), anchor: anchor.clone(), value, pending: None });
        Ok(())
    }

    /// When `step`, of a method that starts jobs, started one, wait for it
    /// to finish and keep its status in `report`; a job that failed or was
    /// cancelled fails the step.
    fn await_job(&self, workspace: &mut dyn Workspace, step: &RecipeStep, result: Value, report: &mut StepReport) -> Result<Value, ApiError> {
        let Some(job) = result.get("job").and_then(Value::as_str) else { return Ok(result) };
        let finished = wait_for_job(workspace, job)?;
        let ended_well = finished.state == JobState::Finished;
        let outcome = finished.outcome.clone().unwrap_or_default();
        report.job = Some(finished);
        if ended_well {
            Ok(result)
        } else {
            Err(ApiError::new(ErrorCode::Cancelled, format!("the job {job} that {} started did not finish: {outcome}", step.method)))
        }
    }

    /// Open one undo step on the run's document for every edit the run
    /// makes.
    fn open_undo_group(&self, workspace: &mut dyn Workspace) {
        let label = self.options.caller.label("Recipe steps");
        if let Some(document) = workspace.document_mut(&self.run_doc) {
            document.begin_labelled_group(label);
        }
    }

    /// Close the run's undo step, and say the run's edits as the caller's.
    fn close_undo_group(&self, workspace: &mut dyn Workspace) {
        if let Some(document) = workspace.document_mut(&self.run_doc) {
            document.end_group();
        }
        workspace.publish_edits(&self.run_doc, &self.options.caller.producer());
    }
}

/// `error` from resolving the anchor at `path`, saying which parameter it
/// was for.
fn at_parameter(error: ApiError, path: &str) -> ApiError {
    let mut data = error.data.clone().unwrap_or_else(|| serde_json::json!({}));
    data["path"] = Value::String(path.to_string());
    ApiError::new(error.code, format!("the parameter {path}: {}", error.message)).with_data(data)
}

/// Wait for job `job` to end, delivering the bus's messages as the window
/// would (headless, asking for the bus delivers them), and return how it
/// ended. A job still running after [`JOB_WAIT_LIMIT`] is cancelled.
pub fn wait_for_job(workspace: &mut dyn Workspace, job: &str) -> Result<JobStatus, ApiError> {
    let started = Instant::now();
    loop {
        if let Some(app) = workspace.window() {
            app.run_bus();
        }
        let status = workspace.bus().jobs().status(job).ok_or_else(|| ApiError::not_found(format!("there is no job '{job}' to wait for")))?;
        if !matches!(status.state, JobState::Running | JobState::Cancelling) {
            return Ok(status);
        }
        if started.elapsed() > JOB_WAIT_LIMIT {
            workspace.bus().jobs_mut().cancel(job);
            return Err(ApiError::new(ErrorCode::Cancelled, format!("the job {job} did not finish within {} minutes, so it was cancelled", JOB_WAIT_LIMIT.as_secs() / 60)));
        }
        std::thread::sleep(JOB_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests;
