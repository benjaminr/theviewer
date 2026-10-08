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
//! 1. **The run's document**, its input, is `options.doc`, or the current
//!    one. A step with no `doc` (when its method takes one), or with
//!    `"current"`, runs on it. The sheets the steps make are kept in a run
//!    map, by step and by the label a step's `makes` gives, and `sheet`
//!    anchors name them (`{"sheet": {"step": 2}}`, `{"sheet": "payload"}`,
//!    `{"sheet": "input"}`). A literal id is kept as it is; running a recipe
//!    (`options.only_own_documents`), one that is neither the input nor a
//!    sheet the run made stops the run, rather than running the step on
//!    some other document. See [`super::recipe`].
//! 2. **Anchors** marked `{"$anchor": …}` in a step's params are resolved
//!    against the step's document (its `doc` first), in the order
//!    [`super::anchors::anchors_in`] lists them, and each is reported in
//!    [`StepReport::anchors`].
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
//! 6. **The run's edits undo as one step** of each document it edited, the
//!    input and each sheet, named "Recipe steps by recipe:NAME", whether it
//!    completed or stopped, so one Undo of a document takes back everything
//!    the run changed in it.
//! 7. **Files.** A step that writes a file runs only when
//!    `options.allow_writes` says so (`theviewer replay --allow-writes`).
//!
//! The report lists the sheets the run made ([`RunReport::sheets`]).
//!
//! A **preview** (`options.preview`) resolves and describes each step on
//! this file without calling anything. It goes on past a problem, marking
//! that step failed and the first such as where the run would stop. A step
//! or pick anchor cannot be known until its step has run, nor a variable
//! until the step that binds it has, so each is shown as waiting for that
//! step.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::anchors::{Anchor, ResolveContext, RunSheets, anchors_in, is_document_id, replace_at, visit_paths};
use super::recipe::{Recipe, RecipeStep};
use super::{FileIdentity, Outcome};
use crate::api::{self, ApiError, Caller, Consent, Effect, ErrorCode, MethodRef, Workspace, workspace};
use crate::bus::{JobState, JobStatus};

/// Longest a run waits for one step's job before giving up on it.
pub const JOB_WAIT_LIMIT: Duration = Duration::from_secs(10 * 60);
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
    /// Whether a step that writes a file may run. `theviewer replay` lets
    /// one only with `--allow-writes`; through the API, the caller's leave
    /// to edit decides.
    pub allow_writes: bool,
    /// Whether a literal document id must name the run's input or a sheet
    /// the run made, as a recipe's must: going back and playback run the
    /// session's own steps, whose ids are its documents.
    pub only_own_documents: bool,
}

impl ReplayOptions {
    /// Options to run every step as `caller` on the current document,
    /// waiting for jobs, each step checked against `caller`'s policy.
    pub fn new(caller: Caller) -> Self {
        ReplayOptions { checked_as: Some(caller.clone()), caller, parameters: BTreeMap::new(), doc: None, through_step: None, preview: false, allow_writes: true, only_own_documents: false }
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
    /// The sheets the run made, in the order made.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sheets: Vec<RunSheet>,
    /// The same sheets as every call that makes sheets names them, so the
    /// `recipes.run` step that made them is their maker in the session's
    /// journal: `{"$sheet": {"step": N, "label": "firmware"}}` names one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<workspace::SheetOutput>,
}

/// A sheet a run made.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunSheet {
    /// The step that made it.
    pub step: u64,
    /// Its id in the workspace the run was in.
    pub doc: String,
    /// The label its step's `makes` gave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Its name, as `documents.info` gives it.
    pub name: String,
    /// Its length in bytes.
    pub len: u64,
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
    let mut run = Run { options, sheets: RunSheets::on(&run_doc), run_doc: run_doc.clone(), done: BTreeMap::new(), grouped: Vec::new(), previewed_bindings: Vec::new() };
    if !options.preview {
        run.open_undo_group(workspace, &run_doc);
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
        run.close_undo_groups(workspace);
    }
    report.sheets = run.sheets_made(workspace);
    report.outputs = report.sheets.iter().map(|sheet| workspace::SheetOutput { doc: sheet.doc.clone(), label: sheet.label.clone(), len: sheet.len }).collect();
    report
}

/// Run `recipe`'s steps as [`run`] does, after checking it can run here:
/// its parameters are given (defaults filled in, text read as the declared
/// type), and its warnings (API version, plugins, another file than it was
/// recorded on) are added to the report.
pub fn run_recipe(workspace: &mut dyn Workspace, recipe: &Recipe, options: &ReplayOptions) -> RunReport {
    let mut options = options.clone();
    options.only_own_documents = true;
    let mut warnings = recipe.warnings(&workspace.journal().session().api_version, &workspace.journal().session().plugins);
    if let Some(recorded_on) = recipe.input_recorded_on()
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
            RunReport { steps: Vec::new(), stopped: Some(Stopped { step, error }), ..RunReport::default() }
        }
    };
    warnings.append(&mut report.warnings);
    warnings.extend(crate::recipes::unknown_methods(workspace, recipe));
    report.warnings = warnings;
    report
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

/// A run in progress: its options, its document, the sheets its steps made,
/// and what each step done so far was given and returned.
struct Run<'a> {
    options: &'a ReplayOptions,
    run_doc: String,
    /// The run's input and the sheets its steps made.
    sheets: RunSheets,
    /// Each step done, by number, as `{"params", "result", "job"?}`, `job`
    /// being the result of the job the step started, once finished.
    done: BTreeMap<u64, Value>,
    /// The documents with an undo step open for the run's edits.
    grouped: Vec<String>,
    /// The variables earlier steps of a preview would have bound.
    previewed_bindings: Vec<String>,
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
            if step.method == "vars.set"
                && let Some(name) = step.params.get("name").and_then(Value::as_str)
            {
                self.previewed_bindings.push(name.to_string());
            }
            return report;
        }
        if let Some(refused) = method.as_ref().ok().and_then(|method| self.refuse_writing(step, method, &report.params)) {
            report.outcome = Outcome::Error(refused);
            return report;
        }
        let step_doc = report.params.get("doc").and_then(Value::as_str).unwrap_or(&self.run_doc).to_string();
        self.open_undo_group(workspace, &step_doc);
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
        self.keep_sheets_made(workspace, step, &result);
        report.result = Some(result);
        report
    }

    /// Put the run's document in the step's params and resolve its anchors
    /// into `report.params`, noting each in `report.anchors`.
    ///
    /// A step with no `doc` (when its method takes one), or with "current",
    /// runs on the run's document; a `doc` anchor is resolved first, as the
    /// other anchors are found in the document it names. This is the one
    /// place that rule is kept.
    fn prepare(&self, workspace: &mut dyn Workspace, method: &MethodRef, report: &mut StepReport) -> Result<(), ApiError> {
        if report.params.is_null() {
            report.params = Value::Object(Default::default());
        }
        if self.options.only_own_documents {
            self.check_documents_named(report)?;
        }
        if let Some(anchor) = report.params.get("doc").and_then(super::anchors::as_anchor) {
            self.resolve_into(workspace, report, "doc", &anchor, &self.run_doc.clone())?;
        }
        let takes_doc = method.takes_doc();
        if let Some(object) = report.params.as_object_mut() {
            let means_run_doc = match object.get("doc") {
                None => takes_doc,
                Some(doc) => doc.as_str() == Some(workspace::CURRENT),
            };
            if means_run_doc {
                object.insert("doc".to_string(), Value::String(self.run_doc.clone()));
            }
        }
        let waiting_for_doc = report.anchors.iter().find(|resolved| resolved.path == "doc").and_then(|resolved| resolved.pending.clone());
        let step_doc = report.params.get("doc").and_then(Value::as_str).map_or_else(|| self.run_doc.clone(), str::to_string);
        // A doc still marked waits for its step; it was reported above.
        for (path, anchor) in anchors_in(&report.params).into_iter().filter(|(path, _)| path != "doc") {
            if let Some(waiting) = &waiting_for_doc
                && !matches!(anchor, Anchor::Param { .. } | Anchor::Step { .. } | Anchor::Sheet { .. } | Anchor::Pick { .. } | Anchor::Var { .. })
            {
                let pending = format!("found in {waiting}");
                report.anchors.push(ResolvedAnchor { path, anchor, value: Value::Null, pending: Some(pending) });
                continue;
            }
            self.resolve_into(workspace, report, &path, &anchor, &step_doc)?;
        }
        Ok(())
    }

    /// Refuse a step whose params name a document by a literal id that is
    /// neither the run's input nor a sheet the run made: a recipe names the
    /// sheets its steps make with sheet anchors, and an id recorded in
    /// another session names some other document here, or none.
    fn check_documents_named(&self, report: &StepReport) -> Result<(), ApiError> {
        let mut foreign = None;
        visit_paths(&report.params, "", &mut |path, value| {
            if super::anchors::as_anchor(value).is_some() {
                return false;
            }
            if foreign.is_none()
                && let Some(id) = value.as_str().filter(|text| is_document_id(text))
                && !self.sheets.holds(id)
            {
                foreign = Some((path.to_string(), id.to_string()));
            }
            true
        });
        let Some((path, id)) = foreign else { return Ok(()) };
        let message = format!(
            "step {} ({}) names {id} at {path}, which is neither this run's input ({}) nor a sheet one of its steps made, so it does not run on some other document; a recipe names the sheet step N made as {}",
            report.step, report.method, self.run_doc, r#"{"$anchor": {"sheet": {"step": N}}}"#
        );
        Err(ApiError::not_found(message).with_data(serde_json::json!({ "path": path, "doc": id })))
    }

    /// Why step `step` may not run, when it would write a file and the run
    /// does not allow that.
    fn refuse_writing(&self, step: &RecipeStep, method: &MethodRef, params: &Value) -> Option<ApiError> {
        if self.options.allow_writes || !method.writes_file(params) {
            return None;
        }
        let message = format!("step {} ({}) writes a file, which this run does not allow; theviewer replay runs such steps only with --allow-writes", step.step, step.method);
        Some(ApiError::new(ErrorCode::ReadOnly, message))
    }

    /// Keep the sheets `step` made, as its result names them, under its
    /// number and the label its `makes` gives, which the workspace notes
    /// as the sheet's label too.
    fn keep_sheets_made(&mut self, workspace: &mut dyn Workspace, step: &RecipeStep, result: &Value) {
        let made: Vec<String> = super::sheets_made(result).into_iter().map(|sheet| sheet.doc).collect();
        if let (Some(label), Some(first)) = (&step.makes, made.first()) {
            self.sheets.labels.insert(label.clone(), first.clone());
            // A step inside a call (a recipes.run's) is not journalled, so
            // nothing has said what made the sheet yet: the run says so,
            // and the sheet is listed and named by its label.
            let made_by = workspace.lineage(first).and_then(|lineage| lineage.made_by);
            let mut made_by = made_by.unwrap_or_else(|| workspace::MadeBy { step: None, method: step.method.clone(), params: step.params.clone(), span: None, label: None });
            made_by.label = Some(label.clone());
            workspace.note_made_by(first, made_by);
        }
        self.sheets.made.insert(step.step, made);
    }

    /// The sheets the run made, in the order made.
    fn sheets_made(&self, workspace: &dyn Workspace) -> Vec<RunSheet> {
        let labelled = |doc: &str| self.sheets.labels.iter().find(|(_, labelled)| labelled.as_str() == doc).map(|(label, _)| label.clone());
        let mut sheets = Vec::new();
        for (step, made) in &self.sheets.made {
            for doc in made {
                let Ok(info) = workspace::info(workspace, doc) else { continue };
                sheets.push(RunSheet { step: *step, doc: doc.clone(), label: labelled(doc), name: info.name, len: info.len });
            }
        }
        sheets
    }

    /// Resolve `anchor` at `path` of `report.params` on document `doc`, and
    /// put its value there. In a preview, a step anchor is left marked and
    /// reported as waiting for its step.
    fn resolve_into(&self, workspace: &mut dyn Workspace, report: &mut StepReport, path: &str, anchor: &Anchor, doc: &str) -> Result<(), ApiError> {
        if self.options.preview
            && let Some(pending) = self.waiting_for(anchor)
        {
            report.anchors.push(ResolvedAnchor { path: path.to_string(), anchor: anchor.clone(), value: Value::Null, pending: Some(pending) });
            return Ok(());
        }
        let mut context = ResolveContext { workspace, doc: Some(doc.to_string()), steps: &self.done, parameters: &self.options.parameters, sheets: &self.sheets };
        let value = anchor.resolve(&mut context).map_err(|error| at_parameter(error, path))?;
        replace_at(&mut report.params, path, value.clone())?;
        report.anchors.push(ResolvedAnchor { path: path.to_string(), anchor: anchor.clone(), value, pending: None });
        Ok(())
    }

    /// Why `anchor` cannot be resolved yet in a preview: a step it reads
    /// has not run, a sheet it names is not made, or a variable it reads is
    /// bound by an earlier step that has not run. A parameter whose default
    /// is an anchor waits as that anchor does.
    fn waiting_for(&self, anchor: &Anchor) -> Option<String> {
        match anchor {
            Anchor::Sheet { sheet } if self.sheets.is_waiting_for(sheet) => return Some(format!("{}, once it is made", sheet.describe())),
            Anchor::Pick { pick } if pick.step.number(&self.sheets).is_err() => return Some(format!("found once {} has run", pick.step.describe())),
            Anchor::Var { var } if self.previewed_bindings.contains(var) => return Some(format!("found once the step that binds ${var} has run")),
            Anchor::Then { of, .. } => return self.waiting_for(of),
            Anchor::Param { param } => return self.options.parameters.get(param).and_then(super::anchors::as_anchor).and_then(|default| self.waiting_for(&default)),
            _ => {}
        }
        let step = anchor.cited_steps(&self.sheets).into_iter().find(|step| !self.done.contains_key(step))?;
        Some(format!("found once step {step} has run"))
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

    /// Open one undo step on document `doc` for every edit the run makes
    /// in it, unless one is open already.
    fn open_undo_group(&mut self, workspace: &mut dyn Workspace, doc: &str) {
        if self.grouped.iter().any(|grouped| grouped == doc) {
            return;
        }
        let label = self.options.caller.label("Recipe steps");
        if let Some(document) = workspace.document_mut(doc) {
            document.begin_labelled_group(label);
            self.grouped.push(doc.to_string());
        }
    }

    /// Close the run's undo step on each document it opened one on, and
    /// say the run's edits as the caller's.
    fn close_undo_groups(&self, workspace: &mut dyn Workspace) {
        for doc in &self.grouped {
            if let Some(document) = workspace.document_mut(doc) {
                document.end_group();
            }
            workspace.publish_edits(doc, &self.options.caller.producer());
        }
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
