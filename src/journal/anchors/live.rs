//! Anchors resolved at call time, against the live session: what
//! [`crate::api::call_as`] does with the anchors any caller marks in a
//! call's params, before the method runs.
//!
//! A recipe's run resolves anchors against what its own steps did
//! ([`super::super::replay`]); a live call resolves them against the
//! session: a step or pick anchor reads the journal's entry for the step
//! (a read it cites is first moved into the journal with
//! [`super::super::promote`], and a job's result is its job's), a sheet
//! anchor names a sheet a step of the session made or one labelled so,
//! and `{"sheet": "input"}` the file the caller's focus descends from.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{Anchor, ResolveContext, RunSheets, anchors_in, as_anchor, is_marked, replace_at, visit_paths};
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller};
use crate::bus::JobState;
use crate::journal::DerivedFrom;
use crate::journal::provenance::{entry_value, not_a_step};

/// The anchors of one call, resolved as the call is prepared.
pub struct LiveAnchors {
    caller: Caller,
    /// The session's sheets, once an anchor needed them.
    sheets: Option<RunSheets>,
    /// Each step an anchor read, as `{"params", "result", "job"?}`.
    steps: BTreeMap<u64, Value>,
}

impl LiveAnchors {
    pub fn new(caller: &Caller) -> Self {
        LiveAnchors { caller: caller.clone(), sheets: None, steps: BTreeMap::new() }
    }

    /// Resolve the anchor marked as the call's `doc`, if there is one, on
    /// the caller's focus, and put its value there.
    pub fn resolve_doc(&mut self, workspace: &mut dyn Workspace, params: &mut Value) -> Result<DerivedFrom, ApiError> {
        let mut derived_from = DerivedFrom::new();
        let Some(marked) = params.get("doc") else { return Ok(derived_from) };
        if let Some(anchor) = as_anchor(marked) {
            let focus = workspace::focus_of(workspace, &self.caller);
            let value = self.resolve(workspace, &anchor, "doc", focus)?;
            params["doc"] = value;
            derived_from.insert("doc".to_string(), anchor);
        }
        Ok(derived_from)
    }

    /// Resolve every other anchor marked in `params`, on the call's `doc`
    /// (or the caller's focus), and put each value in its place.
    pub fn resolve_rest(&mut self, workspace: &mut dyn Workspace, params: &mut Value) -> Result<DerivedFrom, ApiError> {
        check_markers(params)?;
        let mut derived_from = DerivedFrom::new();
        let anchors: Vec<(String, Anchor)> = anchors_in(params).into_iter().filter(|(path, _)| path != "doc").collect();
        if anchors.is_empty() {
            return Ok(derived_from);
        }
        let doc = params.get("doc").and_then(Value::as_str).map(str::to_string).or_else(|| workspace::focus_of(workspace, &self.caller));
        for (path, anchor) in anchors {
            let value = self.resolve(workspace, &anchor, &path, doc.clone())?;
            replace_at(params, &path, value)?;
            derived_from.insert(path, anchor);
        }
        Ok(derived_from)
    }

    /// What `anchor`, at the parameter `path`, finds now on document `doc`.
    fn resolve(&mut self, workspace: &mut dyn Workspace, anchor: &Anchor, path: &str, doc: Option<String>) -> Result<Value, ApiError> {
        let at_parameter = |error: ApiError| {
            let mut data = error.data.clone().unwrap_or_else(|| serde_json::json!({}));
            data["path"] = Value::String(path.to_string());
            ApiError::new(error.code, format!("the parameter {path}: {}", error.message)).with_data(data)
        };
        if self.sheets.is_none() {
            self.sheets = Some(session_sheets(workspace, &self.caller));
        }
        let sheets = self.sheets.clone().unwrap_or_default();
        for step in anchor.cited_steps(&sheets) {
            self.load_step(workspace, step).map_err(at_parameter)?;
        }
        let parameters = BTreeMap::new();
        let mut context = ResolveContext { workspace, doc, steps: &self.steps, parameters: &parameters, sheets: &sheets };
        anchor.resolve(&mut context).map_err(at_parameter)
    }

    /// Read step `step` of the journal for anchors to cite: a read is moved
    /// into the journal first, and a job it started is waited for.
    fn load_step(&mut self, workspace: &mut dyn Workspace, step: u64) -> Result<(), ApiError> {
        if self.steps.contains_key(&step) {
            return Ok(());
        }
        if !crate::journal::promote(workspace, step) {
            return Err(not_a_step(step));
        }
        let entry = workspace.journal().entry(step).cloned().ok_or_else(|| not_a_step(step))?;
        if !entry.outcome.is_ok() {
            return Err(ApiError::invalid_params(format!("step {step} ({}) failed, so it has no value to take", entry.method)));
        }
        let mut value = entry_value(&entry);
        if let Some(job) = entry.result.as_ref().and_then(|result| result.get("job")).and_then(Value::as_str) {
            let finished = crate::journal::replay::wait_for_job(workspace, job)?;
            if finished.state != JobState::Finished {
                return Err(ApiError::not_found(format!("the job {job} that step {step} ({}) started did not finish, so it has no result to take", entry.method)));
            }
            value["job"] = finished.result.unwrap_or(Value::Null);
        }
        self.steps.insert(step, value);
        Ok(())
    }
}

/// Refuse a value marked as an anchor that reads as none: a mistyped
/// anchor would otherwise reach the method as a literal object.
fn check_markers(params: &Value) -> Result<(), ApiError> {
    let mut malformed = None;
    visit_paths(params, "", &mut |path, value| {
        if as_anchor(value).is_some() {
            return false;
        }
        if malformed.is_none() && is_marked(value) {
            malformed = Some(path.to_string());
        }
        true
    });
    match malformed {
        None => Ok(()),
        Some(path) => Err(ApiError::invalid_params(format!(
            "the parameter {path} is marked as an anchor but is not one: an anchor is a step, find, structure, finding, selection, param, sheet, pick, then or var anchor (see docs/recipes.md), $var takes a name and $sheet a step number or label"
        ))),
    }
}

/// The session's sheets as anchors name them: those each successful step
/// made, the open documents by label, and as the input the file the
/// caller's focus descends from.
fn session_sheets(workspace: &dyn Workspace, caller: &Caller) -> RunSheets {
    let mut sheets = RunSheets::default();
    for entry in workspace.journal().entries().filter(|entry| entry.outcome.is_ok() && !entry.made.is_empty()) {
        sheets.made.insert(entry.step, entry.made.clone());
    }
    for document in workspace.documents() {
        if let Some(label) = document.label {
            sheets.labels.insert(label, document.id);
        }
    }
    sheets.input = workspace::focus_of(workspace, caller).map(|focus| workspace::root_of(workspace, &focus));
    sheets
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::{call, workspace_with};
    use crate::api::{Caller, ErrorCode, Workspace};

    #[test]
    fn a_value_a_read_returned_is_passed_on_by_anchor_and_recorded_as_provenance() {
        let mut workspace = workspace_with("a.bin", b"....MAGIC....");
        call(&mut workspace, "search.find", json!({"query": "MAGIC", "mode": "text"})).unwrap();
        let read = workspace.journal().reads().last().unwrap().step;
        let anchor = json!({"$anchor": {"of": {"step": read, "path": "result.at"}, "then": [{"add": 5}]}});
        let after = call(&mut workspace, "bytes.read", json!({"start": anchor, "len": 4, "encoding": "text"})).unwrap();
        assert_eq!(after["data"], "....");
        let marker = call(&mut workspace, "bookmarks.add", json!({"start": {"$anchor": {"step": read, "path": "result.at"}}, "len": 5, "name": "magic"})).unwrap();
        assert!(marker.is_object());
        let entry = workspace.journal().entries().last().unwrap();
        assert_eq!(entry.params["start"], 4, "the journal keeps the value");
        assert_eq!(serde_json::to_value(&entry.derived_from["start"]).unwrap(), json!({"step": read, "path": "result.at"}));
        assert!(workspace.journal().entry(read).is_some(), "the read it cited is a step of the journal");
    }

    #[test]
    fn a_sheet_a_step_made_is_named_by_its_step() {
        let mut workspace = workspace_with("outer.bin", b"outer payload");
        let derived = call(&mut workspace, "documents.derive", json!({"doc": "doc-1", "start": 6, "len": 7})).unwrap();
        let step = workspace.journal().last_step().unwrap();
        let read = call(&mut workspace, "bytes.read", json!({"doc": {"$sheet": step}, "start": 0, "encoding": "text"})).unwrap();
        assert_eq!(read["data"], "payload");
        assert_eq!(derived["output"]["doc"], "doc-2");
        let unknown = call(&mut workspace, "bytes.read", json!({"doc": {"$sheet": 99}, "start": 0})).unwrap_err();
        assert_eq!(unknown.code, ErrorCode::NotFound);
        assert!(unknown.message.starts_with("the parameter doc: the sheet step 99 made did not resolve"), "{}", unknown.message);
    }

    #[test]
    fn a_mistyped_anchor_is_refused_rather_than_passed_on() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let refused = call(&mut workspace, "bytes.read", json!({"start": {"$anchor": {"stpe": 1}}, "len": 1})).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidParams);
        assert!(refused.message.starts_with("the parameter start is marked as an anchor but is not one"), "{}", refused.message);
        let entry = workspace.journal().reads().last();
        assert!(entry.is_none_or(|entry| entry.method != "bytes.read"), "a refused read is not kept");
    }

    #[test]
    fn a_step_that_is_not_held_cannot_be_cited() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let error = crate::api::call(&mut workspace, &Caller::Mcp("claude-code".into()), "bytes.read", json!({"start": {"$anchor": {"step": 40, "path": "result.at"}}})).unwrap_err();
        assert!(error.message.contains("there is no step 40 in the journal"), "{}", error.message);
    }
}
