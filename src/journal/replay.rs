//! Running recorded steps again: a recipe on another file, "go back to step
//! N", and playback one step at a time.
//!
//! Every way of running steps goes through here: the History tab (area A)
//! for "go back to step N" and playback, and the recipe runner, `theviewer
//! replay` and `recipes.run` (area B). Each step is called through
//! [`crate::api::call`] as `options.caller`, so it is journalled and checked
//! like any other call, after its anchors are resolved.
//!
//! The signatures are the foundation's; area B implements them (see
//! `docs/design/history-recipes.md`). Until then every run stops at its
//! first step as `unavailable`.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Outcome;
use super::anchors::Anchor;
use super::recipe::RecipeStep;
use crate::api::{ApiError, Caller, ErrorCode, Workspace};

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
    /// Wait for the jobs steps start before running the next step.
    pub await_jobs: bool,
}

impl ReplayOptions {
    /// Options to run every step as `caller` on the current document,
    /// waiting for jobs.
    pub fn new(caller: Caller) -> Self {
        ReplayOptions { caller, parameters: BTreeMap::new(), doc: None, through_step: None, preview: false, await_jobs: true }
    }
}

/// An anchor of a step and what it resolved to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedAnchor {
    /// The parameter's path in the step's params, such as `start`.
    pub path: String,
    pub anchor: Anchor,
    pub value: Value,
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
    /// The journal step the call was recorded as in this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_step: Option<u64>,
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
}

/// Run `steps` in order on `workspace` as `options` say, resolving each
/// step's anchors first and stopping at the first failure. Area B
/// implements this; for now it stops at the first step.
pub fn run(_workspace: &mut dyn Workspace, steps: &[RecipeStep], _options: &ReplayOptions) -> RunReport {
    let Some(first) = steps.first() else { return RunReport::default() };
    RunReport {
        steps: Vec::new(),
        stopped: Some(Stopped { step: first.step, error: ApiError::new(ErrorCode::Unavailable, "steps cannot be run again yet: the recipe runner is not built") }),
        warnings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_report_of_a_run_that_stopped_says_which_step_and_why() {
        let report = RunReport {
            steps: vec![StepReport {
                step: 1,
                method: "bytes.write".into(),
                params: json!({"start": 4, "data": "00"}),
                description: "Overwrite 1 byte at 0x4 with 00".into(),
                anchors: vec![ResolvedAnchor { path: "start".into(), anchor: Anchor::Param { param: "at".into() }, value: json!(4) }],
                outcome: Outcome::Ok,
                result: Some(json!({"label": "Overwrite 1 byte"})),
                journal_step: Some(7),
            }],
            stopped: Some(Stopped { step: 2, error: ApiError::out_of_range("past the end") }),
            warnings: vec!["acme_telemetry.lua has changed since the recipe was recorded".into()],
        };
        let written = serde_json::to_value(&report).unwrap();
        assert_eq!(written["stopped"]["error"]["code"], "out_of_range");
        assert_eq!(written["steps"][0]["outcome"], "ok");
        assert_eq!(serde_json::from_value::<RunReport>(written).unwrap(), report);
        assert!(!report.completed());
    }

    #[test]
    fn until_the_runner_is_built_a_run_stops_at_its_first_step() {
        let mut workspace = crate::api::test_support::workspace_with("a.bin", b"abc");
        let steps = [RecipeStep { step: 3, method: "bytes.write".into(), params: json!({"start": 0, "data": "00"}), note: None }];
        let report = run(&mut workspace, &steps, &ReplayOptions::new(Caller::Recipe("test".into())));
        assert_eq!(report.stopped.map(|stopped| (stopped.step, stopped.error.code)), Some((3, ErrorCode::Unavailable)));
        assert!(run(&mut workspace, &[], &ReplayOptions::new(Caller::Panel)).completed(), "nothing to run is done at once");
    }
}
