//! Recipes: a saved journal, applied to other files.
//!
//! A recipe is a file, `*.theviewer-recipe.json`:
//!
//! ```json
//! {
//!   "recipe": 1,
//!   "api_version": "1.x",
//!   "name": "Telemetry frames",
//!   "description": "Split the capture after the header and decode the frames",
//!   "parameters": { "key": { "type": "string", "description": "XOR key, hex" } },
//!   "recorded_on": { "name": "flight-03.bin", "size": 1048576, "sha256": "…" },
//!   "plugins": [ { "name": "acme_telemetry.lua", "sha256": "…" } ],
//!   "steps": [ { "step": 1, "method": "search.find", "params": { "pattern": "7EA5" }, "note": "…" } ]
//! }
//! ```
//!
//! A step's `params` are literals, except where a value is marked
//! `{"$anchor": …}` (see [`super::anchors`]). Each step keeps the number it
//! was recorded as, which later steps' step anchors name.
//!
//! This module declares the file format and makes a literal recipe from
//! journal entries. Capturing anchors is area C's; running, saving and
//! loading recipes area B's (see `docs/design/history-recipes.md`).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{FileIdentity, JournalEntry, JournalSession, RecordedPlugin};

/// The recipe format this build writes and reads.
pub const RECIPE_FORMAT: u32 = 1;

/// What recipe files are called: `Telemetry frames.theviewer-recipe.json`.
pub const RECIPE_EXTENSION: &str = ".theviewer-recipe.json";

/// A saved analysis, to run on other files.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Recipe {
    /// The recipe format, 1.
    pub recipe: u32,
    /// The API version the steps were recorded against, by major version:
    /// "1.x".
    pub api_version: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Values the person supplies when running it, by name, which
    /// `{"param": name}` anchors stand for.
    #[serde(default)]
    pub parameters: BTreeMap<String, RecipeParameter>,
    /// The file it was recorded on, to say when another is the same.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_on: Option<FileIdentity>,
    /// The plugins loaded when it was recorded; running it warns when one
    /// is missing or has changed.
    #[serde(default)]
    pub plugins: Vec<RecordedPlugin>,
    pub steps: Vec<RecipeStep>,
}

/// A value a recipe asks for when it runs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RecipeParameter {
    #[serde(rename = "type")]
    pub kind: ParameterType,
    #[serde(default)]
    pub description: String,
    /// The value used when none is given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
}

/// The JSON type of a recipe parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    String,
    Integer,
    Number,
    Boolean,
}

/// One call of a recipe.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RecipeStep {
    /// The step's number: the journal step it was recorded as, or its
    /// place in a recipe written by hand. Step anchors name it.
    pub step: u64,
    /// The method to call, such as `packets.sets.create`.
    pub method: String,
    /// Its parameters: literals, and anchors marked `{"$anchor": …}`.
    #[serde(default)]
    pub params: Value,
    /// What the step is for, in the person's words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Recipe {
    /// A recipe called `name` of the successful calls in `entries`, in step
    /// order, each with its parameters as recorded (literals: anchors are
    /// added from the entries' `derived_from` by area C). It names the API
    /// version and plugins of `session`, and the file the first step was
    /// about, as the session first saw it.
    pub fn from_journal<'a>(name: &str, session: &JournalSession, entries: impl IntoIterator<Item = &'a JournalEntry>) -> Recipe {
        let mut recorded_on = None;
        let mut steps = Vec::new();
        for entry in entries.into_iter().filter(|entry| entry.outcome.is_ok()) {
            if recorded_on.is_none() {
                recorded_on = entry.doc.as_deref().and_then(|doc| session.document(doc)).map(|document| document.file.clone());
            }
            steps.push(RecipeStep { step: entry.step, method: entry.method.clone(), params: entry.params.clone(), note: None });
        }
        steps.sort_by_key(|step| step.step);
        Recipe {
            recipe: RECIPE_FORMAT,
            api_version: major_version(&session.api_version),
            name: name.to_string(),
            description: String::new(),
            parameters: BTreeMap::new(),
            recorded_on,
            plugins: session.plugins.clone(),
            steps,
        }
    }
}

/// "1.x" for "1.0": a recipe runs on any API of the same major version.
fn major_version(version: &str) -> String {
    let major = version.split('.').next().unwrap_or(version);
    format!("{major}.x")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::journal::{Outcome, RecordedDocument};

    fn entry(step: u64, method: &str, params: Value, outcome: Outcome) -> JournalEntry {
        JournalEntry {
            step,
            at: "2026-10-06T14:02:11Z".into(),
            caller: "panel".into(),
            method: method.into(),
            effect: crate::api::Effect::Edit,
            description: String::new(),
            params,
            params_summarised: false,
            doc: Some("doc-1".into()),
            version_before: Some(0),
            version_after: Some(1),
            outcome,
            result: None,
            result_summarised: false,
            derived_from: Default::default(),
            merged: 0,
            before: None,
        }
    }

    fn session() -> JournalSession {
        JournalSession {
            started_at: "2026-10-06T14:00:00Z".into(),
            api_version: "1.0".into(),
            documents: vec![RecordedDocument { id: "doc-1".into(), version: 0, file: FileIdentity { name: "flight-03.bin".into(), size: 1_048_576, sha256: Some("ab".repeat(32)) } }],
            plugins: vec![RecordedPlugin { name: "acme_telemetry.lua".into(), sha256: "cd".repeat(32) }],
        }
    }

    #[test]
    fn a_recipe_from_the_journal_repeats_the_successful_steps_as_recorded() {
        let failed = Outcome::Error(crate::api::ApiError::out_of_range("past the end"));
        let entries = [
            entry(2, "bytes.write", json!({"start": 2, "data": "4142"}), Outcome::Ok),
            entry(3, "bytes.write", json!({"start": 900, "data": "00"}), failed),
            entry(5, "transform.apply", json!({"selection": {"range": [0, 4]}, "operation": {"op": "invert"}}), Outcome::Ok),
        ];
        let recipe = Recipe::from_journal("Patch header", &session(), &entries);
        assert_eq!((recipe.recipe, recipe.api_version.as_str(), recipe.name.as_str()), (1, "1.x", "Patch header"));
        assert_eq!(recipe.recorded_on.as_ref().map(|file| file.name.as_str()), Some("flight-03.bin"));
        assert_eq!(recipe.plugins, session().plugins);
        let steps: Vec<(u64, &str)> = recipe.steps.iter().map(|step| (step.step, step.method.as_str())).collect();
        assert_eq!(steps, [(2, "bytes.write"), (5, "transform.apply")], "the failed step is left out; numbers are kept for step anchors");
        assert_eq!(recipe.steps[0].params, json!({"start": 2, "data": "4142"}));
    }

    #[test]
    fn a_recipe_file_reads_back_as_written_and_matches_the_design_s_example() {
        let written = json!({
            "recipe": 1,
            "api_version": "1.x",
            "name": "Telemetry frames",
            "description": "Split the capture after the header and decode the frames",
            "parameters": {"key": {"type": "string", "description": "XOR key, hex"}},
            "recorded_on": {"name": "flight-03.bin", "size": 1048576, "sha256": "ab"},
            "plugins": [{"name": "acme_telemetry.lua", "sha256": "cd"}],
            "steps": [
                {"step": 1, "method": "transform.apply", "params": {"selection": {"range": [0, 4]}, "operation": {"op": "xor", "key": {"$anchor": {"param": "key"}}}}, "note": "Unmask"},
                {"step": 2, "method": "packets.sets.create", "params": {"from": "split_fixed", "record_len": 12}}
            ]
        });
        let recipe: Recipe = serde_json::from_value(written.clone()).unwrap();
        assert_eq!(recipe.parameters["key"].kind, ParameterType::String);
        assert_eq!(crate::journal::anchors::anchors_in(&recipe.steps[0].params).len(), 1);
        assert_eq!(serde_json::to_value(&recipe).unwrap(), written);
    }

    #[test]
    fn the_recipe_schema_names_every_field_of_the_file() {
        let schema = schemars::schema_for!(Recipe).to_value();
        for field in ["recipe", "api_version", "name", "description", "parameters", "recorded_on", "plugins", "steps"] {
            assert!(schema["properties"][field].is_object(), "{field} is in the schema");
        }
    }
}
