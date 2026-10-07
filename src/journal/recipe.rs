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
//! **Documents.** A recipe runs on one document, the run's (the one given,
//! or the current one). A step's `doc` that names the document it was
//! recorded on means the run's document: a step with no `doc`, with
//! `"current"`, or with the id the first step that names a document names
//! (such as `"doc-1"`, as recorded). Another id is kept as written; a
//! document an earlier step opened is best named by a step anchor, such as
//! `{"$anchor": {"step": 2, "path": "result.doc"}}`, which is found when the
//! recipe runs.
//!
//! **Parameters** are declared with a type (`string`, `integer`, `number`
//! or `boolean`), a description and an optional default. A value given as
//! text (as `theviewer replay --param key=value` gives it) is read as the
//! declared type; an integer may be written in decimal or as 0x hex.
//!
//! This module declares the file format, makes a literal recipe from
//! journal entries, and checks a recipe's parameters and whether it was
//! made for this API and these plugins. Running it is [`super::replay`]'s;
//! saving and loading it [`crate::recipes`]'s.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::anchors::{Anchor, anchors_in, parse_integer};
use super::{FileIdentity, JournalEntry, JournalSession, RecordedPlugin};
use crate::api::ApiError;

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
                recorded_on = entry.doc.as_deref().and_then(|doc| session.document(doc)).map(|document| document.file());
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

    /// Whether this build reads the recipe's format: a recipe written by a
    /// newer theviewer may mean things this one does not know.
    pub fn check_format(&self) -> Result<(), ApiError> {
        if self.recipe > RECIPE_FORMAT || self.recipe == 0 {
            return Err(ApiError::invalid_params(format!(
                "the recipe '{}' is in format {}, and this theviewer reads format {RECIPE_FORMAT}; update theviewer to run it",
                self.name, self.recipe
            )));
        }
        if self.name.trim().is_empty() {
            return Err(ApiError::invalid_params("a recipe needs a name"));
        }
        Ok(())
    }

    /// What to know before running the recipe with this API version and
    /// these plugins loaded: another major version of the API, a plugin
    /// it was recorded with that is missing or has changed since, and
    /// mistakes in the recipe itself (a step anchor naming a step that does
    /// not come before it, a parameter used but not declared, two steps
    /// with one number).
    pub fn warnings(&self, api_version: &str, loaded: &[RecordedPlugin]) -> Vec<String> {
        let mut warnings = Vec::new();
        if major_version(api_version) != self.api_version {
            warnings.push(format!("the recipe was recorded with API {}, and this is API {api_version}; some steps may not run the same", self.api_version));
        }
        for plugin in &self.plugins {
            match loaded.iter().find(|loaded| loaded.name == plugin.name) {
                None => warnings.push(format!("the plugin {} the recipe was recorded with is not loaded; steps that use it will fail", plugin.name)),
                Some(loaded) if loaded.sha256 != plugin.sha256 => warnings.push(format!("the plugin {} has changed since the recipe was recorded; its steps may give other results", plugin.name)),
                Some(_) => {}
            }
        }
        warnings.extend(self.mistakes());
        warnings
    }

    /// Mistakes in the recipe's own steps that will stop it when it runs.
    fn mistakes(&self) -> Vec<String> {
        let mut mistakes = Vec::new();
        let mut earlier: Vec<u64> = Vec::new();
        for step in &self.steps {
            if earlier.contains(&step.step) {
                mistakes.push(format!("two steps are numbered {}; step anchors naming it find the later", step.step));
            }
            for (path, anchor) in anchors_in(&step.params) {
                match anchor {
                    Anchor::Step { step: named, .. } if !earlier.contains(&named) => {
                        mistakes.push(format!("step {} ({}) takes {path} from step {named}, which does not come before it", step.step, step.method));
                    }
                    Anchor::Param { param } if !self.parameters.contains_key(&param) => {
                        mistakes.push(format!("step {} ({}) uses the parameter '{param}', which the recipe does not declare", step.step, step.method));
                    }
                    _ => {}
                }
            }
            earlier.push(step.step);
        }
        mistakes
    }

    /// The parameters' values to run with: those `given` (text read as the
    /// declared type), and the defaults of the rest. A declared parameter
    /// with no default must be given; a value for a parameter the recipe
    /// neither declares nor uses is refused, as it is most likely a typing
    /// mistake.
    pub fn parameter_values(&self, given: &BTreeMap<String, Value>) -> Result<BTreeMap<String, Value>, ApiError> {
        let used: Vec<String> = self
            .steps
            .iter()
            .flat_map(|step| anchors_in(&step.params))
            .filter_map(|(_, anchor)| match anchor {
                Anchor::Param { param } => Some(param),
                _ => None,
            })
            .collect();
        let mut values = BTreeMap::new();
        for (name, value) in given {
            match self.parameters.get(name) {
                Some(declared) => {
                    let value = declared.kind.read(value).map_err(|problem| ApiError::invalid_params(format!("the parameter '{name}' {problem}")))?;
                    values.insert(name.clone(), value);
                }
                None if used.contains(name) => {
                    values.insert(name.clone(), value.clone());
                }
                None => {
                    let declared: Vec<&str> = self.parameters.keys().map(String::as_str).collect();
                    let declared = if declared.is_empty() { "none".to_string() } else { declared.join(", ") };
                    return Err(ApiError::invalid_params(format!("the recipe '{}' has no parameter '{name}' (it has {declared})", self.name)));
                }
            }
        }
        for (name, declared) in &self.parameters {
            if values.contains_key(name) {
                continue;
            }
            match &declared.default {
                Some(default) => {
                    values.insert(name.clone(), default.clone());
                }
                None => {
                    let about = if declared.description.is_empty() { String::new() } else { format!(" ({})", declared.description) };
                    return Err(ApiError::invalid_params(format!("the recipe '{}' needs a value for its parameter '{name}'{about}", self.name)));
                }
            }
        }
        Ok(values)
    }
}

impl ParameterType {
    /// The type's name as a recipe writes it.
    pub fn name(self) -> &'static str {
        match self {
            ParameterType::String => "string",
            ParameterType::Integer => "integer",
            ParameterType::Number => "number",
            ParameterType::Boolean => "boolean",
        }
    }

    /// Whether `value` is already of this type.
    pub fn fits(self, value: &Value) -> bool {
        match self {
            ParameterType::String => value.is_string(),
            ParameterType::Integer => value.is_i64() || value.is_u64(),
            ParameterType::Number => value.is_number(),
            ParameterType::Boolean => value.is_boolean(),
        }
    }

    /// `value` as this type: as it is when it already is one, read from
    /// text when it is text; otherwise why not, as "is not an integer".
    pub fn read(self, value: &Value) -> Result<Value, String> {
        if self.fits(value) {
            return Ok(value.clone());
        }
        match value.as_str() {
            Some(text) => self.parse(text),
            None => Err(format!("is {value}, which is not {}", self.with_article())),
        }
    }

    /// `text` read as this type: an integer in decimal or 0x hex, a
    /// number, `true` or `false`, or the text itself.
    pub fn parse(self, text: &str) -> Result<Value, String> {
        let trimmed = text.trim();
        let parsed = match self {
            ParameterType::String => Some(Value::String(text.to_string())),
            ParameterType::Integer => parse_integer(trimmed).map(Value::Number),
            ParameterType::Number => trimmed.parse::<f64>().ok().and_then(serde_json::Number::from_f64).map(Value::Number),
            ParameterType::Boolean => match trimmed {
                "true" | "yes" | "1" => Some(Value::Bool(true)),
                "false" | "no" | "0" => Some(Value::Bool(false)),
                _ => None,
            },
        };
        parsed.ok_or_else(|| format!("is '{text}', which does not read as {}", self.with_article()))
    }

    fn with_article(self) -> &'static str {
        match self {
            ParameterType::String => "a string",
            ParameterType::Integer => "an integer",
            ParameterType::Number => "a number",
            ParameterType::Boolean => "true or false",
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
            documents: vec![RecordedDocument::new("doc-1", 0, FileIdentity { name: "flight-03.bin".into(), size: 1_048_576, sha256: Some("ab".repeat(32)) })],
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
