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
//! **Documents.** A recipe runs on one document, its input (the one given,
//! or the current one): a step with no `doc`, or with `"current"`, runs on
//! it. The sheets its steps make (`documents.derive`, `unpack.open`…) are
//! named by sheet anchors, `{"$anchor": {"sheet": {"step": 2}}}` for the
//! sheet step 2 made, `{"sheet": "payload"}` for the one a step labelled
//! with `makes`, and `{"sheet": "input"}` for the input. A literal id names
//! a document of the run as it is; one the run neither runs on nor made
//! stops it, rather than running the step on the input.
//!
//! **Format 2** adds what format 1 cannot say: a step's `makes` label and
//! its `expect` (what it must give for the run to go on), the recipe's
//! `inputs`, and the anchors format 1 does not have (sheet, pick,
//! then and var) or a parameter whose default is an anchor. A recipe is
//! written as format 1 unless it uses one of them, so older builds still
//! run what they can; this build reads both.
//!
//! **Variables.** A `vars.set` step binds a value, often found by an anchor
//! (`{"pick": …}`), and later steps read it with `{"var": name}`, so a value
//! found once is used wherever it is needed and found again on each file.
//!
//! **Parameters** are declared with a type (`string`, `integer`, `number`
//! or `boolean`), a description and an optional default: a literal, or an
//! anchor that finds it (`default_anchor`), used when no value is given. A
//! value given as text (as `theviewer replay --param key=value` gives it)
//! is read as the declared type; an integer may be written in decimal or as
//! 0x hex.
//!
//! This module declares the file format, makes a literal recipe from
//! journal entries, and checks a recipe's parameters and whether it was
//! made for this API and these plugins. Running it is [`super::replay`]'s;
//! saving and loading it [`crate::recipes`]'s.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::anchors::{Anchor, INPUT, SheetRef, StepRef, anchors_in, marked, parse_integer};
use super::{FileIdentity, JournalEntry, JournalSession, RecordedPlugin};
use crate::api::ApiError;

/// The newest recipe format this build reads and writes.
pub const RECIPE_FORMAT: u32 = 2;

/// The format of a recipe that needs nothing format 2 added.
pub const FIRST_FORMAT: u32 = 1;

/// What recipe files are called: `Telemetry frames.theviewer-recipe.json`.
pub const RECIPE_EXTENSION: &str = ".theviewer-recipe.json";

/// A saved analysis, to run on other files.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Recipe {
    /// The recipe format: 1, or 2 for a recipe with sheet anchors, `makes`
    /// labels or `inputs`.
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
    /// The file it was recorded on, to say when another is the same (in
    /// format 2, `inputs.input.recorded_on`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_on: Option<FileIdentity>,
    /// The documents it runs on, by name, in format 2: `input` is the one
    /// given when it runs, which `{"sheet": "input"}` names.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inputs: BTreeMap<String, RecipeInput>,
    /// The plugins loaded when it was recorded; running it warns when one
    /// is missing or has changed.
    #[serde(default)]
    pub plugins: Vec<RecordedPlugin>,
    pub steps: Vec<RecipeStep>,
}

/// A document a recipe runs on.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RecipeInput {
    /// The file it was recorded on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_on: Option<FileIdentity>,
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
    /// An anchor that finds the value when none is given, in place of
    /// `default`, which then says what it found when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_anchor: Option<Anchor>,
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
    /// The label of the sheet the step makes, which `{"sheet": label}`
    /// anchors name (format 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub makes: Option<String>,
    /// What the step must give for the run to go on, such as a non-empty
    /// `result.codecs` (format 2): a run on a file where it does not stops
    /// there, saying so, rather than carrying on with nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<StepExpectation>,
}

impl RecipeStep {
    /// Step `step`, a call of `method` with `params`, with no note, label
    /// or expectation.
    pub fn new(step: u64, method: impl Into<String>, params: Value) -> Self {
        RecipeStep { step, method: method.into(), params, note: None, makes: None, expect: None }
    }
}

/// A check of what a recipe's step gave: the value at `path` must be there
/// and not empty, and, with `matches`, match it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepExpectation {
    /// Where the value is in the step's `{"params", "result", "job"}`, as a
    /// step anchor's path is written: `result.codecs`, `job.strings`.
    pub path: String,
    /// A regular expression the value must match: text as it is, a number
    /// or true/false as written, anything else as JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches: Option<String>,
}

impl StepExpectation {
    /// Whether `done`, a step as `{"params", "result", "job"?}`, gives what
    /// is expected; if not, why not, as "result.codecs is empty".
    pub fn check(&self, done: &Value) -> Result<(), String> {
        let value = super::anchors::value_at(done, &self.path).map_err(|error| error.message)?;
        let value = match value {
            None | Some(Value::Null) => return Err(format!("there is nothing at {}", self.path)),
            Some(value) if is_empty(value) => return Err(format!("{} is empty ({value})", self.path)),
            Some(value) => value,
        };
        let Some(pattern) = &self.matches else { return Ok(()) };
        let regex = regex_lite::Regex::new(pattern).map_err(|error| format!("its pattern /{pattern}/ is not a regular expression: {error}"))?;
        let text = match value {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        if regex.is_match(&text) {
            return Ok(());
        }
        Err(format!("{} is {}, which does not match /{pattern}/", self.path, crate::text::truncate_chars(&value.to_string(), 80)))
    }
}

/// Whether `value` is empty text, an empty list or an empty object.
fn is_empty(value: &Value) -> bool {
    match value {
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(fields) => fields.is_empty(),
        _ => false,
    }
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
            steps.push(RecipeStep::new(entry.step, entry.method.clone(), entry.params.clone()));
        }
        steps.sort_by_key(|step| step.step);
        Recipe {
            recipe: FIRST_FORMAT,
            api_version: major_version(&session.api_version),
            name: name.to_string(),
            description: String::new(),
            parameters: BTreeMap::new(),
            recorded_on,
            inputs: BTreeMap::new(),
            plugins: session.plugins.clone(),
            steps,
        }
    }

    /// The file the recipe's input was recorded on: `recorded_on`, or in
    /// format 2 `inputs.input.recorded_on`.
    pub fn input_recorded_on(&self) -> Option<&FileIdentity> {
        self.recorded_on.as_ref().or_else(|| self.inputs.get(INPUT).and_then(|input| input.recorded_on.as_ref()))
    }

    /// Whether the recipe says anything only format 2 can: a sheet, pick,
    /// then or var anchor, a parameter whose default is an anchor, a step's
    /// `makes` or `expect`, or `inputs`.
    pub fn needs_second_format(&self) -> bool {
        let new_anchor = self.steps.iter().flat_map(|step| anchors_in(&step.params)).any(|(_, anchor)| anchor.needs_second_format());
        let anchored_default = self.parameters.values().any(|parameter| parameter.default_anchor.is_some());
        let new_step_field = self.steps.iter().any(|step| step.makes.is_some() || step.expect.is_some());
        new_anchor || anchored_default || !self.inputs.is_empty() || new_step_field
    }

    /// Write the recipe in the oldest format that says all it holds: format
    /// 2 (its file named under `inputs`) when it needs it, otherwise 1.
    pub fn settle_format(&mut self) {
        if !self.needs_second_format() {
            self.recipe = FIRST_FORMAT;
            return;
        }
        self.recipe = RECIPE_FORMAT;
        if let Some(recorded_on) = self.recorded_on.take() {
            self.inputs.entry(INPUT.to_string()).or_default().recorded_on = Some(recorded_on);
        }
    }

    /// Whether this build reads the recipe's format: a recipe written by a
    /// newer theviewer may mean things this one does not know.
    pub fn check_format(&self) -> Result<(), ApiError> {
        if self.recipe > RECIPE_FORMAT || self.recipe == 0 {
            return Err(ApiError::invalid_params(format!(
                "the recipe '{}' is in format {}, and this theviewer reads formats up to {RECIPE_FORMAT}; update theviewer to run it",
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
        let mut labels: Vec<String> = Vec::new();
        let mut bound: Vec<String> = Vec::new();
        for step in &self.steps {
            if earlier.contains(&step.step) {
                mistakes.push(format!("two steps are numbered {}; step anchors naming it find the later", step.step));
            }
            for (path, anchor) in anchors_in(&step.params).into_iter().flat_map(|(path, anchor)| inside(&anchor).into_iter().map(move |inner| (path.clone(), inner))) {
                match anchor {
                    Anchor::Pick { pick } => match &pick.step {
                        StepRef::Number(named) if !earlier.contains(named) => {
                            mistakes.push(format!("step {} ({}) picks {path} from step {named}, which does not come before it", step.step, step.method));
                        }
                        StepRef::Label(label) if !labels.iter().any(|known| Some(known.as_str()) == label.strip_prefix('@')) => {
                            mistakes.push(format!("step {} ({}) picks {path} from the step that made {label}, which no earlier step makes", step.step, step.method));
                        }
                        _ => {}
                    },
                    Anchor::Var { var } if !bound.contains(&var) => {
                        mistakes.push(format!("step {} ({}) reads ${var} at {path}, which no earlier step binds with vars.set", step.step, step.method));
                    }
                    Anchor::Step { step: named, .. } if !earlier.contains(&named) => {
                        mistakes.push(format!("step {} ({}) takes {path} from step {named}, which does not come before it", step.step, step.method));
                    }
                    Anchor::Param { param } if !self.parameters.contains_key(&param) => {
                        mistakes.push(format!("step {} ({}) uses the parameter '{param}', which the recipe does not declare", step.step, step.method));
                    }
                    Anchor::Sheet { sheet: SheetRef::Step { step: named, .. } | SheetRef::Labelled { step: named, .. } } if !earlier.contains(&named) => {
                        mistakes.push(format!("step {} ({}) takes {path} from the sheet step {named} made, which does not come before it", step.step, step.method));
                    }
                    Anchor::Sheet { sheet: SheetRef::Named(label) } if label != INPUT && !labels.contains(&label) => {
                        mistakes.push(format!("step {} ({}) takes {path} from the sheet labelled {label}, which no earlier step makes", step.step, step.method));
                    }
                    _ => {}
                }
            }
            earlier.push(step.step);
            labels.extend(step.makes.clone());
            if step.method == "vars.set"
                && let Some(name) = step.params.get("name").and_then(Value::as_str)
            {
                bound.push(name.to_string());
            }
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
            match (&declared.default_anchor, &declared.default) {
                // Found when the step that uses it runs.
                (Some(anchor), _) => {
                    values.insert(name.clone(), marked(anchor));
                }
                (None, Some(default)) => {
                    values.insert(name.clone(), default.clone());
                }
                (None, None) => {
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

/// `anchor` and every anchor inside it, outermost first: a then anchor's
/// value comes from the anchor it transforms.
fn inside(anchor: &Anchor) -> Vec<Anchor> {
    let mut all = vec![anchor.clone()];
    if let Anchor::Then { of, .. } = anchor {
        all.extend(inside(of));
    }
    all
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
            note: None,
            notes: Vec::new(),
            made: Vec::new(),
            evidence: false,
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
    fn a_recipe_is_written_as_format_one_unless_it_names_sheets() {
        let mut plain = Recipe::from_journal("Patch", &session(), &[entry(2, "bytes.write", json!({"start": 2, "data": "41"}), Outcome::Ok)]);
        plain.settle_format();
        assert_eq!((plain.recipe, plain.inputs.len()), (1, 0), "nothing format 2 adds");
        assert!(plain.recorded_on.is_some());

        let mut derived = plain.clone();
        derived.steps.push(RecipeStep { makes: Some("payload".into()), ..RecipeStep::new(3, "documents.derive", json!({"start": 4})) });
        derived.steps.push(RecipeStep::new(4, "bytes.write", json!({"doc": {"$anchor": {"sheet": "payload"}}, "start": 0, "data": "00"})));
        derived.settle_format();
        assert_eq!(derived.recipe, 2);
        assert_eq!(derived.recorded_on, None, "format 2 names the file under inputs");
        assert_eq!(derived.input_recorded_on().map(|file| file.name.as_str()), Some("flight-03.bin"));
        let written = serde_json::to_value(&derived).unwrap();
        assert_eq!(written["inputs"]["input"]["recorded_on"]["name"], "flight-03.bin");
        assert_eq!(written["steps"][1]["makes"], "payload");
        let read: Recipe = serde_json::from_value(written).unwrap();
        assert!(read.check_format().is_ok(), "this build reads format 2");
        assert!(read.warnings("1.0", &session().plugins).is_empty(), "{:?}", read.warnings("1.0", &session().plugins));
    }

    #[test]
    fn a_sheet_anchor_naming_a_later_step_or_an_unknown_label_is_a_mistake_the_recipe_warns_of() {
        let mut recipe = Recipe::from_journal("Sheets", &session(), &[]);
        recipe.steps = vec![
            RecipeStep::new(1, "bytes.write", json!({"doc": {"$anchor": {"sheet": {"step": 2}}}, "start": 0, "data": "00"})),
            RecipeStep { makes: Some("payload".into()), ..RecipeStep::new(2, "documents.derive", json!({"start": 4})) },
            RecipeStep::new(3, "bytes.write", json!({"doc": {"$anchor": {"sheet": "rootfs"}}, "start": 0, "data": "00"})),
        ];
        let warnings = recipe.warnings("1.0", &session().plugins);
        assert!(warnings.iter().any(|warning| warning.contains("step 1 (bytes.write) takes doc from the sheet step 2 made, which does not come before it")), "{warnings:?}");
        assert!(warnings.iter().any(|warning| warning.contains("step 3 (bytes.write) takes doc from the sheet labelled rootfs, which no earlier step makes")), "{warnings:?}");
    }

    #[test]
    fn a_variable_or_pick_the_recipe_cannot_find_is_a_mistake_it_warns_of() {
        let mut recipe = Recipe::from_journal("Serial", &session(), &[]);
        recipe.steps = vec![
            RecipeStep::new(1, "transform.apply", json!({"operation": {"op": "xor", "key": {"$anchor": {"of": {"var": "serial"}, "then": [{"encode": "text_to_hex"}]}}}})),
            RecipeStep::new(2, "strings.find", json!({})),
            RecipeStep::new(3, "vars.set", json!({"name": "serial", "value": {"$anchor": {"pick": {"step": 4, "list": "job.strings"}}}})),
        ];
        let warnings = recipe.warnings("1.0", &session().plugins);
        assert!(warnings.iter().any(|warning| warning.contains("step 1 (transform.apply) reads $serial at operation.key, which no earlier step binds with vars.set")), "{warnings:?}");
        assert!(warnings.iter().any(|warning| warning.contains("step 3 (vars.set) picks value from step 4, which does not come before it")), "{warnings:?}");
        recipe.settle_format();
        assert_eq!(recipe.recipe, 2, "pick, then and var anchors are format 2");
    }

    #[test]
    fn a_parameter_whose_default_is_an_anchor_is_found_unless_given() {
        let mut recipe = Recipe::from_journal("Serial", &session(), &[]);
        let pick = json!({"pick": {"step": 2, "list": "job.strings", "field": "text"}});
        recipe.parameters.insert(
            "serial".into(),
            RecipeParameter { kind: ParameterType::String, description: "The unit's serial".into(), default: Some(json!("NC500-2F357657")), default_anchor: Some(serde_json::from_value(pick.clone()).unwrap()) },
        );
        let found = recipe.parameter_values(&BTreeMap::new()).unwrap();
        assert_eq!(found["serial"], json!({"$anchor": pick}), "left to the anchor, which the step resolves");
        let given = recipe.parameter_values(&BTreeMap::from([("serial".to_string(), json!("NC500-00000000"))])).unwrap();
        assert_eq!(given["serial"], "NC500-00000000");
        recipe.settle_format();
        assert_eq!(recipe.recipe, 2);
    }

    #[test]
    fn the_recipe_schema_names_every_field_of_the_file() {
        let schema = schemars::schema_for!(Recipe).to_value();
        for field in ["recipe", "api_version", "name", "description", "parameters", "recorded_on", "plugins", "steps"] {
            assert!(schema["properties"][field].is_object(), "{field} is in the schema");
        }
    }
}
