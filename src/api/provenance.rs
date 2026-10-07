//! Methods that edit where a step's values came from: turning a recorded
//! literal into an anchor or a named parameter, suggesting anchors, and
//! making the recipe with anchors, so a recipe made from the journal is
//! portable. Named in the `history` namespace.
//!
//! They change only the journal, which nothing in the document shows, so
//! their effect is `read`, and like other `history.*` reads they are not
//! steps themselves. A client that used an earlier result says so with
//! `history.make_anchor` after its call: calls carry no provenance in band
//! (see [`crate::journal::provenance`]).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ApiError;
use super::workspace::Workspace;
use crate::journal::provenance::{self, AnchorChange, LiteralSuggestions};
use crate::journal::recipe::{ParameterType, Recipe, RecipeParameter};
use crate::journal::Anchor;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("history.suggest_anchors", Read, suggest_anchors, SuggestParams, Suggestions, "Anchors that could stand for a step's literals in a recipe: search matches, structure fields and findings at the same offset in its document as it is now, the selection an earlier step set, and earlier steps' values equal to it, those that port to other files first."),
    method!("history.make_anchor", Read, make_anchor, MakeAnchorParams, AnchorChange, "Turn the literal at a path of a step's params into an anchor in its derived_from, so a recipe made from it finds the value when it runs; a read it cites becomes a step of the journal."),
    method!("history.make_parameter", Read, make_parameter, MakeParameterParams, MadeParameter, "Turn the literal at a path of a step's params into a named recipe parameter, the person's to supply when the recipe runs, the literal its default."),
    method!("history.clear_anchor", Read, clear_anchor, ClearAnchorParams, AnchorChange, "Clear the anchor at a path of a step's params, so a recipe made from it repeats the literal."),
    method!("history.recipe", Read, recipe, RecipeParams, crate::journal::Recipe, "A recipe of the journal's successful steps (or those chosen, with the steps they cite), each recorded provenance as an anchor, parameters declared, steps numbered from 1 and the recorded document left out."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        // Step 1, which the others edit: the document starts with a zlib stream.
        ("selection.set", json!({"selection": {"range": [0, 4]}})),
        ("history.suggest_anchors", json!({"step": 1})),
        ("history.make_anchor", json!({"step": 1, "path": "selection.range[0]", "anchor": {"find": {"hex": "789C"}, "nth": 0}})),
        ("history.make_parameter", json!({"step": 1, "path": "selection.range[1]", "name": "length", "description": "Bytes to select"})),
        ("history.clear_anchor", json!({"step": 1, "path": "selection.range[0]"})),
        ("history.recipe", json!({"name": "Select the header"})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

/// Parameters of `history.suggest_anchors`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SuggestParams {
    /// The step whose literals to anchor.
    pub step: u64,
    /// Only the literal at this path of its params, such as `start`; every
    /// integer when omitted.
    #[serde(default)]
    pub path: Option<String>,
}

/// The result of `history.suggest_anchors`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Suggestions {
    /// Each literal, with the anchors that give the same value.
    pub literals: Vec<LiteralSuggestions>,
}

/// Parameters of `history.make_anchor`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MakeAnchorParams {
    /// The step whose literal to anchor.
    pub step: u64,
    /// The literal's path in the step's params, such as `start` or
    /// `selection.range[0]`.
    pub path: String,
    /// The anchor, written bare: `{"find": {"hex": "7EA5"}, "nth": 0}`,
    /// `{"step": 12, "path": "result.at"}`, `{"param": "key"}`…
    pub anchor: Anchor,
}

/// Parameters of `history.make_parameter`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MakeParameterParams {
    /// The step whose literal to make a parameter.
    pub step: u64,
    /// The literal's path in the step's params.
    pub path: String,
    /// The parameter's name: letters, digits, spaces, '_' or '-'.
    pub name: String,
    /// What to supply, for the person running the recipe.
    #[serde(default)]
    pub description: Option<String>,
    /// "string", "integer", "number" or "boolean"; the literal's type when
    /// omitted.
    #[serde(default, rename = "type")]
    pub kind: Option<ParameterType>,
}

/// The result of `history.make_parameter`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MadeParameter {
    #[serde(flatten)]
    pub change: AnchorChange,
    /// The parameter as a recipe declares it.
    pub parameter: RecipeParameter,
}

/// Parameters of `history.clear_anchor`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClearAnchorParams {
    pub step: u64,
    /// The parameter's path in the step's params.
    pub path: String,
}

/// Parameters of `history.recipe`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeParams {
    /// The recipe's name.
    pub name: String,
    /// What it does, in the person's words.
    #[serde(default)]
    pub description: Option<String>,
    /// The steps to make it of (the earlier steps they cite are added);
    /// every step of the journal when omitted.
    #[serde(default)]
    pub steps: Option<Vec<u64>>,
}

pub fn suggest_anchors(workspace: &mut dyn Workspace, params: SuggestParams) -> Result<Suggestions, ApiError> {
    Ok(Suggestions { literals: provenance::suggest_anchors(workspace, params.step, params.path.as_deref())? })
}

pub fn make_anchor(workspace: &mut dyn Workspace, params: MakeAnchorParams) -> Result<AnchorChange, ApiError> {
    provenance::make_anchor(workspace, params.step, &params.path, params.anchor)
}

pub fn make_parameter(workspace: &mut dyn Workspace, params: MakeParameterParams) -> Result<MadeParameter, ApiError> {
    let (change, parameter) = provenance::make_parameter(workspace, params.step, &params.path, &params.name, params.description, params.kind)?;
    Ok(MadeParameter { change, parameter })
}

pub fn clear_anchor(workspace: &mut dyn Workspace, params: ClearAnchorParams) -> Result<AnchorChange, ApiError> {
    provenance::clear_anchor(workspace, params.step, &params.path)
}

pub fn recipe(workspace: &mut dyn Workspace, params: RecipeParams) -> Result<Recipe, ApiError> {
    let journal = workspace.journal();
    if let Some(missing) = params.steps.iter().flatten().find(|step| journal.entry(**step).is_none()) {
        return Err(ApiError::not_found(format!("there is no step {missing} in the journal; history.list shows the steps held")));
    }
    let mut recipe = Recipe::from_journal_with_anchors(&params.name, journal, params.steps.as_deref());
    recipe.description = params.description.unwrap_or_default();
    Ok(recipe)
}

#[cfg(test)]
pub(crate) mod tests;
