//! `recipes.*`: saved analyses, listed, described, saved, previewed and run
//! on a document.
//!
//! A recipe is named by `name` (one saved in `~/.config/theviewer/recipes/`),
//! by `path` (a `*.theviewer-recipe.json` file anywhere) or given whole as
//! `recipe`. See [`crate::journal::recipe`] for the format and
//! [`crate::journal::replay`] for how a run goes.
//!
//! **Permissions.** `recipes.run` is an edit, so it is checked against its
//! caller's policy like any edit: the person's own calls run at once; Ask,
//! MCP clients and plugins are allowed, asked about (the confirmation lists
//! the recipe's steps) or refused as Settings › Permissions says. Its steps
//! are called as `recipe:NAME`, so their edits are labelled "… by
//! recipe:NAME". Who may do what is decided by who started the run, never
//! by a parameter:
//!
//! * started by the person (the window's Run, after its preview), or by a
//!   client whose run the person has just allowed in the confirmation
//!   window, the run is consented to and its steps are not asked about
//!   again;
//! * started by a client its policy allows, each step is still checked
//!   against that client's policy, so a recipe can do no more than its
//!   caller may.
//!
//! `recipes.save`, `recipes.list`, `recipes.describe` and `recipes.preview`
//! change nothing in a document, so they are reads.

use std::collections::BTreeMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::permissions::{Caller, Consent};
use super::values::NoParams;
use super::workspace::Workspace;
use super::ApiError;
use crate::journal::Recipe;
use crate::journal::provenance;
use crate::journal::replay::{self, ReplayOptions, RunReport};
use crate::recipes::{self, RecipeSummary};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("recipes.list", Read, list, NoParams, ListResult, "The recipes saved in ~/.config/theviewer/recipes/: each one's name, description, steps and the parameters it asks for."),
    method!("recipes.describe", Read, describe, DescribeParams, DescribeResult, "One recipe in full, by name or path, with what to know before running it here: another API version, a plugin missing or changed, a method this build lacks, or mistakes in its anchors."),
    method!("recipes.save", Read, save, SaveParams, SaveResult, "Save a recipe in ~/.config/theviewer/recipes/, given whole or made from steps of this session's journal, to run later on other files.").writes_file(crate::api::WritesFile::Always),
    method!("recipes.preview", Read, preview, RunParams, RunReport, "What a recipe would do to a document, without changing anything: each step described with its anchors resolved on this file, and where the run would stop."),
    method!("recipes.run", Edit, consent run, RunParams, RunReport, "Run a recipe on a document, each step called as recipe:NAME with its anchors resolved on this file, waiting for the jobs steps start; its edits undo as one step, and the first failure stops it with which step and why."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, Value)> {
    use serde_json::json;
    let recipe = json!({
        "recipe": 1,
        "api_version": "1.x",
        "name": "Example recipe",
        "description": "Mark the first fox",
        "parameters": {"letter": {"type": "string", "description": "What to write over it, hex", "default": "46"}},
        "steps": [
            {"step": 1, "method": "search.find", "params": {"query": "fox"}},
            {"step": 2, "method": "bytes.write", "params": {"start": {"$anchor": {"step": 1, "path": "result.at"}}, "data": {"$anchor": {"param": "letter"}}}}
        ]
    });
    vec![
        ("recipes.save", json!({"recipe": recipe, "overwrite": true})),
        ("recipes.list", json!({})),
        ("recipes.describe", json!({"name": "Example recipe"})),
        ("recipes.preview", json!({"name": "Example recipe", "parameters": {"letter": "66"}})),
        ("recipes.run", json!({"name": "Example recipe"})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, params: &Value) -> Option<String> {
    if method != "recipes.run" {
        return None;
    }
    let params: RunParams = serde_json::from_value(params.clone()).ok()?;
    let doc = params.doc.clone().unwrap_or_else(|| "the current document".to_string());
    let Ok((recipe, _)) = chosen(params.name, params.path, params.recipe) else { return Some(format!("Run a recipe on {doc}")) };
    let methods: Vec<&str> = recipe.steps.iter().map(|step| step.method.as_str()).collect();
    let steps = recipe.steps.len();
    Some(format!("Run the recipe '{}' on {doc}: {steps} step{} ({})", recipe.name, if steps == 1 { "" } else { "s" }, methods.join(", ")))
}

/// The result of `recipes.list`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ListResult {
    /// The folder recipes are kept in.
    pub dir: String,
    /// The recipes saved there, by name.
    pub recipes: Vec<RecipeSummary>,
}

/// Parameters of `recipes.describe`. Give the recipe's `name` or `path`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescribeParams {
    /// A saved recipe's name, as recipes.list gives it.
    #[serde(default)]
    pub name: Option<String>,
    /// A recipe file's path.
    #[serde(default)]
    pub path: Option<String>,
}

/// The result of `recipes.describe`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DescribeResult {
    pub recipe: Recipe,
    /// Its file.
    pub path: Option<String>,
    /// What to know before running it here.
    pub warnings: Vec<String>,
}

/// Parameters of `recipes.save`. Give the recipe whole as `recipe`, or the
/// journal steps to make it of as `journal_steps` with a `name`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveParams {
    /// The recipe, as a *.theviewer-recipe.json file holds it.
    #[serde(default)]
    pub recipe: Option<Recipe>,
    /// The recipe's name (in place of the recipe's own, when one is given).
    #[serde(default)]
    pub name: Option<String>,
    /// What it is for (in place of the recipe's own, when one is given).
    #[serde(default)]
    pub description: Option<String>,
    /// Steps of this session's journal (history.list gives them) to make
    /// the recipe of, as recorded; the failed ones are left out.
    #[serde(default)]
    pub journal_steps: Option<Vec<u64>>,
    /// Replace a recipe saved under the same name.
    #[serde(default)]
    pub overwrite: bool,
}

/// The result of `recipes.save`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SaveResult {
    pub name: String,
    /// The file it was saved as.
    pub path: String,
    /// How many steps it has.
    pub steps: usize,
    /// What to know before running it.
    pub warnings: Vec<String>,
}

/// Parameters of `recipes.preview` and `recipes.run`. Give the recipe's
/// `name` or `path`, or the recipe whole.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunParams {
    /// A saved recipe's name, as recipes.list gives it.
    #[serde(default)]
    pub name: Option<String>,
    /// A recipe file's path.
    #[serde(default)]
    pub path: Option<String>,
    /// The recipe itself.
    #[serde(default)]
    pub recipe: Option<Recipe>,
    /// Document id, path or "current" (the default) to run it on.
    #[serde(default)]
    pub doc: Option<String>,
    /// Values for the recipe's parameters, by name; text is read as the
    /// parameter's type. Those left out take their defaults.
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
    /// Stop after the step with this number.
    #[serde(default)]
    pub through_step: Option<u64>,
}

/// The recipe named by `name`, `path` or given whole, with its file.
fn chosen(name: Option<String>, path: Option<String>, recipe: Option<Recipe>) -> Result<(Recipe, Option<PathBuf>), ApiError> {
    match (name, path, recipe) {
        (None, None, Some(recipe)) => {
            recipe.check_format()?;
            Ok((recipe, None))
        }
        (Some(name), None, None) => recipes::find(&recipes::recipes_dir()?, &name).map(|(recipe, path)| (recipe, Some(path))),
        (None, Some(path), None) => {
            let path = PathBuf::from(path);
            recipes::load(&path).map(|recipe| (recipe, Some(path)))
        }
        _ => Err(ApiError::invalid_params("give one of name (a saved recipe), path (a recipe file) or recipe (the recipe itself)")),
    }
}

pub fn list(_workspace: &mut dyn Workspace, _params: NoParams) -> Result<ListResult, ApiError> {
    let dir = recipes::recipes_dir()?;
    Ok(ListResult { recipes: recipes::list(&dir), dir: dir.display().to_string() })
}

pub fn describe(workspace: &mut dyn Workspace, params: DescribeParams) -> Result<DescribeResult, ApiError> {
    let (recipe, path) = chosen(params.name, params.path, None)?;
    let warnings = recipes::warnings(workspace, &recipe);
    Ok(DescribeResult { recipe, path: path.map(|path| path.display().to_string()), warnings })
}

pub fn save(workspace: &mut dyn Workspace, params: SaveParams) -> Result<SaveResult, ApiError> {
    let mut recipe = match (params.recipe, params.journal_steps) {
        (Some(recipe), None) => recipe,
        (None, Some(steps)) => from_journal(workspace, params.name.as_deref(), &steps)?,
        _ => return Err(ApiError::invalid_params("give the recipe whole as recipe, or the journal steps to make it of as journal_steps, with a name")),
    };
    if let Some(name) = params.name {
        recipe.name = name;
    }
    if let Some(description) = params.description {
        recipe.description = description;
    }
    let path = recipes::save(&recipes::recipes_dir()?, &recipe, params.overwrite)?;
    let warnings = recipes::warnings(workspace, &recipe);
    Ok(SaveResult { steps: recipe.steps.len(), name: recipe.name, path: path.display().to_string(), warnings })
}

/// A recipe called `name` of the journal's `steps`.
fn from_journal(workspace: &mut dyn Workspace, name: Option<&str>, steps: &[u64]) -> Result<Recipe, ApiError> {
    let name = name.ok_or_else(|| ApiError::invalid_params("a recipe made from the journal needs a name"))?;
    if steps.is_empty() {
        return Err(ApiError::invalid_params("journal_steps names no steps; history.list gives them"));
    }
    // With the anchors and parameters recorded for the steps, and the
    // earlier steps they cite, so the recipe ports to other files.
    provenance::checked_recipe(workspace.journal(), name, Some(steps))
}

pub fn preview(workspace: &mut dyn Workspace, params: RunParams) -> Result<RunReport, ApiError> {
    let (recipe, _) = chosen(params.name, params.path, params.recipe)?;
    let options = ReplayOptions { parameters: params.parameters, doc: params.doc, through_step: params.through_step, preview: true, ..ReplayOptions::new(Caller::Recipe(recipe.name.clone())) };
    Ok(replay::run_recipe(workspace, &recipe, &options))
}

/// `recipes.run`: the recipe's steps called as `recipe:NAME`, consented to
/// when the person started the run (or allowed it when asked), and
/// otherwise each checked against the policy of the caller that started
/// it. A run that stops fails with the stopped step's error code, and its
/// report as `data.report`.
pub fn run(workspace: &mut dyn Workspace, _caller: &Caller, consent: Consent<'_>, params: RunParams) -> Result<RunReport, ApiError> {
    let (recipe, _) = chosen(params.name, params.path, params.recipe)?;
    let mut options = ReplayOptions { parameters: params.parameters, doc: params.doc, through_step: params.through_step, ..ReplayOptions::new(Caller::Recipe(recipe.name.clone())) };
    // Started by the person, or allowed by them when asked, the run is
    // consented to; allowed by a client's policy, each step is checked
    // against that policy too.
    options.checked_as = match consent {
        Consent::CheckedAs(subject) if subject.client().is_some() => Some(subject.clone()),
        _ => None,
    };
    let report = replay::run_recipe(workspace, &recipe, &options);
    match &report.stopped {
        None => Ok(report),
        Some(stopped) => {
            let message = format!("the recipe '{}' did not finish. {}", recipe.name, report.summary());
            Err(ApiError::new(stopped.error.code, message).with_data(serde_json::json!({ "report": report })))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::api::test_support::{call, workspace_with};
    use crate::api::{ErrorCode, Policy};

    fn use_own_dir(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("theviewer-recipes-api-{}-{test}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        recipes::use_dir_for_this_thread(dir.clone());
        dir
    }

    fn patch_recipe() -> Value {
        json!({
            "recipe": 1, "api_version": "1.x", "name": "Patch",
            "steps": [
                {"step": 1, "method": "bytes.write", "params": {"start": {"$anchor": {"find": {"text": "b"}}}, "data": "42"}},
                {"step": 2, "method": "bytes.write", "params": {"start": {"$anchor": {"find": {"text": "c"}}}, "data": "43"}}
            ]
        })
    }

    #[test]
    fn a_recipe_saved_through_the_api_is_listed_described_previewed_and_run() {
        let dir = use_own_dir("round-trip");
        let mut workspace = workspace_with("a.bin", b"abc");
        let saved = call(&mut workspace, "recipes.save", json!({"recipe": patch_recipe(), "description": "Capitals"})).unwrap();
        assert_eq!(saved["path"], dir.join("Patch.theviewer-recipe.json").display().to_string());
        let listed = call(&mut workspace, "recipes.list", json!({})).unwrap();
        assert_eq!((listed["recipes"][0]["name"].as_str(), listed["recipes"][0]["steps"].as_u64(), listed["recipes"][0]["description"].as_str()), (Some("Patch"), Some(2), Some("Capitals")));
        let described = call(&mut workspace, "recipes.describe", json!({"name": "patch"})).unwrap();
        assert_eq!(described["recipe"]["steps"][1]["method"], "bytes.write");
        assert_eq!(described["warnings"], json!([]));

        let preview = call(&mut workspace, "recipes.preview", json!({"name": "Patch"})).unwrap();
        assert_eq!(preview["steps"][0]["params"]["start"], 1);
        assert_eq!(call(&mut workspace, "bytes.read", json!({"start": 0})).unwrap()["data"], "616263", "the preview changed nothing");

        let ran = call(&mut workspace, "recipes.run", json!({"name": "Patch"})).unwrap();
        assert_eq!(ran["steps"].as_array().unwrap().len(), 2);
        assert_eq!(call(&mut workspace, "bytes.read", json!({"start": 0})).unwrap()["data"], "614243");
        let entries: Vec<String> = workspace.journal().entries().map(|entry| entry.method.clone()).collect();
        assert_eq!(entries, ["recipes.run"], "the run is one step of the journal, its steps inside it");
        let again = call(&mut workspace, "recipes.save", json!({"recipe": patch_recipe()})).unwrap_err();
        assert!(again.message.contains("pass overwrite to replace it"), "{}", again.message);
    }

    #[test]
    fn a_run_that_stops_fails_with_the_report_of_where_and_why() {
        use_own_dir("stops");
        let mut workspace = workspace_with("a.bin", b"abd");
        let error = call(&mut workspace, "recipes.run", json!({"recipe": patch_recipe()})).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotFound);
        assert!(error.message.starts_with("the recipe 'Patch' did not finish. Stopped at step 2 (bytes.write): the parameter start: the 1st match of the text 'c'"), "{}", error.message);
        let report: RunReport = serde_json::from_value(error.data.unwrap()["report"].clone()).unwrap();
        assert_eq!(report.steps.len(), 2);
        assert_eq!(call(&mut workspace, "bytes.read", json!({"start": 0})).unwrap()["data"], "614264", "what ran before stays, as one undo step");
    }

    #[test]
    fn a_recipe_is_made_from_steps_of_the_session_s_journal() {
        let dir = use_own_dir("journal");
        let mut workspace = workspace_with("a.bin", b"abc");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "cursor.set", json!({"offset": 2})).unwrap();
        let saved = call(&mut workspace, "recipes.save", json!({"name": "Capital A", "journal_steps": [1, 2]})).unwrap();
        assert_eq!(saved["steps"], 2);
        let (recipe, _) = recipes::find(&dir, "Capital A").unwrap();
        assert_eq!(recipe.recorded_on.map(|file| file.name), Some("a.bin".to_string()));
        assert_eq!(call(&mut workspace, "recipes.save", json!({"name": "x", "journal_steps": [40]})).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "recipes.save", json!({"name": "x"})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn a_recipe_saved_from_the_journal_keeps_where_its_values_came_from() {
        let dir = use_own_dir("anchored");
        let mut workspace = workspace_with("a.bin", b"..SYNC..");
        let found = crate::journal::Anchor::Find { find: crate::journal::anchors::Needle::Text("SYNC".into()), nth: 0, part: None };
        let derived = crate::journal::DerivedFrom::from([("offset".to_string(), found)]);
        crate::api::call_derived(&mut workspace, &crate::api::Caller::Panel, "cursor.set", json!({"offset": 2}), derived).unwrap();
        call(&mut workspace, "recipes.save", json!({"name": "To the sync word", "journal_steps": [1]})).unwrap();
        let (recipe, _) = recipes::find(&dir, "To the sync word").unwrap();
        assert_eq!(recipe.steps[0].params["offset"], json!({"$anchor": {"find": {"text": "SYNC"}, "nth": 0}}), "the anchor, not the offset it found here");
    }

    #[test]
    fn an_unknown_recipe_says_which_are_saved() {
        use_own_dir("unknown");
        let mut workspace = workspace_with("a.bin", b"abc");
        call(&mut workspace, "recipes.save", json!({"recipe": patch_recipe()})).unwrap();
        let error = call(&mut workspace, "recipes.run", json!({"name": "Pacth"})).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotFound);
        assert!(error.message.contains("there is no recipe 'Pacth' (those saved are Patch)"), "{}", error.message);
        let both = call(&mut workspace, "recipes.run", json!({"name": "Patch", "recipe": patch_recipe()})).unwrap_err();
        assert_eq!(both.code, ErrorCode::InvalidParams);
    }

    fn app_with(bytes: &[u8]) -> crate::app::ViewerApp {
        let mut app = crate::app::ViewerApp::new(crate::app::Launch::default());
        app.open_bytes(bytes.to_vec(), "a.bin".to_string());
        app.run_bus();
        app
    }

    fn mcp() -> Caller {
        Caller::Mcp("claude-code".into())
    }

    #[test]
    fn a_client_whose_edits_are_never_allowed_cannot_edit_through_a_recipe() {
        use_own_dir("denied");
        let mut app = app_with(b"abc");
        app.preferences.permissions.insert("mcp:claude-code".into(), Policy::Deny);
        let error = crate::api::call(&mut app, &mcp(), "recipes.run", json!({"recipe": patch_recipe()})).unwrap_err();
        assert_eq!(error.code, ErrorCode::ReadOnly);
        assert!(error.message.contains("The MCP client claude-code may not call recipes.run"), "{}", error.message);
        assert_eq!(app.document.read_range(0, 3), b"abc");
    }

    #[test]
    fn each_step_of_a_client_s_run_is_checked_against_that_client_s_policy() {
        // Called from inside a call already allowed (a transaction's, say),
        // the run still checks each step against the client that started it.
        let mut app = app_with(b"abc");
        app.preferences.permissions.insert("mcp:claude-code".into(), Policy::Deny);
        let recipe: Recipe = serde_json::from_value(patch_recipe()).unwrap();
        let options = ReplayOptions { checked_as: Some(mcp()), ..ReplayOptions::new(Caller::Recipe("Patch".into())) };
        let report = replay::run_recipe(&mut app, &recipe, &options);
        let stopped = report.stopped.expect("the first edit is refused");
        assert_eq!((stopped.step, stopped.error.code), (1, ErrorCode::ReadOnly));
        assert!(stopped.error.message.contains("The MCP client claude-code may not call bytes.write"), "{}", stopped.error.message);
        assert_eq!(app.document.read_range(0, 3), b"abc");
        let refused = app.journal.entries().last().unwrap();
        assert_eq!((refused.caller.as_str(), refused.method.as_str(), refused.outcome.is_ok()), ("recipe:Patch", "bytes.write", false), "the refusal is journalled");

        app.preferences.permissions.insert("mcp:claude-code".into(), Policy::Ask);
        let report = replay::run_recipe(&mut app, &recipe, &options);
        assert!(report.stopped.expect("the step would need asking").error.needs_confirmation());
    }

    #[test]
    fn a_client_s_run_is_held_for_the_person_and_runs_whole_once_allowed() {
        use_own_dir("held");
        let mut app = app_with(b"abc");
        app.preferences.permissions.insert("mcp:claude-code".into(), Policy::Ask);
        let answer = std::rc::Rc::new(std::cell::RefCell::new(None));
        let kept = answer.clone();
        app.request_api_call(mcp(), "recipes.run", json!({"recipe": patch_recipe()}), Box::new(move |_, result| *kept.borrow_mut() = Some(result)));
        assert_eq!(app.confirmations.len(), 1, "the run waits for the person");
        assert_eq!(app.confirmations.current().unwrap().description, "Run the recipe 'Patch' on the current document: 2 steps (bytes.write, bytes.write)");
        assert_eq!(app.document.read_range(0, 3), b"abc");
        app.answer_confirmation(crate::confirmations::Answer::AllowOnce);
        assert!(answer.borrow().as_ref().unwrap().is_ok(), "{:?}", answer.borrow());
        assert!(app.confirmations.is_empty(), "allowing the run allowed its steps");
        assert_eq!(app.document.read_range(0, 3), b"aBC");
        assert_eq!(app.document.undo_label(), Some("Recipe steps by recipe:Patch"));
    }

    #[test]
    fn the_person_s_run_in_the_window_asks_nothing_more() {
        use_own_dir("window");
        let mut app = app_with(b"abc");
        crate::actions::take_performed();
        app.perform("recipes.run", json!({"recipe": patch_recipe()})).unwrap();
        assert!(app.confirmations.is_empty());
        assert_eq!(app.document.read_range(0, 3), b"aBC");
        assert_eq!(crate::actions::take_performed()[0].0, "recipes.run");
    }
}
