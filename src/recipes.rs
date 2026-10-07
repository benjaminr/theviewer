//! Recipes on disk: saving, loading and listing `*.theviewer-recipe.json`
//! files in `~/.config/theviewer/recipes/`, running one over files for
//! `theviewer replay`, and the window's "Run recipe…" ([`window`]).
//!
//! The file format is [`crate::journal::Recipe`]; running one is
//! [`crate::journal::replay`]'s. A recipe is found by its file's path, or
//! by its name among the saved ones. Loading checks that this build reads
//! its format; what to know before running it (another API version, a
//! plugin missing or changed, a method this build lacks, mistakes in its
//! anchors) is given as warnings.

pub mod window;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{self, ApiError, Caller, ErrorCode, HeadlessWorkspace, Workspace};
use crate::journal::Recipe;
use crate::journal::recipe::{RECIPE_EXTENSION, RecipeParameter};
use crate::journal::replay::{self, ReplayOptions, RunReport};

/// The folder in the app's configuration folder where recipes are kept.
const RECIPES_FOLDER: &str = "recipes";

#[cfg(test)]
thread_local! {
    /// Where this test thread keeps recipes, so tests never touch the
    /// person's own.
    static TEST_DIR: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Keep this test thread's recipes in `dir`.
#[cfg(test)]
pub fn use_dir_for_this_thread(dir: PathBuf) {
    TEST_DIR.with_borrow_mut(|kept| *kept = Some(dir));
}

/// Where recipes are kept: `~/.config/theviewer/recipes/` (under `$HOME`).
#[cfg(not(test))]
pub fn recipes_dir() -> Result<PathBuf, ApiError> {
    crate::config::config_file(RECIPES_FOLDER).ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "there is no home folder ($HOME) to keep recipes in"))
}

/// Where this test thread keeps recipes: its own folder, or one for the
/// test process, never the person's.
#[cfg(test)]
pub fn recipes_dir() -> Result<PathBuf, ApiError> {
    let kept = TEST_DIR.with_borrow(Clone::clone);
    Ok(kept.unwrap_or_else(|| std::env::temp_dir().join(format!("theviewer-recipes-tests-{}", std::process::id())).join(RECIPES_FOLDER)))
}

/// The file a recipe called `name` is saved as: its name with the
/// characters a file name cannot hold made dashes, then
/// `.theviewer-recipe.json`.
pub fn file_name_for(name: &str) -> String {
    let safe: String = name.trim().chars().map(|character| if matches!(character, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || character.is_control() { '-' } else { character }).collect();
    let safe = safe.trim_start_matches('.');
    format!("{}{RECIPE_EXTENSION}", if safe.is_empty() { "recipe" } else { safe })
}

/// Save `recipe` in `dir` as [`file_name_for`] its name, and return the
/// path. An existing recipe of that name is replaced only with `overwrite`.
pub fn save(dir: &Path, recipe: &Recipe, overwrite: bool) -> Result<PathBuf, ApiError> {
    recipe.check_format()?;
    let path = dir.join(file_name_for(&recipe.name));
    if path.exists() && !overwrite {
        return Err(ApiError::invalid_params(format!("a recipe called '{}' is already saved at {}; pass overwrite to replace it", recipe.name, path.display())));
    }
    crate::config::write_json(&path, recipe).map_err(|message| ApiError::new(ErrorCode::Unavailable, format!("the recipe could not be saved: {message}")))?;
    Ok(path)
}

/// Load the recipe in the file at `path`, checking this build reads its
/// format.
pub fn load(path: &Path) -> Result<Recipe, ApiError> {
    let text = std::fs::read_to_string(path).map_err(|error| ApiError::not_found(format!("the recipe {} could not be read: {error}", path.display())))?;
    let recipe: Recipe = serde_json::from_str(&text).map_err(|error| ApiError::invalid_params(format!("{} is not a recipe: {error}", path.display())))?;
    recipe.check_format()?;
    Ok(recipe)
}

/// A saved recipe as `recipes.list` lists it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RecipeSummary {
    /// The recipe's name, or its file's when it could not be read.
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Its file.
    pub path: String,
    /// How many steps it has.
    pub steps: usize,
    /// The values it asks for when it runs.
    #[serde(default)]
    pub parameters: BTreeMap<String, RecipeParameter>,
    /// Why it cannot be run, when its file is not a recipe this build reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Every recipe file in `dir`, by name; none when the folder does not exist.
pub fn list(dir: &Path) -> Vec<RecipeSummary> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|entry| entry.path()).filter(|path| path.to_string_lossy().ends_with(RECIPE_EXTENSION)).collect();
    paths.sort();
    let mut summaries: Vec<RecipeSummary> = paths
        .into_iter()
        .map(|path| match load(&path) {
            Ok(recipe) => RecipeSummary { name: recipe.name, description: recipe.description, path: path.display().to_string(), steps: recipe.steps.len(), parameters: recipe.parameters, error: None },
            Err(error) => {
                let file = path.file_name().map(|name| name.to_string_lossy().trim_end_matches(RECIPE_EXTENSION).to_string()).unwrap_or_default();
                RecipeSummary { name: file, description: String::new(), path: path.display().to_string(), steps: 0, parameters: BTreeMap::new(), error: Some(error.message) }
            }
        })
        .collect();
    summaries.sort_by_key(|summary| summary.name.to_lowercase());
    summaries
}

/// The recipe `name_or_path` names: a recipe file's path, or the name of
/// one saved in `dir` (its file name, or the name inside it, in any case).
pub fn find(dir: &Path, name_or_path: &str) -> Result<(Recipe, PathBuf), ApiError> {
    let as_path = Path::new(name_or_path);
    if name_or_path.ends_with(RECIPE_EXTENSION) || as_path.components().count() > 1 || as_path.is_file() {
        return load(as_path).map(|recipe| (recipe, as_path.to_path_buf()));
    }
    let by_file = dir.join(file_name_for(name_or_path));
    if by_file.is_file() {
        return load(&by_file).map(|recipe| (recipe, by_file));
    }
    let saved = list(dir);
    if let Some(found) = saved.iter().find(|summary| summary.error.is_none() && summary.name.eq_ignore_ascii_case(name_or_path.trim())) {
        let path = PathBuf::from(&found.path);
        return load(&path).map(|recipe| (recipe, path));
    }
    let names: Vec<&str> = saved.iter().map(|summary| summary.name.as_str()).collect();
    let known = if names.is_empty() { format!("none is saved in {}", dir.display()) } else { format!("those saved are {}", names.join(", ")) };
    Err(ApiError::not_found(format!("there is no recipe '{name_or_path}' ({known})")))
}

/// What to know before running `recipe` in `workspace`: its warnings for
/// this API and the plugins loaded, and the steps whose methods this build
/// does not have.
pub fn warnings(workspace: &dyn Workspace, recipe: &Recipe) -> Vec<String> {
    let session = workspace.journal().session();
    let mut warnings = recipe.warnings(&session.api_version, &session.plugins);
    warnings.extend(unknown_methods(workspace, recipe));
    warnings
}

/// A warning for each step of `recipe` whose method `workspace` does not
/// have (a plugin's that is not loaded, or one from a newer theviewer).
pub fn unknown_methods(workspace: &dyn Workspace, recipe: &Recipe) -> Vec<String> {
    recipe
        .steps
        .iter()
        .filter(|step| api::find(workspace, &step.method).is_err())
        .map(|step| format!("step {} calls {}, which this theviewer does not have; it will fail", step.step, step.method))
        .collect()
}

// ---------------------------------------------------------------------------
// theviewer replay
// ---------------------------------------------------------------------------

/// What `theviewer replay` does with a file the recipe changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayOutput {
    /// Leave the file as it was: the report is the point.
    Report,
    /// Save the changes over the file (`--save`).
    SaveInPlace,
    /// Save the changed file into this folder, by its own name (`--out`).
    OutDir(PathBuf),
}

/// One file `theviewer replay` ran a recipe on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FileRun {
    /// The file, as given.
    pub file: String,
    /// What the run did, step by step; none when the file did not open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<RunReport>,
    /// Where the changed file was saved, if it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved: Option<String>,
    /// Why the file could not be opened or saved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl FileRun {
    /// Whether every step ran on the file and it was saved if asked.
    pub fn succeeded(&self) -> bool {
        self.error.is_none() && self.report.as_ref().is_some_and(RunReport::completed)
    }
}

/// Run `recipe` on `file` in `workspace` (fresh, one per file) with
/// `parameters` as text or JSON, as the command line does: its steps are
/// the recipe's, allowed as the command line's are. A run that completed is
/// saved as `output` says; one that stopped is not saved.
pub fn replay_file(workspace: &mut HeadlessWorkspace, recipe: &Recipe, file: &Path, parameters: &BTreeMap<String, Value>, output: &ReplayOutput) -> FileRun {
    let mut run = FileRun { file: file.display().to_string(), report: None, saved: None, error: None };
    let doc = match workspace.open_path(file) {
        Ok(doc) => doc,
        Err(error) => {
            run.error = Some(error);
            return run;
        }
    };
    let options = ReplayOptions { parameters: parameters.clone(), doc: Some(doc.clone()), checked_as: Some(Caller::Cli), ..ReplayOptions::new(Caller::Recipe(recipe.name.clone())) };
    let mut report = replay::run_recipe(workspace, recipe, &options);
    report.warnings.extend(unknown_methods(workspace, recipe));
    let completed = report.completed();
    run.report = Some(report);
    if !completed {
        return run;
    }
    let target = match output {
        ReplayOutput::Report => return run,
        ReplayOutput::SaveInPlace => {
            let modified = workspace.documents().iter().any(|document| document.id == doc && document.modified);
            if !modified {
                return run;
            }
            None
        }
        ReplayOutput::OutDir(dir) => {
            if let Err(error) = std::fs::create_dir_all(dir) {
                run.error = Some(ApiError::new(ErrorCode::Unavailable, format!("the folder {} could not be made: {error}", dir.display())));
                return run;
            }
            Some(dir.join(file.file_name().unwrap_or(file.as_os_str())))
        }
    };
    let params = serde_json::json!({ "doc": doc, "path": target.as_ref().map(|path| path.display().to_string()) });
    match api::call(workspace, &Caller::Cli, "documents.save", params) {
        Ok(_) => run.saved = Some(target.unwrap_or_else(|| file.to_path_buf()).display().to_string()),
        Err(error) => run.error = Some(error),
    }
    run
}

/// `runs` as `theviewer replay` prints them without `--json`: a line per
/// file, then its warnings and where it was saved.
pub fn render_text(recipe: &Recipe, runs: &[FileRun]) -> String {
    let mut out = String::new();
    for run in runs {
        let outcome = match (&run.report, &run.error) {
            (Some(report), _) => report.summary(),
            (None, Some(error)) => format!("not run: {}", error.message),
            (None, None) => "not run".to_string(),
        };
        out.push_str(&format!("{}: {} — {outcome}\n", run.file, recipe.name));
        for warning in run.report.iter().flat_map(|report| &report.warnings) {
            out.push_str(&format!("  warning: {warning}\n"));
        }
        if let (Some(_), Some(error)) = (&run.report, &run.error) {
            out.push_str(&format!("  not saved: {}\n", error.message));
        }
        if let Some(saved) = &run.saved {
            out.push_str(&format!("  saved to {saved}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests;
