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
    let path = dir.join(file_name_for(&recipe.name));
    if path.exists() && !overwrite {
        return Err(ApiError::invalid_params(format!("a recipe called '{}' is already saved at {}; pass overwrite to replace it", recipe.name, path.display())));
    }
    write(&path, recipe)?;
    Ok(path)
}

/// Write `recipe` to the file at `path`, replacing it, once this build is
/// sure it reads the recipe back: how every recipe file is written.
pub fn write(path: &Path, recipe: &Recipe) -> Result<(), ApiError> {
    recipe.check_format()?;
    crate::config::write_json(path, recipe).map_err(|message| ApiError::new(ErrorCode::Unavailable, format!("the recipe could not be saved: {message}")))
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
    load_all(dir).into_iter().map(|(path, loaded)| summary_of(&path, loaded)).collect()
}

/// Every recipe file in `dir` with what loading it gave, by the name
/// [`list`] lists it under.
fn load_all(dir: &Path) -> Vec<(PathBuf, Result<Recipe, ApiError>)> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|entry| entry.path()).filter(|path| path.to_string_lossy().ends_with(RECIPE_EXTENSION)).collect();
    paths.sort();
    let mut loaded: Vec<(PathBuf, Result<Recipe, ApiError>)> = paths.into_iter().map(|path| (path.clone(), load(&path))).collect();
    loaded.sort_by_key(|(path, recipe)| listed_name(path, recipe.as_ref().ok()).to_lowercase());
    loaded
}

/// The name a recipe file is listed under: the recipe's, or its file's
/// when it could not be read.
fn listed_name(path: &Path, recipe: Option<&Recipe>) -> String {
    match recipe {
        Some(recipe) => recipe.name.clone(),
        None => path.file_name().map(|name| name.to_string_lossy().trim_end_matches(RECIPE_EXTENSION).to_string()).unwrap_or_default(),
    }
}

fn summary_of(path: &Path, loaded: Result<Recipe, ApiError>) -> RecipeSummary {
    let name = listed_name(path, loaded.as_ref().ok());
    let path = path.display().to_string();
    match loaded {
        Ok(recipe) => RecipeSummary { name, description: recipe.description, path, steps: recipe.steps.len(), parameters: recipe.parameters, error: None },
        Err(error) => RecipeSummary { name, description: String::new(), path, steps: 0, parameters: BTreeMap::new(), error: Some(error.message) },
    }
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
    let saved = load_all(dir);
    let names: Vec<String> = saved.iter().map(|(path, recipe)| listed_name(path, recipe.as_ref().ok())).collect();
    for (path, loaded) in saved {
        if let Ok(recipe) = loaded
            && recipe.name.eq_ignore_ascii_case(name_or_path.trim())
        {
            return Ok((recipe, path));
        }
    }
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

/// How `theviewer replay` runs a recipe on each file.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplaySettings {
    /// Values for the recipe's parameters, as text or JSON.
    pub parameters: BTreeMap<String, Value>,
    /// What to do with a file the recipe changed.
    pub output: ReplayOutput,
    /// Let steps that write files run (`--allow-writes`); without it they
    /// stop the run, as a recipe from someone else may write anywhere.
    pub allow_writes: bool,
    /// Save each sheet the run made into this folder (`--save-sheets`).
    pub save_sheets: Option<PathBuf>,
}

impl ReplaySettings {
    /// Run with `parameters`, doing `output` with each file, writing no
    /// files of the recipe's own and saving no sheets.
    pub fn new(parameters: BTreeMap<String, Value>, output: ReplayOutput) -> Self {
        ReplaySettings { parameters, output, allow_writes: false, save_sheets: None }
    }
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
    /// Where each sheet the run made was saved, with `--save-sheets`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sheets_saved: Vec<String>,
}

impl FileRun {
    /// Whether every step ran on the file and it was saved if asked.
    pub fn succeeded(&self) -> bool {
        self.error.is_none() && self.report.as_ref().is_some_and(RunReport::completed)
    }
}

/// Run `recipe` on `file` in `workspace` (fresh, one per file) as
/// `settings` say, as the command line does: its steps are the recipe's,
/// allowed as the command line's are, but for writing files, which needs
/// `allow_writes`. The sheets it made are saved when asked, whether or not
/// it completed. A run that completed is saved as `settings.output` says;
/// one that stopped is not saved.
pub fn replay_file(workspace: &mut HeadlessWorkspace, recipe: &Recipe, file: &Path, settings: &ReplaySettings) -> FileRun {
    let mut run = FileRun { file: file.display().to_string(), report: None, saved: None, error: None, sheets_saved: Vec::new() };
    let doc = match workspace.open_path(file) {
        Ok(doc) => doc,
        Err(error) => {
            run.error = Some(error);
            return run;
        }
    };
    let options = ReplayOptions {
        parameters: settings.parameters.clone(),
        doc: Some(doc.clone()),
        checked_as: Some(Caller::Cli),
        allow_writes: settings.allow_writes,
        ..ReplayOptions::new(Caller::Recipe(recipe.name.clone()))
    };
    let report = replay::run_recipe(workspace, recipe, &options);
    let completed = report.completed();
    if let Some(dir) = &settings.save_sheets {
        match save_sheets(workspace, &report, file, dir) {
            Ok(saved) => run.sheets_saved = saved,
            Err(error) => run.error = Some(error),
        }
    }
    run.report = Some(report);
    if !completed || run.error.is_some() {
        return run;
    }
    let target = match &settings.output {
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

/// Save each sheet `report`'s run on `file` made into `dir` (made if need
/// be), as `FILE.stepN.LABEL.bin`, LABEL being the sheet's label or its id;
/// returns where each went.
fn save_sheets(workspace: &mut HeadlessWorkspace, report: &RunReport, file: &Path, dir: &Path) -> Result<Vec<String>, ApiError> {
    if report.sheets.is_empty() {
        return Ok(Vec::new());
    }
    let unavailable = |message: String| ApiError::new(ErrorCode::Unavailable, message);
    std::fs::create_dir_all(dir).map_err(|error| unavailable(format!("the folder {} could not be made: {error}", dir.display())))?;
    let stem = file.file_name().map_or_else(|| "input".to_string(), |name| name.to_string_lossy().into_owned());
    let mut saved = Vec::new();
    for sheet in &report.sheets {
        let Some(document) = workspace.document_mut(&sheet.doc) else { continue };
        let name = file_name_for(sheet.label.as_deref().unwrap_or(&sheet.doc));
        let name = name.trim_end_matches(RECIPE_EXTENSION);
        let path = dir.join(format!("{stem}.step{}.{name}.bin", sheet.step));
        std::fs::write(&path, document.read_range(0, document.len())).map_err(|error| unavailable(format!("the sheet {} could not be saved to {}: {error}", sheet.doc, path.display())))?;
        saved.push(path.display().to_string());
    }
    Ok(saved)
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
        for sheet in &run.sheets_saved {
            out.push_str(&format!("  sheet saved to {sheet}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests;
