//! `history.*`: the session's journal of calls, as the History tab and
//! clients read it (`history.list`, `history.entry`, `history.session`),
//! moving along it (`history.inverse`, `history.undo_step`,
//! `history.go_back`), and saving it as a recipe (`history.save_recipe`).
//!
//! Every edit, view change and job, by every caller, is a step of the
//! journal (see [`crate::journal`]); reads are kept for a while in case a
//! later step cites one. Undoing a step, going back and what happens to the
//! steps after are [`crate::journal::timeline`]'s. `history.undo`, `history.redo` and
//! `history.transaction`, which act on a document's undo steps, are in
//! `edits.rs`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::values::{self, NoParams};
use super::workspace::Workspace;
use super::{ApiError, Caller};
use crate::journal::timeline::{self, Inverse, StepStatus, Timeline};
use crate::journal::{Dropped, JournalEntry, JournalSession};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("history.list", Read, list, ListParams, HistoryList, "The session's journal: each edit, view change and job made through the API, by any caller, in order, with its parameters, result, outcome and a description; optionally the recent reads too. Pass back next as since to follow it.").not_journalled(),
    method!("history.entry", Read, entry, EntryParams, crate::journal::JournalEntry, "One step of the journal, or one recent read, in full.").not_journalled(),
    method!("history.session", Read, session, super::values::NoParams, crate::journal::JournalSession, "What the journal's session ran with: when it started, the API version, the plugins loaded with their hashes, and each document as first seen, with its size and SHA-256.").not_journalled(),
    method!("history.inverse", Read, inverse, EntryParams, StepInverse, "How a step of the journal would be undone now: the calls that undo it (the document's undo for its last edit, or the inverse of a view change, fold, bookmark, selection or document opened), nothing to undo (a job, a read, a file written), or why it cannot be.").not_journalled(),
    method!("history.undo_step", Edit, caller undo_step, EntryParams, timeline::UndoneStep, "Undo one step of the journal through its inverse (see history.inverse), whoever made it, as a step of its own; the step is then shown as undone and left out of recipes and playback.").moves_along_the_timeline(crate::api::Move::UndoStep),
    method!("history.go_back", Edit, caller go_back, GoBackParams, timeline::WentBack, "Go back to a step of the journal (0 for before the first): undo every later step in effect, latest first, or, where one has no inverse, bring the document back to how the session first saw it and run the steps up to it again. The later steps stay in the journal, shown as undone.").moves_along_the_timeline(crate::api::Move::GoBack),
    method!("history.save_recipe", Edit, save_recipe, SaveRecipeParams, SavedRecipe, "Write the steps in effect (all, or up to a step) to a recipe file, *.theviewer-recipe.json, with the anchors and parameters recorded for its steps, to run on other files.").writes_file(crate::api::WritesFile::Always),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        // A step to list: the first call of the session.
        ("bytes.write", json!({"start": 0, "data": "00"})),
        ("history.list", json!({"limit": 10, "include_reads": true})),
        ("history.entry", json!({"step": 1})),
        ("history.session", json!({})),
        // A view change to undo, and to go back before.
        ("view.fold", json!({"ranges": [[16, 8]]})),
        ("history.inverse", json!({"step": 2})),
        ("history.undo_step", json!({"step": 2})),
        ("history.go_back", json!({"step": 0})),
        ("bytes.write", json!({"start": 1, "data": "41"})),
        ("history.save_recipe", json!({"path": example_recipe_path(), "name": "Example"})),
    ]
}

/// Where the example of `history.save_recipe` writes.
#[cfg(test)]
fn example_recipe_path() -> String {
    let name = format!("theviewer-api-examples-{}{}", std::process::id(), crate::journal::recipe::RECIPE_EXTENSION);
    std::env::temp_dir().join(name).display().to_string()
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(workspace: &mut dyn Workspace, method: &str, params: &Value) -> Option<String> {
    let step = params.get("step").and_then(Value::as_u64);
    let description = match method {
        "history.undo_step" => {
            let step = step?;
            let described = workspace.journal().entry(step).map(|entry| entry.description.clone()).filter(|description| !description.is_empty());
            match described {
                Some(description) => format!("Undo step {step}: {description}"),
                None => format!("Undo step {step}"),
            }
        }
        "history.go_back" => match step? {
            0 => "Go back to before the first step, undoing every step".to_string(),
            step => {
                let timeline = Timeline::of(workspace.journal());
                let later = workspace.journal().since(step).filter(|entry| timeline.is_active(entry.step)).count();
                format!("Go back to step {step}, undoing the {later} step(s) after it")
            }
        },
        "history.save_recipe" => {
            let name = params.get("name")?.as_str()?;
            let path = params.get("path")?.as_str()?;
            match params.get("through").and_then(Value::as_u64) {
                Some(through) => format!("Save the history up to step {through} as the recipe \"{name}\" in {path}"),
                None => format!("Save the history as the recipe \"{name}\" in {path}"),
            }
        }
        _ => return None,
    };
    Some(description)
}

/// Parameters of `history.list`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListParams {
    /// List the steps after this one (a `next` from before); from the
    /// first when omitted.
    #[serde(default)]
    pub since: Option<u64>,
    /// Most entries to return (100 when omitted).
    #[serde(default)]
    pub limit: Option<usize>,
    /// Also list the recent reads still held, whose effect is `read`.
    #[serde(default)]
    pub include_reads: bool,
}

/// The result of `history.list`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HistoryList {
    /// The entries, in step order.
    pub entries: Vec<JournalEntry>,
    /// The last step listed, to pass as `since` for the entries after it;
    /// none when this is all there is now.
    pub next: Option<u64>,
    /// The last step recorded or read in the session.
    pub last_step: Option<u64>,
    /// Changes whenever anything recorded changes (a read promoted into the
    /// journal takes its own, earlier, step number).
    pub revision: u64,
    /// The oldest entries the journal no longer holds.
    pub dropped: Dropped,
    /// The steps listed that are undone, and by which step (an undo, an
    /// undo of the step itself, or going back to an earlier step).
    #[serde(default)]
    pub undone: Vec<UndoneBy>,
}

/// A step undone, and by which.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UndoneBy {
    pub step: u64,
    pub by: u64,
}

/// The result of `history.inverse`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StepInverse {
    pub step: u64,
    /// Where it stands: active, failed, undone (by a step) or a move along
    /// the history.
    pub status: StepStatus,
    /// How it would be undone now.
    pub inverse: Inverse,
}

/// Parameters of `history.go_back`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoBackParams {
    /// The step to go back to: every later one is undone. 0 goes back to
    /// before the first step.
    pub step: u64,
}

/// Parameters of `history.save_recipe`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveRecipeParams {
    /// Where to write it; by convention its name ends in
    /// .theviewer-recipe.json.
    pub path: String,
    /// What to call it.
    pub name: String,
    /// What it is for.
    #[serde(default)]
    pub description: String,
    /// The last step to take; every step in effect when omitted.
    #[serde(default)]
    pub through: Option<u64>,
}

/// The result of `history.save_recipe`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SavedRecipe {
    pub path: String,
    pub name: String,
    /// The numbers of the steps it holds, in order.
    pub steps: Vec<u64>,
}

/// Parameters of `history.entry`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntryParams {
    /// The step's number.
    pub step: u64,
}

pub fn list(workspace: &mut dyn Workspace, params: ListParams) -> Result<HistoryList, ApiError> {
    let limit = values::page_limit(params.limit)?;
    let journal = workspace.journal();
    let since = params.since.unwrap_or(0);
    let mut entries: Vec<&JournalEntry> = journal.since(since).collect();
    if params.include_reads {
        entries.extend(journal.reads().filter(|read| read.step > since));
        entries.sort_by_key(|entry| entry.step);
    }
    let more = entries.len() > limit;
    let entries: Vec<JournalEntry> = entries.into_iter().take(limit).cloned().collect();
    let next = if more { entries.last().map(|entry| entry.step) } else { None };
    let timeline = Timeline::of(journal);
    let undone = entries
        .iter()
        .filter_map(|entry| match timeline.status(entry.step) {
            Some(StepStatus::Undone { by }) => Some(UndoneBy { step: entry.step, by }),
            _ => None,
        })
        .collect();
    Ok(HistoryList { entries, next, last_step: journal.last_step(), revision: journal.revision(), dropped: journal.dropped(), undone })
}

pub fn entry(workspace: &mut dyn Workspace, params: EntryParams) -> Result<JournalEntry, ApiError> {
    let journal = workspace.journal();
    if let Some(entry) = journal.entry(params.step).or_else(|| journal.read(params.step)) {
        return Ok(entry.clone());
    }
    let why = if params.step <= journal.dropped().through_step { "it was dropped to keep the journal within its limits" } else { "it is not a step of this session, or a read no longer held" };
    Err(ApiError::not_found(format!("there is no step {}: {why}; history.list shows the steps held", params.step)))
}

pub fn session(workspace: &mut dyn Workspace, _params: NoParams) -> Result<JournalSession, ApiError> {
    Ok(workspace.journal().session().clone())
}

pub fn inverse(workspace: &mut dyn Workspace, params: EntryParams) -> Result<StepInverse, ApiError> {
    let Some(status) = Timeline::of(workspace.journal()).status(params.step) else {
        return Err(crate::journal::provenance::not_a_step(params.step));
    };
    Ok(StepInverse { step: params.step, status, inverse: timeline::inverse_of(workspace, params.step) })
}

pub fn undo_step(workspace: &mut dyn Workspace, caller: &Caller, params: EntryParams) -> Result<timeline::UndoneStep, ApiError> {
    timeline::undo_step(workspace, caller, params.step)
}

pub fn go_back(workspace: &mut dyn Workspace, caller: &Caller, params: GoBackParams) -> Result<timeline::WentBack, ApiError> {
    timeline::go_back(workspace, caller, params.step)
}

pub fn save_recipe(workspace: &mut dyn Workspace, params: SaveRecipeParams) -> Result<SavedRecipe, ApiError> {
    if params.name.trim().is_empty() {
        return Err(ApiError::invalid_params("give the recipe a name"));
    }
    let mut recipe = timeline::recipe_of_history(workspace.journal(), &params.name, params.through);
    if recipe.steps.is_empty() {
        return Err(ApiError::invalid_params("there are no steps in effect to save as a recipe"));
    }
    recipe.description = params.description;
    crate::recipes::write(std::path::Path::new(&params.path), &recipe)?;
    Ok(SavedRecipe { path: params.path, name: recipe.name, steps: recipe.steps.iter().map(|step| step.step).collect() })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::{call, workspace_with};
    use crate::api::{Caller, ErrorCode};

    #[test]
    fn the_history_lists_each_step_in_order_and_pages_through_them() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        for start in 0..3 {
            call(&mut workspace, "bytes.write", json!({"start": start, "data": "41"})).unwrap();
        }
        let first = call(&mut workspace, "history.list", json!({"limit": 2})).unwrap();
        let steps: Vec<u64> = first["entries"].as_array().unwrap().iter().map(|entry| entry["step"].as_u64().unwrap()).collect();
        assert_eq!(steps, [1, 2]);
        assert_eq!(first["entries"][0]["description"], "Overwrite 1 byte at 0x0 with 41");
        assert_eq!(first["next"], 2);
        let rest = call(&mut workspace, "history.list", json!({"since": first["next"]})).unwrap();
        assert_eq!(rest["entries"].as_array().unwrap().len(), 1);
        assert_eq!((rest["entries"][0]["step"].as_u64(), &rest["next"]), (Some(3), &serde_json::Value::Null));
        assert_eq!(rest["last_step"], 3);
    }

    #[test]
    fn reads_are_listed_only_when_asked_for_and_reading_the_history_is_not_recorded() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        call(&mut workspace, "bytes.read", json!({"start": 0, "len": 2})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "history.session", json!({})).unwrap();
        let without = call(&mut workspace, "history.list", json!({})).unwrap();
        assert_eq!(without["entries"].as_array().unwrap().len(), 1);
        assert_eq!(without["entries"][0]["step"], 2, "the read took step 1");
        let with = call(&mut workspace, "history.list", json!({"include_reads": true})).unwrap();
        let listed: Vec<(u64, &str)> = with["entries"].as_array().unwrap().iter().map(|entry| (entry["step"].as_u64().unwrap(), entry["method"].as_str().unwrap())).collect();
        assert_eq!(listed, [(1, "bytes.read"), (2, "bytes.write")], "history.* reads are not among them");
        assert_eq!(call(&mut workspace, "history.entry", json!({"step": 1})).unwrap()["effect"], "read");
    }

    #[test]
    fn saving_the_history_as_a_recipe_writes_a_file_that_reads_back_as_one() {
        let mut workspace = workspace_with("flight.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "view.set_shape", json!({"width": 8})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 9, "data": "0000"})).unwrap_err();
        let path = std::env::temp_dir().join(format!("theviewer-history-test-{}.theviewer-recipe.json", std::process::id()));
        let params = json!({"path": path.display().to_string(), "name": "Patch", "description": "Patch the header"});
        assert_eq!(crate::api::describe_call(&mut workspace, "history.save_recipe", &params), format!("Save the history as the recipe \"Patch\" in {}", path.display()));
        let saved = call(&mut workspace, "history.save_recipe", params).unwrap();
        assert_eq!(saved["steps"], json!([1, 2]), "the failed step is left out");
        let recipe: crate::journal::Recipe = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!((recipe.name.as_str(), recipe.description.as_str(), recipe.steps.len()), ("Patch", "Patch the header", 2));
        assert_eq!(recipe.recorded_on.map(|file| file.name).as_deref(), Some("flight.bin"));
        let saving = crate::api::Workspace::journal(&workspace).entries().last().unwrap();
        assert_eq!(saving.method, "history.save_recipe", "saving is a step of its own");
    }

    #[test]
    fn a_recipe_saved_from_the_history_is_written_as_recipes_save_writes_it() {
        let dir = std::env::temp_dir().join(format!("theviewer-history-writer-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        crate::recipes::use_dir_for_this_thread(dir.join("saved"));
        let mut workspace = workspace_with("flight.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        let by_recipes = call(&mut workspace, "recipes.save", json!({"name": "Patch", "journal_steps": [1]})).unwrap();
        let path = dir.join("from history").join("Patch.theviewer-recipe.json");
        call(&mut workspace, "history.save_recipe", json!({"path": path.display().to_string(), "name": "Patch"})).unwrap();
        let written = std::fs::read_to_string(&path).expect("the folder it is saved in is made");
        let saved = std::fs::read_to_string(by_recipes["path"].as_str().unwrap()).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(written, saved, "one writer for every recipe file");
    }

    #[test]
    fn undoing_and_going_back_say_what_they_will_do() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 1, "data": "41"})).unwrap();
        assert_eq!(crate::api::describe_call(&mut workspace, "history.undo_step", &json!({"step": 2})), "Undo step 2: Overwrite 1 byte at 0x1 with 41");
        assert_eq!(crate::api::describe_call(&mut workspace, "history.go_back", &json!({"step": 1})), "Go back to step 1, undoing the 1 step(s) after it");
        let inverse = call(&mut workspace, "history.inverse", json!({"step": 2})).unwrap();
        assert_eq!(inverse, json!({"step": 2, "status": {"state": "active"}, "inverse": {"kind": "calls", "calls": [{"method": "history.undo", "params": {"doc": "doc-1"}}]}}));
        assert_eq!(call(&mut workspace, "history.inverse", json!({"step": 99})).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn an_entry_not_held_is_not_found() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let missing = call(&mut workspace, "history.entry", json!({"step": 9})).unwrap_err();
        assert_eq!(missing.code, ErrorCode::NotFound);
        assert!(missing.message.contains("history.list"), "{}", missing.message);
    }

    #[test]
    fn the_session_header_names_the_api_version_and_each_document_as_first_seen() {
        let mut workspace = workspace_with("flight.bin", b"abc");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        let session = crate::api::call(&mut workspace, &Caller::Mcp("claude-code".into()), "history.session", json!({})).unwrap();
        assert_eq!(session["api_version"], crate::api::API_VERSION);
        assert_eq!(session["documents"][0]["file"], json!({"name": "flight.bin", "size": 3, "sha256": crate::corpus::sha256_hex(b"abc")}), "hashed before the edit");
        assert_eq!(session["documents"][0]["version"], 0);
    }
}
