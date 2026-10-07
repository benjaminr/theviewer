//! `history.*`: the session's journal of calls, as the History tab and
//! clients read it (`history.list`, `history.entry`, `history.session`),
//! moving along it (`history.inverse`, `history.undo_step`,
//! `history.go_back`), saving it as a recipe (`history.save_recipe`), and
//! notes on the analysis written into it (`history.note`,
//! `history.edit_note`, `history.delete_note`, `history.export_notes`).
//!
//! **Notes.** `history.note` is declared an `analysis` (so any caller may
//! write one without being asked, as it changes nothing in a document)
//! that is journalled as a step where it was written, by its caller, and
//! declared a note (`writes_a_note`): the timeline marks it as one, so it
//! is never undone, repeated by playback, going back or recipes, nor undone
//! by going back past it. Editing and deleting a note are not journalled,
//! as making an anchor is not: they change an entry of the journal in
//! place, and an edited note says when and by whom. `history.export_notes`
//! reads the journal, so it is not journalled either; written to a path, it
//! needs leave to edit like any method that writes a file. See
//! [`crate::journal::notes`].
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
use super::{ApiError, Caller, ErrorCode};
use crate::journal::notes::{self, Note};
use crate::journal::timeline::{self, Inverse, StepStatus, Timeline};
use crate::journal::{Dropped, Journal, JournalEntry, JournalSession};

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
    method!("history.note", Analysis, note, NoteParams, WrittenNote, "Write a note in the history where you are now: what you are doing and why, by you, linked to the steps its text cites as #12 and those given; it changes nothing, is never undone or repeated, and is shown beside the steps it links. Returns its step number.").writes_a_note(),
    method!("history.edit_note", Read, caller edit_note, EditNoteParams, EditedNote, "Change a note's text and the steps it is linked to, in place; the note then says when and by whom it was edited. Only notes can be edited.").not_journalled(),
    method!("history.delete_note", Read, delete_note, DeleteNoteParams, DeletedNote, "Take a note out of the history; the steps it was linked to no longer list it. Only notes can be deleted.").not_journalled(),
    method!("history.export_notes", Read, export_notes, ExportNotesParams, ExportedNotes, "The session's notes as Markdown, in the order written, each with the steps it cites (number, caller and description), returned or written to a path given (which needs leave to edit).").writes_file(crate::api::WritesFile::WhenGiven("path")).not_journalled(),
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
        // A note on the write, step 7, edited; then one more, deleted.
        ("history.note", json!({"text": "#5 marks the start of the payload"})),
        ("history.edit_note", json!({"step": 7, "text": "#5 marks where the payload starts", "steps": [1]})),
        ("history.note", json!({"text": "A dead end"})),
        ("history.delete_note", json!({"step": 8})),
        ("history.export_notes", json!({})),
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
        "history.note" => notes::describe(params.get("text")?.as_str()?),
        "history.export_notes" => {
            let path = params.get("path")?.as_str()?;
            let count = workspace.journal().notes().count();
            format!("Write the session's {count} note(s) as Markdown to {path}")
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

/// Parameters of `history.note`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteParams {
    /// What you are doing and why, at most 4 KiB; `#12` in it cites step
    /// 12 and links the note to it.
    pub text: String,
    /// More steps the note is about, beside those its text cites.
    #[serde(default)]
    pub steps: Vec<u64>,
}

/// The result of `history.note`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WrittenNote {
    /// The note's own step number.
    pub step: u64,
    /// The steps it is linked to, in step order.
    pub steps: Vec<u64>,
}

/// Parameters of `history.edit_note`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EditNoteParams {
    /// The note's step number.
    pub step: u64,
    /// What it says now; `#12` cites step 12.
    pub text: String,
    /// The steps it is about beside those its text cites; those given
    /// when it was written (or last edited) when omitted, so `[]` links it
    /// only to the steps its text cites.
    #[serde(default)]
    pub steps: Option<Vec<u64>>,
}

/// The result of `history.edit_note`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EditedNote {
    pub step: u64,
    /// The note as it is now.
    pub note: Note,
}

/// Parameters of `history.delete_note`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteNoteParams {
    /// The note's step number.
    pub step: u64,
}

/// The result of `history.delete_note`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DeletedNote {
    pub step: u64,
    /// The note as it was.
    pub note: Note,
}

/// Parameters of `history.export_notes`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportNotesParams {
    /// Where to write the Markdown, such as notes.md; it is returned when
    /// omitted.
    #[serde(default)]
    pub path: Option<String>,
}

/// The result of `history.export_notes`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExportedNotes {
    /// How many notes it holds.
    pub notes: usize,
    /// The Markdown, when no path was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
    /// The file written, when a path was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
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
    let noted = journal.notes_by_step();
    let entries: Vec<JournalEntry> = entries.into_iter().take(limit).map(|entry| Journal::with_notes(entry, &noted)).collect();
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
        return Ok(Journal::with_notes(entry, &journal.notes_by_step()));
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

pub fn note(workspace: &mut dyn Workspace, params: NoteParams) -> Result<WrittenNote, ApiError> {
    let (step, steps) = notes::write(workspace, &params.text, &params.steps)?;
    Ok(WrittenNote { step, steps })
}

pub fn edit_note(workspace: &mut dyn Workspace, caller: &Caller, params: EditNoteParams) -> Result<EditedNote, ApiError> {
    let note = notes::edit(workspace, caller, params.step, &params.text, params.steps)?;
    Ok(EditedNote { step: params.step, note })
}

pub fn delete_note(workspace: &mut dyn Workspace, params: DeleteNoteParams) -> Result<DeletedNote, ApiError> {
    let note = notes::delete(workspace, params.step)?;
    Ok(DeletedNote { step: params.step, note })
}

pub fn export_notes(workspace: &mut dyn Workspace, params: ExportNotesParams) -> Result<ExportedNotes, ApiError> {
    let (markdown, count) = notes::markdown(workspace.journal());
    let Some(path) = params.path else { return Ok(ExportedNotes { notes: count, markdown: Some(markdown), path: None }) };
    std::fs::write(&path, markdown).map_err(|error| ApiError::new(ErrorCode::Unavailable, format!("could not write {path}: {error}")))?;
    Ok(ExportedNotes { notes: count, markdown: None, path: Some(path) })
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
    fn a_recipe_saved_from_the_history_carries_each_note_on_the_steps_it_links() {
        let mut workspace = workspace_with("flight.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42"})).unwrap();
        call(&mut workspace, "history.undo_step", json!({"step": 2})).unwrap();
        call(&mut workspace, "view.set_shape", json!({"width": 8})).unwrap();
        call(&mut workspace, "history.note", json!({"text": "#1 fixes the magic; #2 was a dead end"})).unwrap();
        call(&mut workspace, "history.note", json!({"text": "Narrower rows show the records", "steps": [4]})).unwrap();
        call(&mut workspace, "history.note", json!({"text": "And #4 lines up the length fields"})).unwrap();
        call(&mut workspace, "history.note", json!({"text": "A thought about nothing in particular"})).unwrap();
        let path = std::env::temp_dir().join(format!("theviewer-history-notes-{}.theviewer-recipe.json", std::process::id()));
        let saved = call(&mut workspace, "history.save_recipe", json!({"path": path.display().to_string(), "name": "Patch"})).unwrap();
        let recipe: crate::journal::Recipe = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(saved["steps"], json!([1, 2]), "notes are not steps of a recipe");
        let notes: Vec<Option<&str>> = recipe.steps.iter().map(|step| step.note.as_deref()).collect();
        assert_eq!(
            notes,
            [Some("#1 fixes the magic; session step 2 was a dead end"), Some("Narrower rows show the records\n\nAnd #2 lines up the length fields")],
            "renumbered as the recipe numbers its steps; the unlinked note is left out"
        );
    }

    #[test]
    fn a_note_chosen_among_the_journal_steps_of_a_recipe_is_not_one_of_its_steps() {
        let dir = std::env::temp_dir().join(format!("theviewer-history-notes-chosen-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        crate::recipes::use_dir_for_this_thread(dir.clone());
        let mut workspace = workspace_with("flight.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "history.note", json!({"text": "Why #1"})).unwrap();
        let saved = call(&mut workspace, "recipes.save", json!({"name": "Patch", "journal_steps": [1, 2]})).unwrap();
        let (recipe, _) = crate::recipes::find(&dir.clone(), "Patch").unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(saved["steps"], 1);
        assert_eq!((recipe.steps[0].method.as_str(), recipe.steps[0].note.as_deref()), ("bytes.write", Some("Why #1")));
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

    /// Call a method as the MCP client `claude-code`.
    fn call_as_client(workspace: &mut dyn crate::api::Workspace, name: &str, params: serde_json::Value) -> Result<serde_json::Value, crate::api::ApiError> {
        crate::api::call(workspace, &Caller::Mcp("claude-code".into()), name, params)
    }

    #[test]
    fn a_note_is_recorded_where_it_is_written_by_its_caller_and_linked_to_the_steps_it_cites() {
        let mut workspace = workspace_with("flight.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42"})).unwrap();
        let written = call_as_client(&mut workspace, "history.note", json!({"text": "#1 marks the header,\nso the payload starts after it", "steps": [2]})).unwrap();
        assert_eq!(written, json!({"step": 3, "steps": [1, 2]}));

        let listed = call(&mut workspace, "history.list", json!({})).unwrap();
        let note = &listed["entries"][2];
        assert_eq!((note["step"].as_u64(), note["caller"].as_str(), note["method"].as_str()), (Some(3), Some("mcp:claude-code"), Some("history.note")));
        assert_eq!(note["description"], "Note: #1 marks the header, so the payload starts after it");
        assert_eq!(note["note"], json!({"text": "#1 marks the header,\nso the payload starts after it", "steps": [1, 2]}));
        let beside = json!([{"step": 3, "caller": "mcp:claude-code", "text": "#1 marks the header,\nso the payload starts after it"}]);
        assert_eq!(listed["entries"][0]["notes"], beside, "the reasoning is listed beside the action");
        assert_eq!(call(&mut workspace, "history.entry", json!({"step": 2})).unwrap()["notes"], beside);
        assert_eq!(call(&mut workspace, "bytes.read", json!({"start": 0, "len": 2})).unwrap()["data"], "4142", "a note changes no document");
    }

    #[test]
    fn a_note_must_say_something_within_its_limit_and_cite_steps_that_exist() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        assert_eq!(call(&mut workspace, "history.note", json!({"text": "  \n"})).unwrap_err().code, ErrorCode::InvalidParams);
        let long = "x".repeat(crate::journal::notes::NOTE_TEXT_LIMIT + 1);
        assert_eq!(call(&mut workspace, "history.note", json!({"text": long})).unwrap_err().code, ErrorCode::TooLarge);
        let missing = call(&mut workspace, "history.note", json!({"text": "Compare #1 with #7", "steps": [9]})).unwrap_err();
        assert_eq!(missing.code, ErrorCode::NotFound);
        assert!(missing.message.contains("steps 7, 9"), "{}", missing.message);
        assert!(crate::api::Workspace::journal(&workspace).notes().next().is_none(), "no note was written");
    }

    #[test]
    fn a_note_citing_a_recent_read_keeps_that_read_in_the_history() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        call(&mut workspace, "bytes.read", json!({"start": 0, "len": 4})).unwrap();
        let written = call(&mut workspace, "history.note", json!({"text": "#1 shows the magic number"})).unwrap();
        assert_eq!(written["steps"], json!([1]));
        let read = call(&mut workspace, "history.entry", json!({"step": 1})).unwrap();
        assert_eq!((read["method"].as_str(), read["notes"][0]["step"].as_u64()), (Some("bytes.read"), Some(2)));
        let steps: Vec<u64> = crate::api::Workspace::journal(&workspace).entries().map(|entry| entry.step).collect();
        assert_eq!(steps, [1, 2], "the read was moved into the journal");
    }

    #[test]
    fn a_note_is_never_undone_repeated_or_undone_by_going_back_past_it() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "history.note", json!({"text": "Patched #1; now the length"})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42"})).unwrap();

        let undoing = call(&mut workspace, "history.undo_step", json!({"step": 2})).unwrap_err();
        assert_eq!(undoing.code, ErrorCode::Unavailable);
        assert!(undoing.message.contains("it is a note"), "{}", undoing.message);
        assert_eq!(call(&mut workspace, "history.inverse", json!({"step": 2})).unwrap()["status"], json!({"state": "note"}));

        call(&mut workspace, "history.go_back", json!({"step": 0})).unwrap();
        let journal = crate::api::Workspace::journal(&workspace);
        assert_eq!(journal.timeline().status(2), Some(crate::journal::timeline::StepStatus::Note), "going back past a note leaves it");
        assert!(matches!(journal.timeline().status(3), Some(crate::journal::timeline::StepStatus::Undone { .. })));
        assert!(crate::journal::timeline::steps_to_play(crate::api::Workspace::journal(&workspace), 1, 5).iter().all(|step| step.method != "history.note"), "playback skips notes");
    }

    #[test]
    fn a_note_is_written_on_its_own_not_inside_another_call() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        let inside = call(&mut workspace, "history.transaction", json!({"calls": [{"method": "history.note", "params": {"text": "inside"}}]})).unwrap_err();
        assert!(inside.message.contains("a note is written on its own"), "{}", inside.message);
        assert!(crate::api::Workspace::journal(&workspace).notes().next().is_none());
    }

    #[test]
    fn any_caller_may_write_a_note_without_being_asked_as_it_changes_nothing() {
        let mut app = crate::app::ViewerApp::new(crate::app::Launch::default());
        app.open_bytes(vec![0u8; 16], "a.bin".to_string());
        app.preferences.permissions.insert("mcp:claude-code".into(), crate::api::Policy::Ask);
        call_as_client(&mut app, "history.note", json!({"text": "Looking for the length field"})).unwrap();
        app.preferences.permissions.insert("mcp:claude-code".into(), crate::api::Policy::Deny);
        call_as_client(&mut app, "history.note", json!({"text": "Still looking"})).unwrap();
        assert_eq!(app.journal.notes().count(), 2);
    }

    #[test]
    fn editing_a_note_changes_it_in_place_and_says_who_edited_it() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42"})).unwrap();
        call(&mut workspace, "history.note", json!({"text": "Patched #1", "steps": [2]})).unwrap();
        let revision = crate::api::Workspace::journal(&workspace).revision();
        let edited = call_as_client(&mut workspace, "history.edit_note", json!({"step": 3, "text": "Patched the magic"})).unwrap();
        assert_eq!(edited["note"]["steps"], json!([2]), "the steps given before are kept; the text cites none now");
        assert_eq!(edited["note"]["edited_by"], "mcp:claude-code");
        assert!(edited["note"]["edited_at"].is_string());
        let journal = crate::api::Workspace::journal(&workspace);
        assert_eq!((journal.entries().len(), journal.last_step()), (3, Some(3)), "editing is not a step of its own");
        assert!(journal.revision() > revision, "followers see the change");
        let entry = call(&mut workspace, "history.entry", json!({"step": 3})).unwrap();
        assert_eq!((entry["description"].as_str(), entry["params"]["text"].as_str()), (Some("Note: Patched the magic"), Some("Patched the magic")));
        assert!(call(&mut workspace, "history.entry", json!({"step": 1})).unwrap().get("notes").is_none(), "step 1 no longer lists it");

        let relinked = call(&mut workspace, "history.edit_note", json!({"step": 3, "text": "Patched #1", "steps": []})).unwrap();
        assert_eq!(relinked["note"]["steps"], json!([1]));
        let itself = call(&mut workspace, "history.edit_note", json!({"step": 3, "text": "See #3"})).unwrap_err();
        assert_eq!(itself.code, ErrorCode::InvalidParams);
    }

    #[test]
    fn only_notes_can_be_edited_or_deleted() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        for (method, params) in [("history.edit_note", json!({"step": 1, "text": "no"})), ("history.delete_note", json!({"step": 1}))] {
            let refused = call(&mut workspace, method, params).unwrap_err();
            assert_eq!(refused.code, ErrorCode::InvalidParams, "{method}");
            assert_eq!(refused.data.as_ref().map(|data| data["reason"].clone()), Some(json!("not_a_note")), "{method}");
            assert!(refused.message.contains("step 1 is bytes.write, not a note"), "{}", refused.message);
        }
        assert_eq!(call(&mut workspace, "history.delete_note", json!({"step": 9})).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn deleting_a_note_takes_it_out_of_the_history_without_a_step_of_its_own() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "history.note", json!({"text": "A dead end: #1"})).unwrap();
        let deleted = call(&mut workspace, "history.delete_note", json!({"step": 2})).unwrap();
        assert_eq!(deleted["note"]["text"], "A dead end: #1");
        let listed = call(&mut workspace, "history.list", json!({})).unwrap();
        let steps: Vec<u64> = listed["entries"].as_array().unwrap().iter().map(|entry| entry["step"].as_u64().unwrap()).collect();
        assert_eq!(steps, [1]);
        assert!(listed["entries"][0].get("notes").is_none());
        assert_eq!(call(&mut workspace, "history.entry", json!({"step": 2})).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn the_notes_export_as_markdown_with_the_steps_they_cite() {
        let mut workspace = workspace_with("flight.bin", b"0123456789");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42"})).unwrap();
        call(&mut workspace, "history.undo_step", json!({"step": 2})).unwrap();
        call_as_client(&mut workspace, "history.note", json!({"text": "Why #1?\nBecause the magic was wrong.", "steps": [2]})).unwrap();
        call(&mut workspace, "history.note", json!({"text": "Nothing more to patch"})).unwrap();
        let exported = call(&mut workspace, "history.export_notes", json!({})).unwrap();
        assert_eq!(exported["notes"], 2);
        let markdown = exported["markdown"].as_str().unwrap();
        let journal = crate::api::Workspace::journal(&workspace);
        let (first, second) = (journal.entry(4).unwrap().at.clone(), journal.entry(5).unwrap().at.clone());
        let expected = format!(
            "# Notes on flight.bin\n\nSession started {}.\n\n## Note 4 · mcp:claude-code · {first}\n\nWhy #1?\nBecause the magic was wrong.\n\nSteps cited:\n\n\
- #1 · panel · Overwrite 1 byte at 0x0 with 41\n- #2 · panel · Overwrite 1 byte at 0x1 with 42 (undone by step 3)\n\n## Note 5 · panel · {second}\n\nNothing more to patch\n",
            journal.session().started_at
        );
        assert_eq!(markdown, expected);
    }

    #[test]
    fn writing_the_notes_to_a_file_needs_leave_to_edit() {
        let mut app = crate::app::ViewerApp::new(crate::app::Launch::default());
        app.open_bytes(vec![0u8; 16], "a.bin".to_string());
        call(&mut app, "history.note", json!({"text": "Start here"})).unwrap();
        app.preferences.permissions.insert("mcp:claude-code".into(), crate::api::Policy::Deny);
        let path = std::env::temp_dir().join(format!("theviewer-notes-{}.md", std::process::id()));
        let returned = call_as_client(&mut app, "history.export_notes", json!({})).unwrap();
        assert!(returned["markdown"].as_str().unwrap().contains("Start here"), "returning them is a read");
        let refused = call_as_client(&mut app, "history.export_notes", json!({"path": path.display().to_string()})).unwrap_err();
        assert_eq!(refused.code, ErrorCode::ReadOnly);
        assert!(!path.exists());
        let written = call(&mut app, "history.export_notes", json!({"path": path.display().to_string()})).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!((written["notes"].as_u64(), written.get("markdown")), (Some(1), None));
        assert!(text.starts_with("# Notes on a.bin"), "{text}");
        assert_eq!(app.journal.entries().len(), 1, "exporting is not a step");
    }
}
