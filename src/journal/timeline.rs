//! The journal as a timeline the person moves along: undoing steps that
//! changed no bytes through their inverses, going back to step N, and what
//! happens to the steps after it.
//!
//! The journal only grows. Moving back along it is itself a step
//! (`history.undo_step`, `history.go_back`, or the document's own
//! `history.undo` and `history.redo`), and the [`Timeline`] works out from
//! those steps which earlier ones are still in effect:
//!
//! * **Undoing one step** marks it undone by the step that undid it. A byte
//!   edit undoes as the document's own undo does, so only while it is the
//!   document's last edit; a step that changed no bytes undoes through its
//!   inverse (see [`inverse_of`]), so only while no later step changed the
//!   same thing.
//! * **Going back to step N** marks every step after N (up to the step that
//!   went back) undone. It is a branch: those steps stay in the journal,
//!   shown as undone, and are left out of recipes and playback. Steps taken
//!   afterwards follow on from step N.
//! * **The document's undo and redo** mark its last edit undone, or bring the
//!   last one undone back.
//!
//! Going back first tries the undo path: each later step undone through its
//! inverse, latest first (byte edits through the document's undo). When a
//! later step has no inverse, it replays instead: the document is brought
//! back to how the session first saw it, and steps 1 to N on it are run
//! again through [`super::replay::run`], which is deterministic, so the
//! result is the same.
//!
//! What each step's inverse is, method by method, is the table in
//! [`inverse_of`]; [`state_before`] says what a step is about to replace,
//! for the journal to keep as the inverse's target.

use std::collections::{BTreeMap, HashMap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::recipe::{Recipe, RecipeStep};
use super::replay::{self, ReplayOptions, RunReport, StepReport};
use super::{Journal, JournalEntry};
use crate::api::{self, ApiError, Caller, Effect, ErrorCode, Workspace};
use crate::bus::topics::TemplateApplied;

/// Undo one step of the journal.
pub const UNDO_STEP: &str = "history.undo_step";
/// Go back to a step of the journal.
pub const GO_BACK: &str = "history.go_back";
/// The document's own undo and redo of its last edit.
const UNDO: &str = "history.undo";
const REDO: &str = "history.redo";

/// Methods that move along the timeline rather than take a step of the
/// analysis: shown in the history, never repeated.
const MOVES_ALONG_THE_TIMELINE: &[&str] = &[UNDO_STEP, GO_BACK, UNDO, REDO];

/// Methods that open a document and make it current.
const OPENS_DOCUMENT: &[&str] = &[
    "documents.open",
    "documents.new",
    "documents.open_source",
    "documents.derive",
    "codecs.open_decoded",
    "bits.open_plane",
    "bits.decode_linecode",
    "forensics.open_entry",
    "unpack.open",
    "sources.view_version",
];

/// Of [`OPENS_DOCUMENT`], those that open a document derived from the one
/// they are about, which was current when they were called.
const DERIVES_DOCUMENT: &[&str] = &["documents.derive", "codecs.open_decoded", "bits.open_plane", "bits.decode_linecode", "forensics.open_entry", "unpack.open", "sources.view_version"];

/// Methods that write a file and leave the document as it is: there is
/// nothing in the document or view to undo.
const WRITES_A_FILE: &[&str] = &["documents.save", "documents.export", "unpack.save", "learn.save_catalogue", "history.save_recipe", "packets.export_pcap", "packets.extract"];

/// Who pinned templates are published as.
const TEMPLATES_PRODUCER: &str = "tool:templates";

/// Methods going back does not run again: those that open, save or write
/// files, reload plugins or start live sources, and moves along the
/// timeline.
const NOT_REPLAYED: &[&str] = &["plugins.reload", "sources.watch", "sources.record", "sources.stop", "history.save_recipe"];

/// Where a step stands on the timeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StepStatus {
    /// In effect: part of the analysis as it stands.
    Active,
    /// It failed or was refused, and changed nothing.
    Failed,
    /// Undone, by the step `by` (an undo, an undo of this step, or going
    /// back to an earlier step).
    Undone { by: u64 },
    /// A move along the timeline itself: an undo, a redo, an undo of a
    /// step, or going back.
    Move,
}

/// The journal's steps with where each stands: in effect, undone (and by
/// what), failed, or a move along the timeline.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Timeline {
    statuses: BTreeMap<u64, StepStatus>,
    /// Each document's edits in effect, oldest first: the document's undo
    /// stack, as far as the journal saw it.
    edits: HashMap<String, Vec<u64>>,
    /// Each document's edits undone that a redo brings back, the next to
    /// redo last.
    undone_edits: HashMap<String, Vec<u64>>,
}

impl Timeline {
    /// The timeline of everything `journal` holds.
    pub fn of(journal: &Journal) -> Timeline {
        let mut timeline = Timeline::default();
        for entry in journal.entries() {
            timeline.follow(entry);
        }
        timeline
    }

    /// Where `step` stands; `None` when the journal holds no such step.
    pub fn status(&self, step: u64) -> Option<StepStatus> {
        self.statuses.get(&step).copied()
    }

    /// Whether `step` is in effect.
    pub fn is_active(&self, step: u64) -> bool {
        self.status(step) == Some(StepStatus::Active)
    }

    /// The steps in effect, in step order.
    pub fn active_steps(&self) -> impl Iterator<Item = u64> + '_ {
        self.statuses.iter().filter(|(_, status)| **status == StepStatus::Active).map(|(step, _)| *step)
    }

    /// The step that made document `doc`'s last edit still in effect.
    pub fn last_edit(&self, doc: &str) -> Option<u64> {
        self.edits.get(doc).and_then(|edits| edits.last().copied())
    }

    /// Take in the next entry of the journal.
    fn follow(&mut self, entry: &JournalEntry) {
        let step = entry.step;
        if !entry.outcome.is_ok() {
            self.statuses.insert(step, StepStatus::Failed);
            return;
        }
        let doc = entry.doc.clone().unwrap_or_default();
        match entry.method.as_str() {
            UNDO => {
                self.statuses.insert(step, StepStatus::Move);
                if entry.changed_document()
                    && let Some(undone) = self.edits.get_mut(&doc).and_then(Vec::pop)
                {
                    self.statuses.insert(undone, StepStatus::Undone { by: step });
                    self.undone_edits.entry(doc).or_default().push(undone);
                }
            }
            REDO => {
                self.statuses.insert(step, StepStatus::Move);
                if entry.changed_document()
                    && let Some(redone) = self.undone_edits.get_mut(&doc).and_then(Vec::pop)
                {
                    self.statuses.insert(redone, StepStatus::Active);
                    self.edits.entry(doc).or_default().push(redone);
                }
            }
            UNDO_STEP => {
                self.statuses.insert(step, StepStatus::Move);
                if let Some(target) = entry.params.get("step").and_then(Value::as_u64) {
                    self.undo_one(target, step);
                }
            }
            GO_BACK => {
                self.statuses.insert(step, StepStatus::Move);
                let target = entry.params.get("step").and_then(Value::as_u64).unwrap_or(0);
                let replayed = entry.result.as_ref().and_then(|result| result.get("way")).and_then(Value::as_str) == Some("replayed");
                self.go_back(target, step, replayed);
            }
            _ => {
                self.statuses.insert(step, StepStatus::Active);
                if entry.effect == Effect::Edit && entry.changed_document() {
                    self.edits.entry(doc.clone()).or_default().push(step);
                    self.undone_edits.remove(&doc);
                }
            }
        }
    }

    /// Mark `target` undone by step `by`; an edit leaves its document's
    /// stack for the redo stack, as the document's own undo does.
    fn undo_one(&mut self, target: u64, by: u64) {
        if !self.is_active(target) {
            return;
        }
        self.statuses.insert(target, StepStatus::Undone { by });
        for (doc, edits) in &mut self.edits {
            if edits.last() == Some(&target) {
                edits.pop();
                self.undone_edits.entry(doc.clone()).or_default().push(target);
                return;
            }
        }
    }

    /// Mark every step in effect after `target` undone by step `by`. When
    /// they were undone (not replayed over), their edits wait to be redone,
    /// latest first.
    fn go_back(&mut self, target: u64, by: u64, replayed: bool) {
        let later: Vec<u64> = self.statuses.range(target + 1..by).filter(|(_, status)| **status == StepStatus::Active).map(|(step, _)| *step).collect();
        for step in later {
            self.statuses.insert(step, StepStatus::Undone { by });
        }
        for (doc, edits) in &mut self.edits {
            let kept = edits.partition_point(|step| *step <= target);
            let undone: Vec<u64> = edits.split_off(kept);
            let waiting = self.undone_edits.entry(doc.clone()).or_default();
            if replayed {
                waiting.clear();
            } else {
                waiting.extend(undone.into_iter().rev());
            }
        }
    }
}

/// Whether `method` moves along the timeline rather than analysing.
pub fn moves_along_the_timeline(method: &str) -> bool {
    MOVES_ALONG_THE_TIMELINE.contains(&method)
}

// ---------------------------------------------------------------------------
// What each step changed, and its inverse
// ---------------------------------------------------------------------------

/// What a step that changes no bytes changes: a step's inverse restores
/// it, and a later step changing the same thing stands in its way.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Changes {
    /// The shape the document's bytes are drawn in.
    Shape,
    /// The ranges skipped in the views.
    Folds,
    /// The bookmark at an offset.
    Bookmark(u64),
    /// The selection and cursor.
    Selection,
    /// Which document is current.
    CurrentDocument,
    /// The template pinned over the document.
    Template,
    /// How a packet set decodes frames of unknown format.
    Decoding(String),
    /// The findings the caller published under a key.
    Findings(String),
}

impl Changes {
    fn of(method: &str, params: &Value) -> Option<Changes> {
        let changes = match method {
            "view.set_shape" => Changes::Shape,
            "view.fold" | "view.unfold" => Changes::Folds,
            "bookmarks.add" | "bookmarks.remove" => Changes::Bookmark(params.get("start").and_then(Value::as_u64)?),
            "selection.set" | "cursor.set" => Changes::Selection,
            "templates.clear" => Changes::Template,
            "templates.apply" | "templates.infer" if params.get("pin").and_then(Value::as_bool) == Some(true) => Changes::Template,
            "packets.decode_as" => Changes::Decoding(params.get("set").and_then(Value::as_str)?.to_string()),
            "findings.publish" | "findings.retract" => Changes::Findings(params.get("key").and_then(Value::as_str).unwrap_or_default().to_string()),
            method if OPENS_DOCUMENT.contains(&method) => Changes::CurrentDocument,
            _ => return None,
        };
        Some(changes)
    }

    /// Whether `entry` changes the same thing as `of` does: on the same
    /// document, except which document is current (the session's) and a
    /// packet set's decoding (the set's); findings are also their caller's.
    fn same_as(&self, of: &JournalEntry, entry: &JournalEntry) -> bool {
        if Changes::of(&entry.method, &entry.params).as_ref() != Some(self) {
            return false;
        }
        match self {
            Changes::CurrentDocument | Changes::Decoding(_) => true,
            Changes::Findings(_) => entry.caller == of.caller && entry.doc == of.doc,
            _ => entry.doc == of.doc,
        }
    }

    /// What it was after `entry` made its change, in the form
    /// [`state_before`] gives, read from the entry's result.
    fn after(&self, entry: &JournalEntry) -> Option<Value> {
        let result = entry.result.as_ref()?;
        match self {
            Changes::Shape => Some(json!({"shape": result.get("shape")?})),
            Changes::Folds => Some(json!({"folds": result.get("folds")?})),
            Changes::Bookmark(_) => Some(json!({"bookmarks": result.get("bookmarks")?})),
            Changes::Selection if entry.method == "cursor.set" => Some(json!({"selection": null, "cursor": result.get("offset")?})),
            Changes::Selection => Some(json!({"selection": result.get("selection")?, "cursor": entry.params.get("cursor").cloned().unwrap_or(Value::Null)})),
            Changes::CurrentDocument => {
                let id = result.get("id").or_else(|| result.get("document").and_then(|document| document.get("id")))?;
                Some(json!({"current": id}))
            }
            Changes::Template if entry.method == "templates.clear" => Some(json!({"template": null})),
            Changes::Template => Some(json!({"template": {"method": entry.method, "params": entry.params}})),
            Changes::Decoding(_) => Some(json!({"decoding": entry.params})),
            Changes::Findings(_) if entry.method == "findings.retract" => Some(json!({"findings": null})),
            Changes::Findings(_) => Some(json!({"findings": entry.params.get("findings")?})),
        }
    }
}

/// What a step of `method` with `params` is about to replace, for its
/// inverse: called before the step runs, so that the first change of a
/// shape, a selection or a bookmark can be undone too. `None` for methods
/// whose inverse needs nothing kept.
///
/// The value is `{"shape"}`, `{"folds"}`, `{"bookmarks"}`, `{"selection",
/// "cursor"}` or `{"current"}`, as [`inverse_of`] reads it.
pub fn state_before(workspace: &mut dyn Workspace, method: &str, params: &Value) -> Option<Value> {
    let changes = Changes::of(method, params)?;
    match &changes {
        Changes::CurrentDocument => return Some(json!({"current": workspace.current_document()?})),
        Changes::Decoding(set) => return decoding_of(workspace, set),
        _ => {}
    }
    let named = params.get("doc").and_then(Value::as_str);
    let id = api::workspace::resolve(workspace, named).ok()?;
    match changes {
        Changes::Shape => Some(json!({"shape": workspace.shape(&id)?})),
        Changes::Folds => {
            let folds: Vec<(u64, u64)> = workspace.folds(&id)?.ranges().iter().map(|&(start, len)| (start as u64, len as u64)).collect();
            Some(json!({"folds": folds}))
        }
        Changes::Bookmark(_) => {
            let bookmarks: Vec<Value> = workspace.bookmarks(&id)?.iter().map(|bookmark| json!({"start": bookmark.offset, "len": bookmark.len, "name": bookmark.name})).collect();
            Some(json!({"bookmarks": bookmarks}))
        }
        Changes::Selection => {
            let view = workspace.view(&id)?;
            Some(json!({"selection": view.selection, "cursor": view.cursor}))
        }
        Changes::Template => {
            let pinned = workspace.bus().latest_from::<TemplateApplied>(&id, TEMPLATES_PRODUCER).map(|(_, applied)| (applied.source.clone(), applied.structure.start));
            match pinned {
                Some((source, at)) if !source.is_empty() => Some(json!({"template": {"method": "templates.apply", "params": {"doc": id, "source": source, "at": at, "pin": true}}})),
                Some(_) => None,
                None => Some(json!({"template": null})),
            }
        }
        Changes::CurrentDocument | Changes::Decoding(_) | Changes::Findings(_) => None,
    }
}

/// How packet set `set` decodes frames now, as `packets.decode_as`'s
/// parameters; `None` when a template given as source text is not kept.
fn decoding_of(workspace: &dyn Workspace, set: &str) -> Option<Value> {
    let info = &workspace.packet_sets().get(set)?.info;
    if info.template && info.template_name.is_none() {
        return None;
    }
    let mut params = json!({"set": set, "protocol": info.decode_as, "detect": info.detect, "link": info.link});
    if let Some(name) = &info.template_name {
        let field = if name == "protocol" { "template" } else { "template_name" };
        params[field] = json!(name);
    }
    Some(json!({"decoding": params}))
}

/// One call that undoes (part of) a step.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InverseCall {
    pub method: String,
    pub params: Value,
    /// Who it is called as, when not the caller undoing: findings are
    /// withdrawn as the caller that published them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
}

impl InverseCall {
    fn new(method: &str, params: Value) -> Self {
        InverseCall { method: method.to_string(), params, caller: None }
    }

    fn as_caller(method: &str, params: Value, caller: Option<String>) -> Self {
        InverseCall { method: method.to_string(), params, caller }
    }
}

/// How a step can be undone.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Inverse {
    /// By making these calls, in order.
    Calls { calls: Vec<InverseCall> },
    /// It left nothing in the document or view to undo (a job's results, a
    /// file written, a read, a failure); undoing it only takes it out of
    /// the analysis.
    Nothing { why: String },
    /// It cannot be undone now, for the reason given.
    Unavailable { why: String },
}

impl Inverse {
    fn unavailable(why: impl Into<String>) -> Self {
        Inverse::Unavailable { why: why.into() }
    }

    fn nothing(why: impl Into<String>) -> Self {
        Inverse::Nothing { why: why.into() }
    }

    fn calls(calls: Vec<InverseCall>) -> Self {
        Inverse::Calls { calls }
    }

    /// Whether the step can be undone.
    pub fn is_available(&self) -> bool {
        !matches!(self, Inverse::Unavailable { .. })
    }
}

/// How the step numbered `step` would be undone now, on its own: through
/// the document's undo for a byte edit that is its last, through the
/// inverse of a step that changed no bytes while nothing later changed the
/// same thing, or not at all.
///
/// | Step | Inverse |
/// | --- | --- |
/// | a byte edit (`bytes.*`, `transform.apply`, `packets.*` edits, a transaction) | `history.undo`, while it is the document's last edit |
/// | `view.set_shape` | `view.set_shape` back to the shape before |
/// | `view.fold`, `view.unfold` | `view.unfold {all}`, then `view.fold` the ranges skipped before |
/// | `bookmarks.add` | `bookmarks.remove`, or `bookmarks.add` of the bookmark it replaced |
/// | `bookmarks.remove` | `bookmarks.add` of the bookmark removed |
/// | `selection.set`, `cursor.set` | `selection.set` or `cursor.set` back to what was selected before |
/// | a method opening a document (`documents.open`, `documents.derive`, `codecs.open_decoded`…) | `documents.open` of the document current before |
/// | `templates.clear` | `templates.apply` of the template pinned before |
/// | `templates.apply`/`infer` with `pin` | the template pinned before, or `templates.clear` |
/// | `packets.sets.create` | `packets.sets.remove`, while no later step uses the set |
/// | `packets.decode_as` | `packets.decode_as` back to the set's decoding before |
/// | `findings.publish`, `findings.retract` | the findings published before under the key, or `findings.retract`, as their caller |
/// | a job, `jobs.cancel`, a file written, a read, a template applied unpinned, a failed step | nothing to undo |
/// | anything else (`packets.sets.remove`, `protocol.choose_framing`, `sources.*`, `plugins.reload`…) | none |
pub fn inverse_of(workspace: &mut dyn Workspace, step: u64) -> Inverse {
    let timeline = Timeline::of(workspace.journal());
    let Some(entry) = workspace.journal().entry(step).cloned() else {
        return Inverse::unavailable(format!("step {step} is not in the journal"));
    };
    match timeline.status(step) {
        Some(StepStatus::Move) => return Inverse::unavailable("it moves along the history itself: redo, or go back to a step"),
        Some(StepStatus::Undone { by }) => return Inverse::unavailable(format!("it is already undone, by step {by}")),
        _ => {}
    }
    if let Some(blocker) = later_change_of_the_same(workspace.journal(), &timeline, &entry) {
        return Inverse::unavailable(format!("step {blocker} changed the same thing since; undo it first, or go back to step {}", step.saturating_sub(1)));
    }
    if is_byte_edit(&entry) {
        return edit_inverse(workspace, &timeline, &entry);
    }
    let before = before_of(workspace.journal(), &timeline, &entry);
    view_inverse(&entry, before)
}

/// Whether `entry` changed its document's bytes as an undoable edit.
fn is_byte_edit(entry: &JournalEntry) -> bool {
    entry.outcome.is_ok() && entry.effect == Effect::Edit && entry.changed_document() && !moves_along_the_timeline(&entry.method)
}

/// A later step in effect that changed what `entry` changed.
fn later_change_of_the_same(journal: &Journal, timeline: &Timeline, entry: &JournalEntry) -> Option<u64> {
    if !entry.outcome.is_ok() {
        return None;
    }
    let mut later = journal.since(entry.step).filter(|later| timeline.is_active(later.step));
    if let Some(set) = set_created(entry) {
        return later.find(|later| later.params.get("set").and_then(Value::as_str) == Some(set)).map(|later| later.step);
    }
    let changes = Changes::of(&entry.method, &entry.params)?;
    later.find(|later| changes.same_as(entry, later)).map(|later| later.step)
}

/// The packet set `entry` created, when it is a `packets.sets.create`.
fn set_created(entry: &JournalEntry) -> Option<&str> {
    if entry.method != "packets.sets.create" {
        return None;
    }
    entry.result.as_ref()?.get("set")?.as_str()
}

/// The document's undo, while `entry` is its last edit.
fn edit_inverse(workspace: &mut dyn Workspace, timeline: &Timeline, entry: &JournalEntry) -> Inverse {
    let Some(doc) = entry.doc.clone() else { return Inverse::unavailable("the journal does not say which document it edited") };
    if let Some(last) = timeline.last_edit(&doc).filter(|last| *last != entry.step) {
        return Inverse::unavailable(format!("step {last} edited {doc} since; undo it first, or go back to step {}", entry.step.saturating_sub(1)));
    }
    if let Err(why) = is_top_of_undo(workspace, &doc, entry) {
        return Inverse::unavailable(why);
    }
    Inverse::calls(vec![InverseCall::new(UNDO, json!({"doc": doc}))])
}

/// Whether the document's next undo would reverse `entry`: it has one, and
/// its name is the edit's, where the edit returned one.
fn is_top_of_undo(workspace: &mut dyn Workspace, doc: &str, entry: &JournalEntry) -> Result<(), String> {
    let Some(document) = workspace.document_mut(doc) else { return Err(format!("{doc} is no longer open")) };
    if !document.can_undo() {
        return Err(format!("{doc} has nothing left to undo"));
    }
    let label = entry.result.as_ref().and_then(|result| result.get("label")).and_then(Value::as_str);
    match (label, document.undo_label()) {
        (Some(expected), Some(next)) if expected != next => Err(format!("{doc}'s next undo is \"{next}\", made outside the journal; undo it first")),
        _ => Ok(()),
    }
}

/// What `entry` replaced: as kept when it ran ([`state_before`]), or else
/// as the step before it that changed the same thing left it.
fn before_of(journal: &Journal, timeline: &Timeline, entry: &JournalEntry) -> Option<Value> {
    if entry.before.is_some() {
        return entry.before.clone();
    }
    let changes = Changes::of(&entry.method, &entry.params)?;
    let earlier = journal
        .entries()
        .chain(journal.reads())
        .filter(|earlier| earlier.step < entry.step && earlier.outcome.is_ok() && changes.same_as(entry, earlier))
        .filter(|earlier| !matches!(timeline.status(earlier.step), Some(StepStatus::Failed | StepStatus::Move)))
        .max_by_key(|earlier| earlier.step);
    match earlier {
        // A step undone left things as they were before it.
        Some(earlier) if matches!(timeline.status(earlier.step), Some(StepStatus::Undone { .. })) => before_of(journal, timeline, earlier),
        Some(earlier) => changes.after(earlier),
        None => first_before(&changes, entry),
    }
}

/// What was there before the first step that changed it, where that is
/// known without having kept it: nothing skipped, and for a derived
/// document the one it was derived from.
fn first_before(changes: &Changes, entry: &JournalEntry) -> Option<Value> {
    match changes {
        Changes::Folds => Some(json!({"folds": []})),
        Changes::CurrentDocument if DERIVES_DOCUMENT.contains(&entry.method.as_str()) => Some(json!({"current": entry.doc.as_ref()?})),
        _ => None,
    }
}

/// The inverse of a step that changed no bytes, given what it replaced.
fn view_inverse(entry: &JournalEntry, before: Option<Value>) -> Inverse {
    if !entry.outcome.is_ok() {
        return Inverse::nothing("it failed, and changed nothing");
    }
    if let Some(set) = set_created(entry) {
        return Inverse::calls(vec![InverseCall::new("packets.sets.remove", json!({"set": set}))]);
    }
    let Some(changes) = Changes::of(&entry.method, &entry.params) else {
        return leaves_nothing_to_undo(entry).unwrap_or_else(|| Inverse::unavailable(format!("{} has no inverse", entry.method)));
    };
    let doc = entry.doc.clone().map_or(Value::Null, Value::String);
    let unknown = || Inverse::unavailable("what it replaced is not known");
    match changes {
        Changes::Shape => {
            let Some(shape) = before.as_ref().and_then(|before| before.get("shape")) else { return unknown() };
            let mut params = shape.clone();
            params["doc"] = doc;
            Inverse::calls(vec![InverseCall::new("view.set_shape", params)])
        }
        Changes::Folds => {
            let Some(folds) = before.as_ref().and_then(|before| before.get("folds")).and_then(Value::as_array) else { return unknown() };
            let mut calls = vec![InverseCall::new("view.unfold", json!({"doc": doc, "all": true}))];
            if !folds.is_empty() {
                calls.push(InverseCall::new("view.fold", json!({"doc": doc, "ranges": folds})));
            }
            Inverse::calls(calls)
        }
        Changes::Bookmark(start) => {
            let replaced = before.as_ref().and_then(|before| before.get("bookmarks")).and_then(Value::as_array).map(|bookmarks| bookmarks.iter().find(|bookmark| bookmark.get("start").and_then(Value::as_u64) == Some(start)).cloned());
            match (entry.method.as_str(), replaced) {
                (_, Some(Some(bookmark))) => Inverse::calls(vec![InverseCall::new("bookmarks.add", json!({"doc": doc, "start": start, "len": bookmark.get("len").cloned().unwrap_or(json!(0)), "name": bookmark.get("name").cloned().unwrap_or(json!(""))}))]),
                // Not known: an added bookmark is taken to have replaced none.
                ("bookmarks.add", _) => Inverse::calls(vec![InverseCall::new("bookmarks.remove", json!({"doc": doc, "start": start}))]),
                _ => unknown(),
            }
        }
        Changes::Selection => {
            let Some(before) = before else { return unknown() };
            let cursor = before.get("cursor").filter(|cursor| !cursor.is_null());
            match (before.get("selection").filter(|selection| !selection.is_null()), cursor) {
                (Some(selection), cursor) => {
                    let mut params = json!({"doc": doc, "selection": selection});
                    if let Some(cursor) = cursor {
                        params["cursor"] = cursor.clone();
                    }
                    Inverse::calls(vec![InverseCall::new("selection.set", params)])
                }
                (None, Some(cursor)) => Inverse::calls(vec![InverseCall::new("cursor.set", json!({"doc": doc, "offset": cursor}))]),
                (None, None) => Inverse::calls(vec![InverseCall::new("selection.set", json!({"doc": doc, "selection": null}))]),
            }
        }
        Changes::CurrentDocument => match before.as_ref().and_then(|before| before.get("current")).and_then(Value::as_str) {
            Some(current) => Inverse::calls(vec![InverseCall::new("documents.open", json!({"doc": current}))]),
            None => unknown(),
        },
        Changes::Decoding(set) => match before.as_ref().and_then(|before| before.get("decoding")) {
            Some(decoding) => {
                let mut params = decoding.clone();
                params["set"] = json!(set);
                Inverse::calls(vec![InverseCall::new("packets.decode_as", params)])
            }
            None => unknown(),
        },
        Changes::Findings(key) => {
            let caller = Some(entry.caller.clone());
            match before.as_ref().map(|before| before.get("findings").cloned().unwrap_or(Value::Null)) {
                Some(Value::Null) => Inverse::calls(vec![InverseCall::as_caller("findings.retract", json!({"doc": doc, "key": key}), caller)]),
                Some(findings) => Inverse::calls(vec![InverseCall::as_caller("findings.publish", json!({"doc": doc, "key": key, "findings": findings}), caller)]),
                // Never published under the key before: nothing to put back.
                None if entry.method == "findings.publish" => Inverse::calls(vec![InverseCall::as_caller("findings.retract", json!({"doc": doc, "key": key}), caller)]),
                None => unknown(),
            }
        }
        Changes::Template => match before.as_ref().map(|before| before.get("template").cloned().unwrap_or(Value::Null)) {
            Some(Value::Null) => Inverse::calls(vec![InverseCall::new("templates.clear", json!({"doc": doc}))]),
            Some(pinned) => match (pinned.get("method").and_then(Value::as_str), pinned.get("params")) {
                (Some(method), Some(params)) => Inverse::calls(vec![InverseCall::new(method, params.clone())]),
                _ => unknown(),
            },
            None => unknown(),
        },
    }
}

/// Why `entry` left nothing in the document or view to undo, when it did:
/// a job, a read, a file written, or an edit that changed no bytes.
fn leaves_nothing_to_undo(entry: &JournalEntry) -> Option<Inverse> {
    let why = if entry.effect == Effect::Job {
        "a job only adds results, which stay"
    } else if entry.effect == Effect::Read {
        "a read changes nothing"
    } else if WRITES_A_FILE.contains(&entry.method.as_str()) {
        "it wrote a file, which stays as written"
    } else if entry.effect == Effect::Edit && !entry.changed_document() {
        "it changed no bytes"
    } else if entry.method == "jobs.cancel" {
        "a job cancelled stays cancelled; run it again instead"
    } else if matches!(entry.method.as_str(), "templates.apply" | "templates.infer") {
        "it only returned fields, pinning nothing"
    } else {
        return None;
    };
    Some(Inverse::nothing(why))
}

/// Make `calls` inside the call that undoes, as `caller`, stopping at the
/// first that fails.
fn make_calls(workspace: &mut dyn Workspace, caller: &Caller, calls: &[InverseCall], undoing: u64) -> Result<(), ApiError> {
    for call in calls {
        let caller = call.caller.as_deref().map_or_else(|| caller.clone(), Caller::from_producer);
        api::call_permitted(workspace, &caller, &call.method, call.params.clone()).map_err(|error| ApiError::new(error.code, format!("undoing step {undoing}, {} failed: {}", call.method, error.message)))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Undoing one step
// ---------------------------------------------------------------------------

/// What undoing one step did.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UndoneStep {
    /// The step undone.
    pub step: u64,
    /// Its method.
    pub method: String,
    /// The calls that undid it, in order; none when it left nothing to
    /// undo.
    pub calls: Vec<InverseCall>,
    /// Why nothing was called, when nothing was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Undo the step numbered `step` as `caller` through its inverse (see
/// [`inverse_of`]); it is then marked undone by the call doing this.
pub fn undo_step(workspace: &mut dyn Workspace, caller: &Caller, step: u64) -> Result<UndoneStep, ApiError> {
    let Some(method) = workspace.journal().entry(step).map(|entry| entry.method.clone()) else {
        return Err(ApiError::not_found(format!("there is no step {step} to undo; history.list shows the steps held")));
    };
    match inverse_of(workspace, step) {
        Inverse::Calls { calls } => {
            make_calls(workspace, caller, &calls, step)?;
            Ok(UndoneStep { step, method, calls, note: None })
        }
        Inverse::Nothing { why } => Ok(UndoneStep { step, method, calls: Vec::new(), note: Some(why) }),
        Inverse::Unavailable { why } => Err(ApiError::new(ErrorCode::Unavailable, format!("step {step} ({method}) cannot be undone: {why}"))),
    }
}

// ---------------------------------------------------------------------------
// Going back to step N
// ---------------------------------------------------------------------------

/// How going back reached the step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Way {
    /// Every later step was undone through its inverse, latest first.
    Undone,
    /// The document was brought back to how the session first saw it, and
    /// the steps up to N run again.
    Replayed,
}

/// A later step going back could not undo, which stays as it is.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct KeptStep {
    pub step: u64,
    pub method: String,
    pub why: String,
}

/// What going back to a step did.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WentBack {
    /// The step gone back to: everything after it is undone. 0 is before
    /// the first step.
    pub step: u64,
    pub way: Way,
    /// The later steps undone, latest first.
    pub undone: Vec<u64>,
    /// The later steps that changed what they changed for good (no
    /// inverse), and stay as they are.
    #[serde(default)]
    pub kept: Vec<KeptStep>,
    /// The document brought back and replayed, when it was replayed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    /// What running the steps again did, when they were.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replayed: Option<RunReport>,
}

/// How steps are run again: [`replay::run`], or a stand-in in tests.
pub type Runner = fn(&mut dyn Workspace, &[RecipeStep], &ReplayOptions) -> RunReport;

/// Go back to step `step` as `caller`: undo every later step in effect, or
/// replay steps 1 to `step` from the document as first seen when a later
/// step has no inverse. Steps 0 goes back to before the first step.
pub fn go_back(workspace: &mut dyn Workspace, caller: &Caller, step: u64) -> Result<WentBack, ApiError> {
    go_back_with(workspace, caller, step, replay::run)
}

/// [`go_back`], running steps again with `runner`.
pub fn go_back_with(workspace: &mut dyn Workspace, caller: &Caller, step: u64, runner: Runner) -> Result<WentBack, ApiError> {
    let journal = workspace.journal();
    if step != 0 && journal.entry(step).is_none() {
        return Err(ApiError::not_found(format!("there is no step {step} to go back to; history.list shows the steps held")));
    }
    let timeline = Timeline::of(journal);
    let later: Vec<JournalEntry> = journal.since(step).filter(|entry| timeline.is_active(entry.step)).cloned().collect();
    match plan_undo(workspace, &timeline, &later) {
        Ok(plan) => {
            for (undoing, calls) in &plan {
                make_calls(workspace, caller, calls, *undoing)?;
            }
            Ok(WentBack { step, way: Way::Undone, undone: plan.iter().map(|(undoing, _)| *undoing).collect(), kept: Vec::new(), doc: None, replayed: None })
        }
        Err(_) => replay_up_to(workspace, caller, step, &timeline, &later, runner),
    }
}

/// The calls that undo each of `later` (in step order), latest first, or
/// the first step that has no inverse.
fn plan_undo(workspace: &mut dyn Workspace, timeline: &Timeline, later: &[JournalEntry]) -> Result<Vec<(u64, Vec<InverseCall>)>, KeptStep> {
    let journal = workspace.journal().clone();
    let mut checked_documents: Vec<String> = Vec::new();
    let mut plan = Vec::new();
    for entry in later.iter().rev() {
        let kept = |why: String| KeptStep { step: entry.step, method: entry.method.clone(), why };
        if is_byte_edit(entry) {
            let doc = entry.doc.clone().ok_or_else(|| kept("the journal does not say which document it edited".into()))?;
            // Undone latest first, each edit is its document's last in turn
            // once the document's last undo is the journal's last edit.
            if !checked_documents.contains(&doc) {
                is_top_of_undo(workspace, &doc, entry).map_err(kept)?;
                checked_documents.push(doc.clone());
            }
            plan.push((entry.step, vec![InverseCall::new(UNDO, json!({"doc": doc}))]));
            continue;
        }
        match view_inverse(entry, before_of(&journal, timeline, entry)) {
            Inverse::Calls { calls } => plan.push((entry.step, calls)),
            Inverse::Nothing { .. } => plan.push((entry.step, Vec::new())),
            Inverse::Unavailable { why } => return Err(kept(why)),
        }
    }
    Ok(plan)
}

/// Going back by replaying: undo what can be undone of `later`, bring the
/// document of step `step` back to how the session first saw it, and run
/// the steps in effect on it up to `step` again.
fn replay_up_to(workspace: &mut dyn Workspace, caller: &Caller, step: u64, timeline: &Timeline, later: &[JournalEntry], runner: Runner) -> Result<WentBack, ApiError> {
    let journal = workspace.journal().clone();
    let doc = journal
        .entry(step)
        .and_then(|entry| entry.doc.clone())
        .or_else(|| later.iter().find_map(|entry| entry.doc.clone()))
        .or_else(|| workspace.current_document())
        .ok_or_else(|| ApiError::not_found("there is no document to go back on"))?;
    let mut undone = Vec::new();
    let mut kept = Vec::new();
    for entry in later.iter().rev() {
        let outcome = if is_byte_edit(entry) {
            match entry.doc.as_deref() {
                // Bringing the document back undoes its edits.
                Some(edited) if edited == doc => Ok(Vec::new()),
                // Latest first, each is the other document's last in turn.
                Some(edited) => is_top_of_undo(workspace, edited, entry).map(|()| vec![InverseCall::new(UNDO, json!({"doc": edited}))]),
                None => Err("the journal does not say which document it edited".to_string()),
            }
        } else {
            match view_inverse(entry, before_of(&journal, timeline, entry)) {
                Inverse::Calls { calls } => Ok(calls),
                Inverse::Nothing { .. } => Ok(Vec::new()),
                other => Err(why_of(other)),
            }
        };
        let outcome = outcome.and_then(|calls| make_calls(workspace, caller, &calls, entry.step).map_err(|error| error.message));
        match outcome {
            Ok(()) => undone.push(entry.step),
            Err(why) => kept.push(KeptStep { step: entry.step, method: entry.method.clone(), why }),
        }
    }
    bring_back_as_first_seen(workspace, caller, &doc)?;
    let steps: Vec<RecipeStep> = journal
        .entries()
        .filter(|entry| entry.step <= step && timeline.is_active(entry.step) && entry.doc.as_deref() == Some(doc.as_str()) && is_replayed(&entry.method))
        .map(|entry| RecipeStep { step: entry.step, method: entry.method.clone(), params: entry.params.clone(), note: None })
        .collect();
    let mut options = ReplayOptions::new(caller.clone());
    // Going back was allowed; the steps it runs again are not asked about.
    options.consented = true;
    options.doc = Some(doc.clone());
    options.through_step = Some(step);
    let report = runner(workspace, &steps, &options);
    if let Some(stopped) = &report.stopped {
        let message = format!("going back to step {step}, running step {} again failed: {}", stopped.step, stopped.error.message);
        return Err(ApiError::new(stopped.error.code, message).with_data(serde_json::to_value(&report).unwrap_or(Value::Null)));
    }
    Ok(WentBack { step, way: Way::Replayed, undone, kept, doc: Some(doc), replayed: Some(report) })
}

fn why_of(inverse: Inverse) -> String {
    match inverse {
        Inverse::Unavailable { why } | Inverse::Nothing { why } => why,
        Inverse::Calls { .. } => String::new(),
    }
}

/// Whether going back runs a step of `method` again.
fn is_replayed(method: &str) -> bool {
    !moves_along_the_timeline(method) && !OPENS_DOCUMENT.contains(&method) && !WRITES_A_FILE.contains(&method) && !NOT_REPLAYED.contains(&method)
}

/// Undo every edit of document `doc` and check it is as the session first
/// saw it, by its hash.
fn bring_back_as_first_seen(workspace: &mut dyn Workspace, caller: &Caller, doc: &str) -> Result<(), ApiError> {
    while workspace.document_mut(doc).is_some_and(|document| document.can_undo()) {
        api::call_permitted(workspace, caller, UNDO, json!({"doc": doc}))?;
    }
    let first_seen = workspace.journal().session().document(doc).and_then(|recorded| recorded.file.sha256.clone());
    let Some(expected) = first_seen else { return Ok(()) };
    let Some(document) = workspace.document_mut(doc) else { return Err(ApiError::not_found(format!("{doc} is no longer open"))) };
    let len = document.len();
    let bytes = document.read_range(0, len);
    if super::sha256_hex(&bytes) != expected {
        return Err(ApiError::new(
            ErrorCode::Unavailable,
            format!("{doc} cannot be brought back to how the session first saw it: its undo history does not reach back that far; open the file again and replay instead"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Playback and recipes
// ---------------------------------------------------------------------------

/// The steps in effect from `from` through `through`, as steps to run
/// again: those going back replays (not opening or writing files, nor
/// moving along the timeline). Playback takes them, then goes back to the
/// step before `from` (which marks them undone), then plays them.
pub fn steps_to_play(journal: &Journal, from: u64, through: u64) -> Vec<RecipeStep> {
    let timeline = Timeline::of(journal);
    journal
        .entries()
        .filter(|entry| (from..=through).contains(&entry.step) && timeline.is_active(entry.step) && is_replayed(&entry.method))
        .map(|entry| RecipeStep { step: entry.step, method: entry.method.clone(), params: entry.params.clone(), note: None })
        .collect()
}

/// Steps played one at a time, as the person watches: each a run of its
/// own through the runner, recorded in the journal like any other call.
#[derive(Clone, Debug)]
pub struct Playback {
    steps: Vec<RecipeStep>,
    next: usize,
    options: ReplayOptions,
    runner: Runner,
    /// The last step's report, or why it stopped.
    last: Option<StepReport>,
    stopped: Option<ApiError>,
}

impl Playback {
    /// Play `steps` in order as `caller` on document `doc` (the current
    /// one when `None`).
    pub fn new(steps: Vec<RecipeStep>, caller: Caller, doc: Option<String>) -> Self {
        Self::with_runner(steps, caller, doc, replay::run)
    }

    pub fn with_runner(steps: Vec<RecipeStep>, caller: Caller, doc: Option<String>, runner: Runner) -> Self {
        let mut options = ReplayOptions::new(caller);
        // The person plays back steps already taken: each is not asked
        // about again.
        options.consented = true;
        options.doc = doc;
        Playback { steps, next: 0, options, runner, last: None, stopped: None }
    }

    /// Run the next step; returns its number, or `None` when there are no
    /// more or playback stopped at a failure.
    pub fn play_next(&mut self, workspace: &mut dyn Workspace) -> Option<u64> {
        if self.is_finished() {
            return None;
        }
        let step = self.steps[self.next].clone();
        let report = (self.runner)(workspace, std::slice::from_ref(&step), &self.options);
        self.next += 1;
        self.last = report.steps.into_iter().last();
        if let Some(stopped) = report.stopped {
            self.stopped = Some(stopped.error);
        }
        Some(step.step)
    }

    /// Whether every step has been played, or playback stopped.
    pub fn is_finished(&self) -> bool {
        self.next >= self.steps.len() || self.stopped.is_some()
    }

    /// How many steps have been played, of how many.
    pub fn progress(&self) -> (usize, usize) {
        (self.next, self.steps.len())
    }

    /// The step to play next.
    pub fn upcoming(&self) -> Option<&RecipeStep> {
        if self.stopped.is_some() { None } else { self.steps.get(self.next) }
    }

    /// What the last step played did.
    pub fn last_report(&self) -> Option<&StepReport> {
        self.last.as_ref()
    }

    /// Why playback stopped early.
    pub fn stopped(&self) -> Option<&ApiError> {
        self.stopped.as_ref()
    }
}

/// The steps a recipe made from the history takes: those in effect up to
/// `through` (every one when `None`), not moves along the timeline. A
/// recipe with anchors (area C's) is made from these same entries.
pub fn entries_for_recipe(journal: &Journal, through: Option<u64>) -> Vec<&JournalEntry> {
    let timeline = Timeline::of(journal);
    journal.entries().filter(|entry| through.is_none_or(|through| entry.step <= through) && timeline.is_active(entry.step) && !moves_along_the_timeline(&entry.method)).collect()
}

/// A recipe called `name` of the history in effect up to `through`, with
/// the anchors and parameters recorded for its steps (and the earlier
/// steps they cite), numbered from 1.
pub fn recipe_of_history(journal: &Journal, name: &str, through: Option<u64>) -> Recipe {
    let steps: Vec<u64> = entries_for_recipe(journal, through).iter().map(|entry| entry.step).collect();
    Recipe::from_journal_with_anchors(name, journal, Some(&steps))
}

#[cfg(test)]
mod tests;
