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
//! The steps run again make one undo step of the document, as every run
//! does, and the timeline keeps them as one: the document's undo takes them
//! back together and its redo brings them back together. So they are not
//! undone one at a time (`history.undo_step` says to use `history.undo`),
//! and going back to a step between them replays again.
//!
//! Undoing a step, or the steps after N, is all or nothing: when one of
//! the calls fails, what was undone so far is put back (byte edits through
//! the document's redo, other steps by making what they left again through
//! their inverse), so the documents still match the timeline. What cannot
//! be made again (a packet set removed) stays undone, and the failed step
//! lists it, so the timeline marks it undone by that step.
//!
//! A note (`history.note`) stands apart from all of this: it changed
//! nothing, so it is never undone (by an undo of its own, or by going back
//! past it) and never repeated. The timeline marks it as a note.
//!
//! What each step's inverse is, its method declares
//! ([`super::undo::Undo`]), as it declares how going back, playback and
//! recipes treat it ([`Replay`]); [`inverse_of`] puts them together.

use std::collections::{BTreeMap, HashMap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::recipe::{Recipe, RecipeStep};
use super::replay::{self, ReplayOptions, RunReport};
use super::undo::{self, Undo};
use super::{Journal, JournalEntry, Outcome};
use crate::api::{self, ApiError, Caller, Effect, ErrorCode, Workspace};

/// Undo one step of the journal.
pub const UNDO_STEP: &str = "history.undo_step";
/// Go back to a step of the journal.
pub const GO_BACK: &str = "history.go_back";
/// The document's own undo of its last edit.
const UNDO: &str = "history.undo";
/// The document's own redo of its last edit undone.
const REDO: &str = "history.redo";

/// How going back, playback and recipes treat a step of a method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replay {
    /// A step of the analysis: run again by going back and playback, and
    /// kept in recipes.
    Step,
    /// A move along the timeline itself: shown in the history, never
    /// repeated.
    Move(Move),
    /// It opens a document and makes it current; one that `derives` opens a
    /// document derived from the current one. Not repeated: what it opened
    /// is open already.
    OpensDocument { derives: bool },
    /// It makes a new sheet from a document. Kept by recipes, which make
    /// the sheet again and name it by the step that made it; not repeated
    /// by going back or playback, as the sheet is open already.
    MakesSheet,
    /// It writes a file and leaves the document as it is. Not repeated.
    WritesFile,
    /// Not repeated, for its own reasons: it reloads plugins, or starts or
    /// stops a live source.
    Never,
    /// A note on the analysis, which changes nothing: shown in the history
    /// among the steps, never repeated, undone or gone back past.
    Note,
}

/// The moves along the timeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Move {
    /// The document's own undo of its last edit (`history.undo`).
    Undo,
    /// The document's own redo (`history.redo`).
    Redo,
    /// Undoing one step through its inverse (`history.undo_step`).
    UndoStep,
    /// Going back to a step (`history.go_back`).
    GoBack,
}

/// How a step of the method called `method` is treated, as the method
/// table declares it; a method not in the table (a plugin's) is a step.
pub fn replay_of(method: &str) -> Replay {
    api::method(method).map_or(Replay::Step, |method| method.replay)
}

/// How going back, playback and recipes treat `entry`: as its method
/// declares, or as the output it asked for says (a call with
/// `output: "new"` makes a sheet; one in place is a step).
pub fn replay_of_entry(entry: &JournalEntry) -> Replay {
    api::method(&entry.method).map_or(Replay::Step, |method| method.replay_for(&entry.params))
}

/// Whether going back and playback repeat `entry`.
fn is_replayed(entry: &JournalEntry) -> bool {
    replay_of_entry(entry) == Replay::Step
}

/// Whether recipes keep `entry`: the steps going back and playback
/// repeat, and those that make sheets.
pub fn is_kept_by_recipes(entry: &JournalEntry) -> bool {
    matches!(replay_of_entry(entry), Replay::Step | Replay::MakesSheet)
}

/// Where a step stands on the timeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StepStatus {
    /// In effect: part of the analysis as it stands.
    Active,
    /// It failed or was refused, and changed nothing. Only a move that
    /// failed part-way and could not put back all it had undone leaves
    /// steps undone, by it, which its error lists.
    Failed,
    /// Undone, by the step `by` (an undo, an undo of this step, or going
    /// back to an earlier step).
    Undone { by: u64 },
    /// A move along the timeline itself: an undo, a redo, an undo of a
    /// step, or going back.
    Move,
    /// A note on the analysis: it changed nothing, and is never undone or
    /// repeated.
    Note,
}

/// One step of a document's undo history, as the journal saw it: the
/// journal steps one undo of the document takes back, oldest first, and
/// what the undo step is called. An edit is one step of its own; the edits
/// going back ran again are one, as [`super::replay::run`] makes them.
#[derive(Clone, Debug, PartialEq)]
struct UndoGroup {
    steps: Vec<u64>,
    label: Option<String>,
}

impl UndoGroup {
    /// Its latest step.
    fn last_step(&self) -> u64 {
        self.steps.last().copied().unwrap_or_default()
    }
}

/// The journal's steps with where each stands: in effect, undone (and by
/// what), failed, or a move along the timeline. The journal keeps its own
/// up to date as it records ([`Journal::timeline`]).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Timeline {
    statuses: BTreeMap<u64, StepStatus>,
    /// Each document's edits in effect, oldest first: the document's undo
    /// stack, as far as the journal saw it.
    edits: HashMap<String, Vec<UndoGroup>>,
    /// Each document's edits undone that a redo brings back, the next to
    /// redo last.
    undone_edits: HashMap<String, Vec<UndoGroup>>,
}

impl Timeline {
    /// The timeline of everything `journal` holds.
    pub fn of(journal: &Journal) -> &Timeline {
        journal.timeline()
    }

    /// The timeline of `entries`, in step order, from scratch.
    pub(super) fn following<'a>(entries: impl IntoIterator<Item = &'a JournalEntry>) -> Timeline {
        let mut timeline = Timeline::default();
        for entry in entries {
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
    #[cfg(test)]
    pub fn active_steps(&self) -> impl Iterator<Item = u64> + '_ {
        self.statuses.iter().filter(|(_, status)| **status == StepStatus::Active).map(|(step, _)| *step)
    }

    /// The step that made document `doc`'s last edit still in effect.
    pub fn last_edit(&self, doc: &str) -> Option<u64> {
        self.last_undo(doc).map(UndoGroup::last_step)
    }

    /// Document `doc`'s last undo step in effect.
    fn last_undo(&self, doc: &str) -> Option<&UndoGroup> {
        self.edits.get(doc).and_then(|edits| edits.last())
    }

    /// The undo step in effect of document `doc` that holds `step`.
    fn undo_holding(&self, doc: &str, step: u64) -> Option<&UndoGroup> {
        self.edits.get(doc)?.iter().find(|group| group.steps.contains(&step))
    }

    /// Take in the next entry of the journal.
    pub(super) fn follow(&mut self, entry: &JournalEntry) {
        let step = entry.step;
        if !entry.outcome.is_ok() {
            self.statuses.insert(step, StepStatus::Failed);
            for undone in left_undone(entry) {
                self.undo_one(undone, step);
            }
            return;
        }
        let doc = entry.doc.clone().unwrap_or_default();
        if replay_of_entry(entry) == Replay::Note {
            self.statuses.insert(step, StepStatus::Note);
            return;
        }
        let Replay::Move(kind) = replay_of_entry(entry) else {
            self.statuses.insert(step, StepStatus::Active);
            if entry.effect == Effect::Edit && entry.changed_document() {
                self.edits.entry(doc.clone()).or_default().push(UndoGroup { steps: vec![step], label: edit_label(entry) });
                self.undone_edits.remove(&doc);
            }
            return;
        };
        self.statuses.insert(step, StepStatus::Move);
        match kind {
            Move::Undo => {
                if entry.changed_document()
                    && let Some(undone) = self.edits.get_mut(&doc).and_then(Vec::pop)
                {
                    self.mark(&undone.steps, StepStatus::Undone { by: step });
                    self.undone_edits.entry(doc).or_default().push(undone);
                }
            }
            Move::Redo => {
                if entry.changed_document()
                    && let Some(redone) = self.undone_edits.get_mut(&doc).and_then(Vec::pop)
                {
                    self.mark(&redone.steps, StepStatus::Active);
                    self.edits.entry(doc).or_default().push(redone);
                }
            }
            Move::UndoStep => {
                if let Some(target) = entry.params.get("step").and_then(Value::as_u64) {
                    self.undo_one(target, step);
                }
            }
            Move::GoBack => {
                let target = entry.params.get("step").and_then(Value::as_u64).unwrap_or(0);
                let result = entry.result.as_ref();
                let kept = result.map(kept_steps).unwrap_or_default();
                self.go_back(target, step, result.and_then(RunAgain::of), &kept);
            }
        }
    }

    /// Forget `step`, which the journal no longer holds: it was dropped, or
    /// replaced by a later call of the same setter.
    pub(super) fn forget(&mut self, step: u64) {
        self.statuses.remove(&step);
        for stack in self.edits.values_mut().chain(self.undone_edits.values_mut()) {
            for group in stack.iter_mut() {
                group.steps.retain(|held| *held != step);
            }
            stack.retain(|group| !group.steps.is_empty());
        }
    }

    /// Give each of `steps` the status `status`.
    fn mark(&mut self, steps: &[u64], status: StepStatus) {
        for step in steps {
            self.statuses.insert(*step, status);
        }
    }

    /// Mark `target` undone by step `by`; an edit leaves its document's
    /// stack for the redo stack, as the document's own undo does.
    fn undo_one(&mut self, target: u64, by: u64) {
        if !self.is_active(target) {
            return;
        }
        self.statuses.insert(target, StepStatus::Undone { by });
        let holding = self.edits.iter().find(|(_, edits)| edits.last().is_some_and(|group| group.steps.contains(&target))).map(|(doc, _)| doc.clone());
        if let Some(doc) = holding
            && let Some(undone) = self.edits.get_mut(&doc).and_then(Vec::pop)
        {
            self.mark(&undone.steps, StepStatus::Undone { by });
            self.undone_edits.entry(doc).or_default().push(undone);
        }
    }

    /// Mark every step in effect after `target` undone by step `by`. Their
    /// edits wait to be redone, latest first, as each document's undo left
    /// them, except the edits of the `kept` steps, which going back could
    /// not undo and so stay on their document's undo stack. The document a
    /// replay brought back had every edit undone, and its edits up to
    /// `target` run again are its one undo step now, which leaves nothing
    /// to redo.
    fn go_back(&mut self, target: u64, by: u64, replayed: Option<RunAgain>, kept: &[u64]) {
        let later: Vec<u64> = self.statuses.range(target + 1..by).filter(|(_, status)| **status == StepStatus::Active).map(|(step, _)| *step).collect();
        self.mark(&later, StepStatus::Undone { by });
        for (doc, edits) in &mut self.edits {
            let waiting = self.undone_edits.entry(doc.clone()).or_default();
            if let Some(run) = replayed.as_ref().filter(|run| run.doc == *doc) {
                let run_again: Vec<u64> = edits.iter().flat_map(|group| group.steps.iter().copied()).filter(|step| *step <= target).collect();
                let undone = std::mem::take(edits);
                if run_again.is_empty() {
                    waiting.extend(undone.into_iter().rev());
                } else {
                    edits.push(UndoGroup { steps: run_again, label: run.label.clone() });
                    waiting.clear();
                }
                continue;
            }
            let staying = edits.partition_point(|group| group.last_step() <= target || group.steps.iter().any(|step| kept.contains(step)));
            waiting.extend(edits.split_off(staying).into_iter().rev());
        }
    }
}

/// The document going back brought back and ran its steps on again, and
/// what the one undo step those steps made is called.
struct RunAgain {
    doc: String,
    label: Option<String>,
}

impl RunAgain {
    /// What going back by replaying did, from its result; `None` when it
    /// undid the later steps instead.
    fn of(went_back: &Value) -> Option<RunAgain> {
        if went_back.get("way").and_then(Value::as_str) != Some("replayed") {
            return None;
        }
        let doc = went_back.get("doc").and_then(Value::as_str)?.to_string();
        let label = went_back.get("label").and_then(Value::as_str).map(str::to_string);
        Some(RunAgain { doc, label })
    }
}

/// The steps a move along the timeline that failed part-way left undone,
/// latest first, as its error lists them: those it could not put back
/// (see [`undo_all_or_nothing`]).
fn left_undone(entry: &JournalEntry) -> Vec<u64> {
    let Outcome::Error(error) = &entry.outcome else { return Vec::new() };
    if !matches!(replay_of_entry(entry), Replay::Move(_)) {
        return Vec::new();
    }
    let undone = error.data.as_ref().and_then(|data| data.get("undone")).and_then(Value::as_array);
    undone.into_iter().flatten().filter_map(Value::as_u64).collect()
}

/// The later steps going back could not undo, from its result.
fn kept_steps(went_back: &Value) -> Vec<u64> {
    let kept = went_back.get("kept").and_then(Value::as_array);
    kept.into_iter().flatten().filter_map(|kept| kept.get("step").and_then(Value::as_u64)).collect()
}

// ---------------------------------------------------------------------------
// Each step's inverse
// ---------------------------------------------------------------------------

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
    pub(super) fn new(method: &str, params: Value) -> Self {
        InverseCall { method: method.to_string(), params, caller: None }
    }

    pub(super) fn as_caller(method: &str, params: Value, caller: Option<String>) -> Self {
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
    pub(super) fn unavailable(why: impl Into<String>) -> Self {
        Inverse::Unavailable { why: why.into() }
    }

    pub(super) fn nothing(why: impl Into<String>) -> Self {
        Inverse::Nothing { why: why.into() }
    }

    pub(super) fn calls(calls: Vec<InverseCall>) -> Self {
        Inverse::Calls { calls }
    }

    /// Whether the step can be undone.
    pub fn is_available(&self) -> bool {
        !matches!(self, Inverse::Unavailable { .. })
    }

    /// The calls to make (none when there is nothing to undo), or why the
    /// step cannot be undone.
    fn into_calls(self) -> Result<Vec<InverseCall>, String> {
        match self {
            Inverse::Calls { calls } => Ok(calls),
            Inverse::Nothing { .. } => Ok(Vec::new()),
            Inverse::Unavailable { why } => Err(why),
        }
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
/// | a job, `jobs.cancel`, a file written, a read, a template applied unpinned, a plugin's method, a failed step | nothing to undo |
/// | a note (`history.note`) | none: it changed nothing, and stays until deleted |
/// | anything else (`packets.sets.remove`, `protocol.choose_framing`, `sources.*`, `plugins.reload`…) | none |
pub fn inverse_of(workspace: &mut dyn Workspace, step: u64) -> Inverse {
    let journal = workspace.journal();
    let Some(entry) = journal.entry(step) else {
        return Inverse::unavailable(format!("step {step} is not in the journal"));
    };
    let timeline = journal.timeline();
    match timeline.status(step) {
        Some(StepStatus::Move) => return Inverse::unavailable("it moves along the history itself: redo, or go back to a step"),
        Some(StepStatus::Note) => return Inverse::unavailable("it is a note: it changed nothing, and stays in the history until it is deleted"),
        Some(StepStatus::Undone { by }) => return Inverse::unavailable(format!("it is already undone, by step {by}")),
        _ => {}
    }
    if let Some(blocker) = later_change_of_the_same(journal, entry) {
        return Inverse::unavailable(format!("step {blocker} changed the same thing since; undo it first, or go back to step {}", step.saturating_sub(1)));
    }
    if !is_byte_edit(entry) {
        return inverse_for(journal, entry);
    }
    let Some(doc) = entry.doc.clone() else { return Inverse::unavailable("the journal does not say which document it edited") };
    let last_undo = timeline.last_undo(&doc);
    if let Some(last) = last_undo.filter(|group| !group.steps.contains(&step)) {
        return Inverse::unavailable(format!("step {} edited {doc} since; undo it first, or go back to step {}", last.last_step(), step.saturating_sub(1)));
    }
    if let Some(together) = last_undo.filter(|group| group.steps.len() > 1) {
        return Inverse::unavailable(format!("going back ran steps {} again as one change of {doc}; history.undo undoes them together", list_steps(&together.steps)));
    }
    let label = edit_label(entry);
    if let Err(why) = is_top_of_undo(workspace, &doc, label.as_deref()) {
        return Inverse::unavailable(why);
    }
    document_undo(&doc)
}

/// How `entry` is undone, taken on its own: for a byte edit, the
/// document's undo (whether that is the document's next undo is for the
/// caller to check); otherwise as its method declares, given what it
/// replaced.
fn inverse_for(journal: &Journal, entry: &JournalEntry) -> Inverse {
    if !entry.outcome.is_ok() {
        return Inverse::nothing("it failed, and changed nothing");
    }
    if is_byte_edit(entry) {
        return match &entry.doc {
            Some(doc) => document_undo(doc),
            None => Inverse::unavailable("the journal does not say which document it edited"),
        };
    }
    match undo::undo_of(entry) {
        Undo::Nothing(why) => Inverse::nothing(why),
        Undo::Irreversible => Inverse::unavailable(format!("{} has no inverse", entry.method)),
        Undo::Creates(resource) => match resource.made_by(entry) {
            Some(made) => resource.removal(made),
            None => Inverse::unavailable(format!("{} has no inverse", entry.method)),
        },
        Undo::Reverses(reverse) => match reverse.target(&entry.params, entry.doc.as_deref(), &entry.caller) {
            Some(_) => reverse.inverse(entry, before_of(journal, entry)),
            None => reverse.untargeted(&entry.method),
        },
    }
}

/// The document's own undo of document `doc`.
fn document_undo(doc: &str) -> Inverse {
    Inverse::calls(vec![InverseCall::new(UNDO, json!({"doc": doc}))])
}

/// Whether `entry` changed its document's bytes as an undoable edit.
fn is_byte_edit(entry: &JournalEntry) -> bool {
    entry.outcome.is_ok() && entry.effect == Effect::Edit && entry.changed_document() && !matches!(replay_of_entry(entry), Replay::Move(_))
}

/// A later step in effect that changed what `entry` changed, or used what
/// it made.
fn later_change_of_the_same(journal: &Journal, entry: &JournalEntry) -> Option<u64> {
    if !entry.outcome.is_ok() {
        return None;
    }
    let timeline = journal.timeline();
    let mut later = journal.since(entry.step).filter(|later| timeline.is_active(later.step));
    match undo::undo_of(entry) {
        Undo::Creates(resource) => {
            let made = resource.made_by(entry)?;
            later.find(|later| resource.is_used_by(made, later)).map(|later| later.step)
        }
        Undo::Reverses(_) => {
            let target = undo::target_of(entry)?;
            later.find(|later| undo::target_of(later).as_ref() == Some(&target)).map(|later| later.step)
        }
        Undo::Nothing(_) | Undo::Irreversible => None,
    }
}

/// The label `entry`, a byte edit, gave its undo step, where it returned
/// one.
fn edit_label(entry: &JournalEntry) -> Option<String> {
    entry.result.as_ref().and_then(|result| result.get("label")).and_then(Value::as_str).map(str::to_string)
}

/// `steps` as a message names them: "2, 3".
fn list_steps(steps: &[u64]) -> String {
    steps.iter().map(u64::to_string).collect::<Vec<_>>().join(", ")
}

/// Whether document `doc`'s next undo would reverse an edit labelled
/// `label`: it has one, and its name is the edit's, where the edit gave
/// one.
fn is_top_of_undo(workspace: &mut dyn Workspace, doc: &str, label: Option<&str>) -> Result<(), String> {
    let Some(document) = workspace.document_mut(doc) else { return Err(format!("{doc} is no longer open")) };
    if !document.can_undo() {
        return Err(format!("{doc} has nothing left to undo"));
    }
    match (label, document.undo_label()) {
        (Some(expected), Some(next)) if expected != next => Err(format!("{doc}'s next undo is \"{next}\", made outside the journal; undo it first")),
        _ => Ok(()),
    }
}

/// What `entry` replaced: as kept when it ran ([`undo::state_before`]),
/// or else as the step before it that changed the same thing left it.
fn before_of(journal: &Journal, entry: &JournalEntry) -> Option<Value> {
    if entry.before.is_some() {
        return entry.before.clone();
    }
    let Undo::Reverses(reverse) = undo::undo_of(entry) else { return None };
    let target = undo::target_of(entry)?;
    let timeline = journal.timeline();
    let earlier = journal
        .entries()
        .chain(journal.reads())
        .filter(|earlier| earlier.step < entry.step && earlier.outcome.is_ok())
        .filter(|earlier| !matches!(timeline.status(earlier.step), Some(StepStatus::Failed | StepStatus::Move | StepStatus::Note)))
        .filter(|earlier| undo::target_of(earlier).as_ref() == Some(&target))
        .max_by_key(|earlier| earlier.step);
    match earlier {
        // A step undone left things as they were before it.
        Some(earlier) if matches!(timeline.status(earlier.step), Some(StepStatus::Undone { .. })) => before_of(journal, earlier),
        Some(earlier) => match undo::undo_of(earlier) {
            Undo::Reverses(earlier_reverse) => earlier_reverse.after(earlier),
            _ => None,
        },
        None => reverse.first_before(entry),
    }
}

/// A step to undo, and the calls that undo it.
type Undoing = (JournalEntry, Vec<InverseCall>);

/// Undo each of `steps` (latest first) through its calls as `caller`, all
/// or nothing: when a call fails, what was undone so far is put back,
/// latest undone first (see [`putting_back`]), so the documents are as
/// they were and the failed call changed nothing. A step that cannot be
/// put back (a packet set removed) stays undone, and so do the steps
/// undone before it; the error lists them in its data's `undone`, latest
/// first, and the timeline marks them undone by the failed call.
fn undo_all_or_nothing(workspace: &mut dyn Workspace, caller: &Caller, steps: &[Undoing]) -> Result<(), ApiError> {
    let mut undone: Vec<&Undoing> = Vec::new();
    for undoing in steps {
        let (entry, calls) = undoing;
        for (made, call) in calls.iter().enumerate() {
            if let Err(error) = make_call(workspace, caller, call) {
                if made > 0 {
                    undone.push(undoing);
                }
                let failed = ApiError::new(error.code, format!("undoing step {}, {} failed: {}", entry.step, call.method, error.message));
                return Err(put_back(workspace, caller, &undone, failed));
            }
        }
        undone.push(undoing);
    }
    Ok(())
}

/// Put back what undoing `undone` (in the order undone) undid, latest
/// undone first, after `failed` stopped it; `failed` says how far that
/// went.
fn put_back(workspace: &mut dyn Workspace, caller: &Caller, undone: &[&Undoing], failed: ApiError) -> ApiError {
    if undone.is_empty() {
        return failed;
    }
    let mut left_undone: Vec<u64> = Vec::new();
    let mut why_left: Option<String> = None;
    for (entry, calls) in undone.iter().rev() {
        if why_left.is_none() {
            why_left = match putting_back(entry, calls) {
                None => Some(format!("step {} ({}) cannot be made again", entry.step, entry.method)),
                Some(calls) => calls.iter().find_map(|call| make_call(workspace, caller, call).err()).map(|error| format!("putting back step {} failed: {}", entry.step, error.message)),
            };
        }
        // Each is put back on top of the one before, so none can be once
        // one is not.
        if why_left.is_some() {
            left_undone.push(entry.step);
        }
    }
    left_undone.reverse();
    match why_left {
        None => ApiError::new(failed.code, format!("{}; what it had undone was put back, so nothing changed", failed.message)),
        Some(why) => {
            let message = format!("{}; steps {} stay undone, as {why}", failed.message, list_steps(&left_undone));
            ApiError::new(failed.code, message).with_data(json!({ "undone": left_undone }))
        }
    }
}

/// The calls that put back what undoing `entry` through `calls` undid: the
/// document's redo for each of its undos; for a step that changed no
/// bytes, what it left, made again through its inverse. `None` when that
/// cannot be made again (a packet set removed).
fn putting_back(entry: &JournalEntry, calls: &[InverseCall]) -> Option<Vec<InverseCall>> {
    if calls.is_empty() {
        return Some(Vec::new());
    }
    if calls.iter().all(|call| call.method == UNDO) {
        return Some(calls.iter().rev().map(|call| InverseCall::new(REDO, call.params.clone())).collect());
    }
    let Undo::Reverses(reverse) = undo::undo_of(entry) else { return None };
    reverse.inverse(entry, reverse.after(entry)).into_calls().ok()
}

/// Make `call` inside the call that undoes, as `caller` unless it names
/// its own.
fn make_call(workspace: &mut dyn Workspace, caller: &Caller, call: &InverseCall) -> Result<Value, ApiError> {
    let caller = call.caller.as_deref().map_or_else(|| caller.clone(), Caller::from_producer);
    api::call_permitted(workspace, &caller, &call.method, call.params.clone())
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
    let Some(entry) = workspace.journal().entry(step).cloned() else {
        return Err(ApiError::not_found(format!("there is no step {step} to undo; history.list shows the steps held")));
    };
    let method = entry.method.clone();
    match inverse_of(workspace, step) {
        Inverse::Calls { calls } => {
            undo_all_or_nothing(workspace, caller, &[(entry, calls.clone())])?;
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
    /// What the one undo step the steps run again made on the document is
    /// called, when they edited it: one undo takes them all back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A later step to undo, latest first, with its inverse taken on its own.
struct Planned {
    entry: JournalEntry,
    inverse: Inverse,
    /// For a byte edit, what its document's undo step holding it is called.
    label: Option<String>,
}

impl Planned {
    /// `entry`, a step after `target`, to undo going back to `target`. The
    /// edits an earlier going back ran again are one undo step of their
    /// document: the latest of them undoes them all, and going back to
    /// between them replays.
    fn going_back(journal: &Journal, entry: &JournalEntry, target: u64) -> Planned {
        let group = entry.doc.as_deref().filter(|_| is_byte_edit(entry)).and_then(|doc| journal.timeline().undo_holding(doc, entry.step));
        let inverse = match group.filter(|group| group.steps.len() > 1) {
            Some(group) if group.steps[0] <= target => Inverse::unavailable(format!("going back ran it again as one change with steps {}, which are kept", list_steps(&group.steps))),
            Some(group) if group.last_step() != entry.step => Inverse::nothing(format!("undoing step {} undoes it too", group.last_step())),
            _ => inverse_for(journal, entry),
        };
        let label = group.map_or_else(|| edit_label(entry), |group| group.label.clone());
        Planned { entry: entry.clone(), inverse, label }
    }
}

/// Go back to step `step` as `caller`: undo every later step in effect, or
/// replay steps 1 to `step` from the document as first seen when a later
/// step has no inverse. Steps 0 goes back to before the first step.
pub fn go_back(workspace: &mut dyn Workspace, caller: &Caller, step: u64) -> Result<WentBack, ApiError> {
    let journal = workspace.journal();
    if step != 0 && journal.entry(step).is_none() {
        return Err(ApiError::not_found(format!("there is no step {step} to go back to; history.list shows the steps held")));
    }
    let timeline = journal.timeline();
    let later: Vec<Planned> = journal
        .since(step)
        .filter(|entry| timeline.is_active(entry.step))
        .rev()
        .map(|entry| Planned::going_back(journal, entry, step))
        .collect();
    match plan_undo(workspace, &later) {
        Ok(plan) => {
            undo_all_or_nothing(workspace, caller, &plan)?;
            Ok(WentBack { step, way: Way::Undone, undone: plan.iter().map(|(undoing, _)| undoing.step).collect(), kept: Vec::new(), doc: None, replayed: None, label: None })
        }
        Err(_) => replay_up_to(workspace, caller, step, later),
    }
}

/// The calls that undo each of `later` (latest first), or the first step
/// that has no inverse.
fn plan_undo(workspace: &mut dyn Workspace, later: &[Planned]) -> Result<Vec<Undoing>, KeptStep> {
    let mut checked_documents: Vec<String> = Vec::new();
    let mut plan = Vec::new();
    for Planned { entry, inverse, label } in later {
        let kept = |why: String| KeptStep { step: entry.step, method: entry.method.clone(), why };
        // Undone latest first, each edit is its document's last in turn
        // once the document's last undo is the journal's last edit.
        if is_byte_edit(entry)
            && let Some(doc) = &entry.doc
            && !checked_documents.contains(doc)
        {
            is_top_of_undo(workspace, doc, label.as_deref()).map_err(kept)?;
            checked_documents.push(doc.clone());
        }
        plan.push((entry.clone(), inverse.clone().into_calls().map_err(kept)?));
    }
    Ok(plan)
}

/// Going back by replaying: undo what can be undone of `later` (latest
/// first), bring the document of step `step` back to how the session first
/// saw it, and run the steps in effect on it up to `step` again.
fn replay_up_to(workspace: &mut dyn Workspace, caller: &Caller, step: u64, later: Vec<Planned>) -> Result<WentBack, ApiError> {
    let doc = workspace
        .journal()
        .entry(step)
        .and_then(|entry| entry.doc.clone())
        .or_else(|| later.iter().rev().find_map(|planned| planned.entry.doc.clone()))
        .or_else(|| workspace.current_document())
        .ok_or_else(|| ApiError::not_found("there is no document to go back on"))?;
    let steps = replayable_steps(workspace.journal(), 0..=step, Some(&doc));
    let mut undone = Vec::new();
    let mut kept = Vec::new();
    for Planned { entry, inverse, label } in later {
        let calls = match (is_byte_edit(&entry), entry.doc.as_deref()) {
            // Bringing the document back undoes its edits.
            (true, Some(edited)) if edited == doc => Ok(Vec::new()),
            // Latest first, each is the other document's last in turn.
            (true, Some(edited)) => inverse.into_calls().and_then(|calls| if calls.is_empty() { Ok(calls) } else { is_top_of_undo(workspace, edited, label.as_deref()).map(|()| calls) }),
            _ => inverse.into_calls(),
        };
        let step_undone = calls.and_then(|calls| undo_all_or_nothing(workspace, caller, &[(entry.clone(), calls)]).map_err(|error| error.message));
        match step_undone {
            Ok(()) => undone.push(entry.step),
            Err(why) => kept.push(KeptStep { step: entry.step, method: entry.method, why }),
        }
    }
    bring_back_as_first_seen(workspace, caller, &doc)?;
    let mut options = ReplayOptions::new(caller.clone());
    // Going back was allowed; the steps it runs again are not asked about.
    options.checked_as = None;
    options.doc = Some(doc.clone());
    options.through_step = Some(step);
    let report = run_steps(workspace, &steps, &options);
    if let Some(stopped) = &report.stopped {
        let message = format!("going back to step {step}, running step {} again failed: {}", stopped.step, stopped.error.message);
        return Err(ApiError::new(stopped.error.code, message).with_data(serde_json::to_value(&report).unwrap_or(Value::Null)));
    }
    // The steps run again are one undo step of the document; the timeline
    // knows it as theirs by its name.
    let label = workspace.document_mut(&doc).and_then(|document| document.undo_label().map(str::to_string));
    Ok(WentBack { step, way: Way::Replayed, undone, kept, doc: Some(doc), replayed: Some(report), label })
}

/// Undo every edit of document `doc` and check it is as the session first
/// saw it, by its hash.
fn bring_back_as_first_seen(workspace: &mut dyn Workspace, caller: &Caller, doc: &str) -> Result<(), ApiError> {
    while workspace.document_mut(doc).is_some_and(|document| document.can_undo()) {
        api::call_permitted(workspace, caller, UNDO, json!({"doc": doc}))?;
    }
    let first_seen = workspace.journal().session().document(doc).and_then(|recorded| recorded.file().sha256);
    let Some(expected) = first_seen else { return Ok(()) };
    let Some(document) = workspace.document_mut(doc) else { return Err(ApiError::not_found(format!("{doc} is no longer open"))) };
    if super::document_sha256(document).as_deref() != Some(expected.as_str()) {
        return Err(ApiError::new(
            ErrorCode::Unavailable,
            format!("{doc} cannot be brought back to how the session first saw it: its undo history does not reach back that far; open the file again and replay instead"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Running steps again: going back, playback and recipes
// ---------------------------------------------------------------------------

/// How steps are run again: [`replay::run`], or a stand-in in tests.
#[cfg(test)]
pub type Runner = fn(&mut dyn Workspace, &[RecipeStep], &ReplayOptions) -> RunReport;

#[cfg(test)]
thread_local! {
    /// The stand-in for [`replay::run`] a test asked for, if any.
    static RUNNER: std::cell::Cell<Option<Runner>> = const { std::cell::Cell::new(None) };
}

/// Run `body` with steps run again by `runner` rather than
/// [`replay::run`], on this thread.
#[cfg(test)]
pub fn with_runner<T>(runner: Runner, body: impl FnOnce() -> T) -> T {
    RUNNER.set(Some(runner));
    let done = body();
    RUNNER.set(None);
    done
}

/// Run `steps` again as `options` say.
fn run_steps(workspace: &mut dyn Workspace, steps: &[RecipeStep], options: &ReplayOptions) -> RunReport {
    #[cfg(test)]
    if let Some(runner) = RUNNER.get() {
        return runner(workspace, steps, options);
    }
    replay::run(workspace, steps, options)
}

/// The entries in effect numbered within `steps` that going back, playback
/// and recipes repeat (not moves along the timeline, nor steps that open
/// documents, write files, reload plugins or start live sources), in step
/// order.
fn replayable_entries(journal: &Journal, steps: std::ops::RangeInclusive<u64>) -> impl Iterator<Item = &JournalEntry> {
    let timeline = journal.timeline();
    journal.entries().filter(move |entry| steps.contains(&entry.step) && timeline.is_active(entry.step) && is_replayed(entry))
}

/// [`replayable_entries`] as steps to run again, only those about document
/// `doc` when one is given.
fn replayable_steps(journal: &Journal, steps: std::ops::RangeInclusive<u64>, doc: Option<&str>) -> Vec<RecipeStep> {
    replayable_entries(journal, steps)
        .filter(|entry| doc.is_none_or(|doc| entry.doc.as_deref() == Some(doc)))
        .map(|entry| RecipeStep::new(entry.step, entry.method.clone(), entry.params.clone()))
        .collect()
}

/// The steps in effect from `from` through `through`, as steps to run
/// again: those going back replays. Playback takes them, then goes back to
/// the step before `from` (which marks them undone), then plays them.
pub fn steps_to_play(journal: &Journal, from: u64, through: u64) -> Vec<RecipeStep> {
    replayable_steps(journal, from..=through, None)
}

/// Steps played one at a time, as the person watches: each a run of its
/// own through [`replay::run`], recorded in the journal like any other
/// call.
#[derive(Clone, Debug)]
pub struct Playback {
    steps: Vec<RecipeStep>,
    next: usize,
    options: ReplayOptions,
    /// Why it stopped early.
    stopped: Option<ApiError>,
}

impl Playback {
    /// Play `steps` in order as `caller` on document `doc` (the current
    /// one when `None`).
    pub fn new(steps: Vec<RecipeStep>, caller: Caller, doc: Option<String>) -> Self {
        let mut options = ReplayOptions::new(caller);
        // The person plays back steps already taken: each is not asked
        // about again.
        options.checked_as = None;
        options.doc = doc;
        Playback { steps, next: 0, options, stopped: None }
    }

    /// Run the next step; returns its number, or `None` when there are no
    /// more or playback stopped at a failure.
    pub fn play_next(&mut self, workspace: &mut dyn Workspace) -> Option<u64> {
        if self.is_finished() {
            return None;
        }
        let step = self.steps[self.next].clone();
        let report = run_steps(workspace, std::slice::from_ref(&step), &self.options);
        self.next += 1;
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

    /// Why playback stopped early.
    pub fn stopped(&self) -> Option<&ApiError> {
        self.stopped.as_ref()
    }
}

/// The steps a recipe made from the history takes: those in effect up to
/// `through` (every one when `None`) that playback and going back repeat,
/// and those that made sheets. Reads a note cites as evidence are left
/// out; the recipe takes one back when an anchor of its steps cites it.
pub fn entries_for_recipe(journal: &Journal, through: Option<u64>) -> Vec<&JournalEntry> {
    let timeline = journal.timeline();
    let through = through.unwrap_or(u64::MAX);
    journal.entries().filter(|entry| entry.step <= through && !entry.evidence && timeline.is_active(entry.step) && is_kept_by_recipes(entry)).collect()
}

/// A recipe called `name` of the history in effect up to `through`, made
/// by the one builder every way of saving one shares
/// ([`super::provenance::build_recipe`]).
pub fn recipe_of_history(journal: &Journal, name: &str, through: Option<u64>) -> Result<Recipe, ApiError> {
    super::provenance::build_recipe(journal, name, super::provenance::RecipeSteps::InEffect { through })
}

#[cfg(test)]
mod tests;
