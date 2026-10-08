//! Notes: what the person or a client was thinking as they worked, written
//! into the journal among the steps (`history.note`).
//!
//! A note is an entry of its own, recorded where it was written and by
//! whom, so the History tab shows the reasoning in its place. It is of a
//! kind ([`NoteKind`]): an observation unless it says it is a hypothesis,
//! a decision, a fallback or a conclusion. Its text may cite steps as
//! `#12` (`\#12` writes "#12" and cites nothing); those, and any steps
//! given beside it, are the steps it is linked to, which must be in the
//! journal. A recent read it cites is moved into the journal as evidence
//! ([`super::promote_as_evidence`]): shown among the steps, but left out of
//! recipes unless an anchor cites it. Each step lists the notes linked to
//! it ([`Journal::notes_by_step`]).
//!
//! A note changes nothing. Its method is declared a note
//! ([`crate::api::Method::writes_a_note`]), so the timeline marks it as one
//! ([`super::timeline::StepStatus::Note`]): it is never undone, repeated by
//! playback, going back or recipes, nor undone by going back past it.
//! Editing or deleting a note is not a step of its own either: the note is
//! changed in place, or taken out of the journal, and an edited note says
//! when and by whom.
//!
//! Recipes made from the journal carry each note into the `note` of the
//! first recipe step it links, as recorded on the session's file, and the
//! others it links point to it ([`attach_to_recipe`]). [`markdown`] writes
//! the analysis out as Markdown, each step a note cites described in plain
//! words ([`Names`]).

use std::collections::BTreeMap;
use std::time::SystemTime;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::anchors::{Anchor, SheetRef};
use super::recipe::Recipe;
use super::timeline::{Replay, StepStatus, replay_of};
use super::{Held, Journal, JournalEntry, timestamp};
use crate::api::{ApiError, Caller, Effect, Workspace};
use crate::text::truncate_chars;

/// The method that writes a note.
pub const NOTE_METHOD: &str = "history.note";
/// The longest note kept, in bytes of UTF-8.
pub const NOTE_TEXT_LIMIT: usize = 4096;
/// What a note's description starts with in the History tab and
/// `history.list`.
const DESCRIPTION_PREFIX: &str = "Note: ";
/// Written before `#12`, it makes it words rather than a citation.
const ESCAPE: char = '\\';

/// What a note records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NoteKind {
    /// What a step showed.
    #[default]
    Observation,
    /// What might be so, still to test.
    Hypothesis,
    /// What to do next, and why.
    Decision,
    /// A gap the tools could not fill, worked round: a literal, a plugin
    /// or work done outside.
    Fallback,
    /// What the analysis found.
    Conclusion,
}

impl NoteKind {
    pub const ALL: [NoteKind; 5] = [NoteKind::Observation, NoteKind::Hypothesis, NoteKind::Decision, NoteKind::Fallback, NoteKind::Conclusion];

    /// Its name, as `history.note` takes it: "fallback".
    pub fn name(self) -> &'static str {
        match self {
            NoteKind::Observation => "observation",
            NoteKind::Hypothesis => "hypothesis",
            NoteKind::Decision => "decision",
            NoteKind::Fallback => "fallback",
            NoteKind::Conclusion => "conclusion",
        }
    }

    /// The kind `params` give a note, an observation when they give none.
    fn given_in(params: &Value) -> NoteKind {
        params.get("kind").and_then(|kind| serde_json::from_value(kind.clone()).ok()).unwrap_or_default()
    }
}

/// A note's text and the steps it is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Note {
    /// What it says, as written; `#12` cites step 12.
    pub text: String,
    /// What it records: an observation, hypothesis, decision, fallback or
    /// conclusion.
    #[serde(default)]
    pub kind: NoteKind,
    /// The steps it is linked to, in step order: those its text cites and
    /// those given beside it.
    pub steps: Vec<u64>,
    /// When it was last edited, UTC; none while it is as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<String>,
    /// Who last edited it, such as `panel` or `mcp:claude-code`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_by: Option<String>,
}

/// A note linked to a step, as the step lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NoteOn {
    /// The note's own step number.
    pub step: u64,
    /// Who wrote it.
    pub caller: String,
    #[serde(default)]
    pub kind: NoteKind,
    pub text: String,
}

/// A piece of a note's text: words, or a step it cites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment<'a> {
    Text(&'a str),
    /// `#12`: step 12.
    Step(u64),
}

/// `text` cut into words and the steps it cites. A citation is `#` then
/// digits, standing apart from the words around it: `#12.` and `(#12)`
/// cite step 12, `a#12`, `#12b` and `#ff00aa` cite nothing. A backslash
/// before it, `\#917`, makes it words, "#917", the backslash left out.
pub fn segments(text: &str) -> Vec<Segment<'_>> {
    let mut pieces = Vec::new();
    let mut plain_from = 0;
    let mut searched_to = 0;
    while let Some(found) = text[searched_to..].find('#') {
        let hash = searched_to + found;
        searched_to = hash + 1;
        let digits = text[hash + 1..].bytes().take_while(u8::is_ascii_digit).count();
        let end = hash + 1 + digits;
        let stands_apart_before = text[..hash].chars().next_back().is_none_or(|before| !before.is_alphanumeric() && before != '#' && before != '&');
        let stands_apart_after = text[end..].chars().next().is_none_or(|after| !after.is_alphanumeric() && after != '_');
        let Some(step) = text[hash + 1..end].parse::<u64>().ok().filter(|_| digits > 0 && stands_apart_before && stands_apart_after) else { continue };
        if text[..hash].ends_with(ESCAPE) {
            // Words from the `#` on; the backslash before it is left out.
            let backslash = hash - ESCAPE.len_utf8();
            if plain_from < backslash {
                pieces.push(Segment::Text(&text[plain_from..backslash]));
            }
            plain_from = hash;
            searched_to = end;
            continue;
        }
        if plain_from < hash {
            pieces.push(Segment::Text(&text[plain_from..hash]));
        }
        pieces.push(Segment::Step(step));
        plain_from = end;
        searched_to = end;
    }
    if plain_from < text.len() {
        pieces.push(Segment::Text(&text[plain_from..]));
    }
    pieces
}

/// The steps `text` cites, in the order it cites them, each once.
pub fn cited_steps(text: &str) -> Vec<u64> {
    let mut cited: Vec<u64> = Vec::new();
    for segment in segments(text) {
        if let Segment::Step(step) = segment
            && !cited.contains(&step)
        {
            cited.push(step);
        }
    }
    cited
}

/// The steps a note of `text` is linked to: those it cites and those
/// `given`, in step order, each once.
pub fn linked_steps(text: &str, given: &[u64]) -> Vec<u64> {
    let mut linked: Vec<u64> = cited_steps(text).into_iter().chain(given.iter().copied()).collect();
    linked.sort_unstable();
    linked.dedup();
    linked
}

/// A note's description in the journal: "Note: " and its text on one line.
pub fn describe(text: &str) -> String {
    let one_line = as_read(text).split_whitespace().collect::<Vec<_>>().join(" ");
    super::cut_to_a_line(format!("{DESCRIPTION_PREFIX}{one_line}"))
}

/// `text` as it reads: each citation as `#12`, each escaped `\#12` as
/// "#12".
pub fn as_read(text: &str) -> String {
    renumber_with(text, |step| format!("#{step}"))
}

/// Whether `text` can be a note: some words, within [`NOTE_TEXT_LIMIT`].
fn check_text(text: &str) -> Result<(), ApiError> {
    if text.trim().is_empty() {
        return Err(ApiError::invalid_params("a note needs some text: say what you are doing and why"));
    }
    if text.len() > NOTE_TEXT_LIMIT {
        return Err(ApiError::too_large(format!("the note is {} bytes, and a note holds at most {NOTE_TEXT_LIMIT}; split it into several notes", text.len())));
    }
    Ok(())
}

/// Check each of `linked` is a step of the journal that note `itself` (if
/// it is written already) may link to, moving a recent read it cites into
/// the journal as evidence.
fn check_links(workspace: &mut dyn Workspace, linked: &[u64], itself: Option<u64>) -> Result<(), ApiError> {
    if let Some(step) = itself.filter(|step| linked.contains(step)) {
        return Err(ApiError::invalid_params(format!("note {step} cannot be linked to itself; cite the steps it is about")));
    }
    let missing: Vec<u64> = linked.iter().copied().filter(|step| !super::promote_as_evidence(workspace, *step)).collect();
    match missing.as_slice() {
        [] => Ok(()),
        [step] => Err(ApiError::not_found(format!("the note cites step {step}, which is not in the journal; history.list shows the steps held"))),
        steps => Err(ApiError::not_found(format!("the note cites steps {}, which are not in the journal; history.list shows the steps held", list(steps)))),
    }
}

/// `steps` as a message names them: "2, 3".
fn list(steps: &[u64]) -> String {
    steps.iter().map(u64::to_string).collect::<Vec<_>>().join(", ")
}

/// Check a note of `text` linked to the steps it cites and those `given`
/// can be written now, and say which step it will be and which steps it
/// links. The journal then records it, as it records any call, with its
/// caller and time ([`written_by`] takes its text and links).
pub fn write(workspace: &mut dyn Workspace, text: &str, given: &[u64]) -> Result<(u64, Vec<u64>), ApiError> {
    if !workspace.journal().records_the_call_running_now() {
        return Err(ApiError::invalid_params("a note is written on its own, not inside another call (a transaction, a recipe's run or a plugin's method), so it has a place of its own in the history"));
    }
    check_text(text)?;
    let linked = linked_steps(text, given);
    check_links(workspace, &linked, None)?;
    Ok((workspace.journal().next_step(), linked))
}

/// The note a successful call of `method` with `params` wrote, which
/// returned `result`; none for any other method.
pub(super) fn written_by(method: &str, params: &Value, result: &Value) -> Option<Note> {
    if replay_of(method) != Replay::Note {
        return None;
    }
    let text = params.get("text")?.as_str()?.to_string();
    let steps = result.get("steps")?.as_array()?.iter().filter_map(Value::as_u64).collect();
    Some(Note { text, kind: NoteKind::given_in(params), steps, edited_at: None, edited_by: None })
}

/// The change asked of a note: its text, the steps given beside it (those
/// given before when `None`) and its kind (as it was when `None`).
pub struct NoteChange<'a> {
    pub text: &'a str,
    pub given: Option<Vec<u64>>,
    pub kind: Option<NoteKind>,
}

/// Change note `step` as `change` says, linked to the steps its text cites
/// and those given, as `caller`. Not a step of its own: the note is
/// changed in place and says it was edited.
pub fn edit(workspace: &mut dyn Workspace, caller: &Caller, step: u64, change: NoteChange<'_>) -> Result<Note, ApiError> {
    let entry = workspace.journal().note_entry(step)?;
    let given = change.given.unwrap_or_else(|| given_steps(&entry.params));
    let kind = change.kind.or_else(|| entry.note.as_ref().map(|note| note.kind)).unwrap_or_default();
    let text = change.text;
    check_text(text)?;
    let linked = linked_steps(text, &given);
    check_links(workspace, &linked, Some(step))?;
    let note = Note { text: text.to_string(), kind, steps: linked, edited_at: Some(timestamp(SystemTime::now())), edited_by: Some(caller.producer()) };
    workspace.journal_mut().replace_note(step, note.clone(), json!({"text": text, "steps": given, "kind": kind}));
    Ok(note)
}

/// The steps a note was given beside its text, from its parameters.
fn given_steps(params: &Value) -> Vec<u64> {
    params.get("steps").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_u64).collect()
}

/// Take note `step` out of the journal. Not a step of its own; the steps
/// it was linked to no longer list it.
pub fn delete(workspace: &mut dyn Workspace, step: u64) -> Result<Note, ApiError> {
    workspace.journal().note_entry(step)?;
    workspace.journal_mut().remove_note(step).ok_or_else(|| super::provenance::not_a_step(step))
}

/// Why `entry` cannot be edited or deleted as a note: it is a step of the
/// analysis.
fn not_a_note(entry: &JournalEntry) -> ApiError {
    let message = format!("step {} is {}, not a note; only notes written with {NOTE_METHOD} can be edited or deleted", entry.step, entry.method);
    ApiError::invalid_params(message).with_data(json!({"reason": "not_a_note", "step": entry.step, "method": entry.method}))
}

impl Journal {
    /// The notes held, in step order.
    pub fn notes(&self) -> impl Iterator<Item = &JournalEntry> {
        self.entries().filter(|entry| entry.is_note())
    }

    /// The notes linked to each step, oldest first, by the step's number.
    pub fn notes_by_step(&self) -> BTreeMap<u64, Vec<NoteOn>> {
        let mut by_step: BTreeMap<u64, Vec<NoteOn>> = BTreeMap::new();
        for entry in self.notes() {
            let Some(note) = &entry.note else { continue };
            for step in &note.steps {
                by_step.entry(*step).or_default().push(NoteOn { step: entry.step, caller: entry.caller.clone(), kind: note.kind, text: note.text.clone() });
            }
        }
        by_step
    }

    /// `entry` as `history.list` and `history.entry` give it: with the
    /// notes in `by_step` linked to it.
    pub fn with_notes(entry: &JournalEntry, by_step: &BTreeMap<u64, Vec<NoteOn>>) -> JournalEntry {
        let mut listed = entry.clone();
        listed.notes = by_step.get(&entry.step).cloned().unwrap_or_default();
        listed
    }

    /// The entry recorded as `step` when it is a note; otherwise why it
    /// cannot be changed as one.
    fn note_entry(&self, step: u64) -> Result<JournalEntry, ApiError> {
        match self.entry(step) {
            Some(entry) if entry.is_note() => Ok(entry.clone()),
            Some(entry) => Err(not_a_note(entry)),
            None => Err(super::provenance::not_a_step(step)),
        }
    }

    /// Where the entry numbered `step` is held.
    fn held_index(&self, step: u64) -> Option<usize> {
        let index = self.entries.partition_point(|held| held.entry.step < step);
        self.entries.get(index).filter(|held| held.entry.step == step).map(|_| index)
    }

    /// Put `note` in place of note `step`'s, with the `params` that would
    /// write it as it now is.
    fn replace_note(&mut self, step: u64, note: Note, params: Value) {
        let Some(index) = self.held_index(step) else { return };
        let mut entry = self.entries[index].entry.clone();
        entry.description = describe(&note.text);
        entry.params = params;
        if let Some(result) = entry.result.as_mut() {
            result["steps"] = json!(note.steps);
        }
        entry.note = Some(note);
        let held = Held::new(entry);
        self.bytes = self.bytes.saturating_sub(self.entries[index].size) + held.size;
        self.entries[index] = held;
        self.revision += 1;
    }

    /// Take note `step` out of the journal, returning it.
    fn remove_note(&mut self, step: u64) -> Option<Note> {
        let index = self.held_index(step)?;
        let held = self.entries.remove(index)?;
        self.bytes = self.bytes.saturating_sub(held.size);
        self.timeline.forget(step);
        self.revision += 1;
        held.entry.note
    }
}

// ---------------------------------------------------------------------------
// Notes in recipes
// ---------------------------------------------------------------------------

/// Carry `journal`'s notes into `recipe`, made of the journal's steps
/// `recorded` (the journal step of each recipe step, in the recipe's
/// order). A note linked to some of those steps is written in full into
/// the `note` of the first, after "As recorded on <file>:", so a run on
/// another file does not present its values as that file's; the others it
/// links say "See the note on step N." Several notes on one step are
/// joined by a blank line. A note linked only to evidence reads the recipe
/// leaves out goes on the first recipe step taken after it was written
/// (the last when none was). The steps a note cites are renumbered as the
/// recipe numbers them; a step the recipe does not hold is cited as
/// "session step N". Any other note linked to none of the recipe's steps
/// is left out.
pub fn attach_to_recipe(recipe: &mut Recipe, journal: &Journal, recorded: &[u64]) {
    let numbers: BTreeMap<u64, u64> = recorded.iter().zip(&recipe.steps).map(|(journal_step, step)| (*journal_step, step.step)).collect();
    let mut in_full: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut pointing_to: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for entry in journal.notes() {
        let Some(note) = &entry.note else { continue };
        let on = recipe_steps_of(note, entry.step, journal, &numbers);
        let Some((first, others)) = on.split_first() else { continue };
        in_full.entry(*first).or_default().push(renumber(&note.text, &numbers));
        for other in others {
            pointing_to.entry(*other).or_default().push(*first);
        }
    }
    let recorded_on = recipe.input_recorded_on().map(|file| file.name.clone());
    for step in &mut recipe.steps {
        let mut parts = Vec::new();
        if let Some(texts) = in_full.remove(&step.step) {
            let texts = texts.join("\n\n");
            parts.push(match &recorded_on {
                Some(file) => format!("As recorded on {file}: {texts}"),
                None => texts,
            });
        }
        let mut firsts = pointing_to.remove(&step.step).unwrap_or_default();
        firsts.dedup();
        parts.extend(firsts.into_iter().map(|first| format!("See the note on step {first}.")));
        if !parts.is_empty() {
            step.note = Some(parts.join("\n\n"));
        }
    }
}

/// The recipe steps `note`, written as journal step `written`, goes on, in
/// order: those it links that the recipe holds (`numbers`, by journal
/// step), or, when it links only evidence the recipe leaves out, the first
/// recipe step after it (the last step when none is).
fn recipe_steps_of(note: &Note, written: u64, journal: &Journal, numbers: &BTreeMap<u64, u64>) -> Vec<u64> {
    let mut on: Vec<u64> = note.steps.iter().filter_map(|step| numbers.get(step)).copied().collect();
    on.sort_unstable();
    on.dedup();
    let about_evidence = note.steps.iter().any(|step| journal.entry(*step).is_some_and(|entry| entry.evidence));
    if on.is_empty() && about_evidence {
        let next = numbers.range(written..).next().or_else(|| numbers.iter().next_back());
        on.extend(next.map(|(_, number)| *number));
    }
    on
}

/// `text` with each step it cites numbered as `numbers` say, or as
/// "session step N" when they do not hold it.
fn renumber(text: &str, numbers: &BTreeMap<u64, u64>) -> String {
    renumber_with(text, |step| match numbers.get(&step) {
        Some(number) => format!("#{number}"),
        None => format!("session step {step}"),
    })
}

/// `text` with each step it cites written as `cite` says, and each
/// escaped citation as words.
fn renumber_with(text: &str, cite: impl Fn(u64) -> String) -> String {
    segments(text)
        .into_iter()
        .map(|segment| match segment {
            Segment::Text(words) => words.to_string(),
            Segment::Step(step) => cite(step),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The steps in plain words
// ---------------------------------------------------------------------------

/// Between the names of a sheet's ancestors in its name.
const LINEAGE_SEPARATOR: &str = " › ";
/// Longest packet set name, or text value, shown in a description.
const SHOWN_TEXT_LIMIT: usize = 40;
/// Most parts of a result summarised.
const RESULT_PARTS: usize = 3;
/// Lists of a result a summary leaves out while they are empty: "0 notes"
/// says nothing, where "0 matches" does.
const SAID_ONLY_WHEN_THERE: [&str; 2] = ["notes", "warnings"];
/// Places a fraction in a result summary is shown to.
const FRACTION_DIGITS: usize = 4;
/// Parameters a description names in its own words, not as a detail.
const NAMED_PARAMS: [&str; 3] = ["doc", "set", "output"];
/// The fields of a result a summary says first, when it has them.
const HEADLINE_FIELDS: [&str; 4] = ["headline", "summary", "total", "count"];
/// The fields of a result a summary leaves out: ids and bookkeeping.
const BOOKKEEPING_FIELDS: [&str; 9] = ["doc", "set", "step", "steps", "version", "revision", "next", "output", "outputs"];

/// What the notes and the History tab call the session's documents and
/// packet sets, so a step reads "packets.extract of set "2556 frames…" to
/// a new sheet "telemetry"" rather than naming `set-1` and `doc-2`: a sheet
/// by its label (or the step that made it), a file by its name, a set by
/// its name.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Names {
    documents: BTreeMap<String, String>,
    sets: BTreeMap<String, String>,
    /// The labels of the sheets made, each once, in the order made.
    labels: Vec<String>,
    /// How many sheets were made without a label.
    unlabelled: usize,
}

impl Names {
    /// The names of what `journal`'s session saw and made.
    pub fn of(journal: &Journal) -> Names {
        let mut names = Names::default();
        for document in &journal.session().documents {
            let name = &document.identity.name;
            // A sheet derived outside the history is named by the last part
            // of its lineage: "Packed BCD+0@0x1", not the whole breadcrumb.
            let short = match document.parent {
                None => name.clone(),
                Some(_) => name.rsplit(LINEAGE_SEPARATOR).next().unwrap_or(name).to_string(),
            };
            names.documents.insert(document.id.clone(), short);
        }
        for entry in journal.entries().filter(|entry| entry.outcome.is_ok()) {
            names.note_sheets_made(entry);
            let Some(result) = &entry.result else { continue };
            if let (Some(set), Some(name)) = (result.get("set").and_then(Value::as_str), result.get("name").and_then(Value::as_str)) {
                names.sets.entry(set.to_string()).or_insert_with(|| format!("set \"{}\"", truncate_chars(name, SHOWN_TEXT_LIMIT)));
            }
        }
        names
    }

    /// Name each sheet `entry` made by its label, or by the step.
    fn note_sheets_made(&mut self, entry: &JournalEntry) {
        let outputs = entry.result.as_ref().map(super::sheets_made).unwrap_or_default();
        for (nth, doc) in entry.made.iter().enumerate() {
            let label = outputs.get(nth).and_then(|output| output.label.clone());
            let name = match &label {
                Some(label) => format!("\"{label}\""),
                None => SheetRef::Step { step: entry.step, nth }.describe(),
            };
            match label {
                Some(label) if !self.labels.contains(&label) => self.labels.push(label),
                Some(_) => {}
                None => self.unlabelled += 1,
            }
            self.documents.insert(doc.clone(), name);
        }
    }

    /// What document `id` is called.
    pub fn document(&self, id: &str) -> String {
        self.documents.get(id).cloned().unwrap_or_else(|| id.to_string())
    }

    /// What packet set `id` is called.
    fn set(&self, id: &str) -> String {
        self.sets.get(id).cloned().unwrap_or_else(|| id.to_string())
    }

    /// "Sheets: "telemetry", "polls" and 2 unlabelled.", or `None` when no
    /// step made a sheet.
    fn sheets_line(&self) -> Option<String> {
        let mut named: Vec<String> = self.labels.iter().map(|label| format!("\"{label}\"")).collect();
        if self.unlabelled > 0 {
            named.push(format!("{} unlabelled", self.unlabelled));
        }
        let named: Vec<&str> = named.iter().map(String::as_str).collect();
        (!named.is_empty()).then(|| format!("Sheets: {}.", in_words(&named)))
    }

    /// `text` with each document id (`doc-2`) and packet set id (`set-1`)
    /// it holds replaced by its name.
    pub fn named(&self, text: &str) -> String {
        let mut ids: Vec<usize> = text.match_indices("doc-").chain(text.match_indices("set-")).map(|(at, _)| at).collect();
        ids.sort_unstable();
        let mut named = String::with_capacity(text.len());
        let mut copied_to = 0;
        for at in ids {
            let digits = text[at + 4..].bytes().take_while(u8::is_ascii_digit).count();
            let end = at + 4 + digits;
            let stands_apart = text[..at].chars().next_back().is_none_or(|before| !before.is_alphanumeric()) && text[end..].chars().next().is_none_or(|after| !after.is_alphanumeric());
            let id = &text[at..end];
            let Some(name) = self.documents.get(id).or_else(|| self.sets.get(id)).filter(|_| digits > 0 && stands_apart && at >= copied_to) else { continue };
            named.push_str(&text[copied_to..at]);
            named.push_str(name);
            copied_to = end;
        }
        named.push_str(&text[copied_to..]);
        named
    }

    /// What `entry` did, in plain words: its own description with the
    /// documents and sets it names by name, or, for a call no module
    /// describes, its method, what it ran on, its other parameters (those
    /// an anchor gave left to the anchor) and the sheet it made.
    pub fn describe(&self, entry: &JournalEntry) -> String {
        if !described_generally(entry) {
            return self.named(&entry.description);
        }
        let params = entry.params.as_object();
        let given = |name: &str| params.and_then(|params| params.get(name));
        let mut words = entry.method.clone();
        match (given("set").and_then(Value::as_str), entry.doc.as_deref()) {
            (Some(set), _) => words.push_str(&format!(" of {}", self.set(set))),
            (None, Some(doc)) => words.push_str(&format!(" on {}", self.document(doc))),
            (None, None) => {}
        }
        let details: Vec<String> = params
            .into_iter()
            .flatten()
            .filter(|(name, _)| !NAMED_PARAMS.contains(&name.as_str()) && !entry.derived_from.contains_key(name.as_str()))
            .filter_map(|(name, value)| Some(format!("{name} {}", shown(value)?)))
            .collect();
        if !details.is_empty() {
            words.push_str(&format!(" ({})", details.join(", ")));
        }
        if let Some(output) = given("output") {
            let label = output.get("new").and_then(|new| new.get("label")).and_then(Value::as_str);
            match label {
                Some(label) => words.push_str(&format!(" to a new sheet \"{label}\"")),
                None if output == "new" || output.get("new").is_some() => words.push_str(" to a new sheet"),
                None => {}
            }
        }
        super::cut_to_a_line(self.named(&words))
    }

    /// What `entry` returned, in a few words: the sheets it made, or, for a
    /// read or an analysis, its headline, counts and lists; `None` when it
    /// failed or returned nothing its description does not say already.
    pub fn result_summary(&self, entry: &JournalEntry) -> Option<String> {
        if !entry.outcome.is_ok() {
            return None;
        }
        let result = entry.result.as_ref()?;
        let made = super::sheets_made(result);
        if !made.is_empty() {
            let sheets: Vec<String> = made.iter().map(|sheet| format!("made {} ({} bytes)", self.document(&sheet.doc), sheet.len)).collect();
            return Some(sheets.join(", "));
        }
        if !matches!(entry.effect, Effect::Read | Effect::Analysis) {
            return None;
        }
        let fields = result.as_object()?;
        if fields.get("job").is_some_and(Value::is_string) {
            return Some("started a job".to_string());
        }
        let headline = HEADLINE_FIELDS.iter().filter_map(|name| fields.get_key_value(*name));
        let rest = fields.iter().filter(|(name, _)| !HEADLINE_FIELDS.contains(&name.as_str()) && !BOOKKEEPING_FIELDS.contains(&name.as_str()));
        // A field that only repeats a parameter says nothing new.
        let new = |(name, value): &(&String, &Value)| entry.params.get(name.as_str()) != Some(*value);
        let parts: Vec<String> = headline.chain(rest).filter(new).filter_map(|(name, value)| summarised(name, value)).take(RESULT_PARTS).collect();
        (!parts.is_empty()).then(|| self.named(&parts.join(", ")))
    }
}

/// Whether `entry`'s description is the general "Call method with params"
/// that a call no module describes gets.
fn described_generally(entry: &JournalEntry) -> bool {
    entry.description.is_empty() || entry.description.starts_with(&format!("Call {}", entry.method))
}

/// A parameter's value as a description shows it: text quoted and cut,
/// lists and objects as short JSON; `None` for null.
fn shown(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::Bool(_) | Value::Number(_) => Some(value.to_string()),
        Value::String(text) => Some(format!("\"{}\"", truncate_chars(text, SHOWN_TEXT_LIMIT))),
        _ => Some(truncate_chars(&value.to_string(), SHOWN_TEXT_LIMIT)),
    }
}

/// A field of a result in a few words: "total 2556", "5 candidates",
/// `headline "Looks like machine code"`; `None` for what says little.
fn summarised(name: &str, value: &Value) -> Option<String> {
    match value {
        Value::Array(items) if items.is_empty() && SAID_ONLY_WHEN_THERE.contains(&name) => None,
        Value::Array(items) => Some(format!("{} {name}", items.len())),
        Value::Number(number) => match number.as_f64().filter(|_| number.is_f64()) {
            Some(fraction) => Some(format!("{name} {}", rounded(fraction))),
            None => Some(format!("{name} {number}")),
        },
        Value::String(text) if text.chars().count() <= SHOWN_TEXT_LIMIT => Some(format!("{name} \"{text}\"")),
        _ => None,
    }
}

/// A fraction to at most [`FRACTION_DIGITS`] places, without trailing
/// zeros: 0.9960202438 as "0.996".
fn rounded(fraction: f64) -> String {
    let fixed = format!("{fraction:.FRACTION_DIGITS$}");
    fixed.trim_end_matches('0').trim_end_matches('.').to_string()
}

// ---------------------------------------------------------------------------
// The notes as Markdown
// ---------------------------------------------------------------------------

/// The session's notes as Markdown: a title naming the input file(s), the
/// sheets made by label, when the session started, then each note in the
/// order written, with its kind, who wrote it and when, its text and the
/// steps it cites, each in plain words ([`Names`]) with where its values
/// came from and what it returned, the evidence reads marked. It ends with
/// the fallbacks noted. Returns the text and how many notes it holds.
pub fn markdown(journal: &Journal) -> (String, usize) {
    let names = Names::of(journal);
    let mut out = format!("# {}\n\n", title(journal));
    if let Some(sheets) = names.sheets_line() {
        out.push_str(&format!("{sheets}\n\n"));
    }
    out.push_str(&format!("Session started {}.\n", journal.session().started_at));
    let mut fallbacks = Vec::new();
    for entry in journal.notes() {
        let Some(note) = &entry.note else { continue };
        if note.kind == NoteKind::Fallback {
            fallbacks.push(entry);
        }
        out.push_str(&format!("\n## Note {} · {} · {} · {}\n\n", entry.step, note.kind.name(), entry.caller, entry.at));
        if let (Some(at), Some(by)) = (&note.edited_at, &note.edited_by) {
            out.push_str(&format!("*Edited {at} by {by}.*\n\n"));
        }
        out.push_str(as_read(&note.text).trim_end());
        out.push('\n');
        if note.steps.is_empty() {
            continue;
        }
        out.push_str("\nSteps cited:\n\n");
        for step in &note.steps {
            out.push_str(&cited_step(journal, &names, *step, &entry.caller));
        }
    }
    let count = journal.notes().count();
    if count == 0 {
        out.push_str("\nNo notes were written in this session.\n");
        return (out, count);
    }
    out.push_str("\n## Fallbacks\n\n");
    if fallbacks.is_empty() {
        out.push_str("No note was marked as a fallback.\n");
    }
    for entry in fallbacks {
        let text = entry.note.as_ref().map_or_else(String::new, |note| as_read(&note.text));
        let one_line = super::cut_to_a_line(text.split_whitespace().collect::<Vec<_>>().join(" "));
        out.push_str(&format!("- Note {}: {one_line}\n", entry.step));
    }
    (out, count)
}

/// "Notes on capture.bin": the files the session started from, not the
/// sheets made from them; "Analysis notes" when it saw none.
fn title(journal: &Journal) -> String {
    let mut inputs: Vec<&str> = Vec::new();
    for document in journal.session().documents.iter().filter(|document| document.parent.is_none()) {
        if !inputs.contains(&document.identity.name.as_str()) {
            inputs.push(&document.identity.name);
        }
    }
    match inputs.as_slice() {
        [] => "Analysis notes".to_string(),
        inputs => format!("Notes on {}", in_words(inputs)),
    }
}

/// The line of a note's export for step `step`, which it cites: its
/// number, whether it is evidence, its caller (when not the note's own,
/// `note_caller`), what it did, where it stands and what it returned, then
/// where each of its values came from (but its sheets, which it names).
fn cited_step(journal: &Journal, names: &Names, step: u64, note_caller: &str) -> String {
    let Some(cited) = journal.entry(step) else { return format!("- #{step} · no longer in the history\n") };
    let mut line = format!("- #{step}");
    if cited.evidence {
        line.push_str(" · evidence");
    }
    if cited.caller != note_caller {
        line.push_str(&format!(" · {}", cited.caller));
    }
    line.push_str(&format!(" · {}", names.describe(cited)));
    match journal.timeline().status(step) {
        Some(StepStatus::Undone { by }) => line.push_str(&format!(" (undone by step {by})")),
        Some(StepStatus::Failed) => line.push_str(" (failed)"),
        _ => {}
    }
    if let Some(result) = names.result_summary(cited) {
        line.push_str(&format!(" → {result}"));
    }
    line.push('\n');
    // A sheet anchor names the sheet the description names already.
    for (path, anchor) in cited.derived_from.iter().filter(|(_, anchor)| !matches!(anchor, Anchor::Sheet { .. })) {
        line.push_str(&format!("  - `{path}` from {}\n", names.named(&anchor.describe())));
    }
    line
}

/// `names` in a sentence: "a", "a and b", "a, b and c".
fn in_words(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => one.to_string(),
        [first @ .., last] => format!("{} and {last}", first.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_and_digits_standing_apart_cite_a_step() {
        let text = "Split at #3, then (#12). Not a#4, #5b, #ff00aa, &#38; or #.";
        assert_eq!(cited_steps(text), [3, 12]);
        assert_eq!(segments("#7 starts it"), [Segment::Step(7), Segment::Text(" starts it")]);
        assert_eq!(segments("see #7"), [Segment::Text("see "), Segment::Step(7)]);
    }

    #[test]
    fn a_backslash_before_a_citation_makes_it_words_without_the_backslash() {
        assert_eq!(cited_steps("packet \\#917 and #3"), [3]);
        assert_eq!(as_read("packet \\#917 and #3, a \\ b \\#x"), "packet #917 and #3, a \\ b \\#x");
        assert_eq!(segments("\\#5"), [Segment::Text("#5")]);
    }

    #[test]
    fn a_result_summary_rounds_fractions_and_leaves_out_empty_notes() {
        assert_eq!(summarised("coverage", &json!(0.9960202438463308)).as_deref(), Some("coverage 0.996"));
        assert_eq!(summarised("entropy", &json!(5.699736401715849)).as_deref(), Some("entropy 5.6997"));
        assert_eq!(summarised("frames", &json!(2556)).as_deref(), Some("frames 2556"));
        assert_eq!((summarised("matches", &json!([])).as_deref(), summarised("notes", &json!([]))), (Some("0 matches"), None));
    }

    #[test]
    fn ids_in_a_description_are_replaced_by_names_only_where_they_stand_apart() {
        let names = Names {
            documents: BTreeMap::from([("doc-2".to_string(), "\"frames\"".to_string())]),
            sets: BTreeMap::from([("set-1".to_string(), "set \"bursts\"".to_string())]),
            ..Names::default()
        };
        assert_eq!(names.named("doc-2, set-1, doc-22, xdoc-2 and doc-9"), "\"frames\", set \"bursts\", doc-22, xdoc-2 and doc-9");
    }

    #[test]
    fn a_note_is_linked_to_the_steps_it_cites_and_those_given_once_each() {
        assert_eq!(linked_steps("Because #9 found it, #2 and #9 again", &[4, 2]), [2, 4, 9]);
    }

    #[test]
    fn a_note_s_description_is_its_text_on_one_line() {
        assert_eq!(describe("The header\nends at #3"), "Note: The header ends at #3");
    }

    #[test]
    fn a_note_in_a_recipe_cites_the_recipe_s_numbers() {
        let numbers = BTreeMap::from([(4, 1), (9, 2)]);
        assert_eq!(renumber("After #4, #9 decodes; #6 was a dead end", &numbers), "After #1, #2 decodes; session step 6 was a dead end");
    }

    #[test]
    fn the_documents_are_named_in_a_sentence() {
        assert_eq!(in_words(&["a.bin"]), "a.bin");
        assert_eq!(in_words(&["a.bin", "b.bin", "c.bin"]), "a.bin, b.bin and c.bin");
    }
}
