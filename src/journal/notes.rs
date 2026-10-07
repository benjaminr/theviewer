//! Notes: what the person or a client was thinking as they worked, written
//! into the journal among the steps (`history.note`).
//!
//! A note is an entry of its own, recorded where it was written and by
//! whom, so the History tab shows the reasoning in its place. Its text may
//! cite steps as `#12`; those, and any steps given beside it, are the steps
//! it is linked to, which must be in the journal (a recent read it cites is
//! moved into the journal, as a step citing it would be). Each step lists
//! the notes linked to it ([`Journal::notes_by_step`]).
//!
//! A note changes nothing. Its method is declared a note
//! ([`crate::api::Method::writes_a_note`]), so the timeline marks it as one
//! ([`super::timeline::StepStatus::Note`]): it is never undone, repeated by
//! playback, going back or recipes, nor undone by going back past it.
//! Editing or deleting a note is not a step of its own either: the note is
//! changed in place, or taken out of the journal, and an edited note says
//! when and by whom.
//!
//! [`markdown`] writes the analysis out as Markdown.

use std::collections::BTreeMap;
use std::time::SystemTime;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::timeline::{Replay, StepStatus, replay_of};
use super::{Held, Journal, JournalEntry, timestamp};
use crate::api::{ApiError, Caller, Workspace};

/// The method that writes a note.
pub const NOTE_METHOD: &str = "history.note";
/// The longest note kept, in bytes of UTF-8.
pub const NOTE_TEXT_LIMIT: usize = 4096;
/// What a note's description starts with in the History tab and
/// `history.list`.
const DESCRIPTION_PREFIX: &str = "Note: ";

/// A note's text and the steps it is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Note {
    /// What it says, as written; `#12` cites step 12.
    pub text: String,
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
/// cite step 12, `a#12`, `#12b` and `#ff00aa` cite nothing.
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
    let one_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    super::cut_to_a_line(format!("{DESCRIPTION_PREFIX}{one_line}"))
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
/// the journal, as a step citing it would.
fn check_links(workspace: &mut dyn Workspace, linked: &[u64], itself: Option<u64>) -> Result<(), ApiError> {
    if let Some(step) = itself.filter(|step| linked.contains(step)) {
        return Err(ApiError::invalid_params(format!("note {step} cannot be linked to itself; cite the steps it is about")));
    }
    let missing: Vec<u64> = linked.iter().copied().filter(|step| !super::promote(workspace, *step)).collect();
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
    Some(Note { text, steps, edited_at: None, edited_by: None })
}

/// Change note `step` to say `text`, linked to the steps it cites and those
/// `given` (those given before when `None`), as `caller`. Not a step of its
/// own: the note is changed in place and says it was edited.
pub fn edit(workspace: &mut dyn Workspace, caller: &Caller, step: u64, text: &str, given: Option<Vec<u64>>) -> Result<Note, ApiError> {
    let entry = workspace.journal().note_entry(step)?;
    let given = given.unwrap_or_else(|| given_steps(&entry.params));
    check_text(text)?;
    let linked = linked_steps(text, &given);
    check_links(workspace, &linked, Some(step))?;
    let note = Note { text: text.to_string(), steps: linked, edited_at: Some(timestamp(SystemTime::now())), edited_by: Some(caller.producer()) };
    workspace.journal_mut().replace_note(step, note.clone(), json!({"text": text, "steps": given}));
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
                by_step.entry(*step).or_default().push(NoteOn { step: entry.step, caller: entry.caller.clone(), text: note.text.clone() });
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
// The notes as Markdown
// ---------------------------------------------------------------------------

/// The session's notes as Markdown: a title naming the documents, when the
/// session started, then each note in the order written, with who wrote it
/// and when, its text as written (`#12` and all), and the steps it cites:
/// each one's number, caller and description. Returns the text and how
/// many notes it holds.
pub fn markdown(journal: &Journal) -> (String, usize) {
    let session = journal.session();
    let mut names: Vec<&str> = Vec::new();
    for document in &session.documents {
        if !names.contains(&document.identity.name.as_str()) {
            names.push(&document.identity.name);
        }
    }
    let title = match names.as_slice() {
        [] => "Analysis notes".to_string(),
        names => format!("Notes on {}", in_words(names)),
    };
    let mut out = format!("# {title}\n\nSession started {}.\n", session.started_at);
    let timeline = journal.timeline();
    let mut count = 0;
    for entry in journal.notes() {
        let Some(note) = &entry.note else { continue };
        count += 1;
        out.push_str(&format!("\n## Note {} · {} · {}\n\n", entry.step, entry.caller, entry.at));
        if let (Some(at), Some(by)) = (&note.edited_at, &note.edited_by) {
            out.push_str(&format!("*Edited {at} by {by}.*\n\n"));
        }
        out.push_str(note.text.trim_end());
        out.push('\n');
        if note.steps.is_empty() {
            continue;
        }
        out.push_str("\nSteps cited:\n\n");
        for step in &note.steps {
            let line = match journal.entry(*step) {
                Some(cited) => {
                    let description = if cited.description.is_empty() { cited.method.as_str() } else { cited.description.as_str() };
                    let standing = match timeline.status(*step) {
                        Some(StepStatus::Undone { by }) => format!(" (undone by step {by})"),
                        Some(StepStatus::Failed) => " (failed)".to_string(),
                        _ => String::new(),
                    };
                    format!("- #{step} · {} · {description}{standing}\n", cited.caller)
                }
                None => format!("- #{step} · no longer in the history\n"),
            };
            out.push_str(&line);
        }
    }
    if count == 0 {
        out.push_str("\nNo notes were written in this session.\n");
    }
    (out, count)
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
    fn a_note_is_linked_to_the_steps_it_cites_and_those_given_once_each() {
        assert_eq!(linked_steps("Because #9 found it, #2 and #9 again", &[4, 2]), [2, 4, 9]);
    }

    #[test]
    fn a_note_s_description_is_its_text_on_one_line() {
        assert_eq!(describe("The header\nends at #3"), "Note: The header ends at #3");
    }

    #[test]
    fn the_documents_are_named_in_a_sentence() {
        assert_eq!(in_words(&["a.bin"]), "a.bin");
        assert_eq!(in_words(&["a.bin", "b.bin", "c.bin"]), "a.bin, b.bin and c.bin");
    }
}
