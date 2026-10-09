//! The History tab: the session's journal, step by step, with who took
//! each step and what it did; undoing a step, going back to one, playback,
//! and saving the history as a recipe.
//!
//! The tab follows the journal by its revision (a read promoted into the
//! journal takes an earlier number, so following by the last step alone
//! would miss it), and lists each step with its caller, its description
//! (sheets by label, sets by name: [`notes::Names`]) and marks: bytes
//! changed, failed or refused, merged moves, undone, and evidence (a read
//! kept because a note cites it, dimmed, which recipes leave out). A
//! step clicked shows its parameters, result and how it would be undone,
//! with the bytes it touched a click away, and the literals a recipe would
//! repeat, each of which can become an anchor or a named parameter.
//!
//! Notes written into the history (`history.note`) are shown among the
//! steps as cards of their own: who wrote one, when, its kind and its text,
//! in which `#12` is a link to step 12. The box at the foot of the tab
//! writes one, of the kind chosen beside it; each step's *Note* button
//! starts one about it. A note card can be
//! edited or deleted, and steps with notes linked to them link back.
//!
//! Everything the person does here is a method call as the panel:
//! `history.undo_step`, `history.go_back`, `history.save_recipe`, the
//! anchor methods and the note methods. Playback goes back to the step
//! before the first played, then runs the steps again one at a time
//! through the recipe runner, each recorded as a step of its own (see
//! [`crate::journal::timeline`]); notes are never played or undone.

use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

use eframe::egui::{self, Key, Modifiers, RichText, Ui};
use serde_json::{Value, json};

use crate::api::ErrorCode;
use crate::app::ViewerApp;
use crate::journal::notes::{self, Names, Note, NoteKind, Segment};
use crate::journal::provenance::{self, LiteralSuggestions};
use crate::journal::timeline::{self, Inverse, Playback, StepStatus, Timeline};
use crate::journal::{JournalEntry, Outcome};
use crate::{recipes, theme};

mod sheets_view;
mod variables;

/// Height of the list of steps when a step's details are shown below it.
const LIST_HEIGHT: f32 = 220.0;
/// Characters of a parameter or result shown before it is cut.
const DETAIL_CHARS: usize = 4000;
/// The name a recipe is saved under when none is typed.
const DEFAULT_RECIPE_NAME: &str = "My analysis";
/// What the note box says while it is empty.
pub const NOTE_HINT: &str = "Note what you're doing and why… (#12 links a step)";
/// How long a step a link went to stays highlighted.
const HIGHLIGHT_FOR: Duration = Duration::from_millis(1800);
/// Rows of text the note box shows.
const NOTE_BOX_ROWS: usize = 3;

/// How fast playback moves on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Speed {
    /// The person moves on with "Next step".
    #[default]
    OneAtATime,
    Slow,
    Normal,
    Fast,
}

impl Speed {
    const ALL: [Speed; 4] = [Speed::OneAtATime, Speed::Slow, Speed::Normal, Speed::Fast];

    fn label(self) -> &'static str {
        match self {
            Speed::OneAtATime => "One step at a time",
            Speed::Slow => "A step a second",
            Speed::Normal => "Two steps a second",
            Speed::Fast => "Six steps a second",
        }
    }

    /// How long each step stays before the next; none when the person
    /// moves on.
    fn interval(self) -> Option<Duration> {
        match self {
            Speed::OneAtATime => None,
            Speed::Slow => Some(Duration::from_millis(1000)),
            Speed::Normal => Some(Duration::from_millis(500)),
            Speed::Fast => Some(Duration::from_millis(160)),
        }
    }
}

/// One step as the list shows it.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub step: u64,
    pub caller: String,
    pub method: String,
    pub description: String,
    pub status: StepStatus,
    /// Whether it changed its document's bytes.
    pub changed_bytes: bool,
    /// Why it failed, when it did.
    pub error: Option<String>,
    /// Whether the caller's permissions refused it.
    pub refused: bool,
    /// Earlier moves it replaced.
    pub merged: u32,
    /// When it was taken, UTC.
    pub at: String,
    /// For a note, what it says and the steps it links.
    pub note: Option<Note>,
    /// The notes linked to it: each one's step and text.
    pub noted_by: Vec<(u64, String)>,
    /// Whether it is a read kept only because a note cites it.
    pub evidence: bool,
    /// The sheet it was about.
    pub doc: Option<String>,
    /// What the sheets it made are called.
    pub made: Vec<String>,
    /// Where its anchored values came from, each in a few words: "$serial",
    /// "pick #4 /^NC500-/".
    pub sources: Vec<String>,
}

impl Row {
    fn of(entry: &JournalEntry, names: &Names, status: StepStatus, noted_by: Vec<(u64, String)>) -> Row {
        let error = match &entry.outcome {
            Outcome::Ok => None,
            Outcome::Error(error) => Some(error.message.clone()),
        };
        let refused = matches!(&entry.outcome, Outcome::Error(error) if error.code == ErrorCode::ReadOnly);
        let description = names.describe(entry);
        let mut sources: Vec<String> = Vec::new();
        for anchor in entry.derived_from.values() {
            let source = crate::send_to::anchor_source(anchor);
            if !sources.contains(&source) {
                sources.push(source);
            }
        }
        Row {
            step: entry.step,
            caller: entry.caller.clone(),
            method: entry.method.clone(),
            description,
            status,
            changed_bytes: entry.changed_document(),
            error,
            refused,
            merged: entry.merged,
            at: entry.at.clone(),
            note: entry.note.clone(),
            noted_by,
            evidence: entry.evidence,
            doc: entry.doc.clone(),
            made: entry.made.iter().map(|doc| names.document(doc)).collect(),
            sources,
        }
    }

    fn is_undone(&self) -> bool {
        matches!(self.status, StepStatus::Undone { .. })
    }

    fn is_note(&self) -> bool {
        self.note.is_some()
    }
}

/// A note being edited in its card.
#[derive(Clone, Debug, PartialEq)]
pub struct EditingNote {
    pub step: u64,
    pub text: String,
}

/// Playback under way.
pub struct PlaybackRun {
    pub playback: Playback,
    pub paused: bool,
    last_played: Instant,
}

/// The selected step's details as shown, read once for the step, the
/// journal's revision and its document's version rather than every frame.
struct StepDetails {
    step: u64,
    revision: u64,
    doc_version: Option<u64>,
    /// Its method, caller and time.
    heading: String,
    description: String,
    error: Option<String>,
    /// Whether it is in effect, so it can be undone.
    active: bool,
    inverse: Inverse,
    touched: Option<(usize, usize)>,
    params: String,
    result: Option<String>,
    succeeded: bool,
}

impl StepDetails {
    fn read(entry: &JournalEntry, revision: u64, doc_version: Option<u64>, active: bool, inverse: Inverse) -> StepDetails {
        StepDetails {
            step: entry.step,
            revision,
            doc_version,
            heading: format!("{} · {} · {}", entry.method, entry.caller, entry.at),
            description: entry.description.clone(),
            error: match &entry.outcome {
                Outcome::Ok => None,
                Outcome::Error(error) => Some(error.message.clone()),
            },
            active,
            inverse,
            touched: touched_span(entry),
            params: pretty_json_cut(&entry.params, DETAIL_CHARS),
            result: entry.result.as_ref().map(|result| pretty_json_cut(result, DETAIL_CHARS)),
            succeeded: entry.outcome.is_ok(),
        }
    }

    fn is_for(&self, step: u64, revision: u64, doc_version: Option<u64>) -> bool {
        self.step == step && self.revision == revision && self.doc_version == doc_version
    }
}

/// What the tab remembers between frames.
pub struct HistoryState {
    /// The journal's revision the rows were read at.
    seen_revision: Option<u64>,
    pub rows: Vec<Row>,
    /// Rows undone, notes, and whether any step is in effect, as of the
    /// revision the rows were read at.
    undone: usize,
    notes: usize,
    any_active: bool,
    /// Every caller in the journal, for the filter.
    callers: Vec<String>,
    /// The caller whose steps are shown, or every caller's.
    pub caller_filter: Option<String>,
    /// Show the steps undone too.
    pub show_undone: bool,
    /// Show the notes only.
    pub notes_only: bool,
    /// The step whose details are shown.
    pub selected: Option<u64>,
    /// Anchors that could stand for the selected step's literals, at a
    /// journal revision.
    suggestions: Option<(u64, u64, Vec<LiteralSuggestions>)>,
    /// The selected step's details, while they still hold.
    details: Option<StepDetails>,
    /// The name typed for a new recipe parameter.
    pub parameter_name: String,
    /// The name the recipe is saved under.
    pub recipe_name: String,
    /// The range of steps to play, and how fast.
    pub play_from: u64,
    pub play_through: u64,
    pub speed: Speed,
    pub playback: Option<PlaybackRun>,
    /// What the tab last had to say: why an undo, playback or note failed.
    pub message: Option<String>,
    /// The note being written in the box at the foot of the tab.
    pub note_draft: String,
    /// The kind of note the box writes.
    pub note_kind: NoteKind,
    /// Put the cursor in the note box on the next frame.
    focus_note_box: bool,
    /// The note being edited in its card.
    pub editing: Option<EditingNote>,
    /// The step a link asked to be scrolled to, on the next frame.
    pub scroll_to: Option<u64>,
    /// The step a link went to, highlighted for a moment from when.
    pub highlighted: Option<(u64, Instant)>,
    /// How tall each row and note card was when last drawn, by step, so the
    /// list lays out only the rows in view.
    heights: HashMap<u64, f32>,
    /// Show the steps grouped under the sheets they ran on.
    pub sheets_view: bool,
    /// The tree of sheets the Sheets view shows, for a journal revision and
    /// the rows the filters kept.
    sheet_tree: Option<(u64, Vec<usize>, Vec<sheets_view::SheetNode>)>,
    /// What would stop the steps replaying as a recipe, at a revision.
    recipe_checks: Option<(u64, sheets_view::RecipeChecks)>,
    /// The step whose recipe values to open, once its details are shown.
    open_recipe_values: Option<u64>,
}

impl Default for HistoryState {
    fn default() -> Self {
        HistoryState {
            seen_revision: None,
            rows: Vec::new(),
            undone: 0,
            notes: 0,
            any_active: false,
            callers: Vec::new(),
            caller_filter: None,
            show_undone: true,
            notes_only: false,
            selected: None,
            suggestions: None,
            details: None,
            parameter_name: String::new(),
            recipe_name: DEFAULT_RECIPE_NAME.to_string(),
            play_from: 0,
            play_through: 0,
            speed: Speed::default(),
            playback: None,
            message: None,
            note_draft: String::new(),
            note_kind: NoteKind::default(),
            focus_note_box: false,
            editing: None,
            scroll_to: None,
            highlighted: None,
            heights: HashMap::new(),
            sheets_view: false,
            sheet_tree: None,
            recipe_checks: None,
            open_recipe_values: None,
        }
    }
}

impl HistoryState {
    /// Read the journal again when it has changed since the rows were read.
    pub fn follow(&mut self, app: &ViewerApp) {
        let revision = app.journal.revision();
        if self.seen_revision == Some(revision) {
            return;
        }
        self.seen_revision = Some(revision);
        let timeline = Timeline::of(&app.journal);
        let names = Names::of(&app.journal);
        let mut noted = app.journal.notes_by_step();
        self.rows = app
            .journal
            .entries()
            .map(|entry| {
                let noted_by = noted.remove(&entry.step).unwrap_or_default().into_iter().map(|note| (note.step, note.text)).collect();
                Row::of(entry, &names, timeline.status(entry.step).unwrap_or(StepStatus::Active), noted_by)
            })
            .collect();
        self.undone = self.rows.iter().filter(|row| row.is_undone()).count();
        self.notes = self.rows.iter().filter(|row| row.is_note()).count();
        self.any_active = self.rows.iter().any(|row| row.status == StepStatus::Active);
        self.callers = Vec::new();
        for row in &self.rows {
            if !self.callers.contains(&row.caller) {
                self.callers.push(row.caller.clone());
            }
        }
        let last = self.rows.last().map_or(0, |row| row.step);
        if self.play_through == 0 || self.play_through > last {
            self.play_through = last;
        }
    }

    /// Where in `rows` the rows the filters keep are.
    fn shown(&self) -> impl Iterator<Item = usize> {
        let kept = |row: &Row| self.caller_filter.as_ref().is_none_or(|caller| *caller == row.caller) && (self.show_undone || !row.is_undone()) && (!self.notes_only || row.is_note());
        self.rows.iter().enumerate().filter(move |(_, row)| kept(row)).map(|(index, _)| index)
    }

    /// The row of `step`; rows are in step order, as the journal holds them.
    fn row(&self, step: u64) -> Option<&Row> {
        let index = self.rows.binary_search_by_key(&step, |row| row.step).ok()?;
        self.rows.get(index)
    }

    /// Start a note about `step` in the box at the foot of the tab: `#N `,
    /// after anything already typed.
    pub fn note_about(&mut self, step: u64) {
        if !self.note_draft.is_empty() && !self.note_draft.ends_with(char::is_whitespace) {
            self.note_draft.push(' ');
        }
        self.note_draft.push_str(&format!("#{step} "));
        self.focus_note_box = true;
    }

    /// Follow a link to `step`: scroll to it and highlight it, showing it
    /// first if the filters hide it.
    pub fn go_to_step(&mut self, step: u64) {
        let Some(index) = self.rows.binary_search_by_key(&step, |row| row.step).ok() else {
            self.message = Some(format!("Step {step} is no longer in the history"));
            return;
        };
        if !self.shown().any(|shown| shown == index) {
            self.caller_filter = None;
            self.notes_only = false;
            self.show_undone = true;
        }
        self.scroll_to = Some(step);
        self.highlighted = Some((step, Instant::now()));
    }

    /// Whether `step` is highlighted now, having been gone to by a link.
    fn is_highlighted(&self, step: u64) -> bool {
        self.highlighted.is_some_and(|(highlighted, since)| highlighted == step && since.elapsed() < HIGHLIGHT_FOR)
    }
}

pub fn show_history(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui) {
    // In a tab too short for the steps and the note box together, the tab
    // scrolls rather than drawing one over the other.
    let visible = ui.available_height();
    egui::ScrollArea::vertical().id_salt("history-tab").auto_shrink([false, false]).show(ui, |ui| show_history_inside(state, app, ui, visible));
}

fn show_history_inside(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui, visible: f32) {
    let top = ui.cursor().min.y;
    state.follow(app);
    play_due_step(state, app, ui.ctx());
    show_toolbar(state, app, ui);
    show_playback(state, app, ui);
    if let Some(message) = &state.message {
        ui.label(RichText::new(message).small().color(theme::DANGER));
    }
    ui.separator();
    // The list takes what the note box below it leaves, so the box is never
    // drawn over the steps, however short the tab is.
    let used = ui.cursor().min.y - top;
    let left = (visible - used - note_box_height(ui)).max(MIN_LIST_HEIGHT);
    let list_height = if state.selected.is_some() { LIST_HEIGHT.min(left) } else { left };
    if state.rows.is_empty() {
        let list = egui::ScrollArea::vertical().id_salt("history-steps").max_height(list_height).auto_shrink([false, true]);
        list.show(ui, |ui| ui.label(RichText::new("Nothing done yet. Each edit, view change, packet set and job, by you, plugins, Ask or MCP clients, is listed here as a step, with the notes written beside them.").color(theme::TEXT_DIM)));
    } else if state.sheets_view {
        let warnings_height = ui.spacing().interact_size.y;
        sheets_view::show(state, app, ui, (list_height - warnings_height).max(MIN_LIST_HEIGHT));
        sheets_view::show_warnings(state, app, ui);
    } else {
        show_steps(state, app, ui, list_height);
    }
    if let Some(step) = state.selected {
        ui.separator();
        let used = ui.cursor().min.y - top;
        let details_height = (visible - used - note_box_height(ui)).max(MIN_LIST_HEIGHT);
        egui::ScrollArea::vertical().id_salt("history-details").max_height(details_height).show(ui, |ui| show_details(state, app, ui, step));
    }
    ui.separator();
    show_note_box(state, app, ui);
    ui.separator();
    variables::show_variables(state, app, ui);
}

/// The steps keep at least this much room, the note box going below.
const MIN_LIST_HEIGHT: f32 = 48.0;

/// The height the note box, its button row and the variables below take.
fn note_box_height(ui: &Ui) -> f32 {
    let row = ui.text_style_height(&egui::TextStyle::Body);
    let spacing = ui.spacing();
    row * NOTE_BOX_ROWS as f32 + spacing.interact_size.y * 2.0 + spacing.item_spacing.y * 5.0 + spacing.button_padding.y * 4.0 + 8.0
}

/// The steps and notes the filters keep, laying out only those in view: a
/// step is a row of one line, a note a card as tall as its text was when
/// last drawn. A link followed scrolls its step into view.
fn show_steps(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui, list_height: f32) {
    let shown: Vec<usize> = state.shown().collect();
    let gap = ui.spacing().item_spacing.y;
    let row_height = ui.spacing().interact_size.y;
    let heights: Vec<f32> = shown.iter().map(|&index| state.heights.get(&state.rows[index].step).copied().unwrap_or(row_height)).collect();
    let mut tops = Vec::with_capacity(heights.len());
    let mut total = 0.0;
    for height in &heights {
        tops.push(total);
        total += height + gap;
    }
    let mut list = egui::ScrollArea::vertical().id_salt("history-steps").max_height(list_height).stick_to_bottom(true).auto_shrink([false, true]);
    if let Some(step) = state.scroll_to.take()
        && let Some(position) = shown.iter().position(|&index| state.rows[index].step == step)
    {
        list = list.vertical_scroll_offset((tops[position] - list_height / 3.0).max(0.0));
    }
    let mut measured_anew = false;
    list.show_viewport(ui, |ui, viewport| {
        ui.set_height((total - gap).max(0.0));
        let origin = ui.max_rect().min;
        let width = ui.max_rect().width();
        let first = tops.iter().zip(&heights).position(|(top, height)| top + height >= viewport.min.y).unwrap_or(shown.len());
        for position in first..shown.len() {
            if tops[position] > viewport.max.y {
                break;
            }
            // Each copied out, so its buttons can change the state it was
            // read from.
            let row = state.rows[shown[position]].clone();
            let rect = egui::Rect::from_min_size(origin + egui::vec2(0.0, tops[position]), egui::vec2(width, heights[position]));
            let builder = egui::UiBuilder::new().max_rect(rect).id_salt(("history-step", row.step));
            let drawn = ui.scope_builder(builder, |ui| show_item(state, app, ui, &row)).response.rect.height();
            if (drawn - heights[position]).abs() > 0.5 {
                state.heights.insert(row.step, drawn);
                measured_anew = true;
            }
        }
    });
    if measured_anew {
        ui.ctx().request_repaint();
    }
}

/// A step's row or a note's card, highlighted for a moment when a link
/// went to it.
fn show_item(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui, row: &Row) {
    if state.is_highlighted(row.step) {
        ui.painter().rect_filled(ui.max_rect(), 3.0, theme::POINTED_FILL);
        ui.ctx().request_repaint_after(HIGHLIGHT_FOR);
    }
    if row.is_note() {
        show_note_card(state, app, ui, row);
    } else {
        show_row(state, app, ui, row);
    }
}

/// What the person asked of a note's card.
enum CardAction {
    Edit,
    Delete,
    Save,
    Cancel,
    GoTo(u64),
}

/// A note: who wrote it and when, then its text with each step it cites a
/// link; or, while it is edited, its text to change.
fn show_note_card(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui, row: &Row) {
    let Some(note) = &row.note else { return };
    let cited: HashMap<u64, String> = note.steps.iter().map(|step| (*step, state.row(*step).map_or_else(|| "No longer in the history".to_string(), |cited| format!("Step {step}: {}", cited.description)))).collect();
    let mut action = None;
    let frame = egui::Frame::new().fill(theme::SURFACE_RAISED).stroke(egui::Stroke::new(1.0, theme::CURSOR.gamma_multiply(0.6))).corner_radius(4.0).inner_margin(egui::Margin::symmetric(8, 5));
    frame.show(ui, |ui| {
        ui.set_width(ui.available_width());
        let editing = state.editing.as_ref().is_some_and(|editing| editing.step == row.step);
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{:>4}", row.step)).monospace().small().color(theme::TEXT_DIM));
            ui.label(RichText::new("note").small().strong().color(theme::CURSOR));
            ui.label(RichText::new(note.kind.name()).small().color(kind_colour(note.kind)));
            ui.label(RichText::new(&row.caller).small().color(theme::ACCENT));
            ui.label(RichText::new(time_of_day(&row.at)).small().color(theme::TEXT_DIM)).on_hover_text(&row.at);
            if let (Some(at), Some(by)) = (&note.edited_at, &note.edited_by) {
                ui.label(RichText::new("edited").small().italics().color(theme::TEXT_DIM)).on_hover_text(format!("Edited {at} by {by}"));
            }
            if !editing {
                if ui.small_button("Edit").clicked() {
                    action = Some(CardAction::Edit);
                }
                if ui.small_button("Delete").on_hover_text("Take this note out of the history").clicked() {
                    action = Some(CardAction::Delete);
                }
            }
        });
        if let Some(editing) = state.editing.as_mut().filter(|editing| editing.step == row.step) {
            let id = egui::Id::new(("history-note-edit", row.step));
            let saved_by_key = ui.memory(|memory| memory.has_focus(id)) && ui.input_mut(|input| input.consume_key(Modifiers::COMMAND, Key::Enter));
            ui.add(egui::TextEdit::multiline(&mut editing.text).id(id).desired_rows(NOTE_BOX_ROWS).desired_width(f32::INFINITY));
            ui.horizontal(|ui| {
                if saved_by_key || ui.add_enabled(!editing.text.trim().is_empty(), egui::Button::new("Save").small()).clicked() {
                    action = Some(CardAction::Save);
                }
                if ui.small_button("Cancel").clicked() {
                    action = Some(CardAction::Cancel);
                }
            });
        } else if let Some(step) = show_note_text(ui, &note.text, &cited) {
            action = Some(CardAction::GoTo(step));
        }
    });
    match action {
        Some(CardAction::Edit) => state.editing = Some(EditingNote { step: row.step, text: note.text.clone() }),
        Some(CardAction::Delete) => delete_note(state, app, row.step),
        Some(CardAction::Save) => save_edited_note(state, app),
        Some(CardAction::Cancel) => state.editing = None,
        Some(CardAction::GoTo(step)) => state.go_to_step(step),
        None => {}
    }
}

/// A note's text, line by line, each step it cites (`#12`) a link that
/// says what the step did; returns the step whose link was clicked.
fn show_note_text(ui: &mut Ui, text: &str, cited: &HashMap<u64, String>) -> Option<u64> {
    let mut clicked = None;
    for line in text.split('\n') {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            if line.trim().is_empty() {
                ui.label(" ");
                return;
            }
            for segment in notes::segments(line) {
                match segment {
                    Segment::Text(words) => {
                        ui.label(words);
                    }
                    Segment::Step(step) => {
                        let link = ui.link(format!("#{step}"));
                        let link = match cited.get(&step) {
                            Some(about) => link.on_hover_text(about),
                            None => link,
                        };
                        if link.clicked() {
                            clicked = Some(step);
                        }
                    }
                }
            }
        });
    }
    clicked
}

/// The time of day of a UTC timestamp, "14:02:11", or the timestamp as it
/// is when it has none.
fn time_of_day(at: &str) -> &str {
    at.get(11..19).unwrap_or(at)
}

/// The box at the foot of the tab that writes a note where the history is
/// now; Cmd+Enter or *Add note* adds it.
fn show_note_box(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui) {
    let id = egui::Id::new("history-note-box-text");
    let added_by_key = ui.memory(|memory| memory.has_focus(id)) && ui.input_mut(|input| input.consume_key(Modifiers::COMMAND, Key::Enter));
    let wants_focus = std::mem::take(&mut state.focus_note_box);
    if wants_focus {
        // Typing goes on after the step it was started about.
        let mut text_state = egui::TextEdit::load_state(ui.ctx(), id).unwrap_or_default();
        let end = egui::text::CCursor::new(state.note_draft.chars().count());
        text_state.cursor.set_char_range(Some(egui::text::CCursorRange::one(end)));
        text_state.store(ui.ctx(), id);
    }
    let response = ui.add(egui::TextEdit::multiline(&mut state.note_draft).id(id).hint_text(NOTE_HINT).desired_rows(NOTE_BOX_ROWS).desired_width(f32::INFINITY));
    if wants_focus {
        response.request_focus();
    }
    let mut add = added_by_key;
    ui.horizontal(|ui| {
        add |= ui.add_enabled(!state.note_draft.trim().is_empty(), egui::Button::new("Add note")).on_hover_text("Add the note to the history here (Cmd+Enter)").clicked();
        egui::ComboBox::from_id_salt("history-note-kind").selected_text(state.note_kind.name()).show_ui(ui, |ui| {
            for kind in NoteKind::ALL {
                ui.selectable_value(&mut state.note_kind, kind, kind.name());
            }
        });
        ui.label(RichText::new("A note changes nothing and is never undone or played back.").small().color(theme::TEXT_DIM));
    });
    if add && !state.note_draft.trim().is_empty() {
        add_note(state, app);
    }
}

/// The colour of a note kind's tag: a fallback stands out.
fn kind_colour(kind: NoteKind) -> egui::Color32 {
    match kind {
        NoteKind::Fallback => theme::DANGER,
        NoteKind::Conclusion => theme::ACCENT,
        _ => theme::TEXT_DIM,
    }
}

/// Write the note in the box into the history, of the kind chosen, as the
/// person.
pub fn add_note(state: &mut HistoryState, app: &mut ViewerApp) {
    match app.perform("history.note", json!({"text": state.note_draft, "kind": state.note_kind})) {
        Ok(_) => {
            state.note_draft.clear();
            state.note_kind = NoteKind::default();
            state.message = None;
        }
        Err(error) => state.message = Some(format!("The note was not added: {}", error.message)),
    }
}

/// Save the note being edited in its card, as the person.
pub fn save_edited_note(state: &mut HistoryState, app: &mut ViewerApp) {
    let Some(editing) = state.editing.take() else { return };
    if let Err(error) = app.perform("history.edit_note", json!({"step": editing.step, "text": editing.text})) {
        state.message = Some(format!("The note was not changed: {}", error.message));
        state.editing = Some(editing);
    }
}

/// Take note `step` out of the history, as the person.
pub fn delete_note(state: &mut HistoryState, app: &mut ViewerApp, step: u64) {
    state.message = app.perform("history.delete_note", json!({"step": step})).err().map(|error| error.message);
    if state.editing.as_ref().is_some_and(|editing| editing.step == step) {
        state.editing = None;
    }
}

/// Ask where to write the session's notes as Markdown, then write them
/// through `history.export_notes`.
pub fn export_notes(app: &mut ViewerApp) {
    let stem = app.document.path().and_then(std::path::Path::file_stem).map(|stem| stem.to_string_lossy().into_owned());
    let name = stem.map_or_else(|| "notes.md".to_string(), |stem| format!("{stem} notes.md"));
    app.save_dialog_then_call("Export notes", &name, "history.export_notes", json!({}), "path");
}

/// The counts, the caller filter and "Save as recipe…".
fn show_toolbar(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        let steps = state.rows.len() - state.notes;
        ui.label(RichText::new(format!("{steps} steps · {} notes · {} undone", state.notes, state.undone)).small().color(theme::TEXT_DIM));
        ui.selectable_value(&mut state.sheets_view, false, "Steps").on_hover_text("The steps in the order taken");
        ui.selectable_value(&mut state.sheets_view, true, "Sheets").on_hover_text("The steps grouped under the sheet they ran on, following the sheets' lineage");
        egui::ComboBox::from_id_salt("history-caller").selected_text(state.caller_filter.as_deref().unwrap_or("every caller")).show_ui(ui, |ui| {
            ui.selectable_value(&mut state.caller_filter, None, "every caller");
            for caller in state.callers.clone() {
                ui.selectable_value(&mut state.caller_filter, Some(caller.clone()), caller);
            }
        });
        ui.checkbox(&mut state.show_undone, "Show undone");
        ui.checkbox(&mut state.notes_only, "Notes only");
        if ui.add_enabled(state.notes > 0, egui::Button::new("Export notes…")).on_hover_text("Save the notes, with the steps they cite, as Markdown").clicked() {
            export_notes(app);
        }
        ui.separator();
        ui.add(egui::TextEdit::singleline(&mut state.recipe_name).desired_width(140.0).hint_text("Recipe name"));
        let any = state.any_active;
        if ui.add_enabled(any, egui::Button::new("Save as recipe…")).on_hover_text("Save the steps in effect as a recipe file to run on other files").clicked() {
            state.message = save_as_recipe(app, &state.recipe_name);
        }
        if ui.add_enabled(any, egui::Button::new("Save to my recipes")).on_hover_text("Keep the steps in effect among your recipes, to run from Run recipe…").clicked() {
            state.message = save_to_my_recipes(app, &state.recipe_name).err().map(|error| error.message);
        }
        if ui.button("Run recipe…").clicked() {
            app.open_recipe_window();
        }
    });
}

/// Keep the steps in effect among the person's recipes as `name`, through
/// `recipes.save`, with the anchors and parameters recorded for them.
pub fn save_to_my_recipes(app: &mut ViewerApp, name: &str) -> Result<Value, crate::api::ApiError> {
    let steps: Vec<u64> = timeline::entries_for_recipe(&app.journal, None).iter().map(|entry| entry.step).collect();
    app.perform("recipes.save", json!({"name": recipe_name(name), "journal_steps": steps, "overwrite": true}))
}

/// The name a recipe is saved under: the one typed, trimmed, or
/// [`DEFAULT_RECIPE_NAME`] when nothing is.
fn recipe_name(typed: &str) -> &str {
    let trimmed = typed.trim();
    if trimmed.is_empty() { DEFAULT_RECIPE_NAME } else { trimmed }
}

/// Ask where to save the steps in effect as a recipe called `name`, then
/// write it through `history.save_recipe`; or, when a step would not
/// replay, say why instead of asking.
pub fn save_as_recipe(app: &mut ViewerApp, name: &str) -> Option<String> {
    save_recipe_up_to(app, name, None)
}

/// Ask where to save the steps in effect, up to step `through` when given,
/// as a recipe called `name` (or the default name), then write it through
/// `history.save_recipe`. When the recipe would not replay (a step names a
/// document it could not find again), nothing is asked: the warning the
/// recipe builder gives is returned for the tab to show.
fn save_recipe_up_to(app: &mut ViewerApp, name: &str, through: Option<u64>) -> Option<String> {
    let name = recipe_name(name);
    if let Err(error) = timeline::recipe_of_history(&app.journal, name, through) {
        return Some(format!("Not saved: {}", error.message));
    }
    let mut params = json!({"name": name});
    if let Some(through) = through {
        params["through"] = json!(through);
    }
    app.save_dialog_then_call("Save as recipe", &recipes::file_name_for(name), "history.save_recipe", params, "path");
    None
}

/// The playback controls: the range, the speed, and play, pause, next and
/// stop.
fn show_playback(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui) {
    let last = state.rows.last().map_or(0, |row| row.step);
    ui.horizontal_wrapped(|ui| {
        ui.label("Play steps");
        ui.add(egui::DragValue::new(&mut state.play_from).range(1..=last.max(1)));
        ui.label("to");
        ui.add(egui::DragValue::new(&mut state.play_through).range(state.play_from..=last.max(1)));
        egui::ComboBox::from_id_salt("history-speed").selected_text(state.speed.label()).show_ui(ui, |ui| {
            for speed in Speed::ALL {
                ui.selectable_value(&mut state.speed, speed, speed.label());
            }
        });
        match &mut state.playback {
            None => {
                if ui.add_enabled(last > 0, egui::Button::new("▶ Play")).on_hover_text("Go back to before the first step, then run each step again as you watch").clicked() {
                    start_playback(state, app);
                }
            }
            Some(run) => {
                let (done, total) = run.playback.progress();
                ui.label(RichText::new(format!("{done} of {total}")).small());
                if state.speed != Speed::OneAtATime {
                    let label = if run.paused { "▶ Resume" } else { "⏸ Pause" };
                    if ui.button(label).clicked() {
                        run.paused = !run.paused;
                    }
                }
                if ui.add_enabled(!run.playback.is_finished(), egui::Button::new("Next step")).clicked() {
                    play_one(state, app);
                }
                if ui.button("Stop").clicked() {
                    state.playback = None;
                }
            }
        }
    });
    if let Some(run) = &state.playback {
        if let Some(upcoming) = run.playback.upcoming() {
            ui.label(RichText::new(format!("Next: step {} · {}", upcoming.step, upcoming.method)).small().color(theme::TEXT_DIM));
        } else if let Some(error) = run.playback.stopped() {
            ui.label(RichText::new(format!("Stopped: {}", error.message)).small().color(theme::DANGER));
        } else {
            ui.label(RichText::new("Played every step").small().color(theme::TEXT_DIM));
        }
    }
}

/// Go back to before the first step to play, then get ready to play the
/// range one step at a time.
pub fn start_playback(state: &mut HistoryState, app: &mut ViewerApp) {
    let steps = timeline::steps_to_play(&app.journal, state.play_from, state.play_through);
    if steps.is_empty() {
        state.message = Some(format!("There are no steps in effect from {} to {} to play", state.play_from, state.play_through));
        return;
    }
    // Notes are never played or undone, so playback goes back to a step.
    let before = app.journal.entries().filter(|entry| !entry.is_note()).map(|entry| entry.step).filter(|step| *step < steps[0].step).max().unwrap_or(0);
    match app.perform("history.go_back", json!({"step": before})) {
        Ok(_) => {
            state.message = None;
            state.playback = Some(PlaybackRun { playback: Playback::new(steps, crate::api::Caller::Panel, None), paused: false, last_played: Instant::now() });
        }
        Err(error) => state.message = Some(format!("Playback could not go back to step {before}: {}", error.message)),
    }
}

/// Play the next step now.
pub fn play_one(state: &mut HistoryState, app: &mut ViewerApp) {
    let Some(run) = &mut state.playback else { return };
    if let Some(step) = run.playback.play_next(app) {
        state.selected = None;
        run.last_played = Instant::now();
        if let Some(error) = run.playback.stopped() {
            state.message = Some(format!("Step {step} failed when played again: {}", error.message));
        }
    }
}

/// Play the next step when its time has come, at the speed chosen.
fn play_due_step(state: &mut HistoryState, app: &mut ViewerApp, ctx: &egui::Context) {
    let Some(interval) = state.speed.interval() else { return };
    let Some(run) = &state.playback else { return };
    if run.paused || run.playback.is_finished() {
        return;
    }
    let waited = run.last_played.elapsed();
    if waited >= interval {
        play_one(state, app);
        ctx.request_repaint_after(interval);
    } else {
        ctx.request_repaint_after(interval - waited);
    }
}

/// One step: its number, caller, marks and description, and a menu of
/// what can be done with it.
fn show_row(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui, row: &Row) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{:>4}", row.step)).monospace().small().color(theme::TEXT_DIM));
        ui.label(RichText::new(&row.caller).small().color(theme::ACCENT));
        if ui.small_button("Note").on_hover_text(format!("Write a note about step {}", row.step)).clicked() {
            state.note_about(row.step);
        }
        for (note, text) in &row.noted_by {
            if ui.link(RichText::new(format!("note {note}")).small()).on_hover_text(text).clicked() {
                state.go_to_step(*note);
            }
        }
        if row.changed_bytes {
            ui.label(RichText::new("bytes").small().color(theme::CURSOR)).on_hover_text("Changed the document's bytes");
        }
        if row.refused {
            ui.label(RichText::new("refused").small().color(theme::DANGER)).on_hover_text(row.error.clone().unwrap_or_default());
        } else if row.error.is_some() {
            ui.label(RichText::new("failed").small().color(theme::DANGER)).on_hover_text(row.error.clone().unwrap_or_default());
        }
        if row.merged > 0 {
            ui.label(RichText::new(format!("×{}", row.merged + 1)).small().color(theme::TEXT_DIM)).on_hover_text(format!("{} moves in a row, kept as one step", row.merged + 1));
        }
        if row.evidence {
            ui.label(RichText::new("evidence").small().italics().color(theme::TEXT_DIM)).on_hover_text("A read kept because a note cites it; recipes leave it out unless an anchor cites it");
        }
        let mut text = RichText::new(&row.description);
        if row.evidence {
            text = text.color(theme::TEXT_DIM);
        }
        text = match row.status {
            StepStatus::Undone { by } => {
                ui.label(RichText::new(format!("undone by {by}")).small().color(theme::TEXT_DIM));
                text.strikethrough().color(theme::TEXT_DIM)
            }
            StepStatus::Failed => text.color(theme::DANGER),
            StepStatus::Move => text.italics().color(theme::TEXT_DIM),
            StepStatus::Active | StepStatus::Note => text,
        };
        let selected = state.selected == Some(row.step);
        let label = ui.selectable_label(selected, text).on_hover_text(&row.method);
        if label.clicked() {
            state.selected = if selected { None } else { Some(row.step) };
        }
        label.context_menu(|ui| step_menu(state, app, ui, row));
        if !row.made.is_empty() {
            ui.label(RichText::new(format!("→ {}", row.made.join(", "))).small().color(theme::ACCENT)).on_hover_text("The sheets this step made");
        }
        if !row.sources.is_empty() {
            ui.label(RichText::new(format!("← {}", row.sources.join(", "))).small().color(theme::TEXT_DIM)).on_hover_text("Where its values came from, which a recipe finds again");
        }
    });
}

/// What can be done with a step from its menu.
fn step_menu(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui, row: &Row) {
    if ui.add_enabled(row.status == StepStatus::Active, egui::Button::new("Undo this step")).clicked() {
        undo_step(state, app, row.step);
        ui.close();
    }
    if ui.button("Go back to here").on_hover_text("Undo every step after this one").clicked() {
        go_back(state, app, row.step);
        ui.close();
    }
    if ui.button("Play from here").clicked() {
        state.play_from = row.step;
        state.play_through = state.rows.last().map_or(row.step, |last| last.step);
        start_playback(state, app);
        ui.close();
    }
    if ui.button("Save up to here as recipe…").clicked() {
        state.message = save_recipe_up_to(app, &state.recipe_name, Some(row.step));
        ui.close();
    }
    if ui.button("Write a note about it").clicked() {
        state.note_about(row.step);
        ui.close();
    }
    if ui.button("Recipe values…").on_hover_text("Turn this step's values into anchors or parameters").clicked() {
        state.selected = Some(row.step);
        ui.close();
    }
}

/// Undo `step` through its inverse, as the person.
pub fn undo_step(state: &mut HistoryState, app: &mut ViewerApp, step: u64) {
    state.message = app.perform("history.undo_step", json!({"step": step})).err().map(|error| error.message);
}

/// Go back to `step`, as the person.
pub fn go_back(state: &mut HistoryState, app: &mut ViewerApp, step: u64) {
    state.playback = None;
    state.message = app.perform("history.go_back", json!({"step": step})).err().map(|error| error.message);
}

/// The selected step in full: what it did, how it would be undone, the
/// bytes it touched and its values for a recipe.
fn show_details(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui, step: u64) {
    let Some(details) = step_details(state, app, step) else {
        state.selected = None;
        return;
    };
    let mut close = false;
    let mut undo = false;
    let mut back = false;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("Step {step}")).strong());
        ui.label(RichText::new(&details.heading).small().color(theme::TEXT_DIM));
        close = ui.small_button("×").on_hover_text("Close").clicked();
    });
    if !details.description.is_empty() {
        ui.label(&details.description);
    }
    if let Some(error) = &details.error {
        ui.label(RichText::new(error).color(theme::DANGER));
    }
    ui.horizontal_wrapped(|ui| {
        let can_undo = details.inverse.is_available() && details.active;
        undo = ui.add_enabled(can_undo, egui::Button::new("Undo this step")).clicked();
        back = ui.button("Go back to here").clicked();
        if let Some((start, len)) = details.touched
            && ui.button("Show bytes").on_hover_text(format!("Select the {len} bytes at {start:#x} it touched")).clicked()
        {
            app.select_from_tool(start, len);
        }
        let how = match &details.inverse {
            Inverse::Calls { calls } => format!("Undoes by {}", calls.iter().map(|call| call.method.as_str()).collect::<Vec<_>>().join(", then ")),
            Inverse::Nothing { why } => format!("Nothing to undo: {why}"),
            Inverse::Unavailable { why } => format!("Cannot be undone now: {why}"),
        };
        ui.label(RichText::new(how).small().color(theme::TEXT_DIM));
    });
    egui::CollapsingHeader::new("Parameters").id_salt(("history-params", step)).default_open(true).show(ui, |ui| ui.label(RichText::new(&details.params).monospace().small()));
    if let Some(result) = &details.result {
        egui::CollapsingHeader::new("Result").id_salt(("history-result", step)).show(ui, |ui| ui.label(RichText::new(result).monospace().small()));
    }
    if details.succeeded {
        let mut header = egui::CollapsingHeader::new("Recipe values").id_salt(("history-anchors", step));
        if state.open_recipe_values == Some(step) {
            state.open_recipe_values = None;
            header = header.open(Some(true));
        }
        header.show(ui, |ui| show_recipe_values(state, app, ui, step));
    }
    if close {
        state.selected = None;
    }
    if undo {
        undo_step(state, app, step);
    }
    if back {
        go_back(state, app, step);
    }
}

/// The details of `step`, read again only when the step, the journal or
/// the document it is about has changed since they were last read; none
/// when the step is no longer in the journal.
fn step_details<'state>(state: &'state mut HistoryState, app: &mut ViewerApp, step: u64) -> Option<&'state StepDetails> {
    let revision = app.journal.revision();
    let doc = app.journal.entry(step)?.doc.clone();
    let doc_version = doc.and_then(|doc| crate::api::Workspace::document_mut(app, &doc).map(|document| document.version()));
    if !state.details.as_ref().is_some_and(|details| details.is_for(step, revision, doc_version)) {
        let inverse = timeline::inverse_of(app, step);
        let active = state.row(step).is_some_and(|row| row.status == StepStatus::Active);
        let entry = app.journal.entry(step)?;
        state.details = Some(StepDetails::read(entry, revision, doc_version, active, inverse));
    }
    state.details.as_ref()
}

/// `value` as indented JSON, cut with "…" after `limit` characters; the
/// serialising stops there rather than writing out the whole value.
fn pretty_json_cut(value: &Value, limit: usize) -> String {
    let mut writer = CharLimitedWriter { kept: Vec::new(), chars: 0, limit, cut: false };
    // A cut ends the serialising with an error on purpose: what was kept
    // is the text.
    let _ = serde_json::to_writer_pretty(&mut writer, value);
    let mut text = String::from_utf8(writer.kept).unwrap_or_default();
    if writer.cut {
        text.push('…');
    }
    text
}

/// Keeps the first `limit` characters of the UTF-8 written to it, then
/// refuses the rest.
struct CharLimitedWriter {
    kept: Vec<u8>,
    chars: usize,
    limit: usize,
    cut: bool,
}

impl io::Write for CharLimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for (index, byte) in bytes.iter().enumerate() {
            let continues_a_character = byte & 0b1100_0000 == 0b1000_0000;
            if continues_a_character {
                continue;
            }
            if self.chars == self.limit {
                self.kept.extend_from_slice(&bytes[..index]);
                self.cut = true;
                return Err(io::Error::other(format!("cut after {} characters", self.limit)));
            }
            self.chars += 1;
        }
        self.kept.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The step's literals as a recipe would repeat them, each with its anchor
/// and the anchors that could stand for it (area C's provenance): use one,
/// make it a named parameter, or clear it.
fn show_recipe_values(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui, step: u64) {
    let revision = app.journal.revision();
    if state.suggestions.as_ref().is_none_or(|(held, at, _)| *held != step || *at != revision) {
        let found = provenance::suggest_anchors(app, step, None).unwrap_or_default();
        state.suggestions = Some((step, app.journal.revision(), found));
    }
    let literals: &[LiteralSuggestions] = state.suggestions.as_ref().map_or(&[], |(_, _, literals)| literals);
    if literals.is_empty() {
        ui.label(RichText::new("No values a recipe would need to find again.").small().color(theme::TEXT_DIM));
        return;
    }
    ui.horizontal(|ui| {
        ui.label(RichText::new("Parameter name").small());
        ui.add(egui::TextEdit::singleline(&mut state.parameter_name).desired_width(120.0).hint_text("such as key"));
    });
    for literal in literals {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(&literal.path).monospace().small());
            ui.label(RichText::new(literal.value.to_string()).monospace().small().color(theme::TEXT_DIM));
            match &literal.anchor {
                Some(anchor) => {
                    ui.label(RichText::new(format!("anchored: {}", serde_json::to_string(anchor).unwrap_or_default())).small().color(theme::ACCENT));
                    if ui.small_button("Clear anchor").clicked() {
                        state.message = app.perform("history.clear_anchor", json!({"step": step, "path": literal.path})).err().map(|error| error.message);
                    }
                }
                None => {
                    let name = state.parameter_name.trim().to_string();
                    if ui.add_enabled(!name.is_empty(), egui::Button::new("Make a parameter").small()).clicked() {
                        state.message = app.perform("history.make_parameter", json!({"step": step, "path": literal.path, "name": name})).err().map(|error| error.message);
                    }
                }
            }
            for suggestion in &literal.suggestions {
                if ui.small_button(format!("Use {}", suggestion.reason)).on_hover_text(serde_json::to_string(&suggestion.anchor).unwrap_or_default()).clicked() {
                    state.message = app.perform("history.make_anchor", json!({"step": step, "path": literal.path, "anchor": suggestion.anchor})).err().map(|error| error.message);
                }
            }
        });
    }
}

/// The bytes a step touched, where its parameters or result say: an edit's
/// ranges, a selection, a span, or an offset.
pub fn touched_span(entry: &JournalEntry) -> Option<(usize, usize)> {
    let pair = |value: &Value| Some((value.get(0)?.as_u64()? as usize, value.get(1)?.as_u64()? as usize));
    let first_range = |value: Option<&Value>| value.and_then(Value::as_array).and_then(|ranges| ranges.first()).and_then(pair);
    let params = &entry.params;
    first_range(entry.result.as_ref().and_then(|result| result.get("ranges")))
        .or_else(|| first_range(params.get("ranges")))
        .or_else(|| params.get("selection").and_then(|selection| selection.get("range")).and_then(pair))
        .or_else(|| first_range(params.get("selection").and_then(|selection| selection.get("ranges"))))
        .or_else(|| {
            let start = params.get("start").or_else(|| params.get("at")).or_else(|| params.get("offset"))?.as_u64()? as usize;
            let len = params.get("len").and_then(Value::as_u64).map(|len| len as usize).or_else(|| params.get("data").and_then(Value::as_str).map(|hex| hex.len() / 2)).unwrap_or(0);
            Some((start, len))
        })
}

#[cfg(test)]
mod tests {
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    use super::*;
    use crate::actions::take_performed;
    use crate::app::Launch;
    use crate::journal::recipe::RECIPE_EXTENSION;

    type HistoryHarness = Harness<'static, ViewerApp>;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        app
    }

    /// The tab drawn as the window draws it, its state lent out of the app.
    fn harness_for(app: ViewerApp) -> HistoryHarness {
        Harness::new_ui_state(
            |ui, app: &mut ViewerApp| {
                app.perform_waiting_actions();
                crate::panels::show(app, ui, |panels| &mut panels.history, show_history);
            },
            app,
        )
    }

    #[test]
    fn the_tab_lists_the_person_s_actions_with_what_they_did() {
        let mut app = app_with(&[0u8; 64]);
        app.perform("bytes.write", json!({"start": 2, "data": "4142"})).unwrap();
        app.perform("view.set_shape", json!({"width": 16})).unwrap();
        app.perform("bytes.write", json!({"start": 900, "data": "00"})).unwrap_err();
        let mut harness = harness_for(app);
        harness.step();
        harness.get_by_label_contains("Overwrite 2 bytes at 0x2 with 41 42");
        harness.get_by_label_contains("16 pixels per row");
        harness.get_by_label_contains("Overwrite 1 byte at 0x384");
        let rows = &harness.state().bench.panels.history.rows;
        assert_eq!(rows.iter().map(|row| (row.caller.as_str(), row.changed_bytes, row.error.is_some())).collect::<Vec<_>>(), [("panel", true, false), ("panel", false, false), ("panel", false, true)]);
    }

    #[test]
    fn in_a_short_tab_the_note_box_sits_below_the_steps_not_over_them() {
        let mut app = app_with(&[0u8; 64]);
        app.perform("bytes.write", json!({"start": 2, "data": "4142"})).unwrap();
        let mut harness = Harness::builder().with_size(egui::vec2(600.0, 130.0)).build_ui_state(
            |ui, app: &mut ViewerApp| {
                app.perform_waiting_actions();
                crate::panels::show(app, ui, |panels| &mut panels.history, show_history);
            },
            app,
        );
        harness.step();
        let step = harness.get_by_label_contains("Overwrite 2 bytes at 0x2").rect();
        let add = harness.get_by_label("Add note").rect();
        assert!(add.min.y > step.max.y, "the note box ({add:?}) is below the step ({step:?}), the tab scrolling to reach it");
    }

    #[test]
    fn clicking_a_step_shows_its_parameters_and_undoing_it_goes_through_the_api() {
        let mut app = app_with(&[0u8; 64]);
        app.perform("view.set_shape", json!({"width": 16})).unwrap();
        take_performed();
        let mut harness = harness_for(app);
        harness.step();
        harness.get_by_label_contains("16 pixels per row").click();
        harness.step();
        harness.get_by_label("Parameters");
        harness.get_by_label_contains("Undoes by view.set_shape");
        harness.get_by_label("Undo this step").click();
        harness.step();
        assert_eq!(take_performed(), [("history.undo_step".to_string(), json!({"step": 1}))]);
        harness.step();
        harness.get_by_label("undone by 2");
        let shape = crate::api::call(harness.state_mut(), &crate::api::Caller::Panel, "view.get_shape", json!({})).unwrap();
        assert_ne!(shape["shape"]["width"], 16);
    }

    #[test]
    fn going_back_from_the_tab_leaves_the_document_as_it_was_after_the_step() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        app.perform("bytes.write", json!({"start": 1, "data": "42"})).unwrap();
        app.perform("bytes.write", json!({"start": 2, "data": "43"})).unwrap();
        let mut state = HistoryState::default();
        state.follow(&app);
        go_back(&mut state, &mut app, 1);
        assert_eq!(state.message, None);
        assert_eq!(app.document.read_range(0, 3), b"A\0\0");
        state.follow(&app);
        assert_eq!(state.rows.iter().filter(|row| row.is_undone()).count(), 2);
    }

    #[test]
    fn playback_steps_through_the_range_one_step_at_a_time() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        app.perform("bytes.write", json!({"start": 1, "data": "42"})).unwrap();
        let mut state = HistoryState::default();
        state.follow(&app);
        state.play_from = 1;
        start_playback(&mut state, &mut app);
        assert_eq!(app.document.read_range(0, 2), b"\0\0", "gone back to before the first step");
        assert_eq!(state.playback.as_ref().map(|run| run.playback.progress()), Some((0, 2)));
        play_one(&mut state, &mut app);
        assert_eq!(app.document.read_range(0, 2), b"A\0", "the view shows each step as it runs");
        play_one(&mut state, &mut app);
        assert_eq!(app.document.read_range(0, 2), b"AB");
        assert!(state.playback.as_ref().is_some_and(|run| run.playback.is_finished()));
        assert_eq!(state.message, None);
    }

    #[test]
    fn playing_at_a_speed_moves_on_by_itself() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        let mut state = HistoryState { speed: Speed::Fast, play_from: 1, ..HistoryState::default() };
        state.follow(&app);
        start_playback(&mut state, &mut app);
        if let Some(run) = &mut state.playback {
            run.last_played = Instant::now() - Duration::from_secs(1);
        }
        play_due_step(&mut state, &mut app, &egui::Context::default());
        assert_eq!(app.document.read_range(0, 1), b"A");
    }

    #[test]
    fn saving_as_a_recipe_writes_the_steps_in_effect_through_the_api() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        app.perform("view.set_shape", json!({"width": 4})).unwrap();
        let path = std::env::temp_dir().join(format!("theviewer-history-tab-{}{RECIPE_EXTENSION}", std::process::id()));
        take_performed();
        app.call_with_chosen_path("history.save_recipe", json!({"name": "Patch"}), "path", &path).unwrap();
        assert_eq!(take_performed()[0].0, "history.save_recipe");
        let recipe: crate::journal::Recipe = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(recipe.name, "Patch");
        assert_eq!(recipe.steps.iter().map(|step| step.method.as_str()).collect::<Vec<_>>(), ["bytes.write", "view.set_shape"]);
    }

    #[test]
    fn a_recipe_that_would_not_replay_says_why_before_asking_where_to_save_it() {
        let mut app = app_with(b"HEADpayload");
        app.perform("bytes.write", json!({"start": 0, "data": "68"})).unwrap();
        // Opened by a panel of its own, not through a step.
        app.open_derived(b"payload".to_vec(), "payload".to_string());
        app.perform("bytes.write", json!({"start": 0, "data": "50"})).unwrap();
        take_performed();
        let warning = save_as_recipe(&mut app, "Peel").expect("the second write names a sheet no step made");
        assert!(warning.starts_with("Not saved: the recipe would not replay"), "{warning}");
        assert!(warning.contains("outside the history, not by a step"), "{warning}");
        assert!(take_performed().is_empty(), "nothing was saved");
    }

    #[test]
    fn saving_as_a_recipe_keeps_the_derive_and_names_the_sheet() {
        let mut app = app_with(b"HEADpayload");
        app.perform("documents.derive", json!({"start": 4})).unwrap();
        app.perform("bytes.write", json!({"start": 0, "data": "50"})).unwrap();
        let recipe = timeline::recipe_of_history(&app.journal, "Peel", None).unwrap();
        assert_eq!(recipe.steps.iter().map(|step| step.method.as_str()).collect::<Vec<_>>(), ["documents.derive", "bytes.write"]);
        assert_eq!(recipe.steps[1].params["doc"], json!({"$anchor": {"sheet": {"step": 1}}}));
    }

    #[test]
    fn saving_to_my_recipes_keeps_only_the_steps_in_effect() {
        let mut app = app_with(&[0u8; 8]);
        let dir = std::env::temp_dir().join(format!("theviewer-history-tab-recipes-{}", std::process::id()));
        crate::recipes::use_dir_for_this_thread(dir.clone());
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        app.perform("bytes.write", json!({"start": 1, "data": "42"})).unwrap();
        app.perform("history.undo_step", json!({"step": 2})).unwrap();
        take_performed();
        save_to_my_recipes(&mut app, "Patch").unwrap();
        assert_eq!(take_performed(), [("recipes.save".to_string(), json!({"name": "Patch", "journal_steps": [1], "overwrite": true}))]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_selected_step_s_details_are_read_once_until_the_journal_changes() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        let mut state = HistoryState::default();
        state.follow(&app);
        let first = step_details(&mut state, &mut app, 1).map(|details| (details.heading.clone(), details.inverse.is_available()));
        assert_eq!(first.as_ref().map(|(_, undoable)| *undoable), Some(true));
        if let Some(details) = &mut state.details {
            details.heading = "kept from the last frame".to_string();
        }
        let again = step_details(&mut state, &mut app, 1).map(|details| details.heading.clone());
        assert_eq!(again.as_deref(), Some("kept from the last frame"), "nothing changed, so nothing is read again");
        app.perform("bytes.write", json!({"start": 1, "data": "42"})).unwrap();
        state.follow(&app);
        let after_an_edit = step_details(&mut state, &mut app, 1).map(|details| (details.heading.clone(), details.inverse.is_available()));
        assert_eq!(after_an_edit.as_ref().map(|(heading, _)| heading), first.as_ref().map(|(heading, _)| heading));
        assert_eq!(after_an_edit.map(|(_, undoable)| undoable), Some(false), "a later edit of the same document blocks undoing it");
    }

    #[test]
    fn long_parameters_are_cut_at_the_same_character_as_the_whole_text_would_be() {
        let value = json!({"text": "é→".repeat(3000), "list": (0..500).collect::<Vec<_>>()});
        let whole = serde_json::to_string_pretty(&value).unwrap();
        let expected = format!("{}…", whole.chars().take(DETAIL_CHARS).collect::<String>());
        assert_eq!(pretty_json_cut(&value, DETAIL_CHARS), expected);
        let short = json!({"width": 16});
        assert_eq!(pretty_json_cut(&short, DETAIL_CHARS), serde_json::to_string_pretty(&short).unwrap());
        let exact = serde_json::to_string_pretty(&short).unwrap();
        assert_eq!(pretty_json_cut(&short, exact.chars().count()), exact, "a text exactly at the limit is not cut");
    }

    #[test]
    fn a_recipe_without_a_typed_name_is_saved_under_the_default_name() {
        assert_eq!(recipe_name("  "), DEFAULT_RECIPE_NAME);
        assert_eq!(recipe_name(" Patch "), "Patch");
        assert_eq!(recipes::file_name_for(recipe_name("a/b: c")), format!("a-b- c{RECIPE_EXTENSION}"));
    }

    #[test]
    fn the_caller_filter_shows_one_caller_s_steps() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        crate::api::call_permitted(&mut app, &crate::api::Caller::Mcp("claude-code".into()), "cursor.set", json!({"offset": 3})).unwrap();
        let mut state = HistoryState::default();
        state.follow(&app);
        state.caller_filter = Some("mcp:claude-code".into());
        assert_eq!(state.shown().map(|index| state.rows[index].method.as_str()).collect::<Vec<_>>(), ["cursor.set"]);
    }

    #[test]
    fn a_step_shows_the_bytes_it_touched() {
        let mut app = app_with(&[0u8; 64]);
        app.perform("bytes.write", json!({"start": 4, "data": "414243"})).unwrap();
        app.perform("transform.apply", json!({"selection": {"range": [8, 4]}, "operation": {"op": "invert"}})).unwrap();
        app.perform("cursor.set", json!({"offset": 30})).unwrap();
        let spans: Vec<Option<(usize, usize)>> = app.journal.entries().map(touched_span).collect();
        assert_eq!(spans, [Some((4, 3)), Some((8, 4)), Some((30, 0))]);
    }

    /// Write a note as the MCP client `claude-code`.
    fn note_as_client(app: &mut ViewerApp, text: &str) {
        crate::api::call(app, &crate::api::Caller::Mcp("claude-code".into()), "history.note", json!({"text": text})).unwrap();
    }

    #[test]
    fn a_note_is_shown_among_the_steps_as_a_card_with_who_wrote_it_when_and_its_text() {
        let mut app = app_with(&[0u8; 64]);
        app.perform("bytes.write", json!({"start": 2, "data": "4142"})).unwrap();
        note_as_client(&mut app, "Patched #1 because the magic was wrong");
        let at = app.journal.entry(2).unwrap().at.clone();
        let mut harness = harness_for(app);
        harness.step();
        harness.step();
        harness.get_by_label("note");
        harness.get_by_label("mcp:claude-code");
        harness.get_by_label(time_of_day(&at));
        harness.get_by_label(" because the magic was wrong");
        harness.get_by_label("#1");
        harness.get_by_label("note 2");
        let rows = &harness.state().bench.panels.history.rows;
        assert_eq!(rows.iter().map(|row| (row.step, row.is_note(), row.status)).collect::<Vec<_>>(), [(1, false, StepStatus::Active), (2, true, StepStatus::Note)]);
        assert_eq!(rows[0].noted_by, [(2, "Patched #1 because the magic was wrong".to_string())], "the step links back to its note");
    }

    #[test]
    fn a_step_cited_in_a_note_is_a_link_that_scrolls_to_and_highlights_it() {
        let mut app = app_with(&[0u8; 64]);
        app.perform("bytes.write", json!({"start": 2, "data": "4142"})).unwrap();
        note_as_client(&mut app, "See #1");
        let mut harness = harness_for(app);
        harness.step();
        harness.step();
        harness.get_by_label("#1").click();
        harness.step();
        let state = &harness.state().bench.panels.history;
        assert_eq!(state.highlighted.map(|(step, _)| step), Some(1));
        assert!(state.is_highlighted(1));
    }

    #[test]
    fn following_a_link_to_a_step_the_filters_hide_shows_it() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        note_as_client(&mut app, "Why #1");
        let mut state = HistoryState { notes_only: true, caller_filter: Some("mcp:claude-code".into()), ..HistoryState::default() };
        state.follow(&app);
        state.go_to_step(1);
        assert_eq!((state.notes_only, state.caller_filter.as_deref(), state.scroll_to), (false, None, Some(1)));
        state.go_to_step(40);
        assert_eq!(state.message.as_deref(), Some("Step 40 is no longer in the history"));
    }

    #[test]
    fn the_note_box_adds_a_note_with_cmd_enter() {
        let app = app_with(&[0u8; 8]);
        let mut harness = harness_for(app);
        harness.step();
        harness.get_by_role(egui::accesskit::Role::MultilineTextInput).click();
        harness.step();
        harness.get_by_role(egui::accesskit::Role::MultilineTextInput).type_text("Looking for the length field");
        harness.step();
        harness.key_press_modifiers(Modifiers::COMMAND, Key::Enter);
        harness.step();
        let app = harness.state();
        let notes: Vec<&str> = app.journal.notes().filter_map(|entry| entry.note.as_ref()).map(|note| note.text.as_str()).collect();
        assert_eq!(notes, ["Looking for the length field"]);
        assert_eq!(app.journal.notes().next().map(|entry| entry.caller.as_str()), Some("panel"));
        assert_eq!(app.bench.panels.history.note_draft, "", "the box is emptied for the next note");
    }

    #[test]
    fn a_step_s_note_button_starts_a_note_linked_to_it_and_add_note_writes_it() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        take_performed();
        let mut harness = harness_for(app);
        harness.step();
        harness.get_by_label("Note").click();
        harness.step();
        assert_eq!(harness.state().bench.panels.history.note_draft, "#1 ");
        harness.state_mut().bench.panels.history.note_draft.push_str("sets the magic");
        harness.step();
        harness.get_by_label("Add note").click();
        harness.step();
        assert_eq!(take_performed(), [("history.note".to_string(), json!({"text": "#1 sets the magic", "kind": "observation"}))]);
        assert_eq!(harness.state().journal.entry(2).and_then(|entry| entry.note.as_ref()).map(|note| note.steps.clone()), Some(vec![1]));
    }

    #[test]
    fn the_note_box_writes_a_note_of_the_kind_chosen_then_goes_back_to_an_observation() {
        let mut app = app_with(&[0u8; 8]);
        let mut state = HistoryState { note_draft: "Cut the frames by hand".into(), note_kind: NoteKind::Fallback, ..HistoryState::default() };
        add_note(&mut state, &mut app);
        assert_eq!(app.journal.notes().next().and_then(|entry| entry.note.as_ref()).map(|note| note.kind), Some(NoteKind::Fallback));
        assert_eq!((state.note_draft.as_str(), state.note_kind), ("", NoteKind::Observation));
    }

    #[test]
    fn a_read_a_note_cites_is_shown_as_evidence_named_by_its_sheet_s_label() {
        let mut app = app_with(&[0u8; 64]);
        app.perform("documents.derive", json!({"start": 0, "len": 16, "output": {"new": {"label": "head"}}})).unwrap();
        app.perform("analysis.overview", json!({"doc": {"$sheet": "head"}})).unwrap();
        app.perform("history.note", json!({"text": "#2 shows nothing yet"})).unwrap();
        let mut state = HistoryState::default();
        state.follow(&app);
        let read = state.row(2).unwrap();
        assert!(read.evidence);
        assert_eq!(read.description, "analysis.overview on \"head\"");
        assert!(!state.row(1).unwrap().evidence);
    }

    #[test]
    fn a_second_step_s_note_button_adds_its_link_after_what_was_typed() {
        let mut state = HistoryState::default();
        state.note_about(3);
        state.note_draft.push_str("and");
        state.note_about(5);
        assert_eq!(state.note_draft, "#3 and #5 ");
    }

    #[test]
    fn a_note_refused_keeps_its_text_in_the_box_and_says_why() {
        let mut app = app_with(&[0u8; 8]);
        let mut state = HistoryState { note_draft: "About #9".into(), ..HistoryState::default() };
        add_note(&mut state, &mut app);
        assert_eq!(state.note_draft, "About #9");
        assert!(state.message.as_deref().is_some_and(|message| message.contains("step 9")), "{:?}", state.message);
    }

    #[test]
    fn a_note_is_edited_and_deleted_from_its_card() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        note_as_client(&mut app, "First thought");
        let mut harness = harness_for(app);
        harness.step();
        harness.step();
        harness.get_by_label("Edit").click();
        harness.step();
        let editing = harness.state().bench.panels.history.editing.clone();
        assert_eq!(editing, Some(EditingNote { step: 2, text: "First thought".into() }));
        if let Some(editing) = &mut harness.state_mut().bench.panels.history.editing {
            editing.text = "Second thought, about #1".into();
        }
        harness.step();
        harness.get_by_label("Save").click();
        harness.step();
        harness.step();
        let note = harness.state().journal.entry(2).and_then(|entry| entry.note.clone()).unwrap();
        assert_eq!((note.text.as_str(), note.steps.as_slice(), note.edited_by.as_deref()), ("Second thought, about #1", &[1][..], Some("panel")));
        harness.get_by_label("edited");
        harness.get_by_label("Delete").click();
        harness.step();
        assert_eq!(harness.state().journal.notes().count(), 0);
        assert_eq!(harness.state().journal.entries().len(), 1, "deleting is not a step");
    }

    #[test]
    fn the_notes_only_filter_shows_just_the_notes_and_the_caller_filter_still_works() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        note_as_client(&mut app, "Theirs");
        app.perform("history.note", json!({"text": "Mine"})).unwrap();
        let mut state = HistoryState::default();
        state.follow(&app);
        let shown = |state: &HistoryState| state.shown().map(|index| state.rows[index].step).collect::<Vec<_>>();
        assert_eq!(shown(&state), [1, 2, 3], "every caller");
        state.notes_only = true;
        assert_eq!(shown(&state), [2, 3]);
        state.caller_filter = Some("panel".into());
        assert_eq!(shown(&state), [3]);
        assert_eq!((state.rows.len() - state.notes, state.notes), (1, 2));
    }

    #[test]
    fn playback_and_going_back_pass_over_notes() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        app.perform("history.note", json!({"text": "Next, #1's neighbour"})).unwrap();
        app.perform("bytes.write", json!({"start": 1, "data": "42"})).unwrap();
        let mut state = HistoryState::default();
        state.follow(&app);
        state.play_from = 2;
        state.play_through = 3;
        start_playback(&mut state, &mut app);
        assert_eq!(state.playback.as_ref().map(|run| run.playback.progress()), Some((0, 1)), "only the write is played");
        assert_eq!(app.journal.entries().last().map(|entry| entry.params.clone()), Some(json!({"step": 1})), "gone back to the step before, not the note");
        play_one(&mut state, &mut app);
        assert_eq!(app.document.read_range(0, 2), b"AB");
        go_back(&mut state, &mut app, 0);
        state.follow(&app);
        assert_eq!(state.row(2).map(|row| row.status), Some(StepStatus::Note), "going back leaves the note");
    }

    #[test]
    fn exporting_the_notes_writes_them_through_the_api() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("history.note", json!({"text": "Start of the analysis"})).unwrap();
        let path = std::env::temp_dir().join(format!("theviewer-history-tab-notes-{}.md", std::process::id()));
        take_performed();
        app.call_with_chosen_path("history.export_notes", json!({}), "path", &path).unwrap();
        assert_eq!(take_performed()[0].0, "history.export_notes");
        let written = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(written.contains("Start of the analysis"), "{written}");
    }

    /// A file, a sheet derived from it labelled "middle" and one made from
    /// that by a transform, labelled "inner", with a step on each of the
    /// first two.
    fn app_with_lineage() -> (ViewerApp, [String; 3]) {
        let mut app = app_with(b"0123456789abcdef");
        let root = app.document_id();
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        app.perform("documents.derive", json!({"start": 4, "len": 8, "output": {"new": {"label": "middle"}}})).unwrap();
        let middle = app.document_id();
        app.perform("bytes.write", json!({"start": 0, "data": "42"})).unwrap();
        app.perform("transform.apply", json!({"selection": {"range": [0, 2]}, "operation": {"op": "invert"}, "output": {"new": {"label": "inner"}}})).unwrap();
        let inner = app.document_id();
        (app, [root, middle, inner])
    }

    #[test]
    fn the_sheets_view_groups_the_steps_under_their_sheets_following_lineage() {
        use sheets_view::{Item, SheetNode};
        let (app, [root, middle, inner]) = app_with_lineage();
        let mut state = HistoryState::default();
        state.follow(&app);
        let shown: Vec<usize> = state.shown().collect();
        let tree = sheets_view::sheet_tree(&app.journal, &state.rows, &shown);
        let inner_node = SheetNode { doc: inner.clone(), name: "inner".into(), items: vec![] };
        let middle_node = SheetNode { doc: middle.clone(), name: "middle".into(), items: vec![Item::Row(2), Item::Row(3), Item::Sheet(inner_node)] };
        let root_node = SheetNode { doc: root.clone(), name: "test.bin".into(), items: vec![Item::Row(0), Item::Row(1), Item::Sheet(middle_node)] };
        assert_eq!(tree, [root_node], "each sheet under the step that made it");
        assert_eq!(state.rows[1].made, ["\"middle\""]);
    }

    #[test]
    fn the_sheets_view_shows_each_sheet_with_a_button_that_shows_it_and_what_would_not_replay() {
        let (app, [root, ..]) = app_with_lineage();
        let mut harness = harness_for(app);
        harness.step();
        harness.get_by_label("Sheets").click();
        harness.run();
        harness.get_by_label("middle");
        harness.get_by_label("inner");
        harness.get_by_label_contains("⚠ 0 unresolved documents · 2 literal offsets");
        let show_buttons: Vec<_> = harness.get_all_by_label("Show").collect();
        assert_eq!(show_buttons.len(), 3, "one for each sheet");
        show_buttons[0].click();
        harness.run();
        assert_eq!(harness.state().document_id(), root, "Show shows the sheet");
        harness.get_by_label("Suggest anchors…").click();
        harness.run();
        assert_eq!(harness.state().bench.panels.history.selected, Some(2), "the first step with a literal offset, the derive's start");
        harness.get_by_label("Recipe values");
    }

    #[test]
    fn the_variables_footer_lists_each_variable_and_goes_to_the_step_that_bound_it() {
        let mut app = app_with(b"NC500-2F357657 and more");
        app.perform("vars.set", json!({"name": "serial", "value": "NC500-2F357657"})).unwrap();
        let step = app.journal.last_step().unwrap();
        let mut harness = harness_for(app);
        harness.step();
        harness.get_by_label(&format!("$serial = \"NC500-2F357657\" (#{step})")).click();
        harness.run();
        assert_eq!(harness.state().bench.panels.history.selected, Some(step));
    }

    #[test]
    fn plus_binds_a_variable_to_the_selection_with_where_it_came_from() {
        let mut app = app_with(b"..PK....");
        app.search_mode = crate::search::SearchMode::Text;
        app.search_text = "PK".to_string();
        app.find_next();
        app.bench.send_to.variable_name = "magic".to_string();
        let mut harness = harness_for(app);
        harness.step();
        harness.get_by_label("+").click();
        harness.run();
        harness.get_by_label("Bind to the selection").click();
        harness.run();
        let shown = variables::variables(harness.state());
        assert_eq!(shown.len(), 1);
        assert_eq!((shown[0].name.as_str(), &shown[0].value), ("magic", &json!("504b")));
        harness.get_by_label_contains("$magic = \"504b\"");
    }
}
