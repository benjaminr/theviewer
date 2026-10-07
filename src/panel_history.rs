//! The History tab: the session's journal, step by step, with who took
//! each step and what it did; undoing a step, going back to one, playback,
//! and saving the history as a recipe.
//!
//! The tab follows the journal by its revision (a read promoted into the
//! journal takes an earlier number, so following by the last step alone
//! would miss it), and lists each step with its caller, its description
//! and marks: bytes changed, failed or refused, merged moves, undone. A
//! step clicked shows its parameters, result and how it would be undone,
//! with the bytes it touched a click away, and the literals a recipe would
//! repeat, each of which can become an anchor or a named parameter.
//!
//! Everything the person does here is a method call as the panel:
//! `history.undo_step`, `history.go_back`, `history.save_recipe` and the
//! anchor methods. Playback goes back to the step before the first played,
//! then runs the steps again one at a time through the recipe runner, each
//! recorded as a step of its own (see [`crate::journal::timeline`]).

use std::time::{Duration, Instant};

use eframe::egui::{self, RichText, Ui};
use serde_json::{Value, json};

use crate::api::ErrorCode;
use crate::app::ViewerApp;
use crate::journal::provenance::{self, LiteralSuggestions};
use crate::journal::recipe::RECIPE_EXTENSION;
use crate::journal::timeline::{self, Inverse, Playback, StepStatus, Timeline};
use crate::journal::{JournalEntry, Outcome};
use crate::theme;

/// Height of the list of steps when a step's details are shown below it.
const LIST_HEIGHT: f32 = 220.0;
/// Characters of a parameter or result shown before it is cut.
const DETAIL_CHARS: usize = 4000;

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
}

impl Row {
    fn of(entry: &JournalEntry, status: StepStatus) -> Row {
        let error = match &entry.outcome {
            Outcome::Ok => None,
            Outcome::Error(error) => Some(error.message.clone()),
        };
        let refused = matches!(&entry.outcome, Outcome::Error(error) if error.code == ErrorCode::ReadOnly);
        let description = if entry.description.is_empty() { entry.method.clone() } else { entry.description.clone() };
        Row { step: entry.step, caller: entry.caller.clone(), method: entry.method.clone(), description, status, changed_bytes: entry.changed_document(), error, refused, merged: entry.merged }
    }

    fn is_undone(&self) -> bool {
        matches!(self.status, StepStatus::Undone { .. })
    }
}

/// Playback under way.
pub struct PlaybackRun {
    pub playback: Playback,
    pub paused: bool,
    last_played: Instant,
}

/// What the tab remembers between frames.
pub struct HistoryState {
    /// The journal's revision the rows were read at.
    seen_revision: Option<u64>,
    pub rows: Vec<Row>,
    /// Every caller in the journal, for the filter.
    callers: Vec<String>,
    /// The caller whose steps are shown, or every caller's.
    pub caller_filter: Option<String>,
    /// Show the steps undone too.
    pub show_undone: bool,
    /// The step whose details are shown.
    pub selected: Option<u64>,
    /// Anchors that could stand for the selected step's literals, at a
    /// journal revision.
    suggestions: Option<(u64, u64, Vec<LiteralSuggestions>)>,
    /// The name typed for a new recipe parameter.
    pub parameter_name: String,
    /// The name the recipe is saved under.
    pub recipe_name: String,
    /// The range of steps to play, and how fast.
    pub play_from: u64,
    pub play_through: u64,
    pub speed: Speed,
    pub playback: Option<PlaybackRun>,
    /// What the tab last had to say: why an undo or playback failed.
    pub note: Option<String>,
}

impl Default for HistoryState {
    fn default() -> Self {
        HistoryState {
            seen_revision: None,
            rows: Vec::new(),
            callers: Vec::new(),
            caller_filter: None,
            show_undone: true,
            selected: None,
            suggestions: None,
            parameter_name: String::new(),
            recipe_name: "My analysis".to_string(),
            play_from: 0,
            play_through: 0,
            speed: Speed::default(),
            playback: None,
            note: None,
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
        self.rows = app.journal.entries().map(|entry| Row::of(entry, timeline.status(entry.step).unwrap_or(StepStatus::Active))).collect();
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

    /// The rows the filters keep.
    fn shown(&self) -> impl Iterator<Item = &Row> {
        self.rows.iter().filter(|row| self.caller_filter.as_ref().is_none_or(|caller| *caller == row.caller) && (self.show_undone || !row.is_undone()))
    }
}

pub fn show_history(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui) {
    state.follow(app);
    play_due_step(state, app, ui.ctx());
    show_toolbar(state, app, ui);
    show_playback(state, app, ui);
    if let Some(note) = &state.note {
        ui.label(RichText::new(note).small().color(theme::DANGER));
    }
    ui.separator();
    let list_height = if state.selected.is_some() { LIST_HEIGHT } else { ui.available_height() };
    egui::ScrollArea::vertical().id_salt("history-steps").max_height(list_height).stick_to_bottom(true).auto_shrink([false, true]).show(ui, |ui| {
        if state.rows.is_empty() {
            ui.label(RichText::new("Nothing done yet. Each edit, view change, packet set and job, by you, plugins, Ask or MCP clients, is listed here as a step.").color(theme::TEXT_DIM));
        }
        let rows: Vec<Row> = state.shown().cloned().collect();
        for row in &rows {
            show_row(state, app, ui, row);
        }
    });
    if let Some(step) = state.selected {
        ui.separator();
        egui::ScrollArea::vertical().id_salt("history-details").show(ui, |ui| show_details(state, app, ui, step));
    }
}

/// The counts, the caller filter and "Save as recipe…".
fn show_toolbar(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui) {
    let undone = state.rows.iter().filter(|row| row.is_undone()).count();
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{} steps · {undone} undone", state.rows.len())).small().color(theme::TEXT_DIM));
        egui::ComboBox::from_id_salt("history-caller").selected_text(state.caller_filter.as_deref().unwrap_or("every caller")).show_ui(ui, |ui| {
            ui.selectable_value(&mut state.caller_filter, None, "every caller");
            for caller in state.callers.clone() {
                ui.selectable_value(&mut state.caller_filter, Some(caller.clone()), caller);
            }
        });
        ui.checkbox(&mut state.show_undone, "Show undone");
        ui.separator();
        ui.add(egui::TextEdit::singleline(&mut state.recipe_name).desired_width(140.0).hint_text("Recipe name"));
        let any = state.rows.iter().any(|row| row.status == StepStatus::Active);
        if ui.add_enabled(any, egui::Button::new("Save as recipe…")).on_hover_text("Save the steps in effect as a recipe file to run on other files").clicked() {
            save_as_recipe(app, &state.recipe_name);
        }
        if ui.add_enabled(any, egui::Button::new("Save to my recipes")).on_hover_text("Keep the steps in effect among your recipes, to run from Run recipe…").clicked() {
            state.note = save_to_my_recipes(app, &state.recipe_name).err().map(|error| error.message);
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
    let name = if name.trim().is_empty() { "My analysis" } else { name.trim() };
    app.perform("recipes.save", json!({"name": name, "journal_steps": steps, "overwrite": true}))
}

/// Ask where to save the steps in effect as a recipe called `name`, then
/// write it through `history.save_recipe`.
pub fn save_as_recipe(app: &mut ViewerApp, name: &str) {
    let name = if name.trim().is_empty() { "My analysis" } else { name.trim() };
    app.save_dialog_then_call("Save as recipe", &format!("{name}{RECIPE_EXTENSION}"), "history.save_recipe", recipe_params(name), "path");
}

/// The parameters of `history.save_recipe` but the path, for a recipe
/// called `name`.
fn recipe_params(name: &str) -> Value {
    json!({"name": name})
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
        state.note = Some(format!("There are no steps in effect from {} to {} to play", state.play_from, state.play_through));
        return;
    }
    let before = app.journal.entries().map(|entry| entry.step).filter(|step| *step < steps[0].step).max().unwrap_or(0);
    match app.perform("history.go_back", json!({"step": before})) {
        Ok(_) => {
            state.note = None;
            state.playback = Some(PlaybackRun { playback: Playback::new(steps, crate::api::Caller::Panel, None), paused: false, last_played: Instant::now() });
        }
        Err(error) => state.note = Some(format!("Playback could not go back to step {before}: {}", error.message)),
    }
}

/// Play the next step now.
pub fn play_one(state: &mut HistoryState, app: &mut ViewerApp) {
    let Some(run) = &mut state.playback else { return };
    if let Some(step) = run.playback.play_next(app) {
        state.selected = None;
        run.last_played = Instant::now();
        if let Some(error) = run.playback.stopped() {
            state.note = Some(format!("Step {step} failed when played again: {}", error.message));
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
        let mut text = RichText::new(&row.description);
        text = match row.status {
            StepStatus::Undone { by } => {
                ui.label(RichText::new(format!("undone by {by}")).small().color(theme::TEXT_DIM));
                text.strikethrough().color(theme::TEXT_DIM)
            }
            StepStatus::Failed => text.color(theme::DANGER),
            StepStatus::Move => text.italics().color(theme::TEXT_DIM),
            StepStatus::Active => text,
        };
        let selected = state.selected == Some(row.step);
        let label = ui.selectable_label(selected, text).on_hover_text(&row.method);
        if label.clicked() {
            state.selected = if selected { None } else { Some(row.step) };
        }
        label.context_menu(|ui| step_menu(state, app, ui, row));
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
        let mut params = recipe_params(&state.recipe_name);
        params["through"] = json!(row.step);
        app.save_dialog_then_call("Save as recipe", &format!("{}{RECIPE_EXTENSION}", state.recipe_name), "history.save_recipe", params, "path");
        ui.close();
    }
    if ui.button("Recipe values…").on_hover_text("Turn this step's values into anchors or parameters").clicked() {
        state.selected = Some(row.step);
        ui.close();
    }
}

/// Undo `step` through its inverse, as the person.
pub fn undo_step(state: &mut HistoryState, app: &mut ViewerApp, step: u64) {
    state.note = app.perform("history.undo_step", json!({"step": step})).err().map(|error| error.message);
}

/// Go back to `step`, as the person.
pub fn go_back(state: &mut HistoryState, app: &mut ViewerApp, step: u64) {
    state.playback = None;
    state.note = app.perform("history.go_back", json!({"step": step})).err().map(|error| error.message);
}

/// The selected step in full: what it did, how it would be undone, the
/// bytes it touched and its values for a recipe.
fn show_details(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui, step: u64) {
    let Some(entry) = app.journal.entry(step).cloned() else {
        state.selected = None;
        return;
    };
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("Step {step}")).strong());
        ui.label(RichText::new(format!("{} · {} · {}", entry.method, entry.caller, entry.at)).small().color(theme::TEXT_DIM));
        if ui.small_button("×").on_hover_text("Close").clicked() {
            state.selected = None;
        }
    });
    if !entry.description.is_empty() {
        ui.label(&entry.description);
    }
    if let Outcome::Error(error) = &entry.outcome {
        ui.label(RichText::new(&error.message).color(theme::DANGER));
    }
    let inverse = timeline::inverse_of(app, step);
    ui.horizontal_wrapped(|ui| {
        let can_undo = inverse.is_available() && state.rows.iter().any(|row| row.step == step && row.status == StepStatus::Active);
        if ui.add_enabled(can_undo, egui::Button::new("Undo this step")).clicked() {
            undo_step(state, app, step);
        }
        if ui.button("Go back to here").clicked() {
            go_back(state, app, step);
        }
        if let Some((start, len)) = touched_span(&entry)
            && ui.button("Show bytes").on_hover_text(format!("Select the {len} bytes at {start:#x} it touched")).clicked()
        {
            app.select_from_tool(start, len);
        }
        let how = match &inverse {
            Inverse::Calls { calls } => format!("Undoes by {}", calls.iter().map(|call| call.method.as_str()).collect::<Vec<_>>().join(", then ")),
            Inverse::Nothing { why } => format!("Nothing to undo: {why}"),
            Inverse::Unavailable { why } => format!("Cannot be undone now: {why}"),
        };
        ui.label(RichText::new(how).small().color(theme::TEXT_DIM));
    });
    egui::CollapsingHeader::new("Parameters").id_salt(("history-params", step)).default_open(true).show(ui, |ui| json_block(ui, &entry.params));
    if let Some(result) = &entry.result {
        egui::CollapsingHeader::new("Result").id_salt(("history-result", step)).show(ui, |ui| json_block(ui, result));
    }
    if entry.outcome.is_ok() {
        egui::CollapsingHeader::new("Recipe values").id_salt(("history-anchors", step)).show(ui, |ui| show_recipe_values(state, app, ui, step));
    }
}

/// A value as indented JSON, cut when long.
fn json_block(ui: &mut Ui, value: &Value) {
    let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
    if text.chars().count() > DETAIL_CHARS {
        text = format!("{}…", text.chars().take(DETAIL_CHARS).collect::<String>());
    }
    ui.label(RichText::new(text).monospace().small());
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
    let literals = state.suggestions.as_ref().map(|(_, _, literals)| literals.clone()).unwrap_or_default();
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
                        state.note = app.perform("history.clear_anchor", json!({"step": step, "path": literal.path})).err().map(|error| error.message);
                    }
                }
                None => {
                    let name = state.parameter_name.trim().to_string();
                    if ui.add_enabled(!name.is_empty(), egui::Button::new("Make a parameter").small()).clicked() {
                        state.note = app.perform("history.make_parameter", json!({"step": step, "path": literal.path, "name": name})).err().map(|error| error.message);
                    }
                }
            }
            for suggestion in &literal.suggestions {
                if ui.small_button(format!("Use {}", suggestion.reason)).on_hover_text(serde_json::to_string(&suggestion.anchor).unwrap_or_default()).clicked() {
                    state.note = app.perform("history.make_anchor", json!({"step": step, "path": literal.path, "anchor": suggestion.anchor})).err().map(|error| error.message);
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
        assert_eq!(state.note, None);
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
        assert_eq!(state.note, None);
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
        app.call_with_chosen_path("history.save_recipe", recipe_params("Patch"), "path", &path).unwrap();
        assert_eq!(take_performed()[0].0, "history.save_recipe");
        let recipe: crate::journal::Recipe = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(recipe.name, "Patch");
        assert_eq!(recipe.steps.iter().map(|step| step.method.as_str()).collect::<Vec<_>>(), ["bytes.write", "view.set_shape"]);
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
    fn the_caller_filter_shows_one_caller_s_steps() {
        let mut app = app_with(&[0u8; 8]);
        app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        crate::api::call_permitted(&mut app, &crate::api::Caller::Mcp("claude-code".into()), "cursor.set", json!({"offset": 3})).unwrap();
        let mut state = HistoryState::default();
        state.follow(&app);
        state.caller_filter = Some("mcp:claude-code".into());
        assert_eq!(state.shown().map(|row| row.method.as_str()).collect::<Vec<_>>(), ["cursor.set"]);
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
}
