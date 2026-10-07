//! "Run recipe…": pick a saved recipe, fill in its parameters, see what it
//! would do to this file, then run it.
//!
//! The preview is `recipes.preview` and the run `recipes.run`, both called
//! as the person ([`ViewerApp::perform`]). Pressing Run after seeing the
//! preview is the person's consent to the whole run, so its steps are not
//! asked about one by one; they are journalled inside the run's step and
//! their edits undo as one step, "Recipe steps by recipe:NAME".

use std::collections::BTreeMap;

use eframe::egui::{self, Context, RichText};
use serde_json::Value;

use super::RecipeSummary;
use crate::app::ViewerApp;
use crate::journal::Outcome;
use crate::journal::replay::RunReport;
use crate::theme;

/// The window's state, kept by the app.
#[derive(Default)]
pub struct RecipeWindow {
    pub open: bool,
    /// The folder recipes are kept in, or why there is none.
    dir: Option<Result<String, String>>,
    /// The saved recipes, as last listed.
    recipes: Vec<RecipeSummary>,
    /// The recipe picked, by its place in `recipes`.
    chosen: Option<usize>,
    /// The text typed for each parameter of the chosen recipe.
    values: BTreeMap<String, String>,
    /// The last preview of the chosen recipe with these values.
    preview: Option<Result<RunReport, String>>,
    /// How the last run went, in a line.
    outcome: Option<Result<String, String>>,
}

/// What the person asked for in a frame, done once the window is drawn.
enum Request {
    Refresh,
    Choose(usize),
    Preview,
    Run,
}

impl RecipeWindow {
    /// Open the window on the recipes saved now.
    pub fn show(&mut self) {
        self.open = true;
        self.refresh();
    }

    /// List the saved recipes again, keeping the one picked if it is still there.
    fn refresh(&mut self) {
        let kept = self.chosen_recipe().map(|recipe| recipe.path.clone());
        match super::recipes_dir() {
            Ok(dir) => {
                self.recipes = super::list(&dir);
                self.dir = Some(Ok(dir.display().to_string()));
            }
            Err(error) => {
                self.recipes.clear();
                self.dir = Some(Err(error.message));
            }
        }
        self.chosen = kept.and_then(|path| self.recipes.iter().position(|recipe| recipe.path == path));
        if self.chosen.is_none() {
            self.values.clear();
            self.preview = None;
        }
    }

    fn chosen_recipe(&self) -> Option<&RecipeSummary> {
        self.chosen.and_then(|index| self.recipes.get(index))
    }

    fn choose(&mut self, index: usize) {
        self.chosen = Some(index);
        self.values = self.recipes[index]
            .parameters
            .iter()
            .map(|(name, parameter)| {
                let default = match &parameter.default {
                    Some(Value::String(text)) => text.clone(),
                    Some(other) => other.to_string(),
                    None => String::new(),
                };
                (name.clone(), default)
            })
            .collect();
        self.preview = None;
        self.outcome = None;
    }

    /// The parameters' values as typed, leaving out the empty ones so they
    /// take their defaults.
    fn parameters(&self) -> Value {
        let given: serde_json::Map<String, Value> = self.values.iter().filter(|(_, text)| !text.is_empty()).map(|(name, text)| (name.clone(), Value::String(text.clone()))).collect();
        Value::Object(given)
    }

    /// Whether the preview says the recipe would run to its end.
    fn previewed_cleanly(&self) -> bool {
        matches!(&self.preview, Some(Ok(report)) if report.completed())
    }
}

impl ViewerApp {
    /// Open "Run recipe…".
    pub fn open_recipe_window(&mut self) {
        self.recipe_window.show();
    }

    /// Draw "Run recipe…" when open, and carry out what the person asked.
    pub fn show_recipe_window(&mut self, ctx: &Context) {
        if !self.recipe_window.open {
            return;
        }
        let mut window = std::mem::take(&mut self.recipe_window);
        let mut open = true;
        let mut request = None;
        egui::Window::new("Run recipe")
            .open(&mut open)
            .collapsible(false)
            .default_width(560.0)
            .show(ctx, |ui| request = recipe_window_contents(ui, &mut window));
        window.open = open;
        self.recipe_window = window;
        match request {
            Some(Request::Refresh) => self.recipe_window.refresh(),
            Some(Request::Choose(index)) => self.recipe_window.choose(index),
            Some(Request::Preview) => self.preview_chosen_recipe(),
            Some(Request::Run) => self.run_chosen_recipe(),
            None => {}
        }
    }

    fn chosen_recipe_params(&self) -> Option<Value> {
        let recipe = self.recipe_window.chosen_recipe()?;
        Some(serde_json::json!({ "path": recipe.path, "parameters": self.recipe_window.parameters() }))
    }

    /// Show what the chosen recipe would do to this file.
    fn preview_chosen_recipe(&mut self) {
        let Some(params) = self.chosen_recipe_params() else { return };
        let preview = self.perform("recipes.preview", params).map_err(|error| error.message).and_then(|report| serde_json::from_value::<RunReport>(report).map_err(|error| error.to_string()));
        self.recipe_window.preview = Some(preview);
        self.recipe_window.outcome = None;
    }

    /// Run the chosen recipe, the preview having been seen.
    fn run_chosen_recipe(&mut self) {
        let Some(params) = self.chosen_recipe_params() else { return };
        let name = self.recipe_window.chosen_recipe().map(|recipe| recipe.name.clone()).unwrap_or_default();
        let outcome = match self.perform("recipes.run", params) {
            Ok(report) => {
                let report: RunReport = serde_json::from_value(report).unwrap_or_default();
                let line = format!("{name}: {}. Undo takes it all back as one step.", report.summary());
                self.status = line.clone();
                Ok(line)
            }
            Err(error) => Err(error.message),
        };
        self.recipe_window.outcome = Some(outcome);
        self.recipe_window.preview = None;
    }
}

/// The window's buttons, for tests that drive it without drawing it.
#[cfg(test)]
impl ViewerApp {
    pub(crate) fn recipe_window_choose(&mut self, index: usize) {
        self.recipe_window.choose(index);
    }

    pub(crate) fn recipe_window_preview(&mut self) {
        self.preview_chosen_recipe();
    }

    pub(crate) fn recipe_window_can_run(&self) -> bool {
        self.recipe_window.previewed_cleanly()
    }

    pub(crate) fn recipe_window_run(&mut self) {
        self.run_chosen_recipe();
    }
}

/// The window's contents; returns what the person asked for.
fn recipe_window_contents(ui: &mut egui::Ui, window: &mut RecipeWindow) -> Option<Request> {
    let mut request = None;
    match &window.dir {
        Some(Ok(dir)) => {
            ui.label(RichText::new(format!("Recipes in {dir}")).small().color(theme::TEXT_DIM));
        }
        Some(Err(problem)) => {
            ui.colored_label(theme::DANGER, problem);
        }
        None => {}
    }
    if window.recipes.is_empty() {
        ui.label("No recipes are saved yet. Save one from the History tab, or with recipes.save.");
    }
    egui::ScrollArea::vertical().id_salt("recipe list").max_height(160.0).show(ui, |ui| {
        for (index, recipe) in window.recipes.iter().enumerate() {
            let title = if recipe.description.is_empty() { recipe.name.clone() } else { format!("{} — {}", recipe.name, recipe.description) };
            let picked = window.chosen == Some(index);
            if ui.add_enabled(recipe.error.is_none(), egui::Button::selectable(picked, title)).on_disabled_hover_text(recipe.error.clone().unwrap_or_default()).clicked() {
                request = Some(Request::Choose(index));
            }
        }
    });
    if ui.small_button("Refresh").clicked() {
        request = Some(Request::Refresh);
    }
    let Some(recipe) = window.chosen_recipe().cloned() else { return request };
    ui.separator();
    ui.label(RichText::new(format!("{}: {} step{}", recipe.name, recipe.steps, if recipe.steps == 1 { "" } else { "s" })).strong());
    for (name, parameter) in &recipe.parameters {
        ui.horizontal(|ui| {
            ui.label(format!("{name} ({})", parameter.kind.name())).on_hover_text(&parameter.description);
            let value = window.values.entry(name.clone()).or_default();
            if ui.text_edit_singleline(value).changed() {
                window.preview = None;
            }
        });
    }
    ui.horizontal(|ui| {
        if ui.button("Preview").clicked() {
            request = Some(Request::Preview);
        }
        let run = ui.add_enabled(window.previewed_cleanly(), egui::Button::new("Run"));
        if run.on_disabled_hover_text("Preview the recipe on this file first; it runs once the preview shows every step can").clicked() {
            request = Some(Request::Run);
        }
    });
    match &window.preview {
        Some(Ok(report)) => show_preview(ui, report),
        Some(Err(problem)) => {
            ui.colored_label(theme::DANGER, problem);
        }
        None => {}
    }
    match &window.outcome {
        Some(Ok(line)) => {
            ui.colored_label(theme::ACCENT, line);
        }
        Some(Err(problem)) => {
            ui.colored_label(theme::DANGER, problem);
        }
        None => {}
    }
    request
}

/// Each step the recipe would take, where its anchors resolved, and what
/// to know.
fn show_preview(ui: &mut egui::Ui, report: &RunReport) {
    ui.separator();
    egui::ScrollArea::vertical().id_salt("recipe preview").max_height(260.0).show(ui, |ui| {
        for step in &report.steps {
            let colour = if step.outcome.is_ok() { theme::TEXT } else { theme::DANGER };
            ui.colored_label(colour, format!("{}. {}", step.step, step.description));
            for anchor in &step.anchors {
                let value = anchor.pending.clone().unwrap_or_else(|| anchor.value.to_string());
                ui.label(RichText::new(format!("    {} ← {}: {value}", anchor.path, anchor.anchor.describe())).small().color(theme::TEXT_DIM));
            }
            if let Outcome::Error(error) = &step.outcome {
                ui.colored_label(theme::DANGER, format!("    {}", error.message));
            }
        }
    });
    for warning in &report.warnings {
        ui.label(RichText::new(format!("⚠ {warning}")).small().color(theme::CURSOR));
    }
    if let Some(stopped) = &report.stopped {
        ui.colored_label(theme::DANGER, format!("The run would stop at step {}.", stopped.step));
    }
}
