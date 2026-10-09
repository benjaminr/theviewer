//! The History tab's Variables footer: each variable the session bound,
//! its value and the step that bound it.
//!
//! ```text
//!  Variables:  $serial = "NC500-2F357657" (#5)   $key = "65ffb335" (#14)   [+]
//! ```
//!
//! A variable clicked goes to the step that bound it, and shows it; one can
//! be dragged onto a bound field or sent with *Send to*, as `{"$var"}`, so
//! a recipe passes the variable rather than its value. [+] binds a new one
//! to the selection.

use eframe::egui::{self, RichText, Sense, Ui};
use serde_json::Value;

use super::HistoryState;
use crate::app::ViewerApp;
use crate::send_to::{self, Carry, Sending};
use crate::theme;

/// Characters of a value the footer shows before cutting it.
const VALUE_CHARS: usize = 24;

/// One variable as the footer shows it.
#[derive(Clone, Debug, PartialEq)]
pub struct ShownVariable {
    pub name: String,
    pub value: Value,
    /// The step that bound it.
    pub step: Option<u64>,
    /// Where its value came from, in words, when it was bound from an anchor.
    pub from: Option<String>,
}

impl ShownVariable {
    /// "$serial = "NC500-2F357657" (#5)".
    pub fn text(&self) -> String {
        let value = match &self.value {
            Value::String(text) => format!("\"{}\"", crate::text::truncate_chars(text, VALUE_CHARS)),
            other => crate::text::truncate_chars(&other.to_string(), VALUE_CHARS),
        };
        let step = self.step.map(|step| format!(" (#{step})")).unwrap_or_default();
        format!("${} = {value}{step}", self.name)
    }
}

/// The session's variables, as the footer lists them.
pub fn variables(app: &ViewerApp) -> Vec<ShownVariable> {
    let journal = &app.journal;
    journal
        .variables()
        .iter()
        .map(|(name, binding)| {
            let anchor = binding.step.and_then(|step| journal.entry(step)).and_then(|entry| entry.derived_from.get("value"));
            ShownVariable { name: name.clone(), value: binding.value.clone(), step: binding.step, from: anchor.map(|anchor| anchor.describe()) }
        })
        .collect()
}

/// The footer: each variable, and [+].
pub fn show_variables(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui) {
    let shown = variables(app);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Variables:").small().color(theme::TEXT_DIM));
        if shown.is_empty() {
            ui.label(RichText::new("none yet; Send to › Variable… binds one").small().color(theme::TEXT_DIM));
        }
        for variable in &shown {
            let hover = match (&variable.from, variable.step) {
                (Some(from), Some(step)) => format!("{from}, bound by step {step}; click to go to it, drag it onto a field"),
                (None, Some(step)) => format!("Bound by step {step} to a value typed; click to go to it, drag it onto a field"),
                _ => "Drag it onto a field".to_string(),
            };
            let label = ui.add(egui::Label::new(RichText::new(variable.text()).monospace().small().color(theme::ACCENT)).sense(Sense::click_and_drag())).on_hover_text(hover);
            let carry = || Carry::variable(&variable.name, &variable.value, app.document_id());
            send_to::drag_source(&label, carry);
            if label.clicked()
                && let Some(step) = variable.step
            {
                state.selected = Some(step);
                state.go_to_step(step);
            }
            label.context_menu(|ui| {
                let carry = Carry::variable(&variable.name, &variable.value, app.document_id());
                send_to::menu(app, ui, &carry);
            });
        }
        ui.menu_button("+", |ui| add_variable(app, ui)).response.on_hover_text("Bind a variable to the selection");
    });
}

/// [+]: a name, bound to the selection with where it came from.
fn add_variable(app: &mut ViewerApp, ui: &mut Ui) {
    let carry = app.selection_carry();
    ui.label(RichText::new(carry.as_ref().map_or_else(|| "Select the bytes to bind first".to_string(), |carry| format!("{} · {}", carry.summary(), carry.from()))).small().color(theme::TEXT_DIM));
    ui.horizontal(|ui| {
        ui.label("$");
        ui.add(egui::TextEdit::singleline(&mut app.bench.send_to.variable_name).desired_width(120.0).hint_text("name"));
        let name = app.bench.send_to.variable_name.trim().to_string();
        if ui.add_enabled(carry.is_some() && !name.is_empty(), egui::Button::new("Bind to the selection")).clicked()
            && let Some(carry) = carry
        {
            send_to::send_later(app, Sending::Variable(name), carry);
            app.bench.send_to.variable_name.clear();
            ui.close();
        }
    });
}
