//! The Output toggle of the window's apply rows: whether what an operation
//! makes goes over the bytes it came from or into a new worksheet, as the
//! method's `output` parameter says.
//!
//! ```text
//!  Output  (•) In place   ( ) New worksheet [label…]
//! ```
//!
//! Each tool remembers its own choice, starting from the default its method
//! publishes (`outputs.default`).

use eframe::egui::{self, RichText, Ui};
use serde_json::{Value, json};

use crate::api::OutputKind;
use crate::app::ViewerApp;
use crate::journal::DerivedFrom;
use crate::theme;

/// Width of the label field.
const LABEL_WIDTH: f32 = 110.0;

/// Where an apply row sends what it makes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputChoice {
    /// The method the row calls, whose default the choice starts from.
    method: &'static str,
    /// A new worksheet rather than in place.
    pub new: bool,
    /// The new worksheet's label, such as "config.plain"; none when empty.
    pub label: String,
}

impl Default for OutputChoice {
    /// The choice of a row that calls `transform.apply`, as most do.
    fn default() -> Self {
        OutputChoice::for_method("transform.apply")
    }
}

impl OutputChoice {
    /// The choice for a row that calls `method`, starting from its default
    /// output.
    pub fn for_method(method: &'static str) -> Self {
        let new = crate::api::method(method).and_then(|method| method.outputs).is_some_and(|outputs| outputs.default == OutputKind::New);
        OutputChoice { method, new, label: String::new() }
    }

    /// The `output` parameter for the choice: `"in_place"`, `"new"` or
    /// `{"new": {"label": …}}`.
    pub fn param(&self) -> Value {
        let label = self.label.trim();
        match (self.new, label.is_empty()) {
            (false, _) => json!("in_place"),
            (true, true) => json!("new"),
            (true, false) => json!({ "new": { "label": label } }),
        }
    }

    /// Put the choice into a call's `params`, leaving it out when it is the
    /// method's default and says nothing more.
    pub fn add_to(&self, params: &mut Value) {
        let default = Self::for_method(self.method);
        if self.new != default.new || (self.new && !self.label.trim().is_empty()) {
            params["output"] = self.param();
        }
    }
}

/// Apply `operation` to `len` bytes at `start` of sheet `sheet` through
/// `transform.apply`, its output where `choice` says, with the values
/// `derived_from` names the anchors of; another sheet than the one shown is
/// named. In place, the bytes it made are selected; as a new worksheet, the
/// new sheet is shown. Returns whether it was done (a failure is said on the
/// status bar).
pub fn transform_span(app: &mut ViewerApp, sheet: &str, (start, len): (usize, usize), operation: Value, choice: &OutputChoice, derived_from: DerivedFrom) -> bool {
    let mut params = json!({ "selection": { "range": [start, len] }, "operation": operation });
    let shown = sheet == app.document_id();
    if !shown {
        params["doc"] = json!(sheet);
    }
    choice.add_to(&mut params);
    if app.perform_derived("transform.apply", params, derived_from).is_err() {
        return false;
    }
    if shown && !choice.new {
        app.restore_selection(start, len);
    }
    true
}

/// "Output (•) In place ( ) New worksheet [label…]".
pub fn toggle(ui: &mut Ui, choice: &mut OutputChoice) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Output").small().color(theme::TEXT_DIM));
        ui.radio_value(&mut choice.new, false, "In place").on_hover_text("Change the bytes themselves, as one undoable step");
        ui.radio_value(&mut choice.new, true, "New worksheet").on_hover_text("Open what it makes as a sheet derived from this one, leaving this one as it is");
        ui.add_enabled(choice.new, egui::TextEdit::singleline(&mut choice.label).desired_width(LABEL_WIDTH).hint_text("label…"))
            .on_hover_text("A short name for the new sheet, which a recipe names it by");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_choice_starts_from_the_method_s_default_and_names_a_label_when_given() {
        let transform = OutputChoice::for_method("transform.apply");
        assert!(!transform.new, "transform.apply works in place by default");
        assert!(OutputChoice::for_method("crypto.apply").new);
        let mut params = json!({});
        transform.add_to(&mut params);
        assert_eq!(params, json!({}), "the default is left out");
        let labelled = OutputChoice { new: true, label: " config.plain ".into(), ..transform };
        labelled.add_to(&mut params);
        assert_eq!(params["output"], json!({"new": {"label": "config.plain"}}));
    }
}
