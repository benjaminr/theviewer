//! How sheets are shown in the window: the line a tool shows above another
//! sheet's results.

use eframe::egui::{self, RichText, Ui};

use crate::app::ViewerApp;
use crate::theme;

/// Above a tool's results of sheet `sheet`, when another sheet is shown:
/// say whose they are ("From payload (doc-4) · Show it"), the link showing
/// that sheet once the frame is drawn (so a panel lent out to draw is
/// switched too). Returns whether they are another sheet's.
pub fn results_of_other_sheet(app: &mut ViewerApp, ui: &mut Ui, sheet: &str) -> bool {
    if sheet == app.document_id() {
        return false;
    }
    ui.horizontal_wrapped(|ui| {
        match app.sheet_title(sheet) {
            Some(title) => {
                ui.label(RichText::new(format!("From {title} ({sheet})")).small().color(theme::ACCENT));
                ui.label(RichText::new("·").small().color(theme::TEXT_DIM));
                let link = ui.add(egui::Link::new(RichText::new("Show it").small())).on_hover_text("Show that sheet, where these results are");
                if link.clicked() {
                    app.perform_later("documents.activate", serde_json::json!({ "doc": sheet }));
                }
            }
            None => {
                ui.label(RichText::new(format!("From {sheet}, which has closed")).small().color(theme::TEXT_DIM));
            }
        }
    });
    true
}
