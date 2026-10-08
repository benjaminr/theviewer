//! How sheets are shown in the window: the worksheet strip under the
//! toolbar, the tree of every open sheet (≡ Tree, and a section of the
//! Workspace tab), the question asked before unsaved edits are closed, and
//! the line a tool shows above another sheet's results.
//!
//! The strip is the active sheet's ancestry as a breadcrumb, each sheet a
//! link that shows it; a `▸` after a sheet drops down its children (the
//! siblings of the next sheet in the trail), and the other roots follow a
//! separator. `*` marks unsaved edits; a middle-click or ✕ closes a sheet
//! with those derived from it.

use eframe::egui::{self, Context, RichText, Ui};

use super::SheetSummary;
use crate::app::{ViewerApp, human_size};
use crate::theme;

/// What the strip and the tree remember between frames.
#[derive(Default)]
pub struct SheetsView {
    /// The tree of sheets is showing in a window of its own.
    pub tree_open: bool,
    /// The sheet picked in the tree, which its buttons act on.
    pub picked: Option<String>,
    /// A label being typed for a sheet, with the sheet.
    pub label_edit: Option<(String, String)>,
    /// Why the last label could not be given.
    pub label_error: Option<String>,
    /// Sheets the person asked to close, waiting for them to say whether
    /// the unsaved edits in them may be lost.
    pub close_request: Option<CloseRequest>,
}

/// Sheets to close, each with those derived from it, some with unsaved
/// edits.
#[derive(Clone, Debug, PartialEq)]
pub struct CloseRequest {
    /// The sheets to close, each with the sheets derived from it.
    pub sheets: Vec<String>,
    /// The sheets among them with unsaved edits, by title.
    pub unsaved: Vec<String>,
}

/// What the person did in the strip or the tree, carried out once the
/// sheets have been drawn.
enum SheetAction {
    Show(String),
    Close(String),
    ToggleTree,
    Pick(String),
    Compare(String),
    StartLabel(String),
}

impl ViewerApp {
    /// Close sheet `id` with the sheets derived from it, as
    /// `documents.close`, asking first when one has unsaved edits.
    pub fn request_close_sheet(&mut self, id: &str) {
        self.request_close_sheets(vec![id.to_string()]);
    }

    /// Close every sheet but the one shown and those it came from, as File
    /// › Close other worksheets, asking first when one has unsaved edits.
    pub fn request_close_other_sheets(&mut self) {
        let kept = self.active_ancestry();
        let sheets = self.sheets();
        let open = |id: &str| sheets.iter().any(|sheet| sheet.id == id);
        // Close each sheet whose parent stays (or is not open), which takes
        // its descendants with it.
        let tops = sheets
            .iter()
            .filter(|sheet| !kept.contains(&sheet.id))
            .filter(|sheet| sheet.parent.as_deref().is_none_or(|parent| kept.iter().any(|id| id == parent) || !open(parent)))
            .map(|sheet| sheet.id.clone())
            .collect();
        self.request_close_sheets(tops);
    }

    fn request_close_sheets(&mut self, sheets: Vec<String>) {
        if sheets.is_empty() {
            self.status = "No other worksheets are open".to_string();
            return;
        }
        let closing: Vec<String> = sheets.iter().flat_map(|id| self.sheet_and_descendants(id)).collect();
        let unsaved = self.unsaved_sheets(&closing);
        if unsaved.is_empty() {
            self.close_sheets_now(&sheets, false);
        } else {
            self.sheets_view.close_request = Some(CloseRequest { sheets, unsaved });
        }
    }

    /// Close `sheets`, each with those derived from it, as
    /// `documents.close`; `discard` loses their unsaved edits.
    fn close_sheets_now(&mut self, sheets: &[String], discard: bool) {
        for id in sheets {
            let mut params = serde_json::json!({ "doc": id });
            if discard {
                params["discard_unsaved"] = serde_json::json!(true);
            }
            self.perform_later("documents.close", params);
        }
    }

    /// Show the next open sheet in the order they were opened (or the one
    /// before), going round: Ctrl+Tab and Ctrl+Shift+Tab.
    pub fn cycle_sheet(&mut self, forward: bool) {
        let sheets = self.sheets();
        if sheets.len() < 2 {
            return;
        }
        let at = sheets.iter().position(|sheet| sheet.active).unwrap_or(0);
        let next = if forward { (at + 1) % sheets.len() } else { (at + sheets.len() - 1) % sheets.len() };
        self.show_sheet(&sheets[next].id);
    }

    /// Show or hide the tree of sheets.
    pub fn toggle_sheet_tree(&mut self) {
        self.sheets_view.tree_open = !self.sheets_view.tree_open;
    }

    /// Give sheet `id` a label (an empty one takes it away), which the strip
    /// shows and a recipe names the sheet by. Only a sheet a step made can
    /// be labelled, and no two open sheets alike.
    pub fn label_sheet(&mut self, id: &str, label: &str) -> Result<(), String> {
        let label = Some(label.trim()).filter(|label| !label.is_empty()).map(str::to_string);
        if let Some(label) = &label
            && let Some(other) = self.sheets().into_iter().find(|sheet| sheet.id != id && sheet.label.as_ref() == Some(label))
        {
            return Err(format!("{} is labelled {label} already", other.id));
        }
        let lineage = if id == self.document_id() { Some(&mut self.active_lineage) } else { self.parked_sheet_mut(id).map(|sheet| &mut sheet.lineage) };
        let made_by = lineage.and_then(|lineage| lineage.made_by.as_mut()).ok_or_else(|| "only a sheet a step made can be labelled".to_string())?;
        made_by.label = label.clone();
        self.journal.label_sheet(id, label);
        Ok(())
    }
}

/// A sheet as the strip and the tree write it: its title, `*` when it has
/// unsaved edits.
fn written(sheet: &SheetSummary) -> String {
    format!("{}{}", sheet.short, if sheet.modified { "*" } else { "" })
}

/// What the pointer over a sheet says about it.
fn described(sheet: &SheetSummary) -> String {
    let made = match &sheet.made_by {
        Some((method, Some(step))) => format!("made by step #{step}, {method}"),
        Some((method, None)) => format!("made by {method}"),
        None if sheet.parent.is_some() => "derived".to_string(),
        None => "opened".to_string(),
    };
    let unsaved = if sheet.modified { " · unsaved edits" } else { "" };
    format!("{} ({}) · {} · {made}{unsaved}\nClick to show it; middle-click to close it with the sheets derived from it", sheet.name, sheet.id, human_size(sheet.len))
}

/// The worksheet strip, under the toolbar.
pub fn show_strip(app: &mut ViewerApp, ui: &mut Ui) {
    let sheets = app.sheets();
    let ancestry = app.active_ancestry();
    let by_id = |id: &str| sheets.iter().find(|sheet| sheet.id == id);
    let children = |id: &str| -> Vec<&SheetSummary> { sheets.iter().filter(|sheet| sheet.parent.as_deref() == Some(id)).collect() };
    let open = |id: &str| sheets.iter().any(|sheet| sheet.id == id);
    let mut action = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 3.0;
        let tree = ui.selectable_label(app.sheets_view.tree_open, "≡ Tree").on_hover_text("Every open sheet, as a tree (Shift+Cmd+T)");
        if tree.clicked() {
            action = Some(SheetAction::ToggleTree);
        }
        for id in &ancestry {
            let Some(sheet) = by_id(id) else { continue };
            sheet_link(ui, sheet, &mut action);
            let below = children(id);
            if !below.is_empty() {
                ui.menu_button(RichText::new("▸").color(theme::TEXT_DIM), |ui| {
                    for child in below {
                        let on_trail = ancestry.contains(&child.id);
                        let text = format!("{}   {} · {}", written(child), child.id, human_size(child.len));
                        if ui.selectable_label(on_trail, text).on_hover_text(described(child)).clicked() {
                            action = Some(SheetAction::Show(child.id.clone()));
                            ui.close();
                        }
                    }
                })
                .response
                .on_hover_text("The sheets derived from this one");
            }
        }
        let only_blank = sheets.len() == 1 && app.active_is_blank();
        if !only_blank && ui.small_button("×").on_hover_text("Close this sheet and those derived from it (Cmd+W)").clicked() {
            action = Some(SheetAction::Close(app.document_id()));
        }
        let other_roots: Vec<&SheetSummary> =
            sheets.iter().filter(|sheet| sheet.parent.as_deref().is_none_or(|parent| !open(parent)) && Some(&sheet.id) != ancestry.first()).collect();
        if !other_roots.is_empty() {
            ui.separator();
            for root in other_roots {
                sheet_link(ui, root, &mut action);
            }
        }
    });
    carry_out(app, action);
}

/// One sheet in the strip: a link that shows it, closed by a middle-click.
fn sheet_link(ui: &mut Ui, sheet: &SheetSummary, action: &mut Option<SheetAction>) {
    let text = RichText::new(written(sheet));
    let text = if sheet.active { text.strong().color(theme::ACCENT) } else { text };
    let response = ui.selectable_label(sheet.active, text).on_hover_text(described(sheet));
    if response.clicked() {
        *action = Some(SheetAction::Show(sheet.id.clone()));
    }
    if response.middle_clicked() {
        *action = Some(SheetAction::Close(sheet.id.clone()));
    }
    response.context_menu(|ui| {
        if ui.button("Show").clicked() {
            *action = Some(SheetAction::Show(sheet.id.clone()));
            ui.close();
        }
        if !sheet.active && ui.button("Compare with active").clicked() {
            *action = Some(SheetAction::Compare(sheet.id.clone()));
            ui.close();
        }
        if sheet.made_by.is_some() && ui.button("Label…").clicked() {
            *action = Some(SheetAction::StartLabel(sheet.id.clone()));
            ui.close();
        }
        if ui.button("Close").clicked() {
            *action = Some(SheetAction::Close(sheet.id.clone()));
            ui.close();
        }
    });
}

/// Every open sheet as a tree, each with its size and the step and method
/// that made it, and what can be done to the one picked.
pub fn show_tree(app: &mut ViewerApp, ui: &mut Ui) {
    let sheets = app.sheets();
    let open = |id: &str| sheets.iter().any(|sheet| sheet.id == id);
    let mut action = None;
    if app.sheets_view.picked.as_deref().is_none_or(|picked| !open(picked)) {
        app.sheets_view.picked = Some(app.document_id());
    }
    let picked = app.sheets_view.picked.clone();
    let roots: Vec<&SheetSummary> = sheets.iter().filter(|sheet| sheet.parent.as_deref().is_none_or(|parent| !open(parent))).collect();
    egui::Grid::new("sheet-tree").num_columns(4).spacing([12.0, 2.0]).striped(true).show(ui, |ui| {
        for root in roots {
            tree_rows(ui, &sheets, root, 0, picked.as_deref(), &mut action);
        }
    });
    if let Some(picked) = sheets.iter().find(|sheet| Some(&sheet.id) == picked.as_ref()) {
        ui.horizontal(|ui| {
            if ui.add_enabled(!picked.active, egui::Button::new("Show")).clicked() {
                action = Some(SheetAction::Show(picked.id.clone()));
            }
            let compare = ui.add_enabled(!picked.active, egui::Button::new("Compare with active")).on_hover_text("Compare the sheet shown with this one in the Diff tab");
            if compare.clicked() {
                action = Some(SheetAction::Compare(picked.id.clone()));
            }
            if ui.button("Close").on_hover_text("Close this sheet and those derived from it").clicked() {
                action = Some(SheetAction::Close(picked.id.clone()));
            }
            let label = ui.add_enabled(picked.made_by.is_some(), egui::Button::new("Label…")).on_hover_text("A short name the strip shows and a recipe names the sheet by").on_disabled_hover_text("Only a sheet a step made can be labelled");
            if label.clicked() {
                action = Some(SheetAction::StartLabel(picked.id.clone()));
            }
        });
    }
    show_label_editor(app, ui);
    carry_out(app, action);
}

/// One sheet's row of the tree and its descendants' below it.
fn tree_rows(ui: &mut Ui, sheets: &[SheetSummary], sheet: &SheetSummary, depth: usize, picked: Option<&str>, action: &mut Option<SheetAction>) {
    ui.horizontal(|ui| {
        ui.add_space(depth as f32 * 14.0);
        let marker = if sheet.active { "●" } else { "○" };
        let text = RichText::new(format!("{marker} {}", written(sheet)));
        let text = if sheet.active { text.color(theme::ACCENT) } else { text };
        let row = ui.selectable_label(picked == Some(sheet.id.as_str()), text).on_hover_text(described(sheet));
        if row.clicked() {
            *action = Some(SheetAction::Pick(sheet.id.clone()));
        }
        if row.double_clicked() {
            *action = Some(SheetAction::Show(sheet.id.clone()));
        }
        if row.middle_clicked() {
            *action = Some(SheetAction::Close(sheet.id.clone()));
        }
    });
    let step = sheet.made_by.as_ref().and_then(|(_, step)| *step).map(|step| format!("#{step}")).unwrap_or_default();
    ui.label(RichText::new(step).small().monospace().color(theme::TEXT_DIM));
    ui.label(RichText::new(human_size(sheet.len)).small().color(theme::TEXT_DIM));
    let made = match &sheet.made_by {
        Some((method, _)) => method.clone(),
        None if sheet.parent.is_none() => if sheet.name == "untitled" { "new".to_string() } else { "file".to_string() },
        None => "derived".to_string(),
    };
    ui.label(RichText::new(format!("{made} · {}", sheet.id)).small().color(theme::TEXT_DIM));
    ui.end_row();
    for child in sheets.iter().filter(|child| child.parent.as_deref() == Some(sheet.id.as_str())) {
        tree_rows(ui, sheets, child, depth + 1, picked, action);
    }
}

/// The field a label is typed in, under the tree.
fn show_label_editor(app: &mut ViewerApp, ui: &mut Ui) {
    let Some((id, mut text)) = app.sheets_view.label_edit.clone() else { return };
    let mut done = false;
    ui.horizontal(|ui| {
        ui.label(format!("Label {id}"));
        let field = ui.add(egui::TextEdit::singleline(&mut text).hint_text("payload").desired_width(160.0));
        let entered = field.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
        if ui.button("Set").clicked() || entered {
            match app.label_sheet(&id, &text) {
                Ok(()) => done = true,
                Err(message) => app.sheets_view.label_error = Some(message),
            }
        }
        if ui.button("Cancel").clicked() {
            done = true;
        }
    });
    if let Some(error) = &app.sheets_view.label_error {
        ui.label(RichText::new(error).small().color(theme::DANGER));
    }
    app.sheets_view.label_edit = if done { None } else { Some((id, text)) };
    if done {
        app.sheets_view.label_error = None;
    }
}

/// Do what the person asked for in the strip or the tree: sheets are shown
/// and closed through the API once the frame is drawn, so a panel lent out
/// to draw is switched with the rest.
fn carry_out(app: &mut ViewerApp, action: Option<SheetAction>) {
    match action {
        Some(SheetAction::Show(id)) => app.perform_later("documents.activate", serde_json::json!({ "doc": id })),
        Some(SheetAction::Close(id)) => app.request_close_sheet(&id),
        Some(SheetAction::ToggleTree) => app.toggle_sheet_tree(),
        Some(SheetAction::Pick(id)) => app.sheets_view.picked = Some(id),
        Some(SheetAction::Compare(id)) => crate::analysis_tabs::start_diff_with_sheet(app, &id),
        Some(SheetAction::StartLabel(id)) => {
            let current = app.sheets().into_iter().find(|sheet| sheet.id == id).and_then(|sheet| sheet.label).unwrap_or_default();
            app.sheets_view.picked = Some(id.clone());
            app.sheets_view.label_edit = Some((id, current));
            app.sheets_view.label_error = None;
            app.sheets_view.tree_open = true;
        }
        None => {}
    }
}

/// The tree of sheets in a window of its own (≡ Tree, Shift+Cmd+T).
pub fn show_tree_window(app: &mut ViewerApp, ctx: &Context) {
    if !app.sheets_view.tree_open {
        return;
    }
    let mut open = true;
    egui::Window::new("Worksheets").open(&mut open).resizable(true).default_width(460.0).default_pos([16.0, 260.0]).show(ctx, |ui| show_tree(app, ui));
    app.sheets_view.tree_open &= open;
}

/// Ask whether sheets with unsaved edits may be closed, losing them.
pub fn show_close_confirmation(app: &mut ViewerApp, ctx: &Context) {
    let Some(request) = app.sheets_view.close_request.clone() else { return };
    let mut answer = None;
    egui::Window::new("Close worksheets?").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
        let what = match request.unsaved.as_slice() {
            [one] => format!("{one} has unsaved edits."),
            many => format!("{} have unsaved edits.", many.join(", ")),
        };
        ui.label(what);
        ui.label(RichText::new("Closing loses them; the sheets derived from what closes close with it.").color(theme::TEXT_DIM));
        ui.horizontal(|ui| {
            if ui.button(RichText::new("Close and lose the edits").color(theme::DANGER)).clicked() {
                answer = Some(true);
            }
            if ui.button("Cancel").clicked() || ui.input(|input| input.key_pressed(egui::Key::Escape)) {
                answer = Some(false);
            }
        });
    });
    if let Some(close) = answer {
        app.sheets_view.close_request = None;
        if close {
            app.close_sheets_now(&request.sheets, true);
        }
    }
}

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
