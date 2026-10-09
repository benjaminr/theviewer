//! The History tab's Sheets view: the steps grouped under the sheet they
//! ran on, as a tree that follows the sheets' lineage, each sheet made by a
//! step under that step, and a line of what would stop the steps replaying
//! as a recipe.
//!
//! ```text
//!  ▾ novacam_2.0.3.upd  (doc-1, 412 KiB)                          [Show]
//!      #1  Derive "reassembled" …                       ──▶ "reassembled"
//!      ▾ "reassembled"  (doc-2, 401 KiB)                          [Show]
//!          #5  Bind $serial to "NC500-2F357657"   ← pick #4 /^NC500-/
//!  ⚠ 0 unresolved documents · 2 literal offsets  Suggest anchors…
//! ```
//!
//! Notes stay where they were written, under the sheet shown then.

use std::collections::{BTreeMap, BTreeSet};

use eframe::egui::{self, RichText, Ui};

use super::{HistoryState, Row, show_item};
use crate::app::ViewerApp;
use crate::journal::notes::Names;
use crate::journal::provenance::{self, RecipeSteps};
use crate::journal::{Journal, timeline};
use crate::send_to::{self, Carry};
use crate::theme;

/// One sheet of the view: the rows of the steps and notes about it, and the
/// sheets made from it, in step order.
#[derive(Clone, Debug, PartialEq)]
pub struct SheetNode {
    /// Its id; empty for the steps about no sheet.
    pub doc: String,
    /// What it is called: its label, or the name of the file.
    pub name: String,
    pub items: Vec<Item>,
}

/// A row or a sheet under a sheet.
#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    /// A row of the tab's rows, by index.
    Row(usize),
    Sheet(SheetNode),
}

/// The sheets the session saw as a tree of their lineage, each holding the
/// rows of `rows` at the indices `shown` (those the filters keep) about it,
/// and each sheet a step made placed after that step. Rows about no sheet
/// come last, under a node of their own.
pub fn sheet_tree(journal: &Journal, rows: &[Row], shown: &[usize]) -> Vec<SheetNode> {
    let names = Names::of(journal);
    let mut parents: BTreeMap<String, String> = BTreeMap::new();
    let mut makers: BTreeMap<String, u64> = BTreeMap::new();
    let mut docs: BTreeSet<String> = BTreeSet::new();
    for document in &journal.session().documents {
        docs.insert(document.id.clone());
        if let Some(parent) = &document.parent {
            parents.insert(document.id.clone(), parent.clone());
        }
    }
    for entry in journal.entries().filter(|entry| entry.outcome.is_ok()) {
        for made in &entry.made {
            docs.insert(made.clone());
            makers.insert(made.clone(), entry.step);
            if let Some(from) = &entry.doc {
                parents.entry(made.clone()).or_insert_with(|| from.clone());
            }
        }
    }
    let mut rows_of: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut loose = Vec::new();
    for &index in shown {
        match &rows[index].doc {
            Some(doc) => {
                docs.insert(doc.clone());
                rows_of.entry(doc.clone()).or_default().push(index);
            }
            None => loose.push(index),
        }
    }
    let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut roots = Vec::new();
    for doc in &docs {
        match parents.get(doc).filter(|parent| docs.contains(*parent) && *parent != doc) {
            Some(parent) => children.entry(parent.clone()).or_default().push(doc.clone()),
            None => roots.push(doc.clone()),
        }
    }
    roots.sort_by_key(|doc| crate::sheets::opening_order(doc));
    let tree = Tree { names: &names, rows, rows_of: &rows_of, children: &children, makers: &makers };
    let mut seen = BTreeSet::new();
    let mut nodes: Vec<SheetNode> = roots.iter().map(|root| tree.node(root, &mut seen)).collect();
    if !loose.is_empty() {
        nodes.push(SheetNode { doc: String::new(), name: "About no sheet".to_string(), items: loose.into_iter().map(Item::Row).collect() });
    }
    nodes
}

/// What building the tree reads.
struct Tree<'a> {
    names: &'a Names,
    rows: &'a [Row],
    rows_of: &'a BTreeMap<String, Vec<usize>>,
    children: &'a BTreeMap<String, Vec<String>>,
    makers: &'a BTreeMap<String, u64>,
}

impl Tree<'_> {
    /// The node of `doc`, its rows and its children by step, a child after
    /// the step that made it.
    fn node(&self, doc: &str, seen: &mut BTreeSet<String>) -> SheetNode {
        seen.insert(doc.to_string());
        let mut keyed: Vec<((u64, u8, u64), Item)> = Vec::new();
        for &index in self.rows_of.get(doc).into_iter().flatten() {
            keyed.push(((self.rows[index].step, 0, 0), Item::Row(index)));
        }
        for child in self.children.get(doc).into_iter().flatten() {
            if seen.contains(child) {
                continue;
            }
            let after = self.makers.get(child).copied().unwrap_or(u64::MAX);
            keyed.push(((after, 1, crate::sheets::opening_order(child)), Item::Sheet(self.node(child, seen))));
        }
        keyed.sort_by_key(|(key, _)| *key);
        let name = self.names.document(doc).trim_matches('"').to_string();
        SheetNode { doc: doc.to_string(), name, items: keyed.into_iter().map(|(_, item)| item).collect() }
    }
}

/// The steps grouped under their sheets, in a list `height` tall at most.
pub fn show(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui, height: f32) {
    let shown: Vec<usize> = state.shown().collect();
    let revision = app.journal.revision();
    let current = state.sheet_tree.as_ref().is_some_and(|(at, kept, _)| *at == revision && *kept == shown);
    if !current {
        let tree = sheet_tree(&app.journal, &state.rows, &shown);
        state.sheet_tree = Some((revision, shown, tree));
    }
    let tree = state.sheet_tree.as_ref().map(|(_, _, tree)| tree.clone()).unwrap_or_default();
    egui::ScrollArea::vertical().id_salt("history-sheets").max_height(height).auto_shrink([false, true]).show(ui, |ui| {
        for node in &tree {
            show_node(state, app, ui, node);
        }
    });
}

/// A sheet's header, then, while it is open, its rows and sheets.
fn show_node(state: &mut HistoryState, app: &mut ViewerApp, ui: &mut Ui, node: &SheetNode) {
    let id = ui.make_persistent_id(("history-sheet", &node.doc));
    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true).show_header(ui, |ui| sheet_header(app, ui, node)).body(|ui| {
        for item in &node.items {
            match item {
                Item::Row(index) => {
                    let Some(row) = state.rows.get(*index).cloned() else { continue };
                    ui.scope(|ui| show_item(state, app, ui, &row));
                }
                Item::Sheet(child) => show_node(state, app, ui, child),
            }
        }
    });
}

/// "reassembled  (doc-2, 401 KiB)  [Show]": the sheet, its id and size
/// while it is open, and a button that shows it.
fn sheet_header(app: &mut ViewerApp, ui: &mut Ui, node: &SheetNode) {
    if node.doc.is_empty() {
        ui.label(RichText::new(&node.name).strong().color(theme::TEXT_DIM));
        return;
    }
    let active = node.doc == app.document_id();
    let open = app.sheets().into_iter().find(|sheet| sheet.id == node.doc);
    let mut name = RichText::new(&node.name).strong();
    if active {
        name = name.color(theme::ACCENT);
    }
    let label = ui.add(egui::Label::new(name).sense(egui::Sense::click()));
    label.context_menu(|ui| send_to::menu(app, ui, &Carry::Sheet(node.doc.clone())));
    let detail = match &open {
        Some(sheet) => format!("({}, {})", node.doc, crate::compress::human_bytes(sheet.len)),
        None => format!("({}, closed)", node.doc),
    };
    ui.label(RichText::new(detail).small().color(theme::TEXT_DIM));
    let button = ui.add_enabled(open.is_some() && !active, egui::Button::new("Show").small());
    let button = if active { button.on_disabled_hover_text("This sheet is shown") } else { button.on_disabled_hover_text("This sheet has closed") };
    if button.clicked() {
        app.perform_later("documents.activate", serde_json::json!({ "doc": node.doc }));
    }
}

/// What would stop the steps in effect replaying as a recipe: the
/// documents the recipe builder could not name, and the offsets it would
/// repeat literally.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RecipeChecks {
    /// Why each document could not be named, as the builder says.
    pub unresolved: Vec<String>,
    /// Each literal offset: its step and its parameter's path.
    pub literal_offsets: Vec<(u64, String)>,
}

/// The recipe builder's checks of the steps in effect.
pub fn recipe_checks(journal: &Journal) -> RecipeChecks {
    let mut checks = RecipeChecks::default();
    if let Err(error) = provenance::build_recipe(journal, "check", RecipeSteps::InEffect { through: None }) {
        let listed = |key: &str| error.data.as_ref().and_then(|data| data.get(key)).and_then(serde_json::Value::as_array).cloned().unwrap_or_default();
        let problems: Vec<String> = listed("problems").iter().map(|problem| format!("step {}: {}", problem["step"], problem["reason"].as_str().unwrap_or_default())).collect();
        let lost: Vec<String> = listed("anchors").iter().filter_map(|anchor| anchor.as_str().map(str::to_string)).collect();
        checks.unresolved = problems.into_iter().chain(lost).collect();
        if checks.unresolved.is_empty() {
            checks.unresolved.push(error.message);
        }
    }
    for entry in timeline::entries_for_recipe(journal, None) {
        let anchored = |path: &str| entry.derived_from.contains_key(path);
        for (path, _) in crate::journal::replay::literal_offsets_in(&entry.params, &anchored) {
            checks.literal_offsets.push((entry.step, path));
        }
    }
    checks
}

/// "⚠ 1 unresolved document · 2 literal offsets  Suggest anchors…", or a
/// line saying the steps would replay.
pub fn show_warnings(state: &mut HistoryState, app: &ViewerApp, ui: &mut Ui) {
    let revision = app.journal.revision();
    if state.recipe_checks.as_ref().is_none_or(|(at, _)| *at != revision) {
        state.recipe_checks = Some((revision, recipe_checks(&app.journal)));
    }
    let Some((_, checks)) = state.recipe_checks.clone() else { return };
    ui.horizontal_wrapped(|ui| {
        if checks.unresolved.is_empty() && checks.literal_offsets.is_empty() {
            ui.label(RichText::new("✓ The steps in effect would replay as a recipe").small().color(theme::TEXT_DIM));
            return;
        }
        let documents = plural(checks.unresolved.len(), "unresolved document");
        let offsets = plural(checks.literal_offsets.len(), "literal offset");
        let colour = if checks.unresolved.is_empty() { theme::TEXT_DIM } else { theme::DANGER };
        ui.label(RichText::new(format!("⚠ {documents} · {offsets}")).small().color(colour)).on_hover_text(warnings_text(&checks));
        if let Some((step, _)) = checks.literal_offsets.first()
            && ui.link(RichText::new("Suggest anchors…").small()).on_hover_text(format!("Show step {step}'s values and the anchors that could find them on another file")).clicked()
        {
            state.selected = Some(*step);
            state.open_recipe_values = Some(*step);
            state.go_to_step(*step);
        }
    });
}

/// The checks in full, one a line.
fn warnings_text(checks: &RecipeChecks) -> String {
    let documents = checks.unresolved.iter().map(|problem| format!("Unresolved: {problem}"));
    let offsets = checks.literal_offsets.iter().map(|(step, path)| format!("Step {step}'s {path} is a literal offset, which may not fit another file"));
    documents.chain(offsets).collect::<Vec<_>>().join("\n")
}

/// "1 literal offset", "2 literal offsets".
fn plural(count: usize, what: &str) -> String {
    if count == 1 { format!("1 {what}") } else { format!("{count} {what}s") }
}
