//! Worksheets in the window: every document open in it, one of them shown.
//!
//! A **sheet** is an open document with its lineage: a root, opened from a
//! file, a source or new, or a sheet derived from another (a decompressed
//! stream, a node unpacked, a selection opened on its own). The window shows
//! one sheet, the active one, whose state lives in [`ViewerApp`]'s own
//! fields (`document`, `cursor`, `shape` and the rest), so the code that
//! draws and edits keeps working on `app.document`. Every other open sheet
//! is **parked**: put away with its place and what was worked out about it,
//! to be shown again as it was left.
//!
//! - [`ViewerApp::activate_sheet`] parks the active sheet and shows another;
//!   it closes nothing. Back is activating the parent.
//! - Deriving or opening a sheet parks the active one beside it, so deriving
//!   twice from one sheet gives two siblings.
//! - [`ViewerApp::close_sheet_tree`] closes a sheet with every sheet derived
//!   from it.
//!
//! What the tools worked out about a sheet is kept with it: the report, the
//! pinned findings and the like are put away with the sheet
//! ([`crate::workbench::Workbench::sheet_switched`]), and the results of
//! jobs such as Strings, XOR, Crypto and Unpacked are kept per sheet in a
//! [`PerSheet`], so a tool may go on showing another sheet's results, saying
//! whose they are ([`view::results_of_other_sheet`]).
//!
//! The worksheet strip and the tree of sheets are drawn in [`view`].

pub mod view;

use std::collections::HashMap;
use std::sync::Arc;

use crate::analysis::PeriodScan;
use crate::api::workspace::{DOCUMENT_PRODUCER, Lineage};
use crate::app::{PatternKey, Shape, ViewerApp};
use crate::bookmarks::Sidecar;
use crate::document::Document;
use crate::folds::Folds;
use crate::plugin::Finding;
use crate::selection::{ColumnSelection, Selection};

/// A sheet open in the window but not shown, kept with its place and what
/// was worked out about it so it is shown again as it was left.
pub struct ParkedSheet {
    /// The id the API and the bus know it by.
    pub id: String,
    pub document: Document,
    /// The version `document.edited` has been published up to, so edits
    /// made to it through the API while it is parked are published.
    pub(crate) published_version: u64,
    /// Where it came from: its parent and the step that made it.
    pub lineage: Lineage,
    /// The name given to a sheet without a file (a derived one, a source).
    pub derived_name: Option<String>,
    pub shape: Shape,
    pub cursor: usize,
    anchor: Option<usize>,
    extra_ranges: Vec<(usize, usize)>,
    column_selection: Option<ColumnSelection>,
    pub top_row: usize,
    hex_top_row: usize,
    pub folds: Folds,
    /// Its bookmarks and remembered shape: a root's are saved beside its file.
    pub bookmarks: Sidecar,
    /// Analysis results, kept so showing it again does not have to rescan.
    pub(crate) patterns: Vec<Finding>,
    pub(crate) pattern_key: Option<PatternKey>,
    pub(crate) period_scan: Option<PeriodScan>,
    pub(crate) entropy_map: Option<Vec<f32>>,
    mapped_regions: Arc<Vec<crate::explain::Region>>,
}

impl ParkedSheet {
    /// What the sheet is called, as the strip and the title show it.
    pub fn name(&self) -> String {
        sheet_name(self.derived_name.as_deref(), &self.document)
    }

    /// The selection it was left with, as the API describes one.
    pub fn selection(&self) -> Option<Selection> {
        if let Some(column) = self.column_selection {
            return Some(Selection::Columns(column));
        }
        let anchor = self.anchor?;
        let (start, end) = (anchor.min(self.cursor), anchor.max(self.cursor).min(self.document.len()));
        let mut ranges = self.extra_ranges.clone();
        if end > start {
            ranges.push((start, end - start));
        }
        match ranges.len() {
            0 => None,
            1 => Some(Selection::Range(ranges[0].0, ranges[0].1)),
            _ => {
                ranges.sort_unstable();
                Some(Selection::Ranges(ranges))
            }
        }
    }

    /// Move its cursor and set its selection, to be shown when it is: a
    /// range, the span of several ranges, or none.
    pub(crate) fn select(&mut self, cursor: usize, selection: Option<Selection>) {
        let len = self.document.len();
        self.cursor = cursor.min(len);
        self.extra_ranges.clear();
        self.column_selection = None;
        self.anchor = None;
        match selection {
            Some(Selection::Columns(column)) => self.column_selection = Some(column),
            Some(Selection::Range(start, span)) if span > 0 => {
                let (start, end) = (start.min(len), (start + span).min(len));
                (self.anchor, self.cursor) = if self.cursor == start { (Some(end), start) } else { (Some(start), end) };
            }
            Some(Selection::Ranges(mut ranges)) if !ranges.is_empty() => {
                let (start, span) = ranges.pop().expect("not empty");
                self.extra_ranges = ranges;
                (self.anchor, self.cursor) = (Some(start.min(len)), (start + span).min(len));
            }
            _ => {}
        }
    }
}

/// What a sheet is called: the name it was given, else its file's name,
/// else "untitled".
pub fn sheet_name(derived_name: Option<&str>, document: &Document) -> String {
    match derived_name {
        Some(name) => name.to_string(),
        None => document.path().and_then(|path| path.file_name()).map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| "untitled".to_string()),
    }
}

/// One open sheet as the strip and the tree list it.
#[derive(Clone, Debug, PartialEq)]
pub struct SheetSummary {
    pub id: String,
    pub name: String,
    /// The label its maker or the person gave it, such as "payload".
    pub label: Option<String>,
    pub parent: Option<String>,
    /// The file it was opened from, for a root opened from one.
    pub path: Option<std::path::PathBuf>,
    pub len: usize,
    pub modified: bool,
    pub active: bool,
    /// The method that made it and its step, for a sheet a step made.
    pub made_by: Option<(String, Option<u64>)>,
}

impl SheetSummary {
    /// The label when it has one, else its name: what the strip shows.
    pub fn title(&self) -> &str {
        self.label.as_deref().unwrap_or(&self.name)
    }
}

/// The number in a sheet id ("doc-12" is 12), for listing sheets in the
/// order they were opened.
pub fn opening_order(id: &str) -> u64 {
    id.rsplit('-').next().and_then(|number| number.parse().ok()).unwrap_or(u64::MAX)
}

/// A tool's results, kept for each sheet they describe: those shown, and
/// those of other sheets, which are shown again when their sheet is
/// activated. Results of a sheet not active may still be shown (the tool
/// says whose they are) until the active sheet has its own.
pub struct PerSheet<T> {
    shown: Option<(String, T)>,
    others: HashMap<String, T>,
}

impl<T> Default for PerSheet<T> {
    fn default() -> Self {
        PerSheet { shown: None, others: HashMap::new() }
    }
}

impl<T> PerSheet<T> {
    /// The results shown.
    pub fn get(&self) -> Option<&T> {
        self.shown.as_ref().map(|(_, value)| value)
    }

    pub fn get_mut(&mut self) -> Option<&mut T> {
        self.shown.as_mut().map(|(_, value)| value)
    }

    /// The sheet the results shown describe.
    pub fn sheet(&self) -> Option<&str> {
        self.shown.as_ref().map(|(sheet, _)| sheet.as_str())
    }

    /// The results shown with their sheet.
    pub fn shown(&self) -> Option<(&str, &T)> {
        self.shown.as_ref().map(|(sheet, value)| (sheet.as_str(), value))
    }

    /// The results of `sheet`, shown or kept.
    pub fn of(&self, sheet: &str) -> Option<&T> {
        match &self.shown {
            Some((shown, value)) if shown == sheet => Some(value),
            _ => self.others.get(sheet),
        }
    }

    /// Show `value`, results of `sheet`, keeping those shown before for
    /// their own sheet.
    pub fn set(&mut self, sheet: &str, value: T) {
        self.others.remove(sheet);
        if let Some((before, kept)) = self.shown.take()
            && before != sheet
        {
            self.others.insert(before, kept);
        }
        self.shown = Some((sheet.to_string(), value));
    }

    /// `value`, results of `sheet`, arrived while `active` is shown: shown
    /// unless the active sheet's own results are, then kept for `sheet`.
    pub fn deliver(&mut self, sheet: &str, value: T, active: &str) {
        if sheet != active && self.sheet() == Some(active) {
            self.others.insert(sheet.to_string(), value);
        } else {
            self.set(sheet, value);
        }
    }

    /// Forget the results shown.
    pub fn clear(&mut self) {
        self.shown = None;
    }

    /// Sheet `to` is now active: show its results when it has any kept,
    /// else go on showing what was shown.
    pub fn switched(&mut self, to: &str) {
        if let Some(value) = self.others.remove(to) {
            self.set(to, value);
        }
    }

    /// Sheet `id` closed: its results go.
    pub fn closed(&mut self, id: &str) {
        self.others.remove(id);
        if self.sheet() == Some(id) {
            self.shown = None;
        }
    }

    /// Forget every sheet's results.
    pub fn clear_all(&mut self) {
        self.shown = None;
        self.others.clear();
    }
}

impl ViewerApp {
    /// Every open sheet, the active one included, in the order they were
    /// opened.
    pub fn sheets(&self) -> Vec<SheetSummary> {
        let made_by = |lineage: &Lineage| lineage.made_by.as_ref().map(|made_by| (made_by.method.clone(), made_by.step));
        let mut sheets: Vec<SheetSummary> = self
            .parked
            .iter()
            .map(|sheet| SheetSummary {
                id: sheet.id.clone(),
                name: sheet.name(),
                label: sheet.lineage.label(),
                parent: sheet.lineage.parent.clone(),
                path: sheet.document.path().map(std::path::Path::to_path_buf),
                len: sheet.document.len(),
                modified: sheet.document.is_modified(),
                active: false,
                made_by: made_by(&sheet.lineage),
            })
            .collect();
        sheets.push(SheetSummary {
            id: self.document_id.clone(),
            name: self.display_name(),
            label: self.active_lineage.label(),
            parent: self.active_lineage.parent.clone(),
            path: self.document.path().map(std::path::Path::to_path_buf),
            len: self.document.len(),
            modified: self.document.is_modified(),
            active: true,
            made_by: made_by(&self.active_lineage),
        });
        sheets.sort_by_key(|sheet| opening_order(&sheet.id));
        sheets
    }

    /// Whether `id` is an open sheet.
    pub fn is_open_sheet(&self, id: &str) -> bool {
        id == self.document_id || self.parked_sheet(id).is_some()
    }

    pub(crate) fn parked_sheet(&self, id: &str) -> Option<&ParkedSheet> {
        self.parked.iter().find(|sheet| sheet.id == id)
    }

    pub(crate) fn parked_sheet_mut(&mut self, id: &str) -> Option<&mut ParkedSheet> {
        self.parked.iter_mut().find(|sheet| sheet.id == id)
    }

    /// The lineage of the open sheet `id`.
    pub fn sheet_lineage(&self, id: &str) -> Option<&Lineage> {
        if id == self.document_id {
            return Some(&self.active_lineage);
        }
        self.parked_sheet(id).map(|sheet| &sheet.lineage)
    }

    /// The parent of the active sheet, when it is derived and its parent is
    /// still open: where Back goes.
    pub fn active_parent(&self) -> Option<String> {
        self.active_lineage.parent.clone().filter(|parent| self.is_open_sheet(parent))
    }

    /// What the open sheet `id` is called: its label, else its name.
    pub fn sheet_title(&self, id: &str) -> Option<String> {
        if id == self.document_id {
            return Some(self.active_lineage.label().unwrap_or_else(|| self.display_name()));
        }
        let sheet = self.parked_sheet(id)?;
        Some(sheet.lineage.label().unwrap_or_else(|| sheet.name()))
    }

    /// Sheet `id` and every sheet derived from it, at any depth, `id` first.
    pub fn sheet_and_descendants(&self, id: &str) -> Vec<String> {
        let sheets = self.sheets();
        let mut found = vec![id.to_string()];
        let mut next = 0;
        while next < found.len() {
            let parent = found[next].clone();
            found.extend(sheets.iter().filter(|sheet| sheet.parent.as_deref() == Some(parent.as_str())).map(|sheet| sheet.id.clone()));
            next += 1;
        }
        found
    }

    /// The ancestry of the active sheet, its root first and itself last.
    pub fn active_ancestry(&self) -> Vec<String> {
        let mut ancestry = vec![self.document_id.clone()];
        while let Some(parent) = ancestry.last().and_then(|id| self.sheet_lineage(id)).and_then(|lineage| lineage.parent.clone()) {
            if ancestry.contains(&parent) || !self.is_open_sheet(&parent) {
                break;
            }
            ancestry.push(parent);
        }
        ancestry.reverse();
        ancestry
    }

    /// Show the open sheet `id`, parking the one shown with its place and
    /// what was worked out about it; nothing is closed. Returns whether `id`
    /// is open.
    pub fn activate_sheet(&mut self, id: &str) -> bool {
        if id == self.document_id {
            return true;
        }
        let Some(index) = self.parked.iter().position(|sheet| sheet.id == id) else {
            return false;
        };
        let incoming = self.parked.swap_remove(index);
        let from = self.document_id.clone();
        let outgoing = self.take_active_sheet();
        self.parked.push(outgoing);
        self.bench.sheet_switched(&from, id);
        self.show_parked_sheet(incoming);
        true
    }

    /// Park the active sheet before another is installed in its place:
    /// `next` is the id the new one will have.
    pub(crate) fn park_active_for(&mut self, next: &str) {
        let from = self.document_id.clone();
        let outgoing = self.take_active_sheet();
        self.parked.push(outgoing);
        self.bench.sheet_switched(&from, next);
    }

    /// Whether the active sheet is the blank one a window starts with (or
    /// File › New made), with nothing in it and nothing derived from it, so
    /// a file opened takes its place rather than sitting beside it.
    pub(crate) fn active_is_blank(&self) -> bool {
        self.active_lineage.parent.is_none()
            && self.derived_name.is_none()
            && self.document.is_empty()
            && !self.document.is_modified()
            && self.document.path().is_none()
            && !self.parked.iter().any(|sheet| sheet.lineage.parent.as_deref() == Some(self.document_id.as_str()))
    }

    /// Take the active sheet's state out of the window's fields, publishing
    /// the edits made to it first.
    fn take_active_sheet(&mut self) -> ParkedSheet {
        self.publish_edits_as(DOCUMENT_PRODUCER);
        let derived_name = self.derived_name.take();
        ParkedSheet {
            id: self.document_id.clone(),
            published_version: self.document.version(),
            document: std::mem::take(&mut self.document),
            lineage: std::mem::take(&mut self.active_lineage),
            derived_name,
            shape: self.shape,
            cursor: self.cursor,
            anchor: self.anchor.take(),
            extra_ranges: std::mem::take(&mut self.extra_ranges),
            column_selection: self.column_selection.take(),
            top_row: self.top_row,
            hex_top_row: self.hex_top_row,
            folds: std::mem::take(&mut self.folds),
            bookmarks: std::mem::take(&mut self.bookmarks),
            patterns: std::mem::take(&mut self.patterns),
            pattern_key: self.pattern_key.take(),
            period_scan: self.period_scan.take(),
            entropy_map: self.entropy_map.take(),
            mapped_regions: std::mem::take(&mut self.mapped_regions),
        }
    }

    /// Show `sheet` as it was left: its place, its shape and its analysis.
    fn show_parked_sheet(&mut self, sheet: ParkedSheet) {
        let name = sheet.name();
        self.document_id = sheet.id;
        self.document = sheet.document;
        self.active_lineage = sheet.lineage;
        self.derived_name = sheet.derived_name;
        self.shape = sheet.shape;
        let len = self.document.len();
        self.cursor = sheet.cursor.min(len);
        self.anchor = sheet.anchor.map(|anchor| anchor.min(len));
        self.extra_ranges = sheet.extra_ranges;
        self.column_selection = sheet.column_selection;
        self.top_row = sheet.top_row;
        self.hex_top_row = sheet.hex_top_row;
        self.folds = sheet.folds;
        self.bookmarks = sheet.bookmarks;
        self.patterns = sheet.patterns;
        self.pattern_key = sheet.pattern_key;
        self.period_scan = sheet.period_scan;
        self.entropy_map = sheet.entropy_map;
        self.mapped_regions = sheet.mapped_regions;
        self.forget_view_caches();
        // Edits made to it through the API while it was parked are said now.
        self.bus_watch_sheet_switched(sheet.published_version);
        // Facts the views follow are said again about the sheet shown.
        self.republish_sheet_analysis();
        self.clamp_top_row();
        self.status = format!("Showing {name}");
    }

    /// Close sheet `id` and every sheet derived from it, losing their
    /// unsaved edits; when the active sheet is among them, the window shows
    /// the closed sheet's parent, else the sheet opened last, else a blank
    /// document. Returns the sheets closed, as (id, name).
    pub fn close_sheet_tree(&mut self, id: &str) -> Vec<(String, String)> {
        if !self.is_open_sheet(id) {
            return Vec::new();
        }
        let closing = self.sheet_and_descendants(id);
        let mut blank_replaced = None;
        if closing.contains(&self.document_id) {
            let parent = self.sheet_lineage(id).and_then(|lineage| lineage.parent.clone()).filter(|parent| self.is_open_sheet(parent) && !closing.contains(parent));
            let other = || self.sheets().into_iter().rev().map(|sheet| sheet.id).find(|other| !closing.contains(other));
            match parent.or_else(other) {
                Some(next) => {
                    self.activate_sheet(&next);
                }
                None => blank_replaced = Some(self.replace_active_with_blank()),
            }
        }
        if self.bench.live_sheet.as_ref().is_some_and(|live| closing.contains(live)) {
            self.stop_live_sources();
        }
        let mut closed = Vec::new();
        for closing_id in &closing {
            if let Some(index) = self.parked.iter().position(|sheet| &sheet.id == closing_id) {
                let sheet = self.parked.swap_remove(index);
                self.save_sheet_sidecar(&sheet.document, &sheet.shape, &sheet.bookmarks);
                closed.push((sheet.id.clone(), sheet.name()));
            }
            self.bench.sheet_closed(closing_id);
        }
        self.publish_sheets_closed(closed.clone());
        closed.extend(blank_replaced);
        closed
    }

    /// Close every sheet but the active one and those it came from, as
    /// File › Close other worksheets does. Returns the sheets closed.
    pub fn close_other_sheets(&mut self) -> Vec<(String, String)> {
        let kept = self.active_ancestry();
        let mut closed = Vec::new();
        for sheet in self.sheets() {
            if !kept.contains(&sheet.id) && self.is_open_sheet(&sheet.id) {
                closed.extend(self.close_sheet_tree(&sheet.id));
            }
        }
        closed
    }

    /// The sheets among `ids` with unsaved edits, by title.
    pub fn unsaved_sheets(&self, ids: &[String]) -> Vec<String> {
        self.sheets().into_iter().filter(|sheet| sheet.modified && ids.contains(&sheet.id)).map(|sheet| sheet.title().to_string()).collect()
    }

    /// Put an empty, untitled root in place of the active sheet, which is
    /// dropped without being parked: what is left when every sheet closes.
    /// Returns the sheet dropped, as (id, name).
    fn replace_active_with_blank(&mut self) -> (String, String) {
        let dropped = (self.document_id.clone(), self.display_name());
        let next = self.next_sheet_id();
        self.bench.sheet_closed(&self.document_id.clone());
        self.bench.sheet_switched(&self.document_id.clone(), &next);
        let (document, shape, bookmarks) = (std::mem::take(&mut self.document), self.shape, std::mem::take(&mut self.bookmarks));
        self.save_sheet_sidecar(&document, &shape, &bookmarks);
        self.document_id = next;
        self.active_lineage = Lineage::default();
        self.derived_name = None;
        self.reset_sheet_fields();
        self.publish_document_replaced(vec![dropped.clone()]);
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_of_another_sheet_stay_shown_until_the_active_sheet_has_its_own_and_come_back_with_their_sheet() {
        let mut strings: PerSheet<&str> = PerSheet::default();
        strings.set("doc-1", "parent's");
        strings.switched("doc-2");
        assert_eq!(strings.shown(), Some(("doc-1", &"parent's")), "the child has none, so the parent's are shown, saying whose");
        strings.set("doc-2", "child's");
        strings.switched("doc-1");
        assert_eq!(strings.shown(), Some(("doc-1", &"parent's")), "switching back shows the parent's again");
        strings.switched("doc-2");
        assert_eq!(strings.get(), Some(&"child's"));
        strings.closed("doc-2");
        assert_eq!(strings.get(), None);
        strings.switched("doc-1");
        assert_eq!(strings.get(), Some(&"parent's"));
    }

    #[test]
    fn results_arriving_for_a_sheet_not_shown_wait_for_it_when_the_active_sheet_has_its_own() {
        let mut keys: PerSheet<u32> = PerSheet::default();
        keys.set("doc-2", 2);
        keys.deliver("doc-1", 1, "doc-2");
        assert_eq!(keys.shown(), Some(("doc-2", &2)));
        keys.switched("doc-1");
        assert_eq!(keys.get(), Some(&1));
        keys.deliver("doc-3", 3, "doc-2");
        assert_eq!(keys.shown(), Some(("doc-3", &3)), "nothing of the active sheet's was shown, so the new results are");
    }

    #[test]
    fn sheets_are_listed_in_the_order_they_were_opened() {
        assert!(opening_order("doc-2") < opening_order("doc-10"));
    }

    mod window {
        use egui_kittest::kittest::Queryable;

        use crate::analysis_stats::{find_strings, show_strings};
        use crate::app::{Launch, ViewerApp};
        use crate::plugin::{Category, Finding};
        use crate::strings::Encoding;

        fn app_with(bytes: &[u8]) -> ViewerApp {
            let mut app = ViewerApp::new(Launch::default());
            app.open_bytes(bytes.to_vec(), "outer.bin".to_string());
            app.run_bus();
            crate::actions::take_performed();
            app
        }

        /// The strings the Strings tab shows, as `strings.find` delivers them.
        fn find_strings_in(app: &mut ViewerApp) {
            let bytes = app.document.read_range(0, app.document.len());
            let sheet = app.document_id();
            app.bench.tools.stats.strings.set(&sheet, find_strings(&bytes, 0, 4, &[Encoding::Ascii]));
        }

        fn strings_shown(app: &ViewerApp) -> Vec<String> {
            app.bench.tools.stats.strings.get().map(|found| found.strings.iter().map(|string| string.text.clone()).collect()).unwrap_or_default()
        }

        #[test]
        fn a_sheet_s_tool_results_survive_switching_and_another_sheet_s_say_whose_they_are() {
            let mut app = app_with(b"outer words\0\0\0\0more outer text");
            let outer = app.document_id();
            find_strings_in(&mut app);
            app.bench.pinned.push(Finding::new("changed", "live", Category::Custom, 0, 4).title("Changed"));
            app.open_derived(b"child payload".to_vec(), "payload".to_string());
            let child = app.document_id();
            assert_eq!(app.bench.tools.stats.strings.sheet(), Some(outer.as_str()), "the parent's strings are still shown, as the parent's");
            assert!(app.bench.pinned.is_empty(), "the parent's pinned findings went with it");
            find_strings_in(&mut app);
            assert_eq!(strings_shown(&app), ["child payload"]);
            app.back_to_parent();
            assert_eq!(strings_shown(&app), ["outer words", "more outer text"], "switching back shows the parent's again");
            assert_eq!(app.bench.pinned.len(), 1, "and its pinned findings");
            app.activate_sheet(&child);
            assert_eq!(strings_shown(&app), ["child payload"]);
            app.close_sheet_tree(&child);
            assert!(app.bench.tools.stats.strings.of(&child).is_none(), "a closed sheet's results go");
        }

        #[test]
        fn the_strings_tab_says_whose_strings_it_shows_and_shows_that_sheet() {
            let mut app = app_with(b"outer words\0\0\0\0more outer text");
            let outer = app.document_id();
            find_strings_in(&mut app);
            app.open_derived(b"\x01\x02".to_vec(), "payload".to_string());
            let mut harness = egui_kittest::Harness::new_ui_state(
                |ui, app: &mut ViewerApp| {
                    app.perform_waiting_actions();
                    show_strings(app, ui);
                },
                app,
            );
            harness.step();
            harness.get_by_label(&format!("From outer.bin ({outer})"));
            harness.get_by_label("Show it").click();
            harness.step();
            harness.step();
            assert_eq!(harness.state().document_id(), outer, "Show it shows the sheet the strings were found in");
            assert!(harness.query_by_label("Show it").is_none(), "they are the sheet shown's now");
        }
    }
}
