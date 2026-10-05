//! The dockable workspace: every panel is a pane that can be dragged to any
//! edge, stacked with others as tabs, floated as a window, collapsed, closed
//! and reopened. The arrangement is saved between sessions.

use std::path::{Path, PathBuf};

use eframe::egui::{self, RichText, Ui, WidgetText};
use egui_dock::{DockArea, DockState, NodeIndex, Style, TabViewer};
use serde::{Deserialize, Serialize};

use crate::app::ViewerApp;
use crate::config;
use crate::dock::{self, DockTab};
use crate::theme;

/// One dockable panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Pane {
    Raster,
    Inspector,
    Findings,
    HexDump,
    PeriodChart,
    Tool(DockTab),
}

impl Pane {
    /// Every pane, in the order the Panels menu lists them.
    pub fn all() -> Vec<Pane> {
        let mut panes = vec![Pane::Raster, Pane::Inspector, Pane::Findings, Pane::HexDump, Pane::PeriodChart];
        panes.extend(DockTab::ALL.iter().map(|&tab| Pane::Tool(tab)));
        panes
    }

    pub fn title(self) -> &'static str {
        match self {
            Pane::Raster => "View",
            Pane::Inspector => "Inspector",
            Pane::Findings => "Findings",
            Pane::HexDump => "Hex",
            Pane::PeriodChart => "Period chart",
            Pane::Tool(tab) => tab.label(),
        }
    }

    fn tools() -> Vec<Pane> {
        DockTab::ALL.iter().map(|&tab| Pane::Tool(tab)).collect()
    }
}

/// Built-in arrangements offered in the View menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    Default,
    EverythingRight,
    ToolsLeft,
    Focus,
}

impl Preset {
    pub const ALL: [Preset; 4] = [Preset::Default, Preset::EverythingRight, Preset::ToolsLeft, Preset::Focus];

    pub fn label(self) -> &'static str {
        match self {
            Preset::Default => "Default",
            Preset::EverythingRight => "Everything on the right",
            Preset::ToolsLeft => "Tools on the left",
            Preset::Focus => "Focus on the view",
        }
    }

    pub fn build(self) -> DockState<Pane> {
        match self {
            Preset::Default => default_layout(),
            Preset::EverythingRight => everything_right(),
            Preset::ToolsLeft => tools_left(),
            Preset::Focus => focus(),
        }
    }
}

/// The view on the left with tools beneath it; inspector, findings and hex
/// stacked down the right.
pub fn default_layout() -> DockState<Pane> {
    let mut state = DockState::new(vec![Pane::Raster]);
    let surface = state.main_surface_mut();
    let [left, right] = surface.split_right(NodeIndex::root(), 0.55, vec![Pane::Inspector]);
    let [_view, tools] = surface.split_below(left, 0.66, Pane::tools());
    let [_inspector, lower] = surface.split_below(right, 0.34, vec![Pane::Findings]);
    surface.split_below(lower, 0.3, vec![Pane::HexDump]);
    collapse_leaf_with(&mut state, Pane::Tool(DockTab::Report), tools);
    state
}

/// The view alone on the left; everything else stacked down the right.
pub fn everything_right() -> DockState<Pane> {
    let mut state = DockState::new(vec![Pane::Raster]);
    let surface = state.main_surface_mut();
    let [_view, right] = surface.split_right(NodeIndex::root(), 0.5, vec![Pane::Inspector, Pane::Findings]);
    let [_inspector, lower] = surface.split_below(right, 0.3, vec![Pane::HexDump]);
    let mut tools = Pane::tools();
    tools.push(Pane::PeriodChart);
    surface.split_below(lower, 0.4, tools);
    state
}

/// Tools down the left, the view in the middle, inspector and hex on the right.
pub fn tools_left() -> DockState<Pane> {
    let mut state = DockState::new(vec![Pane::Raster]);
    let surface = state.main_surface_mut();
    let [_tools, middle] = surface.split_left(NodeIndex::root(), 0.3, Pane::tools());
    let [_view, right] = surface.split_right(middle, 0.6, vec![Pane::Inspector, Pane::Findings]);
    surface.split_below(right, 0.4, vec![Pane::HexDump]);
    state
}

/// Just the view and the hex dump.
pub fn focus() -> DockState<Pane> {
    let mut state = DockState::new(vec![Pane::Raster]);
    state.main_surface_mut().split_right(NodeIndex::root(), 0.62, vec![Pane::HexDump, Pane::Inspector]);
    state
}

/// Start with the tools leaf open (not collapsed) but showing `active`.
fn collapse_leaf_with(state: &mut DockState<Pane>, active: Pane, _node: NodeIndex) {
    if let Some(path) = state.find_tab(&active) {
        let _ = state.set_active_tab(path);
    }
}

/// Where the arrangement is saved.
pub fn layout_path() -> Option<PathBuf> {
    config::config_file("layout.json")
}

/// Where the toolbar arrangement is saved.
pub fn toolbar_path() -> Option<PathBuf> {
    config::config_file("toolbar.json")
}


/// Saves the toolbar arrangement, or removes the file when there is none.
pub fn save_toolbar(path: &Path, rows: Option<&[Vec<String>]>) -> Result<(), String> {
    let Some(rows) = rows else {
        return match std::fs::remove_file(path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(format!("{}: {error}", path.display())),
            _ => Ok(()),
        };
    };
    config::write_json(path, &rows)
}

/// The saved toolbar arrangement, if there is a readable one.
pub fn load_toolbar(path: &Path) -> Option<Vec<Vec<String>>> {
    config::read_json(path)
}

pub fn save(path: &Path, state: &DockState<Pane>) -> Result<(), String> {
    let mut value = serde_json::to_value(state).map_err(|e| e.to_string())?;
    zero_missing_coordinates(&mut value);
    config::write_json(path, &value)
}

/// The saved arrangement, if there is a readable one that still contains the
/// view (a layout without it would leave nothing to look at).
pub fn load(path: &Path) -> Option<DockState<Pane>> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut value: serde_json::Value = serde_json::from_str(&text).ok()?;
    zero_missing_coordinates(&mut value);
    let state: DockState<Pane> = serde_json::from_value(value).ok()?;
    state.find_tab(&Pane::Raster).is_some().then_some(state)
}

/// Panes not yet drawn have no screen rectangle: their coordinates are not
/// numbers, which JSON stores as null and cannot read back. Rectangles are
/// recomputed every frame, so zero is a safe stand-in.
fn zero_missing_coordinates(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let is_point = map.len() == 2 && map.contains_key("x") && map.contains_key("y");
            for (key, child) in map.iter_mut() {
                if is_point && (key == "x" || key == "y") && child.is_null() {
                    *child = serde_json::json!(0.0);
                } else {
                    zero_missing_coordinates(child);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(zero_missing_coordinates),
        _ => {}
    }
}

/// Bring `pane` to the front, adding it if it was closed. Tools go next to
/// another open tool, other panes to the focused pane.
pub fn show_pane(state: &mut DockState<Pane>, pane: Pane) {
    if let Some(path) = state.find_tab(&pane) {
        let _ = state.set_active_tab(path);
        uncollapse_containing(state, pane);
        return;
    }
    let sibling = match pane {
        Pane::Tool(_) => state.find_tab_from(|tab| matches!(tab, Pane::Tool(_))),
        _ => None,
    };
    match sibling {
        Some(path) => {
            let _ = state.set_active_tab(path);
            state.set_focused_node_and_surface(path.node_path());
            state.push_to_focused_leaf(pane);
        }
        None => state.push_to_focused_leaf(pane),
    }
    uncollapse_containing(state, pane);
}

fn uncollapse_containing(state: &mut DockState<Pane>, pane: Pane) {
    for (_, leaf) in state.iter_leaves_mut() {
        if leaf.tabs.contains(&pane) {
            leaf.collapsed = false;
        }
    }
}

/// Collapse or expand every pane that holds tools. Returns whether they are
/// now expanded.
pub fn toggle_tools(state: &mut DockState<Pane>) -> bool {
    let tool_leaves: Vec<bool> = state
        .iter_leaves()
        .filter(|(_, leaf)| leaf.tabs.iter().any(|tab| matches!(tab, Pane::Tool(_))))
        .map(|(_, leaf)| leaf.collapsed)
        .collect();
    if tool_leaves.is_empty() {
        show_pane(state, Pane::Tool(DockTab::Report));
        return true;
    }
    let expand = tool_leaves.iter().all(|&collapsed| collapsed);
    for (_, leaf) in state.iter_leaves_mut() {
        if leaf.tabs.iter().any(|tab| matches!(tab, Pane::Tool(_))) {
            leaf.collapsed = !expand;
        }
    }
    expand
}

/// Draws each pane's contents.
struct Panes<'a> {
    app: &'a mut ViewerApp,
}

impl TabViewer for Panes<'_> {
    type Tab = Pane;

    fn id(&mut self, tab: &mut Pane) -> egui::Id {
        egui::Id::new(("pane", *tab))
    }

    fn title(&mut self, tab: &mut Pane) -> WidgetText {
        let unavailable = *tab == Pane::Tool(DockTab::Assistant) && !self.app.assistant_available();
        if unavailable {
            RichText::new(tab.title()).color(theme::TEXT_DIM).into()
        } else {
            tab.title().into()
        }
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Pane) {
        let app = &mut *self.app;
        match *tab {
            Pane::Raster => crate::view::show_raster(app, ui),
            Pane::Inspector => crate::hex::show_inspector_pane(app, ui),
            Pane::Findings => crate::findings::show_findings_panel(app, ui),
            Pane::HexDump => crate::hex::show_hex_dump_pane(app, ui),
            Pane::PeriodChart => crate::structure::show_structure_panel(app, ui),
            Pane::Tool(tool) => {
                app.dock.tab = tool;
                app.dock.shown = Some(tool);
                dock::show_tool(app, ui, tool);
            }
        }
    }

    fn closeable(&mut self, tab: &mut Pane) -> bool {
        // The view stays; everything else can be closed and reopened.
        *tab != Pane::Raster
    }

    fn scroll_bars(&self, tab: &Pane) -> [bool; 2] {
        // Panes that size themselves to the space they get manage their own
        // scrolling; the rest scroll vertically when they run long.
        match tab {
            Pane::Inspector
            | Pane::Tool(DockTab::Statistics | DockTab::Columns | DockTab::Checksums | DockTab::Live | DockTab::Unpacked | DockTab::Xor | DockTab::Report) => {
                [false, true]
            }
            _ => [false, false],
        }
    }

    fn clear_background(&self, tab: &Pane) -> bool {
        *tab != Pane::Raster
    }
}

impl ViewerApp {
    /// Draw the whole workspace into `ui`.
    pub fn show_workspace(&mut self, ui: &mut Ui) {
        self.apply_pane_requests();
        let mut state = std::mem::replace(&mut self.layout, DockState::new(Vec::new()));
        let mut style = Style::from_egui(ui.style().as_ref());
        style.tab_bar.bg_fill = theme::PANEL;
        style.tab_bar.height = 26.0;
        style.tab_bar.wrap_tabs = true;
        DockArea::new(&mut state)
            .style(style)
            .show_leaf_collapse_buttons(true)
            .show_leaf_close_all_buttons(false)
            .show_inside(ui, &mut Panes { app: self });
        self.layout = state;
    }

    /// Turn requests made elsewhere (menus, palette, links) into layout
    /// changes: `dock.tab` names a tool to bring forward, `dock.open` asks for
    /// the tools to be visible.
    fn apply_pane_requests(&mut self) {
        if let Some(pane) = self.pane_request.take() {
            show_pane(&mut self.layout, pane);
        }
        if self.dock.open && self.dock.shown != Some(self.dock.tab) {
            show_pane(&mut self.layout, Pane::Tool(self.dock.tab));
            self.dock.shown = Some(self.dock.tab);
        }
    }

    /// Show a pane, adding it back if it was closed.
    pub fn show_panel(&mut self, pane: Pane) {
        if let Pane::Tool(tab) = pane {
            self.dock.open = true;
            self.dock.tab = tab;
            self.dock.shown = None;
        } else {
            self.pane_request = Some(pane);
        }
    }

    /// Close a pane; it can be reopened from View › Panels.
    pub fn close_panel(&mut self, pane: Pane) {
        if pane != Pane::Raster
            && let Some(path) = self.layout.find_tab(&pane)
        {
            self.layout.remove_tab(path);
        }
    }

    pub fn toggle_panel(&mut self, pane: Pane) {
        if self.panel_is_open(pane) {
            self.close_panel(pane);
        } else {
            self.show_panel(pane);
        }
    }

    pub fn panel_is_open(&self, pane: Pane) -> bool {
        self.layout.find_tab(&pane).is_some()
    }

    pub fn apply_preset(&mut self, preset: Preset) {
        self.layout = preset.build();
        self.dock.shown = None;
    }

    /// Use a new toolbar arrangement (`None` packs automatically) and keep it
    /// for next time.
    pub fn set_toolbar_rows(&mut self, rows: Option<Vec<Vec<String>>>) {
        self.toolbar_rows = rows;
        if self.persist_layout
            && let Some(path) = toolbar_path()
        {
            let _ = save_toolbar(&path, self.toolbar_rows.as_deref());
        }
    }

    /// Save the arrangement if this run restores layouts (the app, not tests).
    pub fn save_layout(&self) {
        if self.persist_layout
            && let Some(path) = layout_path()
        {
            let _ = save(&path, &self.layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panes_in(state: &DockState<Pane>) -> Vec<Pane> {
        state.iter_all_tabs().map(|(_, pane)| *pane).collect()
    }

    #[test]
    fn every_preset_holds_the_view_and_the_core_panes() {
        for preset in Preset::ALL {
            let state = preset.build();
            let panes = panes_in(&state);
            assert!(panes.contains(&Pane::Raster), "{preset:?}");
            assert!(panes.contains(&Pane::HexDump), "{preset:?}");
            let mut unique = panes.clone();
            unique.sort_by_key(|p| format!("{p:?}"));
            unique.dedup();
            assert_eq!(unique.len(), panes.len(), "{preset:?} has a pane twice");
        }
        assert!(panes_in(&everything_right()).contains(&Pane::Tool(DockTab::Protocol)));
    }

    #[test]
    fn closed_panes_come_back_beside_their_kind() {
        let mut state = default_layout();
        let path = state.find_tab(&Pane::Tool(DockTab::Xor)).unwrap();
        state.remove_tab(path);
        assert!(state.find_tab(&Pane::Tool(DockTab::Xor)).is_none());
        show_pane(&mut state, Pane::Tool(DockTab::Xor));
        let back = state.find_tab(&Pane::Tool(DockTab::Xor)).expect("reopened");
        let report = state.find_tab(&Pane::Tool(DockTab::Report)).unwrap();
        assert_eq!(back.node_path(), report.node_path(), "stacked with the other tools");
    }

    #[test]
    fn tools_collapse_and_expand_together() {
        let mut state = default_layout();
        assert!(!toggle_tools(&mut state), "first toggle collapses");
        assert!(state.iter_leaves().filter(|(_, l)| l.tabs.contains(&Pane::Tool(DockTab::Report))).all(|(_, l)| l.collapsed));
        assert!(toggle_tools(&mut state), "second toggle expands");
        show_pane(&mut state, Pane::Tool(DockTab::Diff));
        assert!(state.iter_leaves().all(|(_, l)| !l.collapsed));
    }

    #[test]
    fn layouts_round_trip_through_a_file() {
        let path = std::env::temp_dir().join(format!("theviewer-layout-{}.json", std::process::id()));
        let state = everything_right();
        save(&path, &state).unwrap();
        let loaded = load(&path).expect("loads");
        assert_eq!(panes_in(&loaded), panes_in(&state));
        std::fs::write(&path, "{ not json").unwrap();
        assert!(load(&path).is_none(), "a damaged file falls back to the default");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn the_toolbar_arrangement_survives_a_restart_and_can_be_forgotten() {
        let path = std::env::temp_dir().join(format!("theviewer-toolbar-{}.json", std::process::id()));
        let rows = vec![vec!["zoom".to_string(), "format".to_string()], vec!["find".to_string()]];
        save_toolbar(&path, Some(&rows)).unwrap();
        assert_eq!(load_toolbar(&path), Some(rows));
        save_toolbar(&path, None).unwrap();
        assert_eq!(load_toolbar(&path), None);
        save_toolbar(&path, None).expect("forgetting twice is fine");
    }
}
