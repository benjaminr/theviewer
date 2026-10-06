//! Named arrangements of the workspace: recommended ones for each kind of
//! analysis, and the person's own, saved under names they choose.
//!
//! A recommended layout opens only the tools that kind of work needs, so
//! the tab bars stay short; any other tool reopens from Panels or Tools.
//! Saved layouts are JSON files in `~/.config/theviewer/layouts/`, in the
//! same format as the arrangement kept between sessions.

use std::path::{Path, PathBuf};

use eframe::egui::{self, Key, RichText, Ui};
use egui_dock::{DockState, NodeIndex};

use crate::app::ViewerApp;
use crate::config;
use crate::dock::DockTab;
use crate::layout::{self, Pane};
use crate::theme;

/// Bytes from the start of a file that are parsed to suggest a layout.
const SUGGESTION_READ_LIMIT: usize = 64 * 1024;
/// The name the menu ticks after restoring the last session.
const LAST_SESSION: &str = "Last session";

/// A built-in arrangement for one kind of analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recommended {
    Overview,
    Network,
    Structure,
    Firmware,
    Signals,
    Forensics,
    Compare,
    Focus,
}

impl Recommended {
    pub const ALL: [Recommended; 8] = [
        Recommended::Overview,
        Recommended::Network,
        Recommended::Structure,
        Recommended::Firmware,
        Recommended::Signals,
        Recommended::Forensics,
        Recommended::Compare,
        Recommended::Focus,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Recommended::Overview => "Overview",
            Recommended::Network => "Network capture",
            Recommended::Structure => "File structure",
            Recommended::Firmware => "Firmware and code",
            Recommended::Signals => "Signals and bit streams",
            Recommended::Forensics => "Forensics and carving",
            Recommended::Compare => "Compare files",
            Recommended::Focus => "Focus on the view",
        }
    }

    /// What the layout is for, for menus and tooltips.
    pub fn purpose(self) -> &'static str {
        match self {
            Recommended::Overview => "Any file: the report, findings, structure and size maps, strings and statistics",
            Recommended::Network => "Packet captures and message streams: packets first, with the protocol notes, framing and hex beside them",
            Recommended::Structure => "A file format: parsed fields, the notes on the format, templates, columns and the structure map",
            Recommended::Firmware => "Firmware and executables: processor and load address, disassembly, strings, crypto and nested images",
            Recommended::Signals => "Raw bit streams and records: bit tools, the period chart, columns, trigrams and the dot plot",
            Recommended::Forensics => "Disk images and carving: embedded filesystems, pictures, nested archives and the size map",
            Recommended::Compare => "Several files or versions: what varies between them, and a byte diff",
            Recommended::Focus => "Just the view and the hex dump",
        }
    }

    /// The name accepted by `--layout`.
    pub fn cli_name(self) -> &'static str {
        match self {
            Recommended::Overview => "overview",
            Recommended::Network => "network",
            Recommended::Structure => "structure",
            Recommended::Firmware => "firmware",
            Recommended::Signals => "signals",
            Recommended::Forensics => "forensics",
            Recommended::Compare => "compare",
            Recommended::Focus => "focus",
        }
    }

    /// The layout called `name` on the command line. "default" is the
    /// overview, as before layouts were named by purpose.
    pub fn from_cli_name(name: &str) -> Option<Recommended> {
        let name = name.trim().to_ascii_lowercase();
        if name == "default" {
            return Some(Recommended::Overview);
        }
        Recommended::ALL.into_iter().find(|layout| layout.cli_name() == name)
    }

    pub fn build(self) -> DockState<Pane> {
        match self {
            Recommended::Overview => overview(),
            Recommended::Network => network(),
            Recommended::Structure => structure(),
            Recommended::Firmware => firmware(),
            Recommended::Signals => signals(),
            Recommended::Forensics => forensics(),
            Recommended::Compare => compare(),
            Recommended::Focus => focus(),
        }
    }

    /// The layout that suits a file whose start a parser recognised as
    /// `finding_id`, if any is better than the overview.
    pub fn suited_to(finding_id: &str) -> Option<Recommended> {
        match finding_id {
            "pcap" | "pcapng" => Some(Recommended::Network),
            "elf" | "pe" | "macho" | "macho-fat" => Some(Recommended::Firmware),
            "mbr" | "gpt" | "fat" | "ntfs" | "ext" => Some(Recommended::Forensics),
            "png" | "jpeg" | "gif" | "bmp" | "zip" | "tar" | "ar" | "cpio" | "der" | "x509" | "protobuf" | "msgpack" | "cbor" => Some(Recommended::Structure),
            _ => None,
        }
    }
}

fn tools(tabs: &[DockTab]) -> Vec<Pane> {
    tabs.iter().map(|&tab| Pane::Tool(tab)).collect()
}

/// The bits with the packets beside them, showing `front`.
fn view_showing(front: Pane) -> DockState<Pane> {
    let mut state = DockState::new(layout::view_tabs());
    if let Some(path) = state.find_tab(&front) {
        let _ = state.set_active_tab(path);
    }
    state
}

/// The common shape: the view top left with `bottom` tools beneath it, and
/// on the right `right_top` above `right_bottom`. The first tab of each
/// group is the one shown.
fn view_tools_and_column(front: Pane, bottom: Vec<Pane>, right_top: Vec<Pane>, right_bottom: Vec<Pane>) -> DockState<Pane> {
    let mut state = view_showing(front);
    let surface = state.main_surface_mut();
    let [left, right] = surface.split_right(NodeIndex::root(), 0.58, right_top);
    surface.split_below(left, 0.64, bottom);
    surface.split_below(right, 0.45, right_bottom);
    state
}

fn overview() -> DockState<Pane> {
    let mut state = view_showing(Pane::Raster);
    let surface = state.main_surface_mut();
    let [left, right] = surface.split_right(NodeIndex::root(), 0.55, vec![Pane::Inspector]);
    let bottom = tools(&[
        DockTab::Report,
        DockTab::Reference,
        DockTab::StructureMap,
        DockTab::SizeMap,
        DockTab::Strings,
        DockTab::Statistics,
        DockTab::Characterise,
        DockTab::Assistant,
    ]);
    surface.split_below(left, 0.66, bottom);
    let [_inspector, lower] = surface.split_below(right, 0.34, vec![Pane::Findings]);
    surface.split_below(lower, 0.3, vec![Pane::HexDump]);
    state
}

fn network() -> DockState<Pane> {
    view_tools_and_column(
        Pane::Tool(DockTab::Packets),
        tools(&[DockTab::Protocol, DockTab::Strings, DockTab::Statistics, DockTab::Live, DockTab::Assistant]),
        vec![Pane::Tool(DockTab::Reference), Pane::Inspector, Pane::Findings],
        vec![Pane::HexDump],
    )
}

fn structure() -> DockState<Pane> {
    view_tools_and_column(
        Pane::Raster,
        tools(&[DockTab::Template, DockTab::StructureMap, DockTab::Columns, DockTab::Unpacked, DockTab::Learn, DockTab::Report]),
        vec![Pane::Inspector, Pane::Tool(DockTab::Reference), Pane::Findings],
        vec![Pane::HexDump],
    )
}

fn firmware() -> DockState<Pane> {
    view_tools_and_column(
        Pane::Raster,
        tools(&[
            DockTab::Firmware,
            DockTab::Disassembly,
            DockTab::Strings,
            DockTab::Crypto,
            DockTab::Unpacked,
            DockTab::Images,
            DockTab::Checksums,
            DockTab::Assistant,
        ]),
        vec![Pane::Inspector, Pane::Findings, Pane::Tool(DockTab::Reference)],
        vec![Pane::HexDump],
    )
}

fn signals() -> DockState<Pane> {
    view_tools_and_column(
        Pane::Raster,
        vec![
            Pane::Tool(DockTab::Bits),
            Pane::PeriodChart,
            Pane::Tool(DockTab::Columns),
            Pane::Tool(DockTab::Trigrams),
            Pane::Tool(DockTab::DotPlot),
            Pane::Tool(DockTab::Statistics),
            Pane::Tool(DockTab::Xor),
            Pane::Tool(DockTab::Live),
        ],
        vec![Pane::HexDump],
        vec![Pane::Inspector, Pane::Findings],
    )
}

fn forensics() -> DockState<Pane> {
    view_tools_and_column(
        Pane::Raster,
        tools(&[DockTab::Forensics, DockTab::Images, DockTab::Unpacked, DockTab::Strings, DockTab::SizeMap, DockTab::Report]),
        vec![Pane::Findings, Pane::Inspector],
        vec![Pane::HexDump],
    )
}

fn compare() -> DockState<Pane> {
    view_tools_and_column(
        Pane::Raster,
        tools(&[DockTab::Compare, DockTab::Diff, DockTab::Statistics]),
        vec![Pane::HexDump],
        vec![Pane::Inspector, Pane::Findings],
    )
}

fn focus() -> DockState<Pane> {
    let mut state = view_showing(Pane::Raster);
    state.main_surface_mut().split_right(NodeIndex::root(), 0.62, vec![Pane::HexDump, Pane::Inspector]);
    state
}

/// A layout the person saved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedLayout {
    pub name: String,
    pub path: PathBuf,
}

/// Where saved layouts are kept.
pub fn saved_dir() -> Option<PathBuf> {
    config::config_file("layouts")
}

/// Every saved layout in `dir`, by name.
pub fn list_saved(dir: &Path) -> Vec<SavedLayout> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut saved: Vec<SavedLayout> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
        .filter_map(|path| Some(SavedLayout { name: layout::load_name(&path)?, path }))
        .collect();
    saved.sort_by_key(|layout| layout.name.to_lowercase());
    saved
}

/// Save `state` under `name`, replacing a saved layout of the same name.
pub fn save_named(dir: &Path, name: &str, state: &DockState<Pane>) -> Result<SavedLayout, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Give the layout a name".to_string());
    }
    let path = list_saved(dir)
        .into_iter()
        .find(|saved| saved.name.eq_ignore_ascii_case(name))
        .map_or_else(|| unused_path(dir, name), |saved| saved.path);
    layout::save_named(&path, name, state)?;
    Ok(SavedLayout { name: name.to_string(), path })
}

/// Give a saved layout a new name, keeping its arrangement.
pub fn rename(dir: &Path, saved: &SavedLayout, new_name: &str) -> Result<SavedLayout, String> {
    let state = layout::load(&saved.path).ok_or_else(|| format!("Could not read the layout '{}'", saved.name))?;
    let renamed = save_named(dir, new_name, &state)?;
    if renamed.path != saved.path {
        delete(saved)?;
    }
    Ok(renamed)
}

pub fn delete(saved: &SavedLayout) -> Result<(), String> {
    std::fs::remove_file(&saved.path).map_err(|error| format!("Could not delete the layout '{}': {error}", saved.name))
}

/// A file name for a new layout: its name in lower case with anything but
/// letters and digits turned into dashes, numbered if already taken.
fn unused_path(dir: &Path, name: &str) -> PathBuf {
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let slug = if slug.is_empty() { "layout".to_string() } else { slug };
    let mut path = dir.join(format!("{slug}.json"));
    let mut number = 2;
    while path.exists() {
        path = dir.join(format!("{slug}-{number}.json"));
        number += 1;
    }
    path
}

/// What the Layout menu works with.
#[derive(Default)]
pub struct Choices {
    /// The layout last opened, by name, ticked in the menu.
    pub current: Option<String>,
    /// The arrangement found on starting: how the last session left it.
    pub last_session: Option<DockState<Pane>>,
    pub saved: Vec<SavedLayout>,
    /// The name typed into "Save as".
    pub new_name: String,
    /// The saved layout being renamed, with the name typed so far.
    pub renaming: Option<(SavedLayout, String)>,
    /// The saved layout whose Delete was pressed once and awaits a second press.
    pub confirming_delete: Option<PathBuf>,
    /// A layout that suits the file just opened, offered in the status bar.
    pub suggestion: Option<Recommended>,
}

impl ViewerApp {
    pub fn apply_recommended(&mut self, recommended: Recommended) {
        self.use_layout(recommended.build(), recommended.label());
        if recommended == Recommended::Network {
            crate::panel_packets::load_capture_if_empty(self);
        }
    }

    fn use_layout(&mut self, state: DockState<Pane>, name: &str) {
        self.layout = state;
        self.dock.shown = None;
        self.layouts.current = Some(name.to_string());
        self.layouts.suggestion = None;
    }

    pub fn open_saved_layout(&mut self, saved: &SavedLayout) {
        match layout::load(&saved.path) {
            Some(state) => self.use_layout(state, &saved.name),
            None => self.status = format!("Could not read the layout '{}'", saved.name),
        }
    }

    /// Open the layout called `name`: a recommended one by its command-line
    /// name, or one of the person's by its own. Returns whether one was found.
    pub fn open_layout_named(&mut self, name: &str) -> bool {
        if let Some(recommended) = Recommended::from_cli_name(name) {
            self.apply_recommended(recommended);
            return true;
        }
        match self.layouts.saved.iter().find(|saved| saved.name.eq_ignore_ascii_case(name.trim())).cloned() {
            Some(saved) => {
                self.open_saved_layout(&saved);
                true
            }
            None => false,
        }
    }

    pub fn restore_last_session(&mut self) {
        if let Some(state) = self.layouts.last_session.clone() {
            self.use_layout(state, LAST_SESSION);
        }
    }

    /// Re-read the saved layouts from disk.
    pub fn refresh_saved_layouts(&mut self) {
        self.layouts.saved = if self.persist_layout { saved_dir().map(|dir| list_saved(&dir)).unwrap_or_default() } else { Vec::new() };
    }

    /// Keep the current arrangement under `name`, replacing one of that name.
    pub fn save_layout_as(&mut self, name: &str) {
        let Some(dir) = saved_dir().filter(|_| self.persist_layout) else { return };
        match save_named(&dir, name, &self.layout) {
            Ok(saved) => {
                self.status = format!("Saved the layout '{}'", saved.name);
                self.layouts.current = Some(saved.name);
                self.layouts.new_name.clear();
            }
            Err(message) => self.status = message,
        }
        self.refresh_saved_layouts();
    }

    fn rename_saved_layout(&mut self, saved: &SavedLayout, new_name: &str) {
        let Some(dir) = saved_dir() else { return };
        match rename(&dir, saved, new_name) {
            Ok(renamed) => {
                if self.layouts.current.as_deref() == Some(saved.name.as_str()) {
                    self.layouts.current = Some(renamed.name.clone());
                }
                if self.preferences.open_with_layout.eq_ignore_ascii_case(&saved.name) {
                    let mut preferences = self.preferences.clone();
                    preferences.open_with_layout = renamed.name;
                    self.set_preferences(preferences);
                }
            }
            Err(message) => self.status = message,
        }
        self.refresh_saved_layouts();
    }

    fn delete_saved_layout(&mut self, saved: &SavedLayout) {
        match delete(saved) {
            Ok(()) => self.status = format!("Deleted the layout '{}'", saved.name),
            Err(message) => self.status = message,
        }
        if self.preferences.open_with_layout.eq_ignore_ascii_case(&saved.name) {
            let mut preferences = self.preferences.clone();
            preferences.open_with_layout.clear();
            self.set_preferences(preferences);
        }
        self.refresh_saved_layouts();
    }

    /// Set up the arrangement for a new run: the preferred layout, or the
    /// last session's when there is no preference (or it no longer exists).
    pub fn open_startup_layout(&mut self, last_session: Option<DockState<Pane>>) {
        self.refresh_saved_layouts();
        self.layouts.last_session = last_session;
        let preferred = self.preferences.open_with_layout.clone();
        if !preferred.is_empty() && self.open_layout_named(&preferred) {
            return;
        }
        if self.layouts.last_session.is_some() {
            self.restore_last_session();
        } else {
            self.layouts.current = Some(Recommended::Overview.label().to_string());
        }
    }

    /// Offer the recommended layout for the file just opened, when its
    /// start is a format with one and that layout is not already in use.
    pub fn suggest_layout_for_file(&mut self) {
        self.layouts.suggestion = None;
        if !self.preferences.suggest_layouts || self.document.is_empty() {
            return;
        }
        let head = self.document.read_range(0, SUGGESTION_READ_LIMIT);
        let suited = self
            .registry
            .parsers()
            .iter()
            .filter(|parser| parser.looks_like(&head))
            .find_map(|parser| parser.parse(&head, 0))
            .and_then(|finding| Recommended::suited_to(&finding.id));
        self.layouts.suggestion = suited.filter(|recommended| self.layouts.current.as_deref() != Some(recommended.label()));
    }

    /// The offer of a better layout, in the status bar.
    pub fn show_layout_suggestion(&mut self, ui: &mut Ui) {
        let Some(suggestion) = self.layouts.suggestion else { return };
        ui.separator();
        ui.label(RichText::new(format!("Suits the {} layout", suggestion.label())).color(theme::ACCENT))
            .on_hover_text(suggestion.purpose());
        if ui.small_button("Switch").on_hover_text("Open that layout; Restore last session in the Layout menu brings back this one").clicked() {
            self.apply_recommended(suggestion);
        }
        if ui.small_button("Dismiss").on_hover_text("Keep this layout. Suggestions can be turned off in the Layout menu.").clicked() {
            self.layouts.suggestion = None;
        }
    }
}

/// The Layout menu: recommended layouts, the person's own, the last session
/// and what opens at start.
pub fn show_layout_menu(app: &mut ViewerApp, ui: &mut Ui) {
    ui.set_min_width(300.0);
    let current = app.layouts.current.clone();
    let ticked = |name: &str| current.as_deref() == Some(name);
    ui.label(RichText::new("Recommended").small().color(theme::TEXT_DIM));
    for recommended in Recommended::ALL {
        if ui.add(egui::Button::new(recommended.label()).selected(ticked(recommended.label()))).on_hover_text(recommended.purpose()).clicked() {
            app.apply_recommended(recommended);
            ui.close();
        }
    }
    ui.separator();
    ui.label(RichText::new("Yours").small().color(theme::TEXT_DIM));
    if app.layouts.saved.is_empty() {
        ui.label(RichText::new("Layouts you save appear here.").small().color(theme::TEXT_DIM));
    }
    for saved in app.layouts.saved.clone() {
        show_saved_row(app, ui, &saved, ticked(&saved.name));
    }
    show_save_as(app, ui);
    ui.separator();
    let restorable = app.layouts.last_session.is_some();
    if ui
        .add_enabled(restorable, egui::Button::new(LAST_SESSION).selected(ticked(LAST_SESSION)))
        .on_hover_text("The arrangement as it was when theviewer last closed")
        .on_disabled_hover_text("Nothing was saved from a previous session")
        .clicked()
    {
        app.restore_last_session();
        ui.close();
    }
    ui.separator();
    ui.menu_button("When theviewer opens", |ui| show_open_with(app, ui));
    let mut suggest = app.preferences.suggest_layouts;
    if ui.checkbox(&mut suggest, "Suggest a layout for each file").on_hover_text("When a file opens as a capture, an executable, a disk image or a known format, offer the layout made for it").changed() {
        let mut preferences = app.preferences.clone();
        preferences.suggest_layouts = suggest;
        app.set_preferences(preferences);
        if !suggest {
            app.layouts.suggestion = None;
        }
    }
}

fn show_saved_row(app: &mut ViewerApp, ui: &mut Ui, saved: &SavedLayout, ticked: bool) {
    if let Some((renaming, draft)) = app.layouts.renaming.as_mut()
        && renaming.path == saved.path
    {
        let mut done = None;
        ui.horizontal(|ui| {
            let response = ui.add(egui::TextEdit::singleline(draft).desired_width(160.0));
            response.request_focus();
            let entered = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
            if ui.small_button("Rename").clicked() || entered {
                done = Some(true);
            }
            if ui.small_button("Cancel").clicked() || ui.input(|input| input.key_pressed(Key::Escape)) {
                done = Some(false);
            }
        });
        if let Some(confirmed) = done {
            let (renaming, draft) = app.layouts.renaming.take().unwrap_or_else(|| (saved.clone(), String::new()));
            if confirmed {
                app.rename_saved_layout(&renaming, &draft);
            }
        }
        return;
    }
    ui.horizontal(|ui| {
        if ui.add(egui::Button::new(&saved.name).selected(ticked)).clicked() {
            app.open_saved_layout(saved);
            ui.close();
        }
        if ui.small_button("Update").on_hover_text("Replace it with the current arrangement").clicked() {
            app.save_layout_as(&saved.name);
        }
        if ui.small_button("Rename").clicked() {
            app.layouts.renaming = Some((saved.clone(), saved.name.clone()));
        }
        let confirming = app.layouts.confirming_delete.as_ref() == Some(&saved.path);
        let delete_label = if confirming { RichText::new("Really delete?").color(theme::DANGER) } else { RichText::new("Delete") };
        if ui.small_button(delete_label).clicked() {
            if confirming {
                app.layouts.confirming_delete = None;
                app.delete_saved_layout(saved);
            } else {
                app.layouts.confirming_delete = Some(saved.path.clone());
            }
        }
    });
}

fn show_save_as(app: &mut ViewerApp, ui: &mut Ui) {
    if !app.persist_layout {
        return;
    }
    ui.horizontal(|ui| {
        let response = ui.add(egui::TextEdit::singleline(&mut app.layouts.new_name).hint_text("Name for this layout").desired_width(180.0));
        let entered = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
        let named = !app.layouts.new_name.trim().is_empty();
        let existing = app.layouts.saved.iter().any(|saved| saved.name.eq_ignore_ascii_case(app.layouts.new_name.trim()));
        let label = if existing { "Replace" } else { "Save" };
        let clicked = ui.add_enabled(named, egui::Button::new(label)).on_hover_text("Keep the current arrangement under this name").clicked();
        if named && (clicked || entered) {
            let name = app.layouts.new_name.clone();
            app.save_layout_as(&name);
        }
    });
}

fn show_open_with(app: &mut ViewerApp, ui: &mut Ui) {
    let preferred = app.preferences.open_with_layout.clone();
    let mut choice = None;
    if ui.radio(preferred.is_empty(), LAST_SESSION).on_hover_text("As theviewer was when it last closed").clicked() {
        choice = Some(String::new());
    }
    for recommended in Recommended::ALL {
        if ui.radio(preferred == recommended.cli_name(), recommended.label()).clicked() {
            choice = Some(recommended.cli_name().to_string());
        }
    }
    for saved in &app.layouts.saved {
        if ui.radio(preferred.eq_ignore_ascii_case(&saved.name), &saved.name).clicked() {
            choice = Some(saved.name.clone());
        }
    }
    if let Some(choice) = choice {
        let mut preferences = app.preferences.clone();
        preferences.open_with_layout = choice;
        app.set_preferences(preferences);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panes_in(state: &DockState<Pane>) -> Vec<Pane> {
        state.iter_all_tabs().map(|(_, pane)| *pane).collect()
    }

    fn shown(state: &DockState<Pane>) -> Vec<Pane> {
        state.iter_leaves().filter_map(|(_, leaf)| leaf.tabs.get(leaf.active.0).copied()).collect()
    }

    fn temporary_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("theviewer-layouts-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn every_recommended_layout_has_the_view_the_hex_and_no_pane_twice() {
        for recommended in Recommended::ALL {
            let panes = panes_in(&recommended.build());
            assert!(panes.contains(&Pane::Raster), "{recommended:?}");
            assert!(panes.contains(&Pane::HexDump), "{recommended:?}");
            let leaf = recommended.build().iter_leaves().map(|(_, leaf)| leaf.tabs.clone()).find(|tabs| tabs.contains(&Pane::Raster)).unwrap();
            assert_eq!(leaf, layout::view_tabs(), "{recommended:?} keeps the packets beside the bits");
            let mut unique = panes.clone();
            unique.sort_by_key(|pane| format!("{pane:?}"));
            unique.dedup();
            assert_eq!(unique.len(), panes.len(), "{recommended:?} has a pane twice");
            assert_eq!(Recommended::from_cli_name(recommended.cli_name()), Some(recommended));
        }
    }

    #[test]
    fn each_kind_of_analysis_opens_on_its_own_tools() {
        let network = Recommended::Network.build();
        assert!(shown(&network).contains(&Pane::Tool(DockTab::Packets)), "packets first for a capture");
        assert!(shown(&network).contains(&Pane::Tool(DockTab::Reference)));
        assert!(!panes_in(&network).contains(&Pane::Tool(DockTab::Disassembly)), "no disassembler for packets");
        assert!(shown(&Recommended::Firmware.build()).contains(&Pane::Tool(DockTab::Firmware)));
        assert!(shown(&Recommended::Signals.build()).contains(&Pane::Tool(DockTab::Bits)));
        assert!(shown(&Recommended::Compare.build()).contains(&Pane::Tool(DockTab::Compare)));
        assert!(panes_in(&Recommended::Overview.build()).len() < DockTab::ALL.len(), "the overview no longer opens every tool");
    }

    #[test]
    fn a_closed_tool_reopens_beside_the_layouts_tools() {
        let mut state = Recommended::Network.build();
        layout::show_pane(&mut state, Pane::Tool(DockTab::Disassembly));
        let opened = state.find_tab(&Pane::Tool(DockTab::Disassembly)).expect("opened");
        let protocol = state.find_tab(&Pane::Tool(DockTab::Protocol)).unwrap();
        let reference = state.find_tab(&Pane::Tool(DockTab::Reference)).unwrap();
        assert!(opened.node_path() == protocol.node_path() || opened.node_path() == reference.node_path());
    }

    #[test]
    fn files_suggest_the_layout_for_their_kind() {
        assert_eq!(Recommended::suited_to("pcapng"), Some(Recommended::Network));
        assert_eq!(Recommended::suited_to("elf"), Some(Recommended::Firmware));
        assert_eq!(Recommended::suited_to("gpt"), Some(Recommended::Forensics));
        assert_eq!(Recommended::suited_to("png"), Some(Recommended::Structure));
        assert_eq!(Recommended::suited_to("utf8-text"), None);
        assert_eq!(Recommended::from_cli_name("Default"), Some(Recommended::Overview));
    }

    #[test]
    fn a_layout_saved_under_a_name_comes_back_and_can_be_renamed_and_deleted() {
        let dir = temporary_dir("named");
        let mine = save_named(&dir, "  Radio work  ", &Recommended::Signals.build()).unwrap();
        assert_eq!(mine.name, "Radio work");
        assert_eq!(mine.path.file_name().unwrap(), "radio-work.json");
        save_named(&dir, "Captures", &Recommended::Network.build()).unwrap();
        let names: Vec<String> = list_saved(&dir).into_iter().map(|saved| saved.name).collect();
        assert_eq!(names, ["Captures", "Radio work"]);

        // Saving under the same name again updates it rather than adding one.
        save_named(&dir, "radio WORK", &Recommended::Focus.build()).unwrap();
        assert_eq!(list_saved(&dir).len(), 2);
        let updated = layout::load(&mine.path).unwrap();
        assert_eq!(panes_in(&updated), panes_in(&Recommended::Focus.build()));

        let renamed = rename(&dir, &list_saved(&dir)[1], "Bit streams").unwrap();
        let names: Vec<String> = list_saved(&dir).into_iter().map(|saved| saved.name).collect();
        assert_eq!(names, ["Bit streams", "Captures"]);
        delete(&renamed).unwrap();
        assert_eq!(list_saved(&dir).len(), 1);
        assert!(save_named(&dir, "   ", &Recommended::Focus.build()).is_err(), "a layout needs a name");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn names_that_share_a_file_name_get_their_own_files() {
        let dir = temporary_dir("slugs");
        let first = save_named(&dir, "A/B", &Recommended::Focus.build()).unwrap();
        let second = save_named(&dir, "A B", &Recommended::Focus.build()).unwrap();
        assert_ne!(first.path, second.path);
        assert_eq!(list_saved(&dir).len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }
}
