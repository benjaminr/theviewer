//! Dock panel: a size map (squarified treemap) of the file.
//!
//! Two sources can be shown:
//!
//! * **Regions** from the report's file map, one tile per region, coloured
//!   by kind. A click jumps to the region.
//! * **Unpacked contents** from the unpacked tree, as nested tiles shaded by
//!   depth. A click opens the node as a document, as the Unpacked tab does; a
//!   right-click zooms into a node, and the breadcrumb zooms back out.
//!
//! The layout itself is [`crate::treemap::squarify`].

use std::sync::Arc;
use std::time::Duration;

use eframe::egui::{self, Align2, Color32, FontId, Painter, Rect, RichText, Sense, Stroke, Ui, pos2, vec2};

use crate::app::ViewerApp;
use crate::compress::human_bytes;
use crate::explain::Region;
use crate::theme;
use crate::treemap::{self, Tile};
use crate::unpack::Node;

/// How often to look for a finished report or unpack while one is running.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Smallest size, in points, the map is drawn at.
const MIN_MAP_WIDTH: f32 = 160.0;
const MIN_MAP_HEIGHT: f32 = 120.0;
/// Gap, in points, between a nested tile and its parent's edge.
const NESTING_PADDING: f64 = 3.0;
/// Height, in points, of the strip at the top of a parent tile that holds its
/// label above its children.
const HEADER_HEIGHT: f64 = 15.0;
/// Deepest nesting drawn below the node being shown.
const MAX_NESTED_LEVELS: usize = 4;
/// Smallest tile side, in points, worth nesting children inside.
const MIN_NESTING_SIDE: f64 = 24.0;
/// Space, in points, between a label and its tile's edge.
const LABEL_PADDING: f32 = 3.0;
const LABEL_FONT_SIZE: f32 = 11.0;
/// How much lighter each level of nesting is drawn, from 0 to 1.
const DEPTH_SHADE_STEP: f32 = 0.18;
/// Luminance above which labels are drawn dark rather than light.
const LIGHT_BACKGROUND_LUMINANCE: f32 = 150.0;

/// What the map shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TreemapSource {
    /// The report's file map.
    #[default]
    Regions,
    /// The recursively unpacked tree.
    Unpacked,
}

impl TreemapSource {
    pub const ALL: [TreemapSource; 2] = [TreemapSource::Regions, TreemapSource::Unpacked];

    pub fn label(self) -> &'static str {
        match self {
            TreemapSource::Regions => "Regions",
            TreemapSource::Unpacked => "Unpacked contents",
        }
    }
}

/// Everything the size map panel keeps between frames.
#[derive(Default)]
pub struct TreemapState {
    pub source: TreemapSource,
    /// Child indices from the unpacked root to the node being shown.
    pub zoom_path: Vec<usize>,
    /// True once an unpack was started from here and has not arrived yet.
    unpack_requested: bool,
    /// Where the map was last drawn.
    map_rect: Option<Rect>,
}

/// One tile of the unpacked tree, laid out.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeTile {
    pub tile: Tile,
    /// Child indices from the unpacked root.
    pub path: Vec<usize>,
    /// Levels below the node being shown, starting at 0.
    pub depth: usize,
    /// True when the tile's children are drawn inside it, below a header.
    pub nested: bool,
}

/// What a click on the map asks for.
enum MapAction {
    JumpTo(usize),
    Open(Vec<usize>),
    ZoomInto(Vec<usize>),
}

/// Show the size map panel.
pub fn show_treemap(state: &mut TreemapState, app: &mut ViewerApp, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        for source in TreemapSource::ALL {
            ui.selectable_value(&mut state.source, source, source.label());
        }
    });
    let action = match state.source {
        TreemapSource::Regions => show_regions(state, app, ui),
        TreemapSource::Unpacked => show_unpacked(state, app, ui),
    };
    match action {
        Some(MapAction::JumpTo(offset)) => {
            app.jump_found(offset);
            app.status = format!("Jumped to {offset:#x}");
        }
        Some(MapAction::Open(path)) => open_node(app, &path),
        Some(MapAction::ZoomInto(path)) => state.zoom_path = path,
        None => {}
    }
}

// ---------------------------------------------------------------------------
// Regions
// ---------------------------------------------------------------------------

fn show_regions(state: &mut TreemapState, app: &mut ViewerApp, ui: &mut Ui) -> Option<MapAction> {
    if app.mapped_regions.is_empty() {
        ui.horizontal(|ui| {
            if ui.button("Explain this file").clicked() {
                app.explain_file();
            }
            if app.report_running() {
                ui.spinner();
                ui.label(RichText::new("Mapping the file…").color(theme::TEXT_DIM));
                ui.ctx().request_repaint_after(POLL_INTERVAL);
            }
        });
        ui.label(RichText::new("Shows the file's regions as tiles sized by their length. Explain the file first to map its regions.").color(theme::TEXT_DIM));
        return None;
    }
    ui.label(RichText::new("Tiles sized by length and coloured by kind · click to jump to a region").small().color(theme::TEXT_DIM));

    let (response, painter) = allocate_map(ui);
    state.map_rect = Some(response.rect);
    let regions = Arc::clone(&app.mapped_regions);
    let cells = region_cells(&regions, response.rect);
    for &(index, rect) in &cells {
        draw_region(&painter, &regions[index], rect);
    }

    let hovered = response.hover_pos().and_then(|pointer| cells.iter().rev().find(|(_, rect)| rect.contains(pointer)));
    let &(index, rect) = hovered?;
    painter.rect_stroke(rect, 0.0, Stroke::new(2.0, theme::CURSOR), egui::StrokeKind::Inside);
    let clicked = response.clicked();
    response.on_hover_text(describe_region(&regions[index]));
    clicked.then(|| MapAction::JumpTo(regions[index].start))
}

/// One screen rectangle per region with a non-empty tile, as
/// `(region index, rectangle)`.
fn region_cells(regions: &[Region], bounds: Rect) -> Vec<(usize, Rect)> {
    let sizes: Vec<f64> = regions.iter().map(|region| region.len as f64).collect();
    treemap::squarify(&sizes, tile_of(bounds))
        .into_iter()
        .enumerate()
        .filter(|(_, tile)| !tile.is_empty())
        .map(|(index, tile)| (index, rect_of(tile)))
        .collect()
}

fn draw_region(painter: &Painter, region: &Region, rect: Rect) {
    let colour = region.kind.colour();
    painter.rect_filled(rect, 0.0, colour);
    painter.rect_stroke(rect, 0.0, Stroke::new(1.0, theme::BACKGROUND), egui::StrokeKind::Inside);
    let label = format!("{} · {}", region.label, human_bytes(region.len));
    draw_label_if_it_fits(painter, rect, &label, label_colour_on(colour));
}

fn describe_region(region: &Region) -> String {
    let how = if region.confident { "identified by a parser" } else { "a statistical guess" };
    let mut text = format!(
        "{}\n{} · {:#x}–{:#x} · {}\n({how})",
        region.label,
        region.kind.label(),
        region.start,
        region.end(),
        human_bytes(region.len)
    );
    if !region.detail.is_empty() {
        text.push('\n');
        text.push_str(&region.detail);
    }
    text.push_str("\nClick to jump to it");
    text
}

// ---------------------------------------------------------------------------
// Unpacked contents
// ---------------------------------------------------------------------------

fn show_unpacked(state: &mut TreemapState, app: &mut ViewerApp, ui: &mut Ui) -> Option<MapAction> {
    let Some(root) = app.bench.unpacked.of(&app.document_id()) else {
        show_unpack_prompt(state, app, ui);
        return None;
    };
    state.unpack_requested = false;
    if root.find(&state.zoom_path).is_none() {
        state.zoom_path.clear();
    }
    show_breadcrumb(state, root, ui);

    let shown = root.find(&state.zoom_path)?;
    if shown.children.is_empty() {
        let message = if state.zoom_path.is_empty() { "Nothing nested was found." } else { "Nothing nested inside this node." };
        ui.label(RichText::new(message).color(theme::TEXT_DIM));
        return None;
    }
    ui.label(
        RichText::new("Tiles sized by unpacked size, nested by containment · click to open a node, right-click to zoom into it")
            .small()
            .color(theme::TEXT_DIM),
    );

    let (response, painter) = allocate_map(ui);
    state.map_rect = Some(response.rect);
    let tiles = node_tiles(shown, &state.zoom_path, tile_of(response.rect));
    for node_tile in &tiles {
        if let Some(node) = root.find(&node_tile.path) {
            draw_node(&painter, node, node_tile);
        }
    }

    let pointer = response.hover_pos()?;
    let hovered = tiles.iter().rev().find(|node_tile| rect_of(node_tile.tile).contains(pointer))?;
    let node = root.find(&hovered.path)?;
    painter.rect_stroke(rect_of(hovered.tile), 0.0, Stroke::new(2.0, theme::CURSOR), egui::StrokeKind::Inside);
    let action = if response.clicked() {
        Some(MapAction::Open(hovered.path.clone()))
    } else if response.secondary_clicked() && !node.children.is_empty() {
        Some(MapAction::ZoomInto(hovered.path.clone()))
    } else {
        None
    };
    response.on_hover_text(describe_node(node));
    action
}

fn show_unpack_prompt(state: &mut TreemapState, app: &mut ViewerApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        if ui.button("Unpack everything").clicked() && !app.document.is_empty() {
            app.start_unpack();
            state.unpack_requested = true;
        }
        if state.unpack_requested {
            ui.spinner();
            ui.label(RichText::new("Unpacking nested containers…").color(theme::TEXT_DIM));
            ui.ctx().request_repaint_after(POLL_INTERVAL);
        }
    });
    ui.label(
        RichText::new("Shows archives and compressed streams found inside the file as nested tiles. Unpack the file first.")
            .color(theme::TEXT_DIM),
    );
}

/// The path from the root to the node shown, each step a button that zooms
/// back out to it.
fn show_breadcrumb(state: &mut TreemapState, root: &Node, ui: &mut Ui) {
    let mut zoom_to = None;
    ui.horizontal_wrapped(|ui| {
        let mut node = root;
        if ui.small_button(&root.name).on_hover_text("Show the whole tree").clicked() {
            zoom_to = Some(0);
        }
        for (depth, &index) in state.zoom_path.iter().enumerate() {
            let Some(child) = node.children.get(index) else { break };
            node = child;
            ui.label(RichText::new("›").color(theme::TEXT_DIM));
            if ui.small_button(&node.name).clicked() {
                zoom_to = Some(depth + 1);
            }
        }
    });
    if let Some(depth) = zoom_to {
        state.zoom_path.truncate(depth);
    }
}

/// Lay out the children of `shown` (found at `shown_path`) inside `bounds`,
/// nesting grandchildren inside their parents' tiles while they fit. Parents
/// come before their children, so the last tile under the pointer is the
/// deepest.
pub fn node_tiles(shown: &Node, shown_path: &[usize], bounds: Tile) -> Vec<NodeTile> {
    let mut tiles = Vec::new();
    lay_out_children(shown, shown_path, bounds, 0, &mut tiles);
    tiles
}

fn lay_out_children(parent: &Node, parent_path: &[usize], bounds: Tile, depth: usize, tiles: &mut Vec<NodeTile>) {
    let sizes: Vec<f64> = parent.children.iter().map(|child| child.data.len() as f64).collect();
    for (index, (child, tile)) in parent.children.iter().zip(treemap::squarify(&sizes, bounds)).enumerate() {
        if tile.is_empty() {
            continue;
        }
        let mut path = parent_path.to_vec();
        path.push(index);
        let inner = tile.inset(NESTING_PADDING).without_top(HEADER_HEIGHT);
        let nested = !child.children.is_empty()
            && depth + 1 < MAX_NESTED_LEVELS
            && inner.width >= MIN_NESTING_SIDE
            && inner.height >= MIN_NESTING_SIDE;
        tiles.push(NodeTile { tile, path: path.clone(), depth, nested });
        if nested {
            lay_out_children(child, &path, inner, depth + 1, tiles);
        }
    }
}

fn draw_node(painter: &Painter, node: &Node, node_tile: &NodeTile) {
    let rect = rect_of(node_tile.tile);
    let colour = depth_colour(node_tile.depth);
    painter.rect_filled(rect, 2.0, colour);
    painter.rect_stroke(rect, 2.0, Stroke::new(1.0, theme::BACKGROUND), egui::StrokeKind::Inside);
    let label = format!("{} · {}", node.name, human_bytes(node.data.len()));
    let label_area = if node_tile.nested {
        Rect::from_min_size(rect.min, vec2(rect.width(), HEADER_HEIGHT as f32 + NESTING_PADDING as f32))
    } else {
        rect
    };
    draw_label_if_it_fits(painter, label_area, &label, label_colour_on(colour));
}

fn describe_node(node: &Node) -> String {
    let mut text = format!("{}\nAt {:#x} in its parent, {} there", node.summary(), node.source_offset, human_bytes(node.source_len));
    if !node.children.is_empty() {
        text.push_str(&format!("\n{} nested items · right-click to zoom in", node.count() - 1));
    }
    text.push_str("\nClick to open it as a document; Back returns");
    text
}

/// The person opens the node at `path` as a derived document, as the
/// Unpacked tab does: `unpack.open`.
fn open_node(app: &mut ViewerApp, path: &[usize]) {
    if app.bench.unpacked.of(&app.document_id()).and_then(|root| root.find(path)).is_some() {
        let _ = app.perform("unpack.open", serde_json::json!({ "path": path }));
    }
}

/// Darker for outer levels, lighter for each level nested inside.
fn depth_colour(depth: usize) -> Color32 {
    let amount = (depth as f32 * DEPTH_SHADE_STEP).min(1.0);
    blend(theme::ACCENT_DIM, theme::SURFACE_RAISED.linear_multiply(1.6), amount)
}

// ---------------------------------------------------------------------------
// Drawing helpers
// ---------------------------------------------------------------------------

/// Claim the rest of the panel for the map.
fn allocate_map(ui: &mut Ui) -> (egui::Response, Painter) {
    let size = vec2(ui.available_width().max(MIN_MAP_WIDTH), ui.available_height().max(MIN_MAP_HEIGHT));
    ui.allocate_painter(size, Sense::click())
}

/// Draw `text` in the top-left of `rect`, only when it fits whole.
fn draw_label_if_it_fits(painter: &Painter, rect: Rect, text: &str, colour: Color32) {
    let galley = painter.layout_no_wrap(text.to_string(), FontId::proportional(LABEL_FONT_SIZE), colour);
    let needed = galley.size() + vec2(2.0 * LABEL_PADDING, 2.0 * LABEL_PADDING);
    if needed.x <= rect.width() && needed.y <= rect.height() {
        painter.text(rect.min + vec2(LABEL_PADDING, LABEL_PADDING), Align2::LEFT_TOP, text, FontId::proportional(LABEL_FONT_SIZE), colour);
    }
}

/// Dark text on light tiles, light text on dark ones.
fn label_colour_on(background: Color32) -> Color32 {
    let luminance = 0.299 * background.r() as f32 + 0.587 * background.g() as f32 + 0.114 * background.b() as f32;
    if luminance > LIGHT_BACKGROUND_LUMINANCE { theme::BACKGROUND } else { theme::TEXT }
}

/// Mix two opaque colours, `amount` of the way from `from` to `to`.
fn blend(from: Color32, to: Color32, amount: f32) -> Color32 {
    let mix = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * amount).round() as u8;
    Color32::from_rgb(mix(from.r(), to.r()), mix(from.g(), to.g()), mix(from.b(), to.b()))
}

fn tile_of(rect: Rect) -> Tile {
    Tile::new(rect.min.x as f64, rect.min.y as f64, rect.width() as f64, rect.height() as f64)
}

fn rect_of(tile: Tile) -> Rect {
    Rect::from_min_size(pos2(tile.x as f32, tile.y as f32), vec2(tile.width as f32, tile.height as f32))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    use super::*;
    use crate::app::Launch;
    use crate::document::Document;
    use crate::explain::RegionKind;

    type PanelHarness = Harness<'static, (TreemapState, ViewerApp)>;

    fn harness_for(app: ViewerApp) -> PanelHarness {
        Harness::new_ui_state(
            |ui, (state, app): &mut (TreemapState, ViewerApp)| show_treemap(state, app, ui),
            (TreemapState::default(), app),
        )
    }

    fn app_with_bytes(len: usize) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.document = Document::from_bytes(vec![0x41; len]);
        app
    }

    fn region(start: usize, len: usize, kind: RegionKind, label: &str) -> Region {
        Region { start, len, kind, label: label.to_string(), detail: String::new(), confident: false }
    }

    fn node(name: &str, len: usize, children: Vec<Node>) -> Node {
        Node {
            name: name.to_string(),
            kind: "file".to_string(),
            source_offset: 0,
            source_len: len,
            data: Arc::new(vec![0x5A; len]),
            children,
            note: None,
            method: None,
        }
    }

    fn sample_tree() -> Node {
        node(
            "firmware.bin",
            10_000,
            vec![node("kernel.gz", 6000, vec![node("vmlinux", 5000, vec![]), node("initrd", 3000, vec![])]), node("config.txt", 2000, vec![])],
        )
    }

    fn click_at(harness: &mut PanelHarness, position: egui::Pos2, button: egui::PointerButton) {
        harness.input_mut().events.push(egui::Event::PointerMoved(position));
        harness.step();
        for pressed in [true, false] {
            harness.input_mut().events.push(egui::Event::PointerButton { pos: position, button, pressed, modifiers: egui::Modifiers::NONE });
            harness.step();
        }
    }

    #[test]
    fn without_regions_the_panel_offers_to_explain_the_file() {
        let mut harness = harness_for(app_with_bytes(4096));
        harness.step();
        assert!(harness.query_by_label("Explain this file").is_some());
    }

    #[test]
    fn clicking_a_region_tile_jumps_to_that_region() {
        let mut app = app_with_bytes(4096);
        // The report publishes its map on the bus, which the size map reads.
        let regions = [region(0, 1024, RegionKind::Header, "header"), region(1024, 3072, RegionKind::Text, "text")];
        let mapped = regions
            .iter()
            .map(|region| crate::bus::topics::MappedRegion { start: region.start, len: region.len, kind: region.kind.label().to_string(), label: region.label.clone(), detail: String::new(), confident: false })
            .collect();
        app.publish("tool:report", crate::bus::Payload::RegionsMapped(crate::bus::topics::RegionsMapped { regions: mapped }));
        app.run_bus();
        assert!(app.bench.regions.is_empty(), "the size map does not need the report's own state");
        let mut harness = harness_for(app);
        harness.step();
        let map = harness.state().0.map_rect.expect("the map was drawn");
        let cells = region_cells(&harness.state().1.mapped_regions, map);
        let &(_, text_rect) = cells.iter().find(|(index, _)| *index == 1).expect("the text region has a tile");
        click_at(&mut harness, text_rect.center(), egui::PointerButton::Primary);
        assert_eq!(harness.state().1.cursor, 1024);
    }

    #[test]
    fn without_an_unpacked_tree_the_panel_offers_to_unpack() {
        let mut harness = harness_for(app_with_bytes(16));
        harness.step();
        harness.get_by_label("Unpacked contents").click();
        harness.step();
        assert!(harness.query_by_label("Unpack everything").is_some());
    }

    #[test]
    fn right_clicking_a_container_zooms_in_and_the_breadcrumb_zooms_back_out() {
        let mut app = app_with_bytes(16);
        let sheet = app.document_id();
        app.bench.unpacked.set(&sheet, sample_tree());
        let mut harness = harness_for(app);
        harness.state_mut().0.source = TreemapSource::Unpacked;
        harness.step();
        let map = harness.state().0.map_rect.expect("the map was drawn");
        let root = harness.state().1.bench.unpacked.get().cloned().expect("a tree");
        let tiles = node_tiles(&root, &[], tile_of(map));
        let kernel = tiles.iter().find(|tile| tile.path == [0]).expect("kernel.gz has a tile");
        // Its header strip belongs to the container itself, not a child.
        let header = pos2(rect_of(kernel.tile).center().x, kernel.tile.y as f32 + 4.0);
        click_at(&mut harness, header, egui::PointerButton::Secondary);
        assert_eq!(harness.state().0.zoom_path, vec![0]);

        harness.get_by_label("firmware.bin").click();
        harness.step();
        assert!(harness.state().0.zoom_path.is_empty());
    }

    #[test]
    fn clicking_an_unpacked_node_opens_it_as_a_document() {
        let mut app = app_with_bytes(16);
        let sheet = app.document_id();
        app.bench.unpacked.set(&sheet, sample_tree());
        let mut harness = harness_for(app);
        harness.state_mut().0.source = TreemapSource::Unpacked;
        harness.step();
        let map = harness.state().0.map_rect.expect("the map was drawn");
        let root = harness.state().1.bench.unpacked.get().cloned().expect("a tree");
        let config = node_tiles(&root, &[], tile_of(map)).into_iter().find(|tile| tile.path == [1]).expect("config.txt has a tile");
        click_at(&mut harness, rect_of(config.tile).center(), egui::PointerButton::Primary);
        assert_eq!(harness.state().1.document.len(), 2000);
    }

    #[test]
    fn nested_tiles_sit_inside_their_parents_below_the_header() {
        let root = sample_tree();
        let tiles = node_tiles(&root, &[], Tile::new(0.0, 0.0, 800.0, 600.0));
        let kernel = tiles.iter().find(|tile| tile.path == [0]).expect("kernel.gz");
        assert!(kernel.nested);
        for child in tiles.iter().filter(|tile| tile.path.starts_with(&[0]) && tile.path.len() == 2) {
            assert_eq!(child.depth, 1);
            assert!(child.tile.x >= kernel.tile.x && child.tile.x + child.tile.width <= kernel.tile.x + kernel.tile.width + 1e-6);
            assert!(child.tile.y >= kernel.tile.y + HEADER_HEIGHT);
        }
        assert_eq!(tiles.len(), 4);
    }

    #[test]
    fn tiles_too_small_to_hold_children_are_not_nested() {
        let root = sample_tree();
        let tiles = node_tiles(&root, &[], Tile::new(0.0, 0.0, 30.0, 30.0));
        assert!(tiles.iter().all(|tile| !tile.nested && tile.depth == 0));
    }

    #[test]
    fn labels_contrast_with_their_tiles() {
        assert_eq!(label_colour_on(Color32::WHITE), theme::BACKGROUND);
        assert_eq!(label_colour_on(Color32::BLACK), theme::TEXT);
    }
}
