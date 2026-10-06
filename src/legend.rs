//! The legend bar: what colours the view and which highlights are drawn
//! over it.
//!
//! A strip at the top of the raster view (and a condensed one in the hex
//! dump's header) always says how the pixels are coloured and lists each
//! highlight layer that is drawn: the selection, the cursor, search matches,
//! bookmarks, pattern highlights by kind, structure fields, pinned findings
//! grouped by the tool that pinned them, and the packet viewer's selection.
//! Each layer has a swatch, a count and a show or hide toggle; pointing at a
//! layer emphasises exactly its overlays in the raster and the hex dump.

use std::collections::BTreeSet;

use eframe::egui::{self, Color32, Rect, RichText, Sense, Stroke, StrokeKind, Ui, Vec2, vec2};

use crate::app::ViewerApp;
use crate::plugin::{Category, Field, Finding};
use crate::raster::PixelFormat;
use crate::theme;
use crate::workbench::Layout;

/// Side of a layer's colour swatch.
const SWATCH_SIZE: f32 = 9.0;
/// Width and height of the palette gradient in the colouring key.
const GRADIENT_SIZE: Vec2 = vec2(54.0, 9.0);
/// Most search matches looked for in the visible window.
pub const MAX_SEARCH_HIGHLIGHTS: usize = 20_000;
/// Darkening laid over the views while one layer is emphasised.
pub const EMPHASIS_VEIL: Color32 = Color32::from_rgba_premultiplied(0, 0, 0, 150);
/// Outline of an emphasised overlay.
pub const EMPHASIS_OUTLINE: Color32 = Color32::WHITE;
/// Highlight colour of search matches.
pub const SEARCH_COLOUR: Color32 = Color32::from_rgb(255, 236, 120);
/// Outline colour of the packets selected in the packet viewer.
pub const PACKET_SELECTION_COLOUR: Color32 = Color32::from_rgb(120, 200, 255);

/// Where pinned findings came from, read from their id. Each group can be
/// shown or hidden on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PinnedGroup {
    Templates,
    Segments,
    Similar,
    Changes,
    Crypto,
    Packets,
    Messages,
    Checksums,
    Other,
}

impl PinnedGroup {
    pub const ALL: [PinnedGroup; 9] = [
        PinnedGroup::Templates,
        PinnedGroup::Segments,
        PinnedGroup::Similar,
        PinnedGroup::Changes,
        PinnedGroup::Crypto,
        PinnedGroup::Packets,
        PinnedGroup::Messages,
        PinnedGroup::Checksums,
        PinnedGroup::Other,
    ];

    /// The group a pinned finding belongs to, from the prefix of its id.
    pub fn of(id: &str) -> PinnedGroup {
        const PREFIXES: [(&str, PinnedGroup); 9] = [
            ("template:", PinnedGroup::Templates),
            ("segment:", PinnedGroup::Segments),
            ("similar:", PinnedGroup::Similar),
            ("diff", PinnedGroup::Changes),
            ("changed", PinnedGroup::Changes),
            ("crypto:", PinnedGroup::Crypto),
            ("packet", PinnedGroup::Packets),
            ("message", PinnedGroup::Messages),
            ("checksum", PinnedGroup::Checksums),
        ];
        PREFIXES.iter().find(|(prefix, _)| id.starts_with(prefix)).map_or(PinnedGroup::Other, |&(_, group)| group)
    }

    pub fn label(self) -> &'static str {
        match self {
            PinnedGroup::Templates => "Template",
            PinnedGroup::Segments => "Segments",
            PinnedGroup::Similar => "Similar",
            PinnedGroup::Changes => "Changes",
            PinnedGroup::Crypto => "Crypto",
            PinnedGroup::Packets => "Packet",
            PinnedGroup::Messages => "Messages",
            PinnedGroup::Checksums => "Checksum",
            PinnedGroup::Other => "Pinned",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            PinnedGroup::Templates => "Records decoded by an applied template",
            PinnedGroup::Segments => "Regions from Structure map › Segments",
            PinnedGroup::Similar => "Matches from Structure map › Find more like this",
            PinnedGroup::Changes => "Bytes that differ (Diff) or changed (Live, Compare)",
            PinnedGroup::Crypto => "Crypto constants from the Crypto tool",
            PinnedGroup::Packets => "The packet chosen in the packet viewer",
            PinnedGroup::Messages => "Messages found by the Protocol tool",
            PinnedGroup::Checksums => "A stored checksum found by the Checksums tool",
            PinnedGroup::Other => "Other pinned findings",
        }
    }
}

/// One kind of highlight drawn over the raster and the hex dump.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LayerKind {
    Selection,
    Cursor,
    SearchMatches,
    Bookmarks,
    Pattern(Category),
    /// Fields of the structure at the cursor, outlined when zoomed in.
    Fields,
    Pinned(PinnedGroup),
    PacketSelection,
}

/// Which layers are shown. Pattern highlights keep their own flags in the
/// app (`highlight_patterns` and `pattern_kinds`), and structure fields use
/// `show_structure_fields`; everything else lives here.
#[derive(Clone, Debug)]
pub struct LayerVisibility {
    pub selection: bool,
    pub cursor: bool,
    pub search: bool,
    pub bookmarks: bool,
    pub packet_selection: bool,
    pub hidden_pinned: BTreeSet<PinnedGroup>,
}

impl Default for LayerVisibility {
    fn default() -> Self {
        LayerVisibility { selection: true, cursor: true, search: true, bookmarks: true, packet_selection: true, hidden_pinned: BTreeSet::new() }
    }
}

/// A layer as the legend lists it.
#[derive(Clone, Debug, PartialEq)]
pub struct Layer {
    pub kind: LayerKind,
    pub label: String,
    pub colour: Color32,
    /// What the count means, such as "312 B" or "12".
    pub count: String,
    pub visible: bool,
    pub hint: String,
}

impl ViewerApp {
    /// Whether a highlight layer is being drawn.
    pub fn layer_visible(&self, kind: LayerKind) -> bool {
        let shown = &self.layers;
        match kind {
            LayerKind::Selection => shown.selection,
            LayerKind::Cursor => shown.cursor,
            LayerKind::SearchMatches => shown.search,
            LayerKind::Bookmarks => shown.bookmarks,
            LayerKind::Pattern(category) => self.highlight_patterns && self.pattern_kind_enabled(category),
            LayerKind::Fields => self.show_structure_fields,
            LayerKind::Pinned(group) => !shown.hidden_pinned.contains(&group),
            LayerKind::PacketSelection => shown.packet_selection,
        }
    }

    /// Show or hide a highlight layer.
    pub fn set_layer_visible(&mut self, kind: LayerKind, visible: bool) {
        let shown = &mut self.layers;
        match kind {
            LayerKind::Selection => shown.selection = visible,
            LayerKind::Cursor => shown.cursor = visible,
            LayerKind::SearchMatches => shown.search = visible,
            LayerKind::Bookmarks => shown.bookmarks = visible,
            LayerKind::Pattern(category) => {
                self.pattern_kinds[category.index()] = visible;
                if visible {
                    self.highlight_patterns = true;
                }
            }
            LayerKind::Fields => self.show_structure_fields = visible,
            LayerKind::Pinned(group) => {
                if visible {
                    shown.hidden_pinned.remove(&group);
                } else {
                    shown.hidden_pinned.insert(group);
                }
            }
            LayerKind::PacketSelection => shown.packet_selection = visible,
        }
    }

    /// Whether a pinned finding's group is shown.
    pub fn pinned_visible(&self, finding: &Finding) -> bool {
        self.layer_visible(LayerKind::Pinned(PinnedGroup::of(&finding.id)))
    }

    /// Every layer with something to draw, in the order the legend lists
    /// them. Hidden layers are listed too, so they can be shown again.
    pub fn active_layers(&mut self) -> Vec<Layer> {
        let mut layers = Vec::new();
        let layer = |kind, label: String, colour, count: String, hint: &str, app: &ViewerApp| Layer {
            kind,
            label,
            colour,
            count,
            visible: app.layer_visible(kind),
            hint: hint.to_string(),
        };
        if let Some(description) = self.selection_summary() {
            layers.push(layer(LayerKind::Selection, "Selection".into(), theme::ACCENT, description, "The selected bytes", self));
        }
        if self.cursor < self.document.len() {
            layers.push(layer(LayerKind::Cursor, "Cursor".into(), theme::CURSOR, format!("{:#x}", self.cursor), "The byte typed hex goes to", self));
        }
        let matches = self.search_highlights().len();
        if matches > 0 {
            let count = self.search_count.map_or_else(|| format!("{matches} here"), |total| total.to_string());
            layers.push(layer(LayerKind::SearchMatches, "Matches".into(), SEARCH_COLOUR, count, "Matches of the Find box (F3 for the next)", self));
        }
        if !self.bookmarks.bookmarks.is_empty() {
            let count = self.bookmarks.bookmarks.len().to_string();
            layers.push(layer(LayerKind::Bookmarks, "Bookmarks".into(), theme::CURSOR, count, "Bookmarked bytes (Cmd+B)", self));
        }
        if self.highlight_patterns {
            let counts = self.pattern_counts();
            for category in Category::ALL {
                let count = counts[category.index()];
                if count > 0 {
                    layers.push(layer(LayerKind::Pattern(category), category.label().to_string(), category.colour(), count.to_string(), "Pattern highlight: found by the scan of the view", self));
                }
            }
        }
        if self.zoom >= crate::view::HEX_LABEL_MIN_ZOOM
            && let Some(structure) = &self.cursor_structure
            && !structure.fields.is_empty()
        {
            let count = count_fields(&structure.fields).to_string();
            layers.push(layer(LayerKind::Fields, "Fields".into(), crate::view::FIELD_OUTLINE, count, "Fields of the structure at the cursor, outlined", self));
        }
        for group in PinnedGroup::ALL {
            let members: Vec<&Finding> = self.bench.pinned.iter().filter(|finding| PinnedGroup::of(&finding.id) == group).collect();
            if let Some(first) = members.first() {
                let colour = first.category.colour();
                layers.push(layer(LayerKind::Pinned(group), group.label().to_string(), colour, members.len().to_string(), group.hint(), self));
            }
        }
        let packets = self.packet_selection_ranges();
        if packets.len() > 1 {
            layers.push(layer(LayerKind::PacketSelection, "Packets".into(), PACKET_SELECTION_COLOUR, packets.len().to_string(), "Packets selected in the packet viewer", self));
        }
        layers
    }

    /// The byte ranges a layer draws over `[start, end)`.
    pub fn layer_ranges(&mut self, kind: LayerKind, start: usize, end: usize) -> Vec<(usize, usize)> {
        let overlapping = |range_start: usize, len: usize| range_start < end && range_start + len.max(1) > start;
        match kind {
            LayerKind::Selection => self.selection_ranges().into_iter().filter(|&(s, l)| overlapping(s, l)).collect(),
            LayerKind::Cursor => vec![(self.cursor, 1)],
            LayerKind::SearchMatches => {
                let len = self.search_highlight_len();
                self.search_highlights().iter().copied().filter(|&at| overlapping(at, len)).map(|at| (at, len)).collect()
            }
            LayerKind::Bookmarks => self.bookmarks.bookmarks.iter().map(|b| (b.offset, b.len.max(1))).filter(|&(s, l)| overlapping(s, l)).collect(),
            LayerKind::Pattern(category) => self
                .patterns
                .iter()
                .filter(|finding| finding.category == category && overlapping(finding.start, finding.len))
                .map(|finding| (finding.start, finding.len))
                .collect(),
            LayerKind::Fields => {
                let mut ranges = Vec::new();
                if let Some(structure) = &self.cursor_structure {
                    collect_leaf_ranges(&structure.fields, &mut ranges);
                }
                ranges.retain(|&(s, l)| overlapping(s, l));
                ranges
            }
            LayerKind::Pinned(group) => self
                .bench
                .pinned
                .iter()
                .filter(|finding| PinnedGroup::of(&finding.id) == group && overlapping(finding.start, finding.len))
                .map(|finding| (finding.start, finding.len))
                .collect(),
            LayerKind::PacketSelection => self.packet_selection_ranges().into_iter().filter(|&(s, l)| overlapping(s, l)).collect(),
        }
    }

    /// The document ranges of the packets selected in the packet viewer.
    pub fn packet_selection_ranges(&self) -> Vec<(usize, usize)> {
        let state = &self.bench.panels.packets;
        let Some(set) = state.packet_set() else { return Vec::new() };
        state.selected_packets().into_iter().filter_map(|index| set.packets.get(index)).map(|packet| (packet.offset, packet.len)).collect()
    }
}

/// How many fields a tree holds, nested ones included.
fn count_fields(fields: &[Field]) -> usize {
    fields.iter().map(|field| 1 + count_fields(&field.children)).sum()
}

/// The ranges of every field without children.
fn collect_leaf_ranges(fields: &[Field], out: &mut Vec<(usize, usize)>) {
    for field in fields {
        if field.children.is_empty() {
            out.push((field.offset, field.len));
        } else {
            collect_leaf_ranges(&field.children, out);
        }
    }
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

/// The full legend bar above the raster: the colouring, then every layer.
pub fn show_legend_bar(app: &mut ViewerApp, ui: &mut Ui) {
    let layers = app.active_layers();
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(6.0, 3.0);
        show_colouring(app, ui);
        if !layers.is_empty() {
            ui.separator();
        }
        for layer in &layers {
            layer_chip(app, ui, layer, true);
        }
        if !app.highlight_patterns && !app.patterns.is_empty() {
            let off = ui
                .add(egui::Button::new(RichText::new("Patterns off").small().color(theme::TEXT_DIM)).frame(false))
                .on_hover_text("Pattern highlights are hidden. Click (or press H) to show them again.");
            if off.clicked() {
                app.highlight_patterns = true;
            }
        }
    });
}

/// The condensed legend in the hex dump's header: how the text is coloured,
/// then a swatch and count for each layer.
pub fn show_compact_legend(app: &mut ViewerApp, ui: &mut Ui) {
    let layers = app.active_layers();
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(4.0, 3.0);
        ui.label(RichText::new("text by byte class").small().color(theme::TEXT_DIM))
            .on_hover_text("Hex digits are coloured by byte class: 00, text, control, high bytes and FF");
        class_key(ui);
        if !layers.is_empty() {
            ui.separator();
        }
        for layer in &layers {
            layer_chip(app, ui, layer, false);
        }
    });
}

/// One layer: a swatch and a toggle that names it (or, condensed, only its
/// count). Pointing at it emphasises its overlays in both views.
fn layer_chip(app: &mut ViewerApp, ui: &mut Ui, layer: &Layer, full: bool) {
    let (swatch_rect, swatch) = ui.allocate_exact_size(Vec2::splat(SWATCH_SIZE), Sense::click());
    let colour = if layer.visible { layer.colour } else { layer.colour.gamma_multiply(0.25) };
    ui.painter().rect_filled(swatch_rect, 2.0, colour);
    if !layer.visible {
        ui.painter().rect_stroke(swatch_rect, 2.0, Stroke::new(1.0, theme::OUTLINE), StrokeKind::Inside);
    }
    let text = if full { format!("{} {}", layer.label, layer.count) } else { layer.count.clone() };
    let mut rich = RichText::new(text).small();
    rich = if layer.visible { rich.color(theme::TEXT) } else { rich.color(theme::TEXT_DIM).strikethrough() };
    let button = ui.add(egui::Button::selectable(layer.visible, rich));
    let action = if layer.visible { "hide" } else { "show" };
    let hint = format!("{} {}: {}\nClick to {action}; point to pick it out in the views", layer.label, layer.count, layer.hint);
    let button = button.on_hover_text(hint);
    if button.hovered() || swatch.hovered() {
        app.emphasise_layer(layer.kind);
        ui.ctx().request_repaint();
    }
    if button.clicked() || swatch.clicked() {
        app.set_layer_visible(layer.kind, !layer.visible);
    }
}

/// How the raster's pixels are coloured, with a small key.
fn show_colouring(app: &ViewerApp, ui: &mut Ui) {
    let dim = theme::TEXT_DIM;
    if let Some(curve) = app.bench.layout.curve().filter(|_| app.bench.layout != Layout::Rows) {
        let name = match curve {
            crate::hilbert::Curve::Hilbert => "Hilbert curve",
            crate::hilbert::Curve::Morton => "Morton curve",
        };
        ui.label(RichText::new(format!("{name}, coloured by {}", app.bench.curve_colour.label().to_lowercase())).small().color(dim));
        return;
    }
    if app.colours_regions_now() {
        let source = if app.bench.regions.is_empty() { "block class and entropy" } else { "report region" };
        ui.label(RichText::new(format!("Zoomed out: coloured by {source}")).small().color(theme::TEXT))
            .on_hover_text("Below 1× each part is coloured by what it is. Turn off in View › Colour by region when zoomed out.");
        return;
    }
    let format = app.shape.format;
    let palette = if format.is_signed() { crate::raster::Palette::Diverging } else { app.shape.palette };
    let name = if format.uses_palette() { format!("{} · {}", format.label(), palette.label()) } else { format.label().to_string() };
    ui.label(RichText::new(name).small().color(theme::TEXT)).on_hover_text("Pixel format and palette: how bytes become pixels");
    if format == PixelFormat::ByteClass {
        class_key(ui);
    } else if format.uses_palette() {
        gradient_key(ui, palette).on_hover_text(format!("{} palette: low values on the left, high on the right", palette.label()));
        if let Some(range) = app.value_range {
            ui.label(RichText::new(format!("{} … {}", short_number(range.low), short_number(range.high))).small().monospace().color(dim))
                .on_hover_text("Heatmap range: the 1st to 99th percentile of the visible values");
        }
    } else {
        ui.label(RichText::new("true colour").small().color(dim));
    }
    if app.row_difference.is_active() {
        ui.label(RichText::new(app.row_difference.label()).small().color(theme::CURSOR))
            .on_hover_text("Row difference: each row is drawn compared with the row above, so repeated fields go dark");
    }
}

/// Swatches for zeros, text, control bytes, high bytes and FF.
fn class_key(ui: &mut Ui) {
    let classes = [
        (theme::CLASS_NULL, "00"),
        (theme::CLASS_TEXT, "text"),
        (theme::CLASS_CONTROL, "control"),
        (theme::CLASS_HIGH, "≥ 80"),
        (theme::CLASS_FULL, "FF"),
    ];
    for (colour, label) in classes {
        theme::swatch(ui, colour, label);
    }
}

/// The palette as a small left-to-right gradient.
fn gradient_key(ui: &mut Ui, palette: crate::raster::Palette) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(GRADIENT_SIZE, Sense::hover());
    let table = palette.lut();
    let steps = rect.width().max(1.0) as usize;
    for step in 0..steps {
        let value = step * 255 / steps.max(2).saturating_sub(1).max(1);
        let x = rect.min.x + step as f32;
        let column = Rect::from_min_max(egui::pos2(x, rect.min.y), egui::pos2(x + 1.0, rect.max.y));
        ui.painter().rect_filled(column, 0.0, table[value.min(255)]);
    }
    ui.painter().rect_stroke(rect, 1.0, Stroke::new(1.0, theme::OUTLINE), StrokeKind::Outside);
    response
}

/// A heatmap bound, short enough for the legend.
fn short_number(value: f64) -> String {
    const PLAIN_LIMIT: f64 = 1.0e6;
    if value == value.trunc() && value.abs() < PLAIN_LIMIT { format!("{value:.0}") } else { format!("{value:.3e}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_findings_are_grouped_by_the_tool_that_pinned_them() {
        assert_eq!(PinnedGroup::of("segment:text"), PinnedGroup::Segments);
        assert_eq!(PinnedGroup::of("similar:3"), PinnedGroup::Similar);
        assert_eq!(PinnedGroup::of("diff"), PinnedGroup::Changes);
        assert_eq!(PinnedGroup::of("changed"), PinnedGroup::Changes);
        assert_eq!(PinnedGroup::of("crypto:aes"), PinnedGroup::Crypto);
        assert_eq!(PinnedGroup::of("packet"), PinnedGroup::Packets);
        assert_eq!(PinnedGroup::of("template:png"), PinnedGroup::Templates);
        assert_eq!(PinnedGroup::of("message"), PinnedGroup::Messages);
        assert_eq!(PinnedGroup::of("something else"), PinnedGroup::Other);
    }

    #[test]
    fn field_counts_include_nested_fields() {
        let tree = vec![Field::new("header", 0, 8, "").with_children(vec![Field::new("magic", 0, 4, ""), Field::new("size", 4, 4, "")])];
        assert_eq!(count_fields(&tree), 3);
        let mut leaves = Vec::new();
        collect_leaf_ranges(&tree, &mut leaves);
        assert_eq!(leaves, vec![(0, 4), (4, 4)]);
    }
}
