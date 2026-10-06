//! Colour scheme and shared UI building blocks.
//!
//! A restrained graphite palette with one cool accent (teal) for interactive
//! state and one warm accent (amber) for the cursor, so the data itself stays
//! the most colourful thing on screen.

use eframe::egui::{self, Color32, CornerRadius, Frame, Label, Margin, RichText, Stroke, Ui, Vec2, Visuals};


pub const BACKGROUND: Color32 = Color32::from_rgb(20, 22, 27);
pub const PANEL: Color32 = Color32::from_rgb(30, 33, 40);
pub const SURFACE: Color32 = Color32::from_rgb(38, 42, 51);
pub const SURFACE_RAISED: Color32 = Color32::from_rgb(48, 53, 64);
pub const OUTLINE: Color32 = Color32::from_rgb(60, 66, 79);
pub const TEXT: Color32 = Color32::from_rgb(222, 226, 232);
pub const TEXT_DIM: Color32 = Color32::from_rgb(138, 146, 160);
pub const ACCENT: Color32 = Color32::from_rgb(64, 196, 182);
pub const ACCENT_DIM: Color32 = Color32::from_rgb(38, 110, 104);
pub const CURSOR: Color32 = Color32::from_rgb(255, 184, 56);
pub const SELECTION: Color32 = Color32::from_rgba_premultiplied(30, 100, 94, 120);
pub const CURSOR_FILL: Color32 = Color32::from_rgba_premultiplied(80, 58, 18, 80);
/// Bytes a panel's row is pointing at.
pub const POINTED_FILL: Color32 = Color32::from_rgba_premultiplied(90, 66, 20, 90);
pub const DANGER: Color32 = Color32::from_rgb(235, 96, 88);
/// Markers where bytes are skipped (folded out of the views).
pub const FOLD: Color32 = Color32::from_rgb(214, 132, 255);

/// Colours used for the hex dump and the "byte class" pixel format.
pub const CLASS_NULL: Color32 = Color32::from_rgb(70, 76, 88);
pub const CLASS_TEXT: Color32 = Color32::from_rgb(110, 170, 255);
pub const CLASS_CONTROL: Color32 = Color32::from_rgb(90, 205, 130);
pub const CLASS_HIGH: Color32 = Color32::from_rgb(255, 125, 95);
pub const CLASS_FULL: Color32 = Color32::from_rgb(245, 245, 250);

pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    let mut visuals = Visuals::dark();
    visuals.override_text_color = Some(TEXT);
    visuals.weak_text_color = Some(TEXT_DIM);
    visuals.panel_fill = PANEL;
    visuals.window_fill = SURFACE;
    visuals.window_stroke = Stroke::new(1.0, OUTLINE);
    visuals.window_corner_radius = CornerRadius::same(8);
    visuals.extreme_bg_color = BACKGROUND;
    visuals.faint_bg_color = Color32::from_rgb(34, 37, 45);
    visuals.code_bg_color = BACKGROUND;
    visuals.text_edit_bg_color = Some(BACKGROUND);
    visuals.hyperlink_color = ACCENT;
    visuals.warn_fg_color = CURSOR;
    visuals.error_fg_color = DANGER;
    visuals.selection.bg_fill = ACCENT_DIM;
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    visuals.slider_trailing_fill = true;

    let radius = CornerRadius::same(5);
    let widgets = &mut visuals.widgets;
    widgets.noninteractive.bg_fill = PANEL;
    widgets.noninteractive.weak_bg_fill = PANEL;
    widgets.noninteractive.bg_stroke = Stroke::new(1.0, OUTLINE);
    widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_DIM);
    widgets.noninteractive.corner_radius = radius;

    widgets.inactive.bg_fill = SURFACE_RAISED;
    widgets.inactive.weak_bg_fill = SURFACE;
    widgets.inactive.bg_stroke = Stroke::NONE;
    widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    widgets.inactive.corner_radius = radius;

    widgets.hovered.bg_fill = Color32::from_rgb(60, 66, 80);
    widgets.hovered.weak_bg_fill = Color32::from_rgb(54, 59, 72);
    widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT_DIM);
    widgets.hovered.fg_stroke = Stroke::new(1.5, Color32::WHITE);
    widgets.hovered.corner_radius = radius;

    widgets.active.bg_fill = ACCENT_DIM;
    widgets.active.weak_bg_fill = ACCENT_DIM;
    widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    widgets.active.fg_stroke = Stroke::new(2.0, Color32::WHITE);
    widgets.active.corner_radius = radius;

    widgets.open.bg_fill = SURFACE_RAISED;
    widgets.open.weak_bg_fill = SURFACE_RAISED;
    widgets.open.bg_stroke = Stroke::new(1.0, ACCENT_DIM);
    widgets.open.fg_stroke = Stroke::new(1.0, TEXT);
    widgets.open.corner_radius = radius;

    ctx.set_visuals(visuals);
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = Vec2::new(6.0, 6.0);
        style.spacing.button_padding = Vec2::new(8.0, 3.0);
        style.spacing.interact_size = Vec2::new(32.0, 22.0);
        style.spacing.slider_width = 160.0;
        style.spacing.combo_width = 120.0;
    });
}

/// A framed, captioned group of related controls laid out horizontally.
/// Toolbar groups are placed by [`crate::packing::RowPacker`].
pub fn group<R>(ui: &mut Ui, caption: &str, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
    Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, OUTLINE))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                // Not selectable, so a drag on the caption moves the group.
                ui.add(Label::new(RichText::new(caption).small().color(TEXT_DIM)).selectable(false));
                ui.horizontal(|ui| add_contents(ui)).inner
            })
            .inner
        })
        .inner
}

/// A small coloured square followed by a label, used for legends.
pub fn swatch(ui: &mut Ui, colour: Color32, label: &str) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 2.0, colour);
    ui.label(RichText::new(label).small().color(TEXT_DIM));
}

/// A key cap used in the help window.
pub fn keycap(ui: &mut Ui, keys: &str) {
    ui.label(
        RichText::new(keys)
            .monospace()
            .color(TEXT)
            .background_color(SURFACE_RAISED),
    );
}
