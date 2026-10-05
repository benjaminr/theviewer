//! The raster panel: draws the visible window of the document as pixels and
//! handles pointer input over it.

use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, Sense, Stroke, StrokeKind, Ui, Vec2, pos2, vec2};

use crate::app::{Shape, ViewerApp};
use crate::plugin::Category;
use crate::theme;

const SCROLLBAR_WIDTH: f32 = 14.0;
const ENTROPY_STRIP_WIDTH: f32 = 22.0;
/// Draw a pixel grid once pixels are at least this large.
const GRID_MIN_ZOOM: f32 = 8.0;

pub fn show_raster(app: &mut ViewerApp, ui: &mut Ui) {
    app.show_file_map(ui);
    if app.bench.layout == crate::workbench::Layout::Hilbert {
        let (rect, _) = ui.allocate_exact_size(ui.available_size(), Sense::hover());
        app.show_hilbert(ui, rect);
        return;
    }
    let (full_rect, _) = ui.allocate_exact_size(ui.available_size(), Sense::hover());
    if full_rect.width() < SCROLLBAR_WIDTH + 1.0 || full_rect.height() < 1.0 {
        return;
    }
    let strip_width = if app.entropy_map.is_some() { ENTROPY_STRIP_WIDTH } else { 0.0 };
    let image_rect = Rect::from_min_max(full_rect.min, pos2(full_rect.max.x - SCROLLBAR_WIDTH - strip_width, full_rect.max.y));
    let strip_rect = Rect::from_min_max(pos2(image_rect.max.x, full_rect.min.y), pos2(image_rect.max.x + strip_width, full_rect.max.y));
    let bar_rect = Rect::from_min_max(pos2(full_rect.max.x - SCROLLBAR_WIDTH, full_rect.min.y), full_rect.max);

    app.raster_rect = Some(image_rect);
    if app.document.is_empty() {
        draw_empty_state(ui, image_rect);
        return;
    }

    let image_response = ui.interact(image_rect, ui.id().with("raster-image"), Sense::click_and_drag());
    let bar_response = ui.interact(bar_rect, ui.id().with("raster-scrollbar"), Sense::click_and_drag());

    if app.fit_width_requested {
        app.fit_width_requested = false;
        let width = ((image_rect.width() - 2.0) / app.zoom).floor().max(1.0) as usize;
        app.shape.width = width.min(crate::app::MAX_WIDTH);
        app.pan_x = 0.0;
    }

    handle_scroll_and_zoom(app, ui, &image_response, image_rect);

    let zoom = app.zoom;
    let visible_rows = ((image_rect.height() / zoom).ceil() as usize + 1).max(1);
    app.visible_rows = visible_rows;
    app.clamp_top_row();

    let max_pan = (app.shape.width as f32 * zoom - image_rect.width()).max(0.0);
    app.pan_x = app.pan_x.clamp(0.0, max_pan);

    let origin = pos2(image_rect.min.x - app.pan_x, image_rect.min.y);
    handle_pointer(app, &image_response, origin, zoom);
    if image_response.secondary_clicked()
        && let Some(pointer) = image_response.interact_pointer_pos()
    {
        let byte = byte_under(app, pointer, origin, zoom);
        app.set_cursor(byte, false);
    }
    {
        let offset = app.cursor;
        image_response.clone().context_menu(|ui| app.context_menu(ui, offset));
    }

    let painter = ui.painter_at(image_rect);
    let shape = app.shape;
    let top_row = app.top_row;
    let total_rows = shape.total_rows(app.document.len());
    let data_rows_visible = total_rows.saturating_sub(top_row);

    if let Some(texture) = app.ensure_texture(ui.ctx(), visible_rows) {
        let size = texture.size();
        let drawn_rows = size[1].min(data_rows_visible);
        let full = Rect::from_min_size(origin, vec2(size[0] as f32 * zoom, size[1] as f32 * zoom));
        let data = Rect::from_min_size(origin, vec2(size[0] as f32 * zoom, drawn_rows as f32 * zoom));
        // Only the rows that hold real data are shown; the rest is background.
        let uv_bottom = if size[1] == 0 { 0.0 } else { drawn_rows as f32 / size[1] as f32 };
        painter.image(texture.id(), data, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, uv_bottom)), Color32::WHITE);
        painter.rect_stroke(full, 0.0, Stroke::new(1.0, theme::OUTLINE), StrokeKind::Outside);
        if drawn_rows < size[1] {
            let y = data.max.y;
            painter.line_segment([pos2(data.min.x, y), pos2(data.max.x, y)], Stroke::new(1.0, theme::ACCENT_DIM));
            painter.text(
                pos2(data.min.x + 6.0, y + 4.0),
                Align2::LEFT_TOP,
                "end of data",
                FontId::proportional(11.0),
                theme::TEXT_DIM,
            );
        }
        if zoom >= GRID_MIN_ZOOM {
            draw_pixel_grid(&painter, data.intersect(image_rect), origin, zoom);
        }
    }

    draw_hex_window(app, &painter, origin, zoom);
    draw_pattern_overlays(app, &painter, origin, zoom);
    {
        let rects_of = |start: usize, len: usize| byte_range_rects(&shape, start, len, top_row, visible_rows, origin, zoom);
        crate::analysis_tabs::draw_pointer_graph(app, &painter, &rects_of);
    }
    if let Some(description) = app.hover.and_then(|offset| app.pattern_at(offset)).map(|p| p.description()) {
        image_response.clone().on_hover_text(description);
    }

    if let Some((start, len)) = app.selection() {
        for rect in byte_range_rects(&shape, start, len, top_row, visible_rows, origin, zoom) {
            painter.rect_filled(rect, 0.0, theme::SELECTION);
            painter.rect_stroke(rect, 0.0, Stroke::new(1.0, theme::ACCENT), StrokeKind::Inside);
        }
    }
    for bookmark in app.bookmarks.bookmarks.clone() {
        for rect in byte_range_rects(&shape, bookmark.offset, bookmark.len.max(1), top_row, visible_rows, origin, zoom) {
            painter.rect_stroke(rect.expand(2.0), 2.0, Stroke::new(1.0, theme::CURSOR), StrokeKind::Outside);
        }
    }
    if let Some(hovered) = app.hover.filter(|&offset| offset != app.cursor) {
        for rect in byte_range_rects(&shape, hovered, 1, top_row, visible_rows, origin, zoom) {
            painter.rect_stroke(rect.expand(0.5), 0.0, Stroke::new(1.0, theme::ACCENT), StrokeKind::Outside);
        }
    }
    if app.cursor < app.document.len() {
        for rect in byte_range_rects(&shape, app.cursor, 1, top_row, visible_rows, origin, zoom) {
            let rect = rect.expand(1.0);
            painter.rect_stroke(rect, 0.0, Stroke::new(2.0, theme::CURSOR), StrokeKind::Outside);
        }
    }

    draw_scrollbar(app, ui, &bar_response, bar_rect);
    if strip_width > 0.0 {
        draw_entropy_strip(app, ui, strip_rect);
    }
}

/// Colour for an entropy value in bits per byte: dark for empty, teal for
/// structured data, amber through white for compressed or random bytes.
fn entropy_colour(bits: f32) -> Color32 {
    let t = (bits / 8.0).clamp(0.0, 1.0);
    let stops: [(f32, Color32); 4] = [
        (0.0, Color32::from_rgb(22, 26, 40)),
        (0.45, theme::ACCENT_DIM),
        (0.8, theme::CURSOR),
        (1.0, Color32::from_rgb(255, 245, 225)),
    ];
    let mut index = 0;
    while index + 2 < stops.len() && t > stops[index + 1].0 {
        index += 1;
    }
    let (t0, a) = stops[index];
    let (t1, b) = stops[index + 1];
    let mix = ((t - t0) / (t1 - t0).max(1e-6)).clamp(0.0, 1.0);
    let channel = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * mix).round() as u8;
    Color32::from_rgb(channel(a.r(), b.r()), channel(a.g(), b.g()), channel(a.b(), b.b()))
}

fn draw_entropy_strip(app: &mut ViewerApp, ui: &Ui, strip_rect: Rect) {
    let Some(map) = app.entropy_map.as_ref() else { return };
    if map.is_empty() {
        return;
    }
    let response = ui.interact(strip_rect, ui.id().with("entropy-strip"), Sense::click());
    let painter = ui.painter_at(strip_rect);
    let block_height = strip_rect.height() / map.len() as f32;
    // Merge runs of blocks that share a pixel row so tall maps stay cheap.
    let mut y = strip_rect.min.y;
    let mut index = 0;
    while index < map.len() {
        let next_y = (y + block_height).max(y + 1.0);
        let mut end = index + 1;
        while end < map.len() && (strip_rect.min.y + end as f32 * block_height) < next_y {
            end += 1;
        }
        let peak = map[index..end].iter().copied().fold(0.0f32, f32::max);
        painter.rect_filled(
            Rect::from_min_max(pos2(strip_rect.min.x + 1.0, y), pos2(strip_rect.max.x - 1.0, next_y)),
            0.0,
            entropy_colour(peak),
        );
        y = strip_rect.min.y + end as f32 * block_height;
        index = end;
    }

    let len = app.document.len().max(1);
    // Finding and bookmark marks on the right half of the strip, mapped over the whole file.
    let mark_x0 = strip_rect.min.x + strip_rect.width() * 0.55;
    let scale = strip_rect.height() / len as f32;
    let mut marks: Vec<(f32, f32, Color32)> = app
        .patterns_in(0, usize::MAX)
        .filter(|f| !f.weak() && !matches!(f.category, Category::Padding | Category::Text | Category::HighEntropy))
        .map(|f| (f.start as f32 * scale, (f.len as f32 * scale).max(1.5), f.category.colour()))
        .collect();
    marks.extend(app.bookmarks.bookmarks.iter().map(|b| (b.offset as f32 * scale, 2.0, theme::CURSOR)));
    for (y, h, colour) in marks {
        painter.rect_filled(
            Rect::from_min_max(pos2(mark_x0, strip_rect.min.y + y), pos2(strip_rect.max.x - 1.0, strip_rect.min.y + y + h)),
            0.0,
            colour,
        );
    }
    // Bracket the region the pattern scan covered.
    if let Some((scan_start, scan_len)) = app.pattern_scan_region() {
        let y0 = strip_rect.min.y + scan_start as f32 * scale;
        let y1 = strip_rect.min.y + (scan_start + scan_len) as f32 * scale;
        painter.line_segment([pos2(mark_x0 - 1.0, y0), pos2(mark_x0 - 1.0, y1)], Stroke::new(1.0, theme::TEXT_DIM));
    }
    if let Some(pointer) = response.hover_pos() {
        let fraction = ((pointer.y - strip_rect.min.y) / strip_rect.height()).clamp(0.0, 1.0);
        let block = ((fraction * map.len() as f32) as usize).min(map.len() - 1);
        let offset = (fraction as f64 * len as f64) as usize;
        painter.line_segment(
            [pos2(strip_rect.min.x, pointer.y), pos2(strip_rect.max.x, pointer.y)],
            Stroke::new(1.0, theme::TEXT),
        );
        response.clone().on_hover_text(format!(
            "Entropy {:.2} bits/byte around {offset:#x}\nClick to jump there",
            map[block]
        ));
        if response.clicked() {
            app.set_cursor(offset, false);
            if let Some((row, _)) = app.shape.pixel_of_byte(offset) {
                app.top_row = row.saturating_sub(app.visible_rows / 3);
                app.clamp_top_row();
            }
            app.reveal_cursor_in_hex(true);
        }
    }
}

/// Outline the bytes the hex dump is currently showing, so it is obvious which
/// part of the picture the text view corresponds to.
fn draw_hex_window(app: &ViewerApp, painter: &egui::Painter, origin: Pos2, zoom: f32) {
    let start = app.hex_top_row * 16;
    let len = (app.hex_visible_rows * 16).min(app.document.len().saturating_sub(start));
    if len == 0 {
        return;
    }
    let rects = byte_range_rects(&app.shape, start, len, app.top_row, app.visible_rows, origin, zoom);
    if rects.is_empty() {
        return;
    }
    let mut bounds = rects[0];
    for rect in &rects {
        bounds = bounds.union(*rect);
    }
    painter.rect_filled(bounds, 0.0, Color32::from_rgba_unmultiplied(64, 196, 182, 18));
    painter.rect_stroke(bounds, 0.0, Stroke::new(1.0, theme::ACCENT_DIM), StrokeKind::Outside);
}

fn draw_pattern_overlays(app: &ViewerApp, painter: &egui::Painter, origin: Pos2, zoom: f32) {
    if !app.highlight_patterns {
        return;
    }
    let shape = app.shape;
    let stride = shape.row_stride();
    let visible_start = shape.byte_offset + app.top_row * stride;
    let visible_end = visible_start + app.visible_rows * stride + 1;
    for pattern in app.patterns_in(visible_start, visible_end) {
        let colour = pattern.category.colour();
        let (fill_alpha, outline) = match pattern.category {
            Category::Padding | Category::HighEntropy => (45, false),
            _ if pattern.weak() => (50, false),
            _ => (90, true),
        };
        let fill = Color32::from_rgba_unmultiplied(colour.r(), colour.g(), colour.b(), fill_alpha);
        for rect in byte_range_rects(&shape, pattern.start, pattern.len, app.top_row, app.visible_rows, origin, zoom) {
            painter.rect_filled(rect, 0.0, fill);
            if outline {
                painter.rect_stroke(rect, 0.0, Stroke::new(1.0, colour.gamma_multiply(0.8)), StrokeKind::Inside);
            }
        }
    }
}

/// Side of the logo shown in an empty view.
const EMPTY_STATE_LOGO_SIZE: f32 = 96.0;

fn draw_empty_state(ui: &Ui, rect: Rect) {
    let painter = ui.painter_at(rect);
    let centre = rect.center();
    let logo_centre = centre - vec2(0.0, 14.0 + EMPTY_STATE_LOGO_SIZE * 0.75);
    crate::logo::paint(&painter, Rect::from_center_size(logo_centre, Vec2::splat(EMPTY_STATE_LOGO_SIZE)));
    painter.text(
        centre - vec2(0.0, 14.0),
        Align2::CENTER_CENTER,
        "Drop a file here",
        FontId::proportional(22.0),
        theme::TEXT,
    );
    painter.text(
        centre + vec2(0.0, 14.0),
        Align2::CENTER_CENTER,
        "or press Cmd+O to open one — any file works",
        FontId::proportional(14.0),
        theme::TEXT_DIM,
    );
}

fn draw_pixel_grid(painter: &egui::Painter, area: Rect, origin: Pos2, zoom: f32) {
    if area.width() <= 0.0 || area.height() <= 0.0 {
        return;
    }
    let stroke = Stroke::new(1.0, Color32::from_rgba_premultiplied(0, 0, 0, 70));
    let first_col = ((area.min.x - origin.x) / zoom).floor() as i64;
    let last_col = ((area.max.x - origin.x) / zoom).ceil() as i64;
    for col in first_col..=last_col {
        let x = origin.x + col as f32 * zoom;
        painter.line_segment([pos2(x, area.min.y), pos2(x, area.max.y)], stroke);
    }
    let first_row = ((area.min.y - origin.y) / zoom).floor() as i64;
    let last_row = ((area.max.y - origin.y) / zoom).ceil() as i64;
    for row in first_row..=last_row {
        let y = origin.y + row as f32 * zoom;
        painter.line_segment([pos2(area.min.x, y), pos2(area.max.x, y)], stroke);
    }
}

fn handle_scroll_and_zoom(app: &mut ViewerApp, ui: &Ui, response: &egui::Response, image_rect: Rect) {
    if !response.hovered() {
        return;
    }
    let (scroll, zoom_delta, hover) = ui.input(|i| (i.smooth_scroll_delta, i.zoom_delta(), i.pointer.hover_pos()));
    if (zoom_delta - 1.0).abs() > 1e-4 {
        // Keep the row under the pointer fixed while zooming.
        let pointer_y = hover.map(|p| p.y - image_rect.min.y).unwrap_or(0.0);
        let row_under_pointer = app.top_row as f32 + pointer_y / app.zoom;
        app.apply_zoom_delta(zoom_delta);
        let new_top = row_under_pointer - pointer_y / app.zoom;
        app.top_row = new_top.max(0.0) as usize;
        app.clamp_top_row();
        app.sync_hex_to_raster();
    } else {
        if scroll.y != 0.0 {
            app.scroll_rows(-scroll.y / app.zoom);
        }
        if scroll.x != 0.0 {
            app.pan_x -= scroll.x;
        }
    }
}

fn byte_under(app: &ViewerApp, pointer: Pos2, origin: Pos2, zoom: f32) -> usize {
    let shape = app.shape;
    let col = (((pointer.x - origin.x) / zoom).floor().max(0.0) as usize).min(shape.width.saturating_sub(1));
    let row = ((pointer.y - origin.y) / zoom).floor().max(0.0) as usize + app.top_row;
    shape.byte_of_pixel(row, col).min(app.document.len().saturating_sub(1))
}

fn handle_pointer(app: &mut ViewerApp, response: &egui::Response, origin: Pos2, zoom: f32) {
    if let Some(pointer) = response.hover_pos() {
        app.hover = Some(byte_under(app, pointer, origin, zoom));
    }
    if response.hovered() {
        response.ctx.set_cursor_icon(egui::CursorIcon::Crosshair);
    }
    let Some(pointer) = response.interact_pointer_pos() else {
        return;
    };
    let byte = byte_under(app, pointer, origin, zoom);
    let shift = response.ctx.input(|i| i.modifiers.shift);
    if response.secondary_clicked() || response.dragged_by(egui::PointerButton::Secondary) {
        return;
    }
    if response.drag_started_by(egui::PointerButton::Primary) {
        app.begin_drag_selection(byte, shift);
        app.reveal_cursor_in_hex(true);
    } else if response.dragged_by(egui::PointerButton::Primary) {
        app.drag_selection_to(byte);
        app.reveal_cursor_in_hex(false);
    } else if response.clicked() {
        app.set_cursor(byte, shift);
        app.reveal_cursor_in_hex(true);
    }
    if response.drag_stopped() {
        app.end_drag_selection();
    }
}

/// Screen rectangles covering bytes `[start, start + len)` within the visible
/// rows, one rectangle per row touched.
fn byte_range_rects(
    shape: &Shape,
    start: usize,
    len: usize,
    top_row: usize,
    visible_rows: usize,
    origin: Pos2,
    zoom: f32,
) -> Vec<Rect> {
    let mut rects = Vec::new();
    if len == 0 {
        return rects;
    }
    let end = start + len;
    let stride = shape.row_stride();
    let row_bytes = shape.row_bytes() + usize::from(shape.bit_offset > 0);
    let bits_per_pixel = shape.bits_per_pixel();
    let bit_offset = shape.bit_offset as usize;

    let first_row = shape.pixel_of_byte(start).map(|(row, _)| row).unwrap_or(0).max(top_row);
    let last_row = (top_row + visible_rows).min(shape.pixel_of_byte(end - 1).map(|(row, _)| row + 1).unwrap_or(0));
    for row in first_row..last_row {
        let row_start = shape.byte_offset + row * stride;
        let lo = start.max(row_start);
        let hi = end.min(row_start + row_bytes);
        if lo >= hi {
            continue;
        }
        let lo_bits = ((lo - row_start) * 8).saturating_sub(bit_offset);
        let hi_bits = ((hi - row_start) * 8).saturating_sub(bit_offset);
        let col0 = lo_bits / bits_per_pixel;
        if col0 >= shape.width {
            continue;
        }
        let col1 = hi_bits.div_ceil(bits_per_pixel).clamp(col0 + 1, shape.width);
        let y = origin.y + (row - top_row) as f32 * zoom;
        let x0 = origin.x + col0 as f32 * zoom;
        let x1 = origin.x + col1 as f32 * zoom;
        rects.push(Rect::from_min_max(pos2(x0, y), pos2(x1, y + zoom)));
    }
    rects
}

fn draw_scrollbar(app: &mut ViewerApp, ui: &Ui, response: &egui::Response, bar_rect: Rect) {
    let painter = ui.painter_at(bar_rect);
    painter.rect_filled(bar_rect, 0.0, theme::PANEL);

    let total_rows = app.shape.total_rows(app.document.len()).max(1) as f64;
    let visible = (app.visible_rows as f64).min(total_rows);
    let track_height = bar_rect.height() as f64;
    let thumb_height = ((visible / total_rows) * track_height).max(24.0).min(track_height);
    let scrollable = (total_rows - visible).max(1.0);

    if let Some(pointer) = response.interact_pointer_pos()
        && (response.dragged() || response.clicked())
    {
        let fraction = ((pointer.y as f64 - bar_rect.min.y as f64 - thumb_height / 2.0)
            / (track_height - thumb_height).max(1.0))
        .clamp(0.0, 1.0);
        app.top_row = (fraction * scrollable).round() as usize;
        app.clamp_top_row();
    }

    let fraction = (app.top_row as f64 / scrollable).clamp(0.0, 1.0);
    let thumb_top = bar_rect.min.y as f64 + fraction * (track_height - thumb_height);
    let thumb = Rect::from_min_size(
        pos2(bar_rect.min.x + 3.0, thumb_top as f32),
        Vec2::new(bar_rect.width() - 6.0, thumb_height as f32),
    );
    let colour = if response.hovered() || response.dragged() { theme::ACCENT } else { theme::OUTLINE };
    painter.rect_filled(thumb, 4.0, colour);
    if response.hovered() || response.dragged() {
        let label = format!("row {}", app.top_row);
        let pos = pos2(bar_rect.min.x - 6.0, thumb.center().y);
        let galley = painter.layout_no_wrap(label, FontId::proportional(11.0), theme::TEXT);
        let background = Rect::from_center_size(pos - vec2(galley.size().x / 2.0, 0.0), galley.size() + vec2(8.0, 4.0));
        painter.rect_filled(background, 3.0, theme::SURFACE_RAISED);
        painter.galley(background.min + vec2(4.0, 2.0), galley, theme::TEXT);
    }
}
