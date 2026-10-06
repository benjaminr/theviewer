//! The raster panel: draws the visible window of the document as pixels and
//! handles pointer input over it.

use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, Sense, Stroke, StrokeKind, Ui, Vec2, pos2, vec2};

use crate::app::{Shape, ViewerApp};
use crate::legend::{self, LayerKind, PinnedGroup};
use crate::plugin::{Category, Field, Finding};
use crate::raster::{self, PixelFormat};
use crate::theme;

const SCROLLBAR_WIDTH: f32 = 14.0;
const ENTROPY_STRIP_WIDTH: f32 = 22.0;
/// Draw a pixel grid once pixels are at least this large.
const GRID_MIN_ZOOM: f32 = 8.0;

pub fn show_raster(app: &mut ViewerApp, ui: &mut Ui) {
    app.hex_labels_drawn = 0;
    app.field_outlines_drawn = 0;
    app.overlays_drawn.clear();
    legend::show_legend_bar(app, ui);
    app.show_file_map(ui);
    if app.bench.layout != crate::workbench::Layout::Rows {
        let (rect, _) = ui.allocate_exact_size(ui.available_size(), Sense::hover());
        app.show_curve(ui, rect);
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

    let texture = app.ensure_texture(ui.ctx(), visible_rows).map(|texture| (texture.id(), texture.size()));
    let mut drawn_rows = 0;
    if let Some((texture_id, size)) = texture {
        drawn_rows = size[1].min(data_rows_visible);
        let full = Rect::from_min_size(origin, vec2(size[0] as f32 * zoom, size[1] as f32 * zoom));
        let data = Rect::from_min_size(origin, vec2(size[0] as f32 * zoom, drawn_rows as f32 * zoom));
        // Only the rows that hold real data are shown; the rest is background.
        let uv_bottom = if size[1] == 0 { 0.0 } else { drawn_rows as f32 / size[1] as f32 };
        painter.image(texture_id, data, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, uv_bottom)), Color32::WHITE);
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
    let geometry = Geometry { shape, top_row, visible_rows, origin, zoom };
    draw_pattern_overlays(app, &painter, &geometry);
    draw_pinned_overlays(app, &painter, &geometry);
    {
        let rects_of = |start: usize, len: usize| geometry.rects(start, len);
        crate::analysis_tabs::draw_pointer_graph(app, &painter, &rects_of);
    }
    if let Some(description) = app.hover.and_then(|offset| app.pattern_at(offset)).map(|p| p.description()) {
        image_response.clone().on_hover_text(description);
    }
    draw_search_matches(app, &painter, &geometry);
    draw_packet_selection(app, &painter, &geometry);
    draw_selection(app, &painter, &geometry);
    if app.layer_visible(LayerKind::Bookmarks) {
        let mut drawn = 0;
        for bookmark in app.bookmarks.bookmarks.clone() {
            for rect in geometry.rects(bookmark.offset, bookmark.len.max(1)) {
                painter.rect_stroke(rect.expand(2.0), 2.0, Stroke::new(1.0, theme::CURSOR), StrokeKind::Outside);
                drawn += 1;
            }
        }
        note_drawn(app, LayerKind::Bookmarks, drawn);
    }
    if let Some(hovered) = app.hover.filter(|&offset| offset != app.cursor) {
        for rect in geometry.rects(hovered, 1) {
            painter.rect_stroke(rect.expand(0.5), 0.0, Stroke::new(1.0, theme::ACCENT), StrokeKind::Outside);
        }
    }
    if app.cursor < app.document.len() && app.layer_visible(LayerKind::Cursor) {
        let rects = geometry.rects(app.cursor, 1);
        note_drawn(app, LayerKind::Cursor, rects.len());
        for rect in rects {
            painter.rect_stroke(rect.expand(1.0), 0.0, Stroke::new(2.0, theme::CURSOR), StrokeKind::Outside);
        }
    }
    if zoom >= HEX_LABEL_MIN_ZOOM {
        let mut budget = MAX_TEXT_SHAPES_PER_FRAME;
        if app.show_pixel_values {
            app.hex_labels_drawn = draw_pixel_labels(app, &painter, image_rect, origin, drawn_rows, &mut budget);
        }
        app.field_outlines_drawn = draw_field_outlines(app, &painter, origin, &mut budget);
    }
    draw_emphasis(app, &painter, &geometry, image_rect);

    draw_scrollbar(app, ui, &bar_response, bar_rect);
    if strip_width > 0.0 {
        draw_entropy_strip(app, ui, strip_rect);
    }
}

/// Font size of the values drawn inside pixels at high zoom.
const PIXEL_LABEL_FONT_SIZE: f32 = 11.0;
/// Advance of one monospace glyph as a fraction of the font size.
const MONOSPACE_ADVANCE_RATIO: f32 = 0.62;
/// Height of one line of text as a fraction of the font size.
const LINE_HEIGHT_RATIO: f32 = 1.2;
/// Clear space kept between a pixel's value and each edge of the pixel.
const PIXEL_LABEL_PADDING: f32 = 4.0;
/// Hex digits needed to write one byte.
const HEX_DIGITS_PER_BYTE: usize = 2;
/// Width of `chars` monospace glyphs plus the padding on both sides.
const fn label_extent(chars: usize) -> f32 {
    chars as f32 * PIXEL_LABEL_FONT_SIZE * MONOSPACE_ADVANCE_RATIO + 2.0 * PIXEL_LABEL_PADDING
}
/// Smallest zoom at which a byte's two hex digits fit inside its pixel
/// (about 22 px). Template field outlines appear from the same zoom.
pub const HEX_LABEL_MIN_ZOOM: f32 = label_extent(HEX_DIGITS_PER_BYTE);
/// Most text shapes (pixel values and field names) drawn in one frame. When
/// the visible pixels would need more, their values are skipped altogether.
pub const MAX_TEXT_SHAPES_PER_FRAME: usize = 6000;
/// Font size of a field's name on its outline.
const FIELD_LABEL_FONT_SIZE: f32 = 9.0;
/// Space between a field's name and the edge of its backing.
const FIELD_LABEL_PADDING: f32 = 2.0;
/// Fields outlined in one frame at most, so huge templates stay fast.
const MAX_FIELD_OUTLINES_PER_FRAME: usize = 4000;
/// Outline of a template or structure field at high zoom.
pub const FIELD_OUTLINE: Color32 = Color32::from_rgb(255, 214, 102);
/// Backing behind a field's name, so it reads over any pixel colour.
const FIELD_LABEL_BACKING: Color32 = Color32::from_rgba_premultiplied(0, 0, 0, 190);
/// Perceived brightness (0 to 255) above which dark text reads better.
const LUMINANCE_MIDPOINT: f32 = 140.0;

/// Black or white, whichever reads better on `background`, judged by its
/// perceived (Rec. 709) luminance.
pub fn contrasting_text_colour(background: Color32) -> Color32 {
    let luminance = 0.2126 * background.r() as f32 + 0.7152 * background.g() as f32 + 0.0722 * background.b() as f32;
    if luminance >= LUMINANCE_MIDPOINT { Color32::BLACK } else { Color32::WHITE }
}

/// Text written inside pixel `col` of a row whose (transformed) bytes are
/// `row_bytes`: the bit or nibble for sub-byte formats, otherwise the pixel's
/// bytes in hex, wrapped onto as many lines as fit. `None` when the text
/// cannot fit in a pixel `zoom` points square.
pub fn pixel_label(format: PixelFormat, row_bytes: &[u8], col: usize, zoom: f32) -> Option<String> {
    let bits = format.bits_per_pixel();
    let first_byte = col * bits / 8;
    if bits < 8 {
        let byte = *row_bytes.get(first_byte)?;
        let value = match format {
            PixelFormat::Bit1Msb => (byte >> (7 - col % 8)) & 1,
            PixelFormat::Bit1Lsb => (byte >> (col % 8)) & 1,
            _ if col.is_multiple_of(2) => byte >> 4,
            _ => byte & 0x0F,
        };
        return (label_extent(1) <= zoom).then(|| format!("{value:X}"));
    }
    let bytes = row_bytes.get(first_byte..first_byte + bits / 8)?;
    let byte_width = label_extent(HEX_DIGITS_PER_BYTE) - 2.0 * PIXEL_LABEL_PADDING;
    let bytes_per_line = ((zoom - 2.0 * PIXEL_LABEL_PADDING) / byte_width).floor() as usize;
    if bytes_per_line == 0 {
        return None;
    }
    let lines = bytes.len().div_ceil(bytes_per_line);
    let height = lines as f32 * PIXEL_LABEL_FONT_SIZE * LINE_HEIGHT_RATIO + 2.0 * PIXEL_LABEL_PADDING;
    if height > zoom {
        return None;
    }
    let text = bytes
        .chunks(bytes_per_line)
        .map(|line| line.iter().map(|byte| format!("{byte:02X}")).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");
    Some(text)
}

/// Write each visible pixel's value inside it, in black or white to contrast
/// with the pixel. Only pixels on screen are labelled, and nothing is drawn
/// when they would need more than `budget` text shapes. Returns how many
/// labels were drawn and takes them from `budget`.
fn draw_pixel_labels(
    app: &ViewerApp,
    painter: &egui::Painter,
    image_rect: Rect,
    origin: Pos2,
    drawn_rows: usize,
    budget: &mut usize,
) -> usize {
    let shape = app.shape;
    let zoom = app.zoom;
    let bits = shape.bits_per_pixel();
    let stride = shape.row_stride();
    let first_col = ((image_rect.min.x - origin.x) / zoom).floor().max(0.0) as usize;
    let last_col = (((image_rect.max.x - origin.x) / zoom).ceil().max(0.0) as usize).min(shape.width);
    let rows = drawn_rows.min((image_rect.height() / zoom).ceil() as usize);
    if first_col >= last_col || rows == 0 || (last_col - first_col) * rows > *budget {
        return 0;
    }
    // Sub-byte formats are re-rasterised from a byte boundary.
    let pixels_per_byte = (8 / bits).max(1);
    let aligned_col = first_col / pixels_per_byte * pixels_per_byte;
    let columns = last_col - aligned_col;
    let first_byte = aligned_col * bits / 8;
    let segment_bytes = shape.format.bytes_for_pixels(columns);
    let raster_bytes = app.raster_bytes();
    let document_len = app.document.len();
    let font = FontId::monospace(PIXEL_LABEL_FONT_SIZE);
    let mut colours = vec![Color32::BLACK; columns];
    let mut drawn = 0;
    for row in 0..rows {
        let row_start = row * stride;
        let Some(row_bytes) = raster_bytes.get(row_start..row_start + shape.row_bytes()) else { break };
        let Some(segment) = row_bytes.get(first_byte..first_byte + segment_bytes) else { break };
        let style = raster::RasterStyle { format: shape.format, palette: shape.palette, range: app.value_range };
        raster::rasterise_styled(style, segment, columns, 1, segment_bytes, &mut colours);
        for col in first_col..last_col {
            if shape.byte_of_pixel(app.top_row + row, col) >= document_len {
                break;
            }
            let Some(text) = pixel_label(shape.format, row_bytes, col, zoom) else { continue };
            let centre = origin + vec2((col as f32 + 0.5) * zoom, (row as f32 + 0.5) * zoom);
            let colour = contrasting_text_colour(colours[col - aligned_col]);
            painter.text(centre, Align2::CENTER_CENTER, text, font.clone(), colour);
            drawn += 1;
        }
    }
    *budget -= drawn;
    drawn
}

/// Outline every template and structure field on screen and name it where
/// the name fits: fields of pinned findings (applied templates) and of the
/// structure at the cursor. Returns how many fields were outlined.
fn draw_field_outlines(app: &ViewerApp, painter: &egui::Painter, origin: Pos2, budget: &mut usize) -> usize {
    let shape = app.shape;
    let zoom = app.zoom;
    let stride = shape.row_stride();
    let visible_start = shape.byte_offset + app.top_row * stride;
    let visible_end = visible_start + app.visible_rows * stride + 1;
    let mut structures: Vec<&Finding> = app.bench.pinned.iter().filter(|finding| !finding.fields.is_empty() && app.pinned_visible(finding)).collect();
    if app.show_structure_fields
        && let Some(structure) = app.cursor_structure.as_ref()
        && !structures.iter().any(|pinned| pinned.id == structure.id && pinned.start == structure.start)
    {
        structures.push(structure);
    }
    let mut fields: Vec<&Field> = Vec::new();
    for structure in structures {
        collect_visible_fields(&structure.fields, visible_start, visible_end, &mut fields);
    }
    let font = FontId::proportional(FIELD_LABEL_FONT_SIZE);
    for field in &fields {
        let rects = byte_range_rects(&shape, field.offset, field.len, app.top_row, app.visible_rows, origin, zoom);
        let leaf = field.children.is_empty();
        let stroke = if leaf { Stroke::new(1.5, FIELD_OUTLINE) } else { Stroke::new(1.0, FIELD_OUTLINE.gamma_multiply(0.6)) };
        for rect in &rects {
            painter.rect_stroke(*rect, 0.0, stroke, StrokeKind::Inside);
        }
        // Name leaf fields only, so nested names do not pile up on one corner.
        let Some(first) = rects.first().filter(|_| leaf && *budget > 0) else { continue };
        let galley = painter.layout_no_wrap(field.name.clone(), font.clone(), FIELD_OUTLINE);
        let backing = Rect::from_min_size(first.min, galley.size() + Vec2::splat(2.0 * FIELD_LABEL_PADDING));
        if backing.width() > first.width() || backing.height() > first.height() {
            continue;
        }
        painter.rect_filled(backing, 2.0, FIELD_LABEL_BACKING);
        painter.galley(backing.min + Vec2::splat(FIELD_LABEL_PADDING), galley, FIELD_OUTLINE);
        *budget -= 1;
    }
    fields.len()
}

/// Every field (and nested field) overlapping `[start, end)`, outermost
/// first, up to the per-frame limit.
fn collect_visible_fields<'a>(fields: &'a [Field], start: usize, end: usize, out: &mut Vec<&'a Field>) {
    for field in fields {
        if out.len() >= MAX_FIELD_OUTLINES_PER_FRAME {
            return;
        }
        if field.len == 0 || field.offset >= end || field.end() <= start {
            continue;
        }
        out.push(field);
        collect_visible_fields(&field.children, start, end, out);
    }
}

/// Colour for an entropy value in bits per byte: dark for empty, teal for
/// structured data, amber through white for compressed or random bytes.
pub fn entropy_colour(bits: f32) -> Color32 {
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

/// Where the raster's rows sit on screen this frame, for turning byte
/// ranges into rectangles.
pub struct Geometry {
    pub shape: Shape,
    pub top_row: usize,
    pub visible_rows: usize,
    pub origin: Pos2,
    pub zoom: f32,
}

impl Geometry {
    /// Screen rectangles covering bytes `[start, start + len)`, one per row.
    pub fn rects(&self, start: usize, len: usize) -> Vec<Rect> {
        byte_range_rects(&self.shape, start, len, self.top_row, self.visible_rows, self.origin, self.zoom)
    }

    /// The document bytes the visible rows cover, as `(start, end)`.
    pub fn visible_bytes(&self) -> (usize, usize) {
        let stride = self.shape.row_stride();
        let start = self.shape.byte_offset + self.top_row * stride;
        (start, start + self.visible_rows * stride + 1)
    }
}

/// Count `rects` overlay rectangles towards `kind` for this frame.
fn note_drawn(app: &mut ViewerApp, kind: LayerKind, rects: usize) {
    if rects > 0 {
        *app.overlays_drawn.entry(kind).or_default() += rects;
    }
}

/// Fill (and for confident findings outline) one finding's bytes in its
/// category colour. Returns the rectangles drawn.
fn draw_finding(painter: &egui::Painter, geometry: &Geometry, finding: &Finding) -> usize {
    let colour = finding.category.colour();
    let (fill_alpha, outline) = match finding.category {
        Category::Padding | Category::HighEntropy => (45, false),
        _ if finding.weak() => (50, false),
        _ => (90, true),
    };
    let fill = Color32::from_rgba_unmultiplied(colour.r(), colour.g(), colour.b(), fill_alpha);
    let rects = geometry.rects(finding.start, finding.len);
    for rect in &rects {
        painter.rect_filled(*rect, 0.0, fill);
        if outline {
            painter.rect_stroke(*rect, 0.0, Stroke::new(1.0, colour.gamma_multiply(0.8)), StrokeKind::Inside);
        }
    }
    rects.len()
}

/// Pattern highlights: the findings of the scan, by kind, when shown.
fn draw_pattern_overlays(app: &mut ViewerApp, painter: &egui::Painter, geometry: &Geometry) {
    if !app.highlight_patterns {
        return;
    }
    let (visible_start, visible_end) = geometry.visible_bytes();
    let mut drawn: Vec<(LayerKind, usize)> = Vec::new();
    for finding in app.patterns.iter().filter(|f| app.pattern_kind_enabled(f.category) && f.start < visible_end && f.end() > visible_start) {
        drawn.push((LayerKind::Pattern(finding.category), draw_finding(painter, geometry, finding)));
    }
    for (kind, rects) in drawn {
        note_drawn(app, kind, rects);
    }
}

/// Findings pinned by the tools, each group when shown.
fn draw_pinned_overlays(app: &mut ViewerApp, painter: &egui::Painter, geometry: &Geometry) {
    let (visible_start, visible_end) = geometry.visible_bytes();
    let mut drawn: Vec<(LayerKind, usize)> = Vec::new();
    for finding in app.bench.pinned.iter().filter(|f| f.start < visible_end && f.end() > visible_start) {
        let kind = LayerKind::Pinned(PinnedGroup::of(&finding.id));
        if app.layer_visible(kind) {
            drawn.push((kind, draw_finding(painter, geometry, finding)));
        }
    }
    for (kind, rects) in drawn {
        note_drawn(app, kind, rects);
    }
}

/// Outline every match of the Find box on screen.
fn draw_search_matches(app: &mut ViewerApp, painter: &egui::Painter, geometry: &Geometry) {
    if !app.layer_visible(LayerKind::SearchMatches) {
        return;
    }
    let (start, end) = geometry.visible_bytes();
    let ranges = app.layer_ranges(LayerKind::SearchMatches, start, end);
    let mut drawn = 0;
    let fill = legend::SEARCH_COLOUR.gamma_multiply(0.35);
    for (at, len) in ranges {
        for rect in geometry.rects(at, len) {
            painter.rect_filled(rect, 0.0, fill);
            painter.rect_stroke(rect, 0.0, Stroke::new(1.0, legend::SEARCH_COLOUR), StrokeKind::Inside);
            drawn += 1;
        }
    }
    note_drawn(app, LayerKind::SearchMatches, drawn);
}

/// Outline the packets selected in the packet viewer, when there are several.
fn draw_packet_selection(app: &mut ViewerApp, painter: &egui::Painter, geometry: &Geometry) {
    let ranges = app.packet_selection_ranges();
    if ranges.len() < 2 || !app.layer_visible(LayerKind::PacketSelection) {
        return;
    }
    let mut drawn = 0;
    for (start, len) in ranges {
        for rect in geometry.rects(start, len) {
            painter.rect_stroke(rect, 0.0, Stroke::new(1.5, legend::PACKET_SELECTION_COLOUR), StrokeKind::Inside);
            drawn += 1;
        }
    }
    note_drawn(app, LayerKind::PacketSelection, drawn);
}

/// Fill and outline the selected bytes.
fn draw_selection(app: &mut ViewerApp, painter: &egui::Painter, geometry: &Geometry) {
    if !app.layer_visible(LayerKind::Selection) {
        return;
    }
    let mut drawn = 0;
    let (visible_start, visible_end) = geometry.visible_bytes();
    for (start, len) in app.selection_ranges_in(visible_start, visible_end) {
        for rect in geometry.rects(start, len) {
            painter.rect_filled(rect, 0.0, theme::SELECTION);
            painter.rect_stroke(rect, 0.0, Stroke::new(1.0, theme::ACCENT), StrokeKind::Inside);
            drawn += 1;
        }
    }
    note_drawn(app, LayerKind::Selection, drawn);
}

/// While the legend points at a layer, darken the picture and outline only
/// that layer's overlays, so it is obvious which highlights it means.
fn draw_emphasis(app: &mut ViewerApp, painter: &egui::Painter, geometry: &Geometry, image_rect: Rect) {
    let Some(kind) = app.emphasised_layer() else { return };
    let (start, end) = geometry.visible_bytes();
    let ranges = app.layer_ranges(kind, start, end);
    painter.rect_filled(image_rect, 0.0, legend::EMPHASIS_VEIL);
    for (range_start, len) in ranges {
        for rect in geometry.rects(range_start, len) {
            painter.rect_stroke(rect.expand(1.0), 1.0, Stroke::new(2.0, legend::EMPHASIS_OUTLINE), StrokeKind::Outside);
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
    let modifiers = response.ctx.input(|i| i.modifiers);
    if response.secondary_clicked() || response.dragged_by(egui::PointerButton::Secondary) {
        return;
    }
    if response.drag_started_by(egui::PointerButton::Primary) {
        // The drag is noticed once the pointer has moved a little; it starts
        // where the button went down.
        let origin_byte = response.ctx.input(|i| i.pointer.press_origin()).map_or(byte, |press| byte_under(app, press, origin, zoom));
        begin_drag(app, origin_byte, modifiers);
        app.drag_selection_to(byte);
        app.reveal_cursor_in_hex(true);
    } else if response.dragged_by(egui::PointerButton::Primary) {
        app.drag_selection_to(byte);
        app.reveal_cursor_in_hex(false);
    } else if response.clicked() {
        click_byte(app, byte, modifiers);
        app.reveal_cursor_in_hex(true);
    }
    if response.drag_stopped() {
        app.end_drag_selection();
    }
}

/// Start a drag on `byte`: Alt makes a column selection, Cmd adds a range
/// to the selection, Shift extends it, and a plain drag starts a new one.
/// Shared by the raster and the hex dump.
pub fn begin_drag(app: &mut ViewerApp, byte: usize, modifiers: egui::Modifiers) {
    if modifiers.alt {
        app.begin_column_drag(byte);
    } else if modifiers.command {
        app.begin_adding_drag(byte);
    } else {
        app.begin_drag_selection(byte, modifiers.shift);
    }
}

/// A click on `byte`: Cmd adds what is there (a search match, a finding or
/// the byte) to the selection or takes it out, Shift extends the selection,
/// and a plain click places the cursor.
pub fn click_byte(app: &mut ViewerApp, byte: usize, modifiers: egui::Modifiers) {
    if modifiers.command {
        app.add_to_selection_at(byte);
    } else {
        app.set_cursor(byte, modifiers.shift);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_hex_digits_fit_from_about_twenty_two_points() {
        assert!((20.0..=24.0).contains(&HEX_LABEL_MIN_ZOOM), "{HEX_LABEL_MIN_ZOOM}");
        assert_eq!(pixel_label(PixelFormat::Gray8, &[0x4F], 0, HEX_LABEL_MIN_ZOOM).as_deref(), Some("4F"));
        assert_eq!(pixel_label(PixelFormat::Gray8, &[0x4F], 0, HEX_LABEL_MIN_ZOOM - 1.0), None);
    }

    #[test]
    fn sub_byte_pixels_show_their_bit_or_nibble() {
        assert_eq!(pixel_label(PixelFormat::Bit1Msb, &[0b0100_0000], 1, 24.0).as_deref(), Some("1"));
        assert_eq!(pixel_label(PixelFormat::Bit1Lsb, &[0b0000_0010], 1, 24.0).as_deref(), Some("1"));
        assert_eq!(pixel_label(PixelFormat::Nibble4, &[0xA7], 0, 24.0).as_deref(), Some("A"));
        assert_eq!(pixel_label(PixelFormat::Nibble4, &[0xA7], 1, 24.0).as_deref(), Some("7"));
    }

    #[test]
    fn multi_byte_pixels_wrap_their_bytes_or_are_skipped_when_too_small() {
        let row = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        assert_eq!(pixel_label(PixelFormat::Rgba8, &row, 1, 48.0).as_deref(), Some("9ABC\nDEF0"));
        assert_eq!(pixel_label(PixelFormat::Rgba8, &row, 0, 24.0), None, "four lines do not fit in 24 points");
        assert_eq!(pixel_label(PixelFormat::Gray16Le, &row, 1, 48.0).as_deref(), Some("5678"));
        assert_eq!(pixel_label(PixelFormat::Gray8, &row, 8, 48.0), None, "past the row");
    }

    #[test]
    fn text_contrasts_with_light_and_dark_pixels() {
        assert_eq!(contrasting_text_colour(Color32::WHITE), Color32::BLACK);
        assert_eq!(contrasting_text_colour(Color32::from_rgb(253, 231, 37)), Color32::BLACK);
        assert_eq!(contrasting_text_colour(Color32::BLACK), Color32::WHITE);
        assert_eq!(contrasting_text_colour(Color32::from_rgb(68, 1, 84)), Color32::WHITE);
    }
}
