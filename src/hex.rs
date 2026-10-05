//! Right-hand panel: a value inspector for the byte under the cursor and a
//! classic hex dump that stays in sync with the raster view.

use eframe::egui::{self, Align2, Color32, FontId, Rect, RichText, Sense, Stroke, StrokeKind, Ui, pos2, vec2};

use crate::app::ViewerApp;
use crate::patterns;
use crate::plugin::{Category, Field};
use crate::raster::byte_class_colour;
use crate::theme;

const BYTES_PER_ROW: usize = 16;
const FONT_SIZE: f32 = 13.0;

/// Widest the panel's content is allowed to be. Keeps long descriptions
/// truncating instead of stretching the panel, including during egui's
/// sizing passes where the available width is unbounded.
const PANEL_MAX_WIDTH: f32 = 740.0;

/// The inspector pane: values at the cursor and the structure tree.
pub fn show_inspector_pane(app: &mut ViewerApp, ui: &mut Ui) {
    ui.set_max_width(ui.available_width().min(PANEL_MAX_WIDTH));
    ui.add_space(4.0);
    show_inspector(app, ui);
}

/// The hex dump pane, with its colour legend.
pub fn show_hex_dump_pane(app: &mut ViewerApp, ui: &mut Ui) {
    ui.set_max_width(ui.available_width().min(PANEL_MAX_WIDTH));
    show_legend(ui);
    show_hex_dump(app, ui);
}

fn show_legend(ui: &mut Ui) {
    ui.horizontal(|ui| {
        theme::swatch(ui, theme::CLASS_NULL, "00");
        theme::swatch(ui, theme::CLASS_TEXT, "text");
        theme::swatch(ui, theme::CLASS_CONTROL, "control");
        theme::swatch(ui, theme::CLASS_HIGH, "≥ 80");
        theme::swatch(ui, theme::CLASS_FULL, "FF");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new("click to place the cursor · drag to select · scroll to move both views").small().color(theme::TEXT_DIM));
        });
    });
}

fn show_inspector(app: &mut ViewerApp, ui: &mut Ui) {
    let cursor = app.cursor;
    let window = app.document.read_range(cursor, 8);
    let mut padded = [0u8; 8];
    padded[..window.len()].copy_from_slice(&window);

    ui.horizontal(|ui| {
        ui.label(RichText::new("Inspector").strong());
        ui.label(RichText::new("at").color(theme::TEXT_DIM));
        ui.monospace(RichText::new(format!("{cursor:#010x}")).color(theme::CURSOR));
        ui.label(RichText::new(format!("({cursor})")).color(theme::TEXT_DIM));
        if window.is_empty() {
            ui.label(RichText::new("end of file — typed hex appends").color(theme::TEXT_DIM));
        }
    });
    if window.is_empty() {
        return;
    }
    let byte = padded[0];

    ui.horizontal(|ui| {
        ui.monospace(format!("{byte:02X}"));
        ui.label(RichText::new("u8").color(theme::TEXT_DIM));
        ui.monospace(format!("{byte}"));
        ui.label(RichText::new("i8").color(theme::TEXT_DIM));
        ui.monospace(format!("{}", byte as i8));
        ui.label(RichText::new("oct").color(theme::TEXT_DIM));
        ui.monospace(format!("{byte:03o}"));
        ui.separator();
        ui.label(RichText::new("bits").color(theme::TEXT_DIM)).on_hover_text("Click a bit to flip it");
        ui.spacing_mut().item_spacing.x = 2.0;
        for bit in (0..8).rev() {
            let set = (byte >> bit) & 1 == 1;
            let text = RichText::new(if set { "1" } else { "0" })
                .monospace()
                .color(if set { theme::CURSOR } else { theme::TEXT_DIM });
            if ui.selectable_label(set, text).on_hover_text(format!("bit {bit}")).clicked() {
                app.toggle_bit_at_cursor(bit);
            }
            if bit == 4 {
                ui.add_space(4.0);
            }
        }
    });

    // Fixed-width monospace rows: predictable width, no grid measuring.
    let dim = theme::TEXT_DIM;
    let row = |ui: &mut Ui, pairs: &[(&str, String)]| {
        let mut line = String::new();
        for (label, value) in pairs {
            line.push_str(&format!("{label:<7} {value:<22}"));
        }
        ui.label(RichText::new(line.trim_end()).monospace().color(dim));
    };
    let has = |n: usize| window.len() >= n;
    if has(2) {
        let two = [padded[0], padded[1]];
        row(ui, &[("u16 LE", u16::from_le_bytes(two).to_string()), ("u16 BE", u16::from_be_bytes(two).to_string())]);
    }
    if has(4) {
        let four = [padded[0], padded[1], padded[2], padded[3]];
        row(ui, &[("u32 LE", u32::from_le_bytes(four).to_string()), ("u32 BE", u32::from_be_bytes(four).to_string())]);
        row(ui, &[("i32 LE", i32::from_le_bytes(four).to_string()), ("f32 LE", format_float(f32::from_le_bytes(four) as f64))]);
    }
    if has(8) {
        row(ui, &[("u64 LE", u64::from_le_bytes(padded).to_string())]);
        row(ui, &[("f64 LE", format_float(f64::from_le_bytes(padded)))]);
    }
    for (label, text) in patterns::timestamp_readings(&window) {
        ui.horizontal(|ui| {
            ui.label(RichText::new(label).monospace().color(Category::Timestamp.colour()));
            ui.label(RichText::new(text).monospace());
        });
    }
    if let Some(pattern) = app.pattern_at(cursor).cloned() {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
            ui.painter().rect_filled(rect, 2.0, pattern.category.colour());
            ui.add(egui::Label::new(RichText::new(pattern.description()).color(theme::TEXT_DIM)).truncate())
                .on_hover_text(pattern.description());
        });
    }
    if let Some(bookmark) = app.bookmarks.at(cursor).cloned() {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
            ui.painter().rect_filled(rect, 2.0, theme::CURSOR);
            ui.label(RichText::new(format!("Bookmark: {}", bookmark.name)).color(theme::TEXT_DIM));
        });
    }
    show_structure_tree(app, ui);
}

const STRUCTURE_HEIGHT: f32 = 180.0;

/// The parsed structure at the cursor as a collapsible field tree; clicking
/// a field selects its bytes.
fn show_structure_tree(app: &mut ViewerApp, ui: &mut Ui) {
    let Some(structure) = app.cursor_structure.clone() else { return };
    if structure.fields.is_empty() {
        return;
    }
    let cursor = app.cursor;
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
        ui.painter().rect_filled(rect, 2.0, structure.category.colour());
        if ui.selectable_label(app.show_structure_fields, RichText::new(&structure.title).strong()).clicked() {
            app.show_structure_fields = !app.show_structure_fields;
        }
        let path: Vec<String> = structure.field_path(cursor).iter().map(|f| f.name.clone()).collect();
        if !path.is_empty() {
            ui.label(RichText::new(path.join(" › ")).small().color(theme::ACCENT));
        }
    });
    if !app.show_structure_fields {
        return;
    }
    if structure.category == Category::Image {
        let ctx = ui.ctx().clone();
        if let Some(texture) = app.image_preview_texture(&ctx, &structure) {
            let size = texture.size_vec2();
            let thumbnail = ui.add(egui::Image::new((texture.id(), size)).corner_radius(4.0).sense(Sense::click()));
            if thumbnail.on_hover_text("Click to open in the image viewer").clicked() {
                app.set_cursor(structure.start, false);
                app.open_media();
            }
        }
    }
    let mut chosen: Option<(usize, usize)> = None;
    egui::ScrollArea::vertical().id_salt("structure-tree").max_height(STRUCTURE_HEIGHT).show(ui, |ui| {
        for field in &structure.fields {
            show_field(ui, field, cursor, 0, &mut chosen);
        }
    });
    if let Some((start, len)) = chosen {
        app.anchor = Some(start);
        app.cursor = start + len.max(1);
        app.pending_low_nibble = false;
        app.reveal_cursor_in_hex(true);
        app.reveal_cursor_centred();
    }
}

fn show_field(ui: &mut Ui, field: &Field, cursor: usize, depth: usize, chosen: &mut Option<(usize, usize)>) {
    const MAX_DEPTH: usize = 8;
    const MAX_CHILDREN: usize = 300;
    let on_cursor = cursor >= field.offset && cursor < field.end();
    let name = if on_cursor {
        RichText::new(&field.name).color(theme::CURSOR)
    } else {
        RichText::new(&field.name)
    };
    let row = |ui: &mut Ui, chosen: &mut Option<(usize, usize)>| {
        ui.horizontal(|ui| {
            ui.add_space(depth as f32 * 12.0);
            if ui.add(egui::Label::new(name.clone()).sense(Sense::click())).on_hover_text(format!("{:#x}, {} B", field.offset, field.len)).clicked() {
                *chosen = Some((field.offset, field.len));
            }
            ui.monospace(RichText::new(format!("{:#x}", field.offset)).small().color(theme::TEXT_DIM));
            if !field.value.is_empty() {
                ui.add(egui::Label::new(RichText::new(&field.value).color(theme::TEXT_DIM)).truncate());
            }
        });
    };
    if field.children.is_empty() || depth >= MAX_DEPTH {
        row(ui, chosen);
        return;
    }
    let id = ui.id().with((field.offset, field.len, &field.name));
    let default_open = on_cursor || depth == 0;
    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, default_open)
        .show_header(ui, |ui| row(ui, chosen))
        .body(|ui| {
            for child in field.children.iter().take(MAX_CHILDREN) {
                show_field(ui, child, cursor, depth + 1, chosen);
            }
            if field.children.len() > MAX_CHILDREN {
                ui.label(RichText::new(format!("… {} more", field.children.len() - MAX_CHILDREN)).color(theme::TEXT_DIM));
            }
        });
}

/// Floats in a readable, bounded width: plain for everyday magnitudes,
/// scientific for the huge or tiny values random bytes usually decode to.
fn format_float(value: f64) -> String {
    if value == 0.0 {
        "0".to_string()
    } else if !value.is_finite() {
        value.to_string()
    } else if (1e-4..1e12).contains(&value.abs()) {
        format!("{value:.6}")
    } else {
        format!("{value:.4e}")
    }
}

fn show_hex_dump(app: &mut ViewerApp, ui: &mut Ui) {
    let font = FontId::monospace(FONT_SIZE);
    let (char_width, row_height) = ui.ctx().fonts_mut(|fonts| (fonts.glyph_width(&font, '0'), fonts.row_height(&font)));
    let row_height = row_height + 3.0;

    // offset column, 16 hex cells with a group gap, then 16 ascii cells.
    let columns_width = char_width * (10.0 + BYTES_PER_ROW as f32 * 3.0 + 1.0 + 1.0 + BYTES_PER_ROW as f32) + 16.0;
    let width = ui.available_width().min(columns_width);
    let height = ui.available_height().min(ui.ctx().content_rect().height());
    let (rect, response) = ui.allocate_exact_size(vec2(width, height), Sense::click_and_drag());
    if rect.height() < row_height * 2.0 {
        return;
    }
    let header_height = row_height;
    let body = Rect::from_min_max(pos2(rect.min.x, rect.min.y + header_height), rect.max);
    app.hex_body_rect = Some(body);
    let rows = (body.height() / row_height).floor().max(1.0) as usize;
    let total_rows = app.document.len().div_ceil(BYTES_PER_ROW).max(1);

    // The raster and this dump are kept in step by explicit sync calls (see
    // `ViewerApp::sync_hex_to_raster` and friends); here only the wheel over
    // the dump needs handling, and it drags the raster along.
    app.hex_visible_rows = rows;
    if response.hovered() {
        let wheel = ui.input(|i| i.smooth_scroll_delta.y);
        if wheel != 0.0 {
            let delta = (-wheel / row_height).round() as i64;
            if delta != 0 {
                app.scroll_hex_rows(delta);
            }
        }
    }
    app.hex_top_row = app.hex_top_row.min(total_rows.saturating_sub(rows / 2));

    let offset_x = rect.min.x + 8.0;
    let hex_x = offset_x + char_width * 10.0;
    let group_gap = char_width; // extra space after the eighth byte
    let cell_width = char_width * 3.0;
    let hex_cell_x = |col: usize| hex_x + col as f32 * cell_width + if col >= 8 { group_gap } else { 0.0 };
    let ascii_x = hex_cell_x(BYTES_PER_ROW) + char_width;

    let byte_at_pointer = |pointer: egui::Pos2, hex_top_row: usize, document_len: usize| {
        let row = ((pointer.y - body.min.y) / row_height).floor().max(0.0) as usize + hex_top_row;
        let col = if pointer.x >= ascii_x {
            ((pointer.x - ascii_x) / char_width).floor().max(0.0) as usize
        } else {
            let x = pointer.x - hex_x + char_width * 0.5;
            let x = if x > 8.0 * cell_width + group_gap * 0.5 { x - group_gap } else { x };
            (x / cell_width).floor().max(0.0) as usize
        };
        (row * BYTES_PER_ROW + col.min(BYTES_PER_ROW - 1)).min(document_len.saturating_sub(1))
    };
    if let Some(pointer) = response.hover_pos()
        && pointer.y >= body.min.y
        && !app.document.is_empty()
    {
        app.hover = Some(byte_at_pointer(pointer, app.hex_top_row, app.document.len()));
    }

    if let Some(pointer) = response.interact_pointer_pos()
        && response.secondary_clicked()
    {
        let byte = byte_at_pointer(pointer, app.hex_top_row, app.document.len());
        app.set_cursor(byte, false);
    }
    if !app.document.is_empty() {
        let offset = app.cursor;
        response.clone().context_menu(|ui| app.context_menu(ui, offset));
    }

    // Pointer: map to a byte and move the cursor / selection.
    if let Some(pointer) = response.interact_pointer_pos()
        && !response.secondary_clicked()
    {
        let byte = byte_at_pointer(pointer, app.hex_top_row, app.document.len());
        let shift = ui.input(|i| i.modifiers.shift);
        if response.drag_started() {
            app.begin_drag_selection(byte, shift);
        } else if response.dragged() {
            app.drag_selection_to(byte);
        } else if response.clicked() {
            app.set_cursor(byte, shift);
        }
        if response.drag_stopped() {
            app.end_drag_selection();
        }
        if response.clicked() || response.drag_started() {
            app.reveal_cursor_centred();
        } else {
            app.scroll_cursor_into_view();
        }
    }

    let painter = ui.painter_at(rect);
    let dim = theme::TEXT_DIM;

    // Column header.
    painter.text(pos2(offset_x, rect.min.y), Align2::LEFT_TOP, "offset", font.clone(), dim);
    for col in 0..BYTES_PER_ROW {
        painter.text(pos2(hex_cell_x(col), rect.min.y), Align2::LEFT_TOP, format!("{col:02X}"), font.clone(), dim);
    }
    painter.text(pos2(ascii_x, rect.min.y), Align2::LEFT_TOP, "ascii", font.clone(), dim);
    painter.line_segment(
        [pos2(rect.min.x, body.min.y - 1.0), pos2(rect.max.x, body.min.y - 1.0)],
        Stroke::new(1.0, theme::OUTLINE),
    );

    let selection = app.selection();
    let cursor = app.cursor;
    let pending = app.pending_low_nibble;
    let hover = app.hover;
    let raster_range = {
        let first = app.raster_first_byte();
        let stride = app.shape.row_stride();
        first..(first + app.visible_rows * stride).min(app.document.len())
    };
    let start = app.hex_top_row * BYTES_PER_ROW;
    let bytes = app.document.read_range(start, rows * BYTES_PER_ROW);
    let cursor_column_x = hex_cell_x(cursor % BYTES_PER_ROW) - char_width * 0.5;
    let nearby: Vec<(usize, usize, Color32)> = if app.highlight_patterns {
        app.patterns_in(start, start + bytes.len())
            .map(|pattern| (pattern.start, pattern.end(), pattern.category.colour()))
            .collect()
    } else {
        Vec::new()
    };
    let marks: Vec<(usize, usize)> = app.bookmarks.bookmarks.iter().map(|b| (b.offset, b.end())).collect();

    for (row_index, row_bytes) in bytes.chunks(BYTES_PER_ROW).enumerate() {
        let y = body.min.y + row_index as f32 * row_height;
        let row_offset = start + row_index * BYTES_PER_ROW;
        let row_rect = Rect::from_min_size(pos2(rect.min.x, y), vec2(rect.width(), row_height));
        if row_index % 2 == 1 {
            painter.rect_filled(row_rect, 0.0, theme::PANEL.gamma_multiply(1.25));
        }
        let is_cursor_row = row_offset / BYTES_PER_ROW == cursor / BYTES_PER_ROW;
        let in_raster = raster_range.contains(&row_offset);
        let offset_colour = if is_cursor_row {
            theme::TEXT
        } else if in_raster {
            theme::TEXT_DIM.gamma_multiply(1.35)
        } else {
            dim.gamma_multiply(0.6)
        };
        if in_raster {
            // Tick in the margin: this row is on screen in the raster.
            painter.rect_filled(Rect::from_min_size(pos2(rect.min.x + 1.0, y + 2.0), vec2(2.0, row_height - 4.0)), 1.0, theme::ACCENT_DIM);
        }
        painter.text(pos2(offset_x, y + 1.0), Align2::LEFT_TOP, format!("{row_offset:08X}"), font.clone(), offset_colour);

        for (col, &byte) in row_bytes.iter().enumerate() {
            let offset = row_offset + col;
            let hex_cell = Rect::from_min_size(pos2(hex_cell_x(col) - char_width * 0.5, y), vec2(cell_width, row_height));
            let ascii_cell = Rect::from_min_size(pos2(ascii_x + col as f32 * char_width, y), vec2(char_width, row_height));

            let selected = selection.is_some_and(|(s, len)| offset >= s && offset < s + len);
            if selected {
                painter.rect_filled(hex_cell, 0.0, theme::SELECTION);
                painter.rect_filled(ascii_cell, 0.0, theme::SELECTION);
            }
            if let Some(&(_, _, colour)) = nearby.iter().find(|&&(s, e, _)| offset >= s && offset < e) {
                let band = Rect::from_min_max(pos2(hex_cell.min.x, hex_cell.max.y - 2.0), hex_cell.max);
                painter.rect_filled(band, 0.0, colour);
                let band = Rect::from_min_max(pos2(ascii_cell.min.x, ascii_cell.max.y - 2.0), ascii_cell.max);
                painter.rect_filled(band, 0.0, colour);
            }
            if marks.iter().any(|&(s, e)| offset >= s && offset < e) {
                let band = Rect::from_min_max(hex_cell.min, pos2(hex_cell.max.x, hex_cell.min.y + 2.0));
                painter.rect_filled(band, 0.0, theme::CURSOR);
            }
            if hover == Some(offset) && offset != cursor {
                painter.rect_stroke(hex_cell, 2.0, Stroke::new(1.0, theme::ACCENT_DIM), StrokeKind::Inside);
            }
            if offset == cursor {
                painter.rect_filled(hex_cell, 3.0, theme::CURSOR_FILL);
                painter.rect_stroke(hex_cell, 3.0, Stroke::new(1.0, theme::CURSOR), StrokeKind::Inside);
                painter.rect_stroke(ascii_cell, 0.0, Stroke::new(1.0, theme::CURSOR), StrokeKind::Inside);
                if pending {
                    // Underline the low nibble that the next keystroke will fill.
                    let underline_x = hex_cell_x(col) + char_width;
                    painter.line_segment(
                        [pos2(underline_x, y + row_height - 2.0), pos2(underline_x + char_width, y + row_height - 2.0)],
                        Stroke::new(2.0, theme::CURSOR),
                    );
                }
            }

            let colour = byte_class_colour(byte);
            painter.text(pos2(hex_cell_x(col), y + 1.0), Align2::LEFT_TOP, format!("{byte:02X}"), font.clone(), colour);
            let printable = if (0x20..0x7F).contains(&byte) { byte as char } else { '·' };
            let ascii_colour = if printable == '·' { theme::CLASS_NULL } else { colour };
            painter.text(pos2(ascii_x + col as f32 * char_width, y + 1.0), Align2::LEFT_TOP, printable.to_string(), font.clone(), ascii_colour);
        }
    }

    // Faint column guide through the cursor column.
    if cursor < app.document.len() {
        let guide = Rect::from_min_max(pos2(cursor_column_x, body.min.y), pos2(cursor_column_x + cell_width, body.max.y));
        painter.rect_filled(guide, 0.0, Color32::from_rgba_unmultiplied(255, 184, 56, 10));
    }

    if bytes.is_empty() {
        painter.text(pos2(offset_x, body.min.y), Align2::LEFT_TOP, "(empty)", font, dim);
    }
}
