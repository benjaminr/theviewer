//! Packs the toolbar's control groups into as few rows as possible.
//!
//! egui draws widgets in code order, so a wrapping row leaves ragged gaps when
//! a wide group follows a narrow one. Instead, each group is measured on one
//! frame and placed into a packed slot on the next. Groups keep their reading
//! order within a row, and the arrangement only changes when it stops fitting
//! or when a tighter one would save a row, so controls do not jump around.
//!
//! Groups can also be dragged into an order of the person's choosing, which
//! then takes precedence over automatic packing.

use std::collections::HashMap;

use eframe::egui::{
    Align, CursorIcon, Id, Layout, Pos2, Rect, Sense, Stroke, Ui, UiBuilder, Vec2, pos2, vec2,
};

/// Row widths that differ by less than this are treated as unchanged.
const WIDTH_TOLERANCE: f32 = 0.5;

/// Assigns items to rows no wider than `row_width`, using as few rows as it
/// can find. Plain reading order is kept whenever it needs no more rows;
/// otherwise items are placed first-fit decreasing, with reading order
/// restored within each row and between rows.
///
/// An item wider than a row gets a row of its own.
pub fn pack_rows(widths: &[f32], gap: f32, row_width: f32) -> Vec<Vec<usize>> {
    let in_order = flow_row((0..widths.len()).collect(), widths, gap, row_width);
    let tightest = first_fit_decreasing(widths, gap, row_width);
    if in_order.len() <= tightest.len() { in_order } else { tightest }
}

fn first_fit_decreasing(widths: &[f32], gap: f32, row_width: f32) -> Vec<Vec<usize>> {
    let mut widest_first: Vec<usize> = (0..widths.len()).collect();
    widest_first.sort_by(|&a, &b| widths[b].total_cmp(&widths[a]).then(a.cmp(&b)));

    let mut rows: Vec<Vec<usize>> = Vec::new();
    for item in widest_first {
        place_first_fit(&mut rows, item, widths, gap, row_width);
    }
    for row in &mut rows {
        row.sort_unstable();
    }
    rows.sort_by_key(|row| row[0]);
    rows
}

/// Adds `item` to the first row with room for it, or to a new row, and
/// returns the row it went into.
fn place_first_fit<'a>(
    rows: &'a mut Vec<Vec<usize>>,
    item: usize,
    widths: &[f32],
    gap: f32,
    row_width: f32,
) -> &'a mut Vec<usize> {
    let index = match rows.iter().position(|row| fits_with(row, item, widths, gap, row_width)) {
        Some(index) => index,
        None => {
            rows.push(Vec::new());
            rows.len() - 1
        }
    };
    let row = &mut rows[index];
    row.push(item);
    row
}

/// Total width of a row of items, including the gaps between them.
fn row_width_of(row: &[usize], widths: &[f32], gap: f32) -> f32 {
    let items: f32 = row.iter().map(|&item| widths[item]).sum();
    items + gap * row.len().saturating_sub(1) as f32
}

/// Whether `item` fits on the end of `row`. Anything fits on an empty row.
fn fits_with(row: &[usize], item: usize, widths: &[f32], gap: f32, row_width: f32) -> bool {
    row.is_empty() || row_width_of(row, widths, gap) + gap + widths[item] <= row_width
}

/// Whether every row fits, allowing a lone oversized item its own row.
fn rows_fit(rows: &[Vec<usize>], widths: &[f32], gap: f32, row_width: f32) -> bool {
    rows.iter()
        .all(|row| row.len() <= 1 || row_width_of(row, widths, gap) <= row_width)
}

/// Keeps only items that still exist (each once), dropping empty rows, and
/// reports which items were kept.
fn surviving_rows(rows: &[Vec<usize>], item_count: usize) -> (Vec<Vec<usize>>, Vec<bool>) {
    let mut placed = vec![false; item_count];
    let mut kept = Vec::new();
    for row in rows {
        let mut kept_row = Vec::new();
        for &item in row {
            if item < item_count && !placed[item] {
                placed[item] = true;
                kept_row.push(item);
            }
        }
        if !kept_row.is_empty() {
            kept.push(kept_row);
        }
    }
    (kept, placed)
}

/// Updates an existing packing to the current items with as little movement
/// as possible. Returns `None` when a fresh packing would use fewer rows or
/// the old one no longer fits.
///
/// Items that disappeared are dropped; new items go into the first row with
/// room for them, keeping reading order, or onto a new row.
fn adjust_rows(
    previous: &[Vec<usize>],
    widths: &[f32],
    gap: f32,
    row_width: f32,
) -> Option<Vec<Vec<usize>>> {
    let (mut rows, placed) = surviving_rows(previous, widths.len());
    for item in (0..widths.len()).filter(|&item| !placed[item]) {
        place_first_fit(&mut rows, item, widths, gap, row_width).sort_unstable();
    }
    let still_fits = rows_fit(&rows, widths, gap, row_width);
    let fresh_rows = pack_rows(widths, gap, row_width).len();
    (still_fits && rows.len() <= fresh_rows).then_some(rows)
}

/// Uses the order the person chose: groups run left to right in that order
/// and a new row starts only when the next group does not fit, so no row is
/// left short when the group after it would have fitted.
///
/// Groups the order does not mention (one that appears only sometimes, say)
/// come at the end.
fn preferred_rows(
    preferred: &[Vec<usize>],
    widths: &[f32],
    gap: f32,
    row_width: f32,
) -> Vec<Vec<usize>> {
    let (rows, placed) = surviving_rows(preferred, widths.len());
    let mut order: Vec<usize> = rows.into_iter().flatten().collect();
    order.extend((0..widths.len()).filter(|&item| !placed[item]));
    flow_row(order, widths, gap, row_width)
}

/// Splits one row into as many rows as it needs, keeping its order.
fn flow_row(row: Vec<usize>, widths: &[f32], gap: f32, row_width: f32) -> Vec<Vec<usize>> {
    let mut rows: Vec<Vec<usize>> = Vec::new();
    for item in row {
        match rows.last_mut() {
            Some(current) if fits_with(current, item, widths, gap, row_width) => current.push(item),
            _ => rows.push(vec![item]),
        }
    }
    rows
}

/// Where a dragged group will land.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DropSpot {
    /// Before the `index`th of the other groups in `row`.
    InRow { row: usize, index: usize },
    /// After all the others (dropped below the last row).
    NewRow,
}

/// The area a row of groups covers.
fn row_band(row: &[(&str, Rect)]) -> Rect {
    row.iter().fold(Rect::NOTHING, |band, (_, rect)| band.union(*rect))
}

/// Works out the drop position for `pointer`, given where each group is drawn.
fn drop_spot(rows: &[Vec<(&str, Rect)>], dragged: &str, pointer: Pos2) -> DropSpot {
    let bands: Vec<Rect> = rows.iter().map(|row| row_band(row)).collect();
    match bands.last() {
        Some(last) if pointer.y <= last.bottom() => {}
        _ => return DropSpot::NewRow,
    }
    // The row whose band, stretched down to the next row, holds the pointer.
    let row = (0..bands.len())
        .rev()
        .find(|&row| pointer.y >= bands[row].top())
        .unwrap_or(0);
    let index = rows[row]
        .iter()
        .filter(|(key, rect)| *key != dragged && rect.center().x < pointer.x)
        .count();
    DropSpot::InRow { row, index }
}

/// The arrangement after moving `key` to `spot`. Rows left empty are removed.
fn move_group(rows: &[Vec<&'static str>], key: &'static str, spot: DropSpot) -> Vec<Vec<&'static str>> {
    let mut rows: Vec<Vec<&'static str>> = rows
        .iter()
        .map(|row| row.iter().copied().filter(|other| *other != key).collect())
        .collect();
    match spot {
        DropSpot::InRow { row, index } if row < rows.len() => {
            let index = index.min(rows[row].len());
            rows[row].insert(index, key);
        }
        _ => rows.push(vec![key]),
    }
    rows.retain(|row| !row.is_empty());
    rows
}

fn size_of(sizes: &[(&str, Vec2)], key: &str) -> Option<Vec2> {
    sizes.iter().find(|(known, _)| *known == key).map(|(_, size)| *size)
}

/// What the packer remembers between frames.
#[derive(Clone, Default)]
struct Memory {
    row_width: f32,
    /// Measured size of each group, in the order the code draws them.
    sizes: Vec<(&'static str, Vec2)>,
    /// The last automatic packing, kept so groups stay put while it works.
    /// Empty when the person's own arrangement was shown instead.
    packed_rows: Vec<Vec<&'static str>>,
}

/// Places toolbar groups into packed rows. Create it with [`RowPacker::begin`],
/// draw each group with [`RowPacker::group`], then call [`RowPacker::finish`].
///
/// Groups can be dragged by their frame to a new place; `finish` reports the
/// new arrangement so the caller can keep it.
pub struct RowPacker {
    memory_id: Id,
    origin: Pos2,
    row_width: f32,
    gap: Vec2,
    previous: Memory,
    /// The rows shown this frame, and whether they are an automatic packing.
    rows: Vec<Vec<&'static str>>,
    automatic: bool,
    slots: HashMap<&'static str, Pos2>,
    measured: Vec<(&'static str, Vec2)>,
    drawn: Rect,
    dragging: Option<&'static str>,
    dropped: Option<&'static str>,
}

impl RowPacker {
    /// `preferred` is an arrangement the person chose earlier, as rows of
    /// group keys; without one, groups are packed into the fewest rows.
    pub fn begin(ui: &Ui, id_salt: &str, preferred: Option<&[Vec<String>]>) -> Self {
        let memory_id = ui.id().with(("row-packer", id_salt));
        let previous: Memory = ui.data(|data| data.get_temp(memory_id)).unwrap_or_default();
        let origin = ui.cursor().min;
        let row_width = ui.available_width();
        let gap = ui.spacing().item_spacing;
        let rows = arrange(&previous, preferred, row_width, gap.x);
        let slots = slot_positions(&rows, &previous.sizes, origin, gap);
        Self {
            memory_id,
            origin,
            row_width,
            gap,
            previous,
            rows,
            automatic: preferred.is_none(),
            slots,
            measured: Vec::new(),
            drawn: Rect::from_min_size(origin, Vec2::ZERO),
            dragging: None,
            dropped: None,
        }
    }

    /// Draws one group at its packed position. `key` must stay the same while
    /// the caption changes, so the group keeps its place.
    ///
    /// A group not measured yet is laid out invisibly this frame and placed
    /// on the next.
    pub fn group<R>(&mut self, ui: &mut Ui, key: &'static str, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
        let placed = self.slots.get(key).copied().zip(size_of(&self.previous.sizes, key));
        let builder = match placed {
            Some((position, size)) => {
                self.drag_handle(ui, key, Rect::from_min_size(position, size));
                let width_left = self.row_width - (position.x - self.origin.x);
                UiBuilder::new().max_rect(Rect::from_min_size(position, vec2(width_left.max(0.0), f32::INFINITY)))
            }
            None => UiBuilder::new()
                .max_rect(Rect::from_min_size(self.origin, vec2(self.row_width, f32::INFINITY)))
                .sizing_pass()
                .invisible(),
        };
        let mut child = ui.new_child(
            builder
                .layout(Layout::left_to_right(Align::Min))
                .id_salt(("packed-group", key)),
        );
        let inner = add_contents(&mut child);
        let rect = child.min_rect();
        self.measured.push((key, rect.size()));
        if placed.is_some() {
            self.drawn = self.drawn.union(rect);
        }
        inner
    }

    /// Draws a captioned control group (see [`crate::theme::group`]).
    pub fn captioned<R>(
        &mut self,
        ui: &mut Ui,
        key: &'static str,
        caption: &str,
        add_contents: impl FnOnce(&mut Ui) -> R,
    ) -> R {
        self.group(ui, key, |ui| crate::theme::group(ui, caption, add_contents))
    }

    /// Makes the group's background draggable. It is registered before the
    /// group's own widgets, so those stay on top and keep their clicks.
    fn drag_handle(&mut self, ui: &Ui, key: &'static str, rect: Rect) {
        let response = ui.interact(rect, self.memory_id.with(("drag", key)), Sense::drag());
        if response.dragged() {
            self.dragging = Some(key);
            ui.ctx().set_cursor_icon(CursorIcon::Grabbing);
        } else if response.hovered() {
            ui.ctx().set_cursor_icon(CursorIcon::Grab);
        }
        if response.drag_stopped() {
            self.dropped = Some(key);
        }
    }

    /// Where every group sits this frame, row by row.
    fn placed_rows(&self) -> Vec<Vec<(&'static str, Rect)>> {
        self.rows
            .iter()
            .map(|row| {
                row.iter()
                    .filter_map(|&key| {
                        let position = *self.slots.get(key)?;
                        Some((key, Rect::from_min_size(position, size_of(&self.measured, key)?)))
                    })
                    .collect::<Vec<_>>()
            })
            .filter(|row| !row.is_empty())
            .collect()
    }

    /// Shows where the dragged group would land.
    fn paint_drop_marker(&self, ui: &Ui, rows: &[Vec<(&'static str, Rect)>], dragged: &str, spot: DropSpot) {
        let painter = ui.painter();
        let stroke = Stroke::new(3.0, ui.visuals().selection.stroke.color);
        if let Some((_, rect)) = rows.iter().flatten().find(|(key, _)| *key == dragged) {
            painter.rect_filled(*rect, 6.0, ui.visuals().extreme_bg_color.gamma_multiply(0.6));
        }
        match spot {
            DropSpot::InRow { row, index } => {
                let others: Vec<Rect> = rows[row]
                    .iter()
                    .filter(|(key, _)| *key != dragged)
                    .map(|(_, rect)| *rect)
                    .collect();
                let band = row_band(&rows[row]);
                let x = match others.get(index) {
                    Some(next) => next.left() - self.gap.x / 2.0,
                    None => others.last().map_or(band.left(), |last| last.right() + self.gap.x / 2.0),
                };
                painter.vline(x, band.y_range(), stroke);
            }
            DropSpot::NewRow => {
                let y = self.drawn.bottom() + self.gap.y / 2.0;
                painter.hline(self.drawn.x_range(), y, stroke);
            }
        }
    }

    /// Paints the drop marker while dragging, and returns the new arrangement
    /// when a group has just been dropped.
    fn handle_drag(&self, ui: &Ui) -> Option<Vec<Vec<&'static str>>> {
        if self.dragging.is_none() && self.dropped.is_none() {
            return None;
        }
        let pointer = ui.ctx().pointer_latest_pos()?;
        let rows = self.placed_rows();
        if let Some(dragged) = self.dragging {
            self.paint_drop_marker(ui, &rows, dragged, drop_spot(&rows, dragged, pointer));
        }
        let dropped = self.dropped?;
        Some(move_group(&self.rows, dropped, drop_spot(&rows, dropped, pointer)))
    }

    /// Reserves the space the groups used and remembers their sizes.
    /// Returns the new arrangement when a group was dropped somewhere new.
    pub fn finish(self, ui: &mut Ui) -> Option<Vec<Vec<String>>> {
        let rearranged = self.handle_drag(ui);
        ui.advance_cursor_after_rect(self.drawn);
        let settled = rearranged.is_none()
            && same_sizes(&self.previous.sizes, &self.measured)
            && (self.previous.row_width - self.row_width).abs() < WIDTH_TOLERANCE;
        let packed_rows = if self.automatic && rearranged.is_none() { self.rows } else { Vec::new() };
        let memory = Memory { row_width: self.row_width, sizes: self.measured, packed_rows };
        ui.data_mut(|data| data.insert_temp(self.memory_id, memory));
        if !settled {
            ui.ctx().request_repaint();
        }
        rearranged.map(|rows| {
            rows.into_iter()
                .map(|row| row.into_iter().map(str::to_string).collect())
                .collect()
        })
    }
}

/// Chooses rows for the remembered groups. A chosen arrangement wins;
/// otherwise the previous packing is kept while it still works.
fn arrange(
    memory: &Memory,
    preferred: Option<&[Vec<String>]>,
    row_width: f32,
    gap: f32,
) -> Vec<Vec<&'static str>> {
    let keys: Vec<&'static str> = memory.sizes.iter().map(|(key, _)| *key).collect();
    let widths: Vec<f32> = memory.sizes.iter().map(|(_, size)| size.x).collect();

    let rows = match preferred {
        Some(preferred) => preferred_rows(&key_rows_to_indices(preferred, &keys), &widths, gap, row_width),
        None => {
            let width_unchanged = (memory.row_width - row_width).abs() < WIDTH_TOLERANCE;
            let kept = (width_unchanged && !memory.packed_rows.is_empty())
                .then(|| adjust_rows(&key_rows_to_indices(&memory.packed_rows, &keys), &widths, gap, row_width))
                .flatten();
            kept.unwrap_or_else(|| pack_rows(&widths, gap, row_width))
        }
    };
    rows.into_iter()
        .map(|row| row.into_iter().map(|item| keys[item]).collect())
        .collect()
}

/// Turns rows of group keys into rows of indices into `keys`, skipping
/// keys that are not drawn any more.
fn key_rows_to_indices<K: AsRef<str>>(rows: &[Vec<K>], keys: &[&str]) -> Vec<Vec<usize>> {
    rows.iter()
        .map(|row| {
            row.iter()
                .filter_map(|key| keys.iter().position(|known| *known == key.as_ref()))
                .collect()
        })
        .collect()
}

/// Top-left corner of every placed group.
fn slot_positions(
    rows: &[Vec<&'static str>],
    sizes: &[(&'static str, Vec2)],
    origin: Pos2,
    gap: Vec2,
) -> HashMap<&'static str, Pos2> {
    let mut slots = HashMap::new();
    let mut y = origin.y;
    for row in rows {
        let mut x = origin.x;
        let mut row_height: f32 = 0.0;
        for &key in row {
            slots.insert(key, pos2(x, y));
            let size = size_of(sizes, key).unwrap_or(Vec2::ZERO);
            x += size.x + gap.x;
            row_height = row_height.max(size.y);
        }
        y += row_height + gap.y;
    }
    slots
}

fn same_sizes(before: &[(&'static str, Vec2)], after: &[(&'static str, Vec2)]) -> bool {
    before.len() == after.len()
        && before.iter().zip(after).all(|((key_a, size_a), (key_b, size_b))| {
            key_a == key_b && (*size_a - *size_b).length() < WIDTH_TOLERANCE
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAP: f32 = 6.0;

    #[test]
    fn packing_fills_gaps_that_reading_order_would_leave() {
        // Wrapping in reading order needs three rows: [70] [50, 25] [45].
        let widths = [70.0, 50.0, 25.0, 45.0];
        let rows = pack_rows(&widths, GAP, 102.0);
        assert_eq!(rows, vec![vec![0, 2], vec![1, 3]]);
        assert!(rows_fit(&rows, &widths, GAP, 102.0));
    }

    #[test]
    fn reading_order_is_kept_when_reordering_would_not_save_a_row() {
        let widths = [40.0, 90.0, 40.0, 40.0];
        assert_eq!(pack_rows(&widths, GAP, 100.0), vec![vec![0], vec![1], vec![2, 3]]);
    }

    #[test]
    fn groups_keep_reading_order_within_and_between_rows() {
        let widths = [50.0, 50.0, 90.0, 40.0, 40.0];
        let rows = pack_rows(&widths, GAP, 100.0);
        for row in &rows {
            assert!(row.windows(2).all(|pair| pair[0] < pair[1]), "{rows:?}");
        }
        assert!(rows.windows(2).all(|pair| pair[0][0] < pair[1][0]), "{rows:?}");
    }

    #[test]
    fn a_group_wider_than_the_toolbar_gets_its_own_row() {
        let widths = [30.0, 250.0, 30.0];
        let rows = pack_rows(&widths, GAP, 100.0);
        assert!(rows.contains(&vec![1]), "{rows:?}");
        assert!(rows_fit(&rows, &widths, GAP, 100.0));
    }

    #[test]
    fn a_new_group_slots_into_spare_room_without_moving_the_others() {
        let previous = vec![vec![0, 1], vec![2]];
        let widths = [40.0, 40.0, 60.0, 30.0];
        let rows = adjust_rows(&previous, &widths, GAP, 100.0).expect("still fits");
        assert_eq!(rows, vec![vec![0, 1], vec![2, 3]]);
    }

    #[test]
    fn an_arrangement_that_wastes_a_row_is_repacked() {
        // After a group vanished, rows [0] [1] could share one row.
        let previous = vec![vec![0], vec![1]];
        let widths = [40.0, 40.0];
        assert!(adjust_rows(&previous, &widths, GAP, 100.0).is_none());
    }

    #[test]
    fn a_chosen_order_is_kept_and_packed_without_short_rows() {
        let widths = [40.0, 40.0, 40.0];
        // Saved on two rows, but all three fit on one: no short row is left.
        let rows = preferred_rows(&[vec![2], vec![1, 0]], &widths, GAP, 200.0);
        assert_eq!(rows, vec![vec![2, 1, 0]]);
    }

    #[test]
    fn a_chosen_row_flows_onto_extra_rows_when_the_window_narrows() {
        let widths = [40.0, 40.0, 40.0];
        let rows = preferred_rows(&[vec![2, 1, 0]], &widths, GAP, 90.0);
        assert_eq!(rows, vec![vec![2, 1], vec![0]]);
    }

    #[test]
    fn groups_missing_from_a_chosen_arrangement_still_appear_at_the_end() {
        let widths = [40.0, 40.0, 40.0];
        let rows = preferred_rows(&[vec![1]], &widths, GAP, 90.0);
        assert_eq!(rows, vec![vec![1, 0], vec![2]]);
    }

    fn placed(rows: &[&[(&'static str, f32)]]) -> Vec<Vec<(&'static str, Rect)>> {
        rows.iter()
            .enumerate()
            .map(|(row, groups)| {
                groups
                    .iter()
                    .map(|&(key, left)| {
                        let top = row as f32 * 50.0;
                        (key, Rect::from_min_size(pos2(left, top), vec2(40.0, 44.0)))
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn dropping_on_the_left_half_of_a_group_lands_before_it() {
        let rows = placed(&[&[("a", 0.0), ("b", 50.0)], &[("c", 0.0)]]);
        let spot = drop_spot(&rows, "c", pos2(55.0, 20.0));
        assert_eq!(spot, DropSpot::InRow { row: 0, index: 1 });
        let moved = move_group(&[vec!["a", "b"], vec!["c"]], "c", spot);
        assert_eq!(moved, vec![vec!["a", "c", "b"]]);
    }

    #[test]
    fn dropping_below_every_row_moves_the_group_to_the_end() {
        let rows = placed(&[&[("a", 0.0), ("b", 50.0)]]);
        let spot = drop_spot(&rows, "a", pos2(10.0, 200.0));
        assert_eq!(spot, DropSpot::NewRow);
        assert_eq!(move_group(&[vec!["a", "b"]], "a", spot), vec![vec!["b"], vec!["a"]]);
    }

    #[test]
    fn moving_a_group_along_its_own_row_ignores_its_old_place() {
        let rows = placed(&[&[("a", 0.0), ("b", 50.0), ("c", 100.0)]]);
        let spot = drop_spot(&rows, "a", pos2(135.0, 20.0));
        assert_eq!(move_group(&[vec!["a", "b", "c"]], "a", spot), vec![vec!["b", "c", "a"]]);
    }
}
