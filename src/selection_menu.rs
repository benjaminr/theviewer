//! The Selection menu: every byte operation, for any kind of selection, in
//! one place shared by the raster's and the hex dump's right-click menus,
//! the packet viewer, the findings list and the small toolbar that floats
//! beside a selection.
//!
//! Operations act on every selected range (each record of a column, each
//! range of a multi-range selection), or on the byte at the cursor when
//! nothing is selected, and each is one undo step.

use std::sync::Arc;

use eframe::egui::{self, Color32, Frame, Id, Order, Pos2, Rect, RichText, Ui, vec2};

use crate::app::{DialogKind, FileAction, ViewerApp};
use crate::compress::{self, Codec};
use crate::ops;
use crate::selection::Selection;
use crate::selection_ops::{self, CopyFormat, Operation};
use crate::theme;

/// Most bytes one operation reads and rewrites in a single piece; wider
/// selections are rewritten range by range (still one undo step).
const SINGLE_EDIT_LIMIT: usize = 64 * 1024 * 1024;
/// Gap between a selection and the toolbar floating beside it.
const TOOLBAR_GAP: f32 = 6.0;
/// Height kept free for the floating toolbar above a selection.
const TOOLBAR_HEIGHT: f32 = 30.0;
/// Width of the hex fields in the menus.
const FIELD_WIDTH: f32 = 110.0;

/// Builds an operation from a key typed as hex.
type MakeOperation = fn(Vec<u8>) -> Operation;

/// Which view the person last worked in, so the floating toolbar shows in
/// that one only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SelectionView {
    #[default]
    Raster,
    Hex,
}

/// The values typed into the operations' fields, kept between uses.
#[derive(Clone, Debug)]
pub struct OperationInputs {
    /// Key for XOR, add and subtract, as hex.
    pub key_text: String,
    pub counter_start: u64,
    pub counter_step: u64,
    pub counter_little_endian: bool,
    /// Where "Move to" puts the bytes, as an offset.
    pub move_destination_text: String,
}

impl Default for OperationInputs {
    fn default() -> Self {
        OperationInputs { key_text: "FF".to_string(), counter_start: 0, counter_step: 1, counter_little_endian: true, move_destination_text: String::new() }
    }
}

// ---------------------------------------------------------------------------
// The operations model
// ---------------------------------------------------------------------------

impl ViewerApp {
    /// The ranges an operation acts on: every selected range, or the byte at
    /// the cursor when nothing is selected.
    pub fn operation_ranges(&self) -> Vec<(usize, usize)> {
        let selected = self.selection_ranges();
        if !selected.is_empty() {
            return selected;
        }
        if self.cursor < self.document.len() { vec![(self.cursor, 1)] } else { Vec::new() }
    }

    /// Apply `operation` to every selected range as one undo step, then keep
    /// the changed bytes selected.
    pub fn apply_operation(&mut self, operation: Operation) {
        let ranges = self.operation_ranges();
        if ranges.is_empty() {
            self.status = "Nothing to change: the cursor is at the end of the document".to_string();
            return;
        }
        let selected = self.current_selection();
        match self.rewrite_ranges(&ranges, &operation) {
            Ok(changed) => {
                self.select_after_operation(selected, &operation, &changed);
                let bytes: usize = ranges.iter().map(|&(_, len)| len).sum();
                let places = if ranges.len() == 1 { format!("at {:#x}", ranges[0].0) } else { format!("in {} ranges", ranges.len()) };
                self.status = format!("{} {bytes} bytes {places}. Undo with Cmd+Z.", operation.label());
            }
            Err(message) => self.status = format!("{} failed: {message}", operation_name(&operation)),
        }
    }

    /// Write `operation`'s result over `ranges` as one undo step. Returns
    /// where each range's new bytes are.
    fn rewrite_ranges(&mut self, ranges: &[(usize, usize)], operation: &Operation) -> Result<Vec<(usize, usize)>, String> {
        let start = ranges[0].0;
        let end = ranges.last().map_or(start, |&(range_start, len)| range_start + len);
        if end - start <= SINGLE_EDIT_LIMIT {
            let span = self.document.read_range(start, end - start);
            let (rebuilt, changed) = selection_ops::rebuild_span(&span, start, ranges, operation)?;
            if rebuilt != span {
                self.document.replace(start, span.len(), &rebuilt);
            }
            return Ok(changed);
        }
        // Too wide to rewrite in one piece: work out every range first, so a
        // failure changes nothing, then write them from the last back.
        let mut replacements = Vec::with_capacity(ranges.len());
        for (index, &(range_start, len)) in ranges.iter().enumerate() {
            let bytes = self.document.read_range(range_start, len);
            replacements.push(selection_ops::transform_range(operation, &bytes, index)?);
        }
        let mut changed = Vec::with_capacity(ranges.len());
        let mut shift: isize = 0;
        for (&(range_start, len), replacement) in ranges.iter().zip(&replacements) {
            changed.push(((range_start as isize + shift) as usize, replacement.len()));
            shift += replacement.len() as isize - len as isize;
        }
        self.document.grouped(|document| {
            for (&(range_start, len), replacement) in ranges.iter().zip(&replacements).rev() {
                document.replace(range_start, len, replacement);
            }
        });
        Ok(changed)
    }

    /// Select what an operation produced: the same column, the changed
    /// ranges, or just the cursor after a delete.
    fn select_after_operation(&mut self, selected: Option<Selection>, operation: &Operation, changed: &[(usize, usize)]) {
        let kept: Vec<(usize, usize)> = changed.iter().copied().filter(|&(_, len)| len > 0).collect();
        match selected {
            Some(Selection::Columns(column)) if operation.keeps_length() => self.select_column(column),
            Some(_) if kept.len() > 1 => self.select_ranges(kept, None),
            Some(_) if kept.len() == 1 => self.restore_selection(kept[0].0, kept[0].1),
            _ => {
                let at = changed.first().map_or(self.cursor, |&(start, _)| start);
                self.restore_selection(at.min(self.document.len()), 1);
            }
        }
        self.clamp_top_row();
    }

    /// Every selected range's bytes, one after another.
    pub fn selected_bytes(&mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (start, len) in self.operation_ranges() {
            bytes.extend(self.document.read_range(start, len));
        }
        bytes
    }

    /// Copy the selected bytes to the clipboard as hex, a C array or Base64.
    pub fn copy_selection_as(&mut self, ctx: &egui::Context, format: CopyFormat) {
        let bytes = self.selected_bytes();
        if bytes.is_empty() {
            self.status = "Nothing to copy".to_string();
            return;
        }
        ctx.copy_text(format.render(&bytes));
        self.status = format!("{} bytes: {}", bytes.len(), format.label().to_lowercase());
        self.clipboard = bytes;
    }

    /// Save the selected bytes to a file the person chooses.
    pub fn extract_selection(&mut self) {
        let bytes = self.selected_bytes();
        let name = self.selection_summary().map_or_else(|| "byte at cursor".to_string(), |summary| format!("selection ({summary})"));
        let dialog = rfd::AsyncFileDialog::new().set_title("Save the selected bytes").set_file_name("selection.bin");
        self.ask_for_file(DialogKind::Save, dialog, FileAction::SaveBytes { name, bytes: Arc::new(bytes) });
    }

    /// Open the selected bytes as a document of their own; Back returns.
    pub fn open_selection_as_document(&mut self) {
        let bytes = self.selected_bytes();
        let name = format!("{} › selection", self.display_name());
        self.open_derived(bytes, name);
    }

    /// Cut the selected ranges out and put their bytes, one after another,
    /// at document offset `destination` (counted before the cut), as one
    /// undo step. Returns where they landed.
    pub fn move_selection_to(&mut self, destination: usize) -> Option<(usize, usize)> {
        let ranges = self.operation_ranges();
        if ranges.is_empty() {
            return None;
        }
        let bytes = self.selected_bytes();
        let landing = selection_ops::moved_destination(destination.min(self.document.len()), &ranges);
        self.document.begin_group();
        let cut = self.rewrite_ranges(&ranges, &Operation::Delete);
        if cut.is_ok() {
            self.document.insert(landing.min(self.document.len()), &bytes);
        }
        self.document.end_group();
        if let Err(message) = cut {
            self.status = format!("Move failed: {message}");
            return None;
        }
        self.restore_selection(landing, bytes.len());
        self.reveal_cursor_in_hex(false);
        self.status = format!("Moved {} bytes to {landing:#x}. Undo with Cmd+Z.", bytes.len());
        Some((landing, bytes.len()))
    }

    /// The bytes typed into the Insert fields: the pattern repeated to the count.
    pub fn insert_bytes_from_fields(&mut self) -> Option<Vec<u8>> {
        let Some(pattern) = ops::parse_hex(&self.insert_value_text) else {
            self.status = "Insert value must be hex, e.g. 00 or DEADBEEF".to_string();
            return None;
        };
        let pattern = if pattern.is_empty() { vec![0u8] } else { pattern };
        Some(pattern.iter().cycle().take(self.insert_count.max(1)).copied().collect())
    }

    /// The pattern typed for Fill.
    fn fill_pattern(&mut self) -> Option<Vec<u8>> {
        let pattern = ops::parse_hex(&self.fill_value_text).filter(|pattern| !pattern.is_empty());
        if pattern.is_none() {
            self.status = "Fill value must be hex, e.g. 00 or DEADBEEF".to_string();
        }
        pattern
    }

    /// The key typed for XOR, add and subtract.
    fn operation_key(&mut self) -> Option<Vec<u8>> {
        let key = ops::parse_hex(&self.inputs.key_text).filter(|key| !key.is_empty());
        if key.is_none() {
            self.status = "The key must be hex bytes, e.g. 5A or DEADBEEF".to_string();
        }
        key
    }

    /// Fill every selected range with the Fill pattern.
    pub fn fill_selection(&mut self) {
        if let Some(pattern) = self.fill_pattern() {
            self.apply_operation(Operation::Fill(pattern));
        }
    }

    /// Insert the Insert fields' bytes before (or after) every selected range.
    pub fn insert_around_selection(&mut self, after: bool) {
        let Some(bytes) = self.insert_bytes_from_fields() else { return };
        self.apply_operation(if after { Operation::InsertAfter(bytes) } else { Operation::InsertBefore(bytes) });
    }

    /// Combine every selected range with the key.
    pub fn apply_key(&mut self, make: fn(Vec<u8>) -> Operation) {
        if let Some(key) = self.operation_key() {
            self.apply_operation(make(key));
        }
    }

    /// Number each selected range with the counter fields.
    pub fn number_selection(&mut self) {
        let inputs = &self.inputs;
        let operation = Operation::Counter { start: inputs.counter_start, step: inputs.counter_step, little_endian: inputs.counter_little_endian };
        self.apply_operation(operation);
    }
}

/// The name of an operation for an error message.
fn operation_name(operation: &Operation) -> &'static str {
    match operation {
        Operation::Compress(_) => "Compressing",
        Operation::Decompress => "Decompressing",
        Operation::Fill(_) => "Fill",
        Operation::Xor(_) | Operation::Add(_) | Operation::Subtract(_) => "Combining with the key",
        Operation::SwapByteOrder(_) => "Swapping the byte order",
        _ => "The operation",
    }
}

// ---------------------------------------------------------------------------
// The menu
// ---------------------------------------------------------------------------

/// What the Selection menu is called: what it acts on.
pub fn menu_title(app: &ViewerApp) -> String {
    match app.selection_summary() {
        Some(summary) => format!("Selection ({summary})"),
        None => "Byte at cursor".to_string(),
    }
}

/// A "Selection" menu button holding every operation.
pub fn menu_button(app: &mut ViewerApp, ui: &mut Ui) {
    ui.menu_button(menu_title(app), |ui| show_selection_menu(app, ui));
}

/// Every operation on the selection, for any menu.
pub fn show_selection_menu(app: &mut ViewerApp, ui: &mut Ui) {
    ui.label(RichText::new(menu_title(app)).small().color(theme::TEXT_DIM));
    ui.menu_button("Insert…", |ui| show_insert_fields(app, ui));
    if ui.button("Delete").clicked() {
        app.apply_operation(Operation::Delete);
        ui.close();
    }
    ui.menu_button("Fill…", |ui| show_fill_fields(app, ui));
    if ui.button("Invert bits").clicked() {
        app.apply_operation(Operation::Invert);
        ui.close();
    }
    ui.menu_button("XOR, add or subtract…", |ui| show_key_fields(app, ui));
    if ui.button("Reverse bytes").clicked() {
        app.apply_operation(Operation::Reverse);
        ui.close();
    }
    if ui.button("Mirror bits in each byte").clicked() {
        app.apply_operation(Operation::MirrorBits);
        ui.close();
    }
    ui.menu_button("Shift or rotate bits…", |ui| show_bit_fields(app, ui));
    ui.menu_button("Swap byte order", |ui| {
        for width in [2usize, 4, 8] {
            if ui.button(format!("{width}-byte values")).clicked() {
                app.apply_operation(Operation::SwapByteOrder(width));
                ui.close();
            }
        }
    });
    ui.menu_button("Number as a counter…", |ui| show_counter_fields(app, ui));
    ui.separator();
    ui.menu_button("Move to…", |ui| show_move_fields(app, ui));
    if ui.button("Duplicate").on_hover_text("Follow each range with a copy of itself").clicked() {
        app.apply_operation(Operation::Duplicate);
        ui.close();
    }
    if ui.button("Skip (fold out of the views)").on_hover_text("Leave these bytes out of the raster and the hex dump without deleting them; click the marker to show them again").clicked() {
        app.skip_selection();
        ui.close();
    }
    ui.separator();
    ui.menu_button("Copy as", |ui| {
        for format in CopyFormat::ALL {
            if ui.button(format.label()).clicked() {
                let ctx = ui.ctx().clone();
                app.copy_selection_as(&ctx, format);
                ui.close();
            }
        }
    });
    if ui.button("Extract to file…").clicked() {
        app.extract_selection();
        ui.close();
    }
    if ui.button("Open as document").clicked() {
        app.open_selection_as_document();
        ui.close();
    }
    ui.menu_button("Compress as", |ui| {
        for codec in Codec::COMPRESSIBLE {
            if ui.button(codec.label()).clicked() {
                app.apply_operation(Operation::Compress(codec));
                ui.close();
            }
        }
    });
    if ui.button("Decompress").on_hover_text("Replace each range with its decompressed contents").clicked() {
        app.apply_operation(Operation::Decompress);
        ui.close();
    }
}

fn hex_field(ui: &mut Ui, text: &mut String, hint: &str) {
    ui.add(egui::TextEdit::singleline(text).desired_width(FIELD_WIDTH).hint_text(hint));
}

fn show_insert_fields(app: &mut ViewerApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        hex_field(ui, &mut app.insert_value_text, "hex pattern");
        ui.add(egui::DragValue::new(&mut app.insert_count).range(1..=usize::MAX / 2).prefix("× "));
    });
    let size = compress::human_bytes(app.insert_count.max(1));
    ui.label(RichText::new(format!("{size} of the pattern, repeated")).small().color(theme::TEXT_DIM));
    ui.horizontal(|ui| {
        if ui.button("Before").on_hover_text("Insert before each selected range").clicked() {
            app.insert_around_selection(false);
            ui.close();
        }
        if ui.button("After").on_hover_text("Insert after each selected range").clicked() {
            app.insert_around_selection(true);
            ui.close();
        }
        if ui.button("At cursor").clicked() {
            app.insert_from_fields();
            ui.close();
        }
    });
}

fn show_fill_fields(app: &mut ViewerApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        hex_field(ui, &mut app.fill_value_text, "hex pattern");
        if ui.button("Fill").clicked() {
            app.fill_selection();
            ui.close();
        }
    });
}

fn show_key_fields(app: &mut ViewerApp, ui: &mut Ui) {
    hex_field(ui, &mut app.inputs.key_text, "hex key");
    ui.label(RichText::new("The key repeats from the start of each range").small().color(theme::TEXT_DIM));
    ui.horizontal(|ui| {
        let actions: [(&str, MakeOperation); 3] = [("XOR", Operation::Xor), ("Add", Operation::Add), ("Subtract", Operation::Subtract)];
        for (label, make) in actions {
            if ui.button(label).clicked() {
                app.apply_key(make);
                ui.close();
            }
        }
    });
}

fn show_bit_fields(app: &mut ViewerApp, ui: &mut Ui) {
    ui.add(egui::DragValue::new(&mut app.shift_amount).range(1..=i64::MAX / 4).suffix(" bits"));
    let amount = app.shift_amount;
    ui.horizontal(|ui| {
        let actions = [
            ("◀ Shift", Operation::ShiftBits(amount)),
            ("Shift ▶", Operation::ShiftBits(-amount)),
            ("◀ Rotate", Operation::RotateBits(amount)),
            ("Rotate ▶", Operation::RotateBits(-amount)),
        ];
        for (label, operation) in actions {
            if ui.button(label).clicked() {
                app.apply_operation(operation);
                ui.close();
            }
        }
    });
}

fn show_counter_fields(app: &mut ViewerApp, ui: &mut Ui) {
    ui.label(RichText::new("Writes start + step × n into the n-th range (each record of a column)").small().color(theme::TEXT_DIM));
    ui.horizontal(|ui| {
        ui.label("start");
        ui.add(egui::DragValue::new(&mut app.inputs.counter_start));
        ui.label("step");
        ui.add(egui::DragValue::new(&mut app.inputs.counter_step));
    });
    ui.checkbox(&mut app.inputs.counter_little_endian, "Little endian");
    if ui.button("Number them").clicked() {
        app.number_selection();
        ui.close();
    }
}

fn show_move_fields(app: &mut ViewerApp, ui: &mut Ui) {
    ui.label(RichText::new("Cut the selected bytes out and put them at an offset (or drag the selection in the view)").small().color(theme::TEXT_DIM));
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut app.inputs.move_destination_text).desired_width(FIELD_WIDTH).hint_text("0x1F4 or 500"));
        if ui.button("Move").clicked() {
            match ops::parse_offset(&app.inputs.move_destination_text) {
                Some(destination) => {
                    app.move_selection_to(destination);
                }
                None => app.status = "Move to: enter a decimal or 0x-prefixed hex offset".to_string(),
            }
            ui.close();
        }
    });
}

// ---------------------------------------------------------------------------
// The floating toolbar
// ---------------------------------------------------------------------------

/// A few common operations in a small toolbar beside the selection, shown
/// only while something is selected and not being dragged, in the view the
/// person is working in. `anchor` is the selection's outline on screen and
/// `clip` the view's area.
pub fn show_floating_toolbar(app: &mut ViewerApp, ctx: &egui::Context, view: SelectionView, anchor: Rect, clip: Rect) {
    if app.selection_view != view || app.current_selection().is_none() || app.is_dragging() || !clip.intersects(anchor) {
        return;
    }
    let above = anchor.min.y - TOOLBAR_GAP - TOOLBAR_HEIGHT >= clip.min.y;
    let y = if above { anchor.min.y - TOOLBAR_GAP - TOOLBAR_HEIGHT } else { (anchor.max.y + TOOLBAR_GAP).min(clip.max.y - TOOLBAR_HEIGHT) };
    let x = anchor.min.x.clamp(clip.min.x, (clip.max.x - 160.0).max(clip.min.x));
    let id = Id::new(("floating-selection-toolbar", view as u8));
    egui::Area::new(id).order(Order::Foreground).fixed_pos(Pos2::new(x, y)).show(ctx, |ui| {
        Frame::popup(ui.style()).inner_margin(4).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                floating_buttons(app, ui);
            });
        });
    });
}

fn floating_buttons(app: &mut ViewerApp, ui: &mut Ui) {
    let summary = app.selection_summary().unwrap_or_default();
    ui.label(RichText::new(summary).small().color(theme::ACCENT));
    if small(ui, "Invert bits", "Flip every bit of the selection").clicked() {
        app.apply_operation(Operation::Invert);
    }
    ui.menu_button(RichText::new("Fill…").small(), |ui| show_fill_fields(app, ui));
    ui.menu_button(RichText::new("XOR…").small(), |ui| show_key_fields(app, ui));
    ui.menu_button(RichText::new("Insert…").small(), |ui| show_insert_fields(app, ui));
    if small(ui, "Skip", "Fold these bytes out of the views without deleting them").clicked() {
        app.skip_selection();
    }
    if small(ui, "Delete ⌫", "Delete the selected bytes").clicked() {
        app.apply_operation(Operation::Delete);
    }
    ui.menu_button(RichText::new("More ▾").small(), |ui| show_selection_menu(app, ui));
}

fn small(ui: &mut Ui, label: &str, hint: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(label).small())).on_hover_text(hint)
}

/// Draw a small "⋯ N skipped" chip at `at`; returns whether it was clicked.
pub fn fold_chip(ui: &Ui, id: Id, at: Pos2, hidden: usize, colour: Color32) -> bool {
    let text = format!("⋯ {} skipped", compress::human_bytes(hidden));
    let galley = ui.painter().layout_no_wrap(text, egui::FontId::proportional(10.0), Color32::BLACK);
    let rect = Rect::from_min_size(at, galley.size() + vec2(8.0, 2.0));
    let response = ui.interact(rect, id, egui::Sense::click()).on_hover_text("Skipped bytes. Click to show them again.");
    let fill = if response.hovered() { colour } else { colour.gamma_multiply(0.85) };
    ui.painter().rect_filled(rect, 3.0, fill);
    ui.painter().galley(rect.min + vec2(4.0, 1.0), galley, Color32::BLACK);
    response.clicked()
}
