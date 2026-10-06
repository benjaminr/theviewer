//! The Selection menu: every byte operation, for any kind of selection, in
//! one place shared by the raster's and the hex dump's right-click menus,
//! the packet viewer, the findings list and the small toolbar that floats
//! beside a selection.
//!
//! Operations act on every selected range (each record of a column, each
//! range of a multi-range selection), or on the byte at the cursor when
//! nothing is selected, and each is one undo step, taken through the API's
//! `transform.apply` with the selection it acted on.

use std::sync::Arc;

use eframe::egui::{self, Color32, Frame, Id, Order, Pos2, Rect, RichText, Ui, vec2};

use crate::api::edits::{EditResult, HistoryResult};
use crate::app::{DialogKind, FileAction, ViewerApp};
use crate::compress::{self, Codec};
use crate::document::Document;
use crate::ops;
use crate::plugin::Finding;
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
    /// the changed bytes selected. Carried out as `transform.apply`, with
    /// the selection (or the byte at the cursor) it acts on, so the step
    /// can be repeated; a failure is said on the status bar. Returns
    /// whether it was applied.
    pub fn apply_operation(&mut self, operation: Operation) -> bool {
        let ranges = self.operation_ranges();
        if ranges.is_empty() {
            self.status = "Nothing to change: the cursor is at the end of the document".to_string();
            return false;
        }
        let target = self.current_selection().unwrap_or(Selection::Range(self.cursor, 1));
        let params = serde_json::json!({ "selection": target, "operation": operation });
        if self.perform("transform.apply", params).is_err() {
            return false;
        }
        let bytes: usize = ranges.iter().map(|&(_, len)| len).sum();
        let places = if ranges.len() == 1 { format!("at {:#x}", ranges[0].0) } else { format!("in {} ranges", ranges.len()) };
        self.status = format!("{} {bytes} bytes {places}. Undo with Cmd+Z.", operation.label());
        true
    }

    /// Select `selection`, of any kind, with the cursor at `cursor`: at the
    /// start or end of one of its ranges, which is then the one Shift
    /// extends (a column's cursor is at its end); `None` selects nothing and
    /// puts the cursor there.
    pub fn set_selection(&mut self, cursor: usize, selection: Option<Selection>) {
        match selection {
            Some(Selection::Range(start, len)) if len > 0 => {
                self.select_ranges(vec![(start, len)], None);
                self.face_cursor_to_start(cursor);
            }
            Some(Selection::Range(start, _)) => self.set_cursor(start, false),
            Some(Selection::Ranges(ranges)) => {
                let primary = ranges.iter().copied().find(|&(start, len)| cursor == start || cursor == start + len);
                self.select_ranges(ranges, primary);
                self.face_cursor_to_start(cursor);
            }
            Some(Selection::Columns(column)) => self.select_column(column),
            None => self.set_cursor(cursor, false),
        }
    }

    /// Turn the anchor-to-cursor range round when `cursor` is its start, so
    /// Shift extends it backwards from its end.
    fn face_cursor_to_start(&mut self, cursor: usize) {
        if let Some((start, len)) = self.selection()
            && cursor == start
        {
            self.anchor = Some(start + len);
            self.cursor = start;
        }
    }
}

// ---------------------------------------------------------------------------
// The person's cursor and selection
// ---------------------------------------------------------------------------

impl ViewerApp {
    /// The person puts the cursor at `offset` (a click, a key), selecting
    /// nothing, as `cursor.set`. The views stay where the action leaves
    /// them. Returns whether it moved.
    pub fn place_cursor(&mut self, offset: usize) -> bool {
        let offset = offset.min(self.document.len());
        self.keeping_the_hex_dump_still(|app| app.perform("cursor.set", serde_json::json!({ "offset": offset })).is_ok())
    }

    /// The person selects `selection` (nothing when `None`) with the cursor
    /// at `cursor`, as `selection.set`. The cursor is in the step when it
    /// sits where the API allows (an end of one of the ranges, a column's
    /// end); otherwise it goes to the end of the last range. The views stay
    /// where the action leaves them. Returns whether it was selected.
    pub fn select_as_person(&mut self, selection: Option<Selection>, cursor: usize) -> bool {
        let cursor = cursor.min(self.document.len());
        let ranges = selection.as_ref().map(|selected| selected.ranges(self.document.len())).unwrap_or_default();
        let cursor_fits = match &selection {
            None => true,
            Some(Selection::Columns(_)) => ranges.last().is_some_and(|&(start, len)| cursor == start + len),
            Some(_) => ranges.iter().any(|&(start, len)| cursor == start || cursor == start + len),
        };
        let mut params = serde_json::json!({ "selection": selection });
        if cursor_fits {
            params["cursor"] = serde_json::json!(cursor);
        }
        self.keeping_the_hex_dump_still(|app| app.perform("selection.set", params).is_ok())
    }

    /// The person moves the cursor to `target` (a click, an arrow key);
    /// with `extend` (Shift held) the selection runs from its anchor to
    /// `target` instead, beside any other selected ranges.
    pub fn move_cursor_as_person(&mut self, target: usize, extend: bool) {
        let target = target.min(self.document.len());
        if !extend {
            self.place_cursor(target);
            return;
        }
        let anchor = self.anchor.unwrap_or(self.cursor);
        let mut ranges = self.extra_ranges.clone();
        ranges.push((anchor.min(target), anchor.abs_diff(target)));
        self.select_as_person(selection_of(ranges), target);
    }

    /// Esc: the person selects nothing, leaving the cursor where it is, as
    /// `selection.set`; nothing is called when nothing is selected.
    pub fn clear_selection_as_person(&mut self) {
        self.pending_low_nibble = false;
        if self.anchor.is_some() || !self.extra_ranges.is_empty() || self.column_selection.is_some() {
            let cursor = self.cursor;
            self.select_as_person(None, cursor);
        }
    }

    /// The person selects a finding's bytes (the Findings list, the
    /// context menu), as `selection.set`, and brings them into view.
    pub fn select_finding(&mut self, finding: &Finding) {
        let (start, end) = (finding.start.min(self.document.len()), finding.end().min(self.document.len()));
        if self.select_as_person(Some(Selection::Range(start, end - start)), end) {
            self.select_pattern(finding);
        }
    }

    /// Run `action`, which selects through the API, keeping the hex dump
    /// scrolled where it was: the API's selection scrolls the dump to show
    /// a client's selection, but the person's own actions scroll the views
    /// themselves, as they did before.
    pub(crate) fn keeping_the_hex_dump_still(&mut self, action: impl FnOnce(&mut ViewerApp) -> bool) -> bool {
        let hex_top_row = self.hex_top_row;
        let done = action(self);
        self.hex_top_row = hex_top_row;
        done
    }
}

impl ViewerApp {
    /// Undo or redo through `method` (`history.undo` or `history.redo`),
    /// putting the cursor where the step was and keeping the hex dump still
    /// as the keys always have. Returns what the API said, or `None` when
    /// it failed (the status bar says why).
    pub(crate) fn step_history(&mut self, method: &str) -> Option<HistoryResult> {
        let mut stepped = None;
        self.keeping_the_hex_dump_still(|app| {
            stepped = app.perform_typed::<HistoryResult>(method, serde_json::json!({})).ok();
            stepped.is_some()
        });
        let at = stepped.as_ref()?.at as usize;
        self.after_edit(at);
        stepped
    }

    /// One way of pasting, as `method`, leaving the cursor at `cursor`.
    /// Returns whether it was pasted.
    pub(crate) fn paste_step(&mut self, method: &str, params: serde_json::Value, cursor: usize) -> bool {
        let done = self.perform(method, params).is_ok();
        if done {
            self.after_edit(cursor);
        }
        done
    }
}

/// `ranges` as a selection: nothing, one range or several, merged where
/// they touch.
pub fn selection_of(ranges: Vec<(usize, usize)>) -> Option<Selection> {
    match crate::selection::normalise_ranges(ranges).as_slice() {
        [] => None,
        &[(start, len)] => Some(Selection::Range(start, len)),
        many => Some(Selection::Ranges(many.to_vec())),
    }
}

/// Write `operation`'s result over `ranges` (sorted, not overlapping) of
/// `document` as one undo step, or change nothing when it fails. Returns
/// where each range's new bytes are.
pub fn rewrite_ranges(document: &mut Document, ranges: &[(usize, usize)], operation: &Operation) -> Result<Vec<(usize, usize)>, String> {
    let Some(&(start, _)) = ranges.first() else { return Ok(Vec::new()) };
    let end = ranges.last().map_or(start, |&(range_start, len)| range_start + len);
    if end - start <= SINGLE_EDIT_LIMIT {
        let span = document.read_range(start, end - start);
        let (rebuilt, changed) = selection_ops::rebuild_span(&span, start, ranges, operation)?;
        if rebuilt != span {
            document.replace(start, span.len(), &rebuilt);
        }
        return Ok(changed);
    }
    // Too wide to rewrite in one piece: work out every range first, so a
    // failure changes nothing, then write them from the last back.
    let mut replacements = Vec::with_capacity(ranges.len());
    for (index, &(range_start, len)) in ranges.iter().enumerate() {
        let bytes = document.read_range(range_start, len);
        replacements.push(selection_ops::transform_range(operation, &bytes, index)?);
    }
    let mut changed = Vec::with_capacity(ranges.len());
    let mut shift: isize = 0;
    for (&(range_start, len), replacement) in ranges.iter().zip(&replacements) {
        changed.push(((range_start as isize + shift) as usize, replacement.len()));
        shift += replacement.len() as isize - len as isize;
    }
    document.grouped(|document| {
        for (&(range_start, len), replacement) in ranges.iter().zip(&replacements).rev() {
            document.replace(range_start, len, replacement);
        }
    });
    Ok(changed)
}

/// What is selected after `operation` changed `changed` (where each
/// range's new bytes are), when `selected` was selected before: the same
/// column, the changed ranges, or just the cursor (after a delete, say).
/// Returns the cursor and the selection, in a document of `document_len`
/// bytes.
pub fn selection_after_operation(selected: Option<Selection>, operation: &Operation, changed: &[(usize, usize)], cursor: usize, document_len: usize) -> (usize, Option<Selection>) {
    let kept: Vec<(usize, usize)> = changed.iter().copied().filter(|&(_, len)| len > 0).collect();
    match selected {
        Some(Selection::Columns(column)) if operation.keeps_length() => {
            let (start, len) = column.span();
            ((start + len).min(document_len), Some(Selection::Columns(column)))
        }
        Some(_) if kept.len() > 1 => {
            let end = kept.last().map_or(cursor, |&(start, len)| start + len);
            (end, Some(Selection::Ranges(kept)))
        }
        Some(_) if kept.len() == 1 && kept[0].1 > 1 => (kept[0].0 + kept[0].1, Some(Selection::Range(kept[0].0, kept[0].1))),
        Some(_) if kept.len() == 1 => (kept[0].0, None),
        _ => {
            let at = changed.first().map_or(cursor, |&(start, _)| start);
            (at.min(document_len), None)
        }
    }
}

impl ViewerApp {

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

    /// Open the selected bytes (or the byte at the cursor) as a document of
    /// their own, as `documents.derive`; Back returns.
    pub fn open_selection_as_document(&mut self) {
        let name = format!("{} › selection", self.display_name());
        let params = match self.operation_ranges().as_slice() {
            &[(start, len)] => serde_json::json!({ "start": start, "len": len, "name": name }),
            ranges => serde_json::json!({ "ranges": ranges, "name": name }),
        };
        let _ = self.perform("documents.derive", params);
    }

    /// Cut the selected ranges out and put their bytes, one after another,
    /// at document offset `destination` (counted before the cut), as one
    /// undo step through `bytes.move`, which selects them. Returns where
    /// they landed.
    pub fn move_selection_to(&mut self, destination: usize) -> Option<(usize, usize)> {
        let ranges = self.operation_ranges();
        if ranges.is_empty() {
            return None;
        }
        let params = serde_json::json!({ "ranges": ranges, "to": destination.min(self.document.len()) });
        match self.perform_typed::<EditResult>("bytes.move", params) {
            Ok(moved) => {
                let (landing, len) = moved.ranges.first().map_or((0, 0), |&(start, len)| (start as usize, len as usize));
                self.reveal_cursor_in_hex(false);
                self.status = format!("Moved {len} bytes to {landing:#x}. Undo with Cmd+Z.");
                Some((landing, len))
            }
            Err(error) => {
                self.status = format!("Move failed: {}", error.message);
                None
            }
        }
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
    ui.menu_button("Insert…   I", |ui| show_insert_fields(app, ui));
    if ui.button("Delete   ⌫").clicked() {
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
    if ui.button("Skip (fold out of the views)   S").on_hover_text("Leave these bytes out of the raster and the hex dump without deleting them; click the marker to show them again").clicked() {
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

/// The Insert window, opened with I: the insert fields and where to insert.
pub fn show_insert_dialog(app: &mut ViewerApp, ctx: &egui::Context) {
    if !app.insert_dialog_open {
        return;
    }
    let mut open = true;
    let mut acted = false;
    egui::Window::new("Insert bytes").open(&mut open).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
        acted = insert_fields(app, ui);
        if ui.input(|input| input.key_pressed(egui::Key::Escape)) {
            acted = true;
        }
    });
    app.insert_dialog_open = open && !acted;
}

fn show_insert_fields(app: &mut ViewerApp, ui: &mut Ui) {
    if insert_fields(app, ui) {
        ui.close();
    }
}

/// The insert fields and buttons. Returns whether bytes were inserted.
fn insert_fields(app: &mut ViewerApp, ui: &mut Ui) -> bool {
    let mut acted = false;
    ui.horizontal(|ui| {
        hex_field(ui, &mut app.insert_value_text, "hex pattern");
        ui.add(egui::DragValue::new(&mut app.insert_count).range(1..=usize::MAX / 2).prefix("× "));
    });
    let size = compress::human_bytes(app.insert_count.max(1));
    ui.label(RichText::new(format!("{size} of the pattern, repeated")).small().color(theme::TEXT_DIM));
    ui.horizontal(|ui| {
        let has_selection = app.current_selection().is_some();
        if ui.add_enabled(has_selection, egui::Button::new("Before")).on_hover_text("Insert before each selected range").clicked() {
            app.insert_around_selection(false);
            acted = true;
        }
        if ui.add_enabled(has_selection, egui::Button::new("After")).on_hover_text("Insert after each selected range").clicked() {
            app.insert_around_selection(true);
            acted = true;
        }
        if ui.button("At cursor").clicked() {
            app.insert_from_fields();
            acted = true;
        }
    });
    acted
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
    ui.menu_button(RichText::new("Insert…  I").small(), |ui| show_insert_fields(app, ui));
    if small(ui, "Skip  S", "Fold these bytes out of the views without deleting them (S); click the marker to show them again").clicked() {
        app.skip_selection();
    }
    if small(ui, "Delete ⌫", "Delete the selected bytes (Backspace)").clicked() {
        app.apply_operation(Operation::Delete);
    }
    ui.label(RichText::new("drag to move · Alt+arrows nudge").small().color(theme::TEXT_DIM));
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::actions::take_performed;
    use crate::app::{EditMode, Launch, ViewerApp};
    use crate::bus::Topic;
    use crate::selection::Selection;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        app
    }

    /// Who published the edits made since `cursor`.
    fn editors_since(app: &mut ViewerApp, cursor: u64) -> Vec<String> {
        app.run_bus();
        app.bus.changed_since(cursor).messages.iter().filter(|message| message.topic() == Topic::DocumentEdited).map(|message| message.producer().to_string()).collect()
    }

    #[test]
    fn inverting_the_selection_from_the_palette_is_the_person_s_step_through_the_api() {
        let mut app = app_with(&[0x0F; 8]);
        app.restore_selection(2, 3);
        let cursor = app.bus.cursor();
        let invert = crate::commands::commands().into_iter().find(|command| command.id == "edit.invert").unwrap();
        (invert.run)(&mut app, &eframe::egui::Context::default());
        assert_eq!(editors_since(&mut app, cursor), ["panel"]);
        assert_eq!(app.document.read_range(0, 8), [0x0F, 0x0F, 0xF0, 0xF0, 0xF0, 0x0F, 0x0F, 0x0F]);
        assert_eq!(app.current_selection(), Some(Selection::Range(2, 3)), "what it produced stays selected");
        assert_eq!(app.document.undo_label(), Some("Invert"));
        assert!(app.status.starts_with("Inverted 3 bytes at 0x2"), "{}", app.status);
    }

    #[test]
    fn an_operation_with_nothing_selected_changes_the_byte_at_the_cursor() {
        let mut app = app_with(&[0x00; 4]);
        app.set_cursor(1, false);
        app.invert_target();
        assert_eq!(app.document.read_range(0, 4), [0x00, 0xFF, 0x00, 0x00]);
        assert_eq!((app.cursor, app.current_selection()), (1, None), "nothing is selected afterwards, as before");
    }

    #[test]
    fn a_byte_typed_over_another_is_written_through_the_api_and_undoes_as_one_step() {
        let mut app = app_with(&[0x12, 0x34]);
        take_performed();
        app.type_hex_digit(0xA);
        assert_eq!((app.document.read_range(0, 2), app.cursor, app.pending_low_nibble), (vec![0xA2, 0x34], 0, true));
        app.type_hex_digit(0xB);
        assert_eq!((app.document.read_range(0, 2), app.cursor, app.pending_low_nibble), (vec![0xAB, 0x34], 1, false));
        assert_eq!(
            take_performed(),
            [("bytes.write".to_string(), json!({"start": 0, "data": "a2"})), ("bytes.write".to_string(), json!({"start": 0, "data": "ab", "coalesce": true}))]
        );
        assert_eq!(app.document.undo_label(), Some("Overwrite 1 byte"));
        app.document.undo();
        assert_eq!(app.document.read_range(0, 2), [0x12, 0x34], "one undo takes the whole byte back");
        assert!(!app.document.can_undo());
    }

    #[test]
    fn a_byte_typed_in_insert_mode_is_inserted_and_undoes_as_one_step() {
        let mut app = app_with(&[0x12, 0x34]);
        app.edit_mode = EditMode::Insert;
        app.set_cursor(1, false);
        take_performed();
        app.type_hex_digit(0xC);
        app.type_hex_digit(0xD);
        assert_eq!((app.document.read_range(0, 3), app.cursor), (vec![0x12, 0xCD, 0x34], 2));
        assert_eq!(
            take_performed(),
            [("bytes.insert".to_string(), json!({"at": 1, "data": "c0"})), ("bytes.write".to_string(), json!({"start": 1, "data": "cd", "coalesce": true}))]
        );
        assert_eq!(app.document.undo_label(), Some("Insert 1 byte"));
        app.document.undo();
        assert_eq!(app.document.read_range(0, 3), [0x12, 0x34]);
    }

    fn performed(method: &str, params: serde_json::Value) -> (String, serde_json::Value) {
        (method.to_string(), params)
    }

    #[test]
    fn inserting_the_fields_bytes_at_the_cursor_is_one_step_through_the_api() {
        let mut app = app_with(b"abcd");
        app.set_cursor(1, false);
        app.insert_value_text = "DE AD".to_string();
        app.insert_count = 3;
        app.insert_from_fields();
        assert_eq!(take_performed(), [performed("bytes.insert", json!({"at": 1, "data": "deadde"}))]);
        assert_eq!(app.document.read_range(0, 7), [b'a', 0xDE, 0xAD, 0xDE, b'b', b'c', b'd']);
        assert_eq!((app.cursor, app.status.as_str()), (4, "Inserted 3 bytes at 0x1"));
        app.insert_value_text = "not hex".to_string();
        app.insert_from_fields();
        assert!(take_performed().is_empty());
        assert!(app.status.starts_with("Insert value must be hex"), "{}", app.status);
    }

    #[test]
    fn backspace_with_nothing_selected_deletes_the_byte_before_the_cursor_through_the_api() {
        let mut app = app_with(b"abcd");
        app.set_cursor(2, false);
        app.backspace();
        assert_eq!(take_performed(), [performed("bytes.delete", json!({"start": 1, "len": 1}))]);
        assert_eq!((app.document.read_range(0, 3), app.cursor), (b"acd".to_vec(), 1));
        app.set_cursor(0, false);
        app.backspace();
        assert!(take_performed().is_empty(), "at the start there is nothing to delete");
    }

    #[test]
    fn flipping_a_bit_in_the_inspector_writes_that_bit_through_the_api() {
        let mut app = app_with(&[0x00, 0x00]);
        app.set_cursor(1, false);
        app.toggle_bit_at_cursor(7);
        app.toggle_bit_at_cursor(0);
        assert_eq!(app.document.read_range(0, 2), [0x00, 0x81]);
        app.toggle_bit_at_cursor(7);
        assert_eq!(app.document.read_range(0, 2), [0x00, 0x01]);
        assert_eq!(
            take_performed(),
            [
                performed("bits.write", json!({"bit_start": 15, "bits": "1", "order": "lsb"})),
                performed("bits.write", json!({"bit_start": 8, "bits": "1", "order": "lsb"})),
                performed("bits.write", json!({"bit_start": 15, "bits": "0", "order": "lsb"})),
            ]
        );
    }

    #[test]
    fn pasting_replaces_the_selection_overwrites_or_inserts_through_the_api() {
        let mut app = app_with(b"abcd");
        app.restore_selection(1, 2);
        app.paste(Some("AA BB CC".to_string()));
        assert_eq!(app.document.read_range(0, 8), [b'a', 0xAA, 0xBB, 0xCC, b'd']);
        assert_eq!((app.cursor, app.status.as_str()), (4, "Pasted 3 bytes"));
        app.paste(Some("0102".to_string()));
        assert_eq!(app.document.read_range(0, 8), [b'a', 0xAA, 0xBB, 0xCC, 0x01, 0x02], "overwriting runs on past the end");
        app.edit_mode = EditMode::Insert;
        app.set_cursor(0, false);
        app.paste(Some("ff".to_string()));
        assert_eq!(app.document.read_range(0, 2), [0xFF, b'a']);
        assert_eq!(
            take_performed(),
            [
                performed("bytes.replace", json!({"start": 1, "len": 2, "data": "aabbcc"})),
                performed("bytes.replace", json!({"start": 4, "len": 1, "data": "0102"})),
                performed("bytes.insert", json!({"at": 0, "data": "ff"})),
            ]
        );
        app.edit_mode = EditMode::Overwrite;
        app.set_cursor(2, false);
        app.paste(Some("0000".to_string()));
        assert_eq!(take_performed(), [performed("bytes.write", json!({"start": 2, "data": "0000"}))]);
    }

    #[test]
    fn cutting_copies_the_selection_and_deletes_it_through_the_api() {
        let mut app = app_with(b"abcdef");
        app.restore_selection(1, 2);
        app.cut(&eframe::egui::Context::default());
        assert_eq!(take_performed(), [performed("transform.apply", json!({"selection": {"range": [1, 2]}, "operation": crate::selection_ops::Operation::Delete}))]);
        assert_eq!((app.document.read_range(0, 6), app.clipboard.clone()), (b"adef".to_vec(), b"bc".to_vec()));
    }

    #[test]
    fn undo_and_redo_go_through_the_api_and_say_what_they_undid() {
        let mut app = app_with(&[0x12, 0x34]);
        app.undo();
        assert!(take_performed().is_empty(), "with nothing to undo nothing is called");
        app.type_hex_digit(0xA);
        app.type_hex_digit(0xB);
        take_performed();
        app.undo();
        assert_eq!((app.document.read_range(0, 2), app.cursor, app.status.as_str()), (vec![0x12, 0x34], 0, "Undid Overwrite 1 byte"));
        app.redo();
        assert_eq!((app.document.read_range(0, 2), app.status.as_str()), (vec![0xAB, 0x34], "Redid Overwrite 1 byte"));
        assert_eq!(take_performed(), [performed("history.undo", json!({})), performed("history.redo", json!({}))]);
        app.redo();
        assert!(take_performed().is_empty());
    }

    #[test]
    fn an_operation_that_fails_changes_nothing_and_says_why() {
        let mut app = app_with(b"not compressed at all");
        app.restore_selection(0, 8);
        app.apply_operation(crate::selection_ops::Operation::Decompress);
        assert_eq!(app.document.read_range(0, 8), b"not comp");
        assert!(app.status.contains("failed"), "{}", app.status);
        assert!(!app.document.can_undo());
    }
}
