//! Moving, resizing and nudging a selection directly in the raster and the
//! hex dump.
//!
//! Dragging from inside a selection moves its bytes: a caret shows where
//! they will land, and Esc cancels. Dragging the first or last byte of a
//! selected range moves that end. Alt with the arrow keys nudges the
//! selected bytes a byte left or right, or a row up or down.

use crate::app::ViewerApp;
use crate::selection::Selection;
use crate::selection_ops::Operation;

/// What a drag starting on a byte does to the selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionHandle {
    /// Inside the selection: move the selected bytes.
    Move,
    /// The first byte of a range: move the start.
    ResizeStart,
    /// The last byte of a range: move the end.
    ResizeEnd,
}

/// A drag that is moving the selected bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MoveDrag {
    /// Where the bytes would land: before this document offset.
    pub target: usize,
    /// Esc was pressed; releasing the button does nothing.
    pub cancelled: bool,
}

impl ViewerApp {
    /// What dragging from `offset` would do to the selection, if anything.
    pub fn selection_handle_at(&self, offset: usize) -> Option<SelectionHandle> {
        let selected = self.current_selection()?;
        if !selected.contains(offset) {
            return None;
        }
        match selected {
            Selection::Range(start, len) if len >= 2 && offset == start => Some(SelectionHandle::ResizeStart),
            Selection::Range(start, len) if len >= 2 && offset == start + len - 1 => Some(SelectionHandle::ResizeEnd),
            _ => Some(SelectionHandle::Move),
        }
    }

    /// Start a plain drag on `byte`: move the selection when it starts inside
    /// it, resize it from an end, or select a new range.
    pub fn begin_plain_drag(&mut self, byte: usize, extend: bool) {
        if extend {
            self.begin_drag_selection(byte, true);
            return;
        }
        match self.selection_handle_at(byte) {
            Some(SelectionHandle::Move) => self.move_drag = Some(MoveDrag { target: byte, cancelled: false }),
            Some(SelectionHandle::ResizeStart) => {
                let (start, len) = self.selection().unwrap_or((byte, 1));
                self.begin_drag_selection(start + len - 1, false);
                self.drag_selection_to(byte);
            }
            Some(SelectionHandle::ResizeEnd) => {
                let (start, _) = self.selection().unwrap_or((byte, 1));
                self.begin_drag_selection(start, false);
                self.drag_selection_to(byte);
            }
            None => self.begin_drag_selection(byte, false),
        }
    }

    /// Follow the pointer during a drag: the caret of a move, or the
    /// selection's moving end.
    pub fn continue_drag(&mut self, byte: usize) {
        match &mut self.move_drag {
            Some(drag) => drag.target = byte,
            None => self.drag_selection_to(byte),
        }
    }

    /// The button was released: drop moved bytes at the caret, or finish
    /// the selection.
    pub fn finish_drag(&mut self) {
        let Some(drag) = self.move_drag.take() else {
            self.end_drag_selection();
            return;
        };
        if drag.cancelled {
            self.status = "Move cancelled".to_string();
        } else if self.is_selected(drag.target) {
            self.status = "Dropped onto the selection itself: nothing moved".to_string();
        } else {
            self.move_selection_to(drag.target);
        }
    }

    /// Esc during a move: release does nothing. Returns whether a move was
    /// in progress.
    pub fn cancel_move_drag(&mut self) -> bool {
        match &mut self.move_drag {
            Some(drag) => {
                drag.cancelled = true;
                true
            }
            None => false,
        }
    }

    /// Where moved bytes would land, while a move drag is in progress.
    pub fn move_caret(&self) -> Option<usize> {
        self.move_drag.filter(|drag| !drag.cancelled).map(|drag| drag.target)
    }

    /// Alt+arrow: nudge the selected bytes `delta` bytes along the document
    /// (a row is the row stride). A plain range moves as a block; the ranges
    /// of a column or multi-range selection each swap places with the byte
    /// beside them, so they can only be nudged by one byte.
    pub fn nudge_selection(&mut self, delta: i64) {
        let Some(selected) = self.current_selection() else { return };
        match selected {
            Selection::Range(start, len) => {
                let destination = (start as i64 + delta).clamp(0, (self.document.len() - len) as i64) as usize;
                if destination != start {
                    // Counted before the cut: bytes moving right land after the bytes they pass.
                    let before_cut = if destination > start { destination + len } else { destination };
                    self.move_selection_to(before_cut);
                }
            }
            _ if delta.abs() == 1 => self.nudge_ranges_by_one(selected, delta < 0),
            _ => self.status = "A column or several ranges can be nudged a byte left or right; to move them further, drag them".to_string(),
        }
    }

    /// Swap each selected range with the byte before it (`left`) or after it.
    fn nudge_ranges_by_one(&mut self, selected: Selection, left: bool) {
        let len = self.document.len();
        let ranges = selected.ranges(len);
        let widened: Vec<(usize, usize)> = ranges
            .iter()
            .filter_map(|&(start, range_len)| if left { start.checked_sub(1).map(|before| (before, range_len + 1)) } else { (start + range_len < len).then_some((start, range_len + 1)) })
            .collect();
        let overlapping = widened.windows(2).any(|pair| pair[0].0 + pair[0].1 > pair[1].0);
        if widened.len() != ranges.len() || overlapping {
            self.status = "Cannot nudge: a range would run off the document or into the next one".to_string();
            return;
        }
        let shift: i64 = if left { 1 } else { -1 };
        self.select_ranges(widened, None);
        self.apply_operation(Operation::RotateBytes(shift));
        match selected {
            Selection::Columns(mut column) => {
                // Keep the column inside its records where it can be, so it
                // still reads as the same column.
                match left {
                    true if column.column > 0 => column.column -= 1,
                    true => column.first_row_start -= 1,
                    false if column.column + column.width < column.stride => column.column += 1,
                    false => column.first_row_start += 1,
                }
                self.select_column(column);
            }
            _ => {
                let moved = ranges.iter().map(|&(start, range_len)| (if left { start - 1 } else { start + 1 }, range_len)).collect();
                self.select_ranges(moved, None);
            }
        }
    }
}
