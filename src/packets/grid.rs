//! Packets laid out one per row, so the same field lines up in a column
//! across every packet, and operations on whole columns.
//!
//! Each row starts at its packet's first byte, optionally shifted right so a
//! pattern (a sync word, a field) or the packet's end lines up across rows.
//! A grid column then maps to one byte offset in each packet; a column
//! selection becomes one document range per packet, and a column operation
//! changes those ranges together.
//!
//! Everything here is pure and bounded; the panel reads the bytes and turns
//! the results into one undoable document edit.

use super::dissect::Layer;
use super::split::BytePattern;
use crate::columns::{self, ColumnKind};
use crate::plugin::Field;

/// Widest grid drawn, in columns; longer packets are cut off at the right.
pub const MAX_GRID_COLUMNS: usize = 65_536;
/// Bytes of each row searched for an alignment pattern.
pub const ALIGN_SEARCH_LIMIT: usize = 4096;
/// Columns and rows sampled for the column statistics.
pub const MAX_STATISTIC_COLUMNS: usize = 2048;
pub const MAX_STATISTIC_ROWS: usize = 1024;
/// Fewest values a column needs before it is classified.
const MIN_STATISTIC_VALUES: usize = 2;
/// Widest integer a counter or a set value is written as.
const MAX_INTEGER_BYTES: usize = 8;
/// Rows whose dissections name the columns.
pub const MAX_FIELD_ROWS: usize = 32;
/// Layers that hold no protocol's fields, whose bytes go unnamed.
const UNNAMED_LAYERS: [&str; 4] = ["Data", "Payload", "Trailing data", "Padding"];

/// How rows are lined up.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Alignment {
    /// Every row starts in column 0.
    #[default]
    Start,
    /// Rows are shifted so the first match of the pattern lines up; rows
    /// without a match stay in column 0.
    Pattern(BytePattern),
    /// Rows are shifted so their last bytes line up (trailers, checksums).
    End,
}

/// How many columns each row is shifted right by, one per row.
pub fn row_shifts(rows: &[&[u8]], alignment: &Alignment) -> Vec<usize> {
    match alignment {
        Alignment::Start => vec![0; rows.len()],
        Alignment::End => {
            let widest = rows.iter().map(|row| row.len()).max().unwrap_or(0);
            rows.iter().map(|row| widest - row.len()).collect()
        }
        Alignment::Pattern(pattern) => {
            let matches: Vec<Option<usize>> = rows.iter().map(|row| pattern.find_from(&row[..row.len().min(ALIGN_SEARCH_LIMIT)], 0)).collect();
            let target = matches.iter().flatten().copied().max().unwrap_or(0);
            matches.iter().map(|found| found.map_or(0, |at| target - at)).collect()
        }
    }
}

/// Columns the grid needs: the furthest any shifted row reaches, at most
/// [`MAX_GRID_COLUMNS`].
pub fn grid_width(lengths: impl Iterator<Item = usize>, shifts: &[usize]) -> usize {
    lengths.zip(shifts).map(|(len, shift)| len.saturating_add(*shift)).max().unwrap_or(0).min(MAX_GRID_COLUMNS)
}

/// Where a row's packet sits: its document range and its shift in the grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowPlacement {
    pub offset: usize,
    pub len: usize,
    pub shift: usize,
}

impl RowPlacement {
    /// The offset within the packet shown in grid `column`, if any.
    pub fn packet_offset(&self, column: usize) -> Option<usize> {
        let within = column.checked_sub(self.shift)?;
        (within < self.len).then_some(within)
    }

    /// The grid column showing document offset `position`, if this row holds it.
    pub fn column_of(&self, position: usize) -> Option<usize> {
        let within = position.checked_sub(self.offset)?;
        (within < self.len).then_some(within + self.shift)
    }
}

/// One row's part of a column selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnSlice {
    /// Index of the row in the grid.
    pub row: usize,
    /// Document range of the bytes in the selected columns.
    pub offset: usize,
    pub len: usize,
    /// Selected columns left of the row's first byte, so values line up
    /// when a shifted row only partly covers the selection.
    pub skipped: usize,
}

/// The bytes of columns `first..first + width` in each of `rows` (given as
/// `(row index, placement)`), skipping rows that do not reach them.
pub fn column_slices(rows: &[(usize, RowPlacement)], first: usize, width: usize) -> Vec<ColumnSlice> {
    let end = first.saturating_add(width);
    rows.iter()
        .filter_map(|&(row, placement)| {
            let low = first.max(placement.shift);
            let high = end.min(placement.shift.saturating_add(placement.len));
            (low < high).then(|| ColumnSlice { row, offset: placement.offset + (low - placement.shift), len: high - low, skipped: low - first })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Column statistics
// ---------------------------------------------------------------------------

/// What each column looks like across the rows, from the first
/// [`MAX_STATISTIC_ROWS`] rows and [`MAX_STATISTIC_COLUMNS`] columns. `None`
/// where too few rows reach the column.
pub fn column_kinds(rows: &[&[u8]], shifts: &[usize], columns: usize) -> Vec<Option<ColumnKind>> {
    let sampled = rows.len().min(MAX_STATISTIC_ROWS);
    let mut values = Vec::with_capacity(sampled);
    (0..columns.min(MAX_STATISTIC_COLUMNS))
        .map(|column| {
            values.clear();
            for (row, &shift) in rows.iter().zip(shifts).take(sampled) {
                if let Some(&byte) = column.checked_sub(shift).and_then(|within| row.get(within)) {
                    values.push(byte);
                }
            }
            (values.len() >= MIN_STATISTIC_VALUES).then(|| columns::profile_column(&values, column).kind)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Column names from the dissection
// ---------------------------------------------------------------------------

/// The innermost field of a packet's dissection holding packet offset
/// `offset`, as "Transaction ID (DNS)"; `None` where no protocol's field
/// does (data, payload or trailing bytes).
pub fn field_at(layers: &[Layer], offset: usize) -> Option<String> {
    let layer = layers.iter().rev().find(|layer| offset >= layer.offset && offset < layer.offset + layer.len)?;
    if UNNAMED_LAYERS.contains(&layer.name.as_str()) {
        return None;
    }
    let field = innermost_field(&layer.fields, offset)?;
    Some(format!("{} ({})", field.name, layer.name))
}

fn innermost_field(fields: &[Field], offset: usize) -> Option<&Field> {
    let holding = fields.iter().find(|field| offset >= field.offset && offset < field.offset + field.len)?;
    innermost_field(&holding.children, offset).or(Some(holding))
}

/// A name for each grid column from the dissected rows, given as `(layers,
/// lead)` where `lead` is the grid column of the packet's first byte: the
/// field every row reaching the column agrees on, or `None` where they
/// differ or no field covers it.
pub fn column_fields(rows: &[(&[Layer], usize)], columns: usize) -> Vec<Option<String>> {
    (0..columns.min(MAX_STATISTIC_COLUMNS))
        .map(|column| {
            let mut agreed: Option<String> = None;
            for &(layers, lead) in rows.iter().take(MAX_FIELD_ROWS) {
                let Some(offset) = column.checked_sub(lead) else { continue };
                if layers.iter().all(|layer| offset >= layer.offset + layer.len) {
                    continue;
                }
                let name = field_at(layers, offset)?;
                match &agreed {
                    Some(known) if *known != name => return None,
                    _ => agreed = Some(name),
                }
            }
            agreed
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Column operations
// ---------------------------------------------------------------------------

/// A change to the selected columns of each packet. Every operation keeps
/// the packets' lengths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ColumnOperation {
    Invert,
    /// Repeat the pattern across the columns.
    Fill(Vec<u8>),
    /// XOR with the key, which restarts at the first selected column.
    Xor(Vec<u8>),
    /// Add the key byte by byte, wrapping.
    Add(Vec<u8>),
    /// Write exactly these bytes (as wide as the selection).
    Set(Vec<u8>),
    /// Number the packets: `start + step × n` for the nth packet, written in
    /// the selection's width (at most 8 bytes; wider selections keep the rest).
    Counter { start: u64, step: i64, little_endian: bool },
    /// Reverse the bytes of every group of `group` bytes.
    SwapByteOrder { group: usize },
}

impl ColumnOperation {
    pub fn label(&self) -> &'static str {
        match self {
            ColumnOperation::Invert => "Inverted",
            ColumnOperation::Fill(_) => "Filled",
            ColumnOperation::Xor(_) => "XORed",
            ColumnOperation::Add(_) => "Added to",
            ColumnOperation::Set(_) => "Set",
            ColumnOperation::Counter { .. } => "Numbered",
            ColumnOperation::SwapByteOrder { .. } => "Swapped the byte order of",
        }
    }

    /// Change `column`, the whole selected width of the `ordinal`th packet.
    pub fn apply(&self, column: &mut [u8], ordinal: usize) {
        match self {
            ColumnOperation::Invert => column.iter_mut().for_each(|byte| *byte = !*byte),
            ColumnOperation::Fill(pattern) | ColumnOperation::Set(pattern) if !pattern.is_empty() => {
                for (byte, value) in column.iter_mut().zip(pattern.iter().cycle()) {
                    *byte = *value;
                }
            }
            ColumnOperation::Xor(key) if !key.is_empty() => {
                for (byte, value) in column.iter_mut().zip(key.iter().cycle()) {
                    *byte ^= *value;
                }
            }
            ColumnOperation::Add(key) if !key.is_empty() => {
                for (byte, value) in column.iter_mut().zip(key.iter().cycle()) {
                    *byte = byte.wrapping_add(*value);
                }
            }
            ColumnOperation::Counter { start, step, little_endian } => {
                let value = start.wrapping_add((*step as u64).wrapping_mul(ordinal as u64));
                write_integer(column, value, *little_endian);
            }
            ColumnOperation::SwapByteOrder { group } if *group > 1 => {
                for chunk in column.chunks_exact_mut(*group) {
                    chunk.reverse();
                }
            }
            ColumnOperation::Fill(_) | ColumnOperation::Set(_) | ColumnOperation::Xor(_) | ColumnOperation::Add(_) | ColumnOperation::SwapByteOrder { .. } => {}
        }
    }
}

/// Write `value` into the first (little endian) or last (big endian) eight
/// bytes of `column`, keeping only the low bytes when it is narrower.
fn write_integer(column: &mut [u8], value: u64, little_endian: bool) {
    let width = column.len().min(MAX_INTEGER_BYTES);
    if little_endian {
        column[..width].copy_from_slice(&value.to_le_bytes()[..width]);
    } else {
        let start = column.len() - width;
        column[start..].copy_from_slice(&value.to_be_bytes()[MAX_INTEGER_BYTES - width..]);
    }
}

/// Apply `operation` to every slice inside `span` (whose first byte is at
/// document offset `span_start`). `width` is the selection's width; a slice
/// cut short by a shifted or short row gets the matching part of the value.
/// The nth slice is the nth packet for counters.
pub fn apply_to_columns(span: &mut [u8], span_start: usize, slices: &[ColumnSlice], width: usize, operation: &ColumnOperation) {
    let mut column = vec![0u8; width];
    for (ordinal, slice) in slices.iter().enumerate() {
        let Some(start) = slice.offset.checked_sub(span_start) else { continue };
        let end = (start + slice.len).min(span.len());
        let take = end.saturating_sub(start);
        if take == 0 || slice.skipped + take > width {
            continue;
        }
        column.fill(0);
        column[slice.skipped..slice.skipped + take].copy_from_slice(&span[start..end]);
        operation.apply(&mut column, ordinal);
        span[start..end].copy_from_slice(&column[slice.skipped..slice.skipped + take]);
    }
}

/// The document ranges a column deletion removes.
pub fn deletion_ranges(slices: &[ColumnSlice]) -> Vec<(usize, usize)> {
    super::edit::merge_ranges(slices.iter().map(|slice| (slice.offset, slice.len)).collect())
}

// ---------------------------------------------------------------------------
// Copying columns
// ---------------------------------------------------------------------------

/// One packet's bytes in the selected columns, for copying.
pub struct ColumnText<'a> {
    /// The packet's index in its set (counting from 0, as the API does).
    pub packet: usize,
    pub offset: usize,
    pub bytes: &'a [u8],
}

/// One line per packet: its number, then the bytes as hex.
pub fn columns_as_hex(rows: &[ColumnText<'_>]) -> String {
    rows.iter().map(|row| format!("{}: {}\n", row.packet, super::hex_preview(row.bytes, row.bytes.len()))).collect()
}

/// A CSV table: packet, document offset, then one hex cell per column.
pub fn columns_as_csv(rows: &[ColumnText<'_>], first_column: usize, width: usize) -> String {
    let mut text = String::from("packet,offset");
    for column in first_column..first_column + width {
        text.push_str(&format!(",+{column}"));
    }
    text.push('\n');
    for row in rows {
        text.push_str(&format!("{},{:#x}", row.packet, row.offset));
        for byte in row.bytes {
            text.push_str(&format!(",{byte:02x}"));
        }
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placements(lengths: &[(usize, usize, usize)]) -> Vec<(usize, RowPlacement)> {
        lengths.iter().enumerate().map(|(row, &(offset, len, shift))| (row, RowPlacement { offset, len, shift })).collect()
    }

    #[test]
    fn rows_aligned_on_a_pattern_put_every_match_in_one_column() {
        let rows: Vec<&[u8]> = vec![b"\x7E\x01abc", b"xy\x7E\x02d", b"no match", b"z\x7E\x03"];
        let pattern = BytePattern::parse("7E ??").expect("pattern");
        let shifts = row_shifts(&rows, &Alignment::Pattern(pattern));
        assert_eq!(shifts, vec![2, 0, 0, 1]);
        let lined_up: Vec<Option<u8>> = rows
            .iter()
            .zip(&shifts)
            .map(|(row, &shift)| RowPlacement { offset: 0, len: row.len(), shift }.packet_offset(2).map(|within| row[within]))
            .collect();
        assert_eq!(lined_up, vec![Some(0x7E), Some(0x7E), Some(b' '), Some(0x7E)]);
        assert_eq!(grid_width(rows.iter().map(|row| row.len()), &shifts), 8);
    }

    #[test]
    fn rows_aligned_on_their_end_line_up_trailers_and_start_alignment_does_nothing() {
        let rows: Vec<&[u8]> = vec![b"abcd", b"xy", b""];
        assert_eq!(row_shifts(&rows, &Alignment::End), vec![0, 2, 4]);
        assert_eq!(row_shifts(&rows, &Alignment::Start), vec![0, 0, 0]);
    }

    #[test]
    fn a_cell_maps_to_its_packet_byte_and_back() {
        let row = RowPlacement { offset: 100, len: 4, shift: 3 };
        assert_eq!(row.packet_offset(2), None, "left of the packet");
        assert_eq!(row.packet_offset(3), Some(0));
        assert_eq!(row.packet_offset(7), None, "past the packet's end");
        assert_eq!(row.column_of(102), Some(5));
        assert_eq!(row.column_of(104), None);
    }

    #[test]
    fn a_column_selection_becomes_one_range_per_packet_that_reaches_it() {
        let rows = placements(&[(0, 10, 0), (10, 3, 0), (13, 10, 2)]);
        let slices = column_slices(&rows, 2, 3);
        assert_eq!(
            slices,
            vec![
                ColumnSlice { row: 0, offset: 2, len: 3, skipped: 0 },
                ColumnSlice { row: 1, offset: 12, len: 1, skipped: 0 },
                ColumnSlice { row: 2, offset: 13, len: 3, skipped: 0 },
            ]
        );
        let shifted = column_slices(&placements(&[(50, 4, 3)]), 2, 3);
        assert_eq!(shifted, vec![ColumnSlice { row: 0, offset: 50, len: 2, skipped: 1 }]);
    }

    #[test]
    fn xor_fill_and_set_change_the_column_in_every_packet() {
        let mut span: Vec<u8> = vec![0x10; 12];
        let slices = column_slices(&placements(&[(0, 4, 0), (4, 4, 0), (8, 4, 0)]), 1, 2);
        apply_to_columns(&mut span, 0, &slices, 2, &ColumnOperation::Xor(vec![0xFF, 0x01]));
        assert_eq!(span, vec![0x10, 0xEF, 0x11, 0x10, 0x10, 0xEF, 0x11, 0x10, 0x10, 0xEF, 0x11, 0x10]);
        apply_to_columns(&mut span, 0, &slices, 2, &ColumnOperation::Fill(vec![0xAB]));
        assert_eq!(&span[4..8], &[0x10, 0xAB, 0xAB, 0x10]);
        apply_to_columns(&mut span, 0, &slices, 2, &ColumnOperation::Set(vec![0x12, 0x34]));
        assert_eq!(&span[8..12], &[0x10, 0x12, 0x34, 0x10]);
        apply_to_columns(&mut span, 0, &slices, 2, &ColumnOperation::Add(vec![1]));
        assert_eq!(&span[0..4], &[0x10, 0x13, 0x35, 0x10]);
        apply_to_columns(&mut span, 0, &slices, 2, &ColumnOperation::Invert);
        assert_eq!(&span[0..4], &[0x10, 0xEC, 0xCA, 0x10]);
    }

    #[test]
    fn a_counter_numbers_each_packet_in_the_chosen_byte_order() {
        let mut span = vec![0u8; 9];
        let slices = column_slices(&placements(&[(0, 3, 0), (3, 3, 0), (6, 3, 0)]), 1, 2);
        apply_to_columns(&mut span, 0, &slices, 2, &ColumnOperation::Counter { start: 0x00FF, step: 1, little_endian: false });
        assert_eq!(span, vec![0, 0x00, 0xFF, 0, 0x01, 0x00, 0, 0x01, 0x01]);
        apply_to_columns(&mut span, 0, &slices, 2, &ColumnOperation::Counter { start: 10, step: -2, little_endian: true });
        assert_eq!(span, vec![0, 10, 0, 0, 8, 0, 0, 6, 0]);
    }

    #[test]
    fn a_partly_covered_column_gets_the_matching_part_of_the_value() {
        // The row starts one column into the selection, so it only holds the value's second byte.
        let mut span = vec![0u8; 3];
        let slices = column_slices(&placements(&[(0, 3, 1)]), 0, 2);
        apply_to_columns(&mut span, 0, &slices, 2, &ColumnOperation::Set(vec![0xAA, 0xBB]));
        assert_eq!(span, vec![0xBB, 0, 0]);
    }

    #[test]
    fn swapping_byte_order_reverses_each_group() {
        let mut span: Vec<u8> = (0..8).collect();
        let slices = column_slices(&placements(&[(0, 8, 0)]), 0, 8);
        apply_to_columns(&mut span, 0, &slices, 8, &ColumnOperation::SwapByteOrder { group: 4 });
        assert_eq!(span, vec![3, 2, 1, 0, 7, 6, 5, 4]);
        apply_to_columns(&mut span, 0, &slices, 8, &ColumnOperation::SwapByteOrder { group: 8 });
        assert_eq!(span, vec![4, 5, 6, 7, 0, 1, 2, 3]);
    }

    #[test]
    fn deleting_a_column_removes_it_from_every_packet_and_moves_later_bytes_back() {
        let span: Vec<u8> = (0..12).collect();
        let rows = placements(&[(0, 4, 0), (4, 4, 0), (8, 4, 0)]);
        let removed = deletion_ranges(&column_slices(&rows, 1, 2));
        assert_eq!(removed, vec![(1, 2), (5, 2), (9, 2)]);
        let kept = super::super::edit::without_ranges(&span, 0, &removed);
        assert_eq!(kept, vec![0, 3, 4, 7, 8, 11]);
        assert_eq!(super::super::edit::offset_after_deletion(8, &removed), Some(4), "the third packet now starts 4 bytes earlier");
    }

    #[test]
    fn column_statistics_tell_constants_counters_and_random_bytes_apart() {
        let packets: Vec<Vec<u8>> = (0..64u32).map(|index| vec![0xAA, index as u8, (index.wrapping_mul(2_654_435_761) >> 13) as u8]).collect();
        let rows: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
        let kinds = column_kinds(&rows, &vec![0; rows.len()], 4);
        assert_eq!(kinds[0], Some(ColumnKind::Constant));
        assert_eq!(kinds[1], Some(ColumnKind::Counter));
        assert!(matches!(kinds[2], Some(ColumnKind::Random | ColumnKind::Mixed)), "{:?}", kinds[2]);
        assert_eq!(kinds[3], None, "no row reaches the fourth column");
    }

    #[test]
    fn columns_copy_as_hex_lines_and_as_csv() {
        let rows = [ColumnText { packet: 1, offset: 0x10, bytes: &[0xDE, 0xAD] }, ColumnText { packet: 2, offset: 0x20, bytes: &[0x01] }];
        assert_eq!(columns_as_hex(&rows), "1: de ad\n2: 01\n");
        assert_eq!(columns_as_csv(&rows, 4, 2), "packet,offset,+4,+5\n1,0x10,de,ad\n2,0x20,01\n");
    }

    fn dns_layers() -> Vec<Layer> {
        let fields = vec![
            Field::new("Transaction ID", 0, 2, "0x0001"),
            Field::new("Flags", 2, 2, "0x0100"),
            Field::new("Question section", 12, 6, "1 questions").with_children(vec![Field::new("Question 0", 12, 6, "a A").with_children(vec![Field::new("Query name", 12, 2, "a")])]),
        ];
        vec![Layer { name: "DNS".to_string(), offset: 0, len: 18, fields }, Layer { name: "Trailing data".to_string(), offset: 18, len: 2, fields: vec![Field::new("Data", 18, 2, "")] }]
    }

    #[test]
    fn columns_are_named_by_the_innermost_field_the_rows_agree_on() {
        let dns = dns_layers();
        let names = column_fields(&[(&dns, 0), (&dns, 0)], 20);
        assert_eq!(names[0].as_deref(), Some("Transaction ID (DNS)"));
        assert_eq!(names[3].as_deref(), Some("Flags (DNS)"));
        assert_eq!(names[12].as_deref(), Some("Query name (DNS)"));
        assert_eq!(names[14].as_deref(), Some("Question 0 (DNS)"));
        assert_eq!(names[5], None, "no field covers the counts here");
        assert_eq!(names[19], None, "trailing data is not named");
        let shifted = column_fields(&[(&dns, 0), (&dns, 2)], 20);
        assert_eq!(shifted[0].as_deref(), Some("Transaction ID (DNS)"), "the shifted row does not reach column 0");
        assert_eq!(shifted[2], None, "Flags in one row, Transaction ID in the other");
    }
}
