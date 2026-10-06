//! What is selected: one range, a column of every record, or several ranges.
//!
//! The raster, the hex dump and the packet viewer all read and change the
//! same selection. A plain selection is the familiar anchor-to-cursor range.
//! A column selection is a span of bytes at the same place in each record
//! (each row of the raster, `stride` bytes apart) over a run of rows. A
//! multi-range selection is any set of ranges, such as several findings,
//! packets or search matches picked with Cmd-click.

/// The same span of bytes in each of a run of records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnSelection {
    /// Document offset where the first selected record starts.
    pub first_row_start: usize,
    /// Bytes from one record to the next.
    pub stride: usize,
    /// Offset of the span within each record.
    pub column: usize,
    /// Bytes selected in each record.
    pub width: usize,
    /// Records selected.
    pub rows: usize,
}

impl ColumnSelection {
    /// The column spanned by two corner bytes (both included), with rows
    /// `stride` bytes apart starting at `origin`. `None` when the stride is
    /// zero.
    pub fn from_corners(origin: usize, stride: usize, corner_a: usize, corner_b: usize) -> Option<ColumnSelection> {
        if stride == 0 {
            return None;
        }
        let row_and_column = |offset: usize| {
            let relative = offset.saturating_sub(origin);
            (relative / stride, relative % stride)
        };
        let (row_a, column_a) = row_and_column(corner_a);
        let (row_b, column_b) = row_and_column(corner_b);
        let first_row = row_a.min(row_b);
        Some(ColumnSelection {
            first_row_start: origin + first_row * stride,
            stride,
            column: column_a.min(column_b),
            width: column_a.abs_diff(column_b) + 1,
            rows: row_a.abs_diff(row_b) + 1,
        })
    }

    /// Start of the span in record `row` (counted from the first selected).
    fn start_of_row(&self, row: usize) -> usize {
        self.first_row_start + row * self.stride + self.column
    }

    /// The selected span of every record, clipped to a document of
    /// `document_len` bytes.
    pub fn ranges(&self, document_len: usize) -> Vec<(usize, usize)> {
        self.ranges_within(0, usize::MAX, document_len)
    }

    /// The spans of the records that overlap `[start, end)`, clipped to the
    /// document; cheap however many records are selected.
    pub fn ranges_within(&self, start: usize, end: usize, document_len: usize) -> Vec<(usize, usize)> {
        let reach = self.column + self.width;
        let first = start.saturating_sub(self.first_row_start + reach).div_ceil(self.stride.max(1)).min(self.rows);
        let mut ranges = Vec::new();
        for row in first..self.rows {
            let span_start = self.start_of_row(row);
            if span_start >= end || span_start >= document_len {
                break;
            }
            let span_end = (span_start + self.width).min(document_len);
            if span_end > start {
                ranges.push((span_start, span_end - span_start));
            }
        }
        ranges
    }

    /// Whether `offset` is one of the selected bytes.
    pub fn contains(&self, offset: usize) -> bool {
        if offset < self.first_row_start {
            return false;
        }
        let relative = offset - self.first_row_start;
        let (row, within) = (relative / self.stride.max(1), relative % self.stride.max(1));
        row < self.rows && within >= self.column && within < self.column + self.width
    }

    /// The bytes from the first selected byte to the last, as `(start, len)`.
    pub fn span(&self) -> (usize, usize) {
        let start = self.start_of_row(0);
        let end = self.start_of_row(self.rows.saturating_sub(1)) + self.width;
        (start, end - start)
    }

    /// "column 4–7 × 120 rows".
    pub fn describe(&self) -> String {
        let last = self.column + self.width - 1;
        let columns = if self.width == 1 { format!("column {}", self.column) } else { format!("column {}–{last}", self.column) };
        let rows = if self.rows == 1 { "1 row".to_string() } else { format!("{} rows", self.rows) };
        format!("{columns} × {rows}")
    }
}

/// Sort ranges and merge those that overlap or touch, dropping empty ones.
pub fn normalise_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.retain(|&(_, len)| len > 0);
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, len) in ranges {
        match merged.last_mut() {
            Some((last_start, last_len)) if start <= *last_start + *last_len => {
                let end = (start + len).max(*last_start + *last_len);
                *last_len = end - *last_start;
            }
            _ => merged.push((start, len)),
        }
    }
    merged
}

/// Total bytes in a set of ranges.
pub fn total_bytes(ranges: &[(usize, usize)]) -> usize {
    ranges.iter().map(|&(_, len)| len).sum()
}

/// What is selected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    /// One run of bytes, as `(start, len)`.
    Range(usize, usize),
    /// The same span in each of a run of records.
    Columns(ColumnSelection),
    /// Several ranges, sorted and not overlapping.
    Ranges(Vec<(usize, usize)>),
}

impl Selection {
    /// Every selected range, in document order, clipped to the document.
    pub fn ranges(&self, document_len: usize) -> Vec<(usize, usize)> {
        self.ranges_within(0, usize::MAX, document_len)
    }

    /// The selected ranges that overlap `[start, end)`.
    pub fn ranges_within(&self, start: usize, end: usize, document_len: usize) -> Vec<(usize, usize)> {
        let overlaps = |&(range_start, len): &(usize, usize)| range_start < end && range_start + len > start;
        match self {
            Selection::Range(range_start, len) => {
                let clipped = (*range_start, (*len).min(document_len.saturating_sub(*range_start)));
                [clipped].into_iter().filter(|range| range.1 > 0 && overlaps(range)).collect()
            }
            Selection::Columns(column) => column.ranges_within(start, end, document_len),
            Selection::Ranges(ranges) => ranges.iter().copied().filter(overlaps).collect(),
        }
    }

    /// Whether `offset` is selected.
    pub fn contains(&self, offset: usize) -> bool {
        match self {
            Selection::Range(start, len) => offset >= *start && offset < start + len,
            Selection::Columns(column) => column.contains(offset),
            Selection::Ranges(ranges) => ranges.iter().any(|&(start, len)| offset >= start && offset < start + len),
        }
    }

    /// How many bytes are selected.
    pub fn byte_count(&self, document_len: usize) -> usize {
        match self {
            Selection::Range(start, len) => (*len).min(document_len.saturating_sub(*start)),
            Selection::Columns(column) => total_bytes(&column.ranges(document_len)),
            Selection::Ranges(ranges) => total_bytes(ranges),
        }
    }

    /// The bytes from the first selected one to the last, as `(start, len)`.
    pub fn span(&self) -> (usize, usize) {
        match self {
            Selection::Range(start, len) => (*start, *len),
            Selection::Columns(column) => column.span(),
            Selection::Ranges(ranges) => {
                let start = ranges.first().map_or(0, |&(start, _)| start);
                let end = ranges.last().map_or(0, |&(start, len)| start + len);
                (start, end.saturating_sub(start))
            }
        }
    }

    /// A short description: "312 B", "column 4–7 × 120 rows (480 B)" or
    /// "5 ranges, 312 B".
    pub fn describe(&self, document_len: usize) -> String {
        let bytes = self.byte_count(document_len);
        match self {
            Selection::Range(..) => format!("{bytes} B"),
            Selection::Columns(column) => format!("{} ({bytes} B)", column.describe()),
            Selection::Ranges(ranges) => format!("{} ranges, {bytes} B", ranges.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_column_drag_selects_the_same_bytes_in_every_row_between_its_corners() {
        // Rows of 16 bytes from offset 0; drag from row 1 column 6 up to row 0 column 4.
        let column = ColumnSelection::from_corners(0, 16, 16 + 6, 4).unwrap();
        assert_eq!(column, ColumnSelection { first_row_start: 0, stride: 16, column: 4, width: 3, rows: 2 });
        assert_eq!(column.ranges(1000), vec![(4, 3), (20, 3)]);
        assert_eq!(column.describe(), "column 4–6 × 2 rows");
        assert_eq!(column.span(), (4, 19));
    }

    #[test]
    fn column_rows_are_counted_from_the_view_origin() {
        let column = ColumnSelection::from_corners(100, 10, 100 + 23, 100 + 41).unwrap();
        assert_eq!(column.first_row_start, 120);
        assert_eq!(column.column, 1);
        assert_eq!(column.width, 3);
        assert_eq!(column.rows, 3);
        assert!(column.contains(121) && column.contains(143) && !column.contains(124) && !column.contains(150));
    }

    #[test]
    fn column_ranges_are_clipped_to_the_document_and_to_a_window() {
        let column = ColumnSelection { first_row_start: 0, stride: 8, column: 6, width: 4, rows: 10 };
        assert_eq!(column.ranges(20), vec![(6, 4), (14, 4)], "the third row starts past the end");
        assert_eq!(column.ranges_within(30, 46, 1000), vec![(30, 4), (38, 4)], "row 2 ends at 26 and row 5 starts at 46");
        assert_eq!(column.ranges_within(0, usize::MAX, 1000).len(), 10);
    }

    #[test]
    fn a_zero_stride_cannot_make_a_column() {
        assert_eq!(ColumnSelection::from_corners(0, 0, 1, 2), None);
    }

    #[test]
    fn overlapping_and_touching_ranges_merge() {
        assert_eq!(normalise_ranges(vec![(10, 5), (0, 3), (12, 10), (3, 2), (40, 0)]), vec![(0, 5), (10, 12)]);
    }

    #[test]
    fn every_kind_of_selection_describes_itself_and_its_size() {
        assert_eq!(Selection::Range(0, 312).describe(1000), "312 B");
        let column = ColumnSelection { first_row_start: 0, stride: 16, column: 4, width: 4, rows: 120 };
        assert_eq!(Selection::Columns(column).describe(10_000), "column 4–7 × 120 rows (480 B)");
        let ranges = Selection::Ranges(vec![(0, 100), (200, 100), (400, 100), (600, 6), (900, 6)]);
        assert_eq!(ranges.describe(1000), "5 ranges, 312 B");
        assert!(ranges.contains(605) && !ranges.contains(606));
        assert_eq!(ranges.span(), (0, 906));
    }
}
