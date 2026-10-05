//! A heatmap of where a recording changed over time.
//!
//! A [`Recording`] holds snapshots of a live source or watched file. This
//! turns its history into a matrix: one row per snapshot (time runs
//! downwards), one column per byte position (or per bucket of positions when
//! the data is wide), each cell saying how much of that bucket changed since
//! the previous snapshot. It also counts how often each position changed
//! overall and lists the most active positions.
//!
//! Work happens in two steps so the heavy part can run on a background
//! thread: [`collect_changes`] borrows the recording briefly and copies out
//! the changed ranges, and [`build_timeline`] builds the matrix from them.
//!
//! Changes come from the recording's own change ranges, which span from the
//! first to the last differing byte within each 4 KiB block. When the history
//! is small enough to rebuild cheaply ([`EXACT_COMPARE_BUDGET`]) the
//! snapshots are compared byte by byte instead; otherwise unchanged bytes between two changes in one
//! block can count as changed.

use std::fmt;
use std::time::SystemTime;

use crate::sources::Recording;

/// Fewest snapshots that show a change.
pub const MIN_SNAPSHOTS: usize = 2;
/// Most recent snapshots shown; older ones are left out.
pub const MAX_ROWS: usize = 512;
/// Most columns in the heatmap; wider data is bucketed.
pub const MAX_COLUMNS: usize = 1024;
/// Resolution at which activity is counted for the most-active list: data
/// wider than this many bytes is counted in groups of bytes.
pub const ACTIVITY_CELLS: usize = 1 << 20;
/// Entries in the most-active list.
pub const MAX_ACTIVE_LISTED: usize = 20;
/// Most change ranges kept per snapshot; close ranges are merged beyond this.
pub const MAX_RANGES_PER_ROW: usize = 4096;
/// Most bytes copied while rebuilding snapshots to find changes byte by
/// byte. Rebuilding one snapshot copies at most the recording's stored bytes
/// plus its length, so the estimate is rows × (stored bytes + width).
pub const EXACT_COMPARE_BUDGET: usize = 64 * 1024 * 1024;

/// Why a timeline could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineError {
    /// The recording has fewer than [`MIN_SNAPSHOTS`] snapshots.
    TooFewSnapshots(usize),
}

impl fmt::Display for TimelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimelineError::TooFewSnapshots(count) => write!(
                f,
                "The recording has {count} snapshot(s); at least {MIN_SNAPSHOTS} are needed to show changes."
            ),
        }
    }
}

impl std::error::Error for TimelineError {}

/// The ranges `(start, len)` that changed in one snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotChanges {
    /// Index of the snapshot in the recording.
    pub index: usize,
    pub taken_at: Option<SystemTime>,
    pub ranges: Vec<(usize, usize)>,
}

/// Change ranges copied out of a recording.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordingChanges {
    /// Snapshots in the whole recording.
    pub total_snapshots: usize,
    /// Byte positions covered: the longest extent seen.
    pub width: usize,
    /// The most recent snapshots, oldest first.
    pub rows: Vec<SnapshotChanges>,
}

/// Copy the change ranges of the most recent `max_rows` snapshots (capped at
/// [`MAX_ROWS`]) out of `recording`.
pub fn collect_changes(recording: &Recording, max_rows: usize) -> Result<RecordingChanges, TimelineError> {
    let total_snapshots = recording.len();
    if total_snapshots < MIN_SNAPSHOTS {
        return Err(TimelineError::TooFewSnapshots(total_snapshots));
    }
    let row_count = max_rows.clamp(MIN_SNAPSHOTS, MAX_ROWS).min(total_snapshots);
    let first_index = total_snapshots - row_count;
    let mut width = recording.materialise(total_snapshots - 1).len();
    let rebuild_cost = recording.stored_bytes().saturating_add(width).saturating_mul(row_count + 1);
    let exact = rebuild_cost <= EXACT_COMPARE_BUDGET;
    let mut previous = if exact && first_index > 0 { recording.materialise(first_index - 1) } else { Vec::new() };
    let rows: Vec<SnapshotChanges> = (first_index..total_snapshots)
        .map(|index| {
            let mut ranges = recording.changed_ranges(index);
            if exact {
                let current = recording.materialise(index);
                if index > 0 {
                    ranges = exact_ranges(&previous, &current, &ranges);
                }
                previous = current;
            }
            SnapshotChanges { index, taken_at: recording.taken_at(index), ranges: coarsen(ranges, MAX_RANGES_PER_ROW) }
        })
        .collect();
    for row in &rows {
        if let Some(&(start, len)) = row.ranges.last() {
            width = width.max(start.saturating_add(len));
        }
    }
    Ok(RecordingChanges { total_snapshots, width, rows })
}

/// Narrow `ranges` to the runs of bytes that really differ between
/// `previous` and `current`. Bytes beyond the end of `previous` all count as
/// changed.
fn exact_ranges(previous: &[u8], current: &[u8], ranges: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut exact: Vec<(usize, usize)> = Vec::new();
    for &(start, len) in ranges {
        let end = start.saturating_add(len).min(current.len());
        let mut run_start: Option<usize> = None;
        let compared = current.get(start..end).unwrap_or(&[]);
        for (position, byte) in (start..).zip(compared) {
            let differs = previous.get(position) != Some(byte);
            match (differs, run_start) {
                (true, None) => run_start = Some(position),
                (false, Some(first)) => {
                    exact.push((first, position - first));
                    run_start = None;
                }
                _ => {}
            }
        }
        if let Some(first) = run_start {
            exact.push((first, end - first));
        }
    }
    exact
}

/// Merge the closest of sorted `ranges` until at most `max` remain.
fn coarsen(mut ranges: Vec<(usize, usize)>, max: usize) -> Vec<(usize, usize)> {
    let mut allowed_gap = 1usize;
    while ranges.len() > max.max(1) {
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
        for (start, len) in ranges {
            match merged.last_mut() {
                Some((last_start, last_len)) if start <= (*last_start + *last_len).saturating_add(allowed_gap) => {
                    *last_len = (start + len).max(*last_start + *last_len) - *last_start;
                }
                _ => merged.push((start, len)),
            }
        }
        ranges = merged;
        allowed_gap = allowed_gap.saturating_mul(2);
    }
    ranges
}

/// A run of positions that changed equally often.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveSpan {
    pub start: usize,
    pub len: usize,
    /// Snapshots in which this span changed.
    pub changes: u32,
}

/// The change matrix of a recording.
#[derive(Debug, Clone, PartialEq)]
pub struct Timeline {
    /// Snapshots in the whole recording; `rows` may show only the latest.
    pub total_snapshots: usize,
    /// Recording index of the first row.
    pub first_index: usize,
    pub rows: usize,
    pub columns: usize,
    /// Byte positions per column.
    pub bucket: usize,
    /// Byte positions covered.
    pub width: usize,
    pub taken_at: Vec<Option<SystemTime>>,
    /// Changed bytes per cell, row by row.
    cells: Vec<u32>,
    /// Snapshots in which each column changed.
    pub column_activity: Vec<u32>,
    /// The most often changed positions, most active first.
    pub most_active: Vec<ActiveSpan>,
}

impl Timeline {
    /// Share of a cell's bytes that changed, 0 to 1.
    pub fn changed_fraction(&self, row: usize, column: usize) -> f32 {
        if row >= self.rows || column >= self.columns {
            return 0.0;
        }
        let cell_bytes = self.column_len(column).max(1);
        self.cells[row * self.columns + column] as f32 / cell_bytes as f32
    }

    /// First byte position of a column.
    pub fn column_offset(&self, column: usize) -> usize {
        column.saturating_mul(self.bucket).min(self.width)
    }

    /// Byte positions in a column (the last may be narrower).
    pub fn column_len(&self, column: usize) -> usize {
        let start = self.column_offset(column);
        self.column_offset(column + 1) - start
    }

    /// The most changes any column saw.
    pub fn busiest_column_activity(&self) -> u32 {
        self.column_activity.iter().copied().max().unwrap_or(0)
    }
}

/// Build the change matrix with at most `max_columns` columns (capped at
/// [`MAX_COLUMNS`]).
pub fn build_timeline(changes: &RecordingChanges, max_columns: usize) -> Timeline {
    let width = changes.width;
    let columns_wanted = max_columns.clamp(1, MAX_COLUMNS);
    let bucket = width.div_ceil(columns_wanted).max(1);
    let columns = width.div_ceil(bucket).max(1);
    let rows = changes.rows.len();

    let mut cells = vec![0u32; rows * columns];
    let mut column_activity = vec![0u32; columns];
    for (row, snapshot) in changes.rows.iter().enumerate() {
        let row_cells = &mut cells[row * columns..(row + 1) * columns];
        add_changed_bytes(row_cells, &snapshot.ranges, bucket, width);
        for (activity, &changed) in column_activity.iter_mut().zip(row_cells.iter()) {
            if changed > 0 {
                *activity += 1;
            }
        }
    }

    Timeline {
        total_snapshots: changes.total_snapshots,
        first_index: changes.rows.first().map_or(0, |row| row.index),
        rows,
        columns,
        bucket,
        width,
        taken_at: changes.rows.iter().map(|row| row.taken_at).collect(),
        cells,
        column_activity,
        most_active: most_active_spans(changes),
    }
}

/// Add the bytes of each range to the columns it covers.
fn add_changed_bytes(row_cells: &mut [u32], ranges: &[(usize, usize)], bucket: usize, width: usize) {
    for &(start, len) in ranges {
        let end = start.saturating_add(len).min(width);
        let mut position = start;
        while position < end {
            let column = position / bucket;
            let column_end = ((column + 1) * bucket).min(end);
            if let Some(cell) = row_cells.get_mut(column) {
                *cell = cell.saturating_add((column_end - position) as u32);
            }
            position = column_end;
        }
    }
}

/// Count, per position (or per group of positions for wide data), the
/// snapshots in which it changed, and list the busiest runs.
fn most_active_spans(changes: &RecordingChanges) -> Vec<ActiveSpan> {
    let granule = changes.width.div_ceil(ACTIVITY_CELLS).max(1);
    let granules = changes.width.div_ceil(granule);
    // Difference array: +1 where a changed run of granules starts, −1 after it ends.
    let mut steps = vec![0i64; granules + 1];
    for row in &changes.rows {
        for (first, end) in granule_runs(&row.ranges, granule, granules) {
            steps[first] += 1;
            steps[end] -= 1;
        }
    }
    let mut spans: Vec<ActiveSpan> = Vec::new();
    let mut count = 0i64;
    for (index, step) in steps.iter().take(granules).enumerate() {
        count += step;
        if count <= 0 {
            continue;
        }
        let times_changed = u32::try_from(count).unwrap_or(u32::MAX);
        let start = index * granule;
        let len = granule.min(changes.width - start);
        match spans.last_mut() {
            Some(span) if span.start + span.len == start && span.changes == times_changed => span.len += len,
            _ => spans.push(ActiveSpan { start, len, changes: times_changed }),
        }
    }
    spans.sort_by(|a, b| b.changes.cmp(&a.changes).then(a.start.cmp(&b.start)));
    spans.truncate(MAX_ACTIVE_LISTED);
    spans
}

/// Merged runs `(first, end)` of granules touched by one snapshot's ranges,
/// so a snapshot counts once per granule however many ranges touch it.
fn granule_runs(ranges: &[(usize, usize)], granule: usize, granules: usize) -> Vec<(usize, usize)> {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    for &(start, len) in ranges {
        if len == 0 {
            continue;
        }
        let first = (start / granule).min(granules);
        let end = (start.saturating_add(len).div_ceil(granule)).min(granules);
        if first >= end {
            continue;
        }
        match runs.last_mut() {
            Some(run) if first <= run.1 => run.1 = run.1.max(end),
            _ => runs.push((first, end)),
        }
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA_LEN: usize = 256;
    const BUSY_BYTE: usize = 7;
    const RARE_BYTE: usize = 100;
    const BUDGET: usize = 1 << 20;

    /// A recording in which byte 7 changes in every snapshot and byte 100
    /// changes once.
    fn busy_recording(snapshots: usize) -> Recording {
        let mut recording = Recording::new(BUDGET);
        let mut bytes = vec![0u8; DATA_LEN];
        for step in 0..snapshots {
            bytes[BUSY_BYTE] = step as u8;
            if step == 3 {
                bytes[RARE_BYTE] = 0xFF;
            }
            recording.record(&bytes);
        }
        recording
    }

    #[test]
    fn a_byte_that_changes_in_every_snapshot_is_the_most_active() {
        let recording = busy_recording(10);
        let changes = collect_changes(&recording, MAX_ROWS).unwrap();
        let timeline = build_timeline(&changes, MAX_COLUMNS);
        assert_eq!(timeline.most_active[0], ActiveSpan { start: BUSY_BYTE, len: 1, changes: 9 });
        assert_eq!(timeline.most_active[1], ActiveSpan { start: RARE_BYTE, len: 1, changes: 1 });
        assert_eq!(timeline.most_active.len(), 2);
    }

    #[test]
    fn the_matrix_marks_changes_against_the_previous_snapshot() {
        let recording = busy_recording(5);
        let timeline = build_timeline(&collect_changes(&recording, MAX_ROWS).unwrap(), MAX_COLUMNS);
        assert_eq!((timeline.rows, timeline.columns, timeline.bucket), (5, DATA_LEN, 1));
        // The first snapshot has nothing to compare with.
        assert_eq!(timeline.changed_fraction(0, BUSY_BYTE), 0.0);
        for row in 1..5 {
            assert_eq!(timeline.changed_fraction(row, BUSY_BYTE), 1.0);
        }
        assert_eq!(timeline.changed_fraction(3, RARE_BYTE), 1.0);
        assert_eq!(timeline.changed_fraction(4, RARE_BYTE), 0.0);
        assert_eq!(timeline.column_activity[BUSY_BYTE], 4);
        assert_eq!(timeline.column_activity[0], 0);
    }

    #[test]
    fn wide_data_is_bucketed_into_a_bounded_number_of_columns() {
        let recording = busy_recording(4);
        let timeline = build_timeline(&collect_changes(&recording, MAX_ROWS).unwrap(), 16);
        assert_eq!(timeline.columns, 16);
        assert_eq!(timeline.bucket, DATA_LEN / 16);
        assert_eq!(timeline.column_offset(BUSY_BYTE / timeline.bucket), 0);
        assert_eq!(timeline.changed_fraction(1, 0), 1.0 / 16.0);
    }

    #[test]
    fn only_the_most_recent_snapshots_are_kept_when_there_are_many() {
        let recording = busy_recording(20);
        let changes = collect_changes(&recording, 5).unwrap();
        assert_eq!(changes.rows.len(), 5);
        assert_eq!(changes.rows[0].index, 15);
        let timeline = build_timeline(&changes, MAX_COLUMNS);
        assert_eq!(timeline.first_index, 15);
        assert_eq!(timeline.total_snapshots, 20);
        // Every kept row, including the first, changed byte 7.
        assert_eq!(timeline.most_active[0].changes, 5);
    }

    #[test]
    fn a_recording_with_one_snapshot_is_refused() {
        let recording = busy_recording(1);
        assert_eq!(collect_changes(&recording, MAX_ROWS), Err(TimelineError::TooFewSnapshots(1)));
    }

    #[test]
    fn growing_data_widens_the_timeline() {
        let mut recording = Recording::new(BUDGET);
        recording.record(&[0u8; 10]);
        recording.record(&[0u8; 30]);
        let timeline = build_timeline(&collect_changes(&recording, MAX_ROWS).unwrap(), MAX_COLUMNS);
        assert_eq!(timeline.width, 30);
        assert_eq!(timeline.changed_fraction(1, 20), 1.0);
        assert_eq!(timeline.changed_fraction(1, 5), 0.0);
    }

    #[test]
    fn unchanged_bytes_between_two_changes_are_not_counted_as_changed() {
        let previous = [0u8, 0, 0, 0, 0, 0];
        let current = [0u8, 1, 0, 0, 1, 0, 9, 9];
        assert_eq!(exact_ranges(&previous, &current, &[(1, 7)]), vec![(1, 1), (4, 1), (6, 2)]);
    }

    #[test]
    fn many_ranges_in_one_snapshot_are_merged_to_the_cap() {
        let ranges: Vec<(usize, usize)> = (0..100).map(|index| (index * 10, 1)).collect();
        let merged = coarsen(ranges, 10);
        assert!(merged.len() <= 10);
        assert_eq!(merged.first().unwrap().0, 0);
        let last = merged.last().unwrap();
        assert_eq!(last.0 + last.1, 991);
    }

    #[test]
    fn out_of_range_cells_read_as_unchanged() {
        let recording = busy_recording(3);
        let timeline = build_timeline(&collect_changes(&recording, MAX_ROWS).unwrap(), MAX_COLUMNS);
        assert_eq!(timeline.changed_fraction(99, 0), 0.0);
        assert_eq!(timeline.changed_fraction(0, 99_999), 0.0);
    }
}
