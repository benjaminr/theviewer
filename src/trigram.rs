//! Byte trigram counts, reduced to a weighted 3D point cloud.
//!
//! Every run of three consecutive bytes `(b[i], b[i+1], b[i+2])` is a point in
//! a 256 × 256 × 256 cube. Different kinds of data fill that cube in telling
//! shapes: text clusters in the printable corner, machine code forms planes,
//! and compressed or random data fills it evenly.
//!
//! The cube is quantised to [`CELLS_PER_AXIS`]³ cells. Each cell keeps its
//! count and the first trigram (and offset) seen in it, so a point in the
//! cloud can be traced back to real bytes. Only the most populated cells are
//! kept, with weights on a log scale so rare trigrams still show.
//!
//! Large inputs are fed in sampled windows ([`sample_windows`]); trigrams are
//! counted within each window and never across a window boundary.
//!
//! The counter can also be given labelled spans of the data (regions from
//! segmentation or the report, numbered as groups) and a selection. Each kept
//! cell then says how many of its trigrams came from each group and from the
//! selection, so the cloud can be coloured and labelled by region.
//!
//! Everything here is pure and safe on any input, including empty slices.

/// Cells along each axis of the quantised cube.
pub const CELLS_PER_AXIS: usize = 64;
/// Byte values that fall into one cell along an axis.
pub const VALUES_PER_CELL: usize = 256 / CELLS_PER_AXIS;
/// Cells in the whole quantised cube.
const TOTAL_CELLS: usize = CELLS_PER_AXIS * CELLS_PER_AXIS * CELLS_PER_AXIS;
/// Most points a cloud keeps by default.
pub const DEFAULT_MAX_POINTS: usize = 6000;
/// Most bytes read for one cloud; larger ranges are sampled.
pub const SAMPLE_LIMIT: usize = 16 * 1024 * 1024;
/// Size of each sampled window when a range is larger than [`SAMPLE_LIMIT`].
pub const SAMPLE_WINDOW: usize = 256 * 1024;
/// Marks a cell that has not been seen yet.
const UNSEEN: usize = usize::MAX;
/// Most region groups a cloud attributes its trigrams to.
pub const MAX_GROUPS: usize = 12;

/// Bytes `start..end` (absolute offsets) belong to region group `group`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LabelledSpan {
    pub start: usize,
    pub end: usize,
    pub group: u8,
}

/// One occupied cell of the quantised cube.
#[derive(Clone, Debug, PartialEq)]
pub struct TrigramPoint {
    /// Cell coordinates along x, y and z, each in `0..CELLS_PER_AXIS`.
    pub cell: [u8; 3],
    /// The first trigram seen in this cell.
    pub exemplar: [u8; 3],
    /// Absolute offset of that first trigram.
    pub offset: usize,
    /// Trigrams counted in this cell.
    pub count: u64,
    /// Log-scaled weight, from just above 0 (rarest kept) to 1 (most common).
    pub weight: f32,
    /// Trigrams per region group, most first; empty when nothing was labelled.
    pub groups: Vec<(u8, u32)>,
    /// Trigrams from inside the selection, when one was given.
    pub in_selection: u32,
}

impl TrigramPoint {
    /// The cell's centre in unit cube coordinates, each in `0.0..=1.0`.
    pub fn unit_position(&self) -> [f32; 3] {
        let last = (CELLS_PER_AXIS - 1) as f32;
        self.cell.map(|coordinate| coordinate as f32 / last)
    }

    /// The group most of this cell's trigrams came from.
    pub fn dominant_group(&self) -> Option<u8> {
        self.groups.first().map(|&(group, _)| group)
    }

    /// Trigrams in this cell from `group`.
    pub fn count_in(&self, group: u8) -> u32 {
        self.groups.iter().find(|&&(known, _)| known == group).map_or(0, |&(_, count)| count)
    }

    /// The range of byte values this cell covers along one axis.
    pub fn value_range(&self, axis: usize) -> (u8, u8) {
        let low = self.cell[axis.min(2)] as usize * VALUES_PER_CELL;
        (low as u8, (low + VALUES_PER_CELL - 1) as u8)
    }
}

/// The reduced point cloud for one range of bytes.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrigramCloud {
    /// Start of the analysed range.
    pub start: usize,
    /// Length of the analysed range.
    pub len: usize,
    /// Bytes actually read; less than `len` when the range was sampled.
    pub bytes_read: usize,
    /// Trigrams counted.
    pub total_trigrams: u64,
    /// Cells with at least one trigram.
    pub occupied_cells: usize,
    /// The kept points, most common first.
    pub points: Vec<TrigramPoint>,
}

impl TrigramCloud {
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// True when only part of the range was read.
    pub fn is_sampled(&self) -> bool {
        self.bytes_read < self.len
    }

    /// Fraction of the cube's cells that hold at least one trigram.
    pub fn occupancy(&self) -> f64 {
        self.occupied_cells as f64 / TOTAL_CELLS as f64
    }
}

/// Counts trigrams into the quantised cube, one window of bytes at a time.
pub struct TrigramCounter {
    counts: Vec<u64>,
    first_offsets: Vec<usize>,
    exemplars: Vec<[u8; 3]>,
    bytes_read: usize,
    total_trigrams: u64,
    /// Labelled spans, sorted by start and not overlapping.
    spans: Vec<LabelledSpan>,
    group_count: usize,
    /// `TOTAL_CELLS × group_count` counts, cell-major; empty without labels.
    group_counts: Vec<u32>,
    selection: Option<(usize, usize)>,
    /// Per-cell counts from inside the selection; empty without one.
    selection_counts: Vec<u32>,
}

impl Default for TrigramCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl TrigramCounter {
    pub fn new() -> Self {
        Self::with_labels(Vec::new(), 0, None)
    }

    /// A counter that also attributes each trigram to the group of the span
    /// it starts in (at most [`MAX_GROUPS`] groups; spans of other groups are
    /// ignored) and counts trigrams starting inside `selection` (start, len).
    pub fn with_labels(mut spans: Vec<LabelledSpan>, group_count: usize, selection: Option<(usize, usize)>) -> Self {
        let group_count = group_count.min(MAX_GROUPS);
        spans.retain(|span| (span.group as usize) < group_count && span.end > span.start);
        spans.sort_by_key(|span| span.start);
        TrigramCounter {
            counts: vec![0; TOTAL_CELLS],
            first_offsets: vec![UNSEEN; TOTAL_CELLS],
            exemplars: vec![[0; 3]; TOTAL_CELLS],
            bytes_read: 0,
            total_trigrams: 0,
            group_counts: vec![0; if group_count > 0 { TOTAL_CELLS * group_count } else { 0 }],
            spans,
            group_count,
            selection_counts: vec![0; if selection.is_some() { TOTAL_CELLS } else { 0 }],
            selection,
        }
    }

    /// Count the trigrams wholly inside `bytes`, which start at absolute
    /// offset `offset`. Windows shorter than three bytes add nothing.
    pub fn add_window(&mut self, offset: usize, bytes: &[u8]) {
        self.bytes_read = self.bytes_read.saturating_add(bytes.len());
        // Spans are sorted and positions only increase, so one cursor walks them.
        let mut span_index = self.spans.partition_point(|span| span.end <= offset);
        for (index, trigram) in bytes.windows(3).enumerate() {
            let trigram = [trigram[0], trigram[1], trigram[2]];
            let cell = cell_index(trigram);
            let position = offset.saturating_add(index);
            self.counts[cell] += 1;
            if self.first_offsets[cell] == UNSEEN {
                self.first_offsets[cell] = position;
                self.exemplars[cell] = trigram;
            }
            self.total_trigrams += 1;
            while span_index < self.spans.len() && self.spans[span_index].end <= position {
                span_index += 1;
            }
            if let Some(span) = self.spans.get(span_index).filter(|span| span.start <= position) {
                self.group_counts[cell * self.group_count + span.group as usize] += 1;
            }
            if let Some((start, len)) = self.selection
                && position >= start
                && position < start.saturating_add(len)
            {
                self.selection_counts[cell] += 1;
            }
        }
    }

    /// Group counts of one cell, most first, leaving out empty groups.
    fn groups_of(&self, cell: usize) -> Vec<(u8, u32)> {
        if self.group_count == 0 {
            return Vec::new();
        }
        let counts = &self.group_counts[cell * self.group_count..(cell + 1) * self.group_count];
        let mut groups: Vec<(u8, u32)> =
            counts.iter().enumerate().filter(|&(_, &count)| count > 0).map(|(group, &count)| (group as u8, count)).collect();
        groups.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        groups
    }

    /// Reduce the counts to at most `max_points` points for the range
    /// `start..start + len`.
    pub fn finish(self, start: usize, len: usize, max_points: usize) -> TrigramCloud {
        let mut occupied: Vec<usize> = (0..TOTAL_CELLS).filter(|&cell| self.counts[cell] > 0).collect();
        let occupied_cells = occupied.len();
        // Most common first; ties broken by cell index so the result is stable.
        occupied.sort_unstable_by(|&a, &b| self.counts[b].cmp(&self.counts[a]).then(a.cmp(&b)));
        occupied.truncate(max_points);

        let highest = occupied.first().map_or(0, |&cell| self.counts[cell]);
        let points = occupied
            .into_iter()
            .map(|cell| TrigramPoint {
                cell: cell_coordinates(cell),
                exemplar: self.exemplars[cell],
                offset: self.first_offsets[cell],
                count: self.counts[cell],
                weight: log_weight(self.counts[cell], highest),
                groups: self.groups_of(cell),
                in_selection: self.selection_counts.get(cell).copied().unwrap_or(0),
            })
            .collect();
        TrigramCloud { start, len, bytes_read: self.bytes_read, total_trigrams: self.total_trigrams, occupied_cells, points }
    }
}

/// Build the cloud for one contiguous slice that starts at `start`.
pub fn cloud_of(bytes: &[u8], start: usize, max_points: usize) -> TrigramCloud {
    let mut counter = TrigramCounter::new();
    counter.add_window(start, bytes);
    counter.finish(start, bytes.len(), max_points)
}

/// The windows to read from a range of `len` bytes so that at most `limit`
/// bytes are read: the whole range when it fits, else evenly spaced windows
/// of `window` bytes. Offsets are relative to the start of the range.
pub fn sample_windows(len: usize, limit: usize, window: usize) -> Vec<(usize, usize)> {
    if len == 0 || limit == 0 {
        return Vec::new();
    }
    if len <= limit {
        return vec![(0, len)];
    }
    let window = window.clamp(1, limit);
    let count = (limit / window).max(1);
    let stride = len / count;
    (0..count).map(|index| (index * stride, window.min(len - index * stride))).collect()
}

/// Cell coordinates of the cell holding `trigram`, as in [`TrigramPoint::cell`].
pub fn cell_of(trigram: [u8; 3]) -> [u8; 3] {
    trigram.map(|byte| (byte as usize / VALUES_PER_CELL) as u8)
}

/// Index of the cell holding `trigram`.
fn cell_index(trigram: [u8; 3]) -> usize {
    let [x, y, z] = trigram.map(|byte| byte as usize / VALUES_PER_CELL);
    (z * CELLS_PER_AXIS + y) * CELLS_PER_AXIS + x
}

/// Cell coordinates `[x, y, z]` of a cell index.
fn cell_coordinates(cell: usize) -> [u8; 3] {
    let x = cell % CELLS_PER_AXIS;
    let y = (cell / CELLS_PER_AXIS) % CELLS_PER_AXIS;
    let z = cell / (CELLS_PER_AXIS * CELLS_PER_AXIS);
    [x as u8, y as u8, z as u8]
}

/// `ln(1 + count) / ln(1 + highest)`, so one trigram in a large file still
/// gets a visible weight. Zero when `highest` is zero.
fn log_weight(count: u64, highest: u64) -> f32 {
    if highest == 0 {
        return 0.0;
    }
    ((1.0 + count as f64).ln() / (1.0 + highest as f64).ln()) as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple xorshift generator, so "random" test data is reproducible.
    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn is_printable_cell(coordinate: u8) -> bool {
        let low = coordinate as usize * VALUES_PER_CELL;
        let high = low + VALUES_PER_CELL - 1;
        high >= 0x20 && low <= 0x7E
    }

    #[test]
    fn ascii_text_concentrates_trigrams_in_the_printable_cube() {
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(500);
        let cloud = cloud_of(text.as_bytes(), 0, DEFAULT_MAX_POINTS);
        assert!(!cloud.is_empty());
        assert!(cloud.points.iter().all(|point| point.cell.iter().all(|&c| is_printable_cell(c))));
        assert!(cloud.occupancy() < 0.01, "text should occupy few cells, got {}", cloud.occupancy());
    }

    #[test]
    fn random_data_spreads_over_most_cells() {
        let bytes = pseudo_random_bytes(4 * 1024 * 1024);
        let cloud = cloud_of(&bytes, 0, DEFAULT_MAX_POINTS);
        assert!(cloud.occupancy() > 0.9, "random data should fill the cube, got {}", cloud.occupancy());
        assert_eq!(cloud.points.len(), DEFAULT_MAX_POINTS);
    }

    #[test]
    fn empty_and_tiny_inputs_give_an_empty_cloud() {
        assert!(cloud_of(&[], 0, DEFAULT_MAX_POINTS).is_empty());
        let two = cloud_of(&[1, 2], 0, DEFAULT_MAX_POINTS);
        assert!(two.is_empty());
        assert_eq!(two.total_trigrams, 0);
    }

    #[test]
    fn each_point_remembers_where_its_first_trigram_was() {
        let bytes = b"\x00\x00\x00ABCzzABC";
        let cloud = cloud_of(bytes, 100, DEFAULT_MAX_POINTS);
        let abc = cloud.points.iter().find(|point| point.exemplar == *b"ABC").expect("ABC is counted");
        assert_eq!(abc.offset, 103);
        assert_eq!(abc.count, 2);
        assert_eq!(&bytes[abc.offset - 100..abc.offset - 100 + 3], b"ABC");
    }

    #[test]
    fn the_most_common_cell_has_full_weight_and_rarer_cells_less() {
        let mut bytes = vec![0u8; 1000];
        bytes.extend_from_slice(b"xyz");
        let cloud = cloud_of(&bytes, 0, DEFAULT_MAX_POINTS);
        assert_eq!(cloud.points[0].exemplar, [0, 0, 0]);
        assert!((cloud.points[0].weight - 1.0).abs() < 1e-6);
        assert!(cloud.points.iter().skip(1).all(|point| point.weight > 0.0 && point.weight < 1.0));
    }

    #[test]
    fn the_number_of_points_is_capped() {
        let bytes = pseudo_random_bytes(64 * 1024);
        let cloud = cloud_of(&bytes, 0, 50);
        assert_eq!(cloud.points.len(), 50);
        assert!(cloud.points.windows(2).all(|pair| pair[0].count >= pair[1].count));
    }

    #[test]
    fn trigrams_are_not_counted_across_window_boundaries() {
        let mut counter = TrigramCounter::new();
        counter.add_window(0, b"AB");
        counter.add_window(10, b"CD");
        let cloud = counter.finish(0, 12, DEFAULT_MAX_POINTS);
        assert_eq!(cloud.total_trigrams, 0);
        assert_eq!(cloud.bytes_read, 4);
        assert!(cloud.is_sampled());
    }

    #[test]
    fn small_ranges_are_read_whole_and_large_ones_sampled_within_the_limit() {
        assert_eq!(sample_windows(1000, 4096, 256), vec![(0, 1000)]);
        assert!(sample_windows(0, 4096, 256).is_empty());

        let len = 1_000_000;
        let windows = sample_windows(len, 4096, 256);
        assert_eq!(windows.len(), 16);
        let total: usize = windows.iter().map(|&(_, size)| size).sum();
        assert!(total <= 4096);
        assert!(windows.iter().all(|&(start, size)| start + size <= len));
        assert!(windows.last().is_some_and(|&(start, _)| start > len / 2), "windows should spread over the range");
    }

    #[test]
    fn trigrams_are_attributed_to_the_region_they_start_in() {
        let text = b"labelled regions of text ".repeat(40);
        let mut data = text.clone();
        data.extend(std::iter::repeat_n(0u8, 1000));
        let spans = vec![
            LabelledSpan { start: 100, end: 100 + text.len(), group: 0 },
            LabelledSpan { start: 100 + text.len(), end: 100 + data.len(), group: 1 },
        ];
        let mut counter = TrigramCounter::with_labels(spans, 2, Some((100 + text.len(), 10)));
        counter.add_window(100, &data);
        let cloud = counter.finish(100, data.len(), DEFAULT_MAX_POINTS);
        let zeros = cloud.points.iter().find(|point| point.exemplar == [0, 0, 0]).expect("the zero cell");
        assert_eq!(zeros.dominant_group(), Some(1));
        assert_eq!(zeros.in_selection, 10, "ten trigrams start inside the selection");
        let text_cell = cloud.points.iter().find(|point| point.exemplar == *b"lab").expect("a text cell");
        assert_eq!(text_cell.dominant_group(), Some(0));
        assert_eq!(text_cell.in_selection, 0);
        assert_eq!(zeros.count_in(0), 0);
    }

    #[test]
    fn without_labels_points_have_no_groups() {
        let cloud = cloud_of(b"no labels here at all", 0, DEFAULT_MAX_POINTS);
        assert!(cloud.points.iter().all(|point| point.groups.is_empty() && point.dominant_group().is_none()));
    }

    #[test]
    fn cell_indices_and_coordinates_round_trip() {
        for trigram in [[0, 0, 0], [255, 255, 255], [0x41, 0x80, 0x07]] {
            let coordinates = cell_coordinates(cell_index(trigram));
            assert_eq!(coordinates, trigram.map(|byte| byte / VALUES_PER_CELL as u8));
        }
    }

    #[test]
    fn a_point_reports_the_byte_values_its_cell_covers() {
        let cloud = cloud_of(&[0x41, 0x42, 0xFF], 0, DEFAULT_MAX_POINTS);
        let point = &cloud.points[0];
        assert_eq!(point.value_range(0), (0x40, 0x43));
        assert_eq!(point.value_range(2), (0xFC, 0xFF));
        assert_eq!(point.unit_position()[2], 1.0);
    }
}
