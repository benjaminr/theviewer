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
}

impl TrigramPoint {
    /// The cell's centre in unit cube coordinates, each in `0.0..=1.0`.
    pub fn unit_position(&self) -> [f32; 3] {
        let last = (CELLS_PER_AXIS - 1) as f32;
        self.cell.map(|coordinate| coordinate as f32 / last)
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
}

impl Default for TrigramCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl TrigramCounter {
    pub fn new() -> Self {
        TrigramCounter {
            counts: vec![0; TOTAL_CELLS],
            first_offsets: vec![UNSEEN; TOTAL_CELLS],
            exemplars: vec![[0; 3]; TOTAL_CELLS],
            bytes_read: 0,
            total_trigrams: 0,
        }
    }

    /// Count the trigrams wholly inside `bytes`, which start at absolute
    /// offset `offset`. Windows shorter than three bytes add nothing.
    pub fn add_window(&mut self, offset: usize, bytes: &[u8]) {
        self.bytes_read = self.bytes_read.saturating_add(bytes.len());
        for (index, trigram) in bytes.windows(3).enumerate() {
            let trigram = [trigram[0], trigram[1], trigram[2]];
            let cell = cell_index(trigram);
            self.counts[cell] += 1;
            if self.first_offsets[cell] == UNSEEN {
                self.first_offsets[cell] = offset.saturating_add(index);
                self.exemplars[cell] = trigram;
            }
            self.total_trigrams += 1;
        }
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
