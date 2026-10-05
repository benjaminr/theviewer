//! Field variation across many files.
//!
//! Given several versions of the same kind of data (captures, firmware
//! versions, saved states), aligned at offset 0 or at a per-file start
//! offset, this summarises every byte position of the common prefix: whether
//! it is constant, how many distinct values it takes, its range, and whether
//! it moves in one direction across the file order (a counter or version
//! number). Adjacent positions that behave alike are grouped into regions.
//!
//! Files are compared position by position only; no diff alignment is done,
//! so an insertion early in one file shifts everything after it. Use the start
//! offsets to line files up when their headers differ in length.

use std::fmt;

/// Fewest files that can be compared.
pub const MIN_FILES: usize = 2;
/// Most files compared at once, which bounds the time spent per position.
pub const MAX_FILES: usize = 32;
/// Longest common prefix analysed; positions beyond it are not summarised.
pub const MAX_COMPARED_LEN: usize = 16 * 1024 * 1024;
/// Most regions reported; analysis stops at this many.
pub const MAX_REGIONS: usize = 20_000;
/// Widths tried, widest first, when a short changing run might be one counter.
const COUNTER_WIDTHS: [usize; 2] = [4, 2];

/// Why a comparison could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariationError {
    /// Fewer than [`MIN_FILES`] files were given.
    TooFewFiles(usize),
    /// More than [`MAX_FILES`] files were given.
    TooManyFiles(usize),
    /// The number of start offsets does not match the number of files.
    StartCountMismatch { files: usize, starts: usize },
    /// A start offset lies beyond the end of its file.
    StartBeyondEnd { file: usize, start: usize, len: usize },
}

impl fmt::Display for VariationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VariationError::TooFewFiles(count) => {
                write!(f, "Comparing needs at least {MIN_FILES} files; {count} given.")
            }
            VariationError::TooManyFiles(count) => {
                write!(f, "At most {MAX_FILES} files can be compared at once; {count} given.")
            }
            VariationError::StartCountMismatch { files, starts } => {
                write!(f, "{files} files but {starts} start offsets were given; there must be one per file.")
            }
            VariationError::StartBeyondEnd { file, start, len } => {
                write!(f, "File {} starts at 0x{start:X}, beyond its end (it is {len} bytes long).", file + 1)
            }
        }
    }
}

impl std::error::Error for VariationError {}

/// Which way a value moves across the file order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Increasing,
    Decreasing,
}

/// A multi-byte integer that a short run of changing bytes forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterField {
    pub width: usize,
    pub big_endian: bool,
}

/// How a region behaves across the files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Every file has the same bytes here.
    Constant,
    /// The bytes differ between files without a consistent direction.
    /// `fewest_distinct` and `most_distinct` are per byte position.
    Varies { fewest_distinct: usize, most_distinct: usize, min: u8, max: u8 },
    /// Each byte (or, with `field`, the integer the bytes form) never moves
    /// against `direction` from one file to the next, and differs between
    /// the first and last file.
    Trend { direction: Direction, field: Option<CounterField> },
}

/// A run of adjacent positions that behave alike. `start` and `end` are
/// relative to each file's start offset; `end` is exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub start: usize,
    pub end: usize,
    pub kind: RegionKind,
}

impl Region {
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }

    /// A one-line description such as "varies 0x040–0x047 (4 distinct values)".
    pub fn label(&self) -> String {
        let span = format_span(self.start, self.end);
        match self.kind {
            RegionKind::Constant => format!("constant {span}"),
            RegionKind::Varies { fewest_distinct, most_distinct, min, max } => {
                let count = if fewest_distinct == most_distinct {
                    format!("{most_distinct} distinct values")
                } else {
                    format!("{fewest_distinct}–{most_distinct} distinct values per byte")
                };
                format!("varies {span} ({count}, 0x{min:02X}–0x{max:02X})")
            }
            RegionKind::Trend { direction, field } => {
                let verb = match direction {
                    Direction::Increasing => "increments",
                    Direction::Decreasing => "decrements",
                };
                match field {
                    Some(field) => {
                        let order = if field.big_endian { "BE" } else { "LE" };
                        format!("{verb} across files {span} (u{} {order})", field.width * 8)
                    }
                    None => format!("{verb} across files {span}"),
                }
            }
        }
    }
}

/// Bytes of one file beyond the common prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tail {
    pub file: usize,
    /// Relative to the file's start offset, like region offsets.
    pub start: usize,
    pub len: usize,
}

/// The summary of a comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariationReport {
    pub file_count: usize,
    /// Length every file has after its start offset.
    pub common_len: usize,
    /// How much of the common prefix was summarised (less than `common_len`
    /// when the length or region caps were reached).
    pub analysed_len: usize,
    pub regions: Vec<Region>,
    pub tails: Vec<Tail>,
}

impl VariationReport {
    pub fn constant_bytes(&self) -> usize {
        self.regions.iter().filter(|region| region.kind == RegionKind::Constant).map(Region::len).sum()
    }

    pub fn is_truncated(&self) -> bool {
        self.analysed_len < self.common_len
    }
}

/// Each file from its start offset, after checking the offsets are valid.
pub fn apply_start_offsets<'a>(files: &[&'a [u8]], starts: &[usize]) -> Result<Vec<&'a [u8]>, VariationError> {
    if files.len() != starts.len() {
        return Err(VariationError::StartCountMismatch { files: files.len(), starts: starts.len() });
    }
    files
        .iter()
        .zip(starts)
        .enumerate()
        .map(|(file, (bytes, &start))| {
            bytes.get(start..).ok_or(VariationError::StartBeyondEnd { file, start, len: bytes.len() })
        })
        .collect()
}

/// Compare `files`, each read from its entry in `starts`, position by position.
pub fn summarise_variation(files: &[&[u8]], starts: &[usize]) -> Result<VariationReport, VariationError> {
    if files.len() < MIN_FILES {
        return Err(VariationError::TooFewFiles(files.len()));
    }
    if files.len() > MAX_FILES {
        return Err(VariationError::TooManyFiles(files.len()));
    }
    let aligned = apply_start_offsets(files, starts)?;
    let common_len = aligned.iter().map(|bytes| bytes.len()).min().unwrap_or(0);

    let (byte_regions, analysed_len) = group_positions(&aligned, common_len.min(MAX_COMPARED_LEN));
    let regions = promote_counters(byte_regions, &aligned);
    let tails = aligned
        .iter()
        .enumerate()
        .filter(|(_, bytes)| bytes.len() > common_len)
        .map(|(file, bytes)| Tail { file, start: common_len, len: bytes.len() - common_len })
        .collect();
    Ok(VariationReport { file_count: files.len(), common_len, analysed_len, regions, tails })
}

// ---------------------------------------------------------------------------
// Per-position classification
// ---------------------------------------------------------------------------

/// How one byte position behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteClass {
    Constant,
    Varies { distinct: usize, min: u8, max: u8 },
    Trend(Direction),
}

fn classify_position(files: &[&[u8]], position: usize) -> ByteClass {
    let first = files[0][position];
    if files.iter().all(|bytes| bytes[position] == first) {
        return ByteClass::Constant;
    }
    let values = files.iter().map(|bytes| bytes[position] as u64);
    if let Some(direction) = trend(values) {
        return ByteClass::Trend(direction);
    }
    let mut seen = [false; 256];
    let mut distinct = 0;
    let (mut min, mut max) = (u8::MAX, u8::MIN);
    for bytes in files {
        let value = bytes[position];
        if !seen[value as usize] {
            seen[value as usize] = true;
            distinct += 1;
        }
        min = min.min(value);
        max = max.max(value);
    }
    ByteClass::Varies { distinct, min, max }
}

/// The direction of a sequence that never moves backwards and ends somewhere
/// other than where it started; `None` otherwise.
fn trend(values: impl Iterator<Item = u64> + Clone) -> Option<Direction> {
    let mut pairs = values.clone().zip(values.clone().skip(1));
    let first = values.clone().next()?;
    let last = values.last()?;
    if last > first && pairs.clone().all(|(a, b)| b >= a) {
        Some(Direction::Increasing)
    } else if last < first && pairs.all(|(a, b)| b <= a) {
        Some(Direction::Decreasing)
    } else {
        None
    }
}

/// Group positions `0..len` into byte-level regions. Returns the regions and
/// how far the analysis got before the region cap.
fn group_positions(files: &[&[u8]], len: usize) -> (Vec<Region>, usize) {
    let mut regions: Vec<Region> = Vec::new();
    for position in 0..len {
        let class = classify_position(files, position);
        if let Some(last) = regions.last_mut()
            && extend_region(last, class)
        {
            continue;
        }
        if regions.len() == MAX_REGIONS {
            return (regions, position);
        }
        regions.push(Region { start: position, end: position + 1, kind: region_kind(class) });
    }
    (regions, len)
}

fn region_kind(class: ByteClass) -> RegionKind {
    match class {
        ByteClass::Constant => RegionKind::Constant,
        ByteClass::Varies { distinct, min, max } => {
            RegionKind::Varies { fewest_distinct: distinct, most_distinct: distinct, min, max }
        }
        ByteClass::Trend(direction) => RegionKind::Trend { direction, field: None },
    }
}

/// Grow `region` by one position of `class` if they behave alike.
fn extend_region(region: &mut Region, class: ByteClass) -> bool {
    let merged = match (&mut region.kind, class) {
        (RegionKind::Constant, ByteClass::Constant) => true,
        (RegionKind::Trend { direction, field: None }, ByteClass::Trend(next)) => *direction == next,
        (RegionKind::Varies { fewest_distinct, most_distinct, min, max }, ByteClass::Varies { distinct, min: lo, max: hi }) => {
            *fewest_distinct = (*fewest_distinct).min(distinct);
            *most_distinct = (*most_distinct).max(distinct);
            *min = (*min).min(lo);
            *max = (*max).max(hi);
            true
        }
        _ => false,
    };
    if merged {
        region.end += 1;
    }
    merged
}

// ---------------------------------------------------------------------------
// Multi-byte counters
// ---------------------------------------------------------------------------

/// Find short runs of changing bytes that together form an integer moving in
/// one direction (a version number whose low byte carries, for instance) and
/// replace the byte-level regions they cover with one counter region.
fn promote_counters(regions: Vec<Region>, files: &[&[u8]]) -> Vec<Region> {
    let common_len = files.iter().map(|bytes| bytes.len()).min().unwrap_or(0);
    let runs = changing_runs(&regions);
    let mut counters: Vec<Region> = Vec::new();
    for (index, run) in runs.iter().enumerate() {
        // The field may not reach into a neighbouring run of changes.
        let lowest = if index == 0 { 0 } else { runs[index - 1].end };
        let highest = runs.get(index + 1).map_or(common_len, |next| next.start);
        let Some(counter) = find_counter(files, run, lowest..highest) else { continue };
        let overlaps_previous = counters.last().is_some_and(|previous| previous.end > counter.start);
        if !overlaps_previous {
            counters.push(counter);
        }
    }
    if counters.is_empty() {
        return regions;
    }
    overlay(regions, counters)
}

/// A maximal run of adjacent non-constant positions.
struct ChangingRun {
    start: usize,
    end: usize,
    /// Every byte of the run already moves in one shared direction.
    is_byte_trend: bool,
}

fn changing_runs(regions: &[Region]) -> Vec<ChangingRun> {
    let mut runs: Vec<ChangingRun> = Vec::new();
    for region in regions.iter().filter(|region| region.kind != RegionKind::Constant) {
        let is_trend = matches!(region.kind, RegionKind::Trend { .. });
        match runs.last_mut() {
            Some(run) if run.end == region.start => {
                run.end = region.end;
                run.is_byte_trend = false;
            }
            _ => runs.push(ChangingRun { start: region.start, end: region.end, is_byte_trend: is_trend }),
        }
    }
    runs
}

/// The widest aligned integer containing `run`, and lying within `bounds`,
/// whose value moves in one direction across the files.
///
/// The changing bytes must sit at the field's low end: its first byte for
/// little-endian, its last for big-endian. A run whose bytes already trend on
/// their own is only widened as little-endian (a small version number in a
/// wider field); widening it as big-endian would claim a field from bytes
/// that never change.
fn find_counter(files: &[&[u8]], run: &ChangingRun, bounds: std::ops::Range<usize>) -> Option<Region> {
    for width in COUNTER_WIDTHS {
        let field_start = run.start - run.start % width;
        let field_end = field_start + width;
        if run.end > field_end || field_start < bounds.start || field_end > bounds.end {
            continue;
        }
        let little_endian_fits = run.start == field_start;
        let big_endian_fits = run.end == field_end && !run.is_byte_trend;
        let orders = [(false, little_endian_fits), (true, big_endian_fits)];
        for (big_endian, _) in orders.into_iter().filter(|&(_, fits)| fits) {
            let values = files.iter().map(|bytes| read_unsigned(&bytes[field_start..field_end], big_endian));
            if let Some(direction) = trend(values) {
                let field = CounterField { width, big_endian };
                return Some(Region { start: field_start, end: field_end, kind: RegionKind::Trend { direction, field: Some(field) } });
            }
        }
    }
    None
}

fn read_unsigned(bytes: &[u8], big_endian: bool) -> u64 {
    let fold = |value: u64, &byte: &u8| (value << 8) | byte as u64;
    if big_endian { bytes.iter().fold(0, fold) } else { bytes.iter().rev().fold(0, fold) }
}

/// Lay `counters` (sorted, non-overlapping) over `regions`, trimming the
/// regions they cover.
fn overlay(regions: Vec<Region>, counters: Vec<Region>) -> Vec<Region> {
    let mut result = Vec::with_capacity(regions.len() + counters.len());
    let mut counters = counters.into_iter().peekable();
    for region in regions {
        let mut remaining = Some(region);
        while let Some(current) = remaining {
            match counters.peek() {
                Some(counter) if counter.start < current.end => {
                    let counter = *counter;
                    if current.start < counter.start {
                        result.push(Region { end: counter.start, ..current });
                    }
                    if result.last() != Some(&counter) {
                        result.push(counter);
                    }
                    if current.end > counter.end {
                        counters.next();
                        remaining = Some(Region { start: counter.end, ..current });
                    } else {
                        if current.end == counter.end {
                            counters.next();
                        }
                        remaining = None;
                    }
                }
                _ => {
                    result.push(current);
                    remaining = None;
                }
            }
        }
    }
    result
}

/// "0x040–0x047", or a single offset for a one-byte span.
pub fn format_span(start: usize, end: usize) -> String {
    let last = end.saturating_sub(1);
    if last <= start { format!("0x{start:03X}") } else { format!("0x{start:03X}–0x{last:03X}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRMWARE_LEN: usize = 0x40;
    const VERSION_OFFSET: usize = 0x10;
    const CHECKSUM_OFFSET: usize = 0x3C;

    /// Five "firmware versions": constant header, a u32 LE version counter at
    /// 0x10 (1..=5) and a checksum at the end that changes without pattern.
    fn firmware_versions() -> Vec<Vec<u8>> {
        let checksums: [u32; 5] = [0x1234_5678, 0x0BAD_F00D, 0x7777_0001, 0x0102_0304, 0xDEAD_BEEF];
        (0..5u32)
            .map(|index| {
                let mut image = vec![0xAA; FIRMWARE_LEN];
                image[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&(index + 1).to_le_bytes());
                image[CHECKSUM_OFFSET..].copy_from_slice(&checksums[index as usize].to_le_bytes());
                image
            })
            .collect()
    }

    fn summarise(files: &[Vec<u8>]) -> VariationReport {
        let slices: Vec<&[u8]> = files.iter().map(Vec::as_slice).collect();
        summarise_variation(&slices, &vec![0; files.len()]).expect("valid input")
    }

    #[test]
    fn five_firmware_versions_show_the_version_counter_and_changing_checksum() {
        let report = summarise(&firmware_versions());
        let labels: Vec<String> = report.regions.iter().map(Region::label).collect();
        assert_eq!(
            labels,
            vec![
                "constant 0x000–0x00F",
                "increments across files 0x010–0x013 (u32 LE)",
                "constant 0x014–0x03B",
                "varies 0x03C–0x03F (4–5 distinct values per byte, 0x00–0xF0)",
            ]
        );
        assert_eq!(report.common_len, FIRMWARE_LEN);
        assert!(report.tails.is_empty());
        assert!(!report.is_truncated());
    }

    #[test]
    fn counters_whose_low_byte_wraps_are_recognised_as_one_field_in_either_byte_order() {
        let values: [u16; 4] = [0x00FE, 0x00FF, 0x0100, 0x0101];
        let cases = [(false, 2, 4), (true, 0, 2)];
        for (big_endian, start, end) in cases {
            let files: Vec<Vec<u8>> = values
                .iter()
                .map(|value| {
                    let mut bytes = vec![0u8; 8];
                    let encoded = if big_endian { value.to_be_bytes() } else { value.to_le_bytes() };
                    bytes[start..end].copy_from_slice(&encoded);
                    bytes
                })
                .collect();
            let report = summarise(&files);
            let counter = report.regions.iter().find(|region| region.kind != RegionKind::Constant).unwrap();
            assert_eq!((counter.start, counter.end), (start, end), "big endian: {big_endian}");
            assert_eq!(
                counter.kind,
                RegionKind::Trend { direction: Direction::Increasing, field: Some(CounterField { width: 2, big_endian }) }
            );
        }
    }

    #[test]
    fn files_of_different_lengths_report_the_common_prefix_and_each_longer_tail() {
        let files = vec![vec![1u8; 10], vec![1u8; 16], vec![1u8; 12]];
        let report = summarise(&files);
        assert_eq!(report.common_len, 10);
        assert_eq!(report.tails, vec![Tail { file: 1, start: 10, len: 6 }, Tail { file: 2, start: 10, len: 2 }]);
        assert_eq!(report.regions, vec![Region { start: 0, end: 10, kind: RegionKind::Constant }]);
    }

    #[test]
    fn start_offsets_line_up_files_whose_headers_differ_in_length() {
        let shorter = vec![9, 9, 1, 2, 3];
        let longer = vec![7, 7, 7, 9, 9, 1, 2, 3];
        let unaligned = summarise_variation(&[&shorter, &longer], &[0, 0]).unwrap();
        assert!(unaligned.regions.iter().any(|region| region.kind != RegionKind::Constant));
        let report = summarise_variation(&[&shorter, &longer], &[0, 3]).unwrap();
        assert_eq!(report.regions, vec![Region { start: 0, end: 5, kind: RegionKind::Constant }]);
    }

    #[test]
    fn a_decreasing_byte_is_reported_as_decrementing() {
        let files = vec![vec![0, 9], vec![0, 5], vec![0, 5], vec![0, 1]];
        let report = summarise(&files);
        assert_eq!(report.regions[1].label(), "decrements across files 0x001");
    }

    #[test]
    fn invalid_input_is_explained_rather_than_panicking() {
        let one = [1u8, 2, 3];
        assert_eq!(summarise_variation(&[&one], &[0]), Err(VariationError::TooFewFiles(1)));
        assert_eq!(
            summarise_variation(&[&one, &one], &[0, 4]),
            Err(VariationError::StartBeyondEnd { file: 1, start: 4, len: 3 })
        );
        assert_eq!(
            summarise_variation(&[&one, &one], &[0]),
            Err(VariationError::StartCountMismatch { files: 2, starts: 1 })
        );
        let many: Vec<&[u8]> = vec![&one; MAX_FILES + 1];
        assert!(matches!(summarise_variation(&many, &vec![0; MAX_FILES + 1]), Err(VariationError::TooManyFiles(_))));
    }

    #[test]
    fn empty_files_produce_an_empty_report() {
        let report = summarise_variation(&[&[], &[]], &[0, 0]).unwrap();
        assert_eq!(report.common_len, 0);
        assert!(report.regions.is_empty());
    }

    #[test]
    fn regions_tile_the_analysed_prefix_without_gaps() {
        let files: Vec<Vec<u8>> = (0..6u32).map(|seed| (0..300u32).map(|i| ((i * 31 + seed * (i % 7)) % 251) as u8).collect()).collect();
        let report = summarise(&files);
        let mut expected_start = 0;
        for region in &report.regions {
            assert_eq!(region.start, expected_start);
            assert!(!region.is_empty());
            expected_start = region.end;
        }
        assert_eq!(expected_start, report.analysed_len);
    }
}
