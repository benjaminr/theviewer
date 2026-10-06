//! Feature tracks: how a file's character changes along its length.
//!
//! The file is sampled at up to [`MAX_POINTS`] evenly spaced points. Each
//! point covers the stretch up to the next one and reports its entropy,
//! compressibility, printable and zero fractions, byte-kind mix and the
//! **local record width**: the period (2 to 1024 bytes) at which the bytes
//! around the point repeat best, found by a sampled autocorrelation over a
//! window large enough to hold several records.

use rayon::prelude::*;

use crate::features::{self, KindMix};

/// Most points in a track.
pub const MAX_POINTS: usize = 4096;
/// Shortest record width looked for.
pub const MIN_WIDTH: usize = 2;
/// Longest record width looked for.
pub const MAX_WIDTH: usize = 1024;
/// Smallest stretch of bytes measured per point.
const MIN_STATS_WINDOW: usize = 256;
/// Most bytes measured per point for the statistics (larger steps are sampled).
const MAX_STATS_WINDOW: usize = 64 * 1024;
/// Bytes examined around each point for the record width: room for three
/// records of the longest width.
const WIDTH_WINDOW: usize = 3 * MAX_WIDTH;
/// Bytes compared per lag in the width search.
const WIDTH_SAMPLE: usize = 2048;
/// Most positions the (costlier) width search runs at; neighbouring points
/// share the width found for their group.
const MAX_WIDTH_POINTS: usize = 1024;
/// Stretches above this entropy (bits per byte) are treated as random and
/// not searched for a record width.
const RANDOM_ENTROPY: f32 = 7.5;
/// Stretches below this entropy are padding and not searched either.
const PADDING_ENTROPY: f32 = 0.5;

/// Settings for [`compute_tracks`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackOptions {
    /// Points wanted; capped at [`MAX_POINTS`] and at one per [`MIN_STATS_WINDOW`] bytes.
    pub points: usize,
}

impl Default for TrackOptions {
    fn default() -> Self {
        TrackOptions { points: MAX_POINTS }
    }
}

/// Per-position series across the file. Every vector has one entry per point.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FeatureTracks {
    /// Bytes analysed.
    pub scanned_len: usize,
    /// File offset where each point's stretch starts.
    pub offsets: Vec<usize>,
    /// Shannon entropy in bits per byte (0 to 8).
    pub entropy: Vec<f32>,
    /// LZ4 compressed size over original size (0 to 1.2).
    pub compressibility: Vec<f32>,
    /// Fraction of printable bytes.
    pub printable: Vec<f32>,
    /// Fraction of zero bytes.
    pub zeros: Vec<f32>,
    /// Fractions of zero, printable, control and high bytes.
    pub kinds: Vec<KindMix>,
    /// Best local record width in bytes, or 0 where nothing repeats.
    pub width: Vec<usize>,
    /// Strength of that width: match rate above the median lag (0 to 1).
    pub width_strength: Vec<f32>,
}

impl FeatureTracks {
    /// Number of points.
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// Whether there are no points.
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    /// Index of the point whose stretch contains `offset` (the last point for
    /// offsets past the end), or `None` when there are no points.
    pub fn point_at(&self, offset: usize) -> Option<usize> {
        if self.offsets.is_empty() {
            return None;
        }
        Some(self.offsets.partition_point(|&start| start <= offset).saturating_sub(1))
    }
}

/// Compute the tracks for `data`, in parallel.
pub fn compute_tracks(data: &[u8], options: &TrackOptions) -> FeatureTracks {
    let offsets = point_offsets(data.len(), options.points);
    let end_of = |index: usize| offsets.get(index + 1).copied().unwrap_or(data.len());
    let measures: Vec<features::Features> = offsets.par_iter().enumerate().map(|(index, &offset)| measure_stretch(data, offset, end_of(index))).collect();

    let group = offsets.len().div_ceil(MAX_WIDTH_POINTS).max(1);
    let group_widths: Vec<features::PeriodPeak> = (0..offsets.len().div_ceil(group))
        .into_par_iter()
        .map(|group_index| {
            let first = group_index * group;
            let last = (first + group).min(offsets.len()) - 1;
            let typical = &measures[(first + last) / 2];
            if typical.entropy > RANDOM_ENTROPY || typical.entropy < PADDING_ENTROPY {
                return features::PeriodPeak::default();
            }
            let centre = offsets[first] + (end_of(last) - offsets[first]) / 2;
            local_width(&data[window_within(data.len(), centre, WIDTH_WINDOW)])
        })
        .collect();

    let mut tracks = FeatureTracks { scanned_len: data.len(), ..FeatureTracks::default() };
    for (index, (offset, measure)) in offsets.iter().zip(&measures).enumerate() {
        let width = group_widths[index / group];
        tracks.offsets.push(*offset);
        tracks.entropy.push(measure.entropy);
        tracks.compressibility.push(measure.compressibility);
        tracks.printable.push(measure.kinds.printable);
        tracks.zeros.push(measure.kinds.zero);
        tracks.kinds.push(measure.kinds);
        tracks.width.push(width.period);
        tracks.width_strength.push(width.strength);
    }
    tracks
}

/// Evenly spaced point offsets: at most `points` (capped at [`MAX_POINTS`])
/// and at least [`MIN_STATS_WINDOW`] bytes apart.
fn point_offsets(len: usize, points: usize) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }
    let count = points.clamp(1, MAX_POINTS).min(len.div_ceil(MIN_STATS_WINDOW)).max(1);
    (0..count).map(|index| (index as u128 * len as u128 / count as u128) as usize).collect()
}

/// Measure the stretch `offset..next`, widened to [`MIN_STATS_WINDOW`] and
/// sampled to [`MAX_STATS_WINDOW`] about its centre.
fn measure_stretch(data: &[u8], offset: usize, next: usize) -> features::Features {
    let stats_len = (next - offset).clamp(MIN_STATS_WINDOW, MAX_STATS_WINDOW);
    features::measure(&data[window_within(data.len(), offset + (next - offset) / 2, stats_len)])
}

/// A range of up to `len` bytes centred on `centre`, shifted to lie within `0..total`.
fn window_within(total: usize, centre: usize, len: usize) -> std::ops::Range<usize> {
    let len = len.min(total);
    let start = centre.saturating_sub(len / 2).min(total - len);
    start..start + len
}

/// The record width of a window: the best period from [`MIN_WIDTH`] to
/// [`MAX_WIDTH`], comparing the first [`WIDTH_SAMPLE`] bytes with the bytes
/// one lag later, so every lag sees the same number of pairs.
fn local_width(window: &[u8]) -> features::PeriodPeak {
    let max_lag = MAX_WIDTH.min(window.len() / 3);
    if max_lag < MIN_WIDTH {
        return features::PeriodPeak::default();
    }
    let compared = WIDTH_SAMPLE.min(window.len() - max_lag);
    let scores: Vec<f32> = (MIN_WIDTH..=max_lag).map(|lag| equal_fraction(&window[..compared], &window[lag..lag + compared])).collect();
    peak_of(&scores)
}

fn equal_fraction(a: &[u8], b: &[u8]) -> f32 {
    if a.is_empty() {
        return 0.0;
    }
    a.iter().zip(b).filter(|(x, y)| x == y).count() as f32 / a.len() as f32
}

/// The fundamental period from match rates indexed from [`MIN_WIDTH`].
fn peak_of(scores: &[f32]) -> features::PeriodPeak {
    /// A lag at least this share of the best counts as "as good", so the shortest (fundamental) wins.
    const FUNDAMENTAL_SHARE: f32 = 0.9;
    let mut sorted = scores.to_vec();
    sorted.sort_by(f32::total_cmp);
    let (Some(&median), Some(&best)) = (sorted.get(sorted.len() / 2), sorted.last()) else {
        return features::PeriodPeak::default();
    };
    let strength = (best - median).max(0.0);
    if strength < features::MIN_PERIOD_STRENGTH {
        return features::PeriodPeak { period: 0, strength };
    }
    let fundamental = scores.iter().position(|&score| score >= best * FUNDAMENTAL_SHARE).unwrap_or(0);
    features::PeriodPeak { period: fundamental + MIN_WIDTH, strength }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::test_data::*;

    #[test]
    fn the_width_track_shows_each_regions_record_size() {
        let mut data = prose(20_000, 1);
        let wide_start = data.len();
        data.extend(records(40_000, 64, 2));
        let narrow_start = data.len();
        data.extend(records(30_000, 24, 3));
        let narrow_end = data.len();
        data.extend(random_bytes(20_000, 4));
        let tracks = compute_tracks(&data, &TrackOptions::default());
        let width_at = |offset: usize| tracks.width[tracks.point_at(offset).expect("points exist")];
        assert_eq!(width_at(wide_start + 20_000), 64);
        assert_eq!(width_at(narrow_start + 15_000), 24);
        assert_eq!(width_at(narrow_end + 10_000), 0, "random data has no record width");
        assert_eq!(width_at(5_000), 0, "prose has no record width");
    }

    #[test]
    fn the_statistic_tracks_follow_the_content() {
        let mut data = prose(16_000, 5);
        data.extend(vec![0u8; 16_000]);
        data.extend(random_bytes(16_000, 6));
        let tracks = compute_tracks(&data, &TrackOptions { points: 48 });
        assert_eq!(tracks.len(), 48);
        let at = |offset: usize| tracks.point_at(offset).expect("points exist");
        assert!(tracks.printable[at(8_000)] > 0.99);
        assert!(tracks.zeros[at(24_000)] > 0.99);
        assert!(tracks.entropy[at(40_000)] > 7.0);
        assert!(tracks.compressibility[at(40_000)] > tracks.compressibility[at(8_000)]);
        assert!(tracks.kinds[at(40_000)].high > 0.4);
    }

    #[test]
    fn points_are_bounded_and_ordered() {
        let data = random_bytes(10_000_000, 7);
        let tracks = compute_tracks(&data, &TrackOptions { points: 1_000_000 });
        assert_eq!(tracks.len(), MAX_POINTS);
        assert!(tracks.offsets.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(tracks.point_at(usize::MAX), Some(MAX_POINTS - 1));
    }

    #[test]
    fn tiny_and_empty_input_never_panics() {
        assert!(compute_tracks(&[], &TrackOptions::default()).is_empty());
        for len in [1, 5, 255, 256, 257, 3000] {
            let tracks = compute_tracks(&random_bytes(len, len as u64), &TrackOptions { points: 0 });
            assert!(!tracks.is_empty());
            assert_eq!(tracks.offsets[0], 0);
        }
    }
}
