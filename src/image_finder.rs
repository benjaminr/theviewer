//! Finds uncompressed bitmaps (fonts, splash screens, framebuffers) by
//! sweeping row widths and pixel formats across the data.
//!
//! An uncompressed image has one tell-tale property: a pixel looks like the
//! pixel one row below it, and like its neighbour to the right, far more than
//! it looks like a pixel picked at random. Flat regions fail because there is
//! nothing to compare, and random or compressed data fails because every pair
//! is equally unlike.
//!
//! The search is coarse to fine:
//! 1. The data is cut into overlapping windows at two scales (small windows
//!    for narrow rows, large ones for wide rows). Flat and high-entropy
//!    windows are skipped; when there are too many windows they are sampled.
//! 2. In each window a sampled profile scores every row length (stride) by
//!    how alike positions one stride apart are: by byte value, by bits for
//!    one-bit formats, and by decoded colour (at both byte phases) for
//!    RGB565. For each pixel format a handful of the best plausible strides
//!    are kept, each reduced to a divisor that scores nearly as well, then
//!    nudged by whole pixels to reject diagonal neighbours.
//! 3. Those strides are checked again in pixel space at every byte phase,
//!    scoring vertical and horizontal similarity against random pixel pairs;
//!    the best format and stride win.
//! 4. Neighbouring windows that agree are merged, the region is grown and
//!    trimmed row by row, and its first row is located to the byte by a
//!    change-point search.
//!
//! Bounds: at most 2048 small and 256 large windows are examined however
//! large the input, so time is roughly constant beyond 8 MiB.

use rayon::prelude::*;

use crate::raster::PixelFormat;

/// Formats the finder tries, simplest first (ties go to the earlier one).
pub const SEARCH_FORMATS: [PixelFormat; 5] =
    [PixelFormat::Bit1Msb, PixelFormat::Gray8, PixelFormat::Rgb565, PixelFormat::Rgb8, PixelFormat::Rgba8];
/// Narrowest image reported, in pixels.
pub const MIN_WIDTH: usize = 16;
/// Widest image reported, in pixels.
pub const MAX_WIDTH: usize = 2048;
/// Fewest rows for a region to count as an image.
pub const MIN_HEIGHT: usize = 8;
/// Most candidates returned.
pub const MAX_CANDIDATES: usize = 50;

/// A window is flat when one byte value makes up at least this fraction of it.
const FLAT_FRACTION: f32 = 0.97;
/// A window is treated as random or compressed above this entropy (bits per byte).
const RANDOM_ENTROPY: f32 = 7.9;
/// Samples per stride in the coarse byte profile.
const COARSE_SAMPLES: usize = 128;
/// Samples for the fine checks (stride nudging and pixel scores).
const FINE_SAMPLES: usize = 1024;
/// Fewest whole rows a window must hold for a stride to be tried.
const MIN_ROWS_PER_WINDOW: usize = 4;
/// Bytes in a pixel with an alpha or padding byte.
const ALPHA_PIXEL_BYTES: usize = 4;
/// A fourth byte this often one value is taken to be alpha or padding.
const CONSTANT_ALPHA_FRACTION: f32 = 0.9;
/// Scores this close are a tie.
const SCORE_TIE_MARGIN: f32 = 0.01;
/// Strides per format checked in pixel space.
const STRIDES_PER_FORMAT: usize = 6;
/// Largest divisor of the best stride considered as its fundamental.
const MAX_HARMONIC: usize = 8;
/// A divisor stride wins when it scores within this much of the best.
const HARMONIC_TOLERANCE: f32 = 0.05;
/// Whole pixels either side of the best stride tried when nudging it.
const STRIDE_NUDGE_PIXELS: usize = 2;
/// Byte-profile score a stride needs before pixel checks are spent on it.
const MIN_VERTICAL_SCORE: f32 = 0.3;
/// Weight of vertical similarity in the combined score.
const VERTICAL_WEIGHT: f32 = 0.6;
/// Weight of horizontal similarity in the combined score.
const HORIZONTAL_WEIGHT: f32 = 0.4;
/// Combined score a window needs to count as image data.
const MIN_IMAGE_SCORE: f32 = 0.45;
/// Mean distance between random pixel pairs below which data is flat.
const MIN_PIXEL_BASELINE: f32 = 1.0;
/// Pixels compared when deciding whether two rows belong together.
const ROW_SAMPLES: usize = 48;
/// Two rows belong together when their mean distance is below this fraction
/// of the distance between random pixels.
const ROW_SIMILARITY_LIMIT: f32 = 0.6;
/// Most rows a region may grow by in either direction.
const MAX_EXTENSION_ROWS: usize = 1 << 16;
/// A pixel before the first whole row joins the image when its distance to
/// the pixel one row below is within this fraction of the random-pair distance.
const EDGE_PIXEL_LIMIT: f32 = 0.3;
/// For byte-per-channel formats, a byte joins the image when its difference
/// from the byte one row below is at most this multiple of the median
/// difference within the image...
const EDGE_BYTE_TOLERANCE_FACTOR: u32 = 2;
/// ...plus this much, so a perfectly smooth image still tolerates noise.
const EDGE_BYTE_TOLERANCE_FLOOR: u32 = 2;
/// For one-bit formats, a byte (eight pixels) joins the image when at most
/// this many of its bits differ from the byte one row below.
const EDGE_MAX_BIT_FLIPS: u32 = 1;
/// Fixed seed so results are repeatable.
const SAMPLING_SEED: u64 = 0x5EED_1A6E_F1D3_0001;

/// One sweep over the data with a given window size and stride range.
struct Scale {
    window: usize,
    step: usize,
    min_row_bytes: usize,
    max_row_bytes: usize,
    max_windows: usize,
}

/// Small windows for narrow rows, large windows for wide rows.
const SCALES: [Scale; 2] = [
    Scale { window: 4 * 1024, step: 1024, min_row_bytes: 2, max_row_bytes: 1024, max_windows: 2048 },
    Scale { window: 64 * 1024, step: 32 * 1024, min_row_bytes: 2, max_row_bytes: 8192, max_windows: 256 },
];

/// A region that looks like an uncompressed image.
#[derive(Clone, Debug, PartialEq)]
pub struct ImageCandidate {
    /// Document offset of the first pixel.
    pub start: usize,
    /// Bytes spanned: `height` whole rows.
    pub len: usize,
    pub format: PixelFormat,
    /// Pixels per row.
    pub width: usize,
    /// Rows.
    pub height: usize,
    /// 0 to 1: how much more alike neighbouring pixels are than random ones.
    pub score: f32,
}

impl ImageCandidate {
    /// Bytes per row.
    pub fn row_bytes(&self) -> usize {
        self.format.bytes_for_pixels(self.width)
    }

    /// One line for lists, e.g. "RGB 24-bit, 320×240 at 0x1000 (225.0 KiB)".
    pub fn description(&self) -> String {
        format!(
            "{}, {}×{} at {:#x} ({}), score {:.2}",
            self.format.label(),
            self.width,
            self.height,
            self.start,
            crate::compress::human_bytes(self.len),
            self.score
        )
    }
}

/// Search `bytes` (which start at document offset `base`) for uncompressed
/// images, best first. Safe on any input; time is bounded by sampling.
pub fn find_images(bytes: &[u8], base: usize) -> Vec<ImageCandidate> {
    let mut candidates: Vec<ImageCandidate> = SCALES
        .iter()
        .flat_map(|scale| merge_windows(&scan_scale(bytes, scale)))
        .filter_map(|region| refine_region(bytes, &region))
        .map(|mut candidate| {
            candidate.start += base;
            candidate
        })
        .collect();
    candidates.sort_by(|a, b| b.score.total_cmp(&a.score).then(b.len.cmp(&a.len)));
    keep_non_overlapping(candidates)
}

/// The width in pixels of a row of `row_bytes` bytes, if whole and plausible.
fn width_for(format: PixelFormat, row_bytes: usize) -> Option<usize> {
    let bits = row_bytes * 8;
    let bits_per_pixel = format.bits_per_pixel();
    if !bits.is_multiple_of(bits_per_pixel) {
        return None;
    }
    let width = bits / bits_per_pixel;
    (MIN_WIDTH..=MAX_WIDTH).contains(&width).then_some(width)
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

/// What one window looks like, if it looks like an image.
#[derive(Clone, Copy, Debug)]
struct WindowVerdict {
    offset: usize,
    len: usize,
    format: PixelFormat,
    row_bytes: usize,
    score: f32,
    /// Typical distance between unrelated pixels.
    pixel_baseline: f32,
}

fn window_offsets(len: usize, scale: &Scale) -> Vec<usize> {
    if len <= scale.window {
        return vec![0];
    }
    let last = len - scale.window;
    let step = scale.step.max(last / scale.max_windows.max(1));
    let mut offsets: Vec<usize> = (0..=last).step_by(step.max(1)).collect();
    if offsets.last() != Some(&last) {
        offsets.push(last);
    }
    offsets
}

fn scan_scale(bytes: &[u8], scale: &Scale) -> Vec<WindowVerdict> {
    window_offsets(bytes.len(), scale)
        .into_par_iter()
        .filter_map(|offset| {
            let window = &bytes[offset..(offset + scale.window).min(bytes.len())];
            evaluate_window(window, scale).map(|verdict| WindowVerdict { offset: offset + verdict.offset, ..verdict })
        })
        .collect()
}

fn is_flat_or_random(window: &[u8]) -> bool {
    let mut counts = [0u32; 256];
    for &byte in window {
        counts[usize::from(byte)] += 1;
    }
    let total = window.len() as f32;
    let most_common = counts.iter().copied().max().unwrap_or(0) as f32;
    let entropy: f32 = counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f32 / total;
            -p * p.log2()
        })
        .sum();
    most_common >= FLAT_FRACTION * total || entropy > RANDOM_ENTROPY
}

fn evaluate_window(window: &[u8], scale: &Scale) -> Option<WindowVerdict> {
    let max_row_bytes = scale.max_row_bytes.min(window.len() / MIN_ROWS_PER_WINDOW);
    if max_row_bytes < scale.min_row_bytes || is_flat_or_random(window) {
        return None;
    }
    let strides = scale.min_row_bytes..=max_row_bytes;
    let bytes = StrideProfile::measure(window, strides.clone(), Metric::Bytes)?;
    // One-bit rows are short, so their bitwise profile covers fewer strides.
    let bits = StrideProfile::measure(window, scale.min_row_bytes..=max_row_bytes.min(MAX_WIDTH / 8), Metric::Bits);
    let rgb565: Vec<StrideProfile> = (0..2)
        .filter_map(|phase| StrideProfile::measure(window, strides.clone(), Metric::Rgb565Pixels { phase }))
        .collect();

    let mut best: Option<WindowVerdict> = None;
    for format in SEARCH_FORMATS {
        let profiles: Vec<&StrideProfile> = match format {
            PixelFormat::Bit1Msb | PixelFormat::Bit1Lsb => bits.iter().collect(),
            PixelFormat::Rgb565 => rgb565.iter().collect(),
            _ => vec![&bytes],
        };
        for profile in profiles {
            for row_bytes in profile.best_strides(format) {
                let row_bytes = nudge_stride(window, format, row_bytes, profile.metric);
                let Some(fit) = best_phase_fit(window, format, row_bytes) else { continue };
                let candidate = WindowVerdict {
                    offset: fit.phase,
                    len: window.len() - fit.phase,
                    format,
                    row_bytes,
                    score: fit.score,
                    pixel_baseline: fit.pixel_baseline,
                };
                if candidate.score >= MIN_IMAGE_SCORE && best.is_none_or(|current| candidate.beats(&current)) {
                    best = Some(candidate);
                }
            }
        }
    }
    best
}

impl WindowVerdict {
    /// Clearly higher scores win; near ties go to the shorter row of the
    /// same format (a picture whose rows repeat fits every multiple).
    fn beats(&self, other: &WindowVerdict) -> bool {
        let tied = (self.score - other.score).abs() <= SCORE_TIE_MARGIN;
        if tied {
            self.format == other.format && self.row_bytes < other.row_bytes
        } else {
            self.score > other.score
        }
    }
}

// ---------------------------------------------------------------------------
// Byte-level stride profile
// ---------------------------------------------------------------------------

/// How the distance between two positions one stride apart is measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Metric {
    /// Absolute difference of the bytes.
    Bytes,
    /// Differing bits, for one-bit formats.
    Bits,
    /// Colour distance of decoded RGB565 pixels starting at even (phase 0)
    /// or odd (phase 1) positions.
    Rgb565Pixels { phase: usize },
}

impl Metric {
    /// Strides this metric is measured at: 16-bit pixels only fit even rows.
    fn stride_step(self) -> usize {
        match self {
            Metric::Rgb565Pixels { .. } => 2,
            Metric::Bytes | Metric::Bits => 1,
        }
    }

    /// Distance on a 0..=255 scale, or `None` when the pair does not fit.
    fn distance(self, window: &[u8], position: usize, stride: usize) -> Option<u32> {
        match self {
            Metric::Bytes => Some(u32::from(window.get(position)?.abs_diff(*window.get(position + stride)?))),
            Metric::Bits => Some((window.get(position)? ^ window.get(position + stride)?).count_ones() * 32),
            Metric::Rgb565Pixels { phase } => {
                let aligned = (position & !1) + phase;
                if aligned + stride + 1 >= window.len() {
                    return None;
                }
                let here = pixel(&window[aligned..], PixelFormat::Rgb565, stride, 0, 0);
                let below = pixel(&window[aligned..], PixelFormat::Rgb565, stride, 1, 0);
                Some(pixel_distance(here, below) as u32 / 3)
            }
        }
    }
}

/// Mean distance between positions `stride` apart, at `samples` spread positions.
fn mean_distance_at_stride(window: &[u8], stride: usize, samples: usize, metric: Metric) -> Option<f32> {
    let span = window.len().checked_sub(stride).filter(|&span| span > 0)?;
    let samples = samples.min(span);
    let spacing = span / samples;
    let (total, counted) = (0..samples)
        .filter_map(|index| {
            // Jitter within each slot so periodic data is not sampled in step.
            let jitter = (index * 7919) % spacing.max(1);
            metric.distance(window, index * spacing + jitter, stride)
        })
        .fold((0u64, 0u32), |(total, counted), distance| (total + u64::from(distance), counted + 1));
    (counted > 0).then(|| total as f32 / counted as f32)
}

/// Mean byte distance at every stride in a range, with the median as the
/// distance between unrelated bytes.
struct StrideProfile {
    metric: Metric,
    first: usize,
    /// Distance at `first + index * metric.stride_step()`.
    distances: Vec<f32>,
    baseline: f32,
}

impl StrideProfile {
    fn measure(window: &[u8], strides: std::ops::RangeInclusive<usize>, metric: Metric) -> Option<StrideProfile> {
        let step = metric.stride_step();
        let first = strides.start().next_multiple_of(step);
        if first > *strides.end() {
            return None;
        }
        let distances: Vec<f32> = (first..=*strides.end())
            .step_by(step)
            .map(|stride| mean_distance_at_stride(window, stride, COARSE_SAMPLES, metric))
            .collect::<Option<Vec<f32>>>()?;
        let mut sorted = distances.clone();
        sorted.sort_by(f32::total_cmp);
        let baseline = *sorted.get(sorted.len() / 2)?;
        (baseline > 0.0).then_some(StrideProfile { metric, first, distances, baseline })
    }

    fn last(&self) -> usize {
        self.first + self.distances.len().saturating_sub(1) * self.metric.stride_step()
    }

    /// 1 when positions one stride apart are identical, 0 when as unlike as random.
    fn score(&self, stride: usize) -> f32 {
        let step = self.metric.stride_step();
        if stride < self.first || !(stride - self.first).is_multiple_of(step) {
            return 0.0;
        }
        self.distances.get((stride - self.first) / step).map_or(0.0, |distance| 1.0 - distance / self.baseline)
    }

    /// The best-scoring strides whose widths are plausible for `format`, at
    /// most [`STRIDES_PER_FORMAT`] of them and no two within a nudge of each
    /// other. Each is replaced by its smallest divisor that scores nearly as
    /// well, so a picture is not reported two rows to a line.
    fn best_strides(&self, format: PixelFormat) -> Vec<usize> {
        let mut ranked: Vec<usize> = (self.first..=self.last())
            .step_by(self.metric.stride_step())
            .filter(|&stride| width_for(format, stride).is_some() && self.score(stride) >= MIN_VERTICAL_SCORE)
            .collect();
        ranked.sort_by(|&a, &b| self.score(b).total_cmp(&self.score(a)).then(a.cmp(&b)));
        let separation = STRIDE_NUDGE_PIXELS * format.bytes_per_pixel().max(1);
        let mut chosen: Vec<usize> = Vec::new();
        for stride in ranked {
            if chosen.len() == STRIDES_PER_FORMAT {
                break;
            }
            let stride = self.fundamental(format, stride);
            if chosen.iter().all(|&other| other.abs_diff(stride) > separation) {
                chosen.push(stride);
            }
        }
        chosen
    }

    /// The smallest divisor of `stride` that is a plausible row and scores
    /// within [`HARMONIC_TOLERANCE`] of it, else `stride` itself.
    fn fundamental(&self, format: PixelFormat, stride: usize) -> usize {
        let score = self.score(stride);
        (2..=MAX_HARMONIC)
            .rev()
            .filter(|divisor| stride.is_multiple_of(*divisor))
            .map(|divisor| stride / divisor)
            .find(|&divisor_stride| width_for(format, divisor_stride).is_some() && self.score(divisor_stride) >= score - HARMONIC_TOLERANCE)
            .unwrap_or(stride)
    }
}

/// Try the stride a pixel or two either side with more samples, so a
/// diagonal neighbour that scored well by chance loses to the true row.
fn nudge_stride(window: &[u8], format: PixelFormat, row_bytes: usize, metric: Metric) -> usize {
    let step = format.bytes_per_pixel().max(1);
    let reach = STRIDE_NUDGE_PIXELS * step;
    (row_bytes.saturating_sub(reach)..=row_bytes + reach)
        .step_by(step)
        .filter(|&stride| width_for(format, stride).is_some() && stride * MIN_ROWS_PER_WINDOW <= window.len())
        .filter_map(|stride| mean_distance_at_stride(window, stride, FINE_SAMPLES, metric).map(|d| (stride, d)))
        .min_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)))
        .map_or(row_bytes, |(stride, _)| stride)
}

// ---------------------------------------------------------------------------
// Pixel space
// ---------------------------------------------------------------------------

/// Repeatable xorshift sampler.
struct Sampler(u64);

impl Sampler {
    fn below(&mut self, limit: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % limit.max(1) as u64) as usize
    }
}

/// Three channels of pixel `x` in row `row` (rows `row_bytes` apart).
/// Callers keep `row` and `x` inside `data`.
fn pixel(data: &[u8], format: PixelFormat, row_bytes: usize, row: usize, x: usize) -> [i32; 3] {
    let row_start = row * row_bytes;
    match format {
        PixelFormat::Bit1Msb | PixelFormat::Bit1Lsb => {
            let byte = data[row_start + x / 8];
            let shift = if format == PixelFormat::Bit1Msb { 7 - x % 8 } else { x % 8 };
            let value = i32::from((byte >> shift) & 1) * 255;
            [value; 3]
        }
        PixelFormat::Rgb565 => {
            let at = row_start + 2 * x;
            let packed = u16::from_le_bytes([data[at], data[at + 1]]);
            let scale = |value: u16, max: i32| i32::from(value) * 255 / max;
            [scale(packed >> 11, 31), scale((packed >> 5) & 0x3F, 63), scale(packed & 0x1F, 31)]
        }
        PixelFormat::Rgb8 | PixelFormat::Bgr8 | PixelFormat::Rgba8 | PixelFormat::Bgra8 => {
            let at = row_start + format.bytes_per_pixel() * x;
            [i32::from(data[at]), i32::from(data[at + 1]), i32::from(data[at + 2])]
        }
        _ => {
            let at = row_start + format.bytes_per_pixel().max(1) * x;
            [i32::from(data[at]); 3]
        }
    }
}

fn pixel_distance(a: [i32; 3], b: [i32; 3]) -> f32 {
    a.iter().zip(&b).map(|(x, y)| (x - y).abs()).sum::<i32>() as f32
}

/// Vertical and horizontal similarity scores (0 to 1) and the mean distance
/// between random pixel pairs, or `None` when the window is too small or flat.
fn pixel_scores(window: &[u8], format: PixelFormat, row_bytes: usize) -> Option<(f32, f32, f32)> {
    let width = width_for(format, row_bytes)?;
    let rows = window.len() / row_bytes;
    if rows < 2 {
        return None;
    }
    let mut sampler = Sampler(SAMPLING_SEED);
    let (mut vertical, mut horizontal, mut unrelated) = (0f32, 0f32, 0f32);
    for _ in 0..FINE_SAMPLES {
        let row = sampler.below(rows - 1);
        let x = sampler.below(width - 1);
        let here = pixel(window, format, row_bytes, row, x);
        vertical += pixel_distance(here, pixel(window, format, row_bytes, row + 1, x));
        horizontal += pixel_distance(here, pixel(window, format, row_bytes, row, x + 1));
        let elsewhere = pixel(window, format, row_bytes, sampler.below(rows), sampler.below(width));
        unrelated += pixel_distance(here, elsewhere);
    }
    let samples = FINE_SAMPLES as f32;
    let baseline = unrelated / samples;
    if baseline < MIN_PIXEL_BASELINE {
        return None;
    }
    let score = |total: f32| (1.0 - total / samples / baseline).clamp(0.0, 1.0);
    Some((score(vertical), score(horizontal), baseline))
}

/// How well a format and stride fit a window, at the best pixel phase.
struct Fit {
    /// Bytes skipped at the start of the window so pixels line up.
    phase: usize,
    score: f32,
    pixel_baseline: f32,
}

/// Score every byte phase of a multi-byte format and keep the best. For
/// 32-bit pixels, a phase whose fourth byte is nearly constant (alpha or
/// padding) is taken when there is one, since colour distances alone cannot
/// tell which byte is alpha.
fn best_phase_fit(window: &[u8], format: PixelFormat, row_bytes: usize) -> Option<Fit> {
    let fit_at = |phase: usize| {
        let (vertical, horizontal, pixel_baseline) = pixel_scores(window.get(phase..)?, format, row_bytes)?;
        let score = VERTICAL_WEIGHT * vertical + HORIZONTAL_WEIGHT * horizontal;
        Some(Fit { phase, score, pixel_baseline })
    };
    if format.bytes_per_pixel() == ALPHA_PIXEL_BYTES
        && let Some(phase) = constant_alpha_phase(window)
    {
        return fit_at(phase);
    }
    (0..format.bytes_per_pixel().max(1))
        .filter_map(fit_at)
        .max_by(|a, b| a.score.total_cmp(&b.score).then(b.phase.cmp(&a.phase)))
}

/// The phase (0 to 3) at which every fourth byte, read as alpha, is most
/// often one value, if that value covers at least [`CONSTANT_ALPHA_FRACTION`].
fn constant_alpha_phase(window: &[u8]) -> Option<usize> {
    (0..ALPHA_PIXEL_BYTES)
        .map(|phase| {
            let mut counts = [0u32; 256];
            let mut total = 0u32;
            for pixel in window.get(phase..).unwrap_or_default().as_chunks::<ALPHA_PIXEL_BYTES>().0 {
                counts[usize::from(pixel[ALPHA_PIXEL_BYTES - 1])] += 1;
                total += 1;
            }
            let most_common = counts.iter().copied().max().unwrap_or(0);
            (phase, if total == 0 { 0.0 } else { most_common as f32 / total as f32 })
        })
        .filter(|&(_, fraction)| fraction >= CONSTANT_ALPHA_FRACTION)
        .max_by(|a, b| a.1.total_cmp(&b.1).then(b.0.cmp(&a.0)))
        .map(|(phase, _)| phase)
}

// ---------------------------------------------------------------------------
// Regions
// ---------------------------------------------------------------------------

/// Consecutive windows that agree on format and stride.
#[derive(Clone, Copy, Debug)]
struct Region {
    start: usize,
    end: usize,
    format: PixelFormat,
    row_bytes: usize,
    score: f32,
    pixel_baseline: f32,
}

fn merge_windows(verdicts: &[WindowVerdict]) -> Vec<Region> {
    let mut regions: Vec<Region> = Vec::new();
    let mut windows_in_last = 0f32;
    for verdict in verdicts {
        let end = verdict.offset + verdict.len;
        if let Some(last) = regions.last_mut()
            && last.format == verdict.format
            && last.row_bytes == verdict.row_bytes
            && verdict.offset <= last.end
        {
            // Running means of the score and baselines.
            windows_in_last += 1.0;
            let weight = 1.0 / windows_in_last;
            last.score += (verdict.score - last.score) * weight;
            last.pixel_baseline += (verdict.pixel_baseline - last.pixel_baseline) * weight;
            last.end = last.end.max(end);
            continue;
        }
        windows_in_last = 1.0;
        regions.push(Region {
            start: verdict.offset,
            end,
            format: verdict.format,
            row_bytes: verdict.row_bytes,
            score: verdict.score,
            pixel_baseline: verdict.pixel_baseline,
        });
    }
    regions
}

/// Whether the row at `start` and the row after it look like neighbours.
fn rows_belong_together(bytes: &[u8], region: &Region, start: usize) -> bool {
    let row_bytes = region.row_bytes;
    let Some(pair) = bytes.get(start..start + 2 * row_bytes) else { return false };
    if pair.iter().all(|&byte| byte == pair[0]) {
        return false;
    }
    let Some(width) = width_for(region.format, row_bytes) else { return false };
    let samples = ROW_SAMPLES.min(width);
    let total: f32 = (0..samples)
        .map(|index| {
            let x = index * width / samples;
            pixel_distance(pixel(pair, region.format, row_bytes, 0, x), pixel(pair, region.format, row_bytes, 1, x))
        })
        .sum();
    total / samples as f32 <= region.pixel_baseline * ROW_SIMILARITY_LIMIT
}

/// Trim and grow a region row by row, refine its first byte, and turn it
/// into a candidate if enough rows remain.
fn refine_region(bytes: &[u8], region: &Region) -> Option<ImageCandidate> {
    let row_bytes = region.row_bytes;
    let mut start = region.start;
    let mut end = start + (region.end.min(bytes.len()).saturating_sub(start)) / row_bytes * row_bytes;
    if end - start < row_bytes {
        return None;
    }

    while end - start >= 2 * row_bytes && !rows_belong_together(bytes, region, start) {
        start += row_bytes;
    }
    while end - start >= 2 * row_bytes && !rows_belong_together(bytes, region, end - 2 * row_bytes) {
        end -= row_bytes;
    }
    for _ in 0..MAX_EXTENSION_ROWS {
        if start < row_bytes || !rows_belong_together(bytes, region, start - row_bytes) {
            break;
        }
        start -= row_bytes;
    }
    for _ in 0..MAX_EXTENSION_ROWS {
        if !rows_belong_together(bytes, region, end - row_bytes) {
            break;
        }
        end += row_bytes;
    }

    let start = refine_first_byte(bytes, region, start, end);
    let height = (end - start) / row_bytes;
    if height < MIN_HEIGHT {
        return None;
    }
    Some(ImageCandidate {
        start,
        len: height * row_bytes,
        format: region.format,
        width: width_for(region.format, row_bytes)?,
        height,
        score: region.score,
    })
}

/// How far a byte may differ from the byte one row below and still count as
/// image: a multiple of the median difference across the first row of `rows`.
fn vertical_byte_tolerance(rows: &[u8], row_bytes: usize) -> u32 {
    let mut differences: Vec<u8> = (0..row_bytes).map(|index| rows[index].abs_diff(rows[index + row_bytes])).collect();
    differences.sort_unstable();
    let median = u32::from(differences[differences.len() / 2]);
    EDGE_BYTE_TOLERANCE_FACTOR * median + EDGE_BYTE_TOLERANCE_FLOOR
}

/// Find where the image really begins, to the byte, near `start` (the first
/// whole row the row-level search accepted, which may hold a few bytes from
/// before the image or begin part-way into it).
///
/// Every candidate position within a row either side is marked by whether
/// the pixel there resembles the pixel one row below. Before the image the
/// marks are mostly "no", inside it mostly "yes"; the start is the change
/// point that disagrees with the fewest marks. Positions step by whole bytes,
/// which also settles the channel order of RGB data that colour distances
/// alone cannot; RGB565 and 32-bit formats keep the phase already found.
fn refine_first_byte(bytes: &[u8], region: &Region, start: usize, end: usize) -> usize {
    let row_bytes = region.row_bytes;
    let step = match region.format {
        PixelFormat::Rgb565 | PixelFormat::Rgba8 | PixelFormat::Bgra8 => region.format.bytes_per_pixel(),
        _ => 1,
    };
    let pixel_bytes = region.format.bytes_per_pixel().max(1);
    if end < start + 2 * row_bytes {
        return start;
    }
    let first = start - (start.min(row_bytes - 1) / step) * step;
    let last = start + row_bytes - pixel_bytes;
    let positions: Vec<usize> = (first..=last).step_by(step).collect();
    let byte_tolerance = vertical_byte_tolerance(&bytes[start..start + 2 * row_bytes], row_bytes);
    let resembles_below: Vec<bool> = positions
        .iter()
        .map(|&position| match region.format {
            PixelFormat::Bit1Msb | PixelFormat::Bit1Lsb => {
                (bytes[position] ^ bytes[position + row_bytes]).count_ones() <= EDGE_MAX_BIT_FLIPS
            }
            // The low byte of RGB565 is noisy on its own; judge whole pixels.
            PixelFormat::Rgb565 => {
                let pair = &bytes[position..];
                let distance = pixel_distance(pixel(pair, region.format, row_bytes, 0, 0), pixel(pair, region.format, row_bytes, 1, 0));
                distance <= region.pixel_baseline * EDGE_PIXEL_LIMIT
            }
            // Single bytes, so a pixel straddling the edge cannot pass on
            // the strength of the channels that lie inside the image.
            _ => u32::from(bytes[position].abs_diff(bytes[position + row_bytes])) <= byte_tolerance,
        })
        .collect();
    // Disagreements if the image started at positions[split]: resembling
    // pixels before it plus unlike pixels from it on. Ties go to the earliest.
    let mut similar_before = 0usize;
    let mut unlike_after = resembles_below.iter().filter(|&&similar| !similar).count();
    let (mut best_cost, mut best_split) = (unlike_after, 0usize);
    for (split, &similar) in resembles_below.iter().enumerate() {
        if similar {
            similar_before += 1;
        } else {
            unlike_after -= 1;
        }
        let cost = similar_before + unlike_after;
        if cost < best_cost {
            (best_cost, best_split) = (cost, split + 1);
        }
    }
    positions.get(best_split).copied().unwrap_or(start)
}

/// Drop candidates that mostly overlap a better one.
fn keep_non_overlapping(sorted_best_first: Vec<ImageCandidate>) -> Vec<ImageCandidate> {
    let mut kept: Vec<ImageCandidate> = Vec::new();
    for candidate in sorted_best_first {
        let overlaps_better = kept.iter().any(|better| {
            let overlap = (candidate.start + candidate.len).min(better.start + better.len).saturating_sub(candidate.start.max(better.start));
            overlap * 2 > candidate.len.min(better.len)
        });
        if !overlaps_better {
            kept.push(candidate);
        }
        if kept.len() == MAX_CANDIDATES {
            break;
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut sampler = Sampler(seed | 1);
        (0..len).map(|_| sampler.below(256) as u8).collect()
    }

    /// A smooth, textured colour picture with a little noise.
    fn picture(x: usize, y: usize, sampler: &mut Sampler) -> [u8; 3] {
        let (x, y) = (x as f32, y as f32);
        let jitter = |sampler: &mut Sampler| sampler.below(5) as f32 - 2.0;
        let channel = |value: f32| value.clamp(0.0, 255.0) as u8;
        [
            channel(128.0 + 100.0 * (x / 11.0).sin() + jitter(sampler)),
            channel(128.0 + 100.0 * (y / 13.0).cos() + jitter(sampler)),
            channel(128.0 + 80.0 * (x / 7.0).sin() * (y / 9.0).cos() + jitter(sampler)),
        ]
    }

    fn encode(format: PixelFormat, width: usize, height: usize) -> Vec<u8> {
        let mut sampler = Sampler(99);
        let mut out = Vec::new();
        for y in 0..height {
            for x in 0..width {
                let [r, g, b] = picture(x, y, &mut sampler);
                match format {
                    PixelFormat::Gray8 => out.push(((u16::from(r) + u16::from(g) + u16::from(b)) / 3) as u8),
                    PixelFormat::Rgb8 => out.extend_from_slice(&[r, g, b]),
                    PixelFormat::Rgba8 => out.extend_from_slice(&[r, g, b, 255]),
                    PixelFormat::Rgb565 => {
                        let packed = (u16::from(r >> 3) << 11) | (u16::from(g >> 2) << 5) | u16::from(b >> 3);
                        out.extend_from_slice(&packed.to_le_bytes());
                    }
                    other => panic!("test cannot encode {other:?}"),
                }
            }
        }
        out
    }

    /// A 1-bit bitmap of glyph-like rectangles, one per 16×16 cell.
    fn glyphs(width: usize, height: usize) -> Vec<u8> {
        let mut out = vec![0u8; width / 8 * height];
        for y in 0..height {
            for x in 0..width {
                let cell = (x / 16 * 31 + y / 16 * 17) as u32;
                let hash = cell.wrapping_mul(2_654_435_761) >> 7;
                let (left, top) = ((hash % 5) as usize, ((hash >> 3) % 5) as usize);
                let (right, bottom) = (8 + ((hash >> 6) % 8) as usize, 8 + ((hash >> 9) % 8) as usize);
                let (cx, cy) = (x % 16, y % 16);
                if (left..right).contains(&cx) && (top..bottom).contains(&cy) {
                    out[y * width / 8 + x / 8] |= 0x80 >> (x % 8);
                }
            }
        }
        out
    }

    fn embedded(image: &[u8], before: usize, after: usize) -> Vec<u8> {
        [noise(before, 1), image.to_vec(), noise(after, 2)].concat()
    }

    /// Rows the found height may differ by; a glyph sheet ends in blank rows
    /// that cannot be told apart from padding.
    const HEIGHT_TOLERANCE: usize = 1;
    const GLYPH_HEIGHT_TOLERANCE: usize = 16;

    fn assert_found(data: &[u8], image_start: usize, format: PixelFormat, width: usize, height: usize, height_tolerance: usize) {
        let found = find_images(data, 0);
        let best = found.first().unwrap_or_else(|| panic!("no candidates for {format:?}"));
        assert_eq!((best.format, best.width), (format, width), "{}", best.description());
        // A byte just outside the image can match the one below it by
        // chance, so the start is only guaranteed to within a pixel.
        let pixel_bytes = format.bytes_per_pixel().max(1);
        assert!(best.start.abs_diff(image_start) < pixel_bytes, "{} (true start {image_start:#x})", best.description());
        assert!(best.height.abs_diff(height) <= height_tolerance, "{}", best.description());
    }

    #[test]
    fn an_rgb_picture_between_random_data_is_found_with_its_width() {
        let image = encode(PixelFormat::Rgb8, 200, 120);
        assert_found(&embedded(&image, 65_536, 65_536), 65_536, PixelFormat::Rgb8, 200, 120, HEIGHT_TOLERANCE);
    }

    #[test]
    fn a_greyscale_picture_is_found_as_eight_bit_grey() {
        let image = encode(PixelFormat::Gray8, 256, 100);
        assert_found(&embedded(&image, 40_000, 30_000), 40_000, PixelFormat::Gray8, 256, 100, HEIGHT_TOLERANCE);
    }

    #[test]
    fn an_rgb565_picture_is_not_mistaken_for_grey() {
        let image = encode(PixelFormat::Rgb565, 300, 80);
        assert_found(&embedded(&image, 12_345, 20_000), 12_345, PixelFormat::Rgb565, 300, 80, HEIGHT_TOLERANCE);
    }

    #[test]
    fn a_wide_rgba_framebuffer_is_found_by_the_large_window_sweep() {
        let image = encode(PixelFormat::Rgba8, 512, 96);
        assert_found(&embedded(&image, 100_000, 50_000), 100_000, PixelFormat::Rgba8, 512, 96, HEIGHT_TOLERANCE);
    }

    #[test]
    fn a_one_bit_font_sheet_is_found_with_its_width() {
        let image = glyphs(128, 512);
        assert_found(&embedded(&image, 20_000, 20_000), 20_000, PixelFormat::Bit1Msb, 128, 512, GLYPH_HEIGHT_TOLERANCE);
    }

    #[test]
    fn random_flat_and_tiny_inputs_yield_no_images() {
        assert!(find_images(&noise(512 * 1024, 7), 0).is_empty());
        assert!(find_images(&vec![0u8; 256 * 1024], 0).is_empty());
        assert!(find_images(&[], 0).is_empty());
        assert!(find_images(&[1, 2, 3, 4, 5], 0).is_empty());
    }

    #[test]
    fn a_multi_megabyte_file_of_structured_data_is_searched_in_bounded_time() {
        // Six-bit noise passes the entropy filter, so every window is profiled.
        let data: Vec<u8> = noise(8 * 1024 * 1024, 11).iter().map(|byte| byte & 0x3F).collect();
        let started = std::time::Instant::now();
        let found = find_images(&data, 0);
        let elapsed = started.elapsed();
        eprintln!("8 MiB searched in {elapsed:?}");
        assert!(elapsed < std::time::Duration::from_secs(30), "{elapsed:?}");
        assert!(found.len() <= MAX_CANDIDATES);
    }

    #[test]
    fn candidates_report_document_offsets() {
        let image = encode(PixelFormat::Rgb8, 200, 120);
        let found = find_images(&embedded(&image, 65_536, 4096), 0x10_0000);
        assert!(found[0].start >= 0x10_0000 + 65_536 - 600, "{}", found[0].description());
        assert_eq!(found[0].width, 200);
    }

    #[test]
    fn widths_follow_from_the_row_length_and_format() {
        assert_eq!(width_for(PixelFormat::Rgb8, 600), Some(200));
        assert_eq!(width_for(PixelFormat::Bit1Msb, 16), Some(128));
        assert_eq!(width_for(PixelFormat::Rgba8, 30), None);
        assert_eq!(width_for(PixelFormat::Gray8, 8), None);
        assert_eq!(width_for(PixelFormat::Gray8, 4096), None);
    }
}
