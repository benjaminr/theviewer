//! Make data speak: plot a byte range as numbers, and play any bytes as audio.
//!
//! The plot window decodes the selection as typed samples and shows a time
//! series, a histogram of values, or an X/Y scatter of interleaved pairs.
//! `pcm_wav` wraps raw bytes in a WAV header so the media player can play
//! them, which often makes structure audible.

use eframe::egui::{self, Context, RichText};
use egui_plot::{Bar, BarChart, Legend, Line, Plot, PlotPoints, Points};

use crate::theme;

/// Most samples drawn; longer ranges are reduced by taking min and max per
/// bucket so spikes stay visible.
const MAX_PLOTTED: usize = 20_000;
/// Buckets in the histogram.
const HISTOGRAM_BINS: usize = 128;

/// How bytes become numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleType {
    U8,
    I8,
    U16Le,
    U16Be,
    I16Le,
    I16Be,
    U32Le,
    U32Be,
    I32Le,
    I32Be,
    F32Le,
    F32Be,
    F64Le,
}

impl SampleType {
    pub const ALL: [SampleType; 13] = [
        SampleType::U8,
        SampleType::I8,
        SampleType::U16Le,
        SampleType::U16Be,
        SampleType::I16Le,
        SampleType::I16Be,
        SampleType::U32Le,
        SampleType::U32Be,
        SampleType::I32Le,
        SampleType::I32Be,
        SampleType::F32Le,
        SampleType::F32Be,
        SampleType::F64Le,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SampleType::U8 => "u8",
            SampleType::I8 => "i8",
            SampleType::U16Le => "u16 LE",
            SampleType::U16Be => "u16 BE",
            SampleType::I16Le => "i16 LE",
            SampleType::I16Be => "i16 BE",
            SampleType::U32Le => "u32 LE",
            SampleType::U32Be => "u32 BE",
            SampleType::I32Le => "i32 LE",
            SampleType::I32Be => "i32 BE",
            SampleType::F32Le => "f32 LE",
            SampleType::F32Be => "f32 BE",
            SampleType::F64Le => "f64 LE",
        }
    }

    pub fn size(self) -> usize {
        match self {
            SampleType::U8 | SampleType::I8 => 1,
            SampleType::U16Le | SampleType::U16Be | SampleType::I16Le | SampleType::I16Be => 2,
            SampleType::U32Le | SampleType::U32Be | SampleType::I32Le | SampleType::I32Be | SampleType::F32Le | SampleType::F32Be => 4,
            SampleType::F64Le => 8,
        }
    }

    fn decode(self, b: &[u8]) -> f64 {
        match self {
            SampleType::U8 => b[0] as f64,
            SampleType::I8 => b[0] as i8 as f64,
            SampleType::U16Le => u16::from_le_bytes([b[0], b[1]]) as f64,
            SampleType::U16Be => u16::from_be_bytes([b[0], b[1]]) as f64,
            SampleType::I16Le => i16::from_le_bytes([b[0], b[1]]) as f64,
            SampleType::I16Be => i16::from_be_bytes([b[0], b[1]]) as f64,
            SampleType::U32Le => u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64,
            SampleType::U32Be => u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64,
            SampleType::I32Le => i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64,
            SampleType::I32Be => i32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64,
            SampleType::F32Le => f32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64,
            SampleType::F32Be => f32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64,
            SampleType::F64Le => f64::from_le_bytes(b[..8].try_into().expect("eight bytes")),
        }
    }
}

/// Decode `bytes` as consecutive samples taken every `stride` bytes (at least
/// the sample size). Non-finite floats are dropped.
pub fn decode_samples(bytes: &[u8], sample: SampleType, stride: usize) -> Vec<f64> {
    let size = sample.size();
    let stride = stride.max(size);
    let mut values = Vec::with_capacity(bytes.len() / stride);
    let mut at = 0;
    while at + size <= bytes.len() {
        let value = sample.decode(&bytes[at..at + size]);
        if value.is_finite() {
            values.push(value);
        }
        at += stride;
    }
    values
}

/// Reduce a long series for drawing: each bucket contributes its minimum and
/// maximum, in order, so peaks survive.
pub fn reduce_for_plot(values: &[f64], max_points: usize) -> Vec<[f64; 2]> {
    if values.len() <= max_points {
        return values.iter().enumerate().map(|(i, &v)| [i as f64, v]).collect();
    }
    let buckets = (max_points / 2).max(1);
    let mut points = Vec::with_capacity(buckets * 2);
    for bucket in 0..buckets {
        let start = bucket * values.len() / buckets;
        let end = ((bucket + 1) * values.len() / buckets).max(start + 1);
        let slice = &values[start..end];
        let (min_index, min) = slice.iter().enumerate().fold((0, f64::MAX), |best, (i, &v)| if v < best.1 { (i, v) } else { best });
        let (max_index, max) = slice.iter().enumerate().fold((0, f64::MIN), |best, (i, &v)| if v > best.1 { (i, v) } else { best });
        let (first, second) = if min_index <= max_index { ((min_index, min), (max_index, max)) } else { ((max_index, max), (min_index, min)) };
        points.push([(start + first.0) as f64, first.1]);
        points.push([(start + second.0) as f64, second.1]);
    }
    points
}

/// Count values into equal-width bins; returns (bin start, width, count).
pub fn histogram(values: &[f64], bins: usize) -> Vec<(f64, f64, usize)> {
    if values.is_empty() || bins == 0 {
        return Vec::new();
    }
    let min = values.iter().copied().fold(f64::MAX, f64::min);
    let max = values.iter().copied().fold(f64::MIN, f64::max);
    let width = ((max - min) / bins as f64).max(f64::EPSILON);
    let mut counts = vec![0usize; bins];
    for &value in values {
        let bin = (((value - min) / width) as usize).min(bins - 1);
        counts[bin] += 1;
    }
    counts.into_iter().enumerate().map(|(i, count)| (min + i as f64 * width, width, count)).collect()
}

/// Summary statistics shown under the plot.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Stats {
    pub count: usize,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub std_dev: f64,
}

pub fn stats(values: &[f64]) -> Stats {
    if values.is_empty() {
        return Stats::default();
    }
    let count = values.len();
    let mean = values.iter().sum::<f64>() / count as f64;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / count as f64;
    Stats {
        count,
        min: values.iter().copied().fold(f64::MAX, f64::min),
        max: values.iter().copied().fold(f64::MIN, f64::max),
        mean,
        std_dev: variance.sqrt(),
    }
}

// ---------------------------------------------------------------------------
// Bytes as audio
// ---------------------------------------------------------------------------

/// How raw bytes are read as audio samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcmFormat {
    U8,
    S16Le,
    S16Be,
    F32Le,
}

impl PcmFormat {
    pub const ALL: [PcmFormat; 4] = [PcmFormat::U8, PcmFormat::S16Le, PcmFormat::S16Be, PcmFormat::F32Le];

    pub fn label(self) -> &'static str {
        match self {
            PcmFormat::U8 => "8-bit unsigned",
            PcmFormat::S16Le => "16-bit LE",
            PcmFormat::S16Be => "16-bit BE",
            PcmFormat::F32Le => "32-bit float",
        }
    }
}

/// Wrap raw bytes in a WAV header. Big-endian 16-bit data is byte-swapped,
/// since WAV is little-endian; a trailing partial sample is dropped.
pub fn pcm_wav(bytes: &[u8], format: PcmFormat, channels: u16, rate: u32) -> Vec<u8> {
    let channels = channels.max(1);
    let (format_tag, bits): (u16, u16) = match format {
        PcmFormat::U8 => (1, 8),
        PcmFormat::S16Le | PcmFormat::S16Be => (1, 16),
        PcmFormat::F32Le => (3, 32),
    };
    let frame = (bits / 8) as usize * channels as usize;
    let usable = bytes.len() / frame * frame;
    let mut data = bytes[..usable].to_vec();
    if format == PcmFormat::S16Be {
        for pair in data.as_chunks_mut::<2>().0 {
            pair.swap(0, 1);
        }
    }
    let mut wav = Vec::with_capacity(44 + data.len());
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&format_tag.to_le_bytes());
    wav.extend_from_slice(&channels.to_le_bytes());
    wav.extend_from_slice(&rate.to_le_bytes());
    wav.extend_from_slice(&(rate * frame as u32).to_le_bytes());
    wav.extend_from_slice(&(frame as u16).to_le_bytes());
    wav.extend_from_slice(&bits.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&(data.len() as u32).to_le_bytes());
    wav.extend_from_slice(&data);
    wav
}

// ---------------------------------------------------------------------------
// The plot window
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlotKind {
    Series,
    Histogram,
    Scatter,
    Spectrum,
}

/// State of the plot window. The app fills `bytes` from the selection.
pub struct PlotWindow {
    pub open: bool,
    pub start: usize,
    pub bytes: Vec<u8>,
    pub sample: SampleType,
    /// Bytes between samples; 0 means the sample size.
    pub stride: usize,
    pub kind: PlotKind,
    /// Set when the user asks to re-read the current selection.
    pub refresh_requested: bool,
}

impl Default for PlotWindow {
    fn default() -> Self {
        PlotWindow {
            open: false,
            start: 0,
            bytes: Vec::new(),
            sample: SampleType::U8,
            stride: 0,
            kind: PlotKind::Series,
            refresh_requested: false,
        }
    }
}

impl PlotWindow {
    pub fn show(&mut self, ctx: &Context) {
        if !self.open {
            return;
        }
        let mut open = true;
        egui::Window::new("Plot")
            .open(&mut open)
            .default_size([640.0, 420.0])
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    egui::ComboBox::from_id_salt("plot-sample")
                        .selected_text(self.sample.label())
                        .show_ui(ui, |ui| {
                            for sample in SampleType::ALL {
                                ui.selectable_value(&mut self.sample, sample, sample.label());
                            }
                        });
                    ui.label("stride");
                    ui.add(egui::DragValue::new(&mut self.stride).range(0..=65_536).suffix(" B"))
                        .on_hover_text("Bytes between samples; 0 packs them. Use the record length to plot one field of every record.");
                    ui.separator();
                    ui.selectable_value(&mut self.kind, PlotKind::Series, "Series");
                    ui.selectable_value(&mut self.kind, PlotKind::Histogram, "Histogram");
                    ui.selectable_value(&mut self.kind, PlotKind::Scatter, "X/Y pairs");
                    ui.selectable_value(&mut self.kind, PlotKind::Spectrum, "Spectrum")
                        .on_hover_text("Frequency content (FFT); periodic structure shows as peaks. Frequency is in cycles per sample.");
                    ui.separator();
                    if ui.button("Use selection").on_hover_text("Re-read the current selection").clicked() {
                        self.refresh_requested = true;
                    }
                });
                let values = decode_samples(&self.bytes, self.sample, self.stride);
                let summary = stats(&values);
                ui.label(
                    RichText::new(format!(
                        "{} bytes from {:#x} · {} samples · min {:.4} · max {:.4} · mean {:.4} · σ {:.4}",
                        self.bytes.len(),
                        self.start,
                        summary.count,
                        summary.min,
                        summary.max,
                        summary.mean,
                        summary.std_dev
                    ))
                    .small()
                    .color(theme::TEXT_DIM),
                );
                let plot = Plot::new("data-plot").legend(Legend::default());
                match self.kind {
                    PlotKind::Series => {
                        let points = reduce_for_plot(&values, MAX_PLOTTED);
                        plot.x_axis_label("sample").show(ui, |plot_ui| {
                            plot_ui.line(Line::new(self.sample.label(), PlotPoints::new(points)).color(theme::ACCENT));
                        });
                    }
                    PlotKind::Histogram => {
                        let bars: Vec<Bar> = histogram(&values, HISTOGRAM_BINS)
                            .into_iter()
                            .map(|(start, width, count)| Bar::new(start + width / 2.0, count as f64).width(width))
                            .collect();
                        plot.x_axis_label("value").y_axis_label("count").show(ui, |plot_ui| {
                            plot_ui.bar_chart(BarChart::new("count", bars).color(theme::ACCENT));
                        });
                    }
                    PlotKind::Spectrum => {
                        let points: Vec<[f64; 2]> = crate::stats::spectrum(&values, 4096).into_iter().map(|(f, db)| [f, db]).collect();
                        plot.x_axis_label("cycles per sample").y_axis_label("dB").show(ui, |plot_ui| {
                            plot_ui.line(Line::new("magnitude", PlotPoints::new(points)).color(theme::ACCENT));
                        });
                    }
                    PlotKind::Scatter => {
                        let pairs: Vec<[f64; 2]> = values.as_chunks::<2>().0.iter().take(MAX_PLOTTED).copied().collect();
                        plot.data_aspect(1.0).show(ui, |plot_ui| {
                            plot_ui.points(Points::new("pairs", PlotPoints::new(pairs)).radius(1.5).color(theme::ACCENT));
                        });
                    }
                }
            });
        self.open = open;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_decode_with_type_endianness_and_stride() {
        let bytes = [1u8, 0, 2, 0, 0xFF, 0xFF];
        assert_eq!(decode_samples(&bytes, SampleType::U16Le, 0), vec![1.0, 2.0, 65535.0]);
        assert_eq!(decode_samples(&bytes, SampleType::I16Le, 0), vec![1.0, 2.0, -1.0]);
        assert_eq!(decode_samples(&bytes, SampleType::U16Be, 0), vec![256.0, 512.0, 65535.0]);
        assert_eq!(decode_samples(&bytes, SampleType::U8, 2), vec![1.0, 2.0, 255.0]);
        let floats: Vec<u8> = [1.5f32, f32::NAN, -2.0].iter().flat_map(|f| f.to_le_bytes()).collect();
        assert_eq!(decode_samples(&floats, SampleType::F32Le, 0), vec![1.5, -2.0], "NaN dropped");
    }

    #[test]
    fn long_series_keep_their_peaks_when_reduced() {
        let mut values = vec![0.0; 100_000];
        values[54_321] = 99.0;
        let points = reduce_for_plot(&values, 1000);
        assert!(points.len() <= 1000);
        assert!(points.iter().any(|p| p[1] == 99.0 && p[0] == 54_321.0));
    }

    #[test]
    fn histogram_and_stats_summarise_values() {
        let values: Vec<f64> = (0..100).map(f64::from).collect();
        let bins = histogram(&values, 10);
        assert_eq!(bins.len(), 10);
        assert!(bins.iter().all(|&(_, _, count)| count == 10));
        let summary = stats(&values);
        assert_eq!((summary.count, summary.min, summary.max), (100, 0.0, 99.0));
        assert!((summary.mean - 49.5).abs() < 1e-9);
    }

    #[test]
    fn pcm_bytes_become_a_playable_wav() {
        let raw = [0x01u8, 0x02, 0x03, 0x04, 0x05];
        let wav = pcm_wav(&raw, PcmFormat::S16Be, 1, 8000);
        assert_eq!(crate::media::detect(&wav).map(|f| f.name), Some("WAV"));
        assert_eq!(&wav[44..], &[0x02, 0x01, 0x04, 0x03], "byte-swapped, partial sample dropped");
        let info = crate::media::analyse_audio(pcm_wav(&vec![128u8; 8000], PcmFormat::U8, 1, 8000), 10).unwrap();
        assert!((info.duration.as_secs_f64() - 1.0).abs() < 0.01);
    }
}
