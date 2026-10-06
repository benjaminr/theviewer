//! Turns raw bytes into RGBA pixels according to a chosen pixel format.
//!
//! The rasteriser is deliberately simple: it maps a flat byte window onto a
//! `width × rows` grid, one row after another. Everything about *which* bytes
//! land in the window (offset, stride, bit shift) is decided by the caller.

use std::sync::OnceLock;

use eframe::egui::Color32;
use rayon::prelude::*;

use crate::theme;

/// Colour ramp applied to single-channel formats (1-bit, 4-bit, 8-bit,
/// 16-bit grey and the unsigned numeric heatmaps).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Palette {
    Grey,
    Viridis,
    Inferno,
    Ocean,
    Amber,
    /// Blue through white to red, with white in the middle: the map signed
    /// heatmaps always use, so zero is neutral.
    Diverging,
}

impl Palette {
    pub const ALL: [Palette; 6] =
        [Palette::Grey, Palette::Viridis, Palette::Inferno, Palette::Ocean, Palette::Amber, Palette::Diverging];

    pub fn label(self) -> &'static str {
        match self {
            Palette::Grey => "Grey",
            Palette::Viridis => "Viridis",
            Palette::Inferno => "Inferno",
            Palette::Ocean => "Ocean",
            Palette::Amber => "Amber",
            Palette::Diverging => "Diverging",
        }
    }

    pub fn from_name(name: &str) -> Option<Palette> {
        Palette::ALL.into_iter().find(|palette| palette.label().eq_ignore_ascii_case(name))
    }

    fn control_points(self) -> &'static [[u8; 3]] {
        match self {
            Palette::Grey => &[[0, 0, 0], [255, 255, 255]],
            Palette::Viridis => &[
                [68, 1, 84], [72, 40, 120], [62, 74, 137], [49, 104, 142], [38, 130, 142],
                [31, 158, 137], [53, 183, 121], [109, 205, 89], [180, 222, 44], [253, 231, 37],
            ],
            Palette::Inferno => &[
                [0, 0, 4], [31, 12, 72], [85, 15, 109], [136, 34, 106], [186, 54, 85],
                [227, 89, 51], [249, 140, 10], [249, 201, 50], [252, 255, 164],
            ],
            Palette::Ocean => &[[6, 8, 24], [18, 44, 96], [28, 96, 150], [60, 160, 196], [150, 222, 240], [240, 252, 255]],
            Palette::Amber => &[[12, 8, 2], [96, 40, 6], [190, 96, 16], [245, 168, 48], [255, 228, 160], [255, 255, 240]],
            Palette::Diverging => &[
                [33, 102, 172], [103, 169, 207], [209, 229, 240], [247, 247, 247],
                [253, 219, 199], [239, 138, 98], [178, 24, 43],
            ],
        }
    }

    /// 256-entry lookup table, built once per palette.
    pub fn lut(self) -> &'static [Color32; 256] {
        static TABLES: OnceLock<Vec<[Color32; 256]>> = OnceLock::new();
        let tables = TABLES.get_or_init(|| Palette::ALL.iter().map(|palette| palette.build_lut()).collect());
        let index = Palette::ALL.iter().position(|&palette| palette == self).unwrap_or(0);
        &tables[index]
    }

    fn build_lut(self) -> [Color32; 256] {
        let points = self.control_points();
        let segments = (points.len() - 1) as f32;
        let mut table = [Color32::BLACK; 256];
        for (value, slot) in table.iter_mut().enumerate() {
            let position = value as f32 / 255.0 * segments;
            let index = (position.floor() as usize).min(points.len() - 2);
            let t = position - index as f32;
            let a = points[index];
            let b = points[index + 1];
            let mix = |channel: usize| (a[channel] as f32 + (b[channel] as f32 - a[channel] as f32) * t).round() as u8;
            *slot = Color32::from_rgb(mix(0), mix(1), mix(2));
        }
        table
    }
}

/// How bytes are interpreted as pixels. In JSON it is the short name the
/// command line takes, such as "gray8" or "rgb565".
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PixelFormat {
    /// One bit per pixel, most significant bit first.
    #[serde(rename = "bit1")]
    Bit1Msb,
    /// One bit per pixel, least significant bit first.
    Bit1Lsb,
    /// Four bits per pixel, greyscale.
    Nibble4,
    /// One byte per pixel, greyscale.
    Gray8,
    /// One byte per pixel, coloured by byte class (null / ascii / control / high).
    #[serde(rename = "class")]
    ByteClass,
    /// Two bytes per pixel, 5-6-5 little endian.
    Rgb565,
    /// Two bytes per pixel, little endian greyscale.
    Gray16Le,
    /// Two bytes per pixel, big endian greyscale.
    Gray16Be,
    /// Three bytes per pixel, red first.
    Rgb8,
    /// Three bytes per pixel, blue first.
    Bgr8,
    /// Four bytes per pixel, red first, alpha ignored.
    Rgba8,
    /// Four bytes per pixel, blue first, alpha ignored.
    Bgra8,
    /// Unsigned 16-bit numbers, little endian, as a heatmap.
    U16Le,
    /// Unsigned 16-bit numbers, big endian, as a heatmap.
    U16Be,
    /// Signed 16-bit numbers, little endian, as a heatmap centred on zero.
    I16Le,
    /// Signed 16-bit numbers, big endian, as a heatmap centred on zero.
    I16Be,
    /// Unsigned 32-bit numbers, little endian, as a heatmap.
    U32Le,
    /// Unsigned 32-bit numbers, big endian, as a heatmap.
    U32Be,
    /// Signed 32-bit numbers, little endian, as a heatmap centred on zero.
    I32Le,
    /// Signed 32-bit numbers, big endian, as a heatmap centred on zero.
    I32Be,
    /// 32-bit floats, little endian, as a heatmap centred on zero.
    F32Le,
    /// 32-bit floats, big endian, as a heatmap centred on zero.
    F32Be,
}

impl PixelFormat {
    pub const ALL: [PixelFormat; 22] = [
        PixelFormat::Bit1Msb,
        PixelFormat::Bit1Lsb,
        PixelFormat::Nibble4,
        PixelFormat::Gray8,
        PixelFormat::ByteClass,
        PixelFormat::Rgb565,
        PixelFormat::Gray16Le,
        PixelFormat::Gray16Be,
        PixelFormat::Rgb8,
        PixelFormat::Bgr8,
        PixelFormat::Rgba8,
        PixelFormat::Bgra8,
        PixelFormat::U16Le,
        PixelFormat::U16Be,
        PixelFormat::I16Le,
        PixelFormat::I16Be,
        PixelFormat::U32Le,
        PixelFormat::U32Be,
        PixelFormat::I32Le,
        PixelFormat::I32Be,
        PixelFormat::F32Le,
        PixelFormat::F32Be,
    ];

    pub fn label(self) -> &'static str {
        match self {
            PixelFormat::Bit1Msb => "1-bit (MSB first)",
            PixelFormat::Bit1Lsb => "1-bit (LSB first)",
            PixelFormat::Nibble4 => "4-bit grey",
            PixelFormat::Gray8 => "8-bit grey",
            PixelFormat::ByteClass => "Byte class",
            PixelFormat::Rgb565 => "RGB565",
            PixelFormat::Gray16Le => "16-bit grey LE",
            PixelFormat::Gray16Be => "16-bit grey BE",
            PixelFormat::Rgb8 => "RGB 24-bit",
            PixelFormat::Bgr8 => "BGR 24-bit",
            PixelFormat::Rgba8 => "RGBA 32-bit",
            PixelFormat::Bgra8 => "BGRA 32-bit",
            PixelFormat::U16Le => "u16 LE heatmap",
            PixelFormat::U16Be => "u16 BE heatmap",
            PixelFormat::I16Le => "i16 LE heatmap",
            PixelFormat::I16Be => "i16 BE heatmap",
            PixelFormat::U32Le => "u32 LE heatmap",
            PixelFormat::U32Be => "u32 BE heatmap",
            PixelFormat::I32Le => "i32 LE heatmap",
            PixelFormat::I32Be => "i32 BE heatmap",
            PixelFormat::F32Le => "f32 LE heatmap",
            PixelFormat::F32Be => "f32 BE heatmap",
        }
    }

    /// Short name accepted on the command line.
    pub fn short_name(self) -> &'static str {
        match self {
            PixelFormat::Bit1Msb => "bit1",
            PixelFormat::Bit1Lsb => "bit1lsb",
            PixelFormat::Nibble4 => "nibble4",
            PixelFormat::Gray8 => "gray8",
            PixelFormat::ByteClass => "class",
            PixelFormat::Rgb565 => "rgb565",
            PixelFormat::Gray16Le => "gray16le",
            PixelFormat::Gray16Be => "gray16be",
            PixelFormat::Rgb8 => "rgb8",
            PixelFormat::Bgr8 => "bgr8",
            PixelFormat::Rgba8 => "rgba8",
            PixelFormat::Bgra8 => "bgra8",
            PixelFormat::U16Le => "u16le",
            PixelFormat::U16Be => "u16be",
            PixelFormat::I16Le => "i16le",
            PixelFormat::I16Be => "i16be",
            PixelFormat::U32Le => "u32le",
            PixelFormat::U32Be => "u32be",
            PixelFormat::I32Le => "i32le",
            PixelFormat::I32Be => "i32be",
            PixelFormat::F32Le => "f32le",
            PixelFormat::F32Be => "f32be",
        }
    }

    pub fn from_short_name(name: &str) -> Option<PixelFormat> {
        let name = name.to_ascii_lowercase();
        PixelFormat::ALL.into_iter().find(|format| format.short_name() == name)
    }

    pub fn bits_per_pixel(self) -> usize {
        match self {
            PixelFormat::Bit1Msb | PixelFormat::Bit1Lsb => 1,
            PixelFormat::Nibble4 => 4,
            PixelFormat::Gray8 | PixelFormat::ByteClass => 8,
            PixelFormat::Rgb565
            | PixelFormat::Gray16Le
            | PixelFormat::Gray16Be
            | PixelFormat::U16Le
            | PixelFormat::U16Be
            | PixelFormat::I16Le
            | PixelFormat::I16Be => 16,
            PixelFormat::Rgb8 | PixelFormat::Bgr8 => 24,
            PixelFormat::Rgba8
            | PixelFormat::Bgra8
            | PixelFormat::U32Le
            | PixelFormat::U32Be
            | PixelFormat::I32Le
            | PixelFormat::I32Be
            | PixelFormat::F32Le
            | PixelFormat::F32Be => 32,
        }
    }

    /// Number of bytes a run of `pixels` pixels occupies, rounded up.
    pub fn bytes_for_pixels(self, pixels: usize) -> usize {
        (pixels * self.bits_per_pixel()).div_ceil(8)
    }

    /// Whole bytes per pixel, or zero for sub-byte formats.
    pub fn bytes_per_pixel(self) -> usize {
        self.bits_per_pixel() / 8
    }

    /// Whether pixels are numbers drawn as a heatmap over an automatic range.
    pub fn is_numeric(self) -> bool {
        self.numeric_type().is_some()
    }

    /// Whether the numbers can be negative, so the heatmap is centred on zero.
    pub fn is_signed(self) -> bool {
        self.numeric_type().is_some_and(|(kind, _)| kind != NumberKind::Unsigned)
    }

    /// Whether the selected palette colours this format. Signed heatmaps
    /// always use the diverging map, and colour formats carry their own.
    pub fn uses_palette(self) -> bool {
        match self {
            PixelFormat::Bit1Msb
            | PixelFormat::Bit1Lsb
            | PixelFormat::Nibble4
            | PixelFormat::Gray8
            | PixelFormat::Gray16Le
            | PixelFormat::Gray16Be => true,
            _ => self.is_numeric() && !self.is_signed(),
        }
    }

    fn numeric_type(self) -> Option<(NumberKind, Endian)> {
        match self {
            PixelFormat::U16Le | PixelFormat::U32Le => Some((NumberKind::Unsigned, Endian::Little)),
            PixelFormat::U16Be | PixelFormat::U32Be => Some((NumberKind::Unsigned, Endian::Big)),
            PixelFormat::I16Le | PixelFormat::I32Le => Some((NumberKind::Signed, Endian::Little)),
            PixelFormat::I16Be | PixelFormat::I32Be => Some((NumberKind::Signed, Endian::Big)),
            PixelFormat::F32Le => Some((NumberKind::Float, Endian::Little)),
            PixelFormat::F32Be => Some((NumberKind::Float, Endian::Big)),
            _ => None,
        }
    }

    /// The number one pixel's bytes hold, for the numeric heatmap formats.
    /// `None` for other formats, for too few bytes, and for NaN or infinite
    /// floats.
    pub fn decode_value(self, bytes: &[u8]) -> Option<f64> {
        let (kind, endian) = self.numeric_type()?;
        let value = match (self.bits_per_pixel(), kind) {
            (16, NumberKind::Unsigned) => f64::from(u16::from_ne_bytes(endian.order(bytes.first_chunk::<2>()?))),
            (16, _) => f64::from(i16::from_ne_bytes(endian.order(bytes.first_chunk::<2>()?))),
            (_, NumberKind::Unsigned) => f64::from(u32::from_ne_bytes(endian.order(bytes.first_chunk::<4>()?))),
            (_, NumberKind::Signed) => f64::from(i32::from_ne_bytes(endian.order(bytes.first_chunk::<4>()?))),
            (_, NumberKind::Float) => f64::from(f32::from_ne_bytes(endian.order(bytes.first_chunk::<4>()?))),
        };
        value.is_finite().then_some(value)
    }
}

/// How a numeric heatmap format reads its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NumberKind {
    Unsigned,
    Signed,
    Float,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    /// The bytes rearranged into this machine's order.
    fn order<const N: usize>(self, bytes: &[u8; N]) -> [u8; N] {
        let mut ordered = *bytes;
        let stored_little = self == Endian::Little;
        if stored_little != cfg!(target_endian = "little") {
            ordered.reverse();
        }
        ordered
    }
}

/// Values a numeric heatmap spreads across its palette: everything at or
/// below `low` gets the first colour and at or above `high` the last.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ValueRange {
    pub low: f64,
    pub high: f64,
}

impl ValueRange {
    /// Position of `value` along the range, from 0 to 1.
    fn fraction(self, value: f64) -> f64 {
        ((value - self.low) / (self.high - self.low)).clamp(0.0, 1.0)
    }
}

/// Values sampled at most when working out a heatmap's range, so very wide
/// windows stay quick.
const RANGE_SAMPLE_LIMIT: usize = 1 << 16;
/// Share of the values at each end left out of the automatic range, so a
/// few outliers do not wash the rest of the picture out.
const RANGE_OUTLIER_FRACTION: f64 = 0.01;
/// Colour of NaN and infinite floats.
pub const NOT_A_NUMBER_COLOUR: Color32 = Color32::from_rgb(255, 0, 200);

/// The automatic range for the numeric pixels of `rows` rows of `width`
/// pixels in `src` (rows `row_stride` bytes apart): the 1st to 99th
/// percentile of the finite values, ignoring NaN and infinities. Signed
/// formats get a range symmetric about zero, so zero sits in the middle of
/// the diverging map. `None` for other formats.
pub fn numeric_range(format: PixelFormat, src: &[u8], width: usize, rows: usize, row_stride: usize) -> Option<ValueRange> {
    if !format.is_numeric() {
        return None;
    }
    let pixel_bytes = format.bytes_per_pixel();
    let total = width * rows;
    let step = total.div_ceil(RANGE_SAMPLE_LIMIT).max(1);
    let mut values: Vec<f64> = (0..total)
        .step_by(step)
        .filter_map(|index| {
            let at = (index / width.max(1)) * row_stride + (index % width.max(1)) * pixel_bytes;
            format.decode_value(src.get(at..at + pixel_bytes)?)
        })
        .collect();
    Some(range_of_values(&mut values, format.is_signed()))
}

/// The 1st to 99th percentile of `values` (reordered in place), widened to
/// a symmetric range about zero when `signed`, and never empty.
pub fn range_of_values(values: &mut [f64], signed: bool) -> ValueRange {
    if values.is_empty() {
        return if signed { ValueRange { low: -1.0, high: 1.0 } } else { ValueRange { low: 0.0, high: 1.0 } };
    }
    let last = values.len() - 1;
    let skipped = (last as f64 * RANGE_OUTLIER_FRACTION).round() as usize;
    let low = *values.select_nth_unstable_by(skipped, f64::total_cmp).1;
    let high = *values.select_nth_unstable_by(last - skipped, f64::total_cmp).1;
    if signed {
        let bound = low.abs().max(high.abs());
        let bound = if bound > 0.0 { bound } else { 1.0 };
        return ValueRange { low: -bound, high: bound };
    }
    if high > low { ValueRange { low, high } } else { ValueRange { low, high: low + 1.0 } }
}

/// Everything about how bytes become colours, apart from the bytes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RasterStyle {
    pub format: PixelFormat,
    pub palette: Palette,
    /// Range for the numeric heatmaps; `None` works it out from the bytes.
    pub range: Option<ValueRange>,
}

/// A transform applied to the bytes of each row before they become pixels,
/// so the picture shows how every row differs from the one above it.
/// Constant fields of fixed-size records turn to zero (dark) and the fields
/// that change stand out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RowDifference {
    /// Bytes are shown as they are.
    #[default]
    None,
    /// Each byte is XORed with the byte one row above.
    Xor,
    /// The byte one row above is subtracted, wrapping, so an unchanged byte
    /// becomes zero, a small rise a small value and a small fall a value
    /// just below 0x100.
    Subtract,
}

impl RowDifference {
    pub const ALL: [RowDifference; 3] = [RowDifference::None, RowDifference::Xor, RowDifference::Subtract];

    pub fn label(self) -> &'static str {
        match self {
            RowDifference::None => "Rows as they are",
            RowDifference::Xor => "XOR with the row above",
            RowDifference::Subtract => "Subtract the row above",
        }
    }

    /// Compact label for the toolbar.
    pub fn short_label(self) -> &'static str {
        match self {
            RowDifference::None => "Δ off",
            RowDifference::Xor => "Δ XOR",
            RowDifference::Subtract => "Δ −",
        }
    }

    /// The mode after this one, wrapping round, for a single command.
    pub fn next(self) -> RowDifference {
        match self {
            RowDifference::None => RowDifference::Xor,
            RowDifference::Xor => RowDifference::Subtract,
            RowDifference::Subtract => RowDifference::None,
        }
    }

    pub fn is_active(self) -> bool {
        self != RowDifference::None
    }

    fn combine(self, current: u8, above: u8) -> u8 {
        match self {
            RowDifference::None => current,
            RowDifference::Xor => current ^ above,
            RowDifference::Subtract => current.wrapping_sub(above),
        }
    }
}

/// Replace every row of `buffer` after the first with its difference from
/// the row above, byte by byte. Rows are `row_stride` bytes apart; the first
/// row only serves as the reference for the second, and any bytes after the
/// last whole row are left alone.
pub fn difference_rows(mode: RowDifference, buffer: &mut [u8], row_stride: usize) {
    if !mode.is_active() || row_stride == 0 {
        return;
    }
    let rows = buffer.len() / row_stride;
    // Bottom up, so every row is compared with the original row above it.
    for row in (1..rows).rev() {
        let (before, from_row) = buffer.split_at_mut(row * row_stride);
        let above = &before[(row - 1) * row_stride..];
        for (current, &previous) in from_row[..row_stride].iter_mut().zip(above) {
            *current = mode.combine(*current, previous);
        }
    }
}

/// Rasterise `rows` rows of `width` pixels from `src` into `out`.
///
/// Consecutive rows start `row_stride` bytes apart, which must be at least the
/// number of bytes a row of pixels occupies. `src` must hold at least
/// `row_stride * rows` bytes (callers zero-pad) and `out` exactly
/// `width * rows` pixels.
pub fn rasterise(
    format: PixelFormat,
    palette: Palette,
    src: &[u8],
    width: usize,
    rows: usize,
    row_stride: usize,
    out: &mut [Color32],
) {
    rasterise_styled(RasterStyle { format, palette, range: None }, src, width, rows, row_stride, out);
}

/// [`rasterise`] with a fixed heatmap range, so a part of the window can be
/// redrawn in exactly the colours the whole window got.
pub fn rasterise_styled(style: RasterStyle, src: &[u8], width: usize, rows: usize, row_stride: usize, out: &mut [Color32]) {
    debug_assert_eq!(out.len(), width * rows);
    if width == 0 || rows == 0 {
        return;
    }
    let format = style.format;
    let row_bytes = format.bytes_for_pixels(width);
    debug_assert!(row_stride >= row_bytes);
    debug_assert!(src.len() >= row_stride * rows);

    const PARALLEL_THRESHOLD: usize = 1 << 18;
    let palette = if format.is_signed() { Palette::Diverging } else { style.palette };
    let lut = palette.lut();
    let range = style.range.or_else(|| numeric_range(format, src, width, rows, row_stride));
    let render_row = |row_src: &[u8], row_out: &mut [Color32]| match range {
        Some(range) if format.is_numeric() => rasterise_numeric_row(format, lut, range, row_src, row_out),
        _ => rasterise_row(format, lut, row_src, row_out),
    };

    if width * rows >= PARALLEL_THRESHOLD {
        out.par_chunks_mut(width)
            .zip(src.par_chunks(row_stride))
            .for_each(|(row_out, row_src)| render_row(row_src, row_out));
    } else {
        out.chunks_mut(width)
            .zip(src.chunks(row_stride))
            .for_each(|(row_out, row_src)| render_row(row_src, row_out));
    }
}

fn rasterise_row(format: PixelFormat, lut: &[Color32; 256], src: &[u8], out: &mut [Color32]) {
    let (off, on) = (lut[0], lut[255]);
    match format {
        PixelFormat::Bit1Msb => {
            for (index, pixel) in out.iter_mut().enumerate() {
                let bit = (src[index >> 3] >> (7 - (index & 7))) & 1;
                *pixel = if bit == 1 { on } else { off };
            }
        }
        PixelFormat::Bit1Lsb => {
            for (index, pixel) in out.iter_mut().enumerate() {
                let bit = (src[index >> 3] >> (index & 7)) & 1;
                *pixel = if bit == 1 { on } else { off };
            }
        }
        PixelFormat::Nibble4 => {
            for (index, pixel) in out.iter_mut().enumerate() {
                let byte = src[index >> 1];
                let nibble = if index & 1 == 0 { byte >> 4 } else { byte & 0x0F };
                *pixel = lut[(nibble * 17) as usize];
            }
        }
        PixelFormat::Gray8 => {
            for (pixel, &byte) in out.iter_mut().zip(src) {
                *pixel = lut[byte as usize];
            }
        }
        PixelFormat::ByteClass => {
            for (pixel, &byte) in out.iter_mut().zip(src) {
                *pixel = byte_class_colour(byte);
            }
        }
        PixelFormat::Rgb565 => {
            for (pixel, chunk) in out.iter_mut().zip(src.as_chunks::<2>().0) {
                let value = u16::from_le_bytes([chunk[0], chunk[1]]);
                let red = ((value >> 11) & 0x1F) as u8;
                let green = ((value >> 5) & 0x3F) as u8;
                let blue = (value & 0x1F) as u8;
                *pixel = Color32::from_rgb(
                    (red << 3) | (red >> 2),
                    (green << 2) | (green >> 4),
                    (blue << 3) | (blue >> 2),
                );
            }
        }
        PixelFormat::Gray16Le => {
            for (pixel, chunk) in out.iter_mut().zip(src.as_chunks::<2>().0) {
                *pixel = lut[chunk[1] as usize];
            }
        }
        PixelFormat::Gray16Be => {
            for (pixel, chunk) in out.iter_mut().zip(src.as_chunks::<2>().0) {
                *pixel = lut[chunk[0] as usize];
            }
        }
        PixelFormat::Rgb8 => {
            for (pixel, chunk) in out.iter_mut().zip(src.as_chunks::<3>().0) {
                *pixel = Color32::from_rgb(chunk[0], chunk[1], chunk[2]);
            }
        }
        PixelFormat::Bgr8 => {
            for (pixel, chunk) in out.iter_mut().zip(src.as_chunks::<3>().0) {
                *pixel = Color32::from_rgb(chunk[2], chunk[1], chunk[0]);
            }
        }
        PixelFormat::Rgba8 => {
            for (pixel, chunk) in out.iter_mut().zip(src.as_chunks::<4>().0) {
                *pixel = Color32::from_rgb(chunk[0], chunk[1], chunk[2]);
            }
        }
        PixelFormat::Bgra8 => {
            for (pixel, chunk) in out.iter_mut().zip(src.as_chunks::<4>().0) {
                *pixel = Color32::from_rgb(chunk[2], chunk[1], chunk[0]);
            }
        }
        // Heatmaps go through `rasterise_numeric_row` once their range is known.
        PixelFormat::U16Le
        | PixelFormat::U16Be
        | PixelFormat::I16Le
        | PixelFormat::I16Be
        | PixelFormat::U32Le
        | PixelFormat::U32Be
        | PixelFormat::I32Le
        | PixelFormat::I32Be
        | PixelFormat::F32Le
        | PixelFormat::F32Be => {
            let range = range_of_values(&mut [], format.is_signed());
            rasterise_numeric_row(format, lut, range, src, out);
        }
    }
}

/// Colour each number in a row by where it falls in `range`.
fn rasterise_numeric_row(format: PixelFormat, lut: &[Color32; 256], range: ValueRange, src: &[u8], out: &mut [Color32]) {
    let last_entry = (lut.len() - 1) as f64;
    for (pixel, bytes) in out.iter_mut().zip(src.chunks_exact(format.bytes_per_pixel())) {
        *pixel = match format.decode_value(bytes) {
            Some(value) => lut[(range.fraction(value) * last_entry).round() as usize],
            None => NOT_A_NUMBER_COLOUR,
        };
    }
}

/// Colour a byte by what kind of data it most likely is. This is the classic
/// "binvis" palette: it makes text, padding, and machine code visually distinct.
pub fn byte_class_colour(byte: u8) -> Color32 {
    match byte {
        0x00 => theme::CLASS_NULL,
        0xFF => theme::CLASS_FULL,
        0x20..=0x7E => theme::CLASS_TEXT,
        0x01..=0x1F | 0x7F => theme::CLASS_CONTROL,
        _ => theme::CLASS_HIGH,
    }
}

/// Shift the whole buffer left by `bits` (0..8) bits, pulling in bits from the
/// following byte. The last byte is padded with zeros.
pub fn shift_left_bits(buffer: &mut [u8], bits: u32) {
    if bits == 0 || buffer.is_empty() {
        return;
    }
    debug_assert!(bits < 8);
    let last = buffer.len() - 1;
    for index in 0..last {
        buffer[index] = (buffer[index] << bits) | (buffer[index + 1] >> (8 - bits));
    }
    buffer[last] <<= bits;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pixel_format_is_written_in_json_as_its_command_line_name() {
        for format in PixelFormat::ALL {
            let json = serde_json::to_value(format).unwrap();
            assert_eq!(json, format.short_name(), "{format:?}");
            assert_eq!(serde_json::from_value::<PixelFormat>(json).unwrap(), format);
        }
    }

    #[test]
    fn one_bit_msb_maps_each_bit_to_black_or_white() {
        let src = [0b1010_0000u8];
        let mut out = vec![Color32::TRANSPARENT; 4];
        rasterise(PixelFormat::Bit1Msb, Palette::Grey, &src, 4, 1, PixelFormat::Bit1Msb.bytes_for_pixels(4), &mut out);
        assert_eq!(out, [Color32::WHITE, Color32::BLACK, Color32::WHITE, Color32::BLACK]);
    }

    #[test]
    fn one_bit_lsb_reads_bits_from_the_low_end() {
        let src = [0b0000_0101u8];
        let mut out = vec![Color32::TRANSPARENT; 4];
        rasterise(PixelFormat::Bit1Lsb, Palette::Grey, &src, 4, 1, PixelFormat::Bit1Lsb.bytes_for_pixels(4), &mut out);
        assert_eq!(out, [Color32::WHITE, Color32::BLACK, Color32::WHITE, Color32::BLACK]);
    }

    #[test]
    fn rgb_rows_are_laid_out_row_major() {
        let src = [255, 0, 0, 0, 255, 0, 0, 0, 255, 9, 9, 9];
        let mut out = vec![Color32::TRANSPARENT; 4];
        rasterise(PixelFormat::Rgb8, Palette::Grey, &src, 2, 2, PixelFormat::Rgb8.bytes_for_pixels(2), &mut out);
        assert_eq!(out[0], Color32::from_rgb(255, 0, 0));
        assert_eq!(out[1], Color32::from_rgb(0, 255, 0));
        assert_eq!(out[2], Color32::from_rgb(0, 0, 255));
        assert_eq!(out[3], Color32::from_rgb(9, 9, 9));
    }

    #[test]
    fn row_stride_skips_padding_bytes_between_rows() {
        let src = [10, 20, 99, 30, 40, 99];
        let mut out = vec![Color32::TRANSPARENT; 4];
        rasterise(PixelFormat::Gray8, Palette::Grey, &src, 2, 2, 3, &mut out);
        assert_eq!(out, [Color32::from_gray(10), Color32::from_gray(20), Color32::from_gray(30), Color32::from_gray(40)]);
    }

    #[test]
    fn bytes_for_pixels_rounds_sub_byte_formats_up() {
        assert_eq!(PixelFormat::Bit1Msb.bytes_for_pixels(9), 2);
        assert_eq!(PixelFormat::Nibble4.bytes_for_pixels(3), 2);
        assert_eq!(PixelFormat::Rgb8.bytes_for_pixels(3), 9);
    }

    #[test]
    fn bit_shift_pulls_bits_across_byte_boundaries() {
        let mut buffer = [0b0000_0001u8, 0b1000_0000];
        shift_left_bits(&mut buffer, 1);
        assert_eq!(buffer, [0b0000_0011, 0b0000_0000]);
    }

    #[test]
    fn palettes_span_their_full_range() {
        for palette in Palette::ALL {
            let lut = palette.lut();
            let first = palette.control_points()[0];
            let last = *palette.control_points().last().unwrap();
            assert_eq!(lut[0], Color32::from_rgb(first[0], first[1], first[2]));
            assert_eq!(lut[255], Color32::from_rgb(last[0], last[1], last[2]));
        }
    }

    #[test]
    fn rgb565_expands_to_full_range() {
        let src = 0xFFFFu16.to_le_bytes();
        let mut out = vec![Color32::TRANSPARENT; 1];
        rasterise(PixelFormat::Rgb565, Palette::Grey, &src, 1, 1, PixelFormat::Rgb565.bytes_for_pixels(1), &mut out);
        assert_eq!(out[0], Color32::from_rgb(255, 255, 255));
    }

    #[test]
    fn xor_row_difference_turns_repeated_fields_to_zero() {
        let mut buffer = [0xAA, 0x01, 0xAA, 0x02, 0xAA, 0x04];
        difference_rows(RowDifference::Xor, &mut buffer, 2);
        assert_eq!(buffer, [0xAA, 0x01, 0x00, 0x03, 0x00, 0x06]);
    }

    #[test]
    fn subtract_row_difference_wraps_so_unchanged_bytes_are_zero() {
        let mut buffer = [10, 200, 11, 200, 10, 201, 99];
        difference_rows(RowDifference::Subtract, &mut buffer, 2);
        assert_eq!(buffer, [10, 200, 1, 0, 255, 1, 99], "the trailing partial row is untouched");
    }

    #[test]
    fn rows_as_they_are_leave_bytes_alone_and_modes_cycle() {
        let mut buffer = [1, 2, 3, 4];
        difference_rows(RowDifference::None, &mut buffer, 2);
        assert_eq!(buffer, [1, 2, 3, 4]);
        assert_eq!(RowDifference::None.next().next().next(), RowDifference::None);
    }

    #[test]
    fn numeric_formats_decode_both_byte_orders() {
        assert_eq!(PixelFormat::U16Le.decode_value(&[0x34, 0x12]), Some(f64::from(0x1234u16)));
        assert_eq!(PixelFormat::U16Be.decode_value(&[0x12, 0x34]), Some(f64::from(0x1234u16)));
        assert_eq!(PixelFormat::I16Le.decode_value(&[0xFE, 0xFF]), Some(-2.0));
        assert_eq!(PixelFormat::I16Be.decode_value(&[0xFF, 0xFE]), Some(-2.0));
        assert_eq!(PixelFormat::U32Be.decode_value(&[0, 1, 0, 0]), Some(65536.0));
        assert_eq!(PixelFormat::I32Le.decode_value(&(-70_000i32).to_le_bytes()), Some(-70_000.0));
        assert_eq!(PixelFormat::F32Be.decode_value(&1.5f32.to_be_bytes()), Some(1.5));
        assert_eq!(PixelFormat::F32Le.decode_value(&f32::NAN.to_le_bytes()), None, "NaN has no place on the map");
        assert_eq!(PixelFormat::F32Le.decode_value(&f32::INFINITY.to_le_bytes()), None);
        assert_eq!(PixelFormat::Gray8.decode_value(&[1]), None);
        assert_eq!(PixelFormat::U32Le.decode_value(&[1, 2]), None, "too few bytes");
    }

    #[test]
    fn numeric_formats_have_short_names_and_sizes() {
        for format in PixelFormat::ALL.into_iter().filter(|format| format.is_numeric()) {
            assert_eq!(PixelFormat::from_short_name(format.short_name()), Some(format));
            assert!(matches!(format.bits_per_pixel(), 16 | 32));
        }
        assert_eq!(PixelFormat::from_short_name("F32BE"), Some(PixelFormat::F32Be));
        assert!(PixelFormat::I16Le.is_signed() && PixelFormat::F32Le.is_signed() && !PixelFormat::U32Le.is_signed());
    }

    #[test]
    fn automatic_range_ignores_outliers_and_non_finite_values() {
        let mut values: Vec<f32> = (0..1000).map(|i| i as f32).collect();
        values[0] = -1.0e30;
        values[999] = f32::NAN;
        values[500] = f32::INFINITY;
        let src: Vec<u8> = values.iter().flat_map(|value| value.to_le_bytes()).collect();
        let range = numeric_range(PixelFormat::F32Le, &src, 100, 10, 400).unwrap();
        assert!(range.low < 0.0 && range.low == -range.high, "signed ranges are symmetric: {range:?}");
        assert!((980.0..=990.0).contains(&range.high), "the 99th percentile, not the outlier: {range:?}");

        let unsigned: Vec<u8> = (0..200u16).flat_map(|value| value.to_le_bytes()).collect();
        let range = numeric_range(PixelFormat::U16Le, &unsigned, 200, 1, 400).unwrap();
        assert_eq!(range, ValueRange { low: 2.0, high: 197.0 });
        assert_eq!(numeric_range(PixelFormat::Gray8, &unsigned, 200, 1, 400), None);
    }

    #[test]
    fn a_flat_or_empty_window_still_gets_a_usable_range() {
        assert_eq!(range_of_values(&mut [5.0, 5.0], false), ValueRange { low: 5.0, high: 6.0 });
        assert_eq!(range_of_values(&mut [0.0], true), ValueRange { low: -1.0, high: 1.0 });
        assert_eq!(range_of_values(&mut [], false), ValueRange { low: 0.0, high: 1.0 });
    }

    #[test]
    fn signed_heatmaps_put_zero_at_the_white_centre_of_the_diverging_map() {
        let src: Vec<u8> = [-100i16, 0, 100].iter().flat_map(|value| value.to_le_bytes()).collect();
        let mut out = vec![Color32::TRANSPARENT; 3];
        rasterise(PixelFormat::I16Le, Palette::Grey, &src, 3, 1, 6, &mut out);
        let lut = Palette::Diverging.lut();
        assert_eq!(out, [lut[0], lut[128], lut[255]]);
        let centre = out[1];
        assert!(centre.r() > 230 && centre.g() > 230 && centre.b() > 230, "zero is near white: {centre:?}");

        let fixed = RasterStyle { format: PixelFormat::U16Le, palette: Palette::Grey, range: Some(ValueRange { low: 0.0, high: 200.0 }) };
        let src: Vec<u8> = [0u16, 100, 400].iter().flat_map(|value| value.to_le_bytes()).collect();
        rasterise_styled(fixed, &src, 3, 1, 6, &mut out);
        assert_eq!(out, [Color32::BLACK, Palette::Grey.lut()[128], Color32::WHITE]);
    }
}
