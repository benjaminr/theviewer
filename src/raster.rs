//! Turns raw bytes into RGBA pixels according to a chosen pixel format.
//!
//! The rasteriser is deliberately simple: it maps a flat byte window onto a
//! `width × rows` grid, one row after another. Everything about *which* bytes
//! land in the window (offset, stride, bit shift) is decided by the caller.

use std::sync::OnceLock;

use eframe::egui::Color32;
use rayon::prelude::*;

use crate::theme;

/// Colour ramp applied to single-channel formats (1-bit, 4-bit, 8-bit, 16-bit grey).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Palette {
    Grey,
    Viridis,
    Inferno,
    Ocean,
    Amber,
}

impl Palette {
    pub const ALL: [Palette; 5] = [Palette::Grey, Palette::Viridis, Palette::Inferno, Palette::Ocean, Palette::Amber];

    pub fn label(self) -> &'static str {
        match self {
            Palette::Grey => "Grey",
            Palette::Viridis => "Viridis",
            Palette::Inferno => "Inferno",
            Palette::Ocean => "Ocean",
            Palette::Amber => "Amber",
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

/// How bytes are interpreted as pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// One bit per pixel, most significant bit first.
    Bit1Msb,
    /// One bit per pixel, least significant bit first.
    Bit1Lsb,
    /// Four bits per pixel, greyscale.
    Nibble4,
    /// One byte per pixel, greyscale.
    Gray8,
    /// One byte per pixel, coloured by byte class (null / ascii / control / high).
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
}

impl PixelFormat {
    pub const ALL: [PixelFormat; 12] = [
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
            PixelFormat::Rgb565 | PixelFormat::Gray16Le | PixelFormat::Gray16Be => 16,
            PixelFormat::Rgb8 | PixelFormat::Bgr8 => 24,
            PixelFormat::Rgba8 | PixelFormat::Bgra8 => 32,
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
    debug_assert_eq!(out.len(), width * rows);
    if width == 0 || rows == 0 {
        return;
    }
    let row_bytes = format.bytes_for_pixels(width);
    debug_assert!(row_stride >= row_bytes);
    debug_assert!(src.len() >= row_stride * rows);

    const PARALLEL_THRESHOLD: usize = 1 << 18;
    let lut = palette.lut();
    let render_row = |row_src: &[u8], row_out: &mut [Color32]| rasterise_row(format, lut, row_src, row_out);

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
}
