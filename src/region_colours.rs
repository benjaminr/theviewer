//! Colours that say what bytes *are* rather than what they hold: the kinds
//! of region the report found, or, before a report has been run, each
//! block's byte class or entropy.
//!
//! The raster uses them when it is zoomed out so far that one screen pixel
//! covers many bytes (raw subsampled bytes turn to noise there), and the
//! curve layouts use them for their region, entropy and byte-class modes.

use std::hash::{DefaultHasher, Hash, Hasher};

use eframe::egui::Color32;
use rayon::prelude::*;

use crate::analysis::shannon_entropy;
use crate::app::Shape;
use crate::explain::Region;
use crate::theme;
use crate::view::entropy_colour;

/// Bytes summarised by one colour when zoomed out without a report.
pub const BLOCK_BYTES: usize = 256;
/// Share of a block one kind of byte must reach for the block to take that
/// kind's colour rather than its entropy's.
const DOMINANT_SHARE: f32 = 0.75;
/// Brightness kept for regions the report only guessed, as in the file map.
const GUESSED_REGION_BRIGHTNESS: f32 = 0.6;
/// Colour of pixels past the end of the data.
const NO_DATA: Color32 = Color32::BLACK;

/// The colour a region is drawn in: its kind's colour, dimmed when the
/// report only guessed it.
pub fn region_colour(region: &Region) -> Color32 {
    let brightness = if region.confident { 1.0 } else { GUESSED_REGION_BRIGHTNESS };
    region.kind.colour().gamma_multiply(brightness)
}

/// Finds the region holding each offset quickly when offsets mostly rise,
/// as they do walking a row or a curve. `regions` must be sorted by start
/// and not overlap, as [`crate::explain::map_file`] makes them.
pub struct RegionCursor<'a> {
    regions: &'a [Region],
    index: usize,
}

impl<'a> RegionCursor<'a> {
    pub fn new(regions: &'a [Region]) -> Self {
        RegionCursor { regions, index: 0 }
    }

    /// The region containing `offset`, if any.
    pub fn region_at(&mut self, offset: usize) -> Option<&'a Region> {
        let contains = |region: &Region| offset >= region.start && offset < region.end();
        let current = self.regions.get(self.index)?;
        if contains(current) {
            return Some(current);
        }
        if let Some(next) = self.regions.get(self.index + 1)
            && contains(next)
        {
            self.index += 1;
            return Some(next);
        }
        // A jump: search for the last region starting at or before `offset`.
        let after = self.regions.partition_point(|region| region.start <= offset);
        self.index = after.saturating_sub(1);
        self.regions.get(self.index).filter(|region| contains(region))
    }

    /// The colour of the region containing `offset`, if any.
    pub fn colour_at(&mut self, offset: usize) -> Option<Color32> {
        self.region_at(offset).map(region_colour)
    }
}

/// One colour summing up a block of bytes: the byte-class colour when one
/// class (zeros, 0xFF or text) dominates, otherwise the entropy colour, so
/// padding, text, structured data and compressed data all look different.
pub fn block_colour(bytes: &[u8]) -> Color32 {
    if bytes.is_empty() {
        return NO_DATA;
    }
    let (mut zeros, mut full, mut text) = (0usize, 0usize, 0usize);
    for &byte in bytes {
        match byte {
            0x00 => zeros += 1,
            0xFF => full += 1,
            0x20..=0x7E | b'\t' | b'\n' | b'\r' => text += 1,
            _ => {}
        }
    }
    let dominates = |count: usize| count as f32 >= bytes.len() as f32 * DOMINANT_SHARE;
    if dominates(zeros) {
        theme::CLASS_NULL
    } else if dominates(full) {
        theme::CLASS_FULL
    } else if dominates(text) {
        theme::CLASS_TEXT
    } else {
        entropy_colour(shannon_entropy(bytes))
    }
}

/// A cheap fingerprint of a set of regions, so a cached picture coloured by
/// them can tell when the report has changed.
pub fn regions_fingerprint(regions: &[Region]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for region in regions {
        (region.start, region.len, region.kind, region.confident).hash(&mut hasher);
    }
    hasher.finish()
}

/// Colour `rows` rows of the raster from `top_row` by the region holding
/// each pixel's first byte.
pub fn region_pixels(shape: &Shape, top_row: usize, document_len: usize, regions: &[Region], out: &mut [Color32]) {
    out.par_chunks_mut(shape.width.max(1)).enumerate().for_each(|(row, row_out)| {
        let mut cursor = RegionCursor::new(regions);
        for (col, pixel) in row_out.iter_mut().enumerate() {
            let offset = shape.byte_of_pixel(top_row + row, col);
            *pixel = if offset < document_len { cursor.colour_at(offset).unwrap_or(NO_DATA) } else { NO_DATA };
        }
    });
}

/// Colour `rows` rows of the raster from `top_row` by the [`block_colour`]
/// of the [`BLOCK_BYTES`]-aligned block holding each pixel's first byte.
/// `window` holds the document's bytes from `window_start` on, as far as the
/// view reaches; blocks cut by its edges are judged on the part inside.
pub fn block_pixels(shape: &Shape, top_row: usize, document_len: usize, window_start: usize, window: &[u8], out: &mut [Color32]) {
    let window_end = (window_start + window.len()).min(document_len);
    if window_end <= window_start {
        out.fill(NO_DATA);
        return;
    }
    let first_block = window_start / BLOCK_BYTES;
    let last_block = (window_end - 1) / BLOCK_BYTES;
    let colours: Vec<Color32> = (first_block..=last_block)
        .into_par_iter()
        .map(|block| {
            let start = (block * BLOCK_BYTES).max(window_start);
            let end = ((block + 1) * BLOCK_BYTES).min(window_end);
            block_colour(&window[start - window_start..end - window_start])
        })
        .collect();
    out.par_chunks_mut(shape.width.max(1)).enumerate().for_each(|(row, row_out)| {
        for (col, pixel) in row_out.iter_mut().enumerate() {
            let offset = shape.byte_of_pixel(top_row + row, col);
            let block = (offset / BLOCK_BYTES).checked_sub(first_block);
            *pixel = match block.and_then(|block| colours.get(block)) {
                Some(&colour) if offset < window_end => colour,
                _ => NO_DATA,
            };
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explain::RegionKind;
    use crate::raster::{Palette, PixelFormat};

    fn region(start: usize, len: usize, kind: RegionKind) -> Region {
        Region { start, len, kind, label: String::new(), detail: String::new(), confident: true }
    }

    fn shape(width: usize) -> Shape {
        Shape { format: PixelFormat::Gray8, palette: Palette::Grey, width, byte_offset: 0, bit_offset: 0, row_padding: 0 }
    }

    #[test]
    fn region_cursor_finds_regions_walking_forwards_and_jumping_back() {
        let regions = [region(0, 10, RegionKind::Header), region(10, 90, RegionKind::Text), region(100, 50, RegionKind::Padding)];
        let mut cursor = RegionCursor::new(&regions);
        assert_eq!(cursor.region_at(5).map(|r| r.kind), Some(RegionKind::Header));
        assert_eq!(cursor.region_at(10).map(|r| r.kind), Some(RegionKind::Text));
        assert_eq!(cursor.region_at(120).map(|r| r.kind), Some(RegionKind::Padding));
        assert_eq!(cursor.region_at(3).map(|r| r.kind), Some(RegionKind::Header), "jumping back");
        assert_eq!(cursor.region_at(150), None, "past the last region");
        assert_eq!(RegionCursor::new(&[]).region_at(0), None);
    }

    #[test]
    fn guessed_regions_are_dimmer_than_confident_ones() {
        let confident = region(0, 1, RegionKind::Image);
        let guessed = Region { confident: false, ..confident.clone() };
        assert_eq!(region_colour(&confident), RegionKind::Image.colour());
        assert!(region_colour(&guessed).r() < region_colour(&confident).r());
    }

    #[test]
    fn blocks_are_coloured_by_their_dominant_class_or_their_entropy() {
        assert_eq!(block_colour(&[0; 64]), theme::CLASS_NULL);
        assert_eq!(block_colour(&[0xFF; 64]), theme::CLASS_FULL);
        assert_eq!(block_colour(b"plain words of text, line after line\n"), theme::CLASS_TEXT);
        let noise: Vec<u8> = (0..=255).collect();
        assert_eq!(block_colour(&noise), entropy_colour(shannon_entropy(&noise)));
    }

    #[test]
    fn zoomed_out_pixels_take_the_colour_of_their_region() {
        let regions = [region(0, 8, RegionKind::Header), region(8, 8, RegionKind::Code)];
        let mut out = vec![Color32::TRANSPARENT; 4 * 5];
        region_pixels(&shape(4), 0, 16, &regions, &mut out);
        assert!(out[..8].iter().all(|&c| c == RegionKind::Header.colour()));
        assert!(out[8..16].iter().all(|&c| c == RegionKind::Code.colour()));
        assert!(out[16..].iter().all(|&c| c == NO_DATA), "past the end of the data");
    }

    #[test]
    fn zoomed_out_pixels_without_a_report_take_their_block_colour() {
        let mut window = vec![0u8; BLOCK_BYTES];
        window.extend(std::iter::repeat_n(b'a', BLOCK_BYTES));
        let mut out = vec![Color32::TRANSPARENT; 64 * 9];
        block_pixels(&shape(64), 0, window.len(), 0, &window, &mut out);
        assert!(out[..BLOCK_BYTES].iter().all(|&c| c == theme::CLASS_NULL));
        assert!(out[BLOCK_BYTES..2 * BLOCK_BYTES].iter().all(|&c| c == theme::CLASS_TEXT));
        assert!(out[2 * BLOCK_BYTES..].iter().all(|&c| c == NO_DATA));
    }

    #[test]
    fn a_changed_report_changes_the_fingerprint() {
        let before = [region(0, 8, RegionKind::Header)];
        let after = [region(0, 8, RegionKind::Code)];
        assert_ne!(regions_fingerprint(&before), regions_fingerprint(&after));
        assert_eq!(regions_fingerprint(&before), regions_fingerprint(&before.clone()));
    }
}
