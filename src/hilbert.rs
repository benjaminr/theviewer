//! Space-filling curve layouts for the raster: Hilbert and Morton (Z-order).
//!
//! Both curves visit every cell of a 2^order × 2^order grid so that bytes
//! close together in the file land close together in the picture, which
//! makes structure visible without guessing a row width. The Hilbert curve
//! keeps every step next to the last; the Morton curve jumps between
//! quadrants but aligns power-of-two blocks to squares, so aligned
//! structures (pages, sectors) show as clean tiles.
//!
//! Orientation: the curve used here (the classic one from Hilbert's paper as
//! given by the standard `d2xy` algorithm) starts at the top-left cell (0, 0)
//! and ends at the top-right cell (side − 1, 0). `x` grows to the right and
//! `y` grows downwards, matching screen coordinates.

use eframe::egui::Color32;
use rayon::prelude::*;

/// Largest order rendered (4096 × 4096 pixels).
pub const MAX_ORDER: u32 = 12;

/// Which space-filling curve lays the bytes out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Curve {
    Hilbert,
    /// Z-order: the bits of the step interleaved into x (even bits) and y
    /// (odd bits).
    Morton,
}

impl Curve {
    pub fn label(self) -> &'static str {
        match self {
            Curve::Hilbert => "Hilbert curve",
            Curve::Morton => "Morton (Z-order) curve",
        }
    }

    /// Position of step `d` along this curve on a grid of side `2^order`.
    pub fn d_to_xy(self, order: u32, d: u64) -> (u32, u32) {
        match self {
            Curve::Hilbert => d_to_xy(order, d),
            Curve::Morton => morton_d_to_xy(d),
        }
    }

    /// Step along this curve at which cell (`x`, `y`) is visited.
    pub fn xy_to_d(self, order: u32, x: u32, y: u32) -> u64 {
        match self {
            Curve::Hilbert => xy_to_d(order, x, y),
            Curve::Morton => morton_xy_to_d(x, y),
        }
    }
}

/// Morton (Z-order) position of step `d`: x takes the even bits, y the odd.
pub fn morton_d_to_xy(d: u64) -> (u32, u32) {
    (compact_even_bits(d), compact_even_bits(d >> 1))
}

/// Morton step of cell (`x`, `y`): the bits of x and y interleaved.
pub fn morton_xy_to_d(x: u32, y: u32) -> u64 {
    spread_bits(x) | (spread_bits(y) << 1)
}

/// Put bit `i` of `value` at bit `2i`.
fn spread_bits(value: u32) -> u64 {
    let mut spread = u64::from(value);
    spread = (spread | (spread << 16)) & 0x0000_FFFF_0000_FFFF;
    spread = (spread | (spread << 8)) & 0x00FF_00FF_00FF_00FF;
    spread = (spread | (spread << 4)) & 0x0F0F_0F0F_0F0F_0F0F;
    spread = (spread | (spread << 2)) & 0x3333_3333_3333_3333;
    (spread | (spread << 1)) & 0x5555_5555_5555_5555
}

/// Gather bits 0, 2, 4, … of `value` into a number: the inverse of [`spread_bits`].
fn compact_even_bits(value: u64) -> u32 {
    let mut compact = value & 0x5555_5555_5555_5555;
    compact = (compact | (compact >> 1)) & 0x3333_3333_3333_3333;
    compact = (compact | (compact >> 2)) & 0x0F0F_0F0F_0F0F_0F0F;
    compact = (compact | (compact >> 4)) & 0x00FF_00FF_00FF_00FF;
    compact = (compact | (compact >> 8)) & 0x0000_FFFF_0000_FFFF;
    ((compact | (compact >> 16)) & 0x0000_0000_FFFF_FFFF) as u32
}

/// Position of step `d` along a curve of side `2^order`.
pub fn d_to_xy(order: u32, d: u64) -> (u32, u32) {
    let side: u64 = 1 << order;
    let (mut x, mut y) = (0u64, 0u64);
    let mut t = d;
    let mut s = 1u64;
    while s < side {
        let rx = 1 & (t / 2);
        let ry = 1 & (t ^ rx);
        rotate(s, &mut x, &mut y, rx, ry);
        x += s * rx;
        y += s * ry;
        t /= 4;
        s *= 2;
    }
    (x as u32, y as u32)
}

/// Step along a curve of side `2^order` at which cell (`x`, `y`) is visited.
pub fn xy_to_d(order: u32, x: u32, y: u32) -> u64 {
    let side: u64 = 1 << order;
    let (mut x, mut y) = (x as u64, y as u64);
    let mut d = 0u64;
    let mut s = side / 2;
    while s > 0 {
        let rx = u64::from(x & s > 0);
        let ry = u64::from(y & s > 0);
        d += s * s * ((3 * rx) ^ ry);
        rotate(side, &mut x, &mut y, rx, ry);
        s /= 2;
    }
    d
}

/// Rotate or flip a quadrant so the sub-curve joins its neighbours.
fn rotate(side: u64, x: &mut u64, y: &mut u64, rx: u64, ry: u64) {
    if ry == 0 {
        if rx == 1 {
            *x = side - 1 - *x;
            *y = side - 1 - *y;
        }
        std::mem::swap(x, y);
    }
}

/// Smallest order whose grid holds `len` cells, capped at [`MAX_ORDER`].
/// Longer inputs are sampled by [`render`].
pub fn order_for(len: usize) -> u32 {
    let mut order = 0;
    while order < MAX_ORDER && (1u64 << (2 * order)) < len as u64 {
        order += 1;
    }
    order
}

/// Paint `bytes` along a curve of side `2^order`, giving side × side pixels
/// in row-major order. Cells past the end of the data are transparent black.
///
/// When there are more bytes than cells, cell `index` shows the byte at
/// `index * len / cells`, so the whole input is sampled evenly.
pub fn render(bytes: &[u8], order: u32, colour: impl Fn(u8) -> Color32 + Sync) -> Vec<Color32> {
    let cells = 1usize << (2 * order);
    let len = bytes.len();
    let along: Vec<Color32> = (0..cells.min(len))
        .map(|d| {
            let source = if len > cells { (d as u128 * len as u128 / cells as u128) as usize } else { d };
            colour(bytes[source])
        })
        .collect();
    render_along(Curve::Hilbert, order, &along)
}

/// Lay `colours` (one per step, in curve order) out along `curve` on a grid
/// of side `2^order`, giving side × side pixels in row-major order. Cells
/// past the end of `colours` are transparent black.
pub fn render_along(curve: Curve, order: u32, colours: &[Color32]) -> Vec<Color32> {
    let side = 1usize << order;
    let mut pixels = vec![Color32::TRANSPARENT; side * side];
    pixels.par_chunks_mut(side).enumerate().for_each(|(y, row)| {
        for (x, pixel) in row.iter_mut().enumerate() {
            let d = curve.xy_to_d(order, x as u32, y as u32) as usize;
            if let Some(&colour) = colours.get(d) {
                *pixel = colour;
            }
        }
    });
    pixels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_are_inverses() {
        for order in 1..=6 {
            let cells = 1u64 << (2 * order);
            for d in 0..cells {
                let (x, y) = d_to_xy(order, d);
                assert_eq!(xy_to_d(order, x, y), d, "order {order}, d {d}");
            }
        }
    }

    #[test]
    fn consecutive_steps_are_neighbours() {
        for order in 1..=6 {
            let cells = 1u64 << (2 * order);
            for d in 1..cells {
                let (ax, ay) = d_to_xy(order, d - 1);
                let (bx, by) = d_to_xy(order, d);
                assert_eq!(ax.abs_diff(bx) + ay.abs_diff(by), 1, "order {order}, d {d}");
            }
        }
    }

    #[test]
    fn order_fits_the_input() {
        assert_eq!(order_for(0), 0);
        assert_eq!(order_for(1), 0);
        assert_eq!(order_for(2), 1);
        assert_eq!(order_for(4), 1);
        assert_eq!(order_for(5), 2);
        assert_eq!(order_for(16), 2);
        assert_eq!(order_for(1 << 30), MAX_ORDER);
    }

    #[test]
    fn render_follows_the_curve_and_samples_long_input() {
        let bytes: Vec<u8> = (0..16).collect();
        let pixels = render(&bytes, 2, Color32::from_gray);
        assert_eq!(pixels[0], Color32::from_gray(0));
        assert_eq!(pixels[3], Color32::from_gray(15), "last byte at (3, 0)");

        let short = render(&[7, 8], 1, Color32::from_gray);
        assert_eq!(short.iter().filter(|&&p| p == Color32::TRANSPARENT).count(), 2);

        let long: Vec<u8> = (0..64).collect();
        let sampled = render(&long, 1, Color32::from_gray);
        let (x, y) = d_to_xy(1, 3);
        assert_eq!(sampled[y as usize * 2 + x as usize], Color32::from_gray(48));
    }

    #[test]
    fn morton_index_and_position_round_trip() {
        for d in 0..4096u64 {
            let (x, y) = morton_d_to_xy(d);
            assert_eq!(morton_xy_to_d(x, y), d, "d {d}");
        }
        let far = (u32::MAX, 0x1234_5678);
        assert_eq!(morton_d_to_xy(morton_xy_to_d(far.0, far.1)), far);
    }

    #[test]
    fn morton_order_tiles_aligned_blocks_as_squares() {
        assert_eq!(morton_d_to_xy(0), (0, 0));
        assert_eq!(morton_d_to_xy(1), (1, 0));
        assert_eq!(morton_d_to_xy(2), (0, 1));
        assert_eq!(morton_d_to_xy(3), (1, 1));
        assert_eq!(morton_d_to_xy(4), (2, 0));
        // The first 16 steps fill the top-left 4 × 4 square.
        assert!((0..16).map(morton_d_to_xy).all(|(x, y)| x < 4 && y < 4));
        for order in 1..=5 {
            let cells = 1u64 << (2 * order);
            for d in 0..cells {
                let (x, y) = Curve::Morton.d_to_xy(order, d);
                assert_eq!(Curve::Morton.xy_to_d(order, x, y), d);
            }
        }
    }

    #[test]
    fn rendering_along_morton_places_each_step_at_its_cell() {
        let colours: Vec<Color32> = (0..16).map(Color32::from_gray).collect();
        let pixels = render_along(Curve::Morton, 2, &colours);
        assert_eq!(pixels[0], Color32::from_gray(0));
        assert_eq!(pixels[1], Color32::from_gray(1));
        assert_eq!(pixels[4], Color32::from_gray(2), "step 2 sits at (0, 1)");
        assert_eq!(pixels[15], Color32::from_gray(15));
    }
}
