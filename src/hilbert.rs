//! Hilbert-curve layout for the raster.
//!
//! A Hilbert curve visits every cell of a 2^order × 2^order grid so that
//! bytes close together in the file land close together in the picture,
//! which makes structure visible without guessing a row width.
//!
//! Orientation: the curve used here (the classic one from Hilbert's paper as
//! given by the standard `d2xy` algorithm) starts at the top-left cell (0, 0)
//! and ends at the top-right cell (side − 1, 0). `x` grows to the right and
//! `y` grows downwards, matching screen coordinates.

use eframe::egui::Color32;
use rayon::prelude::*;

/// Largest order rendered (4096 × 4096 pixels).
pub const MAX_ORDER: u32 = 12;

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
    let side = 1usize << order;
    let cells = side * side;
    let len = bytes.len();
    let mut pixels = vec![Color32::TRANSPARENT; cells];
    pixels.par_chunks_mut(side).enumerate().for_each(|(y, row)| {
        for (x, pixel) in row.iter_mut().enumerate() {
            let d = xy_to_d(order, x as u32, y as u32) as usize;
            let source = if len > cells { (d as u128 * len as u128 / cells as u128) as usize } else { d };
            if let Some(&byte) = bytes.get(source) {
                *pixel = colour(byte);
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
}
