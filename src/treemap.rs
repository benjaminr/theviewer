//! Squarified treemap layout (Bruls, Huizing and van Wijk, 2000).
//!
//! [`squarify`] cuts a rectangle into one tile per item, with each tile's area
//! in proportion to its item's size. Items are placed largest first in rows
//! along the shorter side, and a row is closed as soon as adding the next item
//! would make its worst aspect ratio worse, which keeps tiles close to square.
//!
//! The layout is a pure function on plain numbers, safe on any input: sizes
//! that are zero, negative or not finite get an empty tile.

/// An axis-aligned rectangle: top-left corner, width and height.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Tile {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Tile {
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Tile { x, y, width: width.max(0.0), height: height.max(0.0) }
    }

    pub fn area(&self) -> f64 {
        self.width * self.height
    }

    pub fn is_empty(&self) -> bool {
        self.width <= 0.0 || self.height <= 0.0
    }

    /// Longer side over shorter side; infinite for an empty tile.
    pub fn aspect_ratio(&self) -> f64 {
        if self.is_empty() {
            return f64::INFINITY;
        }
        self.width.max(self.height) / self.width.min(self.height)
    }

    /// This tile shrunk by `margin` on every side, never below zero size.
    pub fn inset(&self, margin: f64) -> Tile {
        Tile::new(self.x + margin, self.y + margin, self.width - 2.0 * margin, self.height - 2.0 * margin)
    }

    /// This tile with `amount` taken off its top edge.
    pub fn without_top(&self, amount: f64) -> Tile {
        let amount = amount.min(self.height).max(0.0);
        Tile::new(self.x, self.y + amount, self.width, self.height - amount)
    }
}

/// Lay out one tile per entry of `sizes` inside `bounds`, in the same order
/// as `sizes`. Tiles of the positive sizes tile `bounds` exactly, with areas
/// in proportion to their sizes. Unusable sizes get an empty tile at the
/// corner of `bounds`.
pub fn squarify(sizes: &[f64], bounds: Tile) -> Vec<Tile> {
    let empty = Tile::new(bounds.x, bounds.y, 0.0, 0.0);
    let mut tiles = vec![empty; sizes.len()];
    let total: f64 = sizes.iter().copied().filter(|&size| is_usable(size)).sum();
    if bounds.is_empty() || total <= 0.0 || !total.is_finite() {
        return tiles;
    }

    // Largest first, each scaled to the area it will cover.
    let scale = bounds.area() / total;
    let mut order: Vec<usize> = (0..sizes.len()).filter(|&index| is_usable(sizes[index])).collect();
    order.sort_by(|&a, &b| sizes[b].total_cmp(&sizes[a]).then(a.cmp(&b)));
    let areas: Vec<(usize, f64)> = order.into_iter().map(|index| (index, sizes[index] * scale)).collect();

    let mut remaining = bounds;
    let mut row_start = 0;
    while row_start < areas.len() {
        let row_end = row_length(&areas[row_start..], remaining) + row_start;
        let is_last_row = row_end == areas.len();
        remaining = place_row(&areas[row_start..row_end], remaining, is_last_row, &mut tiles);
        row_start = row_end;
    }
    tiles
}

fn is_usable(size: f64) -> bool {
    size.is_finite() && size > 0.0
}

/// How many of `areas` (largest first) belong in the next row along the
/// shorter side of `space`: keep adding while the worst aspect ratio does
/// not get worse. Always at least one.
fn row_length(areas: &[(usize, f64)], space: Tile) -> usize {
    let side = space.width.min(space.height);
    let mut count = 1;
    let mut worst = worst_aspect_ratio(&areas[..1], side);
    while count < areas.len() {
        let candidate = worst_aspect_ratio(&areas[..=count], side);
        if candidate > worst {
            break;
        }
        worst = candidate;
        count += 1;
    }
    count
}

/// The worst aspect ratio of a row of `areas` laid along a side of length
/// `side`.
fn worst_aspect_ratio(areas: &[(usize, f64)], side: f64) -> f64 {
    let sum: f64 = areas.iter().map(|&(_, area)| area).sum();
    if sum <= 0.0 || side <= 0.0 {
        return f64::INFINITY;
    }
    let largest = areas.iter().map(|&(_, area)| area).fold(0.0, f64::max);
    let smallest = areas.iter().map(|&(_, area)| area).fold(f64::INFINITY, f64::min);
    let side_squared = side * side;
    let sum_squared = sum * sum;
    (side_squared * largest / sum_squared).max(sum_squared / (side_squared * smallest))
}

/// Place one row along the shorter side of `space`, writing each tile into
/// `tiles`, and return the space left over. The last row takes all of the
/// remaining space, so rounding never leaves a gap.
fn place_row(row: &[(usize, f64)], space: Tile, is_last_row: bool, tiles: &mut [Tile]) -> Tile {
    let row_area: f64 = row.iter().map(|&(_, area)| area).sum();
    let lay_along_width = space.width >= space.height;
    if lay_along_width {
        // A column on the left, as tall as the space.
        let thickness = if is_last_row { space.width } else { (row_area / space.height).min(space.width) };
        let mut y = space.y;
        for (position, &(index, area)) in row.iter().enumerate() {
            let is_last = position + 1 == row.len();
            let height = if is_last { space.y + space.height - y } else { area / row_area * space.height };
            tiles[index] = Tile::new(space.x, y, thickness, height);
            y += height;
        }
        Tile::new(space.x + thickness, space.y, space.width - thickness, space.height)
    } else {
        // A strip along the top, as wide as the space.
        let thickness = if is_last_row { space.height } else { (row_area / space.width).min(space.height) };
        let mut x = space.x;
        for (position, &(index, area)) in row.iter().enumerate() {
            let is_last = position + 1 == row.len();
            let width = if is_last { space.x + space.width - x } else { area / row_area * space.width };
            tiles[index] = Tile::new(x, space.y, width, thickness);
            x += width;
        }
        Tile::new(space.x, space.y + thickness, space.width, space.height - thickness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOLERANCE: f64 = 1e-6;

    fn overlap_area(a: &Tile, b: &Tile) -> f64 {
        let width = (a.x + a.width).min(b.x + b.width) - a.x.max(b.x);
        let height = (a.y + a.height).min(b.y + b.height) - a.y.max(b.y);
        width.max(0.0) * height.max(0.0)
    }

    fn assert_tiles_parent_in_proportion(sizes: &[f64], bounds: Tile) {
        let tiles = squarify(sizes, bounds);
        assert_eq!(tiles.len(), sizes.len());
        let total: f64 = sizes.iter().filter(|size| is_usable(**size)).sum();

        let covered: f64 = tiles.iter().map(Tile::area).sum();
        assert!((covered - bounds.area()).abs() < TOLERANCE * bounds.area().max(1.0), "tiles cover {covered}, parent {}", bounds.area());
        for (tile, &size) in tiles.iter().zip(sizes) {
            let expected = if is_usable(size) { size / total * bounds.area() } else { 0.0 };
            assert!((tile.area() - expected).abs() < 1e-4 * bounds.area(), "size {size}: area {} expected {expected}", tile.area());
            assert!(tile.x >= bounds.x - TOLERANCE && tile.y >= bounds.y - TOLERANCE);
            assert!(tile.x + tile.width <= bounds.x + bounds.width + TOLERANCE);
            assert!(tile.y + tile.height <= bounds.y + bounds.height + TOLERANCE);
        }
        for (first, a) in tiles.iter().enumerate() {
            for b in &tiles[first + 1..] {
                assert!(overlap_area(a, b) < TOLERANCE, "tiles {a:?} and {b:?} overlap");
            }
        }
    }

    #[test]
    fn treemap_rectangles_tile_the_parent_with_areas_in_proportion() {
        let bounds = Tile::new(10.0, 20.0, 600.0, 400.0);
        assert_tiles_parent_in_proportion(&[6.0, 6.0, 4.0, 3.0, 2.0, 2.0, 1.0], bounds);
        assert_tiles_parent_in_proportion(&[1.0], bounds);
        assert_tiles_parent_in_proportion(&[1000.0, 1.0, 1.0, 1.0], bounds);
        assert_tiles_parent_in_proportion(&(1..=50).map(f64::from).collect::<Vec<_>>(), Tile::new(0.0, 0.0, 100.0, 900.0));
    }

    #[test]
    fn equal_sizes_in_a_square_give_near_square_tiles() {
        let tiles = squarify(&[1.0; 16], Tile::new(0.0, 0.0, 400.0, 400.0));
        let worst = tiles.iter().map(Tile::aspect_ratio).fold(0.0, f64::max);
        assert!(worst < 2.0, "worst aspect ratio {worst}");
    }

    #[test]
    fn the_classic_example_keeps_aspect_ratios_reasonable() {
        // The example from the paper: 6, 6, 4, 3, 2, 2, 1 in a 6 × 4 rectangle.
        let tiles = squarify(&[6.0, 6.0, 4.0, 3.0, 2.0, 2.0, 1.0], Tile::new(0.0, 0.0, 6.0, 4.0));
        let worst = tiles.iter().map(Tile::aspect_ratio).fold(0.0, f64::max);
        assert!(worst <= 3.0, "worst aspect ratio {worst}");
    }

    #[test]
    fn unusable_sizes_get_empty_tiles_and_the_rest_still_fill_the_parent() {
        let sizes = [5.0, 0.0, -3.0, f64::NAN, f64::INFINITY, 5.0];
        let tiles = squarify(&sizes, Tile::new(0.0, 0.0, 100.0, 50.0));
        assert!(tiles[1].is_empty() && tiles[2].is_empty() && tiles[3].is_empty() && tiles[4].is_empty());
        assert!((tiles[0].area() - 2500.0).abs() < 1e-6);
        assert!((tiles[5].area() - 2500.0).abs() < 1e-6);
    }

    #[test]
    fn nothing_to_lay_out_gives_empty_tiles() {
        assert!(squarify(&[], Tile::new(0.0, 0.0, 10.0, 10.0)).is_empty());
        assert!(squarify(&[0.0, 0.0], Tile::new(0.0, 0.0, 10.0, 10.0)).iter().all(Tile::is_empty));
        assert!(squarify(&[1.0, 2.0], Tile::new(0.0, 0.0, 0.0, 10.0)).iter().all(Tile::is_empty));
    }

    #[test]
    fn insets_never_produce_negative_sizes() {
        let tile = Tile::new(0.0, 0.0, 4.0, 4.0);
        assert_eq!(tile.inset(1.0), Tile::new(1.0, 1.0, 2.0, 2.0));
        assert!(tile.inset(10.0).is_empty());
        assert_eq!(tile.without_top(3.0).height, 1.0);
        assert!(tile.without_top(30.0).is_empty());
    }
}
