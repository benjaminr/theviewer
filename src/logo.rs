//! The app's logo: a tile of byte-pixels that have fallen into line.
//!
//! It shows what the viewer does. Raw bytes are drawn as pixels, and once the
//! width is right the rows line up into columns: a teal counter that
//! brightens row by row, a blue column of text, and grey bytes either side.
//! The amber square is the cursor.
//!
//! It is drawn in code, so the window icon, the README image and the empty
//! view all come from the same design and stay sharp at any size.

use eframe::egui::{Color32, CornerRadius, Painter, Pos2, Rect, Vec2, pos2, vec2};

use crate::theme;

/// Cells per side of the pixel grid.
const GRID: usize = 5;
/// Space around the tile, as a fraction of the image (icons are inset).
const TILE_INSET: f32 = 0.08;
/// Tile corner radius, as a fraction of the tile.
const TILE_RADIUS: f32 = 0.22;
/// Space between the tile edge and the grid, as a fraction of the tile.
const GRID_MARGIN: f32 = 0.15;
/// Gap between cells, as a fraction of a cell.
const CELL_GAP: f32 = 0.2;
/// Cell corner radius, as a fraction of a cell.
const CELL_RADIUS: f32 = 0.2;
/// Row and column of the cursor cell.
const CURSOR_CELL: (usize, usize) = (3, 2);
/// Brightness of the grey "unstructured" bytes, chosen to look random.
const NOISE: [[u8; 3]; GRID] = [[86, 58, 104], [64, 112, 72], [98, 70, 60], [56, 94, 118], [108, 62, 84]];

/// The colour of each cell, row by row.
pub fn cell_colours() -> [[Color32; GRID]; GRID] {
    let mut cells = [[Color32::BLACK; GRID]; GRID];
    for (row, cells_in_row) in cells.iter_mut().enumerate() {
        let counter_step = row as f32 / (GRID - 1) as f32;
        let grey = |level: u8| Color32::from_rgb(level, level.saturating_add(4), level.saturating_add(12));
        *cells_in_row = [
            mix(theme::ACCENT_DIM, theme::ACCENT, counter_step),
            grey(NOISE[row][0]),
            theme::CLASS_TEXT,
            grey(NOISE[row][1]),
            grey(NOISE[row][2]),
        ];
    }
    cells[CURSOR_CELL.0][CURSOR_CELL.1] = theme::CURSOR;
    cells
}

/// Where the tile and each cell sit in a square of side `size`.
struct Layout {
    tile: Rect,
    tile_radius: f32,
    cells: Vec<(Rect, Color32)>,
    cell_radius: f32,
}

fn layout(origin: Pos2, size: f32) -> Layout {
    let inset = size * TILE_INSET;
    let tile = Rect::from_min_size(origin + Vec2::splat(inset), Vec2::splat(size - 2.0 * inset));
    let grid = tile.shrink(tile.width() * GRID_MARGIN);
    // GRID cells and GRID - 1 gaps fill the grid.
    let cell = grid.width() / (GRID as f32 + (GRID - 1) as f32 * CELL_GAP);
    let step = cell * (1.0 + CELL_GAP);
    let colours = cell_colours();
    let mut cells = Vec::with_capacity(GRID * GRID);
    for (row, colours_in_row) in colours.iter().enumerate() {
        for (col, &colour) in colours_in_row.iter().enumerate() {
            let min = grid.min + vec2(col as f32 * step, row as f32 * step);
            cells.push((Rect::from_min_size(min, Vec2::splat(cell)), colour));
        }
    }
    Layout { tile, tile_radius: tile.width() * TILE_RADIUS, cells, cell_radius: cell * CELL_RADIUS }
}

/// Paint the logo into `rect` (which should be square).
pub fn paint(painter: &Painter, rect: Rect) {
    let size = rect.width().min(rect.height());
    let layout = layout(rect.center() - Vec2::splat(size / 2.0), size);
    painter.rect_filled(layout.tile, CornerRadius::same(layout.tile_radius as u8), theme::SURFACE);
    for (cell, colour) in layout.cells {
        painter.rect_filled(cell, CornerRadius::same(layout.cell_radius.round() as u8), colour);
    }
}

/// The logo as straight (not premultiplied) RGBA pixels, `size` × `size`,
/// for the window icon and image files.
pub fn render_rgba(size: u32) -> Vec<u8> {
    let layout = layout(pos2(0.0, 0.0), size as f32);
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let centre = pos2(x as f32 + 0.5, y as f32 + 0.5);
            let mut pixel = [0.0f32; 4];
            let tile_cover = coverage(centre, layout.tile, layout.tile_radius);
            blend(&mut pixel, theme::SURFACE, tile_cover);
            for &(cell, colour) in &layout.cells {
                blend(&mut pixel, colour, coverage(centre, cell, layout.cell_radius));
            }
            let at = ((y * size + x) * 4) as usize;
            for channel in 0..4 {
                rgba[at + channel] = (pixel[channel] * 255.0).round() as u8;
            }
        }
    }
    rgba
}

/// How much of the pixel centred on `point` a rounded rectangle covers,
/// from its signed distance, which smooths the edges.
fn coverage(point: Pos2, rect: Rect, radius: f32) -> f32 {
    let half = rect.size() / 2.0 - Vec2::splat(radius);
    let offset = (point - rect.center()).abs() - half;
    let outside = vec2(offset.x.max(0.0), offset.y.max(0.0)).length();
    let inside = offset.x.max(offset.y).min(0.0);
    let distance = outside + inside - radius;
    (0.5 - distance).clamp(0.0, 1.0)
}

/// Lay `colour` over `pixel` (straight RGBA in 0..=1) with the given coverage.
fn blend(pixel: &mut [f32; 4], colour: Color32, cover: f32) {
    if cover <= 0.0 {
        return;
    }
    let [r, g, b, _] = colour.to_array();
    let alpha = pixel[3] + cover * (1.0 - pixel[3]);
    for (channel, value) in [r, g, b].into_iter().enumerate() {
        let source = value as f32 / 255.0;
        pixel[channel] = (source * cover + pixel[channel] * pixel[3] * (1.0 - cover)) / alpha;
    }
    pixel[3] = alpha;
}

fn mix(from: Color32, to: Color32, amount: f32) -> Color32 {
    let lerp = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * amount).round() as u8;
    Color32::from_rgb(lerp(from.r(), to.r()), lerp(from.g(), to.g()), lerp(from.b(), to.b()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(rgba: &[u8], size: u32, x: u32, y: u32) -> [u8; 4] {
        let at = ((y * size + x) * 4) as usize;
        [rgba[at], rgba[at + 1], rgba[at + 2], rgba[at + 3]]
    }

    #[test]
    fn the_icon_has_transparent_corners_and_an_opaque_tile() {
        let size = 64;
        let rgba = render_rgba(size);
        assert_eq!(rgba.len(), (size * size * 4) as usize);
        assert_eq!(pixel(&rgba, size, 0, 0)[3], 0, "outside the tile is transparent");
        assert_eq!(pixel(&rgba, size, size / 2, size / 2)[3], 255, "the middle is solid");
    }

    #[test]
    fn the_cursor_cell_is_amber_and_the_counter_brightens_downwards() {
        let colours = cell_colours();
        assert_eq!(colours[CURSOR_CELL.0][CURSOR_CELL.1], theme::CURSOR);
        let brightness = |c: Color32| c.r() as u32 + c.g() as u32 + c.b() as u32;
        assert!(colours.windows(2).all(|rows| brightness(rows[0][0]) < brightness(rows[1][0])));
    }

    #[test]
    fn the_icon_renders_at_every_common_size() {
        for size in [16, 32, 128, 512] {
            let rgba = render_rgba(size);
            let centre = pixel(&rgba, size, size / 2, size / 2);
            assert_eq!(centre[3], 255, "solid at {size}px");
        }
    }
}
