//! Dock panel: a rotatable 3D cloud of byte trigrams.
//!
//! Each point is a cell of the quantised trigram cube ([`crate::trigram`]):
//! x is a byte, y the byte after it and z the one after that. The cloud is
//! counted on a background thread and drawn with egui's painter in an
//! orthographic projection, far points first. Drag to rotate, scroll to zoom
//! and double-click to reset. Hovering a point names its trigram; a click
//! jumps to the occurrence of that trigram closest to the cursor.

use std::f32::consts::{FRAC_PI_2, FRAC_PI_4};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Align2, Color32, FontId, Painter, Pos2, RichText, Sense, Stroke, Ui, Vec2, vec2};

use crate::app::ViewerApp;
use crate::compress::human_bytes;
use crate::raster::{Palette, byte_class_colour};
use crate::theme;
use crate::trigram::{self, TrigramCloud, TrigramCounter, TrigramPoint};

/// How often to look for a finished cloud while one is being counted.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Smallest side, in points, the view is drawn at.
const MIN_VIEW_SIDE: f32 = 160.0;
/// Space kept below the view for the legend.
const LEGEND_HEIGHT: f32 = 70.0;
/// Fraction of the view's side the cube's edge spans at zoom 1.
const CUBE_SCALE: f32 = 0.55;
/// Radians turned per point dragged.
const ROTATION_PER_POINT: f32 = 0.01;
/// Zoom factor per point of scroll, as an exponent.
const ZOOM_PER_SCROLL_POINT: f32 = 0.002;
const MIN_ZOOM: f32 = 0.3;
const MAX_ZOOM: f32 = 6.0;
/// The isometric pitch, `atan(1 / √2)`, in radians.
const ISOMETRIC_PITCH: f32 = 0.615_479_7;
/// Radius of the lightest and heaviest points, in points.
const MIN_POINT_RADIUS: f32 = 1.2;
const MAX_POINT_RADIUS: f32 = 4.5;
/// Opacity of the lightest point, out of 255.
const MIN_POINT_ALPHA: f32 = 70.0;
/// Extra distance, in points, within which a point counts as hovered.
const HOVER_SLOP: f32 = 3.0;
/// How far either side of the cursor a clicked trigram is searched for.
const SEARCH_RADIUS: usize = 8 * 1024 * 1024;
const LABEL_FONT_SIZE: f32 = 11.0;

/// What a point's colour shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PointColouring {
    /// The third byte's value, on the Viridis ramp.
    #[default]
    ThirdByte,
    /// The byte class (zero, text, control, high, 0xFF) of the middle byte.
    MiddleByteClass,
}

impl PointColouring {
    pub const ALL: [PointColouring; 2] = [PointColouring::ThirdByte, PointColouring::MiddleByteClass];

    pub fn label(self) -> &'static str {
        match self {
            PointColouring::ThirdByte => "Colour by z",
            PointColouring::MiddleByteClass => "Colour by middle byte class",
        }
    }
}

/// An orthographic camera turned about the cube's centre.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Camera {
    /// Turn about the vertical (z) axis, in radians.
    pub yaw: f32,
    /// Tilt towards looking down, in radians: 0 looks along y, π/2 down z.
    pub pitch: f32,
    pub zoom: f32,
}

impl Default for Camera {
    fn default() -> Self {
        Camera::ISOMETRIC
    }
}

impl Camera {
    pub const ISOMETRIC: Camera = Camera { yaw: FRAC_PI_4, pitch: ISOMETRIC_PITCH, zoom: 1.0 };
    /// Looking down z: x across, y up the screen.
    pub const TOP: Camera = Camera { yaw: 0.0, pitch: FRAC_PI_2, zoom: 1.0 };
    /// Looking along y: x across, z up the screen.
    pub const FRONT: Camera = Camera { yaw: 0.0, pitch: 0.0, zoom: 1.0 };

    /// The named presets offered as buttons.
    pub const PRESETS: [(&'static str, Camera); 3] =
        [("Isometric", Camera::ISOMETRIC), ("Top (x/y)", Camera::TOP), ("Front (x/z)", Camera::FRONT)];

    /// Turn by a drag of `delta` points; the pitch stops at straight up or down.
    pub fn rotate(&mut self, delta: Vec2) {
        self.yaw += delta.x * ROTATION_PER_POINT;
        self.pitch = (self.pitch + delta.y * ROTATION_PER_POINT).clamp(-FRAC_PI_2, FRAC_PI_2);
    }

    /// Zoom by a scroll of `scroll` points, within the zoom limits.
    pub fn zoom_by(&mut self, scroll: f32) {
        self.zoom = (self.zoom * (scroll * ZOOM_PER_SCROLL_POINT).exp()).clamp(MIN_ZOOM, MAX_ZOOM);
    }

    /// Project a point of the unit cube to a screen offset from the view's
    /// centre (in cube edges, y pointing down) and a depth (smaller is nearer).
    pub fn project(&self, unit: [f32; 3]) -> (Vec2, f32) {
        let [x, y, z] = unit.map(|coordinate| coordinate - 0.5);
        let (yaw_sin, yaw_cos) = self.yaw.sin_cos();
        let (pitch_sin, pitch_cos) = self.pitch.sin_cos();
        let across = x * yaw_cos - y * yaw_sin;
        let away = x * yaw_sin + y * yaw_cos;
        let up = z * pitch_cos + away * pitch_sin;
        let depth = away * pitch_cos - z * pitch_sin;
        (vec2(across, -up) * self.zoom, depth)
    }
}

/// Everything the trigram panel keeps between frames.
#[derive(Default)]
pub struct TrigramState {
    pub colouring: PointColouring,
    pub camera: Camera,
    pending: Option<Receiver<TrigramCloud>>,
    /// The most recent finished cloud.
    pub cloud: Option<TrigramCloud>,
}

/// A point placed on screen for this frame.
struct PlacedPoint {
    index: usize,
    position: Pos2,
    depth: f32,
    radius: f32,
}

/// The selection, else the whole file, with a word for which.
fn scope(app: &ViewerApp) -> (usize, usize, &'static str) {
    match app.selection() {
        Some((start, len)) => (start, len, "selection"),
        None => (0, app.document.len(), "whole file"),
    }
}

/// Read the scope (sampled when large) and count it on a background thread.
fn start_counting(state: &mut TrigramState, app: &mut ViewerApp) {
    let (start, len, _) = scope(app);
    let windows: Vec<(usize, Vec<u8>)> = trigram::sample_windows(len, trigram::SAMPLE_LIMIT, trigram::SAMPLE_WINDOW)
        .into_iter()
        .map(|(offset, size)| (start + offset, app.document.read_range(start + offset, size)))
        .collect();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut counter = TrigramCounter::new();
        for (offset, bytes) in &windows {
            counter.add_window(*offset, bytes);
        }
        // The receiver may be gone if the panel was closed; nothing to do then.
        let _ = sender.send(counter.finish(start, len, trigram::DEFAULT_MAX_POINTS));
    });
    state.pending = Some(receiver);
}

fn poll(state: &mut TrigramState, ctx: &egui::Context) {
    let Some(receiver) = &state.pending else { return };
    match receiver.try_recv() {
        Ok(cloud) => {
            state.cloud = Some(cloud);
            state.pending = None;
        }
        Err(mpsc::TryRecvError::Empty) => ctx.request_repaint_after(POLL_INTERVAL),
        Err(mpsc::TryRecvError::Disconnected) => state.pending = None,
    }
}

/// Show the trigram cube panel.
pub fn show_trigram(state: &mut TrigramState, app: &mut ViewerApp, ui: &mut Ui) {
    poll(state, ui.ctx());
    show_toolbar(state, app, ui);

    let Some(cloud) = &state.cloud else {
        ui.label(
            RichText::new("Plots every run of three bytes as a point in a 256 × 256 × 256 cube. Different kinds of data make different shapes.")
                .color(theme::TEXT_DIM),
        );
        return;
    };
    if cloud.is_empty() {
        ui.label(RichText::new("Too few bytes to plot; select at least three.").color(theme::TEXT_DIM));
        return;
    }
    ui.label(RichText::new(caption(cloud)).small().color(theme::TEXT_DIM));

    let jump = show_cube(state, ui);
    show_legend(state.colouring, ui);
    if let Some(point) = jump {
        jump_to_trigram(app, &point);
    }
}

fn show_toolbar(state: &mut TrigramState, app: &mut ViewerApp, ui: &mut Ui) {
    let (_, len, what) = scope(app);
    ui.horizontal_wrapped(|ui| {
        if ui.button(format!("Plot {what} ({})", human_bytes(len))).clicked() {
            start_counting(state, app);
        }
        egui::ComboBox::from_id_salt("trigram-colouring").selected_text(state.colouring.label()).show_ui(ui, |ui| {
            for colouring in PointColouring::ALL {
                ui.selectable_value(&mut state.colouring, colouring, colouring.label());
            }
        });
        for (name, preset) in Camera::PRESETS {
            if ui.small_button(name).clicked() {
                state.camera = Camera { zoom: state.camera.zoom, ..preset };
            }
        }
        if state.pending.is_some() {
            ui.spinner();
            ui.label(RichText::new("Counting trigrams…").color(theme::TEXT_DIM));
        }
    });
}

fn caption(cloud: &TrigramCloud) -> String {
    let sampled = if cloud.is_sampled() { format!(", sampled {}", human_bytes(cloud.bytes_read)) } else { String::new() };
    format!(
        "{} trigrams from {:#x} ({}{sampled}) · {:.1}% of cells used · top {} cells shown · drag to rotate, scroll to zoom, double-click to reset, click a point to jump",
        cloud.total_trigrams,
        cloud.start,
        human_bytes(cloud.len),
        cloud.occupancy() * 100.0,
        cloud.points.len()
    )
}

/// Draw the cube and handle rotation, zoom and hovering. Returns the point
/// clicked, if any.
fn show_cube(state: &mut TrigramState, ui: &mut Ui) -> Option<TrigramPoint> {
    let cloud = state.cloud.as_ref()?;
    let side = ui.available_width().min(ui.available_height() - LEGEND_HEIGHT).max(MIN_VIEW_SIDE);
    let (response, painter) = ui.allocate_painter(vec2(ui.available_width().max(side), side), Sense::click_and_drag());
    let rect = response.rect;
    painter.rect_filled(rect, 4.0, theme::BACKGROUND);

    if response.dragged() {
        state.camera.rotate(response.drag_delta());
    }
    if response.hovered() {
        let scroll = ui.input(|input| input.smooth_scroll_delta.y);
        if scroll != 0.0 {
            state.camera.zoom_by(scroll);
        }
    }
    if response.double_clicked() {
        state.camera = Camera::ISOMETRIC;
    }

    let scale = side * CUBE_SCALE;
    let camera = state.camera;
    let to_screen = |unit: [f32; 3]| {
        let (offset, depth) = camera.project(unit);
        (rect.center() + offset * scale, depth)
    };
    draw_cube_frame(&painter, &to_screen);

    let placed = place_points(&cloud.points, &to_screen);
    let hovered = response.hover_pos().and_then(|pointer| nearest_point(&placed, pointer));
    for point in &placed {
        let colour = point_colour(&cloud.points[point.index], state.colouring);
        painter.circle_filled(point.position, point.radius, colour);
    }
    let hovered_point = hovered.map(|placed_index| &placed[placed_index]);
    if let Some(point) = hovered_point {
        painter.circle_stroke(point.position, point.radius + 2.0, Stroke::new(1.5, theme::CURSOR));
    }

    let clicked = hovered_point.filter(|_| response.clicked()).map(|point| cloud.points[point.index].clone());
    if let Some(point) = hovered_point {
        response.on_hover_text(describe_point(&cloud.points[point.index], cloud.total_trigrams));
    }
    clicked
}

/// Draw the cube's twelve edges, with the three axes from the origin
/// brighter and labelled.
fn draw_cube_frame(painter: &Painter, to_screen: &impl Fn([f32; 3]) -> (Pos2, f32)) {
    let corner = |x: f32, y: f32, z: f32| to_screen([x, y, z]).0;
    let edge_stroke = Stroke::new(1.0, theme::OUTLINE);
    for a in [0.0, 1.0] {
        for b in [0.0, 1.0] {
            painter.line_segment([corner(0.0, a, b), corner(1.0, a, b)], edge_stroke);
            painter.line_segment([corner(a, 0.0, b), corner(a, 1.0, b)], edge_stroke);
            painter.line_segment([corner(a, b, 0.0), corner(a, b, 1.0)], edge_stroke);
        }
    }
    let axis_stroke = Stroke::new(1.5, theme::TEXT_DIM);
    let origin = corner(0.0, 0.0, 0.0);
    let font = FontId::proportional(LABEL_FONT_SIZE);
    painter.text(origin, Align2::RIGHT_TOP, "0", font.clone(), theme::TEXT_DIM);
    for (name, end) in [("x 255", corner(1.0, 0.0, 0.0)), ("y 255", corner(0.0, 1.0, 0.0)), ("z 255", corner(0.0, 0.0, 1.0))] {
        painter.line_segment([origin, end], axis_stroke);
        painter.text(end, Align2::LEFT_BOTTOM, name, font.clone(), theme::TEXT);
    }
}

/// Project every point, sized by weight, sorted far to near for painting.
fn place_points(points: &[TrigramPoint], to_screen: &impl Fn([f32; 3]) -> (Pos2, f32)) -> Vec<PlacedPoint> {
    let mut placed: Vec<PlacedPoint> = points
        .iter()
        .enumerate()
        .map(|(index, point)| {
            let (position, depth) = to_screen(point.unit_position());
            let radius = MIN_POINT_RADIUS + (MAX_POINT_RADIUS - MIN_POINT_RADIUS) * point.weight;
            PlacedPoint { index, position, depth, radius }
        })
        .collect();
    placed.sort_by(|a, b| b.depth.total_cmp(&a.depth));
    placed
}

/// The placed point under `pointer`: the closest within its radius plus a
/// little slop, the nearest to the viewer when several are equally close.
fn nearest_point(placed: &[PlacedPoint], pointer: Pos2) -> Option<usize> {
    placed
        .iter()
        .enumerate()
        .filter(|(_, point)| point.position.distance(pointer) <= point.radius + HOVER_SLOP)
        // Points are sorted far to near, so on equal distance prefer the
        // later (nearer) one.
        .min_by(|(a_index, a), (b_index, b)| {
            a.position.distance(pointer).total_cmp(&b.position.distance(pointer)).then(b_index.cmp(a_index))
        })
        .map(|(index, _)| index)
}

fn point_colour(point: &TrigramPoint, colouring: PointColouring) -> Color32 {
    let base = match colouring {
        PointColouring::ThirdByte => Palette::Viridis.lut()[point.value_range(2).0 as usize],
        PointColouring::MiddleByteClass => byte_class_colour(point.exemplar[1]),
    };
    let alpha = MIN_POINT_ALPHA + (255.0 - MIN_POINT_ALPHA) * point.weight.clamp(0.0, 1.0);
    Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), alpha as u8)
}

/// Hover text for a point: its trigram, the cell it stands for and its count.
fn describe_point(point: &TrigramPoint, total: u64) -> String {
    let [a, b, c] = point.exemplar;
    let printable = |byte: u8| if (0x20..=0x7E).contains(&byte) { byte as char } else { '·' };
    let range = |axis: usize| {
        let (low, high) = point.value_range(axis);
        format!("{low:02X}–{high:02X}")
    };
    let share = point.count as f64 / total.max(1) as f64 * 100.0;
    format!(
        "{a:02X} {b:02X} {c:02X}  \"{}{}{}\"\nCell x {} · y {} · z {}\n{} trigrams in this cell ({share:.2}%)\nFirst at {:#x}; click to jump to the one nearest the cursor",
        printable(a),
        printable(b),
        printable(c),
        range(0),
        range(1),
        range(2),
        point.count,
        point.offset
    )
}

fn show_legend(colouring: PointColouring, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| match colouring {
        PointColouring::ThirdByte => {
            ui.label(RichText::new("Colour: third byte, dark (0x00) to yellow (0xFF). Size and opacity: how common.").small().color(theme::TEXT_DIM));
        }
        PointColouring::MiddleByteClass => {
            for (colour, name) in [
                (theme::CLASS_NULL, "0x00"),
                (theme::CLASS_TEXT, "text"),
                (theme::CLASS_CONTROL, "control"),
                (theme::CLASS_HIGH, "high"),
                (theme::CLASS_FULL, "0xFF"),
            ] {
                theme::swatch(ui, colour, name);
            }
        }
    });
    for shape in [
        "Text: a dense cluster in 0x20–0x7E.",
        "Machine code: diagonal planes and streaks along a few opcode values.",
        "Compressed or random: a uniform cloud filling the cube.",
    ] {
        ui.label(RichText::new(shape).small().color(theme::TEXT_DIM));
    }
}

/// Move the cursor to the occurrence of `point`'s trigram nearest the
/// cursor, else to the first one counted.
fn jump_to_trigram(app: &mut ViewerApp, point: &TrigramPoint) {
    let window_start = app.cursor.saturating_sub(SEARCH_RADIUS);
    let window = app.document.read_range(window_start, SEARCH_RADIUS * 2);
    let target = closest_occurrence(&window, window_start, &point.exemplar, app.cursor).unwrap_or(point.offset);
    app.jump_to_offset(target);
    let [a, b, c] = point.exemplar;
    app.status = format!("Trigram {a:02X} {b:02X} {c:02X} at {target:#x}");
}

/// Absolute offset of the occurrence of `needle` in `haystack` (which starts
/// at `haystack_start`) closest to `target`.
fn closest_occurrence(haystack: &[u8], haystack_start: usize, needle: &[u8], target: usize) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, candidate)| *candidate == needle)
        .map(|(index, _)| haystack_start + index)
        .min_by_key(|&offset| offset.abs_diff(target))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    use super::*;
    use eframe::egui::Rect;
    use crate::app::Launch;
    use crate::document::Document;

    /// Longest a background job may take in a test.
    const JOB_TIMEOUT: Duration = Duration::from_secs(20);
    const EPSILON: f32 = 1e-5;

    /// Where the cube's eight corners land in a view filling `rect`.
    fn unit_corners_on_screen(camera: Camera, rect: Rect) -> Vec<Pos2> {
        let scale = rect.width() * CUBE_SCALE;
        let mut corners = Vec::new();
        for x in [0.0, 1.0] {
            for y in [0.0, 1.0] {
                for z in [0.0, 1.0] {
                    corners.push(rect.center() + camera.project([x, y, z]).0 * scale);
                }
            }
        }
        corners
    }

    type PanelHarness = Harness<'static, (TrigramState, ViewerApp)>;

    fn harness_for(bytes: Vec<u8>) -> PanelHarness {
        let mut app = ViewerApp::new(Launch::default());
        app.document = Document::from_bytes(bytes);
        Harness::new_ui_state(
            |ui, (state, app): &mut (TrigramState, ViewerApp)| show_trigram(state, app, ui),
            (TrigramState::default(), app),
        )
    }

    fn plot_whole_file(harness: &mut PanelHarness) {
        harness.step();
        harness.get_by_label_contains("Plot whole file").click();
        harness.step();
        let started = Instant::now();
        while harness.state().0.pending.is_some() && started.elapsed() < JOB_TIMEOUT {
            thread::sleep(POLL_INTERVAL / 5);
            harness.step();
        }
        harness.step();
    }

    #[test]
    fn plotting_text_from_the_button_draws_a_cloud_with_its_legend() {
        let text = "Plain text makes a tight cluster of points. ".repeat(200);
        let mut harness = harness_for(text.into_bytes());
        plot_whole_file(&mut harness);
        let cloud = harness.state().0.cloud.as_ref().expect("a finished cloud");
        assert!(!cloud.is_empty());
        assert!(harness.query_by_label_contains("uniform cloud").is_some());
    }

    #[test]
    fn an_empty_document_explains_that_there_is_nothing_to_plot() {
        let mut harness = harness_for(Vec::new());
        plot_whole_file(&mut harness);
        assert!(harness.query_by_label_contains("Too few bytes").is_some());
    }

    #[test]
    fn choosing_a_preset_turns_the_camera_but_keeps_the_zoom() {
        let mut harness = harness_for(b"abcabcabc".to_vec());
        harness.state_mut().0.camera.zoom = 2.0;
        harness.step();
        harness.get_by_label("Top (x/y)").click();
        harness.step();
        let camera = harness.state().0.camera;
        assert_eq!((camera.yaw, camera.pitch, camera.zoom), (Camera::TOP.yaw, Camera::TOP.pitch, 2.0));
    }

    #[test]
    fn the_top_view_shows_x_across_and_y_up_the_screen() {
        let (x_axis, _) = Camera::TOP.project([1.0, 0.5, 0.5]);
        let (y_axis, _) = Camera::TOP.project([0.5, 1.0, 0.5]);
        assert!((x_axis.x - 0.5).abs() < EPSILON && x_axis.y.abs() < EPSILON);
        assert!(y_axis.x.abs() < EPSILON && (y_axis.y + 0.5).abs() < EPSILON);
        // Looking down, higher z is nearer.
        assert!(Camera::TOP.project([0.5, 0.5, 1.0]).1 < Camera::TOP.project([0.5, 0.5, 0.0]).1);
    }

    #[test]
    fn the_front_view_shows_x_across_and_z_up_the_screen() {
        let (x_axis, _) = Camera::FRONT.project([1.0, 0.5, 0.5]);
        let (z_axis, _) = Camera::FRONT.project([0.5, 0.5, 1.0]);
        assert!((x_axis.x - 0.5).abs() < EPSILON && x_axis.y.abs() < EPSILON);
        assert!(z_axis.x.abs() < EPSILON && (z_axis.y + 0.5).abs() < EPSILON);
    }

    #[test]
    fn the_isometric_view_keeps_the_whole_cube_inside_the_view() {
        let rect = Rect::from_min_size(Pos2::ZERO, vec2(300.0, 300.0));
        assert!(unit_corners_on_screen(Camera::ISOMETRIC, rect).iter().all(|corner| rect.contains(*corner)));
    }

    #[test]
    fn dragging_never_tips_the_camera_past_straight_down() {
        let mut camera = Camera::ISOMETRIC;
        camera.rotate(vec2(0.0, 10_000.0));
        assert!((camera.pitch - FRAC_PI_2).abs() < EPSILON);
        camera.zoom_by(1e9);
        assert_eq!(camera.zoom, MAX_ZOOM);
    }

    #[test]
    fn a_clicked_trigram_is_found_at_the_occurrence_nearest_the_cursor() {
        let haystack = b"ABC.......ABC....ABC";
        assert_eq!(closest_occurrence(haystack, 1000, b"ABC", 1012), Some(1010));
        assert_eq!(closest_occurrence(haystack, 1000, b"ABC", 1019), Some(1017));
        assert_eq!(closest_occurrence(haystack, 1000, b"XYZ", 1000), None);
        assert_eq!(closest_occurrence(b"", 0, b"ABC", 0), None);
    }

    #[test]
    fn hovering_picks_the_closest_point_within_reach() {
        let placed = vec![
            PlacedPoint { index: 0, position: Pos2::new(10.0, 10.0), depth: 1.0, radius: 2.0 },
            PlacedPoint { index: 1, position: Pos2::new(13.0, 10.0), depth: 0.0, radius: 2.0 },
        ];
        assert_eq!(nearest_point(&placed, Pos2::new(12.5, 10.0)), Some(1));
        assert_eq!(nearest_point(&placed, Pos2::new(100.0, 100.0)), None);
    }
}
