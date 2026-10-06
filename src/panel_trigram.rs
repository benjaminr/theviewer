//! Dock panel: a rotatable 3D cloud of byte trigrams.
//!
//! Each point is a cell of the quantised trigram cube ([`crate::trigram`]):
//! x is a byte, y the byte after it and z the one after that. The cloud is
//! counted on a background thread and drawn with egui's painter in an
//! orthographic projection, far points first. Drag to rotate, scroll to zoom
//! and double-click to reset. Hovering a point names its trigram; a click
//! jumps to the occurrence of that trigram closest to the cursor.
//!
//! Points can be labelled by region. The file is segmented (or the report's
//! regions are used) and every trigram is attributed to the region type it
//! comes from, so each type forms its own coloured cluster with a label at its
//! centre. A legend shows or hides each type, a strip of the file under the
//! cube lights up the hovered type's regions, and a click jumps into a region
//! of the type the point belongs to. Plotting the whole file with a selection
//! highlights the selection's trigrams against everything else.

use std::f32::consts::{FRAC_PI_2, FRAC_PI_4};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Align2, Color32, FontId, Painter, Pos2, RichText, Sense, Stroke, Ui, Vec2, vec2};

use crate::app::ViewerApp;
use crate::compress::human_bytes;
use crate::explain::Region;
use crate::segments::{self, SegmentOptions};
use crate::raster::{Palette, byte_class_colour};
use crate::theme;
use crate::trigram::{self, LabelledSpan, MAX_GROUPS, TrigramCloud, TrigramCounter, TrigramPoint};

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
/// Most bytes segmented to label the cloud.
const SEGMENT_LIMIT: usize = 64 * 1024 * 1024;
/// Most bytes read when looking for a clicked trigram inside its region.
const REGION_SEARCH_LIMIT: usize = 16 * 1024 * 1024;
/// Height of the file strip under the cube.
const STRIP_HEIGHT: f32 = 14.0;
/// Opacity kept by points outside the selection, or outside the hovered type.
const DIMMED_ALPHA_FACTOR: f32 = 0.18;

/// What a point's colour shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PointColouring {
    /// The region type most of the point's trigrams come from.
    #[default]
    Region,
    /// The third byte's value, on the Viridis ramp.
    ThirdByte,
    /// The byte class (zero, text, control, high, 0xFF) of the middle byte.
    MiddleByteClass,
}

impl PointColouring {
    pub const ALL: [PointColouring; 3] = [PointColouring::Region, PointColouring::ThirdByte, PointColouring::MiddleByteClass];

    pub fn label(self) -> &'static str {
        match self {
            PointColouring::Region => "Colour by region",
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

/// Where the region labels come from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LabelSource {
    /// Segment the plotted range (automatic, typed regions).
    #[default]
    Segments,
    /// The report's regions, if the report has been run.
    ReportRegions,
    Nothing,
}

impl LabelSource {
    pub const ALL: [LabelSource; 3] = [LabelSource::Segments, LabelSource::ReportRegions, LabelSource::Nothing];

    pub fn label(self) -> &'static str {
        match self {
            LabelSource::Segments => "Label by segments",
            LabelSource::ReportRegions => "Label by report regions",
            LabelSource::Nothing => "No labels",
        }
    }
}

/// One type of region the cloud's trigrams are attributed to.
#[derive(Clone, Debug, PartialEq)]
pub struct RegionGroup {
    pub label: String,
    pub colour: Color32,
    /// The regions of this type, as (start, len).
    pub spans: Vec<(usize, usize)>,
    pub bytes: usize,
}

/// A finished count: the cloud, its region groups and the selection it
/// highlights.
struct Counted {
    cloud: TrigramCloud,
    groups: Vec<RegionGroup>,
    selection: Option<(usize, usize)>,
}

/// Everything the trigram panel keeps between frames.
pub struct TrigramState {
    pub colouring: PointColouring,
    pub camera: Camera,
    pub label_source: LabelSource,
    /// Plot the whole file even when there is a selection, highlighting it.
    pub whole_file: bool,
    /// Dim trigrams that do not occur in the highlighted selection.
    pub highlight_selection: bool,
    /// Region groups whose points are hidden.
    pub hidden: [bool; MAX_GROUPS],
    pending: Option<Receiver<Counted>>,
    /// The most recent finished cloud.
    pub cloud: Option<TrigramCloud>,
    /// The region groups the cloud's points refer to.
    pub groups: Vec<RegionGroup>,
    /// The selection highlighted in the cloud, if any.
    pub selection: Option<(usize, usize)>,
    /// The group under the pointer last frame (a point, legend row or strip).
    pub hovered_group: Option<u8>,
}

impl Default for TrigramState {
    fn default() -> Self {
        TrigramState {
            colouring: PointColouring::default(),
            camera: Camera::default(),
            label_source: LabelSource::default(),
            whole_file: false,
            highlight_selection: true,
            hidden: [false; MAX_GROUPS],
            pending: None,
            cloud: None,
            groups: Vec::new(),
            selection: None,
            hovered_group: None,
        }
    }
}

/// What the background job labels the cloud from.
enum LabelInput {
    /// The plotted bytes from `start`, to segment.
    Bytes { start: usize, bytes: Vec<u8> },
    Regions(Vec<Region>),
    Nothing,
}

/// A point placed on screen for this frame.
struct PlacedPoint {
    index: usize,
    position: Pos2,
    depth: f32,
    radius: f32,
}

/// The selection (unless the whole file is asked for), else the whole file,
/// with a word for which.
fn scope(state: &TrigramState, app: &ViewerApp) -> (usize, usize, &'static str) {
    match app.selection().filter(|_| !state.whole_file) {
        Some((start, len)) => (start, len, "selection"),
        None => (0, app.document.len(), "whole file"),
    }
}

/// Read the scope (sampled when large) and count it on a background thread,
/// labelling trigrams by region and highlighting the selection when the whole
/// file is plotted around it.
pub fn start_counting(state: &mut TrigramState, app: &mut ViewerApp) {
    app.note_tool_result(crate::dock::DockTab::Trigrams);
    let (start, len, _) = scope(state, app);
    let windows: Vec<(usize, Vec<u8>)> = trigram::sample_windows(len, trigram::SAMPLE_LIMIT, trigram::SAMPLE_WINDOW)
        .into_iter()
        .map(|(offset, size)| (start + offset, app.document.read_range(start + offset, size)))
        .collect();
    let selection = app.selection().filter(|&(selected, selected_len)| selected_len < len && selected >= start);
    let labels = match state.label_source {
        LabelSource::Segments => LabelInput::Bytes { start, bytes: app.document.read_range(start, len.min(SEGMENT_LIMIT)) },
        LabelSource::ReportRegions => LabelInput::Regions(app.bench.regions.clone()),
        LabelSource::Nothing => LabelInput::Nothing,
    };
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let groups = region_groups(labels);
        let spans = labelled_spans(&groups);
        let mut counter = TrigramCounter::with_labels(spans, groups.len(), selection);
        for (offset, bytes) in &windows {
            counter.add_window(*offset, bytes);
        }
        let cloud = counter.finish(start, len, trigram::DEFAULT_MAX_POINTS);
        // The receiver may be gone if the panel was closed; nothing to do then.
        let _ = sender.send(Counted { cloud, groups, selection });
    });
    state.pending = Some(receiver);
}

/// The region groups to label the cloud with, at most [`MAX_GROUPS`].
fn region_groups(input: LabelInput) -> Vec<RegionGroup> {
    match input {
        LabelInput::Bytes { start, bytes } => {
            let segmentation = segments::segment_file(&bytes, &SegmentOptions::default());
            let mut groups: Vec<RegionGroup> = segmentation
                .types
                .iter()
                .take(MAX_GROUPS)
                .map(|kind| RegionGroup { label: kind.label.clone(), colour: kind.colour, spans: Vec::new(), bytes: 0 })
                .collect();
            for segment in &segmentation.segments {
                if let Some(group) = groups.get_mut(segment.type_id) {
                    group.spans.push((start + segment.start, segment.len));
                    group.bytes += segment.len;
                }
            }
            groups
        }
        LabelInput::Regions(regions) => {
            let mut groups: Vec<RegionGroup> = Vec::new();
            for region in regions {
                let label = region.kind.label();
                let index = match groups.iter().position(|group| group.label == label) {
                    Some(index) => index,
                    None if groups.len() < MAX_GROUPS => {
                        groups.push(RegionGroup { label: label.to_string(), colour: region.kind.colour(), spans: Vec::new(), bytes: 0 });
                        groups.len() - 1
                    }
                    None => continue,
                };
                groups[index].spans.push((region.start, region.len));
                groups[index].bytes += region.len;
            }
            groups
        }
        LabelInput::Nothing => Vec::new(),
    }
}

/// Every group's regions as labelled spans for the counter.
fn labelled_spans(groups: &[RegionGroup]) -> Vec<LabelledSpan> {
    groups
        .iter()
        .enumerate()
        .flat_map(|(group, region_group)| {
            region_group.spans.iter().map(move |&(start, len)| LabelledSpan { start, end: start + len, group: group as u8 })
        })
        .collect()
}

fn poll(state: &mut TrigramState, ctx: &egui::Context) {
    let Some(receiver) = &state.pending else { return };
    match receiver.try_recv() {
        Ok(counted) => {
            state.cloud = Some(counted.cloud);
            state.groups = counted.groups;
            state.selection = counted.selection;
            state.hidden = [false; MAX_GROUPS];
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
            RichText::new("Plots every run of three bytes as a point in a 256 × 256 × 256 cube. Different kinds of data make different shapes; labelled by region, each part of the file forms its own coloured cluster.")
                .color(theme::TEXT_DIM),
        );
        return;
    };
    if cloud.is_empty() {
        ui.label(RichText::new("Too few bytes to plot; select at least three.").color(theme::TEXT_DIM));
        return;
    }
    // Wrapped, so a long caption cannot widen the panel and push the
    // controls after it out of reach.
    ui.add(egui::Label::new(RichText::new(caption(cloud)).small().color(theme::TEXT_DIM)).wrap());

    let mut hovered = None;
    let jump = show_cube(state, ui, &mut hovered);
    show_legend(state, ui, &mut hovered);
    if let Some(offset) = show_file_strip(state, ui, &mut hovered) {
        app.jump_to_offset(offset);
    }
    state.hovered_group = hovered;
    if let Some(point) = jump {
        jump_to_trigram(app, &point, &state.groups);
    }
}

fn show_toolbar(state: &mut TrigramState, app: &mut ViewerApp, ui: &mut Ui) {
    let (_, len, what) = scope(state, app);
    ui.horizontal_wrapped(|ui| {
        if ui.button(format!("Plot {what} ({})", human_bytes(len))).clicked() {
            start_counting(state, app);
        }
        start_row_unless_fits(ui, combo_width(ui));
        egui::ComboBox::from_id_salt("trigram-labels").selected_text(state.label_source.label()).show_ui(ui, |ui| {
            for source in LabelSource::ALL {
                ui.selectable_value(&mut state.label_source, source, source.label());
            }
        });
        start_row_unless_fits(ui, combo_width(ui));
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
        if app.selection().is_some() {
            ui.checkbox(&mut state.whole_file, "Whole file, selection highlighted")
                .on_hover_text("Plot everything and pick out the selection's trigrams against the rest");
        }
        if state.selection.is_some() {
            ui.checkbox(&mut state.highlight_selection, "Dim the rest");
        }
        if state.pending.is_some() {
            ui.spinner();
            ui.label(RichText::new("Counting trigrams…").color(theme::TEXT_DIM));
        }
    });
    if state.label_source == LabelSource::ReportRegions && app.bench.regions.is_empty() {
        ui.horizontal(|ui| {
            ui.label(RichText::new("The report has not been run, so there are no regions to label with.").small().color(theme::TEXT_DIM));
            if ui.small_button("Run the report").clicked() {
                app.start_report();
            }
        });
    }
}

/// Width a combo box takes: its set width plus the arrow beside it.
fn combo_width(ui: &Ui) -> f32 {
    ui.spacing().combo_width + ui.spacing().icon_width + ui.spacing().button_padding.x * 2.0
}

/// In a wrapping row, start a new row unless `width` fits on this one. Combo
/// boxes do not wrap by themselves, so without this they run off the edge.
fn start_row_unless_fits(ui: &mut Ui, width: f32) {
    let at_row_start = ui.cursor().min.x <= ui.max_rect().min.x + 1.0;
    if !at_row_start && width > ui.available_size_before_wrap().x {
        ui.end_row();
    }
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

/// Whether `point` is drawn: its region type is not hidden.
fn is_visible(state: &TrigramState, point: &TrigramPoint) -> bool {
    point.dominant_group().is_none_or(|group| !state.hidden.get(group as usize).copied().unwrap_or(false))
}

/// Draw the cube and handle rotation, zoom and hovering. Returns the point
/// clicked, if any, and notes the region type under the pointer.
fn show_cube(state: &mut TrigramState, ui: &mut Ui, hovered_group: &mut Option<u8>) -> Option<TrigramPoint> {
    // Never wider than the pane, so nothing after the cube is pushed out of reach.
    let width = ui.available_width();
    let side = width.min(ui.available_height() - LEGEND_HEIGHT).max(MIN_VIEW_SIDE.min(width));
    let (response, painter) = ui.allocate_painter(vec2(width, side), Sense::click_and_drag());
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

    let cloud = state.cloud.as_ref()?;
    let scale = side * CUBE_SCALE;
    let camera = state.camera;
    let to_screen = |unit: [f32; 3]| {
        let (offset, depth) = camera.project(unit);
        (rect.center() + offset * scale, depth)
    };
    draw_cube_frame(&painter, &to_screen);

    let visible: Vec<TrigramPoint> = cloud.points.iter().filter(|point| is_visible(state, point)).cloned().collect();
    let placed = place_points(&visible, &to_screen);
    let hovered = response.hover_pos().and_then(|pointer| nearest_point(&placed, pointer));
    for point in &placed {
        painter.circle_filled(point.position, point.radius, point_colour(state, &visible[point.index]));
    }

    let hovered_point = hovered.map(|placed_index| &placed[placed_index]);
    if let Some(point) = hovered_point {
        painter.circle_stroke(point.position, point.radius + 2.0, Stroke::new(1.5, theme::CURSOR));
        *hovered_group = visible[point.index].dominant_group();
    }
    let clicked = hovered_point.filter(|_| response.clicked()).map(|point| visible[point.index].clone());
    if let Some(point) = hovered_point {
        response.on_hover_text(describe_point(&visible[point.index], cloud.total_trigrams, &state.groups));
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

/// A point's colour: by region, value or class, then dimmed when it is not
/// part of the highlighted selection or the hovered region type.
fn point_colour(state: &TrigramState, point: &TrigramPoint) -> Color32 {
    let region_colour = point.dominant_group().and_then(|group| state.groups.get(group as usize)).map(|group| group.colour);
    let base = match (state.colouring, region_colour) {
        (PointColouring::Region, Some(colour)) => colour,
        (PointColouring::Region, None) if !state.groups.is_empty() => theme::TEXT_DIM,
        (PointColouring::MiddleByteClass, _) => byte_class_colour(point.exemplar[1]),
        _ => Palette::Viridis.lut()[point.value_range(2).0 as usize],
    };
    let mut alpha = MIN_POINT_ALPHA + (255.0 - MIN_POINT_ALPHA) * point.weight.clamp(0.0, 1.0);
    let outside_selection = state.selection.is_some() && state.highlight_selection && point.in_selection == 0;
    let outside_hovered = state.hovered_group.is_some_and(|group| point.dominant_group() != Some(group));
    if outside_selection || outside_hovered {
        alpha *= DIMMED_ALPHA_FACTOR;
    }
    Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), alpha as u8)
}

/// Hover text for a point: its trigram, the cell it stands for, its count and
/// the region types it comes from.
fn describe_point(point: &TrigramPoint, total: u64, groups: &[RegionGroup]) -> String {
    let [a, b, c] = point.exemplar;
    let printable = |byte: u8| if (0x20..=0x7E).contains(&byte) { byte as char } else { '·' };
    let range = |axis: usize| {
        let (low, high) = point.value_range(axis);
        format!("{low:02X}–{high:02X}")
    };
    let share = point.count as f64 / total.max(1) as f64 * 100.0;
    let mut text = format!(
        "{a:02X} {b:02X} {c:02X}  \"{}{}{}\"\nCell x {} · y {} · z {}\n{} trigrams in this cell ({share:.2}%)\nFirst at {:#x}",
        printable(a),
        printable(b),
        printable(c),
        range(0),
        range(1),
        range(2),
        point.count,
        point.offset
    );
    let labelled: u32 = point.groups.iter().map(|&(_, count)| count).sum();
    for &(group, count) in point.groups.iter().take(3) {
        if let Some(region) = groups.get(group as usize) {
            text.push_str(&format!("\n{}: {:.0}%", region.label, count as f64 / labelled.max(1) as f64 * 100.0));
        }
    }
    if point.in_selection > 0 {
        text.push_str(&format!("\n{} in the selection", point.in_selection));
    }
    text.push_str(if point.groups.is_empty() {
        "\nClick to jump to the one nearest the cursor"
    } else {
        "\nClick to jump into a region of its main type"
    });
    text
}

/// The legend: one row per region type (with a checkbox to show or hide it),
/// or the colour key, and the typical shapes.
fn show_legend(state: &mut TrigramState, ui: &mut Ui, hovered_group: &mut Option<u8>) {
    if state.colouring == PointColouring::Region && !state.groups.is_empty() {
        ui.horizontal_wrapped(|ui| {
            // One widget per entry, so entries wrap whole and stay clickable
            // however narrow the pane is.
            for (index, group) in state.groups.iter().enumerate() {
                let mut shown = !state.hidden[index];
                let job = legend_entry(ui, group);
                // Start a new row when the entry would not fit on this one.
                let text_width = ui.painter().layout_job(job.clone()).size().x;
                let entry_width = text_width + ui.spacing().icon_width + ui.spacing().icon_spacing;
                let at_row_start = ui.cursor().min.x <= ui.max_rect().min.x + 1.0;
                if !at_row_start && entry_width > ui.available_size_before_wrap().x {
                    ui.end_row();
                }
                let entry = ui.checkbox(&mut shown, job).on_hover_text("Show or hide this region type");
                if entry.changed() {
                    state.hidden[index] = !shown;
                }
                if entry.hovered() {
                    *hovered_group = Some(index as u8);
                }
            }
        });
    } else {
        ui.horizontal_wrapped(|ui| match state.colouring {
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
            _ => {
                ui.label(RichText::new("Colour: third byte, dark (0x00) to yellow (0xFF). Size and opacity: how common.").small().color(theme::TEXT_DIM));
            }
        });
    }
    for shape in [
        "Text: a dense cluster in 0x20–0x7E.",
        "Machine code: diagonal planes and streaks along a few opcode values.",
        "Compressed or random: a uniform cloud filling the cube.",
    ] {
        ui.add(egui::Label::new(RichText::new(shape).small().color(theme::TEXT_DIM)).wrap());
    }
}

/// A legend entry's text: a square in the type's colour, then its name, how
/// many regions it has and their size.
fn legend_entry(ui: &Ui, group: &RegionGroup) -> egui::text::LayoutJob {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let mut job = egui::text::LayoutJob::default();
    // A layout job does not wrap unless told to. Wrap at a whole row (less the
    // tick box), so an entry moves to a new row first and only wraps its own
    // text when it is wider than the pane.
    job.wrap.max_width = (ui.max_rect().width() - ui.spacing().icon_width - ui.spacing().icon_spacing).max(1.0);
    job.append("■ ", 0.0, egui::TextFormat { font_id: font.clone(), color: group.colour, ..Default::default() });
    job.append(
        &format!("{} ({}, {})", group.label, group.spans.len(), human_bytes(group.bytes)),
        0.0,
        egui::TextFormat { font_id: font, color: theme::TEXT, ..Default::default() },
    );
    job
}

/// A strip of the plotted range with each region coloured by type; the
/// hovered type stands out. Returns the offset clicked, if any.
fn show_file_strip(state: &TrigramState, ui: &mut Ui, hovered_group: &mut Option<u8>) -> Option<usize> {
    let cloud = state.cloud.as_ref()?;
    if state.groups.is_empty() || cloud.len == 0 {
        return None;
    }
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), STRIP_HEIGHT), Sense::click());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 2.0, theme::BACKGROUND);
    let x_of = |offset: usize| rect.left() + (offset.saturating_sub(cloud.start) as f32 / cloud.len as f32) * rect.width();
    let emphasis = state.hovered_group;
    for (index, group) in state.groups.iter().enumerate() {
        let dimmed = emphasis.is_some_and(|hovered| hovered as usize != index) || state.hidden[index];
        let colour = if dimmed { group.colour.gamma_multiply(DIMMED_ALPHA_FACTOR) } else { group.colour };
        for &(start, len) in &group.spans {
            let span = egui::Rect::from_x_y_ranges(x_of(start)..=x_of(start + len).max(x_of(start) + 1.0), rect.y_range());
            painter.rect_filled(span, 0.0, colour);
        }
    }
    if let Some((start, len)) = state.selection {
        let span = egui::Rect::from_x_y_ranges(x_of(start)..=x_of(start + len).max(x_of(start) + 2.0), rect.y_range());
        painter.rect_stroke(span, 0.0, Stroke::new(1.5, theme::CURSOR), egui::StrokeKind::Inside);
    }
    let pointer_offset = response.hover_pos().map(|pointer| {
        cloud.start + (((pointer.x - rect.left()) / rect.width()).clamp(0.0, 1.0) * cloud.len as f32) as usize
    });
    if let Some(offset) = pointer_offset {
        let under = state.groups.iter().position(|group| group.spans.iter().any(|&(start, len)| offset >= start && offset < start + len));
        if let Some(index) = under {
            *hovered_group = Some(index as u8);
            response.clone().on_hover_text(format!("{} at {offset:#x}; click to jump", state.groups[index].label));
        }
    }
    pointer_offset.filter(|_| response.clicked())
}

/// Move the cursor to an occurrence of `point`'s cell: inside a region of its
/// main type when it has one, nearest the cursor; else to the occurrence of
/// its first trigram nearest the cursor, else to the first one counted.
fn jump_to_trigram(app: &mut ViewerApp, point: &TrigramPoint, groups: &[RegionGroup]) {
    let in_region = point
        .dominant_group()
        .and_then(|group| groups.get(group as usize))
        .and_then(|group| nearest_cell_occurrence(app, &group.spans, point.cell).map(|offset| (offset, group.label.clone())));
    let (target, place) = match in_region {
        Some((offset, label)) => (offset, format!(" in {label}")),
        None => {
            let window_start = app.cursor.saturating_sub(SEARCH_RADIUS);
            let window = app.document.read_range(window_start, SEARCH_RADIUS * 2);
            (closest_occurrence(&window, window_start, &point.exemplar, app.cursor).unwrap_or(point.offset), String::new())
        }
    };
    app.jump_to_offset(target);
    let [a, b, c] = point.exemplar;
    app.status = format!("Trigram {a:02X} {b:02X} {c:02X} cell at {target:#x}{place}");
}

/// The occurrence, inside `spans`, of any trigram in `cell` that is nearest
/// the cursor, reading at most [`REGION_SEARCH_LIMIT`] bytes, nearest spans first.
fn nearest_cell_occurrence(app: &mut ViewerApp, spans: &[(usize, usize)], cell: [u8; 3]) -> Option<usize> {
    let cursor = app.cursor;
    let mut ordered: Vec<(usize, usize)> = spans.to_vec();
    let distance = |&(start, len): &(usize, usize)| if cursor < start { start - cursor } else { cursor.saturating_sub(start + len) };
    ordered.sort_by_key(distance);
    let mut budget = REGION_SEARCH_LIMIT;
    let mut best: Option<usize> = None;
    for (start, len) in ordered {
        if budget == 0 {
            break;
        }
        let bytes = app.document.read_range(start, len.min(budget));
        budget -= bytes.len();
        let found = bytes
            .windows(3)
            .enumerate()
            .filter(|(_, trigram)| trigram::cell_of([trigram[0], trigram[1], trigram[2]]) == cell)
            .map(|(index, _)| start + index)
            .min_by_key(|&offset| offset.abs_diff(cursor));
        best = match (best, found) {
            (Some(known), Some(new)) => Some(if new.abs_diff(cursor) < known.abs_diff(cursor) { new } else { known }),
            (known, new) => known.or(new),
        };
    }
    best
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

    /// Text, then zeros, then pseudo-random bytes: three kinds of region.
    fn three_part_file() -> (Vec<u8>, std::ops::Range<usize>) {
        let mut bytes = "Readable sentences make a tight printable cluster. ".repeat(400).into_bytes();
        let text = 0..bytes.len();
        bytes.extend(std::iter::repeat_n(0u8, 16 * 1024));
        let mut state = 0x2545_F491_u32;
        bytes.extend((0..16 * 1024).map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        }));
        (bytes, text)
    }

    #[test]
    fn plotting_attributes_each_kind_of_data_to_its_own_region_type() {
        let (bytes, _) = three_part_file();
        let mut harness = harness_for(bytes);
        plot_whole_file(&mut harness);
        let (state, _) = harness.state();
        assert!(state.groups.len() >= 2, "{:?}", state.groups.iter().map(|g| &g.label).collect::<Vec<_>>());
        let cloud = state.cloud.as_ref().unwrap();
        assert!(cloud.points.iter().any(|point| point.dominant_group().is_some()));
        let text_group = cloud.points.iter().find(|point| point.exemplar == *b"Rea").and_then(TrigramPoint::dominant_group).expect("text is labelled");
        let zero_group = cloud.points.iter().find(|point| point.exemplar == [0, 0, 0]).and_then(TrigramPoint::dominant_group).expect("zeros are labelled");
        assert_ne!(text_group, zero_group, "text and padding are different region types");
    }

    #[test]
    fn hiding_a_region_type_hides_its_points() {
        let (bytes, _) = three_part_file();
        let mut harness = harness_for(bytes);
        plot_whole_file(&mut harness);
        let (state, _) = harness.state_mut();
        let point = state.cloud.as_ref().unwrap().points.iter().find(|point| point.exemplar == [0, 0, 0]).unwrap().clone();
        assert!(is_visible(state, &point));
        state.hidden[point.dominant_group().unwrap() as usize] = true;
        assert!(!is_visible(state, &point));
    }

    #[test]
    fn plotting_the_whole_file_counts_the_selections_trigrams_apart() {
        let (bytes, text) = three_part_file();
        let mut harness = harness_for(bytes);
        {
            let (state, app) = harness.state_mut();
            app.set_cursor(text.start, false);
            app.set_cursor(text.end, true);
            state.whole_file = true;
        }
        plot_whole_file(&mut harness);
        let (state, _) = harness.state();
        assert_eq!(state.selection, Some((text.start, text.end - text.start)));
        let cloud = state.cloud.as_ref().unwrap();
        let text_point = cloud.points.iter().find(|point| point.exemplar == *b"Rea").unwrap();
        let zero_point = cloud.points.iter().find(|point| point.exemplar == [0, 0, 0]).unwrap();
        assert!(text_point.in_selection > 0);
        assert_eq!(zero_point.in_selection, 0, "zeros are outside the selected text");
    }

    #[test]
    fn a_clicked_point_jumps_into_a_region_of_its_type() {
        let (bytes, text) = three_part_file();
        let mut harness = harness_for(bytes);
        plot_whole_file(&mut harness);
        let (state, app) = harness.state_mut();
        app.set_cursor(app.document.len() - 1, false);
        let point = state.cloud.as_ref().unwrap().points.iter().find(|point| point.exemplar == *b"Rea").unwrap().clone();
        jump_to_trigram(app, &point, &state.groups);
        assert!(text.contains(&app.cursor), "landed at {:#x}, inside the text", app.cursor);
        assert!(app.status.contains(" in "), "{}", app.status);
    }

    #[test]
    fn in_a_narrow_pane_every_legend_entry_wraps_into_reach_and_can_be_ticked() {
        let (bytes, _) = three_part_file();
        let mut app = ViewerApp::new(Launch::default());
        app.document = Document::from_bytes(bytes);
        let pane_width = 300.0;
        let mut harness = Harness::builder().with_size(vec2(pane_width, 1400.0)).build_ui_state(
            |ui, (state, app): &mut (TrigramState, ViewerApp)| show_trigram(state, app, ui),
            (TrigramState::default(), app),
        );
        plot_whole_file(&mut harness);
        let groups: Vec<RegionGroup> = harness.state().0.groups.clone();
        assert!(groups.len() >= 2);
        for (index, group) in groups.iter().enumerate() {
            let needle = format!("{} (", group.label);
            let entry = harness.get_by_label_contains(&needle);
            let rect = entry.rect();
            assert!(rect.right() <= pane_width + 1.0, "{} reaches {} in a {pane_width} pane", group.label, rect.right());
            entry.click();
            harness.step();
            assert!(harness.state().0.hidden[index], "ticking {} hides it", group.label);
        }
    }

    #[test]
    fn hovering_a_legend_entry_highlights_that_region_type() {
        let (bytes, _) = three_part_file();
        let mut harness = harness_for(bytes);
        plot_whole_file(&mut harness);
        let label = harness.state().0.groups[0].label.clone();
        let needle = format!("{label} (");
        harness.get_by_label_contains(&needle).hover();
        harness.step();
        harness.step();
        assert_eq!(harness.state().0.hovered_group, Some(0), "the hovered type is highlighted");
    }
}
