//! Structure map panel: automatic segmentation of the file into typed
//! regions, "find more like this" for the selection, and feature tracks that
//! show how entropy, byte kinds and the local record width change along the
//! file. The analysis lives in [`crate::segments`], [`crate::similar`] and
//! [`crate::tracks`]; this panel runs it on background threads and draws it.

use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Color32, CornerRadius, Rect, RichText, Sense, Stroke, Ui, pos2, vec2};

use crate::api::Caller;
use crate::api::findings::PublishParams;
use crate::api::tools::structure_map::{SCAN_LIMIT, run_segmentation, run_similar, run_tracks};
use crate::app::ViewerApp;
use crate::compress::human_bytes;
use crate::features::KindMix;
use crate::plugin::{Category, Finding};
use crate::segments::Segmentation;
use crate::similar::{self, SimilarError, SimilarOptions, SimilarRegion, SimilarityScores};
use crate::theme;
use crate::tracks::{self, FeatureTracks};

/// How often to look for a finished background job.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const STRIP_HEIGHT: f32 = 28.0;
const TRACK_HEIGHT: f32 = 26.0;
const TRACK_LABEL_WIDTH: f32 = 104.0;
const TRACK_LABEL_SIZE: f32 = 12.0;
const LIST_HEIGHT: f32 = 220.0;
/// Pinned findings from the segmentation start with this.
const SEGMENT_ID_PREFIX: &str = "segment:";
/// Pinned findings from the similarity search start with this.
const SIMILAR_ID_PREFIX: &str = "similar:";
/// The `source` of pinned findings.
const FINDING_SOURCE: &str = "structure map";
/// Category of pinned similarity matches.
const SIMILAR_CATEGORY: Category = Category::Custom;
/// Largest LZ4 ratio drawn; matches the cap in [`crate::features`].
const MAX_COMPRESSION_RATIO: f32 = 1.2;
/// Largest byte entropy in bits.
const MAX_ENTROPY: f32 = 8.0;

/// Identifies the document a result was computed from, to flag stale results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DocumentKey {
    len: usize,
    version: u64,
}

impl DocumentKey {
    fn of(app: &ViewerApp) -> Self {
        DocumentKey { len: app.document.len(), version: app.document.version() }
    }
}

struct SegmentJob {
    key: DocumentKey,
    result: Segmentation,
}

struct SimilarJob {
    key: DocumentKey,
    result: Result<SimilarityScores, SimilarError>,
}

struct TracksJob {
    key: DocumentKey,
    tracks: FeatureTracks,
}

/// The similarity search's adjustable settings.
pub struct SimilarSettings {
    /// Similarity a block needs to match (0 to 1).
    pub threshold: f32,
    /// 0 compares statistics only, 1 the coarse histogram only.
    pub histogram_weight: f32,
}

impl Default for SimilarSettings {
    fn default() -> Self {
        SimilarSettings { threshold: similar::DEFAULT_THRESHOLD, histogram_weight: SimilarOptions::default().histogram_weight }
    }
}

/// State of the structure map panel.
#[derive(Default)]
pub struct StructureMapState {
    segments_pending: Option<Receiver<SegmentJob>>,
    segments: Option<SegmentJob>,
    similar_pending: Option<Receiver<SimilarJob>>,
    similar: Option<SimilarJob>,
    similar_settings: SimilarSettings,
    tracks_pending: Option<Receiver<TracksJob>>,
    tracks: Option<TracksJob>,
    /// The track point last clicked, for "Use width here".
    picked_point: Option<usize>,
}

impl StructureMapState {
    /// Whether segments, matches or tracks are being worked out.
    pub fn is_busy(&self) -> bool {
        self.segments_pending.is_some() || self.similar_pending.is_some() || self.tracks_pending.is_some()
    }

    /// Collect any finished background results. New segments replace the
    /// pinned ones, if they were pinned.
    fn poll(&mut self, app: &mut ViewerApp) {
        if let Some(job) = receive(&mut self.segments_pending) {
            if person_pinned(app, SEGMENT_ID_PREFIX) {
                // The person's pins, kept up to date by the tool: not a step of theirs.
                let params = PublishParams { doc: None, findings: segment_findings(&job.result), key: SEGMENT_ID_PREFIX.to_string() };
                let _ = crate::api::findings::publish(app, &Caller::Panel, params);
            }
            self.segments = Some(job);
        }
        if let Some(job) = receive(&mut self.similar_pending) {
            self.similar = Some(job);
        }
        if let Some(job) = receive(&mut self.tracks_pending) {
            self.tracks = Some(job);
            self.picked_point = None;
        }
    }
}

/// A finished job from `pending`, clearing it once finished or abandoned.
fn receive<T>(pending: &mut Option<Receiver<T>>) -> Option<T> {
    let receiver = pending.as_ref()?;
    match receiver.try_recv() {
        Ok(job) => {
            *pending = None;
            Some(job)
        }
        Err(mpsc::TryRecvError::Empty) => None,
        Err(mpsc::TryRecvError::Disconnected) => {
            *pending = None;
            None
        }
    }
}

/// What the user asked for this frame; applied after drawing.
enum Action {
    Select { start: usize, len: usize, title: String },
    Jump(usize),
    SetWidth(usize),
    PinSegments,
    ClearSegments,
    PinSimilar,
    ClearSimilar,
}

/// Show the structure map panel.
pub fn show_structure_map(state: &mut StructureMapState, app: &mut ViewerApp, ui: &mut egui::Ui) {
    state.poll(app);
    if state.is_busy() {
        ui.ctx().request_repaint_after(POLL_INTERVAL);
    }
    let mut actions = Vec::new();
    egui::ScrollArea::vertical().id_salt("structure-map-panel").show(ui, |ui| {
        egui::CollapsingHeader::new(RichText::new("Segments").strong()).id_salt("structure-map-segments").default_open(true).show(ui, |ui| {
            show_segments(state, app, ui, &mut actions);
        });
        egui::CollapsingHeader::new(RichText::new("Find more like this").strong()).id_salt("structure-map-similar").default_open(true).show(ui, |ui| {
            show_similar(state, app, ui, &mut actions);
        });
        egui::CollapsingHeader::new(RichText::new("Feature tracks").strong()).id_salt("structure-map-tracks").default_open(true).show(ui, |ui| {
            show_tracks(state, app, ui, &mut actions);
        });
    });
    for action in actions {
        apply(state, app, action);
    }
}

fn apply(state: &StructureMapState, app: &mut ViewerApp, action: Action) {
    match action {
        Action::Select { start, len, title } => {
            let finding = Finding::new("structure-map:selection", FINDING_SOURCE, Category::Custom, start, len.max(1)).title(title);
            app.select_finding(&finding);
        }
        Action::Jump(offset) => app.go_to_offset(offset),
        Action::SetWidth(width) => app.change_width(width),
        Action::PinSegments => {
            let findings = state.segments.as_ref().map(|job| segment_findings(&job.result)).unwrap_or_default();
            pin(app, SEGMENT_ID_PREFIX, findings);
        }
        Action::ClearSegments => unpin(app, SEGMENT_ID_PREFIX),
        Action::PinSimilar => {
            let findings = match &state.similar {
                Some(SimilarJob { result: Ok(scores), .. }) => similar_findings(&similar::matching_regions(scores, state.similar_settings.threshold)),
                _ => Vec::new(),
            };
            pin(app, SIMILAR_ID_PREFIX, findings);
        }
        Action::ClearSimilar => unpin(app, SIMILAR_ID_PREFIX),
    }
}

/// Pin `findings` on the file map for the person, under `key` in place of
/// those pinned there before, through `findings.publish`.
fn pin(app: &mut ViewerApp, key: &str, findings: Vec<Finding>) {
    let findings = serde_json::to_value(findings).unwrap_or_default();
    let _ = app.perform("findings.publish", serde_json::json!({ "findings": findings, "key": key }));
}

/// Take the findings pinned under `key` off the file map for the person,
/// through `findings.retract`.
fn unpin(app: &mut ViewerApp, key: &str) {
    let _ = app.perform("findings.retract", serde_json::json!({ "key": key }));
}

/// Whether the person has findings pinned under `key` on the document shown.
fn person_pinned(app: &ViewerApp, key: &str) -> bool {
    let document = app.document_id();
    app.bus.facts().any(|fact| {
        fact.topic() == crate::bus::Topic::FindingsPublished && fact.producer() == Caller::Panel.producer() && fact.draft.key == key && fact.draft.document.as_deref() == Some(document.as_str())
    })
}

/// "(document changed since this scan)" when the document has changed.
fn stale_marker(ui: &mut Ui, key: DocumentKey, app: &ViewerApp) {
    if key != DocumentKey::of(app) {
        ui.label(RichText::new("(document changed since this scan)").small().color(theme::CURSOR));
    }
}

/// The analysed prefix of the document and the key of the document it came from.
fn read_scanned(app: &mut ViewerApp) -> (DocumentKey, Vec<u8>) {
    let key = DocumentKey::of(app);
    (key, app.document.read_range(0, key.len.min(SCAN_LIMIT)))
}

/// The x position of `offset` in `rect`, for data of `total` bytes.
fn x_of(rect: Rect, offset: usize, total: usize) -> f32 {
    rect.min.x + rect.width() * offset as f32 / total.max(1) as f32
}

/// The offset under x position `x` in `rect`, for data of `total` bytes.
fn offset_at(rect: Rect, x: f32, total: usize) -> usize {
    let fraction = ((x - rect.min.x) / rect.width().max(1.0)).clamp(0.0, 1.0);
    ((fraction * total as f32) as usize).min(total.saturating_sub(1))
}

// ---------------------------------------------------------------------------
// Segments
// ---------------------------------------------------------------------------

/// Work out again, from the edited document, what had been worked out:
/// the segments and the feature tracks. Results arrive in the background
/// and replace pinned segments.
pub(crate) fn refresh(state: &mut StructureMapState, app: &mut ViewerApp) {
    if state.segments.is_some() || state.segments_pending.is_some() {
        start_segmentation(state, app, TOOL_PRODUCER);
    }
    if state.tracks.is_some() || state.tracks_pending.is_some() {
        start_tracks(state, app, TOOL_PRODUCER);
    }
}

/// Who the work the tool does by itself (a refresh after an edit) is by.
const TOOL_PRODUCER: &str = "tool:structure-map";

/// Run `work` with the panel's state taken out of `app`, for a method that
/// starts the panel's work.
fn with_state<R>(app: &mut ViewerApp, work: impl FnOnce(&mut StructureMapState, &mut ViewerApp) -> R) -> R {
    let mut state = std::mem::take(&mut app.bench.panels.structure_map);
    let result = work(&mut state, app);
    app.bench.panels.structure_map = state;
    result
}

/// Segment the document as `producer`'s job and show the segments here:
/// what `structure_map.segment` does in the window. Returns the job.
pub fn segment_as(app: &mut ViewerApp, producer: &str) -> String {
    with_state(app, |state, app| start_segmentation(state, app, producer))
}

/// Find the parts like `span` as `producer`'s job and list them here:
/// what `structure_map.find_similar` does in the window. Returns the job.
pub fn find_similar_as(app: &mut ViewerApp, span: (usize, usize), histogram_weight: f32, threshold: f32, producer: &str) -> String {
    with_state(app, |state, app| {
        state.similar_settings = SimilarSettings { threshold, histogram_weight };
        start_similar(state, app, span, producer)
    })
}

/// Measure the tracks as `producer`'s job and draw them here: what
/// `structure_map.tracks` does in the window. Returns the job.
pub fn tracks_as(app: &mut ViewerApp, producer: &str) -> String {
    with_state(app, |state, app| start_tracks(state, app, producer))
}

/// Collect finished results while the panel is not drawn, so pinned
/// segments follow edits even when the panel is hidden.
pub fn follow_document(state: &mut StructureMapState, app: &mut ViewerApp) {
    state.poll(app);
}

/// Start a job of `producer`'s, about the document shown.
fn start_job_as(app: &mut ViewerApp, kind: &str, title: &str, producer: &str) -> crate::bus::JobHandle {
    let document = Some((app.document_id(), app.document.version()));
    app.bus.start_job(kind, title, producer, document)
}

fn start_segmentation(state: &mut StructureMapState, app: &mut ViewerApp, producer: &str) -> String {
    app.note_tool_result(crate::dock::DockTab::StructureMap);
    let (key, bytes) = read_scanned(app);
    let (sender, receiver) = mpsc::channel();
    let job = start_job_as(app, "structure-map", "Segmenting the file", producer);
    let id = job.id().to_string();
    thread::spawn(move || {
        if let Some(result) = run_segmentation(&bytes, &job) {
            let _ = sender.send(SegmentJob { key, result });
        }
    });
    state.segments_pending = Some(receiver);
    id
}

fn segment_findings(result: &Segmentation) -> Vec<Finding> {
    result
        .segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            let category = result.types.get(segment.type_id).map_or(Category::Custom, |segment_type| segment_type.category);
            Finding::new(format!("{SEGMENT_ID_PREFIX}{index}"), FINDING_SOURCE, category, segment.start, segment.len.max(1))
                .title(format!("Segment: {}", segment.label))
                .detail(segment.reason.clone())
        })
        .collect()
}

fn show_segments(state: &mut StructureMapState, app: &mut ViewerApp, ui: &mut Ui, actions: &mut Vec<Action>) {
    ui.horizontal_wrapped(|ui| {
        let size = human_bytes(app.document.len().min(SCAN_LIMIT));
        if ui.add_enabled(state.segments_pending.is_none(), egui::Button::new(format!("Segment file ({size})"))).clicked() {
            app.perform_later("structure_map.segment", serde_json::json!({}));
        }
        if state.segments_pending.is_some() {
            ui.spinner();
        }
        let has_result = state.segments.as_ref().is_some_and(|job| !job.result.segments.is_empty());
        if ui.add_enabled(has_result, egui::Button::new("Show on file map")).on_hover_text("Pin the segments as findings, coloured by type").clicked() {
            actions.push(Action::PinSegments);
        }
        if ui.button("Clear").on_hover_text("Remove the pinned segments").clicked() {
            actions.push(Action::ClearSegments);
        }
        if let Some(job) = &state.segments {
            stale_marker(ui, job.key, app);
        }
    });
    let Some(job) = &state.segments else {
        ui.label(
            RichText::new("Splits the file into stretches of uniform character, with boundaries placed to the byte, and groups them into types such as text, tables, compressed data and padding.")
                .color(theme::TEXT_DIM),
        );
        return;
    };
    let result = &job.result;
    if result.segments.is_empty() {
        ui.label(RichText::new("The document is empty.").color(theme::TEXT_DIM));
        return;
    }
    segment_strip(ui, result, actions);
    segment_legend(ui, result);
    ui.label(
        RichText::new(format!("{} segments of {} types, measured in {} blocks", result.segments.len(), result.types.len(), human_bytes(result.block_size)))
            .small()
            .color(theme::TEXT_DIM),
    );
    segment_list(ui, result, actions);
}

/// The file as a strip coloured by segment type; a click selects the segment.
fn segment_strip(ui: &mut Ui, result: &Segmentation, actions: &mut Vec<Action>) {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), STRIP_HEIGHT), Sense::click());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(3), theme::BACKGROUND);
    let total = result.scanned_len;
    for segment in &result.segments {
        let left = x_of(rect, segment.start, total);
        // At least a pixel wide, so short segments stay visible.
        let right = x_of(rect, segment.end(), total).max(left + 1.0);
        let colour = result.types.get(segment.type_id).map_or(theme::OUTLINE, |segment_type| segment_type.colour);
        painter.rect_filled(Rect::from_min_max(pos2(left, rect.min.y), pos2(right, rect.max.y)), CornerRadius::ZERO, colour);
    }
    painter.rect_stroke(rect, CornerRadius::same(3), Stroke::new(1.0, theme::OUTLINE), egui::StrokeKind::Inside);
    let segment_under = |x: f32| {
        let offset = offset_at(rect, x, total);
        result.segments.iter().find(|segment| (segment.start..segment.end()).contains(&offset))
    };
    if response.clicked()
        && let Some(segment) = response.interact_pointer_pos().and_then(|pos| segment_under(pos.x))
    {
        actions.push(Action::Select { start: segment.start, len: segment.len, title: format!("Segment: {}", segment.label) });
    }
    if let Some(segment) = response.hover_pos().and_then(|pos| segment_under(pos.x)) {
        response.on_hover_text(format!("{:#x}–{:#x} ({}): {}\n{}", segment.start, segment.end(), human_bytes(segment.len), segment.label, segment.reason));
    }
}

fn segment_legend(ui: &mut Ui, result: &Segmentation) {
    ui.horizontal_wrapped(|ui| {
        for segment_type in &result.types {
            let plural = if segment_type.count == 1 { "" } else { "s" };
            let text = format!("{}: {} segment{plural}, {}", segment_type.label, segment_type.count, human_bytes(segment_type.total_bytes));
            theme::swatch(ui, segment_type.colour, &text);
        }
    });
}

fn segment_list(ui: &mut Ui, result: &Segmentation, actions: &mut Vec<Action>) {
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
    egui::ScrollArea::vertical().id_salt("structure-map-segment-list").max_height(LIST_HEIGHT).show_rows(ui, row_height, result.segments.len(), |ui, rows| {
        for segment in &result.segments[rows] {
            ui.horizontal(|ui| {
                if ui.link(RichText::new(format!("{:#010x}", segment.start)).monospace()).on_hover_text("Select this segment").clicked() {
                    actions.push(Action::Select { start: segment.start, len: segment.len, title: format!("Segment: {}", segment.label) });
                }
                ui.monospace(RichText::new(format!("{:>9}", human_bytes(segment.len))).color(theme::TEXT_DIM));
                let colour = result.types.get(segment.type_id).map_or(theme::OUTLINE, |segment_type| segment_type.colour);
                theme::swatch(ui, colour, &segment.label);
                ui.add(egui::Label::new(RichText::new(segment.reason.as_str()).small().color(theme::TEXT_DIM)).truncate());
            });
        }
    });
}

// ---------------------------------------------------------------------------
// Find more like this
// ---------------------------------------------------------------------------

fn start_similar(state: &mut StructureMapState, app: &mut ViewerApp, selection: (usize, usize), producer: &str) -> String {
    let (key, bytes) = read_scanned(app);
    let SimilarSettings { threshold, histogram_weight } = state.similar_settings;
    let (sender, receiver) = mpsc::channel();
    let job = start_job_as(app, "similar-blocks", "Finding blocks like the selection", producer);
    let id = job.id().to_string();
    thread::spawn(move || {
        if let Some(result) = run_similar(&bytes, selection, histogram_weight, threshold, &job) {
            let _ = sender.send(SimilarJob { key, result });
        }
    });
    state.similar_pending = Some(receiver);
    id
}

fn similar_findings(regions: &[SimilarRegion]) -> Vec<Finding> {
    regions
        .iter()
        .enumerate()
        .map(|(rank, region)| {
            Finding::new(format!("{SIMILAR_ID_PREFIX}{rank}"), FINDING_SOURCE, SIMILAR_CATEGORY, region.start, region.len.max(1))
                .title(format!("Like the selection ({:.0}%)", region.score * 100.0))
                .detail(format!("{} blocks, mean similarity {:.0}%, best {:.0}%", region.blocks, region.score * 100.0, region.best * 100.0))
                .confidence(region.score)
        })
        .collect()
}

fn show_similar(state: &mut StructureMapState, app: &mut ViewerApp, ui: &mut Ui, actions: &mut Vec<Action>) {
    let selection = app.selection();
    ui.horizontal_wrapped(|ui| {
        let can_search = selection.is_some() && state.similar_pending.is_none();
        let button = ui.add_enabled(can_search, egui::Button::new("Find similar"));
        let button = if selection.is_none() { button.on_disabled_hover_text("Select some bytes first") } else { button };
        if button.clicked()
            && let Some((start, len)) = selection
        {
            let SimilarSettings { threshold, histogram_weight } = state.similar_settings;
            let params = serde_json::json!({ "start": start, "len": len, "histogram_weight": histogram_weight, "threshold": threshold });
            app.perform_later("structure_map.find_similar", params);
        }
        if state.similar_pending.is_some() {
            ui.spinner();
        }
        match selection {
            Some((start, len)) => ui.label(RichText::new(format!("selection {start:#x}, {}", human_bytes(len))).small().color(theme::TEXT_DIM)),
            None => ui.label(RichText::new("no selection").small().color(theme::TEXT_DIM)),
        };
        if let Some(job) = &state.similar {
            stale_marker(ui, job.key, app);
        }
    });
    ui.horizontal_wrapped(|ui| {
        ui.add(egui::Slider::new(&mut state.similar_settings.threshold, 0.0..=1.0).text("threshold").fixed_decimals(2));
        ui.add(egui::Slider::new(&mut state.similar_settings.histogram_weight, 0.0..=1.0).text("histogram weight").fixed_decimals(2))
            .on_hover_text("How much the byte-value histogram counts against the other statistics; applies to the next search");
    });
    let Some(job) = &state.similar else {
        ui.label(RichText::new("Select a stretch of bytes, then find every other part of the file whose statistics resemble it.").color(theme::TEXT_DIM));
        return;
    };
    let scores = match &job.result {
        Ok(scores) => scores,
        Err(error) => {
            ui.label(RichText::new(error.to_string()).color(theme::DANGER));
            return;
        }
    };
    let regions = similar::matching_regions(scores, state.similar_settings.threshold);
    ui.horizontal_wrapped(|ui| {
        if ui.add_enabled(!regions.is_empty(), egui::Button::new("Highlight all")).on_hover_text("Pin the matches as findings").clicked() {
            actions.push(Action::PinSimilar);
        }
        if ui.button("Clear").on_hover_text("Remove the pinned matches").clicked() {
            actions.push(Action::ClearSimilar);
        }
        let (start, len) = scores.selection;
        ui.label(
            RichText::new(format!("{} regions like {start:#x}+{}, in {} blocks", regions.len(), human_bytes(len), human_bytes(scores.block_size)))
                .small()
                .color(theme::TEXT_DIM),
        );
    });
    similar_list(ui, &regions, actions);
}

fn similar_list(ui: &mut Ui, regions: &[SimilarRegion], actions: &mut Vec<Action>) {
    if regions.is_empty() {
        ui.label(RichText::new("Nothing reaches the threshold; lower it to see weaker matches.").color(theme::TEXT_DIM));
        return;
    }
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
    egui::ScrollArea::vertical().id_salt("structure-map-similar-list").max_height(LIST_HEIGHT).show_rows(ui, row_height, regions.len(), |ui, rows| {
        for region in &regions[rows] {
            ui.horizontal(|ui| {
                if ui.link(RichText::new(format!("{:#010x}", region.start)).monospace()).on_hover_text("Select this region").clicked() {
                    actions.push(Action::Select { start: region.start, len: region.len, title: format!("Like the selection ({:.0}%)", region.score * 100.0) });
                }
                ui.monospace(RichText::new(format!("{:>9}", human_bytes(region.len))).color(theme::TEXT_DIM));
                ui.add(egui::ProgressBar::new(region.score).desired_width(80.0).text(format!("{:.0}%", region.score * 100.0)));
                ui.label(RichText::new(format!("{} blocks", region.blocks)).small().color(theme::TEXT_DIM));
            });
        }
    });
}

// ---------------------------------------------------------------------------
// Feature tracks
// ---------------------------------------------------------------------------

fn start_tracks(state: &mut StructureMapState, app: &mut ViewerApp, producer: &str) -> String {
    app.note_tool_result(crate::dock::DockTab::StructureMap);
    let (key, bytes) = read_scanned(app);
    let (sender, receiver) = mpsc::channel();
    let job = start_job_as(app, "feature-tracks", "Feature tracks", producer);
    let id = job.id().to_string();
    thread::spawn(move || {
        if let Some(tracks) = run_tracks(&bytes, &job) {
            let _ = sender.send(TracksJob { key, tracks });
        }
    });
    state.tracks_pending = Some(receiver);
    id
}

/// How one track is drawn.
enum TrackStyle<'a> {
    /// An area chart of values from 0 to 1, with a unit for the hover text.
    Area { values: Vec<f32>, colour: Color32, describe: &'a dyn Fn(usize) -> String },
    /// Stacked byte-kind fractions.
    Kinds(&'a [KindMix]),
    /// A colour band of the local record width.
    Width,
}

fn show_tracks(state: &mut StructureMapState, app: &mut ViewerApp, ui: &mut Ui, actions: &mut Vec<Action>) {
    ui.horizontal_wrapped(|ui| {
        let size = human_bytes(app.document.len().min(SCAN_LIMIT));
        if ui.add_enabled(state.tracks_pending.is_none(), egui::Button::new(format!("Compute tracks ({size})"))).clicked() {
            app.perform_later("structure_map.tracks", serde_json::json!({}));
        }
        if state.tracks_pending.is_some() {
            ui.spinner();
        }
        let picked_width = state.tracks.as_ref().zip(state.picked_point).map_or(0, |(job, point)| job.tracks.width.get(point).copied().unwrap_or(0));
        let label = if picked_width > 0 { format!("Use width here ({picked_width} B)") } else { "Use width here".to_string() };
        let button = ui.add_enabled(picked_width > 0, egui::Button::new(label));
        if button.on_hover_text("Set the view width to the record width at the point last clicked in the tracks").clicked() {
            actions.push(Action::SetWidth(picked_width));
        }
        if let Some(job) = &state.tracks {
            stale_marker(ui, job.key, app);
        }
    });
    let Some(job) = &state.tracks else {
        ui.label(
            RichText::new("Draws entropy, compressibility, printable and zero bytes, the byte-kind mix and the local record width along the whole file. Click a track to jump there.")
                .color(theme::TEXT_DIM),
        );
        return;
    };
    let tracks = &job.tracks;
    if tracks.is_empty() {
        ui.label(RichText::new("The document is empty.").color(theme::TEXT_DIM));
        return;
    }
    let percent = |values: &[f32], index: usize| format!("{:.0}%", values.get(index).copied().unwrap_or(0.0) * 100.0);
    let describe_entropy = |index: usize| format!("{:.2} bits/byte", tracks.entropy[index]);
    let describe_compressibility = |index: usize| format!("compresses to {:.0}%", tracks.compressibility[index] * 100.0);
    let describe_printable = |index: usize| format!("{} printable", percent(&tracks.printable, index));
    let describe_zeros = |index: usize| format!("{} zeros", percent(&tracks.zeros, index));
    let rows: [(&str, TrackStyle); 6] = [
        ("Entropy", TrackStyle::Area { values: tracks.entropy.iter().map(|value| value / MAX_ENTROPY).collect(), colour: theme::ACCENT, describe: &describe_entropy }),
        (
            "Compressibility",
            TrackStyle::Area {
                values: tracks.compressibility.iter().map(|value| value / MAX_COMPRESSION_RATIO).collect(),
                colour: Category::Compressed.colour(),
                describe: &describe_compressibility,
            },
        ),
        ("Printable", TrackStyle::Area { values: tracks.printable.clone(), colour: theme::CLASS_TEXT, describe: &describe_printable }),
        ("Zeros", TrackStyle::Area { values: tracks.zeros.clone(), colour: theme::CLASS_NULL, describe: &describe_zeros }),
        ("Byte kinds", TrackStyle::Kinds(&tracks.kinds)),
        ("Record width", TrackStyle::Width),
    ];
    let cursor = (app.cursor < tracks.scanned_len).then_some(app.cursor);
    let mut picked = None;
    for (label, style) in rows {
        ui.horizontal(|ui| {
            let (label_rect, _) = ui.allocate_exact_size(vec2(TRACK_LABEL_WIDTH, TRACK_HEIGHT), Sense::hover());
            ui.painter().text(label_rect.left_center(), egui::Align2::LEFT_CENTER, label, egui::FontId::proportional(TRACK_LABEL_SIZE), theme::TEXT_DIM);
            if let Some(point) = track_chart(ui, tracks, &style, cursor) {
                picked = Some(point);
                actions.push(Action::Jump(tracks.offsets[point]));
            }
        });
    }
    kinds_legend(ui);
    if picked.is_some() {
        state.picked_point = picked;
    }
}

/// Points `first..last` of `count` drawn in pixel column `column` of `columns`.
fn column_points(column: usize, columns: usize, count: usize) -> std::ops::Range<usize> {
    let first = column * count / columns.max(1);
    let last = ((column + 1) * count / columns.max(1)).max(first + 1).min(count);
    first..last
}

/// Draw one track; returns the point clicked, if any.
fn track_chart(ui: &mut Ui, tracks: &FeatureTracks, style: &TrackStyle, cursor: Option<usize>) -> Option<usize> {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width().max(1.0), TRACK_HEIGHT), Sense::click());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(2), theme::BACKGROUND);
    let columns = rect.width().max(1.0) as usize;
    let count = tracks.len();
    for column in 0..columns {
        let points = column_points(column, columns, count);
        if points.is_empty() {
            continue;
        }
        let x_range = (rect.min.x + column as f32, rect.min.x + column as f32 + 1.0);
        match style {
            TrackStyle::Area { values, colour, .. } => {
                let mean = points.clone().map(|index| values[index]).sum::<f32>() / points.len() as f32;
                fill_column(&painter, rect, x_range, 0.0, mean, *colour);
            }
            TrackStyle::Kinds(kinds) => draw_kinds_column(&painter, rect, x_range, &kinds[points.start]),
            TrackStyle::Width => {
                // The strongest point in the column, so narrow regions stay visible.
                let index = points.clone().max_by(|&a, &b| tracks.width_strength[a].total_cmp(&tracks.width_strength[b])).unwrap_or(points.start);
                fill_column(&painter, rect, x_range, 0.0, 1.0, width_colour(tracks.width[index], tracks.width_strength[index]));
            }
        }
    }
    if let Some(offset) = cursor {
        let x = x_of(rect, offset, tracks.scanned_len);
        painter.vline(x, rect.y_range(), Stroke::new(1.5, theme::CURSOR));
    }
    painter.rect_stroke(rect, CornerRadius::same(2), Stroke::new(1.0, theme::OUTLINE), egui::StrokeKind::Inside);

    let point_under = |x: f32| tracks.point_at(offset_at(rect, x, tracks.scanned_len));
    let clicked = if response.clicked() { response.interact_pointer_pos().and_then(|pos| point_under(pos.x)) } else { None };
    if let Some(point) = response.hover_pos().and_then(|pos| point_under(pos.x)) {
        let value = match style {
            TrackStyle::Area { describe, .. } => describe(point),
            TrackStyle::Kinds(kinds) => describe_kinds(&kinds[point]),
            TrackStyle::Width => match tracks.width[point] {
                0 => "no repeating record width".to_string(),
                width => format!("record width {width} bytes ({:.0}% stronger than a typical lag)", tracks.width_strength[point] * 100.0),
            },
        };
        response.on_hover_text_at_pointer(format!("{:#x}: {value}", tracks.offsets[point]));
    }
    clicked
}

/// Fill a one-pixel column of `rect` from fraction `low` to `high` of its height (0 is the bottom).
fn fill_column(painter: &egui::Painter, rect: Rect, x_range: (f32, f32), low: f32, high: f32, colour: Color32) {
    let y_of = |fraction: f32| rect.max.y - rect.height() * fraction.clamp(0.0, 1.0);
    if high <= low {
        return;
    }
    painter.rect_filled(Rect::from_min_max(pos2(x_range.0, y_of(high)), pos2(x_range.1, y_of(low))), CornerRadius::ZERO, colour);
}

/// The kinds, stacked from the bottom: zeros, control, printable, high.
fn kind_layers(kinds: &KindMix) -> [(f32, Color32); 4] {
    [
        (kinds.zero, theme::CLASS_NULL),
        (kinds.control, theme::CLASS_CONTROL),
        (kinds.printable, theme::CLASS_TEXT),
        (kinds.high, theme::CLASS_HIGH),
    ]
}

fn draw_kinds_column(painter: &egui::Painter, rect: Rect, x_range: (f32, f32), kinds: &KindMix) {
    let mut low = 0.0;
    for (fraction, colour) in kind_layers(kinds) {
        fill_column(painter, rect, x_range, low, low + fraction, colour);
        low += fraction;
    }
}

fn describe_kinds(kinds: &KindMix) -> String {
    format!(
        "{:.0}% zeros, {:.0}% control, {:.0}% printable, {:.0}% high",
        kinds.zero * 100.0,
        kinds.control * 100.0,
        kinds.printable * 100.0,
        kinds.high * 100.0
    )
}

fn kinds_legend(ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.add_space(TRACK_LABEL_WIDTH);
        for (label, colour) in [("zeros", theme::CLASS_NULL), ("control", theme::CLASS_CONTROL), ("printable", theme::CLASS_TEXT), ("high", theme::CLASS_HIGH)] {
            theme::swatch(ui, colour, label);
        }
        ui.label(RichText::new("· record width: hue by size, brighter when stronger").small().color(theme::TEXT_DIM));
    });
}

/// A colour for a record width: hue by the logarithm of the width, opacity by strength.
fn width_colour(width: usize, strength: f32) -> Color32 {
    if width == 0 {
        return Color32::TRANSPARENT;
    }
    let span = (tracks::MAX_WIDTH as f32).log2() - (tracks::MIN_WIDTH as f32).log2();
    let hue = ((width as f32).log2() - (tracks::MIN_WIDTH as f32).log2()) / span.max(f32::EPSILON);
    /// Strength at which the band is fully opaque.
    const FULL_STRENGTH: f32 = 0.6;
    let alpha = (strength / FULL_STRENGTH).clamp(0.25, 1.0);
    egui::ecolor::Hsva::new(hue.clamp(0.0, 1.0) * 0.8, 0.65, 0.95, alpha).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_cover_every_point_without_gaps() {
        let (columns, count) = (300, 4096);
        let mut next = 0;
        for column in 0..columns {
            let points = column_points(column, columns, count);
            assert_eq!(points.start, next);
            next = points.end;
        }
        assert_eq!(next, count);
        assert_eq!(column_points(5, 300, 10), 0..1);
    }

    #[test]
    fn wider_records_get_a_different_hue_and_no_width_is_transparent() {
        assert_eq!(width_colour(0, 1.0), Color32::TRANSPARENT);
        assert_ne!(width_colour(24, 0.8), width_colour(64, 0.8));
    }

    #[test]
    fn pinned_segments_carry_the_segment_prefix_and_type_category() {
        let data: Vec<u8> = (0..20_000u32).map(|index| if index < 10_000 { 0 } else { b'a' + (index % 26) as u8 }).collect();
        let result = crate::segments::segment_file(&data, &crate::segments::SegmentOptions::default());
        let findings = segment_findings(&result);
        assert_eq!(findings.len(), result.segments.len());
        assert!(findings.iter().all(|finding| finding.id.starts_with(SEGMENT_ID_PREFIX)));
        assert_eq!(findings[0].category, Category::Padding);
    }

    use serde_json::json;

    use crate::actions::take_performed;
    use crate::app::Launch;
    use crate::legend::PinnedGroup;

    /// Zeros, then text.
    fn zeros_then_text() -> Vec<u8> {
        let mut bytes = vec![0; 10_000];
        bytes.extend(b"The quick brown fox jumps over the lazy dog. ".repeat(300));
        bytes
    }

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        take_performed();
        app
    }

    /// Carry out the actions asked for while drawing, and collect the panel's
    /// results once its work is done.
    fn run_until_idle(app: &mut ViewerApp) {
        app.perform_waiting_actions();
        let begun = std::time::Instant::now();
        loop {
            let mut state = std::mem::take(&mut app.bench.panels.structure_map);
            state.poll(app);
            let busy = state.is_busy();
            app.bench.panels.structure_map = state;
            if !busy || begun.elapsed() > Duration::from_secs(30) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        app.run_bus();
    }

    fn segments_pinned(app: &ViewerApp) -> Vec<(usize, usize)> {
        app.pinned_findings().into_iter().filter(|(group, _)| *group == PinnedGroup::Segments).map(|(_, finding)| (finding.start, finding.len)).collect()
    }

    #[test]
    fn segmenting_is_a_job_of_the_person_s_and_its_pins_are_their_findings() {
        let mut app = app_with(&zeros_then_text());
        app.perform_later("structure_map.segment", json!({}));
        run_until_idle(&mut app);
        assert_eq!(take_performed(), [("structure_map.segment".to_string(), json!({}))]);
        let job = app.bus.jobs().list().into_iter().find(|job| job.title == "Segmenting the file").expect("a job");
        assert_eq!(job.producer, "panel");
        let segments = app.bench.panels.structure_map.segments.as_ref().map(|job| job.result.segments.len()).expect("the panel shows the segments");
        assert!(segments >= 2);

        let state = std::mem::take(&mut app.bench.panels.structure_map);
        apply(&state, &mut app, Action::PinSegments);
        let performed = take_performed();
        assert_eq!((performed[0].0.as_str(), performed[0].1["key"].clone()), ("findings.publish", json!(SEGMENT_ID_PREFIX)));
        assert_eq!(performed[0].1["findings"].as_array().unwrap().len(), segments, "every segment is in the step");
        app.run_bus();
        assert_eq!(segments_pinned(&app).len(), segments, "drawn in the Segments group");
        assert!(app.bench.pinned.is_empty());
        apply(&state, &mut app, Action::ClearSegments);
        assert_eq!(take_performed(), [("findings.retract".to_string(), json!({"key": SEGMENT_ID_PREFIX}))]);
        app.run_bus();
        assert!(segments_pinned(&app).is_empty());
    }

    #[test]
    fn pinned_segments_follow_a_refresh_without_a_step_of_the_person_s() {
        let mut app = app_with(&zeros_then_text());
        app.perform_later("structure_map.segment", json!({}));
        run_until_idle(&mut app);
        let state = std::mem::take(&mut app.bench.panels.structure_map);
        apply(&state, &mut app, Action::PinSegments);
        app.bench.panels.structure_map = state;
        app.run_bus();
        take_performed();
        let length = app.document.len();
        app.document.insert(0, &[0; 4096]);
        app.publish_edits_as("document");
        crate::panels::with(&mut app, |panels| &mut panels.structure_map, refresh);
        run_until_idle(&mut app);
        assert!(take_performed().is_empty(), "the tool's own work");
        assert_eq!(segments_pinned(&app).iter().map(|(start, len)| start + len).max(), Some(length + 4096));
        let job = app.bus.jobs().list().into_iter().rfind(|job| job.title == "Segmenting the file").unwrap();
        assert_eq!(job.producer, TOOL_PRODUCER);
    }

    #[test]
    fn finding_more_like_the_selection_carries_its_span_and_settings() {
        let mut app = app_with(&zeros_then_text());
        app.perform_later("structure_map.find_similar", json!({"start": 10_000, "len": 1024, "histogram_weight": 0.25, "threshold": 0.7}));
        run_until_idle(&mut app);
        let state = &app.bench.panels.structure_map;
        assert_eq!((state.similar_settings.histogram_weight, state.similar_settings.threshold), (0.25, 0.7));
        let scores = state.similar.as_ref().and_then(|job| job.result.as_ref().ok()).expect("the panel lists the matches");
        assert_eq!(scores.selection, (10_000, 1024));
        let job = app.bus.jobs().list().into_iter().find(|job| job.title == "Finding blocks like the selection").expect("a job");
        assert!(job.result.as_ref().is_some_and(|result| result["regions"].is_array()));
    }

    #[test]
    fn a_track_clicked_moves_the_cursor_and_use_width_here_sets_the_width_through_the_api() {
        let mut app = app_with(&zeros_then_text());
        app.perform_later("structure_map.tracks", json!({}));
        run_until_idle(&mut app);
        assert!(app.bench.panels.structure_map.tracks.is_some());
        take_performed();
        let state = StructureMapState::default();
        apply(&state, &mut app, Action::Jump(0x100));
        apply(&state, &mut app, Action::SetWidth(48));
        assert_eq!(take_performed(), [("cursor.set".to_string(), json!({"offset": 0x100})), ("view.set_shape".to_string(), json!({"width": 48}))]);
        assert_eq!((app.cursor, app.shape.width), (0x100, 48));
    }

    #[test]
    fn a_segment_clicked_in_the_structure_map_is_the_person_s_selection_through_the_api() {
        let mut app = app_with(&zeros_then_text());
        let state = StructureMapState::default();
        apply(&state, &mut app, Action::Select { start: 0x200, len: 0x40, title: "Zeros".to_string() });
        assert_eq!(take_performed(), [("selection.set".to_string(), json!({ "selection": { "range": [0x200, 0x40] }, "cursor": 0x240 }))]);
        assert_eq!(app.selection(), Some((0x200, 0x40)));
        assert!(app.status.contains("Zeros"), "the status bar names the segment: {}", app.status);
    }
}
