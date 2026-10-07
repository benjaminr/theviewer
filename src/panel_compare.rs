//! The Compare panel: field variation across files, correlation with an
//! outside value, and the change timeline of a recording.
//!
//! The current document is always the first file. Other files are added with
//! a non-blocking dialog and read on a background thread; every analysis
//! runs on a background thread too, and the panel collects the result on a
//! later frame.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Color32, ColorImage, Rect, RichText, Sense, TextureHandle, TextureOptions, Ui, pos2, vec2};

use crate::app::ViewerApp;
use crate::correlation::{self, CorrelationReport};
use crate::theme;
use crate::timeline::{self, Timeline};
use crate::variation::{self, VariationReport};

/// Largest part of each file read for comparison.
pub(crate) const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
/// Most bytes held across all added files.
const MAX_TOTAL_BYTES: usize = 512 * 1024 * 1024;
/// How often to look for finished work while something is pending.
const PENDING_REPAINT: Duration = Duration::from_millis(100);
/// Regions listed in the variation section.
const MAX_LISTED_REGIONS: usize = 2000;
/// Bytes of each file shown for the selected region.
const REGION_PREVIEW_BYTES: usize = 8;
/// Height of one snapshot row in the heatmap, in points.
const HEATMAP_ROW_HEIGHT: f32 = 3.0;
/// Tallest the heatmap is drawn, in points.
const HEATMAP_MAX_HEIGHT: f32 = 360.0;
/// Height of the per-column activity strip under the heatmap.
const ACTIVITY_STRIP_HEIGHT: f32 = 28.0;
/// Lowest palette entry used for a changed cell, so small changes stay visible.
const HEATMAP_PALETTE_FLOOR: f32 = 64.0;

/// Which part of the panel is shown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CompareSection {
    #[default]
    Files,
    Variation,
    Correlation,
    Timeline,
}

/// A file added for comparison.
pub struct CompareFile {
    pub name: String,
    pub path: PathBuf,
    pub bytes: Arc<[u8]>,
    /// The file is longer than [`MAX_FILE_BYTES`] and was cut short.
    pub truncated: bool,
    /// Offset in this file that lines up with the other files' starts.
    pub start: usize,
    /// The outside value typed for this file, for correlation.
    pub outside_value: String,
}

/// Files read on a background thread: each one, or why it could not be read.
type LoadedFiles = Vec<Result<CompareFile, String>>;

/// Every file as (bytes, start offset), the document first.
pub(crate) type CompareInputs = Vec<(Arc<[u8]>, usize)>;

/// A finished variation run: the files it compared (for the region
/// previews) and the summary, or why there is none.
pub(crate) struct VariationRun {
    pub inputs: CompareInputs,
    pub report: Result<VariationReport, String>,
}

/// State of the Compare panel.
#[derive(Default)]
pub struct CompareState {
    pub section: CompareSection,
    pub files: Vec<CompareFile>,
    /// Start offset of the current document.
    pub current_start: usize,
    /// Outside value of the current document, for correlation.
    pub current_outside_value: String,
    /// Where the correlation search starts, relative to each file's start.
    pub correlation_from: usize,
    dialog: Option<ManyFilesRequest>,
    loading: Option<Receiver<LoadedFiles>>,
    messages: Vec<String>,

    variation_pending: Option<Receiver<VariationRun>>,
    variation: Option<VariationReport>,
    /// The inputs of the last variation run, to preview a region's bytes.
    variation_inputs: Vec<(Arc<[u8]>, usize)>,
    selected_region: Option<usize>,

    correlation_pending: Option<Receiver<Result<CorrelationReport, String>>>,
    correlation: Option<CorrelationReport>,

    timeline_pending: Option<Receiver<Option<Timeline>>>,
    timeline: Option<Timeline>,
    timeline_texture: Option<TextureHandle>,
}

impl CompareState {
    fn is_busy(&self) -> bool {
        self.dialog.is_some()
            || self.loading.is_some()
            || self.variation_pending.is_some()
            || self.correlation_pending.is_some()
            || self.timeline_pending.is_some()
    }

    fn bytes_held(&self) -> usize {
        self.files.iter().map(|file| file.bytes.len()).sum()
    }

    /// Results no longer match the file list.
    fn forget_results(&mut self) {
        self.variation = None;
        self.variation_inputs.clear();
        self.selected_region = None;
        self.correlation = None;
    }
}

/// Draw the Compare panel.
pub fn show_compare(state: &mut CompareState, app: &mut ViewerApp, ui: &mut Ui) {
    poll_background_work(state, ui.ctx());
    if state.is_busy() {
        ui.ctx().request_repaint_after(PENDING_REPAINT);
    }
    ui.horizontal(|ui| {
        ui.selectable_value(&mut state.section, CompareSection::Files, "Files");
        ui.selectable_value(&mut state.section, CompareSection::Variation, "Variation");
        ui.selectable_value(&mut state.section, CompareSection::Correlation, "Correlation");
        ui.selectable_value(&mut state.section, CompareSection::Timeline, "Timeline");
    });
    ui.separator();
    for message in &state.messages {
        ui.label(RichText::new(message).small().color(theme::DANGER));
    }
    let jump = match state.section {
        CompareSection::Files => {
            show_files(state, app, ui);
            None
        }
        CompareSection::Variation => show_variation(state, app, ui),
        CompareSection::Correlation => show_correlation(state, app, ui),
        CompareSection::Timeline => show_timeline(state, app, ui),
    };
    if let Some(offset) = jump {
        app.jump_found(offset);
    }
}

// ---------------------------------------------------------------------------
// Background work
// ---------------------------------------------------------------------------

/// A multi-file open dialog that does not block the window, like
/// [`crate::dialogs::FileRequest`] but answering with several paths.
struct ManyFilesRequest {
    receiver: Receiver<Option<Vec<PathBuf>>>,
}

impl ManyFilesRequest {
    fn open(dialog: rfd::AsyncFileDialog) -> Self {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let chosen = pollster::block_on(dialog.pick_files())
                .map(|handles| handles.iter().map(|handle| handle.path().to_path_buf()).collect());
            let _ = sender.send(chosen);
        });
        ManyFilesRequest { receiver }
    }

    /// `Some(answer)` once answered; `Some(None)` when cancelled.
    fn poll(&self) -> Option<Option<Vec<PathBuf>>> {
        match self.receiver.try_recv() {
            Ok(answer) => Some(answer),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(None),
        }
    }
}

/// The result of a job, once it has finished. A job whose thread ended
/// without answering is reported as `Some(Err(..))` by the caller.
fn take_finished<T>(pending: &mut Option<Receiver<T>>) -> Option<Result<T, TryRecvError>> {
    let receiver = pending.as_ref()?;
    match receiver.try_recv() {
        Ok(result) => {
            *pending = None;
            Some(Ok(result))
        }
        Err(TryRecvError::Empty) => None,
        Err(TryRecvError::Disconnected) => {
            *pending = None;
            Some(Err(TryRecvError::Disconnected))
        }
    }
}

const JOB_ENDED_EARLY: &str = "The background job stopped without a result.";

fn poll_background_work(state: &mut CompareState, ctx: &egui::Context) {
    if let Some(answer) = state.dialog.as_ref().and_then(ManyFilesRequest::poll) {
        state.dialog = None;
        if let Some(paths) = answer {
            start_loading(state, paths);
        }
    }
    match take_finished(&mut state.loading) {
        Some(Ok(loaded)) => add_loaded_files(state, loaded),
        Some(Err(_)) => state.messages.push(JOB_ENDED_EARLY.to_string()),
        None => {}
    }
    match take_finished(&mut state.variation_pending) {
        Some(Ok(run)) => {
            state.variation_inputs = run.inputs;
            match run.report {
                Ok(report) => state.variation = Some(report),
                Err(message) => state.messages.push(message),
            }
        }
        Some(Err(_)) => state.messages.push(JOB_ENDED_EARLY.to_string()),
        None => {}
    }
    match take_finished(&mut state.correlation_pending) {
        Some(Ok(Ok(report))) => state.correlation = Some(report),
        Some(Ok(Err(message))) => state.messages.push(message),
        Some(Err(_)) => state.messages.push(JOB_ENDED_EARLY.to_string()),
        None => {}
    }
    match take_finished(&mut state.timeline_pending) {
        Some(Ok(Some(built))) => {
            state.timeline_texture = Some(heatmap_texture(ctx, &built));
            state.timeline = Some(built);
        }
        Some(Ok(None)) => state.messages.push(JOB_ENDED_EARLY.to_string()),
        Some(Err(_)) => state.messages.push(JOB_ENDED_EARLY.to_string()),
        None => {}
    }
}

fn start_loading(state: &mut CompareState, paths: Vec<PathBuf>) {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let loaded: LoadedFiles = paths.iter().map(|path| read_compare_file(path)).collect();
        let _ = sender.send(loaded);
    });
    state.loading = Some(receiver);
}

/// Read up to [`MAX_FILE_BYTES`] of `path`.
pub(crate) fn read_compare_file(path: &Path) -> Result<CompareFile, String> {
    let name = path.file_name().map_or_else(|| path.display().to_string(), |name| name.to_string_lossy().into_owned());
    let file = File::open(path).map_err(|error| format!("Could not open {name}: {error}"))?;
    let mut bytes = Vec::new();
    // Read one byte past the cap to learn whether the file was cut short.
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Could not read {name}: {error}"))?;
    let truncated = bytes.len() > MAX_FILE_BYTES;
    bytes.truncate(MAX_FILE_BYTES);
    Ok(CompareFile {
        name,
        path: path.to_path_buf(),
        bytes: bytes.into(),
        truncated,
        start: 0,
        outside_value: String::new(),
    })
}

fn add_loaded_files(state: &mut CompareState, loaded: LoadedFiles) {
    let extra_files_allowed = variation::MAX_FILES - 1;
    for result in loaded {
        match result {
            Err(message) => state.messages.push(message),
            Ok(file) if state.files.len() >= extra_files_allowed => {
                state.messages.push(format!("{} not added: at most {} files can be compared.", file.name, variation::MAX_FILES));
            }
            Ok(file) if state.bytes_held() + file.bytes.len() > MAX_TOTAL_BYTES => {
                let limit = crate::compress::human_bytes(MAX_TOTAL_BYTES);
                state.messages.push(format!("{} not added: the files would hold more than {limit}.", file.name));
            }
            Ok(file) => {
                if file.truncated {
                    let limit = crate::compress::human_bytes(MAX_FILE_BYTES);
                    state.messages.push(format!("{} is larger than {limit}; only its start is compared.", file.name));
                }
                state.files.push(file);
            }
        }
    }
    state.forget_results();
}

/// The files added, as `compare.*` takes them.
fn files_param(state: &CompareState) -> serde_json::Value {
    state.files.iter().map(|file| serde_json::json!({ "path": file.path.display().to_string(), "start": file.start })).collect()
}

/// Where a job's result for the panel is sent, and where the panel waits for it.
fn awaited<T>(pending: &mut Option<Receiver<T>>) -> mpsc::Sender<T> {
    let (sender, receiver) = mpsc::channel();
    *pending = Some(receiver);
    sender
}

/// Wait for a run `compare.variation` started; returns where it is sent.
pub(crate) fn await_variation(app: &mut ViewerApp) -> mpsc::Sender<VariationRun> {
    app.note_tool_result(crate::dock::DockTab::Compare);
    let state = &mut app.bench.panels.compare;
    state.selected_region = None;
    awaited(&mut state.variation_pending)
}

/// Wait for a search `compare.correlate` started; returns where it is sent.
pub(crate) fn await_correlation(app: &mut ViewerApp) -> mpsc::Sender<Result<CorrelationReport, String>> {
    app.note_tool_result(crate::dock::DockTab::Compare);
    awaited(&mut app.bench.panels.compare.correlation_pending)
}

/// Wait for a timeline `compare.timeline` started; returns where it is sent.
pub(crate) fn await_timeline(app: &mut ViewerApp) -> mpsc::Sender<Option<Timeline>> {
    awaited(&mut app.bench.panels.compare.timeline_pending)
}

/// Summarise how the files vary, once they are read.
pub(crate) fn summarise(inputs: Result<CompareInputs, String>) -> VariationRun {
    match inputs {
        Ok(inputs) => {
            let slices: Vec<&[u8]> = inputs.iter().map(|(bytes, _)| &bytes[..]).collect();
            let starts: Vec<usize> = inputs.iter().map(|(_, start)| *start).collect();
            let report = variation::summarise_variation(&slices, &starts).map_err(|error| error.to_string());
            VariationRun { inputs, report }
        }
        Err(message) => VariationRun { inputs: Vec::new(), report: Err(message) },
    }
}

/// The fields of `inputs` that follow `outside`, searched from `from`.
pub(crate) fn correlate(inputs: &[(Arc<[u8]>, usize)], outside: &[f64], from: usize) -> Result<CorrelationReport, String> {
    let slices: Vec<&[u8]> = inputs.iter().map(|(bytes, _)| &bytes[..]).collect();
    let starts: Vec<usize> = inputs.iter().map(|(_, start)| *start).collect();
    let aligned = variation::apply_start_offsets(&slices, &starts).map_err(|error| error.to_string())?;
    let range = from..from.saturating_add(correlation::DEFAULT_SEARCH_LEN);
    correlation::find_correlated_fields(&aligned, outside, range).map_err(|error| error.to_string())
}

/// The changes the window's recording holds, or why there are none.
pub(crate) fn recorded_changes(app: &ViewerApp) -> Result<timeline::RecordingChanges, String> {
    let Some(recording) = &app.bench.recording else {
        return Err("Nothing is being recorded. Turn on \"Record history\" in the Live tab first.".to_string());
    };
    timeline::collect_changes(recording, timeline::MAX_ROWS).map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

fn show_files(state: &mut CompareState, app: &mut ViewerApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        let can_open = state.dialog.is_none() && state.loading.is_none();
        if ui.add_enabled(can_open, egui::Button::new("Add files…")).clicked() {
            state.messages.clear();
            let dialog = rfd::AsyncFileDialog::new().set_title("Add files to compare");
            state.dialog = Some(ManyFilesRequest::open(dialog));
        }
        if state.loading.is_some() {
            ui.spinner();
            ui.label(RichText::new("Reading files…").color(theme::TEXT_DIM));
        }
        if !state.files.is_empty() && ui.button("Remove all").clicked() {
            state.files.clear();
            state.forget_results();
        }
    });
    ui.label(
        RichText::new("Files are compared byte by byte from their start offsets. The open document is always the first file; jumps land in it.")
            .small()
            .color(theme::TEXT_DIM),
    );
    let mut remove = None;
    egui::Grid::new("compare-files").num_columns(4).striped(true).spacing([12.0, 4.0]).show(ui, |ui| {
        ui.label(RichText::new("File").color(theme::TEXT_DIM));
        ui.label(RichText::new("Size").color(theme::TEXT_DIM));
        ui.label(RichText::new("Start offset").color(theme::TEXT_DIM));
        ui.label("");
        ui.end_row();

        ui.label(RichText::new(format!("{} (open document)", app.display_name())).color(theme::ACCENT));
        ui.monospace(crate::compress::human_bytes(app.document.len()));
        ui.add(egui::DragValue::new(&mut state.current_start).hexadecimal(1, false, true).prefix("0x"));
        ui.label("");
        ui.end_row();

        for (index, file) in state.files.iter_mut().enumerate() {
            ui.label(&file.name).on_hover_text(file.path.display().to_string());
            let size = crate::compress::human_bytes(file.bytes.len());
            ui.monospace(if file.truncated { format!("{size} (cut short)") } else { size });
            ui.add(egui::DragValue::new(&mut file.start).hexadecimal(1, false, true).prefix("0x").range(0..=file.bytes.len()));
            if ui.small_button("Remove").clicked() {
                remove = Some(index);
            }
            ui.end_row();
        }
    });
    if let Some(index) = remove {
        state.files.remove(index);
        state.forget_results();
    }
    if state.files.is_empty() {
        ui.label(RichText::new("Add at least one more file to compare it with the open document.").color(theme::TEXT_DIM));
    }
}

// ---------------------------------------------------------------------------
// Variation
// ---------------------------------------------------------------------------

/// Compare again after the open document was edited: whichever of the
/// variation and correlation had been worked out.
pub(crate) fn refresh(state: &mut CompareState, app: &mut ViewerApp) {
    if state.variation.is_some() || state.variation_pending.is_some() {
        start_variation(state, app);
    }
    if (state.correlation.is_some() || state.correlation_pending.is_some())
        && let Err(message) = start_correlation(state, app)
    {
        state.messages.push(message);
    }
}

/// The person compares the files: `compare.variation`, carried out once
/// the panel is drawn.
fn start_variation(state: &mut CompareState, app: &mut ViewerApp) {
    app.perform_later("compare.variation", serde_json::json!({ "start": state.current_start, "files": files_param(state) }));
}

fn show_variation(state: &mut CompareState, app: &mut ViewerApp, ui: &mut Ui) -> Option<usize> {
    ui.horizontal(|ui| {
        let file_count = state.files.len() + 1;
        let can_run = state.variation_pending.is_none() && file_count >= variation::MIN_FILES;
        if ui.add_enabled(can_run, egui::Button::new(format!("Compare {file_count} files"))).clicked() {
            state.messages.clear();
            start_variation(state, app);
        }
        if state.variation_pending.is_some() {
            ui.spinner();
        }
    });
    let Some(report) = &state.variation else {
        ui.label(
            RichText::new("Summarises every byte position across the files: constant, varying (and how many values), or moving one way through the file order, like a counter or version number. Add files in the Files section first.")
                .color(theme::TEXT_DIM),
        );
        return None;
    };
    show_variation_summary(report, ui);
    let mut clicked = None;
    let current_start = state.variation_inputs.first().map_or(0, |(_, start)| *start);
    egui::ScrollArea::vertical().id_salt("compare-regions").max_height(ui.available_height() * 0.6).show(ui, |ui| {
        for (index, region) in report.regions.iter().enumerate().take(MAX_LISTED_REGIONS) {
            let colour = match region.kind {
                variation::RegionKind::Constant => theme::TEXT_DIM,
                variation::RegionKind::Varies { .. } => theme::CURSOR,
                variation::RegionKind::Trend { .. } => theme::ACCENT,
            };
            let selected = state.selected_region == Some(index);
            let label = egui::Button::selectable(selected, RichText::new(region.label()).monospace().small().color(colour));
            if ui.add(label).clicked() {
                clicked = Some(index);
            }
        }
        if report.regions.len() > MAX_LISTED_REGIONS {
            ui.label(RichText::new(format!("… and {} more regions", report.regions.len() - MAX_LISTED_REGIONS)).color(theme::TEXT_DIM));
        }
    });
    if let Some(region) = state.selected_region.and_then(|index| report.regions.get(index)) {
        show_region_preview(&state.variation_inputs, region, ui);
    }
    let jump = clicked.and_then(|index| report.regions.get(index)).map(|region| current_start + region.start);
    if clicked.is_some() {
        state.selected_region = clicked;
    }
    jump
}

fn show_variation_summary(report: &VariationReport, ui: &mut Ui) {
    let constant = report.constant_bytes();
    ui.label(format!(
        "{} files, {} in common, {} constant ({:.0}%), {} regions",
        report.file_count,
        crate::compress::human_bytes(report.common_len),
        crate::compress::human_bytes(constant),
        100.0 * constant as f64 / report.analysed_len.max(1) as f64,
        report.regions.len()
    ));
    if report.is_truncated() {
        ui.label(
            RichText::new(format!("Only the first {} were summarised.", crate::compress::human_bytes(report.analysed_len)))
                .small()
                .color(theme::CURSOR),
        );
    }
    for tail in &report.tails {
        let file = if tail.file == 0 { "The open document".to_string() } else { format!("File {}", tail.file + 1) };
        ui.label(
            RichText::new(format!("{file} has {} more beyond 0x{:X}, not compared.", crate::compress::human_bytes(tail.len), tail.start))
                .small()
                .color(theme::TEXT_DIM),
        );
    }
    if !report.tails.is_empty() {
        ui.label(
            RichText::new("Files are compared position by position, without diff alignment: an insertion shifts everything after it. Adjust start offsets to line files up.")
                .small()
                .color(theme::TEXT_DIM),
        );
    }
}

/// The first bytes of the selected region in each file.
fn show_region_preview(inputs: &[(Arc<[u8]>, usize)], region: &variation::Region, ui: &mut Ui) {
    ui.separator();
    ui.label(RichText::new(region.label()).strong());
    let shown = region.len().min(REGION_PREVIEW_BYTES);
    egui::ScrollArea::vertical().id_salt("compare-region-preview").show(ui, |ui| {
        for (index, (bytes, start)) in inputs.iter().enumerate() {
            let from = start + region.start;
            let preview: Vec<String> =
                bytes.get(from..from + shown).unwrap_or(&[]).iter().map(|byte| format!("{byte:02X}")).collect();
            let more = if region.len() > shown { " …" } else { "" };
            ui.monospace(format!("file {:>2}: {}{more}", index + 1, preview.join(" ")));
        }
    });
}

// ---------------------------------------------------------------------------
// Correlation
// ---------------------------------------------------------------------------

/// The typed outside values, the current document's first.
fn parse_outside_values(state: &CompareState) -> Result<Vec<f64>, String> {
    let typed = std::iter::once(("the open document".to_string(), &state.current_outside_value))
        .chain(state.files.iter().map(|file| (file.name.clone(), &file.outside_value)));
    typed
        .map(|(name, text)| {
            text.trim()
                .parse::<f64>()
                .map_err(|_| format!("The outside value for {name} ('{}') is not a number.", text.trim()))
        })
        .collect()
}

/// The person looks for fields following the values typed:
/// `compare.correlate`, carried out once the panel is drawn. Values that
/// are not numbers are said in the panel instead.
fn start_correlation(state: &mut CompareState, app: &mut ViewerApp) -> Result<(), String> {
    let values = parse_outside_values(state)?;
    let params = serde_json::json!({ "start": state.current_start, "files": files_param(state), "values": values, "from": state.correlation_from });
    app.perform_later("compare.correlate", params);
    Ok(())
}

fn show_correlation(state: &mut CompareState, app: &mut ViewerApp, ui: &mut Ui) -> Option<usize> {
    ui.label(
        RichText::new(format!(
            "Type a number you know for each file (a temperature, a button state, a setting). Fields whose values follow it are ranked. At least {} files are needed; confidence grows with every file added.",
            correlation::MIN_SAMPLES
        ))
        .small()
        .color(theme::TEXT_DIM),
    );
    egui::Grid::new("compare-outside-values").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
        ui.label(RichText::new(app.display_name()).color(theme::ACCENT));
        ui.add(egui::TextEdit::singleline(&mut state.current_outside_value).desired_width(90.0));
        ui.end_row();
        for file in &mut state.files {
            ui.label(&file.name);
            ui.add(egui::TextEdit::singleline(&mut file.outside_value).desired_width(90.0));
            ui.end_row();
        }
    });
    ui.horizontal(|ui| {
        ui.label("Search from");
        ui.add(egui::DragValue::new(&mut state.correlation_from).hexadecimal(1, false, true).prefix("0x"));
        ui.label(
            RichText::new(format!("for {}", crate::compress::human_bytes(correlation::DEFAULT_SEARCH_LEN)))
                .color(theme::TEXT_DIM),
        );
        let can_run = state.correlation_pending.is_none() && state.files.len() + 1 >= correlation::MIN_SAMPLES;
        if ui.add_enabled(can_run, egui::Button::new("Find fields")).clicked() {
            state.messages.clear();
            if let Err(message) = start_correlation(state, app) {
                state.messages.push(message);
            }
        }
        if state.correlation_pending.is_some() {
            ui.spinner();
        }
    });
    let report = state.correlation.as_ref()?;
    ui.label(
        RichText::new(format!(
            "{} samples, searched 0x{:X}–0x{:X}. {}",
            report.samples,
            report.searched.start,
            report.searched.end,
            report.confidence.explanation()
        ))
        .small()
        .color(theme::TEXT_DIM),
    );
    if report.fields.is_empty() {
        ui.label(RichText::new("No field follows the outside values closely.").color(theme::TEXT_DIM));
        return None;
    }
    let mut jump = None;
    egui::ScrollArea::vertical().id_salt("compare-correlated").show(ui, |ui| {
        for field in &report.fields {
            let colour = if field.exact_fit { theme::ACCENT } else { theme::TEXT };
            let values: Vec<String> = field.values.iter().map(|value| format!("{value}")).collect();
            let response = ui
                .add(egui::Label::new(RichText::new(field.summary()).monospace().small().color(colour)).sense(Sense::click()))
                .on_hover_text(format!("Values per file: {}", values.join(", ")));
            if response.clicked() {
                jump = Some(state.current_start + field.offset);
            }
        }
    });
    jump
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

/// The person builds the recording's change timeline: `compare.timeline`,
/// carried out once the panel is drawn. Without a recording to build it
/// from, the panel says why instead.
fn start_timeline(app: &mut ViewerApp) -> Result<(), String> {
    recorded_changes(app)?;
    app.perform_later("compare.timeline", serde_json::json!({}));
    Ok(())
}

fn show_timeline(state: &mut CompareState, app: &mut ViewerApp, ui: &mut Ui) -> Option<usize> {
    let snapshots = app.bench.recording.as_ref().map_or(0, |recording| recording.len());
    ui.horizontal(|ui| {
        let can_run = state.timeline_pending.is_none() && snapshots >= timeline::MIN_SNAPSHOTS;
        let label = if state.timeline.is_some() { "Refresh" } else { "Build timeline" };
        if ui.add_enabled(can_run, egui::Button::new(label)).clicked() {
            state.messages.clear();
            if let Err(message) = start_timeline(app) {
                state.messages.push(message);
            }
        }
        if state.timeline_pending.is_some() {
            ui.spinner();
        }
        ui.label(RichText::new(format!("{snapshots} snapshots recorded")).color(theme::TEXT_DIM));
    });
    if snapshots < timeline::MIN_SNAPSHOTS && state.timeline.is_none() {
        ui.label(
            RichText::new("Record a live source or watched file (Live tab, \"Record history\") to see where it changes over time. At least two snapshots are needed.")
                .color(theme::TEXT_DIM),
        );
        return None;
    }
    let (Some(built), Some(texture)) = (&state.timeline, &state.timeline_texture) else { return None };
    if built.total_snapshots != snapshots {
        ui.label(RichText::new("The recording has changed since this was built; refresh to update.").small().color(theme::CURSOR));
    }
    ui.label(
        RichText::new(format!(
            "{} snapshots (from #{}) × {} columns of {} each. Time runs downwards; click a column to jump to it.",
            built.rows,
            built.first_index + 1,
            built.columns,
            crate::compress::human_bytes(built.bucket)
        ))
        .small()
        .color(theme::TEXT_DIM),
    );
    let mut jump = draw_heatmap(built, texture, ui);
    if let Some(offset) = show_most_active(built, ui) {
        jump = Some(offset);
    }
    jump
}

/// Paint the change matrix and the activity strip; returns a clicked offset.
fn draw_heatmap(built: &Timeline, texture: &TextureHandle, ui: &mut Ui) -> Option<usize> {
    let width = ui.available_width().max(64.0);
    let height = (built.rows as f32 * HEATMAP_ROW_HEIGHT).clamp(32.0, HEATMAP_MAX_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(vec2(width, height + ACTIVITY_STRIP_HEIGHT), Sense::click());
    let matrix_rect = Rect::from_min_size(rect.min, vec2(width, height));
    let strip_rect = Rect::from_min_size(pos2(rect.min.x, matrix_rect.max.y), vec2(width, ACTIVITY_STRIP_HEIGHT));
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, theme::SURFACE);
    painter.image(texture.id(), matrix_rect, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
    paint_activity_strip(built, &painter, strip_rect);

    let pointer = response.hover_pos()?;
    let column = column_at(built, rect, pointer.x);
    let offset = built.column_offset(column);
    let row = (((pointer.y - matrix_rect.min.y) / height) * built.rows as f32).floor() as usize;
    let span = variation::format_span(offset, offset + built.column_len(column));
    let tip = if matrix_rect.contains(pointer) && row < built.rows {
        let age = built.taken_at[row]
            .and_then(|time| time.elapsed().ok())
            .map_or(String::new(), |age| format!(", {}s ago", age.as_secs()));
        let changed = 100.0 * built.changed_fraction(row, column);
        format!("{span}\nsnapshot #{}{age}\n{changed:.0}% changed", built.first_index + row + 1)
    } else {
        format!("{span}\nchanged in {} snapshots", built.column_activity[column])
    };
    response.clone().on_hover_text_at_pointer(tip);
    response.clicked().then_some(offset)
}

fn column_at(built: &Timeline, rect: Rect, x: f32) -> usize {
    let fraction = ((x - rect.min.x) / rect.width()).clamp(0.0, 1.0);
    ((fraction * built.columns as f32) as usize).min(built.columns - 1)
}

/// A bar per column showing how many snapshots changed it.
fn paint_activity_strip(built: &Timeline, painter: &egui::Painter, rect: Rect) {
    let busiest = built.busiest_column_activity().max(1) as f32;
    let column_width = rect.width() / built.columns as f32;
    for (column, &activity) in built.column_activity.iter().enumerate() {
        if activity == 0 {
            continue;
        }
        let bar_height = rect.height() * activity as f32 / busiest;
        let left = rect.min.x + column as f32 * column_width;
        let bar = Rect::from_min_max(pos2(left, rect.max.y - bar_height), pos2(left + column_width.max(1.0), rect.max.y));
        painter.rect_filled(bar, 0.0, theme::ACCENT);
    }
}

/// The most often changed positions, clickable; returns a clicked offset.
fn show_most_active(built: &Timeline, ui: &mut Ui) -> Option<usize> {
    ui.label(RichText::new("Most active positions").strong());
    if built.most_active.is_empty() {
        ui.label(RichText::new("Nothing changed in these snapshots.").color(theme::TEXT_DIM));
        return None;
    }
    let mut jump = None;
    egui::ScrollArea::vertical().id_salt("compare-most-active").show(ui, |ui| {
        for span in &built.most_active {
            let text = format!(
                "{:<20} changed in {} of {} snapshots",
                variation::format_span(span.start, span.start + span.len),
                span.changes,
                built.rows
            );
            if ui.add(egui::Label::new(RichText::new(text).monospace().small()).sense(Sense::click())).clicked() {
                jump = Some(span.start);
            }
        }
    });
    jump
}

/// One pixel per cell: dark when unchanged, brighter the more changed.
fn heatmap_texture(ctx: &egui::Context, built: &Timeline) -> TextureHandle {
    let lut = crate::raster::Palette::Inferno.lut();
    let mut pixels = Vec::with_capacity(built.rows * built.columns);
    for row in 0..built.rows {
        for column in 0..built.columns {
            let fraction = built.changed_fraction(row, column);
            let colour = if fraction <= 0.0 {
                theme::BACKGROUND
            } else {
                let level = HEATMAP_PALETTE_FLOOR + fraction.min(1.0) * (255.0 - HEATMAP_PALETTE_FLOOR);
                lut[level as usize]
            };
            pixels.push(colour);
        }
    }
    let size = [built.columns.max(1), built.rows.max(1)];
    if pixels.len() != size[0] * size[1] {
        pixels.resize(size[0] * size[1], theme::BACKGROUND);
    }
    ctx.load_texture("compare-timeline", ColorImage::new(size, pixels), TextureOptions::NEAREST)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named_file(name: &str, outside_value: &str) -> CompareFile {
        CompareFile {
            name: name.to_string(),
            path: PathBuf::from(name),
            bytes: Arc::from(vec![0u8; 4]),
            truncated: false,
            start: 0,
            outside_value: outside_value.to_string(),
        }
    }

    #[test]
    fn outside_values_are_parsed_with_the_open_document_first() {
        let state = CompareState {
            current_outside_value: " 21.5 ".to_string(),
            files: vec![named_file("b.bin", "24"), named_file("c.bin", "-3")],
            ..Default::default()
        };
        assert_eq!(parse_outside_values(&state), Ok(vec![21.5, 24.0, -3.0]));
    }

    #[test]
    fn an_unparsable_outside_value_names_the_file() {
        let state = CompareState {
            current_outside_value: "1".to_string(),
            files: vec![named_file("warm.bin", "hot")],
            ..Default::default()
        };
        let error = parse_outside_values(&state).unwrap_err();
        assert!(error.contains("warm.bin") && error.contains("hot"), "{error}");
    }

    #[test]
    fn files_beyond_the_comparison_limit_are_refused_with_a_message() {
        let mut state = CompareState::default();
        let loaded: LoadedFiles = (0..variation::MAX_FILES).map(|index| Ok(named_file(&format!("{index}.bin"), ""))).collect();
        add_loaded_files(&mut state, loaded);
        assert_eq!(state.files.len(), variation::MAX_FILES - 1);
        assert_eq!(state.messages.len(), 1);
    }

    /// Draw the panel once in a headless frame.
    fn draw_frame(ctx: &egui::Context, state: &mut CompareState, app: &mut ViewerApp) {
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| show_compare(state, app, ui));
        // No renderer uploads textures here, so drop the uploads deliberately.
        output.textures_delta.clear();
    }

    /// Draw frames until no background work is pending, or give up.
    fn draw_until_idle(ctx: &egui::Context, state: &mut CompareState, app: &mut ViewerApp) {
        for _ in 0..500 {
            draw_frame(ctx, state, app);
            if !state.is_busy() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("background work did not finish");
    }

    fn capture(temperature_tenths: u16) -> Vec<u8> {
        let mut bytes = vec![0x11u8; 64];
        bytes[8..10].copy_from_slice(&temperature_tenths.to_le_bytes());
        bytes
    }

    #[test]
    fn every_section_runs_its_analysis_and_draws_without_panicking() {
        let ctx = egui::Context::default();
        let mut app = ViewerApp::new(crate::app::Launch::default());
        app.document = crate::document::Document::from_bytes(capture(215));
        let mut recording = crate::sources::Recording::new(1 << 20);
        for step in 0..4u8 {
            let mut bytes = capture(215);
            bytes[7] = step;
            recording.record(&bytes);
        }
        app.bench.recording = Some(recording);

        let mut state = CompareState { current_outside_value: "21.5".to_string(), current_start: 0, ..Default::default() };
        let mut paths = Vec::new();
        for (index, (tenths, text)) in [(240u16, "24"), (190, "19"), (302, "30.2")].into_iter().enumerate() {
            let path = std::env::temp_dir().join(format!("theviewer-compare-panel-{}-{index}.bin", std::process::id()));
            std::fs::write(&path, capture(tenths)).unwrap();
            state.files.push(CompareFile { path: path.clone(), bytes: Arc::from(capture(tenths)), ..named_file("capture.bin", text) });
            paths.push(path);
        }

        // Asked for while the panel is drawn, carried out before the next frame.
        crate::actions::take_performed();
        start_variation(&mut state, &mut app);
        start_correlation(&mut state, &mut app).expect("valid outside values");
        start_timeline(&mut app).expect("recording has snapshots");
        app.bench.panels.compare = state;
        app.perform_waiting_actions();
        let performed = crate::actions::take_performed();
        let files: Vec<serde_json::Value> = paths.iter().map(|path| serde_json::json!({"path": path.display().to_string(), "start": 0})).collect();
        assert_eq!(performed[0], ("compare.variation".to_string(), serde_json::json!({"start": 0, "files": files})));
        assert_eq!(performed[1], ("compare.correlate".to_string(), serde_json::json!({"start": 0, "files": files, "values": [21.5, 24.0, 19.0, 30.2], "from": 0})));
        assert_eq!(performed[2], ("compare.timeline".to_string(), serde_json::json!({})));
        let mut state = std::mem::take(&mut app.bench.panels.compare);
        draw_until_idle(&ctx, &mut state, &mut app);
        paths.iter().for_each(|path| drop(std::fs::remove_file(path)));
        assert!(state.messages.is_empty(), "{:?}", state.messages);

        let variation = state.variation.as_ref().expect("variation result");
        assert!(variation.regions.iter().any(|region| region.start == 8));
        let correlation = state.correlation.as_ref().expect("correlation result");
        assert_eq!(correlation.fields[0].offset, 8);
        let built = state.timeline.as_ref().expect("timeline result");
        assert_eq!(built.most_active[0].start, 7);

        for section in [CompareSection::Files, CompareSection::Variation, CompareSection::Correlation, CompareSection::Timeline] {
            state.section = section;
            draw_frame(&ctx, &mut state, &mut app);
        }
    }

    #[test]
    fn reading_a_missing_file_explains_the_failure() {
        let error = read_compare_file(Path::new("/definitely/not/here.bin")).err().expect("missing file");
        assert!(error.contains("here.bin"), "{error}");
    }
}
