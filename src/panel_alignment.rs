//! Panel for message alignment and clustering: takes the messages found by
//! the protocol analysis (or the selection cut into raster rows), clusters
//! them into probable message types and shows each cluster's alignment as a
//! hex grid coloured by column class. Clicking a cell jumps to that byte.

use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Align2, Color32, FontId, Rect, RichText, Sense, Stroke, Ui, vec2};

use crate::alignment::{self, AlignmentOptions, AlignmentReport, ClusterReport, ColumnClass};
use crate::app::ViewerApp;
use crate::plugin::Category;
use crate::theme;

/// How often the panel repaints while alignment runs.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Most bytes read per message; longer messages are aligned on this prefix
/// (and their length field is judged on it).
const READ_LIMIT: usize = 4096;
/// Hex bytes shown in a cluster's sample.
const SAMPLE_BYTES: usize = 16;
/// Grid geometry, in points.
const CELL_WIDTH: f32 = 22.0;
const CELL_HEIGHT: f32 = 16.0;
const ROW_LABEL_WIDTH: f32 = 56.0;
const GRID_FONT_SIZE: f32 = 11.0;
/// Opacity of the class colour behind a cell.
const CELL_TINT: f32 = 0.35;
/// Height of the cluster list before it scrolls.
const CLUSTER_LIST_HEIGHT: f32 = 120.0;

/// A finished alignment and where its messages are in the document.
pub struct AlignmentJob {
    /// Where the messages came from, for display.
    pub source: String,
    /// Document offset of each input message.
    pub offsets: Vec<usize>,
    pub report: AlignmentReport,
}

/// Everything the alignment panel keeps between frames.
#[derive(Default)]
pub struct AlignmentState {
    /// Cluster merge threshold; `None` uses the default.
    pub threshold: Option<f64>,
    pending: Option<Receiver<AlignmentJob>>,
    pub job: Option<AlignmentJob>,
    pub selected_cluster: usize,
    /// Why the last "Align messages" could not start.
    pub input_error: Option<String>,
}

impl AlignmentState {
    fn threshold(&self) -> f64 {
        self.threshold.unwrap_or(alignment::DEFAULT_CLUSTER_THRESHOLD)
    }
}

/// Messages gathered from the document: their offsets and bytes.
struct GatheredMessages {
    source: String,
    offsets: Vec<usize>,
    bytes: Vec<Vec<u8>>,
}

/// Show the alignment panel.
pub fn show_alignment(state: &mut AlignmentState, app: &mut ViewerApp, ui: &mut Ui) {
    poll(state);
    ui.label(
        RichText::new("Groups messages into probable types, aligns each group byte by byte and marks columns as constant, counter, length or variable.")
            .color(theme::TEXT_DIM),
    );
    ui.horizontal_wrapped(|ui| {
        let busy = state.pending.is_some();
        if ui.add_enabled(!busy, egui::Button::new("Align messages")).clicked() {
            start_alignment(state, app);
        }
        let mut threshold = state.threshold();
        let slider = egui::Slider::new(&mut threshold, 0.1..=0.95).text("cluster similarity");
        if ui.add(slider).changed() {
            state.threshold = Some(threshold);
        }
        if busy {
            ui.spinner();
            ui.label(RichText::new("Clustering and aligning…").color(theme::TEXT_DIM));
            ui.ctx().request_repaint_after(POLL_INTERVAL);
        }
    });
    ui.label(RichText::new(source_hint(app)).small().color(theme::TEXT_DIM));
    if let Some(error) = &state.input_error {
        ui.label(RichText::new(error).color(theme::DANGER));
    }
    let Some(job) = &state.job else { return };
    ui.separator();
    let mut jump = None;
    show_job(job, &mut state.selected_cluster, &mut jump, ui);
    if let Some(offset) = jump {
        app.jump_to_offset(offset);
    }
}

fn poll(state: &mut AlignmentState) {
    let Some(receiver) = &state.pending else { return };
    match receiver.try_recv() {
        Ok(job) => {
            state.job = Some(job);
            state.selected_cluster = 0;
            state.pending = None;
        }
        Err(mpsc::TryRecvError::Disconnected) => {
            state.pending = None;
            state.input_error = Some("The alignment stopped unexpectedly.".to_string());
        }
        Err(mpsc::TryRecvError::Empty) => {}
    }
}

fn source_hint(app: &ViewerApp) -> String {
    if let Some(view) = &app.bench.tools.protocol
        && !view.report.messages.is_empty()
    {
        return format!("Uses the {} messages from the protocol analysis.", view.report.messages.len());
    }
    match app.selection() {
        Some(_) => format!("Uses the selection, one message per raster row of {} bytes.", app.shape.row_stride()),
        None => "Run the protocol analysis first, or select messages laid out one per raster row.".to_string(),
    }
}

fn start_alignment(state: &mut AlignmentState, app: &mut ViewerApp) {
    state.input_error = None;
    let gathered = match gather_messages(app) {
        Ok(gathered) => gathered,
        Err(message) => {
            state.input_error = Some(message);
            return;
        }
    };
    let options = AlignmentOptions { threshold: state.threshold() };
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let report = alignment::analyse(&gathered.bytes, &options);
        let _ = sender.send(AlignmentJob { source: gathered.source, offsets: gathered.offsets, report });
    });
    state.pending = Some(receiver);
}

/// The protocol analysis's messages if there are any, else the selection cut
/// into raster rows.
fn gather_messages(app: &mut ViewerApp) -> Result<GatheredMessages, String> {
    let framed: Option<(usize, Vec<(usize, usize)>)> = app.bench.tools.protocol.as_ref().map(|view| {
        let messages = view.report.messages.iter().take(alignment::MAX_CLUSTERED_MESSAGES).map(|m| (m.offset, m.len)).collect();
        (view.base, messages)
    });
    if let Some((base, messages)) = framed
        && !messages.is_empty()
    {
        let offsets: Vec<usize> = messages.iter().map(|&(offset, _)| base + offset).collect();
        let bytes = messages.iter().map(|&(offset, len)| app.document.read_range(base + offset, len.min(READ_LIMIT))).collect();
        return Ok(GatheredMessages { source: "protocol analysis".to_string(), offsets, bytes });
    }
    let (start, len) = app.selection().ok_or("Run the protocol analysis first, or select the messages (one per raster row).")?;
    let stride = app.shape.row_stride().max(1);
    let rows = (len.div_ceil(stride)).min(alignment::MAX_CLUSTERED_MESSAGES);
    if rows < 2 {
        return Err(format!("The selection holds fewer than 2 rows of {stride} bytes."));
    }
    let bytes = app.document.read_range(start, len.min(rows * stride));
    let records = alignment::split_into_records(&bytes, stride);
    let offsets = (0..records.len()).map(|row| start + row * stride).collect();
    Ok(GatheredMessages { source: format!("selection rows of {stride} bytes"), offsets, bytes: records })
}

fn show_job(job: &AlignmentJob, selected: &mut usize, jump: &mut Option<usize>, ui: &mut Ui) {
    let report = &job.report;
    ui.label(
        RichText::new(format!("{} messages from the {} in {} clusters", job.offsets.len(), job.source, report.clusters.len()))
            .small()
            .color(theme::TEXT_DIM),
    );
    for note in &report.notes {
        ui.label(RichText::new(note).small().color(theme::TEXT_DIM));
    }
    if report.clusters.is_empty() {
        return;
    }
    egui::ScrollArea::vertical().id_salt("alignment-clusters").max_height(CLUSTER_LIST_HEIGHT).show(ui, |ui| {
        for (index, cluster) in report.clusters.iter().enumerate() {
            let text = format!("Type {index} · {} messages · {}", cluster.members.len(), cluster_sample(cluster));
            if ui.selectable_label(*selected == index, RichText::new(text).monospace().small()).clicked() {
                *selected = index;
            }
        }
    });
    let Some(cluster) = report.clusters.get(*selected) else { return };
    ui.separator();
    show_cluster_summary(cluster, ui);
    show_grid(cluster, &job.offsets, jump, ui);
}

/// The first bytes of the cluster's first message, as hex.
fn cluster_sample(cluster: &ClusterReport) -> String {
    let Some(row) = cluster.alignment.rows.first() else { return String::new() };
    let bytes: Vec<String> = row.cells.iter().flatten().take(SAMPLE_BYTES).map(|cell| format!("{:02X}", cell.value)).collect();
    bytes.join(" ")
}

fn show_cluster_summary(cluster: &ClusterReport, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        for class in [ColumnClass::Constant, ColumnClass::Counter, ColumnClass::Length, ColumnClass::Variable] {
            theme::swatch(ui, class_colour(class), class.label());
        }
    });
    let fields: Vec<String> = cluster
        .fields
        .iter()
        .filter(|field| field.class != ColumnClass::Variable)
        .map(|field| format!("{} {}..{}", field.class.label(), field.start_column, field.start_column + field.len))
        .collect();
    if !fields.is_empty() {
        ui.label(RichText::new(format!("Fields: {}", fields.join(" · "))).small());
    }
    for note in &cluster.notes {
        ui.label(RichText::new(note).small().color(theme::TEXT_DIM));
    }
}

fn class_colour(class: ColumnClass) -> Color32 {
    match class {
        ColumnClass::Constant => Category::Padding.colour(),
        ColumnClass::Counter => Category::Counter.colour(),
        ColumnClass::Length => Category::Structure.colour(),
        ColumnClass::Variable => Category::HighEntropy.colour(),
    }
}

/// The aligned grid: a header row of column classes, then one row per
/// message. Only the visible cells are painted.
fn show_grid(cluster: &ClusterReport, offsets: &[usize], jump: &mut Option<usize>, ui: &mut Ui) {
    let rows = &cluster.alignment.rows;
    let columns = cluster.alignment.columns();
    let header_rows = 1;
    let size = vec2(ROW_LABEL_WIDTH + columns as f32 * CELL_WIDTH, (rows.len() + header_rows) as f32 * CELL_HEIGHT);
    egui::ScrollArea::both().id_salt("alignment-grid").auto_shrink([false, false]).show_viewport(ui, |ui, viewport| {
        let (grid, response) = ui.allocate_exact_size(size, Sense::click());
        let painter = ui.painter_at(grid);
        let font = FontId::monospace(GRID_FONT_SIZE);
        let first_column = ((viewport.min.x - ROW_LABEL_WIDTH).max(0.0) / CELL_WIDTH) as usize;
        let last_column = (((viewport.max.x - ROW_LABEL_WIDTH).max(0.0) / CELL_WIDTH) as usize + 1).min(columns);
        let first_row = (viewport.min.y / CELL_HEIGHT) as usize;
        let last_row = ((viewport.max.y / CELL_HEIGHT) as usize + 1).min(rows.len() + header_rows);
        let cell_rect = |row: usize, column: usize| {
            let min = grid.min + vec2(ROW_LABEL_WIDTH + column as f32 * CELL_WIDTH, row as f32 * CELL_HEIGHT);
            Rect::from_min_size(min, vec2(CELL_WIDTH - 1.0, CELL_HEIGHT - 1.0))
        };
        for grid_row in first_row..last_row {
            let label_position = grid.min + vec2(2.0, grid_row as f32 * CELL_HEIGHT);
            let label = if grid_row == 0 { "class".to_string() } else { format!("#{}", rows[grid_row - 1].message) };
            painter.text(label_position, Align2::LEFT_TOP, label, font.clone(), theme::TEXT_DIM);
            for column in first_column..last_column {
                let summary = &cluster.columns[column];
                let colour = class_colour(summary.class);
                let rect = cell_rect(grid_row, column);
                if grid_row == 0 {
                    painter.rect_filled(rect, 2.0, colour);
                    continue;
                }
                let cell = rows[grid_row - 1].cells[column];
                let (text, text_colour) = match cell {
                    Some(byte) => (format!("{:02X}", byte.value), theme::TEXT),
                    None => ("--".to_string(), theme::TEXT_DIM),
                };
                if cell.is_some() {
                    painter.rect_filled(rect, 2.0, colour.gamma_multiply(CELL_TINT));
                }
                painter.text(rect.center(), Align2::CENTER_CENTER, text, font.clone(), text_colour);
            }
        }
        if let Some(pointer) = response.hover_pos() {
            let local = pointer - grid.min;
            if local.x >= ROW_LABEL_WIDTH && local.y >= CELL_HEIGHT {
                let column = ((local.x - ROW_LABEL_WIDTH) / CELL_WIDTH) as usize;
                let row = (local.y / CELL_HEIGHT) as usize;
                if column < columns && row > 0 && row <= rows.len() {
                    painter.rect_stroke(cell_rect(row, column), 2.0, Stroke::new(1.0, theme::CURSOR), egui::StrokeKind::Inside);
                    let summary = &cluster.columns[column];
                    let tooltip = format!("column {column}: {} — {}", summary.class.label(), summary.detail);
                    let byte = rows[row - 1].cells[column];
                    let response = response.clone().on_hover_text(tooltip);
                    if response.clicked()
                        && let Some(byte) = byte
                        && let Some(&offset) = offsets.get(rows[row - 1].message)
                    {
                        *jump = Some(offset + byte.position);
                    }
                }
            }
        }
    });
}
