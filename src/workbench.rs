//! State and behaviour behind the dock's tools: the whole-file report and
//! file map, the Hilbert view, templates, unpacking, the assistant's tools,
//! plotting, live sources, watch mode and recording.
//!
//! Kept out of `app.rs` so the core app stays readable. Everything here goes
//! through `ViewerApp`'s public surface.

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, ColorImage, Context, Rect, RichText, Sense, Stroke, StrokeKind, TextureHandle, TextureOptions, Ui, pos2, vec2};

use crate::app::{DialogKind, FileAction, ViewerApp};
use crate::panels::{self, PanelStates};
use crate::assistant::{self, FileContext, ToolCall};
use crate::document::Document;
use crate::dock::{self, DockTab};
use crate::explain::{self, Region, Report};
use crate::hilbert;
use crate::plot::{self, PcmFormat};
use crate::plugin::{Category, Field, Finding, ScanContext};
use crate::raster::{self, PixelFormat};
use crate::search;
use crate::sources::{self, FileWatcher, Recording, SerialCapture, SourceSpec};
use crate::templates::{self, Applied, Template};
use crate::theme;
use crate::unpack::{self, Node};
use crate::{patterns, player};

/// Largest prefix of a file the report and unpacker read into memory.
pub(crate) const ANALYSIS_READ_LIMIT: usize = 256 * 1024 * 1024;
/// Largest file kept in the recording history.
const RECORDING_FILE_LIMIT: usize = 256 * 1024 * 1024;
/// How often watched files and serial captures are checked.
const LIVE_POLL_INTERVAL: Duration = Duration::from_millis(400);
/// Bytes a template is applied to.
const TEMPLATE_READ: usize = 16 * 1024 * 1024;
/// Rows shown in the template records table.
const MAX_TABLE_ROWS: usize = 5000;

/// How the central view lays bytes out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Rows,
    Hilbert,
}

/// Results that arrive from background work.
enum Pending {
    Report(Receiver<(Vec<Region>, Report)>),
    Unpack(Receiver<Node>),
    Source(Receiver<Result<(String, Vec<u8>), String>>),
}

pub struct Workbench {
    /// Findings that belong to the document rather than a scan: applied
    /// templates and changed ranges. Shown with the scanned findings.
    pub pinned: Vec<Finding>,
    pending: Vec<Pending>,

    pub regions: Vec<Region>,
    pub report: Option<Report>,
    pub show_file_map: bool,

    pub layout: Layout,
    hilbert: Option<HilbertView>,

    pub template_source: String,
    pub template_choice: String,
    pub template_result: Option<Applied>,
    pub template_error: Option<String>,
    pub template_records: usize,

    pub unpacked: Option<Node>,

    /// State of the self-contained tool panels.
    pub panels: PanelStates,

    serial: Option<SerialCapture>,
    serial_seen: usize,
    watcher: Option<FileWatcher>,
    pub watch_enabled: bool,
    last_live_poll: Instant,
    pub recording: Option<Recording>,
    pub recording_index: usize,
    pub process_regions: Vec<sources::MemoryRegion>,
    pub process_pid: Option<u32>,
    pub live_error: Option<String>,

    pub pcm_format: PcmFormat,
    pub pcm_rate: u32,
    pub pcm_channels: u16,

    /// Disassembly, checksums, diff and pointer graph.
    pub analysis: crate::analysis_tabs::AnalysisState,
    /// Columns, protocol, statistics, strings and XOR.
    pub tools: crate::analysis_tools::ToolsState,
}

impl Default for Workbench {
    fn default() -> Self {
        Workbench {
            pinned: Vec::new(),
            pending: Vec::new(),
            regions: Vec::new(),
            report: None,
            show_file_map: true,
            layout: Layout::Rows,
            hilbert: None,
            template_source: templates::builtin_templates().first().map(|(_, s)| s.to_string()).unwrap_or_default(),
            template_choice: templates::builtin_templates().first().map(|(n, _)| n.to_string()).unwrap_or_default(),
            template_result: None,
            template_error: None,
            template_records: 8,
            unpacked: None,
            panels: PanelStates::default(),
            serial: None,
            serial_seen: 0,
            watcher: None,
            watch_enabled: false,
            last_live_poll: Instant::now(),
            recording: None,
            recording_index: 0,
            process_regions: Vec::new(),
            process_pid: None,
            live_error: None,
            pcm_format: PcmFormat::S16Le,
            pcm_rate: 22_050,
            pcm_channels: 1,
            analysis: Default::default(),
            tools: Default::default(),
        }
    }
}

impl Workbench {
    /// Forget everything that described the previous document's bytes.
    /// Live sources and recording survive, since they produce the new bytes.
    pub fn document_changed(&mut self) {
        self.pinned.clear();
        self.regions.clear();
        self.report = None;
        self.hilbert = None;
        self.template_result = None;
        self.unpacked = None;
        self.analysis.document_changed();
        self.tools.document_changed();
        self.pending.retain(|pending| matches!(pending, Pending::Source(_)));
    }

    fn busy(&self, kind: fn(&Pending) -> bool) -> bool {
        self.pending.iter().any(kind)
    }
}

/// A cached Hilbert rendering of the whole file.
struct HilbertView {
    version: u64,
    format: PixelFormat,
    palette: raster::Palette,
    order: u32,
    texture: TextureHandle,
    /// Bytes represented by each cell.
    bytes_per_cell: f64,
}

/// One pinned "changed bytes" finding for a range.
fn changed_finding(start: usize, len: usize, label: &str) -> Finding {
    Finding::new("changed", "live", Category::Custom, start, len.max(1))
        .title(label.to_string())
        .detail(format!("{len} bytes"))
}

impl ViewerApp {
    // -----------------------------------------------------------------------
    // Polling
    // -----------------------------------------------------------------------

    /// Collect background results and service live sources. Called every frame.
    pub fn poll_workbench(&mut self, ctx: &Context) {
        let pending = std::mem::take(&mut self.bench.pending);
        for item in pending {
            match item {
                Pending::Report(receiver) => match receiver.try_recv() {
                    Ok((regions, report)) => {
                        self.bench.regions = regions;
                        self.bench.report = Some(report);
                    }
                    Err(mpsc::TryRecvError::Empty) => self.bench.pending.push(Pending::Report(receiver)),
                    Err(mpsc::TryRecvError::Disconnected) => {}
                },
                Pending::Unpack(receiver) => match receiver.try_recv() {
                    Ok(node) => {
                        self.status = format!("Unpacked {} items", node.count().saturating_sub(1));
                        self.bench.unpacked = Some(node);
                    }
                    Err(mpsc::TryRecvError::Empty) => self.bench.pending.push(Pending::Unpack(receiver)),
                    Err(mpsc::TryRecvError::Disconnected) => {}
                },
                Pending::Source(receiver) => match receiver.try_recv() {
                    Ok(Ok((name, bytes))) => self.open_bytes(bytes, name),
                    Ok(Err(message)) => {
                        self.bench.live_error = Some(message.clone());
                        self.status = message;
                    }
                    Err(mpsc::TryRecvError::Empty) => self.bench.pending.push(Pending::Source(receiver)),
                    Err(mpsc::TryRecvError::Disconnected) => {}
                },
            }
        }
        if !self.bench.pending.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(80));
        }

        let mut assistant = std::mem::take(&mut self.assistant);
        if assistant.poll(|call| self.run_assistant_tool(call)) {
            ctx.request_repaint();
        }
        if assistant.is_busy() {
            ctx.request_repaint_after(Duration::from_millis(60));
        }
        self.assistant = assistant;

        if self.plot.refresh_requested {
            self.plot.refresh_requested = false;
            self.open_plot();
        }

        // Live sources feed the top-level document, so they wait while a
        // derived document (an unpacked block, say) is open on top of it.
        let showing_live_document = self.parents.is_empty();
        if (self.bench.serial.is_some() || self.bench.watch_enabled)
            && showing_live_document
            && self.bench.last_live_poll.elapsed() >= LIVE_POLL_INTERVAL
        {
            self.bench.last_live_poll = Instant::now();
            self.poll_serial();
            self.poll_watcher();
        }
        if self.bench.serial.is_some() || self.bench.watch_enabled {
            ctx.request_repaint_after(LIVE_POLL_INTERVAL);
        }
    }

    // -----------------------------------------------------------------------
    // Dock tabs that live here
    // -----------------------------------------------------------------------

    pub fn show_dock_tab(&mut self, tab: DockTab, ui: &mut Ui) {
        match tab {
            DockTab::Report => self.show_report_tab(ui),
            DockTab::Template => self.show_template_tab(ui),
            DockTab::Unpacked => self.show_unpacked_tab(ui),
            DockTab::Disassembly => self.show_disassembly_tab(ui),
            DockTab::Checksums => self.show_checksums_tab(ui),
            DockTab::Diff => self.show_diff_tab(ui),
            DockTab::Columns => crate::analysis_tools::show_columns(self, ui),
            DockTab::Protocol => crate::analysis_tools::show_protocol(self, ui),
            DockTab::Statistics => crate::analysis_stats::show_statistics(self, ui),
            DockTab::Strings => crate::analysis_stats::show_strings(self, ui),
            DockTab::Xor => crate::analysis_stats::show_xor(self, ui),
            DockTab::Crypto => panels::show(self, ui, |p| &mut p.crypto, crate::panel_crypto::show_crypto),
            DockTab::Compare => panels::show(self, ui, |p| &mut p.compare, crate::panel_compare::show_compare),
            DockTab::Bits => panels::show(self, ui, |p| &mut p.bits, crate::panel_bits::show_bits),
            DockTab::Assistant | DockTab::Live => {}
        }
    }

    // -----------------------------------------------------------------------
    // Report and file map
    // -----------------------------------------------------------------------

    /// Map and explain the whole file on a background thread.
    pub fn start_report(&mut self) {
        if self.bench.busy(|p| matches!(p, Pending::Report(_))) || self.document.is_empty() {
            return;
        }
        let bytes = self.document.read_range(0, ANALYSIS_READ_LIMIT);
        let name = self.display_name();
        let registry = Arc::clone(&self.registry);
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let regions = explain::map_file(&bytes, &registry);
            let report = explain::explain(&bytes, &name, &regions);
            let _ = sender.send((regions, report));
        });
        self.bench.pending.push(Pending::Report(receiver));
    }

    pub fn report_running(&self) -> bool {
        self.bench.busy(|p| matches!(p, Pending::Report(_)))
    }

    fn show_report_tab(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.button(if self.bench.report.is_some() { "Re-analyse" } else { "Explain this file" }).clicked() {
                self.start_report();
            }
            if self.report_running() {
                ui.spinner();
                ui.label(RichText::new("Mapping the file…").color(theme::TEXT_DIM));
            }
            ui.checkbox(&mut self.bench.show_file_map, "File map above the view");
            if self.document.len() > ANALYSIS_READ_LIMIT {
                ui.label(RichText::new(format!("analyses the first {}", crate::compress::human_bytes(ANALYSIS_READ_LIMIT))).small().color(theme::TEXT_DIM));
            }
        });
        let Some(report) = self.bench.report.clone() else {
            if !self.report_running() {
                ui.label(RichText::new("A plain-language overview of the whole file: what it is, and where its parts are. Every sentence links to the bytes.").color(theme::TEXT_DIM));
            }
            return;
        };
        ui.add_space(4.0);
        ui.label(RichText::new(&report.headline).heading().color(theme::TEXT));
        egui::ScrollArea::vertical().id_salt("report-sentences").show(ui, |ui| {
            for sentence in &report.sentences {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
                    let kind = self.bench.regions.iter().find(|r| r.start == sentence.start).map(|r| r.kind.colour()).unwrap_or(theme::TEXT_DIM);
                    ui.painter().rect_filled(rect, 2.0, kind);
                    dock::linked_text(self, ui, &sentence.text);
                    if sentence.len > 0 && ui.small_button("select").clicked() {
                        self.anchor = Some(sentence.start);
                        self.cursor = sentence.start + sentence.len;
                        self.reveal_cursor_centred();
                        self.reveal_cursor_in_hex(true);
                    }
                });
            }
        });
    }

    /// The coloured bar of regions above the raster; click to jump.
    pub fn show_file_map(&mut self, ui: &mut Ui) {
        if !self.bench.show_file_map || self.bench.regions.is_empty() || self.document.is_empty() {
            return;
        }
        let (rect, response) = dock::timeline_bar(ui, 16.0);
        let painter = ui.painter_at(rect);
        let total = self.document.len().max(1) as f32;
        for region in &self.bench.regions {
            let x0 = rect.min.x + rect.width() * region.start as f32 / total;
            let x1 = (rect.min.x + rect.width() * region.end() as f32 / total).max(x0 + 1.0);
            painter.rect_filled(Rect::from_min_max(pos2(x0, rect.min.y), pos2(x1, rect.max.y)), 0.0, region.kind.colour().gamma_multiply(if region.confident { 1.0 } else { 0.6 }));
        }
        let cursor_x = rect.min.x + rect.width() * self.cursor as f32 / total;
        painter.line_segment([pos2(cursor_x, rect.min.y), pos2(cursor_x, rect.max.y)], Stroke::new(2.0, theme::CURSOR));
        if let Some(pointer) = response.hover_pos() {
            let offset = ((pointer.x - rect.min.x) / rect.width() * total) as usize;
            if let Some(region) = self.bench.regions.iter().find(|r| offset >= r.start && offset < r.end()) {
                response.clone().on_hover_text(format!("{} at {:#x} ({}): {}", region.label, region.start, crate::compress::human_bytes(region.len), region.detail));
            }
            if response.clicked() {
                self.jump_to_offset(offset);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Hilbert view
    // -----------------------------------------------------------------------

    /// Draw the whole file along a Hilbert curve, which keeps nearby bytes
    /// close together in two dimensions so structure shows without a width.
    pub fn show_hilbert(&mut self, ui: &mut Ui, rect: Rect) {
        let len = self.document.len();
        if len == 0 {
            return;
        }
        let stale = self.bench.hilbert.as_ref().is_none_or(|view| {
            view.version != self.document.version() || view.format != self.shape.format || view.palette != self.shape.palette
        });
        if stale {
            let order = hilbert::order_for(len);
            let cells = 1usize << (2 * order);
            let bytes = sampled_bytes(&mut self.document, cells);
            let lut = self.shape.palette.lut();
            let class = self.shape.format == PixelFormat::ByteClass;
            let pixels = hilbert::render(&bytes, order, |byte| if class { raster::byte_class_colour(byte) } else { lut[byte as usize] });
            let side = 1usize << order;
            let image = ColorImage::new([side, side], pixels);
            let texture = ui.ctx().load_texture("hilbert", image, TextureOptions::NEAREST);
            self.bench.hilbert = Some(HilbertView {
                version: self.document.version(),
                format: self.shape.format,
                palette: self.shape.palette,
                order,
                texture,
                bytes_per_cell: (len as f64 / cells as f64).max(1.0),
            });
        }
        let view = self.bench.hilbert.as_ref().expect("built above");
        let side = (1u32 << view.order) as f32;
        let size = rect.width().min(rect.height());
        let drawn = Rect::from_min_size(rect.min, vec2(size, size));
        let painter = ui.painter_at(rect);
        painter.image(view.texture.id(), drawn, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
        let cell = size / side;
        let (order, bytes_per_cell) = (view.order, view.bytes_per_cell);
        let offset_at = |pointer: egui::Pos2| -> Option<usize> {
            if !drawn.contains(pointer) {
                return None;
            }
            let x = ((pointer.x - drawn.min.x) / cell) as u32;
            let y = ((pointer.y - drawn.min.y) / cell) as u32;
            let d = hilbert::xy_to_d(order, x.min(side as u32 - 1), y.min(side as u32 - 1));
            let offset = (d as f64 * bytes_per_cell) as usize;
            (offset < len).then_some(offset)
        };
        let response = ui.interact(rect, ui.id().with("hilbert"), Sense::click());
        if let Some(pointer) = response.hover_pos() {
            self.hover = offset_at(pointer);
        }
        if response.clicked()
            && let Some(offset) = response.interact_pointer_pos().and_then(offset_at)
        {
            self.jump_to_offset(offset);
        }
        // Cursor marker.
        let d = (self.cursor as f64 / bytes_per_cell) as u64;
        let (x, y) = hilbert::d_to_xy(order, d.min((1u64 << (2 * order)) - 1));
        let marker = Rect::from_min_size(drawn.min + vec2(x as f32 * cell, y as f32 * cell), vec2(cell.max(3.0), cell.max(3.0)));
        painter.rect_stroke(marker.expand(2.0), 0.0, Stroke::new(2.0, theme::CURSOR), StrokeKind::Outside);
        painter.text(
            drawn.right_top() + vec2(8.0, 0.0),
            egui::Align2::LEFT_TOP,
            format!("Hilbert curve, {} B per cell", bytes_per_cell.round() as usize),
            egui::FontId::proportional(12.0),
            theme::TEXT_DIM,
        );
    }

    // -----------------------------------------------------------------------
    // Templates
    // -----------------------------------------------------------------------

    /// Where a template applies: the selection start, else the cursor.
    fn template_origin(&self) -> usize {
        self.selection().map(|(start, _)| start).unwrap_or(self.cursor)
    }

    /// Parse and apply template source at the cursor (or selection start).
    pub fn apply_template_source(&mut self, source: &str) {
        self.bench.template_source = source.to_string();
        self.dock.open = true;
        self.dock.tab = DockTab::Template;
        match Template::parse(source) {
            Ok(template) => {
                let origin = self.template_origin();
                let bytes = self.document.read_range(origin, TEMPLATE_READ);
                let applied = template.apply(&bytes, origin);
                self.bench.pinned.retain(|f| !f.id.starts_with("template:"));
                self.bench.pinned.push(applied.finding.clone());
                self.cursor_structure = Some(applied.finding.clone());
                self.status = format!(
                    "{} applied at {origin:#x}: {} records{}",
                    template.name(),
                    applied.records.len(),
                    if applied.warnings.is_empty() { String::new() } else { format!(", {} warnings", applied.warnings.len()) }
                );
                self.bench.template_error = None;
                self.bench.template_result = Some(applied);
            }
            Err(error) => {
                self.bench.template_error = Some(error.to_string());
                self.status = format!("Template error: {error}");
            }
        }
    }

    /// Propose a struct for the selected records.
    pub fn infer_template(&mut self) {
        let Some((start, len)) = self.selection() else {
            self.status = "Select a few records first".to_string();
            return;
        };
        let bytes = self.document.read_range(start, len);
        let record_len = templates::guess_record_length(&bytes).unwrap_or(self.shape.row_stride()).max(1);
        let records = (len / record_len).max(1);
        let source = templates::infer_struct(&bytes, record_len, records, self.document.len());
        self.status = format!("Inferred a {record_len}-byte record from {records} examples");
        self.apply_template_source(&source);
    }

    fn show_template_tab(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("template-choice")
                .selected_text(&self.bench.template_choice)
                .show_ui(ui, |ui| {
                    let mut all: Vec<(String, String)> = templates::builtin_templates().into_iter().map(|(n, s)| (n.to_string(), s.to_string())).collect();
                    if let Some(dir) = templates::default_dir() {
                        for (name, result) in templates::load_dir(&dir) {
                            if result.is_ok()
                                && let Ok(source) = std::fs::read_to_string(dir.join(format!("{name}.tpl")))
                            {
                                all.push((name, source));
                            }
                        }
                    }
                    for (name, source) in all {
                        if ui.selectable_label(self.bench.template_choice == name, &name).clicked() {
                            self.bench.template_choice = name;
                            self.bench.template_source = source;
                        }
                    }
                });
            if ui.button("Apply at cursor").on_hover_text("Applies at the selection start when there is a selection").clicked() {
                let source = self.bench.template_source.clone();
                self.apply_template_source(&source);
            }
            if ui.button("Infer from selection").on_hover_text("Select several records; the app proposes a struct from what varies").clicked() {
                self.infer_template();
            }
            if ui.button("Clear").clicked() {
                self.bench.pinned.retain(|f| !f.id.starts_with("template:"));
                self.bench.template_result = None;
            }
        });
        let width = ui.available_width();
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width((width * 0.42).max(240.0));
                egui::ScrollArea::vertical().id_salt("template-source").max_height(ui.available_height()).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut self.bench.template_source).code_editor().desired_width(f32::INFINITY).desired_rows(14));
                });
                if let Some(error) = &self.bench.template_error {
                    ui.label(RichText::new(error).color(theme::DANGER));
                }
            });
            ui.separator();
            ui.vertical(|ui| self.show_template_records(ui));
        });
    }

    fn show_template_records(&mut self, ui: &mut Ui) {
        let Some(applied) = &self.bench.template_result else {
            ui.label(RichText::new("Apply a template to see its records as a table. Fields also appear in the inspector's structure tree.").color(theme::TEXT_DIM));
            return;
        };
        for warning in applied.warnings.iter().take(3) {
            ui.label(RichText::new(warning).small().color(theme::CURSOR));
        }
        let columns = applied.columns();
        let records = applied.records.clone();
        if records.is_empty() {
            ui.label(RichText::new("No repeated records; see the structure tree in the inspector.").color(theme::TEXT_DIM));
            return;
        }
        let mut chosen = None;
        egui::ScrollArea::both().id_salt("template-records").show(ui, |ui| {
            egui::Grid::new("template-grid").striped(true).spacing([14.0, 2.0]).show(ui, |ui| {
                ui.label(RichText::new("#").strong());
                ui.label(RichText::new("offset").strong());
                for column in &columns {
                    ui.label(RichText::new(column).strong());
                }
                ui.end_row();
                for (index, record) in records.iter().take(MAX_TABLE_ROWS).enumerate() {
                    if ui.add(egui::Label::new(index.to_string()).sense(Sense::click())).clicked() {
                        chosen = Some((record.offset, record.len));
                    }
                    ui.monospace(RichText::new(format!("{:#x}", record.offset)).color(theme::TEXT_DIM));
                    for column in &columns {
                        ui.monospace(record.value(column).unwrap_or(""));
                    }
                    ui.end_row();
                }
            });
            if records.len() > MAX_TABLE_ROWS {
                ui.label(RichText::new(format!("… {} more records", records.len() - MAX_TABLE_ROWS)).color(theme::TEXT_DIM));
            }
        });
        if let Some((offset, len)) = chosen {
            self.anchor = Some(offset);
            self.cursor = offset + len.max(1);
            self.reveal_cursor_centred();
            self.reveal_cursor_in_hex(true);
        }
    }

    // -----------------------------------------------------------------------
    // Unpacking
    // -----------------------------------------------------------------------

    pub fn start_unpack(&mut self) {
        if self.bench.busy(|p| matches!(p, Pending::Unpack(_))) || self.document.is_empty() {
            return;
        }
        let bytes = Arc::new(self.document.read_range(0, ANALYSIS_READ_LIMIT));
        let name = self.display_name();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(unpack::unpack(bytes, &name, &unpack::Limits::default()));
        });
        self.bench.pending.push(Pending::Unpack(receiver));
        self.status = "Unpacking nested containers…".to_string();
    }

    fn show_unpacked_tab(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.button(if self.bench.unpacked.is_some() { "Unpack again" } else { "Unpack everything" }).clicked() {
                self.start_unpack();
            }
            if self.bench.busy(|p| matches!(p, Pending::Unpack(_))) {
                ui.spinner();
            }
            ui.label(RichText::new("Extracts archives and compressed streams recursively, like binwalk -e, as a browsable tree.").small().color(theme::TEXT_DIM));
        });
        let Some(root) = self.bench.unpacked.clone() else { return };
        let mut action: Option<NodeAction> = None;
        egui::ScrollArea::vertical().id_salt("unpacked-tree").show(ui, |ui| {
            for (index, child) in root.children.iter().enumerate() {
                show_node(ui, child, &[index], 0, &mut action);
            }
            if root.children.is_empty() {
                ui.label(RichText::new("Nothing nested was found.").color(theme::TEXT_DIM));
            }
        });
        match action {
            Some(NodeAction::Open(path)) => {
                if let Some(node) = root.find(&path) {
                    self.open_derived(node.data.to_vec(), format!("{} › {}", self.display_name(), node.name));
                }
            }
            Some(NodeAction::Jump(offset)) => self.jump_to_offset(offset),
            Some(NodeAction::Save(path)) => {
                if let Some(node) = root.find(&path) {
                    let dialog = rfd::AsyncFileDialog::new().set_file_name(node.name.replace('/', "_"));
                    let action = FileAction::SaveBytes { name: node.name.clone(), bytes: Arc::clone(&node.data) };
                    self.ask_for_file(DialogKind::Save, dialog, action);
                }
            }
            None => {}
        }
    }

    // -----------------------------------------------------------------------
    // Ask the file
    // -----------------------------------------------------------------------

    /// Send the typed question with a snapshot of what the user sees.
    pub fn ask_assistant(&mut self) {
        let question = self.dock.question.trim().to_string();
        if question.is_empty() {
            return;
        }
        let context = self.assistant_context();
        let credentials = self.credentials.as_ref().map(|(credentials, _)| credentials.clone());
        match self.assistant.ask(&question, &context, credentials) {
            Ok(()) => self.dock.question.clear(),
            Err(message) => {
                self.assistant.transcript.push(assistant::Turn::Note(message.clone()));
                self.status = message;
            }
        }
    }

    fn assistant_context(&mut self) -> FileContext {
        let around = self.cursor.saturating_sub(64) & !15;
        let hex = assistant::hex_dump(&self.document.read_range(around, 256), around);
        let findings: Vec<String> = self
            .patterns_in(self.cursor.saturating_sub(4096), self.cursor + 4096)
            .filter(|f| !f.weak())
            .take(30)
            .map(|f| format!("{:#x}..{:#x} {}", f.start, f.end(), f.description()))
            .collect();
        let structure = self.cursor_structure.as_ref().map(|s| format!("{} at {:#x}\n{}", s.title, s.start, render_fields(&s.fields, 0, 80)));
        let report = self.bench.report.as_ref().map(|r| {
            let mut text = r.headline.clone();
            for sentence in r.sentences.iter().take(20) {
                text.push_str(&format!("\n- {}", sentence.text));
            }
            text
        });
        FileContext {
            name: self.display_name(),
            size: self.document.len(),
            cursor: self.cursor,
            selection: self.selection(),
            view: format!("{} at {} pixels per row from {:#x}", self.shape.format.label(), self.shape.width, self.shape.byte_offset),
            findings,
            structure,
            hex_dump: hex,
            report,
        }
    }

    /// Carry out a tool call from the assistant against the open document.
    pub fn run_assistant_tool(&mut self, call: &ToolCall) -> String {
        match call {
            ToolCall::ReadBytes { offset, length } => {
                if *offset >= self.document.len() {
                    return format!("Offset {offset:#x} is past the end of the file ({} bytes).", self.document.len());
                }
                assistant::hex_dump(&self.document.read_range(*offset, *length), *offset)
            }
            ToolCall::Search { query, hex } => {
                let mode = if *hex { search::SearchMode::Hex } else { search::SearchMode::Text };
                let needle = match search::needle_for(mode, query, true) {
                    Ok(needle) => needle,
                    Err(message) => return message,
                };
                let mut hits = Vec::new();
                let mut from = 0;
                while hits.len() < 64 {
                    match search::find_next(&mut self.document, &needle, from) {
                        Some(at) => {
                            hits.push(format!("{at:#x}"));
                            from = at + 1;
                        }
                        None => break,
                    }
                }
                if hits.is_empty() { "No matches.".to_string() } else { format!("{} matches: {}", hits.len(), hits.join(", ")) }
            }
            ToolCall::ListFindings { start, length } => {
                let window = self.document.read_range(*start, *length);
                let context = ScanContext { base: *start, document_len: self.document.len(), strides: vec![self.shape.row_stride()] };
                let mut found = self.registry.scan(&window, &context);
                patterns::resolve_overlaps(&mut found);
                let lines: Vec<String> = found
                    .iter()
                    .filter(|f| f.confidence >= 0.5)
                    .take(200)
                    .map(|f| format!("{:#x}..{:#x} [{}] {}", f.start, f.end(), f.category.label(), f.description()))
                    .collect();
                if lines.is_empty() { "Nothing recognised in that range.".to_string() } else { lines.join("\n") }
            }
            ToolCall::ParseStructure { offset } => {
                let bytes = self.document.read_range(*offset, TEMPLATE_READ);
                let mut parsed = self.registry.parse_at(&bytes, *offset);
                parsed.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
                match parsed.first() {
                    Some(finding) => format!("{} ({} bytes)\n{}", finding.description(), finding.len, render_fields(&finding.fields, 0, 300)),
                    None => format!("No parser recognises a structure at {offset:#x}."),
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Plotting and bytes as audio
    // -----------------------------------------------------------------------

    /// Plot the selection (or 64 KiB from the cursor).
    pub fn open_plot(&mut self) {
        let (start, len) = self.selection().unwrap_or((self.cursor, 64 * 1024));
        self.plot.start = start;
        self.plot.bytes = self.document.read_range(start, len.min(16 * 1024 * 1024));
        self.plot.open = true;
    }

    pub fn show_plot_window(&mut self, ctx: &Context) {
        self.plot.show(ctx);
    }

    /// Play the selection (or 1 MiB from the cursor) as raw audio samples.
    pub fn play_bytes_as_audio(&mut self) {
        let (start, len) = self.selection().unwrap_or((self.cursor, 1024 * 1024));
        let bytes = self.document.read_range(start, len.min(64 * 1024 * 1024));
        let wav = plot::pcm_wav(&bytes, self.bench.pcm_format, self.bench.pcm_channels, self.bench.pcm_rate);
        let format = crate::media::detect(&wav).expect("pcm_wav writes a WAV header");
        self.media.open(player::MediaRequest {
            format,
            start,
            bytes: wav,
            source_name: format!("{} as {} {} Hz", self.display_name(), self.bench.pcm_format.label(), self.bench.pcm_rate),
        });
        self.status = format!("Playing {} bytes from {start:#x} as audio", bytes.len());
    }

    // -----------------------------------------------------------------------
    // Live sources, watch mode and recording
    // -----------------------------------------------------------------------

    pub fn source_loading(&self) -> bool {
        self.bench.busy(|p| matches!(p, Pending::Source(_)))
    }

    /// Open a URL, serial port, block device, process or file.
    pub fn open_source(&mut self, text: &str) {
        self.bench.live_error = None;
        let spec = match SourceSpec::parse(text) {
            Ok(spec) => spec,
            Err(message) => {
                self.bench.live_error = Some(message);
                return;
            }
        };
        let name = spec.describe();
        match spec {
            SourceSpec::File(path) => self.load_path(&path),
            SourceSpec::Url(url) => self.spawn_source(name, move || sources::fetch_url(&url, ANALYSIS_READ_LIMIT * 2)),
            SourceSpec::BlockDevice(path) => self.spawn_source(name, move || sources::read_block_device(&path, ANALYSIS_READ_LIMIT * 2)),
            SourceSpec::Serial { port, baud } => match SerialCapture::start(&port, baud) {
                Ok(capture) => {
                    // Opening the capture's document stops any previous source.
                    self.open_bytes(Vec::new(), name);
                    self.bench.serial = Some(capture);
                    self.bench.serial_seen = 0;
                    self.bench.recording.get_or_insert_with(|| Recording::new(sources::DEFAULT_RECORDING_BUDGET));
                }
                Err(message) => self.bench.live_error = Some(message),
            },
            SourceSpec::Process { pid } => match sources::process_regions(pid) {
                Ok(regions) => {
                    self.bench.process_pid = Some(pid);
                    self.bench.process_regions = regions.into_iter().filter(|r| r.is_readable()).collect();
                }
                Err(message) => self.bench.live_error = Some(message),
            },
        }
    }

    fn spawn_source(&mut self, name: String, read: impl FnOnce() -> Result<Vec<u8>, String> + Send + 'static) {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(read().map(|bytes| (name, bytes)));
        });
        self.bench.pending.push(Pending::Source(receiver));
        self.status = "Reading…".to_string();
    }

    /// Stop the serial capture and file watching. Call this when a different
    /// document replaces the one they feed, or they would overwrite it.
    pub fn stop_live_sources(&mut self) {
        self.stop_serial();
        self.set_watch(false);
    }

    pub fn stop_serial(&mut self) {
        if let Some(mut capture) = self.bench.serial.take() {
            capture.stop();
        }
    }

    fn poll_serial(&mut self) {
        let Some(capture) = &self.bench.serial else { return };
        if let Some(error) = capture.error() {
            self.bench.live_error = Some(error);
        }
        let received = capture.received();
        if received == self.bench.serial_seen || self.document.is_modified() {
            return;
        }
        let bytes = capture.snapshot();
        let old_len = self.bench.serial_seen;
        self.bench.serial_seen = received;
        self.record_snapshot(&bytes);
        self.refresh_bytes(Document::from_bytes(bytes));
        self.bench.pinned.push(changed_finding(old_len, received - old_len, "Received"));
        self.force_rescan();
    }

    /// Turn watch mode on or off for the open file.
    pub fn set_watch(&mut self, enabled: bool) {
        self.bench.watch_enabled = false;
        self.bench.watcher = None;
        if !enabled {
            return;
        }
        let Some(path) = self.document.path().map(|p| p.to_path_buf()) else {
            self.bench.live_error = Some("Only files on disk can be watched".to_string());
            return;
        };
        match FileWatcher::new(&path) {
            Ok(watcher) => {
                self.bench.watcher = Some(watcher);
                self.bench.watch_enabled = true;
                let bytes = self.document.read_range(0, RECORDING_FILE_LIMIT);
                self.record_snapshot(&bytes);
            }
            Err(message) => self.bench.live_error = Some(message),
        }
    }

    fn poll_watcher(&mut self) {
        let Some(change) = self.bench.watcher.as_mut().and_then(|w| w.poll()) else { return };
        if self.document.is_modified() {
            self.status = "The file changed on disk; not reloading over your unsaved edits".to_string();
            return;
        }
        let Some(path) = self.document.path().map(|p| p.to_path_buf()) else { return };
        let Ok(document) = Document::open(&path) else { return };
        self.refresh_bytes(document);
        let bytes = self.document.read_range(0, RECORDING_FILE_LIMIT);
        let recorded = self.record_snapshot(&bytes);
        match change.kind {
            sources::ChangeKind::Grew { old_len, new_len } => {
                self.bench.pinned.push(changed_finding(old_len, new_len - old_len, "Appended"));
                self.status = format!("File grew by {} bytes", new_len - old_len);
            }
            sources::ChangeKind::Shrank | sources::ChangeKind::Rewritten => {
                if recorded && let Some(recording) = &self.bench.recording {
                    for (start, len) in recording.changed_ranges(recording.len() - 1) {
                        self.bench.pinned.push(changed_finding(start, len, "Changed"));
                    }
                }
                self.status = "File changed on disk; reloaded".to_string();
            }
        }
        self.force_rescan();
    }

    fn record_snapshot(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > RECORDING_FILE_LIMIT {
            return false;
        }
        let Some(recording) = &mut self.bench.recording else { return false };
        let stored = recording.record(bytes);
        if stored {
            self.bench.recording_index = recording.len() - 1;
        }
        stored
    }

    pub fn show_live_status(&mut self, ui: &mut Ui) {
        if let Some(error) = &self.bench.live_error {
            ui.label(RichText::new(error).color(theme::DANGER));
        }
        ui.horizontal(|ui| {
            let can_watch = self.document.path().is_some() && self.parents.is_empty();
            let mut watching = self.bench.watch_enabled;
            if ui.add_enabled(can_watch, egui::Checkbox::new(&mut watching, "Watch the file for changes")).changed() {
                self.set_watch(watching);
            }
            let mut recording = self.bench.recording.is_some();
            if ui.checkbox(&mut recording, "Record history").on_hover_text("Keep every version as the file or capture changes").changed() {
                self.bench.recording = recording.then(|| Recording::new(sources::DEFAULT_RECORDING_BUDGET));
                if recording {
                    let bytes = self.document.read_range(0, RECORDING_FILE_LIMIT);
                    self.record_snapshot(&bytes);
                }
            }
        });
        if let Some(capture) = &self.bench.serial {
            let running = capture.is_running();
            ui.horizontal(|ui| {
                ui.label(RichText::new(if running { "● receiving" } else { "stopped" }).color(if running { theme::ACCENT } else { theme::TEXT_DIM }));
                ui.label(format!("{} bytes", capture.received()));
            });
            if ui.button("Stop capture").clicked() {
                self.stop_serial();
            }
        }
        if !self.bench.process_regions.is_empty() {
            ui.label(RichText::new(format!("Readable memory of process {}", self.bench.process_pid.unwrap_or(0))).strong());
            let mut open = None;
            egui::ScrollArea::vertical().id_salt("process-regions").max_height(160.0).show(ui, |ui| {
                for (index, region) in self.bench.process_regions.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.monospace(format!("{:#x}-{:#x} {} {}", region.start, region.end, region.permissions, region.path));
                        if ui.small_button("Open").clicked() {
                            open = Some(index);
                        }
                    });
                }
            });
            if let (Some(index), Some(pid)) = (open, self.bench.process_pid) {
                let region = self.bench.process_regions[index].clone();
                let name = format!("pid {pid} {:#x}", region.start);
                self.spawn_source(name, move || sources::read_process_memory(pid, &region, ANALYSIS_READ_LIMIT));
            }
        }
    }

    pub fn show_recording(&mut self, ui: &mut Ui) {
        let Some(recording) = &self.bench.recording else { return };
        if recording.is_empty() {
            return;
        }
        let count = recording.len();
        ui.label(RichText::new(format!("History: {count} versions, {} stored", crate::compress::human_bytes(recording.stored_bytes()))).strong());
        let mut index = self.bench.recording_index.min(count - 1);
        ui.horizontal(|ui| {
            ui.add(egui::Slider::new(&mut index, 0..=count - 1).text("version"));
            if let Some(time) = recording.taken_at(index)
                && let Ok(age) = time.elapsed()
            {
                ui.label(RichText::new(format!("{}s ago", age.as_secs())).color(theme::TEXT_DIM));
            }
        });
        self.bench.recording_index = index;
        let ranges = recording.changed_ranges(index);
        ui.label(RichText::new(format!("{} changed ranges from the previous version", ranges.len())).small().color(theme::TEXT_DIM));
        if ui.button("View this version").clicked() {
            let bytes = recording.materialise(index);
            let name = format!("{} @ version {}", self.display_name(), index + 1);
            self.open_derived(bytes, name);
            for (start, len) in ranges {
                self.bench.pinned.push(changed_finding(start, len, "Changed in this version"));
            }
        }
    }

    // Tabs filled in by the disassembly, checksums and diff integration.
    fn show_disassembly_tab(&mut self, ui: &mut Ui) {
        crate::analysis_tabs::show_disassembly(self, ui);
    }

    fn show_checksums_tab(&mut self, ui: &mut Ui) {
        crate::analysis_tabs::show_checksums(self, ui);
    }

    fn show_diff_tab(&mut self, ui: &mut Ui) {
        crate::analysis_tabs::show_diff(self, ui);
    }
}

/// What a click in the unpacked tree asks for.
enum NodeAction {
    Open(Vec<usize>),
    Jump(usize),
    Save(Vec<usize>),
}

fn show_node(ui: &mut Ui, node: &Node, path: &[usize], depth: usize, action: &mut Option<NodeAction>) {
    let row = |ui: &mut Ui, action: &mut Option<NodeAction>| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(&node.kind).small().color(theme::TEXT_DIM));
            ui.label(node.summary());
            if ui.small_button("Open").on_hover_text("Open its bytes as a document; Back returns").clicked() {
                *action = Some(NodeAction::Open(path.to_vec()));
            }
            if ui.small_button("Save…").clicked() {
                *action = Some(NodeAction::Save(path.to_vec()));
            }
            if depth == 0 && ui.small_button(format!("{:#x}", node.source_offset)).on_hover_text("Jump to it in this file").clicked() {
                *action = Some(NodeAction::Jump(node.source_offset));
            }
        });
    };
    if node.children.is_empty() {
        row(ui, action);
        return;
    }
    let id = ui.id().with(("unpacked", path));
    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, depth < 1)
        .show_header(ui, |ui| row(ui, action))
        .body(|ui| {
            for (index, child) in node.children.iter().enumerate() {
                let mut child_path = path.to_vec();
                child_path.push(index);
                show_node(ui, child, &child_path, depth + 1, action);
            }
        });
}

/// A field tree as indented text, for the assistant.
fn render_fields(fields: &[Field], depth: usize, budget: usize) -> String {
    let mut out = String::new();
    let mut lines = 0;
    render_fields_into(fields, depth, budget, &mut lines, &mut out);
    out
}

fn render_fields_into(fields: &[Field], depth: usize, budget: usize, lines: &mut usize, out: &mut String) {
    for field in fields {
        if *lines >= budget {
            out.push_str(&format!("{}…\n", "  ".repeat(depth)));
            return;
        }
        out.push_str(&format!("{}{} @ {:#x} ({} B): {}\n", "  ".repeat(depth), field.name, field.offset, field.len, field.value));
        *lines += 1;
        render_fields_into(&field.children, depth + 1, budget, lines, out);
    }
}

/// `cells` bytes spread evenly over the document, read in large chunks so a
/// big file is sampled without a read per byte.
fn sampled_bytes(document: &mut Document, cells: usize) -> Vec<u8> {
    let len = document.len();
    if len <= cells {
        return document.read_range(0, len);
    }
    const CHUNK: usize = 4 * 1024 * 1024;
    let mut out = Vec::with_capacity(cells);
    let mut chunk_start = usize::MAX;
    let mut chunk = Vec::new();
    for cell in 0..cells {
        let offset = (cell as u128 * len as u128 / cells as u128) as usize;
        if offset < chunk_start || offset >= chunk_start + chunk.len() {
            chunk_start = offset;
            chunk = document.read_range(offset, CHUNK);
        }
        out.push(chunk[offset - chunk_start]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampling_picks_evenly_spaced_bytes() {
        let mut document = Document::from_bytes((0..=255u8).cycle().take(1024).collect());
        let sampled = sampled_bytes(&mut document, 4);
        assert_eq!(sampled, vec![0, 0, 0, 0]);
        let sampled = sampled_bytes(&mut document, 8);
        assert_eq!(sampled, vec![0, 128, 0, 128, 0, 128, 0, 128]);
        assert_eq!(sampled_bytes(&mut Document::from_bytes(vec![7, 8]), 16), vec![7, 8]);
    }

    #[test]
    fn field_trees_render_as_indented_text_within_a_budget() {
        let fields = vec![Field::new("header", 0, 8, "").with_children(vec![Field::new("magic", 0, 4, "PNG"), Field::new("len", 4, 4, "13")])];
        let text = render_fields(&fields, 0, 10);
        assert_eq!(text, "header @ 0x0 (8 B): \n  magic @ 0x0 (4 B): PNG\n  len @ 0x4 (4 B): 13\n");
        assert!(render_fields(&fields, 0, 1).ends_with("…\n"));
    }
}
