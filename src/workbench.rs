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

use crate::app::ViewerApp;
use crate::panels::{self, PanelStates};
use crate::assistant::{self, FileContext, ToolCall, ToolReply};
use crate::bus::{Message, Payload};
use crate::api::tools::report::REPORT_PRODUCER;
use crate::bus::topics::{RegionsMapped, TemplateApplied};
use crate::document::Document;
use crate::dock::{self, DockTab};
use crate::explain::{Region, Report};
use crate::hilbert;
use crate::plot::{self, PcmFormat};
use crate::plugin::{Category, Field, Finding};
use crate::raster::{self, PixelFormat};
use crate::sources::{self, FileWatcher, Recording, SerialCapture, SourceSpec};
use crate::templates::{self, Applied, Template};
use crate::theme;
use crate::unpack::{self, Node};
use crate::player;

/// Largest prefix of a file the report and unpacker read into memory.
pub(crate) const ANALYSIS_READ_LIMIT: usize = 256 * 1024 * 1024;
/// Largest file kept in the recording history.
pub(crate) const RECORDING_FILE_LIMIT: usize = 256 * 1024 * 1024;
/// How often watched files and serial captures are checked.
const LIVE_POLL_INTERVAL: Duration = Duration::from_millis(400);
/// Bytes a template is applied to.
const TEMPLATE_READ: usize = 16 * 1024 * 1024;
/// What applied templates are published as.
const TEMPLATES: &str = "tool:templates";
/// Rows shown in the template records table.
const MAX_TABLE_ROWS: usize = 5000;

/// How the central view lays bytes out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Rows,
    Hilbert,
    /// Z-order: like Hilbert, the whole file at once without a width, with
    /// power-of-two aligned blocks drawn as squares.
    Morton,
}

impl Layout {
    pub const ALL: [Layout; 3] = [Layout::Rows, Layout::Hilbert, Layout::Morton];

    pub fn label(self) -> &'static str {
        match self {
            Layout::Rows => "rows",
            Layout::Hilbert => "Hilbert curve",
            Layout::Morton => "Morton (Z-order) curve",
        }
    }

    /// The space-filling curve this layout follows, if it is not rows.
    pub fn curve(self) -> Option<hilbert::Curve> {
        match self {
            Layout::Rows => None,
            Layout::Hilbert => Some(hilbert::Curve::Hilbert),
            Layout::Morton => Some(hilbert::Curve::Morton),
        }
    }
}

/// What the curve layouts colour each cell by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum CurveColour {
    /// The byte itself, through the palette (or its class in the byte-class format).
    #[default]
    Bytes,
    /// The entropy of each small block of cells.
    Entropy,
    /// The kind of region the report found there.
    RegionType,
    /// Zeros, text, control bytes and high bytes in distinct colours.
    ByteClass,
}

impl CurveColour {
    pub const ALL: [CurveColour; 4] = [CurveColour::Bytes, CurveColour::Entropy, CurveColour::RegionType, CurveColour::ByteClass];

    pub fn label(self) -> &'static str {
        match self {
            CurveColour::Bytes => "Bytes",
            CurveColour::Entropy => "Entropy",
            CurveColour::RegionType => "Region type",
            CurveColour::ByteClass => "Byte class",
        }
    }

    /// The mode after this one, wrapping round.
    pub fn next(self) -> CurveColour {
        let index = CurveColour::ALL.iter().position(|&mode| mode == self).unwrap_or(0);
        CurveColour::ALL[(index + 1) % CurveColour::ALL.len()]
    }
}

/// Cells (a 8 × 8 square on either curve) whose entropy colours them
/// together in the entropy mode.
const CURVE_ENTROPY_CELLS: usize = 64;
/// Height of the strip of controls above a curve layout.
const CURVE_CONTROLS_HEIGHT: f32 = 26.0;

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
    /// What the curve layouts colour cells by.
    pub curve_colour: CurveColour,
    hilbert: Option<HilbertView>,

    pub template_source: String,
    pub template_choice: String,
    pub template_result: Option<Applied>,
    pub template_error: Option<String>,
    pub template_records: usize,
    /// The source of the template last applied, for applying it again.
    pub template_applied_source: String,

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
    /// The document versions the tools' results describe.
    pub freshness: crate::freshness::Freshness,
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
            curve_colour: CurveColour::Bytes,
            hilbert: None,
            template_source: templates::builtin_templates().first().map(|(_, s)| s.to_string()).unwrap_or_default(),
            template_choice: templates::builtin_templates().first().map(|(n, _)| n.to_string()).unwrap_or_default(),
            template_result: None,
            template_error: None,
            template_records: 8,
            template_applied_source: String::new(),
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
            freshness: Default::default(),
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
        self.panels.packets.document_replaced();
        self.freshness.forget_all();
        self.pending.retain(|pending| matches!(pending, Pending::Source(_)));
    }

    /// Switch to `layout`, or back to rows if it is already showing.
    pub fn toggle_layout(&mut self, layout: Layout) {
        self.layout = if self.layout == layout { Layout::Rows } else { layout };
    }

    fn busy(&self, kind: fn(&Pending) -> bool) -> bool {
        self.pending.iter().any(kind)
    }
}

/// A cached curve rendering of the whole file.
struct HilbertView {
    version: u64,
    format: PixelFormat,
    palette: raster::Palette,
    curve: hilbert::Curve,
    colour: CurveColour,
    /// Fingerprint of the regions the region-type mode was coloured by.
    regions: u64,
    order: u32,
    texture: TextureHandle,
    /// Bytes represented by each cell.
    bytes_per_cell: f64,
}

/// Outline `finding`, a template's parse, in place of the template pinned
/// before (or none).
fn pin_template_finding(app: &mut ViewerApp, finding: Option<Finding>) {
    app.bench.pinned.retain(|pinned| !pinned.id.starts_with("template:"));
    app.bench.pinned.extend(finding);
}

/// The views outline a template whoever applied it, a plugin or a client
/// publishing on `template.applied` included, and stop when it is
/// withdrawn. Runs whether or not the Template tool is showing.
pub fn follow_applied_template(app: &mut ViewerApp, message: &Arc<Message>) {
    let Some(applied) = message.payload_as::<TemplateApplied>() else { return };
    if message.draft.document.as_deref() != Some(app.document_id().as_str()) {
        return;
    }
    let shown = app.bench.pinned.iter().find(|pinned| pinned.id.starts_with("template:"));
    if message.draft.retracts {
        if shown.is_some_and(|shown| shown.id == applied.structure.id && shown.start == applied.structure.start) {
            pin_template_finding(app, None);
        }
    } else if shown != Some(&applied.structure) {
        pin_template_finding(app, Some(applied.structure.clone()));
    }
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
        crate::analysis_tools::poll_protocol(self);
        let pending = std::mem::take(&mut self.bench.pending);
        for item in pending {
            match item {
                Pending::Report(receiver) => match receiver.try_recv() {
                    Ok((regions, report)) => {
                        self.bench.regions = regions;
                        self.bench.report = Some(report);
                        self.publish_regions();
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
        if !self.bench.pending.is_empty() || self.bench.tools.protocol_pending() {
            ctx.request_repaint_after(Duration::from_millis(80));
        }

        let mut assistant = std::mem::take(&mut self.assistant);
        if assistant.poll(|call, reply| self.run_assistant_tool(call, reply)) {
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
            DockTab::Protocol => {
                crate::analysis_tools::show_protocol(self, ui);
                ui.separator();
                egui::CollapsingHeader::new("Align messages").id_salt("align-messages").show(ui, |ui| {
                    panels::show(self, ui, |p| &mut p.alignment, crate::panel_alignment::show_alignment);
                });
            }
            DockTab::Statistics => crate::analysis_stats::show_statistics(self, ui),
            DockTab::Strings => crate::analysis_stats::show_strings(self, ui),
            DockTab::Xor => crate::analysis_stats::show_xor(self, ui),
            DockTab::Crypto => {
                egui::CollapsingHeader::new("Known constants").id_salt("crypto-constants").default_open(true).show(ui, |ui| {
                    panels::show(self, ui, |p| &mut p.crypto_constants, crate::panel_crypto_constants::show_crypto_constants);
                });
                panels::show(self, ui, |p| &mut p.crypto, crate::panel_crypto::show_crypto);
            }
            DockTab::Compare => panels::show(self, ui, |p| &mut p.compare, crate::panel_compare::show_compare),
            DockTab::Bits => panels::show(self, ui, |p| &mut p.bits, crate::panel_bits::show_bits),
            DockTab::Forensics => panels::show(self, ui, |p| &mut p.forensics, crate::panel_forensics::show_forensics),
            DockTab::DotPlot => panels::show(self, ui, |p| &mut p.dot_plot, crate::panel_dotplot::show_dot_plot),
            DockTab::Trigrams => panels::show(self, ui, |p| &mut p.trigrams, crate::panel_trigram::show_trigram),
            DockTab::Characterise => panels::show(self, ui, |p| &mut p.characterise, crate::panel_characterise::show_characterise),
            DockTab::Learn => panels::show(self, ui, |p| &mut p.learn, crate::panel_learn::show_learn),
            DockTab::Packets => panels::show(self, ui, |p| &mut p.packets, crate::panel_packets::show_packets),
            DockTab::Reference => panels::show(self, ui, |p| &mut p.reference, crate::panel_reference::show_reference),
            DockTab::Workspace => panels::show(self, ui, |p| &mut p.workspace, crate::panel_workspace::show_workspace),
            DockTab::SizeMap => panels::show(self, ui, |p| &mut p.size_map, crate::panel_treemap::show_treemap),
            DockTab::StructureMap => panels::show(self, ui, |p| &mut p.structure_map, crate::panel_structure_map::show_structure_map),
            DockTab::Images => panels::show(self, ui, |p| &mut p.images, crate::panel_image_finder::show_image_finder),
            DockTab::Firmware => panels::show(self, ui, |p| &mut p.firmware, crate::panel_firmware::show_firmware),
            DockTab::Assistant | DockTab::Live => {}
        }
    }

    // -----------------------------------------------------------------------
    // Report and file map
    // -----------------------------------------------------------------------

    /// Explain the whole file because the person asked to, through
    /// `report.run`; nothing happens while a report is being worked out or
    /// when the document is empty.
    pub fn explain_file(&mut self) {
        if self.report_running() || self.document.is_empty() {
            return;
        }
        let _ = self.perform("report.run", serde_json::json!({}));
    }

    /// The report the app starts by itself, as the Report tool's: on launch
    /// with the tool asked for, and to refresh it after an edit.
    pub fn start_report(&mut self) {
        self.report_as(REPORT_PRODUCER);
    }

    /// Map and explain the whole file on a background thread, as a job of
    /// `producer`'s, showing the report and the file map when done: what
    /// `report.run` does in the window. Returns the job, or nothing while a
    /// report is being worked out or when the document is empty.
    pub fn report_as(&mut self, producer: &str) -> Option<String> {
        if self.report_running() || self.document.is_empty() {
            return None;
        }
        let bytes = self.document.read_range(0, ANALYSIS_READ_LIMIT);
        let name = self.display_name();
        let registry = Arc::clone(&self.registry);
        let (sender, receiver) = mpsc::channel();
        let job = self.bus.start_job("report", "Report", producer, Some((self.document_id(), self.document.version())));
        let id = job.id().to_string();
        thread::spawn(move || {
            if let Some(found) = crate::api::tools::report::run_report(&bytes, &name, &registry, &job) {
                let _ = sender.send(found);
            }
        });
        self.bench.pending.push(Pending::Report(receiver));
        self.note_tool_result(DockTab::Report);
        Some(id)
    }

    /// Publish the report's map of the file.
    fn publish_regions(&mut self) {
        let regions = crate::api::tools::report::mapped_regions(&self.bench.regions);
        let end = regions.last().map_or(0, |region| region.start + region.len);
        self.bus.publish(self.draft(REPORT_PRODUCER, Payload::RegionsMapped(RegionsMapped { regions })).span(0, end));
    }

    pub fn report_running(&self) -> bool {
        self.bench.busy(|p| matches!(p, Pending::Report(_)))
    }

    fn show_report_tab(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.button(if self.bench.report.is_some() { "Re-analyse" } else { "Explain this file" }).clicked() {
                self.explain_file();
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
                        self.select_from_tool(sentence.start, sentence.len);
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
        let out_of_date = self.tool_out_of_date(DockTab::Report);
        if out_of_date {
            // The map comes from the report; say so when the bytes have moved on.
            painter.rect_filled(rect, 0.0, Color32::from_black_alpha(110));
            painter.text(rect.right_center() - vec2(4.0, 0.0), egui::Align2::RIGHT_CENTER, "file map out of date — Refresh in Report", egui::FontId::proportional(10.0), theme::CURSOR);
        }
        if let Some(pointer) = response.hover_pos() {
            let offset = ((pointer.x - rect.min.x) / rect.width() * total) as usize;
            if let Some(region) = self.bench.regions.iter().find(|r| offset >= r.start && offset < r.end()) {
                response.clone().on_hover_text(format!("{} at {:#x} ({}): {}", region.label, region.start, crate::compress::human_bytes(region.len), region.detail));
            }
            if response.clicked() {
                self.go_to_offset(offset);
            }
        }
        if out_of_date && response.secondary_clicked() {
            self.explain_file();
        }
    }

    // -----------------------------------------------------------------------
    // Curve layouts (Hilbert and Morton)
    // -----------------------------------------------------------------------

    /// Draw the whole file along the layout's space-filling curve, which
    /// keeps nearby bytes close together in two dimensions so structure
    /// shows without a width. A strip of controls above picks the colours.
    pub fn show_curve(&mut self, ui: &mut Ui, rect: Rect) {
        let len = self.document.len();
        let Some(curve) = self.bench.layout.curve() else { return };
        if len == 0 {
            return;
        }
        let controls = Rect::from_min_size(rect.min, vec2(rect.width(), CURVE_CONTROLS_HEIGHT.min(rect.height())));
        let rect = Rect::from_min_max(pos2(rect.min.x, controls.max.y), rect.max);
        let colour = self.bench.curve_colour;
        let needs_report = colour == CurveColour::RegionType && self.mapped_regions.is_empty();
        let regions = if colour == CurveColour::RegionType { crate::region_colours::regions_fingerprint(&self.mapped_regions) } else { 0 };
        let stale = self.bench.hilbert.as_ref().is_none_or(|view| {
            view.version != self.document.version()
                || view.format != self.shape.format
                || view.palette != self.shape.palette
                || view.curve != curve
                || view.colour != colour
                || view.regions != regions
        });
        if stale {
            let order = hilbert::order_for(len);
            let cells = 1usize << (2 * order);
            let bytes = sampled_bytes(&mut self.document, cells);
            let bytes_per_cell = (len as f64 / cells as f64).max(1.0);
            let along = curve_cell_colours(&bytes, bytes_per_cell, colour, self.shape.format, self.shape.palette, &self.mapped_regions);
            let pixels = hilbert::render_along(curve, order, &along);
            let side = 1usize << order;
            let image = ColorImage::new([side, side], pixels);
            let texture = ui.ctx().load_texture("hilbert", image, TextureOptions::NEAREST);
            self.bench.hilbert = Some(HilbertView {
                version: self.document.version(),
                format: self.shape.format,
                palette: self.shape.palette,
                curve,
                colour,
                regions,
                order,
                texture,
                bytes_per_cell,
            });
        }
        let view = self.bench.hilbert.as_ref().expect("built above");
        let side = (1u32 << view.order) as f32;
        let size = rect.width().min(rect.height()).max(0.0);
        let drawn = Rect::from_min_size(rect.min, vec2(size, size));
        self.raster_rect = Some(drawn);
        let painter = ui.painter_at(rect);
        painter.image(view.texture.id(), drawn, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
        let cell = size / side;
        let (order, bytes_per_cell) = (view.order, view.bytes_per_cell);
        let offset_at = |pointer: egui::Pos2| curve_offset_at(curve, order, bytes_per_cell, len, drawn, pointer);
        let response = ui.interact(rect, ui.id().with("hilbert"), Sense::click());
        if let Some(pointer) = response.hover_pos() {
            self.hover = offset_at(pointer);
        }
        if response.clicked()
            && let Some(offset) = response.interact_pointer_pos().and_then(offset_at)
        {
            self.go_to_offset(offset);
        }
        // Cursor marker.
        let d = (self.cursor as f64 / bytes_per_cell) as u64;
        let (x, y) = curve.d_to_xy(order, d.min((1u64 << (2 * order)) - 1));
        let marker = Rect::from_min_size(drawn.min + vec2(x as f32 * cell, y as f32 * cell), vec2(cell.max(3.0), cell.max(3.0)));
        painter.rect_stroke(marker.expand(2.0), 0.0, Stroke::new(2.0, theme::CURSOR), StrokeKind::Outside);
        if needs_report {
            painter.text(
                drawn.center(),
                egui::Align2::CENTER_CENTER,
                "Run the report to colour by region type",
                egui::FontId::proportional(15.0),
                theme::TEXT,
            );
        }
        self.show_curve_controls(ui, controls, curve, bytes_per_cell, needs_report);
    }

    /// The colour picker and description above a curve layout, with a
    /// button that runs the report when the region colours need it.
    fn show_curve_controls(&mut self, ui: &mut Ui, controls: Rect, curve: hilbert::Curve, bytes_per_cell: f64, needs_report: bool) {
        ui.scope_builder(egui::UiBuilder::new().max_rect(controls).layout(egui::Layout::left_to_right(egui::Align::Center)), |ui| {
            ui.label(RichText::new(format!("{}, {} B per cell", curve.label(), bytes_per_cell.round() as usize)).color(theme::TEXT_DIM));
            ui.label(RichText::new("Colour by").color(theme::TEXT_DIM));
            egui::ComboBox::from_id_salt("curve-colour")
                .selected_text(self.bench.curve_colour.label())
                .width(96.0)
                .show_ui(ui, |ui| {
                    for mode in CurveColour::ALL {
                        ui.selectable_value(&mut self.bench.curve_colour, mode, mode.label());
                    }
                });
            if needs_report && ui.button("Run the report").on_hover_text("Explain this file: find its regions so cells can be coloured by them").clicked() {
                self.dock.open = true;
                self.dock.tab = DockTab::Report;
                self.explain_file();
            }
        });
    }

    // -----------------------------------------------------------------------
    // Templates
    // -----------------------------------------------------------------------

    /// Where a template applies: the selection start, else the cursor.
    fn template_origin(&self) -> usize {
        self.selection().map(|(start, _)| start).unwrap_or(self.cursor)
    }

    /// Apply template source at the selection start (else the cursor)
    /// because the person asked to, through `templates.apply`, pinning it
    /// and showing it in the Template tool. Source that does not parse is
    /// said in the tool, as before.
    pub fn apply_template_here(&mut self, source: &str) {
        if let Err(error) = Template::parse(source) {
            self.show_template_error(source, &error.to_string());
            return;
        }
        let at = self.template_origin();
        let _ = self.perform("templates.apply", serde_json::json!({ "source": source, "at": at, "pin": true }));
    }

    /// Put the cursor at `at` and apply template source there because the
    /// person asked a tool to (Columns, Protocol, Learn), through
    /// `cursor.set` and `templates.apply`.
    pub fn apply_template_from_tool(&mut self, source: &str, at: usize) {
        let at = at.min(self.document.len());
        if self.perform("cursor.set", serde_json::json!({ "offset": at })).is_ok() {
            self.apply_template_here(source);
        }
    }

    /// Parse and apply template source at the cursor (or selection start),
    /// for a template someone asked for on the bus.
    pub fn apply_template_source(&mut self, source: &str) {
        match Template::parse(source) {
            Ok(template) => {
                let origin = self.template_origin();
                let bytes = self.document.read_range(origin, TEMPLATE_READ);
                let applied = template.apply(&bytes, origin);
                self.show_applied_template(&template, source, applied);
            }
            Err(error) => self.show_template_error(source, &error.to_string()),
        }
    }

    /// Say in the Template tool that `source` does not parse.
    fn show_template_error(&mut self, source: &str, error: &str) {
        self.bench.template_source = source.to_string();
        self.dock.open = true;
        self.dock.tab = DockTab::Template;
        self.bench.template_error = Some(error.to_string());
        self.status = format!("Template error: {error}");
    }

    /// Show `template` (written as `source`) applied in the Template tool,
    /// and pin its parse: what `templates.apply {pin}` does in the window.
    pub fn show_applied_template(&mut self, template: &Template, source: &str, applied: Applied) {
        self.bench.template_source = source.to_string();
        self.dock.open = true;
        self.dock.tab = DockTab::Template;
        let origin = applied.finding.start;
        let pinned = TemplateApplied { name: template.name().to_string(), source: source.to_string(), records: applied.records.len(), structure: applied.finding.clone() };
        self.pin_template_parse(pinned);
        self.bench.template_applied_source = source.to_string();
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

    /// Apply `template` (written as `source`) at `origin`, pinning the
    /// decoded records.
    fn apply_template_at(&mut self, template: &Template, source: &str, origin: usize) -> Applied {
        let bytes = self.document.read_range(origin, TEMPLATE_READ);
        let applied = template.apply(&bytes, origin);
        let pinned = TemplateApplied { name: template.name().to_string(), source: source.to_string(), records: applied.records.len(), structure: applied.finding.clone() };
        self.pin_template_parse(pinned);
        applied
    }

    /// Pin a template's parse in place of the last: its records are
    /// outlined and listed, and it is published on `template.applied` with
    /// its structure.
    pub fn pin_template_parse(&mut self, applied: TemplateApplied) {
        let finding = applied.structure.clone();
        self.note_tool_result(DockTab::Template);
        self.bus.publish(self.draft(TEMPLATES, Payload::TemplateApplied(applied)).span(finding.start, finding.len));
        self.bus.publish(self.draft(TEMPLATES, Payload::StructureIdentified(crate::app::structure_of(&finding))).span(finding.start, finding.len));
        pin_template_finding(self, Some(finding));
    }

    /// Decode the applied template again where it was applied, after an
    /// edit changed the bytes under it.
    pub fn reapply_template(&mut self) {
        let Some(origin) = self.bench.template_result.as_ref().map(|applied| applied.finding.start) else { return };
        let source = self.bench.template_applied_source.clone();
        let Ok(template) = Template::parse(&source) else { return };
        let applied = self.apply_template_at(&template, &source, origin);
        self.bench.template_result = Some(applied);
    }

    /// Clear the applied template because the person asked to, through
    /// `templates.clear`.
    pub fn clear_template(&mut self) {
        let _ = self.perform("templates.clear", serde_json::json!({}));
    }

    /// Clear the applied template: its records are no longer outlined, and
    /// it is withdrawn from `template.applied`. Returns whether there was
    /// one. What `templates.clear` does in the window.
    pub fn withdraw_template(&mut self) -> bool {
        pin_template_finding(self, None);
        let Some(applied) = self.bench.template_result.take() else { return false };
        let withdrawn = TemplateApplied { name: String::new(), source: String::new(), records: 0, structure: applied.finding.clone() };
        self.bus.publish(self.draft(TEMPLATES, Payload::TemplateApplied(withdrawn)).retraction());
        self.bus.publish(self.draft(TEMPLATES, Payload::StructureIdentified(crate::app::structure_of(&applied.finding))).retraction());
        true
    }

    /// Propose a struct for the selected records and apply it, through
    /// `templates.infer`.
    pub fn infer_template(&mut self) {
        let Some((start, len)) = self.selection() else {
            self.status = "Select a few records first".to_string();
            return;
        };
        let bytes = self.document.read_range(start, len);
        let record_len = templates::guess_record_length(&bytes).unwrap_or(self.shape.row_stride()).max(1);
        let _ = self.perform("templates.infer", serde_json::json!({ "start": start, "len": len, "record_len": record_len, "pin": true }));
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
                self.apply_template_here(&source);
            }
            if ui.button("Infer from selection").on_hover_text("Select several records; the app proposes a struct from what varies").clicked() {
                self.infer_template();
            }
            if ui.button("Clear").clicked() {
                self.clear_template();
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
            self.select_from_tool(offset, len.max(1));
        }
    }

    // -----------------------------------------------------------------------
    // Unpacking
    // -----------------------------------------------------------------------

    /// The person unpacks everything nested in the document: `unpack.run`,
    /// unless an unpacking is already under way.
    pub fn start_unpack(&mut self) {
        if self.bench.busy(|p| matches!(p, Pending::Unpack(_))) || self.document.is_empty() {
            return;
        }
        let _ = self.perform("unpack.run", serde_json::json!({}));
    }

    /// Unpack the document on a thread as a job of `producer`'s, the tree
    /// filling the Unpacked tab and the Size map: what `unpack.run` does in
    /// the window. Returns the job.
    pub(crate) fn unpack_as(&mut self, producer: &str) -> String {
        let bytes = Arc::new(self.document.read_range(0, ANALYSIS_READ_LIMIT));
        let name = self.display_name();
        let (sender, receiver) = mpsc::channel();
        let job = self.bus.start_job("unpack", "Unpack", producer, Some((self.document_id(), self.document.version())));
        let id = job.id().to_string();
        thread::spawn(move || {
            let tree = unpack::unpack(bytes, &name, &unpack::Limits::default());
            if job.is_cancelled() {
                return job.finish_cancelled();
            }
            let summary = crate::api::tools::unpack::tree_summary(&tree);
            job.finish_with(summary.ok, summary.outcome, Some(summary.result));
            let _ = sender.send(tree);
        });
        self.bench.pending.push(Pending::Unpack(receiver));
        self.note_tool_result(DockTab::Unpacked);
        self.status = "Unpacking nested containers…".to_string();
        id
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
                let _ = self.perform("unpack.open", serde_json::json!({ "path": path }));
            }
            Some(NodeAction::Jump(offset)) => self.jump_found(offset),
            Some(NodeAction::Save(path)) => {
                if let Some(node) = root.find(&path) {
                    self.save_dialog_then_call("Save unpacked item", &node.name.replace('/', "_"), "unpack.save", serde_json::json!({ "node": path }), "path");
                }
            }
            None => {}
        }
    }

    // -----------------------------------------------------------------------
    // Ask the file
    // -----------------------------------------------------------------------

    /// Send the typed question with a snapshot of what the user sees.
    /// Ask Claude to characterise the whole file using the analysis tools.
    pub fn characterise_with_ask(&mut self) {
        self.dock.open = true;
        self.dock.tab = DockTab::Assistant;
        self.dock.question = assistant::CHARACTERISE_REQUEST.to_string();
        self.ask_assistant();
    }

    pub fn ask_assistant(&mut self) {
        let question = self.dock.question.trim().to_string();
        if question.is_empty() {
            return;
        }
        let context = self.assistant_context();
        let credentials = self.credentials.as_ref().map(|(credentials, _)| credentials.clone());
        let tools = assistant::offered_tools(self);
        match self.assistant.ask(&question, &context, credentials, tools) {
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
            references: crate::panel_reference::notes_for_assistant(&crate::panel_reference::stack_at_cursor(self)),
        }
    }

    /// Carry out a tool call from the assistant against the open document,
    /// through the data API, as Ask: an edit waits for the person to confirm
    /// it unless Ask may edit. The reply is the method's JSON result, or
    /// its error as JSON.
    pub fn run_assistant_tool(&mut self, call: ToolCall, reply: ToolReply) {
        call.request(self, reply);
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

    /// Whether a serial capture is receiving.
    pub fn serial_capturing(&self) -> bool {
        self.bench.serial.as_ref().is_some_and(SerialCapture::is_running)
    }

    pub fn source_loading(&self) -> bool {
        self.bench.busy(|p| matches!(p, Pending::Source(_)))
    }

    /// Open a URL, serial port, block device, process or file, as the
    /// person's `documents.open_source`; why not is shown in the Live tab.
    pub fn open_source(&mut self, text: &str) {
        self.bench.live_error = None;
        self.perform_live("documents.open_source", serde_json::json!({ "uri": text }));
    }

    /// Call a live-source method as the person, showing a refusal in the
    /// Live tab as these actions always have.
    fn perform_live(&mut self, method: &str, params: serde_json::Value) {
        if let Err(error) = self.perform(method, params) {
            self.bench.live_error = Some(error.message);
        }
    }

    /// Open a URL, serial port, block device, process or file: the work of
    /// `documents.open_source`. A URL, device or process region is read in
    /// the background and opens when it arrives.
    pub(crate) fn open_live_source(&mut self, text: &str) -> Result<(), String> {
        let spec = SourceSpec::parse(text)?;
        let name = spec.describe();
        match spec {
            SourceSpec::File(path) => {
                self.load_path(&path);
                if self.document.path() != Some(path.as_path()) {
                    return Err(self.status.clone());
                }
            }
            SourceSpec::Url(url) => self.spawn_source(name, move || sources::fetch_url(&url, ANALYSIS_READ_LIMIT * 2)),
            SourceSpec::BlockDevice(path) => self.spawn_source(name, move || sources::read_block_device(&path, ANALYSIS_READ_LIMIT * 2)),
            SourceSpec::Serial { port, baud } => {
                let capture = SerialCapture::start(&port, baud)?;
                // Opening the capture's document stops any previous source.
                self.open_bytes(Vec::new(), name);
                self.bench.serial = Some(capture);
                self.bench.serial_seen = 0;
                self.bench.recording.get_or_insert_with(|| Recording::new(sources::DEFAULT_RECORDING_BUDGET));
            }
            SourceSpec::Process { pid } => {
                let regions = sources::process_regions(pid)?;
                self.bench.process_pid = Some(pid);
                self.bench.process_regions = regions.into_iter().filter(|r| r.is_readable()).collect();
            }
            SourceSpec::ProcessRegion { pid, start } => {
                let region = sources::readable_region_at(pid, start)?;
                self.spawn_source(name, move || sources::read_process_memory(pid, &region, ANALYSIS_READ_LIMIT));
            }
        }
        Ok(())
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
        let _ = self.watch_file(false);
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

    /// Turn watch mode on or off for the open file, as the person's
    /// `sources.watch`.
    pub fn set_watch(&mut self, enabled: bool) {
        self.perform_live("sources.watch", serde_json::json!({ "enabled": enabled }));
    }

    /// Turn watch mode on or off for the open file: the work of
    /// `sources.watch`, and of stopping the live sources.
    pub(crate) fn watch_file(&mut self, enabled: bool) -> Result<(), String> {
        self.bench.watch_enabled = false;
        self.bench.watcher = None;
        if !enabled {
            return Ok(());
        }
        let path = self.document.path().map(|p| p.to_path_buf()).ok_or_else(|| "Only files on disk can be watched".to_string())?;
        let watcher = FileWatcher::new(&path)?;
        self.bench.watcher = Some(watcher);
        self.bench.watch_enabled = true;
        let bytes = self.document.read_range(0, RECORDING_FILE_LIMIT);
        self.record_snapshot(&bytes);
        Ok(())
    }

    /// Start or stop keeping every version of the file or capture: the
    /// work of `sources.record`.
    pub(crate) fn record_history(&mut self, enabled: bool) {
        if enabled == self.bench.recording.is_some() {
            return;
        }
        self.bench.recording = enabled.then(|| Recording::new(sources::DEFAULT_RECORDING_BUDGET));
        if enabled {
            let bytes = self.document.read_range(0, RECORDING_FILE_LIMIT);
            self.record_snapshot(&bytes);
        }
    }

    /// Open recorded version `index` as a derived document, with what
    /// changed from the version before pinned: the work of
    /// `sources.view_version`.
    pub(crate) fn view_recorded_version(&mut self, index: usize) -> Result<(), crate::api::ApiError> {
        let (bytes, name) = crate::api::workspace::recorded_version(self.bench.recording.as_ref(), index, &self.display_name())?;
        let ranges = self.bench.recording.as_ref().map(|recording| recording.changed_ranges(index)).unwrap_or_default();
        self.open_derived(bytes, name);
        for (start, len) in ranges {
            self.bench.pinned.push(changed_finding(start, len, "Changed in this version"));
        }
        Ok(())
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
                self.perform_live("sources.record", serde_json::json!({ "enabled": recording }));
            }
        });
        if let Some(capture) = &self.bench.serial {
            let running = capture.is_running();
            ui.horizontal(|ui| {
                ui.label(RichText::new(if running { "● receiving" } else { "stopped" }).color(if running { theme::ACCENT } else { theme::TEXT_DIM }));
                ui.label(format!("{} bytes", capture.received()));
            });
            if ui.button("Stop capture").clicked() {
                self.perform_live("sources.stop", serde_json::json!({}));
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
                let start = self.bench.process_regions[index].start;
                self.perform_live("documents.open_source", serde_json::json!({ "uri": format!("pid:{pid}@{start:#x}") }));
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
            self.perform_live("sources.view_version", serde_json::json!({ "index": index }));
        }
    }

    // Tabs filled in by the disassembly, checksums and diff integration.
    fn show_disassembly_tab(&mut self, ui: &mut Ui) {
        crate::analysis_tabs::show_disassembly(self, ui);
    }

    fn show_checksums_tab(&mut self, ui: &mut Ui) {
        crate::analysis_tabs::show_checksums(self, ui);
        ui.separator();
        egui::CollapsingHeader::new("Solve a custom CRC").id_salt("crc-solver").show(ui, |ui| {
            panels::show(self, ui, |p| &mut p.crc_solver, crate::panel_crc_solver::show_crc_solver);
        });
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
/// The document offset under `pointer` in a curve layout drawn into
/// `drawn`, or `None` outside the picture or past the end of the data.
fn curve_offset_at(curve: hilbert::Curve, order: u32, bytes_per_cell: f64, len: usize, drawn: Rect, pointer: egui::Pos2) -> Option<usize> {
    if !drawn.contains(pointer) {
        return None;
    }
    let side = 1u32 << order;
    let cell = drawn.width() / side as f32;
    let x = (((pointer.x - drawn.min.x) / cell) as u32).min(side - 1);
    let y = (((pointer.y - drawn.min.y) / cell) as u32).min(side - 1);
    let offset = (curve.xy_to_d(order, x, y) as f64 * bytes_per_cell) as usize;
    (offset < len).then_some(offset)
}

/// One colour per cell, in curve order, for the sampled `bytes` (cell `d`
/// stands for the file from `d * bytes_per_cell`).
fn curve_cell_colours(
    bytes: &[u8],
    bytes_per_cell: f64,
    mode: CurveColour,
    format: PixelFormat,
    palette: raster::Palette,
    regions: &[Region],
) -> Vec<Color32> {
    let lut = palette.lut();
    match mode {
        CurveColour::Bytes if format == PixelFormat::ByteClass => bytes.iter().map(|&byte| raster::byte_class_colour(byte)).collect(),
        CurveColour::Bytes => bytes.iter().map(|&byte| lut[byte as usize]).collect(),
        CurveColour::ByteClass => bytes.iter().map(|&byte| raster::byte_class_colour(byte)).collect(),
        CurveColour::Entropy => bytes
            .chunks(CURVE_ENTROPY_CELLS)
            .flat_map(|block| {
                let colour = crate::view::entropy_colour(crate::analysis::shannon_entropy(block));
                std::iter::repeat_n(colour, block.len())
            })
            .collect(),
        // Without a report there are no regions: show the bytes meanwhile.
        CurveColour::RegionType if regions.is_empty() => bytes.iter().map(|&byte| lut[byte as usize]).collect(),
        CurveColour::RegionType => {
            let mut cursor = crate::region_colours::RegionCursor::new(regions);
            (0..bytes.len())
                .map(|cell| cursor.colour_at((cell as f64 * bytes_per_cell) as usize).unwrap_or(Color32::BLACK))
                .collect()
        }
    }
}

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

    #[test]
    fn unpacking_is_a_job_of_the_person_s_that_fills_the_tab_and_a_node_opens_through_the_api() {
        use serde_json::json;
        let mut app = ViewerApp::new(crate::app::Launch::default());
        app.open_bytes(crate::api::test_support::example_bytes(), "example.bin".to_string());
        crate::actions::take_performed();
        app.start_unpack();
        assert_eq!(crate::actions::take_performed(), [("unpack.run".to_string(), json!({}))]);
        let ctx = Context::default();
        let begun = std::time::Instant::now();
        while app.bench.unpacked.is_none() && begun.elapsed() < std::time::Duration::from_secs(60) {
            app.poll_workbench(&ctx);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let tree = app.bench.unpacked.clone().expect("the tree fills the tab");
        assert_eq!(tree.children[0].data.len(), 300);
        app.run_bus();
        let job = app.bus.jobs().list().into_iter().find(|job| job.title == "Unpack").expect("the unpacking is a job");
        assert_eq!((job.producer.as_str(), job.result.as_ref().map(|result| result["children"][0]["len"].clone())), ("panel", Some(json!(300))));
        let opened = app.perform("unpack.open", json!({"path": [0]})).unwrap();
        assert_eq!(opened["len"], 300);
        assert_eq!(app.document.len(), 300, "the node is the document shown");
    }

    use serde_json::json;

    use crate::actions::take_performed;
    use crate::app::Launch;

    const RECORDS: &str = "endian little\nstruct R { n: u16 }\nroot R[until_end]";

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        take_performed();
        app
    }

    #[test]
    fn applying_a_template_at_the_cursor_is_a_pinned_templates_apply_that_fills_the_template_tool() {
        let mut app = app_with(&[1, 0, 2, 0, 3, 0, 4, 0]);
        app.restore_selection(2, 4);
        app.apply_template_here(RECORDS);
        assert_eq!(take_performed(), [("templates.apply".to_string(), json!({"source": RECORDS, "at": 2, "pin": true}))], "applied at the selection start");
        let applied = app.bench.template_result.as_ref().expect("the Template tool shows the records");
        assert_eq!((applied.finding.start, applied.records.len()), (2, 3));
        assert_eq!(app.bench.template_applied_source, RECORDS);
        assert_eq!(app.dock.tab, DockTab::Template);
        assert_eq!(app.status, "R applied at 0x2: 3 records");
        assert!(app.bench.pinned.iter().any(|pinned| pinned.id.starts_with("template:")));
        app.run_bus();
        assert!(app.bus.facts().any(|fact| fact.topic() == crate::bus::Topic::TemplateApplied), "published as before");
    }

    #[test]
    fn a_template_that_does_not_parse_is_said_in_the_tool_without_a_call() {
        let mut app = app_with(&[0; 8]);
        app.apply_template_here("struct {");
        assert!(take_performed().is_empty());
        assert!(app.bench.template_error.is_some());
        assert!(app.status.starts_with("Template error:"), "{}", app.status);
    }

    #[test]
    fn a_tool_s_apply_as_template_moves_the_cursor_and_applies_there() {
        let mut app = app_with(&[1, 0, 2, 0, 3, 0, 4, 0]);
        app.apply_template_from_tool(RECORDS, 4);
        assert_eq!(take_performed(), [("cursor.set".to_string(), json!({"offset": 4})), ("templates.apply".to_string(), json!({"source": RECORDS, "at": 4, "pin": true}))]);
        assert_eq!(app.bench.template_result.as_ref().map(|applied| applied.records.len()), Some(2));
    }

    #[test]
    fn inferring_a_template_from_the_selection_is_a_pinned_templates_infer() {
        let records: Vec<u8> = (0..32u32).flat_map(|index| [vec![0xA5, 0x5A], (index as u16).to_le_bytes().to_vec(), index.wrapping_mul(2_654_435_761).to_le_bytes().to_vec()].concat()).collect();
        let mut app = app_with(&records);
        app.infer_template();
        assert!(take_performed().is_empty(), "nothing selected");
        assert_eq!(app.status, "Select a few records first");
        app.restore_selection(0, 256);
        app.infer_template();
        let guessed = templates::guess_record_length(&records[..256]).expect("a repeating length");
        assert_eq!(take_performed(), [("templates.infer".to_string(), json!({"start": 0, "len": 256, "record_len": guessed, "pin": true}))], "the record length is in the step");
        assert_eq!(app.bench.template_result.as_ref().map(|applied| applied.finding.start), Some(0), "the inferred struct is applied and shown");
    }

    #[test]
    fn clearing_the_template_is_templates_clear() {
        let mut app = app_with(&[1, 0, 2, 0]);
        app.apply_template_here(RECORDS);
        take_performed();
        app.clear_template();
        assert_eq!(take_performed(), [("templates.clear".to_string(), json!({}))]);
        assert!(app.bench.template_result.is_none());
        assert!(!app.bench.pinned.iter().any(|pinned| pinned.id.starts_with("template:")));
    }

    #[test]
    fn explaining_the_file_is_a_report_job_of_the_person_s_that_fills_the_report_and_the_file_map() {
        let mut bytes = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
        bytes.extend(vec![0; 4096]);
        let mut app = app_with(&bytes);
        app.explain_file();
        app.explain_file();
        assert_eq!(take_performed(), [("report.run".to_string(), json!({}))], "once while it is being worked out");
        let ctx = Context::default();
        let begun = Instant::now();
        while app.bench.report.is_none() && begun.elapsed() < Duration::from_secs(30) {
            app.poll_workbench(&ctx);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(app.bench.report.is_some() && !app.bench.regions.is_empty());
        app.run_bus();
        assert!(!app.mapped_regions.is_empty(), "the file map is published");
        let job = app.bus.jobs().list().into_iter().find(|job| job.title == "Report").expect("a job");
        assert_eq!(job.producer, "panel");
        assert!(job.result.as_ref().is_some_and(|result| !result["regions"].as_array().unwrap().is_empty()), "the job's result carries the report");
    }

    #[test]
    fn a_report_of_an_empty_file_or_the_app_s_own_refresh_calls_nothing() {
        let mut app = app_with(b"");
        app.explain_file();
        assert!(take_performed().is_empty());
        let mut app = app_with(b"some text to explain");
        app.start_report();
        assert!(take_performed().is_empty(), "the app's own report is not the person's step");
        assert!(app.report_running());
    }

    #[test]
    fn a_template_record_clicked_is_selected_through_the_api() {
        let mut app = app_with(&[0; 16]);
        app.select_from_tool(4, 2);
        assert_eq!(take_performed(), [("selection.set".to_string(), json!({"selection": {"range": [4, 2]}}))]);
        assert_eq!(app.selection(), Some((4, 2)));
        app.go_to_offset(100);
        assert_eq!(take_performed(), [("cursor.set".to_string(), json!({"offset": 16}))], "a jump past the end goes to the end");
    }
}
