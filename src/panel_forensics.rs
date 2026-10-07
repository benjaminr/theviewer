//! Firmware and forensics panel: embedded filesystems found in the document,
//! and a per-block file-type map for carving headerless fragments.

use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui::{self, Color32, CornerRadius, RichText, Sense, Stroke, Ui, vec2};

use crate::app::ViewerApp;
use crate::compress::human_bytes;
use crate::embedfs::{self, Entry, EntryKind, Filesystem};
use crate::fragments::{self, BlockClass, Run};
use crate::plugin::Category;
use crate::theme;
use crate::unpack::Limits;

/// Largest prefix of the document scanned by either section.
pub(crate) const SCAN_LIMIT: usize = 256 * 1024 * 1024;
/// How often to look for a finished background job.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const STRIP_HEIGHT: f32 = 28.0;
const LIST_HEIGHT: f32 = 220.0;

/// Identifies the document a result was computed from, to flag stale results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DocumentKey {
    pub len: usize,
    pub version: u64,
}

impl DocumentKey {
    fn of(app: &ViewerApp) -> Self {
        DocumentKey { len: app.document.len(), version: app.document.version() }
    }
}

pub(crate) struct FilesystemScan {
    pub key: DocumentKey,
    pub filesystems: Vec<Filesystem>,
}

pub(crate) struct BlockScan {
    pub key: DocumentKey,
    pub scanned_len: usize,
    pub runs: Vec<Run>,
    pub block_count: usize,
}

#[derive(Default)]
pub struct ForensicsState {
    filesystems_pending: Option<Receiver<FilesystemScan>>,
    filesystems: Option<FilesystemScan>,
    selected_filesystem: usize,
    blocks_pending: Option<Receiver<BlockScan>>,
    blocks: Option<BlockScan>,
}

impl ForensicsState {
    fn is_busy(&self) -> bool {
        self.filesystems_pending.is_some() || self.blocks_pending.is_some()
    }

    /// Collect any finished background results.
    fn poll(&mut self) {
        if let Some(receiver) = &self.filesystems_pending
            && let Ok(scan) = receiver.try_recv()
        {
            self.filesystems = Some(scan);
            self.filesystems_pending = None;
            self.selected_filesystem = 0;
        }
        if let Some(receiver) = &self.blocks_pending
            && let Ok(scan) = receiver.try_recv()
        {
            self.blocks = Some(scan);
            self.blocks_pending = None;
        }
    }
}

pub fn show_forensics(state: &mut ForensicsState, app: &mut ViewerApp, ui: &mut Ui) {
    state.poll();
    if state.is_busy() {
        ui.ctx().request_repaint_after(POLL_INTERVAL);
    }
    egui::ScrollArea::vertical().id_salt("forensics-panel").show(ui, |ui| {
        egui::CollapsingHeader::new(RichText::new("Filesystems").strong()).id_salt("forensics-filesystems").default_open(true).show(ui, |ui| {
            show_filesystems(state, app, ui);
        });
        egui::CollapsingHeader::new(RichText::new("Block classes").strong()).id_salt("forensics-blocks").default_open(true).show(ui, |ui| {
            show_block_classes(state, app, ui);
        });
    });
}

/// "(stale)" when the document has changed since a result was computed.
fn stale_marker(ui: &mut Ui, key: DocumentKey, app: &ViewerApp) {
    if key != DocumentKey::of(app) {
        ui.label(RichText::new("(document changed since this scan)").small().color(theme::CURSOR));
    }
}

// ---------------------------------------------------------------------------
// Filesystems
// ---------------------------------------------------------------------------

/// The filesystem images in `bytes`, with their files extracted.
pub(crate) fn filesystems_in(bytes: &[u8]) -> Vec<Filesystem> {
    let limits = Limits::default();
    let mut bytes_left = limits.max_total_bytes;
    embedfs::find_filesystems(bytes, &limits, &mut bytes_left)
}

/// Where a job's result for the panel is sent, and where the panel waits for it.
fn awaited<T>(pending: &mut Option<Receiver<T>>) -> mpsc::Sender<T> {
    let (sender, receiver) = mpsc::channel();
    *pending = Some(receiver);
    sender
}

/// Wait for a search `forensics.find_filesystems` started; returns where it is sent.
pub(crate) fn await_filesystems(app: &mut ViewerApp) -> mpsc::Sender<FilesystemScan> {
    awaited(&mut app.bench.panels.forensics.filesystems_pending)
}

/// Wait for the classes `forensics.classify_blocks` works out; returns where they are sent.
pub(crate) fn await_blocks(app: &mut ViewerApp) -> mpsc::Sender<BlockScan> {
    awaited(&mut app.bench.panels.forensics.blocks_pending)
}

enum FilesystemAction {
    Jump(usize),
    Open { filesystem: usize, entry: usize },
}

fn show_filesystems(state: &mut ForensicsState, app: &mut ViewerApp, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        let size = human_bytes(app.document.len().min(SCAN_LIMIT));
        if ui.add_enabled(state.filesystems_pending.is_none(), egui::Button::new(format!("Scan for filesystems ({size})"))).clicked() {
            app.perform_later("forensics.find_filesystems", serde_json::json!({}));
        }
        if state.filesystems_pending.is_some() {
            ui.spinner();
        }
        if let Some(scan) = &state.filesystems {
            stale_marker(ui, scan.key, app);
        }
    });
    let Some(scan) = &state.filesystems else {
        ui.label(RichText::new("Finds SquashFS, CramFS, JFFS2 and UBI images inside the document and lists their files, which can be opened as documents of their own.").color(theme::TEXT_DIM));
        return;
    };
    if scan.filesystems.is_empty() {
        ui.label(RichText::new("No SquashFS, CramFS, JFFS2 or UBI images found.").color(theme::TEXT_DIM));
        return;
    }
    let mut action = None;
    filesystem_table(ui, &scan.filesystems, &mut state.selected_filesystem, &mut action);
    let selected = state.selected_filesystem.min(scan.filesystems.len() - 1);
    let filesystem = &scan.filesystems[selected];
    if let Some(note) = &filesystem.note {
        ui.label(RichText::new(note).small().color(theme::CURSOR));
    }
    ui.horizontal(|ui| {
        let first = filesystem.entries.iter().position(|entry| entry.kind.has_content());
        let button = egui::Button::new("Open first file");
        if ui.add_enabled(first.is_some(), button).on_hover_text("Open the first file or volume as a document; Back returns").clicked()
            && let Some(entry) = first
        {
            action = Some(FilesystemAction::Open { filesystem: selected, entry });
        }
        ui.label(RichText::new(filesystem.description.as_str()).small().color(theme::TEXT_DIM));
    });
    file_list(ui, filesystem, selected, &mut action);

    match action {
        Some(FilesystemAction::Jump(offset)) => app.jump_found(offset),
        Some(FilesystemAction::Open { filesystem, entry }) => {
            let filesystem = &scan.filesystems[filesystem];
            let params = serde_json::json!({ "filesystem": filesystem.offset, "path": filesystem.entries[entry].path });
            let _ = app.perform("forensics.open_entry", params);
        }
        None => {}
    }
}

fn filesystem_table(ui: &mut Ui, filesystems: &[Filesystem], selected: &mut usize, action: &mut Option<FilesystemAction>) {
    egui::Grid::new("forensics-filesystem-grid").num_columns(5).striped(true).spacing([14.0, 2.0]).show(ui, |ui| {
        for heading in ["Type", "Offset", "Size", "Files", ""] {
            ui.label(RichText::new(heading).small().color(theme::TEXT_DIM));
        }
        ui.end_row();
        for (index, filesystem) in filesystems.iter().enumerate() {
            ui.radio_value(selected, index, filesystem.kind.label());
            if ui.link(RichText::new(format!("{:#x}", filesystem.offset)).monospace()).on_hover_text("Jump to the image").clicked() {
                *action = Some(FilesystemAction::Jump(filesystem.offset));
            }
            ui.monospace(human_bytes(filesystem.len));
            ui.monospace(filesystem.file_count().to_string());
            ui.label(RichText::new(filesystem.description.as_str()).small().color(theme::TEXT_DIM));
            ui.end_row();
        }
    });
}

fn entry_kind_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Directory => "dir",
        EntryKind::Symlink => "link",
        EntryKind::Special => "special",
        EntryKind::Volume => "volume",
    }
}

fn file_list(ui: &mut Ui, filesystem: &Filesystem, filesystem_index: usize, action: &mut Option<FilesystemAction>) {
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 6.0;
    egui::ScrollArea::vertical().id_salt("forensics-files").max_height(LIST_HEIGHT).show_rows(ui, row_height, filesystem.entries.len(), |ui, rows| {
        for index in rows {
            let entry = &filesystem.entries[index];
            ui.horizontal(|ui| {
                let can_open = entry.kind.has_content() || (entry.kind == EntryKind::Symlink && !entry.data.is_empty());
                if ui.add_enabled(can_open, egui::Button::new("Open").small()).clicked() {
                    *action = Some(FilesystemAction::Open { filesystem: filesystem_index, entry: index });
                }
                ui.label(RichText::new(entry_kind_label(entry.kind)).small().color(theme::TEXT_DIM));
                entry_label(ui, entry);
            });
        }
    });
}

fn entry_label(ui: &mut Ui, entry: &Entry) {
    let colour = if entry.kind == EntryKind::Directory { theme::ACCENT } else { theme::TEXT };
    ui.add(egui::Label::new(RichText::new(entry.path.as_str()).monospace().color(colour)).truncate());
    match entry.kind {
        EntryKind::Symlink => {
            ui.label(RichText::new(format!("→ {}", String::from_utf8_lossy(&entry.data))).small().color(theme::TEXT_DIM));
        }
        kind if kind.has_content() => {
            let mut size = human_bytes(entry.data.len());
            if entry.declared_size > entry.data.len() as u64 {
                size.push_str(&format!(" of {}", human_bytes(usize::try_from(entry.declared_size).unwrap_or(usize::MAX))));
            }
            if let Some(method) = &entry.method {
                size.push_str(&format!(" ({method})"));
            }
            ui.label(RichText::new(size).small().color(theme::TEXT_DIM));
        }
        _ => {}
    }
    if let Some(note) = &entry.note {
        ui.label(RichText::new(note.as_str()).small().color(theme::CURSOR));
    }
}

// ---------------------------------------------------------------------------
// Block classes
// ---------------------------------------------------------------------------

/// Strip and legend colour for each class, from the highlight palette.
fn class_colour(class: BlockClass) -> Color32 {
    match class {
        BlockClass::Padding => Category::Padding.colour(),
        BlockClass::Text => Category::Text.colour(),
        BlockClass::Markup => Category::Document.colour(),
        BlockClass::MachineCode => Category::Executable.colour(),
        BlockClass::Compressed => Category::Compressed.colour(),
        BlockClass::Random => Category::HighEntropy.colour(),
        BlockClass::Image => Category::Image.colour(),
        BlockClass::Audio => Category::FloatArray.colour(),
        BlockClass::Table => Category::Structure.colour(),
        BlockClass::Binary => theme::OUTLINE,
    }
}

/// Classify `bytes` (the document of `key`, from its start) in blocks of `block_size`.
pub(crate) fn classify(bytes: &[u8], key: DocumentKey, block_size: usize) -> BlockScan {
    let blocks = fragments::classify_blocks(bytes, block_size);
    let runs = fragments::merge_runs(&blocks);
    BlockScan { key, scanned_len: bytes.len(), runs, block_count: blocks.len() }
}

fn show_block_classes(state: &mut ForensicsState, app: &mut ViewerApp, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        let size = human_bytes(app.document.len().min(SCAN_LIMIT));
        let label = format!("Classify {} KiB blocks ({size})", fragments::DEFAULT_BLOCK_SIZE / 1024);
        if ui.add_enabled(state.blocks_pending.is_none(), egui::Button::new(label)).clicked() {
            app.perform_later("forensics.classify_blocks", serde_json::json!({ "block_size": fragments::DEFAULT_BLOCK_SIZE }));
        }
        if state.blocks_pending.is_some() {
            ui.spinner();
        }
        if let Some(scan) = &state.blocks {
            stale_marker(ui, scan.key, app);
        }
    });
    let Some(scan) = &state.blocks else {
        ui.label(
            RichText::new("Labels every 4 KiB block as padding, text, markup, machine code, compressed, random, raw image, PCM audio or table data, with the reason for each, to locate fragments that have no header.")
                .color(theme::TEXT_DIM),
        );
        return;
    };
    let mut jump = class_strip(ui, scan);
    legend(ui, &scan.runs);
    ui.label(RichText::new(format!("{} blocks in {} runs", scan.block_count, scan.runs.len())).small().color(theme::TEXT_DIM));
    if let Some(offset) = run_list(ui, &scan.runs) {
        jump = Some(offset);
    }
    if let Some(offset) = jump {
        app.jump_found(offset);
    }
}

/// The class strip across the scanned range; returns an offset when clicked.
fn class_strip(ui: &mut Ui, scan: &BlockScan) -> Option<usize> {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), STRIP_HEIGHT), Sense::click());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(3), theme::BACKGROUND);
    let total = scan.scanned_len.max(1) as f32;
    let x_of = |offset: usize| rect.min.x + rect.width() * offset as f32 / total;
    for run in &scan.runs {
        // At least a pixel wide, so short runs stay visible.
        let (left, right) = (x_of(run.offset), x_of(run.end()).max(x_of(run.offset) + 1.0));
        let band = egui::Rect::from_min_max(egui::pos2(left, rect.min.y), egui::pos2(right, rect.max.y));
        painter.rect_filled(band, CornerRadius::ZERO, class_colour(run.class));
    }
    painter.rect_stroke(rect, CornerRadius::same(3), Stroke::new(1.0, theme::OUTLINE), egui::StrokeKind::Inside);
    let pointer_offset = |x: f32| (((x - rect.min.x) / rect.width()).clamp(0.0, 1.0) * total) as usize;
    let hovered = response.hover_pos().map(|pos| pointer_offset(pos.x));
    let clicked = response.clicked().then(|| response.interact_pointer_pos()).flatten().map(|pos| pointer_offset(pos.x));
    if let Some(offset) = hovered
        && let Some(run) = scan.runs.iter().find(|run| (run.offset..run.end()).contains(&offset))
    {
        response.on_hover_text(format!(
            "{:#x}: {} ({} blocks from {:#x}, {:.0}% confidence)\n{}",
            offset,
            run.class.label(),
            run.blocks,
            run.offset,
            run.confidence * 100.0,
            run.reason
        ));
    }
    clicked
}

fn legend(ui: &mut Ui, runs: &[Run]) {
    ui.horizontal_wrapped(|ui| {
        for class in BlockClass::ALL {
            let bytes: usize = runs.iter().filter(|run| run.class == class).map(|run| run.len).sum();
            if bytes > 0 {
                theme::swatch(ui, class_colour(class), &format!("{} ({})", class.label(), human_bytes(bytes)));
            }
        }
    });
}

/// The runs as rows; returns an offset when one is clicked.
fn run_list(ui: &mut Ui, runs: &[Run]) -> Option<usize> {
    let mut jump = None;
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
    egui::ScrollArea::vertical().id_salt("forensics-runs").max_height(LIST_HEIGHT).show_rows(ui, row_height, runs.len(), |ui, rows| {
        for run in &runs[rows] {
            ui.horizontal(|ui| {
                if ui.link(RichText::new(format!("{:#010x}", run.offset)).monospace()).clicked() {
                    jump = Some(run.offset);
                }
                ui.monospace(RichText::new(format!("{:>9}", human_bytes(run.len))).color(theme::TEXT_DIM));
                theme::swatch(ui, class_colour(run.class), run.class.label());
                ui.label(RichText::new(format!("{:.0}%", run.confidence * 100.0)).small().color(theme::TEXT_DIM));
                ui.add(egui::Label::new(RichText::new(run.reason.as_str()).small().color(theme::TEXT_DIM)).truncate());
            });
        }
    });
    jump
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use egui_kittest::kittest::Queryable;
    use serde_json::json;

    use super::*;
    use crate::app::Launch;

    #[test]
    fn the_scans_are_jobs_of_the_person_s_carried_out_once_the_panel_is_drawn() {
        let mut app = ViewerApp::new(Launch::default());
        let mut bytes = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
        bytes.extend(vec![0u8; 8192]);
        app.open_bytes(bytes, "mixed.bin".to_string());
        crate::actions::take_performed();
        // Drawn as the window draws it: its state lent out of the app, and
        // the actions it asked for carried out before each frame.
        let mut harness = egui_kittest::Harness::new_ui_state(
            |ui, app: &mut ViewerApp| {
                app.perform_waiting_actions();
                crate::panels::show(app, ui, |panels| &mut panels.forensics, show_forensics);
            },
            app,
        );
        harness.step();
        harness.get_by_label_contains("Scan for filesystems").click();
        harness.step();
        harness.get_by_label_contains("Classify 4 KiB blocks").click();
        harness.step();
        harness.step();
        assert_eq!(
            crate::actions::take_performed(),
            [("forensics.find_filesystems".to_string(), json!({})), ("forensics.classify_blocks".to_string(), json!({"block_size": fragments::DEFAULT_BLOCK_SIZE}))]
        );
        let state = &harness.state().bench.panels.forensics;
        let blocks = state.blocks_pending.as_ref().expect("the panel waits for the classes").recv_timeout(Duration::from_secs(60)).expect("classified");
        assert_eq!(blocks.runs[0].class, BlockClass::Text);
        let filesystems = state.filesystems_pending.as_ref().expect("and for the filesystems").recv_timeout(Duration::from_secs(60)).expect("searched");
        assert!(filesystems.filesystems.is_empty());
    }
}
