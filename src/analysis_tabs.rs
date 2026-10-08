//! Dock tabs for disassembly, checksums and diff, and the pointer graph drawn
//! over the raster.

use std::sync::mpsc::{self, Receiver, Sender};

use eframe::egui::{self, Color32, ColorImage, Painter, Pos2, Rect, RichText, Sense, Stroke, TextureHandle, TextureOptions, Ui, pos2, vec2};

use crate::app::ViewerApp;
use crate::api::tools::checksums::StoredChecksum;
use crate::checksums::{self, Digests};
use crate::api::tools::diff::DiffOutcome;
use crate::diff::{self, DiffOp, DiffResult};
use crate::disasm::{self, AddressMap, Arch, Instruction};
use crate::document::Document;
use crate::plugin::{Category, Finding};
use crate::pointers::{self, Pointer};
use crate::raster;
use crate::theme;

/// Instructions listed from the cursor.
const LISTING_LEN: usize = 300;
/// Largest range hashed or searched for checksums.
const CHECKSUM_LIMIT: usize = 64 * 1024 * 1024;
/// Differences listed in the diff tab.
const MAX_LISTED_OPS: usize = 2000;
/// The key the stored checksum shown is published under.
const CHECKSUM_KEY: &str = "checksum";
/// The key the differences found by a comparison are published under.
const DIFF_KEY: &str = "diff";
/// Most differences outlined on the views.
const MAX_OUTLINED_DIFFERENCES: usize = 5000;

/// Which architecture the disassembler uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchChoice {
    Auto,
    Fixed(Arch),
}

/// The file's detected architecture and address map, for one document version.
type Detected = (u64, Option<(Arch, u64, String)>, Option<AddressMap>);
/// A disassembly listing for (start, version, arch choice), with a note.
type Listing = ((usize, u64, ArchChoice), Result<Vec<Instruction>, String>, Option<String>);

/// State for the tabs in this module.
pub struct AnalysisState {
    pub arch: ArchChoice,
    /// Detected from the file header, with the reason.
    detected: Option<Detected>,
    listing: Option<Listing>,

    pub digests: Option<(usize, usize, Digests)>,
    pub checksum_matches: Option<Vec<StoredChecksum>>,

    pub diff_other: Option<String>,
    /// The open sheet compared with, when it was one rather than a file.
    pub diff_other_sheet: Option<String>,
    diff_pending: Option<Receiver<DiffOutcome>>,
    pub diff: Option<DiffResult>,
    other: Option<Document>,
    other_texture: Option<(usize, usize, TextureHandle)>,

    pub show_pointers: bool,
    pointer_cache: Option<((u64, usize, usize), Vec<Pointer>)>,
}

impl Default for AnalysisState {
    fn default() -> Self {
        AnalysisState {
            arch: ArchChoice::Auto,
            detected: None,
            listing: None,
            digests: None,
            checksum_matches: None,
            diff_other: None,
            diff_other_sheet: None,
            diff_pending: None,
            diff: None,
            other: None,
            other_texture: None,
            show_pointers: false,
            pointer_cache: None,
        }
    }
}

impl AnalysisState {
    /// Forget results tied to the previous document's bytes.
    pub fn document_changed(&mut self) {
        self.detected = None;
        self.listing = None;
        self.digests = None;
        self.checksum_matches = None;
        self.pointer_cache = None;
        self.diff = None;
        self.other_texture = None;
    }

    /// Take what was worked out about the sheet shown, to keep while it is
    /// parked; the person's choices (the architecture, the pointer arrows)
    /// stay.
    pub fn take_results(&mut self) -> AnalysisState {
        let choices = AnalysisState { arch: self.arch, show_pointers: self.show_pointers, ..Default::default() };
        std::mem::replace(self, choices)
    }

    /// Show what was kept for the sheet now shown, keeping the person's
    /// choices.
    pub fn put_results(&mut self, kept: AnalysisState) {
        let (arch, show_pointers) = (self.arch, self.show_pointers);
        *self = AnalysisState { arch, show_pointers, ..kept };
    }
}

// ---------------------------------------------------------------------------
// Disassembly
// ---------------------------------------------------------------------------

/// The file's own architecture and address map, worked out once per edit.
fn detected(app: &mut ViewerApp) -> (Option<(Arch, u64, String)>, Option<AddressMap>) {
    let version = app.document.version();
    if app.bench.analysis.detected.as_ref().map(|d| d.0) != Some(version) {
        let header = app.document.read_range(0, 64 * 1024 * 1024);
        let arch = disasm::detect_arch(&header);
        let map = AddressMap::from_executable(&header);
        app.bench.analysis.detected = Some((version, arch, map));
    }
    let (_, arch, map) = app.bench.analysis.detected.as_ref().expect("filled above");
    (arch.clone(), map.clone())
}

pub fn show_disassembly(app: &mut ViewerApp, ui: &mut Ui) {
    let (header_arch, map) = detected(app);
    let start = app.selection().map(|(s, _)| s).unwrap_or(app.cursor);
    ui.horizontal(|ui| {
        let label = match app.bench.analysis.arch {
            ArchChoice::Auto => "Auto".to_string(),
            ArchChoice::Fixed(arch) => arch.label().to_string(),
        };
        let mut chosen = app.bench.analysis.arch;
        egui::ComboBox::from_id_salt("disasm-arch").selected_text(label).show_ui(ui, |ui| {
            ui.selectable_value(&mut chosen, ArchChoice::Auto, "Auto");
            for arch in Arch::ALL {
                ui.selectable_value(&mut chosen, ArchChoice::Fixed(arch), arch.label());
            }
        });
        if chosen != app.bench.analysis.arch {
            set_disassembly_arch(app, chosen);
        }
        match &header_arch {
            Some((arch, entry, why)) => {
                ui.label(RichText::new(format!("{} from the header ({why})", arch.label())).small().color(theme::TEXT_DIM));
                if let Some(offset) = map.as_ref().and_then(|m| m.offset_of(*entry))
                    && ui.button(format!("Entry point {entry:#x}")).clicked()
                {
                    app.jump_found(offset);
                }
            }
            None => {
                ui.label(RichText::new("No executable header; the architecture is guessed from the bytes").small().color(theme::TEXT_DIM));
            }
        }
    });

    let key = (start, app.document.version(), app.bench.analysis.arch);
    if app.bench.analysis.listing.as_ref().map(|l| l.0) != Some(key) {
        let bytes = app.document.read_range(start, LISTING_LEN * 16);
        let (arch, note) = match app.bench.analysis.arch {
            ArchChoice::Fixed(arch) => (Some(arch), None),
            ArchChoice::Auto => match &header_arch {
                Some((arch, _, _)) => (Some(*arch), None),
                None => match disasm::guess_arch(&bytes) {
                    Some((arch, score)) => (Some(arch), Some(format!("Looks like {} ({:.0}% of bytes decode as typical instructions)", arch.label(), score * 100.0))),
                    None => (None, Some("These bytes do not look like code for any supported architecture; pick one to force it.".to_string())),
                },
            },
        };
        let address = map.as_ref().and_then(|m| m.address_of(start)).unwrap_or(start as u64);
        let listing = match arch {
            Some(arch) => disasm::disassemble(arch, &bytes, start, address, LISTING_LEN),
            None => Err(String::new()),
        };
        app.bench.analysis.listing = Some((key, listing, note));
    }
    let (_, listing, note) = app.bench.analysis.listing.clone().expect("filled above");
    if let Some(note) = note {
        ui.label(RichText::new(note).small().color(theme::TEXT_DIM));
    }
    let instructions = match listing {
        Ok(instructions) => instructions,
        Err(message) => {
            if !message.is_empty() {
                ui.label(RichText::new(message).color(theme::DANGER));
            }
            return;
        }
    };
    let mut jump = None;
    egui::ScrollArea::vertical().id_salt("disasm-listing").show(ui, |ui| {
        egui::Grid::new("disasm-grid").striped(true).spacing([12.0, 1.0]).show(ui, |ui| {
            for instruction in &instructions {
                let colour = if instruction.is_data() {
                    theme::TEXT_DIM
                } else if instruction.is_call {
                    theme::CURSOR
                } else if instruction.is_return {
                    theme::DANGER
                } else {
                    theme::TEXT
                };
                if ui
                    .add(egui::Label::new(RichText::new(format!("{:#010x}", instruction.address)).monospace().color(theme::TEXT_DIM)).sense(Sense::click()))
                    .clicked()
                {
                    jump = Some(instruction.offset);
                }
                let bytes: Vec<String> = instruction.bytes.iter().take(8).map(|b| format!("{b:02x}")).collect();
                ui.monospace(RichText::new(bytes.join(" ")).color(theme::TEXT_DIM));
                ui.monospace(RichText::new(&instruction.mnemonic).color(colour));
                ui.horizontal(|ui| {
                    ui.monospace(&instruction.operands);
                    if let Some(target) = instruction.branch_target {
                        // With an address map, follow through it; without one, addresses are file offsets.
                        let offset = match &map {
                            Some(map) => map.offset_of(target),
                            None => Some(target as usize),
                        };
                        if let Some(offset) = offset
                            && ui.small_button("→").on_hover_text(format!("Follow to {target:#x} (file offset {offset:#x})")).clicked()
                        {
                            jump = Some(offset);
                        }
                    }
                });
                ui.end_row();
            }
        });
    });
    if let Some(offset) = jump {
        app.jump_found(offset);
    }
}

/// The person chooses the architecture to disassemble as: `disasm.set_arch`.
pub fn set_disassembly_arch(app: &mut ViewerApp, choice: ArchChoice) -> bool {
    let arch = crate::api::tools::disasm::DisasmArch::of_choice(choice);
    app.perform("disasm.set_arch", serde_json::json!({ "arch": arch })).is_ok()
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

pub fn show_checksums(app: &mut ViewerApp, ui: &mut Ui) {
    let (start, len) = app.selection().unwrap_or((0, app.document.len()));
    let len = len.min(CHECKSUM_LIMIT);
    let scope = if app.selection().is_some() { "selection" } else { "whole file" };
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{scope}: {} bytes from {start:#x}", len)).strong());
        if app.document.len() > CHECKSUM_LIMIT && app.selection().is_none() {
            ui.label(RichText::new(format!("(first {})", crate::compress::human_bytes(CHECKSUM_LIMIT))).small().color(theme::TEXT_DIM));
        }
    });
    if app.bench.analysis.digests.as_ref().map(|d| (d.0, d.1)) != Some((start, len)) {
        let bytes = app.document.read_range(start, len);
        app.bench.analysis.digests = Some((start, len, checksums::digests(&bytes)));
        app.note_tool_result(crate::dock::DockTab::Checksums);
    }
    let digests = app.bench.analysis.digests.as_ref().expect("filled above").2.clone();
    let rows = [
        ("CRC-32", format!("{:08x}", digests.crc32)),
        ("Adler-32", format!("{:08x}", digests.adler32)),
        ("MD5", digests.md5.clone()),
        ("SHA-1", digests.sha1.clone()),
        ("SHA-256", digests.sha256.clone()),
        ("sum8 / sum16 / xor8", format!("{:02x} / {:04x} / {:02x}", digests.sum8, digests.sum16, digests.xor8)),
    ];
    egui::Grid::new("digest-grid").spacing([14.0, 2.0]).show(ui, |ui| {
        for (name, value) in rows {
            ui.label(RichText::new(name).color(theme::TEXT_DIM));
            ui.monospace(&value);
            if ui.small_button("copy").clicked() {
                ui.ctx().copy_text(value.clone());
            }
            ui.end_row();
        }
    });
    ui.separator();
    ui.horizontal(|ui| {
        if ui.button("Find the checksum").on_hover_text("Look for a CRC, Adler or sum stored in the data that covers part of it").clicked() {
            find_stored_checksum(app, start, len);
        }
        ui.label(RichText::new("tests header and trailer fields against the bytes before, after and around them").small().color(theme::TEXT_DIM));
    });
    let Some(matches) = app.bench.analysis.checksum_matches.clone() else { return };
    if matches.is_empty() {
        ui.label(RichText::new("No stored checksum matched.").color(theme::TEXT_DIM));
        return;
    }
    let mut chosen = None;
    for found in &matches {
        ui.horizontal(|ui| {
            ui.label(RichText::new(&found.algorithm).strong().color(theme::ACCENT));
            ui.label(format!(
                "{} {} at {:#x} covers {:#x}..{:#x}",
                found.endian,
                if found.value_len == 1 { "byte" } else { "value" },
                found.value_offset,
                found.covered_start,
                found.covered_start + found.covered_len
            ));
            if ui.small_button("show").clicked() {
                chosen = Some(found.clone());
            }
        });
    }
    if let Some(found) = chosen {
        show_stored_checksum(app, &found);
    }
}

/// The person asks for a checksum stored in the span: `checksums.find_stored`,
/// with the edges of the findings in it as the boundaries to try.
fn find_stored_checksum(app: &mut ViewerApp, start: usize, len: usize) {
    let mut boundaries: Vec<usize> = app
        .patterns_in(start, start + len)
        .filter(|finding| !finding.weak())
        .flat_map(|finding| [finding.start, finding.end()])
        .filter(|&boundary| boundary > start && boundary < start + len)
        .collect();
    boundaries.sort_unstable();
    boundaries.dedup();
    let params = serde_json::json!({ "start": start, "len": len, "boundaries": boundaries });
    if let Ok(found) = app.perform_typed::<crate::api::tools::checksums::StoredChecksums>("checksums.find_stored", params) {
        app.bench.analysis.checksum_matches = Some(found.matches);
        app.note_tool_result(crate::dock::DockTab::Checksums);
    }
}

/// Pin a stored checksum on the views (`findings.publish` under the key
/// "checksum", replacing the one shown before) and select what it covers.
fn show_stored_checksum(app: &mut ViewerApp, found: &StoredChecksum) {
    let (covered_start, covered_len) = (found.covered_start as usize, found.covered_len as usize);
    let finding = Finding::new("checksum", "checksums", Category::Structure, found.value_offset as usize, found.value_len as usize)
        .title(format!("{} checksum", found.algorithm))
        .detail(format!("covers {:#x}..{:#x}", covered_start, covered_start + covered_len));
    if app.perform("findings.publish", serde_json::json!({ "findings": [finding], "key": CHECKSUM_KEY })).is_ok() {
        app.select_found(covered_start, covered_len);
    }
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/// The person compares the open document with another file: `diff.run`.
pub fn start_diff(app: &mut ViewerApp, other_path: std::path::PathBuf) {
    let _ = app.perform("diff.run", serde_json::json!({ "path": other_path.display().to_string() }));
}

/// The person compares the sheet shown with the open sheet `other`
/// (Compare with active, in the tree of sheets): `diff.run`, shown in the
/// Diff tab.
pub fn start_diff_with_sheet(app: &mut ViewerApp, other: &str) {
    app.dock.open = true;
    app.dock.tab = crate::dock::DockTab::Diff;
    let title = app.sheet_title(other).unwrap_or_else(|| other.to_string());
    if app.perform("diff.run", serde_json::json!({ "other": other })).is_ok() {
        app.bench.analysis.diff_other = Some(format!("{title} ({other})"));
        app.bench.analysis.diff_other_sheet = Some(other.to_string());
    }
}

/// Wait for a comparison `diff.run` started, to show it in the Diff tab;
/// returns where its outcome is sent.
pub(crate) fn await_diff(app: &mut ViewerApp) -> Sender<DiffOutcome> {
    app.note_tool_result(crate::dock::DockTab::Diff);
    let (sender, receiver) = mpsc::channel();
    app.bench.analysis.diff_pending = Some(receiver);
    app.bench.analysis.diff = None;
    sender
}

/// Outline where the document differs on the views: `findings.publish`
/// under the key "diff", replacing the last comparison's.
fn outline_differences(app: &mut ViewerApp, result: &DiffResult) {
    let findings: Vec<Finding> = result
        .ops
        .iter()
        .filter_map(|op| match *op {
            DiffOp::Replace { a, a_len, .. } => Some((a, a_len, "Differs")),
            DiffOp::Delete { a, len } => Some((a, len, "Only in this file")),
            DiffOp::Insert { .. } | DiffOp::Equal { .. } => None,
        })
        .take(MAX_OUTLINED_DIFFERENCES)
        .map(|(start, len, label)| Finding::new("diff", "diff", Category::Custom, start, len.max(1)).title(label).detail(format!("{len} bytes")))
        .collect();
    // The comparison's own effect, not a step of the person's: published
    // as theirs, but not performed again.
    let params = crate::api::findings::PublishParams { doc: None, findings, key: DIFF_KEY.to_string() };
    if let Err(error) = crate::api::findings::publish(app, &crate::api::Caller::Panel, params) {
        app.status = format!("The differences could not be outlined: {}", error.message);
    }
}

fn poll_diff(app: &mut ViewerApp) {
    let Some(receiver) = &app.bench.analysis.diff_pending else { return };
    match receiver.try_recv() {
        Ok(Ok((other, result))) => {
            outline_differences(app, &result);
            app.status = format!("{} bytes equal, {} differ", result.equal_bytes, result.changed_bytes);
            app.bench.analysis.diff = Some(result);
            app.bench.analysis.other = Some(other);
            app.bench.analysis.diff_pending = None;
        }
        Ok(Err(message)) => {
            app.status = message;
            app.bench.analysis.diff_pending = None;
        }
        Err(_) => {}
    }
}

pub fn show_diff(app: &mut ViewerApp, ui: &mut Ui) {
    poll_diff(app);
    ui.horizontal(|ui| {
        if ui.button("Compare with file…").clicked() {
            let dialog = rfd::AsyncFileDialog::new().set_title("Compare with");
            app.ask_for_file(crate::app::DialogKind::Open, dialog, crate::app::FileAction::Compare);
        }
        if app.bench.analysis.diff_pending.is_some() {
            ui.spinner();
            ui.label(RichText::new("Aligning the two files…").color(theme::TEXT_DIM));
        }
        if let Some(other) = &app.bench.analysis.diff_other {
            ui.label(RichText::new(other).small().color(theme::TEXT_DIM));
        }
    });
    let Some(result) = app.bench.analysis.diff.clone() else {
        ui.label(RichText::new("Finds inserted, deleted and changed regions, not just flipped bytes, and scrolls the other file in step with this one.").color(theme::TEXT_DIM));
        return;
    };
    ui.label(format!(
        "{} equal, {} changed{}",
        crate::compress::human_bytes(result.equal_bytes),
        crate::compress::human_bytes(result.changed_bytes),
        if result.truncated { " (stopped at the operation limit)" } else { "" }
    ));
    let width = ui.available_width();
    let mut jump = None;
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width((width * 0.45).max(260.0));
            egui::ScrollArea::vertical().id_salt("diff-ops").show(ui, |ui| {
                for op in result.ops.iter().filter(|op| !matches!(op, DiffOp::Equal { .. })).take(MAX_LISTED_OPS) {
                    let (text, colour, offset) = match *op {
                        DiffOp::Replace { a, a_len, b, b_len } => (format!("{a:#x}: {a_len} B replaced by {b_len} B (other {b:#x})"), theme::CURSOR, a),
                        DiffOp::Delete { a, len } => (format!("{a:#x}: {len} B only in this file"), theme::DANGER, a),
                        DiffOp::Insert { b, len } => (format!("other {b:#x}: {len} B only in the other file"), theme::ACCENT, crate::diff::aligned_offset_b_to_a(&result.ops, b).unwrap_or(0)),
                        DiffOp::Equal { .. } => continue,
                    };
                    if ui.add(egui::Label::new(RichText::new(text).monospace().small().color(colour)).sense(Sense::click())).clicked() {
                        jump = Some(offset);
                    }
                }
            });
        });
        ui.separator();
        ui.vertical(|ui| show_other_side(app, ui, &result));
    });
    if let Some(offset) = jump {
        app.jump_found(offset);
    }
}

/// The other file rastered with the same shape, at the position aligned with
/// this file's view, so the two scroll together.
fn show_other_side(app: &mut ViewerApp, ui: &mut Ui, result: &DiffResult) {
    let shape = app.shape;
    let first = app.raster_first_byte();
    let zoom = app.zoom.max(1.0);
    let Some(other) = app.bench.analysis.other.as_mut() else { return };
    let aligned = diff::aligned_offset(&result.ops, first).unwrap_or(first).min(other.len());
    ui.label(RichText::new(format!("Other file at {aligned:#x}, aligned with this view")).small().color(theme::TEXT_DIM));
    let rect = ui.available_rect_before_wrap();
    let rows = ((rect.height() / zoom) as usize).clamp(1, 4096);
    let stride = shape.row_stride();
    let key = (aligned, other.version() as usize ^ (rows << 32) ^ stride);
    let stale = app.bench.analysis.other_texture.as_ref().is_none_or(|t| (t.0, t.1) != key);
    if stale {
        let mut buffer = vec![0u8; stride * rows + 1];
        other.read_into(aligned, &mut buffer);
        let mut pixels = vec![Color32::BLACK; shape.width * rows];
        raster::rasterise(shape.format, shape.palette, &buffer, shape.width, rows, stride, &mut pixels);
        let texture = ui.ctx().load_texture("diff-other", ColorImage::new([shape.width, rows], pixels), TextureOptions::NEAREST);
        app.bench.analysis.other_texture = Some((key.0, key.1, texture));
    }
    let (_, _, texture) = app.bench.analysis.other_texture.as_ref().expect("filled above");
    let size = vec2(shape.width as f32 * zoom, rows as f32 * zoom);
    let (drawn, _) = ui.allocate_exact_size(size.min(rect.size()), Sense::hover());
    let uv = Rect::from_min_max(pos2(0.0, 0.0), pos2((drawn.width() / size.x).min(1.0), (drawn.height() / size.y).min(1.0)));
    ui.painter_at(drawn).image(texture.id(), drawn, uv, Color32::WHITE);
}

// ---------------------------------------------------------------------------
// Pointer graph
// ---------------------------------------------------------------------------

/// Draw arrows from values that look like file offsets to their targets, for
/// the visible part of the raster. `rects_of` maps a byte range to screen
/// rectangles (one per row).
pub fn draw_pointer_graph(app: &mut ViewerApp, painter: &Painter, rects_of: &dyn Fn(usize, usize) -> Vec<Rect>) {
    if !app.bench.analysis.show_pointers || app.document.is_empty() {
        return;
    }
    let start = app.raster_first_byte();
    let visible = app.visible_rows.max(1) * app.shape.row_stride();
    let key = (app.document.version(), start, visible);
    if app.bench.analysis.pointer_cache.as_ref().map(|c| c.0) != Some(key) {
        let window = app.document.read_range(start, visible.min(4 * 1024 * 1024));
        let found = pointers::find_pointers(&window, start, app.document.len(), None, true, 0);
        app.bench.analysis.pointer_cache = Some((key, found));
    }
    let pointers = &app.bench.analysis.pointer_cache.as_ref().expect("filled above").1;
    let colour = Color32::from_rgba_unmultiplied(255, 210, 90, 170);
    for pointer in pointers.iter().take(400) {
        let Some(source) = rects_of(pointer.from, pointer.width).first().copied() else { continue };
        painter.rect_stroke(source, 0.0, Stroke::new(1.0, colour), egui::StrokeKind::Inside);
        match rects_of(pointer.to, 1).first() {
            Some(target) => arrow(painter, source.center(), target.center(), colour),
            None => {
                // Target off screen: a short stub pointing up or down.
                let direction = if pointer.to > pointer.from { 1.0 } else { -1.0 };
                arrow(painter, source.center(), source.center() + vec2(0.0, 14.0 * direction), colour);
            }
        }
    }
}

fn arrow(painter: &Painter, from: Pos2, to: Pos2, colour: Color32) {
    let stroke = Stroke::new(1.2, colour);
    painter.line_segment([from, to], stroke);
    let direction = (to - from).normalized();
    if direction.length() > 0.0 {
        let side = vec2(-direction.y, direction.x) * 3.5;
        let back = to - direction * 7.0;
        painter.line_segment([to, back + side], stroke);
        painter.line_segment([to, back - side], stroke);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::actions::take_performed;
    use crate::app::Launch;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        take_performed();
        app
    }

    /// A record whose last four bytes are the CRC-32 of the rest.
    fn record_with_crc() -> Vec<u8> {
        let mut record = b"some header and a payload worth checking".to_vec();
        let crc = checksums::crc32(&record);
        record.extend(crc.to_le_bytes());
        record
    }

    #[test]
    fn finding_the_checksum_reads_it_through_the_api_and_showing_it_pins_it_and_selects_what_it_covers() {
        let mut app = app_with(&record_with_crc());
        find_stored_checksum(&mut app, 0, 44);
        assert_eq!(take_performed(), [("checksums.find_stored".to_string(), json!({"start": 0, "len": 44, "boundaries": []}))]);
        let found = app.bench.analysis.checksum_matches.clone().expect("listed");
        assert_eq!((found[0].algorithm.as_str(), found[0].value_offset), ("CRC-32", 40));
        show_stored_checksum(&mut app, &found[0]);
        let performed = take_performed();
        assert_eq!(performed[0].0, "findings.publish");
        assert_eq!(performed[0].1["key"], "checksum");
        assert_eq!(performed[0].1["findings"][0]["start"], 40);
        assert_eq!(performed[1], ("selection.set".to_string(), json!({"selection": {"range": [0, 40]}})));
        app.run_bus();
        assert!(app.published_findings().iter().any(|(producer, finding)| *producer == "panel" && finding.id == "checksum"), "outlined on the views");
        assert_eq!(app.selection(), Some((0, 40)));
    }

    #[test]
    fn comparing_with_a_file_is_a_diff_job_whose_differences_are_outlined() {
        let original: Vec<u8> = (0..20_000u32).map(|index| (index * 31 % 251) as u8).collect();
        let mut changed = original.clone();
        changed[5000..5010].copy_from_slice(b"0123456789");
        let other = std::env::temp_dir().join(format!("theviewer-diff-tab-{}.bin", std::process::id()));
        std::fs::write(&other, &changed).unwrap();
        let mut app = app_with(&original);
        start_diff(&mut app, other.clone());
        assert_eq!(take_performed(), [("diff.run".to_string(), json!({"path": other.display().to_string()}))]);
        let receiver = app.bench.analysis.diff_pending.take().expect("the tab waits for the comparison");
        let outcome = receiver.recv_timeout(Duration::from_secs(60)).expect("the comparison finishes");
        std::fs::remove_file(&other).ok();
        let (sender, receiver) = mpsc::channel();
        sender.send(outcome).unwrap();
        app.bench.analysis.diff_pending = Some(receiver);
        poll_diff(&mut app);
        assert!(take_performed().is_empty(), "the outlines are the comparison's, not another step");
        app.run_bus();
        let outlined: Vec<_> = app.published_findings().into_iter().filter(|(_, finding)| finding.id == "diff").map(|(producer, finding)| (producer.to_string(), finding.start)).collect();
        assert_eq!(outlined, [("panel".to_string(), 5000)]);
        assert_eq!(app.status, "19990 bytes equal, 10 differ");
    }

    #[test]
    fn choosing_the_disassembly_architecture_is_a_step_of_the_person_s() {
        let mut app = app_with(&[0x90; 64]);
        assert!(set_disassembly_arch(&mut app, ArchChoice::Fixed(Arch::Arm64)));
        assert_eq!(take_performed(), [("disasm.set_arch".to_string(), json!({"arch": "arm64"}))]);
        assert_eq!(app.bench.analysis.arch, ArchChoice::Fixed(Arch::Arm64));
        assert!(set_disassembly_arch(&mut app, ArchChoice::Auto));
        assert_eq!(app.bench.analysis.arch, ArchChoice::Auto);
    }
}
