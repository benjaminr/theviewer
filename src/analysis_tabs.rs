//! Dock tabs for disassembly, checksums and diff, and the pointer graph drawn
//! over the raster.

use std::sync::mpsc::{self, Receiver};
use std::thread;

use eframe::egui::{self, Color32, ColorImage, Painter, Pos2, Rect, RichText, Sense, Stroke, TextureHandle, TextureOptions, Ui, pos2, vec2};

use crate::app::ViewerApp;
use crate::checksums::{self, ChecksumMatch, Digests};
use crate::diff::{self, DiffLimits, DiffOp, DiffResult};
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
/// Largest in-memory copy made when the open document has unsaved edits.
const DIFF_COPY_LIMIT: usize = 512 * 1024 * 1024;
/// Differences listed in the diff tab.
const MAX_LISTED_OPS: usize = 2000;

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
    pub checksum_matches: Option<Vec<ChecksumMatch>>,

    pub diff_other: Option<String>,
    diff_pending: Option<Receiver<Result<(Document, DiffResult), String>>>,
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
        egui::ComboBox::from_id_salt("disasm-arch").selected_text(label).show_ui(ui, |ui| {
            ui.selectable_value(&mut app.bench.analysis.arch, ArchChoice::Auto, "Auto");
            for arch in Arch::ALL {
                ui.selectable_value(&mut app.bench.analysis.arch, ArchChoice::Fixed(arch), arch.label());
            }
        });
        match &header_arch {
            Some((arch, entry, why)) => {
                ui.label(RichText::new(format!("{} from the header ({why})", arch.label())).small().color(theme::TEXT_DIM));
                if let Some(offset) = map.as_ref().and_then(|m| m.offset_of(*entry))
                    && ui.button(format!("Entry point {entry:#x}")).clicked()
                {
                    app.jump_to_offset(offset);
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
        app.jump_to_offset(offset);
    }
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
            let bytes = app.document.read_range(start, len);
            let boundaries: Vec<usize> = app
                .patterns_in(start, start + len)
                .filter(|f| !f.weak())
                .flat_map(|f| [f.start.saturating_sub(start), f.end().saturating_sub(start)])
                .filter(|&b| b > 0 && b < len)
                .collect();
            app.bench.analysis.checksum_matches = Some(checksums::find_checksums(&bytes, start, &[], &boundaries));
            app.note_tool_result(crate::dock::DockTab::Checksums);
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
            ui.label(RichText::new(found.algorithm).strong().color(theme::ACCENT));
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
        app.bench.pinned.retain(|f| f.id != "checksum");
        app.bench.pinned.push(
            Finding::new("checksum", "checksums", Category::Structure, found.value_offset, found.value_len)
                .title(format!("{} checksum", found.algorithm))
                .detail(format!("covers {:#x}..{:#x}", found.covered_start, found.covered_start + found.covered_len)),
        );
        app.anchor = Some(found.covered_start);
        app.cursor = found.covered_start + found.covered_len;
        app.reveal_cursor_centred();
        app.reveal_cursor_in_hex(true);
    }
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/// Compare the open document with another file on a background thread.
pub fn start_diff(app: &mut ViewerApp, other_path: std::path::PathBuf) {
    app.note_tool_result(crate::dock::DockTab::Diff);
    let own = match app.document.path().filter(|_| !app.document.is_modified()).map(|p| p.to_path_buf()) {
        Some(path) => DiffSide::Path(path),
        None => DiffSide::Bytes(app.document.read_range(0, DIFF_COPY_LIMIT)),
    };
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = (|| {
            let mut a = match own {
                DiffSide::Path(path) => Document::open(&path).map_err(|e| format!("{e:#}"))?,
                DiffSide::Bytes(bytes) => Document::from_bytes(bytes),
            };
            let mut b = Document::open(&other_path).map_err(|e| format!("{e:#}"))?;
            let result = diff::diff(&mut a, &mut b, DiffLimits::default());
            Ok((b, result))
        })();
        let _ = sender.send(result);
    });
    app.bench.analysis.diff_pending = Some(receiver);
    app.bench.analysis.diff = None;
}

enum DiffSide {
    Path(std::path::PathBuf),
    Bytes(Vec<u8>),
}

fn poll_diff(app: &mut ViewerApp) {
    let Some(receiver) = &app.bench.analysis.diff_pending else { return };
    match receiver.try_recv() {
        Ok(Ok((other, result))) => {
            app.bench.pinned.retain(|f| f.id != "diff");
            for op in result.ops.iter().take(5000) {
                let (start, len, label) = match *op {
                    DiffOp::Replace { a, a_len, .. } => (a, a_len, "Differs"),
                    DiffOp::Delete { a, len } => (a, len, "Only in this file"),
                    DiffOp::Insert { .. } | DiffOp::Equal { .. } => continue,
                };
                app.bench.pinned.push(Finding::new("diff", "diff", Category::Custom, start, len.max(1)).title(label).detail(format!("{len} bytes")));
            }
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
        app.jump_to_offset(offset);
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
