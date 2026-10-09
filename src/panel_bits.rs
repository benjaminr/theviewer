//! The "Bits and encodings" panel: bit periods and sync words, bit planes,
//! line-code decoding, number-type guessing for a record field, and length
//! field (TLV) hypotheses.
//!
//! Heavy analyses run on background threads; their results arrive through
//! channels polled each frame.

use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui::{self, Color32, ColorImage, RichText, Sense, TextureHandle, TextureOptions, Ui, vec2};

use crate::app::ViewerApp;
use crate::bits::{self, BitOrder, BitPeriodScan, PlaneScore, SyncPattern};
use crate::linecode::{self, BcdTimestamp, DecodeResult, LineCode};
use crate::numeric::{self, FieldError, RankedInterpretation};
use crate::raster::PixelFormat;
use crate::send_to::{self, Carry, Slot, Target};
use crate::theme;
use crate::tlv::{self, Hypothesis};

/// Bytes scanned for bit periods.
pub(crate) const PERIOD_SCAN_BYTES: usize = bits::MAX_SCAN_BITS / 8;
/// Longest bit period looked for unless the user asks for more.
pub(crate) const DEFAULT_MAX_PERIOD: usize = 1024;
/// Upper limit for the period control.
const LARGEST_MAX_PERIOD: usize = crate::api::tools::bits::MOST_MAX_PERIOD;
/// Fundamental periods for which a sync word is looked for.
const SYNC_CANDIDATES: usize = 5;
/// Bytes split into bit planes.
pub(crate) const PLANE_BYTES: usize = 1024 * 1024;
/// Largest preview texture side, in pixels.
const PREVIEW_MAX_ROWS: usize = 256;
pub(crate) const PREVIEW_MAX_WIDTH: usize = 1024;
/// On-screen size of a plane preview.
const PREVIEW_SIZE: f32 = 96.0;
/// Bytes decoded when looking for a line code.
pub(crate) const LINECODE_BYTES: usize = 64 * 1024;
/// Line-code results listed.
const LINECODE_LISTED: usize = 8;
/// Most records read for the number-type guess.
pub(crate) const NUMBER_RECORDS: usize = 4096;
/// Field widths offered for the number-type guess.
const NUMBER_WIDTHS: [usize; 4] = [1, 2, 4, 8];
/// Default field width for the number-type guess.
const DEFAULT_NUMBER_WIDTH: usize = 4;
/// Pause between repaints while background work is pending.
const PENDING_REPAINT: Duration = Duration::from_millis(100);

/// A bit period scan plus sync words for its strongest fundamentals.
pub struct PeriodsResult {
    /// Document offset the scan started at.
    pub start: usize,
    pub scan: BitPeriodScan,
    pub syncs: Vec<SyncPattern>,
}

/// Bit planes of a range: scores and the planes themselves.
pub struct PlanesResult {
    pub start: usize,
    pub len: usize,
    /// Bytes per row used for scoring and previews.
    pub row_width: usize,
    pub scores: [PlaneScore; 8],
    planes: Vec<Vec<u8>>,
}

/// Line-code decodes of a range, best first, and BCD timestamps in it.
pub struct LineCodeResult {
    pub start: usize,
    pub len: usize,
    pub order: BitOrder,
    pub decodes: Vec<DecodeResult>,
    pub timestamps: Vec<BcdTimestamp>,
}

/// Length field hypotheses for a region.
pub struct LengthFieldsResult {
    pub start: usize,
    pub len: usize,
    pub hypotheses: Vec<Hypothesis>,
}

/// What a number-type guess was computed for, so it is recomputed only on change.
#[derive(Clone, Copy, PartialEq, Eq)]
struct NumberKey {
    version: u64,
    origin: usize,
    stride: usize,
    offset: usize,
    width: usize,
}

/// State of the panel.
#[derive(Default)]
pub struct BitsState {
    pub order: BitOrder,
    /// Longest bit period scanned (0 means the default).
    pub max_period: usize,
    periods_pending: Option<Receiver<PeriodsResult>>,
    pub periods: Option<PeriodsResult>,

    planes_pending: Option<Receiver<PlanesResult>>,
    pub planes: Option<PlanesResult>,
    plane_textures: Vec<TextureHandle>,

    linecode_pending: Option<Receiver<LineCodeResult>>,
    pub linecodes: Option<LineCodeResult>,
    /// Code and offset for a manual decode.
    manual_code: Option<LineCode>,
    manual_offset: usize,
    /// Where the bit offset came from, when it was sent from a result.
    offset_bound: Option<send_to::Bound>,

    /// Field width for the number-type guess (0 means the default).
    pub number_width: usize,
    numbers: Option<(NumberKey, Result<Vec<RankedInterpretation>, FieldError>)>,

    lengths_pending: Option<Receiver<LengthFieldsResult>>,
    pub lengths: Option<LengthFieldsResult>,
}

impl BitsState {
    /// Forget results that described the previous document.
    pub fn document_changed(&mut self) {
        *self = BitsState { order: self.order, max_period: self.max_period, number_width: self.number_width, ..Default::default() };
    }

    fn is_pending(&self) -> bool {
        self.periods_pending.is_some() || self.planes_pending.is_some() || self.linecode_pending.is_some() || self.lengths_pending.is_some()
    }

    /// Collect any finished background results.
    fn poll(&mut self, ctx: &egui::Context) {
        if let Some(result) = self.periods_pending.as_ref().and_then(|receiver| receiver.try_recv().ok()) {
            self.periods = Some(result);
            self.periods_pending = None;
        }
        if let Some(result) = self.planes_pending.as_ref().and_then(|receiver| receiver.try_recv().ok()) {
            self.plane_textures = plane_textures(ctx, &result);
            self.planes = Some(result);
            self.planes_pending = None;
        }
        if let Some(result) = self.linecode_pending.as_ref().and_then(|receiver| receiver.try_recv().ok()) {
            self.linecodes = Some(result);
            self.linecode_pending = None;
        }
        if let Some(result) = self.lengths_pending.as_ref().and_then(|receiver| receiver.try_recv().ok()) {
            self.lengths = Some(result);
            self.lengths_pending = None;
        }
    }
}

/// The selection, else `limit` bytes from the cursor: (start, len, description).
fn selection_or_cursor(app: &ViewerApp, limit: usize) -> (usize, usize, &'static str) {
    match app.selection() {
        Some((start, len)) => (start, len.min(limit), "selection"),
        None => {
            let start = app.cursor.min(app.document.len());
            (start, (app.document.len() - start).min(limit), "from cursor")
        }
    }
}

/// The selection, else the start of the file, capped.
fn selection_or_file(app: &ViewerApp, limit: usize) -> (usize, usize, &'static str) {
    match app.selection() {
        Some((start, len)) => (start, len.min(limit), "selection"),
        None => (0, app.document.len().min(limit), "whole file"),
    }
}

fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text).small().color(theme::TEXT_DIM)
}

/// The latest bit a line code's decode starts at.
const MOST_BIT_OFFSET: u64 = 63;

/// The inputs of the Bits tab a carry can fill: the bit offset a line code
/// is decoded from.
pub fn slots(carry: &Carry) -> Vec<Slot> {
    match carry.as_number() {
        Some((offset, _)) if offset <= MOST_BIT_OFFSET => vec![Slot { label: "Bits · line code bit offset", target: Target::BitsOffset }],
        _ => Vec::new(),
    }
}

/// Decode line codes from the bit offset `carry` holds.
pub(crate) fn fill_offset(state: &mut BitsState, _app: &mut ViewerApp, carry: &Carry) -> Result<String, String> {
    match carry.as_number() {
        Some((offset, anchor)) if offset <= MOST_BIT_OFFSET => {
            state.manual_offset = offset as usize;
            let from = match carry {
                Carry::Value(value) => value.from.clone(),
                _ => carry.summary(),
            };
            state.offset_bound = anchor.map(|anchor| send_to::Bound { anchor, from, shown: offset.to_string() });
            Ok(format!("Line codes are decoded from bit {offset}"))
        }
        _ => Err(send_to::does_not_fit(carry, "a bit offset of 0 to 63")),
    }
}

/// Show the panel.
pub fn show_bits(state: &mut BitsState, app: &mut ViewerApp, ui: &mut Ui) {
    state.poll(ui.ctx());
    if state.is_pending() {
        ui.ctx().request_repaint_after(PENDING_REPAINT);
    }
    ui.horizontal(|ui| {
        ui.label("Bit order");
        for order in BitOrder::ALL {
            ui.selectable_value(&mut state.order, order, order.label());
        }
    });
    egui::ScrollArea::vertical().id_salt("bits-panel").show(ui, |ui| {
        egui::CollapsingHeader::new("Bit periods").default_open(true).show(ui, |ui| show_periods(state, app, ui));
        egui::CollapsingHeader::new("Bit planes").show(ui, |ui| show_planes(state, app, ui));
        egui::CollapsingHeader::new("Line codes").show(ui, |ui| show_linecodes(state, app, ui));
        egui::CollapsingHeader::new("Number types").show(ui, |ui| show_numbers(state, app, ui));
        egui::CollapsingHeader::new("Length fields").show(ui, |ui| show_lengths(state, app, ui));
    });
}

// ---------------------------------------------------------------------------
// Bit periods
// ---------------------------------------------------------------------------

/// Bytes a bit period scan reads to look for periods up to `max_period` bits.
pub(crate) fn period_scan_bytes(max_period: usize) -> usize {
    PERIOD_SCAN_BYTES + max_period / 4
}

/// The person asks for the bit periods of the selection, else from the
/// cursor: `bits.scan_periods`, carried out once the panel is drawn.
fn start_periods(state: &mut BitsState, app: &mut ViewerApp) {
    let max_period = effective_max_period(state);
    let (start, len, _) = selection_or_cursor(app, period_scan_bytes(max_period));
    app.perform_later("bits.scan_periods", serde_json::json!({ "start": start, "len": len, "order": state.order, "max_period": max_period }));
}

/// Scan `bytes` (from document offset `start`) for bit periods and the sync
/// words of the strongest.
pub(crate) fn find_periods(bytes: &[u8], start: usize, order: BitOrder, max_period: usize) -> PeriodsResult {
    let scan = bits::scan_bit_periods(bytes, order, max_period);
    let syncs = scan
        .candidates
        .iter()
        .filter(|candidate| candidate.multiple_of.is_none())
        .take(SYNC_CANDIDATES)
        .filter_map(|candidate| bits::find_sync(bytes, order, candidate.period))
        .collect();
    PeriodsResult { start, scan, syncs }
}

/// Where a job's result for the panel is sent, and where the panel waits for it.
fn awaited<T>(pending: &mut Option<Receiver<T>>) -> mpsc::Sender<T> {
    let (sender, receiver) = mpsc::channel();
    *pending = Some(receiver);
    sender
}

/// Wait for a scan `bits.scan_periods` started; returns where it is sent.
pub(crate) fn await_periods(app: &mut ViewerApp) -> mpsc::Sender<PeriodsResult> {
    awaited(&mut app.bench.panels.bits.periods_pending)
}

/// Wait for planes `bits.planes` split; returns where they are sent.
pub(crate) fn await_planes(app: &mut ViewerApp) -> mpsc::Sender<PlanesResult> {
    awaited(&mut app.bench.panels.bits.planes_pending)
}

/// Wait for decodes `bits.detect_linecode` tried; returns where they are sent.
pub(crate) fn await_linecodes(app: &mut ViewerApp) -> mpsc::Sender<LineCodeResult> {
    awaited(&mut app.bench.panels.bits.linecode_pending)
}

/// Wait for hypotheses `bits.find_length_fields` made; returns where they are sent.
pub(crate) fn await_lengths(app: &mut ViewerApp) -> mpsc::Sender<LengthFieldsResult> {
    awaited(&mut app.bench.panels.bits.lengths_pending)
}

fn effective_max_period(state: &BitsState) -> usize {
    if state.max_period == 0 { DEFAULT_MAX_PERIOD } else { state.max_period }
}

fn show_periods(state: &mut BitsState, app: &mut ViewerApp, ui: &mut Ui) {
    let (_, len, what) = selection_or_cursor(app, PERIOD_SCAN_BYTES);
    ui.horizontal_wrapped(|ui| {
        if ui.button(format!("Find bit periods ({what}, {})", crate::compress::human_bytes(len))).clicked() {
            start_periods(state, app);
        }
        if state.periods_pending.is_some() {
            ui.spinner();
        }
        ui.label("up to");
        let mut max_period = effective_max_period(state);
        if ui.add(egui::DragValue::new(&mut max_period).range(8..=LARGEST_MAX_PERIOD).suffix(" bits")).changed() {
            state.max_period = max_period;
        }
    });
    let Some(result) = &state.periods else {
        ui.label(dim("Compares the data with itself shifted by every bit lag to find frames that are not a whole number of bytes (a 10-bit sample, a 37-bit frame), and the sync word that starts each frame."));
        return;
    };
    if result.scan.candidates.is_empty() {
        ui.label(dim(format!("No bit period stands out in {} bits ({}).", result.scan.bits, result.scan.order.label())));
        return;
    }
    ui.label(dim(format!("{} bits read {}; baseline agreement {:.3}", result.scan.bits, result.scan.order.label(), result.scan.baseline)));
    let mut chosen_width = None;
    let mut align_to = None;
    egui::Grid::new("bit-periods").striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
        for candidate in &result.scan.candidates {
            ui.monospace(RichText::new(format!("{} bits", candidate.period)).color(theme::ACCENT));
            ui.monospace(format!("{:.1}% agree", candidate.agreement * 100.0));
            let note = match (candidate.multiple_of, candidate.byte_aligned()) {
                (Some(base), _) => format!("multiple of {base}"),
                (None, true) => format!("{} bytes", candidate.period / 8),
                (None, false) => "not byte aligned".to_string(),
            };
            ui.label(dim(note));
            if ui.small_button("Use as width").on_hover_text("Show one bit per pixel, this many bits per row").clicked() {
                chosen_width = Some(candidate.period);
            }
            ui.end_row();
        }
    });
    for sync in &result.syncs {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("Sync every {} bits", sync.period)).strong());
            ui.monospace(RichText::new(sync.bits_text()).color(theme::CURSOR));
            ui.label(dim(format!(
                "{} bits at bit offset {}, exact in {:.0}% of {} frames",
                sync.length,
                sync.bit_offset,
                sync.match_fraction * 100.0,
                sync.frames
            )));
            if result.scan.order == BitOrder::MsbFirst && ui.small_button("Align view").on_hover_text("Start the view at the first sync word, one frame per row").clicked() {
                align_to = Some((result.start * 8 + sync.bit_offset, sync.period));
            }
        });
    }
    let order = result.scan.order;
    if let Some(period) = chosen_width {
        use_bit_width(app, order, period, None);
    }
    if let Some((bit, period)) = align_to {
        use_bit_width(app, order, period, Some(bit));
    }
}

/// The person shows the data one bit per pixel, `period` bits per row, and
/// with `first_bit` the view starting there: `view.set_shape`.
fn use_bit_width(app: &mut ViewerApp, order: BitOrder, period: usize, first_bit: Option<usize>) {
    let format = match order {
        BitOrder::MsbFirst => PixelFormat::Bit1Msb,
        BitOrder::LsbFirst => PixelFormat::Bit1Lsb,
    };
    let mut params = serde_json::json!({ "format": format, "width": period.min(crate::app::MAX_WIDTH) });
    if let Some(bit) = first_bit {
        params["offset"] = serde_json::json!(bit / 8);
        params["bit_offset"] = serde_json::json!(bit % 8);
    }
    if app.perform("view.set_shape", params).is_ok() {
        app.status = format!("Width set to {period} bits, one bit per pixel");
    }
}

// ---------------------------------------------------------------------------
// Bit planes
// ---------------------------------------------------------------------------

/// The person asks for the bit planes of the selection, else from the
/// cursor, scored with the view's row width: `bits.planes`.
fn start_planes(app: &mut ViewerApp) {
    let (start, len, _) = selection_or_cursor(app, PLANE_BYTES);
    let row_width = app.shape.row_stride().clamp(1, PREVIEW_MAX_WIDTH);
    app.perform_later("bits.planes", serde_json::json!({ "start": start, "len": len, "row_width": row_width }));
}

/// Split `bytes` (from document offset `start`) into bit planes, scored
/// with rows of `row_width` bytes.
pub(crate) fn split_planes(bytes: &[u8], start: usize, row_width: usize) -> PlanesResult {
    let scores = bits::plane_scores(bytes, row_width);
    let planes = (0..8).map(|bit| bits::bit_plane(bytes, bit)).collect();
    PlanesResult { start, len: bytes.len(), row_width, scores, planes }
}

/// One preview texture per plane, `row_width` pixels wide, top rows only.
fn plane_textures(ctx: &egui::Context, result: &PlanesResult) -> Vec<TextureHandle> {
    let width = result.row_width.max(1);
    let rows = (result.len / width).clamp(1, PREVIEW_MAX_ROWS);
    result
        .planes
        .iter()
        .enumerate()
        .map(|(bit, plane)| {
            let pixels: Vec<Color32> = (0..width * rows).map(|index| Color32::from_gray(plane.get(index).copied().unwrap_or(0))).collect();
            ctx.load_texture(format!("bit-plane-{bit}"), ColorImage::new([width, rows], pixels), TextureOptions::NEAREST)
        })
        .collect()
}

fn show_planes(state: &mut BitsState, app: &mut ViewerApp, ui: &mut Ui) {
    let (_, len, what) = selection_or_cursor(app, PLANE_BYTES);
    ui.horizontal(|ui| {
        if ui.button(format!("Split into bit planes ({what}, {})", crate::compress::human_bytes(len))).clicked() {
            start_planes(app);
        }
        if state.planes_pending.is_some() {
            ui.spinner();
        }
    });
    let Some(result) = &state.planes else {
        ui.label(dim("Shows bit k of every byte as its own image and scores how much shape each plane holds, to spot data hidden in low bits or flags packed into high bits. Click a plane to open it."));
        return;
    };
    ui.label(dim(format!("{} bytes from {:#x}, {} per row; structure is what the left and upper neighbours tell about a bit", result.len, result.start, result.row_width)));
    let mut open = None;
    ui.horizontal_wrapped(|ui| {
        for bit in (0..8).rev() {
            let score = &result.scores[bit];
            ui.vertical(|ui| {
                if let Some(texture) = state.plane_textures.get(bit) {
                    let size = texture.size_vec2();
                    let scale = PREVIEW_SIZE / size.x.max(size.y).max(1.0);
                    let response = ui.add(egui::Image::new((texture.id(), size * scale)).sense(Sense::click()));
                    if response.on_hover_text("Open this plane as a document").clicked() {
                        open = Some(bit);
                    }
                } else {
                    ui.allocate_space(vec2(PREVIEW_SIZE, PREVIEW_SIZE));
                }
                let colour = if score.verdict() == "structured" { theme::ACCENT } else { theme::TEXT_DIM };
                ui.label(RichText::new(format!("bit {bit} · {}", score.verdict())).small().color(colour));
                ui.label(dim(format!("{:.0}% set · {:.3}", score.ones_fraction * 100.0, score.structure)));
            });
        }
    });
    if let Some(bit) = open {
        open_plane(app, result.start, result.len, bit, result.row_width);
    }
}

/// The person opens bit plane `bit` of the bytes split as a document
/// (`bits.open_plane`), shown with the rows it was scored with
/// (`view.set_shape`).
fn open_plane(app: &mut ViewerApp, start: usize, len: usize, bit: usize, row_width: usize) {
    if app.perform("bits.open_plane", serde_json::json!({ "start": start, "len": len, "bit": bit })).is_ok() {
        let _ = app.perform("view.set_shape", serde_json::json!({ "width": row_width }));
    }
}

// ---------------------------------------------------------------------------
// Line codes
// ---------------------------------------------------------------------------

/// The person asks which line code the selection, else the bytes from the
/// cursor, is in: `bits.detect_linecode`.
fn start_linecodes(state: &mut BitsState, app: &mut ViewerApp) {
    let (start, len, _) = selection_or_cursor(app, LINECODE_BYTES);
    app.perform_later("bits.detect_linecode", serde_json::json!({ "start": start, "len": len, "order": state.order }));
}

/// Try every line code on `bytes` (from document offset `start`).
pub(crate) fn detect_linecodes(bytes: &[u8], start: usize, order: BitOrder) -> LineCodeResult {
    let mut decodes = linecode::auto_detect(bytes, order);
    decodes.truncate(LINECODE_LISTED);
    let timestamps = linecode::find_bcd_timestamps(bytes);
    LineCodeResult { start, len: bytes.len(), order, decodes, timestamps }
}

/// The person opens a line-code decode as a document: `bits.decode_linecode`.
fn open_decoded(app: &mut ViewerApp, (start, len): (usize, usize), order: BitOrder, code: LineCode, bit_offset: usize, derived_from: crate::journal::DerivedFrom) {
    let code = crate::api::tools::bits::LineCodeName::of(code);
    let params = serde_json::json!({ "start": start, "len": len, "order": order, "code": code, "bit_offset": bit_offset });
    let _ = app.perform_derived("bits.decode_linecode", params, derived_from);
}

/// A line code decode the person asked for: the span, bit order, code, bit
/// offset and where the offset came from.
type Decoding = ((usize, usize), BitOrder, LineCode, usize, crate::journal::DerivedFrom);

fn show_linecodes(state: &mut BitsState, app: &mut ViewerApp, ui: &mut Ui) {
    let (start, len, what) = selection_or_cursor(app, LINECODE_BYTES);
    ui.horizontal(|ui| {
        if ui.button(format!("Detect line code ({what}, {})", crate::compress::human_bytes(len))).clicked() {
            start_linecodes(state, app);
        }
        if state.linecode_pending.is_some() {
            ui.spinner();
        }
    });
    let mut open: Option<Decoding> = None;
    ui.horizontal_wrapped(|ui| {
        ui.label("Decode as");
        let selected = state.manual_code.unwrap_or(LineCode::Nrzi);
        egui::ComboBox::from_id_salt("manual-line-code").selected_text(selected.label()).show_ui(ui, |ui| {
            for code in LineCode::ALL {
                if ui.selectable_label(selected == code, code.label()).clicked() {
                    state.manual_code = Some(code);
                }
            }
        });
        ui.label("from bit");
        match &state.offset_bound {
            Some(bound) => {
                let mut unbind = false;
                egui::Frame::new().fill(theme::SURFACE_RAISED).stroke(egui::Stroke::new(1.0, theme::ACCENT)).corner_radius(8.0).inner_margin(egui::Margin::symmetric(6, 1)).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        ui.monospace(&bound.shown).on_hover_text(format!("from {}", bound.anchor.describe()));
                        ui.label(RichText::new(format!("· {}", bound.from)).small().color(theme::ACCENT));
                        unbind = ui.add(egui::Button::new(RichText::new("×").color(theme::ACCENT)).frame(false)).on_hover_text("Unbind: keep the bit offset, not where it came from").clicked();
                    });
                });
                if unbind {
                    state.offset_bound = None;
                }
            }
            None => {
                ui.add(egui::DragValue::new(&mut state.manual_offset).range(0..=63));
            }
        }
        if ui.button("Open decoded").clicked() {
            open = Some(((start, len), state.order, selected, state.manual_offset, send_to::Bound::at(&state.offset_bound, "bit_offset")));
        }
    });
    if let Some(result) = &state.linecodes {
        ui.label(dim(format!("{} bytes from {:#x}, {}; lowest error rate first", result.len, result.start, result.order.label())));
        egui::Grid::new("line-codes").striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
            for decode in &result.decodes {
                ui.label(RichText::new(decode.code.label()).strong());
                ui.monospace(format!("bit {}", decode.bit_offset));
                let colour = if decode.error_rate() < 0.01 { theme::ACCENT } else { theme::TEXT_DIM };
                ui.monospace(RichText::new(format!("{:.1}% errors", decode.error_rate() * 100.0)).color(colour));
                let mut extra = format!("{} symbols → {} bytes", decode.symbols, decode.bytes.len());
                if decode.code == LineCode::EightBTenB {
                    extra.push_str(&format!(", {} control, {} commas", decode.control_symbols, decode.commas.len()));
                }
                ui.label(dim(extra));
                if ui.small_button("Open decoded").clicked() {
                    open = Some(((result.start, result.len), result.order, decode.code, decode.bit_offset, crate::journal::DerivedFrom::new()));
                }
                ui.end_row();
            }
        });
        if !result.timestamps.is_empty() {
            let shown: Vec<String> = result.timestamps.iter().take(6).map(|stamp| format!("{} at {:#x}", stamp.text, result.start + stamp.offset)).collect();
            ui.label(dim(format!("{} BCD timestamps (YYMMDDhhmmss): {}", result.timestamps.len(), shown.join(", "))));
        }
    } else {
        ui.label(dim("Tries Manchester (both conventions), differential Manchester, 8b/10b and packed BCD at every bit alignment and ranks them by invalid symbols. NRZI and Gray code cannot be checked, so decode them by hand."));
    }
    if let Some((span, order, code, bit_offset, derived_from)) = open {
        open_decoded(app, span, order, code, bit_offset, derived_from);
    }
}

// ---------------------------------------------------------------------------
// Number types
// ---------------------------------------------------------------------------

fn show_numbers(state: &mut BitsState, app: &mut ViewerApp, ui: &mut Ui) {
    if state.number_width == 0 {
        state.number_width = DEFAULT_NUMBER_WIDTH;
    }
    let origin = app.shape.byte_offset;
    let stride = app.shape.row_stride().max(1);
    if app.cursor < origin {
        ui.label(dim("Put the cursor inside the records (after the view origin)."));
        return;
    }
    let offset = (app.cursor - origin) % stride;
    ui.horizontal(|ui| {
        ui.label("Field width");
        for width in NUMBER_WIDTHS {
            ui.selectable_value(&mut state.number_width, width, format!("{width} B"));
        }
        ui.label(dim(format!("at +{offset} of {stride}-byte records from {origin:#x}")));
    });
    let key = NumberKey { version: app.document.version(), origin, stride, offset, width: state.number_width };
    if state.numbers.as_ref().map(|(cached, _)| *cached) != Some(key) {
        let records = app.document.read_range(origin, stride.saturating_mul(NUMBER_RECORDS));
        state.numbers = Some((key, numeric::rank_field(&records, stride, offset, key.width)));
    }
    let Some((_, ranked)) = &state.numbers else { return };
    match ranked {
        Err(error) => {
            ui.label(RichText::new(error.to_string()).color(theme::DANGER));
        }
        Ok(ranked) => {
            egui::Grid::new("number-types").striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
                for entry in ranked {
                    let colour = if entry.score >= 0.85 { theme::ACCENT } else { theme::TEXT };
                    ui.label(RichText::new(entry.interpretation.label()).color(colour));
                    ui.monospace(format!("{:.2}", entry.score));
                    ui.monospace(RichText::new(entry.samples.join(", ")).small());
                    ui.label(dim(&entry.reason));
                    ui.end_row();
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Length fields
// ---------------------------------------------------------------------------

/// The person asks for the length fields of the selection, else the start
/// of the file: `bits.find_length_fields`.
fn start_lengths(app: &mut ViewerApp) {
    let (start, len, _) = selection_or_file(app, tlv::MAX_REGION);
    app.perform_later("bits.find_length_fields", serde_json::json!({ "start": start, "len": len }));
}

/// Find the length fields that explain `bytes` (from document offset `start`).
pub(crate) fn find_lengths(bytes: &[u8], start: usize) -> LengthFieldsResult {
    LengthFieldsResult { start, len: bytes.len(), hypotheses: tlv::analyse(bytes, start) }
}

fn show_lengths(state: &mut BitsState, app: &mut ViewerApp, ui: &mut Ui) {
    let (_, len, what) = selection_or_file(app, tlv::MAX_REGION);
    ui.horizontal(|ui| {
        if ui.button(format!("Find length fields ({what}, {})", crate::compress::human_bytes(len))).clicked() {
            start_lengths(app);
        }
        if state.lengths_pending.is_some() {
            ui.spinner();
        }
    });
    let Some(result) = &state.lengths else {
        ui.label(dim("Finds numbers that are distances: length prefixes counting the rest of a message, chains of tag-length-value records that walk the region exactly, and tables of offsets pointing at later structures. Select one message or a run of records first."));
        return;
    };
    if result.hypotheses.is_empty() {
        ui.label(dim("No length field explains this region."));
        return;
    }
    let mut chosen = None;
    egui::Grid::new("length-fields").striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
        for hypothesis in &result.hypotheses {
            let coverage = hypothesis.coverage(result.len);
            let colour = if coverage > 0.99 { theme::ACCENT } else { theme::TEXT_DIM };
            ui.monospace(format!("{:.2}", hypothesis.score(result.len)));
            ui.monospace(RichText::new(format!("{:>3.0}%", coverage * 100.0)).color(colour));
            if ui.add(egui::Label::new(hypothesis.describe()).sense(Sense::click())).on_hover_text("Select what this explains").clicked() {
                let (start, span) = hypothesis.span(result.len);
                chosen = Some((result.start + start, span));
            }
            ui.add(egui::Label::new(RichText::new(hypothesis.example()).monospace().small().color(theme::TEXT_DIM)).truncate());
            ui.end_row();
        }
    });
    if let Some((start, span)) = chosen {
        app.select_found(start, span);
    }
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn a_bit_offset_sent_from_a_result_is_bound_and_the_decode_journals_where_it_came_from() {
        let mut app = app_with(&[0x55u8; 64]);
        let carry = Carry::variable("phase", &json!(3), app.document_id());
        send_to::send(&mut app, Target::BitsOffset, &carry).unwrap();
        let state = &app.bench.panels.bits;
        assert_eq!((state.manual_offset, state.offset_bound.is_some()), (3, true));
        let derived_from = send_to::Bound::at(&state.offset_bound, "bit_offset");
        open_decoded(&mut app, (0, 64), BitOrder::MsbFirst, LineCode::Nrzi, 3, derived_from);
        let entry = app.journal.entries().rev().find(|entry| entry.method == "bits.decode_linecode").expect("the decode is a step");
        assert_eq!(entry.derived_from.get("bit_offset"), Some(&crate::journal::anchors::Anchor::Var { var: "phase".into() }));
    }

    #[test]
    fn each_search_is_a_job_with_its_span_and_options_carried_out_once_the_panel_is_drawn() {
        let mut app = app_with(&[0x55u8; 4096]);
        app.restore_selection(16, 1024);
        let mut state = BitsState { order: BitOrder::LsbFirst, max_period: 64, ..Default::default() };
        start_periods(&mut state, &mut app);
        start_planes(&mut app);
        start_linecodes(&mut state, &mut app);
        start_lengths(&mut app);
        assert!(take_performed().is_empty(), "nothing while the panel is drawn");
        app.perform_waiting_actions();
        let row_width = app.shape.row_stride().clamp(1, PREVIEW_MAX_WIDTH);
        assert_eq!(
            take_performed(),
            [
                ("bits.scan_periods".to_string(), json!({"start": 16, "len": 1024, "order": "lsb", "max_period": 64})),
                ("bits.planes".to_string(), json!({"start": 16, "len": 1024, "row_width": row_width})),
                ("bits.detect_linecode".to_string(), json!({"start": 16, "len": 1024, "order": "lsb"})),
                ("bits.find_length_fields".to_string(), json!({"start": 16, "len": 1024})),
            ]
        );
        let bits = &app.bench.panels.bits;
        assert!(bits.periods_pending.is_some() && bits.planes_pending.is_some() && bits.linecode_pending.is_some() && bits.lengths_pending.is_some());
        let periods = bits.periods_pending.as_ref().unwrap().recv_timeout(std::time::Duration::from_secs(60)).expect("the scan finishes");
        assert_eq!((periods.start, periods.scan.order), (16, BitOrder::LsbFirst));
    }

    #[test]
    fn using_a_bit_period_as_the_width_or_aligning_to_a_sync_word_is_a_view_shape_step() {
        let mut app = app_with(&[0u8; 4096]);
        use_bit_width(&mut app, BitOrder::MsbFirst, 37, None);
        use_bit_width(&mut app, BitOrder::LsbFirst, 40, Some(8 * 3 + 5));
        assert_eq!(
            take_performed(),
            [
                ("view.set_shape".to_string(), json!({"format": "bit1", "width": 37})),
                ("view.set_shape".to_string(), json!({"format": "bit1lsb", "width": 40, "offset": 3, "bit_offset": 5})),
            ]
        );
        assert_eq!((app.shape.format, app.shape.width, app.shape.byte_offset, app.shape.bit_offset), (PixelFormat::Bit1Lsb, 40, 3, 5));
        assert_eq!(app.status, "Width set to 40 bits, one bit per pixel");
    }

    #[test]
    fn opening_a_plane_or_a_decode_makes_a_derived_document_through_the_api() {
        let mut app = app_with(&[0x81u8; 256]);
        open_plane(&mut app, 0, 64, 7, 8);
        assert_eq!(take_performed(), [("bits.open_plane".to_string(), json!({"start": 0, "len": 64, "bit": 7})), ("view.set_shape".to_string(), json!({"width": 8}))]);
        assert_eq!((app.display_name().as_str(), app.document.len(), app.shape.width), ("test.bin › bit plane 7@0x0", 64, 8));
        let mut app = app_with(&[0x81u8; 256]);
        open_decoded(&mut app, (0, 256), BitOrder::MsbFirst, LineCode::Nrzi, 2, crate::journal::DerivedFrom::new());
        assert_eq!(take_performed(), [("bits.decode_linecode".to_string(), json!({"start": 0, "len": 256, "order": "msb", "code": "nrzi", "bit_offset": 2}))]);
        assert_eq!(app.display_name(), format!("test.bin › {}+2@0x0", LineCode::Nrzi.label()));
    }
}
