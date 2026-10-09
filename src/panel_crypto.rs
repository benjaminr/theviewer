//! The crypto and obfuscation panel: repeated-block (ECB) detection, keys and
//! certificates, attacks on simple ciphers beyond plain XOR, and AES
//! decryption with a key found or typed.
//!
//! Every search runs on a background thread; results remember which sheet
//! they came from and are kept for it, shown again when it is.

use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui::{self, Color32, RichText, Sense, Ui, vec2};

use crate::app::ViewerApp;
use crate::block_cipher::{Algorithm, Mode, Padding};
use crate::blocks::{self, BlockReport};
use crate::ciphers::{self, CipherCandidate, KeyFragment};
use crate::keys::{self, KeyFinding, KeyFormat, KeyKind};
use crate::plugin::{Category, Finding};
use crate::selection_ops::Operation;
use crate::journal::anchors::{Anchor, Pick, StepRef};
use crate::journal::DerivedFrom;
use crate::send_to::{self, Carried, Carry, Slot, Target};
use crate::sheets::PerSheet;
use crate::theme;

/// Largest selection decoded by the cipher attacks.
const DECODE_LIMIT: usize = crate::api::tools::crypto::ATTACK_LIMIT;
/// Bytes from the cursor decoded when nothing is selected.
const CURSOR_WINDOW: usize = 64 * 1024;
/// How often the panel looks for finished background work.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Height of the repeat-map strip.
const STRIP_HEIGHT: f32 = 18.0;
/// Widest a key finding's description may be before it is truncated (points).
const KEY_DETAIL_WIDTH: f32 = 520.0;

/// A background job, the result it delivers, and the sheet it searches.
struct Job<T> {
    receiver: Receiver<T>,
    sheet: String,
    /// The step that started it.
    step: Option<u64>,
}

/// Cipher candidates for the range `start..start + len`.
pub(crate) struct DecodeResults {
    pub start: usize,
    pub len: usize,
    pub candidates: Vec<CipherCandidate>,
    /// With a crib: the key bytes it reveals, whether or not they decode.
    pub fragments: Vec<KeyFragment>,
    /// The `crypto.attack` step that proposed them, which a candidate
    /// carried elsewhere is picked from.
    pub step: Option<u64>,
}

/// State of the crypto panel, kept between frames.
#[derive(Default)]
pub struct CryptoState {
    blocks_job: Option<Job<BlockReport>>,
    blocks: PerSheet<BlockReport>,
    keys_job: Option<Job<Vec<KeyFinding>>>,
    keys: PerSheet<Vec<KeyFinding>>,
    decode_job: Option<Job<DecodeResults>>,
    decode: PerSheet<DecodeResults>,
    /// Known plaintext for crib dragging, with `\xHH` escapes.
    crib: String,
    crib_error: Option<String>,
    decrypt: DecryptForm,
}

/// The AES decryption's settings, as typed.
struct DecryptForm {
    /// The key as hex, typed or filled from a key found.
    key: String,
    /// The IV (CBC) or initial counter block (CTR) as hex.
    iv: String,
    mode: Mode,
    padding: Padding,
    /// Why the last decryption could not be done.
    error: Option<String>,
}

impl Default for DecryptForm {
    fn default() -> Self {
        DecryptForm { key: String::new(), iv: String::new(), mode: Mode::Ecb, padding: Mode::Ecb.usual_padding(), error: None }
    }
}

impl CryptoState {
    /// Sheet `to` is shown: its results are shown again.
    pub fn sheet_switched(&mut self, to: &str) {
        self.blocks.switched(to);
        self.keys.switched(to);
        self.decode.switched(to);
    }

    /// Sheet `id` closed, or has new bytes: its results go.
    pub fn sheet_closed(&mut self, id: &str) {
        self.blocks.closed(id);
        self.keys.closed(id);
        self.decode.closed(id);
    }
}

/// Draw the crypto panel.
pub fn show_crypto(state: &mut CryptoState, app: &mut ViewerApp, ui: &mut egui::Ui) {
    let active = app.document_id();
    collect_finished(state, &active);
    state.sheet_switched(&active);
    if state.blocks_job.is_some() || state.keys_job.is_some() || state.decode_job.is_some() {
        ui.ctx().request_repaint_after(POLL_INTERVAL);
    }
    egui::ScrollArea::vertical().id_salt("crypto-panel").show(ui, |ui| {
        egui::CollapsingHeader::new(RichText::new("Repeated blocks").strong()).default_open(true).show(ui, |ui| show_blocks(state, app, ui));
        egui::CollapsingHeader::new(RichText::new("Keys and certificates").strong()).default_open(true).show(ui, |ui| show_keys(state, app, ui));
        egui::CollapsingHeader::new(RichText::new("Decode").strong()).default_open(true).show(ui, |ui| show_decode(state, app, ui));
        egui::CollapsingHeader::new(RichText::new("Decrypt (AES)").strong()).default_open(true).show(ui, |ui| show_decrypt(state, app, ui));
    });
}

/// A job of the sheet shown, and where its result is to be sent.
fn awaited<T>(app: &ViewerApp) -> (Job<T>, mpsc::Sender<T>) {
    let (sender, receiver) = mpsc::channel();
    (Job { receiver, sheet: app.document_id(), step: app.journal.step_being_recorded() }, sender)
}

/// Wait for a search `crypto.repeated_blocks` started; returns where its report is sent.
pub(crate) fn await_blocks(app: &mut ViewerApp) -> mpsc::Sender<BlockReport> {
    let (job, sender) = awaited(app);
    app.bench.panels.crypto.blocks_job = Some(job);
    sender
}

/// Wait for a search `crypto.find_keys` started; returns where its findings are sent.
pub(crate) fn await_keys(app: &mut ViewerApp) -> mpsc::Sender<Vec<KeyFinding>> {
    let (job, sender) = awaited(app);
    app.bench.panels.crypto.keys_job = Some(job);
    sender
}

/// Wait for attacks `crypto.attack` started; returns where the decodes are sent.
pub(crate) fn await_decode(app: &mut ViewerApp) -> mpsc::Sender<DecodeResults> {
    let (job, sender) = awaited(app);
    app.bench.panels.crypto.decode_job = Some(job);
    sender
}

/// Move a finished job's result into `done`, kept for the sheet it
/// searched, while `active` is shown.
fn poll<T>(job: &mut Option<Job<T>>, done: &mut PerSheet<T>, active: &str) {
    if let Some(pending) = job
        && let Ok(value) = pending.receiver.try_recv()
    {
        done.deliver(&pending.sheet, value, active);
        *job = None;
    }
}

fn collect_finished(state: &mut CryptoState, active: &str) {
    poll(&mut state.blocks_job, &mut state.blocks, active);
    poll(&mut state.keys_job, &mut state.keys, active);
    if let Some(pending) = &state.decode_job
        && let Ok(mut results) = pending.receiver.try_recv()
    {
        results.step = pending.step;
        state.decode.deliver(&pending.sheet, results, active);
        state.decode_job = None;
    }
}

fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).small().color(theme::TEXT_DIM)
}

// ---------------------------------------------------------------------------
// Repeated blocks
// ---------------------------------------------------------------------------

/// The selection, else the whole file, capped at `limit`.
fn selection_or_file(app: &ViewerApp, limit: usize) -> (usize, usize, &'static str) {
    match app.selection() {
        Some((start, len)) => (start, len.min(limit), "selection"),
        None => (0, app.document.len().min(limit), "whole file"),
    }
}

fn show_blocks(state: &mut CryptoState, app: &mut ViewerApp, ui: &mut Ui) {
    let (start, len, what) = selection_or_file(app, blocks::MAX_ANALYSED_BYTES);
    ui.horizontal(|ui| {
        let busy = state.blocks_job.is_some();
        if ui.add_enabled(!busy && len > 0, egui::Button::new(format!("Look for repeated blocks in {what} ({})", crate::compress::human_bytes(len)))).clicked() {
            app.perform_later("crypto.repeated_blocks", serde_json::json!({ "start": start, "len": len }));
        }
        if busy {
            ui.spinner();
        }
    });
    let Some((sheet, report)) = state.blocks.shown() else {
        ui.label(dim("Counts 8- and 16-byte blocks that look random yet repeat: the mark of ECB-mode encryption. CBC, CTR, stream ciphers and compression leave no repeats."));
        return;
    };
    let sheet = sheet.to_string();
    crate::sheets::view::results_of_other_sheet(app, ui, &sheet);
    let verdict_colour = match report.verdict {
        blocks::BlockVerdict::LikelyEcb { .. } => theme::CURSOR,
        _ => theme::ACCENT,
    };
    ui.label(RichText::new(report.verdict.label()).color(verdict_colour));
    let best = report.best;
    ui.label(dim(format!(
        "{} of {} high-entropy {}-byte blocks repeat ({:.1}%), alignment {} · {} analysed from {:#x}",
        best.repeated_blocks,
        best.eligible_blocks,
        best.block_size,
        best.repeat_ratio() * 100.0,
        best.alignment,
        crate::compress::human_bytes(report.analysed_len),
        report.start
    )));
    let mut jump = draw_repeat_strip(ui, report);
    ui.horizontal(|ui| {
        theme::swatch(ui, theme::BACKGROUND, "low entropy");
        theme::swatch(ui, theme::SURFACE_RAISED, "no repeats");
        theme::swatch(ui, theme::CURSOR, "repeats");
    });
    if !report.top_repeats.is_empty() {
        ui.label(RichText::new("Most repeated blocks").strong());
        for repeat in &report.top_repeats {
            ui.horizontal(|ui| {
                ui.monospace(RichText::new(format!("{:>5}×", repeat.count)).color(theme::ACCENT));
                ui.monospace(keys::short_hex(&repeat.bytes, repeat.bytes.len()));
                for &offset in repeat.offsets.iter().take(4) {
                    if ui.small_button(format!("{offset:#x}")).clicked() {
                        jump = Some(offset);
                    }
                }
                if repeat.offsets.len() > 4 {
                    ui.label(dim("…"));
                }
            });
        }
    }
    if let Some(offset) = jump {
        app.jump_found_in(&sheet, offset);
    }
}

fn strip_colour(ratio: Option<f32>) -> Color32 {
    match ratio {
        None => theme::BACKGROUND,
        Some(ratio) if ratio <= 0.0 => theme::SURFACE_RAISED,
        Some(ratio) => theme::ACCENT_DIM.lerp_to_gamma(theme::CURSOR, ratio.clamp(0.0, 1.0)),
    }
}

/// Draw the repeat map; returns the offset clicked, if any.
fn draw_repeat_strip(ui: &mut Ui, report: &BlockReport) -> Option<usize> {
    let width = ui.available_width().max(1.0);
    let (rect, response) = ui.allocate_exact_size(vec2(width, STRIP_HEIGHT), Sense::click());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 2.0, theme::BACKGROUND);
    let count = report.regions.len().max(1) as f32;
    for (index, region) in report.regions.iter().enumerate() {
        let left = rect.left() + rect.width() * index as f32 / count;
        let right = rect.left() + rect.width() * (index + 1) as f32 / count;
        let cell = egui::Rect::from_min_max(egui::pos2(left, rect.top()), egui::pos2(right.max(left + 1.0), rect.bottom()));
        painter.rect_filled(cell, 0.0, strip_colour(region.repeat_ratio()));
    }
    let region_under = |x: f32| {
        let index = ((x - rect.left()) / rect.width() * count) as usize;
        report.regions.get(index.min(report.regions.len().saturating_sub(1)))
    };
    let hovered = response.hover_pos().and_then(|pointer| region_under(pointer.x)).copied();
    let clicked = response.interact_pointer_pos().filter(|_| response.clicked()).and_then(|pointer| region_under(pointer.x)).map(|region| region.offset);
    if let Some(region) = hovered {
        let text = match region.repeat_ratio() {
            Some(ratio) => format!("{:#x}: {} of {} high-entropy blocks repeat ({:.0}%); click to jump", region.offset, region.repeated_blocks, region.eligible_blocks, ratio * 100.0),
            None => format!("{:#x}: no high-entropy blocks", region.offset),
        };
        response.on_hover_text(text);
    }
    clicked
}

// ---------------------------------------------------------------------------
// Keys and certificates
// ---------------------------------------------------------------------------

fn kind_colour(kind: KeyKind) -> Color32 {
    match kind {
        KeyKind::PrivateKey => theme::DANGER,
        KeyKind::Certificate => theme::ACCENT,
        KeyKind::PublicKey => theme::CLASS_TEXT,
        KeyKind::OtherPem => theme::TEXT,
        KeyKind::RawKeyCandidate => theme::CURSOR,
    }
}

/// A finding for `app.select_finding`, so selection behaves as in Findings.
fn as_finding(key: &KeyFinding) -> Finding {
    let category = match key.format {
        KeyFormat::Pem | KeyFormat::OpenSsh => Category::Encoding,
        KeyFormat::Der => Category::Structure,
        KeyFormat::Raw => Category::HighEntropy,
    };
    Finding::new(format!("crypto:{}", key.kind.label()), "panel_crypto", category, key.offset, key.len)
        .title(format!("{} ({})", key.kind.label(), key.format.label()))
        .detail(key.detail.clone())
        .confidence(key.confidence)
}

fn show_keys(state: &mut CryptoState, app: &mut ViewerApp, ui: &mut Ui) {
    let len = app.document.len().min(keys::MAX_SCAN_BYTES);
    ui.horizontal(|ui| {
        let busy = state.keys_job.is_some();
        if ui.add_enabled(!busy && len > 0, egui::Button::new(format!("Find keys and certificates ({})", crate::compress::human_bytes(len)))).clicked() {
            app.perform_later("crypto.find_keys", serde_json::json!({ "start": 0, "len": len }));
        }
        if busy {
            ui.spinner();
        }
    });
    let Some((sheet, findings)) = state.keys.shown() else {
        ui.label(dim("PEM blocks, DER certificates and keys (X.509, PKCS#1, PKCS#8, SEC1), OpenSSH keys, and random-looking 16/24/32-byte runs amid structured data that could be raw symmetric keys."));
        return;
    };
    let sheet = sheet.to_string();
    crate::sheets::view::results_of_other_sheet(app, ui, &sheet);
    if findings.is_empty() {
        ui.label(dim("Nothing found."));
        return;
    }
    let limit_note = if findings.len() >= keys::MAX_FINDINGS { " (stopped at the limit)" } else { "" };
    ui.label(dim(format!("{} found{limit_note}; click one to select it", findings.len())));
    let mut chosen = None;
    let mut key_to_use = None;
    for finding in findings {
        ui.horizontal(|ui| {
            let offset = ui.add(egui::Label::new(RichText::new(format!("{:#010x}", finding.offset)).monospace().color(theme::TEXT_DIM)).sense(Sense::click()));
            if offset.clicked() {
                chosen = Some(as_finding(finding));
            }
            offset.context_menu(|ui| {
                let carry = Carry::bytes(sheet.clone(), vec![(finding.offset, finding.len)], DerivedFrom::new(), format!("{} at {:#x}", finding.kind.label(), finding.offset));
                send_to::menu(app, ui, &carry);
            });
            ui.label(RichText::new(finding.kind.label()).small().color(kind_colour(finding.kind)));
            ui.label(dim(format!("{} · {} B · {:.0}%", finding.format.label(), finding.len, finding.confidence * 100.0)));
            if finding.kind == KeyKind::RawKeyCandidate && ui.small_button("Use this key").on_hover_text("Fill in the key under Decrypt (AES) with these bytes").clicked() {
                key_to_use = Some((finding.offset, finding.len));
            }
            ui.scope(|ui| {
                ui.set_max_width(KEY_DETAIL_WIDTH);
                let colour = if finding.confidence < 0.5 { theme::TEXT_DIM } else { theme::TEXT };
                if ui.add(egui::Label::new(RichText::new(&finding.detail).color(colour)).truncate().sense(Sense::click())).clicked() {
                    chosen = Some(as_finding(finding));
                }
            });
        });
    }
    if let Some(finding) = chosen {
        if sheet == app.document_id() {
            app.select_finding(&finding);
        } else {
            app.select_found_in(&sheet, finding.start, finding.len);
        }
    }
    if let Some((offset, len)) = key_to_use {
        use_key(state, app, &sheet, offset, len);
    }
}

/// The person takes a raw key candidate found in sheet `sheet` as the AES
/// key: its bytes fill the key under Decrypt.
fn use_key(state: &mut CryptoState, app: &mut ViewerApp, sheet: &str, offset: usize, len: usize) {
    let Some(document) = crate::api::Workspace::document_mut(app, sheet) else { return };
    let key = document.read_range(offset, len);
    state.decrypt.key = crate::api::values::encode_bytes(&key, Default::default());
    state.decrypt.error = None;
    let algorithm = Algorithm::for_key_len(key.len()).map_or("no AES", Algorithm::label);
    app.status = format!("The {len} bytes at {offset:#x} are the key under Decrypt ({algorithm})");
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

fn show_decrypt(state: &mut CryptoState, app: &mut ViewerApp, ui: &mut Ui) {
    let form = &mut state.decrypt;
    ui.horizontal_wrapped(|ui| {
        ui.label("Key");
        if ui.add(egui::TextEdit::singleline(&mut form.key).hint_text("hex, 16, 24 or 32 bytes").desired_width(300.0).font(egui::TextStyle::Monospace)).changed() {
            form.error = None;
        }
        let key_len = crate::ops::parse_hex(&form.key).map_or(0, |key| key.len());
        match Algorithm::for_key_len(key_len) {
            Some(algorithm) => ui.label(RichText::new(algorithm.label()).small().color(theme::ACCENT)),
            None if form.key.is_empty() => ui.label(dim("or Use this key on a raw key found above")),
            None => ui.label(dim(format!("{key_len} bytes: not an AES key"))),
        };
    });
    ui.horizontal_wrapped(|ui| {
        ui.label("Mode");
        for mode in Mode::ALL {
            if ui.selectable_value(&mut form.mode, mode, mode.label()).changed() {
                form.padding = mode.usual_padding();
                form.error = None;
            }
        }
        ui.separator();
        ui.label("Padding");
        for padding in [Padding::Pkcs7, Padding::None] {
            ui.selectable_value(&mut form.padding, padding, padding.label());
        }
    });
    if form.mode.needs_iv() {
        ui.horizontal(|ui| {
            ui.label(if form.mode == Mode::Ctr { "Counter" } else { "IV" });
            ui.add(egui::TextEdit::singleline(&mut form.iv).hint_text("hex, 16 bytes").desired_width(300.0).font(egui::TextStyle::Monospace));
        });
    }
    let (start, len, what) = selection_or_file(app, crate::api::MAX_CALL_BYTES);
    ui.horizontal(|ui| {
        let ready = len > 0 && !state.decrypt.key.is_empty();
        if ui.add_enabled(ready, egui::Button::new(format!("Decrypt {what} ({})…", crate::compress::human_bytes(len)))).on_hover_text("Open the plaintext as a document; Back returns").clicked() {
            start_decrypt(state, app, start, len);
        }
        ui.label(dim("select the ciphertext first; without a selection, the whole file"));
    });
    if let Some(error) = &state.decrypt.error {
        ui.label(RichText::new(error).small().color(theme::DANGER));
    }
}

/// The person decrypts `len` bytes at `start` as the form says, opening
/// the plaintext as a document of its own (`crypto.open_decrypted`). What
/// stops it is said under the form.
fn start_decrypt(state: &mut CryptoState, app: &mut ViewerApp, start: usize, len: usize) {
    let form = &state.decrypt;
    let mut params = serde_json::json!({ "start": start, "len": len, "mode": form.mode, "key": form.key.trim(), "padding": form.padding });
    if form.mode.needs_iv() {
        params["iv"] = serde_json::Value::String(form.iv.trim().to_string());
    }
    match app.perform_typed::<crate::api::tools::crypto::OpenDecryptedResult>("crypto.open_decrypted", params) {
        Ok(result) => {
            state.decrypt.error = None;
            app.status = crate::api::tools::crypto::describe_decrypted(&result.done);
        }
        Err(error) => state.decrypt.error = Some(error.message),
    }
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// The selection (capped), else a window from the cursor.
fn decode_range(app: &ViewerApp) -> (usize, usize) {
    let (start, len) = app.selection().map(|(start, len)| (start, len.min(DECODE_LIMIT))).unwrap_or((app.cursor, CURSOR_WINDOW));
    (start, len.min(app.document.len().saturating_sub(start)))
}

fn show_decode(state: &mut CryptoState, app: &mut ViewerApp, ui: &mut Ui) {
    show_crib_controls(state, ui);
    let (start, len) = decode_range(app);
    ui.horizontal(|ui| {
        let busy = state.decode_job.is_some();
        if ui.add_enabled(!busy && len > 0, egui::Button::new(format!("Try cipher attacks on {len} bytes at {start:#x}"))).clicked() {
            start_decode(state, app, start, len);
        }
        if busy {
            ui.spinner();
        }
        ui.label(dim("select the suspect bytes first; without a selection, 64 KiB from the cursor"));
    });
    let Some((sheet, results)) = state.decode.shown() else {
        ui.label(dim("Rolling XOR, XOR with the previous byte, ADD/SUB with a constant or repeating key, bit rotation, XOR combined with ADD, and crib dragging, ranked by how much the result looks like text or structured data. Plain XOR is in the XOR tab."));
        return;
    };
    let sheet = sheet.to_string();
    crate::sheets::view::results_of_other_sheet(app, ui, &sheet);
    show_key_fragments(ui, results);
    if results.candidates.is_empty() {
        ui.label(dim("No convincing decode."));
        return;
    }
    let mut action = None;
    for (index, candidate) in results.candidates.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.monospace(RichText::new(format!("{:.2}", candidate.score)).color(theme::ACCENT));
            let described = ui.add(egui::Label::new(RichText::new(candidate.transform.describe()).strong()).sense(Sense::click()));
            described.context_menu(|ui| {
                let carry = decode_carry(results, index, &sheet);
                send_to::menu(app, ui, &carry);
            });
            let magic = candidate.magic.map(|name| format!(" · starts like a {name}")).unwrap_or_default();
            ui.label(dim(format!("{:.0}% printable · {:.2} bits/byte{magic} · {}", candidate.printable_fraction * 100.0, candidate.entropy, candidate.reason)));
            if ui.small_button("Open decoded").on_hover_text("Open the decoded bytes as a document; Back returns").clicked() {
                action = Some((index, false));
            }
            if ui.small_button("Apply").on_hover_text("Apply the decode to the bytes as an undoable step that a recipe can repeat").clicked() {
                action = Some((index, true));
            }
        });
        ui.monospace(RichText::new(&candidate.preview).small().color(theme::TEXT_DIM));
    }
    if let Some((index, in_place)) = action {
        let (start, len) = (results.start, results.len);
        let transform = results.candidates[index].transform.clone();
        apply_decode(app, &sheet, start, len, &transform, in_place);
        if in_place {
            // The previews describe the bytes as they were before the edit.
            state.decode.closed(&sheet);
        }
    }
}

/// What the decode at `index` of those proposed for `sheet` carries
/// elsewhere: its operation over the span attacked, found again on another
/// file as the candidate at the same place of those the attack proposes
/// there.
fn decode_carry(results: &DecodeResults, index: usize, sheet: &str) -> Carry {
    let operation = serde_json::to_value(Operation::from(results.candidates[index].transform.clone())).unwrap_or_default();
    let (anchor, from) = match results.step {
        Some(step) => {
            let pick = Pick { step: StepRef::Number(step), list: "job.candidates".to_string(), condition: None, sort: None, nth: index, field: Some("operation".to_string()) };
            (Some(Anchor::Pick { pick }), format!("from step {step}, decode {}", index + 1))
        }
        None => (None, format!("decode {}", index + 1)),
    };
    Carry::value(Carried::Operation(operation), anchor, from, sheet).with_span(results.start, results.len)
}

/// The inputs of the Crypto tab a carry can fill: the AES key and the crib.
pub fn slots(carry: &Carry) -> Vec<Slot> {
    if !carry.has_bytes() {
        return Vec::new();
    }
    vec![Slot { label: "Crypto · AES key", target: Target::CryptoKey }, Slot { label: "Crypto · crib", target: Target::CryptoCrib }]
}

/// Fill the AES key under Decrypt with what `carry` holds, as hex.
pub(crate) fn fill_key(state: &mut CryptoState, app: &mut ViewerApp, carry: &Carry) -> Result<String, String> {
    let filled = carry.as_hex(app).ok_or_else(|| send_to::does_not_fit(carry, "an AES key"))?;
    state.decrypt.key = filled.text;
    state.decrypt.error = None;
    Ok(format!("The key under Decrypt is {}", carry.summary()))
}

/// Fill the crib of the cipher attacks with what `carry` holds, bytes that
/// are not printable written as \xHH.
pub(crate) fn fill_crib(state: &mut CryptoState, app: &mut ViewerApp, carry: &Carry) -> Result<String, String> {
    let bytes = carry.bytes_up_to(app, send_to::MOST_CARRIED_BYTES).ok_or_else(|| send_to::does_not_fit(carry, "a crib"))?;
    state.crib = ciphers::crib_text(&bytes);
    state.crib_error = None;
    Ok(format!("The crib is {}", carry.summary()))
}

/// The key bytes the crib revealed, shown even when they decode nothing:
/// with a key longer than the crib they are the start of the answer.
fn show_key_fragments(ui: &mut Ui, results: &DecodeResults) {
    for fragment in &results.fragments {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(format!("Key bytes at {:#x}", results.start + fragment.offset)).strong());
            ui.monospace(keys::short_hex(&fragment.keystream, fragment.keystream.len()));
            if ui.small_button("Copy").on_hover_text("Copy the key bytes as hex").clicked() {
                ui.ctx().copy_text(crate::api::values::encode_bytes(&fragment.keystream, Default::default()));
            }
        });
        ui.label(dim(&fragment.reason));
    }
}

fn show_crib_controls(state: &mut CryptoState, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.label("Crib");
        let edit = ui.add(egui::TextEdit::singleline(&mut state.crib).hint_text("known plaintext, e.g. PK\\x03\\x04").desired_width(180.0));
        if edit.changed() {
            state.crib_error = None;
        }
        for (label, bytes) in ciphers::PRESET_CRIBS {
            if ui.small_button(label).clicked() {
                state.crib = ciphers::crib_text(bytes);
                state.crib_error = None;
            }
        }
        if !state.crib.is_empty() && ui.small_button("Clear").clicked() {
            state.crib.clear();
            state.crib_error = None;
        }
    });
    if let Some(error) = &state.crib_error {
        ui.label(RichText::new(error).small().color(theme::DANGER));
    }
}

/// The person asks for the cipher attacks on `len` bytes at `start`, with
/// the crib typed: `crypto.attack`, carried out once the panel is drawn. A
/// crib that cannot be read is said under it instead.
fn start_decode(state: &mut CryptoState, app: &mut ViewerApp, start: usize, len: usize) {
    let mut params = serde_json::json!({ "start": start, "len": len });
    if !state.crib.is_empty() {
        if let Err(error) = ciphers::parse_crib(&state.crib) {
            state.crib_error = Some(error);
            return;
        }
        params["crib"] = serde_json::Value::String(state.crib.clone());
    }
    app.perform_later("crypto.attack", params);
}

/// The person uses a decode: applied to the bytes as an undoable step
/// (`transform.apply`), or opened as a document of its own
/// (`documents.derive` with the transform), the operation named either way
/// so a recipe repeats it.
fn apply_decode(app: &mut ViewerApp, sheet: &str, start: usize, len: usize, transform: &ciphers::Transform, in_place: bool) {
    let operation = Operation::from(transform.clone());
    let description = transform.describe();
    let shown = sheet == app.document_id();
    let mut params = if in_place {
        serde_json::json!({ "selection": { "range": [start, len] }, "operation": operation })
    } else {
        let name = format!("{} › decoded@{start:#x}", app.sheet_title(sheet).unwrap_or_else(|| app.display_name()));
        serde_json::json!({ "start": start, "len": len, "name": name, "transform": operation })
    };
    if !shown {
        params["doc"] = serde_json::json!(sheet);
    }
    if in_place {
        if app.perform("transform.apply", params).is_ok() {
            if shown {
                app.restore_selection(start, len);
            }
            app.status = format!("{description}: applied to {len} bytes at {start:#x}");
        }
    } else if app.perform("documents.derive", params).is_ok() {
        app.status = format!("Opened the decode ({description})");
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

    #[test]
    fn the_searches_are_jobs_of_the_person_s_carried_out_once_the_panel_is_drawn() {
        let mut app = app_with(&[0x42u8; 4096]);
        let mut state = CryptoState { crib: "PK\\x03\\x04".to_string(), ..Default::default() };
        start_decode(&mut state, &mut app, 16, 256);
        app.perform_later("crypto.repeated_blocks", json!({"start": 0, "len": 4096}));
        assert!(take_performed().is_empty());
        app.perform_waiting_actions();
        let performed = take_performed();
        assert_eq!(performed[0], ("crypto.attack".to_string(), json!({"start": 16, "len": 256, "crib": "PK\\x03\\x04"})));
        let crypto = &app.bench.panels.crypto;
        assert!(crypto.decode_job.is_some() && crypto.blocks_job.is_some(), "the panel waits for both");
        let report = crypto.blocks_job.as_ref().unwrap().receiver.recv_timeout(Duration::from_secs(60)).expect("the search finishes");
        assert_eq!(report.analysed_len, 4096);
    }

    #[test]
    fn a_raw_key_found_fills_the_decrypt_key_and_decrypts_the_selection_into_a_document() {
        let key = crate::ops::parse_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let ciphertext = crate::ops::parse_hex("3ad77bb40d7a3660a89ecaf32466ef97").unwrap();
        let mut app = app_with(&[vec![0u8; 32], key, vec![0u8; 32], ciphertext].concat());
        let mut state = CryptoState::default();
        let sheet = app.document_id();
        use_key(&mut state, &mut app, &sheet, 32, 16);
        assert_eq!(state.decrypt.key, "2b7e151628aed2a6abf7158809cf4f3c");
        state.decrypt.padding = Padding::None;
        start_decrypt(&mut state, &mut app, 80, 16);
        let performed = take_performed();
        assert_eq!(performed[0], ("crypto.open_decrypted".to_string(), json!({"start": 80, "len": 16, "mode": "ecb", "key": "2b7e151628aed2a6abf7158809cf4f3c", "padding": "none"})));
        assert_eq!(app.display_name(), "test.bin › AES-128-ECB@0x50");
        assert_eq!(app.document.read_range(0, 16), crate::ops::parse_hex("6bc1bee22e409f96e93d7e117393172a").unwrap());
        assert!(state.decrypt.error.is_none());
    }

    #[test]
    fn a_decryption_that_cannot_be_done_is_said_under_the_form() {
        let mut app = app_with(&[0u8; 20]);
        let mut state = CryptoState::default();
        state.decrypt.key = "000102030405060708090a0b0c0d0e0f".to_string();
        start_decrypt(&mut state, &mut app, 0, 20);
        assert!(state.decrypt.error.as_deref().is_some_and(|error| error.contains("4 bytes over")), "{:?}", state.decrypt.error);
        assert_eq!(app.display_name(), "test.bin", "nothing was opened");
    }

    #[test]
    fn a_crib_that_cannot_be_read_is_said_under_it_without_a_step() {
        let mut app = app_with(&[0u8; 64]);
        let mut state = CryptoState { crib: "\\xZZ".to_string(), ..Default::default() };
        start_decode(&mut state, &mut app, 0, 64);
        app.perform_waiting_actions();
        assert!(take_performed().is_empty());
        assert!(state.crib_error.is_some());
    }

    #[test]
    fn a_decode_is_applied_as_a_repeatable_operation_or_opened_as_a_derived_document() {
        let mut app = app_with(&[0x10, 0x20, 0x30, 0x40]);
        let rotate = ciphers::Transform::RotateLeft { bits: 4 };
        let sheet = app.document_id();
        apply_decode(&mut app, &sheet, 1, 2, &rotate, true);
        let operation = json!({"op": "rotate_each_byte", "bits": 4});
        assert_eq!(take_performed(), [("transform.apply".to_string(), json!({"selection": {"range": [1, 2]}, "operation": operation}))]);
        assert_eq!(app.document.read_range(0, 4), [0x10, 0x02, 0x03, 0x40]);
        assert_eq!(app.status, format!("{}: applied to 2 bytes at 0x1", rotate.describe()));
        apply_decode(&mut app, &sheet, 0, 1, &rotate, false);
        assert_eq!(take_performed(), [("documents.derive".to_string(), json!({"start": 0, "len": 1, "name": "test.bin › decoded@0x0", "transform": operation}))]);
        assert_eq!(app.display_name(), "test.bin › decoded@0x0");
    }
}
