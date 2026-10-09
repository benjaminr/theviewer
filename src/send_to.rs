//! Carrying what one tool found to another: *Send to…*, *Use as…*, the
//! chips of bound fields, and dragging a result onto a field.
//!
//! A result row (a string, a key a tool proposed, a finding, a field, a
//! packet, the selection) builds a [`Carry`]: a value with the anchor that
//! finds it again, bytes with their sheet and ranges, or a sheet. Sent to an
//! input of another tool (a [`Slot`]), the value fills it and the field is
//! **bound**: it shows a chip such as `NC500-2F357657 · from step 7, string
//! /^NC500-/ ✕` in place of a text box, and the call the tool makes passes
//! the anchor as `derived_from` ([`ViewerApp::perform_derived`]), so the
//! journal and a recipe made from it keep where the value came from. ✕
//! unbinds the field and keeps the value as a literal.
//!
//! Each tool says which of its inputs take a carry (its `slots`), and fills
//! one ([`send`]). A carry can also become a new worksheet (a derive with
//! lineage, `output: "new"`) or a variable (`vars.set` with the anchor).
//!
//! The menus are drawn while a panel's state is lent out, so what the
//! person picks is carried out once the frame is drawn ([`send_later`],
//! run by [`ViewerApp::perform_waiting_actions`]).

use eframe::egui::{self, RichText, Ui};
use serde_json::{Value, json};

use crate::api::ApiError;
use crate::app::ViewerApp;
use crate::dock::DockTab;
use crate::journal::DerivedFrom;
use crate::journal::anchors::{self, Anchor, Operation, SheetRef};
use crate::journal::anchors::then::Encoding;
use crate::layout::Pane;
use crate::theme;

/// Most bytes a carry of bytes puts into a key, crib or needle.
pub const MOST_CARRIED_BYTES: usize = 256;
/// Characters of a value a chip shows before cutting it.
const CHIP_VALUE_CHARS: usize = 24;
/// Characters of a value a menu shows before cutting it.
const MENU_VALUE_CHARS: usize = 40;

/// A value one tool found, as another takes it.
#[derive(Clone, Debug, PartialEq)]
pub enum Carried {
    Text(String),
    Bytes(Vec<u8>),
    Number(u64),
    /// An operation that undoes a cipher, as `transform.apply` and
    /// `crypto.apply` take it.
    Operation(Value),
}

impl Carried {
    /// The value as JSON, as `vars.set` binds it and *Copy value* copies it:
    /// bytes as hex.
    pub fn as_json(&self) -> Value {
        match self {
            Carried::Text(text) => json!(text),
            Carried::Bytes(bytes) => json!(crate::ops::to_compact_hex(bytes)),
            Carried::Number(number) => json!(number),
            Carried::Operation(operation) => operation.clone(),
        }
    }

    /// The value as a chip or a menu shows it.
    pub fn shown(&self) -> String {
        match self {
            Carried::Text(text) => text.clone(),
            Carried::Bytes(bytes) => crate::ops::to_compact_hex(bytes),
            Carried::Number(number) => format!("{number:#x}"),
            Carried::Operation(operation) => operation.to_string(),
        }
    }
}

/// A value carried with where it came from.
#[derive(Clone, Debug, PartialEq)]
pub struct CarriedValue {
    pub value: Carried,
    /// What finds the value again on another file, when the row knows it.
    pub anchor: Option<Anchor>,
    /// Where it came from in a few words: "from step 7, string /^NC500-/".
    pub from: String,
    /// The sheet it was found in.
    pub sheet: String,
    /// The bytes it was read from, when it has them: a string's.
    pub span: Option<(usize, usize)>,
}

/// Bytes carried: some ranges of a sheet, with the anchors that find each
/// range's offset and length again (by path, `ranges[0][0]`, `ranges[0][1]`).
#[derive(Clone, Debug, PartialEq)]
pub struct CarriedBytes {
    pub sheet: String,
    pub ranges: Vec<(usize, usize)>,
    pub derived_from: DerivedFrom,
    /// Where they came from in a few words: "finding png", "packet 4".
    pub from: String,
}

/// What a result row hands on.
#[derive(Clone, Debug, PartialEq)]
pub enum Carry {
    Value(CarriedValue),
    Bytes(CarriedBytes),
    /// A whole sheet, by id.
    Sheet(String),
}

impl Carry {
    /// A value found in `sheet`, `from` saying where in words.
    pub fn value(value: Carried, anchor: Option<Anchor>, from: impl Into<String>, sheet: impl Into<String>) -> Carry {
        Carry::Value(CarriedValue { value, anchor, from: from.into(), sheet: sheet.into(), span: None })
    }

    /// This carry with the span its value was read from.
    pub fn with_span(mut self, start: usize, len: usize) -> Carry {
        if let Carry::Value(value) = &mut self {
            value.span = Some((start, len));
        }
        self
    }

    /// Bytes of `sheet`: `ranges`, their anchors by path (`ranges[0][0]`).
    pub fn bytes(sheet: impl Into<String>, ranges: Vec<(usize, usize)>, derived_from: DerivedFrom, from: impl Into<String>) -> Carry {
        Carry::Bytes(CarriedBytes { sheet: sheet.into(), ranges, derived_from, from: from.into() })
    }

    /// The variable `name`, bound to `value`.
    pub fn variable(name: &str, value: &Value, sheet: impl Into<String>) -> Carry {
        let carried = match value {
            Value::String(text) => Carried::Text(text.clone()),
            Value::Number(number) if number.as_u64().is_some() => Carried::Number(number.as_u64().unwrap_or_default()),
            other => Carried::Operation(other.clone()),
        };
        Carry::value(carried, Some(Anchor::Var { var: name.to_string() }), format!("${name}"), sheet)
    }

    /// The sheet the carry is of.
    pub fn sheet(&self) -> &str {
        match self {
            Carry::Value(value) => &value.sheet,
            Carry::Bytes(bytes) => &bytes.sheet,
            Carry::Sheet(sheet) => sheet,
        }
    }

    /// Where it came from, in a few words.
    pub fn from(&self) -> String {
        match self {
            Carry::Value(value) => value.from.clone(),
            Carry::Bytes(bytes) => bytes.from.clone(),
            Carry::Sheet(sheet) => format!("sheet {sheet}"),
        }
    }

    /// What the carry is, as a menu's heading says it.
    pub fn summary(&self) -> String {
        match self {
            Carry::Value(value) => crate::text::truncate_chars(&value.value.shown(), MENU_VALUE_CHARS),
            Carry::Bytes(bytes) => {
                let len: usize = bytes.ranges.iter().map(|&(_, len)| len).sum();
                match bytes.ranges.as_slice() {
                    [(start, _)] => format!("{len} bytes at {start:#x}"),
                    ranges => format!("{len} bytes in {} ranges", ranges.len()),
                }
            }
            Carry::Sheet(sheet) => sheet.clone(),
        }
    }

    /// The anchor a recipe would find the carry by, as *Copy anchor* copies
    /// it: `{"$anchor": …}`, or for bytes each range's anchors by path.
    pub fn anchor_json(&self, app: &ViewerApp) -> Option<Value> {
        match self {
            Carry::Value(value) => value.anchor.as_ref().map(anchors::marked),
            Carry::Bytes(bytes) if bytes.derived_from.is_empty() => None,
            Carry::Bytes(bytes) => serde_json::to_value(&bytes.derived_from).ok(),
            Carry::Sheet(sheet) => sheet_anchor(app, sheet).map(|anchor| anchors::marked(&anchor)),
        }
    }

    /// Whether the carry holds bytes a key, crib or needle takes: text,
    /// bytes, or a few bytes of a sheet.
    pub fn has_bytes(&self) -> bool {
        match self {
            Carry::Value(value) => matches!(value.value, Carried::Text(_) | Carried::Bytes(_)),
            Carry::Bytes(bytes) => {
                let total: usize = bytes.ranges.iter().map(|&(_, len)| len).sum();
                total > 0 && total <= MOST_CARRIED_BYTES
            }
            Carry::Sheet(_) => false,
        }
    }

    /// The bytes it carries: a value's (text as UTF-8), or the ranges read
    /// from their sheet, up to `most`. `None` for a number, an operation or
    /// a sheet, or bytes past `most`.
    pub fn bytes_up_to(&self, app: &mut ViewerApp, most: usize) -> Option<Vec<u8>> {
        match self {
            Carry::Value(CarriedValue { value: Carried::Text(text), .. }) => Some(text.as_bytes().to_vec()),
            Carry::Value(CarriedValue { value: Carried::Bytes(bytes), .. }) => Some(bytes.clone()),
            Carry::Bytes(carried) => {
                let total: usize = carried.ranges.iter().map(|&(_, len)| len).sum();
                if total == 0 || total > most {
                    return None;
                }
                let document = crate::api::Workspace::document_mut(app, &carried.sheet)?;
                Some(carried.ranges.iter().flat_map(|&(start, len)| document.read_range(start, len)).collect())
            }
            _ => None,
        }
    }

    /// The carry as hex, for a key: text as the hex of its bytes (its
    /// anchor encoded so), bytes as they are.
    pub fn as_hex(&self, app: &mut ViewerApp) -> Option<Filled> {
        let bytes = self.bytes_up_to(app, MOST_CARRIED_BYTES)?;
        let text = crate::ops::to_compact_hex(&bytes);
        let Carry::Value(value) = self else { return Some(Filled::literal(text)) };
        let anchor = value.anchor.clone().map(|anchor| match value.value {
            Carried::Text(_) => text_to_hex(anchor),
            _ => anchor,
        });
        Some(Filled { text, bound: anchor.map(|anchor| Bound { anchor, from: value.from.clone(), shown: value.value.shown() }) })
    }

    /// The carry as text: a text value as it is, anything else as `None`.
    pub fn as_text(&self) -> Option<Filled> {
        let Carry::Value(CarriedValue { value: Carried::Text(text), anchor, from, .. }) = self else { return None };
        Some(Filled { text: text.clone(), bound: anchor.clone().map(|anchor| Bound { anchor, from: from.clone(), shown: text.clone() }) })
    }

    /// The carry as an offset: a number, or where bytes start.
    pub fn as_offset(&self) -> Option<Filled> {
        match self {
            Carry::Value(CarriedValue { value: Carried::Number(number), anchor, from, .. }) => {
                let shown = format!("{number:#x}");
                Some(Filled { text: shown.clone(), bound: anchor.clone().map(|anchor| Bound { anchor, from: from.clone(), shown }) })
            }
            Carry::Bytes(bytes) => {
                let &(start, _) = bytes.ranges.first()?;
                let shown = format!("{start:#x}");
                let anchor = bytes.derived_from.get("ranges[0][0]").cloned();
                Some(Filled { text: shown.clone(), bound: anchor.map(|anchor| Bound { anchor, from: bytes.from.clone(), shown }) })
            }
            _ => None,
        }
    }

    /// A small number the carry is (a bit offset), with its anchor.
    pub fn as_number(&self) -> Option<(u64, Option<Anchor>)> {
        match self {
            Carry::Value(CarriedValue { value: Carried::Number(number), anchor, .. }) => Some((*number, anchor.clone())),
            Carry::Value(CarriedValue { value: Carried::Text(text), anchor, .. }) => Some((crate::ops::parse_offset(text)? as u64, anchor.clone())),
            _ => None,
        }
    }
}

/// `anchor`'s text as the hex of its bytes.
fn text_to_hex(anchor: Anchor) -> Anchor {
    Anchor::Then { of: Box::new(anchor), then: vec![Operation::Encode(Encoding::TextToHex)] }
}

/// The anchor of the open sheet `sheet`: the step that made it, when one did.
fn sheet_anchor(app: &ViewerApp, sheet: &str) -> Option<Anchor> {
    let step = app.sheet_lineage(sheet)?.made_by.as_ref()?.step?;
    Some(Anchor::Sheet { sheet: SheetRef::Step { step, nth: 0 } })
}

/// A field's value bound to where it came from: the chip shows `shown` and
/// `from`, and calls made with the field pass `anchor` as `derived_from`.
#[derive(Clone, Debug, PartialEq)]
pub struct Bound {
    pub anchor: Anchor,
    /// "from step 7, string /^NC500-/", "$serial".
    pub from: String,
    /// The value as it was found ("NC500-2F357657", even in a hex field).
    pub shown: String,
}

impl Bound {
    /// The anchor at `path` of a call's params, when `bound` is set.
    pub fn at(bound: &Option<Bound>, path: &str) -> DerivedFrom {
        bound.iter().map(|bound| (path.to_string(), bound.anchor.clone())).collect()
    }
}

/// What a carry puts into a field: its text, and the binding when it has an
/// anchor.
#[derive(Clone, Debug, PartialEq)]
pub struct Filled {
    pub text: String,
    pub bound: Option<Bound>,
}

impl Filled {
    fn literal(text: String) -> Filled {
        Filled { text, bound: None }
    }
}

// ---------------------------------------------------------------------------
// Slots
// ---------------------------------------------------------------------------

/// An input of a tool a carry can fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The key of the XOR tab's Apply row.
    XorKey,
    /// The key of the Selection menu's XOR, add and subtract.
    TransformKey,
    /// The Find box's needle.
    SearchNeedle,
    /// The AES key of the Crypto tab's Decrypt.
    CryptoKey,
    /// The crib of the Crypto tab's cipher attacks.
    CryptoCrib,
    /// The records of the CRC solver, under Checksums.
    CrcRecords,
    /// The start of the CRC solver's fixed-length records.
    CrcStart,
    /// The bit offset the Bits tab decodes a line code from.
    BitsOffset,
}

impl Target {
    /// The tab the input is in, when it is in one.
    fn tab(self) -> Option<DockTab> {
        match self {
            Target::XorKey => Some(DockTab::Xor),
            Target::CryptoKey | Target::CryptoCrib => Some(DockTab::Crypto),
            Target::CrcRecords | Target::CrcStart => Some(DockTab::Checksums),
            Target::BitsOffset => Some(DockTab::Bits),
            Target::TransformKey | Target::SearchNeedle => None,
        }
    }
}

/// One input a carry can be sent to, as *Send to* lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slot {
    pub label: &'static str,
    pub target: Target,
}

/// The inputs of the open tools that take `carry`, each tool saying which
/// of its own do.
pub fn slots(app: &ViewerApp, carry: &Carry) -> Vec<Slot> {
    let mut slots = Vec::new();
    slots.extend(crate::analysis_stats::slots(carry));
    slots.extend(crate::selection_menu::slots(carry));
    slots.extend(crate::panel_crypto::slots(carry));
    slots.extend(crate::panel_crc_solver::slots(carry));
    slots.extend(crate::panel_bits::slots(carry));
    slots.retain(|slot| slot.target.tab().is_none_or(|tab| app.panel_is_open(Pane::Tool(tab))));
    slots
}

/// Fill `target` with `carry`, bring its tool forward and say so; or say
/// why it does not fit.
pub fn send(app: &mut ViewerApp, target: Target, carry: &Carry) -> Result<(), String> {
    let filled = match target {
        Target::XorKey => crate::analysis_stats::fill_xor_key(app, carry),
        Target::TransformKey => crate::selection_menu::fill_transform_key(app, carry),
        Target::SearchNeedle => crate::selection_menu::fill_search_needle(app, carry),
        Target::CryptoKey => fill_panel(app, carry, |app| &mut app.bench.panels.crypto, crate::panel_crypto::fill_key),
        Target::CryptoCrib => fill_panel(app, carry, |app| &mut app.bench.panels.crypto, crate::panel_crypto::fill_crib),
        Target::CrcRecords => fill_panel(app, carry, |app| &mut app.bench.panels.crc_solver, crate::panel_crc_solver::fill_records),
        Target::CrcStart => fill_panel(app, carry, |app| &mut app.bench.panels.crc_solver, crate::panel_crc_solver::fill_start),
        Target::BitsOffset => fill_panel(app, carry, |app| &mut app.bench.panels.bits, crate::panel_bits::fill_offset),
    };
    match filled {
        Ok(said) => {
            if let Some(tab) = target.tab() {
                app.show_panel(Pane::Tool(tab));
            }
            app.status = said;
            Ok(())
        }
        Err(why) => {
            app.status = why.clone();
            Err(why)
        }
    }
}

/// Fill a panel's input, its state lent out of `app` meanwhile.
fn fill_panel<S: Default>(app: &mut ViewerApp, carry: &Carry, slot: fn(&mut ViewerApp) -> &mut S, fill: fn(&mut S, &mut ViewerApp, &Carry) -> Result<String, String>) -> Result<String, String> {
    let mut state = std::mem::take(slot(app));
    let filled = fill(&mut state, app, carry);
    *slot(app) = state;
    filled
}

/// Why a carry does not fit an input, as the status bar says it.
pub fn does_not_fit(carry: &Carry, input: &str) -> String {
    format!("{} cannot be {input}", carry.summary())
}

// ---------------------------------------------------------------------------
// New worksheet and variables
// ---------------------------------------------------------------------------

/// Open what `carry` holds as a new worksheet derived from its sheet,
/// through the API with `output: "new"`, its anchors passed on: bytes as
/// `documents.derive` of their ranges, a value's span likewise, a value
/// without one as its bytes, an operation as `crypto.apply` over its span.
pub fn new_worksheet(app: &mut ViewerApp, carry: &Carry) -> Result<Value, ApiError> {
    match carry {
        Carry::Bytes(bytes) => derive_ranges(app, &bytes.sheet, &bytes.ranges, &bytes.derived_from),
        Carry::Value(CarriedValue { value: Carried::Operation(operation), anchor, sheet, span: Some((start, len)), .. }) => {
            let params = json!({ "doc": sheet, "start": start, "len": len, "operation": operation, "output": "new" });
            let derived_from = anchor.iter().map(|anchor| ("operation".to_string(), anchor.clone())).collect();
            app.perform_derived("crypto.apply", params, derived_from)
        }
        Carry::Value(CarriedValue { span: Some((start, len)), sheet, .. }) => derive_ranges(app, sheet, &[(*start, *len)], &DerivedFrom::new()),
        Carry::Value(value) => {
            let Some(filled) = carry.as_hex(app) else { return Err(ApiError::invalid_params(format!("{} has no bytes to open", value.value.shown()))) };
            let params = json!({ "doc": value.sheet, "data": filled.text, "output": "new" });
            app.perform_derived("documents.derive", params, Bound::at(&filled.bound, "data"))
        }
        Carry::Sheet(sheet) => Err(ApiError::invalid_params(format!("{sheet} is a worksheet already"))),
    }
}

/// `documents.derive` of `ranges` of `sheet` as a new sheet, the anchors of
/// each range's offset and length passed on.
fn derive_ranges(app: &mut ViewerApp, sheet: &str, ranges: &[(usize, usize)], derived_from: &DerivedFrom) -> Result<Value, ApiError> {
    let (params, derived_from) = match ranges {
        &[(start, len)] => {
            let renamed = derived_from.iter().filter_map(|(path, anchor)| match path.as_str() {
                "ranges[0][0]" => Some(("start".to_string(), anchor.clone())),
                "ranges[0][1]" => Some(("len".to_string(), anchor.clone())),
                _ => None,
            });
            (json!({ "doc": sheet, "start": start, "len": len, "output": "new" }), renamed.collect())
        }
        ranges => (json!({ "doc": sheet, "ranges": ranges, "output": "new" }), derived_from.clone()),
    };
    app.perform_derived("documents.derive", params, derived_from)
}

/// Bind the variable `name` to what `carry` holds, through `vars.set`, its
/// anchor kept so a recipe finds the value again.
pub fn bind_variable(app: &mut ViewerApp, carry: &Carry, name: &str) -> Result<Value, ApiError> {
    let name = name.trim().trim_start_matches('$');
    let (value, anchor, sheet) = match carry {
        Carry::Value(value) => (value.value.as_json(), value.anchor.clone(), value.sheet.clone()),
        Carry::Bytes(bytes) => {
            let Some(read) = carry.bytes_up_to(app, MOST_CARRIED_BYTES) else {
                return Err(ApiError::invalid_params(format!("{} is more than a variable holds ({MOST_CARRIED_BYTES} bytes)", carry.summary())));
            };
            (json!(crate::ops::to_compact_hex(&read)), None, bytes.sheet.clone())
        }
        Carry::Sheet(sheet) => (json!(sheet), sheet_anchor(app, sheet), sheet.clone()),
    };
    let mut params = json!({ "name": name, "value": value });
    if anchor.as_ref().is_some_and(reads_a_document) {
        params["doc"] = json!(sheet);
    }
    let derived_from = anchor.map(|anchor| DerivedFrom::from([("value".to_string(), anchor)])).unwrap_or_default();
    app.perform_derived("vars.set", params, derived_from)
}

/// Whether `anchor` (or one inside it) is found in a document: a find,
/// structure, finding or selection anchor.
fn reads_a_document(anchor: &Anchor) -> bool {
    anchor.within().iter().any(|inner| matches!(inner, Anchor::Find { .. } | Anchor::Structure { .. } | Anchor::Finding { .. } | Anchor::Selection { .. }))
}

/// A name for a variable bound to `carry`: the text's leading word, else
/// "value".
pub fn suggested_name(carry: &Carry) -> String {
    let Carry::Value(CarriedValue { value: Carried::Text(text), .. }) = carry else { return "value".to_string() };
    let word: String = text.chars().take_while(|character| character.is_ascii_alphanumeric()).take(16).collect::<String>().to_lowercase();
    if word.is_empty() || word.starts_with(|character: char| character.is_ascii_digit()) { "value".to_string() } else { word }
}

// ---------------------------------------------------------------------------
// Waiting until the frame is drawn
// ---------------------------------------------------------------------------

/// What the person picked from a *Send to* menu, carried out once the frame
/// is drawn.
#[derive(Clone, Debug, PartialEq)]
pub enum Sending {
    To(Target),
    NewWorksheet,
    Variable(String),
}

/// The *Send to* menus' state: the variable name typed, and what waits for
/// the frame to be drawn.
#[derive(Debug, Default)]
pub struct SendToState {
    pub variable_name: String,
    waiting: Vec<(Sending, Carry)>,
}

/// Carry out `sending` once the frame is drawn.
pub fn send_later(app: &mut ViewerApp, sending: Sending, carry: Carry) {
    app.bench.send_to.waiting.push((sending, carry));
}

/// Carry out what the menus asked for while the frame was drawn.
pub(crate) fn send_waiting(app: &mut ViewerApp) {
    for (sending, carry) in std::mem::take(&mut app.bench.send_to.waiting) {
        match sending {
            Sending::To(target) => {
                let _ = send(app, target, &carry);
            }
            Sending::NewWorksheet => {
                let _ = new_worksheet(app, &carry);
            }
            Sending::Variable(name) => {
                if bind_variable(app, &carry, &name).is_ok() {
                    app.status = format!("${} = {}", name.trim().trim_start_matches('$'), carry.summary());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Menus
// ---------------------------------------------------------------------------

/// A *Send to ▸* submenu for `carry`, then *Copy value* and *Copy anchor*.
pub fn menu(app: &mut ViewerApp, ui: &mut Ui, carry: &Carry) {
    ui.menu_button("Send to", |ui| send_to_items(app, ui, carry));
    copy_items(app, ui, carry);
}

/// The targets of *Send to*: a new worksheet, a variable, and each open
/// tool's input that takes the carry.
fn send_to_items(app: &mut ViewerApp, ui: &mut Ui, carry: &Carry) {
    ui.label(RichText::new(format!("{} · {}", carry.summary(), carry.from())).small().color(theme::TEXT_DIM));
    let can_open = !matches!(carry, Carry::Sheet(_) | Carry::Value(CarriedValue { value: Carried::Number(_), .. }) | Carry::Value(CarriedValue { value: Carried::Operation(_), span: None, .. }));
    if ui.add_enabled(can_open, egui::Button::new("New worksheet")).on_hover_text("Open it as a sheet derived from the one it came from").clicked() {
        send_later(app, Sending::NewWorksheet, carry.clone());
        ui.close();
    }
    ui.menu_button("Variable…", |ui| {
        if app.bench.send_to.variable_name.is_empty() {
            app.bench.send_to.variable_name = suggested_name(carry);
        }
        ui.horizontal(|ui| {
            ui.label("$");
            let field = ui.add(egui::TextEdit::singleline(&mut app.bench.send_to.variable_name).desired_width(120.0).hint_text("name"));
            let entered = field.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            let name = app.bench.send_to.variable_name.trim().to_string();
            if (ui.add_enabled(!name.is_empty(), egui::Button::new("Bind")).clicked() || entered) && !name.is_empty() {
                send_later(app, Sending::Variable(name), carry.clone());
                app.bench.send_to.variable_name.clear();
                ui.close();
            }
        });
        ui.label(RichText::new("Later calls can use it as $name; a recipe finds it again").small().color(theme::TEXT_DIM));
    });
    let slots = slots(app, carry);
    if !slots.is_empty() {
        ui.separator();
    }
    for slot in slots {
        if ui.button(slot.label).clicked() {
            send_later(app, Sending::To(slot.target), carry.clone());
            ui.close();
        }
    }
}

/// *Copy value* and *Copy anchor (JSON)*.
fn copy_items(app: &mut ViewerApp, ui: &mut Ui, carry: &Carry) {
    let value = match carry {
        Carry::Value(value) => Some(match &value.value {
            Carried::Text(text) => text.clone(),
            other => other.as_json().to_string().trim_matches('"').to_string(),
        }),
        Carry::Bytes(_) => carry.bytes_up_to(app, crate::api::MAX_CALL_BYTES).map(|bytes| crate::ops::to_compact_hex(&bytes)),
        Carry::Sheet(sheet) => Some(sheet.clone()),
    };
    if ui.add_enabled(value.is_some(), egui::Button::new("Copy value")).clicked() {
        ui.ctx().copy_text(value.unwrap_or_default());
        ui.close();
    }
    let anchor = carry.anchor_json(app);
    let button = ui.add_enabled(anchor.is_some(), egui::Button::new("Copy anchor")).on_hover_text("Copy, as JSON, the anchor a recipe finds it again by").on_disabled_hover_text("Where it came from is not known, so it would be a literal in a recipe");
    if button.clicked() {
        ui.ctx().copy_text(anchor.map(|anchor| anchor.to_string()).unwrap_or_default());
        ui.close();
    }
}

// ---------------------------------------------------------------------------
// Bound fields
// ---------------------------------------------------------------------------

/// What happened to a bound field this frame.
#[derive(Debug, Default)]
pub struct FieldResponse {
    /// Whether the person typed in it.
    pub changed: bool,
    /// A carry dropped on it.
    pub dropped: Option<Carry>,
    /// Whether Enter was pressed in it.
    pub entered: bool,
    /// The text box, while the field is not bound: to give it the keyboard.
    pub text_box: Option<egui::Response>,
}

/// A text field that shows a chip in place of the text box while it is
/// bound: the value as found and where from, the anchor in words on hover,
/// and ✕ to unbind, keeping the value as a literal. A carry dragged from a
/// result row can be dropped on it, bound or not.
pub fn bound_field(ui: &mut Ui, text: &mut String, bound: &mut Option<Bound>, hint: &str, width: f32) -> FieldResponse {
    let mut answer = FieldResponse::default();
    let response = match bound {
        Some(binding) => {
            let mut unbind = false;
            let chip = egui::Frame::new().fill(theme::SURFACE_RAISED).stroke(egui::Stroke::new(1.0, theme::ACCENT)).corner_radius(8.0).inner_margin(egui::Margin::symmetric(6, 1)).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    let value = crate::text::truncate_chars(&binding.shown, CHIP_VALUE_CHARS);
                    let label = ui.add(egui::Label::new(RichText::new(value).monospace()).sense(egui::Sense::hover()));
                    ui.label(RichText::new(format!("· {}", binding.from)).small().color(theme::ACCENT));
                    unbind = ui.add(egui::Button::new(RichText::new("✕").small()).frame(false)).on_hover_text("Unbind: keep the value as typed, not where it came from").clicked();
                    label
                })
                .inner
            });
            let response = chip.response.union(chip.inner);
            let response = response.on_hover_text(format!("{}\nfrom {}\nas sent: {}", binding.shown, binding.anchor.describe(), text));
            if unbind {
                *bound = None;
            }
            response
        }
        None => {
            let response = ui.add(egui::TextEdit::singleline(text).desired_width(width).hint_text(hint).font(egui::TextStyle::Monospace));
            answer.changed = response.changed();
            answer.entered = response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            answer.text_box = Some(response.clone());
            response
        }
    };
    if response.dnd_hover_payload::<Carry>().is_some() {
        ui.painter().rect_stroke(response.rect.expand(2.0), 3.0, egui::Stroke::new(1.5, theme::CURSOR), egui::StrokeKind::Outside);
    }
    answer.dropped = response.dnd_release_payload::<Carry>().map(|carry| (*carry).clone());
    answer
}

/// Make `response`, a result row's, a source the row's carry can be dragged
/// from onto a bound field.
pub fn drag_source(response: &egui::Response, carry: impl FnOnce() -> Carry) {
    if response.drag_started() {
        response.dnd_set_drag_payload(carry());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Launch;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        app
    }

    #[test]
    fn text_carried_into_a_key_is_its_bytes_as_hex_found_again_as_hex() {
        let mut app = app_with(b"0123");
        let found = Anchor::Var { var: "serial".into() };
        let carry = Carry::value(Carried::Text("NC5".into()), Some(found.clone()), "$serial", "doc-1");
        let filled = carry.as_hex(&mut app).unwrap();
        assert_eq!(filled.text, "4e4335");
        let bound = filled.bound.unwrap();
        assert_eq!(bound.anchor, text_to_hex(found));
        assert_eq!((bound.shown.as_str(), bound.from.as_str()), ("NC5", "$serial"));
    }

    #[test]
    fn bytes_carried_into_a_key_are_read_from_their_sheet_without_an_anchor() {
        let mut app = app_with(b"\x01\x02\x03\x04");
        let sheet = app.document_id();
        let carry = Carry::bytes(sheet, vec![(1, 2)], DerivedFrom::new(), "the selection");
        assert_eq!(carry.as_hex(&mut app), Some(Filled { text: "0203".into(), bound: None }));
        let too_many = Carry::bytes(app.document_id(), vec![(0, MOST_CARRIED_BYTES + 1)], DerivedFrom::new(), "the selection");
        assert_eq!(too_many.as_hex(&mut app), None);
    }

    #[test]
    fn a_name_is_suggested_from_the_text_s_first_word() {
        let carry = |text: &str| Carry::value(Carried::Text(text.into()), None, "", "doc-1");
        assert_eq!(suggested_name(&carry("NC500-2F357657")), "nc500");
        assert_eq!(suggested_name(&carry("--")), "value");
        assert_eq!(suggested_name(&Carry::Sheet("doc-1".into())), "value");
    }

    #[test]
    fn the_selection_sent_to_a_new_worksheet_is_derived_from_its_sheet_with_output_new() {
        let mut app = app_with(b"0123456789");
        let parent = app.document_id();
        app.perform("selection.set", json!({"selection": {"range": [2, 4]}})).unwrap();
        let carry = app.selection_carry().expect("something is selected");
        crate::actions::take_performed();
        new_worksheet(&mut app, &carry).unwrap();
        let performed = crate::actions::take_performed();
        assert_eq!(performed, [("documents.derive".to_string(), json!({"doc": parent, "start": 2, "len": 4, "output": "new"}))]);
        assert_eq!(app.document.read_range(0, 4), b"2345");
        assert_eq!(app.sheets().len(), 2, "the parent stays open beside it");
        let made = app.journal.entries().last().unwrap();
        assert_eq!(made.made, [app.document_id()], "the step made the sheet, so a recipe keeps it");
    }

    #[test]
    fn a_match_of_the_find_box_carries_the_anchor_that_selected_it() {
        let mut app = app_with(b"..PK....PK..");
        app.search_mode = crate::search::SearchMode::Text;
        app.search_text = "PK".to_string();
        app.set_cursor(3, false);
        app.find_next();
        let Some(Carry::Bytes(bytes)) = app.selection_carry() else { panic!("the match is carried as bytes") };
        assert_eq!(bytes.ranges, [(8, 2)]);
        let found = Anchor::Find { find: anchors::Needle::Text("PK".into()), nth: 1, part: None };
        assert_eq!(bytes.derived_from.get("ranges[0][0]"), Some(&found));
        assert_eq!(bytes.from, found.describe());
    }

    #[test]
    fn send_to_offers_the_inputs_that_take_the_carry() {
        let app = app_with(b"0123");
        let text = Carry::value(Carried::Text("NC500".into()), None, "", "doc-1");
        let targets: Vec<Target> = slots(&app, &text).into_iter().map(|slot| slot.target).collect();
        assert!(targets.contains(&Target::TransformKey) && targets.contains(&Target::SearchNeedle), "{targets:?}");
        assert!(!targets.contains(&Target::BitsOffset) && !targets.contains(&Target::CrcRecords));
        let number = Carry::value(Carried::Number(3), None, "", "doc-1");
        let targets: Vec<Target> = crate::panel_bits::slots(&number).into_iter().map(|slot| slot.target).collect();
        assert_eq!(targets, [Target::BitsOffset]);
    }

    #[test]
    fn a_carry_sent_from_a_menu_waits_for_the_frame_to_be_drawn() {
        let mut app = app_with(b"0123");
        let carry = Carry::value(Carried::Text("AB".into()), None, "", app.document_id());
        send_later(&mut app, Sending::To(Target::TransformKey), carry);
        assert_ne!(app.inputs.key_text, "4142");
        app.perform_waiting_actions();
        assert_eq!(app.inputs.key_text, "4142");
        assert!(app.status.starts_with("The Selection menu's key is AB"), "{}", app.status);
    }
}
