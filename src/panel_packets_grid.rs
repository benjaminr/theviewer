//! The packet viewer's raster and hex grids, its splitting rules, and
//! operations on whole columns.
//!
//! Every packet is one row starting at its first byte, so the same field
//! lines up vertically across packets. The raster draws a byte per pixel
//! (byte class or a palette); the hex grid writes each byte. A strip above
//! the columns classifies each byte offset across the packets (constant,
//! counter, few values, random…) so fields stand out.
//!
//! Clicking a byte selects it in the main view (drag selects a run within
//! the packet; Shift extends). Clicking the ruler, the strip, or Alt-clicking
//! a byte selects whole columns, which can then be inverted, filled, XORed,
//! added to, set, numbered, byte-swapped, copied or deleted in every packet as
//! one undoable edit. Clicking a row's number selects that packet.
//!
//! The rows are read from the document whenever it, the packets or the
//! filter change, so edits anywhere show at once and the grid keeps its
//! scroll position. Only the visible rows and columns are drawn.

use eframe::egui::{self, Align2, Color32, ColorImage, FontId, Modifiers, Pos2, Rect, RichText, Sense, Stroke, TextureHandle, TextureOptions, Ui, Vec2, pos2, vec2};

use crate::api::packet_sets::{ColumnFormat, ColumnOp, ColumnsText, LengthFieldFound, LengthFieldSpec, PacketEditResult, PatternPlace};
use crate::app::ViewerApp;
use crate::columns::ColumnKind;
use crate::packets::edit;
use crate::packets::grid::{self, Alignment, ColumnOperation, ColumnSlice, RowPlacement};
use crate::packets::sources::Recipe;
use crate::packets::split::{self, BytePattern, LengthCounts, LengthEncoding, LengthField, PatternMode};
use crate::packets::{self, Layer};
use crate::panel_packets::{self as panel, Expected, Note, PacketsState};
use crate::panel_packets_view as view;
use crate::plugin::Category;
use crate::raster::{Palette, byte_class_colour};
use crate::theme;

/// Most bytes read for the grid's rows altogether.
const GRID_READ_LIMIT: usize = 128 * 1024 * 1024;
/// Share of the pane's height the grid takes.
const GRID_SHARE: f32 = 0.6;
const MIN_GRID_HEIGHT: f32 = 160.0;
/// Raster pixel sizes.
const MIN_ZOOM: f32 = 1.0;
const MAX_ZOOM: f32 = 32.0;
const DEFAULT_ZOOM: f32 = 6.0;
/// Hex grid geometry.
const HEX_CELL: Vec2 = vec2(22.0, 16.0);
const HEX_FONT_SIZE: f32 = 12.0;
const ASCII_WIDTH: f32 = 8.0;
const ASCII_GAP: f32 = 12.0;
/// Width of the row numbers on the left.
const LABEL_WIDTH: f32 = 58.0;
/// Heights of the column-kind strip and the ruler under it.
const STRIP_HEIGHT: f32 = 7.0;
const RULER_HEIGHT: f32 = 14.0;
const HEADER_HEIGHT: f32 = STRIP_HEIGHT + RULER_HEIGHT;
const RULER_FONT_SIZE: f32 = 9.0;
/// Least room between ruler labels and between row labels.
const RULER_LABEL_SPACING: f32 = 30.0;
const ROW_LABEL_SPACING: f32 = 12.0;
const LABEL_FONT_SIZE: f32 = 10.0;
/// Most pixels uploaded for one frame of the raster.
const MAX_RASTER_PIXELS: usize = 8 * 1024 * 1024;
/// Brightness above which a byte's value is written in black.
const LIGHT_PIXEL: f32 = 0.55;
/// Default bytes per row for the fixed-width rule.
const DEFAULT_ROW_WIDTH: usize = 16;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// How the packets are shown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PacketLayout {
    #[default]
    List,
    Raster,
    Hex,
}

impl PacketLayout {
    pub const ALL: [PacketLayout; 3] = [PacketLayout::List, PacketLayout::Raster, PacketLayout::Hex];

    pub fn label(self) -> &'static str {
        match self {
            PacketLayout::List => "List",
            PacketLayout::Raster => "Raster",
            PacketLayout::Hex => "Hex",
        }
    }
}

/// How the raster colours a byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Colouring {
    /// Zero, text, control, high and 0xFF bytes in their own colours.
    ByteClass,
    /// The byte's value through a palette (grey, viridis…).
    Value(Palette),
}

impl Colouring {
    pub const ALL: [Colouring; 6] = [
        Colouring::ByteClass,
        Colouring::Value(Palette::Grey),
        Colouring::Value(Palette::Viridis),
        Colouring::Value(Palette::Inferno),
        Colouring::Value(Palette::Ocean),
        Colouring::Value(Palette::Amber),
    ];

    pub fn label(self) -> &'static str {
        match self {
            Colouring::ByteClass => "Byte class",
            Colouring::Value(palette) => palette.label(),
        }
    }

    pub fn colour(self, byte: u8) -> Color32 {
        match self {
            Colouring::ByteClass => byte_class_colour(byte),
            Colouring::Value(palette) => palette.lut()[byte as usize],
        }
    }
}

/// What the rows are lined up on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AlignChoice {
    #[default]
    Start,
    Pattern,
    End,
}

impl AlignChoice {
    pub const ALL: [AlignChoice; 3] = [AlignChoice::Start, AlignChoice::Pattern, AlignChoice::End];

    pub fn label(self) -> &'static str {
        match self {
            AlignChoice::Start => "Align: packet start",
            AlignChoice::Pattern => "Align: on a pattern",
            AlignChoice::End => "Align: packet end",
        }
    }
}

/// Which rule the "Split into frames" controls use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SplitRule {
    FixedWidth,
    #[default]
    LengthField,
    Pattern,
}

impl SplitRule {
    pub const ALL: [SplitRule; 3] = [SplitRule::FixedWidth, SplitRule::LengthField, SplitRule::Pattern];

    pub fn label(self) -> &'static str {
        match self {
            SplitRule::FixedWidth => "Fixed width",
            SplitRule::LengthField => "Length field",
            SplitRule::Pattern => "Pattern",
        }
    }
}

/// The "Split into frames" form.
pub struct SplitForm {
    pub rule: SplitRule,
    /// Split the whole document rather than the selection.
    pub whole_document: bool,
    /// Bytes skipped at the start of the range before the first frame.
    pub skip: usize,
    pub row_width: usize,
    pub field: LengthField,
    /// Header length for a field that counts the payload only.
    pub header_len: usize,
    pub pattern_text: String,
    pub pattern_mode: PatternMode,
}

impl Default for SplitForm {
    fn default() -> Self {
        SplitForm {
            rule: SplitRule::default(),
            whole_document: false,
            skip: 0,
            row_width: DEFAULT_ROW_WIDTH,
            field: LengthField::default(),
            header_len: 0,
            pattern_text: String::new(),
            pattern_mode: PatternMode::default(),
        }
    }
}

/// What the rows were read for; reading again is needed when it changes.
#[derive(Clone, Debug, PartialEq)]
struct RowsKey {
    rows_generation: u64,
    version: u64,
    include_headers: bool,
    alignment: Alignment,
    visible: Vec<usize>,
}

/// The grid's rows, read from the document.
#[derive(Default)]
struct GridRows {
    key: Option<RowsKey>,
    /// Counts readings, so the raster knows when to redraw.
    generation: u64,
    /// The packet shown in each row.
    packets: Vec<usize>,
    placements: Vec<RowPlacement>,
    data: Vec<u8>,
    /// Where each row's bytes sit in `data`.
    spans: Vec<(usize, usize)>,
    columns: usize,
    kinds: Vec<Option<ColumnKind>>,
    /// The field each column holds in every dissected row, such as
    /// "Transaction ID (DNS)", where the rows agree.
    fields: Vec<Option<String>>,
    /// Some rows were cut short by the read limits.
    truncated: bool,
}

impl GridRows {
    fn row_bytes(&self, row: usize) -> &[u8] {
        self.spans.get(row).map_or(&[], |&(start, len)| &self.data[start..start + len])
    }

    /// The byte in grid cell `(row, column)`, with its document offset.
    fn cell(&self, row: usize, column: usize) -> Option<(usize, u8)> {
        let placement = self.placements.get(row)?;
        let within = placement.packet_offset(column)?;
        let byte = *self.row_bytes(row).get(within)?;
        Some((placement.offset + within, byte))
    }
}

/// A drag in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Drag {
    /// Selecting columns from `anchor`.
    Columns { anchor: usize },
    /// Selecting bytes of one row from document offset `anchor`.
    Bytes { row: usize, anchor: usize },
    /// Selecting a block of rows and columns from a corner cell.
    Block { anchor_row: usize, anchor_column: usize },
}

/// Where the ruler was last drawn: the screen x of column 0's left edge, the
/// ruler's middle y, and the width of a column. For tests and tooling.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RulerPlace {
    pub column_zero_x: f32,
    pub y: f32,
    pub column_width: f32,
}

impl RulerPlace {
    /// Screen position of the middle of `column` on the ruler.
    pub fn column_centre(&self, column: usize) -> Pos2 {
        pos2(self.column_zero_x + (column as f32 + 0.5) * self.column_width, self.y)
    }
}

/// Everything the grids keep between frames.
pub struct GridState {
    pub layout: PacketLayout,
    pub colouring: Colouring,
    /// Raster pixel size.
    pub zoom: f32,
    pub values_in_pixels: bool,
    pub show_ascii: bool,
    /// Rows show pcap and pcapng record headers as well as packet data.
    pub include_record_headers: bool,
    pub align: AlignChoice,
    pub align_text: String,
    pub align_error: Option<String>,
    /// Column operations change only the selected packets.
    pub only_selected: bool,
    /// Selected columns, as `(first, width)`.
    pub columns: Option<(usize, usize)>,
    /// The rows those columns cover, as `(first row, count)`: a block dragged
    /// out of the grid. `None` when the whole columns are selected.
    pub block_rows: Option<(usize, usize)>,
    pub operation_text: String,
    pub little_endian: bool,
    pub counter_start: u64,
    pub counter_step: i64,
    pub split: SplitForm,
    pub ruler: Option<RulerPlace>,
    drag: Option<Drag>,
    rows: GridRows,
    texture: Option<TextureHandle>,
    texture_key: Option<(u64, [usize; 4], Colouring)>,
}

impl Default for GridState {
    fn default() -> Self {
        GridState {
            layout: PacketLayout::default(),
            colouring: Colouring::ByteClass,
            zoom: DEFAULT_ZOOM,
            values_in_pixels: false,
            show_ascii: true,
            include_record_headers: false,
            align: AlignChoice::default(),
            align_text: String::new(),
            align_error: None,
            only_selected: false,
            columns: None,
            block_rows: None,
            operation_text: String::new(),
            little_endian: false,
            counter_start: 0,
            counter_step: 1,
            split: SplitForm::default(),
            ruler: None,
            drag: None,
            rows: GridRows::default(),
            texture: None,
            texture_key: None,
        }
    }
}

impl GridState {
    /// Number of rows read for the grid.
    pub fn row_count(&self) -> usize {
        self.rows.placements.len()
    }

    /// Columns the grid spans.
    pub fn column_count(&self) -> usize {
        self.rows.columns
    }

    /// Each row's shift right, in columns.
    pub fn shifts(&self) -> Vec<usize> {
        self.rows.placements.iter().map(|placement| placement.shift).collect()
    }
}

// ---------------------------------------------------------------------------
// Splitting rules
// ---------------------------------------------------------------------------

/// The document range a rule splits: the selection or the whole document,
/// after the bytes to skip.
fn split_range(state: &PacketsState, app: &ViewerApp) -> Option<(usize, usize)> {
    let form = &state.grid.split;
    let (start, len) = match app.selection() {
        Some(selection) if !form.whole_document => selection,
        _ => (0, app.document.len()),
    };
    let skip = form.skip.min(len);
    (len > skip).then_some((start + skip, len - skip))
}

/// The length field as the form describes it.
fn form_field(form: &SplitForm) -> LengthField {
    let mut field = form.field;
    if let LengthCounts::Payload { .. } = field.counts {
        field.counts = LengthCounts::Payload { header_len: form.header_len };
    }
    field
}

/// `packets.sets.create` splitting `start`, `len` by the form's rule, or a
/// note saying why the form cannot be split by.
fn split_rule_call(state: &PacketsState, app: &ViewerApp, start: usize, len: usize) -> Result<serde_json::Value, String> {
    let form = &state.grid.split;
    let params = match form.rule {
        SplitRule::FixedWidth => serde_json::json!({ "from": "split_fixed", "start": start, "len": len, "record_len": form.row_width }),
        SplitRule::LengthField => serde_json::json!({ "from": "length_field", "start": start, "len": len, "length_field": LengthFieldSpec::of(&form_field(form)) }),
        SplitRule::Pattern => {
            BytePattern::parse(&form.pattern_text).map_err(|reason| format!("The pattern could not be read: {reason}."))?;
            serde_json::json!({ "from": "pattern", "start": start, "len": len, "pattern": form.pattern_text, "pattern_mode": PatternPlace::of(form.pattern_mode) })
        }
    };
    let mut params = params;
    params.as_object_mut().expect("an object").extend(panel::current_decoding(state, app));
    Ok(params)
}

/// Split the selection or the document by the form's rule and show the
/// frames, as `packets.sets.create` once the viewer is drawn.
pub fn split_now(state: &mut PacketsState, app: &mut ViewerApp) {
    let Some((start, len)) = split_range(state, app) else {
        state.note = Some(Note { text: "There are no bytes to split: the range is empty.".to_string(), is_error: true });
        return;
    };
    match split_rule_call(state, app, start, len) {
        Ok(params) => panel::ask_after_drawing(state, app, "packets.sets.create", params, Expected::Split { start, len }),
        Err(note) => state.note = Some(Note { text: note, is_error: true }),
    }
}

/// Fill the length-field form from the protocol tool's framing detection,
/// asked of `packets.detect_length_field`.
pub fn detect_length_field(state: &mut PacketsState, app: &mut ViewerApp) {
    let Some((start, len)) = split_range(state, app) else {
        state.note = Some(Note { text: "There are no bytes to look at: the range is empty.".to_string(), is_error: true });
        return;
    };
    let found = match app.perform_typed::<LengthFieldFound>("packets.detect_length_field", serde_json::json!({ "start": start, "len": len })) {
        Ok(found) => found,
        Err(_) => {
            state.note = Some(Note { text: app.status.clone(), is_error: true });
            return;
        }
    };
    let text = match (&found.length_field, &found.description) {
        (Some(spec), Some(description)) => {
            let form = &mut state.grid.split;
            form.field = LengthField { max_frame: form.field.max_frame, ..spec.field() };
            form.rule = SplitRule::LengthField;
            format!("Found a {description} ({} frames, {:.0}% of the bytes). Press Split to use it.", found.frames, found.coverage * 100.0)
        }
        _ => match &found.best_framing {
            Some(best) => format!("No length field found; the best framing is {best}."),
            None => "No framing found in these bytes.".to_string(),
        },
    };
    state.note = Some(Note { is_error: found.length_field.is_none(), text });
}

/// The "Split into frames" controls.
pub fn show_split_rules(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    egui::CollapsingHeader::new("Split into frames").id_salt("packets-split-rules").show(ui, |ui| {
        let selection = app.selection();
        let form = &mut state.grid.split;
        ui.horizontal_wrapped(|ui| {
            for rule in SplitRule::ALL {
                ui.selectable_value(&mut form.rule, rule, rule.label());
            }
            ui.separator();
            let selection_label = selection.map_or("Selection (none)".to_string(), |(_, len)| format!("Selection ({len} B)"));
            if ui.add_enabled(selection.is_some(), egui::RadioButton::new(!form.whole_document && selection.is_some(), selection_label)).clicked() {
                form.whole_document = false;
            }
            if ui.radio(form.whole_document || selection.is_none(), "Whole document").clicked() {
                form.whole_document = true;
            }
            ui.label("skip");
            ui.add(egui::DragValue::new(&mut form.skip).range(0..=usize::MAX).suffix(" B")).on_hover_text("Bytes before the first frame");
        });
        match form.rule {
            SplitRule::FixedWidth => show_fixed_width_form(form, app.shape.row_stride(), ui),
            SplitRule::LengthField => show_length_form(form, ui),
            SplitRule::Pattern => show_pattern_form(form, ui),
        }
        let mut detect = false;
        let mut split = false;
        ui.horizontal_wrapped(|ui| {
            split = ui.button("Split").on_hover_text("Cut the range into frames by this rule and show them, one per row").clicked();
            if state.grid.split.rule == SplitRule::LengthField {
                detect = ui
                    .button("Auto-detect")
                    .on_hover_text("Ask the protocol tool's framing detection for a length field, and fill it in")
                    .clicked();
            }
        });
        if detect {
            detect_length_field(state, app);
        }
        if split {
            split_now(state, app);
        }
    });
}

fn show_fixed_width_form(form: &mut SplitForm, stride: usize, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.label("Bytes per row");
        ui.add(egui::DragValue::new(&mut form.row_width).range(1..=grid::MAX_GRID_COLUMNS));
        if ui.small_button(format!("Use the view's width ({stride} B)")).clicked() {
            form.row_width = stride.max(1);
        }
    });
}

fn show_length_form(form: &mut SplitForm, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.label("Length field at +");
        ui.add(egui::DragValue::new(&mut form.field.offset).range(0..=4096));
        view::start_row_unless_fits(ui, view::combo_width(ui));
        egui::ComboBox::from_id_salt("split-length-encoding").selected_text(form.field.encoding.label()).show_ui(ui, |ui| {
            for encoding in LengthEncoding::ALL {
                ui.selectable_value(&mut form.field.encoding, encoding, encoding.label());
            }
        });
        if form.field.encoding.has_byte_order() {
            ui.checkbox(&mut form.field.big_endian, "big endian");
        }
        view::start_row_unless_fits(ui, view::combo_width(ui));
        let counts_choices = [LengthCounts::WholeFrame, LengthCounts::AfterField, LengthCounts::Payload { header_len: form.header_len }];
        egui::ComboBox::from_id_salt("split-length-counts").selected_text(format!("counts the {}", form.field.counts.label())).show_ui(ui, |ui| {
            for counts in counts_choices {
                let chosen = std::mem::discriminant(&form.field.counts) == std::mem::discriminant(&counts);
                if ui.selectable_label(chosen, counts.label()).clicked() {
                    form.field.counts = counts;
                }
            }
        });
        if let LengthCounts::Payload { .. } = form.field.counts {
            ui.label("header");
            ui.add(egui::DragValue::new(&mut form.header_len).range(0..=4096).suffix(" B"));
        }
        ui.label("±");
        ui.add(egui::DragValue::new(&mut form.field.adjustment).range(-4096..=4096)).on_hover_text("Added to the length, for a trailer the field does not count (or a byte it counts twice)");
        ui.label("longest");
        ui.add(egui::DragValue::new(&mut form.field.max_frame).range(1..=16 * 1024 * 1024).suffix(" B"))
            .on_hover_text("A longer length is taken as the end of the frames");
    });
}

fn show_pattern_form(form: &mut SplitForm, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.add(egui::TextEdit::singleline(&mut form.pattern_text).hint_text("AA 55 ?? 01, 0D0A or \"text\"").desired_width(170.0))
            .on_hover_text("Hex bytes, ?? for any byte, or text in double quotes");
        view::start_row_unless_fits(ui, view::combo_width(ui));
        egui::ComboBox::from_id_salt("split-pattern-mode").selected_text(form.pattern_mode.label()).show_ui(ui, |ui| {
            for mode in PatternMode::ALL {
                ui.selectable_value(&mut form.pattern_mode, mode, mode.label());
            }
        });
    });
    if !form.pattern_text.trim().is_empty()
        && let Err(reason) = BytePattern::parse(&form.pattern_text)
    {
        ui.label(RichText::new(reason).small().color(theme::DANGER));
    }
}

// ---------------------------------------------------------------------------
// Reading the rows
// ---------------------------------------------------------------------------

/// The alignment the controls ask for; a pattern that does not parse leaves
/// the rows unshifted and says why.
fn chosen_alignment(grid: &mut GridState) -> Alignment {
    grid.align_error = None;
    match grid.align {
        AlignChoice::Start => Alignment::Start,
        AlignChoice::End => Alignment::End,
        AlignChoice::Pattern if grid.align_text.trim().is_empty() => Alignment::Start,
        AlignChoice::Pattern => match BytePattern::parse(&grid.align_text) {
            Ok(pattern) => Alignment::Pattern(pattern),
            Err(reason) => {
                grid.align_error = Some(reason);
                Alignment::Start
            }
        },
    }
}

/// Read the rows again when the document, the packets, the filter or the
/// layout options changed.
pub fn refresh_rows(state: &mut PacketsState, app: &mut ViewerApp) {
    let alignment = chosen_alignment(&mut state.grid);
    let key = RowsKey {
        rows_generation: state.rows_generation,
        version: app.document.version(),
        include_headers: state.grid.include_record_headers,
        alignment,
        visible: state.visible.clone(),
    };
    if state.grid.rows.key.as_ref() == Some(&key) {
        return;
    }
    let mut rows = GridRows { generation: state.grid.rows.generation + 1, ..GridRows::default() };
    if let Some(set) = &state.set {
        for &index in &key.visible {
            let Some(packet) = set.packets.get(index) else { continue };
            let (offset, len) = if key.include_headers { packet.record.unwrap_or((packet.offset, packet.len)) } else { (packet.offset, packet.len) };
            let room = GRID_READ_LIMIT.saturating_sub(rows.data.len());
            let want = len.min(grid::MAX_GRID_COLUMNS).min(room);
            rows.truncated |= want < len.min(grid::MAX_GRID_COLUMNS);
            let start = rows.data.len();
            rows.data.resize(start + want, 0);
            let read = app.document.read_into(offset, &mut rows.data[start..]);
            rows.data.truncate(start + read);
            rows.spans.push((start, read));
            rows.packets.push(index);
            rows.placements.push(RowPlacement { offset, len, shift: 0 });
        }
    }
    let slices: Vec<&[u8]> = (0..rows.spans.len()).map(|row| rows.row_bytes(row)).collect();
    let shifts = grid::row_shifts(&slices, &key.alignment);
    let columns = grid::grid_width(rows.placements.iter().map(|placement| placement.len), &shifts);
    let kinds = grid::column_kinds(&slices, &shifts, columns);
    rows.columns = columns;
    rows.kinds = kinds;
    for (placement, shift) in rows.placements.iter_mut().zip(shifts) {
        placement.shift = shift;
    }
    rows.fields = column_fields(state, &rows);
    rows.key = Some(key);
    state.grid.rows = rows;
}

/// Name the columns from the dissections of the first rows, so a decoded
/// protocol's fields label the grid.
fn column_fields(state: &PacketsState, rows: &GridRows) -> Vec<Option<String>> {
    let dissected: Vec<(Vec<Layer>, usize)> = rows
        .packets
        .iter()
        .zip(&rows.placements)
        .take(grid::MAX_FIELD_ROWS)
        .filter_map(|(&index, placement)| {
            let packet = state.set.as_ref()?.packets.get(index)?;
            let link = state.rows.get(index)?.link;
            let dissection = packets::dissect_with(state.bytes.packet(index), link, &state.raw);
            // With record headers shown, the packet starts after its header.
            let lead = placement.shift + packet.offset.saturating_sub(placement.offset);
            Some((dissection.layers, lead))
        })
        .collect();
    let borrowed: Vec<(&[Layer], usize)> = dissected.iter().map(|(layers, lead)| (layers.as_slice(), *lead)).collect();
    grid::column_fields(&borrowed, rows.columns)
}

/// The field holding grid cell `(row, column)` in that row's own packet.
fn cell_field(state: &PacketsState, row: usize, column: usize) -> Option<String> {
    let rows = &state.grid.rows;
    let index = *rows.packets.get(row)?;
    let placement = rows.placements.get(row)?;
    let packet = state.set.as_ref()?.packets.get(index)?;
    let offset = placement.packet_offset(column)?.checked_sub(packet.offset.saturating_sub(placement.offset))?;
    let dissection = packets::dissect_with(state.bytes.packet(index), state.rows.get(index)?.link, &state.raw);
    grid::field_at(&dissection.layers, offset)
}

/// The fields the columns `first..first + width` hold, for naming a
/// selection: up to three, in order.
fn selected_fields(rows: &GridRows, first: usize, width: usize) -> Vec<&str> {
    const MOST_NAMED: usize = 3;
    let mut names: Vec<&str> = Vec::new();
    for name in rows.fields.iter().skip(first).take(width).flatten() {
        if names.last() != Some(&name.as_str()) && !names.contains(&name.as_str()) {
            names.push(name);
        }
    }
    names.truncate(MOST_NAMED);
    names
}

// ---------------------------------------------------------------------------
// The view
// ---------------------------------------------------------------------------

/// The List · Raster · Hex choice.
pub fn show_layout_choice(state: &mut PacketsState, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        for layout in PacketLayout::ALL {
            ui.selectable_value(&mut state.grid.layout, layout, layout.label());
        }
        if let Some(lengths) = state.set.as_ref().and_then(split::frame_lengths) {
            ui.label(RichText::new(lengths.to_string()).small().color(theme::TEXT_DIM));
        }
    });
}

/// The raster or hex grid with its controls and column operations.
pub fn show_grid_view(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    show_grid_controls(state, ui);
    refresh_rows(state, app);
    if state.grid.rows.placements.is_empty() {
        ui.label(RichText::new("No packets to lay out: the filter hides them all.").color(theme::TEXT_DIM));
        return;
    }
    if state.grid.rows.truncated {
        let text = format!("Rows are cut off at {} bytes, and at {} read in all.", grid::MAX_GRID_COLUMNS, crate::compress::human_bytes(GRID_READ_LIMIT));
        ui.label(RichText::new(text).small().color(theme::TEXT_DIM));
    }
    let height = (state.pane_height * GRID_SHARE).max(MIN_GRID_HEIGHT);
    show_grid(state, app, ui, height);
    show_column_operations(state, app, ui);
}

fn show_grid_controls(state: &mut PacketsState, ui: &mut Ui) {
    let has_records = state.set.as_ref().is_some_and(|set| set.packets.iter().any(|packet| packet.record.is_some()));
    let grid = &mut state.grid;
    ui.horizontal_wrapped(|ui| {
        if grid.layout == PacketLayout::Raster {
            view::start_row_unless_fits(ui, view::combo_width(ui));
            egui::ComboBox::from_id_salt("packet-raster-colouring").selected_text(grid.colouring.label()).show_ui(ui, |ui| {
                for colouring in Colouring::ALL {
                    ui.selectable_value(&mut grid.colouring, colouring, colouring.label());
                }
            });
            ui.add(egui::Slider::new(&mut grid.zoom, MIN_ZOOM..=MAX_ZOOM).step_by(1.0).text("pixel size"));
            ui.checkbox(&mut grid.values_in_pixels, "Show values inside pixels").on_hover_text(format!(
                "Write each byte's hex inside its pixel at {} px and larger",
                crate::view::HEX_LABEL_MIN_ZOOM.ceil()
            ));
        } else {
            ui.checkbox(&mut grid.show_ascii, "ASCII");
        }
        view::start_row_unless_fits(ui, view::combo_width(ui));
        egui::ComboBox::from_id_salt("packet-grid-align").selected_text(grid.align.label()).show_ui(ui, |ui| {
            for align in AlignChoice::ALL {
                ui.selectable_value(&mut grid.align, align, align.label());
            }
        });
        if grid.align == AlignChoice::Pattern {
            ui.add(egui::TextEdit::singleline(&mut grid.align_text).hint_text("pattern, e.g. 7E ?? 01").desired_width(130.0))
                .on_hover_text("Shift each row so the first match lines up; hex with ?? wildcards, or \"text\"");
        }
        if has_records {
            ui.checkbox(&mut grid.include_record_headers, "Record headers").on_hover_text("Start each row at its pcap or pcapng record header rather than the packet data");
        }
    });
    if let Some(error) = &grid.align_error {
        ui.label(RichText::new(format!("Not aligned: {error}")).small().color(theme::DANGER));
    }
}

/// Sizes of the grid's parts.
#[derive(Clone, Copy, Debug)]
struct Geometry {
    cell: Vec2,
    columns: usize,
    rows: usize,
    ascii: bool,
}

impl Geometry {
    fn for_state(grid: &GridState) -> Geometry {
        let raster = grid.layout == PacketLayout::Raster;
        let cell = if raster { Vec2::splat(grid.zoom.clamp(MIN_ZOOM, MAX_ZOOM)) } else { HEX_CELL };
        Geometry { cell, columns: grid.rows.columns, rows: grid.rows.placements.len(), ascii: !raster && grid.show_ascii }
    }

    /// Content x (from the grid's left edge) where the ASCII block starts.
    fn ascii_left(&self) -> f32 {
        LABEL_WIDTH + self.columns as f32 * self.cell.x + ASCII_GAP
    }

    fn content_size(&self) -> Vec2 {
        let width = if self.ascii { self.ascii_left() + self.columns as f32 * ASCII_WIDTH } else { LABEL_WIDTH + self.columns as f32 * self.cell.x };
        vec2(width, HEADER_HEIGHT + self.rows as f32 * self.cell.y)
    }

    /// Screen rectangle of a hex or raster cell.
    fn cell_rect(&self, content: Rect, row: usize, column: usize) -> Rect {
        let min = content.min + vec2(LABEL_WIDTH + column as f32 * self.cell.x, HEADER_HEIGHT + row as f32 * self.cell.y);
        Rect::from_min_size(min, self.cell)
    }

    fn ascii_rect(&self, content: Rect, row: usize, column: usize) -> Rect {
        let min = content.min + vec2(self.ascii_left() + column as f32 * ASCII_WIDTH, HEADER_HEIGHT + row as f32 * self.cell.y);
        Rect::from_min_size(min, vec2(ASCII_WIDTH, self.cell.y))
    }

    /// The grid column under screen x, from the hex/raster block or the ASCII block.
    fn column_at(&self, content: Rect, x: f32) -> Option<usize> {
        let local = x - content.min.x;
        let column = if self.ascii && local >= self.ascii_left() {
            ((local - self.ascii_left()) / ASCII_WIDTH).floor()
        } else if local >= LABEL_WIDTH && local < LABEL_WIDTH + self.columns as f32 * self.cell.x {
            ((local - LABEL_WIDTH) / self.cell.x).floor()
        } else {
            return None;
        };
        (column >= 0.0 && (column as usize) < self.columns).then_some(column as usize)
    }

    fn row_at(&self, content: Rect, y: f32) -> Option<usize> {
        let row = ((y - content.min.y - HEADER_HEIGHT) / self.cell.y).floor();
        (row >= 0.0 && (row as usize) < self.rows).then_some(row as usize)
    }

    /// What is under `position`, given the pinned ruler and row labels.
    fn hit(&self, content: Rect, visible: Rect, position: Pos2) -> Option<Hit> {
        if !visible.contains(position) {
            return None;
        }
        let in_header = position.y < visible.min.y + HEADER_HEIGHT;
        let in_labels = position.x < visible.min.x + LABEL_WIDTH;
        match (in_header, in_labels) {
            (true, true) => None,
            (true, false) => self.column_at(content, position.x).map(Hit::Ruler),
            (false, true) => self.row_at(content, position.y).map(Hit::Label),
            (false, false) => Some(Hit::Cell { row: self.row_at(content, position.y)?, column: self.column_at(content, position.x)? }),
        }
    }

    /// Rows and columns at least partly visible, as `[first_row, end_row,
    /// first_column, end_column]`.
    fn visible_cells(&self, viewport: Rect) -> [usize; 4] {
        let first_row = (viewport.min.y / self.cell.y).floor().max(0.0) as usize;
        let end_row = (((viewport.max.y - HEADER_HEIGHT) / self.cell.y).ceil().max(0.0) as usize).min(self.rows);
        let first_column = (viewport.min.x / self.cell.x).floor().max(0.0) as usize;
        let end_column = (((viewport.max.x - LABEL_WIDTH) / self.cell.x).ceil().max(0.0) as usize).min(self.columns);
        [first_row.min(end_row), end_row, first_column.min(end_column), end_column]
    }

    /// ASCII columns visible, as `(first, end)`.
    fn visible_ascii(&self, viewport: Rect) -> (usize, usize) {
        let first = ((viewport.min.x + LABEL_WIDTH - self.ascii_left()) / ASCII_WIDTH).floor().max(0.0) as usize;
        let end = (((viewport.max.x - self.ascii_left()) / ASCII_WIDTH).ceil().max(0.0) as usize).min(self.columns);
        (first.min(end), end)
    }
}

/// Part of the grid under the pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hit {
    Ruler(usize),
    Label(usize),
    Cell { row: usize, column: usize },
}

fn show_grid(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui, height: f32) {
    let geometry = Geometry::for_state(&state.grid);
    let mut area = egui::ScrollArea::both().id_salt("packet-grid").max_height(height).auto_shrink([false, true]);
    if let Some(index) = state.scroll_to_row.take()
        && let Some(row) = state.grid.rows.packets.iter().position(|&packet| packet == index)
    {
        area = area.vertical_scroll_offset((row as f32 * geometry.cell.y - height / 3.0).max(0.0));
    }
    let output = area.show_viewport(ui, |ui, viewport| {
        let (content, response) = ui.allocate_exact_size(geometry.content_size(), Sense::click_and_drag());
        let visible = Rect::from_min_size(content.min + viewport.min.to_vec2(), viewport.size());
        let cells_clip = Rect::from_min_max(visible.min + vec2(LABEL_WIDTH, HEADER_HEIGHT), visible.max);
        let cells = geometry.visible_cells(viewport);
        let cell_painter = ui.painter_at(cells_clip);
        match state.grid.layout {
            PacketLayout::Raster => paint_raster(state, ui, &cell_painter, &geometry, content, cells),
            _ => paint_hex(state, &cell_painter, &geometry, content, cells, viewport),
        }
        paint_selections(state, app, &cell_painter, &geometry, content, cells);
        let hover = response.hover_pos().and_then(|position| geometry.hit(content, visible, position));
        if let Some(Hit::Cell { row, column }) = hover {
            cell_painter.rect_stroke(geometry.cell_rect(content, row, column), 0.0, Stroke::new(1.0, theme::CURSOR), egui::StrokeKind::Inside);
        }
        paint_header(state, &ui.painter_at(visible), &geometry, content, visible, cells);
        paint_row_labels(state, &ui.painter_at(visible), &geometry, content, visible, cells);
        state.grid.ruler = Some(RulerPlace { column_zero_x: content.min.x + LABEL_WIDTH, y: visible.min.y + STRIP_HEIGHT + RULER_HEIGHT / 2.0, column_width: geometry.cell.x });
        handle_pointer(state, app, ui, &response, &geometry, content, visible);
        if let Some(hit) = hover {
            show_tooltip(state, &response, hit);
        }
    });
    state.list_hovered = ui.rect_contains_pointer(output.inner_rect);
}

/// Draw the visible part of the raster as one texture.
fn paint_raster(state: &mut PacketsState, ui: &Ui, painter: &egui::Painter, geometry: &Geometry, content: Rect, cells: [usize; 4]) {
    let [first_row, end_row, first_column, end_column] = cells;
    let (width, height) = (end_column - first_column, end_row - first_row);
    if width == 0 || height == 0 || width * height > MAX_RASTER_PIXELS {
        return;
    }
    let grid = &mut state.grid;
    let key = (grid.rows.generation, cells, grid.colouring);
    if grid.texture_key != Some(key) || grid.texture.is_none() {
        let mut pixels = vec![Color32::TRANSPARENT; width * height];
        for (line, row) in pixels.chunks_mut(width).zip(first_row..end_row) {
            for (pixel, column) in line.iter_mut().zip(first_column..end_column) {
                if let Some((_, byte)) = grid.rows.cell(row, column) {
                    *pixel = grid.colouring.colour(byte);
                }
            }
        }
        let image = ColorImage::new([width, height], pixels);
        match &mut grid.texture {
            Some(texture) => texture.set(image, TextureOptions::NEAREST),
            None => grid.texture = Some(ui.ctx().load_texture("packet-raster", image, TextureOptions::NEAREST)),
        }
        grid.texture_key = Some(key);
    }
    let Some(texture) = &grid.texture else { return };
    let rect = Rect::from_min_max(geometry.cell_rect(content, first_row, first_column).min, geometry.cell_rect(content, end_row - 1, end_column - 1).max);
    painter.image(texture.id(), rect, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
    if grid.values_in_pixels && geometry.cell.x >= crate::view::HEX_LABEL_MIN_ZOOM && width * height <= crate::view::MAX_TEXT_SHAPES_PER_FRAME {
        let font = FontId::monospace(HEX_FONT_SIZE.min(geometry.cell.y * 0.6));
        for row in first_row..end_row {
            for column in first_column..end_column {
                let Some((_, byte)) = grid.rows.cell(row, column) else { continue };
                let colour = if relative_brightness(grid.colouring.colour(byte)) > LIGHT_PIXEL { Color32::BLACK } else { Color32::WHITE };
                painter.text(geometry.cell_rect(content, row, column).center(), Align2::CENTER_CENTER, format!("{byte:02X}"), font.clone(), colour);
            }
        }
    }
}

fn relative_brightness(colour: Color32) -> f32 {
    (0.299 * colour.r() as f32 + 0.587 * colour.g() as f32 + 0.114 * colour.b() as f32) / 255.0
}

/// Write the visible bytes as hex, and as ASCII beside them.
fn paint_hex(state: &PacketsState, painter: &egui::Painter, geometry: &Geometry, content: Rect, cells: [usize; 4], viewport: Rect) {
    let [first_row, end_row, first_column, end_column] = cells;
    let rows = &state.grid.rows;
    let font = FontId::monospace(HEX_FONT_SIZE);
    for row in first_row..end_row {
        for column in first_column..end_column {
            let Some((_, byte)) = rows.cell(row, column) else { continue };
            let colour = if byte == 0 { theme::TEXT_DIM } else { byte_class_colour(byte) };
            painter.text(geometry.cell_rect(content, row, column).center(), Align2::CENTER_CENTER, format!("{byte:02x}"), font.clone(), colour);
        }
    }
    if !geometry.ascii {
        return;
    }
    let (first_ascii, end_ascii) = geometry.visible_ascii(viewport);
    for row in first_row..end_row {
        for column in first_ascii..end_ascii {
            let Some((_, byte)) = rows.cell(row, column) else { continue };
            let character = if (0x20..0x7F).contains(&byte) { byte as char } else { '.' };
            painter.text(geometry.ascii_rect(content, row, column).left_center(), Align2::LEFT_CENTER, character.to_string(), font.clone(), theme::TEXT_DIM);
        }
    }
}

/// Shade the selected columns, the main view's selection and its cursor.
fn paint_selections(state: &PacketsState, app: &ViewerApp, painter: &egui::Painter, geometry: &Geometry, content: Rect, cells: [usize; 4]) {
    let [first_row, end_row, ..] = cells;
    if first_row == end_row {
        return;
    }
    if let Some((first, width)) = state.grid.columns {
        // The whole columns, or just the block's rows, clipped to what is visible.
        let (block_first, block_end) = state.grid.block_rows.map_or((first_row, end_row), |(row, count)| (row, row + count));
        let (top_row, bottom_row) = (block_first.max(first_row), block_end.min(end_row));
        if top_row < bottom_row {
            let top = geometry.cell_rect(content, top_row, first).min;
            let bottom = geometry.cell_rect(content, bottom_row - 1, first + width - 1).max;
            let band = Rect::from_min_max(top, bottom);
            painter.rect_filled(band, 0.0, theme::SELECTION);
            painter.rect_stroke(band, 0.0, Stroke::new(1.0, theme::ACCENT), egui::StrokeKind::Inside);
        }
    }
    let rows = &state.grid.rows;
    let selection = app.selection();
    for row in first_row..end_row {
        let placement = rows.placements[row];
        if let Some((start, len)) = selection {
            let low = start.max(placement.offset);
            let high = (start + len).min(placement.offset + placement.len);
            if let (true, Some(from), Some(to)) = (low < high, placement.column_of(low), placement.column_of(high - 1)) {
                let rect = Rect::from_min_max(geometry.cell_rect(content, row, from).min, geometry.cell_rect(content, row, to).max);
                painter.rect_filled(rect, 0.0, theme::CURSOR_FILL);
                if geometry.ascii {
                    let ascii = Rect::from_min_max(geometry.ascii_rect(content, row, from).min, geometry.ascii_rect(content, row, to).max);
                    painter.rect_filled(ascii, 0.0, theme::CURSOR_FILL);
                }
            }
        }
        if let Some(column) = placement.column_of(app.cursor) {
            painter.rect_stroke(geometry.cell_rect(content, row, column), 0.0, Stroke::new(1.5, theme::CURSOR), egui::StrokeKind::Inside);
        }
    }
}

/// Colour of a column's kind in the strip above the columns.
fn kind_colour(kind: ColumnKind) -> Color32 {
    match kind {
        ColumnKind::Constant => Category::Padding.colour(),
        ColumnKind::Counter | ColumnKind::Monotonic => Category::Counter.colour(),
        ColumnKind::LowCardinality => Category::Structure.colour(),
        ColumnKind::Text => theme::CLASS_TEXT,
        ColumnKind::Random => Category::HighEntropy.colour(),
        ColumnKind::Mixed => theme::OUTLINE,
    }
}

/// Smallest power-of-two column step whose ruler labels do not collide.
fn ruler_step(column_width: f32) -> usize {
    let mut step = 1usize;
    while (step as f32) * column_width < RULER_LABEL_SPACING && step < grid::MAX_GRID_COLUMNS {
        step *= 2;
    }
    step
}

/// The pinned strip of column kinds and the ruler of byte offsets.
fn paint_header(state: &PacketsState, painter: &egui::Painter, geometry: &Geometry, content: Rect, visible: Rect, cells: [usize; 4]) {
    let [_, _, first_column, end_column] = cells;
    let header = Rect::from_min_size(visible.min, vec2(visible.width(), HEADER_HEIGHT));
    painter.rect_filled(header, 0.0, theme::PANEL);
    let header_painter = painter.with_clip_rect(Rect::from_min_max(header.min + vec2(LABEL_WIDTH, 0.0), header.max));
    let column_x = |column: usize| content.min.x + LABEL_WIDTH + column as f32 * geometry.cell.x;
    for column in first_column..end_column {
        if let Some(Some(kind)) = state.grid.rows.kinds.get(column) {
            let strip = Rect::from_min_size(pos2(column_x(column), header.min.y), vec2(geometry.cell.x.max(1.0), STRIP_HEIGHT - 1.0));
            header_painter.rect_filled(strip, 0.0, kind_colour(*kind));
        }
    }
    if let Some((first, width)) = state.grid.columns {
        let band = Rect::from_min_max(pos2(column_x(first), header.min.y + STRIP_HEIGHT), pos2(column_x(first + width), header.max.y));
        header_painter.rect_filled(band, 0.0, theme::ACCENT_DIM);
    }
    let step = ruler_step(geometry.cell.x);
    let font = FontId::monospace(RULER_FONT_SIZE);
    let first_tick = first_column / step * step;
    for column in (first_tick..end_column).step_by(step) {
        let x = column_x(column);
        header_painter.line_segment([pos2(x, header.max.y - 4.0), pos2(x, header.max.y)], Stroke::new(1.0, theme::TEXT_DIM));
        header_painter.text(pos2(x + 2.0, header.min.y + STRIP_HEIGHT), Align2::LEFT_TOP, column.to_string(), font.clone(), theme::TEXT_DIM);
    }
}

/// The pinned packet numbers down the left.
fn paint_row_labels(state: &PacketsState, painter: &egui::Painter, geometry: &Geometry, content: Rect, visible: Rect, cells: [usize; 4]) {
    let [first_row, end_row, ..] = cells;
    let labels = Rect::from_min_max(visible.min + vec2(0.0, HEADER_HEIGHT), pos2(visible.min.x + LABEL_WIDTH, visible.max.y));
    painter.rect_filled(labels, 0.0, theme::PANEL);
    let label_painter = painter.with_clip_rect(labels);
    let every = (ROW_LABEL_SPACING / geometry.cell.y).ceil().max(1.0) as usize;
    let font = FontId::monospace(LABEL_FONT_SIZE.min(geometry.cell.y.max(ROW_LABEL_SPACING) - 2.0));
    for row in first_row..end_row {
        let packet = state.grid.rows.packets[row];
        let top = content.min.y + HEADER_HEIGHT + row as f32 * geometry.cell.y;
        let band = Rect::from_min_size(pos2(labels.min.x, top), vec2(LABEL_WIDTH - 2.0, geometry.cell.y));
        if state.selected.contains(&packet) {
            label_painter.rect_filled(band, 0.0, theme::ACCENT_DIM);
        }
        if row % every == 0 {
            let colour = if state.focus == Some(packet) { theme::CURSOR } else { theme::TEXT_DIM };
            label_painter.text(pos2(band.max.x - 4.0, top), Align2::RIGHT_TOP, (packet + 1).to_string(), font.clone(), colour);
        }
    }
}

fn show_tooltip(state: &PacketsState, response: &egui::Response, hit: Hit) {
    let rows = &state.grid.rows;
    let kind_text = |column: usize| {
        let kind = match rows.kinds.get(column).copied().flatten() {
            Some(kind) => format!("column +{column}: {} ({})", kind.label(), kind.description()),
            None => format!("column +{column}"),
        };
        match rows.fields.get(column).and_then(Option::as_deref) {
            Some(field) => format!("{field} · {kind}"),
            None => kind,
        }
    };
    let text = match hit {
        Hit::Ruler(column) => format!("{} · click to select the column, drag for several", kind_text(column)),
        Hit::Label(row) => format!("Packet {} · click to select it (Shift or Cmd for several)", rows.packets[row] + 1),
        Hit::Cell { row, column } => {
            let packet = rows.packets[row] + 1;
            match (rows.cell(row, column), rows.placements[row].packet_offset(column)) {
                (Some((offset, byte)), Some(within)) => {
                    let character = if (0x20..0x7F).contains(&byte) { format!(" '{}'", byte as char) } else { String::new() };
                    let field = cell_field(state, row, column).map(|field| format!("\n{field}")).unwrap_or_default();
                    format!("Packet {packet} · +{within} · document {offset:#x} · {byte:#04x} = {byte}{character}{field}\n{}", kind_text(column))
                }
                _ => format!("Packet {packet} · no byte here"),
            }
        }
    };
    response.clone().on_hover_text_at_pointer(text);
}

// ---------------------------------------------------------------------------
// Pointer
// ---------------------------------------------------------------------------

fn handle_pointer(state: &mut PacketsState, app: &mut ViewerApp, ui: &Ui, response: &egui::Response, geometry: &Geometry, content: Rect, visible: Rect) {
    let modifiers = ui.input(|input| input.modifiers);
    let hit_at = |position: Option<Pos2>| position.and_then(|position| geometry.hit(content, visible, position));
    if response.drag_started() {
        let origin = ui.input(|input| input.pointer.press_origin());
        state.grid.drag = match hit_at(origin) {
            Some(Hit::Ruler(column)) => Some(Drag::Columns { anchor: column_anchor(state, column, modifiers) }),
            Some(Hit::Cell { column, .. }) if modifiers.alt => Some(Drag::Columns { anchor: column_anchor(state, column, modifiers) }),
            Some(Hit::Cell { row, column }) => state.grid.rows.cell(row, column).map(|(offset, _)| {
                let anchor = if modifiers.shift { app.anchor.unwrap_or(app.cursor) } else { offset };
                Drag::Bytes { row, anchor }
            }),
            _ => None,
        };
    }
    if response.dragged()
        && let Some(drag) = state.grid.drag
        && let Some(position) = response.interact_pointer_pos()
    {
        drag_to(state, app, geometry, content, drag, position);
    }
    if response.drag_stopped() {
        if let Some(Drag::Bytes { .. }) = state.grid.drag
            && let Some((start, len)) = app.selection()
        {
            panel::select_in_document(state, app, start, len, format!("{len} bytes"));
        }
        state.grid.drag = None;
    }
    if response.clicked() {
        match hit_at(response.interact_pointer_pos()) {
            Some(Hit::Ruler(column)) => click_column(state, column, modifiers),
            Some(Hit::Cell { column, .. }) if modifiers.alt => click_column(state, column, modifiers),
            Some(Hit::Cell { row, column }) => click_cell(state, app, row, column, modifiers),
            Some(Hit::Label(row)) => {
                let packet = state.grid.rows.packets[row];
                view::click_row(state, app, packet, modifiers);
            }
            None => {}
        }
    }
}

/// Where a column drag starts: the column, or the far end of the current
/// selection when Shift extends it.
fn column_anchor(state: &PacketsState, column: usize, modifiers: Modifiers) -> usize {
    match state.grid.columns {
        Some((first, width)) if modifiers.shift => {
            if column >= first { first } else { first + width - 1 }
        }
        _ => column,
    }
}

fn click_column(state: &mut PacketsState, column: usize, modifiers: Modifiers) {
    let anchor = column_anchor(state, column, modifiers);
    state.grid.columns = Some((anchor.min(column), anchor.abs_diff(column) + 1));
    state.grid.block_rows = None;
}

/// The column under screen x, clamped to the grid.
fn clamped_column(geometry: &Geometry, content: Rect, x: f32) -> usize {
    ((x - content.min.x - LABEL_WIDTH) / geometry.cell.x).floor().clamp(0.0, geometry.columns.saturating_sub(1) as f32) as usize
}

/// The row under screen y, clamped to the grid.
fn clamped_row(geometry: &Geometry, content: Rect, y: f32) -> usize {
    ((y - content.min.y - HEADER_HEIGHT) / geometry.cell.y).floor().clamp(0.0, geometry.rows.saturating_sub(1) as f32) as usize
}

/// Select the block between two corner cells.
fn select_block(state: &mut PacketsState, (row_a, column_a): (usize, usize), (row_b, column_b): (usize, usize)) {
    state.grid.columns = Some((column_a.min(column_b), column_a.abs_diff(column_b) + 1));
    state.grid.block_rows = Some((row_a.min(row_b), row_a.abs_diff(row_b) + 1));
}

fn drag_to(state: &mut PacketsState, app: &mut ViewerApp, geometry: &Geometry, content: Rect, drag: Drag, position: Pos2) {
    match drag {
        Drag::Columns { anchor } => {
            let column = clamped_column(geometry, content, position.x);
            state.grid.columns = Some((anchor.min(column), anchor.abs_diff(column) + 1));
            state.grid.block_rows = None;
        }
        Drag::Block { anchor_row, anchor_column } => {
            let corner = (clamped_row(geometry, content, position.y), clamped_column(geometry, content, position.x));
            select_block(state, (anchor_row, anchor_column), corner);
        }
        // Leaving the packet the drag started in turns it into a block.
        Drag::Bytes { row, anchor } if clamped_row(geometry, content, position.y) != row => {
            let anchor_column = state.grid.rows.placements[row].column_of(anchor).unwrap_or(0);
            state.grid.drag = Some(Drag::Block { anchor_row: row, anchor_column });
            let corner = (clamped_row(geometry, content, position.y), clamped_column(geometry, content, position.x));
            select_block(state, (row, anchor_column), corner);
        }
        Drag::Bytes { row, anchor } => {
            let placement = state.grid.rows.placements[row];
            let column = geometry.column_at(content, position.x).unwrap_or(if position.x < content.min.x + LABEL_WIDTH { 0 } else { geometry.columns.saturating_sub(1) });
            let within = column.saturating_sub(placement.shift).min(placement.len.saturating_sub(1));
            let byte = placement.offset + within;
            app.anchor = Some(anchor.min(byte));
            app.cursor = (anchor.max(byte) + 1).min(app.document.len());
            panel::claim_main_selection(app);
        }
    }
}

/// Select a byte in the main view (Shift extends the selection to it) and
/// make its packet the focused one.
fn click_cell(state: &mut PacketsState, app: &mut ViewerApp, row: usize, column: usize, modifiers: Modifiers) {
    let Some((offset, _)) = state.grid.rows.cell(row, column) else { return };
    let packet = state.grid.rows.packets[row];
    if modifiers.shift {
        let anchor = app.anchor.unwrap_or(app.cursor);
        let (start, end) = (anchor.min(offset), (anchor.max(offset + 1)));
        panel::select_in_document(state, app, start, end - start, format!("{} bytes", end - start));
    } else {
        state.selected = std::collections::BTreeSet::from([packet]);
        let title = format!("Packet {} +{}", packet + 1, offset - state.grid.rows.placements[row].offset);
        panel::select_in_document(state, app, offset, 1, title);
    }
    state.focus = Some(packet);
    state.cursor_in_packet = Some(offset - state.grid.rows.placements[row].offset);
}

// ---------------------------------------------------------------------------
// Column operations
// ---------------------------------------------------------------------------

/// The selected columns of every targeted row: all rows, or only those of
/// selected packets when asked.
fn target_slices(state: &PacketsState) -> Vec<ColumnSlice> {
    let Some((first, width)) = state.grid.columns else { return Vec::new() };
    let rows = &state.grid.rows;
    let targets: Vec<(usize, RowPlacement)> = target_rows(state).into_iter().map(|row| (row, rows.placements[row])).collect();
    grid::column_slices(&targets, first, width)
}

/// The grid rows a column operation acts on: those of the block, or every
/// row, or only the selected packets' when asked.
fn target_rows(state: &PacketsState) -> Vec<usize> {
    let rows = &state.grid.rows;
    let only_selected = state.grid.only_selected && !state.selected.is_empty();
    let in_block = |row: usize| state.grid.block_rows.is_none_or(|(first_row, count)| row >= first_row && row < first_row + count);
    (0..rows.placements.len()).filter(|&row| in_block(row)).filter(|&row| !only_selected || state.selected.contains(&rows.packets[row])).collect()
}

fn show_error(state: &mut PacketsState, text: impl Into<String>) {
    state.note = Some(Note { text: text.into(), is_error: true });
}

/// The selected columns as the column methods take them: the targeted
/// packets, in row order, each row's shift when the rows are lined up, and
/// whether rows start at their record headers. Every packet is left
/// unnamed when every one is targeted in set order.
fn columns_params(state: &PacketsState) -> Option<serde_json::Value> {
    let (first, width) = state.grid.columns?;
    let rows = &state.grid.rows;
    let targets = target_rows(state);
    let indices: Vec<usize> = targets.iter().map(|&row| rows.packets[row]).collect();
    let shifts: Vec<usize> = targets.iter().map(|&row| rows.placements[row].shift).collect();
    let mut params = serde_json::json!({ "first": first, "width": width, "record_headers": state.grid.include_record_headers });
    let every_packet = state.set.as_ref().is_some_and(|set| indices.len() == set.len() && indices.iter().enumerate().all(|(position, &index)| position == index));
    if !every_packet {
        params["indices"] = serde_json::json!(indices);
    }
    if shifts.iter().any(|&shift| shift > 0) {
        params["shifts"] = serde_json::json!(shifts);
    }
    Some(params)
}

/// Carry out a column method on the set shown, with the selected columns;
/// a failure is said in the viewer.
fn on_columns<R: serde::de::DeserializeOwned>(state: &mut PacketsState, app: &mut ViewerApp, method: &str, extra: serde_json::Value) -> Option<R> {
    let mut params = columns_params(state)?;
    let set = panel::api_set_id(state, app)?;
    params["set"] = serde_json::json!(set);
    params.as_object_mut().expect("an object").extend(extra.as_object().cloned().unwrap_or_default());
    match app.perform_typed::<R>(method, params) {
        Ok(result) => Some(result),
        Err(_) => {
            show_error(state, app.status.clone());
            None
        }
    }
}

/// `operation` as `packets.columns.apply` takes it, the value to set as the
/// person typed it.
fn operation_params(operation: &ColumnOperation, typed: &str, little_endian: bool) -> serde_json::Value {
    let hex = crate::ops::to_compact_hex;
    match operation {
        ColumnOperation::Invert => serde_json::json!({ "op": ColumnOp::Invert }),
        ColumnOperation::Fill(key) => serde_json::json!({ "op": ColumnOp::Fill, "key": hex(key) }),
        ColumnOperation::Xor(key) => serde_json::json!({ "op": ColumnOp::Xor, "key": hex(key) }),
        ColumnOperation::Add(key) => serde_json::json!({ "op": ColumnOp::Add, "key": hex(key) }),
        ColumnOperation::Set(_) => serde_json::json!({ "op": ColumnOp::Set, "value": typed, "little_endian": little_endian }),
        ColumnOperation::Counter { start, step, little_endian } => serde_json::json!({ "op": ColumnOp::Counter, "start": start, "step": step, "little_endian": little_endian }),
        ColumnOperation::SwapByteOrder { group } => serde_json::json!({ "op": ColumnOp::Swap, "group": group }),
    }
}

/// Apply `operation` to the selected columns of every targeted packet, as
/// `packets.columns.apply`: one undoable edit.
pub fn apply_column_operation(state: &mut PacketsState, app: &mut ViewerApp, operation: &ColumnOperation) {
    let Some((first, width)) = state.grid.columns else {
        show_error(state, "Select columns first: click the ruler above the grid.");
        return;
    };
    let extra = operation_params(operation, &state.grid.operation_text, state.grid.little_endian);
    let Some(result) = on_columns::<PacketEditResult>(state, app, "packets.columns.apply", extra) else { return };
    state.note = Some(Note { text: format!("{} columns +{first}..+{} of {} packets. Undo with Cmd+Z.", operation.label(), first + width, result.packets), is_error: false });
}

/// Remove the selected columns from every targeted packet, as
/// `packets.columns.delete`: one undoable edit. Fixed-width records shrink
/// with them; length fields are not changed.
pub fn delete_columns(state: &mut PacketsState, app: &mut ViewerApp) {
    let Some((first, width)) = state.grid.columns else { return };
    let slices = target_slices(state);
    let Some(result) = on_columns::<PacketEditResult>(state, app, "packets.columns.delete", serde_json::json!({})) else { return };
    let packet_count = state.set.as_ref().map_or(0, |set| set.len());
    let every_row_whole = slices.len() == packet_count && slices.iter().all(|slice| slice.len == width);
    if let Some(set) = &mut state.set
        && let Recipe::Records { record_len, .. } = &mut set.recipe
        && every_row_whole
        && !state.grid.include_record_headers
    {
        *record_len = record_len.saturating_sub(width).max(1);
    }
    state.grid.columns = None;
    state.grid.block_rows = None;
    state.note = Some(Note {
        text: format!(
            "Deleted columns +{first}..+{} from {} packets ({} bytes). Length fields and checksums are not updated; fix them if the format has them. Undo with Cmd+Z.",
            first + width,
            result.packets,
            result.bytes_removed
        ),
        is_error: false,
    });
    if let Some(built) = state.built {
        panel::refresh_from_document(state, app, built);
    }
}

/// Copy the selected columns of the targeted packets as hex lines or CSV,
/// read by `packets.columns.read`.
pub fn copy_columns(state: &mut PacketsState, app: &mut ViewerApp, ctx: &egui::Context, as_csv: bool) {
    let Some((first, width)) = state.grid.columns else { return };
    let format = if as_csv { ColumnFormat::Csv } else { ColumnFormat::Hex };
    let Some(read) = on_columns::<ColumnsText>(state, app, "packets.columns.read", serde_json::json!({ "format": format })) else { return };
    ctx.copy_text(read.text);
    let cut = if read.left_out > 0 { format!(" (the first {}; the rest pass the copy limit)", read.packets) } else { String::new() };
    state.note = Some(Note { text: format!("Copied columns +{first}..+{} of {} packets{cut}.", first + width, read.packets), is_error: false });
}

/// Makes a column operation from the typed hex key.
type KeyedOperation = fn(Vec<u8>) -> ColumnOperation;

/// What the column buttons asked for this frame.
enum ColumnAction {
    Operation(ColumnOperation),
    Delete,
    Copy { as_csv: bool },
    Clear,
}

fn show_column_operations(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    let Some((first, width)) = state.grid.columns else {
        ui.label(
            RichText::new("Drag across packets to select a block, click the ruler (or Alt-click a byte) to select whole columns, and click a row's number to select its packet.").small().color(theme::TEXT_DIM),
        );
        return;
    };
    let targets = target_slices(state).len();
    let has_selected_packets = !state.selected.is_empty();
    let mut action = None;
    let grid = &mut state.grid;
    ui.horizontal_wrapped(|ui| {
        let rows_described = match grid.block_rows {
            Some((row, count)) => {
                let packet = |row: usize| grid.rows.packets.get(row).map_or(row + 1, |&packet| packet + 1);
                format!("Block: packets {}–{}, ", packet(row), packet(row + count - 1))
            }
            None => "Columns ".to_string(),
        };
        let fields = selected_fields(&grid.rows, first, width);
        let fields = if fields.is_empty() { String::new() } else { format!(": {}", fields.join(", ")) };
        ui.label(RichText::new(format!("{rows_described}+{first}..+{} ({width} B) in {targets} packets{fields}", first + width)).strong());
        ui.add_enabled(has_selected_packets, egui::Checkbox::new(&mut grid.only_selected, "only the selected packets"));
        if ui.small_button("Clear").clicked() {
            action = Some(ColumnAction::Clear);
        }
    });
    ui.horizontal_wrapped(|ui| {
        ui.add(egui::TextEdit::singleline(&mut grid.operation_text).hint_text("hex key, or a value to set").desired_width(140.0));
        ui.checkbox(&mut grid.little_endian, "little endian").on_hover_text("Byte order for Set (with a number) and Number");
        let key = packets::parse_hex(&grid.operation_text);
        if ui.small_button("Invert column").clicked() {
            action = Some(ColumnAction::Operation(ColumnOperation::Invert));
        }
        let keyed: [(&str, KeyedOperation, &str); 3] = [
            ("Fill column", ColumnOperation::Fill, "Repeat the hex bytes across the columns"),
            ("XOR column", ColumnOperation::Xor, "XOR with the hex key, restarting at the first column of each packet"),
            ("ADD column", ColumnOperation::Add, "Add the hex key byte by byte, wrapping"),
        ];
        for (label, make, hover) in keyed {
            let button = ui.add_enabled(key.is_ok(), egui::Button::new(label).small()).on_hover_text(hover).on_disabled_hover_text("Type hex bytes first");
            if button.clicked()
                && let Ok(bytes) = &key
            {
                action = Some(ColumnAction::Operation(make(bytes.clone())));
            }
        }
        let value = edit::encode_value(&grid.operation_text, width, grid.little_endian);
        let set = ui.add_enabled(value.is_ok(), egui::Button::new("Set column").small()).on_hover_text("Write this value (a number, or exactly as many hex bytes as columns) into every packet");
        if set.clicked()
            && let Ok(bytes) = value
        {
            action = Some(ColumnAction::Operation(ColumnOperation::Set(bytes)));
        }
    });
    ui.horizontal_wrapped(|ui| {
        ui.label("Number from");
        ui.add(egui::DragValue::new(&mut grid.counter_start));
        ui.label("step");
        ui.add(egui::DragValue::new(&mut grid.counter_step));
        if ui.small_button("Number column").on_hover_text("Write start + step × n into the nth packet, as a counter").clicked() {
            action = Some(ColumnAction::Operation(ColumnOperation::Counter { start: grid.counter_start, step: grid.counter_step, little_endian: grid.little_endian }));
        }
        for group in [2usize, 4, 8] {
            let enabled = width >= group;
            if ui.add_enabled(enabled, egui::Button::new(format!("Swap {group}")).small()).on_hover_text(format!("Reverse each group of {group} bytes")).clicked() {
                action = Some(ColumnAction::Operation(ColumnOperation::SwapByteOrder { group }));
            }
        }
        if ui.small_button("Copy hex").clicked() {
            action = Some(ColumnAction::Copy { as_csv: false });
        }
        if ui.small_button("Copy CSV").clicked() {
            action = Some(ColumnAction::Copy { as_csv: true });
        }
        let delete = egui::Button::new(RichText::new("Delete column").color(theme::DANGER)).small();
        if ui
            .add(delete)
            .on_hover_text("Remove these bytes from every packet, making each shorter. Length fields and checksums are not updated, so a length-field split may need fixing.")
            .clicked()
        {
            action = Some(ColumnAction::Delete);
        }
    });
    match action {
        Some(ColumnAction::Operation(operation)) => apply_column_operation(state, app, &operation),
        Some(ColumnAction::Delete) => delete_columns(state, app),
        Some(ColumnAction::Copy { as_csv }) => copy_columns(state, app, ui.ctx(), as_csv),
        Some(ColumnAction::Clear) => {
            state.grid.columns = None;
            state.grid.block_rows = None;
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruler_labels_are_spaced_by_powers_of_two() {
        assert_eq!(ruler_step(40.0), 1);
        assert_eq!(ruler_step(22.0), 2);
        assert_eq!(ruler_step(1.0), 32);
    }

    #[test]
    fn the_grid_maps_the_pointer_to_ruler_labels_and_cells() {
        let geometry = Geometry { cell: vec2(10.0, 10.0), columns: 8, rows: 5, ascii: false };
        let content = Rect::from_min_size(pos2(0.0, 0.0), geometry.content_size());
        let visible = content;
        assert_eq!(geometry.hit(content, visible, pos2(LABEL_WIDTH + 25.0, 5.0)), Some(Hit::Ruler(2)));
        assert_eq!(geometry.hit(content, visible, pos2(5.0, HEADER_HEIGHT + 15.0)), Some(Hit::Label(1)));
        assert_eq!(geometry.hit(content, visible, pos2(LABEL_WIDTH + 75.0, HEADER_HEIGHT + 45.0)), Some(Hit::Cell { row: 4, column: 7 }));
        assert_eq!(geometry.hit(content, visible, pos2(LABEL_WIDTH + 85.0, HEADER_HEIGHT + 5.0)), None, "past the last column");
        let ascii = Geometry { ascii: true, ..geometry };
        let x = ascii.ascii_left() + 3.5 * ASCII_WIDTH;
        assert_eq!(ascii.hit(content, Rect::from_min_size(pos2(0.0, 0.0), ascii.content_size()), pos2(x, HEADER_HEIGHT + 1.0)), Some(Hit::Cell { row: 0, column: 3 }));
    }

    #[test]
    fn only_the_visible_cells_are_drawn() {
        let geometry = Geometry { cell: vec2(4.0, 4.0), columns: 10_000, rows: 100_000, ascii: false };
        let viewport = Rect::from_min_size(pos2(400.0, 40_000.0), vec2(200.0, 100.0));
        let [first_row, end_row, first_column, end_column] = geometry.visible_cells(viewport);
        assert_eq!((first_row, first_column), (10_000, 100));
        assert!(end_row - first_row <= 25 && end_column - first_column <= 50);
    }
}
