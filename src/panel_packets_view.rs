//! The packet viewer's tables, detail tree, hex editor and operations.
//!
//! Drawn by [`crate::panel_packets`]. Every change to the document goes
//! through the document's undoable edits: one edit for the whole operation
//! when the bytes involved lie within [`SINGLE_EDIT_LIMIT`] of each other,
//! otherwise one per packet.

use std::collections::BTreeSet;
use std::sync::Arc;

use eframe::egui::{self, Align2, Color32, FontId, Key, Modifiers, Rect, RichText, Sense, Stroke, TextWrapMode, Ui, vec2};

use base64::Engine;

use crate::api::packet_sets::{FieldSpan, PacketEditResult, PacketOp};
use crate::app::ViewerApp;
use crate::packets::edit::{self, ByteOperation};
use crate::packets::dissect::WiresharkNames;
use crate::packets::{self, ConversationKey, Layer};
use crate::plugin::Field;
use crate::panel_packets::{self as panel, FieldEdit, PacketsState, PacketsView, Statistics};
use crate::panel_packets_grid::{self as grid, PacketLayout};
use crate::reference::{self, FormatReference};
use crate::theme;

/// Most bytes one undoable edit may span; wider operations are split into
/// one edit per packet.
pub const SINGLE_EDIT_LIMIT: usize = 64 * 1024 * 1024;
/// Share of the panel's height given to the packet list.
const TABLE_SHARE: f32 = 0.42;
const MIN_TABLE_HEIGHT: f32 = 110.0;
const MAX_TABLE_HEIGHT: f32 = 420.0;
/// Share of the panel's height given to the conversation, endpoint and
/// stream lists.
const LIST_SHARE: f32 = 0.75;
/// Character widths of the packet list's columns.
const NUMBER_WIDTH: usize = 6;
const OFFSET_WIDTH: usize = 10;
const TIME_WIDTH: usize = 11;
const ADDRESS_WIDTH: usize = 22;
const PROTOCOL_WIDTH: usize = 10;
const LENGTH_WIDTH: usize = 6;
/// Width at which the detail tree and the hex dump sit side by side.
const SIDE_BY_SIDE_WIDTH: f32 = 720.0;
const DETAIL_TREE_HEIGHT: f32 = 320.0;
/// Hex editor geometry.
const HEX_BYTES_PER_ROW: usize = 16;
const HEX_FONT_SIZE: f32 = 12.0;
const HEX_ROW_HEIGHT: f32 = 16.0;
const HEX_OFFSET_COLUMN: f32 = 48.0;
const HEX_CELL_WIDTH: f32 = 21.0;
const HEX_ASCII_WIDTH: f32 = 8.0;
const HEX_ASCII_GAP: f32 = 10.0;
/// Most rows shown in the stream view, one per segment.
const STREAM_SEGMENTS_SHOWN: usize = 2000;
/// Most bytes of one stream segment shown as hex.
const STREAM_HEX_BYTES: usize = 4096;

/// Width a combo box takes: its set width plus the arrow beside it.
pub fn combo_width(ui: &Ui) -> f32 {
    ui.spacing().combo_width + ui.spacing().icon_width + ui.spacing().button_padding.x * 2.0
}

/// In a wrapping row, start a new row unless `width` fits on this one. Combo
/// boxes do not wrap by themselves, so without this they run off the edge.
pub fn start_row_unless_fits(ui: &mut Ui, width: f32) {
    let at_row_start = ui.cursor().min.x <= ui.max_rect().min.x + 1.0;
    if !at_row_start && width > ui.available_size_before_wrap().x {
        ui.end_row();
    }
}

// ---------------------------------------------------------------------------
// Packet list
// ---------------------------------------------------------------------------

/// The filter, the packet list (or the raster or hex grid of the packets),
/// the operations on the selected packets and the selected packet's detail.
pub fn show_packet_view(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    show_filter(state, ui);
    grid::show_layout_choice(state, ui);
    if state.grid.layout != PacketLayout::List {
        grid::show_grid_view(state, app, ui);
        show_operations(state, app, ui);
        return;
    }
    let height = (state.pane_height * TABLE_SHARE).clamp(MIN_TABLE_HEIGHT, MAX_TABLE_HEIGHT);
    show_table(state, app, ui, height);
    show_operations(state, app, ui);
    ui.separator();
    show_detail(state, app, ui);
}

fn show_filter(state: &mut PacketsState, ui: &mut Ui) {
    let total = state.rows.len();
    ui.horizontal_wrapped(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut state.filter_text)
                .hint_text("Filter: udp port:53 ip:10.0.0.2 len>100 hex:DEADBEEF ip.ttl==64 text")
                .desired_width(ui.available_width().clamp(160.0, 420.0)),
        )
        .on_hover_text(
            "Terms side by side must all match; join them with and (&&), or (||), not (!) and brackets. A term is a protocol (tcp, dns…), port:N, ip:ADDRESS, len>N (or <, >=, <=, ==, !=), hex:BYTES, a Wireshark field such as ip.ttl==64, tcp.port==80 or dns.qry.type==16 (also !=, <, >, ~ for contains), a template field as template.type==60 (or type==60), or text from the summary (\"in quotes\" for several words)",
        );
        if !state.filter_text.is_empty() && ui.small_button("Clear").clicked() {
            state.filter_text.clear();
        }
        ui.label(RichText::new(format!("{} of {total} shown", state.visible.len())).small().color(theme::TEXT_DIM));
    });
    show_order(state, ui);
    panel::refresh_filter(state);
    if let Some(error) = &state.filter_error {
        ui.label(RichText::new(format!("Filter not applied: {error}")).small().color(theme::DANGER));
    }
    if let Some(error) = &state.order_error {
        ui.label(RichText::new(format!("Not sorted: {error}")).small().color(theme::DANGER));
    }
}

/// Choose the order of the list, by a column or a field, and whether to
/// hide repeats.
fn show_order(state: &mut PacketsState, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Sort by").small());
        egui::ComboBox::from_id_salt("packets-sort").selected_text(state.order.column.label()).show_ui(ui, |ui| {
            for column in panel::SortColumn::ALL {
                ui.selectable_value(&mut state.order.column, column, column.label());
            }
        });
        if state.order.column == panel::SortColumn::Field {
            ui.add(egui::TextEdit::singleline(&mut state.order.field).hint_text("dns.qry.name, template.seq…").desired_width(160.0))
                .on_hover_text("Any field a filter can name; numbers sort as numbers, and packets without the field come last");
        }
        ui.checkbox(&mut state.order.descending, "Desc.");
        ui.checkbox(&mut state.order.unique, "Unique").on_hover_text("Show only the first packet of each value, so a chunk sent twice is shown once");
    });
}

fn header_text() -> String {
    format!(
        "{:>NUMBER_WIDTH$} {:>OFFSET_WIDTH$} {:>TIME_WIDTH$} {:<ADDRESS_WIDTH$} {:<ADDRESS_WIDTH$} {:<PROTOCOL_WIDTH$} {:>LENGTH_WIDTH$} Info",
        "No.", "Offset", "Time", "Source", "Destination", "Protocol", "Length"
    )
}

/// Text cut to `width` characters, with an ellipsis when it was longer.
fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

fn row_text(state: &PacketsState, index: usize, first_time: Option<f64>) -> String {
    let Some(packet) = state.set.as_ref().and_then(|set| set.packets.get(index)) else { return String::new() };
    let row = &state.rows[index];
    let time = match (packet.timestamp, first_time) {
        (Some(time), Some(first)) => format!("{:.6}", time - first),
        _ => "-".to_string(),
    };
    format!(
        "{:>NUMBER_WIDTH$} {:>OFFSET_WIDTH$} {:>TIME_WIDTH$} {:<ADDRESS_WIDTH$} {:<ADDRESS_WIDTH$} {:<PROTOCOL_WIDTH$} {:>LENGTH_WIDTH$} {}",
        index + 1,
        format!("{:#x}", packet.offset),
        time,
        fit(&row.summary.source, ADDRESS_WIDTH),
        fit(&row.summary.destination, ADDRESS_WIDTH),
        fit(&row.summary.protocol, PROTOCOL_WIDTH),
        packet.len,
        row.summary.info
    )
}

fn show_table(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui, height: f32) {
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y + 2.0;
    let first_time = state.set.as_ref().and_then(|set| set.packets.iter().find_map(|p| p.timestamp));
    let scroll_to = state.scroll_to_row.take().and_then(|index| state.visible.iter().position(|&shown| shown == index));
    let mut clicked: Option<(usize, Modifiers)> = None;
    let output = egui::ScrollArea::horizontal().id_salt("packets-table-columns").show(ui, |ui| {
        ui.style_mut().wrap_mode = Some(TextWrapMode::Extend);
        ui.label(RichText::new(header_text()).monospace().strong());
        let mut area = egui::ScrollArea::vertical().id_salt("packets-table").max_height(height).auto_shrink([true, false]);
        if let Some(position) = scroll_to {
            area = area.vertical_scroll_offset((position as f32 * row_height - height / 3.0).max(0.0));
        }
        area.show_rows(ui, row_height, state.visible.len(), |ui, range| {
            for position in range {
                let index = state.visible[position];
                let text = RichText::new(row_text(state, index, first_time)).monospace();
                let response = ui.selectable_label(state.selected.contains(&index), text);
                if response.clicked() {
                    clicked = Some((index, ui.input(|input| input.modifiers)));
                }
            }
        });
    });
    state.list_hovered = ui.rect_contains_pointer(output.inner_rect);
    if let Some((index, modifiers)) = clicked {
        click_row(state, app, index, modifiers);
    }
}

/// Plain click selects one packet; Cmd (Ctrl) toggles one; Shift extends
/// from the focused packet along the shown order.
pub(crate) fn click_row(state: &mut PacketsState, app: &mut ViewerApp, index: usize, modifiers: Modifiers) {
    if modifiers.shift
        && let Some(anchor) = state.focus
        && let (Some(from), Some(to)) = (state.visible.iter().position(|&i| i == anchor), state.visible.iter().position(|&i| i == index))
    {
        let (low, high) = (from.min(to), from.max(to));
        state.selected = state.visible[low..=high].iter().copied().collect();
    } else if modifiers.command {
        if !state.selected.remove(&index) {
            state.selected.insert(index);
        }
    } else {
        state.selected = BTreeSet::from([index]);
    }
    if state.selected.len() > 1 {
        focus_packet_only(state, index);
        select_packets_in_document(state, app);
    } else {
        focus_packet(state, app, index);
    }
}

/// Make `index` the packet shown in detail, leaving the selection be.
fn focus_packet_only(state: &mut PacketsState, index: usize) {
    if state.focus != Some(index) {
        state.selected_field = None;
        state.field_edit = None;
        state.hex = panel::HexCursor::default();
    }
    state.focus = Some(index);
}

/// Several packets are selected: select all their bytes in the document as
/// one multi-range selection.
fn select_packets_in_document(state: &mut PacketsState, app: &mut ViewerApp) {
    let Some(set) = &state.set else { return };
    let ranges = state.selected.iter().filter_map(|&index| set.packets.get(index)).map(|packet| (packet.offset, packet.len)).collect();
    panel::select_ranges_in_document(state, app, ranges);
}

/// Make `index` the packet shown in detail and select its bytes.
fn focus_packet(state: &mut PacketsState, app: &mut ViewerApp, index: usize) {
    focus_packet_only(state, index);
    if let Some(packet) = state.set.as_ref().and_then(|set| set.packets.get(index)).cloned() {
        panel::select_in_document(state, app, packet.offset, packet.len, format!("Packet {}", index + 1));
    }
}

/// The selected packets in the order the list shows them (any not shown
/// after, in capture order), or the focused one when none are selected.
pub(crate) fn targets(state: &PacketsState) -> Vec<usize> {
    if state.selected.is_empty() {
        return state.focus.into_iter().collect();
    }
    let mut chosen: Vec<usize> = state.visible.iter().copied().filter(|index| state.selected.contains(index)).collect();
    let shown: std::collections::HashSet<usize> = chosen.iter().copied().collect();
    chosen.extend(state.selected.iter().copied().filter(|index| !shown.contains(index)));
    chosen
}

// ---------------------------------------------------------------------------
// Operations on the selected packets
// ---------------------------------------------------------------------------

fn show_operations(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    let count = targets(state).len();
    if count == 0 {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Click a packet; Shift or Cmd click to select several.").small().color(theme::TEXT_DIM));
            if ui.small_button("Export pcap…").on_hover_text("Save the shown packets as a pcap file").clicked() {
                export_pcap(state, app, false);
            }
        });
        return;
    }
    let field = state.selected_field;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{count} selected")).strong());
        if ui.small_button("Delete packets").on_hover_text("Remove these packets' bytes from the document (their whole capture records, so a capture stays readable)").clicked() {
            delete_selected_packets(state, app);
        }
        if ui.small_button("Save bytes…").clicked() {
            extract_selected(state, app, false);
        }
        if ui.small_button("Open as document").clicked() {
            extract_selected(state, app, true);
        }
        if ui.small_button("Export pcap…").on_hover_text("Save the selected packets (or every shown packet when one is selected) as a pcap file").clicked() {
            export_pcap(state, app, count > 1);
        }
        if ui.small_button("Fix checksums").on_hover_text("Recompute the IPv4 header, TCP and UDP checksums of the selected packets").clicked() {
            fix_checksums(state, app);
        }
        crate::selection_menu::menu_button(app, ui);
    });
    ui.horizontal_wrapped(|ui| {
        ui.add(egui::TextEdit::singleline(&mut state.operation_text).hint_text("hex for fill or XOR").desired_width(120.0));
        let operation_hex = packets::parse_hex(&state.operation_text);
        if ui.small_button("Invert").clicked() {
            apply_operation(state, app, &ByteOperation::Invert);
        }
        for (label, make) in [("Fill", ByteOperation::Fill as fn(Vec<u8>) -> ByteOperation), ("XOR", ByteOperation::Xor)] {
            let enabled = operation_hex.is_ok();
            let button = ui.add_enabled(enabled, egui::Button::new(label).small()).on_disabled_hover_text("Type the hex bytes first");
            if button.clicked()
                && let Ok(bytes) = &operation_hex
            {
                apply_operation(state, app, &make(bytes.clone()));
            }
        }
        let field_label = match field {
            Some((offset, len)) => format!("only bytes +{offset}..+{} of each", offset + len),
            None => "only the chosen field (choose one below)".to_string(),
        };
        ui.add_enabled(field.is_some(), egui::Checkbox::new(&mut state.operation_on_field, field_label))
            .on_hover_text("Work on the same field in every selected packet instead of the whole packets: Invert, Fill and XOR change only it, and Save bytes and Open as document take only it, one packet's after another");
    });
}

/// Carry out `method` on the set shown, with `params` (the set's id is
/// added), and return its result; a failure is said in the viewer.
fn on_set<R: serde::de::DeserializeOwned>(state: &mut PacketsState, app: &mut ViewerApp, method: &str, mut params: serde_json::Value) -> Option<R> {
    let set = panel::api_set_id(state, app)?;
    params["set"] = serde_json::json!(set);
    match app.perform_typed::<R>(method, params) {
        Ok(result) => Some(result),
        Err(_) => {
            state.note = Some(panel::Note { text: app.status.clone(), is_error: true });
            None
        }
    }
}

/// Invert, fill or XOR every target packet (or the chosen field in each),
/// as `packets.apply`.
pub fn apply_operation(state: &mut PacketsState, app: &mut ViewerApp, operation: &ByteOperation) {
    let (op, key) = match operation {
        ByteOperation::Invert => (PacketOp::Invert, None),
        ByteOperation::Fill(key) => (PacketOp::Fill, Some(crate::ops::to_compact_hex(key))),
        ByteOperation::Xor(key) => (PacketOp::Xor, Some(crate::ops::to_compact_hex(key))),
    };
    let field = chosen_field(state);
    let mut params = serde_json::json!({ "indices": targets(state), "op": op });
    if let Some(key) = key {
        params["key"] = serde_json::json!(key);
    }
    if let Some(field) = field {
        params["field"] = serde_json::json!(field);
    }
    let Some(result) = on_set::<PacketEditResult>(state, app, "packets.apply", params) else { return };
    let what = if field.is_some() { "the chosen field of" } else { "" };
    state.note = Some(panel::Note { text: format!("{} {what} {} packets. Undo with Cmd+Z.", operation.label(), result.packets), is_error: false });
}

/// Recompute the IPv4, TCP and UDP checksums of every target packet, as
/// `packets.fix_checksums`.
pub fn fix_checksums(state: &mut PacketsState, app: &mut ViewerApp) {
    let params = serde_json::json!({ "indices": targets(state) });
    let Some(result) = on_set::<PacketEditResult>(state, app, "packets.fix_checksums", params) else { return };
    let text = if result.checksums.is_empty() {
        "Every checksum is already correct.".to_string()
    } else {
        let mut kinds: Vec<&str> = Vec::new();
        for kind in &result.checksums {
            if !kinds.contains(&kind.as_str()) {
                kinds.push(kind);
            }
        }
        format!("Fixed {} checksums ({}). Undo with Cmd+Z.", result.checksums.len(), kinds.join(", "))
    };
    state.note = Some(panel::Note { text, is_error: false });
}

/// Remove the target packets' bytes (their whole capture records) from the
/// document, as `packets.delete`.
pub fn delete_selected_packets(state: &mut PacketsState, app: &mut ViewerApp) {
    let Some(set) = state.set.clone() else { return };
    let chosen = targets(state);
    let removed = edit::merge_ranges(chosen.iter().filter_map(|&index| set.packets.get(index)).map(|packet| packet.removal_range()).collect());
    let Some((start, _)) = edit::covering_span(&removed) else { return };
    let built = state.built;
    if on_set::<PacketEditResult>(state, app, "packets.delete", serde_json::json!({ "indices": chosen })).is_none() {
        return;
    }
    app.set_cursor(start.min(app.document.len()), false);
    panel::claim_main_selection(app);
    if set.recipe == packets::sources::Recipe::Fixed
        && let Some(shown) = &mut state.set
    {
        shown.packets = set
            .packets
            .iter()
            .enumerate()
            .filter(|(index, _)| !chosen.contains(index))
            .filter_map(|(_, packet)| {
                let offset = edit::offset_after_deletion(packet.offset, &removed)?;
                Some(packets::Packet { offset, record: None, ..packet.clone() })
            })
            .collect();
    }
    state.selected.clear();
    state.focus = None;
    let bytes: usize = removed.iter().map(|&(_, len)| len).sum();
    state.note = Some(panel::Note { text: format!("Deleted {} packets ({bytes} bytes). Undo with Cmd+Z.", chosen.len()), is_error: false });
    if let Some(built) = built {
        panel::refresh_from_document(state, app, built);
    }
}

/// Save the target packets' bytes, or open them as a document.
fn extract_selected(state: &mut PacketsState, app: &mut ViewerApp, open: bool) {
    let count = targets(state).len();
    let field = chosen_field(state);
    let packets = if count == 1 { format!("packet {}", state.focus.map_or(0, |i| i + 1)) } else { format!("{count} packets") };
    let name = if field.is_some() { format!("field of {packets}") } else { packets };
    if open {
        let Some(set) = &state.set else { return };
        let ranges: Vec<(usize, usize)> = targets(state)
            .into_iter()
            .filter_map(|index| set.packets.get(index))
            .filter_map(|packet| {
                let packet_len = packet.len.min(panel::PACKET_READ_LIMIT);
                let (offset, len) = match field {
                    Some(field) => field.within(packet_len)?,
                    None => (0, packet_len),
                };
                Some((packet.offset + offset, len))
            })
            .collect();
        open_as_document(state, app, serde_json::json!({ "ranges": ranges, "name": name }));
    } else if let Some(set) = panel::api_set_id(state, app) {
        let mut params = serde_json::json!({ "set": set, "indices": targets(state) });
        if let Some(field) = field {
            params["field"] = serde_json::json!(field);
        }
        app.save_dialog_then_call("Save packet bytes", &format!("{}.bin", name.replace(' ', "-")), "packets.extract", params, "path");
    }
}

/// The field chosen in the detail, when the operations are to be on it
/// alone rather than on whole packets.
fn chosen_field(state: &PacketsState) -> Option<FieldSpan> {
    if state.operation_on_field { state.selected_field.map(|(offset, len)| FieldSpan { offset, len }) } else { None }
}

/// Open bytes as a document derived from the one shown, through
/// `documents.derive` with `params`; the packets then describe a document
/// not shown.
fn open_as_document(state: &mut PacketsState, app: &mut ViewerApp, params: serde_json::Value) {
    if app.perform("documents.derive", params).is_ok() {
        state.foreign_document = true;
    } else {
        state.note = Some(panel::Note { text: app.status.clone(), is_error: true });
    }
}

/// Save packets as a pcap file through `packets.export_pcap`, once a path
/// is chosen: the selected ones, or every shown one.
fn export_pcap(state: &mut PacketsState, app: &mut ViewerApp, selected_only: bool) {
    let Some(set) = panel::api_set_id(state, app) else { return };
    let params = match (selected_only, state.visible.len() == state.rows.len()) {
        (true, _) => serde_json::json!({ "set": set, "indices": targets(state) }),
        (false, false) => serde_json::json!({ "set": set, "indices": state.visible }),
        (false, true) => serde_json::json!({ "set": set }),
    };
    app.save_dialog_then_call("Export packets as pcap", "packets.pcap", "packets.export_pcap", params, "path");
}

// ---------------------------------------------------------------------------
// Detail: layers, fields and the hex editor
// ---------------------------------------------------------------------------

/// What the user asked for in the detail tree.
enum TreeAction {
    Select { offset: usize, len: usize, name: String },
    StartEdit { offset: usize, len: usize, little_endian: bool, text: String },
    ApplyEdit,
    CancelEdit,
    /// Open the Reference tab on a layer's format.
    Reference { offset: usize, len: usize, name: String },
}

fn show_detail(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    let Some(detail) = state.detail.take() else {
        ui.label(RichText::new("Select a packet to see its layers and bytes. Moving the cursor in the main view into a packet selects it here.").color(theme::TEXT_DIM));
        return;
    };
    let Some(packet) = state.set.as_ref().and_then(|set| set.packets.get(detail.index)).cloned() else {
        state.detail = Some(detail);
        return;
    };
    ui.horizontal_wrapped(|ui| {
        let time = packet.timestamp.map_or(String::new(), |t| format!(" · t={t:.6}"));
        ui.label(RichText::new(format!("Packet {} · {} · {:#x} · {} bytes{time}", detail.index + 1, packet.origin, packet.offset, packet.len)).strong());
        if ui.small_button("Open packet as document").clicked() {
            let params = serde_json::json!({ "start": packet.offset, "len": detail.bytes.len(), "name": format!("packet {}", detail.index + 1) });
            open_as_document(state, app, params);
        }
        if let Some(flow) = detail.dissection.flow
            && ui.small_button("Follow stream").clicked()
        {
            follow(state, &flow.key());
        }
        if crate::panel_packets_tshark::can_decode_one(state, app)
            && ui.small_button("Decode with tshark").on_hover_text("Have Wireshark's tshark decode this packet alone (run locally with -n)").clicked()
        {
            crate::panel_packets_tshark::ask_to_decode(state, app, Some(detail.index));
        }
    });
    for note in &detail.dissection.notes {
        ui.label(RichText::new(note).small().color(theme::DANGER));
    }
    let mut actions = Vec::new();
    let mut field_edit = state.field_edit.take();
    let (selected_field, cursor_in_packet) = (state.selected_field, state.cursor_in_packet);
    let side_by_side = ui.available_width() >= SIDE_BY_SIDE_WIDTH;
    let tree = |ui: &mut Ui, actions: &mut Vec<TreeAction>, field_edit: &mut Option<FieldEdit>| {
        egui::ScrollArea::vertical().id_salt("packet-tree").max_height(DETAIL_TREE_HEIGHT).auto_shrink([false, true]).show(ui, |ui| {
            for (number, layer) in detail.dissection.layers.iter().enumerate() {
                let wireshark = detail.dissection.wireshark_names(number);
                show_layer(ui, number, layer, wireshark, selected_field, cursor_in_packet, field_edit, actions);
            }
        });
    };
    if side_by_side {
        let width = ui.available_width();
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(width * 0.5);
                tree(ui, &mut actions, &mut field_edit);
            });
            ui.separator();
            ui.vertical(|ui| show_hex_editor(state, app, ui, &detail.bytes, packet.offset));
        });
    } else {
        tree(ui, &mut actions, &mut field_edit);
        ui.separator();
        show_hex_editor(state, app, ui, &detail.bytes, packet.offset);
    }
    state.field_edit = field_edit;
    state.detail = Some(detail);
    for action in actions {
        act_on_tree(state, app, action, packet.offset);
    }
}

fn act_on_tree(state: &mut PacketsState, app: &mut ViewerApp, action: TreeAction, packet_offset: usize) {
    match action {
        TreeAction::Select { offset, len, name } => {
            // The Reference tab follows the layer the chosen field belongs to.
            let layer = state.detail.as_ref().and_then(|detail| detail.dissection.layers.iter().rev().find(|layer| offset >= layer.offset && offset < layer.offset + layer.len.max(1)));
            if let Some(layer) = layer {
                crate::panel_reference::focus_reference(app, panel::PACKETS_PRODUCER, &layer.name);
            }
            state.selected_field = Some((offset, len));
            state.hex.position = offset;
            state.hex.pending_low_nibble = false;
            panel::select_in_document(state, app, packet_offset + offset, len, name);
        }
        TreeAction::Reference { offset, len, name } => {
            act_on_tree(state, app, TreeAction::Select { offset, len, name: name.clone() }, packet_offset);
            crate::panel_reference::open_reference_for(app, panel::PACKETS_PRODUCER, &name);
        }
        TreeAction::StartEdit { offset, len, little_endian, text } => {
            state.selected_field = Some((offset, len));
            state.field_edit = Some(FieldEdit { offset, len, little_endian, text, error: None });
        }
        TreeAction::CancelEdit => state.field_edit = None,
        TreeAction::ApplyEdit => {
            let (Some(field_edit), Some(index)) = (&mut state.field_edit, state.focus) else { return };
            if let Err(reason) = edit::encode_value(&field_edit.text, field_edit.len, field_edit.little_endian) {
                field_edit.error = Some(reason);
                return;
            }
            let (offset, len) = (field_edit.offset, field_edit.len);
            let params = serde_json::json!({ "index": index, "offset": offset, "len": len, "value": field_edit.text, "little_endian": field_edit.little_endian });
            if on_set::<PacketEditResult>(state, app, "packets.write_field", params).is_some() {
                state.note = Some(panel::Note { text: format!("Wrote {len} bytes at {:#x}. Undo with Cmd+Z.", packet_offset + offset), is_error: false });
                state.field_edit = None;
            }
        }
    }
}

/// One layer of the detail tree; a layer tshark decoded carries a "tshark"
/// tag naming its Wireshark filter name.
#[allow(clippy::too_many_arguments)]
fn show_layer(
    ui: &mut Ui,
    number: usize,
    layer: &Layer,
    wireshark: Option<&WiresharkNames>,
    selected: Option<(usize, usize)>,
    cursor: Option<usize>,
    field_edit: &mut Option<FieldEdit>,
    actions: &mut Vec<TreeAction>,
) {
    let title = RichText::new(format!("{} · {} bytes at +{}", layer.name, layer.len, layer.offset)).strong();
    let notes = reference::lookup(&layer.name);
    let id = ui.make_persistent_id(("packet-layer", number, layer.name.as_str()));
    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true)
        .show_header(ui, |ui| {
            if ui.add(egui::Label::new(title).selectable(false).sense(Sense::click())).on_hover_text("Click to select the layer's bytes").clicked() {
                actions.push(TreeAction::Select { offset: layer.offset, len: layer.len, name: layer.name.clone() });
            }
            if let Some(names) = wireshark {
                ui.label(RichText::new("tshark").small().color(theme::ACCENT))
                    .on_hover_text(format!("Decoded by Wireshark's tshark, not by this viewer (Wireshark filter name: {})", names.protocol));
            }
            if notes.is_some() && ui.small_button("Reference").on_hover_text("How this protocol is organised, what its fields mean and where it is specified").clicked() {
                actions.push(TreeAction::Reference { offset: layer.offset, len: layer.len, name: layer.name.clone() });
            }
        })
        .body(|ui| {
            for field in &layer.fields {
                show_field(ui, field, notes, selected, cursor, field_edit, actions);
            }
        });
}

/// One field of a layer; hovering its name explains it when the layer's
/// reference notes do.
fn show_field(
    ui: &mut Ui,
    field: &Field,
    notes: Option<&FormatReference>,
    selected: Option<(usize, usize)>,
    cursor: Option<usize>,
    field_edit: &mut Option<FieldEdit>,
    actions: &mut Vec<TreeAction>,
) {
    let is_selected = selected == Some((field.offset, field.len));
    if !field.children.is_empty() {
        let title = RichText::new(format!("{}: {}", field.name, field.value));
        let header = egui::CollapsingHeader::new(title).id_salt(("packet-field", field.offset, field.len, field.name.as_str())).default_open(true).show(ui, |ui| {
            for child in &field.children {
                show_field(ui, child, notes, selected, cursor, field_edit, actions);
            }
        });
        if header.header_response.clicked() {
            actions.push(TreeAction::Select { offset: field.offset, len: field.len, name: field.name.clone() });
        }
        return;
    }
    let under_cursor = cursor.is_some_and(|at| at >= field.offset && at < field.offset + field.len.max(1));
    ui.horizontal_wrapped(|ui| {
        let name = RichText::new(format!("{}:", field.name)).color(if under_cursor { theme::CURSOR } else { theme::TEXT });
        let extent = format!("+{} · {} bytes · click to select them", field.offset, field.len);
        let hover = match notes.and_then(|notes| notes.explain_field(&field.name)) {
            Some(explanation) => format!("{explanation}\n\n{extent}"),
            None => extent,
        };
        if ui.selectable_label(is_selected, name).on_hover_text(hover).clicked() {
            actions.push(TreeAction::Select { offset: field.offset, len: field.len, name: field.name.clone() });
        }
        let editing = field_edit.as_ref().is_some_and(|edit| edit.offset == field.offset && edit.len == field.len);
        if editing {
            show_field_editor(ui, field_edit, actions);
            return;
        }
        let value = ui.add(egui::Label::new(RichText::new(&field.value).color(theme::TEXT_DIM)).sense(Sense::click()));
        if value.on_hover_text("Click to type a new value").clicked() && field.len > 0 {
            let first_word = field.value.split_whitespace().next().unwrap_or_default().to_string();
            let little_endian = edit::field_is_little_endian(field);
            let text = if edit::encode_value(&first_word, field.len, little_endian).is_ok() { first_word } else { String::new() };
            actions.push(TreeAction::StartEdit { offset: field.offset, len: field.len, little_endian, text });
        }
    });
}

fn show_field_editor(ui: &mut Ui, field_edit: &mut Option<FieldEdit>, actions: &mut Vec<TreeAction>) {
    let Some(edit) = field_edit else { return };
    let response = ui.add(egui::TextEdit::singleline(&mut edit.text).desired_width(160.0).hint_text(format!("{} bytes", edit.len)));
    if !response.has_focus() && !response.lost_focus() && edit.error.is_none() && edit.text.is_empty() {
        response.request_focus();
    }
    let entered = response.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
    let escaped = ui.input(|input| input.key_pressed(Key::Escape));
    if ui.small_button("Write").on_hover_text(if edit.little_endian { "Written little endian" } else { "Written big endian (network order)" }).clicked() || entered {
        actions.push(TreeAction::ApplyEdit);
    }
    if ui.small_button("Cancel").clicked() || escaped {
        actions.push(TreeAction::CancelEdit);
    }
    if let Some(error) = &edit.error {
        ui.label(RichText::new(error).small().color(theme::DANGER));
    }
}

/// The packet's bytes as an editable hex dump: click a byte, then type hex
/// digits to overwrite it; arrows move; Esc leaves. The chosen field is
/// shaded, and the byte under the main view's cursor is marked.
fn show_hex_editor(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui, bytes: &[u8], packet_offset: usize) {
    if bytes.is_empty() {
        ui.label(RichText::new("The packet is empty.").color(theme::TEXT_DIM));
        return;
    }
    let id = ui.make_persistent_id("packet-hex-editor");
    let has_focus = ui.memory(|memory| memory.has_focus(id));
    ui.label(RichText::new(if has_focus { "Type hex to overwrite · arrows move · Esc to stop" } else { "Click a byte to edit the packet" }).small().color(theme::TEXT_DIM));
    let rows = bytes.len().div_ceil(HEX_BYTES_PER_ROW);
    let row_width = HEX_OFFSET_COLUMN + HEX_BYTES_PER_ROW as f32 * HEX_CELL_WIDTH + HEX_ASCII_GAP + HEX_BYTES_PER_ROW as f32 * HEX_ASCII_WIDTH;
    let mut painted_rows: Vec<(usize, Rect)> = Vec::new();
    let output = egui::ScrollArea::both().id_salt("packet-hex").max_height(DETAIL_TREE_HEIGHT).auto_shrink([false, true]).show_rows(ui, HEX_ROW_HEIGHT, rows, |ui, range| {
        for row in range {
            let (rect, _) = ui.allocate_exact_size(vec2(row_width, HEX_ROW_HEIGHT), Sense::hover());
            paint_hex_row(state, ui, rect, row, bytes, has_focus);
            painted_rows.push((row, rect));
        }
    });
    let response = ui.interact(output.inner_rect, id, Sense::click());
    if response.clicked()
        && let Some(pointer) = response.interact_pointer_pos()
        && let Some(position) = byte_under_pointer(&painted_rows, pointer, bytes.len())
    {
        state.hex = panel::HexCursor { position, pending_low_nibble: false };
        response.request_focus();
        panel::select_in_document(state, app, packet_offset + position, 1, format!("Byte +{position}"));
    }
    if response.has_focus() {
        ui.memory_mut(|memory| {
            memory.set_focus_lock_filter(id, egui::EventFilter { tab: false, horizontal_arrows: true, vertical_arrows: true, escape: true })
        });
        handle_hex_keys(state, app, ui, bytes, packet_offset, &response);
    }
}

fn byte_under_pointer(rows: &[(usize, Rect)], pointer: egui::Pos2, len: usize) -> Option<usize> {
    let &(row, rect) = rows.iter().find(|(_, rect)| rect.y_range().contains(pointer.y))?;
    let x = pointer.x - rect.min.x - HEX_OFFSET_COLUMN;
    let ascii_start = HEX_BYTES_PER_ROW as f32 * HEX_CELL_WIDTH + HEX_ASCII_GAP;
    let column = if x < 0.0 {
        return None;
    } else if x < ascii_start {
        (x / HEX_CELL_WIDTH) as usize
    } else {
        ((x - ascii_start) / HEX_ASCII_WIDTH) as usize
    };
    let position = row * HEX_BYTES_PER_ROW + column.min(HEX_BYTES_PER_ROW - 1);
    (position < len).then_some(position)
}

fn paint_hex_row(state: &PacketsState, ui: &Ui, rect: Rect, row: usize, bytes: &[u8], has_focus: bool) {
    let painter = ui.painter_at(rect);
    let font = FontId::monospace(HEX_FONT_SIZE);
    let start = row * HEX_BYTES_PER_ROW;
    painter.text(rect.min, Align2::LEFT_TOP, format!("{start:04x}"), font.clone(), theme::TEXT_DIM);
    let field = state.selected_field;
    for (column, &byte) in bytes[start..(start + HEX_BYTES_PER_ROW).min(bytes.len())].iter().enumerate() {
        let position = start + column;
        let cell = Rect::from_min_size(rect.min + vec2(HEX_OFFSET_COLUMN + column as f32 * HEX_CELL_WIDTH, 0.0), vec2(HEX_CELL_WIDTH - 2.0, HEX_ROW_HEIGHT - 1.0));
        let ascii = Rect::from_min_size(
            rect.min + vec2(HEX_OFFSET_COLUMN + HEX_BYTES_PER_ROW as f32 * HEX_CELL_WIDTH + HEX_ASCII_GAP + column as f32 * HEX_ASCII_WIDTH, 0.0),
            vec2(HEX_ASCII_WIDTH, HEX_ROW_HEIGHT - 1.0),
        );
        if field.is_some_and(|(offset, len)| position >= offset && position < offset + len) {
            painter.rect_filled(cell, 2.0, theme::SELECTION);
            painter.rect_filled(ascii, 0.0, theme::SELECTION);
        }
        if state.cursor_in_packet == Some(position) {
            painter.rect_filled(cell, 2.0, theme::CURSOR_FILL);
        }
        if has_focus && state.hex.position == position {
            painter.rect_stroke(cell, 2.0, Stroke::new(1.5, theme::CURSOR), egui::StrokeKind::Inside);
        }
        let colour = if byte == 0 { theme::TEXT_DIM } else { theme::TEXT };
        painter.text(cell.left_top() + vec2(2.0, 0.0), Align2::LEFT_TOP, format!("{byte:02x}"), font.clone(), colour);
        let character = if (0x20..0x7F).contains(&byte) { byte as char } else { '.' };
        painter.text(ascii.left_top(), Align2::LEFT_TOP, character.to_string(), font.clone(), Color32::from_gray(170));
    }
}

fn handle_hex_keys(state: &mut PacketsState, app: &mut ViewerApp, ui: &Ui, bytes: &[u8], packet_offset: usize, response: &egui::Response) {
    let events = ui.input(|input| input.events.clone());
    let last = bytes.len() - 1;
    for event in events {
        match event {
            egui::Event::Text(text) => {
                for digit in text.chars().filter_map(|c| c.to_digit(16)) {
                    type_hex_digit(state, app, bytes, packet_offset, digit as u8);
                }
            }
            egui::Event::Key { key, pressed: true, .. } => {
                let position = &mut state.hex.position;
                match key {
                    Key::ArrowLeft => *position = position.saturating_sub(1),
                    Key::ArrowRight => *position = (*position + 1).min(last),
                    Key::ArrowUp => *position = position.saturating_sub(HEX_BYTES_PER_ROW),
                    Key::ArrowDown => *position = (*position + HEX_BYTES_PER_ROW).min(last),
                    Key::Escape => response.surrender_focus(),
                    _ => continue,
                }
                state.hex.pending_low_nibble = false;
            }
            _ => {}
        }
    }
}

/// Overwrite one nibble at the hex cursor, as `bytes.write`. The second
/// digit coalesces with the first, so a typed byte is one undo step, as in
/// the main hex view.
fn type_hex_digit(state: &mut PacketsState, app: &mut ViewerApp, bytes: &[u8], packet_offset: usize, digit: u8) {
    let position = state.hex.position.min(bytes.len() - 1);
    let at = packet_offset + position;
    let current = app.document.byte_at(at).unwrap_or(0);
    if state.hex.pending_low_nibble {
        let data = crate::ops::to_compact_hex(&[(current & 0xF0) | digit]);
        if app.perform("bytes.write", serde_json::json!({ "start": at, "data": data, "coalesce": true })).is_ok() {
            state.hex.pending_low_nibble = false;
            state.hex.position = (position + 1).min(bytes.len() - 1);
        }
    } else {
        let data = crate::ops::to_compact_hex(&[(digit << 4) | (current & 0x0F)]);
        if app.perform("bytes.write", serde_json::json!({ "start": at, "data": data })).is_ok() {
            state.hex.pending_low_nibble = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Conversations, endpoints and streams
// ---------------------------------------------------------------------------

/// Height of a list that fills most of the pane.
fn list_height(state: &PacketsState) -> f32 {
    (state.pane_height * LIST_SHARE).max(MIN_TABLE_HEIGHT)
}

fn ensure_statistics(state: &mut PacketsState) {
    if state.statistics.as_ref().is_some_and(|s| s.generation == state.rows_generation) {
        return;
    }
    let Some(set) = &state.set else { return };
    let flows = || state.rows.iter().zip(&set.packets).map(|(row, packet)| (row.flow.as_ref(), packet.len));
    state.statistics = Some(Statistics { generation: state.rows_generation, conversations: packets::conversations(flows()), endpoints: packets::endpoints(flows()) });
}

/// Collect the stream of `key` and show it.
fn follow(state: &mut PacketsState, key: &ConversationKey) {
    let bytes = Arc::clone(&state.bytes);
    let items = state.rows.iter().enumerate().filter_map(|(index, row)| {
        let flow = row.flow.as_ref()?;
        let (start, len) = row.payload?;
        let packet = bytes.packet(index);
        let end = (start + len).min(packet.len());
        Some((index, flow, packet.get(start..end).unwrap_or_default()))
    });
    let stream = packets::follow_stream(key, items);
    state.stream_http = if key.transport == packets::Transport::Tcp { packets::application::http::http_messages(&stream) } else { Vec::new() };
    state.stream = Some(stream);
    state.view = PacketsView::Stream;
}

pub fn show_conversations(state: &mut PacketsState, _app: &mut ViewerApp, ui: &mut Ui) {
    ensure_statistics(state);
    let Some(statistics) = &state.statistics else { return };
    if statistics.conversations.is_empty() {
        ui.label(RichText::new("No IP conversations: the packets have no addresses. Try another link type.").color(theme::TEXT_DIM));
        return;
    }
    let mut filter = None;
    let mut follow_key = None;
    ui.label(RichText::new(format!("{} conversations · both directions counted together", statistics.conversations.len())).small().color(theme::TEXT_DIM));
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y + 4.0;
    egui::ScrollArea::both().id_salt("packet-conversations").max_height(list_height(state)).auto_shrink([false, true]).show_rows(ui, row_height, statistics.conversations.len(), |ui, range| {
        for conversation in &statistics.conversations[range] {
            ui.horizontal(|ui| {
                if ui.small_button("Filter").on_hover_text("Show only this conversation's packets").clicked() {
                    filter = Some(conversation.key.filter_text());
                }
                if conversation.key.transport.has_ports() && ui.small_button("Follow").on_hover_text("The payloads of both directions, in order").clicked() {
                    follow_key = Some(conversation.key);
                }
                ui.label(
                    RichText::new(format!(
                        "{}  ·  {} packets, {} bytes  ·  A→B {} packets, {} bytes  ·  B→A {} packets, {} bytes",
                        conversation.key,
                        conversation.packets,
                        conversation.bytes,
                        conversation.packets_a_to_b,
                        conversation.bytes_a_to_b,
                        conversation.packets_b_to_a(),
                        conversation.bytes_b_to_a()
                    ))
                    .monospace(),
                );
            });
        }
    });
    if let Some(text) = filter {
        state.filter_text = text;
        state.view = PacketsView::Packets;
    }
    if let Some(key) = follow_key {
        follow(state, &key);
    }
}

pub fn show_endpoints(state: &mut PacketsState, ui: &mut Ui) {
    ensure_statistics(state);
    let Some(statistics) = &state.statistics else { return };
    if statistics.endpoints.is_empty() {
        ui.label(RichText::new("No IP endpoints: the packets have no addresses.").color(theme::TEXT_DIM));
        return;
    }
    let mut filter = None;
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y + 4.0;
    egui::ScrollArea::both().id_salt("packet-endpoints").max_height(list_height(state)).auto_shrink([false, true]).show_rows(ui, row_height, statistics.endpoints.len(), |ui, range| {
        for endpoint in &statistics.endpoints[range] {
            ui.horizontal(|ui| {
                if ui.small_button("Filter").clicked() {
                    filter = Some(format!("ip:{}", endpoint.address));
                }
                ui.label(
                    RichText::new(format!(
                        "{:<40} sent {} packets, {} bytes · received {} packets, {} bytes",
                        endpoint.address.to_string(),
                        endpoint.packets_sent,
                        endpoint.bytes_sent,
                        endpoint.packets_received,
                        endpoint.bytes_received
                    ))
                    .monospace(),
                );
            });
        }
    });
    if let Some(text) = filter {
        state.filter_text = text;
        state.view = PacketsView::Packets;
    }
}

pub fn show_stream(state: &mut PacketsState, app: &mut ViewerApp, ui: &mut Ui) {
    let Some(stream) = &state.stream else {
        ui.label(RichText::new("Choose Follow on a conversation, or Follow stream on a TCP or UDP packet.").color(theme::TEXT_DIM));
        return;
    };
    let mut open = false;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(stream.key.to_string()).strong());
        ui.label(
            RichText::new(format!(
                "{} segments, {} bytes{}{}",
                stream.segments.len(),
                stream.bytes.len(),
                if stream.retransmissions > 0 { format!(", {} retransmissions left out", stream.retransmissions) } else { String::new() },
                if stream.truncated { ", cut short at 16 MiB" } else { "" }
            ))
            .small()
            .color(theme::TEXT_DIM),
        );
        ui.checkbox(&mut state.stream_as_hex, "Hex");
        if ui.small_button("Copy as text").clicked() {
            ui.ctx().copy_text(stream.marked_text(1));
        }
        if ui.small_button("Open as document").on_hover_text("Both directions' payloads, one after the other").clicked() {
            open = true;
        }
    });
    let mut open_body = None;
    if state.stream_http.iter().any(|message| !message.body.is_empty()) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("HTTP").small().strong());
            for (index, message) in state.stream_http.iter().enumerate().filter(|(_, message)| !message.body.is_empty()) {
                let how = [message.chunked.then_some("de-chunked"), message.decoded.then_some("decompressed")].into_iter().flatten().collect::<Vec<_>>().join(", ");
                let hover = format!("{} bytes{}{}", message.body.len(), if how.is_empty() { String::new() } else { format!(", {how}") }, message.notes.iter().map(|note| format!("; {note}")).collect::<String>());
                if ui.small_button(format!("Open body as document: {}", fit(&message.start_line, 40))).on_hover_text(hover).clicked() {
                    open_body = Some(index);
                }
            }
        });
    }
    ui.label(RichText::new("→ from A to B (accent) · ← from B to A (amber)").small().color(theme::TEXT_DIM));
    egui::ScrollArea::both().id_salt("packet-stream").max_height(list_height(state)).auto_shrink([false, true]).show(ui, |ui| {
        ui.style_mut().wrap_mode = Some(TextWrapMode::Wrap);
        for segment in stream.segments.iter().take(STREAM_SEGMENTS_SHOWN) {
            let colour = if segment.a_to_b { theme::ACCENT } else { theme::CURSOR };
            let arrow = if segment.a_to_b { "→" } else { "←" };
            let bytes = &stream.bytes[segment.start..segment.start + segment.len];
            ui.label(RichText::new(format!("{arrow} packet {} · {} bytes", segment.packet + 1, segment.len)).small().color(colour));
            let body = if state.stream_as_hex {
                packets::hex_preview(bytes, STREAM_HEX_BYTES)
            } else {
                bytes.iter().map(|&byte| if byte == b'\n' || byte == b'\t' || (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect()
            };
            ui.label(RichText::new(body).monospace().color(colour));
        }
        if stream.segments.len() > STREAM_SEGMENTS_SHOWN {
            ui.label(RichText::new(format!("… {} more segments; open as a document to see them all", stream.segments.len() - STREAM_SEGMENTS_SHOWN)).color(theme::TEXT_DIM));
        }
    });
    if open {
        // The stream's bytes are reassembled, not a range of the document.
        let params = serde_json::json!({ "data": base64::engine::general_purpose::STANDARD.encode(&stream.bytes), "encoding": "base64", "name": format!("stream {}", stream.key) });
        open_as_document(state, app, params);
    }
    if let Some(message) = open_body.and_then(|index| state.stream_http.get(index)) {
        // The body as the sender meant it: de-chunked and decompressed.
        let params = serde_json::json!({ "data": base64::engine::general_purpose::STANDARD.encode(&message.body), "encoding": "base64", "name": format!("{} body", message.start_line) });
        open_as_document(state, app, params);
    }
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use super::*;
    use crate::app::Launch;
    use crate::document::Document;
    use crate::packets::{LinkKind, sources};

    /// An app whose document is one raw-IP UDP packet after 8 leading bytes,
    /// shown in the packet viewer and focused.
    fn one_packet() -> (PacketsState, ViewerApp, usize, Vec<u8>) {
        let builder = PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).udp(4000, 53);
        let mut packet = Vec::new();
        builder.write(&mut packet, b"payload").unwrap();
        let mut document = vec![0xEEu8; 8];
        document.extend_from_slice(&packet);
        let mut app = ViewerApp::new(Launch::default());
        app.document = Document::from_bytes(document);
        let mut state = PacketsState::default();
        state.set = sources::single(8, packet.len(), LinkKind::RawIp).ok();
        state.focus = Some(0);
        (state, app, 8, packet)
    }

    #[test]
    fn typing_two_hex_digits_overwrites_one_byte_as_one_undo_step() {
        let (mut state, mut app, at, packet) = one_packet();
        state.hex.position = 9; // the protocol byte
        crate::actions::take_performed();
        type_hex_digit(&mut state, &mut app, &packet, at, 0x0);
        type_hex_digit(&mut state, &mut app, &packet, at, 0x6);
        assert_eq!(
            crate::actions::take_performed(),
            [
                ("bytes.write".to_string(), serde_json::json!({ "start": at + 9, "data": "01" })),
                ("bytes.write".to_string(), serde_json::json!({ "start": at + 9, "data": "06", "coalesce": true })),
            ]
        );
        assert_eq!(app.document.byte_at(at + 9), Some(6));
        assert_eq!(state.hex.position, 10, "the cursor moves on after a whole byte");
        app.document.undo();
        assert_eq!(app.document.byte_at(at + 9), Some(17), "one undo restores the byte");
    }

    #[test]
    fn a_typed_field_value_is_written_in_network_order_and_checksums_can_then_be_fixed() {
        let (mut state, mut app, at, _) = one_packet();
        crate::actions::take_performed();
        act_on_tree(&mut state, &mut app, TreeAction::StartEdit { offset: 22, len: 2, little_endian: false, text: "123".to_string() }, at);
        act_on_tree(&mut state, &mut app, TreeAction::ApplyEdit, at);
        assert!(state.field_edit.is_none());
        assert_eq!(app.document.read_range(at + 22, 2), vec![0, 123]);
        assert_eq!(
            crate::actions::take_performed(),
            [("packets.write_field".to_string(), serde_json::json!({ "set": "set-1", "index": 0, "offset": 22, "len": 2, "value": "123", "little_endian": false }))]
        );
        let edited = app.document.read_range(at, 64);
        assert_eq!(edit::checksum_repairs(&edited, &packets::dissect(&edited, LinkKind::RawIp)).len(), 1, "the UDP checksum is now wrong");

        fix_checksums(&mut state, &mut app);
        assert_eq!(crate::actions::take_performed(), [("packets.fix_checksums".to_string(), serde_json::json!({ "set": "set-1", "indices": [0] }))]);
        assert_eq!(state.note.as_ref().map(|note| note.text.as_str()), Some("Fixed 1 checksums (UDP). Undo with Cmd+Z."));
        let fixed = app.document.read_range(at, 64);
        assert!(edit::checksum_repairs(&fixed, &packets::dissect(&fixed, LinkKind::RawIp)).is_empty());
        assert_eq!(app.document.undo_label(), Some("Fix checksums"));

        act_on_tree(&mut state, &mut app, TreeAction::StartEdit { offset: 22, len: 2, little_endian: false, text: "70000".to_string() }, at);
        act_on_tree(&mut state, &mut app, TreeAction::ApplyEdit, at);
        assert!(state.field_edit.as_ref().and_then(|e| e.error.as_ref()).is_some_and(|e| e.contains("65535")));
        assert!(crate::actions::take_performed().is_empty(), "a value that does not fit is not written");
    }

    #[test]
    fn inverting_the_chosen_field_of_each_packet_is_one_call_and_one_undo_step() {
        let (mut state, mut app, at, _) = one_packet();
        state.selected_field = Some((22, 2));
        state.operation_on_field = true;
        crate::actions::take_performed();
        apply_operation(&mut state, &mut app, &ByteOperation::Xor(vec![0xFF]));
        assert_eq!(
            crate::actions::take_performed(),
            [("packets.apply".to_string(), serde_json::json!({ "set": "set-1", "indices": [0], "op": "xor", "key": "ff", "field": { "offset": 22, "len": 2 } }))]
        );
        assert_eq!(app.document.read_range(at + 22, 2), [0xFF, 0xCA], "port 53 XORed");
        assert_eq!(state.note.as_ref().map(|note| note.text.as_str()), Some("XORed the chosen field of 1 packets. Undo with Cmd+Z."));
        app.document.undo();
        assert_eq!(app.document.read_range(at + 22, 2), [0, 53]);
    }

    #[test]
    fn opening_the_chosen_packets_as_a_document_derives_one_from_their_bytes() {
        let (mut state, mut app, at, packet) = one_packet();
        crate::actions::take_performed();
        extract_selected(&mut state, &mut app, true);
        assert_eq!(crate::actions::take_performed(), [("documents.derive".to_string(), serde_json::json!({ "ranges": [[at, packet.len()]], "name": "packet 1" }))]);
        assert_eq!(app.document.read_range(0, packet.len()), packet);
        assert!(state.foreign_document, "the packets describe the document left behind");
    }

    #[test]
    fn opening_only_the_chosen_field_takes_it_from_each_packet_cut_short_at_the_end() {
        let (mut state, mut app, at, packet) = one_packet();
        state.selected = BTreeSet::from([0]);
        state.selected_field = Some((28, 4096));
        state.operation_on_field = true;
        crate::actions::take_performed();
        extract_selected(&mut state, &mut app, true);
        assert_eq!(
            crate::actions::take_performed(),
            [("documents.derive".to_string(), serde_json::json!({ "ranges": [[at + 28, packet.len() - 28]], "name": "field of packet 1" }))]
        );
        assert_eq!(app.document.read_range(0, packet.len() - 28), &packet[28..]);
        app.bench.panels.packets = state;
        assert!(app.packet_selection_ranges().is_empty(), "the packets' offsets belong to the document left behind, so nothing is drawn here");
    }
}
