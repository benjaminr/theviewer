//! The methods that change a set's packets in the document (delete them,
//! fix their checksums, invert, fill or XOR them, write a field, change or
//! remove columns), and those that read parts of them (their bytes, their
//! columns as text).
//!
//! Each change is one undoable step over the packets it touches, named in
//! the undo history by what it did and who did it, and published on
//! `document.edited` as the caller's. Packets are named by their index in
//! the set, never by a position in a filtered list.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::super::values::{self, ByteEncoding};
use super::super::workspace::{DOCUMENT_PRODUCER, Workspace};
use super::super::{ApiError, Caller, ErrorCode};
use super::{PACKET_READ_LIMIT, StoredSet, decode, packet_index, packet_indices, unknown_set, with_set};
use crate::document::Document;
use crate::packets::edit::{self, ByteOperation};
use crate::packets::grid::{self, ColumnOperation, ColumnSlice, ColumnText, RowPlacement};
use crate::packets::sources::Recipe;
use crate::packets::{self, Packet};

/// Most bytes one replacing edit may span; wider changes are made range by
/// range, still as one undoable step.
pub const SINGLE_EDIT_LIMIT: usize = 64 * 1024 * 1024;
/// Most bytes of the columns read as text.
const COLUMN_TEXT_LIMIT: usize = 16 * 1024 * 1024;

/// Parameters naming some of a set's packets.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IndicesParams {
    pub set: String,
    /// The packets, by their index in the set.
    pub indices: Vec<u64>,
}

/// What a change to a set's packets did.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PacketEditResult {
    /// Id of the document edited.
    pub doc: String,
    /// The document's version and length after the change.
    pub version: u64,
    pub len: u64,
    /// What the step is called in the undo history; absent when nothing
    /// needed changing.
    pub label: Option<String>,
    /// Packets changed.
    pub packets: u64,
    /// The document ranges changed, as [start, len].
    pub ranges: Vec<(u64, u64)>,
    /// Bytes removed from the document.
    pub bytes_removed: u64,
    /// For packets.fix_checksums: each checksum rewritten, such as "UDP".
    pub checksums: Vec<String>,
}

/// An operation on whole packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PacketOp {
    Invert,
    /// Repeat `key` from the start of each packet (or field).
    Fill,
    /// XOR with `key`, restarting at the start of each packet (or field).
    Xor,
}

/// The same field in every packet, from each packet's first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldSpan {
    pub offset: usize,
    pub len: usize,
}

impl FieldSpan {
    /// The field's bytes in a packet of `packet_len` bytes, as
    /// `(offset, len)` from its first byte, cut short at the packet's end;
    /// none when the packet ends before the field starts.
    pub fn within(&self, packet_len: usize) -> Option<(usize, usize)> {
        (self.offset < packet_len).then(|| (self.offset, self.len.min(packet_len - self.offset)))
    }
}

/// Parameters of `packets.apply`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyParams {
    pub set: String,
    /// The packets, by their index in the set.
    pub indices: Vec<u64>,
    pub op: PacketOp,
    /// Hex bytes for fill and XOR.
    #[serde(default)]
    pub key: Option<String>,
    /// Only this field of each packet; packets too short to hold it are left alone.
    #[serde(default)]
    pub field: Option<FieldSpan>,
}

/// Parameters of `packets.write_field`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteFieldParams {
    pub set: String,
    /// The packet's index in the set.
    pub index: u64,
    /// Where the field is, from the packet's first byte.
    pub offset: usize,
    pub len: usize,
    /// A whole number (decimal or 0x hex), an IPv4 or IPv6 address, a MAC
    /// address, or exactly len hex bytes.
    pub value: String,
    /// Write a number least significant byte first (big-endian, network
    /// order, by default).
    #[serde(default)]
    pub little_endian: bool,
}

/// Parameters naming columns of a set's packets laid out one per row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ColumnsParams {
    pub set: String,
    /// The first column, a byte offset into each row.
    pub first: usize,
    /// Columns, at least 1.
    pub width: usize,
    /// Only these packets, by their index in the set, in row order; every
    /// packet when omitted.
    #[serde(default)]
    pub indices: Option<Vec<u64>>,
    /// How far each row is shifted right to line the rows up, one per packet
    /// in `indices` (or per packet of the set); none by default.
    #[serde(default)]
    pub shifts: Option<Vec<usize>>,
    /// Rows start at each packet's capture record header rather than its data.
    #[serde(default)]
    pub record_headers: bool,
}

/// What a column operation does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ColumnOp {
    Invert,
    /// Repeat `key` across the columns.
    Fill,
    /// XOR with `key`, restarting at the first column of each packet.
    Xor,
    /// Add `key` byte by byte, wrapping.
    Add,
    /// Write `value` (a number, or exactly as many hex bytes as columns).
    Set,
    /// Write `start` + `step` × n into the nth packet.
    Counter,
    /// Reverse each group of `group` bytes.
    Swap,
}

/// Parameters of `packets.columns.apply`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ColumnOperationParams {
    pub set: String,
    pub first: usize,
    pub width: usize,
    #[serde(default)]
    pub indices: Option<Vec<u64>>,
    #[serde(default)]
    pub shifts: Option<Vec<usize>>,
    #[serde(default)]
    pub record_headers: bool,
    pub op: ColumnOp,
    /// Hex bytes for fill, XOR and add.
    #[serde(default)]
    pub key: Option<String>,
    /// For set: a number, or exactly as many hex bytes as columns.
    #[serde(default)]
    pub value: Option<String>,
    /// For counter: the first packet's number (0 by default).
    #[serde(default)]
    pub start: u64,
    /// For counter: added for each packet after (1 by default).
    #[serde(default = "one")]
    pub step: i64,
    /// For swap: bytes in each group reversed (2, 4 or 8).
    #[serde(default)]
    pub group: Option<usize>,
    /// For set and counter: write numbers least significant byte first.
    #[serde(default)]
    pub little_endian: bool,
}

fn one() -> i64 {
    1
}

impl ColumnOperationParams {
    fn columns(&self) -> ColumnsParams {
        ColumnsParams { set: self.set.clone(), first: self.first, width: self.width, indices: self.indices.clone(), shifts: self.shifts.clone(), record_headers: self.record_headers }
    }
}

/// How columns are written as text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ColumnFormat {
    /// One line per packet: its number, then the bytes as hex.
    #[default]
    Hex,
    /// A table: packet, document offset, then one hex cell per column.
    Csv,
}

/// Parameters of `packets.columns.read`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ColumnsReadParams {
    pub set: String,
    pub first: usize,
    pub width: usize,
    #[serde(default)]
    pub indices: Option<Vec<u64>>,
    #[serde(default)]
    pub shifts: Option<Vec<usize>>,
    #[serde(default)]
    pub record_headers: bool,
    #[serde(default)]
    pub format: ColumnFormat,
}

/// The result of `packets.columns.read`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ColumnsText {
    pub text: String,
    /// Packets written.
    pub packets: u64,
    /// Packets that reach the columns but were left out, past 16 MiB.
    pub left_out: u64,
}

/// Parameters of `packets.extract`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtractParams {
    pub set: String,
    /// The packets, by their index in the set, in the order wanted.
    pub indices: Vec<u64>,
    /// Only this field of each packet (a transfer's data blocks without
    /// their headers, say), cut short where a packet ends; packets that end
    /// before it starts give nothing.
    #[serde(default)]
    pub field: Option<FieldSpan>,
    /// Write the bytes here instead of returning them; needs leave to edit,
    /// as writing a file does.
    #[serde(default)]
    pub path: Option<String>,
    /// How the returned bytes are written: base64 (the default) or hex.
    #[serde(default = "base64_by_default")]
    pub encoding: ByteEncoding,
}

fn base64_by_default() -> ByteEncoding {
    ByteEncoding::Base64
}

/// The result of `packets.extract`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExtractResult {
    /// Packets taken.
    pub count: u64,
    /// Bytes taken.
    pub len: u64,
    /// The bytes, when no path was given.
    pub data: Option<String>,
    /// Where they were written, when a path was given.
    pub path: Option<String>,
}

/// What a change made inside its step.
#[derive(Default)]
struct Changed {
    packets: usize,
    ranges: Vec<(usize, usize)>,
    bytes_removed: usize,
    checksums: Vec<String>,
}

/// Run `change` on set `id` and its document as one undoable step called
/// `action` (as `caller` did it), publishing the edit as the caller's.
/// `change` returns `None` when there was nothing to change, and no step
/// is made.
fn edit_packets(
    workspace: &mut dyn Workspace,
    caller: &Caller,
    id: &str,
    action: &str,
    change: impl FnOnce(&mut StoredSet, &mut Document) -> Result<Option<Changed>, ApiError>,
) -> Result<PacketEditResult, ApiError> {
    let doc = workspace.packet_sets().get(id).map(|stored| stored.info.doc.clone()).ok_or_else(|| unknown_set(id))?;
    workspace.publish_edits(&doc, DOCUMENT_PRODUCER);
    let label = caller.label(action);
    let outcome = with_set(workspace, id, |stored, document| {
        let changed = document.transaction(label.clone(), |document| change(stored, document))?;
        // Packets placed by hand are not found again: the change kept them right.
        if stored.packets.recipe == Recipe::Fixed {
            stored.built = (document.version(), document.len());
        }
        stored.decoded = None;
        Ok((changed, document.version(), document.len()))
    })?;
    workspace.publish_edits(&doc, &caller.producer());
    let (changed, version, len) = outcome;
    let made = changed.is_some();
    let changed = changed.unwrap_or_default();
    Ok(PacketEditResult {
        doc,
        version,
        len: len as u64,
        label: made.then_some(label),
        packets: changed.packets as u64,
        ranges: changed.ranges.iter().map(|&(start, len)| (start as u64, len as u64)).collect(),
        bytes_removed: changed.bytes_removed as u64,
        checksums: changed.checksums,
    })
}

/// Write `(offset, bytes)` patches as one replacement over the span they
/// cover when it is narrow enough, else patch by patch.
fn write_patches(document: &mut Document, patches: &[(usize, Vec<u8>)]) {
    let ranges: Vec<(usize, usize)> = patches.iter().map(|(offset, bytes)| (*offset, bytes.len())).collect();
    let Some((start, len)) = edit::covering_span(&ranges) else { return };
    if len <= SINGLE_EDIT_LIMIT {
        let mut span = document.read_range(start, len);
        for (offset, bytes) in patches {
            let at = offset - start;
            let end = (at + bytes.len()).min(span.len());
            if at < end {
                span[at..end].copy_from_slice(&bytes[..end - at]);
            }
        }
        let span_len = span.len();
        document.replace(start, span_len, &span);
    } else {
        for (offset, bytes) in patches {
            document.overwrite(*offset, bytes);
        }
    }
}

/// Hex bytes given as a key, which must not be empty.
fn key_bytes(key: Option<&str>, what: &str) -> Result<Vec<u8>, ApiError> {
    let text = key.ok_or_else(|| ApiError::invalid_params(format!("{what} needs key, the hex bytes to use")))?;
    match packets::parse_hex(text) {
        Ok(bytes) if !bytes.is_empty() => Ok(bytes),
        Ok(_) => Err(ApiError::invalid_params(format!("{what} needs at least one key byte"))),
        Err(reason) => Err(ApiError::invalid_params(format!("the key is not hex bytes: {reason}"))),
    }
}

pub fn delete(workspace: &mut dyn Workspace, caller: &Caller, params: IndicesParams) -> Result<PacketEditResult, ApiError> {
    edit_packets(workspace, caller, &params.set, "Delete packets", |stored, document| {
        let chosen = packet_indices(stored, &params.indices)?;
        let removed = edit::merge_ranges(chosen.iter().map(|&index| stored.packets.packets[index].removal_range()).collect());
        let Some((start, len)) = edit::covering_span(&removed) else { return Ok(None) };
        if len <= SINGLE_EDIT_LIMIT {
            let span = document.read_range(start, len);
            let kept = edit::without_ranges(&span, start, &removed);
            document.replace(start, span.len(), &kept);
        } else {
            for &(offset, len) in removed.iter().rev() {
                document.delete(offset, len);
            }
        }
        if stored.packets.recipe == Recipe::Fixed {
            let kept: Vec<Packet> = std::mem::take(&mut stored.packets.packets)
                .into_iter()
                .enumerate()
                .filter(|(index, _)| !chosen.contains(index))
                .filter_map(|(_, packet)| Some(Packet { offset: edit::offset_after_deletion(packet.offset, &removed)?, record: None, ..packet }))
                .collect();
            stored.packets.packets = kept;
            stored.info.count = stored.packets.len() as u64;
        }
        let bytes_removed = removed.iter().map(|&(_, len)| len).sum();
        Ok(Some(Changed { packets: chosen.len(), ranges: vec![(start, 0)], bytes_removed, checksums: Vec::new() }))
    })
}

pub fn fix_checksums(workspace: &mut dyn Workspace, caller: &Caller, params: IndicesParams) -> Result<PacketEditResult, ApiError> {
    edit_packets(workspace, caller, &params.set, "Fix checksums", |stored, document| {
        let chosen = packet_indices(stored, &params.indices)?;
        decode(stored, document);
        let raw = stored.decoded.as_ref().expect("decoded").raw.clone();
        let mut patches = Vec::new();
        let mut checksums = Vec::new();
        let mut packets_fixed = 0;
        for index in chosen {
            let packet = &stored.packets.packets[index];
            let bytes = document.read_range(packet.offset, packet.len.min(PACKET_READ_LIMIT));
            let dissection = packets::dissect_with(&bytes, packet.link, &raw);
            let repairs = edit::checksum_repairs(&bytes, &dissection);
            packets_fixed += usize::from(!repairs.is_empty());
            for repair in repairs {
                checksums.push(repair.what.to_string());
                patches.push((packet.offset + repair.offset, repair.bytes.to_vec()));
            }
        }
        if patches.is_empty() {
            return Ok(None);
        }
        write_patches(document, &patches);
        let ranges = patches.iter().map(|(offset, bytes)| (*offset, bytes.len())).collect();
        Ok(Some(Changed { packets: packets_fixed, ranges, bytes_removed: 0, checksums }))
    })
}

pub fn apply(workspace: &mut dyn Workspace, caller: &Caller, params: ApplyParams) -> Result<PacketEditResult, ApiError> {
    let (operation, action) = match params.op {
        PacketOp::Invert => (ByteOperation::Invert, "Invert packets"),
        PacketOp::Fill => (ByteOperation::Fill(key_bytes(params.key.as_deref(), "fill")?), "Fill packets"),
        PacketOp::Xor => (ByteOperation::Xor(key_bytes(params.key.as_deref(), "xor")?), "XOR packets"),
    };
    edit_packets(workspace, caller, &params.set, action, |stored, document| {
        let chosen = packet_indices(stored, &params.indices)?;
        let ranges: Vec<(usize, usize)> = chosen
            .iter()
            .map(|&index| &stored.packets.packets[index])
            .filter_map(|packet| match params.field {
                None => Some((packet.offset, packet.len)),
                Some(FieldSpan { offset, len }) if offset < packet.len => Some((packet.offset + offset, len.min(packet.len - offset))),
                Some(_) => None,
            })
            .collect();
        let Some((start, len)) = edit::covering_span(&ranges) else {
            return Err(ApiError::invalid_params("nothing to change: no packet holds the chosen field"));
        };
        if len <= SINGLE_EDIT_LIMIT {
            let mut span = document.read_range(start, len);
            edit::apply_to_ranges(&mut span, start, &ranges, &operation);
            let span_len = span.len();
            document.replace(start, span_len, &span);
        } else {
            for &(offset, len) in &ranges {
                let mut bytes = document.read_range(offset, len);
                operation.apply(&mut bytes);
                document.overwrite(offset, &bytes);
            }
        }
        Ok(Some(Changed { packets: ranges.len(), ranges, bytes_removed: 0, checksums: Vec::new() }))
    })
}

pub fn write_field(workspace: &mut dyn Workspace, caller: &Caller, params: WriteFieldParams) -> Result<PacketEditResult, ApiError> {
    let bytes = edit::encode_value(&params.value, params.len, params.little_endian).map_err(ApiError::invalid_params)?;
    edit_packets(workspace, caller, &params.set, "Write field", |stored, document| {
        let index = packet_index(stored, params.index)?;
        let packet = &stored.packets.packets[index];
        if params.offset + params.len > packet.len {
            return Err(ApiError::out_of_range(format!("packet {} holds {} bytes; a field of {} at +{} runs past its end", params.index, packet.len, params.len, params.offset)));
        }
        let at = packet.offset + params.offset;
        document.overwrite(at, &bytes);
        Ok(Some(Changed { packets: 1, ranges: vec![(at, bytes.len())], bytes_removed: 0, checksums: Vec::new() }))
    })
}

/// The bytes of the chosen columns in each row `params` names, the rows in
/// the order given and each named by its packet's index.
fn column_slices(stored: &StoredSet, params: &ColumnsParams) -> Result<Vec<ColumnSlice>, ApiError> {
    if params.width == 0 {
        return Err(ApiError::invalid_params("width must be at least 1 column"));
    }
    let rows: Vec<usize> = match &params.indices {
        Some(indices) => packet_indices(stored, indices)?,
        None => (0..stored.packets.len()).collect(),
    };
    let shifts = match &params.shifts {
        Some(shifts) if shifts.len() != rows.len() => return Err(ApiError::invalid_params(format!("give one shift per row: {} rows, {} shifts", rows.len(), shifts.len()))),
        Some(shifts) => shifts.clone(),
        None => vec![0; rows.len()],
    };
    let placements: Vec<(usize, RowPlacement)> = rows
        .iter()
        .zip(shifts)
        .map(|(&index, shift)| {
            let packet = &stored.packets.packets[index];
            let (offset, len) = if params.record_headers { packet.record.unwrap_or((packet.offset, packet.len)) } else { (packet.offset, packet.len) };
            (index, RowPlacement { offset, len, shift })
        })
        .collect();
    Ok(grid::column_slices(&placements, params.first, params.width))
}

/// The span `slices` cover, refused when no row reaches the columns or the
/// span is too wide for one edit.
fn columns_span(slices: &[ColumnSlice], ranges: &[(usize, usize)]) -> Result<(usize, usize), ApiError> {
    let Some((start, len)) = edit::covering_span(ranges) else {
        return Err(ApiError::invalid_params("no packet reaches the chosen columns"));
    };
    if len > SINGLE_EDIT_LIMIT {
        return Err(ApiError::too_large(format!("the {} packets span {}, more than one edit may cover; choose fewer packets", slices.len(), crate::compress::human_bytes(len))));
    }
    Ok((start, len))
}

pub fn apply_to_columns(workspace: &mut dyn Workspace, caller: &Caller, params: ColumnOperationParams) -> Result<PacketEditResult, ApiError> {
    let operation = match params.op {
        ColumnOp::Invert => ColumnOperation::Invert,
        ColumnOp::Fill => ColumnOperation::Fill(key_bytes(params.key.as_deref(), "fill")?),
        ColumnOp::Xor => ColumnOperation::Xor(key_bytes(params.key.as_deref(), "xor")?),
        ColumnOp::Add => ColumnOperation::Add(key_bytes(params.key.as_deref(), "add")?),
        ColumnOp::Set => {
            let value = params.value.as_deref().ok_or_else(|| ApiError::invalid_params("set needs value, a number or as many hex bytes as columns"))?;
            ColumnOperation::Set(edit::encode_value(value, params.width, params.little_endian).map_err(ApiError::invalid_params)?)
        }
        ColumnOp::Counter => ColumnOperation::Counter { start: params.start, step: params.step, little_endian: params.little_endian },
        ColumnOp::Swap => match params.group {
            Some(group) if group > 1 && group <= params.width => ColumnOperation::SwapByteOrder { group },
            _ => return Err(ApiError::invalid_params("swap needs group, 2, 4 or 8 bytes and no wider than the columns")),
        },
    };
    let action = format!("{} columns", operation.label());
    let columns = params.columns();
    edit_packets(workspace, caller, &params.set, &action, |stored, document| {
        let slices = column_slices(stored, &columns)?;
        let ranges: Vec<(usize, usize)> = slices.iter().map(|slice| (slice.offset, slice.len)).collect();
        let (start, len) = columns_span(&slices, &ranges)?;
        let mut span = document.read_range(start, len);
        grid::apply_to_columns(&mut span, start, &slices, columns.width, &operation);
        let span_len = span.len();
        document.replace(start, span_len, &span);
        Ok(Some(Changed { packets: slices.len(), ranges, bytes_removed: 0, checksums: Vec::new() }))
    })
}

pub fn delete_columns(workspace: &mut dyn Workspace, caller: &Caller, params: ColumnsParams) -> Result<PacketEditResult, ApiError> {
    edit_packets(workspace, caller, &params.set, "Delete columns", |stored, document| {
        let slices = column_slices(stored, &params)?;
        let removed = grid::deletion_ranges(&slices);
        let (start, len) = columns_span(&slices, &removed)?;
        let span = document.read_range(start, len);
        let kept = edit::without_ranges(&span, start, &removed);
        document.replace(start, span.len(), &kept);
        // Records cut from every packet whole make every record shorter.
        let every_row_whole = slices.len() == stored.packets.len() && slices.iter().all(|slice| slice.len == params.width);
        if let Recipe::Records { record_len, .. } = &mut stored.packets.recipe
            && every_row_whole
            && !params.record_headers
        {
            *record_len = record_len.saturating_sub(params.width).max(1);
            stored.params.record_len = Some(*record_len);
        }
        let bytes_removed = removed.iter().map(|&(_, len)| len).sum();
        Ok(Some(Changed { packets: slices.len(), ranges: vec![(start, 0)], bytes_removed, checksums: Vec::new() }))
    })
}

pub fn read_columns(workspace: &mut dyn Workspace, params: ColumnsReadParams) -> Result<ColumnsText, ApiError> {
    let columns = ColumnsParams { set: params.set.clone(), first: params.first, width: params.width, indices: params.indices.clone(), shifts: params.shifts.clone(), record_headers: params.record_headers };
    with_set(workspace, &params.set, |stored, document| {
        let slices = column_slices(stored, &columns)?;
        let mut contents = Vec::new();
        let mut total = 0usize;
        for slice in &slices {
            if total + slice.len > COLUMN_TEXT_LIMIT {
                break;
            }
            total += slice.len;
            contents.push((slice.row, slice.offset, document.read_range(slice.offset, slice.len)));
        }
        let rows: Vec<ColumnText<'_>> = contents.iter().map(|(packet, offset, bytes)| ColumnText { packet: *packet, offset: *offset, bytes }).collect();
        let text = match params.format {
            ColumnFormat::Hex => grid::columns_as_hex(&rows),
            ColumnFormat::Csv => grid::columns_as_csv(&rows, params.first, params.width),
        };
        Ok(ColumnsText { text, packets: rows.len() as u64, left_out: (slices.len() - rows.len()) as u64 })
    })
}

pub fn extract(workspace: &mut dyn Workspace, params: ExtractParams) -> Result<ExtractResult, ApiError> {
    let (count, bytes) = with_set(workspace, &params.set, |stored, document| {
        let chosen = packet_indices(stored, &params.indices)?;
        let mut bytes = Vec::new();
        for &index in &chosen {
            let packet = &stored.packets.packets[index];
            let packet_len = packet.len.min(PACKET_READ_LIMIT);
            let span = match params.field {
                Some(field) => field.within(packet_len),
                None => Some((0, packet_len)),
            };
            if let Some((offset, len)) = span {
                bytes.extend(document.read_range(packet.offset + offset, len));
            }
        }
        Ok((chosen.len(), bytes))
    })?;
    match params.path {
        Some(path) => {
            std::fs::write(Path::new(&path), &bytes).map_err(|error| ApiError::new(ErrorCode::Unavailable, format!("could not write {path}: {error}")))?;
            Ok(ExtractResult { count: count as u64, len: bytes.len() as u64, data: None, path: Some(path) })
        }
        None => {
            values::check_call_size(bytes.len())?;
            Ok(ExtractResult { count: count as u64, len: bytes.len() as u64, data: Some(values::encode_bytes(&bytes, params.encoding)), path: None })
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    /// Five records of eight bytes, 0x00 to 0x27, cut into a set.
    fn records() -> crate::api::HeadlessWorkspace {
        let bytes: Vec<u8> = (0..40u8).collect();
        let mut workspace = workspace_with("records.bin", &bytes);
        call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8})).unwrap();
        workspace
    }

    fn read(workspace: &mut crate::api::HeadlessWorkspace, start: u64, len: u64) -> Vec<u8> {
        let read = call(workspace, "bytes.read", json!({"start": start, "len": len})).unwrap();
        crate::ops::parse_hex(read["data"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn xoring_a_column_of_some_packets_changes_only_their_bytes_in_one_undo_step() {
        let mut workspace = records();
        let result = call(&mut workspace, "packets.columns.apply", json!({"set": "set-1", "first": 2, "width": 2, "indices": [1, 3], "op": "xor", "key": "ff"})).unwrap();
        assert_eq!(result["packets"], 2);
        assert_eq!(result["label"], "XORed columns");
        let bytes = read(&mut workspace, 0, 40);
        for (at, &byte) in bytes.iter().enumerate() {
            let changed = [10, 11, 26, 27].contains(&at);
            assert_eq!(byte, if changed { at as u8 ^ 0xFF } else { at as u8 }, "byte {at}");
        }
        call(&mut workspace, "history.undo", json!({})).unwrap();
        assert_eq!(read(&mut workspace, 0, 40), (0..40u8).collect::<Vec<_>>(), "one undo restores both packets");
    }

    #[test]
    fn a_shifted_row_has_its_columns_counted_from_where_it_is_drawn() {
        let mut workspace = records();
        call(&mut workspace, "packets.columns.apply", json!({"set": "set-1", "first": 2, "width": 1, "indices": [0, 1], "shifts": [0, 2], "op": "set", "value": "0x99"})).unwrap();
        let bytes = read(&mut workspace, 0, 16);
        assert_eq!((bytes[2], bytes[8], bytes[10]), (0x99, 0x99, 10), "the second row starts two columns in, so column 2 is its first byte");
    }

    #[test]
    fn deleting_a_column_of_every_record_makes_every_record_shorter() {
        let mut workspace = records();
        let result = call(&mut workspace, "packets.columns.delete", json!({"set": "set-1", "first": 0, "width": 3})).unwrap();
        assert_eq!(result["bytes_removed"], 15);
        let listed = call(&mut workspace, "packets.list", json!({"set": "set-1"})).unwrap();
        assert_eq!(listed["total"], 5);
        assert!(listed["packets"].as_array().unwrap().iter().all(|packet| packet["len"] == 5), "{listed}");
    }

    #[test]
    fn column_operations_refuse_what_they_cannot_do() {
        let mut workspace = records();
        let refused = |workspace: &mut crate::api::HeadlessWorkspace, params| call(workspace, "packets.columns.apply", params).unwrap_err().code;
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "first": 0, "width": 1, "op": "xor"})), ErrorCode::InvalidParams, "xor needs a key");
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "first": 20, "width": 1, "op": "invert"})), ErrorCode::InvalidParams, "no record reaches column 20");
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "first": 0, "width": 1, "op": "invert", "indices": [9]})), ErrorCode::OutOfRange);
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "first": 0, "width": 1, "op": "invert", "indices": [0], "shifts": [1, 2]})), ErrorCode::InvalidParams);
        assert_eq!(refused(&mut workspace, json!({"set": "set-9", "first": 0, "width": 1, "op": "invert"})), ErrorCode::NotFound);
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "first": 0, "width": 1, "op": "set", "value": "300"})), ErrorCode::InvalidParams, "300 does not fit in a byte");
    }

    #[test]
    fn columns_read_as_csv_name_each_packet_and_its_offset() {
        let mut workspace = records();
        let read = call(&mut workspace, "packets.columns.read", json!({"set": "set-1", "first": 1, "width": 2, "indices": [0, 4], "format": "csv"})).unwrap();
        assert_eq!(read["text"], "packet,offset,+1,+2\n0,0x1,01,02\n4,0x21,21,22\n", "packets by their index in the set, as every method numbers them");
    }

    #[test]
    fn a_field_of_each_chosen_packet_is_filled_and_short_packets_are_refused() {
        let mut workspace = records();
        call(&mut workspace, "packets.apply", json!({"set": "set-1", "indices": [0, 2], "op": "fill", "key": "aa", "field": {"offset": 6, "len": 4}})).unwrap();
        let bytes = read(&mut workspace, 0, 24);
        assert_eq!(&bytes[..8], &[0, 1, 2, 3, 4, 5, 0xAA, 0xAA], "cut at the packet's end");
        assert_eq!(&bytes[16..24], &[16, 17, 18, 19, 20, 21, 0xAA, 0xAA]);
        assert_eq!(bytes[14], 14, "packet 1 was not chosen");
        let nothing = call(&mut workspace, "packets.apply", json!({"set": "set-1", "indices": [0], "op": "invert", "field": {"offset": 8, "len": 1}})).unwrap_err();
        assert_eq!(nothing.code, ErrorCode::InvalidParams, "no packet holds the field");
        assert_eq!(call(&mut workspace, "packets.apply", json!({"set": "set-1", "indices": [0], "op": "xor"})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn a_field_value_is_written_in_network_order_unless_asked_otherwise() {
        let mut workspace = records();
        call(&mut workspace, "packets.write_field", json!({"set": "set-1", "index": 1, "offset": 2, "len": 2, "value": "258"})).unwrap();
        call(&mut workspace, "packets.write_field", json!({"set": "set-1", "index": 1, "offset": 4, "len": 2, "value": "258", "little_endian": true})).unwrap();
        assert_eq!(read(&mut workspace, 10, 4), [1, 2, 2, 1]);
        let past = call(&mut workspace, "packets.write_field", json!({"set": "set-1", "index": 1, "offset": 7, "len": 2, "value": "1"})).unwrap_err();
        assert_eq!(past.code, ErrorCode::OutOfRange);
        let too_big = call(&mut workspace, "packets.write_field", json!({"set": "set-1", "index": 1, "offset": 0, "len": 1, "value": "70000"})).unwrap_err();
        assert!(too_big.message.contains("does not fit"), "{}", too_big.message);
    }

    #[test]
    fn deleting_packets_placed_by_hand_keeps_the_rest_where_they_moved() {
        let bytes: Vec<u8> = (0..40u8).collect();
        let mut workspace = workspace_with("ranges.bin", &bytes);
        call(&mut workspace, "packets.sets.create", json!({"from": "selection", "ranges": [[0, 4], [10, 4], [30, 4]]})).unwrap();
        let deleted = call(&mut workspace, "packets.delete", json!({"set": "set-1", "indices": [1]})).unwrap();
        assert_eq!((deleted["bytes_removed"].as_u64(), deleted["label"].as_str()), (Some(4), Some("Delete packets")));
        let listed = call(&mut workspace, "packets.list", json!({"set": "set-1"})).unwrap();
        let offsets: Vec<u64> = listed["packets"].as_array().unwrap().iter().map(|packet| packet["offset"].as_u64().unwrap()).collect();
        assert_eq!(offsets, [0, 26], "the last packet moved back with the bytes removed before it");
        assert_eq!(read(&mut workspace, 26, 4), [30, 31, 32, 33]);
        assert_eq!(call(&mut workspace, "packets.delete", json!({"set": "set-1", "indices": [5]})).unwrap_err().code, ErrorCode::OutOfRange);
    }

    #[test]
    fn checksums_already_right_are_left_alone_and_said_so() {
        let mut workspace = workspace_with("traffic.bin", &super::super::tests::dns_capture(2));
        call(&mut workspace, "packets.sets.create", json!({"from": "capture"})).unwrap();
        let fixed = call(&mut workspace, "packets.fix_checksums", json!({"set": "set-1", "indices": [0, 1]})).unwrap();
        assert!(fixed["label"].is_null() && fixed["checksums"].as_array().unwrap().is_empty(), "{fixed}");
        let listed = call(&mut workspace, "packets.list", json!({"set": "set-1"})).unwrap();
        let port_at = listed["packets"][0]["offset"].as_u64().unwrap() + 14 + 20 + 2;
        call(&mut workspace, "bytes.write", json!({"start": port_at, "data": "007b"})).unwrap();
        let fixed = call(&mut workspace, "packets.fix_checksums", json!({"set": "set-1", "indices": [0]})).unwrap();
        assert_eq!(fixed["checksums"], json!(["UDP"]), "{fixed}");
        assert_eq!(fixed["label"], "Fix checksums");
    }

    #[test]
    fn packets_are_extracted_in_the_order_asked_and_writing_them_needs_a_path_that_works() {
        let mut workspace = records();
        let extracted = call(&mut workspace, "packets.extract", json!({"set": "set-1", "indices": [2, 0], "encoding": "hex"})).unwrap();
        assert_eq!(extracted["data"], "101112131415161700010203040506 07".replace(' ', ""));
        let failed = call(&mut workspace, "packets.extract", json!({"set": "set-1", "indices": [0], "path": "/no/such/dir/packets.bin"})).unwrap_err();
        assert_eq!(failed.code, ErrorCode::Unavailable);
    }

    #[test]
    fn a_transfer_s_data_is_reassembled_from_the_same_field_of_each_packet_cut_short_at_its_end() {
        let mut workspace = records();
        let data = call(&mut workspace, "packets.extract", json!({"set": "set-1", "indices": [0, 1], "field": {"offset": 2, "len": 3}, "encoding": "hex"})).unwrap();
        assert_eq!(data["data"], "0203040a0b0c");
        let tails = call(&mut workspace, "packets.extract", json!({"set": "set-1", "indices": [0, 1], "field": {"offset": 6, "len": 512}, "encoding": "hex"})).unwrap();
        assert_eq!(tails["data"], "06070e0f", "a field running past a packet's end stops there");
        let beyond = call(&mut workspace, "packets.extract", json!({"set": "set-1", "indices": [0], "field": {"offset": 8, "len": 4}, "encoding": "hex"})).unwrap();
        assert_eq!((beyond["count"].as_u64(), beyond["len"].as_u64()), (Some(1), Some(0)));
    }
}
