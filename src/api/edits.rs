//! Edits: `bytes.write`, `bytes.insert`, `bytes.delete`, `bytes.replace`,
//! `bits.write`, `transform.apply` (and `transform.preview`, which only
//! reads), `history.undo`, `history.redo` and `history.transaction`.
//!
//! Every edit is one undoable step, labelled in the undo history with what
//! it did and who did it ("XOR by mcp:claude-code"), and published on
//! `document.edited` as the caller's. Any edit may give `expect_version`:
//! when the document has changed since, the call fails with
//! `version_conflict` and nothing is changed. A transaction runs several
//! calls as one step, and when one fails every change the others made is
//! reversed.
//!
//! [`describe_call`] says in plain words what an edit would do, for the
//! window that asks the person to confirm it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::output::{self, Delivered, Output, Piece, Produced};
use super::permissions::Caller;
use super::values::{self, ByteEncoding};
use super::workspace::{self, DOCUMENT_PRODUCER, Workspace};
use super::{ApiError, MAX_CALL_BYTES, OutputKind};
use crate::bits::BitOrder;
use crate::document::Document;
use crate::selection::{self, Selection};
use crate::selection_menu;
use crate::selection_ops::{self, Operation, preview_hex};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("bytes.write", Edit, caller write, WriteParams, EditResult, "Overwrite bytes in place with new ones, as one undoable step; the document keeps its length."),
    method!("bytes.insert", Edit, caller insert, InsertParams, EditResult, "Insert bytes at an offset, as one undoable step; the bytes after it move along."),
    method!("bytes.delete", Edit, caller delete, DeleteParams, EditResult, "Remove a span of bytes, as one undoable step; the bytes after it move back."),
    method!("bytes.replace", Edit, caller replace, ReplaceParams, EditResult, "Replace a span of bytes with new bytes of any length, as one undoable step."),
    method!("bytes.move", Edit, caller move_bytes, MoveParams, EditResult, "Cut ranges out and put their bytes, one after another, at an offset counted before the cut, as one undoable step, and select them."),
    method!("bits.write", Edit, caller write_bits, BitsWriteParams, EditResult, "Overwrite bits from any bit offset, most or least significant bit of each byte first, as one undoable step; the bits around them are kept."),
    method!("transform.apply", Edit, caller apply_transform, TransformParams, TransformResult, "Apply an operation (XOR, invert, shift bits, swap byte order, number, compress, decompress and more) to every range of a selection: in place by default, as one undoable step, selecting what it produced; or, as output says, open what it makes as a new sheet (the ranges one after another), or return it.").outputs(&[OutputKind::InPlace, OutputKind::New, OutputKind::Return], OutputKind::InPlace),
    method!("transform.preview", Read, preview_transform, PreviewParams, PreviewResult, "What transform.apply would write into each range of a selection, without changing anything, range by range: a shorthand for transform.apply with output \"return\"."),
    method!("history.undo", Edit, caller undo, HistoryParams, HistoryResult, "Undo the document's last step, whoever made it, and put the cursor where it was.").moves_along_the_timeline(crate::api::Move::Undo),
    method!("history.redo", Edit, caller redo, HistoryParams, HistoryResult, "Redo the last step undone, and put the cursor where it was.").moves_along_the_timeline(crate::api::Move::Redo),
    method!("history.transaction", Edit, caller transaction, TransactionParams, TransactionResult, "Run several calls on one document as one undoable step; when one fails, every change the others made is reversed.").passes_anchors_on(),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("transform.preview", json!({"selection": {"range": [0, 4]}, "operation": {"op": "invert"}})),
        ("bytes.write", json!({"start": 0, "data": "00"})),
        ("bytes.write", json!({"start": 0, "data": "0f", "coalesce": true})),
        ("bytes.insert", json!({"at": 0, "data": "00"})),
        ("bytes.insert", json!({"at": 0, "data": "0a", "coalesce": true})),
        ("bytes.delete", json!({"start": 0, "len": 1})),
        ("bytes.replace", json!({"start": 0, "len": 1, "data": "ffff"})),
        ("bytes.move", json!({"ranges": [[0, 2]], "to": 6})),
        ("bits.write", json!({"bit_start": 3, "bits": "101"})),
        ("transform.apply", json!({"selection": {"range": [0, 4]}, "operation": {"op": "xor", "key": "5a"}})),
        ("transform.apply", json!({"selection": {"range": [0, 4]}, "operation": {"op": "invert"}, "output": "return"})),
        ("history.undo", json!({})),
        ("history.redo", json!({})),
        ("history.transaction", json!({"calls": [{"method": "cursor.set", "params": {"offset": 2}}, {"method": "bytes.delete", "params": {"start": 0, "len": 1}}]})),
    ]
}

/// Most bits one `bits.write` writes.
const MAX_BITS: usize = 1024 * 1024;
/// Most calls one transaction may hold.
const MAX_TRANSACTION_CALLS: usize = 1000;

/// Parameters of `bytes.write`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the first byte to overwrite.
    pub start: u64,
    /// The new bytes, written as `encoding` says; they must fit inside the document.
    pub data: String,
    /// How `data` is written: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
    /// Join the caller's previous step when that step wrote or inserted just the one byte at `start`,
    /// so a byte typed as two hex digits undoes as one step.
    #[serde(default)]
    pub coalesce: bool,
    /// Fail with version_conflict, changing nothing, unless the document is at this version.
    #[serde(default)]
    pub expect_version: Option<u64>,
}

/// Parameters of `bytes.insert`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsertParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset to insert at; the document's length appends. Also taken as
    /// `start`, as the other byte methods call it.
    #[serde(alias = "start")]
    pub at: u64,
    /// The bytes to insert, written as `encoding` says.
    pub data: String,
    /// How `data` is written: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
    /// Join the caller's previous step when that step wrote or inserted just the one byte at `at`.
    #[serde(default)]
    pub coalesce: bool,
    /// Fail with version_conflict, changing nothing, unless the document is at this version.
    #[serde(default)]
    pub expect_version: Option<u64>,
}

/// Parameters of `bytes.delete`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the first byte to remove.
    pub start: u64,
    /// Bytes to remove.
    pub len: u64,
    /// Fail with version_conflict, changing nothing, unless the document is at this version.
    #[serde(default)]
    pub expect_version: Option<u64>,
}

/// Parameters of `bytes.replace`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplaceParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the first byte to replace.
    pub start: u64,
    /// Bytes to take out; the new bytes may be longer or shorter.
    pub len: u64,
    /// The bytes to put in their place, written as `encoding` says.
    pub data: String,
    /// How `data` is written: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
    /// Fail with version_conflict, changing nothing, unless the document is at this version.
    #[serde(default)]
    pub expect_version: Option<u64>,
}

/// Parameters of `bytes.move`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// The ranges to move, as [start, len]; their bytes land one after another, in document order.
    pub ranges: Vec<(u64, u64)>,
    /// Where the bytes land, as an offset counted before they are cut out; an offset inside a range
    /// lands them where that range began.
    pub to: u64,
    /// Fail with version_conflict, changing nothing, unless the document is at this version.
    #[serde(default)]
    pub expect_version: Option<u64>,
}

/// Parameters of `bits.write`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BitsWriteParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Bit offset of the first bit: byte offset × 8 plus the bit within the byte, in `order`.
    pub bit_start: u64,
    /// The new bits as "0" and "1", first bit first; spaces and underscores are ignored.
    pub bits: String,
    /// Which bit of each byte comes first: "msb" (the default) or "lsb".
    #[serde(default)]
    pub order: BitOrder,
    /// Fail with version_conflict, changing nothing, unless the document is at this version.
    #[serde(default)]
    pub expect_version: Option<u64>,
}

/// Parameters of `transform.apply`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransformParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// What to change: a range, several ranges or a column of every record.
    /// The document's selection when omitted, or the byte at the cursor when nothing is selected.
    #[serde(default)]
    pub selection: Option<Selection>,
    /// What to do to each selected range, such as {"op": "xor", "key": "5a"}.
    pub operation: Operation,
    /// Fail with version_conflict, changing nothing, unless the document is at this version.
    #[serde(default)]
    pub expect_version: Option<u64>,
    /// Where what it makes goes: "in_place" (the default), "new" (a sheet
    /// of the ranges' new bytes one after another; {"new": {"label": …}} names
    /// it) or "return".
    #[serde(default)]
    pub output: Option<Output>,
    /// With output "return", how the bytes are written: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
}

/// Parameters of `transform.preview`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreviewParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// What to change; the document's selection, or the byte at the cursor, when omitted.
    #[serde(default)]
    pub selection: Option<Selection>,
    /// What to do to each selected range.
    pub operation: Operation,
    /// How to write the new bytes: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
}

/// Parameters of `history.undo` and `history.redo`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HistoryParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Fail with version_conflict, changing nothing, unless the document is at this version.
    #[serde(default)]
    pub expect_version: Option<u64>,
}

/// One call of a transaction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransactionCall {
    /// The method, such as "bytes.write".
    pub method: String,
    /// Its parameters.
    #[serde(default)]
    pub params: Value,
}

/// Parameters of `history.transaction`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransactionParams {
    /// Document id, path or "current" (the default); every call must be about this document.
    #[serde(default)]
    pub doc: Option<String>,
    /// The calls, run in order: edits, selection changes and reads.
    pub calls: Vec<TransactionCall>,
    /// What the step is called in the undo history; "N changes" when omitted.
    #[serde(default)]
    pub label: Option<String>,
    /// Fail with version_conflict, changing nothing, unless the document is at this version.
    #[serde(default)]
    pub expect_version: Option<u64>,
}

/// The result of an edit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EditResult {
    /// Id of the document edited.
    pub doc: String,
    /// The document's version after the edit; pass it as expect_version to the next.
    pub version: u64,
    /// The document's length after the edit.
    pub len: u64,
    /// What the step is called in the undo history, such as "XOR by mcp:claude-code".
    pub label: String,
    /// Where the new bytes are, as [start, len]: one range per range changed.
    pub ranges: Vec<(u64, u64)>,
}

/// The result of `transform.apply`: the edit, when made in place, and
/// where the output went.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TransformResult {
    /// In place: the edit, as every edit returns it.
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub edit: Option<EditResult>,
    /// Where the output went: {version, len, ranges} in place, {doc, label, len} for a new sheet, {len, encoding, data} returned.
    pub output: Delivered,
}

/// One range's new bytes, as `transform.preview` returns them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PreviewRange {
    /// Where the range starts now.
    pub start: u64,
    /// Bytes in the range now.
    pub len: u64,
    /// What the range would hold, written as `encoding` says.
    pub data: String,
}

/// The result of `transform.preview`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PreviewResult {
    /// Id of the document read.
    pub doc: String,
    /// How each range's `data` is written.
    pub encoding: ByteEncoding,
    /// Each selected range with its new bytes.
    pub ranges: Vec<PreviewRange>,
}

/// The result of `history.undo` and `history.redo`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HistoryResult {
    /// Id of the document.
    pub doc: String,
    /// The document's version afterwards.
    pub version: u64,
    /// The document's length afterwards.
    pub len: u64,
    /// The step undone or redone, when it was named.
    pub label: Option<String>,
    /// Where its earliest change was.
    pub at: u64,
}

/// The result of `history.transaction`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TransactionResult {
    /// Id of the document.
    pub doc: String,
    /// The document's version afterwards.
    pub version: u64,
    /// The document's length afterwards.
    pub len: u64,
    /// What the step is called in the undo history.
    pub label: String,
    /// Each call's result, in order.
    pub results: Vec<Value>,
}

/// Fail unless the document is at the version the caller expects.
fn check_version(document: &Document, expect_version: Option<u64>) -> Result<(), ApiError> {
    match expect_version {
        Some(expected) if expected != document.version() => Err(ApiError::version_conflict(format!(
            "the document is at version {}, not {expected}: it changed since you looked; read it again and retry with the new version",
            document.version()
        ))
        .with_data(serde_json::json!({ "version": document.version() }))),
        _ => Ok(()),
    }
}

/// "Overwrite 4 bytes" or "Overwrite 1 byte".
fn count(what: &str, number: usize, unit: &str) -> String {
    let plural = if number == 1 { "" } else { "s" };
    format!("{what} {number} {unit}{plural}")
}

/// Make one change to document `doc` for `caller`: check the version, run
/// `change` as one undo step named "`action` by caller", publish it as the
/// caller's, and return the document's id and what `change` returned.
/// Edits made before, by hand, are published first as the document's own.
pub(super) fn edit<R>(
    workspace: &mut dyn Workspace,
    caller: &Caller,
    doc: Option<&str>,
    expect_version: Option<u64>,
    action: &str,
    change: impl FnOnce(&mut Document) -> Result<R, ApiError>,
) -> Result<(String, R, String), ApiError> {
    edit_joining(workspace, caller, doc, expect_version, action, None, change)
}

/// [`edit`], except that when `join_at` is where the caller's previous
/// step wrote or inserted its one byte, `change` joins that step (keeping
/// its name) instead of making a new one.
fn edit_joining<R>(
    workspace: &mut dyn Workspace,
    caller: &Caller,
    doc: Option<&str>,
    expect_version: Option<u64>,
    action: &str,
    join_at: Option<usize>,
    change: impl FnOnce(&mut Document) -> Result<R, ApiError>,
) -> Result<(String, R, String), ApiError> {
    let id = workspace::resolve(workspace, doc)?;
    workspace.publish_edits(&id, DOCUMENT_PRODUCER);
    let (_, document) = workspace::document(workspace, Some(&id))?;
    check_version(document, expect_version)?;
    let joined_label = join_at.and_then(|at| one_byte_step_at(document, caller, at));
    let (label, result) = match joined_label {
        Some(label) => (label, document.extend_last_step(change)),
        None => {
            let label = caller.label(action);
            let result = document.transaction(label.clone(), change);
            (label, result)
        }
    };
    workspace.publish_edits(&id, &caller.producer());
    result.map(|value| (id, value, label))
}

/// The name of the document's last step, when that step is `caller`'s
/// write or insert of just the one byte at `at`: the step a coalescing
/// edit there joins.
fn one_byte_step_at(document: &Document, caller: &Caller, at: usize) -> Option<String> {
    if document.last_step_byte() != Some(at) {
        return None;
    }
    let label = document.undo_label()?;
    let callers_own = [count("Overwrite", 1, "byte"), count("Insert", 1, "byte")].iter().any(|action| caller.label(action) == label);
    callers_own.then(|| label.to_string())
}

/// Where a coalescing edit at `offset` may join the previous step.
fn join_offset(coalesce: bool, offset: u64) -> Option<usize> {
    if coalesce { usize::try_from(offset).ok() } else { None }
}

/// The result of an edit to document `id` that left new bytes at `ranges`.
fn edit_result(workspace: &mut dyn Workspace, id: String, label: String, ranges: Vec<(usize, usize)>) -> Result<EditResult, ApiError> {
    let info = workspace::info(workspace, &id)?;
    Ok(EditResult { doc: id, version: info.version, len: info.len, label, ranges: ranges.into_iter().map(|(start, len)| (start as u64, len as u64)).collect() })
}

/// New bytes given to an edit, checked against the per-call limit.
fn new_bytes(data: &str, encoding: ByteEncoding) -> Result<Vec<u8>, ApiError> {
    let bytes = values::decode_bytes(data, encoding)?;
    values::check_call_size(bytes.len())?;
    Ok(bytes)
}

pub fn write(workspace: &mut dyn Workspace, caller: &Caller, params: WriteParams) -> Result<EditResult, ApiError> {
    let bytes = new_bytes(&params.data, params.encoding)?;
    let action = count("Overwrite", bytes.len(), "byte");
    let join_at = join_offset(params.coalesce, params.start);
    let (id, start, label) = edit_joining(workspace, caller, params.doc.as_deref(), params.expect_version, &action, join_at, |document| {
        let (start, len) = values::span_within(document.len(), params.start, Some(bytes.len() as u64))
            .map_err(|error| ApiError::out_of_range(format!("{}; bytes.write overwrites only, so use bytes.insert or bytes.replace to grow the document", error.message)))?;
        if len > 0 {
            document.overwrite(start, &bytes);
        }
        Ok(start)
    })?;
    edit_result(workspace, id, label, vec![(start, bytes.len())])
}

pub fn insert(workspace: &mut dyn Workspace, caller: &Caller, params: InsertParams) -> Result<EditResult, ApiError> {
    let bytes = new_bytes(&params.data, params.encoding)?;
    let action = count("Insert", bytes.len(), "byte");
    let join_at = join_offset(params.coalesce, params.at);
    let (id, at, label) = edit_joining(workspace, caller, params.doc.as_deref(), params.expect_version, &action, join_at, |document| {
        let (at, _) = values::span_within(document.len(), params.at, Some(0))?;
        document.insert(at, &bytes);
        Ok(at)
    })?;
    edit_result(workspace, id, label, vec![(at, bytes.len())])
}

pub fn delete(workspace: &mut dyn Workspace, caller: &Caller, params: DeleteParams) -> Result<EditResult, ApiError> {
    let action = count("Delete", params.len as usize, "byte");
    let (id, start, label) = edit(workspace, caller, params.doc.as_deref(), params.expect_version, &action, |document| {
        let (start, len) = values::span_within(document.len(), params.start, Some(params.len))?;
        document.delete(start, len);
        Ok(start)
    })?;
    edit_result(workspace, id, label, vec![(start, 0)])
}

pub fn replace(workspace: &mut dyn Workspace, caller: &Caller, params: ReplaceParams) -> Result<EditResult, ApiError> {
    let bytes = new_bytes(&params.data, params.encoding)?;
    let action = count("Replace", params.len as usize, "byte");
    let (id, start, label) = edit(workspace, caller, params.doc.as_deref(), params.expect_version, &action, |document| {
        let (start, len) = values::span_within(document.len(), params.start, Some(params.len))?;
        document.replace(start, len, &bytes);
        Ok(start)
    })?;
    edit_result(workspace, id, label, vec![(start, bytes.len())])
}

pub fn move_bytes(workspace: &mut dyn Workspace, caller: &Caller, params: MoveParams) -> Result<EditResult, ApiError> {
    if params.ranges.is_empty() {
        return Err(ApiError::invalid_params("give at least one range to move, as [start, len]"));
    }
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let len = workspace::info(workspace, &id)?.len as usize;
    let given: Vec<(usize, usize)> = params.ranges.iter().map(|&(start, range_len)| (start as usize, range_len as usize)).collect();
    check_inside(&Selection::Ranges(given.clone()), len)?;
    let ranges = selection::normalise_ranges(given);
    let total = selection::total_bytes(&ranges);
    if total == 0 {
        return Err(ApiError::invalid_params("the ranges hold no bytes to move"));
    }
    values::check_call_size(total)?;
    let (to, _) = values::span_within(len, params.to, Some(0))?;
    let landing = selection_ops::moved_destination(to, &ranges);
    let action = count("Move", total, "byte");
    let (id, (), label) = edit(workspace, caller, Some(&id), params.expect_version, &action, |document| {
        let mut bytes = Vec::with_capacity(total);
        for &(start, range_len) in &ranges {
            bytes.extend(document.read_range(start, range_len));
        }
        selection_menu::rewrite_ranges(document, &ranges, &Operation::Delete).map_err(|message| ApiError::invalid_params(format!("the move failed: {message}")))?;
        document.insert(landing, &bytes);
        Ok(())
    })?;
    // Select the moved bytes, as the window does after a move; one byte is
    // just the cursor's.
    let (cursor, moved) = if total > 1 { (landing + total, Some(Selection::Range(landing, total))) } else { (landing, None) };
    workspace.select(&id, cursor, moved, caller);
    edit_result(workspace, id, label, vec![(landing, total)])
}

/// Bits written as "0" and "1", with spaces and underscores ignored.
fn parse_bits(text: &str) -> Result<Vec<bool>, ApiError> {
    text.chars()
        .filter(|character| !matches!(character, ' ' | '_'))
        .map(|character| match character {
            '0' => Ok(false),
            '1' => Ok(true),
            other => Err(ApiError::invalid_params(format!("'{other}' is not a bit; write bits as 0s and 1s, such as \"1010 0001\""))),
        })
        .collect()
}

/// The mask of bit `index` within its byte, counting in `order`.
fn bit_mask(index: usize, order: BitOrder) -> u8 {
    match order {
        BitOrder::MsbFirst => 0x80 >> (index % 8),
        BitOrder::LsbFirst => 1 << (index % 8),
    }
}

pub fn write_bits(workspace: &mut dyn Workspace, caller: &Caller, params: BitsWriteParams) -> Result<EditResult, ApiError> {
    let bits = parse_bits(&params.bits)?;
    if bits.len() > MAX_BITS {
        return Err(ApiError::too_large(format!("{} bits is over the limit of {MAX_BITS}; write fewer, or use bytes.write", bits.len())));
    }
    let action = count("Write", bits.len(), "bit");
    let (id, (first_byte, byte_count), label) = edit(workspace, caller, params.doc.as_deref(), params.expect_version, &action, |document| {
        let document_bits = document.len() as u64 * 8;
        let bit_end = params.bit_start.saturating_add(bits.len() as u64);
        if bit_end > document_bits {
            return Err(ApiError::out_of_range(format!("bits {}..{bit_end} run past the end of the document ({document_bits} bits)", params.bit_start)));
        }
        let first_byte = (params.bit_start / 8) as usize;
        let last_byte = bit_end.div_ceil(8) as usize;
        let mut bytes = document.read_range(first_byte, last_byte - first_byte);
        let skip = (params.bit_start % 8) as usize;
        for (offset, &bit) in bits.iter().enumerate() {
            let index = skip + offset;
            let mask = bit_mask(index, params.order);
            if bit {
                bytes[index / 8] |= mask;
            } else {
                bytes[index / 8] &= !mask;
            }
        }
        document.overwrite(first_byte, &bytes);
        Ok((first_byte, bytes.len()))
    })?;
    edit_result(workspace, id, label, vec![(first_byte, byte_count)])
}

/// What an operation acts on: its ranges, sorted, and the selection they
/// came from, if any.
type Target = (Vec<(usize, usize)>, Option<Selection>);

/// The ranges an operation acts on in document `id`: those `selection`
/// names, else the selection, else the byte at the cursor. Checked to lie
/// inside the document.
fn operation_ranges(workspace: &mut dyn Workspace, id: &str, selection: Option<&Selection>) -> Result<Target, ApiError> {
    let (_, document) = workspace::document(workspace, Some(id))?;
    let len = document.len();
    let view = workspace.view(id).unwrap_or_default();
    let (ranges, selected) = match selection.or(view.selection.as_ref()) {
        Some(selected) => {
            check_inside(selected, len)?;
            (selection::normalise_ranges(selected.ranges(len)), Some(selected.clone()))
        }
        None if view.cursor < len => (vec![(view.cursor, 1)], None),
        None => (Vec::new(), None),
    };
    if ranges.is_empty() {
        return Err(ApiError::invalid_params("nothing to change: nothing is selected and the cursor is at the end of the document; give a selection"));
    }
    Ok((ranges, selected))
}

/// Fail when any of `selection` lies past the end of a document of `len` bytes.
pub fn check_inside(selection: &Selection, len: usize) -> Result<(), ApiError> {
    let end = match selection {
        Selection::Range(start, range_len) => start.saturating_add(*range_len),
        Selection::Ranges(ranges) => ranges.iter().map(|&(start, range_len)| start.saturating_add(range_len)).max().unwrap_or(0),
        Selection::Columns(column) => {
            let (start, span) = column.span();
            start.saturating_add(span)
        }
    };
    if end > len {
        return Err(ApiError::out_of_range(format!("the selection runs to {end:#x}, past the end of the document ({len} bytes)")));
    }
    Ok(())
}

pub fn apply_transform(workspace: &mut dyn Workspace, caller: &Caller, params: TransformParams) -> Result<TransformResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let (ranges, selected) = operation_ranges(workspace, &id, params.selection.as_ref())?;
    values::check_call_size(selection::total_bytes(&ranges))?;
    let output = output::chosen("transform.apply", params.output)?;
    let operation = params.operation;
    if output != Output::InPlace {
        let made = transformed(workspace, &id, &ranges, &operation)?;
        let name = format!("{} › {}", workspace::info(workspace, &id)?.name, operation.name());
        let pieces = ranges.iter().zip(made).map(|(&range, bytes)| Piece { replaces: Some(range), bytes }).collect();
        let produced = Produced { pieces, name, action: operation.name().to_string(), encoding: params.encoding };
        let delivered = output::deliver(workspace, caller, &id, produced, &output)?;
        return Ok(TransformResult { edit: None, output: delivered });
    }
    let (id, changed, label) = edit(workspace, caller, Some(&id), params.expect_version, operation.name(), |document| {
        selection_menu::rewrite_ranges(document, &ranges, &operation).map_err(|message| ApiError::invalid_params(format!("{} failed: {message}", operation.name())))
    })?;
    // Select what the operation produced, as the Selection menu does.
    let cursor = workspace.view(&id).unwrap_or_default().cursor;
    let len = workspace::info(workspace, &id)?.len as usize;
    let (cursor, selection) = selection_menu::selection_after_operation(selected, &operation, &changed, cursor, len);
    workspace.select(&id, cursor, selection, caller);
    let edit = edit_result(workspace, id, label, changed)?;
    let delivered = Delivered { len: edit.ranges.iter().map(|&(_, len)| len).sum(), version: Some(edit.version), ranges: Some(edit.ranges.clone()), ..Delivered::default() };
    Ok(TransformResult { edit: Some(edit), output: delivered })
}

/// What `operation` makes of each of `ranges` of document `id`, checked
/// against the per-call limit.
fn transformed(workspace: &mut dyn Workspace, id: &str, ranges: &[(usize, usize)], operation: &Operation) -> Result<Vec<Vec<u8>>, ApiError> {
    let (_, document) = workspace::document(workspace, Some(id))?;
    let made = selection_ops::transform_ranges(operation, document, ranges).map_err(|message| ApiError::invalid_params(format!("{} failed: {message}", operation.name())))?;
    values::check_size(made.iter().map(Vec::len).sum(), MAX_CALL_BYTES, "what the operation makes")?;
    Ok(made)
}

/// `transform.preview`: `transform.apply` with output "return", range by range.
pub fn preview_transform(workspace: &mut dyn Workspace, params: PreviewParams) -> Result<PreviewResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let (ranges, _) = operation_ranges(workspace, &id, params.selection.as_ref())?;
    values::check_call_size(selection::total_bytes(&ranges))?;
    let made = transformed(workspace, &id, &ranges, &params.operation)?;
    let previews = ranges.iter().zip(made).map(|(&(start, len), changed)| PreviewRange { start: start as u64, len: len as u64, data: values::encode_bytes(&changed, params.encoding) }).collect();
    Ok(PreviewResult { doc: id, encoding: params.encoding, ranges: previews })
}

/// Undo or redo the last step of document `doc` for `caller`.
fn step_history(workspace: &mut dyn Workspace, caller: &Caller, params: HistoryParams, redo: bool) -> Result<HistoryResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    workspace.publish_edits(&id, DOCUMENT_PRODUCER);
    let (_, document) = workspace::document(workspace, Some(&id))?;
    check_version(document, params.expect_version)?;
    let label = if redo { document.redo_label() } else { document.undo_label() }.map(str::to_string);
    let at = if redo { document.redo() } else { document.undo() };
    let Some(at) = at else {
        let what = if redo { "redo" } else { "undo" };
        return Err(ApiError::not_found(format!("there is nothing to {what} in {id}")));
    };
    workspace.publish_edits(&id, &caller.producer());
    let info = workspace::info(workspace, &id)?;
    // Show where the change was, as Undo in the Edit menu does.
    workspace.select(&id, at.min(info.len as usize), None, caller);
    Ok(HistoryResult { doc: id, version: info.version, len: info.len, label, at: at as u64 })
}

pub fn undo(workspace: &mut dyn Workspace, caller: &Caller, params: HistoryParams) -> Result<HistoryResult, ApiError> {
    step_history(workspace, caller, params, false)
}

pub fn redo(workspace: &mut dyn Workspace, caller: &Caller, params: HistoryParams) -> Result<HistoryResult, ApiError> {
    step_history(workspace, caller, params, true)
}

/// Methods a transaction may not hold: those that open, close or save
/// documents, or step through the history it is writing.
fn allowed_in_transaction(method: &str) -> bool {
    !matches!(method, "history.undo" | "history.redo") && super::namespace_of(method) != "documents"
}

pub fn transaction(workspace: &mut dyn Workspace, caller: &Caller, params: TransactionParams) -> Result<TransactionResult, ApiError> {
    if params.calls.is_empty() {
        return Err(ApiError::invalid_params("a transaction needs at least one call"));
    }
    if params.calls.len() > MAX_TRANSACTION_CALLS {
        return Err(ApiError::too_large(format!("{} calls is over the limit of {MAX_TRANSACTION_CALLS} for one transaction", params.calls.len())));
    }
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    for (index, call) in params.calls.iter().enumerate() {
        if !allowed_in_transaction(&call.method) {
            return Err(ApiError::invalid_params(format!("call {index}: {} cannot run inside a transaction", call.method)));
        }
        if let Some(doc) = call.params.get("doc").and_then(Value::as_str)
            && workspace::resolve(workspace, Some(doc))? != id
        {
            return Err(ApiError::invalid_params(format!("call {index} is about {doc}, but a transaction edits only {id}")));
        }
    }
    workspace.publish_edits(&id, DOCUMENT_PRODUCER);
    let (_, document) = workspace::document(workspace, Some(&id))?;
    check_version(document, params.expect_version)?;
    let calls = params.calls.len();
    let label = caller.label(&params.label.unwrap_or_else(|| count("", calls, "change").trim_start().to_string()));
    document.begin_labelled_group(label.clone());
    let mut results = Vec::with_capacity(calls);
    for (index, call) in params.calls.into_iter().enumerate() {
        match super::call_permitted(workspace, caller, &call.method, call.params) {
            Ok(result) => results.push(result),
            Err(error) => {
                if let Some(document) = workspace.document_mut(&id) {
                    document.abandon_group();
                }
                workspace.publish_edits(&id, &caller.producer());
                let message = format!("call {index} ({}) failed, so none of the {calls} calls changed anything: {}", call.method, error.message);
                return Err(ApiError::new(error.code, message).with_data(serde_json::json!({ "failed_call": index, "error": error.to_json() })));
            }
        }
    }
    if let Some(document) = workspace.document_mut(&id) {
        document.end_group();
    }
    workspace.publish_edits(&id, &caller.producer());
    let info = workspace::info(workspace, &id)?;
    Ok(TransactionResult { doc: id, version: info.version, len: info.len, label, results })
}

/// "4 bytes at 0x40", or "16 bytes in 3 ranges", or "128 selected bytes"
/// when the selection is the document's own.
pub(super) fn target_phrase(ranges: &[(usize, usize)], from_view: bool) -> String {
    let total = selection::total_bytes(ranges);
    let bytes = count("", total, "byte").trim_start().to_string();
    match ranges {
        _ if from_view => {
            let plural = if total == 1 { "" } else { "s" };
            format!("{total} selected byte{plural}")
        }
        [(start, _)] => format!("{bytes} at {start:#x}"),
        _ => format!("{bytes} in {} ranges", ranges.len()),
    }
}

/// Typed parameters, when `params` fit them.
fn parsed<P: serde::de::DeserializeOwned>(params: &Value) -> Option<P> {
    serde_json::from_value(params.clone()).ok()
}

/// Bytes given to an edit, for a description; the text as given when it
/// does not decode.
fn bytes_phrase(data: &str, encoding: ByteEncoding) -> (usize, String) {
    match values::decode_bytes(data, encoding) {
        Ok(bytes) => (bytes.len(), preview_hex(&bytes)),
        Err(_) => (0, format!("\"{data}\"")),
    }
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person: "Overwrite 4 bytes at 0x40 with
/// DE AD BE EF", "XOR 128 selected bytes with 5A".
pub(super) fn describe_call(workspace: &mut dyn Workspace, method: &str, params: &Value) -> Option<String> {
    let description = match method {
        "bytes.write" => {
            let params: WriteParams = parsed(params)?;
            let (len, hex) = bytes_phrase(&params.data, params.encoding);
            format!("{} at {:#x} with {hex}", count("Overwrite", len, "byte"), params.start)
        }
        "bytes.insert" => {
            let params: InsertParams = parsed(params)?;
            let (len, hex) = bytes_phrase(&params.data, params.encoding);
            format!("{} at {:#x}: {hex}", count("Insert", len, "byte"), params.at)
        }
        "bytes.delete" => {
            let params: DeleteParams = parsed(params)?;
            format!("{} at {:#x}", count("Delete", params.len as usize, "byte"), params.start)
        }
        "bytes.replace" => {
            let params: ReplaceParams = parsed(params)?;
            let (len, hex) = bytes_phrase(&params.data, params.encoding);
            let replaced = count("Replace", params.len as usize, "byte");
            if len as u64 == params.len { format!("{replaced} at {:#x} with {hex}", params.start) } else { format!("{replaced} at {:#x} with {}: {hex}", params.start, count("", len, "byte").trim_start()) }
        }
        "bytes.move" => {
            let params: MoveParams = parsed(params)?;
            let ranges: Vec<(usize, usize)> = params.ranges.iter().map(|&(start, len)| (start as usize, len as usize)).collect();
            format!("Move {} to {:#x}", target_phrase(&selection::normalise_ranges(ranges), false), params.to)
        }
        "bits.write" => {
            let params: BitsWriteParams = parsed(params)?;
            let bits: String = params.bits.chars().filter(|character| !matches!(character, ' ' | '_')).collect();
            let shown = if bits.len() > 64 { format!("{}…", &bits[..64]) } else { bits.clone() };
            format!("{} at bit {} (byte {:#x}): {shown}", count("Write", bits.len(), "bit"), params.bit_start, params.bit_start / 8)
        }
        "transform.apply" => {
            let params: TransformParams = parsed(params)?;
            let id = workspace::resolve(workspace, params.doc.as_deref()).ok()?;
            let from_view = params.selection.is_none();
            let (ranges, _) = operation_ranges(workspace, &id, params.selection.as_ref()).ok()?;
            params.operation.describe(&target_phrase(&ranges, from_view))
        }
        "history.undo" | "history.redo" => {
            let params: HistoryParams = parsed(params)?;
            let (_, document) = workspace::document(workspace, params.doc.as_deref()).ok()?;
            let (verb, label) = if method == "history.undo" { ("Undo", document.undo_label()) } else { ("Redo", document.redo_label()) };
            match label {
                Some(label) => format!("{verb} the last change ({label})"),
                None => format!("{verb} the last change"),
            }
        }
        "history.transaction" => {
            let params: TransactionParams = parsed(params)?;
            let steps: Vec<String> = params.calls.iter().map(|call| super::describe_call(workspace, &call.method, &call.params)).collect();
            format!("{} as one step:\n{}", count("Make", steps.len(), "change"), steps.iter().map(|step| format!("• {step}")).collect::<Vec<_>>().join("\n"))
        }
        _ => return None,
    };
    Some(description)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::workspace::ViewState;
    use crate::api::{self, Caller, ErrorCode, Workspace};
    use crate::selection::Selection;

    fn mcp() -> Caller {
        Caller::Mcp("claude-code".to_string())
    }

    fn call(workspace: &mut dyn Workspace, name: &str, params: serde_json::Value) -> Result<serde_json::Value, api::ApiError> {
        api::call(workspace, &mcp(), name, params)
    }

    fn bytes_of(workspace: &mut dyn Workspace) -> Vec<u8> {
        let (_, document) = api::workspace::document(workspace, None).unwrap();
        document.read_range(0, document.len())
    }

    fn undo_label(workspace: &mut dyn Workspace) -> Option<String> {
        let (_, document) = api::workspace::document(workspace, None).unwrap();
        document.undo_label().map(str::to_string)
    }

    #[test]
    fn each_byte_edit_is_one_step_labelled_with_its_caller() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        let written = call(&mut workspace, "bytes.write", json!({"start": 2, "data": "4142"})).unwrap();
        assert_eq!((written["version"].as_u64(), written["label"].as_str()), (Some(1), Some("Overwrite 2 bytes by mcp:claude-code")));
        call(&mut workspace, "bytes.insert", json!({"at": 10, "data": "!", "encoding": "text"})).unwrap();
        call(&mut workspace, "bytes.delete", json!({"start": 0, "len": 1})).unwrap();
        let replaced = call(&mut workspace, "bytes.replace", json!({"start": 0, "len": 1, "data": "ffff"})).unwrap();
        assert_eq!(replaced["ranges"], json!([[0, 2]]));
        assert_eq!(bytes_of(&mut workspace), b"\xff\xffAB456789!");
        assert_eq!(undo_label(&mut workspace).as_deref(), Some("Replace 1 byte by mcp:claude-code"));
        for expected in [&b"1AB456789!"[..], b"01AB456789!", b"01AB456789", b"0123456789"] {
            call(&mut workspace, "history.undo", json!({})).unwrap();
            assert_eq!(bytes_of(&mut workspace), expected, "each edit undoes on its own");
        }
        assert_eq!(call(&mut workspace, "history.undo", json!({})).unwrap_err().code, ErrorCode::NotFound);
        let redone = call(&mut workspace, "history.redo", json!({})).unwrap();
        assert_eq!(redone["label"], "Overwrite 2 bytes by mcp:claude-code");
        assert_eq!(bytes_of(&mut workspace), b"01AB456789");
    }

    #[test]
    fn a_byte_typed_as_two_digits_undoes_as_one_step() {
        let mut workspace = workspace_with("a.bin", b"abcd");
        call(&mut workspace, "bytes.write", json!({"start": 1, "data": "f2"})).unwrap();
        let joined = call(&mut workspace, "bytes.write", json!({"start": 1, "data": "ff", "coalesce": true})).unwrap();
        assert_eq!(joined["label"], "Overwrite 1 byte by mcp:claude-code", "the joined step keeps its name");
        assert_eq!(joined["ranges"], json!([[1, 1]]));
        let inserted = call(&mut workspace, "bytes.insert", json!({"at": 2, "data": "a0"})).unwrap();
        assert_eq!(inserted["label"], "Insert 1 byte by mcp:claude-code");
        call(&mut workspace, "bytes.write", json!({"start": 2, "data": "a5", "coalesce": true})).unwrap();
        assert_eq!(bytes_of(&mut workspace), [b'a', 0xFF, 0xA5, b'c', b'd']);
        assert_eq!(undo_label(&mut workspace).as_deref(), Some("Insert 1 byte by mcp:claude-code"), "the second digit joined the insert");
        call(&mut workspace, "history.undo", json!({})).unwrap();
        assert_eq!(bytes_of(&mut workspace), [b'a', 0xFF, b'c', b'd'], "one undo takes the inserted byte out");
        call(&mut workspace, "history.undo", json!({})).unwrap();
        assert_eq!(bytes_of(&mut workspace), b"abcd", "and one more restores the overwritten byte");
    }

    #[test]
    fn a_coalescing_edit_joins_only_its_own_caller_s_one_byte_step_there() {
        let mut workspace = workspace_with("a.bin", b"abcd");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42", "coalesce": true})).unwrap();
        api::call(&mut workspace, &Caller::Plugin("sync.lua".into()), "bytes.write", json!({"start": 1, "data": "43", "coalesce": true})).unwrap();
        assert_eq!(undo_label(&mut workspace).as_deref(), Some("Overwrite 1 byte by plugin:sync.lua"), "another caller's step is never joined");
        call(&mut workspace, "bytes.write", json!({"start": 2, "data": "4444"})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 2, "data": "45", "coalesce": true})).unwrap();
        for expected in [b"ACED", b"ACDD", b"ACcd", b"ABcd", b"Abcd"] {
            assert_eq!(bytes_of(&mut workspace), expected);
            call(&mut workspace, "history.undo", json!({})).unwrap();
        }
        assert_eq!(bytes_of(&mut workspace), b"abcd");
        let past = call(&mut workspace, "bytes.write", json!({"start": 4, "data": "00", "coalesce": true})).unwrap_err();
        assert_eq!(past.code, ErrorCode::OutOfRange, "coalescing changes nothing about where an edit may go");
    }

    #[test]
    fn moved_bytes_land_where_the_offset_was_before_the_cut_as_one_step_and_are_selected() {
        let mut workspace = workspace_with("a.bin", b"ABcdefgh");
        let moved = call(&mut workspace, "bytes.move", json!({"ranges": [[0, 2]], "to": 6})).unwrap();
        assert_eq!(bytes_of(&mut workspace), b"cdefABgh", "bytes moving right land after the bytes they pass");
        assert_eq!((moved["label"].as_str(), moved["ranges"].clone()), (Some("Move 2 bytes by mcp:claude-code"), json!([[4, 2]])));
        assert_eq!(workspace.view("doc-1").unwrap(), ViewState { cursor: 6, selection: Some(Selection::Range(4, 2)), record_stride: None });

        let gathered = call(&mut workspace, "bytes.move", json!({"ranges": [[7, 1], [1, 1], [4, 2]], "to": 0})).unwrap();
        assert_eq!(bytes_of(&mut workspace), b"dABhcefg", "several ranges are gathered in document order");
        assert_eq!(gathered["ranges"], json!([[0, 4]]));
        call(&mut workspace, "history.undo", json!({})).unwrap();
        assert_eq!(bytes_of(&mut workspace), b"cdefABgh", "one undo puts every range back");

        call(&mut workspace, "bytes.move", json!({"ranges": [[7, 1]], "to": 5})).unwrap();
        assert_eq!(bytes_of(&mut workspace), b"cdefAhBg");
        assert_eq!(workspace.view("doc-1").unwrap().selection, None, "a single moved byte is where the cursor is, not a selection");
        assert_eq!(workspace.view("doc-1").unwrap().cursor, 5);
    }

    #[test]
    fn a_move_with_nothing_to_move_or_past_the_end_is_refused_and_changes_nothing() {
        let mut workspace = workspace_with("a.bin", b"abcd");
        assert_eq!(call(&mut workspace, "bytes.move", json!({"ranges": [], "to": 0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "bytes.move", json!({"ranges": [[1, 0]], "to": 0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "bytes.move", json!({"ranges": [[2, 4]], "to": 0})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "bytes.move", json!({"ranges": [[0, 1]], "to": 5})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "bytes.move", json!({"ranges": [[0, 1]], "to": 3, "expect_version": 7})).unwrap_err().code, ErrorCode::VersionConflict);
        assert_eq!(bytes_of(&mut workspace), b"abcd");
        assert_eq!(undo_label(&mut workspace), None);
    }

    #[test]
    fn overwriting_past_the_end_is_refused_with_a_pointer_to_insert() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let error = call(&mut workspace, "bytes.write", json!({"start": 2, "data": "0000"})).unwrap_err();
        assert_eq!(error.code, ErrorCode::OutOfRange);
        assert!(error.message.contains("bytes.insert"), "{}", error.message);
        assert_eq!(bytes_of(&mut workspace), b"abc");
        assert_eq!(undo_label(&mut workspace), None, "a failed edit leaves no step");
    }

    #[test]
    fn bits_are_written_in_either_order_without_touching_their_neighbours() {
        let mut workspace = workspace_with("a.bin", &[0b0000_0000, 0b1111_1111]);
        call(&mut workspace, "bits.write", json!({"bit_start": 6, "bits": "11 00"})).unwrap();
        assert_eq!(bytes_of(&mut workspace), [0b0000_0011, 0b0011_1111]);
        call(&mut workspace, "bits.write", json!({"bit_start": 0, "bits": "1", "order": "lsb"})).unwrap();
        assert_eq!(bytes_of(&mut workspace), [0b0000_0011, 0b0011_1111], "bit 0 lsb-first is the lowest bit, already set");
        call(&mut workspace, "bits.write", json!({"bit_start": 1, "bits": "0", "order": "lsb"})).unwrap();
        assert_eq!(bytes_of(&mut workspace)[0], 0b0000_0001);
        assert_eq!(call(&mut workspace, "bits.write", json!({"bit_start": 15, "bits": "11"})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "bits.write", json!({"bit_start": 0, "bits": "12"})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn a_transform_applies_to_the_selection_and_selects_what_it_produced() {
        let mut workspace = workspace_with("a.bin", &[0x0F; 8]);
        workspace.set_view("doc-1", ViewState { cursor: 6, selection: Some(Selection::Range(2, 4)), record_stride: None });
        let preview = call(&mut workspace, "transform.preview", json!({"operation": {"op": "xor", "key": "ff"}})).unwrap();
        assert_eq!(preview["ranges"], json!([{"start": 2, "len": 4, "data": "f0f0f0f0"}]));
        assert_eq!(bytes_of(&mut workspace), [0x0F; 8], "a preview changes nothing");
        let applied = call(&mut workspace, "transform.apply", json!({"operation": {"op": "xor", "key": "ff"}})).unwrap();
        assert_eq!(applied["label"], "XOR by mcp:claude-code");
        assert_eq!(bytes_of(&mut workspace), [0x0F, 0x0F, 0xF0, 0xF0, 0xF0, 0xF0, 0x0F, 0x0F]);
        let doubled = call(&mut workspace, "transform.apply", json!({"selection": {"ranges": [[0, 1], [7, 1]]}, "operation": {"op": "duplicate"}})).unwrap();
        assert_eq!(doubled["ranges"], json!([[0, 2], [8, 2]]));
        assert_eq!(workspace.view("doc-1").unwrap().selection, Some(Selection::Ranges(vec![(0, 2), (8, 2)])), "the output is selected");
        let error = call(&mut workspace, "transform.apply", json!({"selection": {"range": [8, 4]}, "operation": {"op": "invert"}})).unwrap_err();
        assert_eq!(error.code, ErrorCode::OutOfRange);
    }

    #[test]
    fn an_edit_expecting_another_version_changes_nothing() {
        let mut workspace = workspace_with("a.bin", b"abcd");
        let first = call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41", "expect_version": 0})).unwrap();
        assert_eq!(first["version"], 1);
        let stale = call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42", "expect_version": 0})).unwrap_err();
        assert_eq!(stale.code, ErrorCode::VersionConflict);
        assert_eq!(stale.data.unwrap()["version"], 1);
        assert_eq!(bytes_of(&mut workspace), b"Abcd");
        assert_eq!(call(&mut workspace, "history.undo", json!({"expect_version": 5})).unwrap_err().code, ErrorCode::VersionConflict);
        assert!(call(&mut workspace, "history.transaction", json!({"calls": [{"method": "bytes.delete", "params": {"start": 0, "len": 1}}], "expect_version": 0})).is_err());
        assert_eq!(bytes_of(&mut workspace), b"Abcd");
    }

    #[test]
    fn a_transaction_is_one_step_and_rolls_back_when_a_call_fails() {
        let mut workspace = workspace_with("a.bin", b"abcdef");
        let calls = json!([
            {"method": "bytes.write", "params": {"start": 0, "data": "5a"}},
            {"method": "transform.apply", "params": {"selection": {"range": [1, 2]}, "operation": {"op": "invert"}}},
            {"method": "bytes.read", "params": {"start": 0, "len": 1}},
        ]);
        let done = call(&mut workspace, "history.transaction", json!({"calls": calls, "label": "Patch the header"})).unwrap();
        assert_eq!(done["label"], "Patch the header by mcp:claude-code");
        assert_eq!(done["results"][2]["data"], "5a");
        assert_eq!(bytes_of(&mut workspace), [b'Z', !b'b', !b'c', b'd', b'e', b'f']);
        call(&mut workspace, "history.undo", json!({})).unwrap();
        assert_eq!(bytes_of(&mut workspace), b"abcdef", "one undo reverses every call");

        let failing = json!([
            {"method": "bytes.delete", "params": {"start": 0, "len": 2}},
            {"method": "bytes.write", "params": {"start": 0, "data": "00"}},
            {"method": "bytes.write", "params": {"start": 100, "data": "00"}},
        ]);
        let error = call(&mut workspace, "history.transaction", json!({"calls": failing})).unwrap_err();
        assert_eq!(error.code, ErrorCode::OutOfRange);
        assert_eq!(error.data.as_ref().unwrap()["failed_call"], 2);
        assert!(error.message.contains("none of the 3 calls changed anything"), "{}", error.message);
        assert_eq!(bytes_of(&mut workspace), b"abcdef");
        assert_eq!(undo_label(&mut workspace), None, "the failed transaction left no step");
        let redone = call(&mut workspace, "history.redo", json!({})).unwrap_err();
        assert_eq!(redone.code, ErrorCode::NotFound, "the earlier edits' redo was cleared as edits were made");
    }

    #[test]
    fn a_transaction_holds_only_edits_of_its_own_document() {
        let mut workspace = workspace_with("a.bin", b"abc");
        workspace.add_document("b.bin", crate::document::Document::from_bytes(b"xyz".to_vec()));
        let other = json!([{"method": "bytes.delete", "params": {"doc": "doc-1", "start": 0, "len": 1}}]);
        assert_eq!(call(&mut workspace, "history.transaction", json!({"doc": "doc-2", "calls": other})).unwrap_err().code, ErrorCode::InvalidParams);
        let undo = json!([{"method": "history.undo"}]);
        assert_eq!(call(&mut workspace, "history.transaction", json!({"calls": undo})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "history.transaction", json!({"calls": []})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn edits_are_published_as_their_callers() {
        let mut workspace = workspace_with("a.bin", b"abcd");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "00"})).unwrap();
        api::call(&mut workspace, &Caller::Plugin("sync.lua".into()), "bytes.delete", json!({"start": 0, "len": 1})).unwrap();
        let edited: Vec<(String, u64)> = workspace
            .bus()
            .recent()
            .filter(|message| message.topic() == crate::bus::Topic::DocumentEdited)
            .map(|message| (message.producer().to_string(), message.draft.version))
            .collect();
        assert_eq!(edited, [("mcp:claude-code".to_string(), 1), ("plugin:sync.lua".to_string(), 2)]);
    }

    #[test]
    fn calls_are_described_in_plain_words() {
        let mut workspace = workspace_with("a.bin", &[0u8; 256]);
        let describe = |workspace: &mut dyn Workspace, method: &str, params: serde_json::Value| crate::api::describe_call(workspace, method, &params);
        assert_eq!(describe(&mut workspace, "bytes.replace", json!({"start": 0x40, "len": 4, "data": "deadbeef"})), "Replace 4 bytes at 0x40 with DE AD BE EF");
        assert_eq!(describe(&mut workspace, "bytes.replace", json!({"start": 0x40, "len": 4, "data": "dead"})), "Replace 4 bytes at 0x40 with 2 bytes: DE AD");
        assert_eq!(describe(&mut workspace, "bytes.delete", json!({"start": 16, "len": 1})), "Delete 1 byte at 0x10");
        assert_eq!(describe(&mut workspace, "bytes.move", json!({"ranges": [[16, 4]], "to": 64})), "Move 4 bytes at 0x10 to 0x40");
        workspace.set_view("doc-1", ViewState { cursor: 0, selection: Some(Selection::Range(0, 128)), record_stride: None });
        assert_eq!(describe(&mut workspace, "transform.apply", json!({"operation": {"op": "xor", "key": "5a"}})), "XOR 128 selected bytes with 5A");
        assert_eq!(describe(&mut workspace, "bits.write", json!({"bit_start": 515, "bits": "0101"})), "Write 4 bits at bit 515 (byte 0x40): 0101");
        assert_eq!(describe(&mut workspace, "cursor.set", json!({"offset": 64})), "Move the cursor to 0x40");
        assert_eq!(describe(&mut workspace, "acme.decode", json!({"start": 1})), r#"Call acme.decode with {"start":1}"#);
        let transaction = describe(&mut workspace, "history.transaction", json!({"calls": [{"method": "bytes.delete", "params": {"start": 0, "len": 2}}]}));
        assert_eq!(transaction, "Make 1 change as one step:\n• Delete 2 bytes at 0x0");
    }

    #[test]
    fn bytes_are_inserted_at_start_as_the_other_byte_methods_name_an_offset() {
        let mut workspace = workspace_with("a.bin", b"abcd");
        call(&mut workspace, "bytes.insert", json!({"start": 2, "data": "--", "encoding": "text"})).unwrap();
        assert_eq!(bytes_of(&mut workspace), b"ab--cd");
    }
}
