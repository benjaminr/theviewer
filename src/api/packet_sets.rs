//! `packets.sets.*` and the methods on a set: packets taken from a
//! document (a capture in it, a range split into records, by a length
//! field, at a pattern, the selection's ranges, or the protocol framing),
//! listed with a filter, dissected one by one, decoded as a protocol,
//! summarised into conversations, followed as a stream and exported as pcap.
//!
//! A set's parameters say everything needed to find its packets again, so
//! the same call on another file makes the same kind of set; what the call
//! worked out for itself (the capture's offset, the framing detected, the
//! selection's ranges) is returned with the set. A set follows its
//! document: after an edit its packets are found again the way they were
//! found first. In the window, a set made through the API is shown in the
//! Packets panel.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::packets::DissectionResult;
use super::values::{self, ByteEncoding, NoParams};
use super::workspace::{self, Workspace};
use super::{ApiError, Caller, ErrorCode};
use crate::bus::topics::{FieldsGuessed, FramesDefined};
use crate::bus::{Draft, Payload};
use crate::document::Document;
use crate::packets::sources;
use crate::packets::split::{self, BytePattern, LengthCounts, LengthEncoding, LengthField, PatternMode, Resync, SyncWord};
use crate::packets::tshark_layers::{self, TsharkLayers, TsharkMode};
use crate::packets::{self, Dissection, ExportPacket, Flow, FrameProtocol, LinkKind, PacketSet, RawFrames, SetHints, Summary};
use crate::protocol::{self, Framing};
use crate::templates::Template;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("packets.sets.create", Analysis, caller create, CreateParams, SetInfo, "Take a set of packets from a document: a capture in it, a range cut into fixed records, by a length field, at a pattern or with the protocol framing, or the selection's ranges, with how to decode frames of unknown format; returns the set's id and what was worked out (the capture found, the framing), so the call can be made again exactly.").creates(crate::api::Resource { result_field: "set", param: "set", remover: "packets.sets.remove" }),
    method!("packets.sets.remove", Analysis, remove_set, SetParams, RemovedSet, "Forget a packet set: its id stops working and it leaves packets.sets.list. Its document is not changed."),
    method!("packets.sets.list", Read, list_sets, super::values::NoParams, SetList, "The packet sets made, with their ids, documents, sources, packet counts and decoding."),
    method!("packets.list", Read, list, ListParams, PacketList, "A set's packets the display filter keeps, a page at a time: each one's index, offset, length, summary columns, protocols and addresses."),
    method!("packets.dissect", Read, dissect, PacketParams, PacketDissection, "Dissect one packet of a set into protocol layers and fields, as the set decodes frames of unknown format."),
    method!("packets.decode_as", Analysis, caller decode_as, DecodeAsParams, SetInfo, "Choose the protocol a set's frames of unknown format are decoded as, or detection, and a template for frames no protocol reads.").reverses(crate::api::Reverse::Decoding),
    method!("packets.export_pcap", Analysis, export_pcap, ExportParams, ExportResult, "A set's packets (those a filter keeps) as a pcap file, returned or written to a path given (which needs leave to edit).").writes_file(crate::api::WritesFile::WhenGiven("path")),
    method!("packets.conversations", Read, conversations, ConversationsParams, ConversationList, "The conversations in a set (the packets a filter keeps): each pair of endpoints with its transport, packets and bytes each way, its first packet's index in the set, and a filter for it; in order of first packet, or sorted by packets, bytes or address."),
    method!("packets.follow_stream", Read, follow_stream, PacketParams, StreamResult, "The payloads of a packet's conversation in order, each with its direction, and the stream as text."),
    method!("packets.find_captures", Read, find_captures, FindCapturesParams, CaptureList, "The captures inside a span of a document (pcap, pcapng, snoop, Network Monitor or ERF, or one of these compressed with gzip), each with its offset, format, link type and packets, for packets.sets.create."),
    method!("packets.sets.add_packets", View, caller add_packets, AddPacketsParams, SetInfo, "Add ranges of the document to a set as packets of their own, so packets can be gathered one at a time; the set then keeps its packets where they are."),
    method!("packets.sets.refresh", View, caller refresh, RefreshParams, SetInfo, "Find a set's packets again, the way they were found, in another document (the current one by default), which the set then belongs to."),
    method!("packets.detect_length_field", Read, detect_length_field, SpanParams, LengthFieldFound, "Look for a length field that cuts a span into frames, with the protocol analysis's framing detection; returns it as packets.sets.create's length_field, or the best framing found instead."),
    method!("packets.endpoints", Read, endpoints, ConversationsParams, EndpointList, "The addresses in a set (the packets a filter keeps), busiest first or sorted by packets or address, with the packets and bytes each sent and received."),
    method!("packets.extract", Analysis, editing::extract, ExtractParams, ExtractResult, "Some of a set's packets' bytes one after another, returned or written to a path given (which needs leave to edit).").writes_file(crate::api::WritesFile::WhenGiven("path")),
    method!("packets.delete", Edit, caller editing::delete, IndicesParams, PacketEditResult, "Remove packets from the document (their whole capture records, so a capture stays readable), as one undoable step."),
    method!("packets.fix_checksums", Edit, caller editing::fix_checksums, IndicesParams, PacketEditResult, "Recompute the IPv4 header, TCP and UDP checksums of some of a set's packets, as one undoable step."),
    method!("packets.apply", Edit, caller editing::apply, ApplyParams, PacketEditResult, "Invert, fill or XOR some of a set's packets, or the same field of each, as one undoable step."),
    method!("packets.write_field", Edit, caller editing::write_field, WriteFieldParams, PacketEditResult, "Write a value (a number, or hex bytes as wide as the field) into a field of one packet, as one undoable step."),
    method!("packets.columns.apply", Edit, caller editing::apply_to_columns, ColumnOperationParams, PacketEditResult, "Change the same columns (byte offsets) of every packet, or of some, laid out one packet per row: invert, fill, XOR, add, set, number or swap the byte order, as one undoable step."),
    method!("packets.columns.delete", Edit, caller editing::delete_columns, ColumnsParams, PacketEditResult, "Remove the same columns (byte offsets) from every packet, or from some, as one undoable step; length fields and checksums are not changed."),
    method!("packets.columns.read", Read, editing::read_columns, ColumnsReadParams, ColumnsText, "The same columns (byte offsets) of every packet, or of some, as hex lines or CSV, each packet named by its index in the set (from 0, as every packet method counts)."),
    method!("packets.tshark_decode", Job, caller tshark::decode, TsharkParams, super::jobs::JobStartedResult, "Have Wireshark's tshark decode some of a set's packets (run locally with -n) as a background job; the protocols it named are the job's result, and once it finishes its layers and fields are merged into the set's, so packets.dissect shows them and filters (packets.list and the rest) can name tshark's fields, such as dns.flags.response; in the window they merge into the Packets panel's too."),
];

mod editing;
mod tshark;

pub use editing::{
    ApplyParams, ColumnFormat, ColumnOp, ColumnOperationParams, ColumnsParams, ColumnsReadParams, ColumnsText, ExtractParams, ExtractResult, FieldSpan, IndicesParams, PacketEditResult, PacketOp,
    SINGLE_EDIT_LIMIT, WriteFieldParams,
};
pub use tshark::{TsharkPacket, TsharkParams, TsharkResult, TsharkUse};

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("packets.sets.create", json!({"from": "split_fixed", "record_len": 8, "len": 64, "decode_as": "dns", "link": "unknown"})),
        ("packets.sets.list", json!({})),
        ("packets.list", json!({"set": "set-1", "filter": "len>4", "limit": 2})),
        ("packets.dissect", json!({"set": "set-1", "index": 0})),
        ("packets.decode_as", json!({"set": "set-1", "detect": false})),
        ("packets.export_pcap", json!({"set": "set-1"})),
        ("packets.conversations", json!({"set": "set-1"})),
        ("packets.follow_stream", json!({"set": "set-1", "index": 0})),
        ("packets.find_captures", json!({"start": 0})),
        ("packets.sets.add_packets", json!({"set": "set-1", "ranges": [[64, 4]]})),
        ("packets.sets.refresh", json!({"set": "set-1"})),
        ("packets.detect_length_field", json!({"start": 0, "len": 64})),
        ("packets.endpoints", json!({"set": "set-1"})),
        ("packets.extract", json!({"set": "set-1", "indices": [0, 1]})),
        ("packets.columns.read", json!({"set": "set-1", "first": 0, "width": 2, "format": "csv"})),
        ("packets.columns.apply", json!({"set": "set-1", "first": 1, "width": 1, "indices": [0, 2], "op": "xor", "key": "ff"})),
        ("packets.columns.delete", json!({"set": "set-1", "first": 7, "width": 1, "indices": [1]})),
        ("packets.apply", json!({"set": "set-1", "indices": [0], "op": "fill", "key": "00", "field": {"offset": 0, "len": 2}})),
        ("packets.write_field", json!({"set": "set-1", "index": 0, "offset": 0, "len": 2, "value": "258"})),
        ("packets.fix_checksums", json!({"set": "set-1", "indices": [0]})),
        ("packets.delete", json!({"set": "set-1", "indices": [2]})),
        ("packets.tshark_decode", json!({"set": "set-1", "indices": [0]})),
        ("packets.sets.remove", json!({"set": "set-1"})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

/// Most bytes of a capture read to take its packets.
const CAPTURE_READ_LIMIT: usize = 128 * 1024 * 1024;
/// Most bytes of a range read to split it.
const SPLIT_READ_LIMIT: usize = 128 * 1024 * 1024;
/// Most bytes read from any one packet.
const PACKET_READ_LIMIT: usize = 16 * 1024 * 1024;
/// Most bytes of all a set's packets read to dissect them.
const DISSECT_READ_LIMIT: usize = 256 * 1024 * 1024;
/// Packets `packets.list` returns when no limit is given.
const DEFAULT_LIST_LIMIT: usize = 100;

/// Where a set's packets come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SetSource {
    /// A pcap, pcapng, snoop, Network Monitor or ERF capture inside the
    /// document, whose header is at `start` (the first one found when omitted).
    Capture,
    /// The range `start`, `len` cut into records of `record_len` bytes.
    SplitFixed,
    /// The range cut into frames by the `length_field` inside each.
    LengthField,
    /// The range cut at every match of `pattern`, as `pattern_mode` says.
    Pattern,
    /// One packet per range of `ranges` (the selection's when omitted).
    Selection,
    /// The range split with `framing`, or the framing the protocol
    /// analysis finds when omitted.
    ProtocolFraming,
}

/// How a length field is written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LengthFieldEncoding {
    U8,
    #[default]
    U16,
    U32,
    /// Unsigned LEB128.
    Leb128,
}

/// What a length field counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LengthFieldCounts {
    /// The whole frame, from its first byte.
    WholeFrame,
    /// The bytes after the field.
    #[default]
    AfterField,
    /// The payload after a header of `header_len` bytes.
    Payload,
}

/// A length field inside each frame.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LengthFieldSpec {
    /// Offset of the field from each frame's first byte.
    pub offset: usize,
    #[serde(default)]
    pub encoding: LengthFieldEncoding,
    /// Byte order of a u16 or u32 field (big-endian by default).
    #[serde(default = "big_endian_by_default")]
    pub big_endian: bool,
    #[serde(default)]
    pub counts: LengthFieldCounts,
    /// For `counts: payload`, the header's length.
    #[serde(default)]
    pub header_len: usize,
    /// Added to the counted length (negative to subtract).
    #[serde(default)]
    pub adjustment: i64,
    /// Longest frame believed (64 KiB by default).
    #[serde(default)]
    pub max_frame: Option<usize>,
    /// Find the place again when a frame does not fit (a stray byte between
    /// frames, a frame cut short), rather than stopping or reading on out of
    /// step: at the sync word the first frames share before the length
    /// field (or `sync`), else at the next plausible frames. The stretches
    /// skipped are said in the set's description.
    #[serde(default)]
    pub resync: bool,
    /// The sync word, as hex such as "A5 5A", that starts every frame; given,
    /// it is resynchronised at (resync need not be given too).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<String>,
}

fn big_endian_by_default() -> bool {
    true
}

impl LengthFieldSpec {
    /// The length field the splitter reads.
    pub fn field(&self) -> LengthField {
        LengthField {
            offset: self.offset,
            encoding: match self.encoding {
                LengthFieldEncoding::U8 => LengthEncoding::U8,
                LengthFieldEncoding::U16 => LengthEncoding::U16,
                LengthFieldEncoding::U32 => LengthEncoding::U32,
                LengthFieldEncoding::Leb128 => LengthEncoding::Leb128,
            },
            big_endian: self.big_endian,
            counts: match self.counts {
                LengthFieldCounts::WholeFrame => LengthCounts::WholeFrame,
                LengthFieldCounts::AfterField => LengthCounts::AfterField,
                LengthFieldCounts::Payload => LengthCounts::Payload { header_len: self.header_len },
            },
            adjustment: self.adjustment,
            max_frame: self.max_frame.unwrap_or(split::DEFAULT_MAX_FRAME),
            resync: match self.sync_word() {
                Ok(Some(word)) => Resync::Sync(word),
                _ if self.resync || self.sync.is_some() => Resync::Learn,
                _ => Resync::Off,
            },
        }
    }

    /// The sync word given, read from its hex.
    pub fn sync_word(&self) -> Result<Option<SyncWord>, ApiError> {
        let Some(text) = &self.sync else { return Ok(None) };
        let bytes = packets::parse_hex(text).map_err(|reason| ApiError::invalid_params(format!("the sync word does not read: {reason}")))?;
        SyncWord::new(&bytes).map(Some).ok_or_else(|| ApiError::invalid_params(format!("a sync word is 1 to {} bytes", split::MAX_SYNC_LEN)))
    }

    /// `field` as `packets.sets.create` takes it.
    pub fn of(field: &LengthField) -> LengthFieldSpec {
        let (counts, header_len) = match field.counts {
            LengthCounts::WholeFrame => (LengthFieldCounts::WholeFrame, 0),
            LengthCounts::AfterField => (LengthFieldCounts::AfterField, 0),
            LengthCounts::Payload { header_len } => (LengthFieldCounts::Payload, header_len),
        };
        LengthFieldSpec {
            offset: field.offset,
            encoding: match field.encoding {
                LengthEncoding::U8 => LengthFieldEncoding::U8,
                LengthEncoding::U16 => LengthFieldEncoding::U16,
                LengthEncoding::U32 => LengthFieldEncoding::U32,
                LengthEncoding::Leb128 => LengthFieldEncoding::Leb128,
            },
            big_endian: field.big_endian,
            counts,
            header_len,
            adjustment: field.adjustment,
            max_frame: (field.max_frame != split::DEFAULT_MAX_FRAME).then_some(field.max_frame),
            resync: field.resync != Resync::Off,
            sync: match field.resync {
                Resync::Sync(word) => Some(word.describe()),
                _ => None,
            },
        }
    }
}

impl PatternPlace {
    /// Where a pattern of `mode` goes, as `packets.sets.create` takes it.
    pub fn of(mode: PatternMode) -> PatternPlace {
        match mode {
            PatternMode::StartsFrame => PatternPlace::StartsPacket,
            PatternMode::EndsFrame => PatternPlace::EndsPacket,
            PatternMode::Separates => PatternPlace::Separates,
        }
    }
}

/// Where a pattern goes relative to the packets it cuts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PatternPlace {
    /// Each packet starts with it (a sync word).
    #[default]
    StartsPacket,
    /// Each packet ends with it (a terminator such as 0D 0A).
    EndsPacket,
    /// It separates packets and belongs to neither.
    Separates,
}

/// Parameters of `packets.sets.create`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Where the packets come from.
    pub from: SetSource,
    /// Start of the range to split, or a capture's header (the first
    /// capture found when omitted); 0 by default.
    #[serde(default)]
    pub start: Option<u64>,
    /// Bytes in the range; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// For `split_fixed`: bytes per record.
    #[serde(default)]
    pub record_len: Option<usize>,
    /// For `length_field`: where each frame's length is and what it counts.
    #[serde(default)]
    pub length_field: Option<LengthFieldSpec>,
    /// For `pattern`: hex bytes with ?? for any byte (`AA 55 ?? 01`), or
    /// "text" in double quotes.
    #[serde(default)]
    pub pattern: Option<String>,
    /// For `pattern`: where the pattern goes (it starts each packet by default).
    #[serde(default)]
    pub pattern_mode: PatternPlace,
    /// For `selection`: the ranges, each `[start, len]`; the document's
    /// selection when omitted.
    #[serde(default)]
    pub ranges: Option<Vec<(u64, u64)>>,
    /// For `protocol_framing`: how the range is cut into messages; found by
    /// the protocol analysis when omitted.
    #[serde(default)]
    pub framing: Option<Framing>,
    /// What every packet's first byte is, such as "ethernet" or "raw_ip";
    /// each packet's own (its capture's, or frames of unknown format) when omitted.
    #[serde(default)]
    pub link: Option<LinkKind>,
    /// The protocol frames of unknown format are decoded as; detected from a
    /// sample of them when omitted (unless `detect` is false).
    #[serde(default)]
    pub decode_as: Option<FrameProtocol>,
    /// Whether to detect the protocol of frames of unknown format when
    /// `decode_as` is not given (true by default).
    #[serde(default)]
    pub detect: Option<bool>,
    /// Binary template source applied to each frame no protocol reads.
    #[serde(default)]
    pub template: Option<String>,
    /// For `capture`: the capture at `start` is compressed with gzip. It is
    /// opened decompressed as a document of its own, derived from this one,
    /// and the set is taken from there.
    #[serde(default)]
    pub gunzip: bool,
}

/// A packet set, as the set methods describe it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SetInfo {
    /// The set's id, such as "set-1", for the other packet methods.
    pub set: String,
    /// The document its packets are in.
    pub doc: String,
    pub from: SetSource,
    /// Such as "pcap capture at 0x40".
    pub name: String,
    /// How the packets were found.
    pub description: String,
    /// Packets in the set.
    pub count: u64,
    /// Whether the source had more packets than a set holds.
    pub capped: bool,
    /// The link every packet is read as, when one was chosen.
    pub link: Option<LinkKind>,
    /// The protocol chosen for frames of unknown format.
    pub decode_as: Option<FrameProtocol>,
    pub detect: bool,
    /// Whether a template decodes frames no protocol reads.
    pub template: bool,
    /// The template's name when it was chosen by name, or "protocol" for
    /// the one the protocol analysis suggested.
    #[serde(default)]
    pub template_name: Option<String>,
    /// Where the packets were taken from, as [start, len], once worked out
    /// (a capture found, the selection's ranges).
    pub ranges: Vec<(u64, u64)>,
    /// The framing that cut the messages, for `protocol_framing`.
    pub framing: Option<Framing>,
    /// What the person should know about how the set was taken, such as a
    /// decompressed capture cut short.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Parameters naming a set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetParams {
    /// The set's id, from packets.sets.create.
    pub set: String,
}

/// The result of `packets.sets.list`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SetList {
    pub sets: Vec<SetInfo>,
}

/// Parameters of `packets.list`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListParams {
    pub set: String,
    /// A display filter, as the Packets panel takes: protocol names,
    /// addresses, ports, `len > 60`, Wireshark field names and more.
    #[serde(default)]
    pub filter: Option<String>,
    /// Most packets to return (100 by default).
    #[serde(default)]
    pub limit: Option<usize>,
    /// The `next` cursor of the previous page.
    #[serde(default)]
    pub next: Option<String>,
}

/// One packet in a list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PacketEntry {
    /// Its index in the set, for packets.dissect.
    pub index: u64,
    /// Document offset of its first byte.
    pub offset: u64,
    pub len: u64,
    /// The link type it was dissected with.
    pub link: LinkKind,
    /// The packet list's columns.
    pub summary: Summary,
    /// Lower-case names of its layers, as the filter uses them.
    pub protocols: Vec<String>,
    pub flow: Option<Flow>,
}

/// The result of `packets.list`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PacketList {
    pub set: String,
    /// Packets the filter keeps.
    pub total: u64,
    pub packets: Vec<PacketEntry>,
    /// Pass back as `next` for more; absent after the last.
    pub next: Option<String>,
    /// The protocol frames of unknown format were detected as, if they were.
    pub detected: Option<FrameProtocol>,
}

/// Parameters of `packets.dissect` and `packets.follow_stream`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PacketParams {
    pub set: String,
    /// The packet's index in the set.
    pub index: u64,
}

/// The result of `packets.dissect`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PacketDissection {
    pub index: u64,
    /// Document offset of the packet's first byte; layer and field offsets
    /// count from it.
    pub offset: u64,
    pub len: u64,
    pub dissection: DissectionResult,
}

/// Parameters of `packets.decode_as`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecodeAsParams {
    pub set: String,
    /// The protocol frames of unknown format are decoded as; omitted, they
    /// are detected (unless `detect` is false).
    #[serde(default)]
    pub protocol: Option<FrameProtocol>,
    /// Whether to detect the protocol when none is given (true by default).
    #[serde(default)]
    pub detect: Option<bool>,
    /// Template source for frames no protocol reads, or "protocol" for the
    /// template the protocol analysis suggested for the document; omitted
    /// (with no template_name), the set's template is dropped.
    #[serde(default)]
    pub template: Option<String>,
    /// A built-in or saved template, by name, for frames no protocol reads.
    #[serde(default)]
    pub template_name: Option<String>,
    /// What every packet's first byte is, such as "ethernet"; null for each
    /// packet's own; omitted, the set's link stays as it is.
    #[serde(default, deserialize_with = "given", skip_serializing_if = "Option::is_none")]
    pub link: Option<Option<LinkKind>>,
}

/// A field given, even as null, as `Some`; a field left out stays `None`
/// through `#[serde(default)]`.
fn given<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// What a template asked for by `packets.decode_as` is called: "protocol"
/// for the protocol analysis's suggestion.
pub const PROTOCOL_TEMPLATE: &str = "protocol";

/// Parameters of `packets.export_pcap`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportParams {
    pub set: String,
    /// Only the packets this display filter keeps.
    #[serde(default)]
    pub filter: Option<String>,
    /// Only these packets, by their index in the set (those of them the
    /// filter keeps, when one is given too).
    #[serde(default)]
    pub indices: Option<Vec<u64>>,
    /// Write the pcap file here instead of returning it; needs leave to
    /// edit, as writing a file does.
    #[serde(default)]
    pub path: Option<String>,
    /// How the returned file is written: base64 (the default) or hex.
    #[serde(default = "base64_by_default")]
    pub encoding: ByteEncoding,
}

fn base64_by_default() -> ByteEncoding {
    ByteEncoding::Base64
}

/// The result of `packets.export_pcap`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExportResult {
    /// Packets written.
    pub count: u64,
    /// Bytes in the pcap file.
    pub len: u64,
    /// The file, when no path was given.
    pub data: Option<String>,
    /// Where it was written, when a path was given.
    pub path: Option<String>,
}

/// Parameters of `packets.conversations` and `packets.endpoints`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConversationsParams {
    pub set: String,
    /// Only the packets this display filter keeps.
    #[serde(default)]
    pub filter: Option<String>,
    /// The order: conversations come in order of their first packet and
    /// endpoints busiest first (by bytes) when omitted.
    #[serde(default)]
    pub sort: Option<TrafficOrder>,
}

/// How conversations or endpoints are put in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrafficOrder {
    /// Most packets first.
    Packets,
    /// Most bytes first.
    Bytes,
    /// By address (and port), lowest first.
    Address,
    /// Conversations by their first packet; for endpoints, by address.
    First,
}

/// Two endpoints and the traffic between them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ConversationEntry {
    pub transport: packets::Transport,
    pub a: packets::Endpoint,
    pub b: packets::Endpoint,
    pub packets: u64,
    pub bytes: u64,
    pub packets_a_to_b: u64,
    pub bytes_a_to_b: u64,
    /// Index of its first packet, for packets.follow_stream.
    pub first_packet: u64,
    /// A display filter selecting it.
    pub filter: String,
}

/// The result of `packets.conversations`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ConversationList {
    pub conversations: Vec<ConversationEntry>,
}

/// One packet's part of a stream.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StreamPart {
    /// The packet's index in the set.
    pub packet: u64,
    /// Sent from the conversation's first endpoint to its second.
    pub a_to_b: bool,
    /// The payload's bytes, as hex.
    pub data: String,
}

/// The result of `packets.follow_stream`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StreamResult {
    /// The conversation followed; absent when the packet has no addresses
    /// and ports, and so nothing to follow.
    pub conversation: Option<ConversationEntry>,
    /// The payloads in order, each with who sent it.
    pub parts: Vec<StreamPart>,
    /// The whole stream as text, each direction's turns marked with the
    /// packet's index in the set (from 0, as `parts` give it).
    pub text: String,
    /// TCP segments sent again and left out.
    pub retransmissions: u64,
    /// Whether the stream was longer than is kept.
    pub truncated: bool,
}

/// Parameters of `packets.find_captures`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindCapturesParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset looked in (0 by default).
    #[serde(default)]
    pub start: Option<u64>,
    /// Bytes looked in; to the end of the document when omitted, at most 128 MiB.
    #[serde(default)]
    pub len: Option<u64>,
}

/// A capture found in a document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CaptureEntry {
    /// Document offset of its file header, for packets.sets.create's start.
    pub offset: u64,
    /// Such as "pcap", "pcapng", "snoop", "Network Monitor" or "ERF".
    pub format: String,
    /// The link type of its first interface.
    pub link: LinkKind,
    pub packets: u64,
    /// Bytes from the header to the end of the last readable record, or of
    /// the gzip stream.
    pub len: u64,
    /// Whether it is compressed with gzip (packets.sets.create then needs gunzip).
    pub gzipped: bool,
    /// Such as "pcap at 0x40 · Ethernet · 3 packets".
    pub description: String,
}

/// The result of `packets.find_captures`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CaptureList {
    pub captures: Vec<CaptureEntry>,
}

/// Parameters of `packets.sets.add_packets`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddPacketsParams {
    pub set: String,
    /// The ranges to add, each `[start, len]`, one packet each.
    pub ranges: Vec<(u64, u64)>,
}

/// Parameters of `packets.sets.refresh`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RefreshParams {
    pub set: String,
    /// The document to find the packets in: id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// A span of a document.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpanParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes in the span; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
}

/// The result of `packets.detect_length_field`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LengthFieldFound {
    /// The length field, as packets.sets.create's length_field; absent when
    /// none was found.
    pub length_field: Option<LengthFieldSpec>,
    /// The field in words, such as "u16 big-endian length at +1".
    pub description: Option<String>,
    /// Frames the framing that found it cuts.
    pub frames: u64,
    /// Share of the span those frames cover, 0 to 1.
    pub coverage: f64,
    /// When no length field was found, the best framing found instead.
    pub best_framing: Option<String>,
}

/// One address and its traffic.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EndpointEntry {
    pub address: String,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
    /// A display filter keeping its packets.
    pub filter: String,
}

/// The result of `packets.endpoints`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EndpointList {
    pub endpoints: Vec<EndpointEntry>,
}

/// tshark's layers for some of a set's packets, for the document version
/// and decoding they were made from.
pub(crate) struct TsharkDecodes {
    version: u64,
    generation: u64,
    mode: TsharkMode,
    /// Counts what was stored, so dissections are merged again.
    revision: u64,
    layers: HashMap<usize, TsharkLayers>,
}

/// Where a tshark run, on its own thread, leaves its layers for the set.
pub(crate) type SharedTshark = Arc<Mutex<Option<TsharkDecodes>>>;

/// Keep tshark's `layers`, made from document version `version` and
/// decoding `generation` with `mode`, with any made from the same.
pub(crate) fn store_tshark(slot: &SharedTshark, (version, generation): (u64, u64), mode: TsharkMode, layers: &HashMap<usize, TsharkLayers>) {
    let Ok(mut slot) = slot.lock() else { return };
    let revision = slot.as_ref().map_or(0, |decodes| decodes.revision) + 1;
    match slot.as_mut() {
        Some(decodes) if (decodes.version, decodes.generation, decodes.mode) == (version, generation, mode) => {
            decodes.layers.extend(layers.iter().map(|(&index, layers)| (index, layers.clone())));
            decodes.revision = revision;
        }
        _ => *slot = Some(TsharkDecodes { version, generation, mode, revision, layers: layers.clone() }),
    }
}

/// The revision of tshark's layers that fit the set as it is, if any.
fn tshark_revision(stored: &StoredSet, version: u64) -> u64 {
    let Ok(slot) = stored.tshark.lock() else { return 0 };
    slot.as_ref().filter(|decodes| decodes.version == version && decodes.generation == stored.generation).map_or(0, |decodes| decodes.revision)
}

/// Packet `index` dissected as `ours`, with tshark's layers merged in when
/// tshark decoded it for the set as it is.
fn with_tshark(stored: &StoredSet, version: u64, index: usize, ours: Dissection) -> Dissection {
    let Ok(slot) = stored.tshark.lock() else { return ours };
    match slot.as_ref().filter(|decodes| decodes.version == version && decodes.generation == stored.generation).and_then(|decodes| Some((decodes.mode, decodes.layers.get(&index)?))) {
        Some((mode, layers)) => tshark_layers::merge(ours, layers, mode),
        None => ours,
    }
}

/// Every packet dissected, for one document version and decoding.
struct Decoded {
    version: u64,
    generation: u64,
    /// The revision of tshark's layers merged in (0 for none).
    tshark_revision: u64,
    bytes: Vec<Vec<u8>>,
    dissections: Vec<Dissection>,
    raw: RawFrames,
    detected: Option<FrameProtocol>,
}

/// One packet set made through the API.
pub struct StoredSet {
    pub info: SetInfo,
    /// The parameters it was made with.
    pub params: CreateParams,
    pub packets: PacketSet,
    /// The document version and length the packets were found in.
    built: (u64, usize),
    /// Counts changes of decoding, so dissections are made again.
    generation: u64,
    decoded: Option<Decoded>,
    /// tshark's layers, once packets.tshark_decode has run.
    pub(crate) tshark: SharedTshark,
}

/// The packet sets of a workspace.
#[derive(Default)]
pub struct PacketSets {
    sets: Vec<StoredSet>,
    created: usize,
}

impl PacketSets {
    /// Every set, oldest first.
    pub fn list(&self) -> impl Iterator<Item = &StoredSet> {
        self.sets.iter()
    }

    pub fn get(&self, id: &str) -> Option<&StoredSet> {
        self.sets.iter().find(|stored| stored.info.set == id)
    }

    /// Forget the sets of documents no longer open.
    pub fn retain_documents(&mut self, open: &[String]) {
        self.sets.retain(|stored| open.contains(&stored.info.doc));
    }

    /// Keep `packets`, found in document `doc` (at `version`, `len` bytes
    /// long) by some other means than `packets.sets.create`, as a set the
    /// methods on a set can name, and return its id. For packets a tool
    /// handed the Packets panel itself: the set is described as its
    /// packets' ranges, and follows edits as its recipe says.
    pub fn keep(&mut self, doc: &str, packets: PacketSet, (version, len): (u64, usize)) -> String {
        self.created += 1;
        let id = format!("set-{}", self.created);
        let ranges: Vec<(u64, u64)> = packets.packets.iter().map(|packet| (packet.offset as u64, packet.len as u64)).collect();
        let params = CreateParams {
            doc: Some(doc.to_string()),
            from: SetSource::Selection,
            start: None,
            len: None,
            record_len: None,
            length_field: None,
            pattern: None,
            pattern_mode: PatternPlace::default(),
            ranges: Some(ranges.clone()),
            framing: None,
            link: None,
            decode_as: None,
            detect: None,
            template: None,
            gunzip: false,
        };
        let info = SetInfo {
            set: id.clone(),
            doc: doc.to_string(),
            from: SetSource::Selection,
            name: packets.name.clone(),
            description: packets.description.clone(),
            count: packets.len() as u64,
            capped: packets.capped,
            link: None,
            decode_as: None,
            detect: true,
            template: false,
            template_name: None,
            ranges,
            framing: None,
            notes: Vec::new(),
        };
        self.sets.push(StoredSet { info, params, packets, built: (version, len), generation: 0, decoded: None, tshark: SharedTshark::default() });
        id
    }
}

fn unknown_set(id: &str) -> ApiError {
    ApiError::not_found(format!("there is no packet set '{id}'; packets.sets.list shows them"))
}

fn source_error(error: sources::SourceError) -> ApiError {
    ApiError::not_found(error.to_string())
}

/// Packets found, with where they were taken from and the framing that cut them.
struct Found {
    packets: PacketSet,
    ranges: Vec<(u64, u64)>,
    framing: Option<Framing>,
}

/// Find the packets `params` describe in `document`, and say where they came
/// from and with what framing. Packets split from the document are frames
/// of unknown format, and a capture's keep their own link type, until the
/// set's `link` is put over them, so the link can be taken off again.
fn find_packets(document: &mut Document, view_ranges: Vec<(usize, usize)>, params: &CreateParams) -> Result<Found, ApiError> {
    let link = LinkKind::Unknown;
    let range = |document: &mut Document| values::span_within(document.len(), params.start.unwrap_or(0), params.len);
    let needs = |what: &str| ApiError::invalid_params(format!("packets from {} need {what}", serde_json::to_value(params.from).ok().and_then(|from| from.as_str().map(str::to_string)).unwrap_or_default()));
    match params.from {
        SetSource::Capture => {
            let start = match params.start {
                Some(start) => values::span_within(document.len(), start, Some(0))?.0,
                None => {
                    let head = document.read_range(0, CAPTURE_READ_LIMIT);
                    sources::find_captures(&head, 0).first().map(|capture| capture.offset).ok_or_else(|| ApiError::not_found("no capture was found in the document; give the start of one"))?
                }
            };
            let bytes = document.read_range(start, CAPTURE_READ_LIMIT);
            let set = sources::from_capture(&bytes, start).map_err(source_error)?;
            let end = set.packets.iter().map(|packet| packet.end()).max().unwrap_or(start);
            Ok(Found { packets: set, ranges: vec![(start as u64, (end - start) as u64)], framing: None })
        }
        SetSource::SplitFixed => {
            let record_len = params.record_len.filter(|&len| len > 0).ok_or_else(|| needs("record_len, the bytes per record"))?;
            let (start, len) = range(document)?;
            let set = sources::split_fixed(start, len, record_len, link).map_err(source_error)?;
            Ok(Found { packets: set, ranges: vec![(start as u64, len as u64)], framing: None })
        }
        SetSource::LengthField => {
            let spec = params.length_field.as_ref().ok_or_else(|| needs("length_field, where each frame's length is"))?;
            spec.sync_word()?;
            let field = spec.field();
            let (start, len) = range(document)?;
            let bytes = document.read_range(start, len.min(SPLIT_READ_LIMIT));
            let set = split::split_by_length_field(&bytes, start, &field, link).map_err(source_error)?;
            Ok(Found { packets: set, ranges: vec![(start as u64, bytes.len() as u64)], framing: None })
        }
        SetSource::Pattern => {
            let text = params.pattern.as_deref().ok_or_else(|| needs("pattern, the bytes to cut at"))?;
            let pattern = BytePattern::parse(text).map_err(ApiError::invalid_params)?;
            let mode = match params.pattern_mode {
                PatternPlace::StartsPacket => PatternMode::StartsFrame,
                PatternPlace::EndsPacket => PatternMode::EndsFrame,
                PatternPlace::Separates => PatternMode::Separates,
            };
            let (start, len) = range(document)?;
            let bytes = document.read_range(start, len.min(SPLIT_READ_LIMIT));
            let set = split::split_by_pattern(&bytes, start, &pattern, mode, link).map_err(source_error)?;
            Ok(Found { packets: set, ranges: vec![(start as u64, bytes.len() as u64)], framing: None })
        }
        SetSource::Selection => {
            let ranges: Vec<(usize, usize)> = match &params.ranges {
                Some(ranges) => ranges.iter().map(|&(start, len)| values::span_within(document.len(), start, Some(len))).collect::<Result<_, _>>()?,
                None => view_ranges,
            };
            let ranges: Vec<(usize, usize)> = ranges.into_iter().filter(|&(_, len)| len > 0).collect();
            if ranges.is_empty() {
                return Err(ApiError::invalid_params("nothing is selected; give the packets' ranges as ranges, each [start, len]"));
            }
            let mut set = PacketSet::new(format!("{} ranges", ranges.len()), format!("{} ranges given", ranges.len()));
            for &(start, len) in &ranges {
                set.push(packets::Packet::new(start, len, link, format!("range {start:#x}")));
            }
            Ok(Found { packets: set, ranges: ranges.iter().map(|&(start, len)| (start as u64, len as u64)).collect(), framing: None })
        }
        SetSource::ProtocolFraming => {
            let (start, len) = range(document)?;
            let bytes = document.read_range(start, len.min(SPLIT_READ_LIMIT));
            let framing = match &params.framing {
                Some(framing) => framing.clone(),
                None => protocol::detect_framing(&bytes, 1).into_iter().next().map(|candidate| candidate.framing).ok_or_else(|| ApiError::not_found("the protocol analysis found no framing in the range; give one as framing"))?,
            };
            let set = sources::from_framing(&bytes, start, &framing).map_err(source_error)?;
            Ok(Found { packets: set, ranges: vec![(start as u64, bytes.len() as u64)], framing: Some(framing) })
        }
    }
}

/// Open the gzip-compressed capture at `start` of document `doc`
/// decompressed, as a document derived from it, and return the new
/// document's id with what to say of it.
fn open_gunzipped(workspace: &mut dyn Workspace, doc: &str, start: Option<u64>) -> Result<(String, Vec<String>), ApiError> {
    let start = start.ok_or_else(|| ApiError::invalid_params("gunzip needs start, the offset of the gzip stream"))?;
    let parent = workspace::info(workspace, doc)?.name;
    let (_, document) = workspace::document(workspace, Some(doc))?;
    let (offset, _) = values::span_within(document.len(), start, Some(0))?;
    let bytes = document.read_range(offset, CAPTURE_READ_LIMIT);
    if !sources::gzip::looks_like(&bytes) {
        return Err(ApiError::not_found(format!("there is no gzip stream at {offset:#x}; leave out gunzip for a capture that is not compressed")));
    }
    let capture = sources::gzip::gunzip(&bytes, offset).map_err(source_error)?;
    if let Err(error) = sources::from_capture(&capture.data, 0) {
        return Err(ApiError::not_found(format!("the gzip stream at {offset:#x} decompresses to a {} header, but: {error}", capture.format.label())));
    }
    let name = format!("{parent} › {} capture decompressed from {offset:#x}", capture.format.label());
    let notes = if capture.truncated { vec![format!("Only the first {} of the decompressed capture were opened.", crate::compress::human_bytes(sources::gzip::MAX_GUNZIPPED_LEN))] } else { Vec::new() };
    let derived = workspace.open_derived(doc, capture.data, &name)?;
    Ok((derived, notes))
}

pub fn create(workspace: &mut dyn Workspace, caller: &Caller, params: CreateParams) -> Result<SetInfo, ApiError> {
    let mut doc = workspace::resolve(workspace, params.doc.as_deref())?;
    if let Some(source) = &params.template {
        Template::parse(source).map_err(|error| ApiError::invalid_params(format!("the template does not parse: {error}")))?;
    }
    let mut notes = Vec::new();
    let mut params = params;
    if params.gunzip {
        if params.from != SetSource::Capture {
            return Err(ApiError::invalid_params("gunzip is for a capture compressed with gzip: give from \"capture\""));
        }
        (doc, notes) = open_gunzipped(workspace, &doc, params.start)?;
        // The capture is now the derived document's, from its first byte.
        params.doc = Some(doc.clone());
        params.start = Some(0);
        params.gunzip = false;
    }
    let view_ranges = match (params.from, workspace.view(&doc)) {
        (SetSource::Selection, Some(view)) => {
            let len = workspace::info(workspace, &doc)?.len as usize;
            view.selection.map(|selection| selection.ranges(len)).unwrap_or_default()
        }
        _ => Vec::new(),
    };
    let document = workspace.document_mut(&doc).ok_or_else(|| ApiError::not_found(format!("document '{doc}' has closed")))?;
    let Found { packets: mut found, ranges, framing } = find_packets(document, view_ranges, &params)?;
    if let Some(link) = params.link {
        found.packets.iter_mut().for_each(|packet| packet.link = link);
    }
    let built = (document.version(), document.len());
    let sets = workspace.packet_sets_mut();
    sets.created += 1;
    let id = format!("set-{}", sets.created);
    let info = SetInfo {
        set: id.clone(),
        doc: doc.clone(),
        from: params.from,
        name: found.name.clone(),
        description: found.description.clone(),
        count: found.len() as u64,
        capped: found.capped,
        link: params.link,
        decode_as: params.decode_as,
        detect: params.detect.unwrap_or(true),
        template: params.template.is_some(),
        template_name: None,
        ranges,
        framing,
        notes,
    };
    sets.sets.push(StoredSet { info: info.clone(), params, packets: found, built, generation: 0, decoded: None, tshark: SharedTshark::default() });
    publish_set(workspace, caller, &id);
    workspace.show_packet_set(&id);
    Ok(info)
}

/// Say where a set's packets are on `frames.defined`, as the caller's, keyed
/// by the set's id, so tools, plugins and resource subscribers hear of it.
fn publish_set(workspace: &mut dyn Workspace, caller: &Caller, id: &str) {
    let Some(stored) = workspace.packet_sets().get(id) else { return };
    let packets = &stored.packets.packets;
    let start = packets.iter().map(|packet| packet.offset).min().unwrap_or(0);
    let end = packets.iter().map(|packet| packet.end()).max().unwrap_or(start);
    let decoding = match (stored.info.decode_as, stored.info.detect) {
        (Some(protocol), _) => format!(", decoded as {}", protocol.label()),
        (None, true) => String::new(),
        (None, false) => ", not detected".to_string(),
    };
    let mut frames = FramesDefined::new(packets.iter().map(|packet| (packet.offset, packet.len)), format!("{}: {}{decoding}", stored.info.set, stored.info.name));
    if let Some(framing) = &stored.info.framing {
        frames = frames.with_framing(framing.clone());
    }
    let draft = Draft::new(caller.producer(), Payload::FramesDefined(frames)).about(stored.info.doc.clone(), stored.built.0).span(start, end - start).key(id);
    workspace.bus().publish(draft);
}

/// The set that was forgotten.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub struct RemovedSet {
    pub set: String,
}

impl PacketSets {
    /// Forget set `id`. Returns whether there was one.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.sets.len();
        self.sets.retain(|stored| stored.info.set != id);
        self.sets.len() != before
    }
}

pub fn remove_set(workspace: &mut dyn Workspace, params: SetParams) -> Result<RemovedSet, ApiError> {
    if !workspace.packet_sets_mut().remove(&params.set) {
        return Err(unknown_set(&params.set));
    }
    Ok(RemovedSet { set: params.set })
}

pub fn list_sets(workspace: &mut dyn Workspace, _params: NoParams) -> Result<SetList, ApiError> {
    let open: Vec<String> = workspace.documents().into_iter().map(|info| info.id).collect();
    let sets = workspace.packet_sets_mut();
    sets.retain_documents(&open);
    Ok(SetList { sets: sets.list().map(|stored| stored.info.clone()).collect() })
}

/// Run `work` on set `id` with its document, the packets found again first
/// when the document changed since.
fn with_set<R>(workspace: &mut dyn Workspace, id: &str, work: impl FnOnce(&mut StoredSet, &mut Document) -> Result<R, ApiError>) -> Result<R, ApiError> {
    let sets = workspace.packet_sets_mut();
    let index = sets.sets.iter().position(|stored| stored.info.set == id).ok_or_else(|| unknown_set(id))?;
    let mut stored = sets.sets.remove(index);
    let result = match workspace.document_mut(&stored.info.doc) {
        Some(document) => {
            follow_document(&mut stored, document);
            work(&mut stored, document)
        }
        None => Err(ApiError::not_found(format!("the document of {id}, {}, has closed", stored.info.doc))),
    };
    let sets = workspace.packet_sets_mut();
    sets.sets.insert(index.min(sets.sets.len()), stored);
    result
}

/// After an edit, find the packets again the way they were found.
fn follow_document(stored: &mut StoredSet, document: &mut Document) {
    let (version, len) = stored.built;
    if document.version() == version {
        return;
    }
    let growth = document.len() as i64 - len as i64;
    if let Some((start, read)) = stored.packets.recipe.range(growth, document.len(), CAPTURE_READ_LIMIT) {
        let bytes = document.read_range(start, read);
        if let Ok(mut found) = stored.packets.recipe.rebuild(&bytes, start) {
            if let Some(link) = stored.info.link {
                found.packets.iter_mut().for_each(|packet| packet.link = link);
            }
            stored.info.count = found.len() as u64;
            stored.info.description = found.description.clone();
            stored.packets = found;
        }
    }
    stored.built = (document.version(), document.len());
    stored.decoded = None;
}

/// Every packet of the set read and dissected, as the set decodes them.
fn decode<'a>(stored: &'a mut StoredSet, document: &mut Document) -> &'a Decoded {
    let tshark_revision = tshark_revision(stored, document.version());
    let current = stored.decoded.as_ref().is_some_and(|decoded| decoded.version == document.version() && decoded.generation == stored.generation && decoded.tshark_revision == tshark_revision);
    if !current {
        let mut room = DISSECT_READ_LIMIT;
        let bytes: Vec<Vec<u8>> = stored
            .packets
            .packets
            .iter()
            .map(|packet| {
                let read = document.read_range(packet.offset, packet.len.min(PACKET_READ_LIMIT).min(room));
                room -= read.len();
                read
            })
            .collect();
        let links: Vec<LinkKind> = stored.packets.packets.iter().map(|packet| packet.link).collect();
        let mut raw = RawFrames { hints: SetHints::learn(bytes.iter().zip(&links).map(|(bytes, &link)| (bytes.as_slice(), link))), ..RawFrames::default() };
        raw.template = stored.params.template.as_deref().and_then(|source| Template::parse(source).ok());
        let unknown: Vec<&[u8]> = bytes.iter().zip(&links).filter(|(_, link)| **link == LinkKind::Unknown).map(|(bytes, _)| bytes.as_slice()).collect();
        let detected = (stored.info.decode_as.is_none() && stored.info.detect && !unknown.is_empty()).then(|| packets::detect_frame_protocol(&unknown)).flatten().map(|found| found.protocol);
        raw.decode_as = stored.info.decode_as.or(detected);
        let version = document.version();
        let dissections = bytes.iter().zip(&links).enumerate().map(|(index, (bytes, &link))| with_tshark(stored, version, index, packets::dissect_with(bytes, link, &raw))).collect();
        stored.decoded = Some(Decoded { version, generation: stored.generation, tshark_revision, bytes, dissections, raw, detected });
    }
    stored.decoded.as_ref().expect("decoded above")
}

/// Indices of the packets `filter` keeps.
fn filtered(stored: &StoredSet, decoded: &Decoded, filter: Option<&str>) -> Result<Vec<usize>, ApiError> {
    let all = 0..decoded.dissections.len();
    let Some(text) = filter.filter(|text| !text.trim().is_empty()) else { return Ok(all.collect()) };
    let known = packets::filter::KnownFields::of(&decoded.dissections);
    let filter = packets::filter::parse_filter_for(text, &known).map_err(|error| ApiError::invalid_params(format!("the filter does not read: {error}")))?;
    Ok(all
        .filter(|&index| {
            let dissection = &decoded.dissections[index];
            let values = |name: &str| packets::filter::wireshark_values(dissection, name);
            let subject = packets::FilterSubject {
                protocols: &dissection.protocols,
                tshark_protocols: &dissection.tshark_protocols,
                flow: dissection.flow.as_ref(),
                summary: &dissection.summary,
                bytes: &decoded.bytes[index],
                len: stored.packets.packets.get(index).map_or(0, |packet| packet.len),
                fields: Some(&values as &packets::filter::FieldValues),
            };
            filter.matches(&subject)
        })
        .collect())
}

pub fn list(workspace: &mut dyn Workspace, params: ListParams) -> Result<PacketList, ApiError> {
    with_set(workspace, &params.set.clone(), |stored, document| {
        decode(stored, document);
        let decoded = stored.decoded.as_ref().expect("decoded");
        let kept = filtered(stored, decoded, params.filter.as_deref())?;
        let total = kept.len() as u64;
        let limit = Some(params.limit.unwrap_or(DEFAULT_LIST_LIMIT));
        let (page, next) = values::page(kept, params.next.as_deref(), limit)?;
        let packets = page
            .into_iter()
            .map(|index| {
                let packet = &stored.packets.packets[index];
                let dissection = &decoded.dissections[index];
                PacketEntry {
                    index: index as u64,
                    offset: packet.offset as u64,
                    len: packet.len as u64,
                    link: dissection.link,
                    summary: dissection.summary.clone(),
                    protocols: dissection.protocols.iter().map(|name| name.to_string()).collect(),
                    flow: dissection.flow,
                }
            })
            .collect();
        Ok(PacketList { set: params.set.clone(), total, packets, next, detected: decoded.detected })
    })
}

/// A dissection as the API returns it.
pub fn dissection_result(dissection: Dissection) -> DissectionResult {
    DissectionResult {
        link: dissection.link,
        layers: dissection.layers,
        summary: dissection.summary,
        protocols: dissection.protocols.iter().map(|protocol| protocol.to_string()).collect(),
        flow: dissection.flow,
        payload: dissection.payload.map(|(offset, len)| (offset as u64, len as u64)),
        ether_type: dissection.ether_type,
        notes: dissection.notes,
    }
}

/// Check that every one of `indices` is a packet of the set, and return
/// them in the order given, once each.
fn packet_indices(stored: &StoredSet, indices: &[u64]) -> Result<Vec<usize>, ApiError> {
    let mut chosen = Vec::with_capacity(indices.len());
    let mut seen = std::collections::HashSet::new();
    for &index in indices {
        let index = packet_index(stored, index)?;
        if seen.insert(index) {
            chosen.push(index);
        }
    }
    Ok(chosen)
}

/// Check that packet `index` is in the set.
fn packet_index(stored: &StoredSet, index: u64) -> Result<usize, ApiError> {
    let count = stored.packets.len();
    usize::try_from(index).ok().filter(|&index| index < count).ok_or_else(|| ApiError::out_of_range(format!("{} holds {count} packets; packet {index} is not one of them", stored.info.set)))
}

pub fn dissect(workspace: &mut dyn Workspace, params: PacketParams) -> Result<PacketDissection, ApiError> {
    with_set(workspace, &params.set, |stored, document| {
        let index = packet_index(stored, params.index)?;
        decode(stored, document);
        let decoded = stored.decoded.as_ref().expect("decoded");
        let packet = &stored.packets.packets[index];
        // Dissected afresh, with every note, from the bytes as they are.
        let dissection = with_tshark(stored, decoded.version, index, packets::dissect_with(&decoded.bytes[index], packet.link, &decoded.raw));
        Ok(PacketDissection { index: index as u64, offset: packet.offset as u64, len: packet.len as u64, dissection: dissection_result(dissection) })
    })
}

/// The built-in templates and the person's own, as (name, source).
pub fn available_templates() -> Vec<(String, String)> {
    let mut all: Vec<(String, String)> = crate::templates::builtin_templates().into_iter().map(|(name, source)| (name.to_string(), source.to_string())).collect();
    if let Some(dir) = crate::templates::default_dir() {
        for (name, result) in crate::templates::load_dir(&dir) {
            if result.is_ok()
                && let Ok(source) = std::fs::read_to_string(dir.join(format!("{name}.tpl")))
            {
                all.push((name, source));
            }
        }
    }
    all
}

/// The template `params` ask for, as (source, name it was asked for by).
fn chosen_template(workspace: &mut dyn Workspace, params: &DecodeAsParams) -> Result<(Option<String>, Option<String>), ApiError> {
    if let Some(name) = &params.template_name {
        if params.template.is_some() {
            return Err(ApiError::invalid_params("give the template as template (its source) or as template_name, not both"));
        }
        let (_, source) = available_templates().into_iter().find(|(known, _)| known == name).ok_or_else(|| ApiError::not_found(format!("there is no template called '{name}'")))?;
        return Ok((Some(source), Some(name.clone())));
    }
    match params.template.as_deref() {
        Some(PROTOCOL_TEMPLATE) => {
            let doc = workspace.packet_sets().get(&params.set).map(|stored| stored.info.doc.clone()).ok_or_else(|| unknown_set(&params.set))?;
            let suggested = workspace.bus().latest_from::<FieldsGuessed>(&doc, crate::analysis_tools::PROTOCOL_PRODUCER).and_then(|(_, guessed)| guessed.template.clone());
            let source = suggested.ok_or_else(|| ApiError::not_found("the protocol analysis has suggested no template for this document; run it first"))?;
            Ok((Some(source), Some(PROTOCOL_TEMPLATE.to_string())))
        }
        Some(source) => {
            Template::parse(source).map_err(|error| ApiError::invalid_params(format!("the template does not parse: {error}")))?;
            Ok((Some(source.to_string()), None))
        }
        None => Ok((None, None)),
    }
}

/// Put `link` over every packet of `stored`, or give each its own back.
fn relink(stored: &mut StoredSet, link: Option<LinkKind>) {
    for packet in &mut stored.packets.packets {
        packet.link = link.unwrap_or_else(|| LinkKind::from_pcap_link_type(packet.link_type));
    }
    stored.info.link = link;
    stored.params.link = link;
}

pub fn decode_as(workspace: &mut dyn Workspace, caller: &Caller, params: DecodeAsParams) -> Result<SetInfo, ApiError> {
    let (template, template_name) = chosen_template(workspace, &params)?;
    let info = with_set(workspace, &params.set, |stored, _| {
        stored.info.decode_as = params.protocol;
        stored.info.detect = params.detect.unwrap_or(true);
        stored.info.template = template.is_some();
        stored.info.template_name = template_name;
        stored.params.decode_as = params.protocol;
        stored.params.detect = params.detect;
        stored.params.template = template;
        if let Some(link) = params.link {
            relink(stored, link);
        }
        stored.generation += 1;
        Ok(stored.info.clone())
    })?;
    publish_set(workspace, caller, &params.set);
    workspace.show_packet_set(&params.set);
    Ok(info)
}

pub fn export_pcap(workspace: &mut dyn Workspace, params: ExportParams) -> Result<ExportResult, ApiError> {
    let file = with_set(workspace, &params.set, |stored, document| {
        decode(stored, document);
        let decoded = stored.decoded.as_ref().expect("decoded");
        let mut kept = filtered(stored, decoded, params.filter.as_deref())?;
        if let Some(indices) = &params.indices {
            let order: std::collections::HashMap<usize, usize> = packet_indices(stored, indices)?.into_iter().enumerate().map(|(position, index)| (index, position)).collect();
            kept.retain(|index| order.contains_key(index));
            kept.sort_by_key(|index| order[index]);
        }
        let export: Vec<ExportPacket> = kept
            .iter()
            .map(|&index| {
                let packet = &stored.packets.packets[index];
                ExportPacket { bytes: &decoded.bytes[index], original_len: packet.len, timestamp: packet.timestamp, link: decoded.dissections[index].link }
            })
            .collect();
        let file = packets::write_pcap(&export).map_err(|error| ApiError::invalid_params(error.to_string()))?;
        Ok((kept.len(), file))
    })?;
    let (count, file) = file;
    match params.path {
        Some(path) => {
            std::fs::write(Path::new(&path), &file).map_err(|error| ApiError::new(ErrorCode::Unavailable, format!("could not write {path}: {error}")))?;
            Ok(ExportResult { count: count as u64, len: file.len() as u64, data: None, path: Some(path) })
        }
        None => {
            values::check_call_size(file.len())?;
            Ok(ExportResult { count: count as u64, len: file.len() as u64, data: Some(values::encode_bytes(&file, params.encoding)), path: None })
        }
    }
}

fn conversation_entry(conversation: &packets::Conversation) -> ConversationEntry {
    ConversationEntry {
        transport: conversation.key.transport,
        a: conversation.key.a,
        b: conversation.key.b,
        packets: conversation.packets as u64,
        bytes: conversation.bytes as u64,
        packets_a_to_b: conversation.packets_a_to_b as u64,
        bytes_a_to_b: conversation.bytes_a_to_b as u64,
        first_packet: conversation.first_packet as u64,
        filter: conversation.key.filter_text(),
    }
}

pub fn conversations(workspace: &mut dyn Workspace, params: ConversationsParams) -> Result<ConversationList, ApiError> {
    with_set(workspace, &params.set, |stored, document| {
        decode(stored, document);
        let decoded = stored.decoded.as_ref().expect("decoded");
        let kept = filtered(stored, decoded, params.filter.as_deref())?;
        let mut found = packets::flows::conversations_of(kept.iter().map(|&index| (index, decoded.dissections[index].flow.as_ref(), stored.packets.packets[index].len)));
        match params.sort.unwrap_or(TrafficOrder::First) {
            TrafficOrder::Packets => found.sort_by_key(|conversation| (std::cmp::Reverse(conversation.packets), conversation.first_packet)),
            TrafficOrder::Bytes => found.sort_by_key(|conversation| (std::cmp::Reverse(conversation.bytes), conversation.first_packet)),
            TrafficOrder::Address => found.sort_by_key(|conversation| (conversation.key.a, conversation.key.b, conversation.key.transport)),
            TrafficOrder::First => found.sort_by_key(|conversation| conversation.first_packet),
        }
        Ok(ConversationList { conversations: found.iter().map(conversation_entry).collect() })
    })
}

pub fn follow_stream(workspace: &mut dyn Workspace, params: PacketParams) -> Result<StreamResult, ApiError> {
    with_set(workspace, &params.set, |stored, document| {
        let index = packet_index(stored, params.index)?;
        decode(stored, document);
        let decoded = stored.decoded.as_ref().expect("decoded");
        let Some(flow) = decoded.dissections[index].flow else {
            return Ok(StreamResult { conversation: None, parts: Vec::new(), text: String::new(), retransmissions: 0, truncated: false });
        };
        let key = flow.key();
        let payload_of = |index: usize, dissection: &Dissection| {
            let bytes = decoded.bytes[index].as_slice();
            let (start, len) = dissection.payload?;
            bytes.get(start..(start + len).min(bytes.len()))
        };
        let members: Vec<(usize, &Flow, &[u8])> =
            decoded.dissections.iter().enumerate().filter_map(|(index, dissection)| Some((index, dissection.flow.as_ref()?, payload_of(index, dissection)?))).collect();
        let lengths: BTreeMap<usize, usize> = stored.packets.packets.iter().enumerate().map(|(index, packet)| (index, packet.len)).collect();
        let stream = packets::follow_stream(&key, members);
        let in_conversation = decoded.dissections.iter().enumerate().filter(|(_, dissection)| dissection.flow.is_some_and(|other| other.key() == key)).map(|(index, dissection)| (index, dissection.flow.as_ref(), lengths[&index]));
        let conversation = packets::flows::conversations_of(in_conversation).into_iter().next().map(|found| conversation_entry(&found));
        let parts = stream
            .segments
            .iter()
            .map(|segment| StreamPart { packet: segment.packet as u64, a_to_b: segment.a_to_b, data: crate::ops::to_compact_hex(&stream.bytes[segment.start..segment.start + segment.len]) })
            .collect();
        Ok(StreamResult { conversation, parts, text: stream.marked_text(0), retransmissions: stream.retransmissions as u64, truncated: stream.truncated })
    })
}

pub fn endpoints(workspace: &mut dyn Workspace, params: ConversationsParams) -> Result<EndpointList, ApiError> {
    with_set(workspace, &params.set, |stored, document| {
        decode(stored, document);
        let decoded = stored.decoded.as_ref().expect("decoded");
        let kept = filtered(stored, decoded, params.filter.as_deref())?;
        let mut found = packets::endpoints(kept.iter().map(|&index| (decoded.dissections[index].flow.as_ref(), stored.packets.packets[index].len)));
        match params.sort.unwrap_or(TrafficOrder::Bytes) {
            TrafficOrder::Packets => found.sort_by_key(|endpoint| (std::cmp::Reverse(endpoint.packets_sent + endpoint.packets_received), endpoint.address)),
            // packets::endpoints gives the busiest by bytes first already.
            TrafficOrder::Bytes => {}
            TrafficOrder::Address | TrafficOrder::First => found.sort_by_key(|endpoint| endpoint.address),
        }
        let endpoints = found
            .into_iter()
            .map(|endpoint| EndpointEntry {
                address: endpoint.address.to_string(),
                packets_sent: endpoint.packets_sent as u64,
                bytes_sent: endpoint.bytes_sent as u64,
                packets_received: endpoint.packets_received as u64,
                bytes_received: endpoint.bytes_received as u64,
                filter: format!("ip:{}", endpoint.address),
            })
            .collect();
        Ok(EndpointList { endpoints })
    })
}

pub fn find_captures(workspace: &mut dyn Workspace, params: FindCapturesParams) -> Result<CaptureList, ApiError> {
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (start, len) = values::span_within(document.len(), params.start.unwrap_or(0), params.len)?;
    let bytes = document.read_range(start, len.min(CAPTURE_READ_LIMIT));
    let captures = sources::find_captures(&bytes, start)
        .into_iter()
        .map(|capture| CaptureEntry {
            offset: capture.offset as u64,
            format: capture.format.label().to_string(),
            link: capture.link,
            packets: capture.packets as u64,
            len: capture.len as u64,
            gzipped: capture.gzipped,
            description: capture.describe(),
        })
        .collect();
    Ok(CaptureList { captures })
}

/// Framings asked of the protocol analysis's detection when looking for a
/// length field.
const LENGTH_FIELD_CANDIDATES: usize = 8;

pub fn detect_length_field(workspace: &mut dyn Workspace, params: SpanParams) -> Result<LengthFieldFound, ApiError> {
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (start, len) = values::span_within(document.len(), params.start, params.len)?;
    if len == 0 {
        return Err(ApiError::invalid_params("the span is empty; give some bytes to look at"));
    }
    let bytes = document.read_range(start, len.min(SPLIT_READ_LIMIT));
    let candidates = protocol::detect_framing(&bytes, LENGTH_FIELD_CANDIDATES);
    let found = candidates.iter().find_map(|candidate| split::length_field_from_framing(&candidate.framing).map(|field| (field, candidate)));
    Ok(match found {
        Some((field, candidate)) => LengthFieldFound {
            length_field: Some(LengthFieldSpec::of(&field)),
            description: Some(field.describe()),
            frames: candidate.messages as u64,
            coverage: candidate.coverage,
            best_framing: None,
        },
        None => LengthFieldFound { length_field: None, description: None, frames: 0, coverage: 0.0, best_framing: candidates.first().map(|best| best.framing.describe()) },
    })
}

pub fn add_packets(workspace: &mut dyn Workspace, caller: &Caller, params: AddPacketsParams) -> Result<SetInfo, ApiError> {
    if params.ranges.is_empty() {
        return Err(ApiError::invalid_params("give the packets to add as ranges, each [start, len]"));
    }
    let info = with_set(workspace, &params.set, |stored, document| {
        let ranges: Vec<(usize, usize)> = params.ranges.iter().map(|&(start, len)| values::span_within(document.len(), start, Some(len))).collect::<Result<_, _>>()?;
        if ranges.iter().any(|&(_, len)| len == 0) {
            return Err(ApiError::invalid_params("a packet needs at least one byte"));
        }
        if stored.packets.len() + ranges.len() > packets::MAX_PACKETS {
            return Err(ApiError::too_large(format!("a set holds at most {} packets", packets::MAX_PACKETS)));
        }
        let link = stored.info.link;
        for &(start, len) in &ranges {
            let mut packet = packets::Packet::new(start, len, LinkKind::Unknown, format!("range {start:#x}"));
            packet.link = link.unwrap_or(LinkKind::Unknown);
            stored.packets.push(packet);
        }
        let set = &mut stored.packets;
        set.recipe = sources::Recipe::Fixed;
        set.name = "packets added by hand".to_string();
        set.description = format!("{} ranges added by hand", set.len());
        stored.info.name = set.name.clone();
        stored.info.description = set.description.clone();
        stored.info.count = set.len() as u64;
        stored.info.ranges.extend(ranges.iter().map(|&(start, len)| (start as u64, len as u64)));
        stored.decoded = None;
        Ok(stored.info.clone())
    })?;
    publish_set(workspace, caller, &params.set);
    workspace.show_packet_set(&params.set);
    Ok(info)
}

pub fn refresh(workspace: &mut dyn Workspace, caller: &Caller, params: RefreshParams) -> Result<SetInfo, ApiError> {
    let doc = workspace::resolve(workspace, params.doc.as_deref())?;
    let sets = workspace.packet_sets_mut();
    let index = sets.sets.iter().position(|stored| stored.info.set == params.set).ok_or_else(|| unknown_set(&params.set))?;
    let mut stored = sets.sets.remove(index);
    let result = match workspace.document_mut(&doc) {
        Some(document) => {
            // Found again in this document as it is now, with nothing grown.
            stored.built = (u64::MAX, document.len());
            stored.info.doc = doc.clone();
            follow_document(&mut stored, document);
            Ok(stored.info.clone())
        }
        None => Err(ApiError::not_found(format!("document '{doc}' has closed"))),
    };
    let sets = workspace.packet_sets_mut();
    sets.sets.insert(index.min(sets.sets.len()), stored);
    let info = result?;
    publish_set(workspace, caller, &params.set);
    workspace.show_packet_set(&params.set);
    Ok(info)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    /// A pcap capture of DNS queries over UDP from 10.0.0.2 to 10.0.0.1.
    pub(crate) fn dns_capture(queries: u16) -> Vec<u8> {
        let mut file = Vec::new();
        file.extend(0xA1B2_C3D4u32.to_le_bytes());
        file.extend(2u16.to_le_bytes());
        file.extend(4u16.to_le_bytes());
        file.extend([0; 8]);
        file.extend(65_535u32.to_le_bytes());
        file.extend(1u32.to_le_bytes());
        for id in 0..queries {
            let mut message = id.to_be_bytes().to_vec();
            message.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
            message.extend(b"\x07example\x03com\x00");
            message.extend([0, 1, 0, 1]);
            let builder = etherparse::PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]).ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).udp(4000 + id, 53);
            let mut frame = Vec::new();
            builder.write(&mut frame, &message).unwrap();
            file.extend(u32::from(id).to_le_bytes());
            file.extend(0u32.to_le_bytes());
            file.extend((frame.len() as u32).to_le_bytes());
            file.extend((frame.len() as u32).to_le_bytes());
            file.extend(frame);
        }
        file
    }

    #[test]
    fn a_capture_in_the_document_becomes_a_set_listed_filtered_and_dissected() {
        let mut bytes = vec![0xEE; 32];
        bytes.extend(dns_capture(3));
        let mut workspace = workspace_with("traffic.bin", &bytes);
        let created = call(&mut workspace, "packets.sets.create", json!({"from": "capture"})).unwrap();
        assert_eq!(created["set"], "set-1");
        assert_eq!(created["count"], 3);
        assert_eq!(created["ranges"][0][0], 32, "the capture found is said, so the call can be made again exactly");
        let sets = call(&mut workspace, "packets.sets.list", json!({})).unwrap();
        assert_eq!(sets["sets"].as_array().unwrap().len(), 1);
        let listed = call(&mut workspace, "packets.list", json!({"set": "set-1", "filter": "udp.srcport==4001", "limit": 10})).unwrap();
        assert_eq!(listed["total"], 1);
        assert_eq!(listed["packets"][0]["index"], 1);
        assert_eq!(listed["packets"][0]["summary"]["protocol"], "DNS");
        let page = call(&mut workspace, "packets.list", json!({"set": "set-1", "limit": 2})).unwrap();
        assert_eq!((page["packets"].as_array().unwrap().len(), page["next"].as_str()), (2, Some("2")));
        let dissected = call(&mut workspace, "packets.dissect", json!({"set": "set-1", "index": 2})).unwrap();
        assert!(dissected["dissection"]["protocols"].as_array().unwrap().contains(&json!("dns")));
        assert_eq!(call(&mut workspace, "packets.dissect", json!({"set": "set-1", "index": 9})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "packets.list", json!({"set": "set-9"})).unwrap_err().code, ErrorCode::NotFound);
    }

    /// Back-to-back DNS messages, each prefixed with its length as TCP carries them.
    fn length_prefixed_dns(messages: u16) -> Vec<u8> {
        let mut stream = Vec::new();
        for id in 0..messages {
            let mut message = id.to_be_bytes().to_vec();
            message.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
            message.extend(b"\x07example\x03com\x00");
            message.extend([0, 1, 0, 1]);
            stream.extend((message.len() as u16).to_be_bytes());
            stream.extend(message);
        }
        stream
    }

    #[test]
    fn frames_split_by_a_length_field_are_decoded_as_the_protocol_asked_for_or_left_raw() {
        let mut workspace = workspace_with("stream.bin", &length_prefixed_dns(4));
        let params = json!({"from": "length_field", "length_field": {"offset": 0, "encoding": "u16"}, "detect": false});
        let created = call(&mut workspace, "packets.sets.create", params).unwrap();
        assert_eq!(created["count"], 4, "{created}");
        let raw = call(&mut workspace, "packets.list", json!({"set": "set-1"})).unwrap();
        assert_ne!(raw["packets"][0]["summary"]["protocol"], "DNS", "not detected when asked not to");
        // The length prefix is two bytes, so the frames are DNS from their third byte: not readable as DNS whole.
        let chosen = call(&mut workspace, "packets.decode_as", json!({"set": "set-1", "protocol": "dns"})).unwrap();
        assert_eq!(chosen["decode_as"], "dns");
        let fixed = call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 2})).unwrap();
        assert_eq!(fixed["set"], "set-2");
        let missing = call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed"})).unwrap_err();
        assert_eq!(missing.code, ErrorCode::InvalidParams, "split_fixed needs its record length");
    }

    #[test]
    fn a_set_follows_edits_to_its_document() {
        let mut workspace = workspace_with("records.bin", &[1, 2, 3, 4, 5, 6, 7, 8]);
        call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 2})).unwrap();
        call(&mut workspace, "bytes.insert", json!({"at": 8, "data": "0909"})).unwrap();
        let listed = call(&mut workspace, "packets.list", json!({"set": "set-1"})).unwrap();
        assert_eq!(listed["total"], 5, "the range grew with the insert and was cut again");
    }

    #[test]
    fn a_capture_s_set_exports_as_pcap_and_summarises_its_conversations_and_streams() {
        let mut workspace = workspace_with("traffic.bin", &dns_capture(2));
        call(&mut workspace, "packets.sets.create", json!({"from": "capture", "start": 0})).unwrap();
        let exported = call(&mut workspace, "packets.export_pcap", json!({"set": "set-1", "filter": "udp.srcport==4000", "encoding": "hex"})).unwrap();
        assert_eq!(exported["count"], 1);
        assert!(exported["data"].as_str().unwrap().starts_with("d4c3b2a1"), "a pcap file");
        let conversations = call(&mut workspace, "packets.conversations", json!({"set": "set-1"})).unwrap();
        assert_eq!(conversations["conversations"].as_array().unwrap().len(), 2, "one per source port");
        let stream = call(&mut workspace, "packets.follow_stream", json!({"set": "set-1", "index": 0})).unwrap();
        assert_eq!(stream["parts"].as_array().unwrap().len(), 1);
        let ports = [&stream["conversation"]["a"]["port"], &stream["conversation"]["b"]["port"]];
        assert!(ports.contains(&&json!(53)) && ports.contains(&&json!(4000)), "{ports:?}");
        call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 4})).unwrap();
        let nothing = call(&mut workspace, "packets.follow_stream", json!({"set": "set-2", "index": 0})).unwrap();
        assert!(nothing["conversation"].is_null(), "a record without addresses has no stream");
        let path = std::env::temp_dir().join(format!("theviewer-export-{}.pcap", std::process::id()));
        let written = call(&mut workspace, "packets.export_pcap", json!({"set": "set-1", "path": path.display().to_string()})).unwrap();
        assert_eq!(written["count"], 2);
        assert_eq!(std::fs::read(&path).unwrap().len() as u64, written["len"].as_u64().unwrap());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn the_selection_s_ranges_become_packets_and_are_returned_so_the_call_can_be_repeated() {
        let mut workspace = workspace_with("a.bin", &[0u8; 64]);
        call(&mut workspace, "selection.set", json!({"selection": {"ranges": [[0, 8], [16, 4]]}})).unwrap();
        let created = call(&mut workspace, "packets.sets.create", json!({"from": "selection"})).unwrap();
        assert_eq!(created["ranges"], json!([[0, 8], [16, 4]]));
        let given = call(&mut workspace, "packets.sets.create", json!({"from": "selection", "ranges": [[4, 4]]})).unwrap();
        assert_eq!(given["count"], 1);
    }

    #[test]
    fn captures_are_found_where_they_are_and_a_gzipped_one_opens_decompressed_as_its_own_document() {
        let capture = dns_capture(2);
        let mut bytes = vec![0x11; 40];
        bytes.extend(&capture);
        let gzip_at = bytes.len();
        bytes.extend(crate::compress::compress(crate::compress::Codec::Gzip, &capture).unwrap());
        let mut workspace = workspace_with("traffic.bin", &bytes);
        let found = call(&mut workspace, "packets.find_captures", json!({})).unwrap();
        let captures = found["captures"].as_array().unwrap();
        assert_eq!(captures.len(), 2, "{found}");
        assert_eq!((captures[0]["offset"].as_u64(), captures[0]["gzipped"].as_bool()), (Some(40), Some(false)));
        assert_eq!((captures[1]["offset"].as_u64(), captures[1]["gzipped"].as_bool()), (Some(gzip_at as u64), Some(true)));
        assert!(captures[0]["description"].as_str().unwrap().starts_with("pcap at 0x28"));
        let none = call(&mut workspace, "packets.find_captures", json!({"start": 0, "len": 40})).unwrap();
        assert!(none["captures"].as_array().unwrap().is_empty(), "only the span given is looked in");

        let created = call(&mut workspace, "packets.sets.create", json!({"from": "capture", "start": gzip_at, "gunzip": true})).unwrap();
        assert_eq!(created["count"], 2);
        assert_ne!(created["doc"], "doc-1", "the decompressed capture is a document of its own");
        let documents = call(&mut workspace, "documents.list", json!({})).unwrap();
        assert_eq!(documents["documents"].as_array().unwrap().len(), 2);
        let refused = |workspace: &mut crate::api::HeadlessWorkspace, params| call(workspace, "packets.sets.create", params).unwrap_err().code;
        assert_eq!(refused(&mut workspace, json!({"doc": "doc-1", "from": "capture", "start": 40, "gunzip": true})), ErrorCode::NotFound, "no gzip stream there");
        assert_eq!(refused(&mut workspace, json!({"doc": "doc-1", "from": "capture", "gunzip": true})), ErrorCode::InvalidParams, "the stream's start is needed");
        assert_eq!(refused(&mut workspace, json!({"doc": "doc-1", "from": "split_fixed", "record_len": 4, "gunzip": true})), ErrorCode::InvalidParams);
    }

    #[test]
    fn packets_added_by_hand_join_the_set_and_stay_where_they_are() {
        let mut workspace = workspace_with("a.bin", &[0u8; 64]);
        call(&mut workspace, "packets.sets.create", json!({"from": "selection", "ranges": [[0, 8]], "link": "raw_ip"})).unwrap();
        let added = call(&mut workspace, "packets.sets.add_packets", json!({"set": "set-1", "ranges": [[16, 4], [32, 8]]})).unwrap();
        assert_eq!((added["count"].as_u64(), added["name"].as_str()), (Some(3), Some("packets added by hand")));
        let listed = call(&mut workspace, "packets.list", json!({"set": "set-1"})).unwrap();
        assert_eq!(listed["packets"][2]["link"], "raw_ip", "added packets are read as the set's link says");
        let refused = |workspace: &mut crate::api::HeadlessWorkspace, params| call(workspace, "packets.sets.add_packets", params).unwrap_err().code;
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "ranges": []})), ErrorCode::InvalidParams);
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "ranges": [[60, 8]]})), ErrorCode::OutOfRange);
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "ranges": [[4, 0]]})), ErrorCode::InvalidParams);
        assert_eq!(refused(&mut workspace, json!({"set": "set-2", "ranges": [[4, 1]]})), ErrorCode::NotFound);
    }

    #[test]
    fn a_set_is_found_again_in_another_document_the_same_way() {
        let mut workspace = workspace_with("first.bin", &[1u8; 32]);
        call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8})).unwrap();
        let other = workspace.add_document("second.bin", crate::document::Document::from_bytes(vec![2u8; 48]));
        let refreshed = call(&mut workspace, "packets.sets.refresh", json!({"set": "set-1", "doc": other})).unwrap();
        assert_eq!((refreshed["doc"].as_str(), refreshed["count"].as_u64()), (Some(other.as_str()), Some(4)), "the same 32 bytes cut the same way: {refreshed}");
        assert_eq!(call(&mut workspace, "packets.sets.refresh", json!({"set": "set-1", "doc": "doc-9"})).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "packets.sets.refresh", json!({"set": "set-7"})).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn a_length_field_is_found_for_the_split_form_or_the_best_framing_said_instead() {
        let mut workspace = workspace_with("stream.bin", &length_prefixed_dns(12));
        let found = call(&mut workspace, "packets.detect_length_field", json!({"start": 0})).unwrap();
        assert!(found["length_field"].is_object(), "{found}");
        let created = call(&mut workspace, "packets.sets.create", json!({"from": "length_field", "length_field": found["length_field"]})).unwrap();
        assert_eq!(created["count"], found["frames"], "what was found splits the stream as it said");
        let mut text = workspace_with("text.bin", b"hello hello hello hello");
        let none = call(&mut text, "packets.detect_length_field", json!({})).unwrap();
        assert!(none["length_field"].is_null());
        assert_eq!(call(&mut text, "packets.detect_length_field", json!({"start": 5, "len": 0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut text, "packets.detect_length_field", json!({"start": 500})).unwrap_err().code, ErrorCode::OutOfRange);
    }

    #[test]
    fn a_set_s_link_is_put_over_its_packets_and_taken_off_again() {
        let mut workspace = workspace_with("traffic.bin", &dns_capture(1));
        call(&mut workspace, "packets.sets.create", json!({"from": "capture"})).unwrap();
        let link = |workspace: &mut crate::api::HeadlessWorkspace| call(workspace, "packets.list", json!({"set": "set-1"})).unwrap()["packets"][0]["link"].clone();
        assert_eq!(link(&mut workspace), "ethernet");
        let raw = call(&mut workspace, "packets.decode_as", json!({"set": "set-1", "link": "raw_ip"})).unwrap();
        assert_eq!(raw["link"], "raw_ip");
        assert_eq!(link(&mut workspace), "raw_ip");
        call(&mut workspace, "packets.decode_as", json!({"set": "set-1"})).unwrap();
        assert_eq!(link(&mut workspace), "raw_ip", "left out, the link stays");
        call(&mut workspace, "packets.decode_as", json!({"set": "set-1", "link": null})).unwrap();
        assert_eq!(link(&mut workspace), "ethernet", "null gives each packet its capture's own back");
    }

    #[test]
    fn a_template_is_chosen_by_name_or_as_the_protocol_analysis_suggested() {
        let mut workspace = workspace_with("records.bin", &[0u8; 32]);
        call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8})).unwrap();
        let (name, _) = super::available_templates().into_iter().next().expect("built-in templates");
        let named = call(&mut workspace, "packets.decode_as", json!({"set": "set-1", "detect": false, "template_name": name})).unwrap();
        assert_eq!((named["template"].as_bool(), named["template_name"].as_str()), (Some(true), Some(name.as_str())));
        let refused = |workspace: &mut crate::api::HeadlessWorkspace, params| call(workspace, "packets.decode_as", params).unwrap_err().code;
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "template_name": "no such template"})), ErrorCode::NotFound);
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "template_name": name, "template": "x"})), ErrorCode::InvalidParams);
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "template": "protocol"})), ErrorCode::NotFound, "no analysis has suggested one");
        assert_eq!(refused(&mut workspace, json!({"set": "set-1", "template": "struct {"})), ErrorCode::InvalidParams);
    }

    #[test]
    fn only_the_packets_asked_for_are_exported_in_the_order_asked() {
        let mut workspace = workspace_with("traffic.bin", &dns_capture(3));
        call(&mut workspace, "packets.sets.create", json!({"from": "capture"})).unwrap();
        let exported = call(&mut workspace, "packets.export_pcap", json!({"set": "set-1", "indices": [2, 0]})).unwrap();
        assert_eq!(exported["count"], 2);
        let filtered = call(&mut workspace, "packets.export_pcap", json!({"set": "set-1", "indices": [2, 0], "filter": "udp.srcport==4000"})).unwrap();
        assert_eq!(filtered["count"], 1, "those of them the filter keeps");
        assert_eq!(call(&mut workspace, "packets.export_pcap", json!({"set": "set-1", "indices": [3]})).unwrap_err().code, ErrorCode::OutOfRange);
    }

    #[test]
    fn the_endpoints_of_a_set_are_counted_with_a_filter_for_each() {
        let mut workspace = workspace_with("traffic.bin", &dns_capture(2));
        call(&mut workspace, "packets.sets.create", json!({"from": "capture"})).unwrap();
        let endpoints = call(&mut workspace, "packets.endpoints", json!({"set": "set-1"})).unwrap();
        let sender = endpoints["endpoints"].as_array().unwrap().iter().find(|endpoint| endpoint["address"] == "10.0.0.2").expect("the sender");
        assert_eq!((sender["packets_sent"].as_u64(), sender["filter"].as_str()), (Some(2), Some("ip:10.0.0.2")));
        assert_eq!(call(&mut workspace, "packets.endpoints", json!({"set": "set-1", "filter": "len>"})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn the_protocol_framing_found_is_returned_with_the_set() {
        let mut stream = Vec::new();
        for index in 0..40u8 {
            stream.extend([0x7E, 0x7E, index, index % 3, 0x10, 0x20, 0x30, index ^ 0x5A]);
        }
        let mut workspace = workspace_with("stream.bin", &stream);
        let created = call(&mut workspace, "packets.sets.create", json!({"from": "protocol_framing"})).unwrap();
        assert!(created["framing"]["kind"].is_string(), "{created}");
        let again = call(&mut workspace, "packets.sets.create", json!({"from": "protocol_framing", "framing": created["framing"]})).unwrap();
        assert_eq!(again["count"], created["count"], "the framing returned makes the same set");
    }

    #[test]
    fn a_mistyped_field_is_refused_with_the_names_it_was_close_to_rather_than_matching_nothing() {
        let mut workspace = workspace_with("traffic.bin", &dns_capture(2));
        call(&mut workspace, "packets.sets.create", json!({"from": "capture"})).unwrap();
        let refused = call(&mut workspace, "packets.list", json!({"set": "set-1", "filter": "dns.qry.nmae~example"})).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidParams);
        assert!(refused.message.contains("dns.qry.name"), "{}", refused.message);
        let total = |workspace: &mut crate::api::HeadlessWorkspace, filter: &str| call(workspace, "packets.list", json!({"set": "set-1", "filter": filter})).unwrap()["total"].clone();
        assert_eq!(total(&mut workspace, "udp.port==53 && dns.flags.response==0 && dns.qry.type==1"), 2);
        assert_eq!(total(&mut workspace, "not udp.srcport==4000"), 1);
        assert_eq!(total(&mut workspace, "udp.srcport==4000 or udp.srcport==4001"), 2);
    }

    #[test]
    fn frames_are_filtered_on_their_template_fields_by_template_name_or_bare_name() {
        let frames: Vec<u8> = [0x01u8, 0x3C, 0x01, 0x81].iter().enumerate().flat_map(|(seq, &kind)| [0xA5, 0x5A, kind, seq as u8, 0, 0, 0, 7]).collect();
        let mut workspace = workspace_with("bus.bin", &frames);
        call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8, "detect": false})).unwrap();
        let total = |workspace: &mut crate::api::HeadlessWorkspace, filter: &str| call(workspace, "packets.list", json!({"set": "set-1", "filter": filter})).unwrap()["total"].clone();
        let refused = call(&mut workspace, "packets.list", json!({"set": "set-1", "filter": "type==60"})).unwrap_err();
        assert!(refused.message.contains("template"), "without a template the error says how to get one: {}", refused.message);
        call(&mut workspace, "packets.decode_as", json!({"set": "set-1", "detect": false, "template": "struct Frame { sync: u16be  type: u8 display hex  seq: u8  a: u8  b: u8  c: u8  last: u8 }"})).unwrap();
        assert_eq!(total(&mut workspace, "template.type==60"), 1);
        assert_eq!(total(&mut workspace, "type==0x3c"), 1, "a bare name is the template's own");
        assert_eq!(total(&mut workspace, "type==1 && template.seq>0"), 1);
        let unknown = call(&mut workspace, "packets.list", json!({"set": "set-1", "filter": "template.tpye==1"})).unwrap_err();
        assert!(unknown.message.contains("type"), "{}", unknown.message);
        let listed = call(&mut workspace, "packets.list", json!({"set": "set-1"})).unwrap();
        assert!(listed["packets"][1]["summary"]["info"].as_str().unwrap().contains("last=7"), "more than four fields reach the summary: {listed}");
    }

    #[test]
    fn a_conversation_s_first_packet_is_its_index_in_the_set_when_followed_or_filtered() {
        let mut workspace = workspace_with("traffic.bin", &dns_capture(3));
        call(&mut workspace, "packets.sets.create", json!({"from": "capture"})).unwrap();
        let followed = call(&mut workspace, "packets.follow_stream", json!({"set": "set-1", "index": 2})).unwrap();
        assert_eq!(followed["conversation"]["first_packet"], 2);
        let filtered = call(&mut workspace, "packets.conversations", json!({"set": "set-1", "filter": "udp.srcport==4001"})).unwrap();
        assert_eq!(filtered["conversations"][0]["first_packet"], 1);
    }

    #[test]
    fn conversations_and_endpoints_are_sorted_by_traffic_or_address_when_asked() {
        let mut bytes = dns_capture(3);
        // A fourth query from port 4002, so that conversation has two packets.
        let extra = dns_capture(3);
        let record = &extra[24..];
        let third = record.len() / 3 * 2;
        bytes.extend(&record[third..]);
        let mut workspace = workspace_with("traffic.bin", &bytes);
        call(&mut workspace, "packets.sets.create", json!({"from": "capture"})).unwrap();
        let by_packets = call(&mut workspace, "packets.conversations", json!({"set": "set-1", "sort": "packets"})).unwrap();
        let first = &by_packets["conversations"][0];
        assert_eq!((first["packets"].as_u64(), first["first_packet"].as_u64()), (Some(2), Some(2)), "{by_packets}");
        let in_order = call(&mut workspace, "packets.conversations", json!({"set": "set-1"})).unwrap();
        assert_eq!(in_order["conversations"][0]["first_packet"], 0);
        let endpoints = call(&mut workspace, "packets.endpoints", json!({"set": "set-1", "sort": "address"})).unwrap();
        assert_eq!(endpoints["endpoints"][0]["address"], "10.0.0.1");
    }

    #[test]
    fn a_length_field_split_resynchronises_after_stray_bytes_and_says_where_it_lost_its_place() {
        let mut stream = vec![0x00, 0x13];
        for index in 0..40u8 {
            stream.extend([0xA5, 0x5A, 4, index, 1, 2, 3, 0xC0, 0xC1]);
            if index % 9 == 4 {
                stream.push(0);
            }
        }
        let mut workspace = workspace_with("bus.bin", &stream);
        let field = json!({"offset": 2, "encoding": "u8", "adjustment": 2});
        let lost = call(&mut workspace, "packets.sets.create", json!({"from": "length_field", "start": 2, "length_field": field})).unwrap();
        assert!(lost["count"].as_u64().unwrap() < 40 && lost["description"].as_str().unwrap().contains("resync"), "{lost}");
        let resynced = call(&mut workspace, "packets.sets.create", json!({"from": "length_field", "start": 2, "length_field": {"offset": 2, "encoding": "u8", "adjustment": 2, "resync": true}})).unwrap();
        assert_eq!(resynced["count"], 40, "{resynced}");
        assert!(resynced["description"].as_str().unwrap().contains("lost its place 4 times"), "{resynced}");
        let from_the_start = call(&mut workspace, "packets.sets.create", json!({"from": "length_field", "length_field": {"offset": 2, "encoding": "u8", "adjustment": 2, "sync": "A55A"}})).unwrap();
        assert_eq!(from_the_start["count"], 40, "a given sync word skips the lead-in too: {from_the_start}");
        let refused = call(&mut workspace, "packets.sets.create", json!({"from": "length_field", "length_field": {"offset": 2, "sync": "A5Z"}})).unwrap_err();
        assert_eq!(refused.code, ErrorCode::InvalidParams);
    }
}
