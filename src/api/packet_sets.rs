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

use std::collections::BTreeMap;
use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::packets::DissectionResult;
use super::values::{self, ByteEncoding, NoParams};
use super::workspace::{self, Workspace};
use super::{ApiError, Caller, Effect, ErrorCode};
use crate::bus::topics::FramesDefined;
use crate::bus::{Draft, Payload};
use crate::document::Document;
use crate::packets::sources;
use crate::packets::split::{self, BytePattern, LengthCounts, LengthEncoding, LengthField, PatternMode};
use crate::packets::{self, Dissection, ExportPacket, Flow, FrameProtocol, LinkKind, PacketSet, RawFrames, SetHints, Summary};
use crate::protocol::{self, Framing};
use crate::templates::Template;

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
}

fn big_endian_by_default() -> bool {
    true
}

impl LengthFieldSpec {
    fn field(&self) -> LengthField {
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
    /// Where the packets were taken from, as [start, len], once worked out
    /// (a capture found, the selection's ranges).
    pub ranges: Vec<(u64, u64)>,
    /// The framing that cut the messages, for `protocol_framing`.
    pub framing: Option<Framing>,
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
    /// Template source for frames no protocol reads; omitted, the set's
    /// template is dropped.
    #[serde(default)]
    pub template: Option<String>,
}

/// Parameters of `packets.export_pcap`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportParams {
    pub set: String,
    /// Only the packets this display filter keeps.
    #[serde(default)]
    pub filter: Option<String>,
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

/// Parameters of `packets.conversations`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConversationsParams {
    pub set: String,
    /// Only the packets this display filter keeps.
    #[serde(default)]
    pub filter: Option<String>,
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
    /// The whole stream as text, each direction's turns marked.
    pub text: String,
    /// TCP segments sent again and left out.
    pub retransmissions: u64,
    /// Whether the stream was longer than is kept.
    pub truncated: bool,
}

/// Every packet dissected, for one document version and decoding.
struct Decoded {
    version: u64,
    generation: u64,
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
/// from and with what framing.
fn find_packets(document: &mut Document, view_ranges: Vec<(usize, usize)>, params: &CreateParams) -> Result<Found, ApiError> {
    let link = params.link.unwrap_or(LinkKind::Unknown);
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
            let field = params.length_field.as_ref().ok_or_else(|| needs("length_field, where each frame's length is"))?.field();
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
            let mut set = sources::from_framing(&bytes, start, &framing).map_err(source_error)?;
            if link != LinkKind::Unknown {
                set.packets.iter_mut().for_each(|packet| packet.link = link);
            }
            Ok(Found { packets: set, ranges: vec![(start as u64, bytes.len() as u64)], framing: Some(framing) })
        }
    }
}

pub fn create(workspace: &mut dyn Workspace, caller: &Caller, params: CreateParams) -> Result<SetInfo, ApiError> {
    let doc = workspace::resolve(workspace, params.doc.as_deref())?;
    if let Some(source) = &params.template {
        Template::parse(source).map_err(|error| ApiError::invalid_params(format!("the template does not parse: {error}")))?;
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
        ranges,
        framing,
    };
    sets.sets.push(StoredSet { info: info.clone(), params, packets: found, built, generation: 0, decoded: None });
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
    let current = stored.decoded.as_ref().is_some_and(|decoded| decoded.version == document.version() && decoded.generation == stored.generation);
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
        let dissections = bytes.iter().zip(&links).map(|(bytes, &link)| packets::dissect_with(bytes, link, &raw)).collect();
        stored.decoded = Some(Decoded { version: document.version(), generation: stored.generation, bytes, dissections, raw, detected });
    }
    stored.decoded.as_ref().expect("decoded above")
}

/// Indices of the packets `filter` keeps.
fn filtered(stored: &StoredSet, decoded: &Decoded, filter: Option<&str>) -> Result<Vec<usize>, ApiError> {
    let all = 0..decoded.dissections.len();
    let Some(text) = filter.filter(|text| !text.trim().is_empty()) else { return Ok(all.collect()) };
    let filter = packets::parse_filter(text).map_err(|error| ApiError::invalid_params(format!("the filter does not read: {error}")))?;
    let tshark: Vec<String> = Vec::new();
    Ok(all
        .filter(|&index| {
            let dissection = &decoded.dissections[index];
            let values = |name: &str| packets::filter::wireshark_values(dissection, name);
            let subject = packets::FilterSubject {
                protocols: &dissection.protocols,
                tshark_protocols: &tshark,
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
        let dissection = packets::dissect_with(&decoded.bytes[index], packet.link, &decoded.raw);
        Ok(PacketDissection { index: index as u64, offset: packet.offset as u64, len: packet.len as u64, dissection: dissection_result(dissection) })
    })
}

pub fn decode_as(workspace: &mut dyn Workspace, caller: &Caller, params: DecodeAsParams) -> Result<SetInfo, ApiError> {
    if let Some(source) = &params.template {
        Template::parse(source).map_err(|error| ApiError::invalid_params(format!("the template does not parse: {error}")))?;
    }
    let info = with_set(workspace, &params.set, |stored, _| {
        stored.info.decode_as = params.protocol;
        stored.info.detect = params.detect.unwrap_or(true);
        stored.info.template = params.template.is_some();
        stored.params.decode_as = params.protocol;
        stored.params.detect = params.detect;
        stored.params.template = params.template.clone();
        stored.generation += 1;
        Ok(stored.info.clone())
    })?;
    publish_set(workspace, caller, &params.set);
    workspace.show_packet_set(&params.set);
    Ok(info)
}

pub fn export_pcap(workspace: &mut dyn Workspace, caller: &Caller, params: ExportParams) -> Result<ExportResult, ApiError> {
    if params.path.is_some() && workspace.permission(caller, Effect::Edit) != super::Decision::Allowed {
        return Err(ApiError::new(ErrorCode::ReadOnly, "writing a file needs leave to edit; leave out path to have the pcap file returned instead"));
    }
    let file = with_set(workspace, &params.set, |stored, document| {
        decode(stored, document);
        let decoded = stored.decoded.as_ref().expect("decoded");
        let kept = filtered(stored, decoded, params.filter.as_deref())?;
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
        let found = packets::conversations(kept.iter().map(|&index| (decoded.dissections[index].flow.as_ref(), stored.packets.packets[index].len)));
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
        let in_conversation = decoded.dissections.iter().enumerate().filter(|(_, dissection)| dissection.flow.is_some_and(|other| other.key() == key)).map(|(index, dissection)| (dissection.flow.as_ref(), lengths[&index]));
        let conversation = packets::conversations(in_conversation).into_iter().next().map(|found| conversation_entry(&found));
        let parts = stream
            .segments
            .iter()
            .map(|segment| StreamPart { packet: segment.packet as u64, a_to_b: segment.a_to_b, data: crate::ops::to_compact_hex(&stream.bytes[segment.start..segment.start + segment.len]) })
            .collect();
        Ok(StreamResult { conversation, parts, text: stream.marked_text(), retransmissions: stream.retransmissions as u64, truncated: stream.truncated })
    })
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
}
