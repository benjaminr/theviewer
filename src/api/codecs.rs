//! `codecs.*`: the decoders available, which ones a span starts with, and
//! decoding with them.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::output::{self, Delivered, NewSheet, Output, Produced};
use super::permissions::Caller;
use super::values::{self, ByteEncoding, NoParams};
use super::workspace::{self, Workspace};
use super::{ApiError, MAX_CALL_BYTES, OutputKind};
use crate::compress::{self, Codec, Decompressed};
use crate::plugin::{CodecKind, CodecPlugin, Registry};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("codecs.list", Read, list, super::values::NoParams, CodecList, "The codecs available for decoding, built in and from plugins: the decompressors, and the text encodings base32, base64, base64url, hex (hex text), sixbit (DEC SIXBIT) and ais6 (AIS 6-bit ASCII)."),
    method!("codecs.detect", Read, detect, DetectParams, CodecList, "The codecs whose header starts at an offset."),
    method!("codecs.decode", Read, caller decode, DecodeParams, DecodeResult, "Decode (decompress) a span with any codec codecs.list lists, plugins' included, or the first codec that decodes there (a built-in decompressor, then a text encoding a run of whose characters starts there, then a plugin's codec that detects it): return the output by default, or, as output says, open it as a new sheet or put it in place of the bytes it decoded.").outputs(&[OutputKind::Return, OutputKind::New, OutputKind::InPlace], OutputKind::Return),
    method!("codecs.probe", Read, probe, ProbeParams, ProbeResult, "Try every codec at the start of a span and list those that decode: the built-in decompressors (headerless ones included), the text encodings a run of whose characters starts there, then the plugins' codecs."),
    method!("codecs.open_decoded", View, caller open_decoded, OpenDecodedParams, OpenDecodedResult, "Decompress the stream starting at an offset, with the first codec that decodes there or the one named (any codecs.list lists), and open what it holds as a document derived from this one; in the window, Back (or opening the parent by id) returns. A shorthand for codecs.decode with output \"new\".").makes_sheet(),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("codecs.list", json!({})),
        ("codecs.detect", json!({"at": 0})),
        ("codecs.decode", json!({"start": 0, "codec": "zlib", "encoding": "text"})),
        ("codecs.decode", json!({"start": 0, "codec": "zlib", "output": {"new": {"label": "hello"}}})),
        ("documents.open", json!({"doc": "doc-1"})),
        ("codecs.probe", json!({"start": 0})),
        ("codecs.open_decoded", json!({"start": 0, "codec": "zlib"})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(workspace: &mut dyn Workspace, method: &str, params: &serde_json::Value) -> Option<String> {
    match method {
        "codecs.open_decoded" => Some(format!("Open what decompresses at {:#x} as a document of its own", params.get("start")?.as_u64()?)),
        "codecs.decode" => {
            let start = params.get("start")?.as_u64()?;
            let kind = params.get("output").and_then(output::kind_of).filter(|kind| matches!(kind, OutputKind::InPlace | OutputKind::New))?;
            let named = params.get("codec").and_then(serde_json::Value::as_str).map(str::to_string);
            let codec = named.or_else(|| first_decoding(workspace, params)).unwrap_or_else(|| "the first codec that decodes there".to_string());
            Some(match kind {
                OutputKind::InPlace => format!("Replace what decodes as {codec} at {start:#x} with what it decodes to"),
                _ => format!("Open what decodes as {codec} at {start:#x} as a document of its own"),
            })
        }
        _ => None,
    }
}

/// Input read to name the codec a `codecs.decode` without one would use.
const DESCRIBE_INPUT: usize = 1024 * 1024;
/// Output each decoder may make while naming it.
const DESCRIBE_OUTPUT: usize = 64 * 1024;

/// The codec `codecs.decode` with `params` and no codec would decode with,
/// tried on the first MiB of its span, for its description.
fn first_decoding(workspace: &mut dyn Workspace, params: &serde_json::Value) -> Option<String> {
    let registry = workspace.registry();
    let (_, document) = workspace::document(workspace, params.get("doc").and_then(serde_json::Value::as_str)).ok()?;
    let start = params.get("start")?.as_u64()?;
    let len = params.get("len").and_then(serde_json::Value::as_u64);
    let (start, len) = values::span_within(document.len(), start, len).ok()?;
    let input = document.read_range(start, len.min(DESCRIBE_INPUT));
    decode_with(&registry, &input, start, None, DESCRIBE_OUTPUT).ok().map(|decoding| decoding.codec)
}

/// Bytes read at an offset to check codec headers against.
const DETECT_WINDOW: usize = 4096;

/// One codec.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CodecInfo {
    /// The id to pass to codecs.decode, such as "zlib".
    pub id: String,
    pub name: String,
    pub kind: CodecKind,
}

/// The result of `codecs.list` and `codecs.detect`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CodecList {
    pub codecs: Vec<CodecInfo>,
}

/// Parameters of `codecs.detect`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset where the encoded data would start.
    pub at: u64,
}

/// Parameters of `codecs.decode`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecodeParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the encoded data.
    pub start: u64,
    /// Bytes of input, at most 16 MiB returned (64 MiB to a new sheet or in place); to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Codec id from codecs.list, such as "zlib", "gzip" or a plugin's
    /// "base32"; the first built-in decompressor that decodes there when omitted.
    #[serde(default)]
    pub codec: Option<String>,
    /// Most bytes of output, at most 16 MiB returned (the default), 64 MiB to a new sheet or in place.
    #[serde(default)]
    pub max_output: Option<usize>,
    /// How to write the output returned: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
    /// Where the output goes: "return" (the default), "new" (a sheet derived
    /// from this document; {"new": {"label": …, "name": …}} names it) or
    /// "in_place" (in place of the bytes it decoded, as one undoable edit).
    #[serde(default)]
    pub output: Option<Output>,
}

/// The result of `codecs.decode`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DecodeResult {
    pub codec: String,
    /// Input bytes the encoded data occupied.
    pub consumed: u64,
    /// Whether `consumed` is exact rather than a buffered estimate.
    pub consumed_exact: bool,
    /// Whether the data ended cleanly.
    pub complete: bool,
    /// Whether the output was cut at `max_output`.
    pub truncated: bool,
    pub output_len: u64,
    pub encoding: ByteEncoding,
    /// The output, written as `encoding` says, when it was returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Where the output went: {doc, label, len} for a new sheet, {version, len, ranges} in place, {len, encoding} returned (the bytes are `data`).
    pub output: Delivered,
}

/// Parameters of `codecs.probe`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset where compressed data might start.
    pub start: u64,
    /// Bytes of input, at most 16 MiB; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Most bytes of output each decoder may produce, at most 16 MiB (the default).
    #[serde(default)]
    pub max_output: Option<usize>,
}

/// One decoder that read the data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProbedStream {
    /// Its id, to pass to codecs.decode: "zlib", "base32" or a plugin's.
    pub codec: String,
    pub name: String,
    pub kind: CodecKind,
    pub consumed: u64,
    pub consumed_exact: bool,
    pub complete: bool,
    pub truncated: bool,
    pub output_len: u64,
}

/// The result of `codecs.probe`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProbeResult {
    /// Decoders that read the data: decompressors with a header first, then headerless ones, text encodings, and plugins' codecs.
    pub streams: Vec<ProbedStream>,
}

fn describe(codec: &dyn CodecPlugin) -> CodecInfo {
    CodecInfo { id: codec.id().to_string(), name: codec.name().to_string(), kind: codec.kind() }
}

fn output_limit(max_output: Option<usize>) -> Result<usize, ApiError> {
    let limit = max_output.unwrap_or(MAX_CALL_BYTES);
    values::check_size(limit, MAX_CALL_BYTES, "max_output")?;
    Ok(limit)
}

pub fn list(workspace: &mut dyn Workspace, _params: NoParams) -> Result<CodecList, ApiError> {
    Ok(CodecList { codecs: workspace.registry().codecs().iter().map(|codec| describe(codec.as_ref())).collect() })
}

pub fn detect(workspace: &mut dyn Workspace, params: DetectParams) -> Result<CodecList, ApiError> {
    let registry = workspace.registry();
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (at, available) = values::span_within(document.len(), params.at, None)?;
    let bytes = document.read_range(at, available.min(DETECT_WINDOW));
    Ok(CodecList { codecs: registry.codecs_detecting(&bytes).into_iter().map(|codec| describe(codec.as_ref())).collect() })
}

/// What a codec made of the bytes at an offset.
struct Decoding {
    /// The codec's id, such as "zlib" or "base32".
    codec: String,
    /// Its name for people, such as "zlib" or "LZ4".
    label: String,
    data: Vec<u8>,
    consumed: usize,
    consumed_exact: bool,
    complete: bool,
    truncated: bool,
}

impl Decoding {
    fn of_built_in(found: Decompressed) -> Self {
        Decoding {
            codec: found.codec.id().to_string(),
            label: found.codec.label().to_string(),
            data: found.data,
            consumed: found.consumed,
            consumed_exact: found.consumed_exact,
            complete: found.complete,
            truncated: found.truncated,
        }
    }
}

/// The built-in codec with id `id`, if it is one.
fn built_in(id: &str) -> Option<Codec> {
    Codec::ALL.into_iter().find(|codec| codec.id() == id)
}

/// The registry's codecs that are not built in: the plugins'.
fn plugin_codecs(registry: &Registry) -> impl Iterator<Item = &std::sync::Arc<dyn CodecPlugin>> {
    registry.codecs().iter().filter(|codec| built_in(codec.id()).is_none())
}

/// What `codec` made of `input`, by its id.
fn decoding_by(codec: &dyn CodecPlugin, decoded: crate::plugin::Decoded) -> Decoding {
    let label = built_in(codec.id()).map_or_else(|| codec.id().to_string(), |codec| codec.label().to_string());
    Decoding { codec: codec.id().to_string(), label, data: decoded.data, consumed: decoded.consumed, consumed_exact: decoded.consumed_exact, complete: decoded.complete, truncated: decoded.truncated }
}

/// Decode `input` (the bytes at `start`) with the codec whose id is
/// `codec`, any the registry holds, or else the first that decodes it:
/// a built-in decompressor or text encoding ([`compress::probe`]), then a
/// plugin's codec that detects it.
fn decode_with(registry: &Registry, input: &[u8], start: usize, codec: Option<&str>, max_output: usize) -> Result<Decoding, ApiError> {
    let Some(id) = codec else {
        if let Some(found) = compress::probe(input, max_output).into_iter().next() {
            return Ok(Decoding::of_built_in(found));
        }
        let detected = plugin_codecs(registry).filter(|codec| codec.detect(input)).find_map(|codec| codec.decode(input, max_output).ok().map(|decoded| decoding_by(codec.as_ref(), decoded)));
        return detected.ok_or_else(|| {
            ApiError::invalid_params(format!("nothing decodes at {start:#x} (tried gzip, zlib, bzip2, xz, zstd, LZ4, raw deflate, lzma, base32, base64, base64url, hex text and the plugins' codecs); name a codec from codecs.list"))
        });
    };
    let codec = registry.codec(id).ok_or_else(|| ApiError::not_found(format!("there is no codec '{id}'; codecs.list lists them")))?;
    let decoded = codec.decode(input, max_output).map_err(|message| ApiError::invalid_params(format!("the bytes at {start:#x} do not decode as {}: {message}", codec.name())))?;
    Ok(decoding_by(codec.as_ref(), decoded))
}

pub fn decode(workspace: &mut dyn Workspace, caller: &Caller, params: DecodeParams) -> Result<DecodeResult, ApiError> {
    let output = output::chosen("codecs.decode", params.output)?;
    let limit = if output.kind() == OutputKind::Return { MAX_CALL_BYTES } else { OPEN_DECODED_MAX };
    let max_output = params.max_output.unwrap_or(limit);
    values::check_size(max_output, limit, "max_output")?;
    let registry = workspace.registry();
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let name = workspace::info(workspace, &id)?.name;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let (start, len) = values::span_within(document.len(), params.start, params.len)?;
    values::check_size(len, limit, "the span")?;
    let input = document.read_range(start, len);
    let decoding = decode_with(&registry, &input, start, params.codec.as_deref(), max_output)?;
    let output_len = decoding.data.len() as u64;
    let named = format!("{name} › {}@{start:#x}", decoding.label);
    let action = format!("Decode {}", decoding.label);
    let produced = Produced::replacing(start, decoding.consumed, decoding.data, named, action).encoded(params.encoding);
    let mut delivered = output::deliver(workspace, caller, &id, produced, &output)?;
    let data = delivered.data.take();
    Ok(DecodeResult {
        codec: decoding.codec,
        consumed: decoding.consumed as u64,
        consumed_exact: decoding.consumed_exact,
        complete: decoding.complete,
        truncated: decoding.truncated,
        output_len,
        encoding: delivered.encoding.unwrap_or(params.encoding),
        data,
        output: delivered,
    })
}

pub fn probe(workspace: &mut dyn Workspace, params: ProbeParams) -> Result<ProbeResult, ApiError> {
    let max_output = output_limit(params.max_output)?;
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (start, len) = values::span_within(document.len(), params.start, params.len)?;
    values::check_call_size(len)?;
    let input = document.read_range(start, len);
    let registry = workspace.registry();
    let built_ins = compress::probe(&input, max_output).into_iter().map(|found| {
        let stream = probed(found.codec.id(), found.codec.label(), found.codec.kind());
        stream(found.consumed, found.consumed_exact, found.complete, found.truncated, found.data.len())
    });
    let mut seen = std::collections::HashSet::new();
    let plugins = plugin_codecs(&registry).filter(|codec| seen.insert(codec.id().to_string())).filter_map(|codec| {
        let decoded = codec.decode(&input, max_output).ok().filter(|decoded| !decoded.data.is_empty())?;
        let stream = probed(codec.id(), codec.name(), codec.kind());
        Some(stream(decoded.consumed, decoded.consumed_exact, decoded.complete, decoded.truncated, decoded.data.len()))
    });
    Ok(ProbeResult { streams: built_ins.chain(plugins).collect() })
}

/// A [`ProbedStream`] of the codec with this id, name and kind, given what it read.
fn probed<'a>(id: &'a str, name: &'a str, kind: CodecKind) -> impl Fn(usize, bool, bool, bool, usize) -> ProbedStream + 'a {
    move |consumed, consumed_exact, complete, truncated, output_len| ProbedStream {
        codec: id.to_string(),
        name: name.to_string(),
        kind,
        consumed: consumed as u64,
        consumed_exact,
        complete,
        truncated,
        output_len: output_len as u64,
    }
}

/// Most bytes of a stream `codecs.open_decoded` reads, and most it opens.
const OPEN_DECODED_MAX: usize = 64 * 1024 * 1024;

/// Parameters of `codecs.open_decoded`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenDecodedParams {
    /// Document id, path or "current" (left out: the caller's focus): the parent.
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset where the compressed stream starts.
    pub start: u64,
    /// The codec to decode with, any codecs.list lists; the first built-in decompressor that decodes there when omitted.
    #[serde(default)]
    pub codec: Option<String>,
}

/// The result of `codecs.open_decoded`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenDecodedResult {
    /// The document opened, now current.
    pub document: super::workspace::DocumentInfo,
    /// The codec that decoded the stream, such as "zlib".
    pub codec: String,
    /// Input bytes the stream occupied.
    pub consumed: u64,
    /// Whether the stream ended cleanly.
    pub complete: bool,
    /// Whether the output was cut at 64 MiB.
    pub truncated: bool,
    /// The sheet made, in the form every method that makes one gives.
    pub output: workspace::SheetOutput,
}

/// `codecs.open_decoded`: `codecs.decode` with output "new", from the
/// offset to the end of the document. A built-in codec named is found as
/// the decompressors probing there find it.
pub fn open_decoded(workspace: &mut dyn Workspace, caller: &Caller, params: OpenDecodedParams) -> Result<OpenDecodedResult, ApiError> {
    let parent = workspace::resolve(workspace, params.doc.as_deref())?;
    let (_, document) = workspace::document(workspace, Some(&parent))?;
    let (start, available) = values::span_within(document.len(), params.start, None)?;
    if available == 0 {
        return Err(ApiError::invalid_params("nothing to decompress at the end of the document"));
    }
    let input = document.read_range(start, available.min(OPEN_DECODED_MAX));
    let decoding = match params.codec.as_deref().map(|id| (id, built_in(id))) {
        Some((_, Some(codec))) if codec.kind() == CodecKind::Compression => compress::probe(&input, OPEN_DECODED_MAX)
            .into_iter()
            .find(|found| found.codec == codec)
            .map(Decoding::of_built_in)
            .ok_or_else(|| ApiError::invalid_params(format!("nothing decodes as {} at {start:#x}", codec.label())))?,
        Some((id, _)) => decode_with(&workspace.registry(), &input, start, Some(id), OPEN_DECODED_MAX)?,
        None => decode_with(&workspace.registry(), &input, start, None, OPEN_DECODED_MAX)?,
    };
    let name = format!("{} › {}@{start:#x}", workspace::info(workspace, &parent)?.name, decoding.label);
    let (codec, consumed, complete, truncated) = (decoding.codec, decoding.consumed as u64, decoding.complete, decoding.truncated);
    let delivered = output::deliver(workspace, caller, &parent, Produced::bytes(decoding.data, name), &Output::New(NewSheet::default()))?;
    let id = delivered.doc.expect("a new sheet");
    Ok(OpenDecodedResult { document: workspace::info(workspace, &id)?, codec, consumed, complete, truncated, output: workspace::SheetOutput::of(workspace, &id)? })
}

/// What `codecs.open_decoded` did, for the status bar: "zlib at 0x10: 2 KiB
/// compressed to 9 KiB decompressed".
pub fn describe_decoded(start: usize, result: &OpenDecodedResult) -> String {
    let note = if result.truncated {
        " (cut at the 64 MiB limit)"
    } else if !result.complete {
        " (stream was incomplete)"
    } else {
        ""
    };
    let label = built_in(&result.codec).map_or(result.codec.as_str(), |codec| codec.label());
    format!("{label} at {start:#x}: {} compressed to {} decompressed{note}", compress::human_bytes(result.consumed as usize), compress::human_bytes(result.document.len as usize))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::ErrorCode;
    use crate::api::test_support::call;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn a_zlib_stream_is_detected_probed_and_decoded() {
        let mut bytes = b"head".to_vec();
        bytes.extend(zlib(b"hello, hello, hello"));
        let mut workspace = workspace_with("a.bin", &bytes);
        let listed = call(&mut workspace, "codecs.list", json!({})).unwrap();
        assert!(listed["codecs"].as_array().unwrap().iter().any(|codec| codec["id"] == "zlib" && codec["kind"] == "compression"));
        let detected = call(&mut workspace, "codecs.detect", json!({"at": 4})).unwrap();
        assert_eq!(detected["codecs"][0]["id"], "zlib");
        let decoded = call(&mut workspace, "codecs.decode", json!({"start": 4, "codec": "zlib", "encoding": "text"})).unwrap();
        assert_eq!((decoded["data"].as_str(), decoded["complete"].as_bool()), (Some("hello, hello, hello"), Some(true)));
        let probed = call(&mut workspace, "codecs.probe", json!({"start": 4})).unwrap();
        assert_eq!(probed["streams"][0]["codec"], "zlib");
        assert_eq!(probed["streams"][0]["output_len"], 19);
    }

    /// A codec a plugin might add: text hex digits to the bytes they spell.
    struct HexText;

    impl crate::plugin::CodecPlugin for HexText {
        fn id(&self) -> &str {
            "hex_text"
        }
        fn name(&self) -> &str {
            "Hex text"
        }
        fn kind(&self) -> crate::plugin::CodecKind {
            crate::plugin::CodecKind::Encoding
        }
        fn detect(&self, _bytes: &[u8]) -> bool {
            false
        }
        fn decode(&self, input: &[u8], _max_out: usize) -> Result<crate::plugin::Decoded, String> {
            let digits: Vec<u8> = input.iter().copied().take_while(u8::is_ascii_hexdigit).collect();
            let even = digits.len() / 2 * 2;
            let data = crate::ops::parse_hex(std::str::from_utf8(&digits[..even]).unwrap()).ok_or("not hex digits")?;
            Ok(crate::plugin::Decoded { data, consumed: even, consumed_exact: true, complete: true, truncated: false })
        }
        fn encode(&self, _data: &[u8]) -> Option<Result<Vec<u8>, String>> {
            None
        }
    }

    /// A workspace whose registry also holds [`HexText`], holding `bytes`.
    fn with_plugin_codec(bytes: &[u8]) -> crate::api::HeadlessWorkspace {
        let mut registry = crate::app::build_registry();
        registry.add_codec(HexText);
        let mut workspace = crate::api::HeadlessWorkspace::new(std::sync::Arc::new(registry));
        workspace.add_document("notes.txt", crate::document::Document::from_bytes(bytes.to_vec()));
        workspace
    }

    #[test]
    fn a_plugin_s_codec_decodes_to_a_labelled_sheet_without_the_bytes_coming_back() {
        let mut workspace = with_plugin_codec(b"key=68656c6c6f;");
        let decoded = call(&mut workspace, "codecs.decode", json!({"start": 4, "codec": "hex_text", "output": {"new": {"label": "plain"}}})).unwrap();
        assert_eq!(decoded["output"], json!({"doc": "doc-2", "label": "plain", "len": 5}));
        assert!(decoded.get("data").is_none(), "nothing to send back in again");
        assert_eq!((decoded["codec"].as_str(), decoded["consumed"].as_u64()), (Some("hex_text"), Some(10)));
        assert_eq!(call(&mut workspace, "bytes.read", json!({"doc": "doc-2", "start": 0, "encoding": "text"})).unwrap()["data"], "hello");
        let step = crate::api::Workspace::journal(&workspace).entries().last().unwrap().clone();
        assert_eq!((step.method.as_str(), step.made.as_slice(), step.effect), ("codecs.decode", ["doc-2".to_string()].as_slice(), crate::api::Effect::View), "a step that made a sheet");
        let opened = call(&mut workspace, "codecs.open_decoded", json!({"doc": "doc-1", "start": 4, "codec": "hex_text"})).unwrap();
        assert_eq!((opened["codec"].as_str(), opened["document"]["name"].as_str()), (Some("hex_text"), Some("notes.txt › hex_text@0x4")), "the shorthand takes it too");
    }

    #[test]
    fn dns_tunnel_labels_decode_as_base32_without_a_plugin() {
        let half = b"PK\x03\x04 the first half of the archive, sent over DNS".repeat(3);
        let labels = crate::compress::compress(crate::compress::Codec::Base32, &half).unwrap().to_ascii_lowercase();
        let unpadded: Vec<u8> = labels.iter().copied().filter(|&byte| byte != b'=').collect();
        let mut workspace = workspace_with("labels.txt", &unpadded);
        let detected = call(&mut workspace, "codecs.detect", json!({"at": 0})).unwrap();
        assert!(detected["codecs"].as_array().unwrap().iter().any(|codec| codec["id"] == "base32" && codec["kind"] == "encoding"), "{detected}");
        let decoded = call(&mut workspace, "codecs.decode", json!({"start": 0, "codec": "base32", "output": {"new": {"label": "half one"}}})).unwrap();
        assert_eq!((decoded["consumed"].as_u64(), decoded["output"]["len"].as_u64()), (Some(unpadded.len() as u64), Some(half.len() as u64)));
        assert_eq!(call(&mut workspace, "bytes.read", json!({"doc": "doc-2", "start": 0, "len": 4})).unwrap()["data"], "504b0304");
        let probed = call(&mut workspace, "codecs.probe", json!({"doc": "doc-1", "start": 0})).unwrap();
        assert_eq!((probed["streams"][0]["codec"].as_str(), probed["streams"][0]["kind"].as_str()), (Some("base32"), Some("encoding")), "{probed}");
        let unnamed = call(&mut workspace, "codecs.decode", json!({"doc": "doc-1", "start": 0})).unwrap();
        assert_eq!(unnamed["codec"], "base32", "the first codec that decodes is an encoding when nothing decompresses");
    }

    #[test]
    fn a_base64_stage_and_a_six_bit_id_decode_by_their_ids() {
        let mut bytes = b"stage=".to_vec();
        bytes.extend(crate::compress::compress(crate::compress::Codec::Base64, &zlib(b"second stage, second stage")).unwrap());
        let mut workspace = workspace_with("loader.bin", &bytes);
        let decoded = call(&mut workspace, "codecs.decode", json!({"start": 6, "codec": "base64", "output": {"new": {"label": "stage.zlib"}}})).unwrap();
        assert_eq!(decoded["codec"], "base64");
        let inflated = call(&mut workspace, "codecs.decode", json!({"doc": "doc-2", "start": 0, "encoding": "text"})).unwrap();
        assert_eq!((inflated["codec"].as_str(), inflated["data"].as_str()), (Some("zlib"), Some("second stage, second stage")));
        let technician = crate::compress::compress(crate::compress::Codec::Sixbit, b"SERVICE-JB22").unwrap();
        let mut workspace = workspace_with("payload.bin", &technician);
        let read = call(&mut workspace, "codecs.decode", json!({"start": 0, "codec": "sixbit", "encoding": "text"})).unwrap();
        assert_eq!(read["data"], "SERVICE-JB22");
        let opened = call(&mut workspace, "codecs.open_decoded", json!({"start": 0, "codec": "sixbit"})).unwrap();
        assert_eq!(opened["document"]["name"], "payload.bin › DEC SIXBIT@0x0");
    }

    #[test]
    fn decoding_without_a_codec_is_described_by_the_codec_that_will_decode() {
        let mut bytes = b"head".to_vec();
        bytes.extend(zlib(b"hello, hello, hello"));
        let mut workspace = workspace_with("a.bin", &bytes);
        let description = crate::api::describe_call(&mut workspace, "codecs.decode", &json!({"start": 4, "output": "new"}));
        assert_eq!(description, "Open what decodes as zlib at 0x4 as a document of its own");
    }

    #[test]
    fn probing_tries_a_plugin_s_codec_after_the_built_in_ones() {
        let mut workspace = with_plugin_codec(b"68656c6c6f");
        let probed = call(&mut workspace, "codecs.probe", json!({"start": 0})).unwrap();
        let codecs: Vec<&str> = probed["streams"].as_array().unwrap().iter().filter_map(|stream| stream["codec"].as_str()).collect();
        assert_eq!(codecs, ["hex_text"], "ten digits are too few for the built-in hex text to be offered: {probed}");
        assert_eq!(probed["streams"][0]["output_len"], 5);
    }

    #[test]
    fn the_first_codec_that_decodes_is_used_when_none_is_named() {
        let mut bytes = b"head".to_vec();
        bytes.extend(zlib(b"hello, hello, hello"));
        let mut workspace = workspace_with("a.bin", &bytes);
        let decoded = call(&mut workspace, "codecs.decode", json!({"start": 4, "encoding": "text"})).unwrap();
        assert_eq!((decoded["codec"].as_str(), decoded["data"].as_str(), decoded["output"]["len"].as_u64()), (Some("zlib"), Some("hello, hello, hello"), Some(19)));
    }

    #[test]
    fn unknown_codecs_and_undecodable_bytes_are_refused() {
        let mut workspace = workspace_with("a.bin", b"not compressed at all");
        assert_eq!(call(&mut workspace, "codecs.decode", json!({"start": 0, "codec": "rot13"})).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "codecs.decode", json!({"start": 0, "codec": "gzip"})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "codecs.probe", json!({"start": 0, "max_output": 1usize << 30})).unwrap_err().code, ErrorCode::TooLarge);
    }

    #[test]
    fn a_stream_s_contents_open_as_a_derived_document_named_after_the_codec() {
        let mut bytes = b"head".to_vec();
        bytes.extend(zlib(b"hello, hello, hello"));
        let mut workspace = workspace_with("a.bin", &bytes);
        let opened = call(&mut workspace, "codecs.open_decoded", json!({"start": 4})).unwrap();
        assert_eq!((opened["codec"].as_str(), opened["complete"].as_bool()), (Some("zlib"), Some(true)));
        assert_eq!((opened["document"]["id"].as_str(), opened["document"]["name"].as_str(), opened["document"]["len"].as_u64()), (Some("doc-2"), Some("a.bin › zlib@0x4"), Some(19)));
        let named = call(&mut workspace, "codecs.open_decoded", json!({"doc": "doc-1", "start": 4, "codec": "zlib"})).unwrap();
        assert_eq!(named["document"]["id"], "doc-3");
    }

    #[test]
    fn opening_what_does_not_decode_there_is_refused() {
        let mut bytes = b"head".to_vec();
        bytes.extend(zlib(b"hello"));
        let len = bytes.len();
        let mut workspace = workspace_with("a.bin", &bytes);
        assert_eq!(call(&mut workspace, "codecs.open_decoded", json!({"start": 0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "codecs.open_decoded", json!({"start": 4, "codec": "bzip2"})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "codecs.open_decoded", json!({"start": len})).unwrap_err().code, ErrorCode::InvalidParams, "nothing at the end");
        assert_eq!(call(&mut workspace, "codecs.open_decoded", json!({"start": len + 1})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "documents.list", json!({})).unwrap()["documents"].as_array().unwrap().len(), 1, "nothing was opened");
    }

    mod window {
        use serde_json::json;

        use super::zlib;
        use crate::actions::take_performed;
        use crate::app::{Launch, ViewerApp};
        use crate::compress::Codec;

        fn app_with(bytes: &[u8]) -> ViewerApp {
            let mut app = ViewerApp::new(Launch::default());
            app.open_bytes(bytes.to_vec(), "test.bin".to_string());
            app.run_bus();
            take_performed();
            app
        }

        #[test]
        fn flipping_to_the_decompressed_view_and_back_are_api_steps() {
            let mut bytes = b"head".to_vec();
            bytes.extend(zlib(b"hello, hello, hello"));
            let mut app = app_with(&bytes);
            let outer = app.document_id();
            app.set_cursor(4, false);
            take_performed();
            app.toggle_compressed_view();
            assert_eq!(take_performed(), [("codecs.open_decoded".to_string(), json!({"start": 4}))]);
            assert_eq!(app.document.read_range(0, 19), b"hello, hello, hello");
            assert!(app.status.starts_with("zlib at 0x4: "), "{}", app.status);
            app.toggle_compressed_view();
            assert_eq!(take_performed(), [("documents.activate".to_string(), json!({"doc": outer}))]);
            assert_eq!(app.document_id(), outer);
        }

        #[test]
        fn decompressing_in_place_and_compressing_again_are_transform_steps() {
            let packed = zlib(b"hello, hello, hello");
            let mut bytes = b"head".to_vec();
            bytes.extend(&packed);
            bytes.extend(b"tail");
            let mut app = app_with(&bytes);
            app.set_cursor(4, false);
            take_performed();
            app.decompress_in_place();
            assert_eq!(take_performed(), [("transform.apply".to_string(), json!({"selection": {"range": [4, packed.len()]}, "operation": {"op": "decompress"}}))]);
            assert_eq!(app.document.read_range(0, 27), b"headhello, hello, hellotail");
            assert_eq!(app.selection(), Some((4, 19)), "what was decompressed is selected");
            assert!(app.status.starts_with("Replaced in place: zlib at 0x4"), "{}", app.status);
            app.recompress_selection();
            assert_eq!(take_performed(), [("transform.apply".to_string(), json!({"selection": {"range": [4, 19]}, "operation": {"op": "compress", "codec": "zlib"}}))]);
            assert_eq!(app.document.read_range(4, 1), [0x78], "re-packed as zlib, the codec it came in");
            assert!(app.status.starts_with("Compressed 19 B to "), "{}", app.status);
            app.set_selection(0, None);
            app.compress_selection(Codec::Gzip);
            assert_eq!(app.status, "Select the bytes to compress first");
            assert!(take_performed().is_empty());
        }
    }
}
