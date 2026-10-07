//! `codecs.*`: the decoders available, which ones a span starts with, and
//! decoding with them.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values::{self, ByteEncoding, NoParams};
use super::workspace::{self, Workspace};
use super::{ApiError, MAX_CALL_BYTES};
use crate::compress::{self, Codec};
use crate::plugin::{CodecKind, CodecPlugin};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("codecs.list", Read, list, super::values::NoParams, CodecList, "The codecs available for decoding, built in and from plugins."),
    method!("codecs.detect", Read, detect, DetectParams, CodecList, "The codecs whose header starts at an offset."),
    method!("codecs.decode", Read, decode, DecodeParams, DecodeResult, "Decode (decompress) a span with a codec and return the output."),
    method!("codecs.probe", Read, probe, ProbeParams, ProbeResult, "Try every built-in decompressor at the start of a span, headerless ones included, and list those that decode."),
    method!("codecs.open_decoded", View, open_decoded, OpenDecodedParams, OpenDecodedResult, "Decompress the stream starting at an offset, with the first codec that decodes there or the one named, and open what it holds as a document derived from this one; in the window, Back (or opening the parent by id) returns."),
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
        ("codecs.probe", json!({"start": 0})),
        ("codecs.open_decoded", json!({"start": 0, "codec": "zlib"})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, params: &serde_json::Value) -> Option<String> {
    match method {
        "codecs.open_decoded" => Some(format!("Open what decompresses at {:#x} as a document of its own", params.get("start")?.as_u64()?)),
        _ => None,
    }
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
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset where the encoded data would start.
    pub at: u64,
}

/// Parameters of `codecs.decode`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecodeParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the encoded data.
    pub start: u64,
    /// Bytes of input, at most 16 MiB; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Codec id from codecs.list, such as "zlib" or "gzip".
    pub codec: String,
    /// Most bytes of output, at most 16 MiB (the default).
    #[serde(default)]
    pub max_output: Option<usize>,
    /// How to write the output: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
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
    /// The output, written as `encoding` says.
    pub data: String,
}

/// Parameters of `codecs.probe`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeParams {
    /// Document id, path or "current" (the default).
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
    pub codec: Codec,
    pub consumed: u64,
    pub consumed_exact: bool,
    pub complete: bool,
    pub truncated: bool,
    pub output_len: u64,
}

/// The result of `codecs.probe`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProbeResult {
    /// Decoders that read the data, headed ones first.
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

pub fn decode(workspace: &mut dyn Workspace, params: DecodeParams) -> Result<DecodeResult, ApiError> {
    let registry = workspace.registry();
    let codec = registry.codec(&params.codec).ok_or_else(|| ApiError::not_found(format!("there is no codec '{}'; codecs.list lists them", params.codec)))?;
    let max_output = output_limit(params.max_output)?;
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (start, len) = values::span_within(document.len(), params.start, params.len)?;
    values::check_call_size(len)?;
    let input = document.read_range(start, len);
    let decoded = codec
        .decode(&input, max_output)
        .map_err(|message| ApiError::invalid_params(format!("the bytes at {start:#x} do not decode as {}: {message}", codec.name())))?;
    Ok(DecodeResult {
        codec: codec.id().to_string(),
        consumed: decoded.consumed as u64,
        consumed_exact: decoded.consumed_exact,
        complete: decoded.complete,
        truncated: decoded.truncated,
        output_len: decoded.data.len() as u64,
        encoding: params.encoding,
        data: values::encode_bytes(&decoded.data, params.encoding),
    })
}

pub fn probe(workspace: &mut dyn Workspace, params: ProbeParams) -> Result<ProbeResult, ApiError> {
    let max_output = output_limit(params.max_output)?;
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (start, len) = values::span_within(document.len(), params.start, params.len)?;
    values::check_call_size(len)?;
    let input = document.read_range(start, len);
    let streams = compress::probe(&input, max_output)
        .into_iter()
        .map(|found| ProbedStream {
            codec: found.codec,
            consumed: found.consumed as u64,
            consumed_exact: found.consumed_exact,
            complete: found.complete,
            truncated: found.truncated,
            output_len: found.data.len() as u64,
        })
        .collect();
    Ok(ProbeResult { streams })
}

/// Most bytes of a stream `codecs.open_decoded` reads, and most it opens.
const OPEN_DECODED_MAX: usize = 64 * 1024 * 1024;

/// Parameters of `codecs.open_decoded`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenDecodedParams {
    /// Document id, path or "current" (the default): the parent.
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset where the compressed stream starts.
    pub start: u64,
    /// The codec to decode with; the first that decodes there when omitted.
    #[serde(default)]
    pub codec: Option<Codec>,
}

/// The result of `codecs.open_decoded`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenDecodedResult {
    /// The document opened, now current.
    pub document: super::workspace::DocumentInfo,
    /// The codec that decoded the stream.
    pub codec: Codec,
    /// Input bytes the stream occupied.
    pub consumed: u64,
    /// Whether the stream ended cleanly.
    pub complete: bool,
    /// Whether the output was cut at 64 MiB.
    pub truncated: bool,
}

pub fn open_decoded(workspace: &mut dyn Workspace, params: OpenDecodedParams) -> Result<OpenDecodedResult, ApiError> {
    let parent = workspace::resolve(workspace, params.doc.as_deref())?;
    let name = workspace::info(workspace, &parent)?.name;
    let (_, document) = workspace::document(workspace, Some(&parent))?;
    let (start, available) = values::span_within(document.len(), params.start, None)?;
    if available == 0 {
        return Err(ApiError::invalid_params("nothing to decompress at the end of the document"));
    }
    let input = document.read_range(start, available.min(OPEN_DECODED_MAX));
    let found = compress::probe(&input, OPEN_DECODED_MAX).into_iter().find(|found| params.codec.is_none_or(|codec| found.codec == codec));
    let found = found.ok_or_else(|| match params.codec {
        Some(codec) => ApiError::invalid_params(format!("nothing decodes as {} at {start:#x}", codec.label())),
        None => ApiError::invalid_params(format!("nothing decodes at {start:#x} (tried gzip, zlib, bzip2, xz, zstd, LZ4, raw deflate and lzma)")),
    })?;
    let (codec, consumed, complete, truncated) = (found.codec, found.consumed as u64, found.complete, found.truncated);
    let id = workspace.open_derived(&parent, found.data, &format!("{name} › {}@{start:#x}", codec.label()))?;
    Ok(OpenDecodedResult { document: workspace::info(workspace, &id)?, codec, consumed, complete, truncated })
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
    format!(
        "{} at {start:#x}: {} compressed to {} decompressed{note}",
        result.codec.label(),
        compress::human_bytes(result.consumed as usize),
        compress::human_bytes(result.document.len as usize)
    )
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
            assert_eq!(take_performed(), [("documents.open".to_string(), json!({"doc": outer, "discard_unsaved": true}))]);
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
