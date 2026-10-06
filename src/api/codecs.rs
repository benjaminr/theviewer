//! `codecs.*`: the decoders available, which ones a span starts with, and
//! decoding with them.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values::{self, ByteEncoding, NoParams};
use super::workspace::{self, Workspace};
use super::{ApiError, MAX_CALL_BYTES};
use crate::compress::{self, Codec};
use crate::plugin::{CodecKind, CodecPlugin};

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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::{ErrorCode, call};

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
}
