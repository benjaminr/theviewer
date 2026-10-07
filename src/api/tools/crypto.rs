//! `crypto.*`: the Crypto tools' searches: well-known constants that betray
//! crypto and compression code, repeated cipher blocks (ECB), keys and
//! certificates, and attacks on simple ciphers beyond plain XOR.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary, ToolSpan};
use crate::api::jobs::JobStartedResult;
use crate::api::values::{self, ByteEncoding};
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller};
use crate::blocks::BlockReport;
use crate::ciphers::{AttackOptions, CipherCandidate, KeyFragment};
use crate::crypto_constants::CryptoMatch;
use crate::keys::KeyFinding;
use crate::panel_crypto::{self, DecodeResults};
use crate::panel_crypto_constants::{self, ConstantsScan};
use crate::selection_ops::Operation;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("crypto.scan_constants", Job, caller scan_constants, ScanConstantsParams, JobStartedResult, "Start a scan of the whole document (an edited one's first 256 MiB) for well-known constants of crypto and compression code (AES S-boxes, hash initial values, CRC tables, deflate tables, Blowfish, DES, ChaCha, TEA, curve primes, Base64 alphabets) as a job: the matches are job.finished's result, and in the window they fill Crypto constants."),
    method!("crypto.repeated_blocks", Job, caller repeated_blocks, CryptoSpanParams, JobStartedResult, "Start a search of a span (at most 16 MiB) for random-looking 8- and 16-byte blocks that repeat, the mark of ECB-mode encryption, as a job: the verdict, the best block size and alignment, the most repeated blocks and the repeats along the span are job.finished's result, and in the window they fill the Crypto panel."),
    method!("crypto.find_keys", Job, caller find_keys, CryptoSpanParams, JobStartedResult, "Start a search of a span (the whole document by default, at most 64 MiB) for PEM blocks, DER certificates and keys, OpenSSH keys and random-looking runs that could be raw symmetric keys, as a job: what was found is job.finished's result, and in the window it fills the Crypto panel."),
    method!("crypto.attack", Job, caller attack, AttackParams, JobStartedResult, "Start attacks on simple ciphers over a span (at most 1 MiB): rolling XOR, XOR with the previous byte, ADD/SUB with a constant or repeating key, bit rotation, XOR combined with ADD and, with a crib, crib dragging, as a job: the decodes that look most like text or structured data, each with the operation that transform.apply or documents.derive takes to apply it, and with a crib the key bytes it reveals, are job.finished's result, and in the window they fill the Crypto panel."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("crypto.scan_constants", json!({})),
        ("crypto.repeated_blocks", json!({"start": 0, "len": 256})),
        ("crypto.find_keys", json!({})),
        ("crypto.attack", json!({"start": 0, "len": 256, "crib": "PK\\x03\\x04"})),
    ]
}

/// Most bytes the cipher attacks decode.
pub const ATTACK_LIMIT: usize = 1024 * 1024;
/// Most cipher decodes proposed.
pub const MAX_CANDIDATES: usize = 12;

/// Parameters of `crypto.scan_constants`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanConstantsParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// A span for one of the crypto searches.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CryptoSpanParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset searched (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes searched; to the end of the document, or the search's limit, when omitted.
    #[serde(default)]
    pub len: Option<u64>,
}

/// Parameters of `crypto.attack`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttackParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset of the suspect bytes (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes decoded, at most 1 MiB; to the end of the document (or 1 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Known plaintext to drag across the data, as text with \xHH escapes, such as "PK\x03\x04".
    #[serde(default)]
    pub crib: Option<String>,
}

/// A well-known constant found.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ConstantFound {
    /// Algorithm family, such as "AES" or "SHA-256".
    pub algorithm: String,
    /// Which table or value, such as "S-box".
    pub table: String,
    /// Byte order of the stored words, or empty.
    pub byte_order: String,
    pub start: u64,
    pub len: u64,
    /// 0 to 1; short constants that turn up by coincidence score below 0.5.
    pub confidence: f32,
    pub note: String,
}

impl ConstantFound {
    fn of(found: &CryptoMatch) -> Self {
        ConstantFound {
            algorithm: found.algorithm.to_string(),
            table: found.table.clone(),
            byte_order: found.byte_order.to_string(),
            start: found.start as u64,
            len: found.len as u64,
            confidence: found.confidence,
            note: found.note.clone(),
        }
    }
}

/// What `crypto.scan_constants`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ConstantsFound {
    /// Bytes scanned from the start of the document.
    pub scanned: u64,
    /// The matches, by offset.
    pub matches: Vec<ConstantFound>,
}

/// A block that repeats.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RepeatedCipherBlock {
    /// The block, as hex.
    pub bytes: String,
    pub count: u64,
    /// Document offsets of its first occurrences (at most 32).
    pub offsets: Vec<u64>,
}

/// Repeats in one window of the span.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RepeatsAlong {
    pub offset: u64,
    pub len: u64,
    /// Share of its random-looking blocks that repeat, or nothing when it has none.
    pub repeat_ratio: Option<f32>,
}

/// What `crypto.repeated_blocks`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RepeatedBlocks {
    pub start: u64,
    /// Bytes analysed.
    pub analysed_len: u64,
    /// What the repeats say, such as "likely ECB-encrypted with a 16-byte block cipher".
    pub verdict: String,
    /// The block size and alignment with the most repeats.
    pub block_size: usize,
    pub alignment: usize,
    /// Random-looking blocks counted, and those equal to an earlier one.
    pub eligible_blocks: u64,
    pub repeated_blocks: u64,
    /// The most repeated blocks, most frequent first.
    pub top_repeats: Vec<RepeatedCipherBlock>,
    /// Repeats along the span.
    pub regions: Vec<RepeatsAlong>,
}

impl RepeatedBlocks {
    fn of(report: &BlockReport) -> Self {
        RepeatedBlocks {
            start: report.start as u64,
            analysed_len: report.analysed_len as u64,
            verdict: report.verdict.label(),
            block_size: report.best.block_size,
            alignment: report.best.alignment,
            eligible_blocks: report.best.eligible_blocks as u64,
            repeated_blocks: report.best.repeated_blocks as u64,
            top_repeats: report
                .top_repeats
                .iter()
                .map(|repeat| RepeatedCipherBlock { bytes: crate::api::values::encode_bytes(&repeat.bytes, Default::default()), count: repeat.count as u64, offsets: repeat.offsets.iter().map(|&offset| offset as u64).collect() })
                .collect(),
            regions: report.regions.iter().map(|region| RepeatsAlong { offset: region.offset as u64, len: region.len as u64, repeat_ratio: region.repeat_ratio() }).collect(),
        }
    }
}

/// A key or certificate found.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct KeyFound {
    pub offset: u64,
    pub len: u64,
    /// Such as "certificate", "private key" or "raw key candidate".
    pub kind: String,
    /// Such as "PEM", "DER" or "raw".
    pub format: String,
    /// Algorithm, size, subject and the like.
    pub detail: String,
    pub confidence: f32,
}

/// What `crypto.find_keys`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct KeysFound {
    pub start: u64,
    pub len: u64,
    pub keys: Vec<KeyFound>,
}

impl KeysFound {
    fn of(span: (usize, usize), keys: &[KeyFinding]) -> Self {
        KeysFound {
            start: span.0 as u64,
            len: span.1 as u64,
            keys: keys
                .iter()
                .map(|key| KeyFound { offset: key.offset as u64, len: key.len as u64, kind: key.kind.label().to_string(), format: key.format.label().to_string(), detail: key.detail.clone(), confidence: key.confidence })
                .collect(),
        }
    }
}

/// A decode the cipher attacks propose.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CipherDecode {
    /// What undoes the cipher, such as "rolling XOR: key 0x10 + 3·i".
    pub transform: String,
    /// The same as an operation for transform.apply (or documents.derive's
    /// transform) over the span attacked, such as {"op": "rolling_xor", "start": 16, "step": 3}.
    pub operation: Operation,
    pub score: f64,
    pub printable_fraction: f64,
    /// Bits per byte of the decode.
    pub entropy: f32,
    /// A file signature the decode starts with.
    pub magic: Option<String>,
    pub preview: String,
    pub reason: String,
}

impl CipherDecode {
    fn of(candidate: &CipherCandidate) -> Self {
        CipherDecode {
            transform: candidate.transform.describe(),
            operation: Operation::from(candidate.transform.clone()),
            score: candidate.score,
            printable_fraction: candidate.printable_fraction,
            entropy: candidate.entropy,
            magic: candidate.magic.map(str::to_string),
            preview: candidate.preview.clone(),
            reason: candidate.reason.clone(),
        }
    }
}

/// Key bytes a crib reveals where it sits, whether or not they make a decode.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CribKeyFragment {
    /// Document offset of the crib.
    pub offset: u64,
    /// The key bytes under the crib, as hex: the key's first bytes when
    /// the crib is at the span's start.
    pub key: String,
    /// The key bytes as text, when they are all printable.
    pub text: Option<String>,
    /// Such as "key prefix at offset 0: …; a longer key goes on from there".
    pub reason: String,
}

impl CribKeyFragment {
    fn of(span_start: usize, fragment: &KeyFragment) -> Self {
        let printable = fragment.keystream.iter().all(|&byte| (0x20..0x7F).contains(&byte));
        CribKeyFragment {
            offset: (span_start + fragment.offset) as u64,
            key: values::encode_bytes(&fragment.keystream, ByteEncoding::Hex),
            text: printable.then(|| String::from_utf8_lossy(&fragment.keystream).into_owned()),
            reason: fragment.reason.clone(),
        }
    }
}

/// What `crypto.attack`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CipherDecodes {
    pub start: u64,
    pub len: u64,
    /// The decodes, most plausible first.
    pub candidates: Vec<CipherDecode>,
    /// With a crib: the key bytes it reveals at the span's start, and where
    /// they read as text, even when no repeating key decodes the span (a
    /// key longer than the crib).
    pub key_fragments: Vec<CribKeyFragment>,
}

/// `crypto.scan_constants`: scan the document's file mapping (or a copy of
/// an edited one) on a thread, in parallel chunks.
pub fn scan_constants(workspace: &mut dyn Workspace, caller: &Caller, params: ScanConstantsParams) -> Result<JobStartedResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let info = workspace::info(workspace, &id)?;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let source = panel_crypto_constants::ScanSource::of(document);
    let span = ToolSpan { doc: id, version: info.version, start: 0, len: source.len() };
    let progress = Arc::new(AtomicUsize::new(0));
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(|app| panel_crypto_constants::await_scan(app, Arc::clone(&progress), span.len));
    let key = panel_crypto_constants::DocumentKey { path: info.path.map(Into::into), len: info.len as usize, version: info.version };
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("crypto-constants", "Crypto constants"),
        &span,
        deliver,
        move |_| source.scan(key, &progress),
        |scan: &ConstantsScan| Summary::of(format!("{} matches", scan.matches.len()), ConstantsFound { scanned: scan.scanned as u64, matches: scan.matches.iter().map(ConstantFound::of).collect() }),
    ))
}

/// `crypto.repeated_blocks`: read the span now and look for repeats on a thread.
pub fn repeated_blocks(workspace: &mut dyn Workspace, caller: &Caller, params: CryptoSpanParams) -> Result<JobStartedResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, crate::blocks::MAX_ANALYSED_BYTES, "the span searched")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_crypto::await_blocks);
    let start = span.start;
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("repeated-blocks", "Repeated blocks"),
        &span,
        deliver,
        move |_| crate::blocks::analyse(&bytes, start),
        |report| Summary::of(report.verdict.label(), RepeatedBlocks::of(report)),
    ))
}

/// `crypto.find_keys`: read the span now and search it on a thread.
pub fn find_keys(workspace: &mut dyn Workspace, caller: &Caller, params: CryptoSpanParams) -> Result<JobStartedResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, crate::keys::MAX_SCAN_BYTES, "the span searched")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_crypto::await_keys);
    let (start, len) = (span.start, span.len);
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("keys", "Keys and certificates"),
        &span,
        deliver,
        move |_| crate::keys::find_keys(&bytes, start),
        move |keys| Summary::of(format!("{} found", keys.len()), KeysFound::of((start, len), keys)),
    ))
}

/// `crypto.attack`: read the span now and attack it on a thread.
pub fn attack(workspace: &mut dyn Workspace, caller: &Caller, params: AttackParams) -> Result<JobStartedResult, ApiError> {
    let crib = match params.crib.as_deref().filter(|crib| !crib.is_empty()) {
        Some(text) => Some(crate::ciphers::parse_crib(text).map_err(|error| ApiError::invalid_params(format!("the crib '{text}' cannot be read: {error}")))?),
        None => None,
    };
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, ATTACK_LIMIT, "the span decoded")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_crypto::await_decode);
    let (start, len) = (span.start, span.len);
    let options = AttackOptions { crib, max_results: MAX_CANDIDATES };
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("cipher-attacks", "Cipher attacks"),
        &span,
        deliver,
        move |_| {
            let fragments = options.crib.as_deref().map(|crib| crate::ciphers::crib_key_fragments(&bytes, crib)).unwrap_or_default();
            DecodeResults { start, len, candidates: crate::ciphers::attack(&bytes, &options), fragments }
        },
        |results| {
            let decodes = CipherDecodes {
                start: results.start as u64,
                len: results.len as u64,
                candidates: results.candidates.iter().map(CipherDecode::of).collect(),
                key_fragments: results.fragments.iter().map(|fragment| CribKeyFragment::of(results.start, fragment)).collect(),
            };
            Summary::of(format!("{} decodes", decodes.candidates.len()), decodes)
        },
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    /// The AES S-box between runs of zeros.
    fn with_aes_sbox() -> Vec<u8> {
        [vec![0u8; 100], crate::crypto_constants::aes_sbox().to_vec(), vec![0u8; 100]].concat()
    }

    #[test]
    fn scanning_for_constants_finds_the_aes_s_box() {
        let mut workspace = workspace_with("aes.bin", &with_aes_sbox());
        let status = run_job(&mut workspace, "crypto.scan_constants", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        let matches = status["result"]["matches"].as_array().unwrap();
        assert!(matches.iter().any(|found| found["algorithm"] == "AES" && found["start"] == 100), "{matches:?}");
        assert_eq!(status["result"]["scanned"], 456);
    }

    #[test]
    fn repeated_random_blocks_are_judged_ecb() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut block = || -> Vec<u8> {
            (0..16)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect()
        };
        let blocks: Vec<Vec<u8>> = (0..8).map(|_| block()).collect();
        let data: Vec<u8> = (0..400).flat_map(|index| blocks[index % 3 + index % 5 % 2 * 3].clone()).collect();
        let mut workspace = workspace_with("ecb.bin", &data);
        let status = run_job(&mut workspace, "crypto.repeated_blocks", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        assert!(status["result"]["verdict"].as_str().unwrap().contains("ECB"), "{status}");
        assert_eq!(status["result"]["block_size"], 16);
        assert_eq!(call(&mut workspace, "crypto.repeated_blocks", json!({"len": 17 * 1024 * 1024})).unwrap_err().code, ErrorCode::OutOfRange);
    }

    #[test]
    fn a_pem_certificate_is_found_among_other_bytes() {
        let mut bytes = vec![0x11u8; 64];
        bytes.extend(b"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n");
        bytes.extend([0x22u8; 64]);
        let mut workspace = workspace_with("cert.bin", &bytes);
        let status = run_job(&mut workspace, "crypto.find_keys", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        let keys = status["result"]["keys"].as_array().unwrap();
        assert!(keys.iter().any(|key| key["offset"] == 64 && key["format"] == "PEM"), "{keys:?}");
    }

    #[test]
    fn a_rolling_xor_is_undone_and_a_crib_that_cannot_be_read_is_refused() {
        let plain = b"Attack at dawn, the quick brown fox jumps over the lazy dog. ".repeat(20);
        let hidden: Vec<u8> = plain.iter().enumerate().map(|(index, byte)| byte ^ (0x10u8.wrapping_add((index as u8).wrapping_mul(3)))).collect();
        let mut workspace = workspace_with("rolling.bin", &hidden);
        let status = run_job(&mut workspace, "crypto.attack", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        let best = &status["result"]["candidates"][0];
        assert!(best["transform"].as_str().unwrap().starts_with("rolling XOR"), "{best}");
        assert!(best["preview"].as_str().unwrap().starts_with("Attack at dawn"), "{best}");
        assert_eq!(call(&mut workspace, "crypto.attack", json!({"crib": "\\xZZ"})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "crypto.attack", json!({"len": 2 * 1024 * 1024})).unwrap_err().code, ErrorCode::OutOfRange);
    }

    #[test]
    fn the_top_decode_s_operation_applies_with_transform_apply_and_gives_the_plaintext_back() {
        let plain = b"Attack at dawn, the quick brown fox jumps over the lazy dog. ".repeat(20);
        let hidden: Vec<u8> = plain.iter().enumerate().map(|(index, byte)| byte ^ (0x51u8.wrapping_add((index as u8).wrapping_mul(5)))).collect();
        let mut workspace = workspace_with("stage.bin", &[b"head".as_slice(), &hidden].concat());
        let status = run_job(&mut workspace, "crypto.attack", json!({"start": 4, "len": hidden.len()}));
        let operation = status["result"]["candidates"][0]["operation"].clone();
        assert_eq!(operation, json!({"op": "rolling_xor", "start": 0x51, "step": 5}));
        call(&mut workspace, "transform.apply", json!({"selection": {"range": [4, hidden.len()]}, "operation": operation})).unwrap();
        let read = call(&mut workspace, "bytes.read", json!({"start": 4, "len": 14, "encoding": "text"})).unwrap();
        assert_eq!(read["data"], "Attack at dawn");
    }

    #[test]
    fn a_crib_shorter_than_the_key_reports_the_key_prefix_it_pins() {
        let config = b"[camera]\nmodel = NovaCam NC-500\nserial = NC500-8D51266C\nrtsp_port = 554\n[cloud]\nrecovery_flag = FLAG{8d51266c8ea1f897}\n";
        let serial = b"NC500-8D51266C";
        let sealed = crate::xor::apply(config, serial, 0);
        let mut workspace = workspace_with("config.enc", &[vec![0u8; 16], sealed].concat());
        let status = run_job(&mut workspace, "crypto.attack", json!({"start": 16, "crib": "[camera]"}));
        let fragment = &status["result"]["key_fragments"][0];
        assert_eq!((fragment["offset"].as_u64(), fragment["key"].as_str(), fragment["text"].as_str()), (Some(16), Some("4e433530302d3844"), Some("NC500-8D")), "{status}");
        assert!(fragment["reason"].as_str().unwrap().starts_with("key prefix at offset 0"), "{fragment}");
        let without_crib = run_job(&mut workspace, "crypto.attack", json!({"start": 16}));
        assert_eq!(without_crib["result"]["key_fragments"], json!([]));
    }
}
