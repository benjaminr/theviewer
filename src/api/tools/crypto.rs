//! `crypto.*`: the Crypto tools' searches: well-known constants that betray
//! crypto and compression code, repeated cipher blocks (ECB), keys and
//! certificates, and attacks on simple ciphers beyond plain XOR; and AES
//! decryption once they have led to a key.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary, ToolSpan};
use crate::api::jobs::JobStartedResult;
use crate::api::output::{self, Delivered, Made, NewSheet, Output, Produced};
use crate::api::values::{self, ByteEncoding};
use crate::api::workspace::{self, DocumentInfo, Workspace};
use crate::api::{ApiError, Caller, OutputKind};
use crate::block_cipher::{self, Algorithm, Decryption, Mode, Padding};
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
    method!("crypto.decrypt", Read, caller decrypt, DecryptParams, DecryptResult, "Decrypt a span with AES-128, AES-192 or AES-256 in ECB, CBC or CTR mode, with a key (and IV) given as hex, removing PKCS#7 padding, and return the plaintext; or, as output says, open it as a new sheet, put it in place of the ciphertext, or write it to a file (which needs leave to edit).").outputs(&[OutputKind::Return, OutputKind::New, OutputKind::InPlace, OutputKind::File], OutputKind::Return),
    method!("crypto.open_decrypted", View, caller open_decrypted, OpenDecryptedParams, OpenDecryptedResult, "Decrypt a span as crypto.decrypt does and open the plaintext as a document derived from this one; in the window, Back (or opening the parent by id) returns. A shorthand for crypto.decrypt with output \"new\".").makes_sheet(),
    method!("crypto.apply", View, caller apply, ApplyParams, Made, "Undo a simple cipher over a span: a candidate crypto.attack proposed (by its job and index, over the span it attacked), or an operation such as {\"op\": \"rolling_xor\", \"start\": 81, \"step\": 5}; open what it makes as a new sheet by default, or, as output says, put it in place, return it or write it to a file (which needs leave to edit).").outputs(&[OutputKind::New, OutputKind::InPlace, OutputKind::Return, OutputKind::File], OutputKind::New),
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
        ("crypto.decrypt", json!({"start": 0, "len": 32, "mode": "ecb", "key": "2b7e151628aed2a6abf7158809cf4f3c", "padding": "none"})),
        ("crypto.open_decrypted", json!({"start": 0, "len": 32, "mode": "ctr", "key": "2b7e151628aed2a6abf7158809cf4f3c", "iv": "00000000000000000000000000000000"})),
        ("crypto.apply", json!({"doc": "doc-1", "start": 0, "len": 16, "operation": {"op": "rolling_xor", "start": 16, "step": 3}, "output": "return"})),
        // Back to the example document for the tools after these.
        ("documents.open", json!({"doc": "doc-1"})),
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

/// Parameters of `crypto.decrypt`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecryptParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset of the ciphertext (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes of ciphertext, at most 16 MiB, whole 16-byte blocks for ECB and CBC; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Which AES: "aes-128", "aes-192" or "aes-256"; by default the one the key's length is for.
    #[serde(default)]
    pub alg: Option<Algorithm>,
    /// "ecb", "cbc" or "ctr".
    pub mode: Mode,
    /// The key, as hex: 16, 24 or 32 bytes.
    pub key: String,
    /// The IV as hex, 16 bytes, for CBC; for CTR, the initial counter block (nonce and counter), counted up big-endian.
    #[serde(default)]
    pub iv: Option<String>,
    /// "pkcs7" or "none"; by default PKCS#7 for ECB and CBC and none for CTR. Padding that is not valid is left in place and said.
    #[serde(default)]
    pub padding: Option<Padding>,
    /// How to write the plaintext returned: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
    /// Where the plaintext goes: "return" (the default), "new" (a sheet
    /// derived from this document; {"new": {"label": …, "name": …}} names
    /// it), "in_place" (over the ciphertext) or {"file": path}.
    #[serde(default)]
    pub output: Option<Output>,
}

/// Parameters of `crypto.open_decrypted`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenDecryptedParams {
    /// Document id, path or "current" (the default): the parent.
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset of the ciphertext (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes of ciphertext, at most 16 MiB, whole 16-byte blocks for ECB and CBC; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Which AES: "aes-128", "aes-192" or "aes-256"; by default the one the key's length is for.
    #[serde(default)]
    pub alg: Option<Algorithm>,
    /// "ecb", "cbc" or "ctr".
    pub mode: Mode,
    /// The key, as hex: 16, 24 or 32 bytes.
    pub key: String,
    /// The IV as hex, 16 bytes, for CBC; for CTR, the initial counter block (nonce and counter), counted up big-endian.
    #[serde(default)]
    pub iv: Option<String>,
    /// "pkcs7" or "none"; by default PKCS#7 for ECB and CBC and none for CTR. Padding that is not valid is left in place and said.
    #[serde(default)]
    pub padding: Option<Padding>,
    /// What to call the new document; the parent's name, the cipher and the offset when omitted.
    #[serde(default)]
    pub name: Option<String>,
}

impl OpenDecryptedParams {
    /// The same decryption, as `crypto.decrypt` takes it, with output "new".
    fn as_decrypt(&self) -> DecryptParams {
        DecryptParams {
            doc: self.doc.clone(),
            start: self.start,
            len: self.len,
            alg: self.alg,
            mode: self.mode,
            key: self.key.clone(),
            iv: self.iv.clone(),
            padding: self.padding,
            encoding: ByteEncoding::Hex,
            output: Some(Output::New(NewSheet { name: self.name.clone(), ..NewSheet::default() })),
        }
    }
}

/// How a span was decrypted, and whether the padding fitted.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DecryptionDone {
    pub alg: Algorithm,
    pub mode: Mode,
    pub padding: Padding,
    /// First offset and length of the ciphertext.
    pub start: u64,
    pub len: u64,
    /// Padding bytes removed from the end.
    pub padding_removed: u64,
    /// Whether PKCS#7 padding was asked for and not found; the plaintext is
    /// then given whole, and the key, IV or mode is probably wrong.
    pub padding_invalid: bool,
    /// Bits per byte of the plaintext: a right key brings it well under 8.
    pub entropy: f32,
    pub output_len: u64,
}

/// The result of `crypto.decrypt`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DecryptResult {
    #[serde(flatten)]
    pub done: DecryptionDone,
    pub encoding: ByteEncoding,
    /// The plaintext, written as `encoding` says, when it was returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Where the plaintext went: {len, encoding} returned (the bytes are `data`), {doc, label, len} for a new sheet, {version, len, ranges} in place, {path, len} to a file.
    pub output: Delivered,
}

/// The result of `crypto.open_decrypted`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenDecryptedResult {
    /// The document the plaintext was opened as.
    pub document: DocumentInfo,
    #[serde(flatten)]
    pub done: DecryptionDone,
    /// The sheet made, in the form every method that makes one gives.
    pub output: workspace::SheetOutput,
}

/// Read and decrypt the span `params` names: the parent document's id, the
/// plaintext, and how it was done.
fn decrypt_span(workspace: &mut dyn Workspace, params: &DecryptParams) -> Result<(String, Vec<u8>, DecryptionDone), ApiError> {
    let key = values::decode_bytes(&params.key, ByteEncoding::Hex).map_err(|_| ApiError::invalid_params(format!("the key '{}' is not hex bytes; write it like \"2b7e1516 28aed2a6 abf71588 09cf4f3c\"", params.key)))?;
    let iv = match params.iv.as_deref() {
        Some(text) => Some(values::decode_bytes(text, ByteEncoding::Hex).map_err(|_| ApiError::invalid_params(format!("the iv '{text}' is not hex bytes")))?),
        None => None,
    };
    let alg = match params.alg {
        Some(alg) => alg,
        None => Algorithm::for_key_len(key.len()).ok_or_else(|| ApiError::invalid_params(format!("a {}-byte key fits no AES; give 16, 24 or 32 bytes", key.len())))?,
    };
    let decryption = Decryption { algorithm: alg, mode: params.mode, key, iv, padding: params.padding.unwrap_or(params.mode.usual_padding()) };
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let (start, len) = values::span_within(document.len(), params.start, params.len)?;
    values::check_call_size(len)?;
    let ciphertext = document.read_range(start, len);
    let decrypted = block_cipher::decrypt(&decryption, &ciphertext).map_err(ApiError::invalid_params)?;
    let done = DecryptionDone {
        alg,
        mode: decryption.mode,
        padding: decryption.padding,
        start: start as u64,
        len: len as u64,
        padding_removed: decrypted.padding_removed as u64,
        padding_invalid: decrypted.padding_invalid,
        entropy: crate::analysis::shannon_entropy(&decrypted.bytes),
        output_len: decrypted.bytes.len() as u64,
    };
    Ok((id, decrypted.bytes, done))
}

/// `crypto.decrypt`: decrypt a span and send the plaintext where `output`
/// says: returned by default.
pub fn decrypt(workspace: &mut dyn Workspace, caller: &Caller, params: DecryptParams) -> Result<DecryptResult, ApiError> {
    let output = output::chosen("crypto.decrypt", params.output.clone())?;
    let (parent, plaintext, done) = decrypt_span(workspace, &params)?;
    let name = format!("{} › {}-{}@{:#x}", workspace::info(workspace, &parent)?.name, done.alg.label(), done.mode.label(), done.start);
    let action = format!("Decrypt {}-{}", done.alg.label(), done.mode.label());
    let produced = Produced::replacing(done.start as usize, done.len as usize, plaintext, name, action).encoded(params.encoding);
    let mut delivered = output::deliver(workspace, caller, &parent, produced, &output)?;
    let data = delivered.data.take();
    Ok(DecryptResult { done, encoding: delivered.encoding.unwrap_or(params.encoding), data, output: delivered })
}

/// `crypto.open_decrypted`: `crypto.decrypt` with output "new", giving the
/// document opened.
pub fn open_decrypted(workspace: &mut dyn Workspace, caller: &Caller, params: OpenDecryptedParams) -> Result<OpenDecryptedResult, ApiError> {
    let decrypted = decrypt(workspace, caller, params.as_decrypt())?;
    let id = decrypted.output.doc.expect("a new sheet");
    Ok(OpenDecryptedResult { document: workspace::info(workspace, &id)?, done: decrypted.done, output: workspace::SheetOutput::of(workspace, &id)? })
}

/// Parameters of `crypto.apply`: a span and what undoes its cipher, as a
/// candidate `crypto.attack` proposed or an operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyParams {
    /// Document id, path or "current" (the default); with a candidate, the
    /// document its attack read.
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset of the enciphered bytes (0 by default); with a
    /// candidate, the start of the span its attack read.
    #[serde(default)]
    pub start: Option<u64>,
    /// Bytes to decode; to the end of the document when omitted, or, with a
    /// candidate, the span its attack read.
    #[serde(default)]
    pub len: Option<u64>,
    /// A decode crypto.attack proposed: its job and the candidate's index
    /// in the job's result (0, the most plausible, by default).
    #[serde(default)]
    pub candidate: Option<CandidateRef>,
    /// The operation that undoes the cipher, as crypto.attack's candidates
    /// give it, such as {"op": "rolling_xor", "start": 81, "step": 5}; in
    /// place of a candidate.
    #[serde(default)]
    pub operation: Option<Operation>,
    /// Where the decode goes: "new" (the default; {"new": {"label": …}}
    /// labels the sheet), "in_place", "return" or {"file": path}.
    #[serde(default)]
    pub output: Option<Output>,
    /// With output "return", how the bytes are written: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
}

/// One of the decodes a `crypto.attack` job proposed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateRef {
    /// The attack's job, as crypto.attack returned it.
    pub job: String,
    /// The candidate's index in the job's `candidates`, from 0.
    #[serde(default)]
    pub index: usize,
}

/// The operation, document and span a `crypto.apply` call names.
fn applied(workspace: &mut dyn Workspace, params: &ApplyParams) -> Result<(Operation, String, usize, usize), ApiError> {
    let (operation, doc, start, len) = match (&params.candidate, &params.operation) {
        (Some(candidate), None) => {
            let status = workspace.bus().jobs().status(&candidate.job).ok_or_else(|| ApiError::not_found(format!("there is no job '{}'; crypto.attack starts one", candidate.job)))?;
            let result = status.result.ok_or_else(|| ApiError::invalid_params(format!("job {} has not finished; wait for it (jobs.status) before applying its candidates", candidate.job)))?;
            let decodes: CipherDecodes = serde_json::from_value(result).map_err(|_| ApiError::invalid_params(format!("job {} is not a crypto.attack's", candidate.job)))?;
            let found = decodes.candidates.get(candidate.index).ok_or_else(|| ApiError::not_found(format!("job {} proposed {} candidates, so there is no candidate {}", candidate.job, decodes.candidates.len(), candidate.index)))?;
            let doc = params.doc.clone().or(status.document);
            (found.operation.clone(), doc, params.start.unwrap_or(decodes.start), params.len.or(Some(decodes.len)))
        }
        (None, Some(operation)) => (operation.clone(), params.doc.clone(), params.start.unwrap_or(0), params.len),
        _ => return Err(ApiError::invalid_params("give what undoes the cipher one way: a candidate {job, index} from crypto.attack, or an operation")),
    };
    let id = workspace::resolve(workspace, doc.as_deref())?;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let (start, len) = values::span_within(document.len(), start, len)?;
    Ok((operation, id, start, len))
}

/// `crypto.apply`: undo a cipher over a span, as a candidate of
/// `crypto.attack` or an operation says, and send what it makes where
/// `output` says: a new sheet by default.
pub fn apply(workspace: &mut dyn Workspace, caller: &Caller, params: ApplyParams) -> Result<Made, ApiError> {
    let output = output::chosen("crypto.apply", params.output.clone())?;
    let (operation, id, start, len) = applied(workspace, &params)?;
    values::check_size(len, ATTACK_APPLY_LIMIT, "the span")?;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let decoded = crate::selection_ops::transform_range(&operation, &document.read_range(start, len), 0).map_err(|message| ApiError::invalid_params(format!("{} failed: {message}", operation.name())))?;
    let name = format!("{} › {}@{start:#x}", workspace::info(workspace, &id)?.name, operation.name());
    let produced = Produced::replacing(start, len, decoded, name, operation.name()).encoded(params.encoding);
    let delivered = output::deliver(workspace, caller, &id, produced, &output)?;
    Made::of(workspace, delivered)
}

/// Most bytes `crypto.apply` decodes: the window's whole-document limit.
const ATTACK_APPLY_LIMIT: usize = 64 * 1024 * 1024;

/// What a decryption gave, for the status bar: "AES-128-ECB: 304 bytes
/// decrypted to 288", with a warning when the padding was not valid.
pub fn describe_decrypted(done: &DecryptionDone) -> String {
    let warning = if done.padding_invalid { " (no valid PKCS#7 padding: the key, IV or mode may be wrong)" } else { "" };
    format!("{}-{}: {} bytes at {:#x} decrypted to {}{warning}", done.alg.label(), done.mode.label(), done.len, done.start, done.output_len)
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
    fn an_attack_s_candidate_is_applied_to_a_new_sheet_of_the_span_it_attacked() {
        let plain = b"Attack at dawn, the quick brown fox jumps over the lazy dog. ".repeat(20);
        let hidden: Vec<u8> = plain.iter().enumerate().map(|(index, byte)| byte ^ (0x51u8.wrapping_add((index as u8).wrapping_mul(5)))).collect();
        let mut workspace = workspace_with("stage.bin", &[b"head".as_slice(), &hidden, b"tail"].concat());
        let status = run_job(&mut workspace, "crypto.attack", json!({"start": 4, "len": hidden.len()}));
        let job = status["job"].as_str().unwrap().to_string();
        let applied = call(&mut workspace, "crypto.apply", json!({"candidate": {"job": job}, "output": {"new": {"label": "stage2"}}})).unwrap();
        assert_eq!((applied["output"]["label"].as_str(), applied["len"].as_u64()), (Some("stage2"), Some(hidden.len() as u64)));
        let doc = applied["id"].as_str().unwrap().to_string();
        assert_eq!(call(&mut workspace, "bytes.read", json!({"doc": doc, "start": 0, "len": 14, "encoding": "text"})).unwrap()["data"], "Attack at dawn");
        assert_eq!(call(&mut workspace, "documents.info", json!({"doc": doc})).unwrap()["parent"], "doc-1");
        let in_place = call(&mut workspace, "crypto.apply", json!({"doc": "doc-1", "start": 4, "len": hidden.len(), "operation": {"op": "rolling_xor", "start": 0x51, "step": 5}, "output": "in_place"})).unwrap();
        assert_eq!(in_place["output"]["ranges"], json!([[4, hidden.len()]]));
        assert_eq!(call(&mut workspace, "bytes.read", json!({"doc": "doc-1", "start": 4, "len": 6, "encoding": "text"})).unwrap()["data"], "Attack");
        let neither = call(&mut workspace, "crypto.apply", json!({"start": 0})).unwrap_err();
        assert_eq!(neither.code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "crypto.apply", json!({"candidate": {"job": "nope-1"}})).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "crypto.apply", json!({"candidate": {"job": job, "index": 99}})).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn a_recipe_applies_the_candidate_of_the_attack_it_ran_itself() {
        let hide = |plain: &[u8], start: u8, step: u8| -> Vec<u8> { plain.iter().enumerate().map(|(index, byte)| byte ^ start.wrapping_add((index as u8).wrapping_mul(step))).collect() };
        let plain = b"Attack at dawn, the quick brown fox jumps over the lazy dog. ".repeat(20);
        let mut workspace = workspace_with("stage.bin", &hide(&plain, 0x51, 5));
        let status = run_job(&mut workspace, "crypto.attack", json!({}));
        call(&mut workspace, "crypto.apply", json!({"candidate": {"job": status["job"]}, "output": {"new": {"label": "plain"}}})).unwrap();
        let recipe = call(&mut workspace, "history.recipe", json!({"name": "Peel"})).unwrap();
        let apply = recipe["steps"].as_array().unwrap().iter().find(|step| step["method"] == "crypto.apply").unwrap().clone();
        assert_eq!(apply["params"]["candidate"]["job"], json!({"$anchor": {"step": 1, "path": "result.job"}}), "{recipe}");
        let mut other = workspace_with("other.bin", &hide(&plain, 0xD7, 11));
        let report = call(&mut other, "recipes.run", json!({"recipe": recipe})).unwrap();
        assert!(report["stopped"].is_null(), "{report}");
        assert_eq!(call(&mut other, "bytes.read", json!({"doc": "doc-2", "start": 0, "len": 6, "encoding": "text"})).unwrap()["data"], "Attack");
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

    #[test]
    fn aes_ciphertext_decrypts_to_its_plaintext_and_opens_as_a_derived_document() {
        let key = "2b7e151628aed2a6abf7158809cf4f3c";
        let ciphertext = crate::ops::parse_hex("3ad77bb40d7a3660a89ecaf32466ef97").unwrap();
        let mut workspace = workspace_with("payload.enc", &[b"RSRC".as_slice(), &ciphertext].concat());
        let decrypted = call(&mut workspace, "crypto.decrypt", json!({"start": 4, "mode": "ecb", "key": key, "padding": "none"})).unwrap();
        assert_eq!((decrypted["alg"].as_str(), decrypted["data"].as_str()), (Some("aes-128"), Some("6bc1bee22e409f96e93d7e117393172a")), "{decrypted}");
        assert_eq!(decrypted["padding_invalid"], false);
        let padded = call(&mut workspace, "crypto.decrypt", json!({"start": 4, "mode": "ecb", "key": key})).unwrap();
        assert_eq!((padded["padding"].as_str(), padded["padding_invalid"].as_bool(), padded["output_len"].as_u64()), (Some("pkcs7"), Some(true), Some(16)), "invalid padding is said, and the bytes kept");
        let opened = call(&mut workspace, "crypto.open_decrypted", json!({"start": 4, "mode": "ecb", "key": key, "padding": "none"})).unwrap();
        assert_eq!((opened["document"]["id"].as_str(), opened["document"]["name"].as_str(), opened["document"]["len"].as_u64()), (Some("doc-2"), Some("payload.enc › AES-128-ECB@0x4"), Some(16)));
        let read = call(&mut workspace, "bytes.read", json!({"doc": "doc-2", "start": 0, "len": 16})).unwrap();
        assert_eq!(read["data"], "6bc1bee22e409f96e93d7e117393172a");
        let made = call(&mut workspace, "crypto.decrypt", json!({"doc": "doc-1", "start": 4, "mode": "ecb", "key": key, "padding": "none", "output": {"new": {"label": "plaintext"}}})).unwrap();
        assert_eq!((made["output"]["doc"].as_str(), made["output"]["label"].as_str(), made["data"].as_str()), (Some("doc-3"), Some("plaintext"), None), "one method, with output");
        call(&mut workspace, "crypto.decrypt", json!({"doc": "doc-1", "start": 4, "mode": "ecb", "key": key, "padding": "none", "output": "in_place"})).unwrap();
        assert_eq!(call(&mut workspace, "bytes.read", json!({"doc": "doc-1", "start": 4, "len": 16})).unwrap()["data"], "6bc1bee22e409f96e93d7e117393172a", "the ciphertext replaced");
    }

    #[test]
    fn a_decryption_that_cannot_be_done_is_refused_with_the_reason() {
        let mut workspace = workspace_with("payload.enc", &[0u8; 20]);
        let ragged = call(&mut workspace, "crypto.decrypt", json!({"mode": "ecb", "key": "000102030405060708090a0b0c0d0e0f"})).unwrap_err();
        assert_eq!(ragged.code, ErrorCode::InvalidParams);
        assert!(ragged.message.contains("4 bytes over"), "{}", ragged.message);
        let odd_key = call(&mut workspace, "crypto.decrypt", json!({"mode": "ctr", "key": "0001", "iv": "00"})).unwrap_err();
        assert!(odd_key.message.contains("2-byte key"), "{}", odd_key.message);
        let no_iv = call(&mut workspace, "crypto.decrypt", json!({"len": 16, "mode": "cbc", "key": "000102030405060708090a0b0c0d0e0f"})).unwrap_err();
        assert!(no_iv.message.contains("iv"), "{}", no_iv.message);
        let mismatch = call(&mut workspace, "crypto.decrypt", json!({"len": 16, "alg": "aes-256", "mode": "ecb", "key": "000102030405060708090a0b0c0d0e0f"})).unwrap_err();
        assert!(mismatch.message.contains("32-byte key"), "{}", mismatch.message);
    }
}
