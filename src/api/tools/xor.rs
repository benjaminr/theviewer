//! `xor.recover_keys`: the XOR tool's guess at the keys that would turn a
//! span into text or zero padding, and the key lengths that fit it best.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs;
use crate::api::values::{self, ByteEncoding};
use crate::api::workspace::Workspace;
use crate::api::ApiError;
use crate::xor::XorCandidate;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[method!(
    "xor.recover_keys",
    Read,
    recover_keys,
    RecoverKeysParams,
    RecoveredKeys,
    "Recover single-byte and repeating XOR keys for a span (at most 1 MiB) by letter frequency, index of coincidence and the key showing through zero padding, best first, with a preview of each decode and the likely key lengths; transform.apply with {\"op\": \"xor\"} applies one."
)];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("xor.recover_keys", json!({"start": 0, "len": 256, "max_key": 8}))]
}

/// Most bytes searched for keys.
pub const XOR_LIMIT: usize = 1024 * 1024;
/// Longest key looked for when not asked.
pub const DEFAULT_MAX_KEY: usize = 32;
/// Longest key that may be asked for.
pub const MOST_MAX_KEY: usize = 256;
/// Keys proposed.
pub const KEYS_PROPOSED: usize = 12;
/// Key lengths listed.
pub const LENGTHS_LISTED: usize = 6;

/// Parameters of `xor.recover_keys`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecoverKeysParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset of the suspect bytes (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes searched, at most 1 MiB; to the end of the document (or 1 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Longest key looked for, 1 to 256 bytes (32 by default).
    #[serde(default)]
    pub max_key: Option<usize>,
}

/// One key proposed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct KeyCandidate {
    /// The key, as hex.
    pub key: String,
    /// Where the key ranks, from 1 for the best; the candidates come in this order.
    pub rank: usize,
    /// How convincing the decode is, 0 to 1: the larger of how text-like and how zero-rich it is, except that a key nearly repeating a shorter candidate that decodes about as well takes the shorter key's score. Sorting by score descending gives the order of `rank`.
    pub score: f64,
    /// Fraction of the decode that is printable.
    pub printable_fraction: f64,
    /// The first 64 decoded bytes, unprintable ones as '.'.
    pub preview: String,
    /// Why the key was proposed.
    pub reason: String,
}

/// A key length that fits the span.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct KeyLength {
    /// Length in bytes.
    pub length: usize,
    /// Index of coincidence of the columns this length gives; higher fits better.
    pub score: f64,
}

/// The result of `xor.recover_keys`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RecoveredKeys {
    /// First offset searched.
    pub start: u64,
    /// Bytes searched.
    pub len: u64,
    /// The keys proposed, best first.
    pub candidates: Vec<KeyCandidate>,
    /// The likely key lengths, best first.
    pub key_lengths: Vec<KeyLength>,
}

impl RecoveredKeys {
    /// The candidates as the XOR tab holds them.
    pub fn xor_candidates(&self) -> Vec<XorCandidate> {
        self.candidates
            .iter()
            .map(|candidate| XorCandidate {
                key: values::decode_bytes(&candidate.key, ByteEncoding::Hex).unwrap_or_default(),
                score: candidate.score,
                printable_fraction: candidate.printable_fraction,
                preview: candidate.preview.clone(),
                reason: candidate.reason.clone(),
            })
            .collect()
    }
}

pub fn recover_keys(workspace: &mut dyn Workspace, params: RecoverKeysParams) -> Result<RecoveredKeys, ApiError> {
    let max_key = params.max_key.unwrap_or(DEFAULT_MAX_KEY);
    if !(1..=MOST_MAX_KEY).contains(&max_key) {
        return Err(ApiError::invalid_params(format!("a longest key of {max_key} bytes is outside 1 to {MOST_MAX_KEY}")));
    }
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, XOR_LIMIT, "the span searched for keys")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let candidates = crate::xor::recover_keys(&bytes, max_key, KEYS_PROPOSED)
        .into_iter()
        .enumerate()
        .map(|(index, candidate)| KeyCandidate {
            key: values::encode_bytes(&candidate.key, ByteEncoding::Hex),
            rank: index + 1,
            score: candidate.score,
            printable_fraction: candidate.printable_fraction,
            preview: candidate.preview,
            reason: candidate.reason,
        })
        .collect();
    let key_lengths = crate::xor::guess_key_lengths(&bytes, max_key).into_iter().take(LENGTHS_LISTED).map(|(length, score)| KeyLength { length, score }).collect();
    Ok(RecoveredKeys { start: span.start as u64, len: span.len as u64, candidates, key_lengths })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn a_text_hidden_by_a_repeating_key_gives_the_key_back() {
        let plain = b"The quick brown fox jumps over the lazy dog, again and again and again. ".repeat(40);
        let hidden = crate::xor::apply(&plain, b"K3y", 0);
        let mut workspace = workspace_with("hidden.bin", &hidden);
        let found = call(&mut workspace, "xor.recover_keys", json!({"max_key": 8})).unwrap();
        assert_eq!(found["len"].as_u64(), Some(hidden.len() as u64));
        let keys: Vec<&str> = found["candidates"].as_array().unwrap().iter().filter_map(|candidate| candidate["key"].as_str()).collect();
        assert!(keys.contains(&"4b3379"), "{keys:?}");
        let ranks: Vec<u64> = found["candidates"].as_array().unwrap().iter().filter_map(|candidate| candidate["rank"].as_u64()).collect();
        assert_eq!(ranks, (1..=keys.len() as u64).collect::<Vec<_>>(), "{found}");
        assert!(found["key_lengths"].as_array().unwrap().iter().any(|length| length["length"] == 3), "{found}");
    }

    #[test]
    fn a_key_too_long_or_a_span_too_large_is_refused() {
        let mut workspace = workspace_with("a.bin", &vec![0x5A; 2 * 1024 * 1024]);
        assert_eq!(call(&mut workspace, "xor.recover_keys", json!({"max_key": 0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "xor.recover_keys", json!({"len": 2 * 1024 * 1024})).unwrap_err().code, ErrorCode::TooLarge);
        let found = call(&mut workspace, "xor.recover_keys", json!({})).unwrap();
        assert_eq!(found["len"].as_u64(), Some(1024 * 1024), "an omitted length stops at the limit");
    }
}
