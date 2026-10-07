//! `findings.*`: what the detectors recognise in a span, and findings a
//! caller publishes on the bus for every tool to show.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values;
use super::permissions::Caller;
use super::workspace::{self, Workspace};
use super::ApiError;
use crate::bus::topics::FindingsPublished;
use crate::bus::{Draft, Payload};
use crate::patterns;
use crate::plugin::{Category, Finding, ScanContext};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("findings.query", Read, query, QueryParams, QueryResult, "Run the detectors over a span and list what they recognise (signatures, compressed streams, counters, timestamps, text, structures), filtered by category, confidence and producer."),
    method!("findings.publish", Analysis, caller publish, PublishParams, PublishResult, "Publish findings about a document on the bus as the caller's, for the views, Findings and every other tool to show; they replace the caller's earlier ones under the same key.").reverses(crate::api::Reverse::PublishFindings),
    method!("findings.retract", Analysis, caller retract, RetractParams, PublishResult, "Withdraw the findings the caller published under a key.").reverses(crate::api::Reverse::RetractFindings),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("findings.query", json!({"min_confidence": 0.0, "categories": ["compressed", "text"]})),
        ("findings.publish", json!({"findings": [{"id": "x", "source": "test", "category": "custom", "start": 0, "len": 4, "title": "", "detail": "", "confidence": 1.0, "fields": []}]})),
        ("findings.retract", json!({})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

/// Findings below this confidence are chance matches, left out by default.
const DEFAULT_MIN_CONFIDENCE: f32 = 0.5;

/// Parameters of `findings.query`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset scanned (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes scanned, at most 16 MiB; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Only findings of these categories, such as "compressed" or "timestamp".
    #[serde(default)]
    pub categories: Option<Vec<Category>>,
    /// Only findings at least this confident, 0 to 1 (0.5 by default).
    #[serde(default)]
    pub min_confidence: Option<f32>,
    /// Only findings from these producers (a finding's `source`, such as "catalogue").
    #[serde(default)]
    pub producers: Option<Vec<String>>,
    /// Most findings to return (100 by default).
    #[serde(default)]
    pub limit: Option<usize>,
    /// The `next` cursor of the previous page.
    #[serde(default)]
    pub next: Option<String>,
}

/// The result of `findings.query`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct QueryResult {
    /// Findings in document order, overlaps resolved as the views show them.
    pub findings: Vec<Finding>,
    /// Pass back as `next` for more findings; absent after the last.
    pub next: Option<String>,
}

pub fn query(workspace: &mut dyn Workspace, params: QueryParams) -> Result<QueryResult, ApiError> {
    let (doc, document) = workspace::document(workspace, params.doc.as_deref())?;
    let document_len = document.len();
    let (start, len) = values::span_within(document_len, params.start, params.len)?;
    values::check_call_size(len)?;
    let window = document.read_range(start, len);
    let strides = workspace.view(&doc).and_then(|view| view.record_stride).into_iter().collect();
    let context = ScanContext { base: start, document_len, strides };
    let mut found = workspace.registry().scan(&window, &context);
    patterns::resolve_overlaps(&mut found);
    let min_confidence = params.min_confidence.unwrap_or(DEFAULT_MIN_CONFIDENCE);
    found.retain(|finding| {
        finding.confidence >= min_confidence
            && params.categories.as_ref().is_none_or(|categories| categories.contains(&finding.category))
            && params.producers.as_ref().is_none_or(|producers| producers.contains(&finding.source))
    });
    found.sort_by_key(|finding| (finding.start, finding.len));
    let (findings, next) = values::page(found, params.next.as_deref(), params.limit)?;
    Ok(QueryResult { findings, next })
}

/// Most findings one `findings.publish` may carry.
const MOST_PUBLISHED: usize = 10_000;

/// Parameters of `findings.publish`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// The findings, in document offsets; they replace those the caller published before under the same key.
    pub findings: Vec<Finding>,
    /// Tells apart several sets of findings one caller keeps (empty by default).
    #[serde(default)]
    pub key: String,
}

/// Parameters of `findings.retract`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetractParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// The key the findings were published under (empty by default).
    #[serde(default)]
    pub key: String,
}

/// The result of `findings.publish` and `findings.retract`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PublishResult {
    /// Id of the document.
    pub doc: String,
    /// Who the findings are published as, such as "mcp:claude-code".
    pub producer: String,
    /// Findings published (none for a retraction).
    pub findings: usize,
}

/// The `findings.published` message for `findings` about document `doc`, as `caller`'s.
fn findings_draft(workspace: &mut dyn Workspace, caller: &Caller, doc: &str, key: String, findings: Vec<Finding>) -> Result<Draft, ApiError> {
    let version = workspace::info(workspace, doc)?.version;
    let mut draft = Draft::new(caller.producer(), Payload::FindingsPublished(FindingsPublished { findings: Vec::new() })).about(doc, version).key(key);
    if let Some(start) = findings.iter().map(|finding| finding.start).min() {
        let end = findings.iter().map(Finding::end).max().unwrap_or(start);
        draft = draft.span(start, end - start);
    }
    draft.payload = Payload::FindingsPublished(FindingsPublished { findings });
    Ok(draft)
}

pub fn publish(workspace: &mut dyn Workspace, caller: &Caller, params: PublishParams) -> Result<PublishResult, ApiError> {
    if params.findings.len() > MOST_PUBLISHED {
        return Err(ApiError::too_large(format!("{} findings is over the limit of {MOST_PUBLISHED} for one call", params.findings.len())));
    }
    let doc = workspace::resolve(workspace, params.doc.as_deref())?;
    let len = workspace::info(workspace, &doc)?.len as usize;
    if let Some(outside) = params.findings.iter().find(|finding| finding.end() > len) {
        return Err(ApiError::out_of_range(format!("the finding '{}' at {:#x} runs past the end of the document ({len} bytes)", outside.id, outside.start)));
    }
    let count = params.findings.len();
    let draft = findings_draft(workspace, caller, &doc, params.key, params.findings)?;
    workspace.bus().publish(draft);
    Ok(PublishResult { doc, producer: caller.producer(), findings: count })
}

pub fn retract(workspace: &mut dyn Workspace, caller: &Caller, params: RetractParams) -> Result<PublishResult, ApiError> {
    let doc = workspace::resolve(workspace, params.doc.as_deref())?;
    let draft = findings_draft(workspace, caller, &doc, params.key, Vec::new())?.retraction();
    workspace.bus().publish(draft);
    Ok(PublishResult { doc, producer: caller.producer(), findings: 0 })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::ErrorCode;
    use crate::api::test_support::call;

    fn file_with_gzip() -> (Vec<u8>, usize) {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&b"theviewer finds compressed streams ".repeat(40)).unwrap();
        let mut bytes = vec![0x11; 300];
        let at = bytes.len();
        bytes.extend(encoder.finish().unwrap());
        bytes.extend([0x22; 300]);
        (bytes, at)
    }

    #[test]
    fn the_detectors_find_a_compressed_stream_in_a_span() {
        let (bytes, at) = file_with_gzip();
        let mut workspace = workspace_with("a.bin", &bytes);
        let found = call(&mut workspace, "findings.query", json!({"categories": ["compressed"]})).unwrap();
        let findings = found["findings"].as_array().unwrap();
        assert!(findings.iter().any(|finding| finding["start"] == at && finding["category"] == "compressed"), "{found}");
        let none = call(&mut workspace, "findings.query", json!({"start": 0, "len": 200, "categories": ["compressed"]})).unwrap();
        assert!(none["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn findings_come_a_page_at_a_time() {
        let (bytes, _) = file_with_gzip();
        let mut workspace = workspace_with("a.bin", &bytes);
        let all = call(&mut workspace, "findings.query", json!({"min_confidence": 0.0})).unwrap();
        let total = all["findings"].as_array().unwrap().len();
        let first = call(&mut workspace, "findings.query", json!({"min_confidence": 0.0, "limit": 1})).unwrap();
        assert_eq!(first["findings"].as_array().unwrap().len(), total.min(1));
        assert_eq!(first["next"].is_string(), total > 1, "a cursor is given exactly when more findings follow");
        assert_eq!(call(&mut workspace, "findings.query", json!({"categories": ["melted"]})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn published_findings_are_kept_as_the_callers_until_retracted() {
        let mut workspace = workspace_with("a.bin", &[0u8; 64]);
        let caller = crate::api::Caller::Plugin("sync_word.lua".into());
        let finding = json!({"id": "sync", "source": "sync_word", "category": "protocol", "start": 8, "len": 2, "title": "Sync word", "detail": "", "confidence": 0.9, "fields": []});
        let published = crate::api::call(&mut workspace, &caller, "findings.publish", json!({"findings": [finding], "key": "sync"})).unwrap();
        assert_eq!(published["producer"], "plugin:sync_word.lua");
        let facts = call(&mut workspace, "events.facts", json!({"topic": "findings.published", "producer": "plugin:sync_word.lua"})).unwrap();
        assert_eq!(facts["facts"][0]["span"], json!({"start": 8, "len": 2}));
        assert_eq!(facts["facts"][0]["key"], "sync");
        crate::api::call(&mut workspace, &caller, "findings.retract", json!({"key": "sync"})).unwrap();
        let facts = call(&mut workspace, "events.facts", json!({"topic": "findings.published", "producer": "plugin:sync_word.lua"})).unwrap();
        assert!(facts["facts"].as_array().unwrap().is_empty());
        let outside = json!({"id": "x", "source": "x", "category": "custom", "start": 60, "len": 8, "title": "", "detail": "", "confidence": 1.0, "fields": []});
        assert_eq!(call(&mut workspace, "findings.publish", json!({"findings": [outside]})).unwrap_err().code, ErrorCode::OutOfRange);
    }
}
