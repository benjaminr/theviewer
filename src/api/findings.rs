//! `findings.*`: what the detectors recognise in a span.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values;
use super::workspace::{self, Workspace};
use super::ApiError;
use crate::patterns;
use crate::plugin::{Category, Finding, ScanContext};

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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::{ErrorCode, call};

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
}
