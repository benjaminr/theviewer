//! `search.*`: finding hex bytes, text, UTF-16 text or integers.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values;
use super::workspace::{self, Workspace};
use super::ApiError;
use crate::search::{self, SearchMode};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("search.find", Read, find, FindParams, FindResult, "The next (or previous) occurrence of hex bytes, text, UTF-16 text or an integer from an offset."),
    method!("search.find_all", Read, find_all, FindAllParams, FindAllResult, "Every occurrence of hex bytes, text, UTF-16 text or an integer in the document, a page at a time."),
    method!("search.count", Read, count, CountParams, CountResult, "How many times hex bytes, text, UTF-16 text or an integer occur in the document, up to a cap."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("search.find", json!({"query": "fox", "mode": "text"})),
        ("search.find_all", json!({"query": "6f 78", "mode": "hex", "limit": 5})),
        ("search.count", json!({"query": "the"})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

/// Matches `search.count` stops at when no cap is given.
const DEFAULT_COUNT_CAP: usize = 100_000;

/// Parameters of `search.find`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Hex bytes such as "89 50 4E 47", text, or a decimal or 0x hex integer.
    pub query: String,
    /// How to read the query: "hex", "text" (the default), "utf16" (little-endian) or "integer".
    #[serde(default = "text_mode")]
    pub mode: SearchMode,
    /// For integers: store them little-endian (the default) or big-endian.
    #[serde(default = "little_endian")]
    pub little_endian: bool,
    /// Offset to search from: the first match at or after it, or before it when searching backwards.
    #[serde(default)]
    pub from: Option<u64>,
    /// Search towards the start of the document.
    #[serde(default)]
    pub backwards: bool,
}

/// The result of `search.find`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FindResult {
    /// Offset of the match, or nothing when there is none.
    pub at: Option<u64>,
}

/// Parameters of `search.find_all`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindAllParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Hex bytes such as "89 50 4E 47", text, or a decimal or 0x hex integer.
    pub query: String,
    /// How to read the query: "hex", "text" (the default), "utf16" (little-endian) or "integer".
    #[serde(default = "text_mode")]
    pub mode: SearchMode,
    /// For integers: store them little-endian (the default) or big-endian.
    #[serde(default = "little_endian")]
    pub little_endian: bool,
    /// Most matches to return (100 by default).
    #[serde(default)]
    pub limit: Option<usize>,
    /// The `next` cursor of the previous page.
    #[serde(default)]
    pub next: Option<String>,
}

/// The result of `search.find_all`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FindAllResult {
    /// Offsets of the matches, in document order; matches may overlap.
    pub matches: Vec<u64>,
    /// Pass back as `next` for more matches; absent after the last.
    pub next: Option<String>,
}

/// Parameters of `search.count`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CountParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Hex bytes such as "89 50 4E 47", text, or a decimal or 0x hex integer.
    pub query: String,
    /// How to read the query: "hex", "text" (the default), "utf16" (little-endian) or "integer".
    #[serde(default = "text_mode")]
    pub mode: SearchMode,
    /// For integers: store them little-endian (the default) or big-endian.
    #[serde(default = "little_endian")]
    pub little_endian: bool,
    /// Stop counting here (100000 by default), so huge files stay quick.
    #[serde(default)]
    pub cap: Option<usize>,
}

/// The result of `search.count`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CountResult {
    pub count: u64,
    /// Whether counting stopped at the cap.
    pub capped: bool,
}

fn text_mode() -> SearchMode {
    SearchMode::Text
}

fn little_endian() -> bool {
    true
}

fn needle(mode: SearchMode, query: &str, little_endian: bool) -> Result<Vec<u8>, ApiError> {
    search::needle_for(mode, query, little_endian).map_err(|message| ApiError::invalid_params(format!("the query '{query}' does not read as {}: {message}", mode.label())))
}

pub fn find(workspace: &mut dyn Workspace, params: FindParams) -> Result<FindResult, ApiError> {
    let needle = needle(params.mode, &params.query, params.little_endian)?;
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let at = if params.backwards {
        let before = params.from.map_or(document.len(), |from| from.min(document.len() as u64) as usize);
        search::find_previous(document, &needle, before)
    } else {
        let (from, _) = values::span_within(document.len(), params.from.unwrap_or(0), None)?;
        search::find_next(document, &needle, from)
    };
    Ok(FindResult { at: at.map(|at| at as u64) })
}

pub fn find_all(workspace: &mut dyn Workspace, params: FindAllParams) -> Result<FindAllResult, ApiError> {
    let needle = needle(params.mode, &params.query, params.little_endian)?;
    let limit = values::page_limit(params.limit)?;
    let mut from = match params.next.as_deref() {
        Some(cursor) => cursor.parse::<usize>().map_err(|_| ApiError::invalid_params(format!("'{cursor}' is not a cursor search.find_all returned")))?,
        None => 0,
    };
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let mut matches = Vec::new();
    let mut next = None;
    while let Some(at) = search::find_next(document, &needle, from) {
        if matches.len() == limit {
            next = Some(at.to_string());
            break;
        }
        matches.push(at as u64);
        from = at + 1;
    }
    Ok(FindAllResult { matches, next })
}

pub fn count(workspace: &mut dyn Workspace, params: CountParams) -> Result<CountResult, ApiError> {
    let needle = needle(params.mode, &params.query, params.little_endian)?;
    let cap = params.cap.unwrap_or(DEFAULT_COUNT_CAP).max(1);
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let count = search::count_matches(document, &needle, cap);
    Ok(CountResult { count: count as u64, capped: count >= cap })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::ErrorCode;
    use crate::api::test_support::call;

    #[test]
    fn the_next_and_previous_matches_are_found_from_an_offset() {
        let mut workspace = workspace_with("a.bin", b"PK..PK..PK");
        assert_eq!(call(&mut workspace, "search.find", json!({"query": "PK", "from": 1})).unwrap()["at"], 4);
        assert_eq!(call(&mut workspace, "search.find", json!({"query": "50 4b", "mode": "hex", "from": 5, "backwards": true})).unwrap()["at"], 4);
        assert_eq!(call(&mut workspace, "search.find", json!({"query": "ZIP"})).unwrap()["at"], serde_json::Value::Null);
    }

    #[test]
    fn every_match_is_listed_a_page_at_a_time() {
        let mut workspace = workspace_with("a.bin", b"aXaXaXaX");
        let first = call(&mut workspace, "search.find_all", json!({"query": "X", "limit": 3})).unwrap();
        assert_eq!(first["matches"], json!([1, 3, 5]));
        let rest = call(&mut workspace, "search.find_all", json!({"query": "X", "limit": 3, "next": first["next"]})).unwrap();
        assert_eq!((rest["matches"].clone(), rest["next"].clone()), (json!([7]), serde_json::Value::Null));
    }

    #[test]
    fn integers_are_found_in_either_byte_order_and_counted() {
        let mut workspace = workspace_with("a.bin", &[0x34, 0x12, 0x00, 0x12, 0x34]);
        assert_eq!(call(&mut workspace, "search.find", json!({"query": "0x1234", "mode": "integer"})).unwrap()["at"], 0);
        assert_eq!(call(&mut workspace, "search.find", json!({"query": "4660", "mode": "integer", "little_endian": false})).unwrap()["at"], 3);
        let counted = call(&mut workspace, "search.count", json!({"query": "12", "mode": "hex", "cap": 1})).unwrap();
        assert_eq!((counted["count"].as_u64(), counted["capped"].as_bool()), (Some(1), Some(true)));
    }

    #[test]
    fn a_query_that_does_not_read_in_its_mode_is_invalid() {
        let mut workspace = workspace_with("a.bin", b"abc");
        assert_eq!(call(&mut workspace, "search.find", json!({"query": "xyz", "mode": "hex"})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "search.find", json!({"query": "a", "mode": "regex"})).unwrap_err().code, ErrorCode::InvalidParams);
    }
}
