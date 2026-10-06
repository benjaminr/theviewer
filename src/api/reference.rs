//! `reference.*`: the app's notes on formats and protocols.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values;
use super::workspace::Workspace;
use super::ApiError;
use crate::reference::{self, FormatReference};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("reference.lookup", Read, lookup, LookupParams, LookupResult, "The reference notes on a format or protocol, by id, finding id, layer name, port (udp/67) or number (port, IP protocol or EtherType): layout, field meanings and specifications."),
    method!("reference.search", Read, search, SearchParams, SearchResult, "Reference entries whose notes mention every word of a query, or that a port or number names."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("reference.lookup", json!({"name": "zlib"})),
        ("reference.search", json!({"query": "compression", "limit": 3})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

/// Parameters of `reference.lookup`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LookupParams {
    /// A format id ("ipv4", "png"), finding id, packet layer name, port ("udp/67") or number (a port, IP protocol number or EtherType).
    pub name: String,
}

/// The result of `reference.lookup`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LookupResult {
    /// The entries the name stands for: one for an id or key, perhaps several for a port or number.
    pub entries: Vec<FormatReference>,
}

/// Parameters of `reference.search`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchParams {
    /// Words the notes must all mention, a port such as "tcp/502", or a number; every entry when empty.
    #[serde(default)]
    pub query: String,
    /// Most entries to return (100 by default).
    #[serde(default)]
    pub limit: Option<usize>,
    /// The `next` cursor of the previous page.
    #[serde(default)]
    pub next: Option<String>,
}

/// One entry in a list of matches.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EntrySummary {
    /// Pass to reference.lookup for the full notes.
    pub id: String,
    pub name: String,
    pub summary: String,
    pub group: Option<String>,
}

/// The result of `reference.search`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SearchResult {
    pub entries: Vec<EntrySummary>,
    /// Pass back as `next` for more entries; absent after the last.
    pub next: Option<String>,
}

pub fn lookup(_workspace: &mut dyn Workspace, params: LookupParams) -> Result<LookupResult, ApiError> {
    let library = reference::library();
    let entries: Vec<FormatReference> = library.matching(&params.name).into_iter().cloned().collect();
    if entries.is_empty() {
        let known: Vec<&str> = library.entries().iter().map(|entry| entry.id.as_str()).collect();
        return Err(ApiError::not_found(format!("there are no reference notes for '{}'; reference.search finds entries by words, and data.known_ids lists every id", params.name.trim()))
            .with_data(serde_json::json!({ "known_ids": known })));
    }
    Ok(LookupResult { entries })
}

pub fn search(_workspace: &mut dyn Workspace, params: SearchParams) -> Result<SearchResult, ApiError> {
    let found: Vec<EntrySummary> = reference::library()
        .search(&params.query)
        .into_iter()
        .map(|entry| EntrySummary { id: entry.id.clone(), name: entry.name.clone(), summary: entry.summary.clone(), group: entry.group.clone() })
        .collect();
    let (entries, next) = values::page(found, params.next.as_deref(), params.limit)?;
    Ok(SearchResult { entries, next })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::ErrorCode;
    use crate::api::test_support::call;

    #[test]
    fn notes_are_found_by_id_by_port_and_by_words() {
        let mut workspace = workspace_with("a.bin", b"");
        let udp = call(&mut workspace, "reference.lookup", json!({"name": "udp"})).unwrap();
        assert_eq!(udp["entries"][0]["id"], "udp");
        assert!(udp["entries"][0]["specs"][0]["document"].as_str().unwrap().contains("RFC"), "{udp}");
        let dhcp = call(&mut workspace, "reference.lookup", json!({"name": "udp/67"})).unwrap();
        assert!(dhcp["entries"].as_array().unwrap().iter().any(|entry| entry["id"] == "dhcp"), "{dhcp}");
        let searched = call(&mut workspace, "reference.search", json!({"query": "datagram", "limit": 1})).unwrap();
        assert_eq!(searched["entries"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn an_unknown_name_lists_the_known_ids() {
        let mut workspace = workspace_with("a.bin", b"");
        let error = call(&mut workspace, "reference.lookup", json!({"name": "no such format"})).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotFound);
        assert!(error.data.unwrap()["known_ids"].as_array().unwrap().contains(&json!("ipv4")));
    }
}
