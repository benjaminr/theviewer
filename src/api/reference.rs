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
    method!("reference.rfc", Read, rfc, RfcParams, RfcResult, "The plain text of an RFC, or of one of its sections, fetched from the RFC Editor once and then kept in ~/.cache/theviewer/rfc."),
    method!("reference.reload", View, reload, super::values::NoParams, ReloadResult, "Read the user's own reference notes again, and say which files could not be read."),
    method!("reference.pick_alternative", View, pick_alternative, PickAlternativeParams, PickAlternativeResult, "Take another entry in place of a format guessed from a port, EtherType or IP protocol number, for the payload at an offset; the Reference panel shows it, and the entry's notes are returned."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("reference.lookup", json!({"name": "zlib"})),
        ("reference.search", json!({"query": "compression", "limit": 3})),
        ("reference.rfc", json!({"number": 768})),
        ("reference.reload", json!({})),
        ("reference.pick_alternative", json!({"at": 0, "id": "udp"})),
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
    fn an_rfc_or_one_of_its_sections_is_given_as_text() {
        let mut workspace = workspace_with("a.bin", b"");
        let whole = call(&mut workspace, "reference.rfc", json!({"number": 768})).unwrap();
        assert!(whole["text"].as_str().unwrap().starts_with("RFC 768"));
        let section = call(&mut workspace, "reference.rfc", json!({"number": 768, "section": "2"})).unwrap();
        assert!(section["text"].as_str().unwrap().contains("The fields"), "{section}");
        assert!(!section["text"].as_str().unwrap().contains("What this RFC is for"), "{section}");
        let missing = call(&mut workspace, "reference.rfc", json!({"number": 768, "section": "9"})).unwrap();
        assert!(missing["note"].as_str().unwrap().contains("§9 was not found"));
        assert_eq!(call(&mut workspace, "reference.rfc", json!({"number": 0})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn reloading_the_notes_says_what_was_read_and_an_alternative_must_be_an_entry() {
        let mut workspace = workspace_with("a.bin", b"");
        let reloaded = call(&mut workspace, "reference.reload", json!({})).unwrap();
        assert!(reloaded["problems"].is_array());
        let picked = call(&mut workspace, "reference.pick_alternative", json!({"at": 0, "id": "dhcp"})).unwrap();
        assert_eq!((picked["entry"]["id"].clone(), picked["shown"].clone()), (json!("dhcp"), json!(false)), "nothing to show it in without the window");
        assert_eq!(call(&mut workspace, "reference.pick_alternative", json!({"at": 0, "id": "nothing"})).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn an_unknown_name_lists_the_known_ids() {
        let mut workspace = workspace_with("a.bin", b"");
        let error = call(&mut workspace, "reference.lookup", json!({"name": "no such format"})).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotFound);
        assert!(error.data.unwrap()["known_ids"].as_array().unwrap().contains(&json!("ipv4")));
    }
}

/// Parameters of `reference.rfc`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RfcParams {
    /// The RFC's number, such as 768.
    pub number: u32,
    /// A section, such as "3.1"; the whole RFC when omitted.
    #[serde(default)]
    pub section: Option<String>,
}

/// The result of `reference.rfc`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RfcResult {
    pub number: u32,
    /// The section's text, or the whole RFC's.
    pub text: String,
    /// Said when the section asked for was not found, so the whole RFC is given.
    pub note: Option<String>,
}

/// The result of `reference.reload`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReloadResult {
    /// The user's reference files that were read.
    pub user_files: usize,
    /// Those that could not be, as "path: error".
    pub problems: Vec<String>,
}

/// Parameters of `reference.pick_alternative`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PickAlternativeParams {
    /// Where the guessed payload starts.
    pub at: u64,
    /// The entry to take instead, one of the guess's alternatives.
    pub id: String,
}

/// The result of `reference.pick_alternative`.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PickAlternativeResult {
    /// The notes on the entry taken.
    pub entry: FormatReference,
    /// Whether the Reference panel showed a guess there and took the entry
    /// in its place.
    pub shown: bool,
}

/// Most bytes of an RFC downloaded.
pub const RFC_DOWNLOAD_LIMIT: usize = 4 * 1024 * 1024;

/// The text of RFC `number`, from the cache or the RFC Editor; while
/// testing, a stand-in text that needs no network.
pub fn fetch_rfc(number: u32) -> Result<String, String> {
    #[cfg(test)]
    return Ok(format!("RFC {number}\n\n1. Introduction\n\n   What this RFC is for.\n\n2. Format\n\n   The fields.\n"));
    #[cfg(not(test))]
    reference::load_rfc_text(reference::rfc_cache_dir().as_deref(), number, |url| {
        let bytes = crate::sources::fetch_url(url, RFC_DOWNLOAD_LIMIT)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    })
}

/// The part of an RFC's `text` that `section` names, with a note when it is
/// not found and the whole text is given instead.
pub fn rfc_part(text: String, section: Option<&str>) -> (String, Option<String>) {
    match section {
        None => (text, None),
        Some(section) => match reference::rfc_section(&text, section) {
            Some(shown) => (shown, None),
            None => (text, Some(format!("§{section} was not found, so the whole RFC is shown."))),
        },
    }
}

pub fn rfc(_workspace: &mut dyn Workspace, params: RfcParams) -> Result<RfcResult, ApiError> {
    if params.number == 0 {
        return Err(ApiError::invalid_params("RFCs are numbered from 1"));
    }
    let text = fetch_rfc(params.number).map_err(|error| ApiError::new(super::ErrorCode::Unavailable, format!("could not fetch RFC {}: {error}", params.number)))?;
    let (text, note) = rfc_part(text, params.section.as_deref());
    Ok(RfcResult { number: params.number, text, note })
}

pub fn reload(workspace: &mut dyn Workspace, _params: super::values::NoParams) -> Result<ReloadResult, ApiError> {
    let loaded = reference::reload_user_notes();
    if let Some(app) = workspace.window() {
        crate::panel_reference::notes_reloaded(app);
    }
    Ok(ReloadResult { user_files: loaded.user_files, problems: loaded.problems.clone() })
}

pub fn pick_alternative(workspace: &mut dyn Workspace, params: PickAlternativeParams) -> Result<PickAlternativeResult, ApiError> {
    let entry = reference::library().by_id(&params.id).cloned().ok_or_else(|| ApiError::not_found(format!("there are no reference notes with the id '{}'; reference.search finds entries", params.id)))?;
    let at = usize::try_from(params.at).unwrap_or(usize::MAX);
    let shown = workspace.window().is_some_and(|app| crate::panel_reference::pick_alternative_at(app, at, &params.id));
    Ok(PickAlternativeResult { entry, shown })
}
