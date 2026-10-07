//! `history.list`, `history.entry` and `history.session`: the session's
//! journal of calls, as the History tab and clients read it.
//!
//! Every edit, view change and job, by every caller, is a step of the
//! journal (see [`crate::journal`]); reads are kept for a while in case a
//! later step cites one. `history.undo`, `history.redo` and
//! `history.transaction`, which act on a document's undo steps, are in
//! `edits.rs`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ApiError;
use super::values::{self, NoParams};
use super::workspace::Workspace;
use crate::journal::{Dropped, JournalEntry, JournalSession};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("history.list", Read, list, ListParams, HistoryList, "The session's journal: each edit, view change and job made through the API, by any caller, in order, with its parameters, result, outcome and a description; optionally the recent reads too. Pass back next as since to follow it."),
    method!("history.entry", Read, entry, EntryParams, crate::journal::JournalEntry, "One step of the journal, or one recent read, in full."),
    method!("history.session", Read, session, super::values::NoParams, crate::journal::JournalSession, "What the journal's session ran with: when it started, the API version, the plugins loaded with their hashes, and each document as first seen, with its size and SHA-256."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        // A step to list: the first call of the session.
        ("bytes.write", json!({"start": 0, "data": "00"})),
        ("history.list", json!({"limit": 10, "include_reads": true})),
        ("history.entry", json!({"step": 1})),
        ("history.session", json!({})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

/// Parameters of `history.list`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListParams {
    /// List the steps after this one (a `next` from before); from the
    /// first when omitted.
    #[serde(default)]
    pub since: Option<u64>,
    /// Most entries to return (100 when omitted).
    #[serde(default)]
    pub limit: Option<usize>,
    /// Also list the recent reads still held, whose effect is `read`.
    #[serde(default)]
    pub include_reads: bool,
}

/// The result of `history.list`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HistoryList {
    /// The entries, in step order.
    pub entries: Vec<JournalEntry>,
    /// The last step listed, to pass as `since` for the entries after it;
    /// none when this is all there is now.
    pub next: Option<u64>,
    /// The last step recorded or read in the session.
    pub last_step: Option<u64>,
    /// Changes whenever anything recorded changes (a read promoted into the
    /// journal takes its own, earlier, step number).
    pub revision: u64,
    /// The oldest entries the journal no longer holds.
    pub dropped: Dropped,
}

/// Parameters of `history.entry`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntryParams {
    /// The step's number.
    pub step: u64,
}

pub fn list(workspace: &mut dyn Workspace, params: ListParams) -> Result<HistoryList, ApiError> {
    let limit = values::page_limit(params.limit)?;
    let journal = workspace.journal();
    let since = params.since.unwrap_or(0);
    let mut entries: Vec<&JournalEntry> = journal.since(since).collect();
    if params.include_reads {
        entries.extend(journal.reads().filter(|read| read.step > since));
        entries.sort_by_key(|entry| entry.step);
    }
    let more = entries.len() > limit;
    let entries: Vec<JournalEntry> = entries.into_iter().take(limit).cloned().collect();
    let next = if more { entries.last().map(|entry| entry.step) } else { None };
    Ok(HistoryList { entries, next, last_step: journal.last_step(), revision: journal.revision(), dropped: journal.dropped() })
}

pub fn entry(workspace: &mut dyn Workspace, params: EntryParams) -> Result<JournalEntry, ApiError> {
    let journal = workspace.journal();
    if let Some(entry) = journal.entry(params.step).or_else(|| journal.read(params.step)) {
        return Ok(entry.clone());
    }
    let why = if params.step <= journal.dropped().through_step { "it was dropped to keep the journal within its limits" } else { "it is not a step of this session, or a read no longer held" };
    Err(ApiError::not_found(format!("there is no step {}: {why}; history.list shows the steps held", params.step)))
}

pub fn session(workspace: &mut dyn Workspace, _params: NoParams) -> Result<JournalSession, ApiError> {
    Ok(workspace.journal().session().clone())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::{call, workspace_with};
    use crate::api::{Caller, ErrorCode};

    #[test]
    fn the_history_lists_each_step_in_order_and_pages_through_them() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        for start in 0..3 {
            call(&mut workspace, "bytes.write", json!({"start": start, "data": "41"})).unwrap();
        }
        let first = call(&mut workspace, "history.list", json!({"limit": 2})).unwrap();
        let steps: Vec<u64> = first["entries"].as_array().unwrap().iter().map(|entry| entry["step"].as_u64().unwrap()).collect();
        assert_eq!(steps, [1, 2]);
        assert_eq!(first["entries"][0]["description"], "Overwrite 1 byte at 0x0 with 41");
        assert_eq!(first["next"], 2);
        let rest = call(&mut workspace, "history.list", json!({"since": first["next"]})).unwrap();
        assert_eq!(rest["entries"].as_array().unwrap().len(), 1);
        assert_eq!((rest["entries"][0]["step"].as_u64(), &rest["next"]), (Some(3), &serde_json::Value::Null));
        assert_eq!(rest["last_step"], 3);
    }

    #[test]
    fn reads_are_listed_only_when_asked_for_and_reading_the_history_is_not_recorded() {
        let mut workspace = workspace_with("a.bin", b"0123456789");
        call(&mut workspace, "bytes.read", json!({"start": 0, "len": 2})).unwrap();
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        call(&mut workspace, "history.session", json!({})).unwrap();
        let without = call(&mut workspace, "history.list", json!({})).unwrap();
        assert_eq!(without["entries"].as_array().unwrap().len(), 1);
        assert_eq!(without["entries"][0]["step"], 2, "the read took step 1");
        let with = call(&mut workspace, "history.list", json!({"include_reads": true})).unwrap();
        let listed: Vec<(u64, &str)> = with["entries"].as_array().unwrap().iter().map(|entry| (entry["step"].as_u64().unwrap(), entry["method"].as_str().unwrap())).collect();
        assert_eq!(listed, [(1, "bytes.read"), (2, "bytes.write")], "history.* reads are not among them");
        assert_eq!(call(&mut workspace, "history.entry", json!({"step": 1})).unwrap()["effect"], "read");
    }

    #[test]
    fn an_entry_not_held_is_not_found() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let missing = call(&mut workspace, "history.entry", json!({"step": 9})).unwrap_err();
        assert_eq!(missing.code, ErrorCode::NotFound);
        assert!(missing.message.contains("history.list"), "{}", missing.message);
    }

    #[test]
    fn the_session_header_names_the_api_version_and_each_document_as_first_seen() {
        let mut workspace = workspace_with("flight.bin", b"abc");
        call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
        let session = crate::api::call(&mut workspace, &Caller::Mcp("claude-code".into()), "history.session", json!({})).unwrap();
        assert_eq!(session["api_version"], crate::api::API_VERSION);
        assert_eq!(session["documents"][0]["file"], json!({"name": "flight.bin", "size": 3, "sha256": crate::journal::sha256_hex(b"abc")}), "hashed before the edit");
        assert_eq!(session["documents"][0]["version"], 0);
    }
}
