use serde_json::{Value, json};

use super::*;
use crate::api::test_support::workspace_with;
use crate::api::{Caller, HeadlessWorkspace, call};
use crate::bus::Topic;

fn steps(workspace: &HeadlessWorkspace) -> Vec<(u64, String, String)> {
    workspace.journal().entries().map(|entry| (entry.step, entry.caller.clone(), entry.method.clone())).collect()
}

fn mcp() -> Caller {
    Caller::Mcp("claude-code".into())
}

#[test]
fn every_edit_view_change_and_job_is_a_step_by_whoever_called() {
    let mut workspace = workspace_with("a.bin", &crate::api::test_support::example_bytes());
    call(&mut workspace, &Caller::Panel, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, &mcp(), "cursor.set", json!({"offset": 4})).unwrap();
    call(&mut workspace, &Caller::Plugin("sync.lua".into()), "analysis.overview_job", json!({"max_findings": 1})).unwrap();
    call(&mut workspace, &Caller::Ask, "bytes.read", json!({"start": 0, "len": 4})).unwrap();
    call(&mut workspace, &Caller::Cli, "transform.apply", json!({"selection": {"range": [0, 2]}, "operation": {"op": "invert"}})).unwrap();
    call(&mut workspace, &Caller::Recipe("Patch".into()), "bytes.delete", json!({"start": 0, "len": 1})).unwrap();
    assert_eq!(
        steps(&workspace),
        [
            (1, "panel".to_string(), "bytes.write".to_string()),
            (2, "mcp:claude-code".to_string(), "cursor.set".to_string()),
            (3, "plugin:sync.lua".to_string(), "analysis.overview_job".to_string()),
            (5, "cli".to_string(), "transform.apply".to_string()),
            (6, "recipe:Patch".to_string(), "bytes.delete".to_string()),
        ],
        "the read took step 4 but is not a step of the journal"
    );
    let write = workspace.journal().entry(1).unwrap();
    assert_eq!((write.effect, write.doc.as_deref(), write.version_before, write.version_after), (Effect::Edit, Some("doc-1"), Some(0), Some(1)));
    assert!(write.changed_document());
    assert_eq!(write.params, json!({"start": 0, "data": "41"}));
    assert_eq!(write.result.as_ref().unwrap()["label"], "Overwrite 1 byte", "the result is kept");
    assert!(!write.description.is_empty());
    let cursor = workspace.journal().entry(2).unwrap();
    assert!(!cursor.changed_document(), "a view change leaves the bytes");
    assert_eq!(workspace.journal().entry(3).unwrap().result.as_ref().unwrap()["job"].as_str().map(|job| job.starts_with("overview")), Some(true), "the job's id is kept for later steps");
    assert_eq!(workspace.journal().entry(6).unwrap().caller(), Caller::Recipe("Patch".into()));
}

#[test]
fn a_failed_edit_is_recorded_with_its_error_and_a_failed_read_is_not() {
    let mut workspace = workspace_with("a.bin", b"abc");
    let error = call(&mut workspace, &Caller::Panel, "bytes.write", json!({"start": 2, "data": "0000"})).unwrap_err();
    call(&mut workspace, &Caller::Panel, "bytes.read", json!({"start": 9, "len": 1})).unwrap_err();
    call(&mut workspace, &Caller::Panel, "bytes.melt", json!({})).unwrap_err();
    let failed = workspace.journal().entries().next().expect("the failed edit is recorded");
    assert_eq!(failed.outcome, Outcome::Error(error));
    assert_eq!((failed.result.as_ref(), failed.version_after), (None, Some(0)));
    assert_eq!(workspace.journal().entries().len(), 1, "an unknown method is not a step");
    assert_eq!(workspace.journal().reads().len(), 0, "a failed read is not kept");
}

#[test]
fn a_call_inside_a_transaction_is_part_of_the_transaction_s_step() {
    let mut workspace = workspace_with("a.bin", b"0123456789");
    let calls = json!({"calls": [
        {"method": "bytes.write", "params": {"start": 0, "data": "41"}},
        {"method": "bytes.write", "params": {"start": 1, "data": "42"}},
    ]});
    call(&mut workspace, &Caller::Panel, "history.transaction", calls).unwrap();
    assert_eq!(steps(&workspace), [(1, "panel".to_string(), "history.transaction".to_string())]);
    call(&mut workspace, &Caller::Panel, "bytes.write", json!({"start": 2, "data": "43"})).unwrap();
    assert_eq!(workspace.journal().entries().len(), 2, "the next call is recorded again");
}

#[test]
fn moving_the_cursor_again_replaces_the_last_move_rather_than_adding_a_step() {
    let mut workspace = workspace_with("a.bin", b"0123456789");
    for offset in [1, 2, 3] {
        call(&mut workspace, &Caller::Panel, "cursor.set", json!({"offset": offset})).unwrap();
    }
    call(&mut workspace, &mcp(), "cursor.set", json!({"offset": 4})).unwrap();
    let kept: Vec<(u64, Value, u32)> = workspace.journal().entries().map(|entry| (entry.step, entry.params["offset"].clone(), entry.merged)).collect();
    assert_eq!(kept, [(3, json!(3), 2), (4, json!(4), 0)], "another caller's move is a step of its own");
    call(&mut workspace, &Caller::Panel, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, &Caller::Panel, "cursor.set", json!({"offset": 5})).unwrap();
    assert_eq!(workspace.journal().entries().len(), 4, "a move after an edit is a new step");
}

#[test]
fn a_read_a_later_step_used_is_promoted_into_the_journal_under_its_own_number() {
    let mut workspace = workspace_with("a.bin", b"..\x7e\xa5....");
    let found = call(&mut workspace, &mcp(), "search.find", json!({"query": "7ea5", "mode": "hex"})).unwrap();
    let read_step = workspace.journal().reads().last().unwrap().step;
    call(&mut workspace, &mcp(), "cursor.set", json!({"offset": 0})).unwrap();
    let offset = found["at"].as_u64().unwrap();
    let cursor = workspace.bus().cursor();
    assert!(promote(&mut workspace, read_step));
    let derived = DerivedFrom::from([("start".to_string(), Anchor::Step { step: read_step, path: "result.at".into() })]);
    crate::api::call_derived(&mut workspace, &mcp(), "bytes.write", json!({"start": offset, "data": "00"}), derived.clone()).unwrap();
    let listed: Vec<(u64, &str)> = workspace.journal().entries().map(|entry| (entry.step, entry.method.as_str())).collect();
    assert_eq!(listed, [(1, "search.find"), (2, "cursor.set"), (3, "bytes.write")], "in step order");
    let promoted = workspace.journal().entry(read_step).unwrap();
    assert_eq!((promoted.effect, promoted.description.is_empty()), (Effect::Read, false), "described once promoted");
    assert!(workspace.journal().read(read_step).is_none(), "moved out of the ring");
    assert_eq!(workspace.journal().entry(3).unwrap().derived_from, derived);
    assert!(promote(&mut workspace, read_step), "promoting twice is harmless");
    assert!(!promote(&mut workspace, 99));
    let published: Vec<u64> = workspace.bus().changed_since(cursor).messages.iter().filter_map(|message| message.payload_as::<JournalRecorded>()).map(|recorded| recorded.step).collect();
    assert_eq!(published, [read_step, 3], "the promotion is published for followers");
}

#[test]
fn provenance_given_for_a_call_that_never_ran_is_not_kept_for_the_next() {
    let mut workspace = workspace_with("a.bin", b"abc");
    let derived = DerivedFrom::from([("start".to_string(), Anchor::Param { param: "at".into() })]);
    crate::api::call_derived(&mut workspace, &Caller::Panel, "bytes.melt", json!({}), derived).unwrap_err();
    call(&mut workspace, &Caller::Panel, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    assert!(workspace.journal().entries().next().unwrap().derived_from.is_empty());
}

#[test]
fn the_recent_reads_are_bounded_and_keep_the_newest() {
    let mut workspace = workspace_with("a.bin", b"abcdef");
    *workspace.journal_mut() = Journal::with_limits(JournalLimits { max_reads: 2, ..JournalLimits::default() });
    for start in 0..4 {
        call(&mut workspace, &Caller::Panel, "bytes.read", json!({"start": start, "len": 1})).unwrap();
    }
    let kept: Vec<u64> = workspace.journal().reads().map(|read| read.step).collect();
    assert_eq!(kept, [3, 4]);
    assert_eq!(workspace.journal().last_step(), Some(4));
}

#[test]
fn the_oldest_steps_are_dropped_beyond_the_limit_and_counted() {
    let mut workspace = workspace_with("a.bin", b"abcdef");
    *workspace.journal_mut() = Journal::with_limits(JournalLimits { max_entries: 3, ..JournalLimits::default() });
    for start in 0..5 {
        call(&mut workspace, &Caller::Panel, "bytes.write", json!({"start": start, "data": "41"})).unwrap();
    }
    let kept: Vec<u64> = workspace.journal().entries().map(|entry| entry.step).collect();
    assert_eq!(kept, [3, 4, 5]);
    assert_eq!(workspace.journal().dropped(), Dropped { entries: 2, through_step: 2 });
    let since: Vec<u64> = workspace.journal().since(3).map(|entry| entry.step).collect();
    assert_eq!(since, [4, 5]);
    assert!(workspace.journal().entry(1).is_none());
}

#[test]
fn large_parameters_and_results_are_kept_as_a_summary_that_keeps_ids() {
    let mut workspace = workspace_with("a.bin", &[0u8; 4096]);
    *workspace.journal_mut() = Journal::with_limits(JournalLimits { max_params_bytes: 256, max_result_bytes: 256, ..JournalLimits::default() });
    call(&mut workspace, &Caller::Panel, "bytes.write", json!({"start": 0, "data": "ab".repeat(1000)})).unwrap();
    let write = workspace.journal().entries().next().unwrap();
    assert!(write.params_summarised);
    assert_eq!(write.params["start"], 0);
    assert!(write.params["data"].as_str().unwrap().ends_with("(2000 characters in all)"));
    let matches = call(&mut workspace, &Caller::Panel, "search.find_all", json!({"query": "00", "mode": "hex", "limit": 100})).unwrap();
    assert!(matches["matches"].as_array().unwrap().len() > 32);
    let read = workspace.journal().reads().last().unwrap();
    assert!(read.result_summarised);
    let kept = read.result.as_ref().unwrap()["matches"].as_array().unwrap();
    assert_eq!(kept.len(), 33, "32 matches and a note of how many more");
}

#[test]
fn each_step_is_published_on_journal_recorded() {
    let mut workspace = workspace_with("a.bin", b"abc");
    let cursor = workspace.bus().cursor();
    call(&mut workspace, &mcp(), "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, &mcp(), "bytes.write", json!({"start": 9, "data": "41"})).unwrap_err();
    let changes = workspace.bus().changed_since(cursor);
    let recorded: Vec<(&JournalRecorded, Option<&str>)> = changes
        .messages
        .iter()
        .filter(|message| message.topic() == Topic::JournalRecorded)
        .map(|message| (message.payload_as::<JournalRecorded>().unwrap(), message.draft.document.as_deref()))
        .collect();
    assert_eq!(recorded.len(), 2);
    let (first, document) = recorded[0];
    assert_eq!((first.step, first.method.as_str(), first.caller.as_str(), first.ok, document), (1, "bytes.write", "mcp:claude-code", true, Some("doc-1")));
    assert_eq!(first.description, workspace.journal().entry(1).unwrap().description);
    assert!(!recorded[1].0.ok, "a failed step is published as failed");
}

#[test]
fn the_session_header_hashes_each_document_once_and_names_the_plugins() {
    let mut workspace = workspace_with("a.bin", b"abc");
    call(&mut workspace, &Caller::Panel, "bytes.read", json!({"start": 0, "len": 1})).unwrap();
    call(&mut workspace, &Caller::Panel, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    let session = workspace.journal().session();
    assert_eq!(session.documents.len(), 1, "noted the first time only");
    assert_eq!(session.documents[0].file, FileIdentity { name: "a.bin".into(), size: 3, sha256: Some(sha256_hex(b"abc")) });
    assert_eq!(session.api_version, crate::api::API_VERSION);
    assert!(session.started_at.ends_with('Z') && session.started_at.len() == 20, "{}", session.started_at);

    let mut host = crate::plugins::LuaHost::new();
    let source = "theviewer.register_detector{ id = 'nothing', name = 'Nothing', scan = function(window) return {} end }";
    host.load_source("nothing.lua", source).unwrap();
    workspace.journal_mut().note_plugins(plugins_of(&host));
    assert_eq!(workspace.journal().session().plugins, [RecordedPlugin { name: "nothing.lua".into(), sha256: sha256_hex(source.as_bytes()) }]);
}

#[test]
fn a_journal_entry_is_written_as_the_design_shows_and_reads_back() {
    let entry = JournalEntry {
        step: 14,
        at: "2026-10-06T14:02:11Z".into(),
        caller: "panel".into(),
        method: "packets.sets.create".into(),
        effect: Effect::View,
        description: "Split 4096 bytes at 0x100 into packets by a length field".into(),
        params: json!({"doc": "doc-1", "from": "length_field", "start": 256, "len": 4096}),
        params_summarised: false,
        doc: Some("doc-1".into()),
        version_before: Some(412),
        version_after: Some(412),
        outcome: Outcome::Ok,
        result: Some(json!({"set": "set-2", "frames": 61})),
        result_summarised: false,
        derived_from: DerivedFrom::from([("start".to_string(), Anchor::Step { step: 12, path: "result.matches[0].offset".into() })]),
        merged: 0,
    };
    let written = serde_json::to_value(&entry).unwrap();
    assert_eq!(written["derived_from"], json!({"start": {"step": 12, "path": "result.matches[0].offset"}}));
    assert_eq!(written["outcome"], "ok");
    assert!(written.get("merged").is_none() && written.get("params_summarised").is_none(), "defaults are left out");
    assert_eq!(serde_json::from_value::<JournalEntry>(written).unwrap(), entry);
    let failed = Outcome::Error(crate::api::ApiError::out_of_range("past the end"));
    assert_eq!(serde_json::to_value(&failed).unwrap(), json!({"error": {"code": "out_of_range", "message": "past the end"}}));
    let schema = schemars::schema_for!(JournalEntry).to_value();
    for field in ["step", "at", "caller", "method", "params", "doc", "version_before", "version_after", "result", "derived_from", "effect", "outcome", "description"] {
        assert!(schema["properties"][field].is_object(), "{field} is in the schema");
    }
}

#[test]
fn timestamps_are_rfc_3339_in_utc() {
    let moment = UNIX_EPOCH + std::time::Duration::from_secs(1_791_295_331);
    assert_eq!(timestamp(moment), "2026-10-06T14:02:11Z");
}

mod window {
    use serde_json::json;

    use crate::api::{Caller, ErrorCode, Policy, Workspace, call};
    use crate::app::{Launch, ViewerApp};

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        app
    }

    #[test]
    fn the_person_s_action_is_a_step_of_the_history_by_panel_with_what_it_did() {
        let mut app = app_with(&[0x0F; 8]);
        app.restore_selection(2, 3);
        let invert = crate::commands::commands().into_iter().find(|command| command.id == "edit.invert").unwrap();
        (invert.run)(&mut app, &eframe::egui::Context::default());
        let history = call(&mut app, &Caller::Mcp("claude-code".into()), "history.list", json!({})).unwrap();
        let last = history["entries"].as_array().unwrap().last().unwrap().clone();
        assert_eq!((last["caller"].as_str(), last["method"].as_str()), (Some("panel"), Some("transform.apply")));
        assert_eq!(last["description"], "Invert 3 bytes at 0x2");
        assert_ne!(last["version_before"], last["version_after"]);
    }

    #[test]
    fn a_client_s_denied_edit_is_recorded_as_refused() {
        let mut app = app_with(b"abc");
        app.preferences.permissions.insert("mcp:claude-code".into(), Policy::Deny);
        app.preferences.permissions.insert("ask".into(), Policy::Ask);
        let refused = call(&mut app, &Caller::Mcp("claude-code".into()), "bytes.write", json!({"start": 0, "data": "41"})).unwrap_err();
        assert_eq!(refused.code, ErrorCode::ReadOnly);
        call(&mut app, &Caller::Ask, "bytes.write", json!({"start": 0, "data": "41"})).unwrap_err();
        let entries: Vec<_> = app.journal().entries().map(|entry| (entry.caller.clone(), entry.outcome.is_ok())).collect();
        assert_eq!(entries, [("mcp:claude-code".to_string(), false)], "a call waiting to be confirmed is recorded when it runs, not before");
    }

    #[test]
    fn the_window_notes_the_plugins_it_loads() {
        let mut app = app_with(b"abc");
        app.load_plugin_source("quiet.lua", "theviewer.log('hello')").unwrap();
        assert!(app.journal.session().plugins.iter().any(|plugin| plugin.name == "quiet.lua"));
    }
}
