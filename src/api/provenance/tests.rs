use serde_json::{Value, json};

use crate::api::test_support::{call, workspace_with};
use crate::api::{self, Caller, ErrorCode, Workspace};
use crate::journal::anchors::{Anchor, Needle};
use crate::journal::DerivedFrom;

/// A document with "PK" at 4 and 20, a search for it (a read, step 1), and
/// the second match selected (step 2).
fn searched_and_selected() -> crate::api::HeadlessWorkspace {
    let mut bytes = vec![0u8; 32];
    bytes[4..6].copy_from_slice(b"PK");
    bytes[20..22].copy_from_slice(b"PK");
    let mut workspace = workspace_with("a.bin", &bytes);
    call(&mut workspace, "search.find_all", json!({"query": "PK"})).unwrap();
    call(&mut workspace, "selection.set", json!({"selection": {"range": [20, 2]}})).unwrap();
    workspace
}

fn derived_from(workspace: &dyn Workspace, step: u64) -> DerivedFrom {
    workspace.journal().entry(step).expect("a step").derived_from.clone()
}

#[test]
fn a_literal_cited_from_an_earlier_read_brings_that_read_into_the_journal() {
    let mut workspace = searched_and_selected();
    assert!(workspace.journal().entry(1).is_none(), "the search is a read");
    let made = call(&mut workspace, "history.make_anchor", json!({"step": 2, "path": "selection.range[0]", "anchor": {"step": 1, "path": "result.matches[1]"}})).unwrap();
    assert_eq!((made["value"].clone(), made["replaced"].clone()), (json!(20), Value::Null));
    assert_eq!(derived_from(&workspace, 2)["selection.range[0]"], Anchor::Step { step: 1, path: "result.matches[1]".into() });
    assert_eq!(workspace.journal().entry(1).map(|entry| entry.method.as_str()), Some("search.find_all"), "the cited read is a step now");
    let listed = call(&mut workspace, "history.list", json!({})).unwrap();
    assert_eq!(listed["entries"].as_array().unwrap().len(), 2, "editing the journal is not a step itself");
}

#[test]
fn an_anchor_must_stand_for_a_literal_the_step_was_given() {
    let mut workspace = searched_and_selected();
    let anchor = json!({"find": {"text": "PK"}, "nth": 1});
    let missing = call(&mut workspace, "history.make_anchor", json!({"step": 2, "path": "selection.range[5]", "anchor": anchor})).unwrap_err();
    assert_eq!(missing.code, ErrorCode::NotFound);
    let no_step = call(&mut workspace, "history.make_anchor", json!({"step": 9, "path": "start", "anchor": anchor})).unwrap_err();
    assert_eq!(no_step.code, ErrorCode::NotFound);
    let later = call(&mut workspace, "history.make_anchor", json!({"step": 2, "path": "selection.range[0]", "anchor": {"step": 2, "path": "result.ranges"}})).unwrap_err();
    assert!(later.message.contains("earlier step"), "{}", later.message);
    let absent = call(&mut workspace, "history.make_anchor", json!({"step": 2, "path": "selection.range[0]", "anchor": {"step": 1, "path": "result.matches[7]"}})).unwrap_err();
    assert_eq!(absent.code, ErrorCode::NotFound);
    call(&mut workspace, "bytes.write", json!({"doc": "current", "start": 0, "data": "41"})).unwrap();
    let doc = call(&mut workspace, "history.make_anchor", json!({"step": 3, "path": "doc", "anchor": {"param": "file"}})).unwrap_err();
    assert_eq!(doc.code, ErrorCode::InvalidParams);
}

#[test]
fn a_literal_made_a_parameter_is_declared_with_its_type_default_and_description() {
    let mut workspace = searched_and_selected();
    let made = call(&mut workspace, "history.make_parameter", json!({"step": 2, "path": "selection.range[1]", "name": "length", "description": "Bytes to select"})).unwrap();
    assert_eq!(made["parameter"], json!({"type": "integer", "description": "Bytes to select", "default": 2}));
    assert_eq!(made["anchor"], json!({"param": "length"}));
    let recipe = call(&mut workspace, "history.recipe", json!({"name": "Select"})).unwrap();
    assert_eq!(recipe["parameters"]["length"]["description"], "Bytes to select");
    assert_eq!(recipe["steps"][0]["params"]["selection"]["range"][1], json!({"$anchor": {"param": "length"}}));
    let wrong = call(&mut workspace, "history.make_parameter", json!({"step": 2, "path": "selection.range[0]", "name": "start", "type": "string"})).unwrap_err();
    assert_eq!(wrong.code, ErrorCode::InvalidParams);
    let clash = call(&mut workspace, "history.make_parameter", json!({"step": 2, "path": "selection.range[0]", "name": "length", "type": "number"})).unwrap_err();
    assert!(clash.message.contains("already"), "{}", clash.message);
    let unnamed = call(&mut workspace, "history.make_parameter", json!({"step": 2, "path": "selection.range[0]", "name": "a.b"})).unwrap_err();
    assert_eq!(unnamed.code, ErrorCode::InvalidParams);
}

#[test]
fn clearing_an_anchor_leaves_the_literal_for_the_recipe() {
    let mut workspace = searched_and_selected();
    call(&mut workspace, "history.make_anchor", json!({"step": 2, "path": "selection.range[0]", "anchor": {"find": {"text": "PK"}, "nth": 1}})).unwrap();
    let cleared = call(&mut workspace, "history.clear_anchor", json!({"step": 2, "path": "selection.range[0]"})).unwrap();
    assert_eq!(cleared["replaced"], json!({"find": {"text": "PK"}, "nth": 1}));
    assert!(derived_from(&workspace, 2).is_empty());
    let recipe = call(&mut workspace, "history.recipe", json!({"name": "Select"})).unwrap();
    assert_eq!(recipe["steps"][0]["params"]["selection"]["range"], json!([20, 2]));
}

#[test]
fn a_literal_equal_to_a_search_match_is_offered_the_match_first_and_the_step_after() {
    let mut workspace = searched_and_selected();
    let suggested = call(&mut workspace, "history.suggest_anchors", json!({"step": 2, "path": "selection.range[0]"})).unwrap();
    let anchors: Vec<Value> = suggested["literals"][0]["suggestions"].as_array().unwrap().iter().map(|suggestion| suggestion["anchor"].clone()).collect();
    assert_eq!(anchors.first(), Some(&json!({"find": {"text": "PK"}, "nth": 1})), "{suggested}");
    assert!(anchors.contains(&json!({"step": 1, "path": "result.matches[1]"})), "{suggested}");
    let all = call(&mut workspace, "history.suggest_anchors", json!({"step": 2})).unwrap();
    let paths: Vec<&str> = all["literals"].as_array().unwrap().iter().map(|literal| literal["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["selection.range[0]", "selection.range[1]"]);
    let length = &all["literals"][1]["suggestions"];
    assert!(length.as_array().unwrap().iter().any(|suggestion| suggestion["anchor"] == json!({"find": {"text": "PK"}, "nth": 1, "part": "len"})), "{length}");
}

#[test]
fn a_literal_equal_to_where_a_finding_starts_or_the_selection_was_is_offered_those() {
    let mut bytes = vec![0u8; 16];
    bytes.extend(crate::api::test_support::example_bytes());
    let mut workspace = workspace_with("a.bin", &bytes);
    let found = call(&mut workspace, "findings.query", json!({})).unwrap();
    let first = found["findings"][0].clone();
    let start = first["start"].as_u64().unwrap();
    call(&mut workspace, "selection.set", json!({"selection": {"range": [start, 4]}})).unwrap();
    call(&mut workspace, "cursor.set", json!({"offset": start})).unwrap();
    let step = workspace.journal().last_step().unwrap();
    let suggested = call(&mut workspace, "history.suggest_anchors", json!({"step": step})).unwrap();
    let anchors: Vec<Value> = suggested["literals"][0]["suggestions"].as_array().unwrap().iter().map(|suggestion| suggestion["anchor"].clone()).collect();
    assert!(anchors.contains(&json!({"finding": {"id": first["id"], "nth": 0}})), "{suggested}");
    assert!(anchors.contains(&json!({"selection": "current", "part": "offset"})), "{suggested}");
}

#[test]
fn a_recipe_of_chosen_steps_brings_in_what_they_cite_and_anchors_them() {
    let mut workspace = searched_and_selected();
    let anchors = DerivedFrom::from([("offset".to_string(), Anchor::Step { step: 1, path: "result.matches[0]".into() })]);
    crate::journal::promote(&mut workspace, 1);
    api::call_derived(&mut workspace, &Caller::Panel, "cursor.set", json!({"offset": 4}), anchors).unwrap();
    let step = workspace.journal().last_step().unwrap();
    let recipe = call(&mut workspace, "history.recipe", json!({"name": "Jump", "description": "Go to the first PK", "steps": [step]})).unwrap();
    let methods: Vec<&str> = recipe["steps"].as_array().unwrap().iter().map(|step| step["method"].as_str().unwrap()).collect();
    assert_eq!(methods, ["search.find_all", "cursor.set"]);
    assert_eq!(recipe["steps"][1]["params"]["offset"], json!({"$anchor": {"step": 1, "path": "result.matches[0]"}}));
    assert_eq!(recipe["description"], "Go to the first PK");
    let missing = call(&mut workspace, "history.recipe", json!({"name": "Jump", "steps": [99]})).unwrap_err();
    assert_eq!(missing.code, ErrorCode::NotFound);
}

#[test]
fn a_client_may_anchor_its_own_steps_after_the_call() {
    let mut workspace = searched_and_selected();
    let client = Caller::Mcp("claude-code".into());
    let made = api::call(&mut workspace, &client, "history.make_anchor", json!({"step": 2, "path": "selection.range[0]", "anchor": {"find": {"text": "PK"}, "nth": 1}})).unwrap();
    assert_eq!(made["anchor"], json!({"find": {"text": "PK"}, "nth": 1}));
    assert_eq!(derived_from(&workspace, 2)["selection.range[0]"], Anchor::Find { find: Needle::Text("PK".into()), nth: 1, part: None });
}

/// Records of 8 bytes after "SYNC" at `at`, in 160 bytes.
pub(crate) fn capture_with_sync_at(at: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; 160];
    bytes[at..at + 4].copy_from_slice(b"SYNC");
    for (index, byte) in bytes[at + 4..at + 68].iter_mut().enumerate() {
        *byte = (index % 8) as u8 + 1;
    }
    bytes
}

/// The offsets of set `set`'s packets.
pub(crate) fn packet_offsets(workspace: &mut dyn Workspace, set: &Value) -> Vec<u64> {
    let listed = call(workspace, "packets.list", json!({"set": set})).unwrap();
    listed["packets"].as_array().unwrap().iter().map(|packet| packet["offset"].as_u64().unwrap()).collect()
}

#[test]
fn a_recipe_recorded_on_one_file_splits_another_where_its_match_is_elsewhere() {
    // Recorded on the first file: find the sync word, split from it, decode the set.
    let mut recorded = workspace_with("first.bin", &capture_with_sync_at(30));
    assert_eq!(call(&mut recorded, "search.find", json!({"query": "SYNC"})).unwrap()["at"], 30);
    let from_the_match = DerivedFrom::from([("start".to_string(), Anchor::Find { find: Needle::Text("SYNC".into()), nth: 0, part: None })]);
    let split = api::call_derived(&mut recorded, &Caller::Panel, "packets.sets.create", json!({"from": "split_fixed", "start": 30, "len": 64, "record_len": 8}), from_the_match).unwrap();
    let split_step = recorded.journal().last_step().unwrap();
    let that_set = DerivedFrom::from([("set".to_string(), Anchor::Step { step: split_step, path: "result.set".into() })]);
    api::call_derived(&mut recorded, &Caller::Panel, "packets.decode_as", json!({"set": split["set"], "detect": false}), that_set).unwrap();
    let recipe: crate::journal::Recipe = serde_json::from_value(call(&mut recorded, "history.recipe", json!({"name": "Frames from the sync word"})).unwrap()).unwrap();
    assert_eq!(recipe.steps.len(), 2, "the search's match is found again by the anchor, so the search is not a step");

    // Run on a second file, whose sync word is further in.
    let mut other = workspace_with("second.bin", &capture_with_sync_at(77));
    let options = crate::journal::replay::ReplayOptions::new(Caller::Recipe(recipe.name.clone()));
    let report = crate::journal::replay::run_recipe(&mut other, &recipe, &options);
    assert!(report.completed(), "{}", report.summary());
    assert_eq!(report.steps[0].anchors[0].value, json!(77), "the match is found where it is in this file");
    let set = report.steps[0].result.as_ref().expect("a set")["set"].clone();
    assert_eq!(report.steps[1].anchors[0].value, set, "the decoding is of the set this run made");
    let offsets = packet_offsets(&mut other, &set);
    assert_eq!(offsets, (0..8).map(|record| 77 + record * 8).collect::<Vec<u64>>());
}
