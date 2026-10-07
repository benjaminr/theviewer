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

// ---------------------------------------------------------------------------
// Values bound at call time, and found again by a recipe
// ---------------------------------------------------------------------------

/// A firmware-like file: a unit serial among its strings, then after
/// "CONFIG:" a config XORed with that serial.
fn firmware_with_serial(serial: &str) -> Vec<u8> {
    let config = b"[camera]\nflag=FLAG{bound}\n";
    let key = serial.as_bytes();
    let mut bytes = b"\x00\x01novacamd v2.1\x00\x00".to_vec();
    bytes.extend(serial.as_bytes());
    bytes.extend(b"\x00\x00\x00CONFIG:");
    bytes.extend(config.iter().enumerate().map(|(index, byte)| byte ^ key[index % key.len()]));
    bytes
}

/// The config's length, as [`firmware_with_serial`] writes it.
const CONFIG_LEN: u64 = 26;

/// A session that finds the strings, binds the serial with a pick over
/// them, and XORs the config with it as hex, all as an MCP client passing
/// anchors; returns the strings step.
fn bind_serial_and_decrypt(workspace: &mut crate::api::HeadlessWorkspace) -> u64 {
    let client = Caller::Mcp("claude-code".into());
    let started = api::call(workspace, &client, "strings.find", json!({"min_chars": 5})).unwrap();
    let strings = workspace.journal().last_step().unwrap();
    crate::journal::replay::wait_for_job(workspace, started["job"].as_str().unwrap()).unwrap();
    let serial = json!({"$anchor": {"pick": {"step": strings, "list": "job.strings", "where": {"text": {"regex": "^NC500-[0-9A-F]{8}$"}}, "field": "text"}}});
    api::call(workspace, &client, "vars.set", json!({"name": "serial", "value": serial})).unwrap();
    let start = json!({"$anchor": {"of": {"find": {"text": "CONFIG:"}}, "then": [{"add": 7}]}});
    let key = json!({"$anchor": {"of": {"var": "serial"}, "then": [{"encode": "text_to_hex"}]}});
    api::call(workspace, &client, "transform.apply", json!({"selection": {"range": [start, CONFIG_LEN]}, "operation": {"op": "xor", "key": key}})).unwrap();
    strings
}

fn config_of(workspace: &mut crate::api::HeadlessWorkspace) -> String {
    let at = call(workspace, "search.find", json!({"query": "CONFIG:", "mode": "text"})).unwrap()["at"].as_u64().unwrap() + 7;
    call(workspace, "bytes.read", json!({"doc": "doc-1", "start": at, "len": CONFIG_LEN, "encoding": "text"})).unwrap()["data"].as_str().unwrap().to_string()
}

#[test]
fn a_serial_bound_from_one_file_s_strings_decrypts_the_config_of_another_through_its_recipe() {
    let mut recorded = workspace_with("novacam_2.1.0.upd", &firmware_with_serial("NC500-8D98EE98"));
    bind_serial_and_decrypt(&mut recorded);
    assert_eq!(config_of(&mut recorded), "[camera]\nflag=FLAG{bound}\n");
    let recipe = call(&mut recorded, "history.recipe", json!({"name": "Config"})).unwrap();
    let methods: Vec<&str> = recipe["steps"].as_array().unwrap().iter().map(|step| step["method"].as_str().unwrap()).collect();
    assert_eq!(methods, ["strings.find", "vars.set", "transform.apply"]);
    assert_eq!(recipe["recipe"], 2, "picks, thens and variables are format 2");
    assert_eq!(recipe["steps"][1]["params"]["value"]["$anchor"]["pick"]["step"], 1, "the pick names the strings step by its number in the recipe");
    assert_eq!(recipe["steps"][2]["params"]["operation"]["key"], json!({"$anchor": {"of": {"var": "serial"}, "then": [{"encode": "text_to_hex"}]}}));

    let mut other = workspace_with("novacam_2.1.0.upd", &firmware_with_serial("NC500-2F357657"));
    let report = call(&mut other, "recipes.run", json!({"recipe": recipe})).unwrap();
    assert!(report.get("stopped").is_none(), "{report}");
    assert_eq!(report["steps"][1]["result"]["value"], "NC500-2F357657", "the variant's own serial");
    assert_eq!(config_of(&mut other), "[camera]\nflag=FLAG{bound}\n");
}

#[test]
fn a_bound_value_made_a_parameter_is_found_by_its_anchor_unless_one_is_given() {
    let mut recorded = workspace_with("a.upd", &firmware_with_serial("NC500-8D98EE98"));
    bind_serial_and_decrypt(&mut recorded);
    let bound = latest_step_of(&recorded, "vars.set");
    let made = call(&mut recorded, "history.make_parameter", json!({"step": bound, "path": "value", "name": "serial", "description": "The unit's serial"})).unwrap();
    assert_eq!(made["parameter"]["default"], "NC500-8D98EE98");
    assert_eq!(made["parameter"]["default_anchor"]["pick"]["list"], "job.strings", "{made}");
    let recipe = call(&mut recorded, "history.recipe", json!({"name": "Config"})).unwrap();
    assert_eq!(recipe["parameters"]["serial"]["default_anchor"]["pick"]["step"], 1, "renumbered with the recipe's steps");
    assert_eq!(recipe["steps"][1]["params"]["value"], json!({"$anchor": {"param": "serial"}}));

    let mut found = workspace_with("b.upd", &firmware_with_serial("NC500-2F357657"));
    let report = call(&mut found, "recipes.run", json!({"recipe": recipe})).unwrap();
    assert_eq!(report["steps"][1]["result"]["value"], "NC500-2F357657", "{report}");
    let mut given = workspace_with("b.upd", &firmware_with_serial("NC500-2F357657"));
    let report = call(&mut given, "recipes.run", json!({"recipe": recipe, "parameters": {"serial": "NC500-00000000"}})).unwrap();
    assert_eq!(report["steps"][1]["result"]["value"], "NC500-00000000");
}

/// The latest step of `method` in `workspace`'s journal.
fn latest_step_of(workspace: &crate::api::HeadlessWorkspace, method: &str) -> u64 {
    workspace.journal().entries().rev().find(|entry| entry.method == method).unwrap().step
}

#[test]
fn a_literal_found_in_an_earlier_list_is_offered_picks_by_its_shape_and_place() {
    let mut workspace = workspace_with("a.upd", &firmware_with_serial("NC500-8D98EE98"));
    let started = call(&mut workspace, "strings.find", json!({"min_chars": 5})).unwrap();
    let strings = workspace.journal().last_step().unwrap();
    crate::journal::replay::wait_for_job(&mut workspace, started["job"].as_str().unwrap()).unwrap();
    call(&mut workspace, "vars.set", json!({"name": "serial", "value": "NC500-8D98EE98"})).unwrap();
    let bound = workspace.journal().last_step().unwrap();
    let suggested = call(&mut workspace, "history.suggest_anchors", json!({"step": bound})).unwrap();
    let literals = suggested["literals"].as_array().unwrap();
    let value = literals.iter().find(|literal| literal["path"] == "value").expect("the text is listed, as a list holds it");
    let first = &value["suggestions"][0];
    assert_eq!(first["anchor"], json!({"pick": {"step": strings, "list": "job.strings", "where": {"text": {"regex": "^NC500\\-[0-9A-F]{8}$"}}, "field": "text"}}));
    assert!(first["reason"].as_str().unwrap().starts_with("the first text in job.strings of step"), "{first}");
    assert!(value["suggestions"].as_array().unwrap().iter().any(|suggestion| suggestion["anchor"]["pick"]["nth"].is_u64()), "and by its place: {value}");
    assert!(!literals.iter().any(|literal| literal["path"] == "name"), "text no list holds is not listed");
}

#[test]
fn text_is_given_a_pattern_of_its_shape() {
    use crate::journal::provenance::shape_of;
    assert_eq!(shape_of("NC500-2F357657").as_deref(), Some("^NC500\\-[0-9A-F]{8}$"));
    assert_eq!(shape_of("65ffb335").as_deref(), Some("^[0-9a-f]{8}$"));
    assert_eq!(shape_of("key=Kestrel42").as_deref(), Some("^key=[0-9A-Za-z]{9}$"));
    assert_eq!(shape_of("hello"), None, "plain words have no shape to find again");
    assert_eq!(shape_of("a-b"), None);
}

#[test]
fn a_sheet_passed_by_anchor_brings_the_step_that_made_it_into_a_recipe_of_chosen_steps() {
    let mut workspace = workspace_with("example.bin", &crate::api::test_support::example_bytes());
    let client = Caller::Mcp("claude-code".into());
    api::call(&mut workspace, &client, "documents.derive", json!({"doc": "doc-1", "start": 0})).unwrap();
    let made = workspace.journal().last_step().unwrap();
    api::call(&mut workspace, &client, "unpack.open", json!({"doc": "doc-1", "tree_doc": {"$sheet": made}, "path": [0]})).unwrap();
    let opened = workspace.journal().last_step().unwrap();
    let recipe = call(&mut workspace, "history.recipe", json!({"name": "Node", "steps": [opened]})).unwrap();
    let methods: Vec<&str> = recipe["steps"].as_array().unwrap().iter().map(|step| step["method"].as_str().unwrap()).collect();
    assert_eq!(methods, ["documents.derive", "unpack.open"], "the sheet's maker is kept");
    assert_eq!(recipe["steps"][1]["params"]["tree_doc"], json!({"$anchor": {"sheet": {"step": 1}}}));
}
