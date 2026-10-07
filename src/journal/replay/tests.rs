use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;
use crate::api::test_support::{example_bytes, workspace_with};
use crate::api::{HeadlessWorkspace, Workspace};
use crate::journal::anchors::{FindingMatch, Needle, Part, SelectionWhich, marked};
use crate::journal::RecordedPlugin;
use crate::journal::recipe::{ParameterType, RecipeParameter};

fn recipe_caller() -> Caller {
    Caller::Recipe("Patch".into())
}

fn step(number: u64, method: &str, params: Value) -> RecipeStep {
    RecipeStep { step: number, method: method.into(), params, note: None }
}

fn bytes_of(workspace: &mut HeadlessWorkspace) -> Vec<u8> {
    let id = workspace.current_document().unwrap();
    let document = workspace.document_mut(&id).unwrap();
    document.read_range(0, document.len())
}

/// Resolve `anchor` on the current document of `workspace`, with `steps`
/// done and `parameters` given.
fn resolve(workspace: &mut HeadlessWorkspace, anchor: Anchor, steps: &BTreeMap<u64, Value>, parameters: &BTreeMap<String, Value>) -> Result<Value, ApiError> {
    let mut context = ResolveContext { workspace, doc: None, steps, parameters };
    anchor.resolve(&mut context)
}

fn resolve_here(workspace: &mut HeadlessWorkspace, anchor: Anchor) -> Result<Value, ApiError> {
    resolve(workspace, anchor, &BTreeMap::new(), &BTreeMap::new())
}

/// A 3×2 PNG image after `prefix` bytes of padding.
fn png_after(prefix: usize) -> Vec<u8> {
    let image = image::RgbaImage::from_fn(3, 2, |x, y| image::Rgba([x as u8 * 80, y as u8 * 120, 200, 255]));
    let mut encoded = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image).write_to(&mut encoded, image::ImageFormat::Png).unwrap();
    let mut bytes = vec![0u8; prefix];
    bytes.extend(encoded.into_inner());
    bytes
}

fn find(hex: &str, nth: usize, part: Option<Part>) -> Anchor {
    Anchor::Find { find: Needle::Hex(hex.into()), nth, part }
}

// ---------------------------------------------------------------------------
// Each kind of anchor
// ---------------------------------------------------------------------------

#[test]
fn a_step_anchor_takes_a_value_an_earlier_step_of_the_run_was_given_or_returned() {
    let mut workspace = workspace_with("a.bin", b"abc");
    let done = BTreeMap::from([(3, json!({"params": {"start": 7}, "result": {"matches": [{"offset": 40}, {"offset": 64}]}}))]);
    let anchor = Anchor::Step { step: 3, path: "result.matches[1].offset".into() };
    assert_eq!(resolve(&mut workspace, anchor, &done, &BTreeMap::new()).unwrap(), json!(64));
    let given = Anchor::Step { step: 3, path: "params.start".into() };
    assert_eq!(resolve(&mut workspace, given, &done, &BTreeMap::new()).unwrap(), json!(7));
}

#[test]
fn a_step_anchor_to_a_step_that_has_not_run_or_a_missing_value_says_so() {
    let mut workspace = workspace_with("a.bin", b"abc");
    let done = BTreeMap::from([(3, json!({"params": {}, "result": {"matches": []}}))]);
    let error = resolve(&mut workspace, Anchor::Step { step: 9, path: "result.at".into() }, &done, &BTreeMap::new()).unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    assert!(error.message.contains("the value at result.at of step 9 did not resolve: step 9 has not run earlier in this run (those that have are 3)"), "{}", error.message);
    assert_eq!(error.data.as_ref().unwrap()["anchor"], json!({"step": 9, "path": "result.at"}), "the error carries the anchor");
    let missing = resolve(&mut workspace, Anchor::Step { step: 3, path: "result.matches[0].offset".into() }, &done, &BTreeMap::new()).unwrap_err();
    assert!(missing.message.contains("step 3 has nothing at result.matches[0].offset"), "{}", missing.message);
    let outside = resolve(&mut workspace, Anchor::Step { step: 3, path: "matches".into() }, &done, &BTreeMap::new()).unwrap_err();
    assert_eq!(outside.code, ErrorCode::InvalidParams, "{}", outside.message);
}

#[test]
fn a_find_anchor_gives_the_nth_match_s_offset_length_or_span() {
    let mut workspace = workspace_with("a.bin", b"..\x7e\xa5....\x7e\xa5..PK");
    assert_eq!(resolve_here(&mut workspace, find("7EA5", 0, None)).unwrap(), json!(2));
    assert_eq!(resolve_here(&mut workspace, find("7E A5", 1, Some(Part::Offset))).unwrap(), json!(8));
    assert_eq!(resolve_here(&mut workspace, find("7EA5", 1, Some(Part::Len))).unwrap(), json!(2));
    assert_eq!(resolve_here(&mut workspace, find("7EA5", 1, Some(Part::Value))).unwrap(), json!({"range": [8, 2]}));
    let text = Anchor::Find { find: Needle::Text("PK".into()), nth: 0, part: None };
    assert_eq!(resolve_here(&mut workspace, text).unwrap(), json!(12));
}

#[test]
fn a_find_anchor_with_too_few_matches_says_how_many_there_are() {
    let mut workspace = workspace_with("a.bin", b"..\x7e\xa5....\x7e\xa5..");
    let error = resolve_here(&mut workspace, find("7EA5", 2, None)).unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    assert!(error.message.starts_with("the 3rd match of hex 7EA5 did not resolve: doc-1 has no 3rd match of hex 7EA5: it occurs 2 times"), "{}", error.message);
    let bad = resolve_here(&mut workspace, find("zz", 0, None)).unwrap_err();
    assert_eq!(bad.code, ErrorCode::InvalidParams, "{}", bad.message);
}

#[test]
fn a_structure_anchor_gives_a_parsed_field_s_offset_length_or_value() {
    let mut workspace = workspace_with("image.png", &png_after(0));
    let width = |part| Anchor::Structure { structure: "png".into(), field: "IHDR.width".into(), part };
    assert_eq!(resolve_here(&mut workspace, width(None)).unwrap(), json!(16), "IHDR's data starts after the signature, length and type");
    assert_eq!(resolve_here(&mut workspace, width(Some(Part::Len))).unwrap(), json!(4));
    assert_eq!(resolve_here(&mut workspace, width(Some(Part::Value))).unwrap(), json!(3), "a value that reads as a number is one");
    let full_path = Anchor::Structure { structure: "png".into(), field: "chunks.IHDR.height".into(), part: Some(Part::Value) };
    assert_eq!(resolve_here(&mut workspace, full_path).unwrap(), json!(2));
    let colour = Anchor::Structure { structure: "png".into(), field: "IHDR.colour type".into(), part: Some(Part::Value) };
    assert!(resolve_here(&mut workspace, colour).unwrap().is_string(), "other values are the parser's text");
}

#[test]
fn a_structure_anchor_finds_the_structure_where_it_is_not_at_the_start() {
    let mut workspace = workspace_with("padded.bin", &png_after(64));
    let anchor = Anchor::Structure { structure: "png".into(), field: "IHDR.width".into(), part: None };
    assert_eq!(resolve_here(&mut workspace, anchor).unwrap(), json!(64 + 16));
}

#[test]
fn a_structure_anchor_that_does_not_fit_names_the_parser_and_the_field() {
    let mut workspace = workspace_with("image.png", &png_after(0));
    let no_field = Anchor::Structure { structure: "png".into(), field: "IHDR.depth".into(), part: None };
    let error = resolve_here(&mut workspace, no_field).unwrap_err();
    assert!(error.message.contains("the png structure at 0x0 has no field IHDR.depth (its top-level fields are signature, chunks)"), "{}", error.message);
    let no_parser = Anchor::Structure { structure: "pong".into(), field: "x".into(), part: None };
    assert!(resolve_here(&mut workspace, no_parser).unwrap_err().message.contains("there is no parser 'pong'"));
    let mut text = workspace_with("notes.txt", b"just some words, nothing parsed");
    let nowhere = Anchor::Structure { structure: "png".into(), field: "IHDR.width".into(), part: None };
    assert!(resolve_here(&mut text, nowhere).unwrap_err().message.contains("the png parser recognises nothing"));
}

#[test]
fn a_finding_anchor_gives_the_nth_finding_of_a_category_or_id() {
    let mut workspace = workspace_with("example.bin", &example_bytes());
    let zlib = |part| Anchor::Finding { finding: FindingMatch { category: Some("compressed".into()), id: Some("compressed".into()), nth: 0 }, part };
    assert_eq!(resolve_here(&mut workspace, zlib(None)).unwrap(), json!(0));
    let span = resolve_here(&mut workspace, zlib(Some(Part::Value))).unwrap();
    assert_eq!(span["range"][0], 0);
    assert!(span["range"][1].as_u64().unwrap() > 2, "{span}");
}

#[test]
fn a_finding_anchor_with_no_such_finding_says_how_many_there_are() {
    let mut workspace = workspace_with("example.bin", &example_bytes());
    let second = Anchor::Finding { finding: FindingMatch { category: Some("compressed".into()), id: Some("compressed".into()), nth: 5 }, part: None };
    let error = resolve_here(&mut workspace, second).unwrap_err();
    assert!(error.message.starts_with("the 6th compressed finding whose id starts with compressed did not resolve: the document has 1 such finding"), "{}", error.message);
    let bad = Anchor::Finding { finding: FindingMatch { category: Some("squashed".into()), id: None, nth: 0 }, part: None };
    assert!(resolve_here(&mut workspace, bad).unwrap_err().message.contains("'squashed' is not a finding category"));
}

#[test]
fn a_selection_anchor_gives_what_is_selected_when_the_step_runs() {
    let mut workspace = workspace_with("a.bin", &[0u8; 64]);
    let current = |part| Anchor::Selection { selection: SelectionWhich::Current, part };
    let nothing = resolve_here(&mut workspace, current(None)).unwrap_err();
    assert!(nothing.message.contains("the current selection did not resolve: nothing is selected in doc-1"), "{}", nothing.message);
    crate::api::test_support::call(&mut workspace, "selection.set", json!({"selection": {"range": [8, 4]}})).unwrap();
    assert_eq!(resolve_here(&mut workspace, current(None)).unwrap(), json!({"range": [8, 4]}));
    assert_eq!(resolve_here(&mut workspace, current(Some(Part::Offset))).unwrap(), json!(8));
    assert_eq!(resolve_here(&mut workspace, current(Some(Part::Len))).unwrap(), json!(4));
}

#[test]
fn a_param_anchor_gives_the_value_the_person_supplied() {
    let mut workspace = workspace_with("a.bin", b"abc");
    let given = BTreeMap::from([("key".to_string(), json!("5a"))]);
    assert_eq!(resolve(&mut workspace, Anchor::Param { param: "key".into() }, &BTreeMap::new(), &given).unwrap(), json!("5a"));
    let missing = resolve(&mut workspace, Anchor::Param { param: "offset".into() }, &BTreeMap::new(), &given).unwrap_err();
    assert_eq!(missing.code, ErrorCode::InvalidParams);
    assert!(missing.message.contains("the parameter 'offset' did not resolve: no value was given for it (those given are key)"), "{}", missing.message);
}

// ---------------------------------------------------------------------------
// Running steps
// ---------------------------------------------------------------------------

#[test]
fn nothing_to_run_is_done_at_once() {
    let mut workspace = workspace_with("a.bin", b"abc");
    assert!(run(&mut workspace, &[], &ReplayOptions::new(Caller::Panel)).completed());
}

#[test]
fn a_run_resolves_each_anchor_calls_each_step_as_the_recipe_and_reports_both() {
    let mut workspace = workspace_with("frames.bin", b"header..\x7e\xa5\x01\x02\x03\x04");
    let steps = [
        step(1, "search.find", json!({"query": "7EA5", "mode": "hex"})),
        step(2, "bytes.write", json!({"start": {"$anchor": {"step": 1, "path": "result.at"}}, "data": "0000"})),
        step(3, "cursor.set", json!({"offset": {"$anchor": {"find": {"hex": "0102"}, "part": "offset"}}})),
    ];
    let report = run(&mut workspace, &steps, &ReplayOptions::new(recipe_caller()));
    assert!(report.completed(), "{report:?}");
    assert_eq!(bytes_of(&mut workspace), b"header..\x00\x00\x01\x02\x03\x04");
    assert_eq!(report.steps[1].anchors, [ResolvedAnchor { path: "start".into(), anchor: Anchor::Step { step: 1, path: "result.at".into() }, value: json!(8), pending: None }]);
    assert_eq!(report.steps[1].params, json!({"doc": "doc-1", "start": 8, "data": "0000"}), "the run's document is named and the anchor resolved");
    assert_eq!(report.steps[1].result.as_ref().unwrap()["label"], "Overwrite 2 bytes by recipe:Patch");
    assert_eq!(report.steps[2].params["offset"], 10);
    assert!(report.steps[1].description.starts_with("Overwrite 2 bytes at 0x8"), "{}", report.steps[1].description);
    let journalled: Vec<(String, String)> = workspace.journal().entries().map(|entry| (entry.caller.clone(), entry.method.clone())).collect();
    assert_eq!(journalled, [("recipe:Patch".to_string(), "bytes.write".to_string()), ("recipe:Patch".to_string(), "cursor.set".to_string())], "each step is journalled as the recipe's");
    assert_eq!(report.steps[1].journal_step, workspace.journal().entries().next().map(|entry| entry.step));
}

#[test]
fn a_failed_step_stops_the_run_with_which_step_and_why() {
    let mut workspace = workspace_with("a.bin", b"abcdef");
    let steps = [
        step(1, "bytes.write", json!({"start": 0, "data": "41"})),
        step(2, "bytes.write", json!({"start": {"$anchor": {"find": {"text": "zz"}}}, "data": "42"})),
        step(3, "bytes.write", json!({"start": 2, "data": "43"})),
    ];
    let report = run(&mut workspace, &steps, &ReplayOptions::new(recipe_caller()));
    let stopped = report.stopped.as_ref().expect("the run stopped");
    assert_eq!((stopped.step, stopped.error.code), (2, ErrorCode::NotFound));
    assert_eq!(stopped.error.message, "the parameter start: the 1st match of the text 'zz' did not resolve: doc-1 has no 1st match of the text 'zz': it does not occur");
    assert_eq!(stopped.error.data.as_ref().unwrap()["path"], "start");
    assert_eq!(report.steps.len(), 2, "step 3 never ran");
    assert!(matches!(report.steps[1].outcome, Outcome::Error(_)));
    assert!(report.summary().starts_with("Stopped at step 2 (bytes.write): the parameter start"), "{}", report.summary());
    assert_eq!(bytes_of(&mut workspace), b"Abcdef", "what ran before stays");

    let failing_call = [step(1, "bytes.write", json!({"start": 99, "data": "00"}))];
    let report = run(&mut workspace, &failing_call, &ReplayOptions::new(recipe_caller()));
    assert_eq!(report.stopped.map(|stopped| (stopped.step, stopped.error.code)), Some((1, ErrorCode::OutOfRange)));
}

#[test]
fn a_run_s_edits_undo_as_one_step_named_for_the_recipe() {
    let mut workspace = workspace_with("a.bin", b"abcdef");
    let steps = [step(1, "bytes.write", json!({"start": 0, "data": "41"})), step(2, "bytes.write", json!({"start": 1, "data": "42"})), step(3, "bytes.delete", json!({"start": 5, "len": 1}))];
    assert!(run(&mut workspace, &steps, &ReplayOptions::new(recipe_caller())).completed());
    assert_eq!(bytes_of(&mut workspace), b"ABcde");
    let undone = crate::api::test_support::call(&mut workspace, "history.undo", json!({})).unwrap();
    assert_eq!(undone["label"], "Recipe steps by recipe:Patch");
    assert_eq!(bytes_of(&mut workspace), b"abcdef", "one undo takes back the whole run");
}

#[test]
fn a_preview_resolves_and_describes_each_step_without_changing_anything() {
    let mut workspace = workspace_with("a.bin", b"....\x7e\xa5..");
    let steps = [
        step(1, "bytes.write", json!({"start": {"$anchor": {"find": {"hex": "7EA5"}}}, "data": "0000"})),
        step(2, "cursor.set", json!({"offset": {"$anchor": {"step": 1, "path": "params.start"}}})),
        step(3, "bytes.write", json!({"start": {"$anchor": {"param": "at"}}, "data": "ff"})),
        step(4, "bytes.write", json!({"start": 1, "data": "ff"})),
    ];
    let options = ReplayOptions { preview: true, ..ReplayOptions::new(recipe_caller()) };
    let report = run(&mut workspace, &steps, &options);
    assert_eq!(bytes_of(&mut workspace), b"....\x7e\xa5..", "nothing changed");
    assert_eq!(workspace.journal().entries().len(), 0, "nothing was called");
    assert_eq!(report.steps.len(), 4, "a preview goes on past a problem");
    assert_eq!(report.steps[0].params["start"], 4);
    assert!(report.steps[0].description.starts_with("Overwrite 2 bytes at 0x4"), "{}", report.steps[0].description);
    assert_eq!(report.steps[1].anchors[0].pending.as_deref(), Some("found once step 1 has run"));
    assert!(report.steps[1].description.ends_with("(found once step 1 has run)"), "{}", report.steps[1].description);
    assert!(matches!(&report.steps[2].outcome, Outcome::Error(error) if error.message.contains("the parameter 'at'")));
    assert_eq!(report.stopped.as_ref().map(|stopped| stopped.step), Some(3), "where the run would stop");
    assert!(report.steps[3].outcome.is_ok());
}

#[test]
fn a_run_stops_after_the_step_it_was_asked_to_go_through() {
    let mut workspace = workspace_with("a.bin", b"abc");
    let steps = [step(2, "bytes.write", json!({"start": 0, "data": "41"})), step(5, "bytes.write", json!({"start": 1, "data": "42"})), step(9, "bytes.write", json!({"start": 2, "data": "43"}))];
    let options = ReplayOptions { through_step: Some(5), ..ReplayOptions::new(Caller::Panel) };
    let report = run(&mut workspace, &steps, &options);
    assert!(report.completed());
    assert_eq!(report.steps.iter().map(|report| report.step).collect::<Vec<_>>(), [2, 5]);
    assert_eq!(bytes_of(&mut workspace), b"ABc");
}

#[test]
fn the_recorded_document_s_id_means_the_run_s_document() {
    let mut workspace = workspace_with("old.bin", b"old!");
    workspace.add_document("new.bin", crate::document::Document::from_bytes(b"new!".to_vec()));
    let steps = [step(1, "bytes.write", json!({"doc": "doc-7", "start": 0, "data": "4e"})), step(2, "bytes.write", json!({"doc": "current", "start": 1, "data": "45"}))];
    let options = ReplayOptions { doc: Some("doc-1".into()), ..ReplayOptions::new(recipe_caller()) };
    let report = run(&mut workspace, &steps, &options);
    assert!(report.completed(), "{report:?}");
    assert_eq!(workspace.document_mut("doc-1").unwrap().read_range(0, 4), b"NEd!", "doc-7 was the recorded document, and current means the run's");
    assert_eq!(workspace.document_mut("doc-2").unwrap().read_range(0, 4), b"new!");
}

#[test]
fn a_step_that_starts_a_job_is_waited_for_and_its_result_feeds_later_steps() {
    let mut workspace = workspace_with("notes.txt", &b"The quick brown fox jumps over the lazy dog. ".repeat(50));
    let steps = [
        step(1, "analysis.overview_job", json!({"max_findings": 1})),
        step(2, "bytes.write", json!({"start": 0, "data": {"$anchor": {"step": 1, "path": "job.file"}}})),
    ];
    let report = run(&mut workspace, &steps, &ReplayOptions::new(recipe_caller()));
    let job = report.steps[0].job.as_ref().expect("the job was waited for");
    assert_eq!(job.state, JobState::Finished);
    assert_eq!(job.result.as_ref().unwrap()["file"], "notes.txt");
    let stopped = report.stopped.expect("'notes.txt' is not hex, so step 2 fails");
    assert_eq!(stopped.step, 2);
    assert_eq!(report.steps[1].anchors[0].value, json!("notes.txt"), "the job's result was there for the anchor");
}

#[test]
fn in_the_window_a_run_the_person_allowed_needs_no_confirmation_for_each_step() {
    let mut app = crate::app::ViewerApp::new(crate::app::Launch::default());
    app.open_bytes(b"abcdef".to_vec(), "a.bin".to_string());
    app.run_bus();
    let steps = [step(1, "bytes.write", json!({"start": 0, "data": "41"})), step(2, "selection.set", json!({"selection": {"range": [1, 2]}}))];
    let unasked = run(&mut app, &steps, &ReplayOptions::new(recipe_caller()));
    let refused = unasked.stopped.expect("a recipe's steps are checked like any other caller's");
    assert!(refused.error.needs_confirmation(), "{}", refused.error.message);
    assert_eq!(app.document.read_range(0, 6), b"abcdef");

    let allowed = run(&mut app, &steps, &ReplayOptions { checked_as: None, ..ReplayOptions::new(recipe_caller()) });
    assert!(allowed.completed(), "{allowed:?}");
    assert!(app.confirmations.is_empty(), "nothing waits for the person");
    assert_eq!(app.document.read_range(0, 6), b"Abcdef");
    assert_eq!(app.document.undo_label(), Some("Recipe steps by recipe:Patch"));
}

// ---------------------------------------------------------------------------
// Recipes
// ---------------------------------------------------------------------------

/// A recipe written as one made from a recorded session would be, with its
/// literals turned into anchors by hand.
fn recorded_and_anchored() -> Recipe {
    let mut recorded = workspace_with("first.bin", b"junk\x7e\xa5\x00\x10payload");
    let calls = [
        ("search.find", json!({"query": "7EA5", "mode": "hex"})),
        ("bytes.write", json!({"start": 6, "data": "ffff"})),
        ("selection.set", json!({"selection": {"range": [4, 4]}})),
    ];
    for (method, params) in calls {
        crate::api::call(&mut recorded, &Caller::Panel, method, params).unwrap();
    }
    let session = recorded.journal().session().clone();
    let entries: Vec<_> = recorded.journal().reads().chain(recorded.journal().entries()).cloned().collect();
    let mut recipe = Recipe::from_journal("Mark frames", &session, &entries);
    assert_eq!(recipe.steps.iter().map(|step| step.method.as_str()).collect::<Vec<_>>(), ["search.find", "bytes.write", "selection.set"]);
    let found = recipe.steps[0].step;
    recipe.steps[1].params["start"] = json!({"$anchor": {"param": "length_at"}});
    recipe.steps[2].params["selection"] = marked(&Anchor::Find { find: Needle::Hex("7EA5".into()), nth: 0, part: Some(Part::Value) });
    recipe.steps[0].note = Some(format!("step {found} finds the sync word"));
    recipe.parameters.insert("length_at".into(), RecipeParameter { kind: ParameterType::Integer, description: "Where the length is".into(), default: None });
    recipe
}

#[test]
fn a_recorded_session_made_into_a_recipe_runs_on_another_file() {
    let recipe = recorded_and_anchored();
    let mut other = workspace_with("second.bin", b"a longer header\x7e\xa5\x00\x20more payload");
    let parameters = BTreeMap::from([("length_at".to_string(), json!("0x11"))]);
    let options = ReplayOptions { parameters, ..ReplayOptions::new(Caller::Recipe(recipe.name.clone())) };
    let report = run_recipe(&mut other, &recipe, &options);
    assert!(report.completed(), "{report:?}");
    assert_eq!(report.steps[0].result.as_ref().unwrap()["at"], 15);
    assert_eq!(bytes_of(&mut other), b"a longer header\x7e\xa5\xff\xffmore payload", "the length after the sync word is overwritten, here as there");
    let selected = crate::api::test_support::call(&mut other, "selection.get", json!({})).unwrap();
    assert_eq!(selected["ranges"], json!([[15, 2]]), "the selection follows the sync word");
    assert!(report.warnings.iter().any(|warning| warning.contains("not the file the recipe was recorded on (first.bin")), "{:?}", report.warnings);
}

#[test]
fn a_recipe_s_parameters_are_read_as_their_types_and_defaults_fill_the_rest() {
    let mut recipe = recorded_and_anchored();
    assert!(recipe.parameter_values(&BTreeMap::new()).unwrap_err().message.contains("needs a value for its parameter 'length_at' (Where the length is)"));
    let wrong = recipe.parameter_values(&BTreeMap::from([("length_at".to_string(), json!("six"))])).unwrap_err();
    assert_eq!(wrong.message, "the parameter 'length_at' is 'six', which does not read as an integer");
    let unknown = recipe.parameter_values(&BTreeMap::from([("lenght_at".to_string(), json!(1))])).unwrap_err();
    assert_eq!(unknown.message, "the recipe 'Mark frames' has no parameter 'lenght_at' (it has length_at)");
    recipe.parameters.get_mut("length_at").unwrap().default = Some(json!(6));
    assert_eq!(recipe.parameter_values(&BTreeMap::new()).unwrap()["length_at"], 6);
    assert_eq!(recipe.parameter_values(&BTreeMap::from([("length_at".to_string(), json!(17))])).unwrap()["length_at"], 17);

    let mut workspace = workspace_with("a.bin", b"abc");
    let report = run_recipe(&mut workspace, &recorded_and_anchored(), &ReplayOptions::new(recipe_caller()));
    assert!(report.steps.is_empty() && report.stopped.unwrap().error.message.contains("'length_at'"), "a missing parameter stops the run before it starts");
}

#[test]
fn a_recipe_warns_about_another_api_and_missing_or_changed_plugins_and_its_own_mistakes() {
    let mut recipe = recorded_and_anchored();
    recipe.api_version = "2.x".into();
    recipe.plugins = vec![RecordedPlugin { name: "gone.lua".into(), sha256: "aa".into() }, RecordedPlugin { name: "edited.lua".into(), sha256: "bb".into() }];
    recipe.steps[1].params["data"] = json!({"$anchor": {"step": 999, "path": "result.x"}});
    recipe.steps[2].params["cursor"] = json!({"$anchor": {"param": "undeclared"}});
    let loaded = [RecordedPlugin { name: "edited.lua".into(), sha256: "cc".into() }];
    let warnings = recipe.warnings("1.0", &loaded);
    let expected = [
        "the recipe was recorded with API 2.x, and this is API 1.0",
        "the plugin gone.lua the recipe was recorded with is not loaded",
        "the plugin edited.lua has changed since the recipe was recorded",
        "takes data from step 999, which does not come before it",
        "uses the parameter 'undeclared', which the recipe does not declare",
    ];
    for phrase in expected {
        assert!(warnings.iter().any(|warning| warning.contains(phrase)), "{phrase} in {warnings:?}");
    }
    assert!(recorded_and_anchored().warnings("1.0", &[]).is_empty(), "a recipe that fits warns of nothing");
}
