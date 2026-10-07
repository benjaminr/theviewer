use serde_json::json;

use crate::app::{Launch, ViewerApp};
use crate::journal::anchors::{Anchor, FindingMatch, Needle, Part, SelectionWhich};
use crate::journal::{DerivedFrom, JournalEntry};
use crate::plugin::{Category, Field, Finding};
use crate::search::SearchMode;

fn app_with(bytes: &[u8]) -> ViewerApp {
    let mut app = ViewerApp::new(Launch::default());
    app.open_bytes(bytes.to_vec(), "test.bin".to_string());
    app.run_bus();
    crate::actions::take_performed();
    app
}

/// The last journal entry calling `method`.
fn last_entry<'a>(app: &'a ViewerApp, method: &str) -> &'a JournalEntry {
    app.journal.entries().rev().find(|entry| entry.method == method).unwrap_or_else(|| panic!("{method} is in the journal"))
}

fn find(hex_or_text: Needle, nth: usize, part: Option<Part>) -> Anchor {
    Anchor::Find { find: hex_or_text, nth, part }
}

fn selection(part: Part) -> Anchor {
    Anchor::Selection { selection: SelectionWhich::Current, part: Some(part) }
}

#[test]
fn a_match_found_with_find_next_is_selected_as_the_nth_match_of_the_needle() {
    let mut app = app_with(b"PK..PK....PK");
    app.search_mode = SearchMode::Text;
    app.search_text = "PK".to_string();
    app.set_cursor(1, false);
    app.find_next();
    let selected = last_entry(&app, "selection.set");
    assert_eq!(selected.params, json!({"selection": {"range": [4, 2]}}), "the step's own params are unchanged");
    let text = Needle::Text("PK".into());
    let expected = DerivedFrom::from([("selection.range[0]".into(), find(text.clone(), 1, None)), ("selection.range[1]".into(), find(text, 1, Some(Part::Len)))]);
    assert_eq!(selected.derived_from, expected);
}

#[test]
fn pressing_find_next_again_and_again_does_not_count_every_match_from_the_start_each_time() {
    const MATCHES: usize = 2_000;
    let mut app = app_with(&b"PK..".repeat(MATCHES));
    app.search_mode = SearchMode::Text;
    app.search_text = "PK".to_string();
    app.set_cursor(0, false);
    app.find_next();
    let made_before = crate::search::SEARCHES_MADE.with(std::cell::Cell::get);
    for _ in 1..MATCHES {
        app.find_next();
    }
    let made = crate::search::SEARCHES_MADE.with(std::cell::Cell::get) - made_before;
    assert!(made < 10 * MATCHES, "{made} searches for {MATCHES} presses: counting from the start each time would make millions");
    let last = &last_entry(&app, "selection.set").derived_from["selection.range[0]"];
    assert_eq!(last, &find(Needle::Text("PK".into()), MATCHES - 1, None), "the last press still names the last match");
    app.find_previous();
    let previous = &last_entry(&app, "selection.set").derived_from["selection.range[0]"];
    assert_eq!(previous, &find(Needle::Text("PK".into()), MATCHES - 2, None), "stepping back counts back");
}

#[test]
fn a_hex_search_s_match_names_its_bytes_as_hex() {
    let mut app = app_with(&[0, 0x7E, 0xA5, 0, 0x7E, 0xA5]);
    app.search_mode = SearchMode::Hex;
    app.search_text = "7e a5".to_string();
    app.find_previous();
    let anchor = &last_entry(&app, "selection.set").derived_from["selection.range[0]"];
    assert_eq!(anchor, &find(Needle::Hex("7ea5".into()), 1, None), "searching back from the start wraps to the last match");
}

#[test]
fn selecting_all_matches_anchors_each_range_to_its_match() {
    let mut app = app_with(b"PK..PK....");
    app.search_mode = SearchMode::Text;
    app.search_text = "PK".to_string();
    app.select_all_matches();
    let selected = last_entry(&app, "selection.set");
    assert_eq!(selected.derived_from.len(), 4);
    assert_eq!(selected.derived_from["selection.ranges[1][0]"], find(Needle::Text("PK".into()), 1, None));
    assert_eq!(selected.derived_from["selection.ranges[1][1]"], find(Needle::Text("PK".into()), 1, Some(Part::Len)));
}

#[test]
fn matches_that_touch_are_merged_so_they_are_left_literal() {
    let mut app = app_with(b"PKPK....");
    app.search_mode = SearchMode::Text;
    app.search_text = "PK".to_string();
    app.select_all_matches();
    assert!(last_entry(&app, "selection.set").derived_from.is_empty());
}

#[test]
fn selecting_a_finding_names_the_finding_by_its_id_and_place_among_its_kind() {
    let mut bytes = vec![0u8; 64];
    bytes.extend(crate::api::test_support::example_bytes());
    bytes.extend(crate::api::test_support::example_bytes());
    let mut app = app_with(&bytes);
    let doc = app.document_id();
    let findings = crate::journal::anchors::findings_in(&mut app, &doc, bytes.len() as u64, None).unwrap();
    let twice = |finding: &&Finding| findings.iter().filter(|other| other.id == finding.id).count() > 1;
    let first = findings.iter().find(twice).cloned().expect("a kind of finding the example bytes hold twice");
    let second = findings.iter().filter(|finding| finding.id == first.id).nth(1).cloned().unwrap();
    app.select_finding(&second);
    let selected = last_entry(&app, "selection.set");
    let anchor = Anchor::Finding { finding: FindingMatch { category: None, id: Some(first.id.clone()), nth: 1 }, part: None };
    assert_eq!(selected.derived_from["selection.range[0]"], anchor);
    assert_eq!(selected.derived_from["selection.range[1]"], super::with_part(&anchor, Part::Len));
}

#[test]
fn a_field_of_a_parsed_structure_is_named_by_its_path_in_the_tree() {
    let app = app_with(&[0u8; 64]);
    let chunk = |name: &str, offset| Field::new(name, offset, 12, "").with_children(vec![Field::new("length", offset, 4, "13")]);
    let png = Finding::new("png", "parsers", Category::Image, 0, 64).fields(vec![chunk("IHDR", 8), chunk("IDAT", 20), chunk("IDAT", 32)]);
    let derived_from = app.field_provenance(&png, 32, 4);
    let field = Anchor::Structure { structure: "png".into(), field: "IDAT[1].length".into(), part: None };
    assert_eq!(derived_from, DerivedFrom::from([("selection.range[0]".into(), field.clone()), ("selection.range[1]".into(), super::with_part(&field, Part::Len))]));
    let from_a_template = Finding::new("my template", "template", Category::Structure, 0, 64).fields(vec![chunk("IHDR", 8)]);
    assert!(app.field_provenance(&from_a_template, 8, 12).is_empty(), "only a parser's structures are found again in another file");
}

#[test]
fn the_selection_made_into_a_packet_set_is_anchored_to_the_selection() {
    let mut app = app_with(&[0x42; 64]);
    app.perform("selection.set", json!({"selection": {"range": [4, 8]}})).unwrap();
    crate::panel_packets::add_selection_as_packet(&mut app);
    let created = last_entry(&app, "packets.sets.create");
    assert_eq!(created.derived_from, DerivedFrom::from([("ranges[0][0]".into(), selection(Part::Offset)), ("ranges[0][1]".into(), selection(Part::Len))]));
}

#[test]
fn a_split_asked_for_while_drawing_carries_the_selection_as_its_span() {
    let mut app = app_with(&[0x42; 64]);
    app.perform("selection.set", json!({"selection": {"range": [8, 32]}})).unwrap();
    let params = json!({"from": "split_fixed", "start": 8, "len": 32, "record_len": 8});
    let derived_from = app.selection_call_provenance(&params);
    app.perform_later_derived("packets.sets.create", params, derived_from);
    app.perform_waiting_actions();
    let created = last_entry(&app, "packets.sets.create");
    assert_eq!(created.derived_from, DerivedFrom::from([("start".into(), selection(Part::Offset)), ("len".into(), selection(Part::Len))]));
    assert!(app.selection_call_provenance(&json!({"start": 9, "len": 32})).is_empty(), "a span that is not the selection is left literal");
}

#[test]
fn a_split_by_the_detected_length_field_cites_the_detection() {
    let mut frames = Vec::new();
    for size in [6u8, 9, 4, 12, 7, 5, 10, 8, 6, 11, 4, 9] {
        frames.push(0xAA);
        frames.push(size);
        frames.extend(std::iter::repeat_n(size, size as usize));
    }
    let mut app = app_with(&frames);
    let found = app.perform("packets.detect_length_field", json!({"start": 0, "len": frames.len()})).unwrap();
    let detected = found["length_field"].clone();
    assert!(detected.is_object(), "{found}");
    let read = app.journal.reads().next_back().expect("the detection is a read").step;
    let mut field = detected.clone();
    field["max_frame"] = json!(4096);
    let derived_from = app.length_field_provenance(&json!({"from": "length_field", "start": 0, "len": frames.len(), "length_field": field}));
    assert_eq!(derived_from["length_field.offset"], Anchor::Step { step: read, path: "result.length_field.offset".into() });
    assert!(!derived_from.contains_key("length_field.max_frame"), "the longest frame is the person's own");
    assert!(app.journal.entry(read).is_some(), "the cited read is now a step of the journal");
}

#[test]
fn a_width_set_from_a_scanned_period_cites_the_scan_s_job() {
    let mut app = app_with(&[0u8; 4096]);
    app.perform("analysis.period_scan", json!({"start": 0, "len": 4096, "max_period": 64})).unwrap();
    let step = last_entry(&app, "analysis.period_scan").step;
    let candidate = |period| crate::analysis::Candidate { period, score: 1.0, prominence: 9.0, column_gain: 1.0, multiple_of: None };
    app.period_scan = Some(crate::analysis::PeriodScan { window_start: 0, window_len: 4096, scores: vec![0.0; 65], baseline: 0.1, candidates: vec![candidate(12), candidate(24)] });
    app.apply_period(24);
    let set = last_entry(&app, "view.set_shape");
    if set.params["width"] == 24 && set.params["row_padding"] == 0 {
        assert_eq!(set.derived_from["width"], Anchor::Step { step, path: "job.candidates[1].period".into() });
    } else {
        assert!(set.derived_from.is_empty(), "a width that is not the period itself is left literal");
    }
}

#[test]
fn what_the_person_found_and_made_a_packet_of_is_found_again_in_another_file() {
    use crate::api::provenance::tests::{capture_with_sync_at, packet_offsets};
    let mut app = app_with(&capture_with_sync_at(30));
    app.search_mode = SearchMode::Text;
    app.search_text = "SYNC".to_string();
    app.find_next();
    crate::panel_packets::add_selection_as_packet(&mut app);
    let recipe = crate::journal::provenance::build_recipe(&app.journal, "Sync packet", crate::journal::provenance::RecipeSteps::InEffect { through: None }).unwrap();
    let methods: Vec<&str> = recipe.steps.iter().map(|step| step.method.as_str()).collect();
    assert_eq!(methods, ["selection.set", "packets.sets.create"]);
    assert_eq!(recipe.steps[0].params, json!({"selection": {"range": [{"$anchor": {"find": {"text": "SYNC"}, "nth": 0}}, {"$anchor": {"find": {"text": "SYNC"}, "nth": 0, "part": "len"}}]}}));

    let mut other = crate::api::test_support::workspace_with("second.bin", &capture_with_sync_at(77));
    let options = crate::journal::replay::ReplayOptions::new(crate::api::Caller::Recipe(recipe.name.clone()));
    let report = crate::journal::replay::run_recipe(&mut other, &recipe, &options);
    assert!(report.completed(), "{}", report.summary());
    let set = report.steps[1].result.as_ref().expect("a set")["set"].clone();
    assert_eq!(packet_offsets(&mut other, &set), [77]);
}

#[test]
fn an_action_that_calls_nothing_leaves_no_provenance_for_the_next_call() {
    let mut app = app_with(&[0u8; 16]);
    let anchors = DerivedFrom::from([("start".into(), selection(Part::Offset))]);
    app.with_provenance(anchors, |_| ());
    app.perform("bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    assert!(last_entry(&app, "bytes.write").derived_from.is_empty());
}
