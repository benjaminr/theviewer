use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;
use crate::journal::anchors::anchors_in;
use crate::journal::{FileIdentity, Outcome, RecordedDocument};
use crate::plugin::Category;

fn entry(step: u64, method: &str, params: Value, derived_from: DerivedFrom) -> JournalEntry {
    JournalEntry {
        step,
        at: "2026-10-06T14:02:11Z".into(),
        caller: "panel".into(),
        method: method.into(),
        effect: crate::api::Effect::View,
        description: String::new(),
        params,
        params_summarised: false,
        doc: Some("doc-1".into()),
        version_before: Some(0),
        version_after: Some(0),
        outcome: Outcome::Ok,
        result: Some(json!({"matches": [96, 512]})),
        result_summarised: false,
        derived_from,
        merged: 0,
        before: None,
        note: None,
        notes: Vec::new(),
        made: Vec::new(),
        evidence: false,
    }
}

fn session() -> JournalSession {
    JournalSession {
        started_at: "2026-10-06T14:00:00Z".into(),
        api_version: "1.0".into(),
        documents: vec![RecordedDocument::new("doc-1", 0, FileIdentity { name: "flight-03.bin".into(), size: 4096, sha256: None })],
        plugins: Vec::new(),
    }
}

fn find_7ea5(nth: usize) -> Anchor {
    Anchor::Find { find: Needle::Hex("7EA5".into()), nth, part: None }
}

#[test]
fn a_recipe_with_anchors_puts_each_recorded_provenance_in_place_of_its_literal() {
    let entries = [
        entry(4, "search.find_all", json!({"doc": "doc-1", "query": "7EA5", "mode": "hex"}), DerivedFrom::new()),
        entry(9, "packets.sets.create", json!({"doc": "doc-1", "from": "split_fixed", "start": 96, "len": 400, "record_len": 12}), DerivedFrom::from([
            ("start".into(), Anchor::Step { step: 4, path: "result.matches[0]".into() }),
            ("record_len".into(), Anchor::Param { param: "record".into() }),
        ])),
        entry(12, "selection.set", json!({"selection": {"range": [512, 2]}}), DerivedFrom::from([("selection.range[0]".into(), find_7ea5(1))])),
    ];
    let recipe = Recipe::with_anchors("Frames", &session(), &entries, &BTreeMap::new(), &SheetLineage::default()).unwrap();
    let numbers: Vec<u64> = recipe.steps.iter().map(|step| step.step).collect();
    assert_eq!(numbers, [1, 2, 3], "steps are numbered from 1");
    assert_eq!(recipe.steps[1].params["start"], json!({"$anchor": {"step": 1, "path": "result.matches[0]"}}), "the step anchor names the recipe's own step");
    assert_eq!(recipe.steps[1].params["record_len"], json!({"$anchor": {"param": "record"}}));
    assert_eq!(recipe.steps[1].params["len"], 400, "a value with no provenance stays literal");
    assert_eq!(recipe.parameters["record"], RecipeParameter { kind: ParameterType::Integer, description: String::new(), default: Some(json!(12)), default_anchor: None });
    assert!(recipe.steps.iter().all(|step| step.params.get("doc").is_none()), "the recorded document is the one the recipe runs on");
    assert_eq!(anchors_in(&recipe.steps[2].params), [("selection.range[0]".to_string(), find_7ea5(1))]);
    assert_eq!(recipe.recorded_on.as_ref().map(|file| file.name.as_str()), Some("flight-03.bin"));
}

#[test]
fn a_parameter_declared_for_the_session_keeps_its_description_and_type() {
    let entries = [entry(2, "transform.apply", json!({"selection": {"range": [0, 4]}, "operation": {"op": "xor", "key": "5A"}}), DerivedFrom::from([("operation.key".into(), Anchor::Param { param: "key".into() })]))];
    let declared = BTreeMap::from([("key".to_string(), RecipeParameter { kind: ParameterType::String, description: "XOR key, hex".into(), default: Some(json!("5A")), default_anchor: None })]);
    let recipe = Recipe::with_anchors("Unmask", &session(), &entries, &declared, &SheetLineage::default()).unwrap();
    assert_eq!(recipe.parameters, declared);
}

#[test]
fn a_recipe_whose_anchor_cites_a_step_it_cannot_hold_is_refused_rather_than_repeating_the_old_value() {
    let mut failed = entry(3, "search.find", json!({"query": "PK"}), DerivedFrom::new());
    failed.outcome = Outcome::Error(ApiError::not_found("gone"));
    let entries = [failed, entry(5, "cursor.set", json!({"offset": 40}), DerivedFrom::from([("offset".into(), Anchor::Step { step: 3, path: "result.at".into() })]))];
    let refused = Recipe::with_anchors("Jump", &session(), &entries, &BTreeMap::new(), &SheetLineage::default()).unwrap_err();
    assert_eq!(refused.code, crate::api::ErrorCode::InvalidParams);
    assert!(refused.message.contains("step 5 (cursor.set) takes offset from step 3, which the recipe does not hold"), "{}", refused.message);
    assert!(refused.message.contains("so the recipe would repeat the literal"), "{}", refused.message);
}

#[test]
fn a_selection_found_again_keeps_the_cursor_as_the_person_placed_it() {
    let anchored = DerivedFrom::from([("selection.range[0]".into(), find_7ea5(0))]);
    let entries = [
        entry(1, "selection.set", json!({"selection": {"range": [96, 2]}}), anchored.clone()),
        entry(2, "selection.set", json!({"selection": {"range": [96, 2]}, "cursor": 96}), anchored),
    ];
    let recipe = Recipe::with_anchors("Select", &session(), &entries, &BTreeMap::new(), &SheetLineage::default()).unwrap();
    assert!(recipe.steps[0].params.get("cursor").is_none(), "the cursor goes to the end of the range found");
    assert_eq!(recipe.steps[1].params["cursor"], 96, "a cursor at the start is the person's choice");
}

#[test]
fn steps_on_a_second_file_cannot_make_one_recipe() {
    let mut other = entry(2, "bytes.write", json!({"doc": "doc-2", "start": 0, "data": "00"}), DerivedFrom::new());
    other.doc = Some("doc-2".into());
    let entries = [entry(1, "cursor.set", json!({"doc": "doc-1", "offset": 0}), DerivedFrom::new()), other];
    let refused = Recipe::with_anchors("Two", &session(), &entries, &BTreeMap::new(), &SheetLineage::default()).unwrap_err();
    assert!(refused.message.contains("its steps run on two files, flight-03.bin (doc-1) and doc-2 (from step 2, bytes.write); a recipe runs on one"), "{}", refused.message);
}

#[test]
fn choosing_steps_for_a_recipe_brings_in_the_steps_they_cite() {
    let mut journal = Journal::new();
    for (step, cited) in [(1, None), (2, None), (3, Some(1)), (4, Some(3))] {
        let derived_from = cited.map(|cited| DerivedFrom::from([("offset".to_string(), Anchor::Step { step: cited, path: "result.at".into() })])).unwrap_or_default();
        journal.record(entry(step, if step % 2 == 0 { "cursor.set" } else { "bytes.write" }, json!({"offset": step}), derived_from));
    }
    let steps: Vec<u64> = with_cited_steps(&journal, &[4]).iter().map(|entry| entry.step).collect();
    assert_eq!(steps, [1, 3, 4]);
}

#[test]
fn siblings_sharing_a_name_are_told_apart_by_their_place() {
    let leaf = |name: &str, offset| Field::new(name, offset, 4, "");
    let structure = Finding::new("png", "parsers", Category::Image, 0, 64).fields(vec![
        Field::new("IHDR", 8, 25, "").with_children(vec![leaf("width", 16), leaf("height", 20)]),
        Field::new("IDAT", 33, 10, "").with_children(vec![Field::new("data", 41, 2, "")]),
        Field::new("IDAT", 43, 10, "").with_children(vec![Field::new("data", 51, 2, "")]),
    ]);
    assert_eq!(field_name(&structure, 20, 4).as_deref(), Some("IHDR.height"));
    assert_eq!(field_name(&structure, 51, 2).as_deref(), Some("IDAT[1].data"));
    assert_eq!(field_name(&structure, 43, 10).as_deref(), Some("IDAT[1]"));
    assert_eq!(field_name(&structure, 44, 10), None);
}

#[test]
fn the_outermost_of_fields_sharing_a_span_names_it() {
    let structure = Finding::new("x", "parsers", Category::Structure, 0, 8).fields(vec![Field::new("header", 0, 4, "").with_children(vec![Field::new("magic", 0, 4, "")])]);
    assert_eq!(field_name(&structure, 0, 4).as_deref(), Some("header"));
}

#[test]
fn a_finding_is_counted_among_those_whose_id_starts_like_its_own() {
    let found = |id: &str, start| Finding::new(id, "catalogue", Category::Compressed, start, 10);
    let findings = [found("zlib", 0), found("gzip", 20), found("zlib", 40), found("zlib", 60)];
    let anchor = finding_anchor(&findings, &findings[3]).unwrap();
    assert_eq!(anchor, Anchor::Finding { finding: FindingMatch { category: None, id: Some("zlib".into()), nth: 2 }, part: None });
    assert_eq!(finding_anchor(&findings, &found("zlib", 61)), None);
}

/// What `anchor` resolves to in `workspace`'s current document.
fn resolved(workspace: &mut dyn Workspace, anchor: &Anchor) -> Value {
    let (steps, parameters) = (BTreeMap::new(), BTreeMap::new());
    let sheets = anchors::RunSheets::default();
    let mut context = anchors::ResolveContext { workspace, doc: None, steps: &steps, parameters: &parameters, sheets: &sheets, warnings: Vec::new() };
    anchor.resolve(&mut context).unwrap()
}

#[test]
fn the_match_recorded_is_the_match_its_anchor_finds_again_however_it_was_counted() {
    let bytes = b"aaa.aaaa..aa.aaaaa";
    let mut workspace = crate::api::test_support::workspace_with("a.bin", bytes);
    let mut document = Document::from_bytes(bytes.to_vec());
    let starts: Vec<usize> = crate::search::matches_from(&mut document, b"aa", 0).collect();
    for (index, &at) in starts.iter().enumerate() {
        let fresh = nth_match(&mut document, b"aa", at, None).unwrap();
        let after_first = nth_match(&mut document, b"aa", at, Some(KnownMatch { at: starts[0], nth: 0 })).unwrap();
        let before_last = nth_match(&mut document, b"aa", at, Some(KnownMatch { at: starts[starts.len() - 1], nth: starts.len() - 1 })).unwrap();
        assert_eq!((fresh, after_first, before_last), (index, index, index), "the match at {at}, counted from the start, forwards and back");
        let anchor = Anchor::Find { find: Needle::Text("aa".into()), nth: fresh, part: None };
        assert_eq!(resolved(&mut workspace, &anchor), json!(at), "the anchor recorded for {at} finds it again");
    }
    assert_eq!(nth_match(&mut document, b"aa", 3, Some(KnownMatch { at: 9, nth: 5 })), None, "no match starts at 3");
}

#[test]
fn the_finding_recorded_is_the_finding_its_anchor_finds_again() {
    let mut bytes = crate::api::test_support::example_bytes();
    bytes.extend(crate::api::test_support::example_bytes());
    let mut workspace = crate::api::test_support::workspace_with("a.bin", &bytes);
    let findings = anchors::findings_in(&mut workspace, "doc-1", bytes.len() as u64, None).unwrap();
    assert!(!findings.is_empty());
    for finding in &findings {
        let anchor = finding_anchor(&findings, finding).expect("each finding listed has an anchor");
        assert_eq!(resolved(&mut workspace, &anchor), json!(finding.start), "{anchor:?} finds {} again", finding.id);
    }
}

#[test]
fn which_match_counts_overlapping_matches_from_the_start() {
    let mut document = Document::from_bytes(b"aaaa".to_vec());
    assert_eq!(nth_match(&mut document, b"aa", 2, None), Some(2));
    assert_eq!(nth_match(&mut document, b"aa", 3, None), None);
}

#[test]
fn a_text_search_is_written_as_text_and_any_other_as_hex() {
    assert_eq!(needle_of(SearchMode::Text, "PK", b"PK"), Needle::Text("PK".into()));
    assert_eq!(needle_of(SearchMode::TextUtf16, "PK", b"P\0K\0"), Needle::Hex(crate::ops::to_compact_hex(b"P\0K\0")));
    assert_eq!(needle_of(SearchMode::Integer, "513", &[1, 2]), Needle::Hex(crate::ops::to_compact_hex(&[1, 2])));
}
