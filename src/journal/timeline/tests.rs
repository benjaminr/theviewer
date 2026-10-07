use serde_json::{Value, json};

use super::*;
use crate::api::test_support::{call, workspace_with};
use crate::api::{HeadlessWorkspace, Workspace};
use crate::journal::Outcome;
use crate::journal::replay::{StepReport, Stopped};

/// The bytes of document `doc`.
fn bytes_of(workspace: &mut HeadlessWorkspace, doc: &str) -> Vec<u8> {
    let document = workspace.document_mut(doc).unwrap();
    let len = document.len();
    document.read_range(0, len)
}

/// The last step recorded.
fn last_step(workspace: &HeadlessWorkspace) -> u64 {
    workspace.journal().entries().last().unwrap().step
}

fn undo(workspace: &mut HeadlessWorkspace, step: u64) -> Result<Value, ApiError> {
    call(workspace, UNDO_STEP, json!({"step": step}))
}

fn shape(workspace: &mut HeadlessWorkspace) -> Value {
    call(workspace, "view.get_shape", json!({})).unwrap()["shape"].clone()
}

/// A runner that calls each step through the API as recorded, as the
/// recipe runner does for literal steps.
fn run_literally(workspace: &mut dyn Workspace, steps: &[RecipeStep], options: &ReplayOptions) -> RunReport {
    let mut report = RunReport::default();
    for step in steps.iter().filter(|step| options.through_step.is_none_or(|through| step.step <= through)) {
        match api::call(workspace, &options.caller, &step.method, step.params.clone()) {
            Ok(result) => report.steps.push(StepReport {
                step: step.step,
                method: step.method.clone(),
                params: step.params.clone(),
                description: String::new(),
                anchors: Vec::new(),
                outcome: Outcome::Ok,
                result: Some(result),
                journal_step: workspace.journal().entries().last().map(|entry| entry.step),
                job: None,
            }),
            Err(error) => {
                report.stopped = Some(Stopped { step: step.step, error });
                break;
            }
        }
    }
    report
}

#[test]
fn undoing_a_shape_change_restores_the_shape_before_even_the_first_change() {
    let mut workspace = workspace_with("a.bin", &[0u8; 256]);
    let original = shape(&mut workspace);
    call(&mut workspace, "view.set_shape", json!({"width": 48})).unwrap();
    let first = last_step(&workspace);
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, "view.set_shape", json!({"row_padding": 4, "format": "rgb565"})).unwrap();
    let second = last_step(&workspace);
    undo(&mut workspace, second).unwrap();
    assert_eq!(shape(&mut workspace)["width"], 48);
    assert_eq!((shape(&mut workspace)["row_padding"].clone(), shape(&mut workspace)["format"].clone()), (json!(0), json!("gray8")));
    undo(&mut workspace, first).unwrap();
    assert_eq!(shape(&mut workspace), original, "the shape the session started with");
    assert!(matches!(Timeline::of(workspace.journal()).status(second), Some(StepStatus::Undone { by }) if by > second));
}

#[test]
fn undoing_a_fold_shows_its_bytes_again_and_keeps_the_folds_made_before() {
    let mut workspace = workspace_with("a.bin", &[0u8; 256]);
    call(&mut workspace, "view.fold", json!({"ranges": [[16, 8]]})).unwrap();
    call(&mut workspace, "view.fold", json!({"ranges": [[100, 20]]})).unwrap();
    let second = last_step(&workspace);
    let undone = undo(&mut workspace, second).unwrap();
    assert_eq!(undone["calls"][0]["method"], "view.unfold");
    let folds = call(&mut workspace, "view.unfold", json!({"start": 16})).unwrap();
    assert_eq!(folds["folds"], json!([]), "only the first fold was left");
}

#[test]
fn undoing_an_added_bookmark_removes_it_and_undoing_a_removal_puts_it_back() {
    let mut workspace = workspace_with("a.bin", &[0u8; 64]);
    call(&mut workspace, "bookmarks.add", json!({"start": 4, "len": 2, "name": "magic"})).unwrap();
    call(&mut workspace, "bookmarks.add", json!({"start": 8, "name": "length"})).unwrap();
    let added = last_step(&workspace);
    call(&mut workspace, "bookmarks.remove", json!({"start": 4})).unwrap();
    let removed = last_step(&workspace);
    undo(&mut workspace, removed).unwrap();
    undo(&mut workspace, added).unwrap();
    let left = call(&mut workspace, "bookmarks.list", json!({})).unwrap();
    assert_eq!(left["bookmarks"], json!([{"start": 4, "len": 2, "name": "magic"}]));
}

#[test]
fn undoing_a_selection_restores_what_was_selected_before() {
    let mut workspace = workspace_with("a.bin", &[0u8; 64]);
    call(&mut workspace, "selection.set", json!({"selection": {"range": [2, 4]}})).unwrap();
    call(&mut workspace, "bytes.write", json!({"start": 40, "data": "41"})).unwrap();
    call(&mut workspace, "cursor.set", json!({"offset": 30})).unwrap();
    let moved = last_step(&workspace);
    undo(&mut workspace, moved).unwrap();
    let selected = call(&mut workspace, "selection.get", json!({})).unwrap();
    assert_eq!(selected["ranges"], json!([[2, 4]]));
}

#[test]
fn undoing_opening_a_derived_document_returns_to_the_one_it_came_from() {
    let mut workspace = workspace_with("a.bin", b"0123456789");
    call(&mut workspace, "documents.derive", json!({"start": 2, "len": 3})).unwrap();
    let derived = last_step(&workspace);
    assert_ne!(workspace.current_document().as_deref(), Some("doc-1"));
    let undone = undo(&mut workspace, derived).unwrap();
    assert_eq!(undone["calls"], json!([{"method": "documents.open", "params": {"doc": "doc-1"}}]));
    assert_eq!(workspace.current_document().as_deref(), Some("doc-1"));
}

#[test]
fn undoing_a_packet_set_removes_it_unless_a_later_step_uses_it() {
    let mut workspace = workspace_with("a.bin", &[0u8; 128]);
    call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8, "len": 64})).unwrap();
    let first = last_step(&workspace);
    call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 16, "len": 64})).unwrap();
    let second = last_step(&workspace);
    call(&mut workspace, "packets.decode_as", json!({"set": "set-1", "detect": false})).unwrap();
    let refused = undo(&mut workspace, first).unwrap_err();
    assert_eq!(refused.code, ErrorCode::Unavailable);
    assert!(refused.message.contains(&format!("step {}", first + 2)), "{}", refused.message);
    undo(&mut workspace, second).unwrap();
    let sets: Vec<String> = workspace.packet_sets().list().map(|stored| stored.info.set.clone()).collect();
    assert_eq!(sets, ["set-1"]);
}

#[test]
fn undoing_a_decode_as_restores_the_set_s_decoding_before() {
    let mut workspace = workspace_with("a.bin", &[0u8; 128]);
    call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8, "len": 64, "decode_as": "dns", "link": "unknown"})).unwrap();
    let before = workspace.packet_sets().get("set-1").unwrap().info.clone();
    call(&mut workspace, "packets.decode_as", json!({"set": "set-1", "detect": false})).unwrap();
    let chosen = last_step(&workspace);
    assert_ne!(workspace.packet_sets().get("set-1").unwrap().info.decode_as, before.decode_as);
    undo(&mut workspace, chosen).unwrap();
    let after = &workspace.packet_sets().get("set-1").unwrap().info;
    assert_eq!((after.decode_as, after.detect, after.link), (before.decode_as, before.detect, before.link));
}

#[test]
fn undoing_published_findings_withdraws_them_as_their_publisher() {
    let mut workspace = workspace_with("a.bin", &[0u8; 64]);
    let finding = json!({"id": "x", "source": "test", "category": "custom", "start": 0, "len": 4, "title": "Header", "detail": "", "confidence": 1.0, "fields": []});
    let plugin = Caller::Plugin("sync.lua".into());
    api::call(&mut workspace, &plugin, "findings.publish", json!({"findings": [finding], "key": "k"})).unwrap();
    let published = last_step(&workspace);
    undo(&mut workspace, published).unwrap();
    let facts = call(&mut workspace, "events.facts", json!({"producer": "plugin:sync.lua"})).unwrap();
    assert!(facts["facts"].as_array().unwrap().is_empty(), "{facts}");
}

#[test]
fn undoing_a_pinned_template_clears_it_and_undoing_a_clear_pins_it_again() {
    let mut workspace = workspace_with("a.bin", &[1, 0, 2, 0]);
    let source = "endian little\nstruct R { n: u16 }\nroot R[until_end]";
    call(&mut workspace, "templates.apply", json!({"source": source, "pin": true})).unwrap();
    let pinned = last_step(&workspace);
    let templates = |workspace: &mut HeadlessWorkspace| call(workspace, "events.facts", json!({"producer": "tool:templates"})).unwrap()["facts"].as_array().unwrap().len();
    call(&mut workspace, "templates.clear", json!({})).unwrap();
    let cleared = last_step(&workspace);
    assert_eq!(templates(&mut workspace), 0);
    undo(&mut workspace, cleared).unwrap();
    assert!(templates(&mut workspace) > 0, "pinned again");
    call(&mut workspace, "templates.clear", json!({})).unwrap();
    let cleared_again = last_step(&workspace);
    let refused = undo(&mut workspace, pinned).unwrap_err();
    assert!(refused.message.contains("changed the same thing"), "a later clear stands in the way: {}", refused.message);
    undo(&mut workspace, cleared_again).unwrap();
    undo(&mut workspace, pinned).unwrap();
    assert_eq!(templates(&mut workspace), 0, "the first pin undone leaves none");
}

#[test]
fn a_byte_edit_undoes_only_while_it_is_the_document_s_last_edit() {
    let mut workspace = workspace_with("a.bin", b"0123");
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    let first = last_step(&workspace);
    call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42"})).unwrap();
    let second = last_step(&workspace);
    let refused = undo(&mut workspace, first).unwrap_err();
    assert!(refused.message.contains(&format!("step {second} edited doc-1 since")), "{}", refused.message);
    undo(&mut workspace, second).unwrap();
    undo(&mut workspace, first).unwrap();
    assert_eq!(bytes_of(&mut workspace, "doc-1"), b"0123");
    let redo = call(&mut workspace, "history.redo", json!({})).unwrap();
    assert_eq!(redo["at"], 0);
    assert!(Timeline::of(workspace.journal()).is_active(first), "redo brings the first edit back");
}

#[test]
fn a_job_has_nothing_to_undo_but_leaves_the_analysis_once_undone() {
    let mut workspace = workspace_with("a.bin", &[0u8; 1024]);
    call(&mut workspace, "analysis.period_scan", json!({"max_period": 64})).unwrap();
    let job = last_step(&workspace);
    let inverse = call(&mut workspace, "history.inverse", json!({"step": job})).unwrap();
    assert_eq!(inverse["inverse"]["kind"], "nothing");
    let undone = undo(&mut workspace, job).unwrap();
    assert!(undone["note"].as_str().unwrap().contains("job"));
    assert!(entries_for_recipe(workspace.journal(), None).is_empty());
}

#[test]
fn a_step_with_no_inverse_says_so() {
    let mut workspace = workspace_with("a.bin", &[0u8; 128]);
    call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8, "len": 64})).unwrap();
    call(&mut workspace, "packets.sets.remove", json!({"set": "set-1"})).unwrap();
    let removed = last_step(&workspace);
    let inverse = call(&mut workspace, "history.inverse", json!({"step": removed})).unwrap();
    assert_eq!(inverse["inverse"], json!({"kind": "unavailable", "why": "packets.sets.remove has no inverse"}));
    assert_eq!(undo(&mut workspace, removed).unwrap_err().code, ErrorCode::Unavailable);
}

#[test]
fn the_document_s_own_undo_and_redo_mark_its_last_edit_undone_and_back() {
    let mut workspace = workspace_with("a.bin", b"0123");
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, "history.undo", json!({})).unwrap();
    let timeline = Timeline::of(workspace.journal());
    assert_eq!((timeline.status(1), timeline.status(2)), (Some(StepStatus::Undone { by: 2 }), Some(StepStatus::Move)));
    call(&mut workspace, "history.redo", json!({})).unwrap();
    assert!(Timeline::of(workspace.journal()).is_active(1));
    call(&mut workspace, "bytes.write", json!({"start": 9, "data": "41"})).unwrap_err();
    assert_eq!(Timeline::of(workspace.journal()).status(4), Some(StepStatus::Failed));
}

#[test]
fn going_back_undoes_every_later_step_and_leaves_things_as_they_were_after_it() {
    let mut workspace = workspace_with("a.bin", &[0u8; 64]);
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, "view.set_shape", json!({"width": 32})).unwrap();
    let target = last_step(&workspace);
    let bytes_then = bytes_of(&mut workspace, "doc-1");
    let shape_then = shape(&mut workspace);
    call(&mut workspace, "bytes.write", json!({"start": 1, "data": "4243"})).unwrap();
    call(&mut workspace, "view.fold", json!({"ranges": [[8, 8]]})).unwrap();
    call(&mut workspace, "view.set_shape", json!({"width": 16})).unwrap();
    call(&mut workspace, "bookmarks.add", json!({"start": 4, "name": "x"})).unwrap();
    let went = call(&mut workspace, GO_BACK, json!({"step": target})).unwrap();
    assert_eq!(went["way"], "undone");
    assert_eq!(went["undone"].as_array().unwrap().len(), 4);
    assert_eq!(bytes_of(&mut workspace, "doc-1"), bytes_then);
    assert_eq!(shape(&mut workspace), shape_then);
    assert_eq!(call(&mut workspace, "bookmarks.list", json!({})).unwrap()["bookmarks"], json!([]));
    let timeline = Timeline::of(workspace.journal());
    let active: Vec<u64> = timeline.active_steps().collect();
    assert_eq!(active, [1, target], "the later steps are marked undone, not removed");
    let listed = call(&mut workspace, "history.list", json!({})).unwrap();
    assert_eq!(listed["undone"].as_array().unwrap().len(), 4);
}

#[test]
fn going_back_past_a_step_with_no_inverse_replays_from_the_document_as_first_seen() {
    let mut workspace = workspace_with("a.bin", &[0u8; 128]);
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42"})).unwrap();
    let target = last_step(&workspace);
    let bytes_then = bytes_of(&mut workspace, "doc-1");
    call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8, "len": 64})).unwrap();
    call(&mut workspace, "bytes.write", json!({"start": 2, "data": "43"})).unwrap();
    call(&mut workspace, "packets.sets.remove", json!({"set": "set-1"})).unwrap();
    let went = with_runner(run_literally, || go_back(&mut workspace, &Caller::Panel, target)).unwrap();
    assert_eq!(went.way, Way::Replayed);
    let kept: Vec<&str> = went.kept.iter().map(|kept| kept.method.as_str()).collect();
    assert_eq!(kept, ["packets.sets.remove", "packets.sets.create"], "the set removed for good cannot be removed again");
    assert_eq!(went.replayed.unwrap().steps.iter().map(|step| step.step).collect::<Vec<_>>(), [1, 2], "steps 1 to N on the document, again");
    assert_eq!(bytes_of(&mut workspace, "doc-1"), bytes_then, "the same bytes as after step N");
}

#[test]
fn going_back_by_replaying_one_document_leaves_another_document_s_edits_to_redo() {
    let mut workspace = workspace_with("a.bin", &[0u8; 128]);
    call(&mut workspace, "documents.derive", json!({"start": 0, "len": 8})).unwrap();
    let opened = last_step(&workspace);
    let derived = workspace.current_document().unwrap();
    call(&mut workspace, "bytes.write", json!({"doc": derived, "start": 0, "data": "41"})).unwrap();
    let written = last_step(&workspace);
    let written_bytes = bytes_of(&mut workspace, &derived);
    call(&mut workspace, "packets.sets.create", json!({"doc": "doc-1", "from": "split_fixed", "record_len": 8, "len": 64})).unwrap();
    call(&mut workspace, "packets.sets.remove", json!({"set": "set-1"})).unwrap();
    let went = call(&mut workspace, GO_BACK, json!({"step": opened})).unwrap();
    assert_eq!(went["way"], "replayed", "a set removed for good has no inverse");
    assert_ne!(bytes_of(&mut workspace, &derived), written_bytes, "the write was undone");
    call(&mut workspace, "history.redo", json!({"doc": derived})).unwrap();
    assert_eq!(bytes_of(&mut workspace, &derived), written_bytes);
    assert!(Timeline::of(workspace.journal()).is_active(written), "redo brings the write back into the analysis");
    let in_recipe: Vec<u64> = entries_for_recipe(workspace.journal(), None).iter().map(|entry| entry.step).collect();
    assert!(in_recipe.contains(&written), "{in_recipe:?}");
}

#[test]
fn the_edits_going_back_runs_again_undo_and_redo_together_as_the_document_does() {
    let mut workspace = workspace_with("a.bin", &[0u8; 128]);
    call(&mut workspace, "view.set_shape", json!({"width": 32})).unwrap();
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    let first_write = last_step(&workspace);
    call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42"})).unwrap();
    let second_write = last_step(&workspace);
    call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8, "len": 64})).unwrap();
    call(&mut workspace, "packets.sets.remove", json!({"set": "set-1"})).unwrap();
    let went = call(&mut workspace, GO_BACK, json!({"step": second_write})).unwrap();
    assert_eq!(went["way"], "replayed");
    let refused = undo(&mut workspace, second_write).unwrap_err();
    assert!(refused.message.contains("history.undo undoes them together"), "{}", refused.message);

    call(&mut workspace, "history.undo", json!({})).unwrap();
    assert_eq!(bytes_of(&mut workspace, "doc-1")[..2], [0, 0], "one undo takes back both writes run again");
    let timeline = Timeline::of(workspace.journal());
    assert!(matches!(timeline.status(first_write), Some(StepStatus::Undone { .. })));
    assert!(matches!(timeline.status(second_write), Some(StepStatus::Undone { .. })));
    assert!(entries_for_recipe(workspace.journal(), None).iter().all(|entry| entry.method != "bytes.write"), "neither write goes into a recipe");

    call(&mut workspace, "history.redo", json!({})).unwrap();
    assert_eq!(bytes_of(&mut workspace, "doc-1")[..2], [0x41, 0x42]);
    let active: Vec<u64> = Timeline::of(workspace.journal()).active_steps().collect();
    assert_eq!(active, [1, first_write, second_write], "redo brings both back");

    let between = call(&mut workspace, GO_BACK, json!({"step": first_write})).unwrap();
    assert_eq!(between["way"], "replayed", "the writes cannot be undone apart");
    assert_eq!(bytes_of(&mut workspace, "doc-1")[..2], [0x41, 0]);
    let before_both = call(&mut workspace, GO_BACK, json!({"step": 1})).unwrap();
    assert_eq!(before_both["way"], "undone", "the write run again on its own undoes as the document's last edit");
    assert_eq!(bytes_of(&mut workspace, "doc-1")[..2], [0, 0]);
}

#[test]
fn going_back_that_fails_part_way_puts_back_what_it_had_undone() {
    let mut workspace = workspace_with("a.bin", &[0u8; 64]);
    call(&mut workspace, "view.set_shape", json!({"width": 32})).unwrap();
    call(&mut workspace, "bookmarks.add", json!({"start": 4, "name": "x"})).unwrap();
    call(&mut workspace, "view.set_shape", json!({"width": 16})).unwrap();
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    let last = last_step(&workspace);
    let (bytes_then, shape_then) = (bytes_of(&mut workspace, "doc-1"), shape(&mut workspace));
    // Removed outside the journal, so undoing the step that added it fails.
    workspace.set_bookmarks("doc-1", Vec::new()).unwrap();
    let failed = call(&mut workspace, GO_BACK, json!({"step": 0})).unwrap_err();
    assert!(failed.message.contains("undoing step 2, bookmarks.remove failed"), "{}", failed.message);
    assert!(failed.message.contains("put back, so nothing changed"), "{}", failed.message);
    assert_eq!(bytes_of(&mut workspace, "doc-1"), bytes_then, "the write undone first is redone");
    assert_eq!(shape(&mut workspace), shape_then);
    let timeline = Timeline::of(workspace.journal());
    assert_eq!(timeline.active_steps().collect::<Vec<_>>(), [1, 2, 3, last], "the timeline still has every step in effect");
    assert_eq!(timeline.status(last_step(&workspace)), Some(StepStatus::Failed));
    call(&mut workspace, "history.undo", json!({})).unwrap();
    assert!(matches!(Timeline::of(workspace.journal()).status(last), Some(StepStatus::Undone { .. })), "the document's undo still meets the timeline's last edit");
}

#[test]
fn going_back_that_fails_part_way_marks_undone_what_it_could_not_put_back() {
    let mut workspace = workspace_with("a.bin", &[0u8; 128]);
    call(&mut workspace, "bookmarks.add", json!({"start": 4, "name": "x"})).unwrap();
    call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8, "len": 64})).unwrap();
    let created = last_step(&workspace);
    workspace.set_bookmarks("doc-1", Vec::new()).unwrap();
    let failed = call(&mut workspace, GO_BACK, json!({"step": 0})).unwrap_err();
    assert!(failed.message.contains(&format!("steps {created} stay undone")), "{}", failed.message);
    assert_eq!(failed.data.as_ref().map(|data| data["undone"].clone()), Some(json!([created])));
    assert_eq!(workspace.packet_sets().list().count(), 0, "the set removed cannot be made again");
    let timeline = Timeline::of(workspace.journal());
    let went_back = created + 1;
    assert_eq!(timeline.status(created), Some(StepStatus::Undone { by: went_back }), "marked undone, as it is");
    assert!(timeline.is_active(1), "the bookmark's step was never undone");
}

#[test]
fn going_back_by_replaying_stops_with_why_when_a_step_cannot_run_again() {
    let mut workspace = workspace_with("a.bin", &[0u8; 128]);
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8, "len": 64})).unwrap();
    call(&mut workspace, "packets.sets.remove", json!({"set": "set-1"})).unwrap();
    let stopped = |_: &mut dyn Workspace, steps: &[RecipeStep], _: &ReplayOptions| RunReport {
        steps: Vec::new(),
        stopped: Some(Stopped { step: steps[0].step, error: ApiError::new(ErrorCode::Unavailable, "not built") }),
        warnings: Vec::new(),
    };
    let error = with_runner(stopped, || go_back(&mut workspace, &Caller::Panel, 1)).unwrap_err();
    assert!(error.message.contains("running step 1 again failed: not built"), "{}", error.message);
    assert!(error.data.is_some(), "the run's report comes with it");
}

#[test]
fn going_back_to_a_step_not_held_is_not_found() {
    let mut workspace = workspace_with("a.bin", b"abc");
    assert_eq!(call(&mut workspace, GO_BACK, json!({"step": 7})).unwrap_err().code, ErrorCode::NotFound);
}

#[test]
fn playback_runs_one_step_at_a_time_each_recorded_as_a_step_of_its_own() {
    let mut workspace = workspace_with("a.bin", &[0u8; 64]);
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, "view.set_shape", json!({"width": 32})).unwrap();
    call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42"})).unwrap();
    let last = last_step(&workspace);
    // The steps to watch are taken before going back undoes them.
    let steps = steps_to_play(workspace.journal(), 1, last);
    call(&mut workspace, GO_BACK, json!({"step": 0})).unwrap();
    assert_eq!(bytes_of(&mut workspace, "doc-1")[..2], [0, 0]);
    let mut playback = Playback::new(steps, Caller::Panel, None);
    assert_eq!(playback.progress(), (0, 3));
    assert_eq!(with_runner(run_literally, || playback.play_next(&mut workspace)), Some(1));
    assert_eq!(bytes_of(&mut workspace, "doc-1")[..2], [0x41, 0], "the view updates after each step");
    assert_eq!(playback.upcoming().map(|step| step.method.as_str()), Some("view.set_shape"));
    while with_runner(run_literally, || playback.play_next(&mut workspace)).is_some() {}
    assert!(playback.is_finished() && playback.stopped().is_none());
    assert_eq!(bytes_of(&mut workspace, "doc-1")[..2], [0x41, 0x42]);
    let replayed: Vec<&str> = workspace.journal().since(last + 1).map(|entry| entry.method.as_str()).collect();
    assert_eq!(replayed, ["bytes.write", "view.set_shape", "bytes.write"]);
}

#[test]
fn playback_stops_at_a_step_that_fails() {
    let mut workspace = workspace_with("a.bin", &[0u8; 8]);
    let steps = vec![RecipeStep { step: 1, method: "bytes.write".into(), params: json!({"start": 7, "data": "0000"}), note: None }, RecipeStep { step: 2, method: "cursor.set".into(), params: json!({"offset": 1}), note: None }];
    let mut playback = Playback::new(steps, Caller::Panel, None);
    assert_eq!(with_runner(run_literally, || playback.play_next(&mut workspace)), Some(1));
    assert_eq!(playback.stopped().map(|error| error.code), Some(ErrorCode::OutOfRange));
    assert!(playback.is_finished() && playback.play_next(&mut workspace).is_none());
}

#[test]
fn a_recipe_of_the_history_leaves_out_undone_steps_and_moves_along_it() {
    let mut workspace = workspace_with("flight.bin", &[0u8; 64]);
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, "view.set_shape", json!({"width": 32})).unwrap();
    let shaped = last_step(&workspace);
    call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42"})).unwrap();
    undo(&mut workspace, shaped + 1).unwrap();
    let recipe = recipe_of_history(workspace.journal(), "Header", None);
    let steps: Vec<(u64, &str)> = recipe.steps.iter().map(|step| (step.step, step.method.as_str())).collect();
    assert_eq!(steps, [(1, "bytes.write"), (2, "view.set_shape")], "numbered from 1");
    assert_eq!(recipe.recorded_on.map(|file| file.name), Some("flight.bin".to_string()));
    assert_eq!(recipe_of_history(workspace.journal(), "Header", Some(1)).steps.len(), 1);
}

#[test]
fn the_state_before_a_step_is_kept_on_its_entry() {
    let mut workspace = workspace_with("a.bin", &[0u8; 64]);
    call(&mut workspace, "selection.set", json!({"selection": {"range": [2, 4]}})).unwrap();
    call(&mut workspace, "bookmarks.add", json!({"start": 4, "name": "x"})).unwrap();
    let journal = workspace.journal();
    assert_eq!(journal.entry(1).unwrap().before, Some(json!({"selection": null, "cursor": 0})));
    assert_eq!(journal.entry(2).unwrap().before, Some(json!({"bookmarks": []})));
}

#[test]
fn going_back_through_the_recipe_runner_gives_the_document_as_it_was_after_step_n() {
    let mut workspace = workspace_with("a.bin", &[0u8; 128]);
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, "transform.apply", json!({"selection": {"range": [4, 4]}, "operation": {"op": "invert"}})).unwrap();
    call(&mut workspace, "view.set_shape", json!({"width": 32})).unwrap();
    let target = last_step(&workspace);
    let (bytes_then, shape_then) = (bytes_of(&mut workspace, "doc-1"), shape(&mut workspace));
    call(&mut workspace, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8, "len": 64})).unwrap();
    call(&mut workspace, "bytes.write", json!({"start": 2, "data": "4343"})).unwrap();
    call(&mut workspace, "packets.sets.remove", json!({"set": "set-1"})).unwrap();
    let went = call(&mut workspace, GO_BACK, json!({"step": target})).unwrap();
    assert_eq!(went["way"], "replayed", "a set removed for good has no inverse");
    assert_eq!(went["replayed"]["steps"].as_array().unwrap().len(), 3);
    assert_eq!(bytes_of(&mut workspace, "doc-1"), bytes_then);
    assert_eq!(shape(&mut workspace), shape_then);
    let active: Vec<u64> = Timeline::of(workspace.journal()).active_steps().collect();
    assert_eq!(active, [1, 2, target], "the steps run again are inside going back, not steps of their own");
}

#[test]
fn playback_through_the_recipe_runner_shows_each_step_as_it_runs() {
    let mut workspace = workspace_with("a.bin", &[0u8; 64]);
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, "bytes.write", json!({"start": 1, "data": "42"})).unwrap();
    let steps = steps_to_play(workspace.journal(), 1, 2);
    call(&mut workspace, GO_BACK, json!({"step": 0})).unwrap();
    let mut playback = Playback::new(steps, Caller::Panel, None);
    playback.play_next(&mut workspace);
    assert_eq!(bytes_of(&mut workspace, "doc-1")[..2], [0x41, 0]);
    assert!(playback.stopped().is_none());
    playback.play_next(&mut workspace);
    assert_eq!(bytes_of(&mut workspace, "doc-1")[..2], [0x41, 0x42]);
    assert!(playback.is_finished() && playback.stopped().is_none());
}

#[test]
fn recipes_and_playback_leave_out_the_same_steps_that_open_documents_write_files_or_reload_plugins() {
    let mut workspace = workspace_with("flight.bin", &[0u8; 64]);
    let saved = std::env::temp_dir().join(format!("theviewer-timeline-agree-{}.bin", std::process::id()));
    call(&mut workspace, "bytes.write", json!({"start": 0, "data": "41"})).unwrap();
    call(&mut workspace, "documents.save", json!({"path": saved.display().to_string()})).unwrap();
    call(&mut workspace, "plugins.reload", json!({})).unwrap();
    call(&mut workspace, "view.set_shape", json!({"width": 32})).unwrap();
    call(&mut workspace, "documents.derive", json!({"start": 0, "len": 8})).unwrap();
    std::fs::remove_file(&saved).ok();
    let last = last_step(&workspace);
    let in_recipe: Vec<u64> = entries_for_recipe(workspace.journal(), None).iter().map(|entry| entry.step).collect();
    let played: Vec<u64> = steps_to_play(workspace.journal(), 1, last).iter().map(|step| step.step).collect();
    assert_eq!(in_recipe, played, "a recipe of the history takes the steps playback repeats");
    let methods: Vec<String> = in_recipe.iter().map(|step| workspace.journal().entry(*step).unwrap().method.clone()).collect();
    assert_eq!(methods, ["bytes.write", "view.set_shape"]);
}

#[test]
fn undoing_a_dragged_selection_restores_what_was_selected_before_the_drag() {
    let mut workspace = workspace_with("a.bin", &[0u8; 64]);
    call(&mut workspace, "selection.set", json!({"selection": {"range": [40, 2]}})).unwrap();
    call(&mut workspace, "bytes.write", json!({"start": 63, "data": "41"})).unwrap();
    for len in [1, 2, 3, 4] {
        call(&mut workspace, "selection.set", json!({"selection": {"range": [2, len]}})).unwrap();
    }
    let dragged = last_step(&workspace);
    assert_eq!(workspace.journal().entry(dragged).unwrap().merged, 3, "the drag is one step");
    undo(&mut workspace, dragged).unwrap();
    let selected = call(&mut workspace, "selection.get", json!({})).unwrap();
    assert_eq!(selected["ranges"], json!([[40, 2]]), "not the drag's next to last selection");
}

#[test]
fn a_plugin_s_method_is_repeated_and_leaves_nothing_kept_to_undo_it_by() {
    let mut workspace = workspace_with("a.bin", &[0u8; 16]);
    workspace.set_registered_methods(vec![std::sync::Arc::new(crate::api::RegisteredMethod {
        name: "acme.mark".to_string(),
        summary: "Mark something.".to_string(),
        effect: Effect::Analysis,
        params: json!({"type": "object"}),
        result: json!({"type": "object"}),
        owner: "plugin:acme.lua".to_string(),
        run: Box::new(|_, _, _| Ok(json!({}))),
    })]);
    let method = api::find(&workspace, "acme.mark").unwrap();
    assert_eq!((method.undo(), method.replay()), (Undo::registered(Effect::Analysis), Replay::Step));
    assert!(matches!(method.undo(), Undo::Nothing(_)));
    call(&mut workspace, "acme.mark", json!({})).unwrap();
    let marked = last_step(&workspace);
    assert_eq!(call(&mut workspace, "history.inverse", json!({"step": marked})).unwrap()["inverse"]["kind"], "nothing");
    assert_eq!(steps_to_play(workspace.journal(), 1, marked).len(), 1, "played back like any step");
}

#[test]
fn a_method_s_declarations_say_how_its_steps_are_journalled_undone_and_repeated() {
    let declared = |name: &str| api::method(name).unwrap();
    assert_eq!(declared("documents.derive").replay, Replay::OpensDocument { derives: true });
    assert_eq!(declared("documents.derive").undo, Undo::Reverses(crate::api::Reverse::OpenDocument { derives: true }));
    assert_eq!(declared("history.go_back").replay, Replay::Move(Move::GoBack));
    assert_eq!((declared("recipes.save").replay, declared("history.save_recipe").replay), (Replay::WritesFile, Replay::WritesFile), "both write files");
    assert!(declared("selection.set").merge && !declared("bytes.write").merge);
    assert_eq!(declared("history.list").journal, crate::journal::Journalled::Skip);
    assert_eq!(declared("bytes.read").journal, crate::journal::Journalled::Read);
    assert!(declared("bytes.write").takes_doc && !declared("history.list").takes_doc, "filled in from the params");
}
