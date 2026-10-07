use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};

use super::*;
use crate::journal::RecordedPlugin;

fn temp_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("theviewer-recipes-{}-{test}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn recipe(value: Value) -> Recipe {
    serde_json::from_value(value).unwrap()
}

/// Overwrite the sync word with a marker, wherever it is.
fn sync_recipe() -> Recipe {
    recipe(json!({
        "recipe": 1, "api_version": "1.x", "name": "Telemetry: frames",
        "description": "Overwrite the sync word with a marker",
        "parameters": {"length": {"type": "integer", "description": "The new length", "default": 255}},
        "recorded_on": {"name": "flight-03.bin", "size": 4, "sha256": null},
        "steps": [
            {"step": 1, "method": "search.find", "params": {"doc": "current", "query": "7EA5", "mode": "hex"}},
            {"step": 2, "method": "bytes.write", "params": {"start": {"$anchor": {"step": 1, "path": "result.at"}}, "data": {"$anchor": {"param": "length_hex"}}}}
        ]
    }))
}

fn workspace() -> HeadlessWorkspace {
    HeadlessWorkspace::new(Arc::new(crate::app::build_registry()))
}

#[test]
fn a_recipe_s_file_is_named_after_it_without_characters_a_file_name_cannot_hold() {
    assert_eq!(file_name_for("Telemetry: frames"), "Telemetry- frames.theviewer-recipe.json");
    assert_eq!(file_name_for("../up"), "-up.theviewer-recipe.json");
    assert_eq!(file_name_for("  "), "recipe.theviewer-recipe.json");
}

#[test]
fn a_saved_recipe_loads_back_as_it_was_and_is_listed_and_found_by_name_or_path() {
    let dir = temp_dir("round-trip");
    let saved = save(&dir, &sync_recipe(), false).unwrap();
    assert_eq!(saved, dir.join("Telemetry- frames.theviewer-recipe.json"));
    assert_eq!(load(&saved).unwrap(), sync_recipe());
    let listed = list(&dir);
    assert_eq!(listed.len(), 1);
    assert_eq!((listed[0].name.as_str(), listed[0].steps, listed[0].parameters["length"].default.clone()), ("Telemetry: frames", 2, Some(json!(255))));
    assert_eq!(find(&dir, "telemetry: FRAMES").unwrap().0, sync_recipe(), "by its name, in any case");
    assert_eq!(find(&dir, saved.to_str().unwrap()).unwrap().1, saved, "by its path");
    assert!(save(&dir, &sync_recipe(), false).is_err(), "not over another without overwrite");
    assert!(save(&dir, &sync_recipe(), true).is_ok());
}

#[test]
fn a_file_that_is_not_a_recipe_this_build_reads_is_listed_with_why() {
    let dir = temp_dir("broken");
    std::fs::write(dir.join("Broken.theviewer-recipe.json"), "{not json").unwrap();
    let mut newer = sync_recipe();
    newer.recipe = 9;
    std::fs::write(dir.join("Newer.theviewer-recipe.json"), serde_json::to_string(&newer).unwrap()).unwrap();
    std::fs::write(dir.join("notes.txt"), "not a recipe file at all").unwrap();
    let listed = list(&dir);
    assert_eq!(listed.iter().map(|summary| summary.name.as_str()).collect::<Vec<_>>(), ["Broken", "Newer"]);
    assert!(listed[0].error.as_deref().unwrap().contains("is not a recipe"));
    assert!(listed[1].error.as_deref().unwrap().contains("is in format 9, and this theviewer reads formats up to 2; update theviewer"), "{:?}", listed[1].error);
    assert!(save(&dir, &newer, false).is_err(), "nor is one saved");
    assert!(find(&dir, "Nothing").unwrap_err().message.contains("there is no recipe 'Nothing' (those saved are Broken, Newer)"));
}

#[test]
fn loading_warns_about_plugins_another_api_and_methods_this_build_lacks() {
    let mut recipe = sync_recipe();
    recipe.plugins = vec![RecordedPlugin { name: "acme_telemetry.lua".into(), sha256: "ab".into() }];
    recipe.steps[0].method = "acme.find_frames".into();
    recipe.parameters.insert("length_hex".into(), crate::journal::recipe::RecipeParameter { kind: crate::journal::recipe::ParameterType::String, description: String::new(), default: None });
    let found = warnings(&workspace(), &recipe);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found[0].contains("the plugin acme_telemetry.lua the recipe was recorded with is not loaded"));
    assert!(found[1].contains("step 1 calls acme.find_frames, which this theviewer does not have"));
}

fn capture(dir: &std::path::Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn replaying_over_two_files_reports_each_and_saves_those_that_completed_into_a_folder() {
    let dir = temp_dir("replay");
    let first = capture(&dir, "first.bin", b"ab\x7e\xa5\x00\x00");
    let second = capture(&dir, "second.bin", b"no sync word here");
    let out = dir.join("out");
    let parameters = BTreeMap::from([("length_hex".to_string(), json!("0102"))]);
    let recipe = sync_recipe();
    let runs: Vec<FileRun> = [&first, &second].into_iter().map(|file| replay_file(&mut workspace(), &recipe, file, &parameters, &ReplayOutput::OutDir(out.clone()))).collect();
    assert!(runs[0].succeeded(), "{:?}", runs[0]);
    assert_eq!(std::fs::read(out.join("first.bin")).unwrap(), b"ab\x01\x02\x00\x00", "the run's edits are in the copy");
    assert_eq!(std::fs::read(&first).unwrap(), b"ab\x7e\xa5\x00\x00", "and the file is left as it was");
    assert_eq!(runs[0].saved.as_deref(), Some(out.join("first.bin").to_str().unwrap()));
    let report = runs[0].report.as_ref().unwrap();
    assert_eq!(report.steps[1].params["start"], 2);
    assert!(report.warnings.iter().any(|warning| warning.contains("not the file the recipe was recorded on")));

    assert!(!runs[1].succeeded());
    assert!(runs[1].saved.is_none() && !out.join("second.bin").exists(), "a run that stopped is not saved");
    let stopped = runs[1].report.as_ref().unwrap().stopped.as_ref().unwrap();
    assert_eq!(stopped.step, 2, "search.find finds nothing, so step 2's anchor has no value");

    let text = render_text(&recipe, &runs);
    assert!(text.contains(&format!("{}: Telemetry: frames — 2 steps ran", first.display())), "{text}");
    assert!(text.contains(&format!("{}: Telemetry: frames — Stopped at step 2 (bytes.write)", second.display())), "{text}");
    let json = serde_json::to_value(&runs).unwrap();
    assert_eq!(json[1]["report"]["stopped"]["step"], 2);
}

#[test]
fn replaying_with_save_writes_over_the_file_and_a_missing_file_is_reported() {
    let dir = temp_dir("replay-save");
    let file = capture(&dir, "capture.bin", b"\x7e\xa5\x00\x00");
    let parameters = BTreeMap::from([("length_hex".to_string(), json!("ffff"))]);
    let run = replay_file(&mut workspace(), &sync_recipe(), &file, &parameters, &ReplayOutput::SaveInPlace);
    assert!(run.succeeded(), "{run:?}");
    assert_eq!(std::fs::read(&file).unwrap(), b"\xff\xff\x00\x00");
    let missing = replay_file(&mut workspace(), &sync_recipe(), &dir.join("absent.bin"), &parameters, &ReplayOutput::Report);
    assert!(!missing.succeeded() && missing.report.is_none() && missing.error.is_some());
    assert!(render_text(&sync_recipe(), &[missing]).contains("not run:"));
}

#[test]
fn the_window_previews_then_runs_the_chosen_recipe_without_asking_about_each_step() {
    let dir = temp_dir("window");
    use_dir_for_this_thread(dir.clone());
    let mut recipe = sync_recipe();
    recipe.parameters.insert("length_hex".into(), crate::journal::recipe::RecipeParameter { kind: crate::journal::recipe::ParameterType::String, description: "Hex".into(), default: Some(json!("0a0b")) });
    save(&dir, &recipe, false).unwrap();
    let mut app = crate::app::ViewerApp::new(crate::app::Launch::default());
    app.open_bytes(b"..\x7e\xa5\x00\x00".to_vec(), "frames.bin".to_string());
    app.run_bus();
    crate::actions::take_performed();
    app.open_recipe_window();
    app.recipe_window_choose(0);
    app.recipe_window_preview();
    assert!(app.recipe_window_can_run(), "the preview shows every step can run");
    assert_eq!(app.document.read_range(0, 6), b"..\x7e\xa5\x00\x00", "the preview changed nothing");
    app.recipe_window_run();
    assert!(app.confirmations.is_empty(), "the person's Run is consent to every step");
    assert_eq!(app.document.read_range(0, 6), b"..\x0a\x0b\x00\x00");
    let performed: Vec<String> = crate::actions::take_performed().into_iter().map(|(method, _)| method).collect();
    assert_eq!(performed, ["recipes.preview", "recipes.run"]);
    assert_eq!(app.document.undo_label(), Some("Recipe steps by recipe:Telemetry: frames"));
    assert!(app.status.starts_with("Telemetry: frames: 2 steps ran"), "{}", app.status);
}
