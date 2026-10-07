//! The window's "Run recipe…", driven through egui_kittest: pick a recipe,
//! preview it, run it, with nothing asked about step by step.
//!
//! Its own test binary, because it points `$HOME` at a folder of its own to
//! keep the recipe in.

use std::path::PathBuf;

use eframe::egui;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use theviewer::app::{Launch, ViewerApp};

fn home_with_recipe() -> PathBuf {
    let home = std::env::temp_dir().join(format!("theviewer-ui-recipes-{}", std::process::id()));
    std::fs::remove_dir_all(&home).ok();
    let recipes = home.join(".config/theviewer/recipes");
    std::fs::create_dir_all(&recipes).unwrap();
    let recipe = serde_json::json!({
        "recipe": 1, "api_version": "1.x", "name": "Mark frames",
        "steps": [
            {"step": 1, "method": "bytes.write", "params": {"start": {"$anchor": {"find": {"hex": "7EA5"}}}, "data": "0000"}},
            {"step": 2, "method": "bytes.write", "params": {"start": {"$anchor": {"find": {"hex": "7EA5"}}}, "data": "1111"}}
        ]
    });
    std::fs::write(recipes.join("Mark frames.theviewer-recipe.json"), recipe.to_string()).unwrap();
    home
}

fn steps(harness: &mut Harness<'static, ViewerApp>, count: usize) {
    for _ in 0..count {
        harness.step();
    }
}

#[test]
fn the_person_previews_a_recipe_then_runs_it_without_confirming_each_step() {
    let home = home_with_recipe();
    // SAFETY: this binary's only test sets it before any thread reads it.
    unsafe { std::env::set_var("HOME", &home) };
    let file = home.join("frames.bin");
    std::fs::write(&file, b"..\x7e\xa5....\x7e\xa5..").unwrap();
    let launch = Launch { path: Some(file), ..Default::default() };
    let mut harness = Harness::builder().with_size(egui::vec2(1400.0, 900.0)).build_eframe(move |creation| {
        theviewer::theme::apply(&creation.egui_ctx);
        ViewerApp::new(launch)
    });
    harness.step();
    harness.state_mut().open_recipe_window();
    harness.step();
    harness.get_by_label("Mark frames").click();
    steps(&mut harness, 3);
    harness.get_by_label("Preview").click();
    steps(&mut harness, 3);
    assert!(harness.query_by_label_contains("1. Overwrite 2 bytes at 0x2").is_some(), "the preview describes each step on this file");
    assert_eq!(harness.state_mut().document.read_range(0, 12), b"..\x7e\xa5....\x7e\xa5..", "the preview changed nothing");
    harness.get_by_label("Run").click();
    steps(&mut harness, 3);
    let app = harness.state_mut();
    assert!(app.confirmations.is_empty(), "the person's Run allowed every step");
    assert_eq!(app.document.read_range(0, 12), b"..\x00\x00....\x11\x11..", "the second step found the next sync word");
    assert_eq!(app.document.undo_label(), Some("Recipe steps by recipe:Mark frames"));
    std::fs::remove_dir_all(home).ok();
}
