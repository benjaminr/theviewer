//! Acceptance: the firmware-update challenge's key flow done through the
//! panels alone, as the person would at the window (Strings, *Send to ›
//! Variable…*, the History tab's variables, *Send to › XOR tab · key*, the
//! XOR tab's Output toggle), and the recipe saved from the History tab
//! replaying on the challenge's variant to its flag.
//!
//! The challenge lives beside the repository, in theviewer-demo; without it
//! the test says so and passes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use serde_json::json;

use super::{Sending, send_later};
use crate::api::{HeadlessWorkspace, Workspace};
use crate::app::{Launch, ViewerApp};
use crate::journal::DerivedFrom;
use crate::selection::Selection;
use crate::unpack::Node;

/// The challenge: its files, and the variant its recipe replays on.
const CHALLENGE: &str = "../theviewer-demo/ctf/firmware-update";
/// What the variant's config decrypts to.
const VARIANT_FLAG: &str = "FLAG{19d7ca9a1514222d}";
/// How the unit's serial, the config's XOR key, starts.
const SERIAL_PREFIX: &str = "NC500-";
/// Longest the test waits for a job.
const PATIENCE: Duration = Duration::from_secs(120);

/// Where the challenge is, found from the repository (or its worktree).
fn challenge() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.ancestors().map(|dir| dir.join(CHALLENGE)).find(|dir| dir.join("files/novacam_2.1.0.upd").exists())
}

/// The Strings, XOR and History tabs side by side, drawn as the window
/// draws them.
fn tabs(app: ViewerApp) -> Harness<'static, ViewerApp> {
    Harness::builder().with_size(egui::vec2(1800.0, 1000.0)).build_ui_state(
        |ui, app: &mut ViewerApp| {
            app.perform_waiting_actions();
            app.poll_workbench(ui.ctx());
            ui.columns(3, |columns| {
                crate::analysis_stats::show_strings(app, &mut columns[0]);
                crate::analysis_stats::show_xor(app, &mut columns[1]);
                crate::panels::show(app, &mut columns[2], |panels| &mut panels.history, crate::panel_history::show_history);
            });
        },
        app,
    )
}

/// The path of child indices to the node called `name`, depth first.
fn path_to(node: &Node, name: &str) -> Option<Vec<usize>> {
    for (index, child) in node.children.iter().enumerate() {
        if child.name.rsplit('/').next() == Some(name) {
            return Some(vec![index]);
        }
        if let Some(mut below) = path_to(child, name) {
            below.insert(0, index);
            return Some(below);
        }
    }
    None
}

/// Draw frames until `done` holds of the app.
fn draw_until(harness: &mut Harness<'static, ViewerApp>, done: impl Fn(&ViewerApp) -> bool) {
    let begun = Instant::now();
    while !done(harness.state()) {
        assert!(begun.elapsed() < PATIENCE, "gave up waiting");
        harness.step();
        std::thread::sleep(Duration::from_millis(5));
    }
    harness.run();
}

/// Open `menu_path` from the item labelled `item`'s right-click menu, then
/// click its last entry.
fn right_click_through(harness: &mut Harness<'static, ViewerApp>, item: &str, menu_path: &[&str]) {
    harness.get_by_label_contains(item).click_secondary();
    harness.run();
    for entry in menu_path {
        harness.get_by_label(entry).click();
        harness.run();
    }
}

#[test]
fn the_firmware_key_flow_is_done_through_the_panels_and_its_recipe_replays_on_the_variant() {
    let Some(challenge) = challenge() else {
        eprintln!("skipped: the firmware-update challenge is not beside the repository");
        return;
    };
    let mut app = ViewerApp::new(Launch::default());
    app.load_path(&challenge.join("files/novacam_2.1.0.upd"));
    app.run_bus();

    // The records' data, without their headers and CRCs, sent to a new
    // worksheet from the Selection menu.
    let records: Vec<(usize, usize)> = (0..6).map(|record| (64 + 256 * record, 252)).collect();
    app.select_as_person(Some(Selection::Ranges(records)), 64 + 252, DerivedFrom::new());
    let selection = app.selection_carry().expect("the records are selected");
    send_later(&mut app, Sending::NewWorksheet, selection);
    app.perform_waiting_actions();
    let payload = app.document_id();
    assert_eq!(app.document.len(), 6 * 252);

    // Unpacked: unpack everything and open the daemon, as the tab does.
    app.start_unpack();
    let begun = Instant::now();
    while app.bench.unpacked.get().is_none() {
        assert!(begun.elapsed() < PATIENCE, "the unpacking finishes");
        app.poll_workbench(&egui::Context::default());
        std::thread::sleep(Duration::from_millis(5));
    }
    let tree = app.bench.unpacked.get().cloned().expect("the tree");
    let daemon = path_to(&tree, "novacamd").expect("the firmware holds the daemon");
    let config = path_to(&tree, "config.enc").expect("and the encrypted config");
    app.perform("unpack.open", json!({"path": daemon})).unwrap();

    // Strings: find them, then Send to › Variable… $serial.
    crate::analysis_stats::start_strings(&mut app);
    app.bench.send_to.variable_name = "serial".to_string();
    app.bench.tools.stats.filter = SERIAL_PREFIX.to_string();
    let mut harness = tabs(app);
    draw_until(&mut harness, |app| app.bench.tools.stats.strings.get().is_some());
    right_click_through(&mut harness, SERIAL_PREFIX, &["Send to ⏵", "Variable… ⏵", "Bind"]);
    let serial = harness.state().journal.variable("serial").and_then(|binding| binding.value.as_str().map(str::to_string)).expect("$serial is bound");
    assert!(serial.starts_with(SERIAL_PREFIX) && serial.len() == 14, "{serial}");

    // Unpacked again: the config, from the payload's tree.
    let mut app = harness.into_state();
    app.perform("unpack.open", json!({"path": config, "tree_doc": payload})).unwrap();

    // The History tab's variables: $serial, Send to › XOR tab · key; then
    // the XOR tab applies it as a new worksheet, config.plain.
    // The XOR tab is open, as View › Panels opens it.
    crate::layout::show_pane(&mut app.layout, crate::layout::Pane::Tool(crate::dock::DockTab::Xor));
    let mut harness = tabs(app);
    harness.run();
    right_click_through(&mut harness, "$serial = ", &["Send to ⏵", "XOR tab · key"]);
    harness.get_by_label("· $serial");
    harness.get_by_label("New worksheet").click();
    harness.run();
    harness.state_mut().bench.tools.stats.xor_output.label = "config.plain".to_string();
    harness.get_by_label_contains("Apply to ").click();
    harness.run();
    let mut app = harness.into_state();
    let plain = app.document.read_range(0, app.document.len());
    assert!(String::from_utf8_lossy(&plain).contains("[camera]"), "the config decrypts: {}", String::from_utf8_lossy(&plain));
    assert_eq!(app.sheet_title(&app.document_id()).as_deref(), Some("config.plain"));

    // The History tab's Save as recipe…, its path chosen.
    let path = std::env::temp_dir().join(format!("theviewer-firmware-{}.theviewer-recipe.json", std::process::id()));
    app.call_with_chosen_path("history.save_recipe", json!({"name": "NovaCam config"}), "path", &path).unwrap();
    let recipe = crate::recipes::load(&path).expect("the recipe reads back");
    std::fs::remove_file(&path).ok();
    let saved = serde_json::to_string(&recipe).unwrap();
    assert!(saved.contains("\"var\":\"serial\"") && saved.contains("job.strings"), "the key is found again by $serial, bound by a pick: {saved}");

    // Replayed on the variant, it finds the variant's serial and its flag.
    let mut workspace = HeadlessWorkspace::new(Arc::new(crate::app::build_registry_with(None)));
    let settings = crate::recipes::ReplaySettings::new(Default::default(), crate::recipes::ReplayOutput::Report);
    let run = crate::recipes::replay_file(&mut workspace, &recipe, &challenge.join("variant/novacam_2.1.0.upd"), &settings);
    assert!(run.succeeded(), "the recipe replays: {run:?}");
    let report = run.report.expect("a report");
    let made = report.sheets.iter().find(|sheet| sheet.label.as_deref() == Some("config.plain")).expect("the run makes config.plain");
    let document = workspace.document_mut(&made.doc).expect("the sheet is open");
    let bytes = document.read_range(0, document.len());
    assert!(String::from_utf8_lossy(&bytes).contains(VARIANT_FLAG), "the variant's flag: {}", String::from_utf8_lossy(&bytes));
}
