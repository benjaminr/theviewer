//! `theviewer replay`, run as a separate process over files.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

/// A home folder of its own for a test, with the recipe saved in it.
fn home_with_recipe(test: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("theviewer-replay-cli-{}-{test}", std::process::id()));
    std::fs::remove_dir_all(&home).ok();
    let recipes = home.join(".config/theviewer/recipes");
    std::fs::create_dir_all(&recipes).unwrap();
    let recipe = json!({
        "recipe": 1, "api_version": "1.x", "name": "Mark frames",
        "parameters": {"marker": {"type": "string", "description": "Hex to write over the sync word", "default": "0000"}},
        "steps": [
            {"step": 1, "method": "bytes.write", "params": {"start": {"$anchor": {"find": {"hex": "7EA5"}}}, "data": {"$anchor": {"param": "marker"}}}}
        ]
    });
    std::fs::write(recipes.join("Mark frames.theviewer-recipe.json"), recipe.to_string()).unwrap();
    home
}

fn file_in(home: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = home.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn replay(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_theviewer")).arg("replay").args(args).env("HOME", home).output().expect("the theviewer binary runs")
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|error| panic!("not JSON ({error}): {}", String::from_utf8_lossy(bytes)))
}

#[test]
fn a_recipe_replayed_over_two_files_reports_each_as_json_and_fails_when_one_stopped() {
    let home = home_with_recipe("two-files");
    let first = file_in(&home, "first.bin", b"..\x7e\xa5..");
    let second = file_in(&home, "second.bin", b"nothing to find");
    let output = replay(&home, &["Mark frames", first.to_str().unwrap(), second.to_str().unwrap(), "--param", "marker=abcd", "--json"]);
    assert!(!output.status.success(), "the recipe stopped on the second file");
    let printed = json_of(&output.stdout);
    assert_eq!(printed["recipe"], "Mark frames");
    let files = printed["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0]["file"], first.to_str().unwrap());
    assert_eq!(files[0]["report"]["steps"][0]["params"]["start"], 2);
    assert_eq!(files[0]["report"]["steps"][0]["params"]["data"], "abcd", "the parameter given on the command line");
    assert!(files[0]["report"].get("stopped").is_none());
    assert_eq!(files[1]["report"]["stopped"]["step"], 1);
    assert_eq!(files[1]["report"]["stopped"]["error"]["code"], "not_found");
    assert_eq!(std::fs::read(&first).unwrap(), b"..\x7e\xa5..", "nothing is saved unless asked");
    std::fs::remove_dir_all(home).ok();
}

#[test]
fn a_recipe_replayed_with_out_saves_the_changed_files_in_that_folder() {
    let home = home_with_recipe("out");
    let first = file_in(&home, "first.bin", b"..\x7e\xa5..");
    let out = home.join("marked");
    let output = replay(&home, &["Mark frames", first.to_str().unwrap(), "--out", out.to_str().unwrap()]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let printed = String::from_utf8_lossy(&output.stdout);
    assert!(printed.contains("Mark frames — 1 step ran"), "{printed}");
    assert!(printed.contains(&format!("saved to {}", out.join("first.bin").display())), "{printed}");
    assert_eq!(std::fs::read(out.join("first.bin")).unwrap(), b"..\x00\x00..", "the default marker");
    std::fs::remove_dir_all(home).ok();
}

#[test]
fn replay_without_files_or_with_an_unknown_recipe_says_what_is_wrong() {
    let home = home_with_recipe("usage");
    let no_files = replay(&home, &["Mark frames"]);
    assert_eq!(no_files.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&no_files.stderr).contains("needs at least one file"));
    let file = file_in(&home, "a.bin", b"x");
    let unknown = replay(&home, &["Mark frams", file.to_str().unwrap()]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("there is no recipe 'Mark frams' (those saved are Mark frames)"));
    std::fs::remove_dir_all(home).ok();
}
