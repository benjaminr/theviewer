//! The `theviewer api` command line, run as a separate process.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

fn temp_file(name: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("theviewer-api-cli-{}-{name}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    path
}

fn theviewer(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_theviewer")).args(args).output().expect("the theviewer binary runs")
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|error| panic!("not JSON ({error}): {}", String::from_utf8_lossy(bytes)))
}

#[test]
fn describe_prints_every_method_with_its_schemas() {
    let output = theviewer(&["api", "--describe"]);
    assert!(output.status.success());
    let description = json_of(&output.stdout);
    assert_eq!(description["version"], "1.0");
    let methods = description["methods"].as_array().unwrap();
    assert!(methods.iter().any(|method| method["name"] == "bytes.read" && method["params"]["type"] == "object"));
}

#[test]
fn a_method_runs_on_a_file_and_prints_its_result() {
    let path = temp_file("read.bin", b"\x89PNG\r\n\x1a\nrest of the file");
    let file = path.to_str().unwrap();
    let output = theviewer(&["api", "bytes.read", r#"{"start": 0, "len": 4}"#, file]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(json_of(&output.stdout)["data"], "89504e47");

    let info = theviewer(&["api", "documents.info", file]);
    assert_eq!(json_of(&info.stdout)["len"], 24, "parameters may be left out");
    std::fs::remove_file(path).ok();
}

#[test]
fn an_error_exits_non_zero_with_the_error_as_json_on_stderr() {
    let path = temp_file("error.bin", b"four");
    let file = path.to_str().unwrap();
    let output = theviewer(&["api", "bytes.read", r#"{"start": 2, "len": 10}"#, file]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(json_of(&output.stderr)["code"], "out_of_range");

    let unknown = theviewer(&["api", "bytes.melt", "{}", file]);
    assert_eq!(json_of(&unknown.stderr)["code"], "not_found");
    let bad_json = theviewer(&["api", "bytes.read", "{start", file]);
    assert_eq!(json_of(&bad_json.stderr)["code"], "invalid_params");
    let no_file = theviewer(&["api", "bytes.read", r#"{"start": 0}"#]);
    assert_eq!(json_of(&no_file.stderr)["code"], "not_found", "without a file there is no current document");
    std::fs::remove_file(path).ok();
}

#[test]
fn the_command_line_may_edit_and_runs_methods_plugins_registered() {
    let path = temp_file("edit.bin", &[0x7E, 0xA5, 3, 9]);
    let file = path.to_str().unwrap();
    let written = theviewer(&["api", "bytes.write", r#"{"start": 0, "data": "00"}"#, file]);
    assert!(written.status.success(), "the command line works on the file it was given, so nothing asks: {}", String::from_utf8_lossy(&written.stderr));
    assert_eq!(json_of(&written.stdout)["label"], "Overwrite 1 byte by cli");
    assert_eq!(std::fs::read(&path).unwrap(), [0x7E, 0xA5, 3, 9], "an edit is not saved unless asked");

    let described = json_of(&theviewer(&["api", "--describe"]).stdout);
    assert!(described["methods"].as_array().unwrap().iter().any(|method| method["name"] == "acme.decode_frame"), "the example plugin's method is listed");
    let decoded = theviewer(&["api", "acme.decode_frame", r#"{"start": 0}"#, file]);
    assert!(decoded.status.success(), "{}", String::from_utf8_lossy(&decoded.stderr));
    assert_eq!(json_of(&decoded.stdout)["length"], 9);
    std::fs::remove_file(path).ok();
}

#[test]
fn one_command_edits_and_saves_the_file_when_asked_to() {
    let path = temp_file("save.bin", &[1, 2, 3, 4]);
    let file = path.to_str().unwrap();
    let transaction = r#"{"calls": [{"method": "bytes.write", "params": {"start": 0, "data": "ff"}}, {"method": "bytes.insert", "params": {"at": 4, "data": "0a"}}]}"#;
    let saved = theviewer(&["api", "--save", "history.transaction", transaction, file]);
    assert!(saved.status.success(), "{}", String::from_utf8_lossy(&saved.stderr));
    assert_eq!(json_of(&saved.stdout)["len"], 5, "the transaction's result is printed");
    assert_eq!(std::fs::read(&path).unwrap(), [0xFF, 2, 3, 4, 0x0A], "both edits are saved");

    let read = theviewer(&["api", "--save", "bytes.read", r#"{"start": 0, "len": 1}"#, file]);
    assert!(read.status.success(), "a call that edits nothing leaves the file alone");
    std::fs::remove_file(path).ok();
}

#[test]
fn a_command_without_a_method_is_a_usage_error() {
    let output = theviewer(&["api"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
}
