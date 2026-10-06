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
fn a_command_without_a_method_is_a_usage_error() {
    let output = theviewer(&["api"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
}
