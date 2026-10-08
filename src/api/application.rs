//! The application around the documents: plugins (`plugins.*`) and live
//! sources (`sources.*`), for the person's actions that change neither the
//! bytes nor the view's shape but still belong in a recorded analysis
//! (reloading the plugins it used, watching a file, viewing a recorded
//! version).
//!
//! Watching files, serial captures and reloading plugins happen in the
//! window; a headless workspace has none of them to start, so it does what
//! it can (there is nothing to stop) and refuses the rest as unavailable.
//! Recording versions works in both: headless, a version is kept after each
//! edit. See `docs/design/ui-actions.md`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values::NoParams;
use super::workspace::{self, DocumentInfo, Workspace};
use super::{ApiError, ErrorCode};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("plugins.reload", View, reload_plugins, super::values::NoParams, ReloadResult, "Load the Lua plugins again from disk, so the detectors, parsers, codecs and methods they register are the ones in their files now; the command line and MCP load them once, when they start.").not_replayed(),
    method!("sources.watch", View, watch, SwitchParams, SourcesResult, "Watch the window's file for changes on disk, reloading it and marking what changed, or stop watching it.").not_replayed(),
    method!("sources.record", View, record, SwitchParams, SourcesResult, "Keep every version of a document as it changes (the window's file or capture as it changes on disk, or after each edit), or stop keeping them.").not_replayed(),
    method!("sources.stop", View, stop, super::values::NoParams, SourcesResult, "Stop the window's serial capture.").not_replayed(),
    method!("sources.view_version", View, view_version, VersionParams, super::workspace::DocumentInfo, "Open a recorded version of a document as a document derived from it; the window marks what changed from the version before.").opens_document(true),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("plugins.reload", json!({})),
        ("sources.watch", json!({"enabled": false})),
        ("sources.record", json!({"enabled": true})),
        ("sources.view_version", json!({"index": 0})),
        ("sources.stop", json!({})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, params: &serde_json::Value) -> Option<String> {
    let enabled = params.get("enabled").and_then(serde_json::Value::as_bool);
    let description = match method {
        "plugins.reload" => "Reload the plugins from disk".to_string(),
        "sources.watch" if enabled == Some(true) => "Watch the file for changes on disk".to_string(),
        "sources.watch" => "Stop watching the file".to_string(),
        "sources.record" if enabled == Some(true) => "Record every version of the document".to_string(),
        "sources.record" => "Stop recording versions, forgetting those kept".to_string(),
        "sources.stop" => "Stop the serial capture".to_string(),
        "sources.view_version" => format!("Open recorded version {} as a document", params.get("index")?.as_u64()? + 1),
        _ => return None,
    };
    Some(description)
}

/// Parameters of `sources.watch` and `sources.record`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SwitchParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// On or off.
    pub enabled: bool,
}

/// Parameters of `sources.view_version`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// The version, counting from 0 for the first one recorded.
    pub index: usize,
}

/// The result of `plugins.reload`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReloadResult {
    /// What happened, as the status bar says it.
    pub message: String,
}

/// The live sources after a `sources.*` call.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SourcesResult {
    /// Whether the window's file is watched for changes.
    pub watching: bool,
    /// Whether versions of the document are being recorded.
    pub recording: bool,
    /// Versions recorded so far.
    pub versions: usize,
    /// Whether a serial capture is receiving.
    pub capturing: bool,
    /// Whether bytes asked for (a URL, a device, a process region) are still being read.
    pub reading: bool,
}

/// The live sources of document `id` now.
fn sources_result(workspace: &mut dyn Workspace, id: &str) -> SourcesResult {
    let versions = workspace.recorded_versions(id);
    let mut result = SourcesResult { recording: versions.is_some(), versions: versions.unwrap_or(0), ..SourcesResult::default() };
    if let Some(app) = workspace.window() {
        result.watching = app.bench.watch_enabled;
        result.capturing = app.serial_capturing();
        result.reading = app.source_loading();
    }
    result
}

pub fn reload_plugins(workspace: &mut dyn Workspace, _params: NoParams) -> Result<ReloadResult, ApiError> {
    let Some(app) = workspace.window() else {
        return Ok(ReloadResult { message: "Nothing reloaded: the command line and MCP load the plugins when they start".to_string() });
    };
    app.reload_plugins();
    Ok(ReloadResult { message: app.status.clone() })
}

pub fn watch(workspace: &mut dyn Workspace, params: SwitchParams) -> Result<SourcesResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    match workspace.window() {
        Some(app) if id != app.document_id() => return Err(ApiError::invalid_params(format!("{id} is open but not shown; the window watches the file it shows, so show it first (documents.activate)"))),
        Some(app) => app.watch_file(params.enabled).map_err(|message| ApiError::new(ErrorCode::Unavailable, message))?,
        None if params.enabled => return Err(ApiError::new(ErrorCode::Unavailable, "files are watched only in the window; theviewer api and mcp read a file once")),
        None => {}
    }
    Ok(sources_result(workspace, &id))
}

pub fn record(workspace: &mut dyn Workspace, params: SwitchParams) -> Result<SourcesResult, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    workspace.set_recording(&id, params.enabled)?;
    Ok(sources_result(workspace, &id))
}

/// Headless there is no capture to stop.
pub fn stop(workspace: &mut dyn Workspace, _params: NoParams) -> Result<SourcesResult, ApiError> {
    let id = workspace::resolve(workspace, None)?;
    if let Some(app) = workspace.window() {
        app.stop_serial();
    }
    Ok(sources_result(workspace, &id))
}

pub fn view_version(workspace: &mut dyn Workspace, params: VersionParams) -> Result<DocumentInfo, ApiError> {
    let id = workspace::resolve(workspace, params.doc.as_deref())?;
    let opened = workspace.open_recorded_version(&id, params.index)?;
    workspace::info(workspace, &opened)
}

impl crate::app::ViewerApp {
    /// Reload the plugins, as the person's `plugins.reload` (the View menu
    /// and the palette); the app's own reloads, after Learn saves a format,
    /// call [`crate::app::ViewerApp::reload_plugins`] directly.
    pub fn reload_plugins_by_hand(&mut self) {
        let _ = self.perform("plugins.reload", serde_json::json!({}));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn versions_recorded_after_each_edit_open_as_documents_of_their_own() {
        let mut workspace = workspace_with("log.bin", b"version one");
        let recording = call(&mut workspace, "sources.record", json!({"enabled": true})).unwrap();
        assert_eq!((recording["recording"].as_bool(), recording["versions"].as_u64()), (Some(true), Some(1)));
        call(&mut workspace, "bytes.write", json!({"start": 8, "data": "TWO", "encoding": "text"})).unwrap();
        assert_eq!(call(&mut workspace, "sources.record", json!({"enabled": true})).unwrap()["versions"], 2, "the edit kept a version");
        let first = call(&mut workspace, "sources.view_version", json!({"doc": "doc-1", "index": 0})).unwrap();
        assert_eq!(first["name"], "log.bin @ version 1");
        let read = call(&mut workspace, "bytes.read", json!({"doc": first["id"], "start": 0, "encoding": "text"})).unwrap();
        assert_eq!(read["data"], "version one");
        let second = call(&mut workspace, "sources.view_version", json!({"doc": "doc-1", "index": 1})).unwrap();
        let read = call(&mut workspace, "bytes.read", json!({"doc": second["id"], "start": 0, "encoding": "text"})).unwrap();
        assert_eq!(read["data"], "version TWO");
    }

    #[test]
    fn a_version_not_recorded_is_refused() {
        let mut workspace = workspace_with("log.bin", b"bytes");
        assert_eq!(call(&mut workspace, "sources.view_version", json!({"index": 0})).unwrap_err().code, ErrorCode::InvalidParams, "nothing is recorded");
        call(&mut workspace, "sources.record", json!({"enabled": true})).unwrap();
        assert_eq!(call(&mut workspace, "sources.view_version", json!({"index": 3})).unwrap_err().code, ErrorCode::NotFound);
        let stopped = call(&mut workspace, "sources.record", json!({"enabled": false})).unwrap();
        assert_eq!((stopped["recording"].as_bool(), stopped["versions"].as_u64()), (Some(false), Some(0)));
    }

    #[test]
    fn without_a_window_files_are_not_watched_and_there_is_nothing_to_stop_or_reload() {
        let mut workspace = workspace_with("a.bin", b"bytes");
        assert_eq!(call(&mut workspace, "sources.watch", json!({"enabled": true})).unwrap_err().code, ErrorCode::Unavailable);
        assert_eq!(call(&mut workspace, "sources.watch", json!({"enabled": false})).unwrap()["watching"], false);
        assert_eq!(call(&mut workspace, "sources.stop", json!({})).unwrap()["capturing"], false);
        assert!(call(&mut workspace, "plugins.reload", json!({})).unwrap()["message"].as_str().unwrap().starts_with("Nothing reloaded"));
    }

    mod window {
        use serde_json::json;

        use crate::actions::take_performed;
        use crate::api::{Caller, call};
        use crate::app::{Launch, ViewerApp};

        fn app_with(bytes: &[u8]) -> ViewerApp {
            let mut app = ViewerApp::new(Launch::default());
            app.open_bytes(bytes.to_vec(), "test.bin".to_string());
            app.run_bus();
            take_performed();
            app
        }

        #[test]
        fn watching_is_a_sources_step_and_a_document_with_no_file_says_why_in_the_live_tab() {
            let mut app = app_with(b"no file");
            app.set_watch(true);
            assert_eq!(take_performed(), [("sources.watch".to_string(), json!({"enabled": true}))]);
            assert_eq!(app.bench.live_error.as_deref(), Some("Only files on disk can be watched"));
            assert!(!app.bench.watch_enabled);
        }

        #[test]
        fn watching_a_file_starts_and_opening_another_stops_it_without_a_step() {
            let path = std::env::temp_dir().join(format!("theviewer-watch-{}.bin", std::process::id()));
            std::fs::write(&path, b"watched").unwrap();
            let mut app = app_with(b"x");
            app.open_file(&path);
            take_performed();
            app.set_watch(true);
            assert!(app.bench.watch_enabled);
            app.open_new_document();
            assert_eq!(take_performed(), [("sources.watch".to_string(), json!({"enabled": true})), ("documents.new".to_string(), json!({}))], "stopping by itself is not the person's step");
            assert!(!app.bench.watch_enabled);
            std::fs::remove_file(path).ok();
        }

        #[test]
        fn a_recorded_version_opens_with_what_changed_marked() {
            let mut app = app_with(b"version one");
            call(&mut app, &Caller::Panel, "sources.record", json!({"enabled": true})).unwrap();
            let opened = call(&mut app, &Caller::Panel, "sources.view_version", json!({"index": 0})).unwrap();
            assert_eq!(opened["name"], "test.bin @ version 1");
            assert_eq!(app.document.read_range(0, 11), b"version one");
            assert!(app.active_parent().is_some(), "Back returns to the file");
        }

        #[test]
        fn opening_a_source_by_hand_is_a_documents_step_and_says_why_not_in_the_live_tab() {
            let mut app = app_with(b"x");
            app.open_source("serial:");
            assert_eq!(take_performed(), [("documents.open_source".to_string(), json!({"uri": "serial:"}))]);
            assert_eq!(app.bench.live_error.as_deref(), Some("serial: needs a port, e.g. serial:/dev/cu.usbserial-1420@115200"));
            let path = std::env::temp_dir().join(format!("theviewer-source-{}.bin", std::process::id()));
            std::fs::write(&path, b"from a source").unwrap();
            app.open_source(&path.display().to_string());
            assert_eq!(app.document.read_range(0, 13), b"from a source");
            assert_eq!(app.bench.live_error, None);
            std::fs::remove_file(path).ok();
        }

        #[test]
        fn reloading_plugins_by_hand_is_a_plugins_step() {
            let mut app = app_with(b"x");
            app.reload_plugins_by_hand();
            assert_eq!(take_performed(), [("plugins.reload".to_string(), json!({}))]);
        }
    }
}
