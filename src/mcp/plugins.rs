//! The Lua plugins, as the MCP server runs them: loaded from the same
//! directories as the window and the command line (or those given with
//! `--plugins`), their methods offered as tools, their subscription
//! handlers run from the server's drain of the bus, and reloaded when a
//! script in their directories changes.
//!
//! The window delivers the bus once a frame; the server does it after each
//! request and on a timer ([`drain`]). Handlers are queued per handler and
//! run a bounded number at a time with their scripts' budgets, exactly as
//! the window runs them (the same [`PluginInbox`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use crate::api::{HeadlessWorkspace, RegisteredMethod, Workspace};
use crate::app::{self, SharedLuaHost};
use crate::bus::topics::PluginLog;
use crate::bus::window::PluginInbox;
use crate::bus::{Draft, Message, Payload};
use crate::plugin::Registry;
use crate::plugins::{LoadReport, LuaHost, Subscription};

/// Most plugin handlers run in one drain; the rest wait for the next, so a
/// flood cannot hold up the client's requests.
const MOST_HANDLERS_PER_DRAIN: usize = 64;
/// Most rounds of delivering and handling in one drain.
const MOST_ROUNDS_PER_DRAIN: usize = 16;

/// A script file as last seen: its path, when it was changed and its size.
type FileStamp = (PathBuf, Option<SystemTime>, u64);

/// The plugin host and what the server needs of it.
pub struct PluginRuntime {
    host: SharedLuaHost,
    dirs: Vec<PathBuf>,
    subscriptions: Vec<Arc<Subscription>>,
    inbox: PluginInbox,
    /// The scripts as they were when last loaded, to notice changes.
    stamps: Vec<FileStamp>,
}

impl PluginRuntime {
    /// Load every script in `dirs`, in order.
    pub fn load(dirs: Vec<PathBuf>) -> (Self, Vec<LoadReport>) {
        let mut host = LuaHost::new();
        let reports = dirs.iter().flat_map(|dir| host.load_dir(dir)).collect();
        let subscriptions = host.subscriptions();
        let stamps = stamps_of(&dirs);
        let runtime = PluginRuntime { host: Arc::new(std::sync::Mutex::new(host)), dirs, subscriptions, inbox: PluginInbox::default(), stamps };
        (runtime, reports)
    }

    /// No plugins at all.
    pub fn none() -> Self {
        Self::load(Vec::new()).0
    }

    /// The directories scripts are loaded from.
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    /// Every detector, parser and codec, the plugins' included.
    pub fn registry(&self) -> Registry {
        app::build_registry_with(Some(&self.host))
    }

    /// The methods scripts registered.
    pub fn methods(&self) -> Vec<Arc<RegisteredMethod>> {
        self.host.lock().map(|host| host.methods()).unwrap_or_default()
    }

    /// Whether a script was added, removed or changed since they were loaded.
    pub fn changed_on_disk(&self) -> bool {
        stamps_of(&self.dirs) != self.stamps
    }

    /// Load every script again, and take what they register now.
    pub fn reload(&mut self) -> Vec<LoadReport> {
        self.stamps = stamps_of(&self.dirs);
        let Ok(mut host) = self.host.lock() else { return Vec::new() };
        let reports = host.reload();
        self.subscriptions = host.subscriptions();
        self.inbox = PluginInbox::default();
        reports
    }

    /// Lines scripts logged and their callbacks' errors, since last taken.
    fn take_log(&self) -> Vec<PluginLog> {
        self.host.lock().map(|mut host| host.take_entries()).unwrap_or_default()
    }

    /// Queue `message` for every handler subscribed to its topic.
    fn queue(&mut self, message: &Arc<Message>) {
        for subscription in self.subscriptions.iter().filter(|subscription| subscription.wants(message)) {
            self.inbox.push(subscription, message);
        }
    }
}

/// The scripts in `dirs` as they are on disk now.
fn stamps_of(dirs: &[PathBuf]) -> Vec<FileStamp> {
    let mut stamps: Vec<FileStamp> = dirs.iter().flat_map(|dir| scripts_in(dir)).collect();
    stamps.sort();
    stamps
}

fn scripts_in(dir: &Path) -> Vec<FileStamp> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    entries
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|extension| extension == "lua"))
        .map(|entry| {
            let metadata = entry.metadata().ok();
            (entry.path(), metadata.as_ref().and_then(|metadata| metadata.modified().ok()), metadata.map_or(0, |metadata| metadata.len()))
        })
        .collect()
}

/// What one drain of the bus found.
#[derive(Default)]
pub struct Drained {
    /// Every message delivered, in order.
    pub messages: Vec<Arc<Message>>,
    /// What plugins logged.
    pub logs: Vec<PluginLog>,
    /// Whether handlers were left waiting for the next drain.
    pub unfinished: bool,
}

/// Deliver what was published since `cursor`, run the plugins' handlers
/// for it (what they publish is delivered in turn) and publish what they
/// logged on `plugin.log`. Advances `cursor` past what was delivered.
pub fn drain(workspace: &mut HeadlessWorkspace, plugins: &mut PluginRuntime, cursor: &mut u64) -> Drained {
    let mut drained = Drained::default();
    let mut handled = 0;
    for _ in 0..MOST_ROUNDS_PER_DRAIN {
        for line in plugins.take_log() {
            workspace.bus().publish(Draft::new(format!("plugin:{}", line.plugin), Payload::PluginLog(line.clone())));
            drained.logs.push(line);
        }
        let bus = workspace.bus();
        let changes = bus.changed_since(*cursor);
        *cursor = bus.cursor();
        if changes.missed > 0 {
            eprintln!("theviewer mcp: {} bus messages went by unseen; subscribers may have missed changes", changes.missed);
        }
        for message in changes.messages {
            plugins.queue(&message);
            drained.messages.push(message);
        }
        if plugins.inbox.is_empty() {
            break;
        }
        while handled < MOST_HANDLERS_PER_DRAIN
            && let Some((subscription, message)) = plugins.inbox.pop()
        {
            workspace.set_cause(Some(message.id));
            subscription.deliver(workspace, &message);
            workspace.set_cause(None);
            handled += 1;
        }
        if handled == MOST_HANDLERS_PER_DRAIN {
            break;
        }
    }
    plugins.inbox.report_dropped();
    drained.unfinished = !plugins.inbox.is_empty();
    drained
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::test_support::workspace_with;
    use crate::api::{self, Caller};
    use crate::bus::topics::LogLevel;
    use serde_json::json;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("theviewer-mcp-plugins-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const MARKER: &str = r#"
        theviewer.plugin{ name = "marker", edits = true }
        theviewer.subscribe("document.edited", function(event, api)
            theviewer.log("saw an edit at version " .. event.version)
            api.publish("findings.published", { findings = { { id = "edit", source = "marker", category = "custom", start = 0, len = 1, title = "edited", detail = "", confidence = 1.0, fields = theviewer.array() } } }, { key = "edits" })
        end)
        theviewer.register_method{ name = "marker.hello", summary = "Say hello.", run = function(params, api) return { hello = "world" } end }
    "#;

    #[test]
    fn handlers_run_from_the_drain_and_what_they_publish_and_log_is_delivered() {
        let dir = temp_dir("handlers");
        std::fs::write(dir.join("marker.lua"), MARKER).unwrap();
        let (mut plugins, reports) = PluginRuntime::load(vec![dir.clone()]);
        assert!(reports.iter().all(|report| report.result.is_ok()), "{reports:?}");
        let mut workspace = workspace_with("a.bin", b"abc");
        workspace.set_registered_methods(plugins.methods());
        let mut cursor = 0;
        drain(&mut workspace, &mut plugins, &mut cursor);

        api::call(&mut workspace, &Caller::Mcp("test".into()), "bytes.write", json!({ "start": 0, "data": "00" })).unwrap();
        let drained = drain(&mut workspace, &mut plugins, &mut cursor);
        let topics: Vec<&str> = drained.messages.iter().map(|message| message.topic_name()).collect();
        assert!(topics.contains(&"document.edited") && topics.contains(&"findings.published") && topics.contains(&"plugin.log"), "{topics:?}");
        let published = drained.messages.iter().find(|message| message.topic_name() == "findings.published").unwrap();
        assert!(published.draft.caused_by.is_some(), "what a handler publishes says what caused it");
        assert_eq!(drained.logs.len(), 1);
        assert_eq!((drained.logs[0].level, drained.logs[0].text.as_str()), (LogLevel::Info, "saw an edit at version 1"));
        assert!(!drained.unfinished);
        assert!(drain(&mut workspace, &mut plugins, &mut cursor).messages.is_empty(), "each message is delivered once");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_changed_script_is_noticed_and_reloaded() {
        let dir = temp_dir("reload");
        let (mut plugins, _) = PluginRuntime::load(vec![dir.clone()]);
        assert!(!plugins.changed_on_disk());
        assert!(plugins.methods().is_empty());
        std::fs::write(dir.join("marker.lua"), MARKER).unwrap();
        assert!(plugins.changed_on_disk());
        let reports = plugins.reload();
        assert_eq!(reports.len(), 1);
        assert!(!plugins.changed_on_disk());
        assert_eq!(plugins.methods()[0].name, "marker.hello");
        std::fs::remove_dir_all(dir).ok();
    }
}
