//! The window's side of the bus: what the app publishes from its own state
//! each frame, the reactions it runs when messages are delivered, and the
//! one place in the frame where that happens.
//!
//! Once per frame, [`ViewerApp::run_bus`] notes what changed in the app
//! since the last frame (edits from the document's edit log, the cursor and
//! selection, pinned findings, plugins' log lines) and publishes it, then
//! delivers every queued message in publication order. Each delivered
//! message is handed to the reactions registered for its topic: plain
//! functions taking the app, which run whether or not the tool they belong
//! to is on screen. A reaction that publishes says what caused it with
//! [`Draft::caused_by`], which is how loops are stopped.

use std::sync::Arc;

use crate::api::workspace::WINDOW_DOCUMENT_ID;
use crate::app::ViewerApp;
use crate::plugin::Finding;
use crate::selection::Selection;

use super::topics::*;
use super::{Draft, Message, Payload, Topic};

/// What the window publishes its own changes as.
pub const MAIN_VIEW: &str = "view:main";
/// What the app publishes documents opening and closing as.
pub const APP: &str = "app";
/// Most messages delivered in one frame; the rest wait for the next, so a
/// flood cannot stall the window.
const MOST_PER_FRAME: usize = 2000;

/// What a reaction does with a delivered message.
pub type React = fn(&mut ViewerApp, &Arc<Message>);

/// A function run for every delivered message on one topic.
#[derive(Clone, Copy)]
pub struct Reaction {
    pub topic: Topic,
    /// Who reacts, for the Workspace tab.
    pub name: &'static str,
    pub react: React,
}

/// The reactions built into the app.
pub fn builtin_reactions() -> Vec<Reaction> {
    vec![
        Reaction { topic: Topic::SelectionChanged, name: "Packets follows the selection", react: crate::panel_packets::follow_selection },
        Reaction { topic: Topic::ReferenceFocus, name: "Reference shows the format asked for", react: crate::panel_reference::follow_focus },
        Reaction { topic: Topic::PluginLog, name: "The status bar shows plugin errors", react: show_plugin_error },
    ]
}

/// What the app last published of its own state, to notice changes.
#[derive(Default)]
pub struct BusWatch {
    /// The document version `document.edited` has been published up to.
    version: u64,
    /// The cursor and selection last published.
    selection: Option<(usize, Option<Selection>)>,
    /// The pinned findings last published.
    pinned: Vec<Finding>,
}

impl ViewerApp {
    /// A message from `producer` about the window's document as it is now.
    pub fn draft(&self, producer: impl Into<String>, payload: Payload) -> Draft {
        Draft::new(producer, payload).about(WINDOW_DOCUMENT_ID, self.document.version())
    }

    /// Publish `payload` from `producer` about the document as it is now.
    pub fn publish(&self, producer: impl Into<String>, payload: Payload) {
        self.bus.publish(self.draft(producer, payload));
    }

    /// Publish what changed in the app, then deliver every queued message
    /// and run the reactions to each. Called once per frame from `logic()`.
    pub fn run_bus(&mut self) {
        self.publish_edits();
        self.publish_selection_if_changed(MAIN_VIEW);
        self.publish_pinned_findings();
        self.publish_plugin_log();
        let reactions = std::mem::take(&mut self.reactions);
        for _ in 0..MOST_PER_FRAME {
            let Some(message) = self.bus.deliver_next() else { break };
            for reaction in reactions.iter().filter(|reaction| reaction.topic == message.topic()) {
                (reaction.react)(self, &message);
            }
        }
        self.reactions = reactions;
    }

    /// The reactions run when messages are delivered.
    pub fn reactions(&self) -> &[Reaction] {
        &self.reactions
    }

    /// The document was swapped for another: say so, and start watching the
    /// new one's edits and selection afresh.
    pub(crate) fn publish_document_replaced(&mut self, previous_name: String) {
        self.publish(APP, Payload::DocumentClosed(DocumentClosed { name: previous_name }));
        let opened = DocumentOpened { name: self.display_name(), path: self.document.path().map(|path| path.display().to_string()), len: self.document.len() };
        self.publish(APP, Payload::DocumentOpened(opened));
        self.bus_watch.version = self.document.version();
        self.bus_watch.pinned.clear();
    }

    /// Publish the edits made since the last `document.edited`.
    fn publish_edits(&mut self) {
        let version = self.document.version();
        if version == self.bus_watch.version {
            return;
        }
        // When the log no longer reaches back, the edits are not listed and
        // nothing can be carried through them.
        let edits = self.document.edits_since(self.bus_watch.version);
        let complete = edits.is_some();
        let edits = edits.unwrap_or_default();
        self.publish("document", Payload::DocumentEdited(DocumentEdited { edits, complete }));
        self.bus_watch.version = version;
    }

    /// Publish the selection (and the cursor, if it moved) as `producer`'s
    /// doing, when either changed since last published.
    fn publish_selection_if_changed(&mut self, producer: &str) {
        let now = (self.cursor, self.current_selection());
        let before = self.bus_watch.selection.replace(now.clone());
        if before.as_ref() == Some(&now) {
            return;
        }
        if before.is_none_or(|(cursor, _)| cursor != now.0) {
            self.publish(producer, Payload::CursorMoved(CursorMoved { offset: now.0 }));
        }
        self.publish(producer, Payload::SelectionChanged(SelectionChanged { cursor: now.0, selection: now.1 }));
    }

    /// A tool changed the selection in the document: publish it as that
    /// tool's doing, so the tool can tell it from a selection to follow.
    pub fn publish_selection(&mut self, producer: &str) {
        self.publish_selection_if_changed(producer);
    }

    /// Publish each producer's pinned findings (templates, the structure
    /// map, crypto constants, a comparison, checksums, protocol messages,
    /// live changes) when they changed; a producer whose findings went
    /// publishes an empty list.
    fn publish_pinned_findings(&mut self) {
        if self.bench.pinned == self.bus_watch.pinned {
            return;
        }
        let mut sources: Vec<&str> = self.bench.pinned.iter().chain(&self.bus_watch.pinned).map(|finding| finding.source.as_str()).collect();
        sources.sort_unstable();
        sources.dedup();
        for source in sources {
            let findings: Vec<Finding> = self.bench.pinned.iter().filter(|finding| finding.source == source).cloned().collect();
            let mut draft = self.draft(format!("tool:{source}"), Payload::FindingsPublished(FindingsPublished { findings: Vec::new() }));
            if let Some(start) = findings.iter().map(|finding| finding.start).min() {
                let end = findings.iter().map(Finding::end).max().unwrap_or(start);
                draft = draft.span(start, end - start);
            }
            draft.payload = Payload::FindingsPublished(FindingsPublished { findings });
            self.bus.publish(draft);
        }
        self.bus_watch.pinned = self.bench.pinned.clone();
    }

    /// Publish what plugins logged, from actions, loading and background
    /// scans alike.
    pub(crate) fn publish_plugin_log(&mut self) {
        let Some(host) = &self.plugin_host else { return };
        // A plugin action holds the host; its lines are collected after it.
        let Ok(mut host) = host.try_lock() else { return };
        for line in host.take_entries() {
            self.bus.publish(Draft::new(format!("plugin:{}", line.plugin), Payload::PluginLog(line)));
        }
    }

    /// Start a background job: publish `job.started`, returning its id.
    pub fn publish_job_started(&mut self, kind: &str, title: &str) -> String {
        let job = self.bus.new_job_id(kind);
        self.publish(format!("tool:{kind}"), Payload::JobStarted(JobStarted { job: job.clone(), title: title.to_string() }));
        job
    }
}

/// A finished job's message, for a background thread to publish.
pub fn job_finished(job: &str, title: &str, ok: bool, outcome: impl Into<String>) -> Draft {
    let kind = job.rsplit_once('-').map_or(job, |(kind, _)| kind);
    Draft::new(format!("tool:{kind}"), Payload::JobFinished(JobFinished { job: job.to_string(), title: title.to_string(), ok, outcome: outcome.into() }))
}

/// Errors from plugins, in a background scan or anywhere else, go to the
/// status bar so they are seen.
fn show_plugin_error(app: &mut ViewerApp, message: &Arc<Message>) {
    if let Some(line) = message.payload_as::<PluginLog>()
        && line.level == LogLevel::Error
    {
        app.status = format!("Plugin {} failed: {}", line.plugin, line.text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Launch;
    use crate::bus::Kind;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        app
    }

    /// The topics delivered after `cursor`, in order.
    fn topics_since(app: &ViewerApp, cursor: u64) -> Vec<Topic> {
        app.bus.changed_since(cursor).messages.iter().map(|message| message.topic()).collect()
    }

    #[test]
    fn opening_a_document_says_the_last_one_closed_and_forgets_what_was_known_about_it() {
        let mut app = app_with(b"first document");
        app.bus.publish(app.draft("tool:test", Payload::RecordWidthEstimated(RecordWidthEstimated { width: 4, score: 1.0, alternatives: Vec::new() })));
        app.run_bus();
        assert_eq!(app.bus.facts().count(), 1);
        let cursor = app.bus.cursor();
        app.open_bytes(b"second".to_vec(), "second.bin".to_string());
        app.run_bus();
        assert_eq!(&topics_since(&app, cursor)[..2], [Topic::DocumentClosed, Topic::DocumentOpened]);
        let opened = app.bus.recent().rev().find_map(|message| message.payload_as::<DocumentOpened>()).unwrap();
        assert_eq!((opened.name.as_str(), opened.len), ("second.bin", 6));
        assert_eq!(app.bus.facts().count(), 0, "facts about the first document are gone");
    }

    #[test]
    fn edits_are_published_once_a_frame_from_the_edit_log() {
        let mut app = app_with(&[0u8; 64]);
        let cursor = app.bus.cursor();
        app.document.insert(4, b"ab");
        app.document.delete(0, 1);
        app.run_bus();
        app.run_bus();
        let edited: Vec<_> = app.bus.changed_since(cursor).messages.iter().filter_map(|message| message.payload_as::<DocumentEdited>().cloned()).collect();
        assert_eq!(edited.len(), 1, "both edits in one message");
        assert_eq!(edited[0].edits.iter().map(|edit| edit.version).collect::<Vec<_>>(), [1, 2]);
        assert!(edited[0].complete);
    }

    #[test]
    fn moving_the_cursor_and_selecting_are_published_once_each() {
        let mut app = app_with(&[0u8; 64]);
        let cursor = app.bus.cursor();
        app.set_cursor(10, false);
        app.run_bus();
        app.run_bus();
        assert_eq!(topics_since(&app, cursor), [Topic::CursorMoved, Topic::SelectionChanged]);
        let cursor = app.bus.cursor();
        app.anchor = Some(4);
        app.run_bus();
        assert_eq!(topics_since(&app, cursor), [Topic::SelectionChanged], "the cursor stayed put");
        let changed = app.bus.recent().last().unwrap();
        assert_eq!(changed.producer(), MAIN_VIEW);
        assert_eq!(changed.payload_as::<SelectionChanged>().unwrap().selection, Some(Selection::Range(4, 6)));
    }

    #[test]
    fn applying_a_template_publishes_its_structure_and_its_pinned_findings() {
        let mut app = app_with(&[1u8; 256]);
        let source = crate::templates::builtin_templates().first().map(|(_, source)| source.to_string()).unwrap();
        app.apply_template_source(&source);
        app.run_bus();
        let structure = app.bus.facts().find(|fact| fact.topic() == Topic::StructureIdentified && fact.producer() == "tool:templates").expect("the applied template");
        assert!(structure.payload_as::<StructureIdentified>().unwrap().format.starts_with("template:"));
        let findings = app.bus.facts().find(|fact| fact.topic() == Topic::FindingsPublished && fact.producer() == "tool:templates").expect("the pinned records");
        assert_eq!(findings.topic().kind(), Kind::Fact);
        assert!(!findings.payload_as::<FindingsPublished>().unwrap().findings.is_empty());
    }
}
