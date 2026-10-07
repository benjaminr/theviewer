//! Dock panel: what is known about the document and what has happened, as
//! the workspace bus holds it.
//!
//! Retained facts are listed by topic, each with its producer, the document
//! version it describes (dimmed once stale) and its span, which selects the
//! bytes when clicked; "why" shows the messages that led to it. Below,
//! the recent messages scroll past, filtered by topic, with any messages the
//! bus dropped as loops.

use std::sync::Arc;

use eframe::egui::{self, RichText, Sense, Ui};

use crate::app::ViewerApp;
use crate::bus::topics::{self, LogLevel};
use crate::bus::{Message, MessageId, Payload, Topic};
use crate::theme;

/// Height of the recent messages' log.
const LOG_HEIGHT: f32 = 220.0;
/// Least height the facts get when the pane is short.
const FACTS_MIN_HEIGHT: f32 = 80.0;
/// Most recent messages listed.
const LOG_LINES: usize = 300;

/// What the panel remembers between frames.
#[derive(Default)]
pub struct WorkspaceState {
    /// The topic the log shows, or every topic.
    pub log_topic: Option<Topic>,
    /// The fact whose causes are shown.
    pub why: Option<MessageId>,
}

pub fn show_workspace(state: &mut WorkspaceState, app: &mut ViewerApp, ui: &mut Ui) {
    let facts: Vec<Arc<Message>> = app.bus.facts().cloned().collect();
    ui.label(
        RichText::new(format!("{} facts kept · {} messages delivered · {} reactions", facts.len(), app.bus.cursor(), app.reactions().len()))
            .small()
            .color(theme::TEXT_DIM),
    )
    .on_hover_text("What the tools, panels and plugins published on the workspace bus. Facts are kept, the latest per producer; events pass by.");
    let mut select = None;
    egui::ScrollArea::vertical().id_salt("workspace-facts").max_height((ui.available_height() - LOG_HEIGHT - 40.0).max(FACTS_MIN_HEIGHT)).show(ui, |ui| {
        if facts.is_empty() {
            ui.label(RichText::new("Nothing is known yet: run the report, a period scan or the protocol tool, or move the cursor onto a structure.").color(theme::TEXT_DIM));
        }
        for info in topics::TOPICS.iter().filter(|info| info.kind == topics::Kind::Fact) {
            let on_topic: Vec<&Arc<Message>> = facts.iter().filter(|fact| fact.topic() == info.topic).collect();
            if on_topic.is_empty() {
                continue;
            }
            egui::CollapsingHeader::new(format!("{} ({})", info.name, on_topic.len())).id_salt(info.name).default_open(true).show(ui, |ui| {
                for fact in on_topic {
                    show_fact(state, app, ui, fact, &mut select);
                }
            });
        }
    });
    ui.separator();
    show_log(state, app, ui, &mut select);
    if let Some((start, len)) = select {
        select_span(app, start, len);
    }
}

/// One fact: producer, version, span, a summary and "why".
fn show_fact(state: &mut WorkspaceState, app: &ViewerApp, ui: &mut Ui, fact: &Arc<Message>, select: &mut Option<(usize, usize)>) {
    let stale = app.bus.is_stale(fact);
    let colour = if stale { theme::TEXT_DIM } else { theme::TEXT };
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(fact.producer()).monospace().color(colour));
        let version = RichText::new(format!("v{}{}", fact.draft.version, if stale { " · stale" } else { "" })).small().color(theme::TEXT_DIM);
        ui.label(version).on_hover_text(if stale { "Describes the document before its latest edit" } else { "Describes the document as it is" });
        span_link(ui, fact, select);
        ui.label(RichText::new(summary(fact.payload(), app.document.len())).color(colour));
        if fact.draft.caused_by.is_some() && ui.small_button("why").clicked() {
            state.why = if state.why == Some(fact.id) { None } else { Some(fact.id) };
        }
    });
    if state.why == Some(fact.id) {
        for (depth, cause) in app.bus.cause_chain(fact).iter().enumerate().skip(1) {
            ui.label(RichText::new(format!("{}↳ {} {} from {}", "  ".repeat(depth), cause.id, cause.topic_name(), cause.producer())).small().color(theme::TEXT_DIM));
        }
    }
}

/// The span as a link that selects its bytes.
fn span_link(ui: &mut Ui, message: &Message, select: &mut Option<(usize, usize)>) {
    let Some(span) = message.draft.span else { return };
    let text = if span.len == 0 { format!("{:#x}", span.start) } else { format!("{:#x}–{:#x}", span.start, span.end()) };
    let link = ui.add(egui::Label::new(RichText::new(text).monospace().color(theme::ACCENT)).sense(Sense::click()));
    if link.on_hover_text("Select these bytes").clicked() {
        *select = Some((span.start, span.len));
    }
}

/// The recent messages, newest last, of one topic or all.
fn show_log(state: &mut WorkspaceState, app: &ViewerApp, ui: &mut Ui, select: &mut Option<(usize, usize)>) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Recent").strong());
        egui::ComboBox::from_id_salt("workspace-log-topic").selected_text(state.log_topic.map_or("every topic", Topic::name)).show_ui(ui, |ui| {
            ui.selectable_value(&mut state.log_topic, None, "every topic");
            for info in topics::TOPICS {
                ui.selectable_value(&mut state.log_topic, Some(info.topic), info.name);
            }
        });
    });
    let problems: Vec<&str> = app.bus.problems().collect();
    for problem in problems.iter().rev().take(3) {
        ui.label(RichText::new(format!("Dropped: {problem}")).small().color(theme::DANGER));
    }
    let shown: Vec<&Arc<Message>> = app.bus.recent().rev().filter(|message| state.log_topic.is_none_or(|topic| message.topic() == topic)).take(LOG_LINES).collect();
    egui::ScrollArea::vertical().id_salt("workspace-log").max_height(LOG_HEIGHT).stick_to_bottom(true).show(ui, |ui| {
        for message in shown.into_iter().rev() {
            let failed = message.payload_as::<topics::PluginLog>().is_some_and(|line| line.level == LogLevel::Error);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(message.id.to_string()).small().monospace().color(theme::TEXT_DIM));
                ui.label(RichText::new(message.topic_name()).small().monospace());
                ui.label(RichText::new(message.producer()).small().color(theme::TEXT_DIM));
                span_link(ui, message, select);
                ui.label(RichText::new(summary(message.payload(), app.document.len())).small().color(if failed { theme::DANGER } else { theme::TEXT }));
            });
        }
    });
}

/// Select `len` bytes at `start`, or put the cursor there, as the person's
/// step.
fn select_span(app: &mut ViewerApp, start: usize, len: usize) {
    app.select_from_tool(start, len);
}

/// Characters of a plugin's own payload shown in the log.
const CUSTOM_SUMMARY_CHARS: usize = 80;

/// A few words on a payload, for a document `document_len` bytes long.
fn summary(payload: &Payload, document_len: usize) -> String {
    match payload {
        Payload::DocumentOpened(opened) => format!("{} ({} bytes)", opened.name, opened.len),
        Payload::DocumentClosed(closed) => closed.name.clone(),
        Payload::DocumentEdited(edited) => format!("{} change(s){}", edited.edits.len(), if edited.complete { "" } else { ", some forgotten" }),
        Payload::CursorMoved(cursor) => format!("{:#x}", cursor.offset),
        Payload::ViewJump(jump) => format!("{:#x}", jump.offset),
        Payload::PaneShow(shown) => shown.pane.clone(),
        Payload::TemplateApplyRequested(requested) => requested.source.lines().next().unwrap_or_default().to_string(),
        Payload::ViewPointed(pointed) => pointed.bytes.map_or_else(|| "nothing".to_string(), |span| format!("{} bytes at {:#x}", span.len, span.start)),
        Payload::SelectionChanged(changed) => match &changed.selection {
            Some(selection) => format!("{} from {:#x}", selection.describe(document_len), selection.ranges(document_len).first().map_or(changed.cursor, |&(start, _)| start)),
            None => format!("nothing selected, cursor at {:#x}", changed.cursor),
        },
        Payload::FindingsPublished(published) => match published.findings.as_slice() {
            [] => "nothing found".to_string(),
            [only] => only.title.clone(),
            many => format!("{} findings, such as {}", many.len(), many[0].title),
        },
        Payload::StructureIdentified(structure) => format!("{} ({} fields)", structure.title, structure.fields.len()),
        Payload::FieldsDecoded(decoded) => decoded.layers.iter().map(|layer| layer.name.as_str()).collect::<Vec<_>>().join(" / "),
        Payload::TemplateApplied(applied) => format!("{} at {:#x} ({} records)", applied.name, applied.structure.start, applied.records),
        Payload::RegionsMapped(mapped) => format!("{} regions", mapped.regions.len()),
        Payload::RecordWidthEstimated(estimate) => format!("{} bytes (score {:.2})", estimate.width, estimate.score),
        Payload::FramesDefined(defined) => format!("{} frames: {}", defined.total, defined.origin),
        Payload::FieldsGuessed(guessed) => format!("{} fields{}", guessed.fields.len(), if guessed.template.is_some() { ", with a template" } else { "" }),
        Payload::ProtocolIdentified(identified) => format!("{}: {}", identified.protocol, identified.how),
        Payload::ReferenceFocus(focus) => focus.key.clone(),
        Payload::JobStarted(started) => started.title.clone(),
        Payload::JobProgress(progress) => match progress.total {
            Some(total) => format!("{} of {total}", progress.done),
            None => progress.done.to_string(),
        },
        Payload::JobFinished(finished) => format!("{}: {}", finished.title, finished.outcome),
        Payload::PluginLog(line) => format!("{}: {}", line.plugin, line.text),
        Payload::JournalRecorded(recorded) => format!("step {} by {}: {}", recorded.step, recorded.caller, recorded.description),
        Payload::Custom(custom) => {
            let text = custom.payload.to_string();
            if text.chars().count() > CUSTOM_SUMMARY_CHARS { format!("{}…", text.chars().take(CUSTOM_SUMMARY_CHARS).collect::<String>()) } else { text }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::actions::take_performed;
    use crate::app::Launch;

    #[test]
    fn a_fact_s_span_clicked_selects_its_bytes_or_moves_the_cursor_through_the_api() {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(vec![0; 64], "test.bin".to_string());
        app.run_bus();
        take_performed();
        select_span(&mut app, 8, 4);
        select_span(&mut app, 32, 0);
        assert_eq!(take_performed(), [("selection.set".to_string(), json!({"selection": {"range": [8, 4]}})), ("cursor.set".to_string(), json!({"offset": 32}))]);
        assert_eq!((app.cursor, app.selection()), (32, None));
        app.run_bus();
        let moved = app.bus.recent().rfind(|message| message.topic() == Topic::CursorMoved).expect("published");
        assert_eq!(moved.producer(), "panel");
    }
}
