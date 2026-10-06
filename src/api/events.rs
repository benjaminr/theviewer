//! `events.*`: what tools, panels and plugins published on the workspace
//! bus. `events.facts` reads the retained facts; `events.poll` lists every
//! message delivered after a cursor, so a client can keep up by passing
//! back the `next` it was given.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::ApiError;
use super::workspace::{self, Workspace};
use crate::bus::{Kind, Message, Span, Topic};

/// Messages `events.poll` returns when no limit is given.
const DEFAULT_POLL_LIMIT: usize = 100;
/// Most messages one `events.poll` returns.
const MOST_POLLED: usize = 1000;

/// Bytes to look for facts about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpanParam {
    pub start: usize,
    pub len: usize,
}

/// Parameters of `events.facts`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FactsParams {
    /// Only facts on this topic, such as "record_width.estimated".
    #[serde(default)]
    pub topic: Option<String>,
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Only facts whose span overlaps these bytes.
    #[serde(default)]
    pub span: Option<SpanParam>,
    /// Only facts from this producer, such as "tool:period-scan".
    #[serde(default)]
    pub producer: Option<String>,
}

/// Parameters of `events.poll`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PollParams {
    /// The `next` of the previous poll; omitted, every message still held.
    #[serde(default)]
    pub cursor: Option<u64>,
    /// Only messages on these topics.
    #[serde(default)]
    pub topics: Option<Vec<String>>,
    /// Most messages to return (default 100, at most 1000).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// One message with its envelope, as the API returns it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MessageEntry {
    /// Such as "evt-12".
    pub id: String,
    pub topic: String,
    pub kind: Kind,
    /// Who published it, such as "tool:period-scan" or "plugin:modbus_rtu.lua".
    pub producer: String,
    /// The document it is about.
    pub document: Option<String>,
    /// The document version it describes.
    pub version: u64,
    /// The bytes it is about.
    pub span: Option<Span>,
    /// 0 to 1, when the producer could say.
    pub confidence: Option<f32>,
    /// Tells apart several facts one producer keeps on a topic.
    pub key: String,
    /// The message whose reaction published this one.
    pub caused_by: Option<String>,
    /// The topic's payload; `api.describe` lists each topic's schema.
    pub payload: Value,
    /// A fact about an older version of its document than the newest.
    pub stale: bool,
    /// A fact withdrawn by its producer.
    pub retracted: bool,
}

/// The result of `events.facts`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FactsResult {
    /// The facts, by topic, producer and key.
    pub facts: Vec<MessageEntry>,
}

/// The result of `events.poll`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PollResult {
    /// Messages delivered after the cursor, oldest first.
    pub messages: Vec<MessageEntry>,
    /// Pass back as `cursor` to get the messages after these.
    pub next: u64,
    /// Messages delivered after the cursor but no longer held.
    pub missed: u64,
}

/// A message as the API returns it.
fn entry(message: &Message, stale: bool) -> MessageEntry {
    let draft = &message.draft;
    MessageEntry {
        id: message.id.to_string(),
        topic: message.topic_name().to_string(),
        kind: message.topic().kind(),
        producer: draft.producer.clone(),
        document: draft.document.clone(),
        version: draft.version,
        span: draft.span,
        confidence: draft.confidence,
        key: draft.key.clone(),
        caused_by: draft.caused_by.map(|cause| cause.to_string()),
        payload: draft.payload.payload_json(),
        stale,
        retracted: draft.retracts,
    }
}

/// The topic called `name`, or an error listing them.
fn topic_named(name: &str) -> Result<Topic, ApiError> {
    Topic::named(name).ok_or_else(|| {
        let names: Vec<&str> = crate::bus::topics::TOPICS.iter().map(|info| info.name).collect();
        ApiError::invalid_params(format!("there is no topic '{name}'; the topics are {}", names.join(", ")))
    })
}

pub fn facts(workspace: &mut dyn Workspace, params: FactsParams) -> Result<FactsResult, ApiError> {
    let topic = params.topic.as_deref().map(topic_named).transpose()?;
    let doc = workspace::resolve(workspace, params.doc.as_deref())?;
    let bus = workspace.bus();
    let facts = bus
        .facts()
        .filter(|fact| topic.is_none_or(|topic| fact.topic() == topic))
        .filter(|fact| fact.draft.document.as_deref() == Some(doc.as_str()))
        .filter(|fact| params.producer.as_deref().is_none_or(|producer| fact.producer() == producer))
        .filter(|fact| params.span.is_none_or(|span| fact.draft.span.is_some_and(|own| own.overlaps(span.start, span.len))))
        .map(|fact| entry(fact, bus.is_stale(fact)))
        .collect();
    Ok(FactsResult { facts })
}

pub fn poll(workspace: &mut dyn Workspace, params: PollParams) -> Result<PollResult, ApiError> {
    let topics = params.topics.unwrap_or_default();
    for name in &topics {
        topic_named(name)?;
    }
    let limit = params.limit.unwrap_or(DEFAULT_POLL_LIMIT).clamp(1, MOST_POLLED);
    let bus = workspace.bus();
    let changes = bus.changed_since(params.cursor.unwrap_or(0));
    let mut next = bus.cursor();
    let mut messages = Vec::new();
    for message in changes.messages.iter().filter(|message| topics.is_empty() || topics.iter().any(|name| name == message.topic_name())) {
        if messages.len() == limit {
            next = message.id.0 - 1;
            break;
        }
        let stale = message.topic().kind() == Kind::Fact && bus.is_stale(message);
        messages.push(entry(message, stale));
    }
    Ok(PollResult { messages, next, missed: changes.missed })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::workspace::Workspace;
    use crate::api::ErrorCode;
    use crate::api::test_support::call;
    use crate::bus::topics::{DocumentEdited, FramesDefined, RecordWidthEstimated};
    use crate::bus::{Draft, Payload};
    use crate::document::Edit;

    fn width(width: usize) -> Payload {
        Payload::RecordWidthEstimated(RecordWidthEstimated { width, score: 0.8, alternatives: vec![width * 2] })
    }

    #[test]
    fn facts_are_read_by_topic_producer_and_span_with_their_staleness() {
        let mut workspace = workspace_with("a.bin", &[0; 4096]);
        let bus = workspace.bus();
        bus.publish(Draft::new("tool:period-scan", width(48)).about("doc-1", 0).span(0, 1024).confidence(0.8));
        bus.publish(Draft::new("tool:protocol", Payload::FramesDefined(FramesDefined::new([(2048, 16)].into_iter(), "test"))).about("doc-1", 0).span(2048, 16));
        bus.publish(Draft::new("document", Payload::DocumentEdited(DocumentEdited { edits: vec![Edit { version: 1, at: 100, removed: 1, inserted: 1 }], complete: true })).about("doc-1", 1));

        let all = call(&mut workspace, "events.facts", json!({})).unwrap();
        assert_eq!(all["facts"].as_array().unwrap().len(), 2);
        let width = call(&mut workspace, "events.facts", json!({"topic": "record_width.estimated", "doc": "current"})).unwrap();
        let fact = &width["facts"][0];
        assert_eq!((fact["producer"].as_str(), fact["payload"]["width"].as_u64()), (Some("tool:period-scan"), Some(48)));
        assert_eq!(fact["kind"], "fact");
        assert_eq!(fact["stale"], true, "the edit landed inside its span");
        let frames = call(&mut workspace, "events.facts", json!({"span": {"start": 2050, "len": 1}})).unwrap();
        assert_eq!(frames["facts"][0]["producer"], "tool:protocol");
        assert_eq!(frames["facts"][0]["stale"], false, "carried forward through an edit elsewhere");
        let none = call(&mut workspace, "events.facts", json!({"producer": "tool:nobody"})).unwrap();
        assert!(none["facts"].as_array().unwrap().is_empty());
        assert_eq!(call(&mut workspace, "events.facts", json!({"topic": "weather.report"})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn polling_returns_what_was_delivered_after_the_cursor_a_page_at_a_time() {
        let mut workspace = workspace_with("a.bin", &[0; 16]);
        let first = call(&mut workspace, "events.poll", json!({})).unwrap();
        assert_eq!(first["messages"][0]["topic"], "document.opened", "opening the document was published");
        let cursor = first["next"].as_u64().unwrap();
        for n in 1..=5 {
            workspace.bus().publish(Draft::new("tool:period-scan", width(n)).about("doc-1", 0));
        }
        let page = call(&mut workspace, "events.poll", json!({"cursor": cursor, "limit": 2})).unwrap();
        let widths: Vec<u64> = page["messages"].as_array().unwrap().iter().map(|message| message["payload"]["width"].as_u64().unwrap()).collect();
        assert_eq!(widths, [1, 2]);
        let rest = call(&mut workspace, "events.poll", json!({"cursor": page["next"], "topics": ["record_width.estimated"]})).unwrap();
        assert_eq!(rest["messages"].as_array().unwrap().len(), 3);
        let after = call(&mut workspace, "events.poll", json!({"cursor": rest["next"]})).unwrap();
        assert!(after["messages"].as_array().unwrap().is_empty());
        assert_eq!(after["missed"], 0);
        let filtered = call(&mut workspace, "events.poll", json!({"cursor": cursor, "topics": ["plugin.log"]})).unwrap();
        assert!(filtered["messages"].as_array().unwrap().is_empty());
        assert_eq!(filtered["next"], rest["next"], "skipping other topics still moves the cursor on");
    }
}
