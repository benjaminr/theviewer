//! The workspace bus: where tools, panels and plugins publish what they
//! learn as typed messages on named topics, and read what others published.
//!
//! There are two kinds of message (see [`topics`]):
//!
//! * **Facts** are retained: the latest per `(topic, producer, document,
//!   key)` is kept until a newer one replaces it. A fact about an older
//!   document version is kept but counts as stale, unless it has a span the
//!   edits since did not touch, in which case it is carried forward to the
//!   new version (its offsets moved with the edits).
//! * **Events** are transient: something happened.
//!
//! Anything may publish, from any thread, through a cloneable [`Publisher`].
//! Messages wait in one queue until the owner delivers them, in publication
//! order: the window does so once per frame at a fixed point in its
//! `logic()`, running the reactions registered for each topic (see
//! [`window`]). Delivery gives each message its id, keeps facts, and drops
//! loops: a message more than [`MAX_CAUSE_DEPTH`] reactions removed from its
//! origin, or a fact identical to the one it would replace.
//!
//! In-process consumers pull: [`Bus::latest`] and [`Bus::facts_in`] read
//! retained facts, and [`Bus::changed_since`] lists what was delivered after
//! a cursor. See `docs/design/shared-knowledge-and-api.md`, section 1.

pub mod topics;
pub mod window;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::document::map_span_through;
pub use topics::{Kind, Payload, Topic, TopicPayload};

/// How many reactions deep a chain of messages may go before the next
/// message is dropped as a loop.
pub const MAX_CAUSE_DEPTH: u8 = 8;
/// Messages kept for [`Bus::changed_since`] and the Workspace tab's log.
const RECENT_LIMIT: usize = 1000;
/// Problems (dropped messages) kept for the Workspace tab.
const PROBLEM_LIMIT: usize = 50;

/// A delivered message's id, unique for the bus and increasing in delivery
/// order, written `evt-12`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub u64);

impl fmt::Display for MessageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "evt-{}", self.0)
    }
}

/// Bytes a message is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Span {
    pub start: usize,
    pub len: usize,
}

impl Span {
    pub fn end(self) -> usize {
        self.start + self.len
    }

    /// Whether the span shares a byte with `[start, start + len)`; an empty
    /// span counts as the byte it sits on.
    pub fn overlaps(self, start: usize, len: usize) -> bool {
        self.start < start + len.max(1) && start < self.start + self.len.max(1)
    }
}

/// A message to publish, before it is delivered and given an id.
#[derive(Clone, Debug, PartialEq)]
pub struct Draft {
    pub payload: Payload,
    /// A stable id: `tool:period-scan`, `parser:pcap`, `panel:packets`,
    /// `plugin:modbus_rtu.lua` or `mcp:claude-code`.
    pub producer: String,
    /// The document's id (`doc-1`), when the message is about one.
    pub document: Option<String>,
    /// The document version the message describes.
    pub version: u64,
    pub span: Option<Span>,
    /// 0 to 1, when the producer can say.
    pub confidence: Option<f32>,
    /// Tells apart several facts one producer keeps on a topic.
    pub key: String,
    /// The message whose reaction published this one.
    pub caused_by: Option<MessageId>,
    /// Withdraws the fact with the same topic, producer, document and key
    /// instead of publishing one.
    pub retracts: bool,
}

impl Draft {
    pub fn new(producer: impl Into<String>, payload: Payload) -> Draft {
        Draft { payload, producer: producer.into(), document: None, version: 0, span: None, confidence: None, key: String::new(), caused_by: None, retracts: false }
    }

    /// About `document` at `version`.
    pub fn about(mut self, document: impl Into<String>, version: u64) -> Draft {
        self.document = Some(document.into());
        self.version = version;
        self
    }

    pub fn span(mut self, start: usize, len: usize) -> Draft {
        self.span = Some(Span { start, len });
        self
    }

    pub fn confidence(mut self, confidence: f32) -> Draft {
        self.confidence = Some(confidence);
        self
    }

    pub fn key(mut self, key: impl Into<String>) -> Draft {
        self.key = key.into();
        self
    }

    pub fn caused_by(mut self, cause: MessageId) -> Draft {
        self.caused_by = Some(cause);
        self
    }

    /// Withdraw this producer's fact on the payload's topic (and key)
    /// instead of publishing it; the payload is not kept.
    pub fn retraction(mut self) -> Draft {
        self.retracts = true;
        self
    }
}

/// A delivered message: a draft with its id and how many reactions deep it is.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub id: MessageId,
    pub draft: Draft,
    /// Reactions between the message that started the chain and this one.
    pub depth: u8,
}

impl Message {
    pub fn topic(&self) -> Topic {
        self.draft.payload.topic()
    }

    /// The topic's name, a plugin's own topic's included.
    pub fn topic_name(&self) -> &str {
        self.draft.payload.topic_name()
    }

    pub fn payload(&self) -> &Payload {
        &self.draft.payload
    }

    pub fn producer(&self) -> &str {
        &self.draft.producer
    }

    /// The payload as type `T`, when the message is on `T`'s topic.
    pub fn payload_as<T: TopicPayload>(&self) -> Option<&T> {
        T::from_payload(&self.draft.payload)
    }

    /// Where retained: one fact per topic, producer, document and key.
    fn fact_key(&self) -> FactKey {
        (self.topic(), self.draft.producer.clone(), self.draft.document.clone(), self.draft.key.clone())
    }

    /// The message as plugins and remote clients receive it: the envelope
    /// of the design, with the payload typed by its topic.
    pub fn to_json(&self) -> Value {
        let mut envelope = serde_json::json!({ "topic": self.topic_name(), "payload": self.draft.payload.payload_json() });
        let Some(object) = envelope.as_object_mut() else { return Value::Null };
        let draft = &self.draft;
        object.insert("id".into(), Value::String(self.id.to_string()));
        object.insert("kind".into(), serde_json::to_value(self.topic().kind()).unwrap_or(Value::Null));
        object.insert("producer".into(), Value::String(draft.producer.clone()));
        object.insert("document".into(), draft.document.clone().map_or(Value::Null, Value::String));
        object.insert("version".into(), Value::from(draft.version));
        object.insert("span".into(), serde_json::to_value(draft.span).unwrap_or(Value::Null));
        object.insert("confidence".into(), draft.confidence.map_or(Value::Null, |confidence| Value::from(f64::from(confidence))));
        object.insert("key".into(), Value::String(draft.key.clone()));
        object.insert("caused_by".into(), draft.caused_by.map_or(Value::Null, |cause| Value::String(cause.to_string())));
        if draft.retracts {
            object.insert("retracted".into(), Value::Bool(true));
        }
        envelope
    }
}

type FactKey = (Topic, String, Option<String>, String);

/// Publishes onto a bus from anywhere: background threads keep a clone.
/// Messages wait until the bus's owner delivers them.
#[derive(Clone)]
pub struct Publisher {
    sender: Sender<Draft>,
}

impl Publisher {
    pub fn publish(&self, draft: Draft) {
        // The bus has gone only when the app is closing; nothing is lost.
        let _ = self.sender.send(draft);
    }
}

/// Delivered messages since a cursor.
#[derive(Clone, Debug, Default)]
pub struct Changes {
    pub messages: Vec<Arc<Message>>,
    /// Messages delivered after the cursor but no longer held.
    pub missed: u64,
}

/// The queue, the retained facts and the recent messages.
pub struct Bus {
    publisher: Publisher,
    queue: Receiver<Draft>,
    next_id: u64,
    retained: BTreeMap<FactKey, Arc<Message>>,
    recent: VecDeque<Arc<Message>>,
    /// The newest version each document is known to be at.
    versions: HashMap<String, u64>,
    /// Messages dropped as loops, newest last.
    problems: VecDeque<String>,
    jobs_started: u64,
}

impl Default for Bus {
    fn default() -> Self {
        let (sender, queue) = mpsc::channel();
        Bus {
            publisher: Publisher { sender },
            queue,
            next_id: 0,
            retained: BTreeMap::new(),
            recent: VecDeque::new(),
            versions: HashMap::new(),
            problems: VecDeque::new(),
            jobs_started: 0,
        }
    }
}

impl Bus {
    pub fn new() -> Self {
        Self::default()
    }

    /// A publisher for a background job.
    pub fn publisher(&self) -> Publisher {
        self.publisher.clone()
    }

    /// Queue a message for the next delivery.
    pub fn publish(&self, draft: Draft) {
        self.publisher.publish(draft);
    }

    /// An id for a new background job, such as `period-scan-3`.
    pub fn new_job_id(&mut self, kind: &str) -> String {
        self.jobs_started += 1;
        format!("{kind}-{}", self.jobs_started)
    }

    /// Deliver the next queued message that is not dropped, in publication
    /// order. The caller runs its reactions before asking for the next.
    pub fn deliver_next(&mut self) -> Option<Arc<Message>> {
        while let Ok(draft) = self.queue.try_recv() {
            if let Some(message) = self.accept(draft) {
                return Some(message);
            }
        }
        None
    }

    /// Deliver everything queued, without reactions (for workspaces with no
    /// frame loop).
    pub fn deliver_all(&mut self) -> Vec<Arc<Message>> {
        std::iter::from_fn(|| self.deliver_next()).collect()
    }

    /// Check a draft against the loop rules, give it an id and keep it.
    fn accept(&mut self, draft: Draft) -> Option<Arc<Message>> {
        let depth = match draft.caused_by {
            None => 0,
            Some(cause) => self.find(cause).map_or(1, |cause| cause.depth.saturating_add(1)),
        };
        if depth > MAX_CAUSE_DEPTH {
            self.note_problem(format!("dropped {} from {}: {depth} reactions deep, which looks like a loop", draft.payload.topic().name(), draft.producer));
            return None;
        }
        if draft.payload.topic().kind() == Kind::Fact {
            let key = (draft.payload.topic(), draft.producer.clone(), draft.document.clone(), draft.key.clone());
            let kept = self.retained.get(&key);
            // Nothing new, or nothing to withdraw.
            if draft.retracts && kept.is_none() || !draft.retracts && kept.is_some_and(|kept| same_fact(&kept.draft, &draft)) {
                return None;
            }
        }
        self.next_id += 1;
        let message = Arc::new(Message { id: MessageId(self.next_id), draft, depth });
        self.keep(&message);
        Some(message)
    }

    /// Note what a delivered message changes: documents' versions, which
    /// facts are kept, and the recent log.
    fn keep(&mut self, message: &Arc<Message>) {
        let draft = &message.draft;
        match (&draft.payload, &draft.document) {
            (Payload::DocumentOpened(_) | Payload::DocumentClosed(_), Some(document)) => {
                self.retained.retain(|_, fact| fact.draft.document.as_ref() != Some(document));
                self.versions.insert(document.clone(), draft.version);
            }
            (Payload::DocumentEdited(edited), Some(document)) => {
                self.versions.insert(document.clone(), draft.version);
                // Facts can be carried only through every change up to the new version.
                if edited.complete && edited.edits.last().is_some_and(|last| last.version == draft.version) {
                    self.carry_forward(document, &edited.edits, draft.version);
                }
            }
            (_, Some(document)) => {
                let known = self.versions.entry(document.clone()).or_insert(draft.version);
                *known = (*known).max(draft.version);
            }
            _ => {}
        }
        if draft.payload.topic().kind() == Kind::Fact {
            if draft.retracts {
                self.retained.remove(&message.fact_key());
            } else {
                self.retained.insert(message.fact_key(), Arc::clone(message));
            }
        }
        if self.recent.len() == RECENT_LIMIT {
            self.recent.pop_front();
        }
        self.recent.push_back(Arc::clone(message));
    }

    /// Move the facts about `document` whose spans `edits` did not touch to
    /// `version`, with their offsets; the rest stay as they were (stale).
    fn carry_forward(&mut self, document: &str, edits: &[crate::document::Edit], version: u64) {
        for fact in self.retained.values_mut() {
            let draft = &fact.draft;
            if draft.document.as_deref() != Some(document) || draft.version >= version {
                continue;
            }
            let Some(span) = draft.span else { continue };
            let Some((start, len)) = map_span_through(edits, draft.version, span.start, span.len) else { continue };
            let mut carried = (**fact).clone();
            carried.draft.payload.move_offsets(start as isize - span.start as isize);
            carried.draft.span = Some(Span { start, len });
            carried.draft.version = version;
            *fact = Arc::new(carried);
        }
    }

    fn note_problem(&mut self, problem: String) {
        eprintln!("theviewer: bus {problem}");
        if self.problems.len() == PROBLEM_LIMIT {
            self.problems.pop_front();
        }
        self.problems.push_back(problem);
    }

    /// Messages dropped as loops, oldest first.
    pub fn problems(&self) -> impl Iterator<Item = &str> {
        self.problems.iter().map(String::as_str)
    }

    /// A recent message by id.
    pub fn find(&self, id: MessageId) -> Option<&Arc<Message>> {
        let index = self.recent.binary_search_by_key(&id, |message| message.id).ok()?;
        self.recent.get(index)
    }

    /// The newest version `document` is known to be at.
    pub fn document_version(&self, document: &str) -> Option<u64> {
        self.versions.get(document).copied()
    }

    /// Whether a fact describes an older version of its document than the
    /// newest one known.
    pub fn is_stale(&self, message: &Message) -> bool {
        let draft = &message.draft;
        draft.document.as_deref().and_then(|document| self.document_version(document)).is_some_and(|newest| draft.version < newest)
    }

    /// Every retained fact, by topic, producer, document and key.
    pub fn facts(&self) -> impl Iterator<Item = &Arc<Message>> {
        self.retained.values()
    }

    /// The newest fact on `T`'s topic about `document`, from any producer.
    pub fn latest<T: TopicPayload>(&self, document: &str) -> Option<(&Arc<Message>, &T)> {
        self.retained
            .values()
            .filter(|fact| fact.draft.document.as_deref() == Some(document))
            .filter_map(|fact| fact.payload_as::<T>().map(|payload| (fact, payload)))
            .max_by_key(|(fact, _)| fact.id)
    }

    /// Facts on `topic` about `document` whose span overlaps
    /// `[start, start + len)`.
    pub fn facts_in(&self, topic: Topic, document: &str, start: usize, len: usize) -> Vec<&Arc<Message>> {
        self.retained
            .values()
            .filter(|fact| fact.topic() == topic && fact.draft.document.as_deref() == Some(document))
            .filter(|fact| fact.draft.span.is_some_and(|span| span.overlaps(start, len)))
            .collect()
    }

    /// The id of the newest delivered message: a cursor for
    /// [`Bus::changed_since`].
    pub fn cursor(&self) -> u64 {
        self.next_id
    }

    /// The messages delivered after `cursor`, oldest first.
    pub fn changed_since(&self, cursor: u64) -> Changes {
        let first_held = self.recent.front().map_or(self.next_id + 1, |message| message.id.0);
        let missed = first_held.saturating_sub(cursor + 1);
        let messages = self.recent.iter().filter(|message| message.id.0 > cursor).cloned().collect();
        Changes { messages, missed }
    }

    /// The recent messages, oldest first.
    pub fn recent(&self) -> impl DoubleEndedIterator<Item = &Arc<Message>> {
        self.recent.iter()
    }

    /// `message` and the messages that caused it, newest first, as far back
    /// as they are still held.
    pub fn cause_chain(&self, message: &Arc<Message>) -> Vec<Arc<Message>> {
        let mut chain = vec![Arc::clone(message)];
        while let Some(cause) = chain.last().and_then(|last| last.draft.caused_by).and_then(|id| self.find(id)) {
            if chain.len() > usize::from(MAX_CAUSE_DEPTH) + 1 {
                break;
            }
            chain.push(Arc::clone(cause));
        }
        chain
    }

    /// Whether `producer` published `message` or anything that led to it.
    pub fn caused_by_producer(&self, message: &Arc<Message>, producer: &str) -> bool {
        self.cause_chain(message).iter().any(|link| link.producer() == producer)
    }
}

/// Whether `draft` says nothing new against the fact `kept`.
fn same_fact(kept: &Draft, draft: &Draft) -> bool {
    kept.version == draft.version && kept.span == draft.span && kept.confidence == draft.confidence && kept.payload == draft.payload
}

#[cfg(test)]
mod tests {
    use super::topics::*;
    use super::*;
    use crate::document::Edit;

    const DOC: &str = "doc-1";

    fn width(width: usize) -> Payload {
        Payload::RecordWidthEstimated(RecordWidthEstimated { width, score: 0.9, alternatives: Vec::new() })
    }

    fn reference(key: &str) -> Payload {
        Payload::ReferenceFocus(ReferenceFocus { key: key.to_string() })
    }

    fn edited(edits: Vec<Edit>) -> Payload {
        Payload::DocumentEdited(DocumentEdited { edits, complete: true })
    }

    fn frames(frames: &[(usize, usize)]) -> Payload {
        Payload::FramesDefined(FramesDefined::new(frames.iter().copied(), "test"))
    }

    #[test]
    fn the_latest_fact_per_producer_and_key_is_kept() {
        let mut bus = Bus::new();
        bus.publish(Draft::new("tool:period-scan", width(48)).about(DOC, 0));
        bus.publish(Draft::new("tool:period-scan", width(64)).about(DOC, 0));
        bus.publish(Draft::new("tool:bits", width(7)).about(DOC, 0).key("bits"));
        assert_eq!(bus.deliver_all().len(), 3);
        assert_eq!(bus.facts().count(), 2, "the period scan's second width replaced its first");
        let (fact, latest) = bus.latest::<RecordWidthEstimated>(DOC).unwrap();
        assert_eq!((fact.producer(), latest.width), ("tool:bits", 7), "the newest from any producer");
        assert!(bus.latest::<RecordWidthEstimated>("doc-2").is_none());
    }

    #[test]
    fn events_are_logged_but_not_kept_as_facts() {
        let mut bus = Bus::new();
        bus.publish(Draft::new("panel:packets", reference("udp")));
        let delivered = bus.deliver_all();
        assert_eq!(delivered.len(), 1);
        assert_eq!(bus.facts().count(), 0);
        assert_eq!(bus.changed_since(0).messages.len(), 1);
    }

    #[test]
    fn messages_are_delivered_in_publication_order_with_increasing_ids() {
        let mut bus = Bus::new();
        for key in ["a", "b", "c"] {
            bus.publish(Draft::new("test", reference(key)));
        }
        let keys: Vec<String> = bus.deliver_all().iter().map(|message| message.payload_as::<ReferenceFocus>().unwrap().key.clone()).collect();
        assert_eq!(keys, ["a", "b", "c"]);
        let ids: Vec<u64> = bus.recent().map(|message| message.id.0).collect();
        assert_eq!(ids, [1, 2, 3]);
        assert_eq!(bus.cursor(), 3);
        let since = bus.changed_since(1);
        assert_eq!(since.messages.len(), 2);
        assert_eq!(since.missed, 0);
    }

    #[test]
    fn a_fact_about_an_older_version_is_kept_but_stale() {
        let mut bus = Bus::new();
        bus.publish(Draft::new("tool:period-scan", width(48)).about(DOC, 0));
        bus.publish(Draft::new("document", edited(vec![Edit { version: 1, at: 0, removed: 1, inserted: 1 }])).about(DOC, 1));
        bus.deliver_all();
        let (fact, _) = bus.latest::<RecordWidthEstimated>(DOC).unwrap();
        assert!(bus.is_stale(fact), "a fact without a span cannot be carried through an edit");
    }

    #[test]
    fn a_fact_whose_bytes_an_edit_did_not_touch_is_carried_forward_with_its_offsets() {
        let mut bus = Bus::new();
        bus.publish(Draft::new("tool:protocol", frames(&[(0x9000, 8), (0x9008, 8)])).about(DOC, 0).span(0x9000, 16));
        bus.publish(Draft::new("tool:other", frames(&[(0x80, 8)])).about(DOC, 0).span(0x80, 8).key("touched"));
        bus.publish(Draft::new("document", edited(vec![Edit { version: 1, at: 0x84, removed: 0, inserted: 4 }])).about(DOC, 1));
        bus.deliver_all();
        let carried = bus.facts().find(|fact| fact.producer() == "tool:protocol").unwrap();
        assert!(!bus.is_stale(carried));
        assert_eq!(carried.draft.version, 1);
        assert_eq!(carried.draft.span, Some(Span { start: 0x9004, len: 16 }));
        let moved: Vec<usize> = carried.payload_as::<FramesDefined>().unwrap().frames.iter().map(|frame| frame.start).collect();
        assert_eq!(moved, [0x9004, 0x900C], "the frames moved with the insert");
        let touched = bus.facts().find(|fact| fact.producer() == "tool:other").unwrap();
        assert!(bus.is_stale(touched), "the insert landed inside this one");
        assert_eq!(touched.draft.span, Some(Span { start: 0x80, len: 8 }));
    }

    #[test]
    fn closing_a_document_forgets_its_facts() {
        let mut bus = Bus::new();
        bus.publish(Draft::new("tool:period-scan", width(48)).about(DOC, 3));
        bus.publish(Draft::new("tool:period-scan", width(16)).about("doc-2", 0));
        bus.publish(Draft::new("app", Payload::DocumentClosed(DocumentClosed { name: "a.bin".into() })).about(DOC, 3));
        bus.publish(Draft::new("app", Payload::DocumentOpened(DocumentOpened { name: "b.bin".into(), path: None, len: 4 })).about(DOC, 0));
        bus.deliver_all();
        assert!(bus.latest::<RecordWidthEstimated>(DOC).is_none());
        assert!(bus.latest::<RecordWidthEstimated>("doc-2").is_some());
        assert_eq!(bus.document_version(DOC), Some(0), "the new document starts again at version 0");
    }

    #[test]
    fn an_identical_republished_fact_is_ignored() {
        let mut bus = Bus::new();
        for _ in 0..3 {
            bus.publish(Draft::new("tool:period-scan", width(48)).about(DOC, 0));
        }
        assert_eq!(bus.deliver_all().len(), 1);
        bus.publish(Draft::new("tool:period-scan", width(48)).about(DOC, 0).confidence(0.5));
        assert_eq!(bus.deliver_all().len(), 1, "a different confidence is news");
    }

    #[test]
    fn a_retraction_withdraws_the_fact() {
        let mut bus = Bus::new();
        bus.publish(Draft::new("tool:period-scan", width(48)).about(DOC, 0));
        bus.publish(Draft::new("tool:period-scan", width(48)).about(DOC, 0).retraction());
        let delivered = bus.deliver_all();
        assert_eq!(delivered.len(), 2, "the retraction is delivered so readers notice");
        assert_eq!(delivered[1].to_json()["retracted"], true);
        assert!(bus.latest::<RecordWidthEstimated>(DOC).is_none());
        bus.publish(Draft::new("tool:period-scan", width(48)).about(DOC, 0).retraction());
        assert!(bus.deliver_all().is_empty(), "withdrawing what is not there says nothing");
    }

    #[test]
    fn a_chain_of_reactions_deeper_than_eight_is_dropped_and_logged() {
        let mut bus = Bus::new();
        bus.publish(Draft::new("a", reference("0")));
        let mut cause = bus.deliver_next().unwrap();
        let mut depth = 0;
        loop {
            bus.publish(Draft::new("echo", reference("again")).caused_by(cause.id));
            match bus.deliver_next() {
                Some(next) => {
                    depth += 1;
                    cause = next;
                }
                None => break,
            }
        }
        assert_eq!(depth, usize::from(MAX_CAUSE_DEPTH));
        assert_eq!(bus.problems().count(), 1);
        assert!(bus.problems().next().unwrap().contains("loop"));
        let chain = bus.cause_chain(&cause);
        assert_eq!(chain.len(), usize::from(MAX_CAUSE_DEPTH) + 1, "why: back to the first message");
        assert!(bus.caused_by_producer(&cause, "a"));
        assert!(!bus.caused_by_producer(&cause, "b"));
    }

    #[test]
    fn a_background_job_publishes_from_its_own_thread() {
        let mut bus = Bus::new();
        let publisher = bus.publisher();
        std::thread::spawn(move || {
            publisher.publish(Draft::new("tool:report", Payload::JobFinished(JobFinished { job: "report-1".into(), title: "Report".into(), ok: true, outcome: "done".into() })));
        })
        .join()
        .unwrap();
        let delivered = bus.deliver_all();
        assert_eq!(delivered[0].topic(), Topic::JobFinished);
    }

    #[test]
    fn facts_are_found_by_the_bytes_they_cover() {
        let mut bus = Bus::new();
        bus.publish(Draft::new("one", frames(&[(0, 16)])).about(DOC, 0).span(0, 16));
        bus.publish(Draft::new("two", frames(&[(100, 4)])).about(DOC, 0).span(100, 4));
        bus.deliver_all();
        let producers = |start, len| bus.facts_in(Topic::FramesDefined, DOC, start, len).iter().map(|fact| fact.producer().to_string()).collect::<Vec<_>>();
        assert_eq!(producers(8, 1), ["one"]);
        assert_eq!(producers(0, 200).len(), 2);
        assert!(producers(16, 84).is_empty());
    }

    #[test]
    fn a_message_is_written_as_the_design_s_envelope() {
        let mut bus = Bus::new();
        bus.publish(Draft::new("tool:period-scan", width(48)).about(DOC, 412).span(256, 1232).confidence(1.0).key("256"));
        let message = bus.deliver_next().unwrap();
        let json = message.to_json();
        assert_eq!(json["topic"], "record_width.estimated");
        assert_eq!(json["kind"], "fact");
        assert_eq!(json["id"], "evt-1");
        assert_eq!(json["producer"], "tool:period-scan");
        assert_eq!(json["document"], "doc-1");
        assert_eq!(json["version"], 412);
        assert_eq!(json["span"], serde_json::json!({"start": 256, "len": 1232}));
        assert_eq!(json["key"], "256");
        assert_eq!(json["caused_by"], Value::Null);
        assert_eq!(json["payload"]["width"], 48);
        let payload: Payload = serde_json::from_value(serde_json::json!({"topic": json["topic"], "payload": json["payload"]})).unwrap();
        assert_eq!(&payload, message.payload(), "payloads read back from JSON");
    }

    #[test]
    fn every_topic_is_named_once_in_lower_case_with_a_description() {
        let mut names = std::collections::HashSet::new();
        for info in topics::TOPICS {
            assert!(names.insert(info.name), "{} is declared twice", info.name);
            if info.topic == Topic::Custom {
                assert_eq!(info.name, "x.*", "plugins' own topics are listed as one");
                assert_eq!(Topic::named("x.acme.frames"), Some(Topic::Custom));
                assert_eq!(Topic::named("x.acme"), None, "a plugin's topic has a name after the plugin's");
                continue;
            }
            assert!(info.name.contains('.') && info.name.chars().all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'), "{}", info.name);
            assert!(info.description.ends_with('.'), "{}", info.name);
            assert_eq!(Topic::named(info.name), Some(info.topic));
            assert_eq!((info.payload)().as_value()["type"], "object", "{}", info.name);
        }
    }
}
