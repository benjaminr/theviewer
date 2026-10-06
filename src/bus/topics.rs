//! The bus's topics, declared once: each topic's name, whether it carries
//! facts or events, its payload type and what it means. The payload types
//! are what in-process consumers read and what plugins and remote clients
//! will receive as JSON; `api.describe` lists the table with each payload's
//! schema.

use schemars::{JsonSchema, Schema};
use serde::{Deserialize, Serialize};

use crate::document::Edit;
use crate::plugin::{Field, Finding};
use crate::selection::Selection;

/// Whether a topic's messages are kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Retained: the latest per producer, document and key is kept.
    Fact,
    /// Transient: something happened.
    Event,
}

/// One row of the topic table.
pub struct TopicInfo {
    pub topic: Topic,
    /// Dotted lower-case name, such as `record_width.estimated`.
    pub name: &'static str,
    pub kind: Kind,
    /// One sentence on what the topic carries.
    pub description: &'static str,
    /// JSON Schema of the payload.
    pub payload: fn() -> Schema,
}

/// A payload type that belongs to one topic, for typed queries such as
/// `bus.latest::<RecordWidthEstimated>(doc)`.
pub trait TopicPayload: Sized {
    const TOPIC: Topic;
    /// The payload, when `payload` is of this topic.
    fn from_payload(payload: &Payload) -> Option<&Self>;
}

fn schema_of<T: JsonSchema>() -> Schema {
    schemars::schema_for!(T)
}

/// Declare every topic: its variant, payload type, name, kind and
/// description. This writes the `Topic` and `Payload` enums, the table and
/// the typed-query impls, so they cannot drift apart.
macro_rules! topics {
    ($($variant:ident($payload:ty) = $name:literal, $kind:ident, $description:literal;)*) => {
        /// A topic on the bus.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Topic {
            $($variant,)*
        }

        /// A message's typed payload; the variant names the topic. As JSON
        /// it is `{"topic": name, "payload": {…}}`.
        #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
        #[serde(tag = "topic", content = "payload")]
        pub enum Payload {
            $(#[serde(rename = $name)] $variant($payload),)*
        }

        impl Payload {
            pub fn topic(&self) -> Topic {
                match self {
                    $(Payload::$variant(_) => Topic::$variant,)*
                }
            }
        }

        /// Every topic, in the order the reference lists them.
        pub static TOPICS: &[TopicInfo] = &[
            $(TopicInfo { topic: Topic::$variant, name: $name, kind: Kind::$kind, description: $description, payload: schema_of::<$payload> },)*
        ];

        $(
            impl TopicPayload for $payload {
                const TOPIC: Topic = Topic::$variant;
                fn from_payload(payload: &Payload) -> Option<&Self> {
                    match payload {
                        Payload::$variant(inner) => Some(inner),
                        #[allow(unreachable_patterns)]
                        _ => None,
                    }
                }
            }
        )*
    };
}

topics! {
    DocumentOpened(DocumentOpened) = "document.opened", Event, "A document was opened, or replaced the one shown.";
    DocumentClosed(DocumentClosed) = "document.closed", Event, "A document was closed or replaced; what was known about it is forgotten.";
    DocumentEdited(DocumentEdited) = "document.edited", Event, "The document's bytes changed: each change's offset, bytes removed and bytes inserted, undo and redo included.";
    CursorMoved(CursorMoved) = "cursor.moved", Event, "The cursor moved in the main view.";
    SelectionChanged(SelectionChanged) = "selection.changed", Event, "What is selected changed, in the main view or by a tool selecting bytes in the document.";
    FindingsPublished(FindingsPublished) = "findings.published", Fact, "What one producer recognises in the document: the scan, signatures, templates, the structure map, crypto constants, a comparison, checksums or protocol messages.";
    StructureIdentified(StructureIdentified) = "structure.identified", Fact, "A structure parsed at the cursor, or a template applied, with its field tree.";
    RegionsMapped(RegionsMapped) = "regions.mapped", Fact, "The file split into regions of one kind, from the report.";
    RecordWidthEstimated(RecordWidthEstimated) = "record_width.estimated", Fact, "The length of the records the data repeats in, from the period scan.";
    FramesDefined(FramesDefined) = "frames.defined", Fact, "Message or packet boundaries: from the protocol framing, a capture or the packet viewer's splitting rules.";
    ProtocolIdentified(ProtocolIdentified) = "protocol.identified", Fact, "The protocol a set of frames or a payload is, and how that was decided.";
    ReferenceFocus(ReferenceFocus) = "reference.focus", Event, "A tool asks the Reference tab to show a format or protocol.";
    JobStarted(JobStarted) = "job.started", Event, "Background work started.";
    JobFinished(JobFinished) = "job.finished", Event, "Background work finished, with a one-line outcome.";
    PluginLog(PluginLog) = "plugin.log", Event, "A plugin logged a line, or one of its callbacks failed (in a background scan, say).";
    Custom(CustomTopic) = "x.*", Event, "A plugin's own topic, named x.<plugin>.<name>, with a payload of its choosing.";
}

/// The prefix of plugins' own topics: `x.<plugin>.<name>`.
pub const CUSTOM_PREFIX: &str = "x.";

impl Topic {
    /// The topic's row in the table.
    pub fn info(self) -> &'static TopicInfo {
        TOPICS.iter().find(|info| info.topic == self).expect("every topic is in the table")
    }

    pub fn name(self) -> &'static str {
        self.info().name
    }

    pub fn kind(self) -> Kind {
        self.info().kind
    }

    /// The topic called `name`; every `x.<plugin>.<name>` is
    /// [`Topic::Custom`].
    pub fn named(name: &str) -> Option<Topic> {
        if is_custom_topic(name) {
            return Some(Topic::Custom);
        }
        TOPICS.iter().find(|info| info.name == name && info.topic != Topic::Custom).map(|info| info.topic)
    }
}

/// Whether `name` is a plugin's own topic, `x.<plugin>.<name>`: lower case
/// letters, digits and underscores in dotted parts.
pub fn is_custom_topic(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(CUSTOM_PREFIX) else { return false };
    let parts: Vec<&str> = rest.split('.').collect();
    parts.len() >= 2 && parts.iter().all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
}

impl Payload {
    /// The topic's name; a plugin's own topic is named by its payload.
    pub fn topic_name(&self) -> &str {
        match self {
            Payload::Custom(custom) => &custom.name,
            other => other.topic().name(),
        }
    }

    /// The payload alone as JSON, as clients receive it: a plugin's own
    /// topic carries its payload as given.
    pub fn payload_json(&self) -> serde_json::Value {
        match self {
            Payload::Custom(custom) => custom.payload.clone(),
            other => serde_json::to_value(other).map(|mut tagged| tagged["payload"].take()).unwrap_or(serde_json::Value::Null),
        }
    }
}

impl Payload {
    /// Move every document offset the payload holds by `delta` bytes, for a
    /// fact carried forward through an edit before its span.
    pub fn move_offsets(&mut self, delta: isize) {
        let moved = |offset: &mut usize| *offset = offset.saturating_add_signed(delta);
        fn move_fields(fields: &mut [Field], delta: isize) {
            for field in fields {
                field.offset = field.offset.saturating_add_signed(delta);
                move_fields(&mut field.children, delta);
            }
        }
        match self {
            Payload::FindingsPublished(published) => {
                for finding in &mut published.findings {
                    moved(&mut finding.start);
                    move_fields(&mut finding.fields, delta);
                }
            }
            Payload::StructureIdentified(structure) => {
                moved(&mut structure.start);
                move_fields(&mut structure.fields, delta);
            }
            Payload::RegionsMapped(mapped) => mapped.regions.iter_mut().for_each(|region| moved(&mut region.start)),
            Payload::FramesDefined(defined) => defined.frames.iter_mut().for_each(|frame| moved(&mut frame.start)),
            Payload::ProtocolIdentified(identified) => identified.frames.iter_mut().for_each(|frame| moved(&mut frame.start)),
            Payload::CursorMoved(cursor) => moved(&mut cursor.offset),
            Payload::DocumentOpened(_)
            | Payload::DocumentClosed(_)
            | Payload::DocumentEdited(_)
            | Payload::SelectionChanged(_)
            | Payload::RecordWidthEstimated(_)
            | Payload::ReferenceFocus(_)
            | Payload::JobStarted(_)
            | Payload::JobFinished(_)
            | Payload::PluginLog(_)
            | Payload::Custom(_) => {}
        }
    }
}

/// A document was opened.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DocumentOpened {
    /// File name, or the name of a derived document.
    pub name: String,
    /// Path on disk, for a document opened from a file.
    pub path: Option<String>,
    /// Length in bytes.
    pub len: usize,
}

/// A document was closed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DocumentClosed {
    /// The document's name.
    pub name: String,
}

/// Changes to a document's bytes, oldest first.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DocumentEdited {
    /// The changes, oldest first, each with the version it made.
    pub edits: Vec<Edit>,
    /// False when the edit log no longer held every change since the last
    /// message; spans described before then cannot be mapped forward.
    pub complete: bool,
}

/// Where the cursor is.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CursorMoved {
    /// Document offset of the cursor.
    pub offset: usize,
}

/// What is selected now.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SelectionChanged {
    /// Document offset of the cursor.
    pub cursor: usize,
    /// `None` when nothing is selected.
    pub selection: Option<Selection>,
}

/// One producer's findings; an empty list withdraws what it found before.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FindingsPublished {
    /// What was found, each with its offset, length, category and title.
    pub findings: Vec<Finding>,
}

/// A structure and its fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StructureIdentified {
    /// The parser or template's id, such as `parser:pcap` or `template:Header`.
    pub format: String,
    /// Such as "PNG image".
    pub title: String,
    /// Document offset of the structure's first byte.
    pub start: usize,
    pub len: usize,
    /// The field tree, at document offsets.
    pub fields: Vec<Field>,
}

/// One region of the file map.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MappedRegion {
    pub start: usize,
    pub len: usize,
    /// Such as "compressed", "text" or "structure".
    pub kind: String,
    /// Such as "zlib stream".
    pub label: String,
    /// Identified by a parser or verified decoder, rather than guessed.
    pub confident: bool,
}

/// The file's regions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegionsMapped {
    /// The regions in document order.
    pub regions: Vec<MappedRegion>,
}

/// A record width.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RecordWidthEstimated {
    /// Bytes per record.
    pub width: usize,
    /// How alike records this far apart are, 0 to 1.
    pub score: f32,
    /// The next best widths, best first.
    pub alternatives: Vec<usize>,
}

/// A frame's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FrameSpan {
    pub start: usize,
    pub len: usize,
}

/// Most frames one message lists; `total` says how many there were.
pub const MOST_FRAMES: usize = 10_000;

/// A set of frames.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FramesDefined {
    /// The first [`MOST_FRAMES`] frames, in document order.
    pub frames: Vec<FrameSpan>,
    /// How many frames there are in all.
    pub total: usize,
    /// How they were found, such as "length prefix u16be" or "pcap capture at 0x40".
    pub origin: String,
}

impl FramesDefined {
    /// Frames from `spans`, keeping the first [`MOST_FRAMES`].
    pub fn new(spans: impl Iterator<Item = (usize, usize)>, origin: impl Into<String>) -> Self {
        let mut frames = Vec::new();
        let mut total = 0;
        for (start, len) in spans {
            total += 1;
            if frames.len() < MOST_FRAMES {
                frames.push(FrameSpan { start, len });
            }
        }
        FramesDefined { frames, total, origin: origin.into() }
    }
}

/// A protocol, and what it was found for.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProtocolIdentified {
    /// Such as "DNS" or "Modbus/TCP".
    pub protocol: String,
    /// How it was decided, such as "read 30 of 32 sampled frames in full".
    pub how: String,
    /// The frames it was found for; empty when it is about one payload,
    /// which the message's span gives.
    pub frames: Vec<FrameSpan>,
}

/// A format or protocol for the Reference tab.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReferenceFocus {
    /// A reference id, finding id or layer name.
    pub key: String,
}

/// Background work that started.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobStarted {
    /// Unique for the session, such as "period-scan-3".
    pub job: String,
    /// What the job does, such as "Period scan".
    pub title: String,
}

/// Background work that finished.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobFinished {
    /// The id `job.started` gave.
    pub job: String,
    pub title: String,
    /// Whether it produced a result.
    pub ok: bool,
    /// One line on what it found, or why it stopped.
    pub outcome: String,
}

/// How serious a logged line is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Info,
    Error,
}

/// A plugin's log line.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PluginLog {
    /// The plugin's file name, such as `modbus_rtu.lua`.
    pub plugin: String,
    /// `error` for a failed callback, `info` for a line the plugin logged.
    pub level: LogLevel,
    pub text: String,
}

/// A message on a plugin's own topic.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CustomTopic {
    /// The topic, `x.<plugin>.<name>`.
    pub name: String,
    /// Whatever the plugin published.
    pub payload: serde_json::Value,
}
