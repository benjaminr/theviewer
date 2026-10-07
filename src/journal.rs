//! The journal: every call that changed something, in order, by whom.
//!
//! Every way in (panels, plugins, Ask, MCP clients, the command line and
//! recipes) calls methods through [`crate::api::call`], so an analysis is
//! a sequence of method calls. The journal records that sequence, which
//! gives the History tab, undo across analysis steps, playback and recipes
//! from one mechanism (`docs/design/shared-knowledge-and-api.md` §4).
//!
//! What is recorded, as each method declares it ([`Journalled`]):
//!
//! * **Every call whose effect is edit, view, job or analysis**, by every
//!   caller, as a [`JournalEntry`] with a step number. A call that fails is
//!   recorded too, with its error, so the History tab can show what was
//!   tried; a call refused because it must first be confirmed is not,
//!   because it is recorded when the person allows it.
//! * **Reads** go into a bounded ring of recent reads, numbered from the same
//!   sequence as the steps. A later step that used a value a read returned
//!   cites it as provenance, and [`promote`] moves the read into the journal
//!   under its own step number, so `{"step": 12, "path": …}` stays valid.
//! * **Not** calls made inside another call (a transaction's, or those a
//!   plugin method makes while it runs): the outer call is the step.
//!   Not the app's own work either, which does not go through the API.
//!   Not the methods that read the journal itself or edit its provenance
//!   (`history.list`, `history.make_anchor`…), which say so.
//! * **Notes** (`history.note`): what the person or a client was thinking,
//!   as a step of its own linked to the steps it is about (see [`notes`]).
//!   A note changes nothing, so it is never undone, repeated or gone back
//!   past, and it can be edited or deleted in place.
//! * Consecutive calls of a setter that merges its repeats (`selection.set`,
//!   `cursor.set`, `view.set_shape`) by the same caller on the same document
//!   are merged into the last, so dragging a selection is one step, not
//!   fifty, which undoes to what was there before the drag.
//!
//! Each new entry is published on the bus as `journal.recorded`.
//!
//! The journal is bounded ([`JournalLimits`]): very large parameters and
//! results are kept as a summary (long strings and arrays cut, ids kept),
//! and once there are too many entries or bytes the oldest are dropped and
//! counted in [`Journal::dropped`].
//!
//! Submodules hold the types the three phase 7 areas share: [`anchors`]
//! (portable values), [`recipe`] (the recipe file) and [`replay`] (running
//! steps again); [`timeline`] and [`undo`] say which steps are in effect
//! and how each is undone. `docs/design/history-recipes.md` says who owns
//! what.

pub mod anchors;
pub mod notes;
pub mod provenance;
pub mod recipe;
pub mod replay;
pub mod timeline;
pub mod undo;

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use schemars::JsonSchema;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::api::workspace::{MadeBy, SheetOutput};
use crate::api::{self, ApiError, Caller, Effect, MethodRef, Workspace};
use crate::bus::topics::JournalRecorded;
use crate::bus::{Draft, Payload};
use crate::document::{Backing, Document};

pub use anchors::Anchor;
pub use notes::{Note, NoteOn};
pub use recipe::Recipe;
use timeline::Timeline;

/// Where the values of a step's parameters came from: each parameter's
/// path (`start`, `length_field.offset`, `ranges[0][0]`) and its anchor.
pub type DerivedFrom = BTreeMap<String, Anchor>;

/// The producer `journal.recorded` is published as.
pub const JOURNAL_PRODUCER: &str = "journal";

/// Longest description kept, in characters.
const DESCRIPTION_LIMIT: usize = 240;
/// Longest string kept in a summarised value, in characters.
const SUMMARY_STRING_LIMIT: usize = 1024;
/// Most items of an array kept in a summarised value.
const SUMMARY_ARRAY_LIMIT: usize = 32;
/// Largest document hashed, for the session header and to tell whether a
/// document is one seen before.
pub const HASH_LIMIT: usize = 256 * 1024 * 1024;
/// Bytes read at a time while hashing a document.
const HASH_CHUNK: usize = 16 * 1024 * 1024;

/// How a method's calls are kept in the journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Journalled {
    /// As a step, whether it succeeded, failed or was refused.
    Step,
    /// In the ring of recent reads when it succeeds, for a later step to
    /// cite.
    Read,
    /// Not at all: it reads the journal itself, or edits its provenance.
    Skip,
}

impl Journalled {
    /// How a method of `effect` is kept unless it says otherwise: a read in
    /// the ring of reads, anything else as a step.
    pub const fn for_effect(effect: Effect) -> Journalled {
        match effect {
            Effect::Read => Journalled::Read,
            _ => Journalled::Step,
        }
    }
}

/// How much the journal keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalLimits {
    /// Most entries kept; the oldest are dropped beyond it.
    pub max_entries: usize,
    /// Most bytes of entries kept, roughly; the oldest entries are dropped
    /// beyond it.
    pub max_bytes: usize,
    /// Parameters larger than this are kept as a summary, and the step
    /// cannot be repeated exactly.
    pub max_params_bytes: usize,
    /// Results larger than this are kept as a summary; what a step replaced
    /// larger than this is not kept, and the step has no inverse.
    pub max_result_bytes: usize,
    /// Most recent reads kept for provenance.
    pub max_reads: usize,
    /// Most bytes of recent reads kept, roughly; the oldest are dropped
    /// beyond it.
    pub max_reads_bytes: usize,
}

impl Default for JournalLimits {
    fn default() -> Self {
        JournalLimits { max_entries: 10_000, max_bytes: 64 * 1024 * 1024, max_params_bytes: 1024 * 1024, max_result_bytes: 64 * 1024, max_reads: 256, max_reads_bytes: 4 * 1024 * 1024 }
    }
}

/// How a recorded call ended.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// It did what was asked: `"ok"`.
    Ok,
    /// It failed and changed nothing: `{"error": {code, message, data}}`.
    Error(ApiError),
}

impl Outcome {
    pub fn is_ok(&self) -> bool {
        matches!(self, Outcome::Ok)
    }
}

/// One recorded call.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JournalEntry {
    /// The step's number, unique in the session and increasing; reads
    /// share the sequence, so the steps listed may skip numbers.
    pub step: u64,
    /// When the call was made, UTC, such as "2026-10-06T14:02:11Z".
    pub at: String,
    /// Who called: `panel`, `plugin:sync.lua`, `ask`, `mcp:claude-code`,
    /// `cli` or `recipe:Telemetry frames`.
    pub caller: String,
    /// The method called, such as `packets.sets.create`.
    pub method: String,
    pub effect: Effect,
    /// What the call did in plain words, the same text the confirmation
    /// window shows: "XOR 128 selected bytes with 5A". Empty for a read
    /// not promoted into the journal.
    pub description: String,
    /// The parameters as given (or, when `params_summarised`, a summary).
    pub params: Value,
    /// Whether `params` were too large to keep and are a summary: such a
    /// step cannot be repeated exactly.
    #[serde(default, skip_serializing_if = "is_false")]
    pub params_summarised: bool,
    /// The document the call was about: the one its `doc` named, or the
    /// current one.
    pub doc: Option<String>,
    /// That document's version before the call.
    pub version_before: Option<u64>,
    /// Its version after (none when the call closed it).
    pub version_after: Option<u64>,
    pub outcome: Outcome,
    /// What the call returned (or, when `result_summarised`, a summary that
    /// keeps the ids of what it made); none when it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub result_summarised: bool,
    /// Where parameters' values came from, by parameter path: the anchors
    /// a recipe made from this step uses in place of the literals.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub derived_from: DerivedFrom,
    /// How many earlier calls of the same setter this one replaced.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub merged: u32,
    /// What the step replaced, for its inverse (see
    /// [`undo::state_before`]): the view shape, bookmarks or selection as
    /// they were before it ran (before the first call it merged), when its
    /// method reverses a change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    /// For a note (`history.note`): its text, the steps it links and when
    /// it was last edited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<Note>,
    /// The notes linked to this step, oldest first, as `history.list` and
    /// `history.entry` give it: the reasoning beside the action.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<NoteOn>,
    /// The sheets the call made (documents derived from `doc`), by id, in
    /// the order made, as its result's `output` (or `outputs`) names them:
    /// a recipe names them by this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub made: Vec<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

impl JournalEntry {
    /// Whether the step changed its document's bytes.
    pub fn changed_document(&self) -> bool {
        matches!((self.version_before, self.version_after), (Some(before), Some(after)) if before != after)
    }

    /// Whether the entry is a note rather than a step of the analysis.
    pub fn is_note(&self) -> bool {
        self.note.is_some()
    }
}

/// An entry held, with the bytes it takes, worked out once.
#[derive(Clone, Debug)]
struct Held {
    entry: JournalEntry,
    size: usize,
}

impl Held {
    fn new(entry: JournalEntry) -> Self {
        let size = entry_size(&entry);
        Held { entry, size }
    }
}

/// Entries the journal no longer holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Dropped {
    /// How many entries were dropped, oldest first.
    pub entries: u64,
    /// The last step dropped: every step up to it is gone.
    pub through_step: u64,
}

/// A file as a recipe names it: enough to tell whether another file is the
/// same.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileIdentity {
    /// File name, or the name of a derived document.
    pub name: String,
    /// Length in bytes.
    pub size: u64,
    /// SHA-256 of the bytes, lower-case hex; none for a document too large
    /// to hash (over 256 MiB).
    pub sha256: Option<String>,
}

/// The SHA-256 of a document as first seen, worked out on a thread of its
/// own so the call that first saw it does not wait; asking for it waits
/// until it is known. Empty for a document too large to hash.
#[derive(Clone, Default)]
struct PendingDigest(Option<Arc<OnceLock<String>>>);

impl PendingDigest {
    /// Start working out the hash of `document`'s bytes as they are now: of
    /// the file's own bytes when it is unedited, otherwise of a copy.
    fn start(document: &mut Document) -> Self {
        let len = document.len();
        if len > HASH_LIMIT {
            return PendingDigest(None);
        }
        let bytes = if document.version() == 0 { document.original() } else { Backing::Owned(Arc::new(document.read_range(0, len))) };
        let digest: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
        let hash = {
            let (digest, bytes) = (Arc::clone(&digest), bytes.clone());
            move || {
                digest.get_or_init(|| crate::corpus::sha256_hex(bytes.as_slice()));
            }
        };
        if std::thread::Builder::new().name("journal-hash".into()).spawn(hash).is_err() {
            // Without a thread to spare, it is worked out here after all.
            digest.get_or_init(|| crate::corpus::sha256_hex(bytes.as_slice()));
        }
        PendingDigest(Some(digest))
    }

    /// The hash, once worked out.
    fn wait(&self) -> Option<String> {
        self.0.as_ref().map(|digest| digest.wait().clone())
    }
}

impl fmt::Debug for PendingDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            None => formatter.write_str("none"),
            Some(digest) => formatter.write_str(if digest.get().is_some() { "known" } else { "working" }),
        }
    }
}

/// A document as the session first saw it.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct RecordedDocument {
    /// Its id in this session, such as "doc-1".
    pub id: String,
    /// The version it was at.
    pub version: u64,
    /// Its name and size, and its hash once known: read it whole through
    /// [`RecordedDocument::file`].
    #[serde(rename = "file")]
    identity: FileIdentity,
    /// The document it was derived from, when it was one, as the
    /// workspace said when the session first saw it.
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(skip)]
    digest: PendingDigest,
}

impl RecordedDocument {
    /// Document `id` first seen at `version` as `file`, hash and all.
    pub fn new(id: impl Into<String>, version: u64, file: FileIdentity) -> Self {
        RecordedDocument { id: id.into(), version, identity: file, parent: None, digest: PendingDigest::default() }
    }

    /// The file as first seen, waiting for its hash to be worked out.
    pub fn file(&self) -> FileIdentity {
        let mut file = self.identity.clone();
        if file.sha256.is_none() {
            file.sha256 = self.digest.wait();
        }
        file
    }
}

impl PartialEq for RecordedDocument {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.version == other.version && self.parent == other.parent && self.file() == other.file()
    }
}

impl Eq for RecordedDocument {}

impl Serialize for RecordedDocument {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("RecordedDocument", 4)?;
        fields.serialize_field("id", &self.id)?;
        fields.serialize_field("version", &self.version)?;
        fields.serialize_field("file", &self.file())?;
        if let Some(parent) = &self.parent {
            fields.serialize_field("parent", parent)?;
        } else {
            fields.skip_field("parent")?;
        }
        fields.end()
    }
}

/// A plugin script loaded in the session, which a step may have used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecordedPlugin {
    /// The script's file name, such as `acme_telemetry.lua`.
    pub name: String,
    /// SHA-256 of its source, lower-case hex.
    pub sha256: String,
}

/// What a recipe needs to know about the session it was recorded in, to
/// warn when it runs somewhere different.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JournalSession {
    /// When the session started, UTC.
    pub started_at: String,
    /// The API version, such as "1.0".
    pub api_version: String,
    /// Each document a call was about, as it was the first time.
    pub documents: Vec<RecordedDocument>,
    /// The plugin scripts loaded, as last loaded.
    pub plugins: Vec<RecordedPlugin>,
}

impl JournalSession {
    fn starting_now() -> Self {
        JournalSession { started_at: timestamp(SystemTime::now()), api_version: api::API_VERSION.to_string(), documents: Vec::new(), plugins: Vec::new() }
    }

    /// The document `id` as the session first saw it.
    pub fn document(&self, id: &str) -> Option<&RecordedDocument> {
        self.documents.iter().find(|document| document.id == id)
    }
}

/// The session's journal: its entries, the recent reads, and the header.
/// One per workspace.
#[derive(Clone, Debug)]
pub struct Journal {
    limits: JournalLimits,
    session: JournalSession,
    /// Recorded steps, in step order.
    entries: VecDeque<Held>,
    /// Recent successful reads, in step order, the oldest dropped first.
    reads: VecDeque<Held>,
    next_step: u64,
    /// Changes whenever anything recorded changes, for followers.
    revision: u64,
    /// Calls running now: only the outermost is recorded.
    depth: u32,
    /// Where the next recorded call's parameters came from.
    pending_provenance: Option<DerivedFrom>,
    dropped: Dropped,
    /// Rough bytes held by `entries`.
    bytes: usize,
    /// Rough bytes held by `reads`.
    reads_bytes: usize,
    /// Where each step held stands, kept up to date as entries are
    /// recorded.
    timeline: Timeline,
    /// Parameters the person named while making steps portable, with their
    /// descriptions and types, kept until a recipe is built (see
    /// [`provenance`]).
    parameters: BTreeMap<String, recipe::RecipeParameter>,
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

impl Journal {
    /// An empty journal for a session starting now.
    pub fn new() -> Self {
        Self::with_limits(JournalLimits::default())
    }

    /// Parameters named while making steps portable, by name.
    pub fn parameters(&self) -> &BTreeMap<String, recipe::RecipeParameter> {
        &self.parameters
    }

    pub fn with_limits(limits: JournalLimits) -> Self {
        Journal {
            limits,
            session: JournalSession::starting_now(),
            entries: VecDeque::new(),
            reads: VecDeque::new(),
            next_step: 1,
            revision: 0,
            depth: 0,
            pending_provenance: None,
            dropped: Dropped::default(),
            bytes: 0,
            reads_bytes: 0,
            timeline: Timeline::default(),
            parameters: BTreeMap::new(),
        }
    }

    /// The session header: API version, plugins and documents.
    pub fn session(&self) -> &JournalSession {
        &self.session
    }

    /// Every entry held, in step order.
    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &JournalEntry> + ExactSizeIterator {
        self.entries.iter().map(|held| &held.entry)
    }

    /// The entries after `step`, in step order: what a follower that has
    /// seen up to `step` has not. A promoted read takes its own (earlier)
    /// step number, so a follower also watches [`Journal::revision`] or
    /// `journal.recorded` to notice one.
    pub fn since(&self, step: u64) -> impl DoubleEndedIterator<Item = &JournalEntry> {
        let from = self.entries.partition_point(|held| held.entry.step <= step);
        self.entries.range(from..).map(|held| &held.entry)
    }

    /// The entry recorded as `step`.
    pub fn entry(&self, step: u64) -> Option<&JournalEntry> {
        find_step(&self.entries, step)
    }

    /// The entry recorded as `step`, to change in place (its provenance).
    fn entry_mut(&mut self, step: u64) -> Option<&mut JournalEntry> {
        let index = self.entries.partition_point(|held| held.entry.step < step);
        self.entries.get_mut(index).map(|held| &mut held.entry).filter(|entry| entry.step == step)
    }

    /// The recent reads, oldest first.
    pub fn reads(&self) -> impl DoubleEndedIterator<Item = &JournalEntry> + ExactSizeIterator {
        self.reads.iter().map(|held| &held.entry)
    }

    /// The recent read numbered `step`.
    pub fn read(&self, step: u64) -> Option<&JournalEntry> {
        find_step(&self.reads, step)
    }

    /// Where each step held stands: in effect, undone, failed or a move.
    pub fn timeline(&self) -> &Timeline {
        &self.timeline
    }

    /// The last step recorded or read, if any.
    pub fn last_step(&self) -> Option<u64> {
        self.next_step.checked_sub(1).filter(|step| *step > 0)
    }

    /// The number the call being recorded now will take, once it finishes.
    fn next_step(&self) -> u64 {
        self.next_step
    }

    /// Whether the call running now is the outermost, which the journal
    /// records as a step of its own: not one inside a transaction, a
    /// recipe's run or a plugin's method.
    fn records_the_call_running_now(&self) -> bool {
        self.depth == 1
    }

    /// A number that changes whenever an entry is recorded, merged,
    /// promoted or dropped.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// What was dropped to keep within the limits.
    pub fn dropped(&self) -> Dropped {
        self.dropped
    }

    /// Note the plugin scripts loaded now, after they were loaded or
    /// reloaded.
    pub fn note_plugins(&mut self, plugins: Vec<RecordedPlugin>) {
        self.session.plugins = plugins;
    }

    /// Say where the parameters of the next call came from. The next call
    /// recorded (not one inside it) takes them; see
    /// [`crate::api::call_derived`].
    pub fn set_pending_provenance(&mut self, derived_from: DerivedFrom) {
        self.pending_provenance = Some(derived_from);
    }

    /// Take back provenance no call has taken, after a call that never ran.
    pub fn take_pending_provenance(&mut self) -> Option<DerivedFrom> {
        self.pending_provenance.take()
    }

    /// Whether a call of a setter that merges its repeats, `method` by
    /// `caller` about `doc`, would replace the last entry: see
    /// [`merges_into`].
    fn would_merge(&self, method: &str, caller: &str, doc: Option<&str>) -> bool {
        self.entries.back().is_some_and(|last| {
            let last = &last.entry;
            last.method == method && last.caller == caller && last.doc.as_deref() == doc && last.outcome.is_ok() && last.derived_from.is_empty()
        })
    }

    /// Record `entry` under the next step number (merging it into the last
    /// entry when its method merges repeats and both set the same thing)
    /// and keep within the limits. Returns its step.
    fn record(&mut self, mut entry: JournalEntry) -> u64 {
        entry.step = self.take_step();
        let merges = api::method(&entry.method).is_some_and(|method| method.merge);
        if merges && let Some(replaced) = self.entries.pop_back_if(|last| merges_into(&last.entry, &entry)) {
            entry.merged = replaced.entry.merged + 1;
            // Undone, the merged calls leave what was there before the first.
            entry.before = replaced.entry.before;
            self.bytes = self.bytes.saturating_sub(replaced.size);
            self.timeline.forget(replaced.entry.step);
        }
        let step = entry.step;
        self.timeline.follow(&entry);
        let held = Held::new(entry);
        self.bytes += held.size;
        self.entries.push_back(held);
        self.trim();
        self.revision += 1;
        step
    }

    /// Keep a successful read in the ring under the next step number.
    fn keep_read(&mut self, mut entry: JournalEntry) -> u64 {
        entry.step = self.take_step();
        let step = entry.step;
        let held = Held::new(entry);
        self.reads_bytes += held.size;
        self.reads.push_back(held);
        while self.reads.len() > self.limits.max_reads || (self.reads_bytes > self.limits.max_reads_bytes && self.reads.len() > 1) {
            let Some(oldest) = self.reads.pop_front() else { break };
            self.reads_bytes = self.reads_bytes.saturating_sub(oldest.size);
        }
        step
    }

    /// Move the read numbered `step` from the ring into the journal, with
    /// `description`, keeping its number. Returns the entry, or `None` when
    /// no such read is held.
    fn promote_read(&mut self, step: u64, description: String) -> Option<&JournalEntry> {
        let index = self.reads.iter().position(|read| read.entry.step == step)?;
        let read = self.reads.remove(index)?;
        self.reads_bytes = self.reads_bytes.saturating_sub(read.size);
        let mut entry = read.entry;
        entry.description = description;
        let held = Held::new(entry);
        self.bytes += held.size;
        let at = self.entries.partition_point(|entry| entry.entry.step < step);
        self.entries.insert(at, held);
        // Taken in among later steps, it is followed in its place.
        self.timeline = Timeline::following(self.entries());
        self.trim();
        self.revision += 1;
        self.entry(step)
    }

    fn take_step(&mut self) -> u64 {
        let step = self.next_step;
        self.next_step += 1;
        step
    }

    /// Drop the oldest entries beyond the limits, counting them.
    fn trim(&mut self) {
        while self.entries.len() > self.limits.max_entries || (self.bytes > self.limits.max_bytes && self.entries.len() > 1) {
            let Some(oldest) = self.entries.pop_front() else { break };
            self.bytes = self.bytes.saturating_sub(oldest.size);
            self.timeline.forget(oldest.entry.step);
            self.dropped.entries += 1;
            self.dropped.through_step = self.dropped.through_step.max(oldest.entry.step);
        }
    }

    /// Whether the session header has noted document `id`.
    fn knows_document(&self, id: &str) -> bool {
        self.session.document(id).is_some()
    }
}

/// The entry numbered `step` in `entries`, which are in step order.
fn find_step(entries: &VecDeque<Held>, step: u64) -> Option<&JournalEntry> {
    let index = entries.partition_point(|held| held.entry.step < step);
    entries.get(index).map(|held| &held.entry).filter(|entry| entry.step == step)
}

/// Whether `next`, a call of a setter that merges its repeats, replaces
/// `last`, the entry recorded just before it: the same setter, caller and
/// document, both successful, and the last has no provenance that merging
/// would lose.
fn merges_into(last: &JournalEntry, next: &JournalEntry) -> bool {
    last.method == next.method && last.caller == next.caller && last.doc == next.doc && last.outcome.is_ok() && next.outcome.is_ok() && last.derived_from.is_empty()
}

/// Rough bytes an entry holds.
fn entry_size(entry: &JournalEntry) -> usize {
    const OVERHEAD: usize = 256;
    let held = [Some(&entry.params), entry.result.as_ref(), entry.before.as_ref()];
    let note = entry.note.as_ref().map_or(0, |note| note.text.len());
    OVERHEAD + held.into_iter().flatten().map(approximate_size).sum::<usize>() + entry.description.len() + note
}

/// Rough bytes `value` takes as JSON, without writing it.
pub fn approximate_size(value: &Value) -> usize {
    match value {
        Value::Null | Value::Bool(_) => 5,
        Value::Number(_) => 8,
        Value::String(text) => text.len() + 2,
        Value::Array(items) => 2 + items.iter().map(|item| approximate_size(item) + 1).sum::<usize>(),
        Value::Object(fields) => 2 + fields.iter().map(|(key, item)| key.len() + 4 + approximate_size(item)).sum::<usize>(),
    }
}

/// `value` as kept: whole when it is at most `limit` bytes, otherwise a
/// summary (with `true`) that cuts long strings and arrays but keeps every
/// field, so the ids of what a call made survive.
pub fn bounded(value: &Value, limit: usize) -> (Value, bool) {
    if approximate_size(value) <= limit {
        return (value.clone(), false);
    }
    (summarise(value), true)
}

fn summarise(value: &Value) -> Value {
    match value {
        Value::String(text) if text.chars().count() > SUMMARY_STRING_LIMIT => {
            let kept: String = text.chars().take(SUMMARY_STRING_LIMIT).collect();
            Value::String(format!("{kept}… ({} characters in all)", text.chars().count()))
        }
        Value::Array(items) => {
            let mut kept: Vec<Value> = items.iter().take(SUMMARY_ARRAY_LIMIT).map(summarise).collect();
            if items.len() > SUMMARY_ARRAY_LIMIT {
                kept.push(Value::String(format!("… {} more items", items.len() - SUMMARY_ARRAY_LIMIT)));
            }
            Value::Array(kept)
        }
        Value::Object(fields) => Value::Object(fields.iter().map(|(key, item)| (key.clone(), summarise(item))).collect()),
        other => other.clone(),
    }
}

/// `time` as an RFC 3339 UTC timestamp to the second.
pub fn timestamp(time: SystemTime) -> String {
    crate::patterns::format_unix_seconds_rfc3339(time.duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs()))
}

/// SHA-256 of `document`'s bytes as they are now, lower-case hex, read a
/// chunk at a time; none over [`HASH_LIMIT`].
pub fn document_sha256(document: &mut Document) -> Option<String> {
    let len = document.len();
    if len > HASH_LIMIT {
        return None;
    }
    let mut hasher = Sha256::new();
    for start in (0..len).step_by(HASH_CHUNK) {
        hasher.update(document.read_range(start, HASH_CHUNK.min(len - start)));
    }
    Some(crate::ops::to_compact_hex(&hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Recording, called by `api::call` around every method it runs
// ---------------------------------------------------------------------------

/// A call being recorded, from [`begin`] to [`finish`].
pub(crate) enum CallRecord {
    /// Not recorded: a call inside another, or one its method keeps out of
    /// the journal.
    Unrecorded,
    /// The outermost call, as known before it ran.
    Outermost {
        entry: Box<JournalEntry>,
        kept: Journalled,
        /// Whether its method takes a `doc` parameter.
        takes_doc: bool,
    },
}

/// Start recording a call to `method` by `caller`, before it runs.
pub(crate) fn begin(workspace: &mut dyn Workspace, caller: &Caller, method: &MethodRef, params: &Value) -> CallRecord {
    let journal = workspace.journal_mut();
    journal.depth += 1;
    if journal.depth > 1 {
        return CallRecord::Unrecorded;
    }
    // Provenance given for this call is this call's, kept or not.
    let derived_from = journal.pending_provenance.take().unwrap_or_default();
    let kept = method.journalled();
    if kept == Journalled::Skip {
        return CallRecord::Unrecorded;
    }
    let (kept_params, params_summarised) = bounded(params, journal.limits.max_params_bytes);
    let mut entry = Box::new(JournalEntry {
        step: 0,
        at: timestamp(SystemTime::now()),
        caller: caller.producer(),
        method: method.name().to_string(),
        effect: method.effect(),
        description: String::new(),
        params: kept_params,
        params_summarised,
        doc: None,
        version_before: None,
        version_after: None,
        outcome: Outcome::Ok,
        result: None,
        result_summarised: false,
        derived_from,
        merged: 0,
        before: None,
        note: None,
        notes: Vec::new(),
        made: Vec::new(),
    });
    // A read is about its document once it has succeeded, and is described
    // only if promoted: most never are, and only steps can be undone, so
    // only they keep what they replaced.
    if kept == Journalled::Step {
        let doc = document_of_call(workspace, method.takes_doc(), params);
        if let Some(id) = doc.as_deref() {
            entry.version_before = workspace.version(id);
            note_document(workspace, id);
        }
        entry.description = describe(workspace, method, params);
        // A call merged into the last keeps what the last replaced.
        if !(method.merges_repeats() && workspace.journal().would_merge(&entry.method, &entry.caller, doc.as_deref())) {
            let limit = workspace.journal().limits.max_result_bytes;
            entry.before = undo::state_before(workspace, method.undo(), doc.as_deref(), params).filter(|before| approximate_size(before) <= limit);
        }
        entry.doc = doc;
    }
    CallRecord::Outermost { entry, kept, takes_doc: method.takes_doc() }
}

/// Finish recording a call with its result: a step goes into the journal
/// (failed or not) and is published; a successful read goes into the ring
/// of recent reads.
pub(crate) fn finish(workspace: &mut dyn Workspace, record: CallRecord, result: &Result<Value, ApiError>) {
    let journal = workspace.journal_mut();
    journal.depth = journal.depth.saturating_sub(1);
    let CallRecord::Outermost { mut entry, kept, takes_doc } = record else { return };
    if kept == Journalled::Read {
        let Ok(value) = result else { return };
        entry.doc = document_of_call(workspace, takes_doc, &entry.params);
        if let Some(id) = entry.doc.as_deref() {
            entry.version_before = workspace.version(id);
            note_document(workspace, id);
        }
        entry.version_after = entry.version_before;
        (entry.result, entry.result_summarised) = kept_result(workspace, value);
        workspace.journal_mut().keep_read(*entry);
        return;
    }
    entry.version_after = entry.doc.as_deref().and_then(|id| workspace.version(id));
    let mut made = Vec::new();
    match result {
        Ok(value) => {
            (entry.result, entry.result_summarised) = kept_result(workspace, value);
            entry.note = notes::written_by(&entry.method, &entry.params, value);
            made = sheets_made(value);
            entry.made = made.iter().map(|sheet| sheet.doc.clone()).collect();
        }
        Err(error) => entry.outcome = Outcome::Error(error.clone()),
    }
    let (method, params) = (entry.method.clone(), entry.params.clone());
    let step = workspace.journal_mut().record(*entry);
    for sheet in made {
        let made_by = MadeBy { step: Some(step), method: method.clone(), params: params.clone(), span: span_of(&params), label: sheet.label };
        workspace.note_made_by(&sheet.doc, made_by);
    }
    publish(workspace, step);
}

/// The sheets a call's result says it made: its `output`, or each of its
/// `outputs`, in order. Every method that makes a sheet names it so.
pub fn sheets_made(result: &Value) -> Vec<SheetOutput> {
    let one = result.get("output").filter(|output| output.get("doc").is_some()).cloned().into_iter();
    let several = result.get("outputs").and_then(Value::as_array).into_iter().flatten().cloned();
    one.chain(several).filter_map(|output| serde_json::from_value(output).ok()).collect()
}

/// The ranges of its parent a sheet was made from, where the call that made
/// it names them: `ranges`, or `start` and `len`.
fn span_of(params: &Value) -> Option<Vec<(u64, u64)>> {
    if let Some(ranges) = params.get("ranges") {
        return serde_json::from_value(ranges.clone()).ok();
    }
    let start = params.get("start")?.as_u64()?;
    let len = params.get("len")?.as_u64()?;
    Some(vec![(start, len)])
}

/// A call's result as the journal keeps it, and whether it is a summary.
fn kept_result(workspace: &dyn Workspace, value: &Value) -> (Option<Value>, bool) {
    let (kept, summarised) = bounded(value, workspace.journal().limits.max_result_bytes);
    (Some(kept), summarised)
}

/// Record a call that was refused before it ran (its caller may never
/// make it), and return the refusal.
pub(crate) fn record_refusal(workspace: &mut dyn Workspace, caller: &Caller, method: &MethodRef, params: &Value, refusal: ApiError) -> Result<Value, ApiError> {
    let record = begin(workspace, caller, method, params);
    let result = Err(refusal);
    finish(workspace, record, &result);
    result
}

/// Run `action`, which makes one call through the API, so that call's
/// journal entry carries `derived_from`: where the values of some of its
/// parameters came from, by parameter path. The one way provenance goes in,
/// for [`crate::api::call_derived`] and the window's actions alike.
pub fn with_provenance<W: Workspace + ?Sized, T>(workspace: &mut W, derived_from: DerivedFrom, action: impl FnOnce(&mut W) -> T) -> T {
    if derived_from.is_empty() {
        return action(workspace);
    }
    workspace.journal_mut().set_pending_provenance(derived_from);
    let done = action(workspace);
    // An action that called nothing (no such method, or a call held for
    // confirmation) leaves nothing for the next call.
    workspace.journal_mut().take_pending_provenance();
    done
}

/// Move the recent read numbered `step` into the journal, because a later
/// step used a value it returned, and publish it. Returns whether `step`
/// is now in the journal (it may already have been).
pub fn promote(workspace: &mut dyn Workspace, step: u64) -> bool {
    if workspace.journal().entry(step).is_some() {
        return true;
    }
    let Some(read) = workspace.journal().read(step) else { return false };
    let (method, params) = (read.method.clone(), read.params.clone());
    let description = cut_to_a_line(api::describe_call(workspace, &method, &params));
    if workspace.journal_mut().promote_read(step, description).is_none() {
        return false;
    }
    publish(workspace, step);
    true
}

/// Publish the entry numbered `step` on `journal.recorded`.
fn publish(workspace: &mut dyn Workspace, step: u64) {
    let Some(entry) = workspace.journal().entry(step) else { return };
    let recorded = JournalRecorded { step, method: entry.method.clone(), caller: entry.caller.clone(), description: entry.description.clone(), ok: entry.outcome.is_ok() };
    let about = entry.doc.clone().map(|doc| (doc, entry.version_after.or(entry.version_before).unwrap_or(0)));
    let mut draft = Draft::new(JOURNAL_PRODUCER, Payload::JournalRecorded(recorded));
    if let Some((doc, version)) = about {
        draft = draft.about(doc, version);
    }
    workspace.bus().publish(draft);
}

/// The call to `method` described in plain words, cut to a line.
fn describe(workspace: &mut dyn Workspace, method: &MethodRef, params: &Value) -> String {
    cut_to_a_line(method.describe_call(workspace, params))
}

/// `description` cut to [`DESCRIPTION_LIMIT`] characters.
fn cut_to_a_line(description: String) -> String {
    crate::text::truncate_chars(&description, DESCRIPTION_LIMIT)
}

/// The document a call is about: the one its `doc` parameter names, when
/// its method takes one, or the current one.
fn document_of_call(workspace: &dyn Workspace, takes_doc: bool, params: &Value) -> Option<String> {
    let named = if takes_doc { params.get("doc").and_then(Value::as_str) } else { None };
    api::workspace::resolve(workspace, named).ok()
}

/// Note document `id` in the session header the first time a call is about
/// it, with its name and size; its hash is worked out meanwhile, away from
/// the call (see [`RecordedDocument::file`]).
fn note_document(workspace: &mut dyn Workspace, id: &str) {
    if workspace.journal().knows_document(id) {
        return;
    }
    let Ok(info) = api::workspace::info(workspace, id) else { return };
    let Some(document) = workspace.document_mut(id) else { return };
    let digest = PendingDigest::start(document);
    let parent = workspace.lineage(id).and_then(|lineage| lineage.parent);
    let recorded = RecordedDocument { id: id.to_string(), version: info.version, identity: FileIdentity { name: info.name, size: info.len, sha256: None }, parent, digest };
    workspace.journal_mut().session.documents.push(recorded);
}

/// The plugin scripts `host` has loaded, with their sources' hashes.
pub fn plugins_of(host: &crate::plugins::LuaHost) -> Vec<RecordedPlugin> {
    host.script_digests().into_iter().map(|(name, sha256)| RecordedPlugin { name, sha256 }).collect()
}

#[cfg(test)]
mod tests;
