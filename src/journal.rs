//! The journal: every call that changed something, in order, by whom.
//!
//! Every way in (panels, plugins, Ask, MCP clients, the command line and
//! recipes) calls methods through [`crate::api::call`], so an analysis is
//! a sequence of method calls. The journal records that sequence, which
//! gives the History tab, undo across analysis steps, playback and recipes
//! from one mechanism (`docs/design/shared-knowledge-and-api.md` §4).
//!
//! What is recorded:
//!
//! * **Every call whose effect is edit, view or job**, by every caller, as a
//!   [`JournalEntry`] with a step number. A call that fails is recorded too,
//!   with its error, so the History tab can show what was tried; a call
//!   refused because it must first be confirmed is not, because it is
//!   recorded when the person allows it.
//! * **Reads** go into a bounded ring of recent reads, numbered from the same
//!   sequence as the steps. A later step that used a value a read returned
//!   cites it as provenance, and [`promote`] moves the read into the journal
//!   under its own step number, so `{"step": 12, "path": …}` stays valid.
//! * **Not** calls made inside another call (a transaction's, or those a
//!   plugin method makes while it runs): the outer call is the step.
//!   Not the app's own work either, which does not go through the API.
//!   Not reads of the journal itself (`history.*` reads).
//! * Consecutive calls of one setter (`selection.set`, `cursor.set`,
//!   `view.set_shape`) by the same caller on the same document are merged
//!   into the last, so dragging a selection is one step, not fifty.
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
//! steps again). `docs/design/history-recipes.md` says who owns what.

pub mod anchors;
pub mod provenance;
pub mod recipe;
pub mod replay;
pub mod timeline;

use std::collections::{BTreeMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::api::{self, ApiError, Caller, Effect, Workspace};
use crate::bus::topics::JournalRecorded;
use crate::bus::{Draft, Payload};

pub use anchors::Anchor;
pub use recipe::Recipe;

/// Where the values of a step's parameters came from: each parameter's
/// path (`start`, `length_field.offset`, `ranges[0][0]`) and its anchor.
pub type DerivedFrom = BTreeMap<String, Anchor>;

/// The producer `journal.recorded` is published as.
pub const JOURNAL_PRODUCER: &str = "journal";

/// Setters whose next call by the same caller on the same document
/// replaces the last, when nothing came between.
const MERGED_SETTERS: &[&str] = &["selection.set", "cursor.set", "view.set_shape"];

/// The namespace whose reads are not recorded: reading the journal is
/// not a step of the analysis.
const UNRECORDED_READ_NAMESPACE: &str = "history";

/// Longest description kept, in characters.
const DESCRIPTION_LIMIT: usize = 240;
/// Longest string kept in a summarised value, in characters.
const SUMMARY_STRING_LIMIT: usize = 1024;
/// Most items of an array kept in a summarised value.
const SUMMARY_ARRAY_LIMIT: usize = 32;
/// Largest document hashed for the session header.
const HASH_LIMIT: usize = 256 * 1024 * 1024;
/// Bytes read at a time while hashing.
const HASH_CHUNK: usize = 16 * 1024 * 1024;

/// How much the journal keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalLimits {
    /// Most entries kept; the oldest are dropped beyond it.
    pub max_entries: usize,
    /// Most bytes of parameters and results kept, roughly; the oldest
    /// entries are dropped beyond it.
    pub max_bytes: usize,
    /// Parameters larger than this are kept as a summary, and the step
    /// cannot be repeated exactly.
    pub max_params_bytes: usize,
    /// Results larger than this are kept as a summary.
    pub max_result_bytes: usize,
    /// Most recent reads kept for provenance.
    pub max_reads: usize,
}

impl Default for JournalLimits {
    fn default() -> Self {
        JournalLimits { max_entries: 10_000, max_bytes: 64 * 1024 * 1024, max_params_bytes: 1024 * 1024, max_result_bytes: 64 * 1024, max_reads: 256 }
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
    /// [`timeline::state_before`]): the view shape, bookmarks or selection
    /// as they were before it ran, when the timeline models the method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
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

    /// The caller, as the API knows it, to call the method again as.
    pub fn caller(&self) -> Caller {
        Caller::from_producer(&self.caller)
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

/// A document as the session first saw it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecordedDocument {
    /// Its id in this session, such as "doc-1".
    pub id: String,
    /// The version it was at.
    pub version: u64,
    pub file: FileIdentity,
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
    entries: VecDeque<JournalEntry>,
    /// Recent successful reads, in step order, the oldest dropped first.
    reads: VecDeque<JournalEntry>,
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
            parameters: BTreeMap::new(),
        }
    }

    pub fn limits(&self) -> JournalLimits {
        self.limits
    }

    /// The session header: API version, plugins and documents.
    pub fn session(&self) -> &JournalSession {
        &self.session
    }

    /// Every entry held, in step order.
    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &JournalEntry> + ExactSizeIterator {
        self.entries.iter()
    }

    /// The entries after `step`, in step order: what a follower that has
    /// seen up to `step` has not. A promoted read takes its own (earlier)
    /// step number, so a follower also watches [`Journal::revision`] or
    /// `journal.recorded` to notice one.
    pub fn since(&self, step: u64) -> impl DoubleEndedIterator<Item = &JournalEntry> {
        let from = self.entries.partition_point(|entry| entry.step <= step);
        self.entries.range(from..)
    }

    /// The entry recorded as `step`.
    pub fn entry(&self, step: u64) -> Option<&JournalEntry> {
        find_step(&self.entries, step)
    }

    /// The recent reads, oldest first.
    pub fn reads(&self) -> impl DoubleEndedIterator<Item = &JournalEntry> + ExactSizeIterator {
        self.reads.iter()
    }

    /// The recent read numbered `step`.
    pub fn read(&self, step: u64) -> Option<&JournalEntry> {
        find_step(&self.reads, step)
    }

    /// The last step recorded or read, if any.
    pub fn last_step(&self) -> Option<u64> {
        self.next_step.checked_sub(1).filter(|step| *step > 0)
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

    /// Record `entry` under the next step number (merging it into the last
    /// entry when both set the same thing) and keep within the limits.
    /// Returns its step.
    fn record(&mut self, mut entry: JournalEntry) -> u64 {
        entry.step = self.take_step();
        if let Some(replaced) = self.entries.pop_back_if(|last| merges_into(last, &entry)) {
            entry.merged = replaced.merged + 1;
            self.bytes = self.bytes.saturating_sub(entry_size(&replaced));
        }
        self.bytes += entry_size(&entry);
        let step = entry.step;
        self.entries.push_back(entry);
        self.trim();
        self.revision += 1;
        step
    }

    /// Keep a successful read in the ring under the next step number.
    fn keep_read(&mut self, mut entry: JournalEntry) -> u64 {
        entry.step = self.take_step();
        let step = entry.step;
        self.reads.push_back(entry);
        while self.reads.len() > self.limits.max_reads {
            self.reads.pop_front();
        }
        step
    }

    /// Move the read numbered `step` from the ring into the journal, with
    /// `description`, keeping its number. Returns the entry, or `None` when
    /// no such read is held.
    fn promote_read(&mut self, step: u64, description: String) -> Option<&JournalEntry> {
        let index = self.reads.iter().position(|read| read.step == step)?;
        let mut entry = self.reads.remove(index)?;
        entry.description = description;
        self.bytes += entry_size(&entry);
        let at = self.entries.partition_point(|held| held.step < step);
        self.entries.insert(at, entry);
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
            self.bytes = self.bytes.saturating_sub(entry_size(&oldest));
            self.dropped.entries += 1;
            self.dropped.through_step = self.dropped.through_step.max(oldest.step);
        }
    }

    /// Whether the session header has noted document `id`.
    fn knows_document(&self, id: &str) -> bool {
        self.session.document(id).is_some()
    }
}

/// The entry numbered `step` in `entries`, which are in step order.
fn find_step(entries: &VecDeque<JournalEntry>, step: u64) -> Option<&JournalEntry> {
    let index = entries.partition_point(|entry| entry.step < step);
    entries.get(index).filter(|entry| entry.step == step)
}

/// Whether `next` replaces `last`, the entry recorded just before it: the
/// same setter, caller and document, both successful, and the last has no
/// provenance that merging would lose.
fn merges_into(last: &JournalEntry, next: &JournalEntry) -> bool {
    MERGED_SETTERS.contains(&next.method.as_str())
        && last.method == next.method
        && last.caller == next.caller
        && last.doc == next.doc
        && last.outcome.is_ok()
        && next.outcome.is_ok()
        && last.derived_from.is_empty()
}

/// Rough bytes an entry holds.
fn entry_size(entry: &JournalEntry) -> usize {
    const OVERHEAD: usize = 256;
    OVERHEAD + approximate_size(&entry.params) + entry.result.as_ref().map_or(0, approximate_size) + entry.description.len()
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
    let seconds = time.duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs());
    let (year, month, day) = crate::patterns::civil_from_days((seconds / 86_400) as i64);
    let in_day = seconds % 86_400;
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", in_day / 3600, (in_day % 3600) / 60, in_day % 60)
}

/// SHA-256 of `bytes` as lower-case hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Recording, called by `api::call` around every method it runs
// ---------------------------------------------------------------------------

/// A call being recorded, from [`begin`] to [`finish`].
pub(crate) enum CallRecord {
    /// A call inside another: not recorded.
    Nested,
    /// The outermost call, with what was known before it ran.
    Outermost(Box<Begun>),
}

pub(crate) struct Begun {
    at: String,
    caller: String,
    method: String,
    effect: Effect,
    description: String,
    params: Value,
    params_summarised: bool,
    doc: Option<String>,
    version_before: Option<u64>,
    derived_from: DerivedFrom,
    before: Option<Value>,
}

/// Start recording a call to `method` by `caller`, before it runs.
pub(crate) fn begin(workspace: &mut dyn Workspace, caller: &Caller, method: &str, effect: Effect, params: &Value) -> CallRecord {
    let journal = workspace.journal_mut();
    journal.depth += 1;
    if journal.depth > 1 {
        return CallRecord::Nested;
    }
    let derived_from = journal.pending_provenance.take().unwrap_or_default();
    let limits = journal.limits;
    let doc = document_of_call(workspace, params);
    let version_before = doc.as_deref().and_then(|id| version_of(workspace, id));
    if let Some(id) = doc.as_deref() {
        note_document(workspace, id);
    }
    // Reads are described only if they are promoted: most never are, and
    // only steps can be undone, so only they keep what they replaced.
    let description = if effect == Effect::Read { String::new() } else { describe(workspace, method, params) };
    let before = if effect == Effect::Read { None } else { timeline::state_before(workspace, method, params) };
    let (params, params_summarised) = bounded(params, limits.max_params_bytes);
    CallRecord::Outermost(Box::new(Begun {
        at: timestamp(SystemTime::now()),
        caller: caller.producer(),
        method: method.to_string(),
        effect,
        description,
        params,
        params_summarised,
        doc,
        version_before,
        derived_from,
        before,
    }))
}

/// Finish recording a call with its result: an edit, view change or job
/// goes into the journal (failed or not) and is published; a successful
/// read goes into the ring of recent reads.
pub(crate) fn finish(workspace: &mut dyn Workspace, record: CallRecord, result: &Result<Value, ApiError>) {
    let journal = workspace.journal_mut();
    journal.depth = journal.depth.saturating_sub(1);
    let CallRecord::Outermost(begun) = record else { return };
    let begun = *begun;
    let is_read = begun.effect == Effect::Read;
    if is_read && (result.is_err() || api::namespace_of(&begun.method) == UNRECORDED_READ_NAMESPACE) {
        return;
    }
    let version_after = begun.doc.as_deref().and_then(|id| version_of(workspace, id));
    let limits = workspace.journal().limits;
    let (outcome, result, result_summarised) = match result {
        Ok(value) => {
            let (kept, summarised) = bounded(value, limits.max_result_bytes);
            (Outcome::Ok, Some(kept), summarised)
        }
        Err(error) => (Outcome::Error(error.clone()), None, false),
    };
    let entry = JournalEntry {
        step: 0,
        at: begun.at,
        caller: begun.caller,
        method: begun.method,
        effect: begun.effect,
        description: begun.description,
        params: begun.params,
        params_summarised: begun.params_summarised,
        doc: begun.doc,
        version_before: begun.version_before,
        version_after,
        outcome,
        result,
        result_summarised,
        derived_from: begun.derived_from,
        merged: 0,
        before: begun.before,
    };
    if is_read {
        workspace.journal_mut().keep_read(entry);
        return;
    }
    let step = workspace.journal_mut().record(entry);
    publish(workspace, step);
}

/// Record a call that was refused before it ran (its caller may never
/// make it), and return the refusal.
pub(crate) fn record_refusal(workspace: &mut dyn Workspace, caller: &Caller, method: &str, effect: Effect, params: &Value, refusal: ApiError) -> Result<Value, ApiError> {
    let record = begin(workspace, caller, method, effect, params);
    let result = Err(refusal);
    finish(workspace, record, &result);
    result
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
    let description = describe(workspace, &method, &params);
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

/// The call described in plain words, cut to a line.
fn describe(workspace: &mut dyn Workspace, method: &str, params: &Value) -> String {
    let description = api::describe_call(workspace, method, params);
    if description.chars().count() <= DESCRIPTION_LIMIT {
        return description;
    }
    let mut cut: String = description.chars().take(DESCRIPTION_LIMIT).collect();
    cut.push('…');
    cut
}

/// The document a call is about: the one its `doc` parameter names, or the
/// current one.
fn document_of_call(workspace: &dyn Workspace, params: &Value) -> Option<String> {
    let named = params.get("doc").and_then(Value::as_str);
    api::workspace::resolve(workspace, named).ok()
}

fn version_of(workspace: &dyn Workspace, id: &str) -> Option<u64> {
    workspace.documents().into_iter().find(|info| info.id == id).map(|info| info.version)
}

/// Note document `id` in the session header the first time a call is about
/// it, with its name, size and hash.
fn note_document(workspace: &mut dyn Workspace, id: &str) {
    if workspace.journal().knows_document(id) {
        return;
    }
    let Some(info) = workspace.documents().into_iter().find(|info| info.id == id) else { return };
    let sha256 = workspace.document_mut(id).and_then(|document| {
        let len = document.len();
        (len <= HASH_LIMIT).then(|| {
            let mut hasher = Sha256::new();
            for start in (0..len).step_by(HASH_CHUNK) {
                hasher.update(document.read_range(start, HASH_CHUNK.min(len - start)));
            }
            hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
        })
    });
    let recorded = RecordedDocument { id: id.to_string(), version: info.version, file: FileIdentity { name: info.name, size: info.len, sha256 } };
    workspace.journal_mut().session.documents.push(recorded);
}

/// The plugin scripts `host` has loaded, with their sources' hashes.
pub fn plugins_of(host: &crate::plugins::LuaHost) -> Vec<RecordedPlugin> {
    host.script_digests().into_iter().map(|(name, sha256)| RecordedPlugin { name, sha256 }).collect()
}

#[cfg(test)]
mod tests;
