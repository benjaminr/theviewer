//! The data API: one table of methods over documents, bytes, bits,
//! selections, findings, structures, codecs, packets and analysis, each
//! declared once with its name, effect and JSON schemas.
//!
//! Every way in uses the same table: Ask's tools are generated from it, the
//! command line runs one method (`theviewer api bytes.read '{…}' FILE`), and
//! `docs/api.md` is written from it by [`reference_markdown`] (its prose is
//! in `manual.rs`). Rust callers use the typed
//! functions in each namespace module directly; JSON callers go through
//! [`call`], which checks the parameters against the method's types.
//!
//! Each module under `src/api/` declares its own part of the table: its
//! `METHODS`, a `describe_call` that says in plain words what a call would
//! do (for the confirmation window), and for the tests an `examples` call
//! of each method. [`METHODS`] joins the parts, grouped by namespace, so a
//! new method touches only its module.
//!
//! Methods run against a [`Workspace`]: the window's open document, or a
//! [`HeadlessWorkspace`] of files opened from paths. See
//! `docs/design/shared-knowledge-and-api.md` for the design.
//!
//! Conventions every method follows:
//!
//! * Documents are named by id (`doc-1`), by path, or as `"current"`, the
//!   window's document. An omitted `doc` means the caller's focus (see
//!   [`workspace::focus_of`]), filled in before the method runs.
//! * Any parameter may be an anchor, `{"$anchor": …}` (or `{"$var": name}`,
//!   `{"$sheet": step or label}`), resolved before the method runs and
//!   recorded as the call's provenance (see [`call_as`]).
//! * Spans are `start` and `len` in bytes and must lie inside the document;
//!   an omitted `len` runs to the end.
//! * Bytes in JSON are hex strings unless `encoding` asks for `base64` or
//!   `text`.
//! * Integers larger than 2^53 are written as strings.
//! * List methods take `limit` and return `next`, an opaque cursor to pass
//!   back for the following page.
//! * One call reads or returns at most [`MAX_CALL_BYTES`].

/// One row of the method table: name, effect, typed function, its params
/// and result types, and the summary. Methods that act for their caller
/// (edits are labelled with it, facts published as it) are written
/// `caller fn`, and take the caller after the workspace; one that needs to
/// know whether its call was already allowed is written `consent fn`, and
/// takes the caller and the [`Consent`] too. Defined before the namespace
/// modules, which each declare their own rows with it.
///
/// A row says how the history treats the method's calls as its effect
/// does ([`Method::with_effect`]); the builders on [`Method`] say
/// otherwise (`method!(…).merges_repeats()`).
macro_rules! method {
    ($name:literal, $effect:ident, consent $function:path, $params:ty, $result:ty, $summary:literal) => {
        $crate::api::Method::with_effect(
            $name,
            $summary,
            $crate::api::Effect::$effect,
            $crate::api::schema_of::<$params>,
            $crate::api::schema_of::<$result>,
            |workspace, caller, consent, params| $crate::api::run_typed(|workspace, typed| $function(workspace, caller, consent, typed), workspace, params),
        )
    };
    ($name:literal, $effect:ident, caller $function:path, $params:ty, $result:ty, $summary:literal) => {
        $crate::api::Method::with_effect(
            $name,
            $summary,
            $crate::api::Effect::$effect,
            $crate::api::schema_of::<$params>,
            $crate::api::schema_of::<$result>,
            |workspace, caller, _consent, params| $crate::api::run_typed(|workspace, typed| $function(workspace, caller, typed), workspace, params),
        )
    };
    ($name:literal, $effect:ident, $function:path, $params:ty, $result:ty, $summary:literal) => {
        $crate::api::Method::with_effect(
            $name,
            $summary,
            $crate::api::Effect::$effect,
            $crate::api::schema_of::<$params>,
            $crate::api::schema_of::<$result>,
            |workspace, _caller, _consent, params| $crate::api::run_typed($function, workspace, params),
        )
    };
}

pub mod analysis;
pub mod application;
pub mod bytes;
pub mod codecs;
pub mod documents;
pub mod edits;
pub mod events;
pub mod findings;
pub mod history;
pub mod jobs;
mod manual;
pub mod numbers;
pub mod packet_sets;
pub mod packets;
pub mod permissions;
pub mod provenance;
pub mod recipes;
pub mod reference;
pub mod search;
pub mod selection;
pub mod structure;
pub mod tools;
pub mod values;
pub mod vars;
pub mod view;
pub mod workspace;

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, LazyLock};

use schemars::{JsonSchema, Schema};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::journal::timeline::{Move, Replay};
pub use crate::journal::undo::{Resource, Reverse, Undo};
use crate::journal::{self, Journalled, undo};
pub use manual::reference_markdown;
pub use permissions::{Caller, Consent, Decision, HeldCall, Policy};
pub use workspace::{HeadlessWorkspace, Workspace};

/// The API version, which `api.version` returns. Within a major version
/// changes are additive only.
pub const API_VERSION: &str = "1.0";

/// Most bytes one call reads or returns: 16 MiB. Larger work will be a job.
pub const MAX_CALL_BYTES: usize = 16 * 1024 * 1024;

/// What calling a method does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Looks without changing anything.
    Read,
    /// Changes a document's bytes, as one undoable step.
    Edit,
    /// Changes what is shown or open, but no bytes.
    View,
    /// Starts long-running work and returns a job to follow.
    Job,
    /// Changes the session's analysis, but no bytes and nothing on screen:
    /// packet sets and how they decode, published findings, pinned
    /// templates, jobs cancelled, files written from analysis results. It is
    /// journalled and replayed like an edit, and allowed without asking like
    /// a read (one that writes a file needs leave to edit for that; see
    /// [`WritesFile`]).
    Analysis,
}

/// Whether a method writes a file, which needs leave to edit whatever its
/// effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WritesFile {
    /// It writes none.
    No,
    /// Every call writes one.
    Always,
    /// A call writes one when it names it with this parameter, and returns
    /// what it would write otherwise.
    WhenGiven(&'static str),
}

/// Where what a method produces can go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutputKind {
    /// An undoable edit of the document it read.
    InPlace,
    /// A new sheet: a document derived from the one it read.
    New,
    /// Bytes in the result.
    Return,
    /// A file, which needs leave to edit.
    File,
}

/// The outputs a method offers, and the one it gives when none is asked
/// for. A method whose default is [`OutputKind::New`] makes a sheet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outputs {
    pub allowed: &'static [OutputKind],
    pub default: OutputKind,
}

impl Outputs {
    /// A method that makes a new sheet, and nothing else.
    pub const NEW_SHEET: Outputs = Outputs { allowed: &[OutputKind::New], default: OutputKind::New };
}

/// A method's outputs as `api.describe` lists them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OutputsDescription {
    pub allowed: Vec<OutputKind>,
    pub default: OutputKind,
}

impl From<Outputs> for OutputsDescription {
    fn from(outputs: Outputs) -> Self {
        OutputsDescription { allowed: outputs.allowed.to_vec(), default: outputs.default }
    }
}

/// Whether a method's name, parameters and results are settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Stability {
    /// Changes only by addition within the major version.
    Stable,
    /// May change in any release.
    Experimental,
}

/// Check a method's JSON parameters, run it for the caller (once allowed as
/// the consent says) and return its JSON result.
pub type RunMethod = fn(&mut dyn Workspace, &Caller, Consent<'_>, Value) -> Result<Value, ApiError>;

/// One method of the API, declared once: what it does, and how the
/// journal, undo, going back, playback, recipes and permissions treat its
/// calls.
#[derive(Clone, Copy)]
pub struct Method {
    /// Dotted name, such as `bytes.read`.
    pub name: &'static str,
    /// One sentence on what the method does, for tool lists and the reference.
    pub summary: &'static str,
    pub effect: Effect,
    pub stability: Stability,
    /// JSON Schema of the parameters.
    pub params: fn() -> Schema,
    /// JSON Schema of the result.
    pub result: fn() -> Schema,
    pub run: RunMethod,
    /// How the journal keeps its calls.
    pub journal: Journalled,
    /// How going back, playback and recipes treat a step of it.
    pub replay: Replay,
    /// How a step of it that changed no bytes is undone.
    pub undo: Undo,
    /// Whether a call replaces the last entry when that was a call of the
    /// same method by the same caller on the same document, so dragging a
    /// selection is one step.
    pub merge: bool,
    /// Whether it writes a file, which needs leave to edit.
    pub writes_file: WritesFile,
    /// Whether it takes a `doc` parameter; filled in from the params
    /// schema when the table is built ([`METHODS`]).
    pub takes_doc: bool,
    /// What an omitted `doc` means, for a method that takes one.
    pub doc_default: DocDefault,
    /// Whether the anchors marked in its params are resolved when it is
    /// called; not for a method whose params carry other calls or a recipe,
    /// whose anchors are theirs ([`Method::passes_anchors_on`]).
    pub resolves_anchors: bool,
    /// Where what it produces can go, for a method that produces bytes.
    pub outputs: Option<Outputs>,
    /// Says in plain words what a call would do; its module's, filled in
    /// when the table is built ([`METHODS`]).
    describe_call: DescribeCall,
}

impl Method {
    /// A method whose calls the journal, undo and replay treat as its
    /// effect says: see [`Journalled::for_effect`] and
    /// [`Undo::for_effect`]. Its steps are repeated by going back, playback
    /// and recipes.
    pub const fn with_effect(name: &'static str, summary: &'static str, effect: Effect, params: fn() -> Schema, result: fn() -> Schema, run: RunMethod) -> Method {
        Method {
            name,
            summary,
            effect,
            stability: Stability::Stable,
            params,
            result,
            run,
            journal: Journalled::for_effect(effect),
            replay: Replay::Step,
            undo: Undo::for_effect(effect),
            merge: false,
            writes_file: WritesFile::No,
            takes_doc: false,
            doc_default: DocDefault::Focus,
            resolves_anchors: true,
            outputs: None,
            describe_call: describe_nothing,
        }
    }

    /// An omitted `doc` is left out rather than filled in with the
    /// caller's focus: the method says what it means (`documents.open`
    /// opens the path given).
    pub const fn leaves_doc_out(mut self) -> Self {
        self.doc_default = DocDefault::LeftOut;
        self
    }

    /// Its params carry other calls or a recipe (`history.transaction`,
    /// `recipes.run`), whose anchors are resolved when those run: only its
    /// own `doc`'s anchor is resolved when it is called.
    pub const fn passes_anchors_on(mut self) -> Self {
        self.resolves_anchors = false;
        self
    }

    /// An omitted `doc` is the document `chosen` names for the caller, or,
    /// when it names none, the caller's focus.
    pub const fn doc_defaults_to(mut self, chosen: ChooseDoc) -> Self {
        self.doc_default = DocDefault::Chosen(chosen);
        self
    }

    /// The namespace, such as `bytes` for `bytes.read`.
    pub fn namespace(&self) -> &'static str {
        namespace_of(self.name)
    }

    /// Its steps change one thing a later call can change back, as
    /// `reverse` says.
    pub const fn reverses(mut self, reverse: Reverse) -> Self {
        self.undo = Undo::Reverses(reverse);
        self
    }

    /// Its steps make what `resource` says, which undoing removes.
    pub const fn creates(mut self, resource: Resource) -> Self {
        self.undo = Undo::Creates(resource);
        self
    }

    /// Its steps leave nothing to undo, because `why`.
    pub const fn leaves_nothing_to_undo(mut self, why: &'static str) -> Self {
        self.undo = Undo::Nothing(why);
        self
    }

    /// It opens a document and makes it current (one that `derives` opens
    /// one derived from the current document): undone by opening the one
    /// current before, and not repeated.
    pub const fn opens_document(mut self, derives: bool) -> Self {
        self.replay = Replay::OpensDocument { derives };
        self.undo = Undo::Reverses(Reverse::OpenDocument { derives });
        self
    }

    /// It makes a new sheet, a document derived from the one it reads, and
    /// makes it current: kept by recipes, which make the sheet again and
    /// name it by this step, but not repeated by going back or playback,
    /// as the sheet is open already; undone by opening the document current
    /// before.
    pub const fn makes_sheet(mut self) -> Self {
        self.replay = Replay::MakesSheet;
        self.undo = Undo::Reverses(Reverse::OpenDocument { derives: true });
        self.outputs = Some(Outputs::NEW_SHEET);
        self
    }

    /// It writes a file, as `writes` says: that needs leave to edit, the
    /// file stays as written, and it is not repeated.
    pub const fn writes_file(mut self, writes: WritesFile) -> Self {
        self.writes_file = writes;
        self.replay = Replay::WritesFile;
        self.undo = Undo::Nothing(undo::WROTE_A_FILE);
        self
    }

    /// It moves along the timeline rather than taking a step of the
    /// analysis.
    pub const fn moves_along_the_timeline(mut self, kind: Move) -> Self {
        self.replay = Replay::Move(kind);
        self
    }

    /// Its steps are never repeated: it reloads plugins, or starts or stops
    /// a live source.
    pub const fn not_replayed(mut self) -> Self {
        self.replay = Replay::Never;
        self
    }

    /// Its repeated calls merge into one step.
    pub const fn merges_repeats(mut self) -> Self {
        self.merge = true;
        self
    }

    /// Its steps are notes on the analysis: journalled where they are
    /// written, but they change nothing, so they are never repeated, undone
    /// or gone back past (see [`Replay::Note`]).
    pub const fn writes_a_note(mut self) -> Self {
        self.replay = Replay::Note;
        self.undo = Undo::Nothing(undo::A_NOTE_CHANGES_NOTHING);
        self
    }

    /// Its calls are not journalled: it reads the journal, or edits its
    /// provenance or its notes.
    pub const fn not_journalled(mut self) -> Self {
        self.journal = Journalled::Skip;
        self
    }
}

/// Chooses the document an omitted `doc` means for a caller, from the
/// call's params, or `None` to leave it to the caller's focus.
pub type ChooseDoc = fn(&dyn Workspace, &Caller, &Value) -> Option<String>;

/// What an omitted `doc` means, for a method that takes one.
#[derive(Clone, Copy)]
pub enum DocDefault {
    /// The caller's focus: filled in before the method runs, so the
    /// journal entry names the document.
    Focus,
    /// Nothing: it is left out, and the method says what that means.
    LeftOut,
    /// The document a function chooses, else the caller's focus.
    Chosen(ChooseDoc),
}

/// The namespace of a dotted method name.
pub fn namespace_of(name: &str) -> &str {
    name.split_once('.').map_or(name, |(namespace, _)| namespace)
}

/// What runs a method a plugin registered.
pub type RunRegistered = dyn Fn(&mut dyn Workspace, &Caller, Value) -> Result<Value, ApiError> + Send + Sync;

/// A method added at run time, by a plugin's `theviewer.register_method`.
/// It joins the table for `api.describe`, Ask's tools and every other
/// client, and is always experimental.
pub struct RegisteredMethod {
    /// Dotted name, such as `acme.decode_frame`.
    pub name: String,
    pub summary: String,
    /// `read` or `edit`.
    pub effect: Effect,
    /// JSON Schema of the parameters.
    pub params: Value,
    /// JSON Schema of the result.
    pub result: Value,
    /// Who registered it, such as `plugin:acme.lua`.
    pub owner: String,
    pub run: Box<RunRegistered>,
}

impl fmt::Debug for RegisteredMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("RegisteredMethod").field("name", &self.name).field("effect", &self.effect).field("owner", &self.owner).finish()
    }
}

/// A method found by name: one of the table's or one a plugin registered.
#[derive(Clone)]
pub enum MethodRef {
    Builtin(&'static Method),
    Registered(Arc<RegisteredMethod>),
}

impl MethodRef {
    pub fn name(&self) -> &str {
        match self {
            MethodRef::Builtin(method) => method.name,
            MethodRef::Registered(method) => &method.name,
        }
    }

    pub fn summary(&self) -> &str {
        match self {
            MethodRef::Builtin(method) => method.summary,
            MethodRef::Registered(method) => &method.summary,
        }
    }

    pub fn effect(&self) -> Effect {
        match self {
            MethodRef::Builtin(method) => method.effect,
            MethodRef::Registered(method) => method.effect,
        }
    }

    /// JSON Schema of the parameters.
    pub fn params_schema(&self) -> Value {
        match self {
            MethodRef::Builtin(method) => (method.params)().to_value(),
            MethodRef::Registered(method) => method.params.clone(),
        }
    }

    pub fn describe(&self) -> MethodDescription {
        match self {
            MethodRef::Builtin(method) => MethodDescription {
                name: method.name.to_string(),
                summary: method.summary.to_string(),
                effect: method.effect,
                stability: method.stability,
                params: (method.params)().to_value(),
                result: (method.result)().to_value(),
                outputs: method.outputs.map(OutputsDescription::from),
            },
            MethodRef::Registered(method) => MethodDescription {
                name: method.name.clone(),
                summary: method.summary.clone(),
                effect: method.effect,
                stability: Stability::Experimental,
                params: method.params.clone(),
                result: method.result.clone(),
                outputs: None,
            },
        }
    }

    /// How the journal keeps its calls; a plugin's as its effect says.
    pub fn journalled(&self) -> Journalled {
        match self {
            MethodRef::Builtin(method) => method.journal,
            MethodRef::Registered(method) => Journalled::for_effect(method.effect),
        }
    }

    /// How going back, playback and recipes treat a step of it; a
    /// plugin's steps are repeated.
    pub fn replay(&self) -> Replay {
        match self {
            MethodRef::Builtin(method) => method.replay,
            MethodRef::Registered(_) => Replay::Step,
        }
    }

    /// How a step of it that changed no bytes is undone; a plugin's leave
    /// nothing kept to undo them by.
    pub fn undo(&self) -> Undo {
        match self {
            MethodRef::Builtin(method) => method.undo,
            MethodRef::Registered(method) => Undo::registered(method.effect),
        }
    }

    /// Whether its repeated calls merge into one step.
    pub fn merges_repeats(&self) -> bool {
        matches!(self, MethodRef::Builtin(method) if method.merge)
    }

    /// Whether a call with `params` writes a file.
    pub fn writes_file(&self, params: &Value) -> bool {
        match self {
            MethodRef::Builtin(method) => match method.writes_file {
                WritesFile::No => false,
                WritesFile::Always => true,
                WritesFile::WhenGiven(param) => params.get(param).is_some_and(|path| !path.is_null()),
            },
            MethodRef::Registered(_) => false,
        }
    }

    /// Whether it takes a `doc` parameter.
    pub fn takes_doc(&self) -> bool {
        match self {
            MethodRef::Builtin(method) => method.takes_doc,
            MethodRef::Registered(method) => method.params["properties"].get("doc").is_some(),
        }
    }

    /// Whether the anchors marked in its params are resolved when it is
    /// called; a plugin's are.
    pub fn resolves_anchors(&self) -> bool {
        match self {
            MethodRef::Builtin(method) => method.resolves_anchors,
            MethodRef::Registered(_) => true,
        }
    }

    /// What an omitted `doc` means; a plugin's method's is the caller's
    /// focus.
    pub fn doc_default(&self) -> DocDefault {
        match self {
            MethodRef::Builtin(method) => method.doc_default,
            MethodRef::Registered(_) => DocDefault::Focus,
        }
    }

    /// What a call with `params` would do, in plain words: see
    /// [`describe_call`].
    pub fn describe_call(&self, workspace: &mut dyn Workspace, params: &Value) -> String {
        let described = match self {
            MethodRef::Builtin(method) => (method.describe_call)(workspace, method.name, params),
            MethodRef::Registered(_) => None,
        };
        described.unwrap_or_else(|| described_generally(self.name(), params))
    }

    /// The effect whose leave a call with `params` needs: an edit's when it
    /// writes a file, otherwise its own.
    pub fn needs_leave_for(&self, params: &Value) -> Effect {
        if self.writes_file(params) { Effect::Edit } else { self.effect() }
    }

    fn run(&self, workspace: &mut dyn Workspace, caller: &Caller, consent: Consent<'_>, params: Value) -> Result<Value, ApiError> {
        match self {
            MethodRef::Builtin(method) => (method.run)(workspace, caller, consent, params),
            MethodRef::Registered(method) => (method.run)(workspace, caller, params),
        }
    }
}

/// Why a call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The parameters don't match the schema.
    InvalidParams,
    /// A span falls outside the document.
    OutOfRange,
    /// No such document, method or entry.
    NotFound,
    /// The document changed since `expect_version`.
    VersionConflict,
    /// The caller may not edit.
    ReadOnly,
    /// Over the per-call limit.
    TooLarge,
    /// A job was cancelled.
    Cancelled,
    /// A plugin raised an error or used up its budget.
    PluginFailed,
    /// Something needed is missing, such as tshark.
    Unavailable,
}

/// A failed call: a code to act on, a message saying what to do next, and
/// any details.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError { code, message: message.into(), data: None }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidParams, message)
    }

    pub fn out_of_range(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::OutOfRange, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    pub fn too_large(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::TooLarge, message)
    }

    pub fn version_conflict(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::VersionConflict, message)
    }

    pub fn plugin_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PluginFailed, message)
    }

    /// Whether this is the error of a call that must be confirmed first.
    pub fn needs_confirmation(&self) -> bool {
        self.data.as_ref().is_some_and(|data| data["reason"] == permissions::NEEDS_CONFIRMATION)
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// The error as JSON, as the command line and Ask report it.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| Value::String(self.message.clone()))
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", serde_json::to_value(self.code).ok().and_then(|code| code.as_str().map(str::to_string)).unwrap_or_default(), self.message)
    }
}

impl std::error::Error for ApiError {}

/// The schema of a type, for the method table.
fn schema_of<T: JsonSchema>() -> Schema {
    schemars::schema_for!(T)
}

/// Run a typed method on JSON parameters: missing parameters count as `{}`,
/// and parameters that do not fit the method's type are `invalid_params`.
fn run_typed<P: DeserializeOwned, R: Serialize>(
    function: impl FnOnce(&mut dyn Workspace, P) -> Result<R, ApiError>,
    workspace: &mut dyn Workspace,
    params: Value,
) -> Result<Value, ApiError> {
    let params = if params.is_null() { Value::Object(Default::default()) } else { params };
    let typed: P = serde_json::from_value(params).map_err(|error| ApiError::invalid_params(format!("{error}; see the method's params schema in api.describe")))?;
    let result = function(workspace, typed)?;
    serde_json::to_value(result).map_err(|error| ApiError::new(ErrorCode::InvalidParams, format!("the result could not be written as JSON: {error}")))
}

/// The API's own methods.
const API_METHODS: &[Method] = &[
    method!("api.version", Read, version, values::NoParams, VersionResult, "The API version: 1.0. Changes within a major version only add methods, optional parameters and result fields."),
    method!("api.describe", Read, describe_method, values::NoParams, Description, "Every method with its summary, effect, stability and the JSON schemas of its parameters and result."),
];

/// Says in plain words what a call would do, for the window that asks the
/// person to confirm it; `None` for a call the module does not describe.
type DescribeCall = fn(&mut dyn Workspace, &str, &Value) -> Option<String>;

/// One module's part of the method table: its methods, how it describes
/// calls to them and, for the tests, an example call of each.
struct Part {
    methods: &'static [Method],
    describe_call: DescribeCall,
    #[cfg(test)]
    examples: fn() -> Vec<(&'static str, Value)>,
}

/// The part of the table the module `$module` declares: its `METHODS`,
/// `describe_call` and `examples`.
macro_rules! part {
    ($module:ident) => {
        Part {
            methods: $module::METHODS,
            describe_call: $module::describe_call,
            #[cfg(test)]
            examples: $module::examples,
        }
    };
}

/// Every module's part, in a fixed order. Each module declares its own
/// methods, so adding a method touches only its module; adding a module
/// adds one line here.
const PARTS: &[Part] = &[
    Part {
        methods: API_METHODS,
        describe_call: describe_nothing,
        #[cfg(test)]
        examples: api_examples,
    },
    part!(documents),
    part!(bytes),
    part!(edits),
    part!(search),
    part!(numbers),
    part!(selection),
    part!(findings),
    part!(structure),
    part!(codecs),
    part!(packets),
    part!(packet_sets),
    part!(analysis),
    part!(reference),
    part!(events),
    part!(jobs),
    part!(tools),
    part!(view),
    part!(application),
    part!(history),
    part!(provenance),
    part!(recipes),
    part!(vars),
];

/// For modules whose calls need no description of their own.
fn describe_nothing(_workspace: &mut dyn Workspace, _method: &str, _params: &Value) -> Option<String> {
    None
}

#[cfg(test)]
fn api_examples() -> Vec<(&'static str, Value)> {
    vec![("api.version", serde_json::json!({})), ("api.describe", serde_json::json!({}))]
}

/// Every method, grouped by namespace. The namespaces come in the order
/// their first method appears in [`PARTS`], and within a namespace the
/// methods keep their modules' order, so the table, `api.describe` and
/// `docs/api.md` list them the same way every time. Each method carries
/// its module's describer, and whether it takes a `doc` parameter.
pub static METHODS: LazyLock<Vec<Method>> = LazyLock::new(|| {
    let declared = PARTS.iter().flat_map(|part| part.methods.iter().map(|method| Method { takes_doc: params_name_doc(method), describe_call: part.describe_call, ..*method }));
    grouped_by_namespace(declared.collect())
});

/// Where each method of [`METHODS`] is, by name.
static INDEX: LazyLock<HashMap<&'static str, usize>> = LazyLock::new(|| METHODS.iter().enumerate().map(|(index, method)| (method.name, index)).collect());

/// Whether `method`'s parameters include `doc`.
fn params_name_doc(method: &Method) -> bool {
    (method.params)().as_value()["properties"].get("doc").is_some()
}

/// `methods` grouped by namespace, the namespaces in the order they first
/// appear; a stable sort keeps each namespace's methods in order.
fn grouped_by_namespace(mut methods: Vec<Method>) -> Vec<Method> {
    let mut namespaces: Vec<&str> = Vec::new();
    for method in &methods {
        if !namespaces.contains(&method.namespace()) {
            namespaces.push(method.namespace());
        }
    }
    methods.sort_by_key(|method| namespaces.iter().position(|namespace| *namespace == method.namespace()));
    methods
}

/// The method called `name` in the table.
pub fn method(name: &str) -> Option<&'static Method> {
    INDEX.get(name).map(|index| &METHODS[*index])
}

/// The method called `name`: the table's, or one a plugin registered in
/// `workspace`.
pub fn find(workspace: &dyn Workspace, name: &str) -> Result<MethodRef, ApiError> {
    if let Some(method) = method(name) {
        return Ok(MethodRef::Builtin(method));
    }
    workspace
        .registered_methods()
        .into_iter()
        .find(|method| method.name == name)
        .map(MethodRef::Registered)
        .ok_or_else(|| ApiError::not_found(format!("there is no method '{name}'; api.describe lists them")))
}

/// Every method: the table's, then those plugins registered in `workspace`.
pub fn all_methods(workspace: &dyn Workspace) -> Vec<MethodRef> {
    METHODS.iter().map(MethodRef::Builtin).chain(workspace.registered_methods().into_iter().map(MethodRef::Registered)).collect()
}

/// Run the method called `name` with JSON parameters for `caller`, once the
/// workspace allows it: a method that edits, changes the view or writes a
/// file, called by anyone but the person at the keyboard, is checked
/// against the caller's policy. A call that must be confirmed fails here
/// with a `read_only` error for which [`ApiError::needs_confirmation`]
/// holds; callers that can wait for the person hold it instead (see
/// [`call_or_hold`]).
///
/// Every call is journalled (see [`crate::journal`]): an edit, view change
/// or job as a step, whether it succeeded, failed or was denied; a read in
/// the ring of recent reads.
pub fn call(workspace: &mut dyn Workspace, caller: &Caller, name: &str, params: Value) -> Result<Value, ApiError> {
    call_as(workspace, caller, name, params, Consent::CheckedAs(caller))
}

/// [`call`], noting where the values of some parameters came from (by
/// parameter path, such as `start` or `length_field.offset`), so the
/// journal entry carries them as `derived_from` and a recipe made from it
/// uses the anchors in place of the literals.
pub fn call_derived(workspace: &mut dyn Workspace, caller: &Caller, name: &str, params: Value, derived_from: journal::DerivedFrom) -> Result<Value, ApiError> {
    journal::with_provenance(workspace, derived_from, |workspace| call(workspace, caller, name, params))
}

/// Run the method called `name` without checking anyone's policy: for
/// calls the person has just allowed (in the confirmation window), calls
/// inside a call already allowed (a transaction's, an undo's), and plugin
/// actions the person ran. Journalled as [`call`] is; a call inside another
/// is part of that one's step.
pub fn call_permitted(workspace: &mut dyn Workspace, caller: &Caller, name: &str, params: Value) -> Result<Value, ApiError> {
    call_as(workspace, caller, name, params, Consent::Given)
}

/// Run the method called `name` for `caller` once `consent` allows it:
/// given, or the policy of the caller it names allows the call's effect (an
/// edit's, when the call writes a file). A call that policy denies is
/// recorded as refused; one it would ask about fails with a `read_only`
/// error for which [`ApiError::needs_confirmation`] holds. Every way a call
/// runs comes here, but for [`call_or_hold`]'s holding.
///
/// Before the call runs ([`prepare_call`]):
///
/// * **Anchors** marked anywhere in `params` (`{"$anchor": …}`, `{"$var":
///   name}`, `{"$sheet": step or label}`) are resolved against the live
///   session, `doc`'s first: step and pick anchors read the journal's
///   entries (a read they cite becomes a step), sheet anchors the sheets
///   the session's steps made. The call runs on the values, which its
///   journal entry keeps in `params`, with the anchors as its
///   `derived_from`, so a recipe made from it finds them again.
/// * **The document.** An omitted `doc`, for a method that takes one, is
///   filled in with the caller's focus (or what the method chooses), so the
///   journal entry always names the document.
///
/// The caller's focus is kept from its first call on (see
/// [`workspace::pin_focus`]), and after a call succeeds it follows a
/// document the call opened or activated, or a new sheet it asked to focus
/// (`output: {"new": {"focus": true}}`). Neither making a sheet nor naming a
/// document in a call moves it.
pub fn call_as(workspace: &mut dyn Workspace, caller: &Caller, name: &str, params: Value, consent: Consent<'_>) -> Result<Value, ApiError> {
    let method = find(workspace, name)?;
    let prepared = match prepare_call(workspace, caller, &method, params) {
        Ok(prepared) => prepared,
        Err((params, error)) => return journal::record_refusal(workspace, caller, &method, &params, error),
    };
    let PreparedCall { params, derived_from } = prepared;
    let focuses_sheet = workspace::asks_to_focus_the_sheet(&params);
    let outermost = workspace.journal_mut().provide_for_next_call(derived_from);
    let result = match leave(workspace, &method, &params, consent) {
        Leave::Granted => run_journalled(workspace, &method, caller, consent, params),
        Leave::Denied(subject) => journal::record_refusal(workspace, caller, &method, &params, permissions::denied(subject, name)),
        Leave::MustAsk(subject) => Err(permissions::needs_confirmation(subject, name)),
    };
    if outermost {
        // A call that never ran leaves its provenance for none other.
        workspace.journal_mut().take_pending_provenance();
    }
    if let Ok(value) = &result {
        workspace::follow_focus(workspace, caller, &method, focuses_sheet, value);
    }
    result
}

/// A call ready to run: its params with anchors resolved and `doc` filled
/// in, and where those anchors came from.
struct PreparedCall {
    params: Value,
    derived_from: journal::DerivedFrom,
}

/// Resolve the anchors marked in `params` and fill in an omitted `doc`, as
/// [`call_as`] says. On failure, the params as far as they were prepared,
/// and why.
fn prepare_call(workspace: &mut dyn Workspace, caller: &Caller, method: &MethodRef, mut params: Value) -> Result<PreparedCall, (Value, ApiError)> {
    let takes_doc = method.takes_doc();
    // Kept from the caller's first call, so what that call opens or derives
    // does not move it.
    let focus = workspace::pin_focus(workspace, caller);
    if takes_doc && params.is_null() {
        params = Value::Object(Default::default());
    }
    let mut live = journal::anchors::live::LiveAnchors::new(caller);
    let mut derived_from = match live.resolve_doc(workspace, &mut params) {
        Ok(derived_from) => derived_from,
        Err(error) => return Err((params, error)),
    };
    if takes_doc && params.get("doc").is_none_or(Value::is_null) {
        let filled = match method.doc_default() {
            DocDefault::LeftOut => None,
            DocDefault::Chosen(choose) => choose(&*workspace, caller, &params).or(focus),
            DocDefault::Focus => focus,
        };
        if let (Some(doc), Some(fields)) = (filled, params.as_object_mut()) {
            fields.insert("doc".to_string(), Value::String(doc));
        }
    }
    if method.resolves_anchors() {
        match live.resolve_rest(workspace, &mut params) {
            Ok(resolved) => derived_from.extend(resolved),
            Err(error) => return Err((params, error)),
        }
    }
    Ok(PreparedCall { params, derived_from })
}

/// Whether a call may run now.
enum Leave<'a> {
    Granted,
    /// This caller's policy never allows it.
    Denied(&'a Caller),
    /// The person must be asked, for this caller.
    MustAsk(&'a Caller),
}

/// Whether a call of `method` with `params` may run, as `consent` says.
fn leave<'a>(workspace: &dyn Workspace, method: &MethodRef, params: &Value, consent: Consent<'a>) -> Leave<'a> {
    let Consent::CheckedAs(subject) = consent else { return Leave::Granted };
    match workspace.permission(subject, method.needs_leave_for(params)) {
        Decision::Allowed => Leave::Granted,
        Decision::Denied => Leave::Denied(subject),
        Decision::NeedsConfirmation => Leave::MustAsk(subject),
    }
}

/// Run `method` for `caller` and record the call in the journal.
fn run_journalled(workspace: &mut dyn Workspace, method: &MethodRef, caller: &Caller, consent: Consent<'_>, params: Value) -> Result<Value, ApiError> {
    let record = journal::begin(workspace, caller, method, &params);
    let result = method.run(workspace, caller, consent, params);
    journal::finish(workspace, record, &result);
    result
}

/// Run `name` for `caller` if allowed, refuse it if denied, and otherwise
/// hold it for the person to decide on; `reply` gets the result in every
/// case, at once or once the person has decided (the confirmation window
/// then runs it through [`call_permitted`]). This is how callers that
/// cannot block (Ask's tool calls, plugins' handlers, MCP requests) ask.
pub fn call_or_hold(workspace: &mut dyn Workspace, caller: Caller, name: &str, params: Value, reply: permissions::ReplyTo) {
    let method = match find(workspace, name) {
        Ok(method) => method,
        Err(error) => return reply(workspace, Err(error)),
    };
    let result = match leave(workspace, &method, &params, Consent::CheckedAs(&caller)) {
        Leave::Granted => call_as(workspace, &caller, name, params, Consent::CheckedAs(&caller)),
        Leave::Denied(_) => journal::record_refusal(workspace, &caller, &method, &params, permissions::denied(&caller, name)),
        Leave::MustAsk(_) => {
            let description = method.describe_call(workspace, &params);
            let held = HeldCall { caller, method: name.to_string(), params, description, reply };
            if let Some(held) = workspace.hold_for_confirmation(held) {
                let error = permissions::needs_confirmation(&held.caller, name);
                (held.reply)(workspace, Err(error));
            }
            return;
        }
    };
    reply(workspace, result);
}

/// What a call to `method` with `params` would do, in plain words, for the
/// window that asks the person: "Overwrite 4 bytes at 0x40 with DE AD BE
/// EF", "XOR 128 selected bytes with 5A". The method's module describes
/// it; a call no module describes is shown as "Call method with params".
pub fn describe_call(workspace: &mut dyn Workspace, method: &str, params: &Value) -> String {
    match find(workspace, method) {
        Ok(found) => found.describe_call(workspace, params),
        Err(_) => described_generally(method, params),
    }
}

/// A call no module describes: "Call method with params".
fn described_generally(method: &str, params: &Value) -> String {
    let shown = if params.as_object().is_some_and(|object| !object.is_empty()) { format!(" with {params}") } else { String::new() };
    format!("Call {method}{shown}")
}

/// The result of `api.version`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VersionResult {
    /// Major and minor version, such as "1.0".
    pub version: String,
}

pub fn version(_workspace: &mut dyn Workspace, _params: values::NoParams) -> Result<VersionResult, ApiError> {
    Ok(VersionResult { version: API_VERSION.to_string() })
}

/// One method as `api.describe` lists it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MethodDescription {
    pub name: String,
    pub summary: String,
    pub effect: Effect,
    pub stability: Stability,
    /// JSON Schema of the parameters.
    pub params: Value,
    /// JSON Schema of the result.
    pub result: Value,
    /// Where what it produces can go, for a method that produces bytes: a
    /// method whose default is `new` makes a sheet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs: Option<OutputsDescription>,
}

/// One topic of the workspace bus as `api.describe` lists it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TopicDescription {
    /// Dotted name, such as `record_width.estimated`.
    pub name: String,
    /// Facts are kept (the latest per producer, document and key); events are not.
    pub kind: crate::bus::Kind,
    pub description: String,
    /// JSON Schema of the payload.
    pub payload: Value,
}

/// The whole method table, as `api.describe` returns it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Description {
    pub version: String,
    pub methods: Vec<MethodDescription>,
    /// The bus's topics, which `events.facts` and `events.poll` read.
    pub topics: Vec<TopicDescription>,
}

/// Every method in the table and every topic, with their schemas.
pub fn describe() -> Description {
    let methods: Vec<MethodRef> = METHODS.iter().map(MethodRef::Builtin).collect();
    describe_methods(&methods)
}

/// `methods` and every topic, with their schemas.
fn describe_methods(methods: &[MethodRef]) -> Description {
    let methods = methods.iter().map(MethodRef::describe).collect();
    let topics = crate::bus::topics::TOPICS
        .iter()
        .map(|topic| TopicDescription { name: topic.name.to_string(), kind: topic.kind, description: topic.description.to_string(), payload: (topic.payload)().to_value() })
        .collect();
    Description { version: API_VERSION.to_string(), methods, topics }
}

/// What `api.describe` returns: the table and the methods plugins
/// registered in this workspace.
fn describe_method(workspace: &mut dyn Workspace, _params: values::NoParams) -> Result<Description, ApiError> {
    Ok(describe_methods(&all_methods(workspace)))
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::PathBuf;
    use std::sync::{Arc, LazyLock};

    use serde_json::Value;

    use super::{ApiError, Caller, HeadlessWorkspace, Workspace};
    use crate::document::Document;
    use crate::plugin::Registry;

    /// The app's registry, built once for all the API tests.
    static REGISTRY: LazyLock<Registry> = LazyLock::new(crate::app::build_registry);

    /// A workspace holding one document of `bytes`, called `name`.
    pub fn workspace_with(name: &str, bytes: &[u8]) -> HeadlessWorkspace {
        let mut workspace = HeadlessWorkspace::new(Arc::new(REGISTRY.clone()));
        workspace.add_document(name, Document::from_bytes(bytes.to_vec()));
        workspace
    }

    /// Call a method as the person at the keyboard would.
    pub fn call(workspace: &mut dyn Workspace, name: &str, params: Value) -> Result<Value, ApiError> {
        super::call(workspace, &Caller::Panel, name, params)
    }

    /// The bytes the method examples run on: a zlib stream, then text.
    pub fn example_bytes() -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &b"hello ".repeat(50)).unwrap();
        let mut bytes = encoder.finish().unwrap();
        bytes.extend(b"The quick brown fox jumps over the lazy dog. ".repeat(20));
        bytes
    }

    /// A file holding [`example_bytes`], for the examples that open one.
    pub fn example_file() -> PathBuf {
        let path = std::env::temp_dir().join(format!("theviewer-api-examples-{}.bin", std::process::id()));
        std::fs::write(&path, example_bytes()).unwrap();
        path
    }

    /// Where the examples that save a document save it.
    pub fn example_save_path() -> PathBuf {
        std::env::temp_dir().join(format!("theviewer-api-examples-saved-{}.bin", std::process::id()))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::test_support::{call, workspace_with};
    use super::*;

    #[test]
    fn every_method_has_a_unique_dotted_name_and_a_summary() {
        let mut names = std::collections::HashSet::new();
        for method in METHODS.iter() {
            assert!(names.insert(method.name), "{} is declared twice", method.name);
            assert!(method.name.contains('.') && method.name.chars().all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'), "{}", method.name);
            assert!(method.summary.ends_with('.'), "{} needs a one-sentence summary", method.name);
        }
    }

    #[test]
    fn every_schema_is_an_object_schema_that_closes_its_parameters() {
        for method in METHODS.iter() {
            let params = (method.params)().to_value();
            assert_eq!(params["type"], "object", "{} params", method.name);
            assert_eq!(params["additionalProperties"], false, "{} rejects unknown parameters", method.name);
            assert!((method.result)().to_value().is_object(), "{} result", method.name);
        }
    }

    /// Whether `value` fits `schema`, for the parts of JSON Schema the
    /// method table's schemas use. Returns where it does not fit.
    fn check_against(schema: &Value, value: &Value, root: &Value, path: &str) -> Result<(), String> {
        if schema == &Value::Bool(true) {
            return Ok(());
        }
        if let Some(reference) = schema["$ref"].as_str() {
            let name = reference.strip_prefix("#/$defs/").ok_or_else(|| format!("{path}: unexpected reference {reference}"))?;
            return check_against(&root["$defs"][name], value, root, path);
        }
        for key in ["anyOf", "oneOf"] {
            if let Some(options) = schema[key].as_array()
                && !options.iter().any(|option| check_against(option, value, root, path).is_ok())
            {
                return Err(format!("{path}: {value} fits none of the {key} options"));
            }
        }
        if let Some(options) = schema["enum"].as_array()
            && !options.contains(value)
        {
            return Err(format!("{path}: {value} is not one of {options:?}"));
        }
        if let Some(constant) = schema.get("const")
            && constant != value
        {
            return Err(format!("{path}: {value} is not {constant}"));
        }
        let types: Vec<&str> = match &schema["type"] {
            Value::String(name) => vec![name.as_str()],
            Value::Array(names) => names.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        let fits = |name: &str| match name {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => false,
        };
        if !types.is_empty() && !types.iter().any(|name| fits(name)) {
            return Err(format!("{path}: {value} is not {types:?}"));
        }
        if let Some(object) = value.as_object() {
            let properties = schema["properties"].as_object();
            for required in schema["required"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                if !object.contains_key(required) {
                    return Err(format!("{path}: '{required}' is missing"));
                }
            }
            for (key, item) in object {
                match properties.and_then(|properties| properties.get(key)) {
                    Some(property) => check_against(property, item, root, &format!("{path}.{key}"))?,
                    None if schema["additionalProperties"] == false => return Err(format!("{path}: '{key}' is not allowed")),
                    None => {}
                }
            }
        }
        if let Some(items) = value.as_array() {
            let prefix = schema["prefixItems"].as_array();
            for (index, item) in items.iter().enumerate() {
                let item_schema = prefix.and_then(|prefix| prefix.get(index)).unwrap_or(&schema["items"]);
                if !item_schema.is_null() {
                    check_against(item_schema, item, root, &format!("{path}[{index}]"))?;
                }
            }
        }
        Ok(())
    }

    fn fits_schema(schema: &Schema, value: &Value) -> Result<(), String> {
        let schema = schema.as_value();
        check_against(schema, value, schema, "")
    }

    #[test]
    fn every_module_gives_an_example_of_each_of_its_methods() {
        for part in PARTS {
            let named: std::collections::HashSet<&str> = (part.examples)().iter().map(|(name, _)| *name).collect();
            for method in part.methods {
                assert!(named.contains(method.name), "{} needs an example in its module's examples()", method.name);
            }
        }
    }

    #[test]
    fn every_method_accepts_its_example_and_answers_in_its_result_schema() {
        for part in PARTS {
            // Each module's examples run in order on a document of their own.
            let mut workspace = workspace_with("example.bin", &test_support::example_bytes());
            for (name, params) in (part.examples)() {
                let method = method(name).unwrap_or_else(|| panic!("{name} is not in the table"));
                fits_schema(&(method.params)(), &params).unwrap_or_else(|problem| panic!("{name} params: {problem}"));
                let result = call(&mut workspace, name, params).unwrap_or_else(|error| panic!("{name}: {error}"));
                fits_schema(&(method.result)(), &result).unwrap_or_else(|problem| panic!("{name} result: {problem}"));
            }
        }
        std::fs::remove_file(test_support::example_file()).ok();
        std::fs::remove_file(test_support::example_save_path()).ok();
    }

    #[test]
    fn the_table_lists_every_module_s_methods_once_grouped_by_namespace() {
        let declared: usize = PARTS.iter().map(|part| part.methods.len()).sum();
        assert_eq!(METHODS.len(), declared, "every module's methods are in the table");
        let mut finished: Vec<&str> = Vec::new();
        let mut current = "";
        for method in METHODS.iter() {
            if method.namespace() != current {
                assert!(!finished.contains(&method.namespace()), "{} is apart from the rest of its namespace", method.name);
                finished.push(current);
                current = method.namespace();
            }
        }
        let first: Vec<&str> = METHODS.iter().take(4).map(|method| method.name).collect();
        assert_eq!(first, ["api.version", "api.describe", "documents.list", "documents.info"]);
    }

    #[test]
    fn every_method_that_makes_a_sheet_names_it_in_its_result_s_output() {
        let makers: Vec<&Method> = METHODS.iter().filter(|method| method.replay == Replay::MakesSheet).collect();
        let names: Vec<&str> = makers.iter().map(|method| method.name).collect();
        for expected in ["documents.derive", "codecs.open_decoded", "bits.open_plane", "bits.decode_linecode", "unpack.open", "forensics.open_entry", "crypto.open_decrypted"] {
            assert!(names.contains(&expected), "{expected} makes a sheet");
        }
        for method in makers {
            assert!((method.result)().to_value()["properties"].get("output").is_some(), "{} gives output", method.name);
            assert_eq!(method.outputs, Some(Outputs::NEW_SHEET), "{} says so in api.describe", method.name);
        }
        for opener in ["documents.open", "documents.new", "documents.open_source"] {
            assert!(matches!(method(opener).unwrap().replay, Replay::OpensDocument { .. }), "{opener} opens an input, not a step");
        }
    }

    #[test]
    fn the_schema_check_notices_values_that_do_not_fit() {
        let schema = (method("bytes.read").unwrap().params)();
        assert!(fits_schema(&schema, &json!({"start": 0})).is_ok());
        assert!(fits_schema(&schema, &json!({"len": 4})).is_err(), "start is required");
        assert!(fits_schema(&schema, &json!({"start": "0"})).is_err());
        assert!(fits_schema(&schema, &json!({"start": 0, "encoding": "rot13"})).is_err());
    }

    #[test]
    fn the_version_is_one_point_zero() {
        let mut workspace = workspace_with("a.bin", b"abc");
        assert_eq!(call(&mut workspace, "api.version", Value::Null).unwrap(), json!({"version": "1.0"}));
    }

    #[test]
    fn describe_lists_every_method_with_its_schemas() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let description = call(&mut workspace, "api.describe", json!({})).unwrap();
        let methods = description["methods"].as_array().unwrap();
        assert_eq!(methods.len(), METHODS.len());
        let read = methods.iter().find(|method| method["name"] == "bytes.read").unwrap();
        assert_eq!(read["effect"], "read");
        assert!(read["params"]["properties"]["start"].is_object());
        let topics = description["topics"].as_array().unwrap();
        assert_eq!(topics.len(), crate::bus::topics::TOPICS.len());
        let width = topics.iter().find(|topic| topic["name"] == "record_width.estimated").unwrap();
        assert_eq!(width["kind"], "fact");
        assert!(width["payload"]["properties"]["width"].is_object());
    }

    #[test]
    fn an_unknown_method_is_not_found_and_bad_params_are_invalid() {
        let mut workspace = workspace_with("a.bin", b"abc");
        assert_eq!(call(&mut workspace, "bytes.melt", json!({})).unwrap_err().code, ErrorCode::NotFound);
        let error = call(&mut workspace, "bytes.read", json!({"start": "zero"})).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
        let error = call(&mut workspace, "bytes.read", json!({"start": 0, "len": 1, "colour": "red"})).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams, "unknown parameters are rejected");
    }

    #[test]
    fn writing_a_file_needs_leave_to_edit_whatever_the_method_s_effect() {
        let mut app = crate::app::ViewerApp::new(crate::app::Launch::default());
        app.open_bytes(vec![0u8; 128], "a.bin".to_string());
        app.run_bus();
        call(&mut app, "packets.sets.create", json!({"from": "split_fixed", "record_len": 8, "len": 64})).unwrap();
        app.preferences.permissions.insert("mcp:claude-code".into(), Policy::Deny);
        let client = Caller::Mcp("claude-code".into());
        let returned = super::call(&mut app, &client, "packets.extract", json!({"set": "set-1", "indices": [0]})).unwrap();
        assert_eq!(returned["len"], 8, "an analysis is allowed without asking");
        let path = std::env::temp_dir().join(format!("theviewer-api-leave-to-write-{}.bin", std::process::id()));
        let refused = super::call(&mut app, &client, "packets.extract", json!({"set": "set-1", "indices": [0], "path": path.display().to_string()})).unwrap_err();
        assert_eq!(refused.code, ErrorCode::ReadOnly);
        assert!(!path.exists(), "nothing was written");
        app.preferences.permissions.insert("mcp:claude-code".into(), Policy::Ask);
        let asked = super::call(&mut app, &client, "packets.export_pcap", json!({"set": "set-1", "path": path.display().to_string()})).unwrap_err();
        assert!(asked.needs_confirmation(), "the person can be asked: {}", asked.message);
    }

    #[test]
    fn errors_are_written_with_a_snake_case_code() {
        let error = ApiError::too_large("read less").with_data(json!({"limit": 1}));
        assert_eq!(error.to_json(), json!({"code": "too_large", "message": "read less", "data": {"limit": 1}}));
        assert_eq!(error.to_string(), "too_large: read less");
    }

    #[test]
    fn the_reference_document_matches_the_method_table() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/api.md");
        let written = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            written == reference_markdown(),
            "docs/api.md is out of date with the method table; regenerate it with `cargo run --bin api_docs`"
        );
    }
}
