//! What API methods run against: the open documents, where the cursor and
//! selection are in each, and the registry of detectors, parsers and codecs.
//!
//! The window is one workspace ([`ViewerApp`] implements [`Workspace`]); a
//! [`HeadlessWorkspace`] is another, holding files opened from paths, for the
//! command line and, later, the MCP server. Methods see only the trait, so
//! the same method works in both. Each workspace has its own bus of facts
//! and events.
//!
//! **Focus.** Each caller has a focus: the document an omitted `doc` means
//! for it ([`focus_of`]). It is the current document when the caller first
//! calls, and moves when the caller opens or activates a document or asks
//! for a new sheet to be focused. Neither a sheet made (a derive, a node
//! opened) nor a document named in a call moves it, so a client's next call
//! without `doc` is about the document it was working on.
//! The person's focus is the window's document, as are a plugin's and
//! Ask's, which act for the person; `"current"` still names that (or,
//! headless, the document opened or made last).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::permissions::{self, Caller, Decision, HeldCall};
use super::packet_sets::PacketSets;
use super::view::ViewShape;
use super::{ApiError, Effect, MethodRef, RegisteredMethod, Replay};
use crate::app::ViewerApp;
use crate::bookmarks::Bookmark;
use crate::bus::topics::{CursorMoved, DocumentEdited, DocumentOpened, FindingsPublished, SelectionChanged, TemplateApplied};
use crate::bus::{Bus, Draft, MessageId, Payload};
use crate::document::Document;
use crate::folds::Folds;
use crate::journal::Journal;
use crate::plugin::Registry;
use crate::selection::Selection;
use crate::sources::{self, Recording};

/// Who publishes edits made by hand, outside any API call.
pub const DOCUMENT_PRODUCER: &str = "document";
/// Who publishes the template pinned by `templates.apply`.
pub const TEMPLATES_PRODUCER: &str = "tool:templates";

/// The name that stands for the current document.
pub const CURRENT: &str = "current";

/// One open document, as `documents.list` and `documents.info` describe it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DocumentInfo {
    /// Stable id, such as "doc-1".
    pub id: String,
    /// File name, or the name of a derived document.
    pub name: String,
    /// Path on disk, for documents opened from a file.
    pub path: Option<String>,
    /// Length in bytes.
    pub len: u64,
    /// Incremented on every edit.
    pub version: u64,
    /// Whether there are edits not saved.
    pub modified: bool,
    /// Whether this is the current document.
    pub current: bool,
    /// The document it was derived from, for a sheet made from another;
    /// none for one opened from a file, a source or new.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// The step that made it, for a sheet made from another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub made_by: Option<MadeBy>,
    /// A short name its maker gave it, such as "payload", which a recipe
    /// names it by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Whether it is the focus of the caller listing it: what an omitted
    /// `doc` means for that caller (`documents.list` says).
    #[serde(default, skip_serializing_if = "is_false")]
    pub focus: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Where each caller works: the document an omitted `doc` means for it, by
/// the caller's producer id. The person at the window, and every caller
/// with `legacy_current`, works on the current document instead.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Foci {
    by_caller: HashMap<String, String>,
    /// Every caller's omitted `doc` means the current document, as before
    /// callers had a focus of their own (`theviewer mcp --legacy-current`).
    pub legacy_current: bool,
}

/// Where a document came from: the document it was derived from and the
/// step that made it. A root, opened from a file, a source or new, has
/// neither.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Lineage {
    /// The document it was derived from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// The call that made it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub made_by: Option<MadeBy>,
}

/// The call that made a sheet.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MadeBy {
    /// The journal step it was recorded as, when it was the outermost call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<u64>,
    /// The method called, such as `documents.derive`.
    pub method: String,
    /// Its parameters, as called.
    #[serde(default)]
    pub params: serde_json::Value,
    /// The ranges of the parent it came from, as [start, len], where known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<Vec<(u64, u64)>>,
    /// A short name for it, such as "payload".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Lineage {
    /// The lineage of a sheet derived from `parent`, its maker not yet known.
    pub fn derived_from(parent: &str) -> Self {
        Lineage { parent: Some(parent.to_string()), made_by: None }
    }

    /// The label its maker gave it.
    pub fn label(&self) -> Option<String> {
        self.made_by.as_ref().and_then(|made_by| made_by.label.clone())
    }
}

/// A sheet a call made, as every such call's result gives it under
/// `output` (or, for a call that may make several, `outputs`): one stable
/// place for later steps to find it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SheetOutput {
    /// The new document's id, such as "doc-4".
    pub doc: String,
    /// The short name it was given, if any, which a recipe names it by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Its length in bytes.
    pub len: u64,
}

impl SheetOutput {
    /// The output naming the open document `id`.
    pub fn of(workspace: &dyn Workspace, id: &str) -> Result<SheetOutput, ApiError> {
        let info = info(workspace, id)?;
        Ok(SheetOutput { doc: info.id, label: info.label, len: info.len })
    }
}

/// The result of a method that opens one sheet and describes it: the new
/// document, as `documents.info` gives it, and `output`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SheetMade {
    #[serde(flatten)]
    pub document: DocumentInfo,
    /// The sheet made, in the form every method that makes one gives.
    pub output: SheetOutput,
}

impl SheetMade {
    /// The open document `id`, just made.
    pub fn of(workspace: &dyn Workspace, id: &str) -> Result<SheetMade, ApiError> {
        Ok(SheetMade { document: info(workspace, id)?, output: SheetOutput::of(workspace, id)? })
    }
}

/// Where the cursor and selection are in a document, and what the view
/// knows about its layout.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ViewState {
    pub cursor: usize,
    pub selection: Option<Selection>,
    /// Bytes per record or raster row, which detectors use as a stride.
    pub record_stride: Option<usize>,
}

/// The documents and tools API methods run against.
pub trait Workspace {
    /// Every open document.
    fn documents(&self) -> Vec<DocumentInfo>;
    /// The id of the current document, if one is open.
    fn current_document(&self) -> Option<String>;
    /// The version of the document with this id, without describing every
    /// open document.
    fn version(&self, id: &str) -> Option<u64> {
        self.documents().into_iter().find(|info| info.id == id).map(|info| info.version)
    }
    /// The document with this id.
    fn document_mut(&mut self, id: &str) -> Option<&mut Document>;
    /// The cursor, selection and layout of the document with this id.
    fn view(&self, id: &str) -> Option<ViewState>;
    /// Every detector, parser and codec, built in or from plugins.
    fn registry(&self) -> Arc<Registry>;
    /// Open the file at `path` and make it current, returning its id; a
    /// file already open is made current again.
    fn open_path(&mut self, path: &Path) -> Result<String, ApiError>;
    /// Make the open document `id` current.
    fn switch_to(&mut self, id: &str) -> Result<(), ApiError>;
    /// The workspace's bus, with every message published so far delivered.
    fn bus(&mut self) -> &mut Bus;
    /// Publish the changes made to document `id` since they were last
    /// published, on `document.edited` as `producer`'s.
    fn publish_edits(&mut self, id: &str, producer: &str);
    /// Move the cursor and set the selection in document `id` (`None`
    /// selects nothing), and publish the change as `caller`'s.
    fn select(&mut self, id: &str, cursor: usize, selection: Option<Selection>, caller: &Caller);
    /// Save document `id` to `path`, or to the file it came from.
    fn save(&mut self, id: &str, path: Option<&Path>) -> Result<(), ApiError>;
    /// Open a new empty document called `name` and make it current,
    /// returning its id.
    fn new_document(&mut self, name: &str) -> Result<String, ApiError>;
    /// [`Workspace::open_path`], but documents it closes are closed even
    /// with unsaved edits, which are lost, as the window's File › Open
    /// does; the file is opened again even when it is already open. Only
    /// for the person at the window.
    fn open_path_discarding(&mut self, path: &Path) -> Result<String, ApiError> {
        self.open_path(path)
    }
    /// [`Workspace::switch_to`], losing unsaved edits in what it closes, as
    /// the window's Back does.
    fn switch_to_discarding(&mut self, id: &str) -> Result<(), ApiError> {
        self.switch_to(id)
    }
    /// [`Workspace::new_document`], losing unsaved edits in what it closes,
    /// as the window's File › New does.
    fn new_document_discarding(&mut self, name: &str) -> Result<String, ApiError> {
        self.new_document(name)
    }
    /// Open `bytes` as a document called `name` derived from the open
    /// document `parent` (a selection, a decoded stream, a packet), make it
    /// current and return its id. The window keeps the parent waiting
    /// behind it, to go back to.
    fn open_derived(&mut self, parent: &str, bytes: Vec<u8>, name: &str) -> Result<String, ApiError>;
    /// Pin a template's parse over document `id`, as the template tool
    /// does: it is published on `template.applied`, with its structure and
    /// records, and shown.
    fn pin_template(&mut self, id: &str, applied: TemplateApplied);
    /// Whether `caller` may call a method with `effect` here.
    fn permission(&self, caller: &Caller, effect: Effect) -> Decision;
    /// Hold a call until the person allows or denies it, then reply. A
    /// workspace that cannot ask anyone gives the call back.
    fn hold_for_confirmation(&mut self, held: HeldCall) -> Option<HeldCall> {
        Some(held)
    }
    /// The methods plugins registered here.
    fn registered_methods(&self) -> Vec<Arc<RegisteredMethod>> {
        Vec::new()
    }
    /// The packet sets made through the API.
    fn packet_sets(&self) -> &PacketSets;
    fn packet_sets_mut(&mut self) -> &mut PacketSets;
    /// Show packet set `id` where packets are shown, after it was made or
    /// its decoding changed; a workspace with nowhere to show it does nothing.
    fn show_packet_set(&mut self, _id: &str) {}
    /// The shape document `id`'s bytes are drawn in.
    fn shape(&self, id: &str) -> Option<ViewShape>;
    /// Draw document `id`'s bytes in `shape`, already checked against the
    /// document and the limits.
    fn set_shape(&mut self, id: &str, shape: ViewShape) -> Result<(), ApiError>;
    /// The ranges skipped (folded) out of document `id`'s views.
    fn folds(&self, id: &str) -> Option<Folds>;
    /// Skip `folds` in document `id`'s views, already checked against the
    /// document.
    fn set_folds(&mut self, id: &str, folds: Folds) -> Result<(), ApiError>;
    /// Document `id`'s bookmarks, in offset order.
    fn bookmarks(&self, id: &str) -> Option<Vec<Bookmark>>;
    /// Keep `bookmarks` for document `id` (the window keeps them beside
    /// its file too).
    fn set_bookmarks(&mut self, id: &str, bookmarks: Vec<Bookmark>) -> Result<(), ApiError>;
    /// Open `bytes` read from a source (a URL, a device, a process) as a
    /// new document called `name` and make it current, returning its id.
    fn open_source_bytes(&mut self, name: &str, bytes: Vec<u8>) -> Result<String, ApiError>;
    /// Start or stop keeping every version of document `id` as it changes;
    /// starting keeps the version it is at now.
    fn set_recording(&mut self, id: &str, enabled: bool) -> Result<(), ApiError>;
    /// How many versions of document `id` are kept, or `None` when they
    /// are not being recorded.
    fn recorded_versions(&self, id: &str) -> Option<usize>;
    /// Open version `index` of document `id`, counting from 0, as a
    /// derived document, returning its id.
    fn open_recorded_version(&mut self, id: &str, index: usize) -> Result<String, ApiError>;
    /// The window, when this workspace is the window: for a method whose
    /// effect only the window has (a panel to show, a chart to fill), so it
    /// need not add a hook of its own here. Headless workspaces have none,
    /// and such a method does what it can without it.
    fn window(&mut self) -> Option<&mut ViewerApp> {
        None
    }
    /// The session's journal of calls (see [`crate::journal`]).
    fn journal(&self) -> &Journal;
    fn journal_mut(&mut self) -> &mut Journal;
    /// Where the open document `id` came from: the document it was derived
    /// from and the step that made it; `None` for a document not open.
    fn lineage(&self, id: &str) -> Option<Lineage>;
    /// Say which call made the open document `id` (the journal does, once
    /// the call that made it has finished).
    fn note_made_by(&mut self, id: &str, made_by: MadeBy);
    /// Each caller's focus (see [`focus_of`]).
    fn foci(&self) -> &Foci;
    fn foci_mut(&mut self) -> &mut Foci;
}

/// Whether `caller` works on the current document rather than a focus of
/// its own: the person at the window, whose focus is the document shown;
/// a plugin's action and Ask, which act for the person on what they see;
/// and every caller when foci are turned off. MCP clients, the command
/// line and recipes keep a focus of their own.
pub fn follows_current(workspace: &dyn Workspace, caller: &Caller) -> bool {
    matches!(caller, Caller::Panel | Caller::Plugin(_) | Caller::Ask) || workspace.foci().legacy_current
}

/// The document `caller` works on, which an omitted `doc` means: the one
/// it last opened or activated (or the current one when it first called),
/// while that is open; else the current document.
pub fn focus_of(workspace: &dyn Workspace, caller: &Caller) -> Option<String> {
    if follows_current(workspace, caller) {
        return workspace.current_document();
    }
    let focus = workspace.foci().by_caller.get(&caller.producer()).filter(|id| workspace.version(id).is_some()).cloned();
    focus.or_else(|| workspace.current_document())
}

/// [`focus_of`], kept as the caller's focus from now on, so making a new
/// document current does not move it.
pub fn pin_focus(workspace: &mut dyn Workspace, caller: &Caller) -> Option<String> {
    let focus = focus_of(workspace, caller)?;
    set_focus(workspace, caller, &focus);
    Some(focus)
}

/// Make the open document `id` `caller`'s focus; the person's focus is the
/// window's document, which this does not change.
pub fn set_focus(workspace: &mut dyn Workspace, caller: &Caller, id: &str) {
    if follows_current(workspace, caller) {
        return;
    }
    workspace.foci_mut().by_caller.insert(caller.producer(), id.to_string());
}

/// Whether a call's `params` ask for the sheet it makes to become the
/// caller's focus: `output: {"new": {"focus": true}}`.
pub fn asks_to_focus_the_sheet(params: &serde_json::Value) -> bool {
    params.pointer("/output/new/focus").and_then(serde_json::Value::as_bool) == Some(true)
}

/// Move `caller`'s focus after a successful call of `method`: to a document
/// it opened or activated, or to the new sheet it made when it asked for
/// that (`focuses_sheet`, see [`asks_to_focus_the_sheet`]). A document it
/// only named stays where it was.
pub fn follow_focus(workspace: &mut dyn Workspace, caller: &Caller, method: &MethodRef, focuses_sheet: bool, result: &serde_json::Value) {
    let opened = matches!(method.replay(), Replay::OpensDocument { .. }).then(|| opened_by(result)).flatten();
    let focused_sheet = focuses_sheet.then(|| result.pointer("/output/doc")).flatten().and_then(serde_json::Value::as_str).map(str::to_string);
    let moved_to = opened.or(focused_sheet);
    if let Some(id) = moved_to.filter(|id| workspace.version(id).is_some()) {
        set_focus(workspace, caller, &id);
    }
}

/// The document a call that opens one opened, as its result names it.
fn opened_by(result: &serde_json::Value) -> Option<String> {
    let id = result.get("id").or_else(|| result.pointer("/document/id"));
    id.and_then(serde_json::Value::as_str).map(str::to_string)
}

/// The open document `id` descends from that was opened, not derived: its
/// parent's parent, and so on.
pub fn root_of(workspace: &dyn Workspace, id: &str) -> String {
    let mut current = id.to_string();
    let mut seen = Vec::new();
    while let Some(parent) = workspace.lineage(&current).and_then(|lineage| lineage.parent) {
        if seen.contains(&parent) {
            break;
        }
        seen.push(current);
        current = parent;
    }
    current
}

/// `document.edited` with the changes `document` made since `published`,
/// or nothing when there were none.
pub fn edits_since(document: &Document, published: u64) -> Option<DocumentEdited> {
    if document.version() == published {
        return None;
    }
    // When the log no longer reaches back, the edits are not listed and
    // nothing can be carried through them.
    let edits = document.edits_since(published);
    let complete = edits.is_some();
    Some(DocumentEdited { edits: edits.unwrap_or_default(), complete })
}

/// The id of the document `doc` names: an id, an open document's path, or
/// "current" (which `None` also means).
pub fn resolve(workspace: &dyn Workspace, doc: Option<&str>) -> Result<String, ApiError> {
    match doc {
        None | Some(CURRENT) => workspace.current_document().ok_or_else(|| ApiError::not_found("no document is open; open one with documents.open")),
        Some(name) => workspace
            .documents()
            .into_iter()
            .find(|info| info.id == name || info.path.as_deref() == Some(name))
            .map(|info| info.id)
            .ok_or_else(|| ApiError::not_found(format!("no open document is called '{name}'; documents.list shows the open ones"))),
    }
}

/// The document `doc` names, with its id.
pub fn document<'a>(workspace: &'a mut dyn Workspace, doc: Option<&str>) -> Result<(String, &'a mut Document), ApiError> {
    let id = resolve(workspace, doc)?;
    let document = workspace.document_mut(&id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
    Ok((id, document))
}

/// The description of the document `id`.
pub fn info(workspace: &dyn Workspace, id: &str) -> Result<DocumentInfo, ApiError> {
    workspace.documents().into_iter().find(|info| info.id == id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))
}

/// `recording` with `document`'s bytes now kept as a version, when they
/// are small enough to keep.
fn record_version(mut recording: Recording, document: &mut Document) -> Recording {
    if document.len() <= crate::workbench::RECORDING_FILE_LIMIT {
        recording.record(&document.read_range(0, document.len()));
    }
    recording
}

/// The bytes of recorded version `index` of the document called `name`,
/// and the name to open them under.
pub fn recorded_version(recording: Option<&Recording>, index: usize, name: &str) -> Result<(Vec<u8>, String), ApiError> {
    let recording = recording.ok_or_else(|| ApiError::invalid_params("no versions are being recorded; start with sources.record"))?;
    if index >= recording.len() {
        return Err(ApiError::not_found(format!("there is no version {index}: {} are recorded, counting from 0", recording.len())));
    }
    Ok((recording.materialise(index), format!("{name} @ version {}", index + 1)))
}

/// One document of a headless workspace, with its own cursor and selection.
struct OpenDocument {
    id: String,
    name: String,
    document: Document,
    view: ViewState,
    shape: ViewShape,
    folds: Folds,
    bookmarks: Vec<Bookmark>,
    /// Every version kept since recording started, a version after each edit.
    recording: Option<Recording>,
    /// The version `document.edited` has been published up to.
    published_version: u64,
    /// Where it came from: its parent and the step that made it.
    lineage: Lineage,
}

/// Documents opened without a window, for the command line, scripts and
/// a standalone MCP server. Its client opened every file in it, so every
/// call is allowed: there is nobody else to ask.
pub struct HeadlessWorkspace {
    documents: Vec<OpenDocument>,
    current: Option<usize>,
    registry: Arc<Registry>,
    /// Documents ever opened, for the next id.
    opened: usize,
    bus: Bus,
    methods: Vec<Arc<RegisteredMethod>>,
    /// The message whose plugin handler is running, which the edits and
    /// selections it makes are published as caused by.
    cause: Option<MessageId>,
    packet_sets: PacketSets,
    journal: Journal,
    foci: Foci,
}

impl HeadlessWorkspace {
    pub fn new(registry: Arc<Registry>) -> Self {
        HeadlessWorkspace {
            documents: Vec::new(),
            current: None,
            registry,
            opened: 0,
            bus: Bus::new(),
            methods: Vec::new(),
            cause: None,
            packet_sets: PacketSets::default(),
            journal: Journal::new(),
            foci: Foci::default(),
        }
    }

    /// Offer the methods plugins registered.
    pub fn set_registered_methods(&mut self, methods: Vec<Arc<RegisteredMethod>>) {
        self.methods = methods;
    }

    /// Use another registry of detectors, parsers and codecs, after the
    /// plugins were reloaded.
    pub fn set_registry(&mut self, registry: Arc<Registry>) {
        self.registry = registry;
    }

    /// Say which message the plugin handler about to run handles (`None`
    /// once it has finished), so what it changes is published as caused by
    /// it and loops are stopped.
    pub fn set_cause(&mut self, cause: Option<MessageId>) {
        self.cause = cause;
    }

    /// `draft` marked as caused by the message being handled, if any.
    fn caused(&self, draft: Draft) -> Draft {
        match self.cause {
            Some(cause) => draft.caused_by(cause),
            None => draft,
        }
    }

    fn open_document(&mut self, id: &str) -> Option<&mut OpenDocument> {
        self.documents.iter_mut().find(|open| open.id == id)
    }

    /// Add a document and make it current; returns its id.
    pub fn add_document(&mut self, name: impl Into<String>, document: Document) -> String {
        self.opened += 1;
        let id = format!("doc-{}", self.opened);
        let name = name.into();
        let opened = DocumentOpened { name: name.clone(), path: document.path().map(|path| path.display().to_string()), len: document.len() };
        self.bus.publish(Draft::new("workspace", Payload::DocumentOpened(opened)).about(id.clone(), document.version()));
        let published_version = document.version();
        let lineage = Lineage::default();
        self.documents.push(OpenDocument { id: id.clone(), name, document, view: ViewState::default(), shape: ViewShape::default(), folds: Folds::default(), bookmarks: Vec::new(), recording: None, published_version, lineage });
        self.current = Some(self.documents.len() - 1);
        id
    }

    /// Set where the cursor and selection are in document `id`.
    pub fn set_view(&mut self, id: &str, view: ViewState) {
        if let Some(open) = self.documents.iter_mut().find(|open| open.id == id) {
            open.view = view;
        }
    }
}

impl Workspace for HeadlessWorkspace {
    fn documents(&self) -> Vec<DocumentInfo> {
        self.documents
            .iter()
            .enumerate()
            .map(|(index, open)| DocumentInfo {
                id: open.id.clone(),
                name: open.name.clone(),
                path: open.document.path().map(|path| path.display().to_string()),
                len: open.document.len() as u64,
                version: open.document.version(),
                modified: open.document.is_modified(),
                current: self.current == Some(index),
                parent: open.lineage.parent.clone(),
                made_by: open.lineage.made_by.clone(),
                label: open.lineage.label(),
                focus: false,
            })
            .collect()
    }

    fn current_document(&self) -> Option<String> {
        self.current.map(|index| self.documents[index].id.clone())
    }

    fn version(&self, id: &str) -> Option<u64> {
        self.documents.iter().find(|open| open.id == id).map(|open| open.document.version())
    }

    fn document_mut(&mut self, id: &str) -> Option<&mut Document> {
        self.documents.iter_mut().find(|open| open.id == id).map(|open| &mut open.document)
    }

    fn view(&self, id: &str) -> Option<ViewState> {
        self.documents.iter().find(|open| open.id == id).map(|open| open.view.clone())
    }

    fn shape(&self, id: &str) -> Option<ViewShape> {
        self.documents.iter().find(|open| open.id == id).map(|open| open.shape)
    }

    /// Records are a row's bytes in its pixel format and its padding apart.
    fn set_shape(&mut self, id: &str, shape: ViewShape) -> Result<(), ApiError> {
        let open = self.documents.iter_mut().find(|open| open.id == id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
        open.shape = shape;
        open.view.record_stride = Some(shape.format.bytes_for_pixels(shape.width) + shape.row_padding);
        Ok(())
    }

    fn folds(&self, id: &str) -> Option<Folds> {
        self.documents.iter().find(|open| open.id == id).map(|open| open.folds.clone())
    }

    fn set_folds(&mut self, id: &str, folds: Folds) -> Result<(), ApiError> {
        let open = self.open_document(id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
        open.folds = folds;
        Ok(())
    }

    fn bookmarks(&self, id: &str) -> Option<Vec<Bookmark>> {
        self.documents.iter().find(|open| open.id == id).map(|open| open.bookmarks.clone())
    }

    fn set_bookmarks(&mut self, id: &str, bookmarks: Vec<Bookmark>) -> Result<(), ApiError> {
        let open = self.open_document(id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
        open.bookmarks = bookmarks;
        Ok(())
    }

    fn open_source_bytes(&mut self, name: &str, bytes: Vec<u8>) -> Result<String, ApiError> {
        Ok(self.add_document(name, Document::from_bytes(bytes)))
    }

    /// Without a file watcher, a version is kept after each edit.
    fn set_recording(&mut self, id: &str, enabled: bool) -> Result<(), ApiError> {
        let open = self.open_document(id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
        if enabled == open.recording.is_some() {
            return Ok(());
        }
        open.recording = enabled.then(|| record_version(Recording::new(sources::DEFAULT_RECORDING_BUDGET), &mut open.document));
        Ok(())
    }

    fn recorded_versions(&self, id: &str) -> Option<usize> {
        self.documents.iter().find(|open| open.id == id)?.recording.as_ref().map(Recording::len)
    }

    fn open_recorded_version(&mut self, id: &str, index: usize) -> Result<String, ApiError> {
        let open = self.documents.iter().find(|open| open.id == id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
        let (bytes, name) = recorded_version(open.recording.as_ref(), index, &open.name)?;
        Ok(self.add_document(name, Document::from_bytes(bytes)))
    }

    fn registry(&self) -> Arc<Registry> {
        Arc::clone(&self.registry)
    }

    fn open_path(&mut self, path: &Path) -> Result<String, ApiError> {
        if let Some(index) = self.documents.iter().position(|open| open.document.path() == Some(path)) {
            self.current = Some(index);
            return Ok(self.documents[index].id.clone());
        }
        let document = Document::open(path).map_err(|error| ApiError::not_found(format!("could not open {}: {error:#}", path.display())))?;
        let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string());
        Ok(self.add_document(name, document))
    }

    fn switch_to(&mut self, id: &str) -> Result<(), ApiError> {
        let index = self.documents.iter().position(|open| open.id == id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
        self.current = Some(index);
        Ok(())
    }

    /// With no frame loop to deliver messages, they are delivered whenever
    /// the bus is asked for.
    fn bus(&mut self) -> &mut Bus {
        self.bus.deliver_all();
        &mut self.bus
    }

    fn publish_edits(&mut self, id: &str, producer: &str) {
        let Some(open) = self.documents.iter_mut().find(|open| open.id == id) else { return };
        let Some(edited) = edits_since(&open.document, open.published_version) else { return };
        open.published_version = open.document.version();
        if let Some(recording) = open.recording.take() {
            open.recording = Some(record_version(recording, &mut open.document));
        }
        let draft = Draft::new(producer, Payload::DocumentEdited(edited)).about(id, open.published_version);
        self.bus.publish(self.caused(draft));
    }

    fn select(&mut self, id: &str, cursor: usize, selection: Option<Selection>, caller: &Caller) {
        let Some(open) = self.open_document(id) else { return };
        let moved = open.view.cursor != cursor;
        open.view.cursor = cursor;
        open.view.selection = selection.clone();
        let version = open.document.version();
        if moved {
            self.bus.publish(self.caused(Draft::new(caller.producer(), Payload::CursorMoved(CursorMoved { offset: cursor })).about(id, version)));
        }
        self.bus.publish(self.caused(Draft::new(caller.producer(), Payload::SelectionChanged(SelectionChanged { cursor, selection })).about(id, version)));
    }

    fn save(&mut self, id: &str, path: Option<&Path>) -> Result<(), ApiError> {
        let open = self.open_document(id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
        let path = path.or(open.document.path()).map(Path::to_path_buf).ok_or_else(|| ApiError::invalid_params("this document has no file yet; give a path to save it to"))?;
        open.document.save_to(&path).map_err(|error| ApiError::new(super::ErrorCode::Unavailable, format!("could not save {}: {error:#}", path.display())))?;
        // Reopen, so the saved file is what the document reads and the
        // edits are no longer counted as unsaved.
        let reopened = Document::open(&path).map_err(|error| ApiError::not_found(format!("saved {}, but could not open it again: {error:#}", path.display())))?;
        open.document = reopened;
        open.published_version = open.document.version();
        open.name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| open.name.clone());
        let opened = DocumentOpened { name: open.name.clone(), path: Some(path.display().to_string()), len: open.document.len() };
        let draft = Draft::new("workspace", Payload::DocumentOpened(opened)).about(id, open.published_version);
        self.bus.publish(draft);
        Ok(())
    }

    fn new_document(&mut self, name: &str) -> Result<String, ApiError> {
        Ok(self.add_document(name, Document::default()))
    }

    /// The derived document is recorded as its parent's child.
    fn open_derived(&mut self, parent: &str, bytes: Vec<u8>, name: &str) -> Result<String, ApiError> {
        if self.open_document(parent).is_none() {
            return Err(ApiError::not_found(format!("document '{parent}' has closed")));
        }
        let id = self.add_document(name, Document::from_bytes(bytes));
        if let Some(open) = self.open_document(&id) {
            open.lineage = Lineage::derived_from(parent);
        }
        Ok(id)
    }

    fn pin_template(&mut self, id: &str, applied: TemplateApplied) {
        let Some(version) = self.open_document(id).map(|open| open.document.version()) else { return };
        let parse = applied.structure.clone();
        let structure = crate::app::structure_of(&parse);
        let (start, len) = (parse.start, parse.len);
        self.bus.publish(Draft::new(TEMPLATES_PRODUCER, Payload::TemplateApplied(applied)).about(id, version).span(start, len));
        self.bus.publish(Draft::new(TEMPLATES_PRODUCER, Payload::StructureIdentified(structure)).about(id, version).span(start, len));
        self.bus.publish(Draft::new(TEMPLATES_PRODUCER, Payload::FindingsPublished(FindingsPublished { findings: vec![parse] })).about(id, version).span(start, len));
    }

    fn permission(&self, _caller: &Caller, _effect: Effect) -> Decision {
        Decision::Allowed
    }

    fn registered_methods(&self) -> Vec<Arc<RegisteredMethod>> {
        self.methods.clone()
    }

    fn packet_sets(&self) -> &PacketSets {
        &self.packet_sets
    }

    fn packet_sets_mut(&mut self) -> &mut PacketSets {
        &mut self.packet_sets
    }

    fn journal(&self) -> &Journal {
        &self.journal
    }

    fn journal_mut(&mut self) -> &mut Journal {
        &mut self.journal
    }

    fn lineage(&self, id: &str) -> Option<Lineage> {
        self.documents.iter().find(|open| open.id == id).map(|open| open.lineage.clone())
    }

    fn note_made_by(&mut self, id: &str, made_by: MadeBy) {
        if let Some(open) = self.open_document(id) {
            open.lineage.made_by = Some(made_by);
        }
    }

    fn foci(&self) -> &Foci {
        &self.foci
    }

    fn foci_mut(&mut self) -> &mut Foci {
        &mut self.foci
    }
}

/// The window shows one document at a time; the documents it was derived
/// from (a decompressed stream's container, say) wait on its parent stack,
/// and are open too: they can be read, edited and gone back to.
impl Workspace for ViewerApp {
    fn documents(&self) -> Vec<DocumentInfo> {
        let parents = self.parents.iter().map(|parent| DocumentInfo {
            id: parent.id.clone(),
            name: parent.name.clone(),
            path: parent.document.path().map(|path| path.display().to_string()),
            len: parent.document.len() as u64,
            version: parent.document.version(),
            modified: parent.document.is_modified(),
            current: false,
            parent: None,
            made_by: None,
            label: None,
            focus: false,
        });
        let shown = DocumentInfo {
            id: self.document_id(),
            name: self.display_name(),
            path: self.document.path().map(|path| path.display().to_string()),
            len: self.document.len() as u64,
            version: self.document.version(),
            modified: self.document.is_modified(),
            current: true,
            parent: None,
            made_by: None,
            label: None,
            focus: false,
        };
        parents
            .chain(std::iter::once(shown))
            .map(|mut info| {
                let lineage = self.lineage(&info.id).unwrap_or_default();
                info.label = lineage.label();
                (info.parent, info.made_by) = (lineage.parent, lineage.made_by);
                info
            })
            .collect()
    }

    fn current_document(&self) -> Option<String> {
        Some(self.document_id())
    }

    fn version(&self, id: &str) -> Option<u64> {
        if id == self.document_id {
            return Some(self.document.version());
        }
        self.parents.iter().find(|parent| parent.id == id).map(|parent| parent.document.version())
    }

    fn document_mut(&mut self, id: &str) -> Option<&mut Document> {
        if id == self.document_id {
            return Some(&mut self.document);
        }
        self.parents.iter_mut().find(|parent| parent.id == id).map(|parent| &mut parent.document)
    }

    fn view(&self, id: &str) -> Option<ViewState> {
        if id == self.document_id {
            return Some(ViewState { cursor: self.cursor, selection: self.current_selection(), record_stride: Some(self.shape.row_stride()) });
        }
        let parent = self.parents.iter().find(|parent| parent.id == id)?;
        Some(ViewState { cursor: parent.cursor, selection: None, record_stride: Some(parent.shape.row_stride()) })
    }

    fn registry(&self) -> Arc<Registry> {
        Arc::clone(&self.registry)
    }

    /// The document shown has the folds; a parent waiting behind it has
    /// none (they are dropped when a document is derived).
    fn folds(&self, id: &str) -> Option<Folds> {
        if id == self.document_id {
            return Some(self.folds.clone());
        }
        self.parents.iter().any(|parent| parent.id == id).then(Folds::default)
    }

    /// The views lay the bytes out again without what is skipped.
    fn set_folds(&mut self, id: &str, folds: Folds) -> Result<(), ApiError> {
        if id != self.document_id {
            return Err(ApiError::invalid_params(format!("{id} waits behind the document shown; go back to it (documents.open with its id) to skip parts of it")));
        }
        self.folds = folds;
        self.clamp_top_row();
        self.sync_hex_to_raster();
        Ok(())
    }

    /// The window keeps one set of bookmarks, for the document shown.
    fn bookmarks(&self, id: &str) -> Option<Vec<Bookmark>> {
        (id == self.document_id).then(|| self.bookmarks.bookmarks.clone())
    }

    /// Saved beside the file, as the bookmarks made by hand always were.
    fn set_bookmarks(&mut self, id: &str, bookmarks: Vec<Bookmark>) -> Result<(), ApiError> {
        if id != self.document_id {
            return Err(ApiError::invalid_params(format!("{id} waits behind the document shown; go back to it (documents.open with its id) to bookmark it")));
        }
        self.bookmarks.bookmarks = bookmarks;
        self.save_sidecar();
        Ok(())
    }

    /// In place of every document shown, unless one has unsaved edits.
    fn open_source_bytes(&mut self, name: &str, bytes: Vec<u8>) -> Result<String, ApiError> {
        refuse_unsaved(self)?;
        ViewerApp::open_bytes(self, bytes, name.to_string());
        Ok(self.document_id())
    }

    /// The window records the document shown, as the file or capture
    /// changes.
    fn set_recording(&mut self, id: &str, enabled: bool) -> Result<(), ApiError> {
        if id != self.document_id {
            return Err(ApiError::invalid_params(format!("{id} waits behind the document shown; the window records the document it shows")));
        }
        self.record_history(enabled);
        Ok(())
    }

    fn recorded_versions(&self, id: &str) -> Option<usize> {
        (id == self.document_id).then_some(())?;
        self.bench.recording.as_ref().map(Recording::len)
    }

    /// What changed from the version before is marked too.
    fn open_recorded_version(&mut self, id: &str, index: usize) -> Result<String, ApiError> {
        if id != self.document_id {
            return Err(ApiError::invalid_params(format!("{id} waits behind the document shown; the window records the document it shows")));
        }
        self.view_recorded_version(index)?;
        Ok(self.document_id())
    }

    fn shape(&self, id: &str) -> Option<ViewShape> {
        let shape = if id == self.document_id { &self.shape } else { &self.parents.iter().find(|parent| parent.id == id)?.shape };
        Some(ViewShape { format: shape.format, width: shape.width, offset: shape.byte_offset as u64, bit_offset: shape.bit_offset, row_padding: shape.row_padding })
    }

    /// The main view is drawn in the new shape, its hex dump following;
    /// a parent's shape changes only once it is gone back to.
    fn set_shape(&mut self, id: &str, shape: ViewShape) -> Result<(), ApiError> {
        if id != self.document_id {
            return Err(ApiError::invalid_params(format!("{id} waits behind the document shown; go back to it (documents.open with its id) to change its view")));
        }
        self.shape.format = shape.format;
        self.shape.byte_offset = (shape.offset as usize).min(self.document.len());
        self.shape.bit_offset = shape.bit_offset;
        self.shape.row_padding = shape.row_padding;
        self.set_width(shape.width);
        Ok(())
    }

    /// A document already open is gone back to; another file is opened in
    /// place of the one shown, unless that has unsaved edits.
    fn open_path(&mut self, path: &Path) -> Result<String, ApiError> {
        if let Some(open) = self.documents().into_iter().find(|info| info.path.as_deref().map(Path::new) == Some(path)) {
            self.switch_to(&open.id)?;
            return Ok(open.id);
        }
        refuse_unsaved(self)?;
        self.load_path(path);
        if self.document.path() != Some(path) {
            return Err(ApiError::not_found(format!("could not open {}: {}", path.display(), self.status)));
        }
        Ok(self.document_id())
    }

    /// Go back to a parent, closing the documents derived from it, as Back
    /// does; refused while one of those has unsaved edits.
    fn switch_to(&mut self, id: &str) -> Result<(), ApiError> {
        if id == self.document_id {
            return Ok(());
        }
        let Some(depth) = self.parents.iter().position(|parent| parent.id == id) else {
            return Err(ApiError::not_found(format!("document '{id}' has closed")));
        };
        let unsaved = self.document.is_modified() || self.parents[depth + 1..].iter().any(|parent| parent.document.is_modified());
        if unsaved {
            return Err(ApiError::new(
                super::ErrorCode::ReadOnly,
                format!("going back to {id} closes the documents derived from it, and one has unsaved edits; save it (documents.save with a path) or undo them first"),
            ));
        }
        while self.document_id != id {
            self.back_to_parent();
        }
        Ok(())
    }

    /// The file is opened in place of every document shown, whatever they
    /// hold, as File › Open always has.
    fn open_path_discarding(&mut self, path: &Path) -> Result<String, ApiError> {
        let before = self.document_id();
        self.load_path(path);
        if self.document_id() == before {
            // The status bar says why, as "Failed to open …".
            let mut reason = self.status.chars();
            let reason: String = reason.next().map(|first| first.to_lowercase().chain(reason).collect()).unwrap_or_default();
            return Err(ApiError::not_found(reason));
        }
        Ok(self.document_id())
    }

    fn switch_to_discarding(&mut self, id: &str) -> Result<(), ApiError> {
        if id != self.document_id && !self.parents.iter().any(|parent| parent.id == id) {
            return Err(ApiError::not_found(format!("document '{id}' has closed")));
        }
        while self.document_id != id {
            self.back_to_parent();
        }
        Ok(())
    }

    fn new_document_discarding(&mut self, _name: &str) -> Result<String, ApiError> {
        ViewerApp::new_document(self);
        Ok(self.document_id())
    }

    /// Messages are delivered once per frame, before the API is called.
    fn bus(&mut self) -> &mut Bus {
        &mut self.bus
    }

    fn publish_edits(&mut self, id: &str, producer: &str) {
        if id != self.document_id {
            self.publish_parent_edits(id, producer);
            return;
        }
        self.publish_edits_as(producer);
        // An edit made through the API may have shortened the document
        // under the cursor.
        let len = self.document.len();
        self.cursor = self.cursor.min(len);
        self.anchor = self.anchor.map(|anchor| anchor.min(len));
        self.clamp_top_row();
    }

    fn select(&mut self, id: &str, cursor: usize, selection: Option<Selection>, caller: &Caller) {
        if id != self.document_id {
            // A parent keeps only its cursor until it is gone back to.
            if let Some(parent) = self.parents.iter_mut().find(|parent| parent.id == id) {
                parent.cursor = cursor.min(parent.document.len());
            }
            return;
        }
        self.set_selection(cursor, selection);
        self.clamp_top_row();
        self.reveal_cursor_in_hex(true);
        self.publish_selection(&caller.producer());
    }

    fn save(&mut self, id: &str, path: Option<&Path>) -> Result<(), ApiError> {
        if id != self.document_id {
            return Err(ApiError::invalid_params(format!("{id} waits behind the document shown; go back to it (documents.open with its id) to save it")));
        }
        let path = path.or(self.document.path()).map(Path::to_path_buf).ok_or_else(|| ApiError::invalid_params("this document has no file yet; give a path to save it to"))?;
        self.save_sidecar();
        self.save_to(&path).map_err(|message| ApiError::new(super::ErrorCode::Unavailable, message))
    }

    fn new_document(&mut self, _name: &str) -> Result<String, ApiError> {
        refuse_unsaved(self)?;
        ViewerApp::new_document(self);
        Ok(self.document_id())
    }

    /// The document shown goes on the parent stack, with its place and
    /// analysis, and Back returns to it; a parent already waiting must be
    /// gone back to first.
    fn open_derived(&mut self, parent: &str, bytes: Vec<u8>, name: &str) -> Result<String, ApiError> {
        if parent != self.document_id {
            return Err(ApiError::invalid_params(format!("{parent} waits behind the document shown; go back to it (documents.open with its id) to open part of it")));
        }
        ViewerApp::open_derived(self, bytes, name.to_string());
        let id = self.document_id();
        self.lineages.insert(id.clone(), Lineage::derived_from(parent));
        Ok(id)
    }

    fn pin_template(&mut self, id: &str, applied: TemplateApplied) {
        if id == self.document_id {
            self.pin_template_parse(applied);
        }
    }

    fn permission(&self, caller: &Caller, effect: Effect) -> Decision {
        permissions::decide(caller, effect, &self.preferences.permissions)
    }

    fn hold_for_confirmation(&mut self, held: HeldCall) -> Option<HeldCall> {
        self.hold_call(held);
        None
    }

    fn registered_methods(&self) -> Vec<Arc<RegisteredMethod>> {
        self.plugin_methods.clone()
    }

    fn packet_sets(&self) -> &PacketSets {
        &self.packet_sets
    }

    fn packet_sets_mut(&mut self) -> &mut PacketSets {
        &mut self.packet_sets
    }

    /// A set made through the API shows in the Packets panel, when it is
    /// about the document shown.
    fn show_packet_set(&mut self, id: &str) {
        crate::panel_packets::show_api_set(self, id);
    }

    fn window(&mut self) -> Option<&mut ViewerApp> {
        Some(self)
    }

    fn journal(&self) -> &Journal {
        &self.journal
    }

    fn journal_mut(&mut self) -> &mut Journal {
        &mut self.journal
    }

    /// The window keeps each document's lineage beside it, by id; a
    /// document derived outside the API (by a panel of its own) has, for
    /// its parent, the one waiting behind it.
    fn lineage(&self, id: &str) -> Option<Lineage> {
        let stack: Vec<&str> = self.parents.iter().map(|parent| parent.id.as_str()).chain(std::iter::once(self.document_id.as_str())).collect();
        let depth = stack.iter().position(|open| *open == id)?;
        let mut lineage = self.lineages.get(id).cloned().unwrap_or_default();
        if lineage.parent.is_none() && depth > 0 {
            lineage.parent = Some(stack[depth - 1].to_string());
        }
        Some(lineage)
    }

    fn note_made_by(&mut self, id: &str, made_by: MadeBy) {
        if self.lineage(id).is_some() {
            self.lineages.entry(id.to_string()).or_default().made_by = Some(made_by);
        }
    }

    fn foci(&self) -> &Foci {
        &self.foci
    }

    fn foci_mut(&mut self) -> &mut Foci {
        &mut self.foci
    }
}

/// Refuse to replace the window's documents while one has unsaved edits.
fn refuse_unsaved(app: &ViewerApp) -> Result<(), ApiError> {
    if app.document.is_modified() || app.parents.iter().any(|parent| parent.document.is_modified()) {
        return Err(ApiError::new(super::ErrorCode::ReadOnly, "an open document has unsaved edits; save it (documents.save) or undo them first"));
    }
    Ok(())
}

impl ViewerApp {
    /// Publish the edits made through the API to the parent `id` while it
    /// waits behind the document shown.
    fn publish_parent_edits(&mut self, id: &str, producer: &str) {
        let Some(parent) = self.parents.iter_mut().find(|parent| parent.id == id) else { return };
        let Some(edited) = edits_since(&parent.document, parent.published_version) else { return };
        parent.published_version = parent.document.version();
        let mut draft = self.draft(producer, Payload::DocumentEdited(edited));
        draft.document = Some(id.to_string());
        draft.version = self.parents.iter().find(|parent| parent.id == id).map_or(0, |parent| parent.published_version);
        self.bus.publish(draft);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ErrorCode;
    use crate::api::test_support::workspace_with;

    #[test]
    fn documents_are_named_by_id_path_or_current() {
        let mut workspace = workspace_with("first.bin", b"one");
        let second = workspace.add_document("second.bin", Document::from_bytes(b"two".to_vec()));
        assert_eq!(second, "doc-2");
        assert_eq!(resolve(&workspace, None).unwrap(), "doc-2", "the newest document is current");
        assert_eq!(resolve(&workspace, Some("current")).unwrap(), "doc-2");
        assert_eq!(resolve(&workspace, Some("doc-1")).unwrap(), "doc-1");
        assert_eq!(resolve(&workspace, Some("doc-9")).unwrap_err().code, ErrorCode::NotFound);
        let (_, document) = document(&mut workspace, Some("doc-1")).unwrap();
        assert_eq!(document.read_range(0, 3), b"one");
    }

    #[test]
    fn a_derived_document_is_listed_with_the_document_it_came_from() {
        let mut workspace = workspace_with("container.bin", b"outer stream");
        let inner = workspace.open_derived("doc-1", b"stream".to_vec(), "inner").unwrap();
        let listed = workspace.documents();
        assert_eq!((listed[0].parent.as_deref(), listed[1].parent.as_deref()), (None, Some("doc-1")), "a file is a root; the derived document names its parent");
        assert_eq!(workspace.lineage(&inner), Some(Lineage::derived_from("doc-1")));
        assert_eq!(workspace.lineage("doc-9"), None, "a document not open has no lineage");
        let as_json = serde_json::to_value(&listed[0]).unwrap();
        assert!(as_json.get("parent").is_none() && as_json.get("made_by").is_none(), "a root's listing is as it was: {as_json}");
    }

    #[test]
    fn an_empty_workspace_has_no_current_document() {
        let workspace = HeadlessWorkspace::new(Arc::new(Registry::new()));
        assert_eq!(resolve(&workspace, None).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn opening_a_file_twice_switches_back_to_it() {
        let path = std::env::temp_dir().join(format!("theviewer-api-workspace-{}.bin", std::process::id()));
        std::fs::write(&path, b"on disk").unwrap();
        let mut workspace = HeadlessWorkspace::new(Arc::new(Registry::new()));
        let first = workspace.open_path(&path).unwrap();
        workspace.add_document("other", Document::from_bytes(Vec::new()));
        assert_eq!(workspace.open_path(&path).unwrap(), first);
        assert_eq!(workspace.current_document().as_deref(), Some(first.as_str()));
        assert_eq!(resolve(&workspace, Some(&path.display().to_string())).unwrap(), first, "an open document is found by its path");
        assert_eq!(workspace.open_path(Path::new("/no/such/file")).unwrap_err().code, ErrorCode::NotFound);
        std::fs::remove_file(path).ok();
    }

    mod focus {
        use serde_json::json;

        use super::super::*;
        use crate::api::test_support::workspace_with;
        use crate::api::{self, Caller};

        fn client(name: &str) -> Caller {
            Caller::Mcp(name.into())
        }

        fn read_text(workspace: &mut HeadlessWorkspace, caller: &Caller, params: serde_json::Value) -> String {
            api::call(workspace, caller, "bytes.read", params).unwrap()["data"].as_str().unwrap().to_string()
        }

        #[test]
        fn a_client_s_omitted_doc_stays_on_its_document_when_a_derive_makes_a_sheet() {
            let mut workspace = workspace_with("container.bin", b"header payload");
            let claude = client("claude-code");
            let derived = api::call(&mut workspace, &claude, "documents.derive", json!({"start": 7})).unwrap();
            assert_eq!(derived["output"]["doc"], "doc-2");
            assert_eq!(workspace.current_document().as_deref(), Some("doc-2"), "headless, the newest document is current");
            assert_eq!(read_text(&mut workspace, &claude, json!({"start": 0, "len": 6, "encoding": "text"})), "header", "the client's focus did not move");
            assert_eq!(read_text(&mut workspace, &claude, json!({"doc": "current", "start": 0, "len": 7, "encoding": "text"})), "payload", "\"current\" is still the current document");
            let entry = workspace.journal().entries().last().unwrap();
            assert_eq!(entry.params["doc"], "doc-1", "the journal entry names the document");
        }

        #[test]
        fn opening_or_activating_a_document_moves_the_client_s_focus_and_naming_one_does_not() {
            let mut workspace = workspace_with("container.bin", b"header payload");
            let claude = client("claude-code");
            api::call(&mut workspace, &claude, "documents.derive", json!({"start": 7})).unwrap();
            assert_eq!(read_text(&mut workspace, &claude, json!({"doc": "doc-2", "start": 0, "encoding": "text"})), "payload");
            assert_eq!(read_text(&mut workspace, &claude, json!({"start": 0, "len": 6, "encoding": "text"})), "header", "a doc named once is not the default after");
            api::call(&mut workspace, &claude, "documents.activate", json!({"doc": "doc-2"})).unwrap();
            assert_eq!(focus_of(&workspace, &claude).as_deref(), Some("doc-2"), "a document activated becomes the focus");
            api::call(&mut workspace, &claude, "documents.activate", json!({"doc": "doc-1"})).unwrap();
            assert_eq!(focus_of(&workspace, &claude).as_deref(), Some("doc-1"));
            assert_eq!(workspace.current_document().as_deref(), Some("doc-2"), "a client's activation leaves the current document");
            let listed = api::call(&mut workspace, &claude, "documents.list", json!({})).unwrap();
            let focused: Vec<&str> = listed["documents"].as_array().unwrap().iter().filter(|info| info["focus"] == true).map(|info| info["id"].as_str().unwrap()).collect();
            assert_eq!(focused, ["doc-1"], "documents.list marks the caller's focus");
            let path = std::env::temp_dir().join(format!("theviewer-focus-open-{}.bin", std::process::id()));
            std::fs::write(&path, b"opened").unwrap();
            let opened = api::call(&mut workspace, &claude, "documents.open", json!({"path": path.display().to_string()})).unwrap();
            assert_eq!(focus_of(&workspace, &claude), opened["id"].as_str().map(str::to_string), "a document opened becomes the focus");
            std::fs::remove_file(path).ok();
        }

        #[test]
        fn each_client_has_a_focus_of_its_own_and_the_person_s_is_the_current_document() {
            let mut workspace = workspace_with("first.bin", b"first");
            workspace.add_document("second.bin", crate::document::Document::from_bytes(b"second".to_vec()));
            let (claude, other) = (client("claude-code"), client("other"));
            api::call(&mut workspace, &claude, "documents.activate", json!({"doc": "doc-1"})).unwrap();
            assert_eq!(read_text(&mut workspace, &other, json!({"start": 0, "encoding": "text"})), "second", "a client starts on the current document");
            assert_eq!(read_text(&mut workspace, &claude, json!({"start": 0, "encoding": "text"})), "first");
            assert_eq!(focus_of(&workspace, &Caller::Panel).as_deref(), Some("doc-2"), "the person's focus is the current document");
            api::call(&mut workspace, &Caller::Plugin("sync.lua".into()), "documents.activate", json!({"doc": "doc-1"})).unwrap();
            assert_eq!(workspace.current_document().as_deref(), Some("doc-1"), "a plugin acts for the person, on the current document");
            assert_eq!(focus_of(&workspace, &Caller::Ask).as_deref(), Some("doc-1"), "as Ask does");
            workspace.switch_to("doc-2").unwrap();
            set_focus(&mut workspace, &Caller::Panel, "doc-1");
            assert_eq!(workspace.current_document().as_deref(), Some("doc-2"), "and is not moved by a focus of its own");
        }

        #[test]
        fn with_legacy_current_every_client_s_omitted_doc_is_the_current_document() {
            let mut workspace = workspace_with("container.bin", b"header payload");
            workspace.foci_mut().legacy_current = true;
            let claude = client("claude-code");
            api::call(&mut workspace, &claude, "documents.derive", json!({"start": 7})).unwrap();
            assert_eq!(read_text(&mut workspace, &claude, json!({"start": 0, "encoding": "text"})), "payload", "as before callers had a focus");
        }

        #[test]
        fn a_new_sheet_asked_to_be_focused_becomes_the_focus() {
            let mut workspace = workspace_with("container.bin", b"header payload");
            let claude = client("claude-code");
            let derive = api::find(&workspace, "documents.derive").unwrap();
            set_focus(&mut workspace, &claude, "doc-1");
            let sheet = workspace.open_derived("doc-1", b"payload".to_vec(), "payload").unwrap();
            let result = json!({"output": {"doc": sheet, "len": 7}});
            follow_focus(&mut workspace, &claude, &derive, asks_to_focus_the_sheet(&json!({"start": 7, "output": "new"})), &result);
            assert_ne!(focus_of(&workspace, &claude).as_deref(), Some(sheet.as_str()), "a sheet made does not move the focus");
            follow_focus(&mut workspace, &claude, &derive, asks_to_focus_the_sheet(&json!({"start": 7, "output": {"new": {"focus": true}}})), &result);
            assert_eq!(focus_of(&workspace, &claude).as_deref(), Some(sheet.as_str()));
        }

        #[test]
        fn a_closed_focus_falls_back_to_the_current_document_and_a_sheet_s_root_is_its_file() {
            let mut workspace = workspace_with("container.bin", b"header payload");
            let child = workspace.open_derived("doc-1", b"payload".to_vec(), "payload").unwrap();
            let grandchild = workspace.open_derived(&child, b"load".to_vec(), "load").unwrap();
            assert_eq!(root_of(&workspace, &grandchild), "doc-1");
            let claude = client("claude-code");
            set_focus(&mut workspace, &claude, "doc-9");
            assert_eq!(focus_of(&workspace, &claude), workspace.current_document(), "a focus no longer open is the current document");
        }
    }

    mod window {
        use serde_json::json;

        use crate::api::{Caller, ErrorCode, call};
        use crate::app::{Launch, ViewerApp};
        use crate::bus::Topic;
        use crate::bus::topics::RecordWidthEstimated;

        fn ids(app: &mut ViewerApp) -> Vec<(String, bool)> {
            let listed = call(app, &Caller::Panel, "documents.list", json!({})).unwrap();
            listed["documents"].as_array().unwrap().iter().map(|info| (info["id"].as_str().unwrap().to_string(), info["current"].as_bool().unwrap())).collect()
        }

        #[test]
        fn a_derived_document_and_the_one_it_came_from_are_listed_with_their_own_ids() {
            let mut app = ViewerApp::new(Launch::default());
            app.open_bytes(b"outer container".to_vec(), "outer.bin".to_string());
            let outer = app.document_id();
            app.publish("tool:period-scan", crate::bus::Payload::RecordWidthEstimated(RecordWidthEstimated { width: 4, score: 1.0, alternatives: Vec::new() }));
            app.run_bus();
            app.open_derived(b"inner stream".to_vec(), "outer.bin > zlib".to_string());
            app.run_bus();
            let inner = app.document_id();
            assert_ne!(inner, outer);
            assert_eq!(ids(&mut app), [(outer.clone(), false), (inner.clone(), true)]);
            assert!(app.bus.latest::<RecordWidthEstimated>(&outer).is_some(), "what is known about the parent is kept while it waits");

            // The parent can be read and edited by id while it waits.
            let read = call(&mut app, &Caller::Panel, "bytes.read", json!({"doc": outer, "start": 0, "len": 5, "encoding": "text"})).unwrap();
            assert_eq!(read["data"], "outer");
            call(&mut app, &Caller::Panel, "bytes.write", json!({"doc": outer, "start": 0, "data": "4f"})).unwrap();
            app.run_bus();
            let edited = app.bus.recent().rev().find(|message| message.topic() == Topic::DocumentEdited).unwrap();
            assert_eq!(edited.draft.document.as_deref(), Some(outer.as_str()));

            // Going back to it by id closes the derived document.
            let shown = call(&mut app, &Caller::Panel, "documents.open", json!({"doc": outer})).unwrap();
            assert_eq!(shown["id"], outer.as_str());
            assert_eq!(app.document.read_range(0, 5), b"Outer");
            app.run_bus();
            assert_eq!(ids(&mut app), [(outer.clone(), true)]);
            assert_eq!(call(&mut app, &Caller::Panel, "documents.info", json!({"doc": inner})).unwrap_err().code, ErrorCode::NotFound);
        }

        #[test]
        fn a_derived_document_with_unsaved_edits_is_not_closed_by_going_back() {
            let mut app = ViewerApp::new(Launch::default());
            app.open_bytes(b"outer".to_vec(), "outer.bin".to_string());
            let outer = app.document_id();
            app.open_derived(b"inner".to_vec(), "inner".to_string());
            call(&mut app, &Caller::Panel, "bytes.write", json!({"start": 0, "data": "00"})).unwrap();
            let refused = call(&mut app, &Caller::Panel, "documents.open", json!({"doc": outer})).unwrap_err();
            assert_eq!(refused.code, ErrorCode::ReadOnly);
            assert_ne!(app.document_id(), outer);
        }

        #[test]
        fn the_window_opens_another_file_from_the_api_and_switches_back_to_an_open_one() {
            let path = std::env::temp_dir().join(format!("theviewer-window-open-{}.bin", std::process::id()));
            std::fs::write(&path, b"on disk").unwrap();
            let mut app = ViewerApp::new(Launch::default());
            app.open_bytes(b"first".to_vec(), "first.bin".to_string());
            let first = app.document_id();
            let opened = call(&mut app, &Caller::Panel, "documents.open", json!({"path": path.display().to_string()})).unwrap();
            assert_ne!(opened["id"], first.as_str(), "a new document has a new id");
            assert_eq!(app.document.read_range(0, 7), b"on disk");
            let again = call(&mut app, &Caller::Panel, "documents.open", json!({"path": path.display().to_string()})).unwrap();
            assert_eq!(again["id"], opened["id"], "a file already open is made current again");
            let saved = call(&mut app, &Caller::Panel, "documents.save", json!({})).unwrap();
            assert_eq!(saved["id"], opened["id"], "saving keeps the id");
            std::fs::remove_file(path).ok();
        }
    }
}
