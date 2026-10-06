//! What API methods run against: the open documents, where the cursor and
//! selection are in each, and the registry of detectors, parsers and codecs.
//!
//! The window is one workspace ([`ViewerApp`] implements [`Workspace`]); a
//! [`HeadlessWorkspace`] is another, holding files opened from paths, for the
//! command line and, later, the MCP server. Methods see only the trait, so
//! the same method works in both. Each workspace has its own bus of facts
//! and events.

use std::path::Path;
use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::permissions::{self, Caller, Decision, HeldCall};
use super::{ApiError, Effect, RegisteredMethod};
use crate::app::ViewerApp;
use crate::bus::topics::{CursorMoved, DocumentEdited, DocumentOpened, FindingsPublished, SelectionChanged};
use crate::bus::{Bus, Draft, MessageId, Payload};
use crate::document::Document;
use crate::plugin::{Finding, Registry};
use crate::selection::Selection;

/// Who publishes edits made by hand, outside any API call.
pub const DOCUMENT_PRODUCER: &str = "document";
/// Who publishes the template pinned by `templates.apply`.
pub const TEMPLATES_PRODUCER: &str = "tool:templates";

/// The name that stands for the current document.
pub const CURRENT: &str = "current";
/// The id the window gives its document, which is the only one it shows.
pub const WINDOW_DOCUMENT_ID: &str = "doc-1";

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
    /// The document with this id.
    fn document_mut(&mut self, id: &str) -> Option<&mut Document>;
    /// The cursor, selection and layout of the document with this id.
    fn view(&self, id: &str) -> Option<ViewState>;
    /// Every detector, parser and codec, built in or from plugins.
    fn registry(&self) -> Arc<Registry>;
    /// Open the file at `path` and make it current, returning its id.
    fn open_path(&mut self, path: &Path) -> Result<String, ApiError>;
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
    /// Pin a template's parse over document `id`, as the template tool
    /// does: its structure and records are published and shown.
    fn pin_template(&mut self, id: &str, parse: Finding);
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

/// One document of a headless workspace, with its own cursor and selection.
struct OpenDocument {
    id: String,
    name: String,
    document: Document,
    view: ViewState,
    /// The version `document.edited` has been published up to.
    published_version: u64,
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
}

impl HeadlessWorkspace {
    pub fn new(registry: Arc<Registry>) -> Self {
        HeadlessWorkspace { documents: Vec::new(), current: None, registry, opened: 0, bus: Bus::new(), methods: Vec::new(), cause: None }
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
        self.documents.push(OpenDocument { id: id.clone(), name, document, view: ViewState::default(), published_version });
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
            })
            .collect()
    }

    fn current_document(&self) -> Option<String> {
        self.current.map(|index| self.documents[index].id.clone())
    }

    fn document_mut(&mut self, id: &str) -> Option<&mut Document> {
        self.documents.iter_mut().find(|open| open.id == id).map(|open| &mut open.document)
    }

    fn view(&self, id: &str) -> Option<ViewState> {
        self.documents.iter().find(|open| open.id == id).map(|open| open.view.clone())
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

    fn pin_template(&mut self, id: &str, parse: Finding) {
        let Some(version) = self.open_document(id).map(|open| open.document.version()) else { return };
        let structure = crate::app::structure_of(&parse);
        let (start, len) = (parse.start, parse.len);
        self.bus.publish(Draft::new(TEMPLATES_PRODUCER, Payload::StructureIdentified(structure)).about(id, version).span(start, len));
        self.bus.publish(Draft::new(TEMPLATES_PRODUCER, Payload::FindingsPublished(FindingsPublished { findings: vec![parse] })).about(id, version).span(start, len));
    }

    fn permission(&self, _caller: &Caller, _effect: Effect) -> Decision {
        Decision::Allowed
    }

    fn registered_methods(&self) -> Vec<Arc<RegisteredMethod>> {
        self.methods.clone()
    }
}

/// The window shows one document at a time, which the API calls `doc-1`.
impl Workspace for ViewerApp {
    fn documents(&self) -> Vec<DocumentInfo> {
        vec![DocumentInfo {
            id: WINDOW_DOCUMENT_ID.to_string(),
            name: self.display_name(),
            path: self.document.path().map(|path| path.display().to_string()),
            len: self.document.len() as u64,
            version: self.document.version(),
            modified: self.document.is_modified(),
            current: true,
        }]
    }

    fn current_document(&self) -> Option<String> {
        Some(WINDOW_DOCUMENT_ID.to_string())
    }

    fn document_mut(&mut self, id: &str) -> Option<&mut Document> {
        (id == WINDOW_DOCUMENT_ID).then_some(&mut self.document)
    }

    fn view(&self, id: &str) -> Option<ViewState> {
        (id == WINDOW_DOCUMENT_ID).then(|| ViewState { cursor: self.cursor, selection: self.current_selection(), record_stride: Some(self.shape.row_stride()) })
    }

    fn registry(&self) -> Arc<Registry> {
        Arc::clone(&self.registry)
    }

    fn open_path(&mut self, path: &Path) -> Result<String, ApiError> {
        if self.document.path() == Some(path) {
            return Ok(WINDOW_DOCUMENT_ID.to_string());
        }
        Err(ApiError::not_found(format!("{} is not the open document; switching documents from the API is not supported yet", path.display())))
    }

    /// Messages are delivered once per frame, before the API is called.
    fn bus(&mut self) -> &mut Bus {
        &mut self.bus
    }

    fn publish_edits(&mut self, id: &str, producer: &str) {
        if id != WINDOW_DOCUMENT_ID {
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
        if id != WINDOW_DOCUMENT_ID {
            return;
        }
        self.set_selection(cursor, selection);
        self.clamp_top_row();
        self.reveal_cursor_in_hex(true);
        self.publish_selection(&caller.producer());
    }

    fn save(&mut self, id: &str, path: Option<&Path>) -> Result<(), ApiError> {
        if id != WINDOW_DOCUMENT_ID {
            return Err(ApiError::not_found(format!("document '{id}' has closed")));
        }
        let path = path.or(self.document.path()).map(Path::to_path_buf).ok_or_else(|| ApiError::invalid_params("this document has no file yet; give a path to save it to"))?;
        self.save_sidecar();
        self.save_to(&path).map_err(|message| ApiError::new(super::ErrorCode::Unavailable, message))
    }

    fn new_document(&mut self, _name: &str) -> Result<String, ApiError> {
        if self.document.is_modified() {
            return Err(ApiError::new(super::ErrorCode::ReadOnly, "the open document has unsaved edits; save it (documents.save) or undo them first"));
        }
        ViewerApp::new_document(self);
        Ok(WINDOW_DOCUMENT_ID.to_string())
    }

    fn pin_template(&mut self, id: &str, parse: Finding) {
        if id == WINDOW_DOCUMENT_ID {
            self.pin_template_parse(parse);
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
}
