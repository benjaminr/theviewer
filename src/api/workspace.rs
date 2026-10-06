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
use super::packet_sets::PacketSets;
use super::view::ViewShape;
use super::{ApiError, Effect, RegisteredMethod};
use crate::app::ViewerApp;
use crate::bus::topics::{CursorMoved, DocumentEdited, DocumentOpened, FindingsPublished, SelectionChanged, TemplateApplied};
use crate::bus::{Bus, Draft, MessageId, Payload};
use crate::document::Document;
use crate::plugin::Registry;
use crate::selection::Selection;

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
    /// The window, when this workspace is the window: for a method whose
    /// effect only the window has (a panel to show, a chart to fill), so it
    /// need not add a hook of its own here. Headless workspaces have none,
    /// and such a method does what it can without it.
    fn window(&mut self) -> Option<&mut ViewerApp> {
        None
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
    shape: ViewShape,
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
    packet_sets: PacketSets,
}

impl HeadlessWorkspace {
    pub fn new(registry: Arc<Registry>) -> Self {
        HeadlessWorkspace { documents: Vec::new(), current: None, registry, opened: 0, bus: Bus::new(), methods: Vec::new(), cause: None, packet_sets: PacketSets::default() }
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
        self.documents.push(OpenDocument { id: id.clone(), name, document, view: ViewState::default(), shape: ViewShape::default(), published_version });
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

    fn shape(&self, id: &str) -> Option<ViewShape> {
        self.documents.iter().find(|open| open.id == id).map(|open| open.shape)
    }

    /// Without pixel formats, a row's pixels are its bytes, so records are
    /// a row and its padding apart.
    fn set_shape(&mut self, id: &str, shape: ViewShape) -> Result<(), ApiError> {
        let open = self.documents.iter_mut().find(|open| open.id == id).ok_or_else(|| ApiError::not_found(format!("document '{id}' has closed")))?;
        open.shape = shape;
        open.view.record_stride = Some(shape.width + shape.row_padding);
        Ok(())
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
        });
        let shown = DocumentInfo {
            id: self.document_id(),
            name: self.display_name(),
            path: self.document.path().map(|path| path.display().to_string()),
            len: self.document.len() as u64,
            version: self.document.version(),
            modified: self.document.is_modified(),
            current: true,
        };
        parents.chain(std::iter::once(shown)).collect()
    }

    fn current_document(&self) -> Option<String> {
        Some(self.document_id())
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

    fn shape(&self, id: &str) -> Option<ViewShape> {
        let shape = if id == self.document_id { &self.shape } else { &self.parents.iter().find(|parent| parent.id == id)?.shape };
        Some(ViewShape { width: shape.width, offset: shape.byte_offset as u64, bit_offset: shape.bit_offset, row_padding: shape.row_padding })
    }

    /// The main view is drawn in the new shape, its hex dump following;
    /// a parent's shape changes only once it is gone back to.
    fn set_shape(&mut self, id: &str, shape: ViewShape) -> Result<(), ApiError> {
        if id != self.document_id {
            return Err(ApiError::invalid_params(format!("{id} waits behind the document shown; go back to it (documents.open with its id) to change its view")));
        }
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
