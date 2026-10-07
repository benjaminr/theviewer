//! How a step that changed no bytes is undone, as its method declares it.
//!
//! Each method of the table says, beside its name and effect, what undoing
//! one of its steps means ([`Undo`]): nothing to undo (a job, a read, a file
//! written), no inverse at all, something it made that a later call removes
//! ([`Resource`]), or one thing it changed that a later call can change
//! back ([`Reverse`]). A byte edit is undone through its document's own
//! undo whatever its method, so it needs no declaration.
//!
//! A [`Reverse`] knows four things about its method's steps: what one
//! changes ([`Target`], so a later step changing the same thing stands in
//! the way), what that was just before a step ran (kept on its entry as
//! `before`), what it was just after (read from the entry, for the step
//! after it), and the calls that put back what a step replaced.
//! [`super::timeline`] puts these together.

use serde_json::{Value, json};

use super::JournalEntry;
use super::timeline::{Inverse, InverseCall};
use crate::api::workspace::TEMPLATES_PRODUCER;
use crate::api::{self, Effect, Workspace};
use crate::bus::topics::TemplateApplied;

/// Why a job leaves nothing to undo.
const A_JOB_ADDS_RESULTS: &str = "a job only adds results, which stay";
/// Why a read leaves nothing to undo.
const A_READ_CHANGES_NOTHING: &str = "a read changes nothing";
/// Why an edit that changed no bytes leaves nothing to undo.
const NO_BYTES_CHANGED: &str = "it changed no bytes";
/// Why a file written leaves nothing to undo.
pub const WROTE_A_FILE: &str = "it wrote a file, which stays as written";
/// Why a plugin's analysis leaves nothing to undo: it says nothing of how.
const A_PLUGIN_KEEPS_NO_INVERSE: &str = "a plugin's method keeps nothing to undo it by; undoing it only takes it out of the analysis";

/// How a step of a method is undone, when it changed no bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Undo {
    /// It leaves nothing in the document or view to undo, for the reason
    /// given; undoing it only takes it out of the analysis.
    Nothing(&'static str),
    /// It changed something for good: it has no inverse.
    Irreversible,
    /// It changed one thing that a later call can change back.
    Reverses(Reverse),
    /// It made something that a later call removes, while no later step
    /// uses it.
    Creates(Resource),
}

impl Undo {
    /// What a method of `effect` declares unless it says otherwise: a read,
    /// a job and an edit's steps leave nothing to undo once their bytes are
    /// undone; a view or analysis change has no inverse.
    pub const fn for_effect(effect: Effect) -> Undo {
        match effect {
            Effect::Read => Undo::Nothing(A_READ_CHANGES_NOTHING),
            Effect::Job => Undo::Nothing(A_JOB_ADDS_RESULTS),
            Effect::Edit => Undo::Nothing(NO_BYTES_CHANGED),
            Effect::View | Effect::Analysis => Undo::Irreversible,
        }
    }

    /// What a method a plugin registered declares: nothing kept to undo it
    /// by, as its effect says.
    pub const fn registered(effect: Effect) -> Undo {
        match effect {
            Effect::View | Effect::Analysis => Undo::Nothing(A_PLUGIN_KEEPS_NO_INVERSE),
            effect => Undo::for_effect(effect),
        }
    }
}

/// Something a method makes, which a later call names and another removes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resource {
    /// The field of the result that names what was made, such as `set`.
    pub result_field: &'static str,
    /// The parameter later calls name it by.
    pub param: &'static str,
    /// The method that removes it, called with `param`.
    pub remover: &'static str,
}

impl Resource {
    /// What `entry` made, from its result.
    pub(super) fn made_by<'a>(&self, entry: &'a JournalEntry) -> Option<&'a str> {
        entry.result.as_ref()?.get(self.result_field)?.as_str()
    }

    /// Whether `later` uses `made`.
    pub(super) fn is_used_by(&self, made: &str, later: &JournalEntry) -> bool {
        later.params.get(self.param).and_then(Value::as_str) == Some(made)
    }

    /// The call that removes `made`.
    pub(super) fn removal(&self, made: &str) -> Inverse {
        let mut params = json!({});
        params[self.param] = json!(made);
        Inverse::calls(vec![InverseCall::new(self.remover, params)])
    }
}

/// One thing a method's step changes, which its inverse changes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reverse {
    /// `view.set_shape`: the shape the document's bytes are drawn in.
    Shape,
    /// `view.fold`, `view.unfold`: the ranges skipped in the views.
    Folds,
    /// `bookmarks.add`: the bookmark at an offset.
    AddBookmark,
    /// `bookmarks.remove`: the bookmark at an offset.
    RemoveBookmark,
    /// `selection.set`: the selection and cursor.
    Select,
    /// `cursor.set`: the selection and cursor.
    MoveCursor,
    /// A method that opens a document and makes it current; one that
    /// `derives` opens a document derived from the current one.
    OpenDocument { derives: bool },
    /// `templates.clear`: the template pinned over the document.
    ClearTemplate,
    /// `templates.apply`, `templates.infer`: the template pinned over the
    /// document, when the call pins one.
    PinTemplate,
    /// `packets.decode_as`: how a packet set decodes frames of unknown
    /// format.
    Decoding,
    /// `findings.publish`: the findings the caller published under a key.
    PublishFindings,
    /// `findings.retract`: the findings the caller published under a key.
    RetractFindings,
}

/// What a step changed: two steps with the same target change the same
/// thing, so the later stands in the way of undoing the earlier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Target {
    Shape(Option<String>),
    Folds(Option<String>),
    Bookmark(Option<String>, u64),
    Selection(Option<String>),
    /// Which document is current: the session's, not a document's.
    CurrentDocument,
    Template(Option<String>),
    /// A packet set's decoding: the set's, not a document's.
    Decoding(String),
    /// Findings are their publisher's, under a key, about a document.
    Findings { doc: Option<String>, key: String, caller: String },
}

impl Reverse {
    /// What a call with `params` about document `doc` by `caller` changes;
    /// `None` when it changes nothing to undo (a template applied without
    /// pinning it).
    pub(super) fn target(self, params: &Value, doc: Option<&str>, caller: &str) -> Option<Target> {
        let doc = doc.map(str::to_string);
        let target = match self {
            Reverse::Shape => Target::Shape(doc),
            Reverse::Folds => Target::Folds(doc),
            Reverse::AddBookmark | Reverse::RemoveBookmark => Target::Bookmark(doc, params.get("start").and_then(Value::as_u64)?),
            Reverse::Select | Reverse::MoveCursor => Target::Selection(doc),
            Reverse::OpenDocument { .. } => Target::CurrentDocument,
            Reverse::ClearTemplate => Target::Template(doc),
            Reverse::PinTemplate if params.get("pin").and_then(Value::as_bool) == Some(true) => Target::Template(doc),
            Reverse::PinTemplate => return None,
            Reverse::Decoding => Target::Decoding(params.get("set").and_then(Value::as_str)?.to_string()),
            Reverse::PublishFindings | Reverse::RetractFindings => {
                let key = params.get("key").and_then(Value::as_str).unwrap_or_default().to_string();
                Target::Findings { doc, key, caller: caller.to_string() }
            }
        };
        Some(target)
    }

    /// What a step whose target is `None` leaves to undo.
    pub(super) fn untargeted(self, method: &str) -> Inverse {
        match self {
            Reverse::PinTemplate => Inverse::nothing("it only returned fields, pinning nothing"),
            _ => Inverse::unavailable(format!("{method} has no inverse")),
        }
    }

    /// What a call with `params` about document `doc` is about to replace,
    /// for its inverse: taken before it runs, so the first change of a
    /// shape, a selection or a bookmark can be undone too. `None` when its
    /// inverse needs nothing kept, or what it replaced cannot be kept.
    ///
    /// The value is `{"shape"}`, `{"folds"}`, `{"bookmarks"}`,
    /// `{"selection", "cursor"}`, `{"current"}`, `{"template"}` or
    /// `{"decoding"}`, as [`Reverse::inverse`] reads it.
    pub(super) fn snapshot(self, workspace: &mut dyn Workspace, doc: Option<&str>, params: &Value) -> Option<Value> {
        match self {
            Reverse::OpenDocument { .. } => return Some(json!({"current": workspace.current_document()?})),
            Reverse::Decoding => return decoding_of(workspace, params.get("set").and_then(Value::as_str)?),
            Reverse::PublishFindings | Reverse::RetractFindings => return None,
            Reverse::PinTemplate if self.target(params, doc, "").is_none() => return None,
            _ => {}
        }
        let id = doc?;
        match self {
            Reverse::Shape => Some(json!({"shape": workspace.shape(id)?})),
            Reverse::Folds => {
                let folds: Vec<(u64, u64)> = workspace.folds(id)?.ranges().iter().map(|&(start, len)| (start as u64, len as u64)).collect();
                Some(json!({"folds": folds}))
            }
            Reverse::AddBookmark | Reverse::RemoveBookmark => {
                let bookmarks: Vec<Value> = workspace.bookmarks(id)?.iter().map(|bookmark| json!({"start": bookmark.offset, "len": bookmark.len, "name": bookmark.name})).collect();
                Some(json!({"bookmarks": bookmarks}))
            }
            Reverse::Select | Reverse::MoveCursor => {
                let view = workspace.view(id)?;
                Some(json!({"selection": view.selection, "cursor": view.cursor}))
            }
            Reverse::ClearTemplate | Reverse::PinTemplate => {
                let pinned = workspace.bus().latest_from::<TemplateApplied>(id, TEMPLATES_PRODUCER).map(|(_, applied)| (applied.source.clone(), applied.structure.start));
                match pinned {
                    Some((source, at)) if !source.is_empty() => Some(json!({"template": {"method": "templates.apply", "params": {"doc": id, "source": source, "at": at, "pin": true}}})),
                    Some(_) => None,
                    None => Some(json!({"template": null})),
                }
            }
            Reverse::OpenDocument { .. } | Reverse::Decoding | Reverse::PublishFindings | Reverse::RetractFindings => None,
        }
    }

    /// What it was after `entry` made its change, in the form
    /// [`Reverse::snapshot`] gives, read from the entry's result.
    pub(super) fn after(self, entry: &JournalEntry) -> Option<Value> {
        let result = entry.result.as_ref()?;
        match self {
            Reverse::Shape => Some(json!({"shape": result.get("shape")?})),
            Reverse::Folds => Some(json!({"folds": result.get("folds")?})),
            Reverse::AddBookmark | Reverse::RemoveBookmark => Some(json!({"bookmarks": result.get("bookmarks")?})),
            Reverse::MoveCursor => Some(json!({"selection": null, "cursor": result.get("offset")?})),
            Reverse::Select => Some(json!({"selection": result.get("selection")?, "cursor": entry.params.get("cursor").cloned().unwrap_or(Value::Null)})),
            Reverse::OpenDocument { .. } => {
                let id = result.get("id").or_else(|| result.get("document").and_then(|document| document.get("id")))?;
                Some(json!({"current": id}))
            }
            Reverse::ClearTemplate => Some(json!({"template": null})),
            Reverse::PinTemplate => Some(json!({"template": {"method": entry.method, "params": entry.params}})),
            Reverse::Decoding => Some(json!({"decoding": entry.params})),
            Reverse::RetractFindings => Some(json!({"findings": null})),
            Reverse::PublishFindings => Some(json!({"findings": entry.params.get("findings")?})),
        }
    }

    /// What was there before the first step that changed it, where that is
    /// known without having kept it: nothing skipped, and for a derived
    /// document the one it was derived from.
    pub(super) fn first_before(self, entry: &JournalEntry) -> Option<Value> {
        match self {
            Reverse::Folds => Some(json!({"folds": []})),
            Reverse::OpenDocument { derives: true } => Some(json!({"current": entry.doc.as_ref()?})),
            _ => None,
        }
    }

    /// The calls that put back what `entry` replaced, `before`.
    pub(super) fn inverse(self, entry: &JournalEntry, before: Option<Value>) -> Inverse {
        let doc = entry.doc.clone().map_or(Value::Null, Value::String);
        let unknown = || Inverse::unavailable("what it replaced is not known");
        let one = |method: &str, params: Value| Inverse::calls(vec![InverseCall::new(method, params)]);
        match self {
            Reverse::Shape => {
                let Some(shape) = before.as_ref().and_then(|before| before.get("shape")) else { return unknown() };
                let mut params = shape.clone();
                params["doc"] = doc;
                one("view.set_shape", params)
            }
            Reverse::Folds => {
                let Some(folds) = before.as_ref().and_then(|before| before.get("folds")).and_then(Value::as_array) else { return unknown() };
                let mut calls = vec![InverseCall::new("view.unfold", json!({"doc": doc, "all": true}))];
                if !folds.is_empty() {
                    calls.push(InverseCall::new("view.fold", json!({"doc": doc, "ranges": folds})));
                }
                Inverse::calls(calls)
            }
            Reverse::AddBookmark | Reverse::RemoveBookmark => {
                let Some(start) = entry.params.get("start").and_then(Value::as_u64) else { return unknown() };
                let replaced = before.as_ref().and_then(|before| before.get("bookmarks")).and_then(Value::as_array).map(|bookmarks| bookmarks.iter().find(|bookmark| bookmark.get("start").and_then(Value::as_u64) == Some(start)).cloned());
                match (self, replaced) {
                    (_, Some(Some(bookmark))) => one("bookmarks.add", json!({"doc": doc, "start": start, "len": bookmark.get("len").cloned().unwrap_or(json!(0)), "name": bookmark.get("name").cloned().unwrap_or(json!(""))})),
                    // Not known: an added bookmark is taken to have replaced none.
                    (Reverse::AddBookmark, _) => one("bookmarks.remove", json!({"doc": doc, "start": start})),
                    _ => unknown(),
                }
            }
            Reverse::Select | Reverse::MoveCursor => {
                let Some(before) = before else { return unknown() };
                let cursor = before.get("cursor").filter(|cursor| !cursor.is_null());
                match (before.get("selection").filter(|selection| !selection.is_null()), cursor) {
                    (Some(selection), cursor) => {
                        let mut params = json!({"doc": doc, "selection": selection});
                        if let Some(cursor) = cursor {
                            params["cursor"] = cursor.clone();
                        }
                        one("selection.set", params)
                    }
                    (None, Some(cursor)) => one("cursor.set", json!({"doc": doc, "offset": cursor})),
                    (None, None) => one("selection.set", json!({"doc": doc, "selection": null})),
                }
            }
            Reverse::OpenDocument { .. } => match before.as_ref().and_then(|before| before.get("current")).and_then(Value::as_str) {
                Some(current) => one("documents.open", json!({"doc": current})),
                None => unknown(),
            },
            Reverse::Decoding => match (before.as_ref().and_then(|before| before.get("decoding")), entry.params.get("set")) {
                (Some(decoding), Some(set)) => {
                    let mut params = decoding.clone();
                    params["set"] = set.clone();
                    one("packets.decode_as", params)
                }
                _ => unknown(),
            },
            Reverse::PublishFindings | Reverse::RetractFindings => {
                let key = entry.params.get("key").and_then(Value::as_str).unwrap_or_default();
                let as_publisher = |method: &str, params: Value| Inverse::calls(vec![InverseCall::as_caller(method, params, Some(entry.caller.clone()))]);
                match before.as_ref().map(|before| before.get("findings").cloned().unwrap_or(Value::Null)) {
                    Some(Value::Null) => as_publisher("findings.retract", json!({"doc": doc, "key": key})),
                    Some(findings) => as_publisher("findings.publish", json!({"doc": doc, "key": key, "findings": findings})),
                    // Never published under the key before: nothing to put back.
                    None if self == Reverse::PublishFindings => as_publisher("findings.retract", json!({"doc": doc, "key": key})),
                    None => unknown(),
                }
            }
            Reverse::ClearTemplate | Reverse::PinTemplate => match before.as_ref().map(|before| before.get("template").cloned().unwrap_or(Value::Null)) {
                Some(Value::Null) => one("templates.clear", json!({"doc": doc})),
                Some(pinned) => match (pinned.get("method").and_then(Value::as_str), pinned.get("params")) {
                    (Some(method), Some(params)) => one(method, params.clone()),
                    _ => unknown(),
                },
                None => unknown(),
            },
        }
    }
}

/// How packet set `set` decodes frames now, as `packets.decode_as`'s
/// parameters; `None` when a template given as source text is not kept.
fn decoding_of(workspace: &dyn Workspace, set: &str) -> Option<Value> {
    let info = &workspace.packet_sets().get(set)?.info;
    if info.template && info.template_name.is_none() {
        return None;
    }
    let mut params = json!({"set": set, "protocol": info.decode_as, "detect": info.detect, "link": info.link});
    if let Some(name) = &info.template_name {
        let field = if name == "protocol" { "template" } else { "template_name" };
        params[field] = json!(name);
    }
    Some(json!({"decoding": params}))
}

/// How a step of the method called `method` (whose effect was `effect`)
/// is undone, as the method table declares it; a method not in the table
/// is a plugin's.
pub(super) fn undo_of(method: &str, effect: Effect) -> Undo {
    api::method(method).map_or(Undo::registered(effect), |method| method.undo)
}

/// What `entry` changed, when its method reverses a change.
pub(super) fn target_of(entry: &JournalEntry) -> Option<Target> {
    match undo_of(&entry.method, entry.effect) {
        Undo::Reverses(reverse) => reverse.target(&entry.params, entry.doc.as_deref(), &entry.caller),
        _ => None,
    }
}

/// What a call to `method` with `params` about document `doc` is about to
/// replace, for the journal to keep as its inverse's target (see
/// [`Reverse::snapshot`]).
pub(crate) fn state_before(workspace: &mut dyn Workspace, undo: Undo, doc: Option<&str>, params: &Value) -> Option<Value> {
    match undo {
        Undo::Reverses(reverse) => reverse.snapshot(workspace, doc, params),
        _ => None,
    }
}
