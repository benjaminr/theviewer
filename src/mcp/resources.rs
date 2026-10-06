//! MCP resources: what is known about each open document, its bytes, and
//! the reference notes.
//!
//! * `theviewer://doc/{id}`: the document's info (JSON).
//! * `theviewer://doc/{id}/bytes/{start}-{end}`: bytes `start..end` as a
//!   blob, or as a hex dump with `?encoding=hex`; at most
//!   [`MAX_RESOURCE_BYTES`].
//! * `theviewer://doc/{id}/findings`: the findings published on the bus
//!   (by plugins, clients and templates) and what the detectors recognise.
//! * `theviewer://doc/{id}/facts`: every fact the bus keeps about it.
//! * `theviewer://reference/{id}`: notes on a format or protocol (Markdown).
//!
//! `{id}` is a document's id, an open document's path, or `current`.
//! Subscriptions follow the bus: [`DocumentChanges`] gathers which
//! documents' resources the delivered messages changed.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Value, json};

use crate::api::{self, Caller, ErrorCode, Workspace, workspace};
use crate::bus::topics::Kind;
use crate::bus::{Message, Payload};
use crate::reference;

/// Where every resource's URI starts.
pub const SCHEME: &str = "theviewer://";
/// Most bytes one read of a bytes resource returns: 1 MiB.
pub const MAX_RESOURCE_BYTES: usize = 1024 * 1024;
/// Most findings the detectors' part of a findings resource lists.
const DETECTED_LIMIT: usize = 100;

const JSON: &str = "application/json";
const MARKDOWN: &str = "text/markdown";

/// What part of a document a resource is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DocumentPart {
    Info,
    /// Bytes `start..end`, as a hex dump when `hex`.
    Bytes { start: usize, end: usize, hex: bool },
    Findings,
    Facts,
}

/// A resource URI, understood.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    /// Part of the document named `doc` (an id, a path or "current").
    Document { doc: String, part: DocumentPart },
    /// The reference notes with this id.
    Reference(String),
}

/// Understand a resource URI, or say what is wrong with it.
pub fn parse_uri(uri: &str) -> Result<Resource, String> {
    let rest = uri.strip_prefix(SCHEME).ok_or_else(|| format!("'{uri}' is not a theviewer resource; they start with {SCHEME}"))?;
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let segments: Vec<&str> = path.split('/').collect();
    match segments.as_slice() {
        ["reference", id] if !id.is_empty() => Ok(Resource::Reference(id.to_string())),
        ["doc", doc, part @ ..] if !doc.is_empty() => {
            let part = match part {
                [] => DocumentPart::Info,
                ["findings"] => DocumentPart::Findings,
                ["facts"] => DocumentPart::Facts,
                ["bytes", range] => parse_range(range, query)?,
                _ => return Err(format!("'{uri}' is not one of a document's resources: its info, bytes/{{start}}-{{end}}, findings or facts")),
            };
            Ok(Resource::Document { doc: doc.to_string(), part })
        }
        _ => Err(format!("'{uri}' is not a resource; resources/templates/list shows their forms")),
    }
}

/// `{start}-{end}` (decimal or 0x hex, end exclusive) and the query.
fn parse_range(range: &str, query: &str) -> Result<DocumentPart, String> {
    let (start, end) = range.split_once('-').ok_or_else(|| format!("'{range}' is not a byte range; write it start-end, such as 0-256"))?;
    let offset = |text: &str| crate::ops::parse_offset(text).ok_or_else(|| format!("'{text}' is not an offset"));
    let (start, end) = (offset(start)?, offset(end)?);
    if end <= start {
        return Err(format!("the range {range} is empty; the end comes after the start and is not included"));
    }
    let hex = match query {
        "" | "encoding=base64" => false,
        "encoding=hex" => true,
        other => return Err(format!("'{other}' is not understood; the only option is encoding=hex")),
    };
    Ok(DocumentPart::Bytes { start, end, hex })
}

/// The URI of part of document `id`.
pub fn document_uri(id: &str, part: &DocumentPart) -> String {
    match part {
        DocumentPart::Info => format!("{SCHEME}doc/{id}"),
        DocumentPart::Findings => format!("{SCHEME}doc/{id}/findings"),
        DocumentPart::Facts => format!("{SCHEME}doc/{id}/facts"),
        DocumentPart::Bytes { start, end, hex } => format!("{SCHEME}doc/{id}/bytes/{start}-{end}{}", if *hex { "?encoding=hex" } else { "" }),
    }
}

/// Every resource: each open document's info, findings and facts, then
/// the reference notes.
pub fn list(workspace: &dyn Workspace) -> Vec<Value> {
    let mut resources = Vec::new();
    for document in workspace.documents() {
        let (id, name) = (&document.id, &document.name);
        resources.push(json!({
            "uri": document_uri(id, &DocumentPart::Info), "name": id, "title": format!("{name}: info"),
            "description": format!("{name}'s id, path, length, version and whether it has unsaved edits."), "mimeType": JSON,
        }));
        resources.push(json!({
            "uri": document_uri(id, &DocumentPart::Findings), "name": format!("{id}/findings"), "title": format!("{name}: findings"),
            "description": format!("What the detectors recognise in {name}, and the findings tools, plugins and clients published about it."), "mimeType": JSON,
        }));
        resources.push(json!({
            "uri": document_uri(id, &DocumentPart::Facts), "name": format!("{id}/facts"), "title": format!("{name}: facts"),
            "description": format!("Every fact the workspace bus keeps about {name}, each marked stale once the document changed under it."), "mimeType": JSON,
        }));
    }
    for entry in reference::library().entries() {
        resources.push(json!({
            "uri": format!("{SCHEME}reference/{}", entry.id), "name": entry.id, "title": entry.name,
            "description": entry.summary, "mimeType": MARKDOWN,
        }));
    }
    resources
}

/// The forms of resource URI, with their parameters.
pub fn templates() -> Vec<Value> {
    vec![
        json!({ "uriTemplate": format!("{SCHEME}doc/{{id}}"), "name": "document", "title": "Document info", "description": "A document's id, path, length, version and whether it has unsaved edits. {id} is a document id, an open document's path, or current.", "mimeType": JSON }),
        json!({ "uriTemplate": format!("{SCHEME}doc/{{id}}/bytes/{{start}}-{{end}}"), "name": "bytes", "title": "Document bytes", "description": format!("Bytes start up to (not including) end, at most {MAX_RESOURCE_BYTES}, as a blob; add ?encoding=hex for a hex dump. Offsets are decimal or 0x hex."), "mimeType": "application/octet-stream" }),
        json!({ "uriTemplate": format!("{SCHEME}doc/{{id}}/findings"), "name": "findings", "title": "Document findings", "description": "What the detectors recognise in a document, and the findings published about it on the bus.", "mimeType": JSON }),
        json!({ "uriTemplate": format!("{SCHEME}doc/{{id}}/facts"), "name": "facts", "title": "Document facts", "description": "Every fact the workspace bus keeps about a document.", "mimeType": JSON }),
        json!({ "uriTemplate": format!("{SCHEME}reference/{{id}}"), "name": "reference", "title": "Reference notes", "description": "Notes on a format or protocol: layout, field meanings and specifications. reference_search finds ids.", "mimeType": MARKDOWN }),
    ]
}

/// Why a resource could not be read.
#[derive(Clone, Debug, PartialEq)]
pub enum ReadError {
    /// There is no such resource.
    NotFound(String),
    /// The URI asks for something that cannot be given, such as too many bytes.
    Invalid(String),
    /// Something went wrong reading it.
    Failed(String),
}

impl ReadError {
    fn from_api(error: api::ApiError) -> Self {
        match error.code {
            ErrorCode::NotFound => ReadError::NotFound(error.message),
            ErrorCode::InvalidParams | ErrorCode::OutOfRange | ErrorCode::TooLarge => ReadError::Invalid(error.message),
            _ => ReadError::Failed(error.message),
        }
    }
}

/// Read the resource at `uri` for `caller`: its contents, one item.
pub fn read(workspace: &mut dyn Workspace, caller: &Caller, uri: &str) -> Result<Value, ReadError> {
    let resource = parse_uri(uri).map_err(ReadError::NotFound)?;
    let mut call = |method: &str, params: Value| api::call(workspace, caller, method, params).map_err(ReadError::from_api);
    let json_contents = |value: &Value| json!({ "uri": uri, "mimeType": JSON, "text": serde_json::to_string_pretty(value).unwrap_or_default() });
    match resource {
        Resource::Reference(id) => {
            let entry = reference::library().by_id(&id).ok_or_else(|| ReadError::NotFound(format!("there are no reference notes with the id '{id}'; reference_search finds them")))?;
            Ok(json!({ "uri": uri, "mimeType": MARKDOWN, "text": entry.to_markdown() }))
        }
        Resource::Document { doc, part: DocumentPart::Info } => Ok(json_contents(&call("documents.info", json!({ "doc": doc }))?)),
        Resource::Document { doc, part: DocumentPart::Facts } => Ok(json_contents(&call("events.facts", json!({ "doc": doc }))?)),
        Resource::Document { doc, part: DocumentPart::Findings } => {
            let published = call("events.facts", json!({ "doc": doc, "topic": "findings.published" }))?;
            let detected = call("findings.query", json!({ "doc": doc, "limit": DETECTED_LIMIT }))?;
            Ok(json_contents(&json!({ "published": published["facts"], "detected": detected })))
        }
        Resource::Document { doc, part: DocumentPart::Bytes { start, end, hex } } => {
            let len = end - start;
            if len > MAX_RESOURCE_BYTES {
                return Err(ReadError::Invalid(format!("{len} bytes is more than the {MAX_RESOURCE_BYTES} one read gives; read a smaller range, or use the bytes_read tool")));
            }
            if hex {
                let dump = call("bytes.hexdump", json!({ "doc": doc, "start": start, "len": len }))?;
                Ok(json!({ "uri": uri, "mimeType": "text/plain", "text": dump["dump"] }))
            } else {
                let read = call("bytes.read", json!({ "doc": doc, "start": start, "len": len, "encoding": "base64" }))?;
                Ok(json!({ "uri": uri, "mimeType": "application/octet-stream", "blob": read["data"] }))
            }
        }
    }
}

/// Which documents' resources delivered messages changed, by document id.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DocumentChanges {
    /// Bytes or info changed: every resource of the document did.
    edited: BTreeSet<String>,
    /// Findings were published or withdrawn.
    findings: BTreeSet<String>,
    /// Some fact was published or withdrawn.
    facts: BTreeSet<String>,
}

impl DocumentChanges {
    /// Note what `message` changes.
    pub fn note(&mut self, message: &Arc<Message>) {
        let Some(document) = message.draft.document.clone() else { return };
        match message.payload() {
            Payload::DocumentEdited(_) | Payload::DocumentOpened(_) | Payload::DocumentClosed(_) => {
                self.edited.insert(document);
            }
            Payload::FindingsPublished(_) => {
                self.findings.insert(document.clone());
                self.facts.insert(document);
            }
            payload if payload.topic().kind() == Kind::Fact => {
                self.facts.insert(document);
            }
            _ => {}
        }
    }

    pub fn is_empty(&self) -> bool {
        self.edited.is_empty() && self.findings.is_empty() && self.facts.is_empty()
    }

    /// Whether the resource at `uri` changed. Its document may be named by
    /// path or as "current", so names are resolved in `workspace`.
    pub fn touches(&self, workspace: &dyn Workspace, uri: &str) -> bool {
        let Ok(Resource::Document { doc, part }) = parse_uri(uri) else { return false };
        let Ok(id) = workspace::resolve(workspace, Some(&doc)) else { return false };
        self.edited.contains(&id)
            || match part {
                DocumentPart::Findings => self.findings.contains(&id),
                DocumentPart::Facts => self.facts.contains(&id),
                DocumentPart::Info | DocumentPart::Bytes { .. } => false,
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::test_support::workspace_with;
    use crate::bus::Draft;
    use crate::bus::topics::{FindingsPublished, RecordWidthEstimated};

    fn caller() -> Caller {
        Caller::Mcp("test".into())
    }

    #[test]
    fn uris_name_a_documents_parts_and_the_reference_notes() {
        assert_eq!(parse_uri("theviewer://doc/doc-1"), Ok(Resource::Document { doc: "doc-1".into(), part: DocumentPart::Info }));
        assert_eq!(parse_uri("theviewer://doc/current/findings"), Ok(Resource::Document { doc: "current".into(), part: DocumentPart::Findings }));
        assert_eq!(parse_uri("theviewer://doc/doc-2/facts"), Ok(Resource::Document { doc: "doc-2".into(), part: DocumentPart::Facts }));
        assert_eq!(parse_uri("theviewer://doc/doc-1/bytes/0x10-32?encoding=hex"), Ok(Resource::Document { doc: "doc-1".into(), part: DocumentPart::Bytes { start: 16, end: 32, hex: true } }));
        assert_eq!(parse_uri("theviewer://reference/ipv4"), Ok(Resource::Reference("ipv4".into())));
        for wrong in ["file:///etc/passwd", "theviewer://doc/", "theviewer://doc/doc-1/bytes/9-3", "theviewer://doc/doc-1/bytes/abc", "theviewer://doc/doc-1/colour", "theviewer://doc/doc-1/bytes/0-4?encoding=rot13"] {
            assert!(parse_uri(wrong).is_err(), "{wrong}");
        }
        let bytes = DocumentPart::Bytes { start: 0, end: 4, hex: false };
        assert_eq!(parse_uri(&document_uri("doc-1", &bytes)), Ok(Resource::Document { doc: "doc-1".into(), part: bytes }));
    }

    #[test]
    fn the_list_has_each_documents_info_findings_and_facts_and_the_reference_notes() {
        let workspace = workspace_with("sample.bin", b"abc");
        let resources = list(&workspace);
        let uris: Vec<&str> = resources.iter().map(|resource| resource["uri"].as_str().unwrap()).collect();
        assert_eq!(&uris[..3], ["theviewer://doc/doc-1", "theviewer://doc/doc-1/findings", "theviewer://doc/doc-1/facts"]);
        assert!(uris.contains(&"theviewer://reference/ipv4"));
        assert_eq!(resources[0]["title"], "sample.bin: info");
        assert_eq!(templates().len(), 5);
    }

    #[test]
    fn bytes_are_read_as_a_blob_or_a_hex_dump() {
        let mut workspace = workspace_with("sample.bin", b"hello world");
        let blob = read(&mut workspace, &caller(), "theviewer://doc/doc-1/bytes/0-5").unwrap();
        assert_eq!((blob["blob"].as_str(), blob["mimeType"].as_str()), (Some("aGVsbG8="), Some("application/octet-stream")));
        let dump = read(&mut workspace, &caller(), "theviewer://doc/current/bytes/6-11?encoding=hex").unwrap();
        assert!(dump["text"].as_str().unwrap().contains("77 6f 72 6c 64"), "{dump}");
        assert!(matches!(read(&mut workspace, &caller(), "theviewer://doc/doc-1/bytes/8-20"), Err(ReadError::Invalid(_))), "past the end");
        let too_many = format!("theviewer://doc/doc-1/bytes/0-{}", MAX_RESOURCE_BYTES + 1);
        assert!(matches!(read(&mut workspace, &caller(), &too_many), Err(ReadError::Invalid(message)) if message.contains("smaller range")));
    }

    #[test]
    fn info_findings_facts_and_notes_are_read_as_text() {
        let mut workspace = workspace_with("sample.bin", b"hello world");
        let info = read(&mut workspace, &caller(), "theviewer://doc/doc-1").unwrap();
        let info: Value = serde_json::from_str(info["text"].as_str().unwrap()).unwrap();
        assert_eq!((info["name"].as_str(), info["len"].as_u64()), (Some("sample.bin"), Some(11)));
        let findings = read(&mut workspace, &caller(), "theviewer://doc/doc-1/findings").unwrap();
        let findings: Value = serde_json::from_str(findings["text"].as_str().unwrap()).unwrap();
        assert!(findings["published"].is_array() && findings["detected"]["findings"].is_array(), "{findings}");
        let facts = read(&mut workspace, &caller(), "theviewer://doc/doc-1/facts").unwrap();
        assert_eq!(facts["mimeType"], JSON);
        let notes = read(&mut workspace, &caller(), "theviewer://reference/ipv4").unwrap();
        assert!(notes["text"].as_str().unwrap().starts_with("# Internet Protocol version 4"), "{notes}");
        assert_eq!(notes["mimeType"], MARKDOWN);
    }

    #[test]
    fn a_resource_that_does_not_exist_is_not_found() {
        let mut workspace = workspace_with("sample.bin", b"abc");
        assert!(matches!(read(&mut workspace, &caller(), "theviewer://doc/doc-9"), Err(ReadError::NotFound(_))));
        assert!(matches!(read(&mut workspace, &caller(), "theviewer://reference/no-such-format"), Err(ReadError::NotFound(_))));
        assert!(matches!(read(&mut workspace, &caller(), "https://example.com"), Err(ReadError::NotFound(_))));
    }

    #[test]
    fn an_edit_changes_every_resource_of_its_document_and_a_fact_only_the_facts() {
        let mut workspace = workspace_with("sample.bin", b"abc");
        workspace.add_document("other.bin", crate::document::Document::from_bytes(b"xyz".to_vec()));
        let mut changes = DocumentChanges::default();
        let cursor = workspace.bus().cursor();
        workspace.bus().publish(Draft::new("tool:period-scan", Payload::RecordWidthEstimated(RecordWidthEstimated { width: 4, score: 1.0, alternatives: Vec::new() })).about("doc-2", 0));
        for message in workspace.bus().changed_since(cursor).messages {
            changes.note(&message);
        }
        assert!(changes.touches(&workspace, "theviewer://doc/doc-2/facts"));
        assert!(changes.touches(&workspace, "theviewer://doc/current/facts"), "doc-2 is current");
        assert!(!changes.touches(&workspace, "theviewer://doc/doc-2/findings"));
        assert!(!changes.touches(&workspace, "theviewer://doc/doc-1/facts"));

        let mut changes = DocumentChanges::default();
        let cursor = workspace.bus().cursor();
        workspace.bus().publish(Draft::new("mcp:test", Payload::FindingsPublished(FindingsPublished { findings: Vec::new() })).about("doc-1", 0).key("k"));
        api::call(&mut workspace, &caller(), "bytes.write", json!({ "doc": "doc-1", "start": 0, "data": "00" })).unwrap();
        for message in workspace.bus().changed_since(cursor).messages {
            changes.note(&message);
        }
        for uri in ["theviewer://doc/doc-1", "theviewer://doc/doc-1/bytes/0-2", "theviewer://doc/doc-1/findings", "theviewer://doc/doc-1/facts"] {
            assert!(changes.touches(&workspace, uri), "{uri}");
        }
        assert!(!changes.touches(&workspace, "theviewer://reference/ipv4"));
    }
}
