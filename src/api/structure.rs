//! `structure.*` and `templates.*`: parsing the structure at an offset with
//! the app's parsers, or with a binary template.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values::{self, NoParams};
use super::workspace::{self, Workspace};
use super::{ApiError, MAX_CALL_BYTES};
use crate::bus::topics::{FindingsPublished, TemplateApplied};
use crate::bus::{Draft, Payload, Topic};
use crate::plugin::Finding;
use crate::templates::{self, Applied, Template};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("structure.parse", Read, parse, ParseParams, ParseResult, "Parse the structure starting exactly at an offset (executables, images, archives, captures, ASN.1, filesystems) into a field tree, best match first."),
    method!("structure.parsers", Read, parsers, super::values::NoParams, ParsersResult, "The structure parsers available, built in and from plugins."),
    method!("templates.list", Read, list_templates, super::values::NoParams, TemplateList, "The binary templates available: the built-in ones and the user's own."),
    method!("templates.apply", Analysis, apply_template, ApplyParams, ApplyResult, "Apply a binary template, by name or as source text, at an offset and return its field tree and records; with pin, also show it as the template tool does.").reverses(crate::api::Reverse::PinTemplate),
    method!("templates.infer", Analysis, infer_template, InferParams, InferResult, "Propose a template struct from several example records, from what varies between them; with pin, also apply it at the first record and show it as the template tool does.").reverses(crate::api::Reverse::PinTemplate),
    method!("templates.clear", View, clear_template, ClearParams, ClearResult, "Withdraw the template pinned over a document: its records are no longer outlined, and it leaves template.applied.").reverses(crate::api::Reverse::ClearTemplate),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("structure.parse", json!({"at": 0})),
        ("structure.parsers", json!({})),
        ("templates.list", json!({})),
        ("templates.apply", json!({"name": "Fixed-size records", "limit": 2})),
        ("templates.infer", json!({"start": 0, "len": 400, "record_len": 45})),
        ("templates.clear", json!({})),
    ]
}

/// What a call to one of this module's methods would do, in plain words,
/// for the window that asks the person to confirm it; `None` leaves it to
/// the general "Call method with params".
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, _params: &serde_json::Value) -> Option<String> {
    match method {
        "templates.clear" => Some("Clear the applied template".to_string()),
        _ => None,
    }
}

/// Parameters of `structure.parse`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParseParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset where the structure starts.
    pub at: u64,
    /// Only this parser, by id (see structure.parsers); every parser when omitted.
    #[serde(default)]
    pub parser: Option<String>,
}

/// The result of `structure.parse`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ParseResult {
    /// Every parse of the bytes, most confident first, each with its field
    /// tree in document offsets. Empty when no parser recognises them.
    pub structures: Vec<Finding>,
}

/// One parser.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ParserInfo {
    pub id: String,
    pub name: String,
}

/// The result of `structure.parsers`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ParsersResult {
    pub parsers: Vec<ParserInfo>,
}

/// Where a template comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TemplateOrigin {
    /// Shipped with the app.
    Builtin,
    /// A `.tpl` file in the user's templates directory.
    User,
}

/// One template `templates.list` knows.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TemplateInfo {
    pub name: String,
    pub origin: TemplateOrigin,
    /// Why the template cannot be used, when its source has a mistake.
    pub error: Option<String>,
}

/// The result of `templates.list`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TemplateList {
    pub templates: Vec<TemplateInfo>,
}

/// Parameters of `templates.apply`. Give the template by `name` or as `source`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset the template's root starts at (0 by default).
    #[serde(default)]
    pub at: u64,
    /// A template from templates.list.
    #[serde(default)]
    pub name: Option<String>,
    /// Template source text, as written in the template language.
    #[serde(default)]
    pub source: Option<String>,
    /// Most records to return (100 by default).
    #[serde(default)]
    pub limit: Option<usize>,
    /// The `next` cursor of the previous page of records.
    #[serde(default)]
    pub next: Option<String>,
    /// Pin the parse as the template tool does: its records are outlined
    /// in the views and its structure published, in place of the last
    /// template pinned.
    #[serde(default)]
    pub pin: bool,
}

/// One leaf value of a record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RecordValue {
    /// Field name, dotted for nested structs.
    pub name: String,
    pub value: String,
}

/// One element of the outermost array of structs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RecordResult {
    pub offset: u64,
    pub len: u64,
    pub values: Vec<RecordValue>,
}

/// The result of `templates.apply`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ApplyResult {
    /// The whole parse, with its field tree in document offsets.
    pub structure: Finding,
    /// Column names across all records, in order of first appearance.
    pub columns: Vec<String>,
    /// One page of records.
    pub records: Vec<RecordResult>,
    /// Records in all.
    pub total_records: u64,
    /// Pass back as `next` for more records; absent after the last.
    pub next: Option<String>,
    /// Problems met while applying, each with its template line.
    pub warnings: Vec<String>,
}

pub fn parse(workspace: &mut dyn Workspace, params: ParseParams) -> Result<ParseResult, ApiError> {
    let registry = workspace.registry();
    if let Some(id) = &params.parser
        && !registry.has_parser(id)
    {
        return Err(ApiError::not_found(format!("there is no parser '{id}'; structure.parsers lists them")));
    }
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (at, available) = values::span_within(document.len(), params.at, None)?;
    let bytes = document.read_range(at, available.min(MAX_CALL_BYTES));
    let mut structures = match &params.parser {
        Some(id) => registry.parse_with(id, &bytes, at).into_iter().collect(),
        None => registry.parse_at(&bytes, at),
    };
    structures.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
    Ok(ParseResult { structures })
}

pub fn parsers(workspace: &mut dyn Workspace, _params: NoParams) -> Result<ParsersResult, ApiError> {
    let parsers = workspace.registry().parsers().iter().map(|parser| ParserInfo { id: parser.id().to_string(), name: parser.name().to_string() }).collect();
    Ok(ParsersResult { parsers })
}

/// One template known by name.
struct KnownTemplate {
    name: String,
    origin: TemplateOrigin,
    /// The source text, when it could be read.
    source: String,
    parsed: Result<Template, String>,
}

/// Every template: the built-in ones, then the user's.
fn known_templates() -> Vec<KnownTemplate> {
    let builtin = templates::builtin_templates().into_iter().map(|(name, source)| KnownTemplate {
        name: name.to_string(),
        origin: TemplateOrigin::Builtin,
        source: source.to_string(),
        parsed: Template::parse(source).map_err(|error| error.to_string()),
    });
    let dir = templates::default_dir();
    let user = dir.as_ref().map(|dir| templates::load_dir(dir)).unwrap_or_default().into_iter().map(|(name, parsed)| KnownTemplate {
        source: dir.as_ref().and_then(|dir| std::fs::read_to_string(dir.join(format!("{name}.tpl"))).ok()).unwrap_or_default(),
        name,
        origin: TemplateOrigin::User,
        parsed: parsed.map_err(|error| error.to_string()),
    });
    builtin.chain(user).collect()
}

pub fn list_templates(_workspace: &mut dyn Workspace, _params: NoParams) -> Result<TemplateList, ApiError> {
    let templates = known_templates().into_iter().map(|known| TemplateInfo { name: known.name, origin: known.origin, error: known.parsed.err() }).collect();
    Ok(TemplateList { templates })
}

/// Pin `applied`, the parse of `template` (written as `source`), over
/// document `doc` as the template tool does: in the window the Template
/// tool shows it too.
fn pin(workspace: &mut dyn Workspace, doc: &str, template: &Template, source: String, applied: &Applied) {
    if let Some(app) = workspace.window()
        && app.document_id() == doc
    {
        return app.show_applied_template(template, &source, applied.clone());
    }
    let pinned = TemplateApplied { name: template.name().to_string(), source, records: applied.records.len(), structure: applied.finding.clone() };
    workspace.pin_template(doc, pinned);
}

/// Parameters of `templates.infer`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InferParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset of the example records.
    pub start: u64,
    /// Bytes of example records, several of them.
    pub len: u64,
    /// Bytes per record; guessed from what repeats when omitted.
    #[serde(default)]
    pub record_len: Option<usize>,
    /// Also apply the struct at `start` and pin it, as templates.apply with
    /// pin does.
    #[serde(default)]
    pub pin: bool,
}

/// The result of `templates.infer`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InferResult {
    /// The struct proposed, as template source for templates.apply.
    pub source: String,
    pub record_len: usize,
    /// Example records it was inferred from.
    pub records: usize,
}

/// Parameters of `templates.clear`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClearParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
}

/// The result of `templates.clear`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClearResult {
    /// Id of the document.
    pub doc: String,
    /// Whether a template was pinned there.
    pub cleared: bool,
}

pub fn infer_template(workspace: &mut dyn Workspace, params: InferParams) -> Result<InferResult, ApiError> {
    let (doc, document) = workspace::document(workspace, params.doc.as_deref())?;
    let document_len = document.len();
    let (start, len) = values::span_within(document_len, params.start, Some(params.len))?;
    values::check_call_size(len)?;
    if len == 0 {
        return Err(ApiError::invalid_params("give the example records' len; a struct is inferred from several records"));
    }
    let bytes = document.read_range(start, len);
    let record_len = match params.record_len {
        Some(0) => return Err(ApiError::invalid_params("a record_len of 0 holds nothing")),
        Some(record_len) => record_len,
        None => templates::guess_record_length(&bytes).ok_or_else(|| ApiError::invalid_params("no record length repeats in these bytes; give record_len"))?,
    };
    let records = (len / record_len).max(1);
    let source = templates::infer_struct(&bytes, record_len, records, document_len);
    if params.pin {
        let template = Template::parse(&source).map_err(|error| ApiError::invalid_params(format!("the inferred struct does not parse: {error}")))?;
        let (_, document) = workspace::document(workspace, Some(&doc))?;
        let bytes = document.read_range(start, (document_len - start).min(MAX_CALL_BYTES));
        let applied = template.apply(&bytes, start);
        pin(workspace, &doc, &template, source.clone(), &applied);
    }
    Ok(InferResult { source, record_len, records })
}

/// `templates.clear`: in the window the Template tool clears its template;
/// elsewhere the pinned template's facts are withdrawn.
pub fn clear_template(workspace: &mut dyn Workspace, params: ClearParams) -> Result<ClearResult, ApiError> {
    let doc = workspace::resolve(workspace, params.doc.as_deref())?;
    if let Some(app) = workspace.window()
        && app.document_id() == doc
    {
        let cleared = app.withdraw_template();
        return Ok(ClearResult { doc, cleared });
    }
    let version = workspace::info(workspace, &doc)?.version;
    let bus = workspace.bus();
    let cleared = bus.facts().any(|fact| fact.producer() == workspace::TEMPLATES_PRODUCER && fact.draft.document.as_deref() == Some(doc.as_str()) && fact.topic() == Topic::TemplateApplied);
    let empty = Finding::new("template", "templates", crate::plugin::Category::Structure, 0, 0);
    let withdrawn = [
        Payload::TemplateApplied(TemplateApplied { name: String::new(), source: String::new(), records: 0, structure: empty.clone() }),
        Payload::StructureIdentified(crate::app::structure_of(&empty)),
        Payload::FindingsPublished(FindingsPublished { findings: Vec::new() }),
    ];
    for payload in withdrawn {
        bus.publish(Draft::new(workspace::TEMPLATES_PRODUCER, payload).about(doc.clone(), version).retraction());
    }
    Ok(ClearResult { doc, cleared })
}

pub fn apply_template(workspace: &mut dyn Workspace, params: ApplyParams) -> Result<ApplyResult, ApiError> {
    let (template, source) = match (&params.name, &params.source) {
        (Some(name), None) => {
            let known = known_templates()
                .into_iter()
                .find(|known| known.name.eq_ignore_ascii_case(name))
                .ok_or_else(|| ApiError::not_found(format!("there is no template '{name}'; templates.list lists them")))?;
            let template = known.parsed.map_err(|error| ApiError::invalid_params(format!("the template '{name}' does not parse: {error}")))?;
            (template, known.source)
        }
        (None, Some(source)) => (Template::parse(source).map_err(|error| ApiError::invalid_params(format!("the template does not parse: {error}")))?, source.clone()),
        _ => return Err(ApiError::invalid_params("give the template by name or as source, not both")),
    };
    let (doc, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (at, available) = values::span_within(document.len(), params.at, None)?;
    let bytes = document.read_range(at, available.min(MAX_CALL_BYTES));
    let applied = template.apply(&bytes, at);
    if params.pin {
        pin(workspace, &doc, &template, source, &applied);
    }
    let columns = applied.columns();
    let total_records = applied.records.len() as u64;
    let records = applied
        .records
        .into_iter()
        .map(|record| RecordResult {
            offset: record.offset as u64,
            len: record.len as u64,
            values: record.values.into_iter().map(|(name, value)| RecordValue { name, value }).collect(),
        })
        .collect();
    let (records, next) = values::page(records, params.next.as_deref(), params.limit)?;
    Ok(ApplyResult { structure: applied.finding, columns, records, total_records, next, warnings: applied.warnings })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::ErrorCode;
    use crate::api::test_support::call;

    fn png() -> Vec<u8> {
        let image = image::RgbaImage::from_fn(3, 2, |x, _| image::Rgba([x as u8, 0, 0, 255]));
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image).write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    #[test]
    fn a_png_is_parsed_into_its_chunks_at_its_offset() {
        let mut bytes = vec![0; 16];
        bytes.extend(png());
        let mut workspace = workspace_with("a.bin", &bytes);
        let parsed = call(&mut workspace, "structure.parse", json!({"at": 16})).unwrap();
        assert_eq!(parsed["structures"][0]["id"], "png");
        assert_eq!(parsed["structures"][0]["start"], 16);
        let only_png = call(&mut workspace, "structure.parse", json!({"at": 16, "parser": "png"})).unwrap();
        assert_eq!(only_png["structures"].as_array().unwrap().len(), 1);
        let nothing = call(&mut workspace, "structure.parse", json!({"at": 1})).unwrap();
        assert!(nothing["structures"].as_array().unwrap().is_empty());
        assert_eq!(call(&mut workspace, "structure.parse", json!({"at": 0, "parser": "nope"})).unwrap_err().code, ErrorCode::NotFound);
        let parsers = call(&mut workspace, "structure.parsers", json!({})).unwrap();
        assert!(parsers["parsers"].as_array().unwrap().iter().any(|parser| parser["id"] == "png"));
    }

    #[test]
    fn a_template_reads_records_by_name_or_from_source() {
        let mut workspace = workspace_with("a.bin", &[1, 0, 2, 0, 3, 0]);
        let applied = call(&mut workspace, "templates.apply", json!({"source": "endian little\nstruct R { n: u16 }\nroot R[until_end]", "limit": 2})).unwrap();
        assert_eq!(applied["total_records"], 3);
        assert_eq!(applied["records"][1], json!({"offset": 2, "len": 2, "values": [{"name": "n", "value": "2"}]}));
        assert_eq!(applied["next"], "2");
        let listed = call(&mut workspace, "templates.list", json!({})).unwrap();
        assert!(listed["templates"].as_array().unwrap().iter().any(|template| template["name"] == "PNG" && template["origin"] == "builtin"));
        assert!(call(&mut workspace, "templates.apply", json!({"name": "png"})).is_ok(), "names match without regard to case");
    }

    #[test]
    fn a_template_must_be_named_once_and_parse() {
        let mut workspace = workspace_with("a.bin", b"abc");
        assert_eq!(call(&mut workspace, "templates.apply", json!({})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "templates.apply", json!({"source": "struct {"})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "templates.apply", json!({"name": "no such"})).unwrap_err().code, ErrorCode::NotFound);
    }

    /// Records of 8 bytes: a constant tag, a counter and a varying value.
    fn records() -> Vec<u8> {
        (0..32u32).flat_map(|index| {
            let mut record = vec![0xA5, 0x5A];
            record.extend((index as u16).to_le_bytes());
            record.extend((index.wrapping_mul(2_654_435_761)).to_le_bytes());
            record
        }).collect()
    }

    #[test]
    fn a_struct_is_inferred_from_example_records_and_can_be_pinned() {
        let mut workspace = workspace_with("records.bin", &records());
        let inferred = call(&mut workspace, "templates.infer", json!({"start": 0, "len": 256})).unwrap();
        let guessed = crate::templates::guess_record_length(&records()).unwrap();
        assert_eq!(inferred["record_len"], guessed, "the record length is guessed from what repeats");
        assert_eq!(inferred["records"], 256 / guessed);
        let source = inferred["source"].as_str().unwrap().to_string();
        assert!(call(&mut workspace, "templates.apply", json!({"source": source})).is_ok(), "the struct is template source:\n{source}");
        let none = call(&mut workspace, "events.facts", json!({"producer": "tool:templates"})).unwrap();
        assert!(none["facts"].as_array().unwrap().is_empty(), "inferring alone pins nothing");
        call(&mut workspace, "templates.infer", json!({"start": 0, "len": 256, "pin": true})).unwrap();
        let pinned = call(&mut workspace, "events.facts", json!({"topic": "template.applied", "producer": "tool:templates"})).unwrap();
        assert_eq!(pinned["facts"][0]["payload"]["source"], json!(source));
    }

    #[test]
    fn inferring_needs_records_to_look_at() {
        let mut workspace = workspace_with("records.bin", &records());
        assert_eq!(call(&mut workspace, "templates.infer", json!({"start": 0, "len": 0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "templates.infer", json!({"start": 0, "len": 16, "record_len": 0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "templates.infer", json!({"start": 200, "len": 100})).unwrap_err().code, ErrorCode::OutOfRange);
    }

    #[test]
    fn clearing_withdraws_the_pinned_template() {
        let mut workspace = workspace_with("a.bin", &[1, 0, 2, 0]);
        let cleared = call(&mut workspace, "templates.clear", json!({})).unwrap();
        assert_eq!(cleared["cleared"], false, "nothing was pinned");
        call(&mut workspace, "templates.apply", json!({"source": "endian little\nstruct R { n: u16 }\nroot R[until_end]", "pin": true})).unwrap();
        let cleared = call(&mut workspace, "templates.clear", json!({})).unwrap();
        assert_eq!(cleared, json!({"doc": "doc-1", "cleared": true}));
        let left = call(&mut workspace, "events.facts", json!({"producer": "tool:templates"})).unwrap();
        assert!(left["facts"].as_array().unwrap().is_empty(), "{left}");
        assert_eq!(call(&mut workspace, "templates.clear", json!({"doc": "doc-7"})).unwrap_err().code, ErrorCode::NotFound);
    }

    #[test]
    fn a_pinned_template_is_published_as_the_template_tools() {
        let mut workspace = workspace_with("a.bin", &[1, 0, 2, 0]);
        call(&mut workspace, "templates.apply", json!({"source": "endian little\nstruct R { n: u16 }\nroot R[until_end]"})).unwrap();
        let none = call(&mut workspace, "events.facts", json!({"producer": "tool:templates"})).unwrap();
        assert!(none["facts"].as_array().unwrap().is_empty(), "applying alone pins nothing");
        call(&mut workspace, "templates.apply", json!({"source": "endian little\nstruct R { n: u16 }\nroot R[until_end]", "pin": true})).unwrap();
        let pinned = call(&mut workspace, "events.facts", json!({"producer": "tool:templates"})).unwrap();
        let topics: Vec<&str> = pinned["facts"].as_array().unwrap().iter().filter_map(|fact| fact["topic"].as_str()).collect();
        assert!(topics.contains(&"structure.identified") && topics.contains(&"findings.published"), "{topics:?}");
        let applied = pinned["facts"].as_array().unwrap().iter().find(|fact| fact["topic"] == "template.applied").expect("the template, to apply again");
        assert_eq!(applied["payload"]["records"], 2);
        assert!(applied["payload"]["source"].as_str().unwrap().contains("struct R"));
    }
}
