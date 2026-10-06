//! `structure.*` and `templates.*`: parsing the structure at an offset with
//! the app's parsers, or with a binary template.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values::{self, NoParams};
use super::workspace::{self, Workspace};
use super::{ApiError, MAX_CALL_BYTES};
use crate::plugin::Finding;
use crate::templates::{self, Template};

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
        && !registry.parsers().iter().any(|parser| parser.id() == id)
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

/// Every template: the built-in ones, then the user's.
fn known_templates() -> Vec<(String, TemplateOrigin, Result<Template, String>)> {
    let builtin = templates::builtin_templates()
        .into_iter()
        .map(|(name, source)| (name.to_string(), TemplateOrigin::Builtin, Template::parse(source).map_err(|error| error.to_string())));
    let user = templates::default_dir()
        .map(|dir| templates::load_dir(&dir))
        .unwrap_or_default()
        .into_iter()
        .map(|(name, parsed)| (name, TemplateOrigin::User, parsed.map_err(|error| error.to_string())));
    builtin.chain(user).collect()
}

pub fn list_templates(_workspace: &mut dyn Workspace, _params: NoParams) -> Result<TemplateList, ApiError> {
    let templates = known_templates().into_iter().map(|(name, origin, parsed)| TemplateInfo { name, origin, error: parsed.err() }).collect();
    Ok(TemplateList { templates })
}

pub fn apply_template(workspace: &mut dyn Workspace, params: ApplyParams) -> Result<ApplyResult, ApiError> {
    let template = match (&params.name, &params.source) {
        (Some(name), None) => {
            let (_, _, parsed) = known_templates()
                .into_iter()
                .find(|(known, _, _)| known.eq_ignore_ascii_case(name))
                .ok_or_else(|| ApiError::not_found(format!("there is no template '{name}'; templates.list lists them")))?;
            parsed.map_err(|error| ApiError::invalid_params(format!("the template '{name}' does not parse: {error}")))?
        }
        (None, Some(source)) => Template::parse(source).map_err(|error| ApiError::invalid_params(format!("the template does not parse: {error}")))?,
        _ => return Err(ApiError::invalid_params("give the template by name or as source, not both")),
    };
    let (doc, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (at, available) = values::span_within(document.len(), params.at, None)?;
    let bytes = document.read_range(at, available.min(MAX_CALL_BYTES));
    let applied = template.apply(&bytes, at);
    if params.pin {
        workspace.pin_template(&doc, applied.finding.clone());
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
    }
}
