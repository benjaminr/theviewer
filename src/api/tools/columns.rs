//! `columns.*`: profiling the byte columns of fixed-size records, as the
//! Columns tool does.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, values};
use crate::columns::{self, ColumnProfile, FieldGuess};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("columns.profile", Read, profile, ProfileParams, ProfileResult, "Profile the byte columns of fixed-size records from an offset (each column's kind, entropy and values) and group them into likely fields; in the window the Columns tool shows it."),
];

/// An example call of each of [`METHODS`].
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("columns.profile", json!({"start": 0, "record_len": 16}))]
}

/// What a call to one of this module's methods would do, in plain words.
pub(super) fn describe_call(_workspace: &mut dyn Workspace, _method: &str, _params: &serde_json::Value) -> Option<String> {
    None
}

/// Records profiled at most.
pub const PROFILE_RECORDS: usize = 4096;
/// Longest record `columns.profile` takes.
pub const MOST_RECORD_LEN: usize = 65_536;

/// Parameters of `columns.profile`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the first record.
    #[serde(default)]
    pub start: u64,
    /// Bytes per record, 1 to 65536.
    pub record_len: usize,
    /// Bytes of records to profile, every record counting (a selection);
    /// when omitted, the records run from `start` until they stop looking alike.
    #[serde(default)]
    pub len: Option<u64>,
}

/// One byte position of the records.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ColumnResult {
    /// Position within the record.
    pub position: usize,
    /// Such as "constant", "counter" or "text".
    pub kind: String,
    /// Entropy of the column's values, in bits.
    pub entropy: f32,
    pub distinct: usize,
    pub most_common: u8,
    pub most_common_fraction: f32,
    /// How often the value differs from the previous record's.
    pub changes_fraction: f32,
}

/// A likely field of the records.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FieldResult {
    /// The field's name in `template`, from where it starts (`field_7`):
    /// the same whatever the field is guessed to be.
    pub name: String,
    /// Position within the record.
    pub start: usize,
    pub len: usize,
    /// Role, type and byte order, such as "counter u32 LE +1".
    pub kind: String,
    /// The evidence, in words.
    pub detail: String,
}

/// The result of `columns.profile`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProfileResult {
    pub start: u64,
    pub record_len: usize,
    /// Records profiled.
    pub records: usize,
    pub columns: Vec<ColumnResult>,
    pub fields: Vec<FieldResult>,
    /// The fields as a template, to apply with templates.apply.
    pub template: String,
}

/// A column profile of the records at `start`: how many records it
/// covers, each column, and the fields they group into.
pub struct Profiled {
    pub records: usize,
    pub profiles: Vec<ColumnProfile>,
    pub fields: Vec<FieldGuess>,
}

/// Profile the records in `bytes` (read from the first record on, up to
/// [`PROFILE_RECORDS`] of them): all of `selected` bytes' records when
/// given, else as many as look alike.
pub fn profile_records(bytes: &[u8], record_len: usize, selected: Option<usize>, document_len: usize) -> Profiled {
    let records = match selected {
        Some(len) => (len / record_len).clamp(1, PROFILE_RECORDS),
        None => columns::table_length(bytes, record_len, PROFILE_RECORDS),
    };
    let bytes = &bytes[..(records * record_len).min(bytes.len())];
    let profiles = columns::profile(bytes, record_len, PROFILE_RECORDS);
    let fields = columns::group_fields(bytes, record_len, &profiles, document_len);
    Profiled { records, profiles, fields }
}

pub fn profile(workspace: &mut dyn Workspace, params: ProfileParams) -> Result<ProfileResult, ApiError> {
    if !(1..=MOST_RECORD_LEN).contains(&params.record_len) {
        return Err(ApiError::invalid_params(format!("a record length of {} is outside 1 to {MOST_RECORD_LEN}", params.record_len)));
    }
    let record_len = params.record_len;
    let (id, document) = workspace::document(workspace, params.doc.as_deref())?;
    let document_len = document.len();
    let (start, selected) = values::span_within(document_len, params.start, params.len.or(Some(0)))?;
    let bytes = document.read_range(start, record_len * PROFILE_RECORDS);
    let selected = params.len.map(|_| selected);
    let profiled = profile_records(&bytes, record_len, selected, document_len);
    let result = ProfileResult {
        start: start as u64,
        record_len,
        records: profiled.records,
        columns: profiled
            .profiles
            .iter()
            .map(|column| ColumnResult {
                position: column.position,
                kind: column.kind.label().to_string(),
                entropy: column.entropy,
                distinct: column.distinct,
                most_common: column.most_common,
                most_common_fraction: column.most_common_fraction,
                changes_fraction: column.changes_fraction,
            })
            .collect(),
        fields: profiled.fields.iter().map(|field| FieldResult { name: field.name.clone(), start: field.start, len: field.len, kind: field.kind.clone(), detail: field.detail.clone() }).collect(),
        template: columns::to_template(record_len, &profiled.fields),
    };
    if let Some(app) = workspace.window()
        && app.document_id() == id
    {
        app.show_column_profile(start, record_len, profiled);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    fn records() -> Vec<u8> {
        (0..64u8).flat_map(|index| [0xA5, index, b'x', index.wrapping_mul(37)]).collect()
    }

    #[test]
    fn the_columns_of_records_are_profiled_and_grouped_into_fields() {
        let mut workspace = workspace_with("records.bin", &records());
        let profiled = call(&mut workspace, "columns.profile", json!({"start": 0, "record_len": 4})).unwrap();
        assert_eq!(profiled["records"], 64);
        assert_eq!(profiled["columns"][0]["kind"], "constant");
        assert_eq!(profiled["columns"][1]["kind"], "counter");
        assert!(!profiled["fields"].as_array().unwrap().is_empty());
        let template = profiled["template"].as_str().unwrap();
        assert!(template.contains("struct"), "{profiled}");
        let name = profiled["fields"][0]["name"].as_str().unwrap();
        assert!(template.contains(&format!("    {name}:")), "a field is named as the template names it: {profiled}");
        let selected = call(&mut workspace, "columns.profile", json!({"start": 8, "record_len": 4, "len": 40})).unwrap();
        assert_eq!(selected["records"], 10, "within a selection every record counts");
    }

    #[test]
    fn a_record_length_outside_the_limits_or_a_start_past_the_end_is_refused() {
        let mut workspace = workspace_with("records.bin", &records());
        assert_eq!(call(&mut workspace, "columns.profile", json!({"record_len": 0})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "columns.profile", json!({"record_len": 70_000})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "columns.profile", json!({"start": 1000, "record_len": 4})).unwrap_err().code, ErrorCode::OutOfRange);
    }
}
