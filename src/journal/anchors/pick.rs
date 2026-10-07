//! Pick anchors: an item chosen from a list in an earlier step's result,
//! by what it holds rather than where it is.
//!
//! ```json
//! {"pick": {"step": 5, "list": "job.strings", "where": {"text": {"regex": "^NC500-"}}, "nth": 0, "field": "text"}}
//! ```
//!
//! * `step` is the earlier step, by number or as `"@label"`: the step that
//!   made the sheet labelled so.
//! * `list` is the path of a list in that step's `{"params", "result",
//!   "job"}`, as a step anchor's path is written.
//! * `where` keeps the items that pass it (see [`Condition`]); every item
//!   when omitted.
//! * `sort` orders what is kept by a field, before `nth` (from 0) chooses
//!   one.
//! * `field` is the path of the value to give inside the chosen item; the
//!   whole item when omitted.

use std::cmp::Ordering;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{ResolveContext, RunSheets, ordinal, value_at};
use crate::api::ApiError;

/// An item chosen from a list in an earlier step's result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Pick {
    /// The earlier step: its number, or "@label" for the step that made the
    /// sheet labelled so.
    pub step: StepRef,
    /// Where the list is in that step: `job.strings`, `result.candidates`.
    pub list: String,
    /// Which items to keep, such as {"text": {"regex": "^NC500-"}}: each
    /// key a field of the item with a test (regex, equals, contains, min,
    /// max) or a value it must equal; "tag" a tag the item has; "all" and
    /// "any" lists of such conditions. Every item when omitted.
    #[serde(default, rename = "where", skip_serializing_if = "Option::is_none")]
    pub condition: Option<Map<String, Value>>,
    /// The order to choose from, by a field of the items; as listed when
    /// omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<Sort>,
    /// Which of those kept, counting from 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub nth: usize,
    /// The value to give inside the item chosen, such as `text`; the whole
    /// item when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// An earlier step, by number or by the label of the sheet it made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum StepRef {
    Number(u64),
    /// "@payload": the step that made the sheet labelled payload.
    Label(String),
}

impl StepRef {
    /// "step 5", "the step that made payload".
    pub fn describe(&self) -> String {
        match self {
            StepRef::Number(step) => format!("step {step}"),
            StepRef::Label(label) => format!("the step that made {}", label.trim_start_matches('@')),
        }
    }

    /// The step's number in the run `sheets` describes: the number, or the
    /// step that made the sheet the label names.
    pub fn number(&self, sheets: &RunSheets) -> Result<u64, ApiError> {
        let label = match self {
            StepRef::Number(step) => return Ok(*step),
            StepRef::Label(label) => label.strip_prefix('@').ok_or_else(|| ApiError::invalid_params(format!("'{label}' names no step: write a number, or @label for the step that made the sheet so labelled")))?,
        };
        let doc = sheets.labels.get(label).ok_or_else(|| ApiError::not_found(format!("no step has made a sheet labelled {label}")))?;
        sheets.made.iter().find(|(_, made)| made.contains(doc)).map(|(step, _)| *step).ok_or_else(|| ApiError::not_found(format!("the sheet labelled {label} ({doc}) was not made by a step")))
    }
}

/// The order a pick chooses from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Sort {
    /// The field of each item to order by, such as `score`.
    pub by: String,
    /// Ascending (the default) or descending.
    #[serde(default)]
    pub order: SortOrder,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    #[default]
    Ascending,
    Descending,
}

impl Pick {
    /// "the text of the 1st item of job.strings of step 5 whose text
    /// matches /^NC500-/".
    pub fn describe(&self) -> String {
        let field = self.field.as_deref().map_or(String::new(), |field| format!("the {field} of "));
        let condition = self.condition.as_ref().map_or(String::new(), |condition| format!(" where {}", describe_condition(condition)));
        let sort = self.sort.as_ref().map_or(String::new(), |sort| format!(", by {}{}", sort.by, if sort.order == SortOrder::Descending { " descending" } else { "" }));
        format!("{field}the {} item of {} of {}{condition}{sort}", ordinal(self.nth), self.list, self.step.describe())
    }

    /// The value the pick chooses, from the steps `context` has done.
    pub fn resolve(&self, context: &ResolveContext<'_>) -> Result<Value, ApiError> {
        let step = self.step.number(context.sheets)?;
        let entry = context.steps.get(&step).ok_or_else(|| ApiError::not_found(format!("step {step} has not run before this one")))?;
        let list = value_at(entry, &self.list)?.ok_or_else(|| ApiError::not_found(format!("step {step} has nothing at {}", self.list)))?;
        let items = list.as_array().ok_or_else(|| ApiError::invalid_params(format!("{} of step {step} is not a list", self.list)))?;
        let mut kept = Vec::new();
        for item in items {
            if self.condition.as_ref().map_or(Ok(true), |condition| passes(item, condition))? {
                kept.push(item);
            }
        }
        if let Some(sort) = &self.sort {
            kept.sort_by(|a, b| {
                let order = compare(field_of(a, &sort.by), field_of(b, &sort.by));
                if sort.order == SortOrder::Descending { order.reverse() } else { order }
            });
        }
        let chosen = kept.get(self.nth).ok_or_else(|| {
            let whose = self.condition.as_ref().map_or(String::new(), |condition| format!(" where {}", describe_condition(condition)));
            match kept.len() {
                0 => ApiError::not_found(format!("none of the {} items of {} of step {step} passes{whose}", items.len(), self.list)),
                count => ApiError::not_found(format!("{count} of the items of {} of step {step} pass{whose}, so there is no {}", self.list, ordinal(self.nth))),
            }
        })?;
        match &self.field {
            None => Ok((*chosen).clone()),
            Some(field) => value_at(chosen, field)?.cloned().ok_or_else(|| ApiError::not_found(format!("the item chosen from {} of step {step} has no {field}", self.list))),
        }
    }
}

/// The value at `path` in `item`, or none.
fn field_of<'a>(item: &'a Value, path: &str) -> Option<&'a Value> {
    value_at(item, path).ok().flatten()
}

/// Order two field values: numbers by size, text by its characters, a
/// missing value after any other.
fn compare(a: Option<&Value>, b: Option<&Value>) -> Ordering {
    match (a, b) {
        (Some(Value::Number(a)), Some(Value::Number(b))) => a.as_f64().partial_cmp(&b.as_f64()).unwrap_or(Ordering::Equal),
        (Some(Value::String(a)), Some(Value::String(b))) => a.cmp(b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        _ => Ordering::Equal,
    }
}

/// Whether `item` passes `condition`: every key of it holds.
///
/// * `all`: a list of conditions, each of which it passes;
/// * `any`: a list of conditions, one of which it passes;
/// * `tag`: a tag the item has, as its `tag` or among its `tags`;
/// * any other key: a field of the item (a path), with a test object
///   (`regex`, `equals`, `contains`, `min`, `max`, all of which hold) or a
///   value the field equals.
pub fn passes(item: &Value, condition: &Map<String, Value>) -> Result<bool, ApiError> {
    for (key, wanted) in condition {
        let holds = match key.as_str() {
            "all" => {
                let mut all = true;
                for inner in conditions_in(key, wanted)? {
                    all &= passes(item, inner)?;
                }
                all
            }
            "any" => {
                let mut any = false;
                for inner in conditions_in(key, wanted)? {
                    any |= passes(item, inner)?;
                }
                any
            }
            "tag" if wanted.is_string() => has_tag(item, wanted),
            path => match wanted {
                Value::Object(tests) => passes_tests(field_of(item, path), path, tests)?,
                literal => field_of(item, path) == Some(literal),
            },
        };
        if !holds {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The conditions an `all` or `any` lists.
fn conditions_in<'a>(key: &str, wanted: &'a Value) -> Result<Vec<&'a Map<String, Value>>, ApiError> {
    let invalid = || ApiError::invalid_params(format!("'{key}' takes a list of conditions, such as [{{\"text\": {{\"regex\": \"^key=\"}}}}]"));
    wanted.as_array().ok_or_else(invalid)?.iter().map(|inner| inner.as_object().ok_or_else(invalid)).collect()
}

/// Whether `item` is tagged `tag`: its `tag` is it, or its `tags` hold it.
fn has_tag(item: &Value, tag: &Value) -> bool {
    item.get("tag") == Some(tag) || item.get("tags").and_then(Value::as_array).is_some_and(|tags| tags.contains(tag))
}

/// Whether `value`, the item's field at `path`, passes every test.
fn passes_tests(value: Option<&Value>, path: &str, tests: &Map<String, Value>) -> Result<bool, ApiError> {
    for (test, wanted) in tests {
        let holds = match test.as_str() {
            "equals" => value == Some(wanted),
            "regex" => {
                let pattern = wanted.as_str().ok_or_else(|| ApiError::invalid_params(format!("the regex for {path} is not text")))?;
                let regex = regex_lite::Regex::new(pattern).map_err(|error| ApiError::invalid_params(format!("the regex for {path}, /{pattern}/, does not read: {error}")))?;
                value.and_then(Value::as_str).is_some_and(|text| regex.is_match(text))
            }
            "contains" => match (value, wanted) {
                (Some(Value::String(text)), Value::String(part)) => text.contains(part.as_str()),
                (Some(Value::Array(items)), wanted) => items.contains(wanted),
                _ => false,
            },
            "min" | "max" => {
                let bound = wanted.as_f64().ok_or_else(|| ApiError::invalid_params(format!("the {test} for {path} is not a number")))?;
                match value.and_then(number_of) {
                    Some(number) if test == "min" => number >= bound,
                    Some(number) => number <= bound,
                    None => false,
                }
            }
            other => return Err(ApiError::invalid_params(format!("'{other}' is not a test of a field; use regex, equals, contains, min or max"))),
        };
        if !holds {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A field's value as a number: a number, or text that reads as an integer.
fn number_of(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => super::parse_integer(text).and_then(|number| number.as_f64()),
        _ => None,
    }
}

/// A condition in words: "text matches /^NC500-/ and tag is serial".
pub fn describe_condition(condition: &Map<String, Value>) -> String {
    let parts: Vec<String> = condition
        .iter()
        .map(|(key, wanted)| match (key.as_str(), wanted) {
            ("all" | "any", Value::Array(inner)) => {
                let joined: Vec<String> = inner.iter().filter_map(Value::as_object).map(describe_condition).collect();
                format!("({})", joined.join(if key == "all" { " and " } else { " or " }))
            }
            ("tag", Value::String(tag)) => format!("tagged {tag}"),
            (path, Value::Object(tests)) => {
                let tests: Vec<String> = tests
                    .iter()
                    .map(|(test, value)| match (test.as_str(), value) {
                        ("regex", Value::String(pattern)) => format!("{path} matches /{pattern}/"),
                        ("equals", value) => format!("{path} is {value}"),
                        ("contains", value) => format!("{path} contains {value}"),
                        ("min", value) => format!("{path} is at least {value}"),
                        ("max", value) => format!("{path} is at most {value}"),
                        (test, value) => format!("{path} {test} {value}"),
                    })
                    .collect();
                tests.join(" and ")
            }
            (path, value) => format!("{path} is {value}"),
        })
        .collect();
    parts.join(" and ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn condition(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn a_condition_tests_fields_tags_and_combinations() {
        let serial = json!({"offset": 412, "text": "NC500-2F357657", "tag": "serial", "len": 14});
        let path = json!({"offset": 600, "text": "/etc/config.enc", "tag": "path", "len": 15});
        let serial_regex = condition(json!({"text": {"regex": "^NC500-[0-9A-F]{8}$"}}));
        assert!(passes(&serial, &serial_regex).unwrap());
        assert!(!passes(&path, &serial_regex).unwrap());
        assert!(passes(&path, &condition(json!({"tag": "path"}))).unwrap());
        assert!(passes(&serial, &condition(json!({"len": {"min": 10, "max": 14}}))).unwrap());
        assert!(!passes(&path, &condition(json!({"len": {"max": 14}}))).unwrap());
        assert!(passes(&path, &condition(json!({"text": {"contains": "config"}}))).unwrap());
        assert!(passes(&serial, &condition(json!({"any": [{"tag": "path"}, {"offset": 412}]}))).unwrap());
        assert!(!passes(&serial, &condition(json!({"all": [{"tag": "serial"}, {"offset": 0}]}))).unwrap());
        let unknown = passes(&serial, &condition(json!({"text": {"like": "NC%"}}))).unwrap_err();
        assert!(unknown.message.contains("'like' is not a test"), "{}", unknown.message);
    }

    #[test]
    fn a_condition_is_described_in_words() {
        let described = describe_condition(&condition(json!({"text": {"regex": "^NC500-"}, "tag": "serial"})));
        assert_eq!(described, "tagged serial and text matches /^NC500-/");
    }

    #[test]
    fn a_step_named_by_label_is_the_step_that_made_that_sheet() {
        let sheets = RunSheets { input: Some("doc-1".into()), made: [(2, vec!["doc-2".to_string()]), (4, vec!["doc-3".to_string()])].into(), labels: [("rootfs".to_string(), "doc-3".to_string())].into() };
        assert_eq!(StepRef::Label("@rootfs".into()).number(&sheets).unwrap(), 4);
        assert_eq!(StepRef::Number(2).number(&sheets).unwrap(), 2);
        assert!(StepRef::Label("rootfs".into()).number(&sheets).unwrap_err().message.contains("@label"));
        assert!(StepRef::Label("@payload".into()).number(&sheets).unwrap_err().message.contains("no step has made a sheet labelled payload"));
    }
}
