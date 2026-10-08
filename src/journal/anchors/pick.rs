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
//!   "job"}`, as a step anchor's path is written; `[field=value]` in it
//!   keeps the items of a list on the way whose field is that value
//!   (`job.filesystems[kind=FAT].entries`), and `..name` gathers what is
//!   called so at any depth (`job..children`, every node of a tree).
//! * `where` keeps the items that pass it (see [`passes`]); every item
//!   when omitted. A bound or value in it may be an anchor, marked as in
//!   a step's params (`{"$var": "seq"}`), which is resolved first.
//! * `sort` orders what is kept by a field, before `nth` (from 0) chooses
//!   one.
//! * `field` is the path of the value to give inside the chosen item; the
//!   whole item when omitted.

use std::cmp::Ordering;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{Anchor, ResolveContext, RunSheets, as_anchor, is_marked, marked, ordinal, value_at};
use crate::api::ApiError;

/// An item chosen from a list in an earlier step's result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Pick {
    /// The earlier step: its number, or "@label" for the step that made the
    /// sheet labelled so.
    pub step: StepRef,
    /// Where the list is in that step: `job.strings`, `result.candidates`,
    /// `job.filesystems[kind=FAT].entries`, `job..children`.
    pub list: String,
    /// Which items to keep, such as {"text": {"regex": "^NC500-"}}: each
    /// key a field of the item with a test (regex, equals, contains, min,
    /// max) or a value it must equal; "tag" a tag the item has; "all" and
    /// "any" lists of such conditions. A value or bound may be a marked
    /// anchor, such as {"$var": "seq"}. Every item when omitted.
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
    pub fn resolve(&self, context: &mut ResolveContext<'_>) -> Result<Value, ApiError> {
        let step = self.step.number(context.sheets)?;
        let condition = match &self.condition {
            Some(condition) => Some(resolve_marked(condition, context)?),
            None => None,
        };
        let entry = context.steps.get(&step).ok_or_else(|| ApiError::not_found(format!("step {step} has not run before this one")))?;
        let items = items_at(entry, &self.list, step)?;
        if let Some(warning) = only_a_page(entry, &self.list, step) {
            context.warnings.push(warning);
        }
        let mut kept = Vec::new();
        for item in &items {
            if condition.as_ref().map_or(Ok(true), |condition| passes(item, condition))? {
                kept.push(*item);
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

    /// The anchors marked in `where`, which the pick compares with.
    pub fn anchors(&self) -> Vec<Anchor> {
        let mut found = Vec::new();
        if let Some(condition) = &self.condition {
            let _ = change_marked(condition, &mut |anchor| {
                found.push(anchor.clone());
                Ok(marked(&anchor))
            });
        }
        found
    }

    /// This pick with the steps it names by number, its own and those of
    /// the anchors in its `where`, changed as `renumber` says; `None` when
    /// one is not there to name.
    pub fn renumbered(&self, renumber: &impl Fn(u64) -> Option<u64>) -> Option<Pick> {
        let mut pick = self.clone();
        if let StepRef::Number(step) = pick.step {
            pick.step = StepRef::Number(renumber(step)?);
        }
        if let Some(condition) = &self.condition {
            let renumbered = change_marked(condition, &mut |anchor| anchor.renumbered(renumber).map(|anchor| marked(&anchor)).ok_or_else(|| ApiError::not_found("a step not held")));
            pick.condition = Some(renumbered.ok()?);
        }
        Some(pick)
    }
}

/// `condition` with each anchor marked in it replaced by what it finds.
fn resolve_marked(condition: &Map<String, Value>, context: &mut ResolveContext<'_>) -> Result<Map<String, Value>, ApiError> {
    change_marked(condition, &mut |anchor| anchor.resolve(context))
}

/// `condition` with each anchor marked in it, at any depth, replaced by
/// what `change` makes of it. The keys of a condition are paths that may
/// hold dots, so it is walked here rather than by path.
fn change_marked(condition: &Map<String, Value>, change: &mut impl FnMut(Anchor) -> Result<Value, ApiError>) -> Result<Map<String, Value>, ApiError> {
    let mut changed = Map::new();
    for (key, value) in condition {
        changed.insert(key.clone(), change_value(key, value, change)?);
    }
    Ok(changed)
}

fn change_value(key: &str, value: &Value, change: &mut impl FnMut(Anchor) -> Result<Value, ApiError>) -> Result<Value, ApiError> {
    if let Some(anchor) = as_anchor(value) {
        return change(anchor);
    }
    if is_marked(value) {
        return Err(ApiError::invalid_params(format!("{key} in the where is marked as an anchor but is not one: {}", super::why_not_an_anchor(value))));
    }
    Ok(match value {
        Value::Object(fields) => Value::Object(change_marked(fields, change)?),
        Value::Array(items) => Value::Array(items.iter().map(|item| change_value(key, item, change)).collect::<Result<_, _>>()?),
        other => other.clone(),
    })
}

/// One step of a pick's list path: a key, an index, a filter of a list's
/// items, or a key gathered at any depth.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ListStep {
    Key(String),
    Index(usize),
    /// `[field=value]`: the items whose field is the value.
    Filter(String, String),
    /// `..key`: every value called `key`, at any depth.
    Deep(String),
}

/// `path` split into its steps, as a pick's `list` is written.
fn list_path(path: &str) -> Result<Vec<ListStep>, ApiError> {
    let invalid = |why: &str| {
        ApiError::invalid_params(format!(
            "'{path}' is not a list path ({why}); write keys with dots, an index or field=value in brackets, and ..key for a key at any depth, such as job.filesystems[kind=FAT].entries or job..children"
        ))
    };
    let mut steps = Vec::new();
    let mut characters = path.chars().peekable();
    let mut first = true;
    while characters.peek().is_some() {
        let deep = !first && {
            if characters.next() != Some('.') {
                return Err(invalid("a key follows a dot"));
            }
            characters.next_if_eq(&'.').is_some()
        };
        first = false;
        let mut key = String::new();
        while let Some(character) = characters.next_if(|character| *character != '.' && *character != '[') {
            key.push(character);
        }
        match (key.is_empty(), deep) {
            (false, true) => steps.push(ListStep::Deep(key)),
            (false, false) => steps.push(ListStep::Key(key)),
            (true, true) => return Err(invalid("a key follows ..")),
            (true, false) if characters.peek() != Some(&'[') => return Err(invalid("a key is empty")),
            (true, false) => {}
        }
        while characters.next_if_eq(&'[').is_some() {
            let inside: String = characters.by_ref().take_while(|character| *character != ']').collect();
            match inside.split_once('=') {
                Some((field, value)) if !field.trim().is_empty() => steps.push(ListStep::Filter(field.trim().to_string(), value.trim().to_string())),
                _ => steps.push(ListStep::Index(inside.trim().parse().map_err(|_| invalid("an index is a number, a filter field=value"))?)),
            }
        }
    }
    Ok(steps)
}

/// The items of the list `path` names in `entry`, step `step`'s. A plain
/// path names one list; one with filters or `..` gathers what it reaches:
/// the items of each list reached, and each other value reached as an item.
fn items_at<'a>(entry: &'a Value, path: &str, step: u64) -> Result<Vec<&'a Value>, ApiError> {
    let steps = list_path(path)?;
    if steps.iter().all(|step| matches!(step, ListStep::Key(_) | ListStep::Index(_))) {
        let list = value_at(entry, path)?.ok_or_else(|| ApiError::not_found(format!("step {step} has nothing at {path}")))?;
        return list.as_array().map(|items| items.iter().collect()).ok_or_else(|| ApiError::invalid_params(format!("{path} of step {step} is not a list")));
    }
    let mut reached = vec![entry];
    for list_step in &steps {
        let mut next = Vec::new();
        for value in reached {
            match (list_step, value) {
                (ListStep::Key(key), Value::Array(items)) => next.extend(items.iter().filter_map(|item| item.get(key.as_str()))),
                (ListStep::Key(key), value) => next.extend(value.get(key.as_str())),
                (ListStep::Index(index), value) => next.extend(value.get(*index)),
                (ListStep::Filter(field, wanted), Value::Array(items)) => next.extend(items.iter().filter(|item| field_is(item, field, wanted))),
                (ListStep::Filter(field, wanted), value) => next.extend(field_is(value, field, wanted).then_some(value)),
                (ListStep::Deep(key), value) => gather(value, key, &mut next),
            }
        }
        reached = next;
    }
    let mut items = Vec::new();
    for value in reached {
        match value {
            Value::Array(inner) => items.extend(inner),
            other => items.push(other),
        }
    }
    Ok(items)
}

/// Whether `item`'s field at `path` is `wanted`, written as text.
fn field_is(item: &Value, path: &str, wanted: &str) -> bool {
    match field_of(item, path) {
        Some(Value::String(text)) => text == wanted,
        Some(other) => serde_json::from_str::<Value>(wanted).is_ok_and(|parsed| parsed == *other) || same_value(other, &Value::String(wanted.to_string())),
        None => false,
    }
}

/// Every value called `key` in `value`, at any depth, depth first.
fn gather<'a>(value: &'a Value, key: &str, found: &mut Vec<&'a Value>) {
    match value {
        Value::Object(fields) => {
            for (name, inner) in fields {
                if name == key {
                    found.push(inner);
                }
                gather(inner, key, found);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| gather(item, key, found)),
        _ => {}
    }
}

/// A warning when the list at `path` of step `step` is one page of more:
/// the object holding it has a `next` cursor, so a pick saw only some of
/// the items.
fn only_a_page(entry: &Value, path: &str, step: u64) -> Option<String> {
    let (holder, _) = path.rsplit_once('.')?;
    let cursor = value_at(entry, holder).ok().flatten()?.get("next").filter(|next| !next.is_null())?;
    Some(format!(
        "the pick on {path} of step {step} saw only the first page: {holder} has a next cursor ({cursor}), so items on later pages were not looked at; ask that step for more with a larger limit"
    ))
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
                literal => field_of(item, path).is_some_and(|value| same_value(value, literal)),
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
            "equals" => value.is_some_and(|value| same_value(value, wanted)),
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
                let bound = number_of(wanted).ok_or_else(|| ApiError::invalid_params(format!("the {test} for {path} is {wanted}, which is not a number")))?;
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

/// Whether a field's value is the value wanted: equal, or both numbers
/// (or text that reads as one) of the same size, so a field shown as
/// `0x10` is 16.
fn same_value(value: &Value, wanted: &Value) -> bool {
    value == wanted || number_of(value).zip(number_of(wanted)).is_some_and(|(value, wanted)| value == wanted)
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
            (path, value) if is_marked(value) => format!("{path} is {}", describe_value(value)),
            (path, Value::Object(tests)) => {
                let tests: Vec<String> = tests
                    .iter()
                    .map(|(test, value)| match (test.as_str(), value) {
                        ("regex", Value::String(pattern)) => format!("{path} matches /{pattern}/"),
                        ("equals", value) => format!("{path} is {}", describe_value(value)),
                        ("contains", value) => format!("{path} contains {}", describe_value(value)),
                        ("min", value) => format!("{path} is at least {}", describe_value(value)),
                        ("max", value) => format!("{path} is at most {}", describe_value(value)),
                        (test, value) => format!("{path} {test} {}", describe_value(value)),
                    })
                    .collect();
                tests.join(" and ")
            }
            (path, value) => format!("{path} is {value}"),
        })
        .collect();
    parts.join(" and ")
}

/// A value of a condition in words: an anchor marked there as what it
/// finds, any other value as JSON.
fn describe_value(value: &Value) -> String {
    as_anchor(value).map_or_else(|| value.to_string(), |anchor| anchor.describe())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::api::Workspace;

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

    /// Resolve `pick` against earlier steps `done`, with `reply` bound to 1406 and `seq` to
    /// "0x2a"; what it chose and the warnings.
    fn pick_from(done: &std::collections::BTreeMap<u64, Value>, pick: Value) -> (Result<Value, ApiError>, Vec<String>) {
        let mut workspace = crate::api::test_support::workspace_with("a.bin", b"abc");
        workspace.journal_mut().bind_variable("reply", json!(1406), Some(1));
        workspace.journal_mut().bind_variable("seq", json!("0x2a"), Some(1));
        let sheets = RunSheets::on("doc-1");
        let parameters = std::collections::BTreeMap::new();
        let mut context = ResolveContext { workspace: &mut workspace, doc: None, steps: done, parameters: &parameters, sheets: &sheets, warnings: Vec::new() };
        let pick: Pick = serde_json::from_value(pick).unwrap();
        let chosen = pick.resolve(&mut context);
        (chosen, context.warnings)
    }

    #[test]
    fn the_unlock_request_is_picked_by_the_sequence_number_its_reply_carries() {
        let packets = json!([
            {"index": 917, "template": {"type": 60, "seq": 41}},
            {"index": 1405, "template": {"type": 60, "seq": 42}},
            {"index": 1406, "template": {"type": 61, "seq": 42}},
            {"index": 1425, "template": {"type": 60, "seq": 43}},
        ]);
        let done = std::collections::BTreeMap::from([(4, json!({"params": {}, "result": {"packets": packets}}))]);
        let by_seq = json!({"step": 4, "list": "result.packets", "where": {"template.seq": {"$var": "seq"}, "template.type": 60}, "field": "index"});
        assert_eq!(pick_from(&done, by_seq).0.unwrap(), json!(1405), "the variable's 0x2a is the field's 42");
        let before_reply = json!({"step": 4, "list": "result.packets", "where": {"index": {"max": {"$var": "reply"}}}, "sort": {"by": "index", "order": "descending"}, "nth": 1, "field": "index"});
        assert_eq!(pick_from(&done, before_reply).0.unwrap(), json!(1405));
        let unbound = pick_from(&done, json!({"step": 4, "list": "result.packets", "where": {"index": {"$var": "missing"}}})).0.unwrap_err();
        assert!(unbound.message.contains("no value is bound to $missing"), "{}", unbound.message);
        let condition = json!({"template.seq": {"$var": "seq"}});
        assert_eq!(describe_condition(condition.as_object().unwrap()), "template.seq is the variable $seq");
    }

    #[test]
    fn an_entry_is_picked_from_the_fat_volume_whatever_its_place_among_the_volumes() {
        let filesystems = json!([
            {"kind": "NTFS", "entries": [{"path": "/pagefile.sys", "deleted": false}]},
            {"kind": "FAT", "entries": [{"path": "/notes.txt", "deleted": false}, {"path": "/IMG_0001.JPG", "deleted": true}]},
        ]);
        let done = std::collections::BTreeMap::from([(2, json!({"params": {}, "result": {"job": "find-1"}, "job": {"filesystems": filesystems}}))]);
        let deleted = json!({"step": 2, "list": "job.filesystems[kind=FAT].entries", "where": {"deleted": true}, "field": "path"});
        assert_eq!(pick_from(&done, deleted).0.unwrap(), json!("/IMG_0001.JPG"));
        let none = pick_from(&done, json!({"step": 2, "list": "job.filesystems[kind=exFAT].entries"})).0.unwrap_err();
        assert!(none.message.contains("none of the 0 items"), "{}", none.message);
        let unclosed = pick_from(&done, json!({"step": 2, "list": "job.filesystems[kind=FAT]..", "field": "path"})).0.unwrap_err();
        assert!(unclosed.message.contains("is not a list path"), "{}", unclosed.message);
    }

    #[test]
    fn a_file_is_picked_from_an_unpacked_tree_at_any_depth() {
        let tree = json!({"name": "/", "children": [
            {"name": "bin", "children": [{"name": "busybox", "path": "bin/busybox"}, {"name": "novacamd", "path": "bin/novacamd"}]},
            {"name": "etc", "children": [{"name": "deep", "children": [{"name": "config.enc", "path": "etc/deep/config.enc"}]}]},
        ]});
        let done = std::collections::BTreeMap::from([(5, json!({"params": {}, "result": {"job": "unpack-1"}, "job": tree}))]);
        let daemon = json!({"step": 5, "list": "job..children", "where": {"name": "novacamd"}, "field": "path"});
        assert_eq!(pick_from(&done, daemon).0.unwrap(), json!("bin/novacamd"));
        let config = json!({"step": 5, "list": "job..children", "where": {"name": {"regex": "\\.enc$"}}, "field": "path"});
        assert_eq!(pick_from(&done, config).0.unwrap(), json!("etc/deep/config.enc"));
    }

    #[test]
    fn a_pick_over_one_page_of_records_warns_that_later_pages_were_not_looked_at() {
        let done = std::collections::BTreeMap::from([
            (3, json!({"params": {}, "result": {"records": [{"action": "sync"}, {"action": "delete"}], "next": "100"}})),
            (4, json!({"params": {}, "result": {"records": [{"action": "delete"}], "next": null}})),
        ]);
        let (chosen, warnings) = pick_from(&done, json!({"step": 3, "list": "result.records", "where": {"action": "delete"}}));
        assert_eq!(chosen.unwrap(), json!({"action": "delete"}));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("the pick on result.records of step 3 saw only the first page"), "{}", warnings[0]);
        let (_, last_page) = pick_from(&done, json!({"step": 4, "list": "result.records"}));
        assert!(last_page.is_empty(), "the last page has no next cursor");
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
