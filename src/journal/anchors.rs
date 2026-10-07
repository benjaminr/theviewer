//! Anchors: parameter values that are found when a step runs, not fixed
//! when it was recorded, so a recipe made on one file works on the next.
//!
//! An absolute offset such as 0x1F40 is right for one file and wrong for
//! another. A recipe step's parameter may therefore be an [`Anchor`] in
//! place of a literal:
//!
//! | Anchor | JSON | Means |
//! | --- | --- | --- |
//! | [`Anchor::Step`] | `{"step": 12, "path": "result.matches[0].offset"}` | a value an earlier step was given or returned |
//! | [`Anchor::Find`] | `{"find": {"hex": "7EA5"}, "nth": 0}` | where a search matches |
//! | [`Anchor::Structure`] | `{"structure": "png", "field": "IHDR.width", "part": "value"}` | a parsed field's offset, length or value |
//! | [`Anchor::Finding`] | `{"finding": {"category": "compressed", "nth": 0}}` | a finding's span |
//! | [`Anchor::Selection`] | `{"selection": "current"}` | whatever is selected when the recipe runs |
//! | [`Anchor::Param`] | `{"param": "key"}` | a value the person supplies when running the recipe |
//!
//! **How an anchor is marked in a recipe step's parameters.** Any value at
//! any depth of a step's `params` may be `{"$anchor": ANCHOR}`, an object
//! with that one key; everything else is a literal. The marker keeps a
//! literal object that happens to look like an anchor (a `selection`
//! parameter, say) from being taken for one:
//!
//! ```json
//! {"method": "packets.sets.create",
//!  "params": {"from": "length_field", "start": {"$anchor": {"find": {"hex": "7EA5"}}}, "len": 4096}}
//! ```
//!
//! In a journal entry's `derived_from`, which maps parameter paths to
//! anchors, anchors are written bare: the map says they are anchors.
//!
//! **Paths** name a value inside JSON: dotted keys and `[n]` indices, such
//! as `matches[0].offset` or `length_field.offset`. A step anchor's path
//! starts at the entry, so it begins with `result.` or `params.`.
//!
//! This module declares the types and the JSON plumbing. Resolving an
//! anchor against a document is area B's (see
//! `docs/design/history-recipes.md`); capturing one while recording is
//! area C's.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{ApiError, ErrorCode, Workspace};

/// The key that marks an anchor among a step's literal parameters.
pub const ANCHOR_KEY: &str = "$anchor";

/// A value found when a step runs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Anchor {
    /// A value an earlier step was given or returned.
    Step {
        /// The earlier step's number.
        step: u64,
        /// Where in that step's entry: `result.matches[0].offset`,
        /// `params.start`.
        path: String,
    },
    /// Where a search matches, as `search.find` would find it.
    Find {
        find: Needle,
        /// Which match, counting from 0.
        #[serde(default)]
        nth: usize,
        /// The match's offset (the default) or length.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        part: Option<Part>,
    },
    /// A field of a structure a parser recognises.
    Structure {
        /// The parser's id, such as `png`.
        structure: String,
        /// The field's dotted name, such as `IHDR.width`.
        field: String,
        /// The field's offset (the default), length or value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        part: Option<Part>,
    },
    /// A finding's span.
    Finding {
        finding: FindingMatch,
        /// The span's offset (the default) or length.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        part: Option<Part>,
    },
    /// What is selected when the step runs.
    Selection {
        selection: SelectionWhich,
        /// The selection itself (the default, as `{"range": …}` or
        /// `{"ranges": …}`), or its first range's offset or length.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        part: Option<Part>,
    },
    /// A value the person supplies when running the recipe, declared in
    /// its `parameters`.
    Param {
        /// The parameter's name.
        param: String,
    },
}

/// What a find anchor looks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Needle {
    /// Bytes written as hex, such as "7EA5".
    Hex(String),
    /// UTF-8 text.
    Text(String),
}

/// Which part of a found thing an anchor gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    /// Its offset in the document.
    Offset,
    /// Its length in bytes.
    Len,
    /// Its value (a field's decoded value, the selection itself).
    Value,
}

/// Which finding a finding anchor names: the `nth` of those that match a
/// category or whose id starts with a prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FindingMatch {
    /// The finding's category, such as `compressed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// The start of the finding's id, such as `zlib`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Which of those matching, counting from 0 in offset order.
    #[serde(default)]
    pub nth: usize,
}

/// Which selection a selection anchor means: only `"current"` for now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SelectionWhich {
    /// What is selected when the step runs.
    Current,
}

/// One parameter value of a recipe step: a literal or an anchor.
#[derive(Clone, Debug, PartialEq)]
pub enum ParamValue {
    Literal(Value),
    Anchor(Anchor),
}

impl ParamValue {
    /// The value as written in a recipe: a literal as it is, an anchor as
    /// `{"$anchor": …}`.
    pub fn to_json(&self) -> Value {
        match self {
            ParamValue::Literal(value) => value.clone(),
            ParamValue::Anchor(anchor) => marked(anchor),
        }
    }

    /// `value` as written in a recipe: `{"$anchor": …}` with a valid anchor
    /// is an anchor, anything else a literal.
    pub fn from_json(value: &Value) -> ParamValue {
        match as_anchor(value) {
            Some(anchor) => ParamValue::Anchor(anchor),
            None => ParamValue::Literal(value.clone()),
        }
    }
}

/// `anchor` marked for a step's parameters: `{"$anchor": …}`.
pub fn marked(anchor: &Anchor) -> Value {
    let mut object = serde_json::Map::new();
    object.insert(ANCHOR_KEY.to_string(), serde_json::to_value(anchor).unwrap_or(Value::Null));
    Value::Object(object)
}

/// The anchor `value` marks, when it is `{"$anchor": …}` and nothing else.
pub fn as_anchor(value: &Value) -> Option<Anchor> {
    let object = value.as_object().filter(|object| object.len() == 1)?;
    serde_json::from_value(object.get(ANCHOR_KEY)?.clone()).ok()
}

/// Every anchor marked in `params`, with its path (`start`,
/// `length_field.offset`), in the order they appear.
pub fn anchors_in(params: &Value) -> Vec<(String, Anchor)> {
    let mut found = Vec::new();
    collect_anchors(params, String::new(), &mut found);
    found
}

fn collect_anchors(value: &Value, path: String, found: &mut Vec<(String, Anchor)>) {
    if let Some(anchor) = as_anchor(value) {
        found.push((path, anchor));
        return;
    }
    match value {
        Value::Object(fields) => {
            for (key, item) in fields {
                let inner = if path.is_empty() { key.clone() } else { format!("{path}.{key}") };
                collect_anchors(item, inner, found);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_anchors(item, format!("{path}[{index}]"), found);
            }
        }
        _ => {}
    }
}

/// One step of a path: a key or an index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathStep {
    Key(String),
    Index(usize),
}

/// `path` split into keys and indices: `matches[0].offset` is
/// `matches`, `0`, `offset`.
pub fn parse_path(path: &str) -> Result<Vec<PathStep>, ApiError> {
    let invalid = || ApiError::invalid_params(format!("'{path}' is not a path; write keys with dots and indices in brackets, such as result.matches[0].offset"));
    let mut steps = Vec::new();
    for part in path.split('.') {
        let (key, mut rest) = part.split_once('[').map_or((part, ""), |(key, rest)| (key, rest));
        if !key.is_empty() {
            steps.push(PathStep::Key(key.to_string()));
        } else if rest.is_empty() {
            return Err(invalid());
        }
        while !rest.is_empty() {
            let (index, after) = rest.split_once(']').ok_or_else(invalid)?;
            steps.push(PathStep::Index(index.parse().map_err(|_| invalid())?));
            rest = match after {
                "" => "",
                after => after.strip_prefix('[').ok_or_else(invalid)?,
            };
        }
    }
    Ok(steps)
}

/// The value at `path` in `value`, if there is one.
pub fn value_at<'a>(value: &'a Value, path: &str) -> Result<Option<&'a Value>, ApiError> {
    let mut current = value;
    for step in parse_path(path)? {
        let next = match step {
            PathStep::Key(key) => current.get(key.as_str()),
            PathStep::Index(index) => current.get(index),
        };
        let Some(next) = next else { return Ok(None) };
        current = next;
    }
    Ok(Some(current))
}

/// Put `replacement` at `path` in `value`, which must already hold a value
/// there (as a literal to turn into an anchor does). Returns the value it
/// replaced.
pub fn replace_at(value: &mut Value, path: &str, replacement: Value) -> Result<Value, ApiError> {
    let mut current = value;
    for step in parse_path(path)? {
        let next = match step {
            PathStep::Key(key) => current.get_mut(key.as_str()),
            PathStep::Index(index) => current.get_mut(index),
        };
        current = next.ok_or_else(|| ApiError::not_found(format!("there is no value at '{path}'")))?;
    }
    Ok(std::mem::replace(current, replacement))
}

/// What resolving an anchor may use: the workspace and document the step
/// runs on, what earlier steps of the run were given and returned, and the
/// values the person supplied.
pub struct ResolveContext<'a> {
    pub workspace: &'a mut dyn Workspace,
    /// The document the step runs on (an id); the current one when `None`.
    pub doc: Option<String>,
    /// Each earlier step of this run by its number, as
    /// `{"params": …, "result": …}`, which step anchors' paths start in.
    pub steps: &'a BTreeMap<u64, Value>,
    /// The recipe's parameters as the person gave them.
    pub parameters: &'a BTreeMap<String, Value>,
}

impl Anchor {
    /// The value this anchor stands for now. Area B implements this; until
    /// then every anchor is `unavailable`.
    pub fn resolve(&self, _context: &mut ResolveContext<'_>) -> Result<Value, ApiError> {
        Err(ApiError::new(ErrorCode::Unavailable, "anchors cannot be resolved yet: the recipe runner is not built"))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn round_trip(anchor: Anchor, written: Value) {
        assert_eq!(serde_json::to_value(&anchor).unwrap(), written, "{anchor:?} is written as the design shows");
        assert_eq!(serde_json::from_value::<Anchor>(written).unwrap(), anchor);
    }

    #[test]
    fn every_kind_of_anchor_is_written_as_the_design_s_table_shows() {
        round_trip(Anchor::Step { step: 12, path: "result.matches[0].offset".into() }, json!({"step": 12, "path": "result.matches[0].offset"}));
        round_trip(Anchor::Find { find: Needle::Hex("7EA5".into()), nth: 0, part: None }, json!({"find": {"hex": "7EA5"}, "nth": 0}));
        round_trip(
            Anchor::Structure { structure: "png".into(), field: "IHDR.width".into(), part: Some(Part::Value) },
            json!({"structure": "png", "field": "IHDR.width", "part": "value"}),
        );
        round_trip(
            Anchor::Finding { finding: FindingMatch { category: Some("compressed".into()), id: None, nth: 0 }, part: None },
            json!({"finding": {"category": "compressed", "nth": 0}}),
        );
        round_trip(Anchor::Selection { selection: SelectionWhich::Current, part: None }, json!({"selection": "current"}));
        round_trip(Anchor::Param { param: "key".into() }, json!({"param": "key"}));
    }

    #[test]
    fn a_find_anchor_written_by_hand_may_leave_out_which_match() {
        let anchor: Anchor = serde_json::from_value(json!({"find": {"text": "PK"}})).unwrap();
        assert_eq!(anchor, Anchor::Find { find: Needle::Text("PK".into()), nth: 0, part: None });
    }

    #[test]
    fn the_anchor_schema_offers_each_kind() {
        let schema = schemars::schema_for!(Anchor).to_value();
        assert_eq!(schema["anyOf"].as_array().map(Vec::len), Some(6), "{schema}");
    }

    #[test]
    fn a_marked_anchor_is_told_apart_from_a_literal_that_looks_like_one() {
        let anchor = Anchor::Param { param: "key".into() };
        assert_eq!(marked(&anchor), json!({"$anchor": {"param": "key"}}));
        assert_eq!(ParamValue::from_json(&json!({"$anchor": {"param": "key"}})), ParamValue::Anchor(anchor.clone()));
        let literal = json!({"selection": "current"});
        assert_eq!(ParamValue::from_json(&literal), ParamValue::Literal(literal.clone()), "only the marker makes an anchor");
        assert_eq!(ParamValue::from_json(&json!({"$anchor": {"param": "key"}, "other": 1})), ParamValue::Literal(json!({"$anchor": {"param": "key"}, "other": 1})));
        assert_eq!(ParamValue::Anchor(anchor).to_json(), json!({"$anchor": {"param": "key"}}));
    }

    #[test]
    fn the_anchors_in_a_step_s_params_are_listed_with_their_paths() {
        let params = json!({
            "from": "length_field",
            "start": {"$anchor": {"find": {"hex": "7EA5"}, "nth": 0}},
            "length_field": {"offset": {"$anchor": {"param": "offset"}}, "encoding": "u16"},
            "ranges": [[{"$anchor": {"step": 3, "path": "result.offset"}}, 4]],
        });
        let paths: Vec<String> = anchors_in(&params).into_iter().map(|(path, _)| path).collect();
        assert_eq!(paths, ["length_field.offset", "ranges[0][0]", "start"]);
    }

    #[test]
    fn a_path_reaches_into_objects_and_arrays_and_a_literal_can_be_replaced_there() {
        let mut entry = json!({"result": {"matches": [{"offset": 7}, {"offset": 64}]}, "params": {"ranges": [[1, 2]]}});
        assert_eq!(value_at(&entry, "result.matches[1].offset").unwrap(), Some(&json!(64)));
        assert_eq!(value_at(&entry, "params.ranges[0][1]").unwrap(), Some(&json!(2)));
        assert_eq!(value_at(&entry, "result.matches[5].offset").unwrap(), None);
        assert!(value_at(&entry, "result.matches[x]").is_err());
        assert!(value_at(&entry, "result..matches").is_err());
        let replaced = replace_at(&mut entry, "params.ranges[0][0]", marked(&Anchor::Param { param: "start".into() })).unwrap();
        assert_eq!(replaced, json!(1));
        assert_eq!(anchors_in(&entry["params"]).len(), 1);
        assert_eq!(replace_at(&mut entry, "params.missing", json!(0)).unwrap_err().code, ErrorCode::NotFound);
    }
}
