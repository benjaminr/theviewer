//! `vars.*`: the session's variables, values bound by name so later calls
//! can use them as `{"$var": "serial"}`.
//!
//! A variable is a clipboard with provenance. `vars.set` is journalled as
//! a step like any analysis: when its `value` was given as an anchor
//! (`{"$anchor": {"pick": …}}`), the step records the anchor, so a recipe
//! made from it finds the value again on the next file, and a later step
//! that read the variable reads that value. Undoing the step puts back the
//! value bound before, or removes the binding.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::workspace::Workspace;
use super::{ApiError, Reverse};
use crate::journal::Anchor;

/// Longest variable name.
const NAME_LIMIT: usize = 64;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[super::Method] = &[
    method!("vars.set", Analysis, set, SetParams, VariableSet, "Bind a value to a variable by name, so later calls can pass it as {\"$var\": name}: give the value as an anchor ({\"$anchor\": {\"pick\": …}}) to keep where it came from, and a recipe finds it again on the next file. Undone by putting back the value bound before.").reverses(Reverse::Variable),
    method!("vars.list", Read, list, super::values::NoParams, VariableList, "The session's variables, each with its value, the step that bound it and the anchor it was found by."),
    method!("vars.clear", Analysis, clear, ClearParams, VariablesCleared, "Remove a variable's binding, or every variable's."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, Value)> {
    use serde_json::json;
    vec![("vars.set", json!({"name": "serial", "value": "NC500-2F357657"})), ("vars.list", json!({})), ("vars.clear", json!({"name": "serial"}))]
}

/// What a call to one of this module's methods would do, in plain words.
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, params: &Value) -> Option<String> {
    match method {
        "vars.set" => Some(format!("Bind ${} to {}", params.get("name")?.as_str()?, shown(params.get("value")?))),
        "vars.clear" => Some(match params.get("name").and_then(Value::as_str) {
            Some(name) => format!("Clear ${name}"),
            None => "Clear every variable".to_string(),
        }),
        _ => None,
    }
}

/// A value as a description shows it, cut short.
fn shown(value: &Value) -> String {
    crate::text::truncate_chars(&value.to_string(), 80)
}

/// Parameters of `vars.set`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetParams {
    /// The variable's name: letters, digits, '_' or '-', such as "serial".
    pub name: String,
    /// The value: any JSON, or an anchor that finds it, such as
    /// {"$anchor": {"pick": {"step": 7, "list": "job.strings", "where": {"text": {"regex": "^NC500-"}}, "field": "text"}}}.
    pub value: Value,
}

/// The result of `vars.set`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VariableSet {
    pub name: String,
    /// The value bound, its anchor resolved.
    pub value: Value,
    /// The value it replaced, if it was bound before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced: Option<Value>,
}

/// One variable as `vars.list` gives it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Variable {
    pub name: String,
    pub value: Value,
    /// The step that bound it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<u64>,
    /// Where its value came from, when it was bound from an anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<Anchor>,
    /// That anchor in words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// The result of `vars.list`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VariableList {
    pub variables: Vec<Variable>,
}

/// Parameters of `vars.clear`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClearParams {
    /// The variable to clear; every variable when omitted.
    #[serde(default)]
    pub name: Option<String>,
}

/// The result of `vars.clear`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VariablesCleared {
    /// The variables no longer bound.
    pub cleared: Vec<String>,
}

fn check_name(name: &str) -> Result<(), ApiError> {
    let fits = !name.is_empty() && name.chars().count() <= NAME_LIMIT && name.chars().all(|character| character.is_alphanumeric() || matches!(character, '_' | '-'));
    if fits {
        return Ok(());
    }
    Err(ApiError::invalid_params(format!("'{name}' cannot name a variable: use up to {NAME_LIMIT} letters, digits, '_' or '-'")))
}

pub fn set(workspace: &mut dyn Workspace, params: SetParams) -> Result<VariableSet, ApiError> {
    check_name(&params.name)?;
    let step = workspace.journal().step_being_recorded();
    let replaced = workspace.journal_mut().bind_variable(&params.name, params.value.clone(), step);
    Ok(VariableSet { name: params.name, value: params.value, replaced: replaced.map(|binding| binding.value) })
}

pub fn list(workspace: &mut dyn Workspace, _params: super::values::NoParams) -> Result<VariableList, ApiError> {
    let journal = workspace.journal();
    let variables = journal
        .variables()
        .iter()
        .map(|(name, binding)| {
            let anchor = binding.step.and_then(|step| journal.entry(step)).and_then(|entry| entry.derived_from.get("value").cloned());
            let from = anchor.as_ref().map(Anchor::describe);
            Variable { name: name.clone(), value: binding.value.clone(), step: binding.step, anchor, from }
        })
        .collect();
    Ok(VariableList { variables })
}

pub fn clear(workspace: &mut dyn Workspace, params: ClearParams) -> Result<VariablesCleared, ApiError> {
    if let Some(name) = &params.name
        && workspace.journal().variable(name).is_none()
    {
        return Err(ApiError::not_found(format!("no value is bound to ${name}; vars.list lists the variables")));
    }
    Ok(VariablesCleared { cleared: workspace.journal_mut().unbind_variables(params.name.as_deref()) })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::{call, workspace_with};
    use crate::api::{ErrorCode, Workspace};

    #[test]
    fn a_value_bound_to_a_variable_is_passed_to_a_later_call_by_name() {
        let mut workspace = workspace_with("a.bin", b"secret!!");
        call(&mut workspace, "vars.set", json!({"name": "key", "value": "5a"})).unwrap();
        let applied = call(&mut workspace, "transform.apply", json!({"selection": {"range": [0, 2]}, "operation": {"op": "xor", "key": {"$var": "key"}}})).unwrap();
        assert!(applied.get("version").is_some(), "{applied}");
        let read = call(&mut workspace, "bytes.read", json!({"start": 0, "len": 2})).unwrap();
        assert_eq!(read["data"], "293f", "s and e XORed with 5a");
        let step = workspace.journal().entries().last().unwrap();
        assert_eq!(step.params["operation"]["key"], "5a", "the journal keeps the value");
        assert_eq!(step.derived_from["operation.key"], crate::journal::Anchor::Var { var: "key".into() }, "and where it came from");
    }

    #[test]
    fn a_variable_set_from_an_anchor_lists_where_it_came_from() {
        let mut workspace = workspace_with("a.bin", b"header MAGIC payload");
        let found = call(&mut workspace, "search.find", json!({"query": "MAGIC", "mode": "text"})).unwrap();
        assert_eq!(found["at"], 7);
        let read_step = workspace.journal().reads().last().unwrap().step;
        let anchor = json!({"$anchor": {"step": read_step, "path": "result.at"}});
        let set = call(&mut workspace, "vars.set", json!({"name": "magic", "value": anchor})).unwrap();
        assert_eq!(set["value"], 7);
        assert!(workspace.journal().entry(read_step).is_some(), "the read it cites is a step now");
        let listed = call(&mut workspace, "vars.list", json!({})).unwrap();
        let magic = &listed["variables"][0];
        assert_eq!((magic["name"].as_str(), magic["value"].as_u64()), (Some("magic"), Some(7)));
        assert_eq!(magic["anchor"], json!({"step": read_step, "path": "result.at"}));
        assert_eq!(magic["from"], format!("the value at result.at of step {read_step}"));
    }

    #[test]
    fn undoing_a_binding_puts_back_the_value_before_or_removes_it() {
        let mut workspace = workspace_with("a.bin", b"abc");
        call(&mut workspace, "vars.set", json!({"name": "serial", "value": "first"})).unwrap();
        let first = workspace.journal().last_step().unwrap();
        call(&mut workspace, "vars.set", json!({"name": "serial", "value": "second"})).unwrap();
        let second = workspace.journal().last_step().unwrap();
        call(&mut workspace, "history.undo_step", json!({"step": second})).unwrap();
        assert_eq!(workspace.journal().variable("serial").unwrap().value, "first");
        call(&mut workspace, "history.undo_step", json!({"step": first})).unwrap();
        assert!(workspace.journal().variable("serial").is_none(), "the first binding is removed");
    }

    #[test]
    fn clearing_removes_one_variable_or_all_and_an_unknown_one_is_not_found() {
        let mut workspace = workspace_with("a.bin", b"abc");
        call(&mut workspace, "vars.set", json!({"name": "a", "value": 1})).unwrap();
        call(&mut workspace, "vars.set", json!({"name": "b", "value": 2})).unwrap();
        assert_eq!(call(&mut workspace, "vars.clear", json!({"name": "a"})).unwrap()["cleared"], json!(["a"]));
        assert_eq!(call(&mut workspace, "vars.clear", json!({"name": "a"})).unwrap_err().code, ErrorCode::NotFound);
        assert_eq!(call(&mut workspace, "vars.clear", json!({})).unwrap()["cleared"], json!(["b"]));
        let unbound = call(&mut workspace, "bytes.read", json!({"start": {"$var": "a"}, "len": 1})).unwrap_err();
        assert_eq!(unbound.code, ErrorCode::NotFound);
        assert!(unbound.message.contains("no value is bound to $a"), "{}", unbound.message);
        assert_eq!(call(&mut workspace, "vars.set", json!({"name": "no spaces", "value": 1})).unwrap_err().code, ErrorCode::InvalidParams);
    }
}
