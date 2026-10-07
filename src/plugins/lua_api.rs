//! What scripts reach the data API and the workspace bus through:
//! `theviewer.api.<namespace>.<method>{…}`, `theviewer.publish`,
//! `theviewer.subscribe` and `theviewer.register_method`.
//!
//! The API works only while one of the script's callbacks runs on the
//! window's side: an action, a subscription handler or a method it
//! registered. For that call, a [`Binding`] in the script's Lua state says
//! which workspace to call into, as whom, and what it may do:
//!
//! * an **action** is run by the person, so it may edit freely
//!   ([`Access::Granted`]), and its edits are labelled with the plugin;
//! * a **handler** reads only, unless the plugin declared
//!   `theviewer.plugin{ edits = true }`: then each edit goes through the
//!   plugin's permission, and one that must be confirmed is held for the
//!   person and answered with `{pending = true}` ([`Access::Checked`]);
//! * a **registered method** that edits was allowed when it was called,
//!   so it edits as an action does; one that reads only reads.
//!
//! Detectors and parsers get no binding: they stay pure, scanning their
//! window of bytes on background threads.
//!
//! Values cross as JSON: tables with keys 1..n become arrays and other
//! tables objects; `theviewer.array()` makes an empty array. An API error
//! is raised as a Lua error, `"<code>: <message>"`, which `pcall` catches.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Weak};

use mlua::{Function, Lua, Table, Value as LuaValue};
use serde_json::{Map, Number, Value};

use super::{ActionHost, ScriptState, lua_error};
use crate::api::permissions::{self, Caller};
use crate::api::{self, ApiError, Effect, RegisteredMethod, Workspace};
use crate::bus::topics::{CUSTOM_PREFIX, CustomTopic, LogLevel, is_custom_topic};
use crate::bus::{Draft, MessageId, Payload, Topic};

/// How deep tables may nest when they cross to JSON and back.
const MAX_DEPTH: usize = 64;
/// The registry name of the metatable that marks a table as a JSON array.
const ARRAY_MARK: &str = "theviewer.array";
/// The field set in that metatable.
const ARRAY_FLAG: &str = "__theviewer_array";
/// The registry name of the function that makes errors plain strings.
const RAISING: &str = "theviewer.raising";

/// What a callback's API calls may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Access {
    /// Read, and publish facts; no edits or view changes.
    ReadOnly,
    /// Edit within the plugin's permission, holding calls the person must confirm.
    Checked,
    /// Edit without asking: the person ran it, or allowed the call it is part of.
    Granted,
}

/// Where a callback's calls go: a workspace, or the host of an action.
#[derive(Clone, Copy, Debug)]
pub(super) enum Target {
    /// A `*mut &mut dyn Workspace`, valid while the callback runs.
    Workspace(usize),
    /// A `*mut &mut dyn ActionHost`, valid while the action runs.
    Action(usize),
}

/// What one running callback's API calls are bound to. Set in the script's
/// Lua state for the length of the callback and removed after it, so a
/// function a script kept cannot reach a workspace later.
#[derive(Clone)]
pub(super) struct Binding {
    target: Target,
    caller: Caller,
    access: Access,
    /// The plugin's name, which its own topics start with: `x.<namespace>.`.
    namespace: String,
    /// The message a handler is running for, which what it publishes says caused it.
    cause: Option<MessageId>,
    state: Weak<ScriptState>,
}

impl Binding {
    pub(super) fn new(target: Target, caller: Caller, access: Access, namespace: &str, state: &Arc<ScriptState>) -> Binding {
        Binding { target, caller, access, namespace: namespace.to_string(), cause: None, state: Arc::downgrade(state) }
    }

    /// Run `body` with the workspace the callback is bound to.
    fn with_workspace<R>(&self, body: impl FnOnce(&mut dyn Workspace) -> R) -> Result<R, String> {
        match self.target {
            Target::Workspace(pointer) => {
                // SAFETY: the pointer was made from a live `&mut dyn
                // Workspace` by `run_bound`, which holds that borrow for
                // the whole callback and removes this binding before it
                // returns. Calls are serialised by the script's Lua lock.
                let workspace = unsafe { &mut *(pointer as *mut &mut dyn Workspace) };
                Ok(body(&mut **workspace))
            }
            Target::Action(pointer) => {
                // SAFETY: as above, for the `&mut dyn ActionHost` that
                // `run_action` holds for the whole action.
                let host = unsafe { &mut *(pointer as *mut &mut dyn ActionHost) };
                match host.workspace() {
                    Some(workspace) => Ok(body(workspace)),
                    None => Err("theviewer.api is not available here".to_string()),
                }
            }
        }
    }

    /// Call `method` as this callback may.
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let result = self.with_workspace(|workspace| self.call_in(workspace, method, params))?;
        result.map_err(|error| error.to_string())
    }

    fn call_in(&self, workspace: &mut dyn Workspace, method: &str, params: Value) -> Result<Value, ApiError> {
        match self.access {
            Access::Granted => api::call_permitted(workspace, &self.caller, method, params),
            Access::ReadOnly => {
                let found = api::find(workspace, method)?;
                if permissions::needs_permission(found.needs_leave_for(&params)) {
                    return Err(ApiError::new(
                        api::ErrorCode::ReadOnly,
                        format!("{method} changes the document or the view, or writes a file, which a handler may do only when its plugin declares theviewer.plugin{{ edits = true }}"),
                    ));
                }
                api::call_permitted(workspace, &self.caller, method, params)
            }
            Access::Checked => self.call_or_hold(workspace, method, params),
        }
    }

    /// Call `method` if the plugin may, or hold it for the person: the
    /// result then is `{pending = true, message = …}`, and the outcome is
    /// logged once the person answers.
    fn call_or_hold(&self, workspace: &mut dyn Workspace, method: &str, params: Value) -> Result<Value, ApiError> {
        let answered: Rc<RefCell<Option<Result<Value, ApiError>>>> = Rc::new(RefCell::new(None));
        let now = Rc::downgrade(&answered);
        let state = self.state.clone();
        let later = method.to_string();
        let reply: permissions::ReplyTo = Box::new(move |_, result| match now.upgrade() {
            Some(cell) => *cell.borrow_mut() = Some(result),
            None => {
                let Some(state) = state.upgrade() else { return };
                match result {
                    Ok(_) => state.log(LogLevel::Info, format!("{later} was allowed and made")),
                    Err(error) => state.log(LogLevel::Error, format!("{later}: {}", error.message)),
                }
            }
        });
        api::call_or_hold(workspace, self.caller.clone(), method, params, reply);
        let outcome = answered.borrow_mut().take();
        match outcome {
            Some(result) => result,
            None => Ok(serde_json::json!({ "pending": true, "message": format!("{method} is waiting for the person to allow it") })),
        }
    }
}

/// The binding of the callback running in `lua`.
fn current(lua: &Lua) -> Result<Binding, String> {
    lua.app_data_ref::<Binding>()
        .map(|binding| binding.clone())
        .ok_or_else(|| "theviewer.api and theviewer.publish work only while an action, a subscription handler or a registered method runs".to_string())
}

/// Call `method` as the callback running in `lua` may, as `theviewer.api`
/// would: journalled, labelled with the plugin and within its access.
pub(super) fn call_bound(lua: &Lua, method: &str, params: Value) -> Result<Value, String> {
    current(lua)?.call(method, params)
}

/// A Lua function that runs `body` and raises its error as a plain string,
/// `"<code>: <message>"`, which `pcall` returns as it is.
fn raising<A: mlua::FromLuaMulti + 'static>(lua: &Lua, body: impl Fn(&Lua, A) -> Result<LuaValue, String> + Send + 'static) -> mlua::Result<Function> {
    let raw = lua.create_function(move |lua, arguments: A| match body(lua, arguments) {
        Ok(value) => Ok((true, value)),
        Err(message) => Ok((false, LuaValue::String(lua.create_string(message)?))),
    })?;
    let wrap: Function = match lua.named_registry_value::<Function>(RAISING) {
        Ok(wrap) => wrap,
        Err(_) => {
            let wrap = lua
                .load("local raw = ... return function(...) local ok, result = raw(...) if ok then return result end error(result, 0) end")
                .set_name("theviewer")
                .into_function()?;
            lua.set_named_registry_value(RAISING, &wrap)?;
            wrap
        }
    };
    wrap.call(raw)
}

/// Run `body` in `state` with `binding` in force, and without it after.
pub(super) fn run_bound<R>(state: &ScriptState, binding: Binding, body: impl FnOnce(&Lua) -> Result<R, String>) -> Result<R, String> {
    state.with_lua(|lua| {
        lua.set_app_data(binding);
        let result = body(lua);
        lua.remove_app_data::<Binding>();
        result
    })
}

/// Run `body` bound to `workspace`.
pub(super) fn run_in_workspace<R>(
    state: &Arc<ScriptState>,
    workspace: &mut dyn Workspace,
    caller: Caller,
    access: Access,
    namespace: &str,
    cause: Option<MessageId>,
    body: impl FnOnce(&Lua) -> Result<R, String>,
) -> Result<R, String> {
    let mut workspace_ref: &mut dyn Workspace = workspace;
    let target = Target::Workspace((&mut workspace_ref as *mut &mut dyn Workspace) as usize);
    let mut binding = Binding::new(target, caller, access, namespace, state);
    binding.cause = cause;
    run_bound(state, binding, body)
}

// ---------------------------------------------------------------------------
// JSON and Lua values
// ---------------------------------------------------------------------------

/// A JSON value as a Lua value; arrays are marked so they come back as arrays.
pub(super) fn json_to_lua(lua: &Lua, value: &Value) -> mlua::Result<LuaValue> {
    Ok(match value {
        Value::Null => LuaValue::Nil,
        Value::Bool(flag) => LuaValue::Boolean(*flag),
        Value::Number(number) => match number.as_i64() {
            Some(integer) => LuaValue::Integer(integer),
            None => LuaValue::Number(number.as_f64().unwrap_or(f64::NAN)),
        },
        Value::String(text) => LuaValue::String(lua.create_string(text)?),
        Value::Array(items) => {
            let table = lua.create_table_with_capacity(items.len(), 0)?;
            for (index, item) in items.iter().enumerate() {
                table.raw_set(index + 1, json_to_lua(lua, item)?)?;
            }
            table.set_metatable(Some(array_mark(lua)?))?;
            LuaValue::Table(table)
        }
        Value::Object(fields) => {
            let table = lua.create_table_with_capacity(0, fields.len())?;
            for (key, item) in fields {
                table.raw_set(key.as_str(), json_to_lua(lua, item)?)?;
            }
            LuaValue::Table(table)
        }
    })
}

/// The metatable that marks a table as a JSON array.
fn array_mark(lua: &Lua) -> mlua::Result<Table> {
    if let Ok(mark) = lua.named_registry_value::<Table>(ARRAY_MARK) {
        return Ok(mark);
    }
    let mark = lua.create_table()?;
    mark.raw_set(ARRAY_FLAG, true)?;
    lua.set_named_registry_value(ARRAY_MARK, &mark)?;
    Ok(mark)
}

/// A Lua value as JSON. Tables keyed 1..n, and tables marked as arrays,
/// are arrays; other tables are objects with string keys.
pub(super) fn lua_to_json(value: &LuaValue) -> Result<Value, String> {
    to_json_at(value, 0)
}

fn to_json_at(value: &LuaValue, depth: usize) -> Result<Value, String> {
    if depth > MAX_DEPTH {
        return Err(format!("tables nest more than {MAX_DEPTH} deep"));
    }
    match value {
        LuaValue::Nil => Ok(Value::Null),
        LuaValue::Boolean(flag) => Ok(Value::Bool(*flag)),
        LuaValue::Integer(integer) => Ok(Value::from(*integer)),
        LuaValue::Number(number) => Number::from_f64(*number).map(Value::Number).ok_or_else(|| format!("{number} is not a number JSON can hold")),
        LuaValue::String(text) => match text.to_str() {
            Ok(text) => Ok(Value::String(text.to_string())),
            Err(_) => Err("a string is not UTF-8 text; give bytes as hex, with theviewer.hex(bytes)".to_string()),
        },
        LuaValue::Table(table) => table_to_json(table, depth),
        other => Err(format!("a {} cannot be sent to the API", other.type_name())),
    }
}

/// Longest array a table becomes, so a stray huge index cannot ask for a
/// huge allocation.
const MAX_ARRAY_LEN: usize = 1 << 20;

fn table_to_json(table: &Table, depth: usize) -> Result<Value, String> {
    let marked = is_array_mark(table);
    let mut entries: Vec<(LuaValue, LuaValue)> = Vec::new();
    for pair in table.pairs::<LuaValue, LuaValue>() {
        entries.push(pair.map_err(|error| error.to_string())?);
    }
    let length = entries.len();
    let is_sequence = length > 0 && entries.iter().all(|(key, _)| matches!(key, LuaValue::Integer(index) if *index >= 1 && (*index as usize) <= length));
    if marked || is_sequence {
        // A JSON null in an array arrives in Lua as a hole, so a marked
        // array runs to its highest index, the holes null again. (Nulls at
        // the end leave no trace in Lua and are lost.)
        let highest = entries.iter().filter_map(|(key, _)| if let LuaValue::Integer(index) = key { usize::try_from(*index).ok() } else { None }).max().unwrap_or(0);
        if highest > MAX_ARRAY_LEN {
            return Err(format!("an array reaches index {highest}, more than {MAX_ARRAY_LEN}"));
        }
        let length = length.max(highest);
        let mut items = vec![Value::Null; length];
        for (key, item) in &entries {
            let LuaValue::Integer(index) = key else { return Err("an array has a key that is not a whole number".to_string()) };
            let slot = items.get_mut((*index as usize).wrapping_sub(1)).ok_or("an array has gaps")?;
            *slot = to_json_at(item, depth + 1)?;
        }
        return Ok(Value::Array(items));
    }
    let mut fields = Map::new();
    for (key, item) in &entries {
        let key = match key {
            LuaValue::String(text) => text.to_str().map_err(|_| "a table key is not UTF-8 text".to_string())?.to_string(),
            LuaValue::Integer(index) => index.to_string(),
            other => return Err(format!("a table key is a {}, not a string", other.type_name())),
        };
        fields.insert(key, to_json_at(item, depth + 1)?);
    }
    Ok(Value::Object(fields))
}

/// Whether `table` carries the array mark.
fn is_array_mark(table: &Table) -> bool {
    let Some(meta) = table.metatable() else { return false };
    meta.raw_get::<bool>(ARRAY_FLAG).unwrap_or(false)
}

fn runtime(message: impl Into<String>) -> mlua::Error {
    mlua::Error::RuntimeError(message.into())
}

// ---------------------------------------------------------------------------
// The `theviewer` functions
// ---------------------------------------------------------------------------

/// A Lua function that calls the API method `name` with its one table of
/// parameters, as the running callback may.
fn method_function(lua: &Lua, name: String) -> mlua::Result<Function> {
    raising(lua, move |lua, params: LuaValue| {
        let binding = current(lua)?;
        let params = lua_to_json(&params).map_err(|problem| format!("invalid_params: {name}: {problem}"))?;
        let result = binding.call(&name, params)?;
        json_to_lua(lua, &result).map_err(|error| error.to_string())
    })
}

/// A table of a namespace's methods; a method not in the table (one a
/// plugin registered later) is made when first asked for.
fn namespace_table(lua: &Lua, namespace: &str) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    for method in api::METHODS.iter().filter(|method| method.namespace() == namespace) {
        let short = method.name.split_once('.').map_or(method.name, |(_, short)| short);
        table.set(short, method_function(lua, method.name.to_string())?)?;
    }
    let meta = lua.create_table()?;
    let prefix = namespace.to_string();
    meta.set(
        "__index",
        lua.create_function(move |lua, (table, key): (Table, String)| {
            let function = method_function(lua, format!("{prefix}.{key}"))?;
            table.raw_set(key, function.clone())?;
            Ok(function)
        })?,
    )?;
    table.set_metatable(Some(meta))?;
    Ok(table)
}

/// `theviewer.api`: a table per namespace of the method table, and any
/// other namespace (a plugin's) made when first asked for.
fn api_table(lua: &Lua, publish: Function) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    let mut namespaces: Vec<&str> = api::METHODS.iter().map(|method| method.namespace()).collect();
    namespaces.dedup();
    for namespace in namespaces {
        table.set(namespace, namespace_table(lua, namespace)?)?;
    }
    table.set("publish", publish)?;
    let meta = lua.create_table()?;
    meta.set(
        "__index",
        lua.create_function(|lua, (table, key): (Table, String)| {
            let namespace = namespace_table(lua, &key)?;
            table.raw_set(key, namespace.clone())?;
            Ok(namespace)
        })?,
    )?;
    table.set_metatable(Some(meta))?;
    Ok(table)
}

/// Topics plugins may not publish: what the app itself says happened, to
/// the documents, the cursor and selection, its jobs, its journal and its
/// plugins' log. Every topic is named, so a new one must be decided on.
fn published_only_by_the_app(topic: Topic) -> bool {
    match topic {
        Topic::DocumentOpened
        | Topic::DocumentClosed
        | Topic::DocumentEdited
        | Topic::CursorMoved
        | Topic::SelectionChanged
        | Topic::JobStarted
        | Topic::JobProgress
        | Topic::JobFinished
        | Topic::PluginLog
        | Topic::JournalRecorded => true,
        Topic::ViewJump
        | Topic::PaneShow
        | Topic::ViewPointed
        | Topic::FindingsPublished
        | Topic::StructureIdentified
        | Topic::FieldsDecoded
        | Topic::TemplateApplied
        | Topic::RegionsMapped
        | Topic::RecordWidthEstimated
        | Topic::FramesDefined
        | Topic::FieldsGuessed
        | Topic::ProtocolIdentified
        | Topic::ReferenceFocus
        | Topic::TemplateApplyRequested
        | Topic::Custom => false,
    }
}

/// The payload of a message on `topic`, checked against the topic's type,
/// or free-form on one of the plugin's own topics.
fn payload_for(binding: &Binding, topic: &str, payload: Value) -> Result<Payload, String> {
    if is_custom_topic(topic) {
        let own = format!("{CUSTOM_PREFIX}{}.", binding.namespace);
        if !topic.starts_with(&own) {
            return Err(format!("a plugin's own topics start with {own}, so '{topic}' is not this plugin's"));
        }
        return Ok(Payload::Custom(CustomTopic { name: topic.to_string(), payload }));
    }
    let known = Topic::named(topic).ok_or_else(|| format!("there is no topic '{topic}'; publish a built-in topic, or one of your own named {CUSTOM_PREFIX}{}.<name>", binding.namespace))?;
    if published_only_by_the_app(known) {
        return Err(format!("{topic} is published by the app itself; change the document or the selection through theviewer.api, and log with theviewer.log, instead"));
    }
    serde_json::from_value(serde_json::json!({ "topic": topic, "payload": payload })).map_err(|error| format!("the payload does not fit {topic}: {error}; api.describe lists each topic's payload"))
}

/// `theviewer.publish(topic, payload, options)`: publish on the bus as the
/// plugin, about the current document. `options` may give `key`, `span`
/// (`{start, len}`) and `confidence`.
fn publish_function(lua: &Lua) -> mlua::Result<Function> {
    raising(lua, |lua, (topic, payload, options): (String, LuaValue, Option<Table>)| {
        let binding = current(lua)?;
        let payload = lua_to_json(&payload).map_err(|problem| format!("invalid_params: publish {topic}: {problem}"))?;
        let payload = payload_for(&binding, &topic, payload).map_err(|problem| format!("invalid_params: {problem}"))?;
        let mut draft = Draft::new(binding.caller.producer(), payload);
        if let Some(options) = &options {
            draft = with_options(draft, options).map_err(|error| format!("invalid_params: publish {topic}: {error}"))?;
        }
        if let Some(cause) = binding.cause {
            draft = draft.caused_by(cause);
        }
        binding.with_workspace(|workspace| {
            if let Some(doc) = workspace.current_document() {
                let version = workspace.documents().into_iter().find(|info| info.id == doc).map_or(0, |info| info.version);
                draft = draft.clone().about(doc, version);
            }
            workspace.bus().publish(draft);
        })?;
        Ok(LuaValue::Nil)
    })
}

/// `draft` with the `key`, `span` and `confidence` that `options` gives.
fn with_options(mut draft: Draft, options: &Table) -> mlua::Result<Draft> {
    if let Some(key) = options.get::<Option<String>>("key")? {
        draft = draft.key(key);
    }
    if let Some(span) = options.get::<Option<Table>>("span")? {
        draft = draft.span(span.get::<usize>("start")?, span.get::<usize>("len")?);
    }
    if let Some(confidence) = options.get::<Option<f32>>("confidence")? {
        draft = draft.confidence(confidence);
    }
    Ok(draft)
}

/// Install `theviewer.api`, `theviewer.publish`, `theviewer.array`,
/// `theviewer.hex` and `theviewer.unhex` into `theviewer`.
pub(super) fn install(lua: &Lua, theviewer: &Table) -> mlua::Result<()> {
    let publish = publish_function(lua)?;
    theviewer.set("api", api_table(lua, publish.clone())?)?;
    theviewer.set("publish", publish)?;
    theviewer.set(
        "array",
        lua.create_function(|lua, items: Option<Table>| {
            let table = match items {
                Some(table) => table,
                None => lua.create_table()?,
            };
            table.set_metatable(Some(array_mark(lua)?))?;
            Ok(table)
        })?,
    )?;
    theviewer.set("hex", lua.create_function(|_, bytes: mlua::LuaString| Ok(crate::ops::to_compact_hex(&bytes.as_bytes())))?)?;
    theviewer.set(
        "unhex",
        lua.create_function(|lua, text: String| {
            let bytes = crate::ops::parse_hex(&text).ok_or_else(|| runtime(format!("'{text}' is not hex bytes")))?;
            lua.create_string(bytes)
        })?,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Methods scripts register
// ---------------------------------------------------------------------------

/// The simple types a parameter map may name.
const SIMPLE_TYPES: [&str; 6] = ["integer", "number", "string", "boolean", "object", "array"];

/// The types JSON Schema's `type` keyword names.
const JSON_SCHEMA_TYPES: [&str; 7] = ["object", "array", "string", "integer", "number", "boolean", "null"];

/// A method's parameter schema from a script: a JSON schema, or a simple
/// map of names to types, such as `{ start = "integer", len = "integer?" }`,
/// where `?` makes one optional. See [`is_full_schema`] for which is which.
pub(super) fn params_schema(value: &LuaValue) -> Result<Value, String> {
    let json = lua_to_json(value)?;
    let Value::Object(fields) = &json else {
        return match json {
            Value::Null => Ok(serde_json::json!({ "type": "object", "properties": {}, "additionalProperties": false })),
            _ => Err("params must be a table".to_string()),
        };
    };
    if is_full_schema(fields) {
        return Ok(json);
    }
    let mut properties = Map::new();
    let mut required = Vec::new();
    for (name, kind) in fields {
        let kind = kind.as_str().ok_or_else(|| format!("params.{name} must name a type, such as \"integer\""))?;
        let (kind, optional) = kind.strip_suffix('?').map_or((kind, false), |kind| (kind, true));
        if !SIMPLE_TYPES.contains(&kind) {
            return Err(format!("params.{name}: '{kind}' is not one of {}", SIMPLE_TYPES.join(", ")));
        }
        properties.insert(name.clone(), serde_json::json!({ "type": kind }));
        if !optional {
            required.push(Value::String(name.clone()));
        }
    }
    Ok(serde_json::json!({ "type": "object", "properties": properties, "required": required, "additionalProperties": false }))
}

/// Whether a schema table is a full JSON Schema rather than a simple map:
/// its `type` names a JSON Schema type and no other key declares a
/// parameter the simple way (its value a simple type, such as "integer" or
/// "string?"). So `{ type = "object", properties = {…} }` is a schema,
/// while `{ type = "string", value = "integer" }` declares two parameters,
/// one of them called `type`.
fn is_full_schema(fields: &Map<String, Value>) -> bool {
    let names_a_schema_type = fields.get("type").and_then(Value::as_str).is_some_and(|kind| JSON_SCHEMA_TYPES.contains(&kind));
    let declares_parameters = fields
        .iter()
        .filter(|(name, _)| name.as_str() != "type")
        .any(|(_, kind)| kind.as_str().is_some_and(is_simple_declaration));
    names_a_schema_type && !declares_parameters
}

/// Whether `kind` is how a simple map declares a parameter: "integer", "string?"…
fn is_simple_declaration(kind: &str) -> bool {
    SIMPLE_TYPES.contains(&kind.strip_suffix('?').unwrap_or(kind))
}

/// Check `params` against a method's schema: an object, with the required
/// parameters, no unknown ones when the schema closes them, and each of
/// the right simple type.
pub(super) fn check_params(schema: &Value, params: &Value) -> Result<(), ApiError> {
    let Value::Object(given) = params else {
        return Err(ApiError::invalid_params("the parameters must be an object"));
    };
    for name in schema["required"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        if !given.contains_key(name) {
            return Err(ApiError::invalid_params(format!("'{name}' is missing; see the method's params schema in api.describe")));
        }
    }
    let properties = schema["properties"].as_object();
    for (name, value) in given {
        let Some(property) = properties.and_then(|properties| properties.get(name)) else {
            if schema["additionalProperties"] == false {
                return Err(ApiError::invalid_params(format!("'{name}' is not a parameter of this method")));
            }
            continue;
        };
        let fits = match property["type"].as_str() {
            Some("integer") => value.is_i64() || value.is_u64(),
            Some("number") => value.is_number(),
            Some("string") => value.is_string(),
            Some("boolean") => value.is_boolean(),
            Some("object") => value.is_object(),
            Some("array") => value.is_array(),
            _ => true,
        };
        if !fits {
            return Err(ApiError::invalid_params(format!("'{name}' should be {}, not {value}", property["type"])));
        }
    }
    Ok(())
}

/// Whether `name` may name a method a plugin called `namespace` registers:
/// `<namespace>.<method>`, lower case, outside the table's namespaces.
pub(super) fn check_method_name(name: &str, namespace: &str) -> Result<(), String> {
    let Some((prefix, method)) = name.split_once('.') else {
        return Err(format!("a method's name is <plugin>.<name>, such as {namespace}.decode; '{name}' has no dot"));
    };
    if prefix != namespace {
        return Err(format!("this plugin's methods are named {namespace}.<name>, so '{name}' is not one of them"));
    }
    if api::METHODS.iter().any(|known| known.namespace() == prefix) {
        return Err(format!("{prefix} is one of the API's own namespaces; name the plugin something else"));
    }
    if method.is_empty() || !method.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return Err(format!("'{method}' must be lower-case letters, digits and underscores"));
    }
    Ok(())
}

/// What a script registered with `theviewer.register_method`, before the
/// method joins the table.
pub(super) struct MethodSpec {
    pub name: String,
    pub summary: String,
    pub effect: Effect,
    pub params: Value,
    pub result: Value,
    pub run: mlua::RegistryKey,
}

/// The method `spec` describes, run by `state` for the plugin `plugin`.
pub(super) fn registered_method(spec: MethodSpec, state: &Arc<ScriptState>, plugin: &str, namespace: &str) -> RegisteredMethod {
    let MethodSpec { name, summary, effect, params, result, run } = spec;
    let run = Arc::new(run);
    let weak = Arc::downgrade(state);
    let plugin = plugin.to_string();
    let namespace = namespace.to_string();
    let schema = params.clone();
    let method_name = name.clone();
    RegisteredMethod {
        owner: Caller::Plugin(plugin.clone()).producer(),
        name,
        summary,
        effect,
        params,
        result,
        run: Box::new(move |workspace, _caller, params| {
            let params = if params.is_null() { Value::Object(Map::new()) } else { params };
            check_params(&schema, &params)?;
            let state = weak.upgrade().ok_or_else(|| ApiError::new(api::ErrorCode::Unavailable, format!("the plugin {plugin} was unloaded")))?;
            // The call itself was allowed, so an edit method's edits are too.
            let access = if effect == Effect::Edit { Access::Granted } else { Access::ReadOnly };
            let result = run_in_workspace(&state, workspace, Caller::Plugin(plugin.clone()), access, &namespace, None, |lua| {
                let function: Function = lua.registry_value(&run).map_err(|error| error.to_string())?;
                let api: Table = lua.globals().get::<Table>("theviewer").and_then(|theviewer| theviewer.get("api")).map_err(|error| error.to_string())?;
                let params = json_to_lua(lua, &params).map_err(|error| error.to_string())?;
                let returned: LuaValue = function.call((params, api)).map_err(|error| lua_error(&method_name, error))?;
                lua_to_json(&returned).map_err(|problem| format!("{method_name} returned something JSON cannot hold: {problem}"))
            });
            result.map_err(|message| {
                state.log(LogLevel::Error, message.clone());
                ApiError::plugin_failed(message)
            })
        }),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::{self, Caller, ErrorCode, Policy};
    use crate::app::{Launch, ViewerApp};
    use crate::bus::topics::{FramesDefined, LogLevel, PluginLog, ProtocolIdentified};
    use crate::bus::{Payload, Topic};

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        app
    }

    fn load(app: &mut ViewerApp, name: &str, source: &str) {
        app.load_plugin_source(name, source).unwrap_or_else(|error| panic!("{name}: {error}"));
    }

    /// The lines plugins logged, from the bus, as "plugin: text".
    fn logged(app: &ViewerApp, level: LogLevel) -> Vec<String> {
        app.bus
            .recent()
            .filter_map(|message| message.payload_as::<PluginLog>())
            .filter(|line| line.level == level)
            .map(|line| format!("{}: {}", line.plugin, line.text))
            .collect()
    }

    fn publish_frames(app: &mut ViewerApp, frames: &[(usize, usize)]) {
        app.publish("tool:protocol", Payload::FramesDefined(FramesDefined::new(frames.iter().copied(), "test")));
        app.run_bus();
    }

    #[test]
    fn an_action_reads_and_edits_through_the_api_without_asking() {
        let mut app = app_with(b"hello world");
        load(
            &mut app,
            "shout.lua",
            r#"theviewer.register_action{ id = "shout", title = "Shout", run = function()
                local read = theviewer.api.bytes.read{ start = 0, len = 5, encoding = "text" }
                theviewer.api.bytes.write{ start = 0, data = read.data:upper(), encoding = "text" }
            end }"#,
        );
        app.run_plugin_action("shout");
        assert!(app.confirmations.is_empty(), "the person ran the action, so nothing is asked");
        assert_eq!(app.document.read_range(0, 11), b"HELLO world");
        assert_eq!(app.document.undo_label(), Some("Overwrite 5 bytes by plugin:shout.lua"));
    }

    #[test]
    fn an_actions_host_replace_is_journalled_as_the_plugins_edit() {
        let mut app = app_with(b"hello world");
        load(&mut app, "uppercase_selection.lua", include_str!("../../plugins/uppercase_selection.lua"));
        crate::plugins::ActionHost::select(&mut app, 6, 5);
        app.run_plugin_action("uppercase-selection");
        assert_eq!(app.document.read_range(0, 11), b"hello WORLD");
        assert_eq!(app.status, "Uppercased 5 bytes");
        assert_eq!(app.document.undo_label(), Some("Replace 5 bytes by plugin:uppercase_selection.lua"));
        let step = app.journal.entries().rev().find(|entry| entry.method == "bytes.replace").expect("the edit is in the journal");
        assert_eq!(step.caller, "plugin:uppercase_selection.lua");
        assert_eq!(step.params, json!({"start": 6, "len": 5, "data": "574f524c44"}));
    }

    #[test]
    fn the_api_is_out_of_reach_outside_callbacks_and_errors_can_be_caught() {
        let mut app = app_with(b"abc");
        let refused = app.load_plugin_source("early.lua", "theviewer.api.bytes.read{ start = 0 }");
        assert!(refused.unwrap_err().contains("work only while"), "a script cannot reach the document while it loads");
        load(
            &mut app,
            "careful.lua",
            r#"theviewer.register_action{ id = "careful", run = function(host)
                local ok, err = pcall(theviewer.api.bytes.read, { start = 99 })
                host:status(err)
            end }"#,
        );
        app.run_plugin_action("careful");
        assert!(app.status.starts_with("out_of_range:"), "{}", app.status);
    }

    #[test]
    fn a_handler_runs_for_its_topic_even_with_every_panel_hidden_and_publishes_what_it_finds() {
        let mut app = app_with(&[0x7E, 0x7E, 1, 2, 0x7E, 0x7E, 3, 4, 0, 0]);
        load(
            &mut app,
            "acme.lua",
            r#"theviewer.subscribe("frames.defined", function(message, api)
                local first = message.payload.frames[1]
                local head = api.bytes.read{ start = first.start, len = 2 }
                if head.data == "7e7e" then
                    api.publish("protocol.identified", { frames = message.payload.frames, protocol = "acme-telemetry", how = "sync word 7E 7E" })
                end
            end)"#,
        );
        publish_frames(&mut app, &[(0, 4), (4, 4)]);
        let (fact, identified) = app.bus.latest::<ProtocolIdentified>(&app.document_id()).expect("the plugin identified the frames");
        assert_eq!((identified.protocol.as_str(), identified.frames.len()), ("acme-telemetry", 2));
        assert_eq!(fact.producer(), "plugin:acme.lua");
        assert!(fact.draft.caused_by.is_some(), "it says which message it answered");
        publish_frames(&mut app, &[(8, 2)]);
        assert!(logged(&app, LogLevel::Error).is_empty(), "{:?}", logged(&app, LogLevel::Error));
    }

    #[test]
    fn a_plugin_cannot_publish_the_apps_jobs_journal_or_log() {
        let mut app = app_with(&[0u8; 16]);
        load(
            &mut app,
            "forger.lua",
            r#"theviewer.subscribe("frames.defined", function(message, api)
                for _, topic in ipairs({ "job.started", "job.progress", "job.finished", "journal.recorded", "plugin.log", "selection.changed" }) do
                    local ok, err = pcall(api.publish, topic, {})
                    theviewer.log(topic .. ": " .. tostring(ok) .. " " .. tostring(err))
                end
            end)"#,
        );
        publish_frames(&mut app, &[(0, 4)]);
        let lines = logged(&app, LogLevel::Info);
        assert_eq!(lines.len(), 6, "{lines:?}");
        for line in &lines {
            assert!(line.contains(": false invalid_params:") && line.contains("published by the app itself"), "{line}");
        }
    }

    #[test]
    fn a_payload_must_fit_its_topic_and_a_plugins_own_topics_carry_anything() {
        let mut app = app_with(&[0u8; 16]);
        load(
            &mut app,
            "chatty.lua",
            r#"theviewer.subscribe("frames.defined", function(message, api)
                api.publish("x.chatty.seen", { count = #message.payload.frames, note = "free form" }, { key = "n" })
                local ok, err = pcall(api.publish, "protocol.identified", { protocol = 7 })
                theviewer.log("wrong payload: " .. tostring(err))
                ok, err = pcall(api.publish, "x.other.seen", {})
                theviewer.log("other's topic: " .. tostring(err))
                ok, err = pcall(api.publish, "document.edited", {})
                theviewer.log("app's topic: " .. tostring(err))
            end)
            theviewer.subscribe("x.chatty.seen", function(message) theviewer.log("heard " .. message.payload.count) end)"#,
        );
        publish_frames(&mut app, &[(0, 4), (4, 4), (8, 4)]);
        let custom = app.bus.recent().find(|message| message.topic() == Topic::Custom).expect("its own topic was published");
        assert_eq!(custom.topic_name(), "x.chatty.seen");
        assert_eq!(custom.to_json()["payload"], json!({"count": 3, "note": "free form"}));
        let lines = logged(&app, LogLevel::Info).join("\n");
        assert!(lines.contains("wrong payload: ") && lines.contains("does not fit protocol.identified"), "{lines}");
        assert!(lines.contains("other's topic: ") && lines.contains("start with x.chatty."), "{lines}");
        assert!(lines.contains("app's topic: ") && lines.contains("published by the app itself"), "{lines}");
        assert!(lines.contains("chatty.lua: heard 3"), "a plugin hears its own topic: {lines}");
        let polled = api::call(&mut app, &Caller::Panel, "events.poll", json!({"topics": ["x.chatty.seen"]})).unwrap();
        assert_eq!(polled["messages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_handler_reads_only_unless_its_plugin_declares_edits() {
        let mut app = app_with(&[0u8; 16]);
        load(&mut app, "reader.lua", r#"theviewer.subscribe("frames.defined", function(message, api) api.bytes.write{ start = 0, data = "ff" } end)"#);
        publish_frames(&mut app, &[(0, 4)]);
        assert_eq!(app.document.read_range(0, 1), [0]);
        let errors = logged(&app, LogLevel::Error).join("\n");
        assert!(errors.contains("read_only") && errors.contains("edits = true"), "{errors}");

        load(
            &mut app,
            "writer.lua",
            r#"theviewer.plugin{ name = "writer", edits = true }
            theviewer.subscribe("frames.defined", function(message, api)
                local result = api.bytes.write{ start = 1, data = "ee" }
                theviewer.log(result.pending and "pending" or "written")
            end)"#,
        );
        assert!(app.editing_plugins().contains(&"writer.lua".to_string()), "Settings lists it");
        publish_frames(&mut app, &[(0, 8)]);
        assert!(logged(&app, LogLevel::Info).iter().any(|line| line == "writer.lua: pending"));
        assert_eq!(app.confirmations.current().map(|call| call.description.clone()).as_deref(), Some("Overwrite 1 byte at 0x1 with EE"));
        app.answer_confirmation(crate::confirmations::Answer::AllowOnce);
        assert_eq!(app.document.read_range(1, 1), [0xEE]);
        assert_eq!(app.document.undo_label(), Some("Overwrite 1 byte by plugin:writer.lua"));

        app.preferences.permissions.insert("plugin:writer.lua".into(), Policy::Allow);
        publish_frames(&mut app, &[(0, 12)]);
        assert!(app.confirmations.is_empty());
        assert!(logged(&app, LogLevel::Info).iter().any(|line| line == "writer.lua: written"));
    }

    #[test]
    fn a_runaway_handler_is_stopped_by_its_budget_and_the_window_carries_on() {
        let mut app = app_with(&[0u8; 16]);
        load(&mut app, "spin.lua", r#"theviewer.subscribe("frames.defined", function() while true do end end)"#);
        publish_frames(&mut app, &[(0, 4)]);
        let errors = logged(&app, LogLevel::Error).join("\n");
        assert!(errors.contains("spin.lua") && errors.contains("aborted"), "{errors}");
        publish_frames(&mut app, &[(0, 8)]);
        assert_eq!(logged(&app, LogLevel::Error).len(), 2, "it runs, and is stopped, each time");
    }

    #[test]
    fn a_registered_method_joins_the_table_and_runs_for_any_caller() {
        let mut app = app_with(&[0x7E, 0x7E, 0x10, 0x20, 0, 0, 0, 0]);
        load(
            &mut app,
            "beacon.lua",
            r#"theviewer.register_method{
                name = "beacon.decode_frame",
                summary = "Decode one beacon frame.",
                params = { start = "integer", len = "integer?" },
                run = function(params, api)
                    local frame = api.bytes.read{ start = params.start, len = params.len or 4 }
                    return { sync = frame.data:sub(1, 4), value = tonumber(frame.data:sub(5, 8), 16) }
                end,
            }"#,
        );
        let description = api::call(&mut app, &Caller::Panel, "api.describe", json!({})).unwrap();
        let method = description["methods"].as_array().unwrap().iter().find(|method| method["name"] == "beacon.decode_frame").expect("listed in api.describe");
        assert_eq!((method["effect"].as_str(), method["stability"].as_str()), (Some("read"), Some("experimental")));
        assert_eq!(method["params"]["required"], json!(["start"]));

        let decoded = api::call(&mut app, &Caller::Mcp("claude-code".into()), "beacon.decode_frame", json!({"start": 0})).unwrap();
        assert_eq!(decoded, json!({"sync": "7e7e", "value": 0x1020}));
        let missing = api::call(&mut app, &Caller::Panel, "beacon.decode_frame", json!({"len": 2})).unwrap_err();
        assert_eq!(missing.code, ErrorCode::InvalidParams);
        let wrong = api::call(&mut app, &Caller::Panel, "beacon.decode_frame", json!({"start": "zero"})).unwrap_err();
        assert_eq!(wrong.code, ErrorCode::InvalidParams);
        let past = api::call(&mut app, &Caller::Panel, "beacon.decode_frame", json!({"start": 7})).unwrap_err();
        assert_eq!(past.code, ErrorCode::PluginFailed, "its error is the plugin's");
        assert!(past.message.contains("out_of_range"), "{}", past.message);
    }

    #[test]
    fn an_edit_method_edits_when_its_call_is_allowed_and_a_plugin_cannot_call_itself() {
        let mut app = app_with(&[1, 2, 3, 4]);
        load(
            &mut app,
            "flip.lua",
            r#"theviewer.register_method{
                name = "flip.first", summary = "Invert the first byte.", effect = "edit",
                run = function(params, api) return api.transform.apply{ selection = { range = { 0, 1 } }, operation = { op = "invert" } } end,
            }
            theviewer.register_method{ name = "flip.again", effect = "edit", run = function(params, api) return api.flip.first{} end }"#,
        );
        let held = api::call(&mut app, &Caller::Mcp("claude-code".into()), "flip.first", json!({})).unwrap_err();
        assert!(held.needs_confirmation(), "an edit method asks first, like any edit");
        api::call(&mut app, &Caller::Panel, "flip.first", json!({})).unwrap();
        assert_eq!(app.document.read_range(0, 1), [0xFE]);
        assert_eq!(app.document.undo_label(), Some("Invert by plugin:flip.lua"));
        let looped = api::call(&mut app, &Caller::Panel, "flip.again", json!({})).unwrap_err();
        assert!(looped.message.contains("called itself"), "{}", looped.message);
    }

    #[test]
    fn method_names_must_belong_to_their_plugin() {
        let mut app = app_with(&[0u8; 4]);
        let stray = app.load_plugin_source("acme.lua", r#"theviewer.register_method{ name = "other.thing", run = function() end }"#);
        assert!(stray.unwrap_err().contains("acme.<name>"));
        let builtin = app.load_plugin_source("bytes.lua", r#"theviewer.register_method{ name = "bytes.melt", run = function() end }"#);
        assert!(builtin.unwrap_err().contains("API's own namespaces"));
        let topic = app.load_plugin_source("deaf.lua", r#"theviewer.subscribe("weather.report", function() end)"#);
        assert!(topic.unwrap_err().contains("no topic 'weather.report'"));
    }

    #[test]
    fn the_shipped_acme_example_identifies_its_frames_and_leaves_ordinary_files_alone() {
        let mut frames = Vec::new();
        for kind in 0..4u8 {
            frames.extend([0x7E, 0xA5, kind, 4, 1, 2, 3, 4]);
        }
        let mut app = app_with(&frames);
        assert!(app.plugin_methods.iter().any(|method| method.name == "acme.decode_frame"), "the example in plugins/ is loaded");
        publish_frames(&mut app, &[(0, 8), (8, 8), (16, 8), (24, 8)]);
        let identified = app.bus.facts().find(|fact| fact.producer() == "plugin:acme_telemetry.lua").expect("the example identified its frames");
        assert_eq!(identified.payload_as::<ProtocolIdentified>().unwrap().protocol, "ACME telemetry");
        let decoded = api::call(&mut app, &Caller::Ask, "acme.decode_frame", json!({"start": 8})).unwrap();
        assert_eq!(decoded, json!({"sync": true, "type": 1, "length": 4}));

        let mut ordinary = app_with(&[0x55; 64]);
        publish_frames(&mut ordinary, &[(0, 16), (16, 16), (32, 16), (60, 16)]);
        assert!(ordinary.bus.facts().all(|fact| fact.producer() != "plugin:acme_telemetry.lua"), "nothing is claimed for frames without the sync word");
        assert!(logged(&ordinary, LogLevel::Error).is_empty(), "a frame past the end is passed over quietly: {:?}", logged(&ordinary, LogLevel::Error));
        assert_eq!(api::call(&mut ordinary, &Caller::Panel, "acme.decode_frame", json!({"start": 0})).unwrap(), json!({"sync": false}));
        assert!(!ordinary.document.is_modified());
    }

    #[test]
    fn a_simple_map_may_declare_a_parameter_called_type() {
        let lua = mlua::Lua::new();
        let schema = |source: &str| super::params_schema(&lua.load(source).eval::<mlua::Value>().unwrap()).unwrap();
        let simple = schema(r#"return { type = "string", value = "integer?" }"#);
        assert_eq!(simple["properties"], json!({"type": {"type": "string"}, "value": {"type": "integer"}}));
        assert_eq!(simple["required"], json!(["type"]));
        let full = schema(r#"return { type = "object", properties = { type = { type = "string" } }, description = "A kind of thing." }"#);
        assert_eq!(full["properties"], json!({"type": {"type": "string"}}), "a full schema is kept as it is");
        assert_eq!(schema(r#"return { type = "array" }"#), json!({"type": "array"}), "a lone JSON Schema type is a schema");
        let optional = schema(r#"return { type = "string?" }"#);
        assert_eq!((optional["properties"].clone(), optional["required"].clone()), (json!({"type": {"type": "string"}}), json!([])));
    }

    #[test]
    fn values_cross_between_lua_and_json_intact() {
        let lua = mlua::Lua::new();
        let value = json!({"list": [1, 2.5, "three", true, null], "empty": [], "nested": {"a": {"b": [[]]}}});
        let back = super::lua_to_json(&super::json_to_lua(&lua, &value).unwrap()).unwrap();
        assert_eq!(back, json!({"list": [1, 2.5, "three", true], "empty": [], "nested": {"a": {"b": [[]]}}}), "nulls in arrays end them, as Lua's nil does");
        let gapped = json!({"list": [1, null, 3]});
        let back = super::lua_to_json(&super::json_to_lua(&lua, &gapped).unwrap()).unwrap();
        assert_eq!(back, gapped, "a null inside an array comes back as null");
        let made: mlua::Value = lua.load("return { 10, 20 }").eval().unwrap();
        assert_eq!(super::lua_to_json(&made).unwrap(), json!([10, 20]));
        let binary: mlua::Value = lua.load(r#"return "\xff\x00""#).eval().unwrap();
        assert!(super::lua_to_json(&binary).unwrap_err().contains("theviewer.hex"));
    }
}
