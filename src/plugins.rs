//! Lua plugin host.
//!
//! Scripts in a plugin directory register detectors, parsers, codecs and
//! actions through a `theviewer` global. Each script runs in its own
//! sandboxed Lua state (no `io`, `os`, `package` or `debug`, a memory cap and
//! an instruction budget per callback), so a broken or runaway plugin can
//! only ever fail its own callback, never the viewer.
//!
//! Scripts also call the data API (`theviewer.api`), subscribe to the
//! workspace bus's topics and publish on it, and register methods of their
//! own that join the API's table (see [`lua_api`]).
//!
//! See `docs/plugins.md` for the scripting API.

mod lua_api;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread::ThreadId;

use mlua::{AnyUserData, Function, HookTriggers, Lua, LuaOptions, RegistryKey, StdLib, Table, UserData, UserDataMethods, Value, VmState};

use crate::api::{Caller, Effect, RegisteredMethod, Workspace};
use crate::bus::topics::{LogLevel, PluginLog};
use crate::bus::{Message, Topic};
use crate::plugin::{Category, CodecKind, CodecPlugin, Decoded, Detector, Field, Finding, Parser, ScanContext};
use lua_api::{Access, Binding, MethodSpec, Target};

/// Memory a single script may allocate.
const MEMORY_LIMIT_BYTES: usize = 64 * 1024 * 1024;
/// Instructions a single callback may execute before it is aborted.
const INSTRUCTION_LIMIT: u64 = 50_000_000;
/// How often the instruction hook fires.
const HOOK_INTERVAL: u32 = 1000;

/// Outcome of loading one script file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadReport {
    pub name: String,
    /// `Ok` carries a short summary of what the script registered.
    pub result: Result<String, String>,
}

/// An action a script offers, for menus and the command palette.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionInfo {
    pub id: String,
    pub title: String,
    pub plugin: String,
}

/// What an action may do to the document. The application implements this;
/// tests use a fake.
pub trait ActionHost {
    fn document_len(&self) -> usize;
    fn cursor(&self) -> usize;
    fn selection(&self) -> Option<(usize, usize)>;
    fn read(&mut self, start: usize, len: usize) -> Vec<u8>;
    fn select(&mut self, start: usize, len: usize);
    fn set_status(&mut self, text: &str);
    /// The workspace `theviewer.api` calls into during an action; none
    /// leaves the API unavailable.
    fn workspace(&mut self) -> Option<&mut dyn Workspace> {
        None
    }
}

/// Where plugins are looked for by default.
pub fn default_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("plugins")];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".config").join("theviewer").join("plugins"));
    }
    dirs
}

// ---------------------------------------------------------------------------
// Script state
// ---------------------------------------------------------------------------

/// A sandboxed Lua state plus the bookkeeping callbacks need.
struct ScriptState {
    name: String,
    lua: Mutex<Lua>,
    /// Instructions executed by the callback currently running.
    instructions: AtomicU64,
    /// Lines logged and callback errors, until the host collects them.
    log: Mutex<Vec<PluginLog>>,
    /// The thread running one of the script's callbacks, if any: a callback
    /// that calls back into its own script (through a method it registered)
    /// is refused rather than left waiting for itself.
    running_on: Mutex<Option<ThreadId>>,
}

impl ScriptState {
    fn new(name: &str) -> Result<Arc<Self>, String> {
        let libraries = StdLib::STRING | StdLib::TABLE | StdLib::MATH | StdLib::UTF8;
        let lua = Lua::new_with(libraries, LuaOptions::default()).map_err(|e| e.to_string())?;
        lua.set_memory_limit(MEMORY_LIMIT_BYTES).map_err(|e| e.to_string())?;
        // `dofile` and `loadfile` would reach the filesystem. `load` stays
        // because it is useful, but only for source text: crafted bytecode can
        // corrupt the interpreter's memory and escape the sandbox, so binary
        // chunks are refused and `string.dump` (which makes them) is removed.
        let globals = lua.globals();
        for name in ["dofile", "loadfile"] {
            globals.set(name, Value::Nil).map_err(|e| e.to_string())?;
        }
        lua.load(
            r#"
            local load_any = load
            load = function(chunk, chunk_name, _mode, env)
                return load_any(chunk, chunk_name, "t", env)
            end
            string.dump = nil
            "#,
        )
        .set_name("sandbox")
        .exec()
        .map_err(|e| e.to_string())?;
        let state = Arc::new(ScriptState {
            name: name.to_string(),
            lua: Mutex::new(lua),
            instructions: AtomicU64::new(0),
            log: Mutex::new(Vec::new()),
            running_on: Mutex::new(None),
        });
        state.install_instruction_budget()?;
        Ok(state)
    }

    /// Abort any callback that runs past the instruction budget.
    fn install_instruction_budget(self: &Arc<Self>) -> Result<(), String> {
        let weak = Arc::downgrade(self);
        let lua = self.lua.lock().map_err(|_| "plugin state poisoned")?;
        let triggers = HookTriggers { every_nth_instruction: Some(HOOK_INTERVAL), ..Default::default() };
        lua.set_hook(triggers, move |_, _| {
            let Some(state) = weak.upgrade() else {
                return Ok(VmState::Continue);
            };
            let executed = state.instructions.fetch_add(HOOK_INTERVAL as u64, Ordering::Relaxed) + HOOK_INTERVAL as u64;
            if executed > INSTRUCTION_LIMIT {
                Err(mlua::Error::RuntimeError(format!(
                    "plugin callback aborted after {INSTRUCTION_LIMIT} instructions"
                )))
            } else {
                Ok(VmState::Continue)
            }
        })
        .map_err(|e| e.to_string())
    }

    fn log(&self, level: LogLevel, text: String) {
        if let Ok(mut log) = self.log.lock() {
            log.push(PluginLog { plugin: self.name.clone(), level, text });
        }
    }

    /// Run `body` with the Lua state locked and a fresh instruction budget.
    fn with_lua<R>(&self, body: impl FnOnce(&Lua) -> Result<R, String>) -> Result<R, String> {
        let this_thread = std::thread::current().id();
        if self.running_on.lock().is_ok_and(|running| *running == Some(this_thread)) {
            return Err(format!("{} called itself through the API; call its own Lua function directly instead", self.name));
        }
        let lua = self.lua.lock().map_err(|_| "plugin state poisoned".to_string())?;
        if let Ok(mut running) = self.running_on.lock() {
            *running = Some(this_thread);
        }
        self.instructions.store(0, Ordering::Relaxed);
        let result = body(&lua);
        if let Ok(mut running) = self.running_on.lock() {
            *running = None;
        }
        result
    }
}

fn lua_error(context: &str, error: mlua::Error) -> String {
    format!("{context}: {error}")
}

// ---------------------------------------------------------------------------
// Window userdata exposed to scripts
// ---------------------------------------------------------------------------

/// Read-only view of bytes for scripts. Offsets are 0-based except `byte`,
/// which follows Lua's 1-based convention.
struct Window(Arc<[u8]>);

impl Window {
    fn slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        self.0.get(offset..offset.checked_add(len)?)
    }

    fn read_le(&self, offset: usize, size: usize) -> Option<u64> {
        let bytes = self.slice(offset, size)?;
        Some(bytes.iter().rev().fold(0u64, |acc, &b| (acc << 8) | b as u64))
    }

    fn read_be(&self, offset: usize, size: usize) -> Option<u64> {
        let bytes = self.slice(offset, size)?;
        Some(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
    }

    fn find(&self, needle: &[u8], start: usize) -> Option<usize> {
        if needle.is_empty() || start >= self.0.len() {
            return None;
        }
        self.0[start..].windows(needle.len()).position(|w| w == needle).map(|p| p + start)
    }
}

/// Parse "89 50 4E 47" or "89504e47" into bytes.
fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return Err(format!("odd number of hex digits in '{text}'"));
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|_| format!("bad hex in '{text}'")))
        .collect()
}

impl UserData for Window {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("len", |_, this, ()| Ok(this.0.len()));
        methods.add_method("byte", |_, this, index: usize| {
            Ok(index.checked_sub(1).and_then(|i| this.0.get(i)).copied())
        });
        methods.add_method("bytes", |lua, this, (offset, len): (usize, usize)| {
            match this.slice(offset, len) {
                Some(bytes) => lua.create_string(bytes).map(Value::String),
                None => Ok(Value::Nil),
            }
        });
        methods.add_method("u8", |_, this, offset: usize| Ok(this.read_le(offset, 1)));
        methods.add_method("u16le", |_, this, offset: usize| Ok(this.read_le(offset, 2)));
        methods.add_method("u16be", |_, this, offset: usize| Ok(this.read_be(offset, 2)));
        methods.add_method("u32le", |_, this, offset: usize| Ok(this.read_le(offset, 4)));
        methods.add_method("u32be", |_, this, offset: usize| Ok(this.read_be(offset, 4)));
        methods.add_method("u64le", |_, this, offset: usize| Ok(this.read_le(offset, 8).map(|v| v as i64)));
        methods.add_method("u64be", |_, this, offset: usize| Ok(this.read_be(offset, 8).map(|v| v as i64)));
        methods.add_method("i32le", |_, this, offset: usize| Ok(this.read_le(offset, 4).map(|v| v as u32 as i32)));
        methods.add_method("f32le", |_, this, offset: usize| Ok(this.read_le(offset, 4).map(|v| f32::from_bits(v as u32))));
        methods.add_method("find", |_, this, (needle, start): (mlua::LuaString, Option<usize>)| {
            Ok(this.find(&needle.as_bytes(), start.unwrap_or(0)))
        });
        methods.add_method("find_hex", |_, this, (hex, start): (String, Option<usize>)| {
            let needle = parse_hex(&hex).map_err(mlua::Error::RuntimeError)?;
            Ok(this.find(&needle, start.unwrap_or(0)))
        });
    }
}

// ---------------------------------------------------------------------------
// Converting Lua tables into findings
// ---------------------------------------------------------------------------

fn get_string(table: &Table, key: &str) -> Option<String> {
    table.get::<Option<String>>(key).ok().flatten()
}

fn get_usize(table: &Table, key: &str) -> Option<usize> {
    table.get::<Option<i64>>(key).ok().flatten().and_then(|v| usize::try_from(v).ok())
}

fn field_from_table(table: &Table, base: usize) -> Field {
    let children = table
        .get::<Option<Table>>("children")
        .ok()
        .flatten()
        .map(|list| list.sequence_values::<Table>().flatten().map(|t| field_from_table(&t, base)).collect())
        .unwrap_or_default();
    Field {
        name: get_string(table, "name").unwrap_or_default(),
        offset: base + get_usize(table, "offset").unwrap_or(0),
        len: get_usize(table, "len").unwrap_or(0),
        value: get_string(table, "value").unwrap_or_default(),
        children,
    }
}

/// Build a finding from a script's table. `base` is added to every offset.
fn finding_from_table(table: &Table, base: usize, source: &str, default_id: &str) -> Result<Finding, String> {
    let start = get_usize(table, "start").ok_or("finding needs a numeric 'start'")?;
    let len = get_usize(table, "len").ok_or("finding needs a numeric 'len'")?;
    let category = get_string(table, "category")
        .and_then(|name| Category::from_name(&name))
        .unwrap_or(Category::Custom);
    let fields = table
        .get::<Option<Table>>("fields")
        .map_err(|e| e.to_string())?
        .map(|list| list.sequence_values::<Table>().flatten().map(|t| field_from_table(&t, base)).collect())
        .unwrap_or_default();
    let mut finding = Finding::new(get_string(table, "id").unwrap_or_else(|| default_id.to_string()), source, category, base + start, len)
        .title(get_string(table, "title").unwrap_or_default())
        .detail(get_string(table, "detail").unwrap_or_default())
        .fields(fields);
    if let Some(confidence) = table.get::<Option<f32>>("confidence").ok().flatten() {
        finding = finding.confidence(confidence);
    }
    Ok(finding)
}

fn findings_from_value(value: Value, base: usize, source: &str, default_id: &str) -> Result<Vec<Finding>, String> {
    match value {
        Value::Nil => Ok(Vec::new()),
        Value::Table(list) => list
            .sequence_values::<Table>()
            .map(|entry| entry.map_err(|e| e.to_string()).and_then(|t| finding_from_table(&t, base, source, default_id)))
            .collect(),
        other => Err(format!("scan must return a table of findings or nil, got {}", other.type_name())),
    }
}

fn scan_context_table(lua: &Lua, context: &ScanContext) -> Result<Table, String> {
    let table = lua.create_table().map_err(|e| e.to_string())?;
    table.set("base", context.base).map_err(|e| e.to_string())?;
    table.set("document_len", context.document_len).map_err(|e| e.to_string())?;
    let strides = lua.create_table().map_err(|e| e.to_string())?;
    for (index, stride) in context.strides.iter().enumerate() {
        strides.set(index + 1, *stride).map_err(|e| e.to_string())?;
    }
    table.set("strides", strides).map_err(|e| e.to_string())?;
    Ok(table)
}

fn categories_from_table(table: &Table) -> Vec<Category> {
    table
        .get::<Option<Table>>("categories")
        .ok()
        .flatten()
        .map(|list| list.sequence_values::<String>().flatten().filter_map(|name| Category::from_name(&name)).collect())
        .unwrap_or_else(|| vec![Category::Custom])
}

// ---------------------------------------------------------------------------
// Plugin implementations backed by Lua callbacks
// ---------------------------------------------------------------------------

struct LuaDetector {
    state: Arc<ScriptState>,
    id: String,
    name: String,
    categories: Vec<Category>,
    scan: RegistryKey,
}

impl Detector for LuaDetector {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn categories(&self) -> Vec<Category> {
        self.categories.clone()
    }

    fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding> {
        let result = self.state.with_lua(|lua| {
            let function: Function = lua.registry_value(&self.scan).map_err(|e| lua_error("scan", e))?;
            let window = lua.create_userdata(Window(Arc::from(window))).map_err(|e| e.to_string())?;
            let context_table = scan_context_table(lua, context)?;
            let value: Value = function.call((window, context_table)).map_err(|e| lua_error(&self.id, e))?;
            findings_from_value(value, context.base, &self.id, &self.id)
        });
        match result {
            Ok(findings) => findings,
            Err(error) => {
                self.state.log(LogLevel::Error, error);
                Vec::new()
            }
        }
    }
}

struct LuaParser {
    state: Arc<ScriptState>,
    id: String,
    name: String,
    looks_like: RegistryKey,
    parse: RegistryKey,
}

impl Parser for LuaParser {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn looks_like(&self, bytes: &[u8]) -> bool {
        // Keep this cheap: only the first 64 bytes are handed over.
        let head: Arc<[u8]> = Arc::from(&bytes[..bytes.len().min(64)]);
        let result = self.state.with_lua(|lua| {
            let function: Function = lua.registry_value(&self.looks_like).map_err(|e| e.to_string())?;
            let window = lua.create_userdata(Window(head)).map_err(|e| e.to_string())?;
            function.call::<bool>(window).map_err(|e| lua_error(&self.id, e))
        });
        result.unwrap_or_else(|error| {
            self.state.log(LogLevel::Error, error);
            false
        })
    }

    fn parse(&self, bytes: &[u8], base: usize) -> Option<Finding> {
        let result = self.state.with_lua(|lua| {
            let function: Function = lua.registry_value(&self.parse).map_err(|e| e.to_string())?;
            let window = lua.create_userdata(Window(Arc::from(bytes))).map_err(|e| e.to_string())?;
            let value: Value = function.call((window, base)).map_err(|e| lua_error(&self.id, e))?;
            match value {
                Value::Nil => Ok(None),
                Value::Table(table) => finding_from_table(&table, base, &self.id, &self.id).map(Some),
                other => Err(format!("parse must return a finding table or nil, got {}", other.type_name())),
            }
        });
        result.unwrap_or_else(|error| {
            self.state.log(LogLevel::Error, error);
            None
        })
    }
}

struct LuaCodec {
    state: Arc<ScriptState>,
    id: String,
    name: String,
    kind: CodecKind,
    detect: RegistryKey,
    decode: RegistryKey,
    encode: Option<RegistryKey>,
}

impl CodecPlugin for LuaCodec {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> CodecKind {
        self.kind
    }

    fn detect(&self, bytes: &[u8]) -> bool {
        let head: Arc<[u8]> = Arc::from(&bytes[..bytes.len().min(4096)]);
        let result = self.state.with_lua(|lua| {
            let function: Function = lua.registry_value(&self.detect).map_err(|e| e.to_string())?;
            let window = lua.create_userdata(Window(head)).map_err(|e| e.to_string())?;
            function.call::<bool>(window).map_err(|e| lua_error(&self.id, e))
        });
        result.unwrap_or_else(|error| {
            self.state.log(LogLevel::Error, error);
            false
        })
    }

    fn decode(&self, input: &[u8], max_out: usize) -> Result<Decoded, String> {
        self.state.with_lua(|lua| {
            let function: Function = lua.registry_value(&self.decode).map_err(|e| e.to_string())?;
            let window = lua.create_userdata(Window(Arc::from(input))).map_err(|e| e.to_string())?;
            let (data, consumed): (Option<mlua::LuaString>, Option<i64>) =
                function.call((window, max_out)).map_err(|e| lua_error(&self.id, e))?;
            let Some(data) = data else {
                return Err(format!("{} could not decode these bytes", self.name));
            };
            let mut data = data.as_bytes().to_vec();
            let truncated = data.len() > max_out;
            data.truncate(max_out);
            let consumed_exact = consumed.is_some();
            let consumed = consumed.and_then(|c| usize::try_from(c).ok()).unwrap_or(input.len()).min(input.len());
            Ok(Decoded { data, consumed, consumed_exact, complete: !truncated, truncated })
        })
    }

    fn encode(&self, data: &[u8]) -> Option<Result<Vec<u8>, String>> {
        let key = self.encode.as_ref()?;
        Some(self.state.with_lua(|lua| {
            let function: Function = lua.registry_value(key).map_err(|e| e.to_string())?;
            let input = lua.create_string(data).map_err(|e| e.to_string())?;
            let output: mlua::LuaString = function.call(input).map_err(|e| lua_error(&self.id, e))?;
            Ok(output.as_bytes().to_vec())
        }))
    }
}

struct LuaAction {
    state: Arc<ScriptState>,
    id: String,
    title: String,
    run: RegistryKey,
}

/// Hands an [`ActionHost`] to a script for the duration of one action call.
/// The pointer is only dereferenced while `alive` is set, which the host
/// clears before returning, so a script that keeps the handle gets an error
/// instead of a dangling reference.
struct ActionApi {
    host: usize,
    alive: Arc<AtomicBool>,
}

impl ActionApi {
    fn with_host<R>(&self, body: impl FnOnce(&mut dyn ActionHost) -> R) -> mlua::Result<R> {
        if !self.alive.load(Ordering::Acquire) {
            return Err(mlua::Error::RuntimeError("the action has finished; the api handle is no longer valid".into()));
        }
        // SAFETY: `host` was created from a live `&mut dyn ActionHost` in
        // `run_action`, which holds that borrow for the whole call and
        // clears `alive` before it returns. Calls are serialised by the
        // script's Lua lock, so no two uses overlap.
        let host = unsafe { &mut *(self.host as *mut &mut dyn ActionHost) };
        Ok(body(*host))
    }
}

impl UserData for ActionApi {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("document_len", |_, this, ()| this.with_host(|h| h.document_len()));
        methods.add_method("cursor", |_, this, ()| this.with_host(|h| h.cursor()));
        methods.add_method("selection", |_, this, ()| {
            this.with_host(|h| h.selection()).map(|selection| match selection {
                Some((start, len)) => (Some(start), Some(len)),
                None => (None, None),
            })
        });
        methods.add_method("read", |lua, this, (start, len): (usize, usize)| {
            let bytes = this.with_host(|h| h.read(start, len))?;
            lua.create_string(bytes)
        });
        // Through the data API, as `theviewer.api.bytes.replace` would be,
        // so the edit is journalled, labelled with the plugin and can be
        // part of a recipe.
        methods.add_method("replace", |lua, this, (start, len, bytes): (usize, usize, mlua::LuaString)| {
            this.with_host(|_| ())?;
            let params = serde_json::json!({ "start": start, "len": len, "data": crate::ops::to_compact_hex(&bytes.as_bytes()) });
            lua_api::call_bound(lua, "bytes.replace", params).map(|_| ()).map_err(mlua::Error::RuntimeError)
        });
        methods.add_method("select", |_, this, (start, len): (usize, usize)| this.with_host(|h| h.select(start, len)));
        methods.add_method("status", |_, this, text: String| this.with_host(|h| h.set_status(&text)));
    }
}

// ---------------------------------------------------------------------------
// Registration collected while a script loads
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Registrations {
    detectors: Vec<(String, String, Vec<Category>, RegistryKey)>,
    parsers: Vec<(String, String, RegistryKey, RegistryKey)>,
    codecs: Vec<(String, String, CodecKind, RegistryKey, RegistryKey, Option<RegistryKey>)>,
    actions: Vec<(String, String, RegistryKey)>,
    /// From `theviewer.plugin{ name = …, edits = … }`.
    name: Option<String>,
    edits: bool,
    /// Topic and handler of each `theviewer.subscribe`.
    subscriptions: Vec<(String, RegistryKey)>,
    methods: Vec<MethodSpec>,
}

fn required_string(spec: &Table, key: &str) -> mlua::Result<String> {
    spec.get::<Option<String>>(key)?
        .ok_or_else(|| mlua::Error::RuntimeError(format!("registration needs a string '{key}'")))
}

fn required_function(lua: &Lua, spec: &Table, key: &str) -> mlua::Result<RegistryKey> {
    let function: Function = spec
        .get::<Option<Function>>(key)?
        .ok_or_else(|| mlua::Error::RuntimeError(format!("registration needs a function '{key}'")))?;
    lua.create_registry_value(function)
}

fn optional_function(lua: &Lua, spec: &Table, key: &str) -> mlua::Result<Option<RegistryKey>> {
    match spec.get::<Option<Function>>(key)? {
        Some(function) => lua.create_registry_value(function).map(Some),
        None => Ok(None),
    }
}

fn with_registrations<R>(lua: &Lua, body: impl FnOnce(&mut Registrations) -> R) -> mlua::Result<R> {
    let mut registrations = lua
        .app_data_mut::<Registrations>()
        .ok_or_else(|| mlua::Error::RuntimeError("registration is only possible while a script loads".into()))?;
    Ok(body(&mut registrations))
}

/// Install the `theviewer` global into a fresh state. `log` writes to
/// `state`'s log, so it works while loading and in every later callback.
fn install_api(lua: &Lua, state: Weak<ScriptState>) -> mlua::Result<()> {
    let api = lua.create_table()?;

    api.set(
        "register_detector",
        lua.create_function(|lua, spec: Table| {
            let id = required_string(&spec, "id")?;
            let name = get_string(&spec, "name").unwrap_or_else(|| id.clone());
            let categories = categories_from_table(&spec);
            let scan = required_function(lua, &spec, "scan")?;
            with_registrations(lua, |r| r.detectors.push((id, name, categories, scan)))
        })?,
    )?;

    api.set(
        "register_parser",
        lua.create_function(|lua, spec: Table| {
            let id = required_string(&spec, "id")?;
            let name = get_string(&spec, "name").unwrap_or_else(|| id.clone());
            let looks_like = required_function(lua, &spec, "looks_like")?;
            let parse = required_function(lua, &spec, "parse")?;
            with_registrations(lua, |r| r.parsers.push((id, name, looks_like, parse)))
        })?,
    )?;

    api.set(
        "register_codec",
        lua.create_function(|lua, spec: Table| {
            let id = required_string(&spec, "id")?;
            let name = get_string(&spec, "name").unwrap_or_else(|| id.clone());
            let kind = match get_string(&spec, "kind").as_deref() {
                Some("compression") => CodecKind::Compression,
                _ => CodecKind::Encoding,
            };
            let detect = required_function(lua, &spec, "detect")?;
            let decode = required_function(lua, &spec, "decode")?;
            let encode = optional_function(lua, &spec, "encode")?;
            with_registrations(lua, |r| r.codecs.push((id, name, kind, detect, decode, encode)))
        })?,
    )?;

    api.set(
        "register_action",
        lua.create_function(|lua, spec: Table| {
            let id = required_string(&spec, "id")?;
            let title = get_string(&spec, "title").unwrap_or_else(|| id.clone());
            let run = required_function(lua, &spec, "run")?;
            with_registrations(lua, |r| r.actions.push((id, title, run)))
        })?,
    )?;

    api.set(
        "plugin",
        lua.create_function(|lua, spec: Table| {
            let name = get_string(&spec, "name");
            if let Some(name) = &name
                && (name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
            {
                return Err(mlua::Error::RuntimeError(format!("a plugin's name is lower-case letters, digits and underscores, not '{name}'")));
            }
            let edits = spec.get::<Option<bool>>("edits")?.unwrap_or(false);
            with_registrations(lua, |r| {
                r.name = name;
                r.edits = edits;
            })
        })?,
    )?;

    api.set(
        "subscribe",
        lua.create_function(|lua, (topic, handler): (String, Function)| {
            if Topic::named(&topic).is_none() {
                return Err(mlua::Error::RuntimeError(format!("there is no topic '{topic}' to subscribe to; api.describe lists them, and plugins' own are x.<plugin>.<name>")));
            }
            let handler = lua.create_registry_value(handler)?;
            with_registrations(lua, |r| r.subscriptions.push((topic, handler)))
        })?,
    )?;

    api.set(
        "register_method",
        lua.create_function(|lua, spec: Table| {
            let name = required_string(&spec, "name")?;
            let summary = get_string(&spec, "summary").unwrap_or_else(|| format!("{name}, from a plugin."));
            let effect = match get_string(&spec, "effect").as_deref() {
                None | Some("read") => Effect::Read,
                Some("edit") => Effect::Edit,
                Some("analysis") => Effect::Analysis,
                Some(other) => return Err(mlua::Error::RuntimeError(format!("a method's effect is \"read\", \"analysis\" or \"edit\", not '{other}'"))),
            };
            let params = lua_api::params_schema(&spec.get::<Value>("params")?).map_err(|problem| mlua::Error::RuntimeError(format!("{name}: {problem}")))?;
            let result = match spec.get::<Value>("result")? {
                Value::Nil => serde_json::json!({ "type": "object" }),
                given => lua_api::params_schema(&given).map_err(|problem| mlua::Error::RuntimeError(format!("{name} result: {problem}")))?,
            };
            let run = required_function(lua, &spec, "run")?;
            with_registrations(lua, |r| r.methods.push(MethodSpec { name, summary, effect, params, result, run }))
        })?,
    )?;

    lua_api::install(lua, &api)?;

    let log_state = state.clone();
    api.set(
        "log",
        lua.create_function(move |_, text: String| {
            if let Some(state) = log_state.upgrade() {
                state.log(LogLevel::Info, text);
            }
            Ok(())
        })?,
    )?;

    // Lua's own `print` writes to standard output, which under `theviewer
    // mcp` is the protocol's channel. This one writes a line to the plugin's
    // log instead, its values converted by `tostring` and joined by tabs as
    // Lua's would be.
    lua.globals().set(
        "print",
        lua.create_function(move |lua, values: mlua::Variadic<Value>| {
            let tostring: Function = lua.globals().get("tostring")?;
            let mut parts = Vec::with_capacity(values.len());
            for value in values {
                let text: mlua::LuaString = tostring.call(value)?;
                parts.push(text.to_string_lossy());
            }
            if let Some(state) = state.upgrade() {
                state.log(LogLevel::Info, parts.join("\t"));
            }
            Ok(())
        })?,
    )?;

    lua.globals().set("theviewer", api)
}

// ---------------------------------------------------------------------------
// The host
// ---------------------------------------------------------------------------

/// One loaded script and everything it registered.
struct Script {
    state: Arc<ScriptState>,
    /// SHA-256 of the source it was loaded from, lower-case hex, for the
    /// journal's record of which plugins a session used.
    sha256: String,
    /// The plugin's name: the one it declared, or its file's stem. Its own
    /// topics and methods are named after it.
    namespace: String,
    /// Whether it declared that its handlers edit.
    edits: bool,
    detectors: Vec<Arc<LuaDetector>>,
    parsers: Vec<Arc<LuaParser>>,
    codecs: Vec<Arc<LuaCodec>>,
    actions: Vec<Arc<LuaAction>>,
    subscriptions: Vec<Arc<Subscription>>,
    methods: Vec<Arc<RegisteredMethod>>,
}

/// A plugin's name from its file name: the stem, lower case, with
/// anything but letters, digits and underscores made an underscore.
fn namespace_from_file(file: &str) -> String {
    let stem = file.strip_suffix(".lua").unwrap_or(file);
    stem.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect()
}

/// A handler a script subscribed to a topic with.
pub struct Subscription {
    state: Arc<ScriptState>,
    /// The topic's name, a plugin's own `x.<plugin>.<name>` included.
    pub topic: String,
    /// The plugin's file name.
    pub plugin: String,
    namespace: String,
    edits: bool,
    handler: RegistryKey,
}

impl Subscription {
    /// Whether this handler wants `message`.
    pub fn wants(&self, message: &Message) -> bool {
        message.topic_name() == self.topic
    }

    /// Run the handler for `message` against `workspace`, with the script's
    /// budgets. Its API calls read only, unless the plugin declared edits,
    /// when they edit within its permission. Failures are logged.
    pub fn deliver(&self, workspace: &mut dyn Workspace, message: &Message) {
        let access = if self.edits { Access::Checked } else { Access::ReadOnly };
        let caller = Caller::Plugin(self.plugin.clone());
        let result = lua_api::run_in_workspace(&self.state, workspace, caller, access, &self.namespace, Some(message.id), |lua| {
            let handler: Function = lua.registry_value(&self.handler).map_err(|error| error.to_string())?;
            let envelope = lua_api::json_to_lua(lua, &message.to_json()).map_err(|error| error.to_string())?;
            let api: Table = lua.globals().get::<Table>("theviewer").and_then(|theviewer| theviewer.get("api")).map_err(|error| error.to_string())?;
            handler.call::<()>((envelope, api)).map_err(|error| lua_error(&format!("{} handler", self.topic), error))
        });
        if let Err(error) = result {
            self.state.log(LogLevel::Error, error);
        }
    }

    /// Log that `count` messages for this handler were dropped, as it fell behind.
    pub fn note_dropped(&self, count: usize) {
        self.state.log(LogLevel::Error, format!("its {} handler fell behind; {count} messages were dropped", self.topic));
    }
}

/// Loads scripts and exposes what they registered.
#[derive(Default)]
pub struct LuaHost {
    scripts: Vec<Script>,
    loaded_dirs: Vec<PathBuf>,
}

impl LuaHost {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load every `*.lua` file in `dir`, in name order. A missing directory
    /// yields an empty report rather than an error.
    pub fn load_dir(&mut self, dir: &Path) -> Vec<LoadReport> {
        if !self.loaded_dirs.contains(&dir.to_path_buf()) {
            self.loaded_dirs.push(dir.to_path_buf());
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "lua"))
            .collect();
        paths.sort();
        paths
            .into_iter()
            .map(|path| {
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let result = std::fs::read_to_string(&path)
                    .map_err(|e| format!("could not read {}: {e}", path.display()))
                    .and_then(|source| self.load_source(&name, &source));
                LoadReport { name, result }
            })
            .collect()
    }

    /// Load one script from source. Returns a summary of what it registered.
    pub fn load_source(&mut self, name: &str, source: &str) -> Result<String, String> {
        let state = ScriptState::new(name)?;
        let weak_state = Arc::downgrade(&state);
        let registrations = state.with_lua(|lua| {
            lua.set_app_data(Registrations::default());
            install_api(lua, weak_state).map_err(|e| lua_error("installing api", e))?;
            lua.load(source).set_name(name).exec().map_err(|e| lua_error(name, e))?;
            lua.remove_app_data::<Registrations>().ok_or_else(|| "registrations vanished".to_string())
        })?;

        let namespace = registrations.name.clone().unwrap_or_else(|| namespace_from_file(name));
        for method in &registrations.methods {
            lua_api::check_method_name(&method.name, &namespace).map_err(|problem| format!("{name}: {problem}"))?;
        }
        let summary = format!(
            "{} detector(s), {} parser(s), {} codec(s), {} action(s), {} subscription(s), {} method(s)",
            registrations.detectors.len(),
            registrations.parsers.len(),
            registrations.codecs.len(),
            registrations.actions.len(),
            registrations.subscriptions.len(),
            registrations.methods.len()
        );
        let mut methods = Vec::with_capacity(registrations.methods.len());
        for spec in registrations.methods {
            if self.methods().iter().any(|known| known.name == spec.name) {
                state.log(LogLevel::Error, format!("{} is already registered by another plugin; this one is left out", spec.name));
                continue;
            }
            methods.push(Arc::new(lua_api::registered_method(spec, &state, name, &namespace)));
        }
        let edits = registrations.edits;
        let subscriptions = registrations
            .subscriptions
            .into_iter()
            .map(|(topic, handler)| Arc::new(Subscription { state: state.clone(), topic, plugin: name.to_string(), namespace: namespace.clone(), edits, handler }))
            .collect();
        let script = Script {
            sha256: crate::corpus::sha256_hex(source.as_bytes()),
            namespace,
            edits,
            subscriptions,
            methods,
            detectors: registrations
                .detectors
                .into_iter()
                .map(|(id, name, categories, scan)| Arc::new(LuaDetector { state: state.clone(), id, name, categories, scan }))
                .collect(),
            parsers: registrations
                .parsers
                .into_iter()
                .map(|(id, name, looks_like, parse)| Arc::new(LuaParser { state: state.clone(), id, name, looks_like, parse }))
                .collect(),
            codecs: registrations
                .codecs
                .into_iter()
                .map(|(id, name, kind, detect, decode, encode)| {
                    Arc::new(LuaCodec { state: state.clone(), id, name, kind, detect, decode, encode })
                })
                .collect(),
            actions: registrations
                .actions
                .into_iter()
                .map(|(id, title, run)| Arc::new(LuaAction { state: state.clone(), id, title, run }))
                .collect(),
            state,
        };
        self.scripts.push(script);
        Ok(summary)
    }

    /// Drop every script and load the directories again.
    pub fn reload(&mut self) -> Vec<LoadReport> {
        self.scripts.clear();
        let dirs = std::mem::take(&mut self.loaded_dirs);
        dirs.iter().flat_map(|dir| self.load_dir(dir)).collect()
    }

    pub fn detectors(&self) -> Vec<Arc<dyn Detector>> {
        self.scripts
            .iter()
            .flat_map(|script| script.detectors.iter().map(|d| d.clone() as Arc<dyn Detector>))
            .collect()
    }

    pub fn parsers(&self) -> Vec<Arc<dyn Parser>> {
        self.scripts
            .iter()
            .flat_map(|script| script.parsers.iter().map(|p| p.clone() as Arc<dyn Parser>))
            .collect()
    }

    pub fn codecs(&self) -> Vec<Arc<dyn CodecPlugin>> {
        self.scripts
            .iter()
            .flat_map(|script| script.codecs.iter().map(|c| c.clone() as Arc<dyn CodecPlugin>))
            .collect()
    }

    pub fn actions(&self) -> Vec<ActionInfo> {
        self.scripts
            .iter()
            .flat_map(|script| {
                script.actions.iter().map(|action| ActionInfo {
                    id: action.id.clone(),
                    title: action.title.clone(),
                    plugin: script.state.name.clone(),
                })
            })
            .collect()
    }

    /// Run the action with `id` against `host`. The person ran it, so its
    /// `theviewer.api` calls may edit without asking; its edits are
    /// labelled with the plugin.
    pub fn run_action(&self, id: &str, host: &mut dyn ActionHost) -> Result<(), String> {
        let (script, action) = self
            .scripts
            .iter()
            .find_map(|script| script.actions.iter().find(|action| action.id == id).map(|action| (script, action)))
            .ok_or_else(|| format!("no plugin action '{id}'"))?;
        let alive = Arc::new(AtomicBool::new(true));
        let mut host_ref: &mut dyn ActionHost = host;
        let host_pointer = (&mut host_ref as *mut &mut dyn ActionHost) as usize;
        let api = ActionApi { host: host_pointer, alive: alive.clone() };
        let binding = Binding::new(Target::Action(host_pointer), Caller::Plugin(script.state.name.clone()), Access::Granted, &script.namespace, &action.state);
        let result = lua_api::run_bound(&action.state, binding, |lua| {
            let function: Function = lua.registry_value(&action.run).map_err(|e| e.to_string())?;
            let api: AnyUserData = lua.create_userdata(api).map_err(|e| e.to_string())?;
            function.call::<()>(api).map_err(|e| lua_error(&action.id, e))
        });
        alive.store(false, Ordering::Release);
        result
    }

    /// Every handler scripts subscribed to topics with.
    pub fn subscriptions(&self) -> Vec<Arc<Subscription>> {
        self.scripts.iter().flat_map(|script| script.subscriptions.iter().cloned()).collect()
    }

    /// Every method scripts registered, for the API's table.
    pub fn methods(&self) -> Vec<Arc<RegisteredMethod>> {
        self.scripts.iter().flat_map(|script| script.methods.iter().cloned()).collect()
    }

    /// The scripts that declared their handlers edit, by file name.
    pub fn editing_plugins(&self) -> Vec<String> {
        self.scripts.iter().filter(|script| script.edits).map(|script| script.state.name.clone()).collect()
    }

    /// Lines logged by scripts and errors from their callbacks, from the
    /// UI thread and background scans alike, cleared on read.
    pub fn take_entries(&mut self) -> Vec<PluginLog> {
        let mut lines = Vec::new();
        for script in &self.scripts {
            if let Ok(mut log) = script.state.log.lock() {
                lines.append(&mut log);
            }
        }
        lines
    }

    /// [`LuaHost::take_entries`] as text, each line led by its script's name.
    pub fn take_log(&mut self) -> Vec<String> {
        self.take_entries().into_iter().map(|line| format!("{}: {}", line.plugin, line.text)).collect()
    }

    pub fn script_names(&self) -> Vec<String> {
        self.scripts.iter().map(|script| script.state.name.clone()).collect()
    }

    /// Each script's file name with the SHA-256 of its source, in load order.
    pub fn script_digests(&self) -> Vec<(String, String)> {
        self.scripts.iter().map(|script| (script.state.name.clone(), script.sha256.clone())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn examples_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("plugins")
    }

    fn host_with_examples() -> LuaHost {
        let mut host = LuaHost::new();
        let reports = host.load_dir(&examples_dir());
        for report in &reports {
            assert!(report.result.is_ok(), "{}: {:?}", report.name, report.result);
        }
        assert!(reports.len() >= 5, "expected the example scripts, got {reports:?}");
        host
    }

    struct FakeHost {
        bytes: Vec<u8>,
        cursor: usize,
        selection: Option<(usize, usize)>,
        status: String,
    }

    impl ActionHost for FakeHost {
        fn document_len(&self) -> usize {
            self.bytes.len()
        }
        fn cursor(&self) -> usize {
            self.cursor
        }
        fn selection(&self) -> Option<(usize, usize)> {
            self.selection
        }
        fn read(&mut self, start: usize, len: usize) -> Vec<u8> {
            self.bytes[start..(start + len).min(self.bytes.len())].to_vec()
        }
        fn select(&mut self, start: usize, len: usize) {
            self.selection = Some((start, len));
        }
        fn set_status(&mut self, text: &str) {
            self.status = text.to_string();
        }
    }

    #[test]
    fn example_scripts_load_and_register_things() {
        let host = host_with_examples();
        assert!(host.codecs().iter().any(|c| c.id() == "base64-lua"));
        assert!(host.codecs().iter().any(|c| c.id() == "xor-55"));
        assert!(host.detectors().iter().any(|d| d.id() == "ntp-timestamps"));
        assert!(host.parsers().iter().any(|p| p.id() == "tlv"));
        assert!(host.actions().iter().any(|a| a.id == "uppercase-selection"));
    }

    #[test]
    fn base64_codec_round_trips_and_detects() {
        let host = host_with_examples();
        let codecs = host.codecs();
        let base64 = codecs.iter().find(|c| c.id() == "base64-lua").unwrap();
        let encoded = base64.encode(b"hello world").unwrap().unwrap();
        assert_eq!(encoded, b"aGVsbG8gd29ybGQ=");
        let decoded = base64.decode(&encoded, usize::MAX).unwrap();
        assert_eq!(decoded.data, b"hello world");
        assert!(base64.detect(b"aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmdlciBzdHJpbmc="));
        assert!(!base64.detect(&[0x00, 0xFF, 0x12, 0x80, 0x7F, 0x01]));
        assert_eq!(base64.kind(), CodecKind::Encoding);
    }

    #[test]
    fn xor_codec_is_its_own_inverse() {
        let host = host_with_examples();
        let codecs = host.codecs();
        let xor = codecs.iter().find(|c| c.id() == "xor-55").unwrap();
        let masked = xor.encode(b"secret").unwrap().unwrap();
        assert_ne!(masked, b"secret");
        assert_eq!(xor.decode(&masked, usize::MAX).unwrap().data, b"secret");
        assert!(!xor.detect(b"anything"));
    }

    #[test]
    fn ntp_detector_finds_a_planted_run_at_document_offsets() {
        let host = host_with_examples();
        let detectors = host.detectors();
        let ntp = detectors.iter().find(|d| d.id() == "ntp-timestamps").unwrap();
        let mut window = vec![0u8; 64];
        // 2024-01-01 in NTP seconds (Unix 1704067200 + 2208988800).
        let mut seconds: u32 = 1_704_067_200 + 2_208_988_800;
        for _ in 0..6 {
            window.extend_from_slice(&seconds.to_be_bytes());
            window.extend_from_slice(&[0u8; 4]);
            seconds += 30;
        }
        let context = ScanContext { base: 1000, document_len: 2000, strides: vec![] };
        let findings = ntp.scan(&window, &context);
        let hit = findings.iter().find(|f| f.category == Category::Timestamp).expect("an NTP run");
        assert_eq!(hit.start, 1064);
        assert_eq!(hit.sequence.map(|s| s.stride), None);
        assert!(hit.detail.contains("2024"), "{}", hit.detail);
    }

    #[test]
    fn tlv_parser_builds_one_field_per_element() {
        let host = host_with_examples();
        let parsers = host.parsers();
        let tlv = parsers.iter().find(|p| p.id() == "tlv").unwrap();
        let mut bytes = Vec::new();
        for (tag, len) in [(1u8, 4usize), (2, 6), (3, 2), (4, 8)] {
            bytes.push(tag);
            bytes.push(len as u8);
            bytes.extend(std::iter::repeat_n(0xEE, len));
        }
        assert!(tlv.looks_like(&bytes));
        let finding = tlv.parse(&bytes, 500).expect("a TLV finding");
        assert_eq!(finding.start, 500);
        assert_eq!(finding.len, bytes.len());
        assert_eq!(finding.fields.len(), 4);
        assert_eq!(finding.fields[1].offset, 506);
        assert_eq!(finding.category, Category::Structure);
    }

    #[test]
    fn an_action_reaches_the_window_through_its_host_and_edits_only_through_the_api() {
        let host = host_with_examples();
        let mut fake = FakeHost { bytes: b"hello world".to_vec(), cursor: 0, selection: None, status: String::new() };
        host.run_action("uppercase-selection", &mut fake).unwrap();
        assert_eq!(fake.status, "Select some text first");
        fake.selection = Some((6, 5));
        let without_api = host.run_action("uppercase-selection", &mut fake).unwrap_err();
        assert!(without_api.contains("theviewer.api is not available"), "{without_api}");
        assert_eq!(fake.bytes, b"hello world", "a host without the data API cannot be edited");
        assert!(host.run_action("no-such-action", &mut fake).is_err());
    }

    #[test]
    fn a_broken_script_only_fails_itself() {
        let dir = std::env::temp_dir().join(format!("theviewer-plugins-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a_broken.lua"), "this is not lua (").unwrap();
        std::fs::write(
            dir.join("b_fine.lua"),
            "theviewer.register_detector{ id='fine', scan=function(w, ctx) return nil end }",
        )
        .unwrap();
        let mut host = LuaHost::new();
        let reports = host.load_dir(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(reports.len(), 2);
        assert!(reports[0].result.is_err());
        assert!(reports[1].result.is_ok());
        assert_eq!(host.detectors().len(), 1);
    }

    #[test]
    fn a_runaway_callback_is_aborted() {
        let mut host = LuaHost::new();
        host.load_source("loop.lua", "theviewer.register_detector{ id='loop', scan=function(w, ctx) while true do end end }")
            .unwrap();
        let detector = host.detectors().remove(0);
        let findings = detector.scan(&[0u8; 16], &ScanContext::default());
        assert!(findings.is_empty());
        let log = host.take_log();
        assert!(log.iter().any(|line| line.contains("aborted")), "{log:?}");
    }

    #[test]
    fn a_failing_detector_is_logged_as_an_error_and_a_logged_line_as_information() {
        let mut host = LuaHost::new();
        host.load_source("faulty.lua", "theviewer.register_detector{ id='faulty', scan=function(w, ctx) theviewer.log('looking'); error('no luck') end }").unwrap();
        let detector = host.detectors().remove(0);
        // Scans run on background threads, away from the host.
        std::thread::spawn(move || detector.scan(&[0u8; 8], &ScanContext::default())).join().unwrap();
        let lines = host.take_entries();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!((lines[0].plugin.as_str(), lines[0].level, lines[0].text.as_str()), ("faulty.lua", LogLevel::Info, "looking"));
        assert_eq!(lines[1].level, LogLevel::Error);
        assert!(lines[1].text.contains("no luck"), "{lines:?}");
        assert!(host.take_entries().is_empty(), "collected once");
    }

    #[test]
    fn scripts_cannot_reach_the_operating_system() {
        let mut host = LuaHost::new();
        assert!(host.load_source("os.lua", "os.exit(1)").is_err());
        assert!(host.load_source("io.lua", "io.open('/etc/passwd')").is_err());
        assert!(host.load_source("file.lua", "dofile('/etc/passwd')").is_err());
        host.load_source("late.lua", "theviewer.register_detector{ id='late', scan=function() return os.getenv('HOME') end }")
            .unwrap();
        let detector = host.detectors().remove(0);
        assert!(detector.scan(&[0u8; 4], &ScanContext::default()).is_empty());
        assert!(host.take_log().iter().any(|l| l.contains("os")));
    }

    #[test]
    fn scripts_cannot_load_bytecode_but_can_load_source_text() {
        let mut host = LuaHost::new();
        assert!(host.load_source("dump.lua", "local f = string.dump(function() end)").is_err(), "string.dump is gone");
        // "\27Lua" starts every binary chunk; even asking for binary mode is refused.
        let refused = host.load_source(
            "binary.lua",
            r"local f, err = load('\27Lua\84\0', 'x', 'b'); assert(f == nil and err:find('binary'), err)",
        );
        assert!(refused.is_ok(), "{refused:?}");
        let text = host.load_source("text.lua", "local f = load('return 1 + 1'); assert(f() == 2)");
        assert!(text.is_ok(), "{text:?}");
    }

    #[test]
    fn log_works_while_loading_and_inside_callbacks() {
        let mut host = LuaHost::new();
        host.load_source(
            "chatty.lua",
            "theviewer.log('loaded'); theviewer.register_detector{ id='c', scan=function(w, ctx) theviewer.log('scanned ' .. w:len()); return { { start=0, len=1 } } end }",
        )
        .unwrap();
        let detector = host.detectors().remove(0);
        let found = detector.scan(&[0u8; 4], &ScanContext::default()).len();
        assert_eq!(found, 1, "logging does not lose the results: {:?}", host.take_log());
        let log = host.take_log();
        assert!(log.contains(&"chatty.lua: loaded".to_string()), "{log:?}");
        assert!(log.contains(&"chatty.lua: scanned 4".to_string()), "{log:?}");
    }

    #[test]
    fn print_writes_to_the_plugin_log_rather_than_standard_output() {
        let mut host = LuaHost::new();
        host.load_source(
            "printer.lua",
            "print('loaded', 1, true, nil); theviewer.register_detector{ id='p', scan=function(w, ctx) print('scanned ' .. w:len()); return {} end }",
        )
        .unwrap();
        let detector = host.detectors().remove(0);
        detector.scan(&[0u8; 4], &ScanContext::default());
        let lines = host.take_entries();
        let texts: Vec<_> = lines.iter().map(|line| (line.plugin.as_str(), line.level, line.text.as_str())).collect();
        assert_eq!(texts, [("printer.lua", LogLevel::Info, "loaded\t1\ttrue\tnil"), ("printer.lua", LogLevel::Info, "scanned 4")]);
    }

    #[test]
    fn findings_need_start_and_len_and_default_the_rest() {
        let mut host = LuaHost::new();
        host.load_source(
            "f.lua",
            "theviewer.register_detector{ id='f', scan=function(w, ctx) return { { start=2, len=3, title='x' }, { start=0, len=1, category='Protocol', confidence=0.4, fields={ {name='a', offset=0, len=1, children={ {name='b', offset=0, len=1} }} } } } end }",
        )
        .unwrap();
        let detector = host.detectors().remove(0);
        let findings = detector.scan(&[0u8; 8], &ScanContext { base: 100, document_len: 108, strides: vec![] });
        assert_eq!(findings.len(), 2);
        assert_eq!((findings[0].start, findings[0].len, findings[0].category), (102, 3, Category::Custom));
        assert_eq!(findings[1].category, Category::Protocol);
        assert!(findings[1].weak());
        assert_eq!(findings[1].fields[0].children[0].offset, 100);
    }
}
