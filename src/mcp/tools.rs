//! MCP tools: API methods, named with underscores for dots (`bytes.read`
//! is `bytes_read`), with its parameters' schema as the input schema, the
//! built-in methods' result schema as the output schema, and hints on what
//! calling it does.
//!
//! A client keeps every listed tool in its model's context, and the API has
//! well over a hundred methods, so by default only the [`CORE`] methods and
//! those plugins registered are listed, beside three tools that reach the
//! rest: `api_search` finds methods, `api_describe` gives one's schemas and
//! `api_call` calls any of them. `theviewer mcp --all-tools` lists every
//! method instead ([`ToolSet::All`]). Either way, `tools/call` takes any
//! method's tool name.

use serde_json::{Map, Value, json};

use super::jsonrpc::RpcError;
use super::protocol::{RequestContext, has_structured_output};
use crate::api::{self, ApiError, Caller, Effect, MethodRef, Workspace};

/// Most text one tool result carries: a larger result is refused with a
/// message saying to ask for less.
pub const MAX_RESULT_TEXT: usize = 1024 * 1024;

/// Methods that overwrite or remove what is there: an earlier state is
/// lost, though each edit can be undone.
const DESTRUCTIVE: &[&str] = &["bytes.write", "bytes.delete", "bytes.replace", "bits.write", "transform.apply", "history.undo", "history.redo", "history.transaction", "documents.save"];
/// Methods that change something but, called twice with the same
/// parameters, leave things as one call does.
const IDEMPOTENT: &[&str] = &["bytes.write", "bits.write", "selection.set", "cursor.set", "documents.open", "documents.save"];

/// Which tools `tools/list` gives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ToolSet {
    /// The [`CORE`] methods, the plugins' methods, `api_search`,
    /// `api_describe` and `api_call`.
    #[default]
    Core,
    /// Every method, as the method table and the plugins list them.
    All,
}

/// The methods listed as tools of their own by default: those a model
/// analysing a file reaches for first. The rest are found with `api_search`
/// and called with `api_call`.
pub const CORE: &[&str] = &[
    // What is open, and opening and saving: the only way edits reach disk.
    "documents.list",
    "documents.open",
    "documents.save",
    // Looking at bytes, raw and as a dump a model reads easily.
    "bytes.read",
    "bytes.hexdump",
    // Finding a pattern, and every place it occurs.
    "search.find",
    "search.find_all",
    // A value at an offset in every common type and byte order.
    "numbers.decode",
    // The map of a whole file, the first call of any triage; the job for
    // large files, and following any job.
    "analysis.overview",
    "analysis.overview_job",
    "jobs.status",
    // Where the file's regions begin and end.
    "analysis.segments",
    // What the detectors and tools recognised, by span.
    "findings.query",
    // Known formats parsed into fields, and a template laid over bytes.
    "structure.parse",
    "templates.apply",
    // Which decompressors decode at an offset.
    "codecs.probe",
    // Packets: one dissected from bytes, a set taken from the file, and one
    // packet of a set dissected.
    "packets.dissect_bytes",
    "packets.sets.create",
    "packets.dissect",
    // Notes on a format or protocol, with the specification's sections.
    "reference.lookup",
    // Edits, each one undoable step, and undoing them. transform.preview
    // shares transform.apply's large schema, so it is left to api_call:
    // applying and undoing does as well.
    "bytes.write",
    "bytes.replace",
    "transform.apply",
    "history.undo",
];

/// The tool that finds methods.
const API_SEARCH: &str = "api_search";
/// The tool that describes one method.
const API_DESCRIBE: &str = "api_describe";
/// The tool that calls any method.
const API_CALL: &str = "api_call";
/// Methods `api_search` gives when it is not asked for a number.
const DEFAULT_SEARCH_LIMIT: usize = 30;

/// The tool name of a method: MCP clients pass tool names to models whose
/// tool names may not have dots.
pub fn tool_name(method: &str) -> String {
    method.replace('.', "_")
}

/// A human title for a method, such as "Bytes › read" or "Analysis › text encoding".
fn title(method: &str) -> String {
    let (namespace, rest) = method.split_once('.').unwrap_or(("", method));
    let mut namespace: Vec<char> = namespace.chars().collect();
    if let Some(first) = namespace.first_mut() {
        *first = first.to_ascii_uppercase();
    }
    let namespace: String = namespace.into_iter().collect();
    format!("{namespace} › {}", rest.replace(['_', '.'], " "))
}

/// What calling a method does, as MCP's tool annotations say it.
fn annotations(method: &MethodRef) -> Value {
    let name = method.name();
    let read_only = method.effect() == Effect::Read;
    let destructive = !read_only && (DESTRUCTIVE.contains(&name) || matches!(method, MethodRef::Registered(_)));
    let idempotent = read_only || IDEMPOTENT.contains(&name);
    json!({
        "title": title(name),
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        // Only the files given and opened are reached.
        "openWorldHint": false,
    })
}

/// The output schema of a built-in method, when it is an object schema as
/// MCP requires. Plugins' methods declare none: their results are not
/// checked against what they say, so a client checking them could refuse a
/// good answer.
fn output_schema(method: &MethodRef) -> Option<Value> {
    let MethodRef::Builtin(builtin) = method else { return None };
    let schema = (builtin.result)().to_value();
    (schema["type"] == "object").then_some(schema)
}

/// One method as an MCP tool, for a client speaking `version`. Output
/// schemas are optional in MCP and double the size of the tool list, which a
/// client keeps in its model's context, so they are given only on request.
pub fn describe(method: &MethodRef, version: &str, output_schemas: bool) -> Value {
    let name = method.name();
    let mut description = method.summary().to_string();
    if let MethodRef::Registered(registered) = method {
        description.push_str(&format!(" (From {}; experimental.)", registered.owner));
    }
    let mut tool = json!({
        "name": tool_name(name),
        "description": description,
        "inputSchema": method.params_schema(),
    });
    // 2024-11-05 had no annotations.
    if version > "2024-11-05" {
        tool["annotations"] = annotations(method);
    }
    if has_structured_output(version) {
        tool["title"] = Value::String(title(name));
        if let Some(schema) = output_schema(method).filter(|_| output_schemas) {
            tool["outputSchema"] = schema;
        }
    }
    tool
}

/// Whether `method` has a tool of its own in `tools`: plugins' methods
/// always do, as the person installed them on purpose.
fn is_listed(method: &MethodRef, tools: ToolSet) -> bool {
    tools == ToolSet::All || matches!(method, MethodRef::Registered(_)) || CORE.contains(&method.name())
}

/// The tools of `tools`, for a client speaking `version`: the methods in
/// the method table's order and then the plugins', and with the core set,
/// the tools that reach the rest.
pub fn list(workspace: &dyn Workspace, version: &str, output_schemas: bool, tools: ToolSet) -> Vec<Value> {
    let methods = api::all_methods(workspace).into_iter().filter(|method| is_listed(method, tools)).map(|method| describe(&method, version, output_schemas));
    match tools {
        ToolSet::All => methods.collect(),
        ToolSet::Core => methods.chain(meta_tools(version)).collect(),
    }
}

/// The method a tool name stands for; a method's dotted name is taken too.
pub fn method_named(workspace: &dyn Workspace, tool: &str) -> Option<MethodRef> {
    api::all_methods(workspace).into_iter().find(|method| method.name() == tool || tool_name(method.name()) == tool)
}

/// `api_search`, `api_describe` and `api_call`, for a client speaking `version`.
fn meta_tools(version: &str) -> Vec<Value> {
    let tools = [
        (
            API_SEARCH,
            "Search all the API's methods, beyond those listed as tools, by words in their names and summaries; gives each one's name, summary and effect. Call one with api_call.",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Words that must all appear in a method's name or summary, such as \"entropy\" or \"packets export\"; empty lists every method" },
                    "namespace": { "type": "string", "description": "Only methods of this namespace, such as \"bits\" or \"packets\"; \"plugins\" for the plugins' methods" },
                    "limit": { "type": "integer", "minimum": 1, "description": "Most methods given (30 by default)" },
                },
                "required": ["query"],
                "additionalProperties": false,
            }),
            true,
        ),
        (
            API_DESCRIBE,
            "One API method's summary, effect and the JSON schemas of its parameters and result, to call it with api_call.",
            json!({
                "type": "object",
                "properties": { "method": { "type": "string", "description": "The method's name, such as \"bits.scan_periods\"" } },
                "required": ["method"],
                "additionalProperties": false,
            }),
            true,
        ),
        (
            API_CALL,
            "Call any API method by name with its parameters, as its own tool would be called; find methods with api_search and their parameters with api_describe.",
            json!({
                "type": "object",
                "properties": {
                    "method": { "type": "string", "description": "The method's name, such as \"bytes.insert\"" },
                    "params": { "type": "object", "description": "The method's parameters, as api_describe gives their schema" },
                },
                "required": ["method"],
                "additionalProperties": false,
            }),
            false,
        ),
    ];
    tools
        .into_iter()
        .map(|(name, description, input_schema, read_only)| {
            let mut tool = json!({ "name": name, "description": description, "inputSchema": input_schema });
            if version > "2024-11-05" {
                tool["annotations"] = json!({
                    "title": title(&name.replace('_', ".")),
                    "readOnlyHint": read_only,
                    // api_call may call a method that overwrites.
                    "destructiveHint": !read_only,
                    "idempotentHint": read_only,
                    "openWorldHint": false,
                });
            }
            if has_structured_output(version) {
                tool["title"] = Value::String(title(&name.replace('_', ".")));
            }
            tool
        })
        .collect()
}

/// `api_search`: the methods whose name or summary holds every word of the
/// query, in the namespace asked for, at most `limit` of them.
fn search(workspace: &dyn Workspace, arguments: &Value, tools: ToolSet) -> Result<Value, ApiError> {
    let query = arguments.get("query").and_then(Value::as_str).unwrap_or_default().to_lowercase();
    let words: Vec<String> = query.split_whitespace().map(|word| word.replace('_', ".")).collect();
    let namespace = arguments.get("namespace").and_then(Value::as_str).filter(|namespace| !namespace.is_empty());
    let limit = match arguments.get("limit") {
        None | Some(Value::Null) => DEFAULT_SEARCH_LIMIT,
        Some(limit) => limit.as_u64().filter(|&limit| limit > 0).ok_or_else(|| ApiError::invalid_params("limit is a whole number above 0"))? as usize,
    };
    let in_namespace = |method: &MethodRef| match namespace {
        None => true,
        Some("plugins") => matches!(method, MethodRef::Registered(_)),
        Some(namespace) => method.name().strip_prefix(namespace).is_some_and(|rest| rest.starts_with('.')),
    };
    let matches_query = |method: &MethodRef| {
        let text = format!("{} {}", method.name(), method.summary()).to_lowercase();
        words.iter().all(|word| text.contains(word.as_str()))
    };
    let found: Vec<MethodRef> = api::all_methods(workspace).into_iter().filter(|method| in_namespace(method) && matches_query(method)).collect();
    let methods: Vec<Value> = found
        .iter()
        .take(limit)
        .map(|method| {
            let mut entry = json!({ "name": method.name(), "summary": method.summary(), "effect": method.effect() });
            if is_listed(method, tools) {
                entry["tool"] = Value::String(tool_name(method.name()));
            }
            entry
        })
        .collect();
    Ok(json!({ "methods": methods, "total": found.len() }))
}

/// The method `arguments.method` names, or why there is none.
fn named_method(workspace: &dyn Workspace, arguments: &Value) -> Result<MethodRef, ApiError> {
    let name = arguments.get("method").and_then(Value::as_str).ok_or_else(|| ApiError::invalid_params("name the method, such as {\"method\": \"bytes.insert\"}"))?;
    method_named(workspace, name).ok_or_else(|| ApiError::not_found(format!("there is no method {name}; api_search finds them")))
}

/// `api_describe`: one method as `api.describe` lists it.
fn describe_one(workspace: &dyn Workspace, arguments: &Value) -> Result<Value, ApiError> {
    let method = named_method(workspace, arguments)?;
    Ok(serde_json::to_value(method.describe()).unwrap_or_default())
}

/// `api_call`: the method named, called with the parameters given.
fn call_any(workspace: &mut dyn Workspace, caller: &Caller, arguments: &Value) -> Result<Value, ApiError> {
    let method = named_method(workspace, arguments)?;
    let params = match arguments.get("params") {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(params @ Value::Object(_)) => params.clone(),
        Some(_) => return Err(ApiError::invalid_params("a method's params are an object")),
    };
    api::call(workspace, caller, method.name(), params)
}

/// What `tools/call` answers: the method's result as compact JSON text and,
/// where the revision has it, as structured content; an API error as a
/// result marked `isError`, so the model sees it and can try again.
///
/// With the core set, `api_search`, `api_describe` and `api_call` are the
/// tools of those names; with every method listed, they are methods'.
pub fn call(workspace: &mut dyn Workspace, context: &RequestContext, params: &Map<String, Value>, tools: ToolSet) -> Result<Value, RpcError> {
    let tool = params.get("name").and_then(Value::as_str).ok_or_else(|| RpcError::invalid_params("tools/call needs the tool's name"))?;
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(arguments @ Value::Object(_)) => arguments.clone(),
        Some(_) => return Err(RpcError::invalid_params("a tool's arguments are an object")),
    };
    let caller = Caller::Mcp(context.client.clone());
    let answer = match (tools, tool) {
        (ToolSet::Core, API_SEARCH) => search(workspace, &arguments, tools),
        (ToolSet::Core, API_DESCRIBE) => describe_one(workspace, &arguments),
        (ToolSet::Core, API_CALL) => call_any(workspace, &caller, &arguments),
        _ => {
            let method = method_named(workspace, tool).ok_or_else(|| RpcError::invalid_params(format!("Unknown tool: {tool}; tools/list lists them")))?;
            api::call(workspace, &caller, method.name(), arguments)
        }
    };
    Ok(match answer {
        Ok(value) => success(value, context.version),
        Err(error) => failure(&error.to_json()),
    })
}

/// A successful tool result.
fn success(value: Value, version: &str) -> Value {
    let text = serde_json::to_string(&value).unwrap_or_default();
    if text.len() > MAX_RESULT_TEXT {
        let error = json!({
            "code": "too_large",
            "message": format!("the result is {} bytes of JSON, more than the {MAX_RESULT_TEXT} a tool result carries; ask for less: a shorter len, a smaller limit, or a page at a time with next", text.len()),
        });
        return failure(&error);
    }
    let mut result = json!({ "content": [{ "type": "text", "text": text }], "isError": false });
    if has_structured_output(version) && value.is_object() {
        result["structuredContent"] = value;
    }
    result
}

/// A tool result reporting an error.
fn failure(error: &Value) -> Value {
    json!({ "content": [{ "type": "text", "text": serde_json::to_string(error).unwrap_or_default() }], "isError": true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::test_support::workspace_with;
    use crate::mcp::protocol::MODERN_VERSION;

    fn context(version: &'static str) -> RequestContext {
        RequestContext { version, client: "test-client".into(), log_level: None }
    }

    fn arguments(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn arguments_of(value: Value) -> Map<String, Value> {
        arguments(value)
    }

    fn names(tools: &[Value]) -> Vec<&str> {
        tools.iter().map(|tool| tool["name"].as_str().unwrap()).collect()
    }

    fn structured(result: &Value) -> Value {
        assert_eq!(result["isError"], false, "{result}");
        result["structuredContent"].clone()
    }

    fn error_code(result: &Value) -> Value {
        assert_eq!(result["isError"], true, "{result}");
        serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap()["code"].clone()
    }

    #[test]
    fn by_default_the_core_methods_are_tools_with_three_that_reach_the_rest() {
        let workspace = workspace_with("a.bin", b"abc");
        let tools = list(&workspace, MODERN_VERSION, false, ToolSet::Core);
        let names = names(&tools);
        assert_eq!(names.len(), CORE.len() + 3, "{names:?}");
        assert!(CORE.iter().all(|method| names.contains(&tool_name(method).as_str())), "{names:?}");
        assert_eq!(names[names.len() - 3..], ["api_search", "api_describe", "api_call"]);
        assert!(!names.contains(&"bytes_insert") && !names.contains(&"bits_scan_periods"));
        let call_tool = &tools[names.len() - 1];
        assert_eq!((call_tool["annotations"]["readOnlyHint"].clone(), call_tool["inputSchema"]["required"].clone()), (json!(false), json!(["method"])));
        assert!(list(&workspace, "2024-11-05", false, ToolSet::Core).iter().all(|tool| tool.get("annotations").is_none()), "2024-11-05 had no annotations");
    }

    #[test]
    fn every_core_method_is_in_the_method_table() {
        for method in CORE {
            assert!(api::METHODS.iter().any(|known| known.name == *method), "{method} is not a method");
        }
    }

    #[test]
    fn a_plugin_s_methods_are_tools_of_their_own_even_with_the_core_set() {
        let mut workspace = workspace_with("a.bin", b"abc");
        workspace.set_registered_methods(vec![std::sync::Arc::new(crate::api::RegisteredMethod {
            name: "probe.echo".to_string(),
            summary: "Echo the text given.".to_string(),
            effect: Effect::Read,
            params: json!({ "type": "object" }),
            result: json!({ "type": "object" }),
            owner: "plugin:probe.lua".to_string(),
            run: Box::new(|_, _, params| Ok(params)),
        })]);
        let tools = list(&workspace, MODERN_VERSION, false, ToolSet::Core);
        assert!(names(&tools).contains(&"probe_echo"));
        let found = structured(&call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "api_search", "arguments": { "query": "", "namespace": "plugins" } })), ToolSet::Core).unwrap());
        assert_eq!((found["total"].clone(), found["methods"][0]["name"].clone(), found["methods"][0]["tool"].clone()), (json!(1), json!("probe.echo"), json!("probe_echo")));
    }

    #[test]
    fn api_search_finds_methods_by_words_in_their_names_and_summaries() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let search = |workspace: &mut crate::api::HeadlessWorkspace, arguments: Value| structured(&call(workspace, &context(MODERN_VERSION), &arguments_of(json!({ "name": "api_search", "arguments": arguments })), ToolSet::Core).unwrap());
        let found = search(&mut workspace, json!({ "query": "pcap" }));
        let names: Vec<&str> = found["methods"].as_array().unwrap().iter().map(|method| method["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"packets.export_pcap"), "{found}");
        let export = found["methods"].as_array().unwrap().iter().find(|method| method["name"] == "packets.export_pcap").unwrap();
        assert_eq!(export["effect"], "analysis");
        assert!(export.get("tool").is_none(), "not a tool of its own: it is called with api_call");
        let insert = search(&mut workspace, json!({ "query": "bytes_insert" }));
        assert_eq!(insert["methods"][0]["name"], "bytes.insert", "a tool name finds its method");
        let in_bits = search(&mut workspace, json!({ "query": "", "namespace": "bits" }));
        assert!(in_bits["methods"].as_array().unwrap().iter().all(|method| method["name"].as_str().unwrap().starts_with("bits.")));
        let read = search(&mut workspace, json!({ "query": "read", "namespace": "bytes", "limit": 1 }));
        assert_eq!((read["methods"].as_array().unwrap().len(), read["methods"][0]["tool"].clone()), (1, json!("bytes_read")));
        assert!(read["total"].as_u64().unwrap() >= 1);
        assert_eq!(search(&mut workspace, json!({ "query": "no such words at all" }))["total"], 0);
    }

    #[test]
    fn api_describe_gives_one_method_s_schemas() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let described = structured(&call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "api_describe", "arguments": { "method": "bytes.insert" } })), ToolSet::Core).unwrap());
        assert_eq!((described["name"].clone(), described["effect"].clone()), (json!("bytes.insert"), json!("edit")));
        assert_eq!((described["params"]["type"].clone(), described["result"]["type"].clone()), (json!("object"), json!("object")));
        let unknown = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "api_describe", "arguments": { "method": "bytes.melt" } })), ToolSet::Core).unwrap();
        assert_eq!(error_code(&unknown), "not_found");
    }

    #[test]
    fn api_call_calls_any_method_as_the_client_with_the_same_result() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let inserted = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "api_call", "arguments": { "method": "bytes.insert", "params": { "at": 0, "data": "7a" } } })), ToolSet::Core).unwrap();
        assert_eq!(structured(&inserted)["version"], 1);
        let read = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "api_call", "arguments": { "method": "bytes_read", "params": { "start": 0, "len": 2 } } })), ToolSet::Core).unwrap();
        let direct = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_read", "arguments": { "start": 0, "len": 2 } })), ToolSet::Core).unwrap();
        assert_eq!(read, direct, "the same shape as calling the tool itself");
        assert!(workspace.bus().changed_since(0).messages.iter().any(|message| message.producer() == "mcp:test-client"), "the edit is the client's");
        let unknown = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "api_call", "arguments": { "method": "bytes.melt" } })), ToolSet::Core).unwrap();
        assert_eq!(error_code(&unknown), "not_found");
        let positional = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "api_call", "arguments": { "method": "bytes.read", "params": [0] } })), ToolSet::Core).unwrap();
        assert_eq!(error_code(&positional), "invalid_params");
        let out_of_range = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "api_call", "arguments": { "method": "bytes.read", "params": { "start": 9 } } })), ToolSet::Core).unwrap();
        assert_eq!(error_code(&out_of_range), "out_of_range", "the method's own errors come back as they would from its tool");
    }

    #[test]
    fn api_call_is_refused_what_the_client_may_not_do() {
        let mut app = crate::app::ViewerApp::new(crate::app::Launch::default());
        app.open_bytes(b"abc".to_vec(), "a.bin".to_string());
        app.preferences.permissions.insert("mcp:test-client".to_string(), crate::api::permissions::Policy::Deny);
        let refused = call(&mut app, &context(MODERN_VERSION), &arguments(json!({ "name": "api_call", "arguments": { "method": "bytes.insert", "params": { "at": 0, "data": "7a" } } })), ToolSet::Core).unwrap();
        assert_eq!(error_code(&refused), "read_only");
        assert_eq!(app.document.len(), 3, "nothing was inserted");
    }

    #[test]
    fn with_every_tool_listed_the_api_names_are_the_methods_own() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let tools = list(&workspace, MODERN_VERSION, false, ToolSet::All);
        assert!(!names(&tools).contains(&"api_search"));
        let described = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "api_describe" })), ToolSet::All).unwrap();
        assert!(structured(&described)["methods"].as_array().unwrap().len() >= api::METHODS.len(), "api_describe is the method api.describe");
    }

    #[test]
    fn every_method_is_a_tool_named_with_underscores() {
        let workspace = workspace_with("a.bin", b"abc");
        let tools = list(&workspace, MODERN_VERSION, true, ToolSet::All);
        assert_eq!(tools.len(), api::METHODS.len());
        let names: Vec<&str> = tools.iter().map(|tool| tool["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"bytes_read") && names.contains(&"analysis_text_encoding"));
        assert!(names.iter().all(|name| name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && name.len() <= 64), "{names:?}");
    }

    #[test]
    fn tools_say_whether_they_read_edit_or_destroy() {
        let workspace = workspace_with("a.bin", b"abc");
        let tools = list(&workspace, MODERN_VERSION, true, ToolSet::All);
        let tool = |name: &str| tools.iter().find(|tool| tool["name"] == name).unwrap().clone();
        let read = tool("bytes_read");
        assert_eq!((read["annotations"]["readOnlyHint"].clone(), read["title"].clone()), (json!(true), json!("Bytes › read")));
        assert_eq!(read["inputSchema"]["type"], "object");
        assert_eq!(read["outputSchema"]["type"], "object", "built-in methods describe their results");
        let delete = tool("bytes_delete");
        assert_eq!((delete["annotations"]["readOnlyHint"].clone(), delete["annotations"]["destructiveHint"].clone()), (json!(false), json!(true)));
        let insert = tool("bytes_insert");
        assert_eq!((insert["annotations"]["destructiveHint"].clone(), insert["annotations"]["idempotentHint"].clone()), (json!(false), json!(false)), "inserting loses nothing");
        assert_eq!(tool("bytes_write")["annotations"]["idempotentHint"], true);
        assert_eq!(tool("history_undo")["annotations"]["destructiveHint"], true);
    }

    #[test]
    fn older_revisions_get_no_output_schema_or_structured_content() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let tools = list(&workspace, "2025-03-26", true, ToolSet::All);
        let read = tools.iter().find(|tool| tool["name"] == "bytes_read").unwrap();
        assert!(read.get("outputSchema").is_none() && read.get("title").is_none());
        assert_eq!(read["annotations"]["readOnlyHint"], true);
        assert!(list(&workspace, "2024-11-05", true, ToolSet::All)[0].get("annotations").is_none(), "2024-11-05 had no annotations");
        let result = call(&mut workspace, &context("2025-03-26"), &arguments(json!({ "name": "bytes_read", "arguments": { "start": 0, "len": 2 } })), ToolSet::Core).unwrap();
        assert!(result.get("structuredContent").is_none());
        assert_eq!(serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap()["data"], "6162");
    }

    #[test]
    fn a_call_returns_compact_json_text_and_structured_content() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let result = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_read", "arguments": { "start": 1 } })), ToolSet::Core).unwrap();
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["data"], "6263");
        assert!(!result["content"][0]["text"].as_str().unwrap().contains('\n'), "compact");
    }

    #[test]
    fn edits_are_labelled_with_the_client() {
        let mut workspace = workspace_with("a.bin", b"abc");
        call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_write", "arguments": { "start": 0, "data": "7a" } })), ToolSet::Core).unwrap();
        let facts = workspace.bus().changed_since(0);
        assert!(facts.messages.iter().any(|message| message.producer() == "mcp:test-client"), "the edit is published as the client's");
    }

    #[test]
    fn an_api_error_is_a_result_the_model_can_read() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let result = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_read", "arguments": { "start": 9 } })), ToolSet::Core).unwrap();
        assert_eq!(result["isError"], true);
        let error: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(error["code"], "out_of_range");
    }

    #[test]
    fn an_unknown_tool_or_bad_arguments_are_protocol_errors() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let unknown = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_melt" })), ToolSet::Core).unwrap_err();
        assert_eq!(unknown.code, crate::mcp::jsonrpc::INVALID_PARAMS);
        assert!(unknown.message.contains("Unknown tool: bytes_melt"));
        let positional = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_read", "arguments": [0] })), ToolSet::Core).unwrap_err();
        assert_eq!(positional.code, crate::mcp::jsonrpc::INVALID_PARAMS);
    }

    #[test]
    fn a_result_too_large_to_carry_says_to_ask_for_less() {
        let mut workspace = workspace_with("big.bin", &vec![0x41; MAX_RESULT_TEXT]);
        let result = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_read", "arguments": { "start": 0 } })), ToolSet::Core).unwrap();
        assert_eq!(result["isError"], true);
        let error: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(error["code"], "too_large");
        assert!(error["message"].as_str().unwrap().contains("ask for less"));
    }
}
