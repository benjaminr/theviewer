//! MCP tools: every API method, the table's and those plugins registered,
//! named with underscores for dots (`bytes.read` is `bytes_read`), with its
//! parameters' schema as the input schema, the built-in methods' result
//! schema as the output schema, and hints on what calling it does.

use serde_json::{Map, Value, json};

use super::jsonrpc::RpcError;
use super::protocol::{RequestContext, has_structured_output};
use crate::api::{self, Caller, Effect, MethodRef, Workspace};

/// Most text one tool result carries: a larger result is refused with a
/// message saying to ask for less.
pub const MAX_RESULT_TEXT: usize = 1024 * 1024;

/// Methods that overwrite or remove what is there: an earlier state is
/// lost, though each edit can be undone.
const DESTRUCTIVE: &[&str] = &["bytes.write", "bytes.delete", "bytes.replace", "bits.write", "transform.apply", "history.undo", "history.redo", "history.transaction", "documents.save"];
/// Methods that change something but, called twice with the same
/// parameters, leave things as one call does.
const IDEMPOTENT: &[&str] = &["bytes.write", "bits.write", "selection.set", "cursor.set", "documents.open", "documents.save"];

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

/// Every tool, in the method table's order and then the plugins', for a
/// client speaking `version`.
pub fn list(workspace: &dyn Workspace, version: &str, output_schemas: bool) -> Vec<Value> {
    api::all_methods(workspace).iter().map(|method| describe(method, version, output_schemas)).collect()
}

/// The method a tool name stands for.
pub fn method_named(workspace: &dyn Workspace, tool: &str) -> Option<MethodRef> {
    api::all_methods(workspace).into_iter().find(|method| tool_name(method.name()) == tool)
}

/// What `tools/call` answers: the method's result as compact JSON text and,
/// where the revision has it, as structured content; an API error as a
/// result marked `isError`, so the model sees it and can try again.
pub fn call(workspace: &mut dyn Workspace, context: &RequestContext, params: &Map<String, Value>) -> Result<Value, RpcError> {
    let tool = params.get("name").and_then(Value::as_str).ok_or_else(|| RpcError::invalid_params("tools/call needs the tool's name"))?;
    let method = method_named(workspace, tool).ok_or_else(|| RpcError::invalid_params(format!("Unknown tool: {tool}; tools/list lists them")))?;
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(arguments @ Value::Object(_)) => arguments.clone(),
        Some(_) => return Err(RpcError::invalid_params("a tool's arguments are an object")),
    };
    let caller = Caller::Mcp(context.client.clone());
    Ok(match api::call(workspace, &caller, method.name(), arguments) {
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

    #[test]
    fn every_method_is_a_tool_named_with_underscores() {
        let workspace = workspace_with("a.bin", b"abc");
        let tools = list(&workspace, MODERN_VERSION, true);
        assert_eq!(tools.len(), api::METHODS.len());
        let names: Vec<&str> = tools.iter().map(|tool| tool["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"bytes_read") && names.contains(&"analysis_text_encoding"));
        assert!(names.iter().all(|name| name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && name.len() <= 64), "{names:?}");
    }

    #[test]
    fn tools_say_whether_they_read_edit_or_destroy() {
        let workspace = workspace_with("a.bin", b"abc");
        let tools = list(&workspace, MODERN_VERSION, true);
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
        let tools = list(&workspace, "2025-03-26", true);
        let read = tools.iter().find(|tool| tool["name"] == "bytes_read").unwrap();
        assert!(read.get("outputSchema").is_none() && read.get("title").is_none());
        assert_eq!(read["annotations"]["readOnlyHint"], true);
        assert!(list(&workspace, "2024-11-05", true)[0].get("annotations").is_none(), "2024-11-05 had no annotations");
        let result = call(&mut workspace, &context("2025-03-26"), &arguments(json!({ "name": "bytes_read", "arguments": { "start": 0, "len": 2 } }))).unwrap();
        assert!(result.get("structuredContent").is_none());
        assert_eq!(serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap()["data"], "6162");
    }

    #[test]
    fn a_call_returns_compact_json_text_and_structured_content() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let result = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_read", "arguments": { "start": 1 } }))).unwrap();
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["data"], "6263");
        assert!(!result["content"][0]["text"].as_str().unwrap().contains('\n'), "compact");
    }

    #[test]
    fn edits_are_labelled_with_the_client() {
        let mut workspace = workspace_with("a.bin", b"abc");
        call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_write", "arguments": { "start": 0, "data": "7a" } }))).unwrap();
        let facts = workspace.bus().changed_since(0);
        assert!(facts.messages.iter().any(|message| message.producer() == "mcp:test-client"), "the edit is published as the client's");
    }

    #[test]
    fn an_api_error_is_a_result_the_model_can_read() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let result = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_read", "arguments": { "start": 9 } }))).unwrap();
        assert_eq!(result["isError"], true);
        let error: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(error["code"], "out_of_range");
    }

    #[test]
    fn an_unknown_tool_or_bad_arguments_are_protocol_errors() {
        let mut workspace = workspace_with("a.bin", b"abc");
        let unknown = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_melt" }))).unwrap_err();
        assert_eq!(unknown.code, crate::mcp::jsonrpc::INVALID_PARAMS);
        assert!(unknown.message.contains("Unknown tool: bytes_melt"));
        let positional = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_read", "arguments": [0] }))).unwrap_err();
        assert_eq!(positional.code, crate::mcp::jsonrpc::INVALID_PARAMS);
    }

    #[test]
    fn a_result_too_large_to_carry_says_to_ask_for_less() {
        let mut workspace = workspace_with("big.bin", &vec![0x41; MAX_RESULT_TEXT]);
        let result = call(&mut workspace, &context(MODERN_VERSION), &arguments(json!({ "name": "bytes_read", "arguments": { "start": 0 } }))).unwrap();
        assert_eq!(result["isError"], true);
        let error: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(error["code"], "too_large");
        assert!(error["message"].as_str().unwrap().contains("ask for less"));
    }
}
