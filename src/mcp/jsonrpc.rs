//! JSON-RPC 2.0 framing for the MCP server: one message per line, read
//! from a client and written back, with the standard error codes.
//!
//! Only what MCP uses is accepted: requests with a string or integer id,
//! notifications, and responses (which this server never asks for, so it
//! ignores them). Batches were removed from MCP and are refused.

use std::io::{self, Write};

use serde_json::{Map, Value, json};

/// The text was not JSON.
pub const PARSE_ERROR: i64 = -32700;
/// The JSON was not a request, notification or response.
pub const INVALID_REQUEST: i64 = -32600;
/// No such method.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// The parameters are wrong, or (since MCP 2026-07-28) the resource asked for does not exist.
pub const INVALID_PARAMS: i64 = -32602;
/// Something went wrong inside the server.
pub const INTERNAL_ERROR: i64 = -32603;
/// A resource that does not exist, as MCP 2025-11-25 and earlier say it.
pub const LEGACY_RESOURCE_NOT_FOUND: i64 = -32002;
/// The request's protocol version is not one this server speaks (MCP 2026-07-28).
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// A request's id: a string or an integer, never null.
pub type RequestId = Value;

/// One line from the client, understood.
#[derive(Clone, Debug, PartialEq)]
pub enum Incoming {
    /// A call that wants an answer.
    Request { id: RequestId, method: String, params: Map<String, Value> },
    /// A one-way message; nothing is sent back.
    Notification { method: String, params: Map<String, Value> },
    /// An answer to a request: this server sends none, so these are ignored.
    Response,
}

/// Why a line could not be understood: what to answer, and to which id
/// (null when the id could not be read).
#[derive(Clone, Debug, PartialEq)]
pub struct Malformed {
    pub id: Value,
    pub error: RpcError,
}

/// A JSON-RPC error object.
#[derive(Clone, Debug, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        RpcError { code, message: message.into(), data: None }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, message)
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(METHOD_NOT_FOUND, format!("there is no method '{method}'"))
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    fn to_json(&self) -> Value {
        let mut error = json!({ "code": self.code, "message": self.message });
        if let Some(data) = &self.data {
            error["data"] = data.clone();
        }
        error
    }
}

/// Understand one line from the client.
pub fn parse(line: &str) -> Result<Incoming, Malformed> {
    let value: Value = serde_json::from_str(line).map_err(|error| Malformed { id: Value::Null, error: RpcError::new(PARSE_ERROR, format!("not JSON: {error}")) })?;
    let invalid = |id: &Value, message: &str| Malformed { id: id.clone(), error: RpcError::new(INVALID_REQUEST, message) };
    let Value::Object(mut message) = value else {
        let what = if value.is_array() { "batches are not supported; send one message per line" } else { "a message is a JSON object" };
        return Err(invalid(&Value::Null, what));
    };
    let id = message.remove("id");
    let readable_id = id.clone().filter(is_valid_id).unwrap_or(Value::Null);
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(invalid(&readable_id, "a message needs \"jsonrpc\": \"2.0\""));
    }
    let Some(method) = message.remove("method") else {
        return if message.contains_key("result") || message.contains_key("error") { Ok(Incoming::Response) } else { Err(invalid(&readable_id, "a message needs a method, or a result or error")) };
    };
    let Value::String(method) = method else {
        return Err(invalid(&readable_id, "a method is a string"));
    };
    let params = match message.remove("params") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(params)) => params,
        Some(_) => {
            let error = RpcError::invalid_params("params is an object of named parameters");
            return Err(Malformed { id: readable_id, error });
        }
    };
    match id {
        None => Ok(Incoming::Notification { method, params }),
        Some(id) if is_valid_id(&id) => Ok(Incoming::Request { id, method, params }),
        Some(_) => Err(invalid(&Value::Null, "an id is a string or an integer")),
    }
}

/// Whether `id` may identify a request: a string or an integer.
fn is_valid_id(id: &Value) -> bool {
    id.is_string() || id.is_i64() || id.is_u64()
}

/// A successful response.
pub fn result(id: &RequestId, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// A failed response.
pub fn error(id: &RequestId, error: &RpcError) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": error.to_json() })
}

/// A notification from the server.
pub fn notification(method: &str, params: Value) -> Value {
    if params.as_object().is_some_and(Map::is_empty) {
        json!({ "jsonrpc": "2.0", "method": method })
    } else {
        json!({ "jsonrpc": "2.0", "method": method, "params": params })
    }
}

/// Write one message as a line and flush it, so the client sees it at once.
/// Compact JSON has no newlines in it: those inside strings are escaped.
pub fn write_message(out: &mut dyn Write, message: &Value) -> io::Result<()> {
    let mut line = serde_json::to_string(message).map_err(io::Error::other)?;
    line.push('\n');
    out.write_all(line.as_bytes())?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_a_notification_and_a_response_are_told_apart() {
        let request = parse(r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"cursor":"2"}}"#).unwrap();
        let Incoming::Request { id, method, params } = request else { panic!("a request") };
        assert_eq!((id, method.as_str(), &params["cursor"]), (json!(7), "tools/list", &json!("2")));
        assert_eq!(parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).unwrap(), Incoming::Notification { method: "notifications/initialized".into(), params: Map::new() });
        assert_eq!(parse(r#"{"jsonrpc":"2.0","id":"a","result":{}}"#).unwrap(), Incoming::Response);
        let Incoming::Request { id, .. } = parse(r#"{"jsonrpc":"2.0","id":"abc","method":"ping"}"#).unwrap() else { panic!("a request") };
        assert_eq!(id, json!("abc"), "string ids are kept as they are");
    }

    #[test]
    fn text_that_is_not_json_is_a_parse_error_with_a_null_id() {
        let malformed = parse("{not json").unwrap_err();
        assert_eq!((malformed.id, malformed.error.code), (Value::Null, PARSE_ERROR));
    }

    #[test]
    fn messages_that_are_not_requests_are_invalid_and_keep_their_id_when_it_can_be_read() {
        assert_eq!(parse(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#).unwrap_err().error.code, INVALID_REQUEST, "no batches");
        assert_eq!(parse("42").unwrap_err().error.code, INVALID_REQUEST);
        let wrong_version = parse(r#"{"jsonrpc":"1.0","id":3,"method":"ping"}"#).unwrap_err();
        assert_eq!((wrong_version.id, wrong_version.error.code), (json!(3), INVALID_REQUEST));
        assert_eq!(parse(r#"{"jsonrpc":"2.0","id":3,"method":5}"#).unwrap_err().error.code, INVALID_REQUEST);
        let null_id = parse(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#).unwrap_err();
        assert_eq!((null_id.id, null_id.error.code), (Value::Null, INVALID_REQUEST), "MCP ids are never null");
        assert_eq!(parse(r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#).unwrap_err().error.code, INVALID_REQUEST);
        let positional = parse(r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":[1]}"#).unwrap_err();
        assert_eq!((positional.id, positional.error.code), (json!(4), INVALID_PARAMS));
    }

    #[test]
    fn each_message_is_written_as_one_line_even_when_its_text_has_newlines() {
        let mut out = Vec::new();
        write_message(&mut out, &result(&json!(1), json!({ "text": "two\nlines" }))).unwrap();
        write_message(&mut out, &notification("notifications/tools/list_changed", json!({}))).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert_eq!(serde_json::from_str::<Value>(lines[0]).unwrap()["result"]["text"], "two\nlines");
        assert_eq!(lines[1], r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#, "an empty params is left out");
    }

    #[test]
    fn errors_carry_their_code_message_and_data() {
        let failure = error(&json!("x"), &RpcError::invalid_params("no such resource").with_data(json!({ "uri": "theviewer://doc/doc-9" })));
        assert_eq!(failure, json!({ "jsonrpc": "2.0", "id": "x", "error": { "code": -32602, "message": "no such resource", "data": { "uri": "theviewer://doc/doc-9" } } }));
    }
}
