//! The MCP server: requests in, answers out, against a headless workspace
//! of the files it was given.
//!
//! Each line is handled in turn on one thread, while another reads them.

use std::collections::VecDeque;
use std::io::{self, BufRead, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;

use serde_json::{Map, Value, json};

use super::jsonrpc::{self, INTERNAL_ERROR, Incoming, RequestId, RpcError};
use super::protocol::{self, RequestContext};
use super::tools;
use crate::api::HeadlessWorkspace;
use crate::app::SharedLuaHost;

/// Items in one page of a list.
pub const PAGE_SIZE: usize = 100;
/// How long clients may keep lists that change only with the plugins or
/// documents.
const STABLE_TTL_MS: u64 = 60 * 60 * 1000;

/// The handshake session of a client speaking a revision before 2026-07-28.
struct Session {
    version: &'static str,
    client: String,
}

/// The server's state.
pub struct Server {
    workspace: HeadlessWorkspace,
    /// Kept so the methods plugins registered stay loaded.
    _plugin_host: SharedLuaHost,
    session: Option<Session>,
    page_size: usize,
}

impl Server {
    pub fn new(workspace: HeadlessWorkspace, plugin_host: SharedLuaHost) -> Self {
        Server { workspace, _plugin_host: plugin_host, session: None, page_size: PAGE_SIZE }
    }

    /// Use pages of `size` items in lists.
    pub fn with_page_size(mut self, size: usize) -> Self {
        self.page_size = size.max(1);
        self
    }

    /// Handle one line from the client, writing what it causes.
    pub fn handle_line(&mut self, line: &str, out: &mut dyn Write) -> io::Result<()> {
        if line.trim().is_empty() {
            return Ok(());
        }
        match jsonrpc::parse(line) {
            Err(malformed) => jsonrpc::write_message(out, &jsonrpc::error(&malformed.id, &malformed.error)),
            // Notifications need no answer, and this server asks nothing.
            Ok(Incoming::Response | Incoming::Notification { .. }) => Ok(()),
            Ok(Incoming::Request { id, method, params }) => self.request(&id, &method, &params, out),
        }
    }

    fn request(&mut self, id: &RequestId, method: &str, params: &Map<String, Value>, out: &mut dyn Write) -> io::Result<()> {
        let outcome = catch_unwind(AssertUnwindSafe(|| self.answer(method, params)));
        let (context, reply) = outcome.unwrap_or_else(|_| (None, Err(RpcError::new(INTERNAL_ERROR, format!("{method} failed inside the server; the error is on its standard error")))));
        let message = match reply {
            Ok(result) => jsonrpc::result(id, decorate(result, method, context.as_ref())),
            Err(error) => jsonrpc::error(id, &error),
        };
        jsonrpc::write_message(out, &message)
    }

    /// Answer a request: the context it was made in, when it could be
    /// told, and its result.
    fn answer(&mut self, method: &str, params: &Map<String, Value>) -> (Option<RequestContext>, Result<Value, RpcError>) {
        if method == "initialize" {
            return (None, Ok(self.initialize(params)));
        }
        if method == "ping" {
            return (protocol::modern_context(params).ok().flatten(), Ok(json!({})));
        }
        match self.context(params) {
            Ok(context) => {
                let reply = self.dispatch(&context, method, params);
                (Some(context), reply)
            }
            Err(error) => (None, Err(error)),
        }
    }

    /// The context a request is made in: its own `_meta`, or the session
    /// `initialize` began.
    fn context(&self, params: &Map<String, Value>) -> Result<RequestContext, RpcError> {
        if let Some(context) = protocol::modern_context(params)? {
            return Ok(context);
        }
        let session = self.session.as_ref().ok_or_else(|| {
            RpcError::invalid_params(format!(
                "the request has no \"{}\" in its _meta; send it on every request (protocol {}), or begin with initialize (protocol {} and earlier)",
                protocol::META_PROTOCOL_VERSION,
                protocol::MODERN_VERSION,
                protocol::LEGACY_VERSIONS[0],
            ))
        })?;
        Ok(RequestContext { version: session.version, client: session.client.clone(), log_level: None })
    }

    /// Begin a handshake session, agreeing on a revision.
    fn initialize(&mut self, params: &Map<String, Value>) -> Value {
        let version = protocol::negotiate_legacy(params.get("protocolVersion").and_then(Value::as_str));
        let client = protocol::client_label(params.get("clientInfo").and_then(|info| info["name"].as_str()));
        eprintln!("theviewer mcp: {client} connected, speaking {version}");
        self.session = Some(Session { version, client });
        json!({
            "protocolVersion": version,
            "capabilities": protocol::capabilities(),
            "serverInfo": protocol::server_info(),
            "instructions": protocol::INSTRUCTIONS,
        })
    }

    fn dispatch(&mut self, context: &RequestContext, method: &str, params: &Map<String, Value>) -> Result<Value, RpcError> {
        match method {
            "server/discover" => Ok(json!({ "supportedVersions": protocol::supported_versions(), "capabilities": protocol::capabilities(), "instructions": protocol::INSTRUCTIONS })),
            "tools/list" => {
                let (tools, next) = page(tools::list(&self.workspace, context.version), params, self.page_size)?;
                Ok(with_next(json!({ "tools": tools }), next))
            }
            "tools/call" => tools::call(&mut self.workspace, context, params),
            _ => Err(RpcError::method_not_found(method)),
        }
    }
}

/// The page of `items` the request's `cursor` asks for, and the cursor of
/// the next page, if any.
fn page(items: Vec<Value>, params: &Map<String, Value>, size: usize) -> Result<(Vec<Value>, Option<String>), RpcError> {
    let from = match params.get("cursor") {
        None | Some(Value::Null) => 0,
        Some(cursor) => cursor.as_str().and_then(|text| text.parse::<usize>().ok()).filter(|from| *from <= items.len()).ok_or_else(|| RpcError::invalid_params(format!("{cursor} is not a cursor this server gave; list again from the start")))?,
    };
    let total = items.len();
    let page: Vec<Value> = items.into_iter().skip(from).take(size).collect();
    let after = from + page.len();
    Ok((page, (after < total).then(|| after.to_string())))
}

fn with_next(mut result: Value, next: Option<String>) -> Value {
    if let Some(next) = next {
        result["nextCursor"] = Value::String(next);
    }
    result
}

/// A result as the request's revision writes it: the current one says the
/// result is complete, names the server, and gives caching hints.
fn decorate(mut result: Value, method: &str, context: Option<&RequestContext>) -> Value {
    if !context.is_some_and(RequestContext::is_modern) {
        return result;
    }
    result["resultType"] = json!("complete");
    result["_meta"] = json!({ (protocol::META_SERVER_INFO): protocol::server_info() });
    let ttl = match method {
        "server/discover" => Some(STABLE_TTL_MS),
        "tools/list" => Some(0),
        _ => None,
    };
    if let Some(ttl) = ttl {
        result["ttlMs"] = json!(ttl);
        result["cacheScope"] = json!("private");
    }
    result
}

/// What the line reader hands the server.
enum Input {
    Line(String),
    /// A line that was not UTF-8 text.
    NotText,
}

/// Read lines from `input` on a thread of their own, until it ends.
fn read_lines(mut input: impl BufRead, sender: mpsc::Sender<Input>) {
    let mut line = Vec::new();
    loop {
        line.clear();
        match input.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                let read = match String::from_utf8(std::mem::take(&mut line)) {
                    Ok(text) => Input::Line(text),
                    Err(_) => Input::NotText,
                };
                if sender.send(read).is_err() {
                    return;
                }
            }
        }
    }
}

/// Whether a request was cancelled before it was started: a cancellation
/// for its id is already waiting behind it. Requests are answered in turn,
/// so one already started is finished.
fn cancelled_while_waiting(line: &str, waiting: &VecDeque<Input>) -> bool {
    let Ok(Incoming::Request { id, .. }) = jsonrpc::parse(line) else { return false };
    waiting.iter().any(|later| match later {
        Input::Line(later) => matches!(jsonrpc::parse(later), Ok(Incoming::Notification { method, params }) if method == "notifications/cancelled" && params.get("requestId") == Some(&id)),
        Input::NotText => false,
    })
}

/// Serve MCP on `input` and `output` until the input ends.
pub fn serve(server: &mut Server, input: impl BufRead + Send + 'static, output: &mut dyn Write) -> io::Result<()> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || read_lines(input, sender));
    let mut waiting: VecDeque<Input> = VecDeque::new();
    while let Ok(input) = receiver.recv() {
        waiting.push_back(input);
        waiting.extend(receiver.try_iter());
        while let Some(input) = waiting.pop_front() {
            match input {
                Input::Line(line) if cancelled_while_waiting(&line, &waiting) => eprintln!("theviewer mcp: a request was cancelled before it started"),
                Input::Line(line) => server.handle_line(&line, output)?,
                Input::NotText => jsonrpc::write_message(output, &jsonrpc::error(&Value::Null, &RpcError::new(jsonrpc::PARSE_ERROR, "the line is not UTF-8 text")))?,
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api;
    use crate::api::test_support::workspace_with;
    use crate::mcp::jsonrpc::{INVALID_PARAMS, METHOD_NOT_FOUND, PARSE_ERROR, UNSUPPORTED_PROTOCOL_VERSION};
    use crate::mcp::protocol::MODERN_VERSION;

    fn server() -> Server {
        let host = std::sync::Arc::new(std::sync::Mutex::new(crate::plugins::LuaHost::new()));
        Server::new(workspace_with("sample.bin", b"hello world"), host)
    }

    /// Serve `lines` to the end, returning every message written.
    fn exchange(server: &mut Server, lines: &[Value]) -> Vec<Value> {
        let input: String = lines.iter().map(|line| format!("{line}\n")).collect();
        let mut output = Vec::new();
        serve(server, io::Cursor::new(input.into_bytes()), &mut output).unwrap();
        String::from_utf8(output).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect()
    }

    fn request(id: i64, method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    fn modern(mut params: Value) -> Value {
        params["_meta"] = json!({
            (protocol::META_PROTOCOL_VERSION): MODERN_VERSION,
            (protocol::META_CLIENT_CAPABILITIES): {},
            (protocol::META_CLIENT_INFO): { "name": "unit-test", "version": "1" },
        });
        params
    }

    fn initialize(version: &str) -> Value {
        request(0, "initialize", json!({ "protocolVersion": version, "capabilities": {}, "clientInfo": { "name": "Legacy Client", "version": "1" } }))
    }

    fn initialized() -> Value {
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
    }

    fn response(messages: &[Value], id: i64) -> Value {
        messages.iter().find(|message| message["id"] == id).unwrap_or_else(|| panic!("no answer to {id} in {messages:?}")).clone()
    }

    #[test]
    fn initialize_agrees_on_a_revision_and_offers_tools() {
        let messages = exchange(&mut server(), &[initialize("2025-06-18"), initialized(), request(1, "ping", json!({}))]);
        let result = &response(&messages, 0)["result"];
        assert_eq!(result["protocolVersion"], "2025-06-18");
        assert_eq!(result["serverInfo"]["name"], "theviewer");
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result.get("resultType").is_none(), "older revisions have no resultType");
        assert_eq!(response(&messages, 1)["result"], json!({}));
        assert_eq!(messages.len(), 2, "a notification is not answered");

        let newer = exchange(&mut server(), &[initialize("2030-01-01")]);
        assert_eq!(response(&newer, 0)["result"]["protocolVersion"], "2025-11-25", "an unknown version gets the newest handshake revision");
    }

    #[test]
    fn a_modern_request_is_served_without_a_handshake_and_says_it_is_complete() {
        let messages = exchange(&mut server(), &[request(1, "server/discover", modern(json!({}))), request(2, "tools/list", modern(json!({})))]);
        let discover = &response(&messages, 1)["result"];
        assert_eq!(discover["supportedVersions"][0], MODERN_VERSION);
        assert_eq!(discover["resultType"], "complete");
        assert_eq!(discover["_meta"][protocol::META_SERVER_INFO]["name"], "theviewer");
        assert!(discover["ttlMs"].is_u64() && discover["cacheScope"] == "private");
        let tools = &response(&messages, 2)["result"];
        assert!(tools["tools"].as_array().unwrap().iter().any(|tool| tool["name"] == "bytes_read" && tool["outputSchema"].is_object()));
        assert_eq!(tools["ttlMs"], 0);
    }

    #[test]
    fn a_request_before_any_handshake_or_in_an_unknown_version_is_refused() {
        let messages = exchange(&mut server(), &[request(1, "tools/list", json!({})), request(2, "tools/list", json!({ "_meta": { (protocol::META_PROTOCOL_VERSION): "1999-01-01", (protocol::META_CLIENT_CAPABILITIES): {} } }))]);
        assert_eq!(response(&messages, 1)["error"]["code"], INVALID_PARAMS);
        assert!(response(&messages, 1)["error"]["message"].as_str().unwrap().contains("initialize"));
        let unsupported = &response(&messages, 2)["error"];
        assert_eq!(unsupported["code"], UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(unsupported["data"]["requested"], "1999-01-01");
    }

    #[test]
    fn bad_lines_get_errors_and_the_server_carries_on() {
        let mut lines = "{oops\n[1,2]\n{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"no/such\",\"params\":{}}\n\n".to_string();
        lines.push_str(&format!("{}\n", request(6, "ping", json!({}))));
        let mut output = Vec::new();
        serve(&mut server(), io::Cursor::new(lines.into_bytes()), &mut output).unwrap();
        let messages: Vec<Value> = String::from_utf8(output).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!((messages[0]["id"].clone(), messages[0]["error"]["code"].clone()), (Value::Null, json!(PARSE_ERROR)));
        assert_eq!(messages[1]["error"]["code"], jsonrpc::INVALID_REQUEST);
        assert_eq!(response(&messages, 5)["error"]["code"], INVALID_PARAMS, "without a handshake even an unknown method has no context");
        assert_eq!(response(&messages, 6)["result"], json!({}), "still serving");
        let unknown = exchange(&mut server(), &[request(1, "no/such", modern(json!({})))]);
        assert_eq!(response(&unknown, 1)["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn invalid_utf8_is_a_parse_error() {
        let mut output = Vec::new();
        serve(&mut server(), io::Cursor::new(b"\xff\xfe\n".to_vec()), &mut output).unwrap();
        let message: Value = serde_json::from_slice(output.split(|byte| *byte == b'\n').next().unwrap()).unwrap();
        assert_eq!(message["error"]["code"], PARSE_ERROR);
    }

    #[test]
    fn lists_come_a_page_at_a_time() {
        let mut server = server().with_page_size(10);
        let messages = exchange(&mut server, &[request(1, "tools/list", modern(json!({}))), request(2, "tools/list", modern(json!({ "cursor": "10" }))), request(3, "tools/list", modern(json!({ "cursor": "nonsense" })))]);
        let first = &response(&messages, 1)["result"];
        assert_eq!(first["tools"].as_array().unwrap().len(), 10);
        assert_eq!(first["nextCursor"], "10");
        assert_eq!(response(&messages, 2)["result"]["tools"][0]["name"], json!(tools::tool_name(api::METHODS[10].name)));
        assert_eq!(response(&messages, 3)["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn a_handshake_client_calls_tools_as_itself() {
        let messages = exchange(&mut server(), &[initialize("2025-11-25"), initialized(), request(1, "tools/call", json!({ "name": "bytes_write", "arguments": { "start": 0, "data": "4a" } }))]);
        let result = &response(&messages, 1)["result"];
        assert_eq!(result["structuredContent"]["version"], 1);
        assert_eq!(result["structuredContent"]["label"].as_str().map(|label| label.ends_with("by mcp:legacy-client")), Some(true), "{result}");
    }

    #[test]
    fn a_request_with_a_cancellation_waiting_behind_it_is_not_started() {
        let call = request(1, "tools/call", modern(json!({ "name": "bytes_write", "arguments": { "start": 0, "data": "00" } }))).to_string();
        let cancel = |id: i64| Input::Line(json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": id, "reason": "changed my mind" } }).to_string());
        assert!(cancelled_while_waiting(&call, &VecDeque::from([Input::NotText, cancel(1)])));
        assert!(!cancelled_while_waiting(&call, &VecDeque::from([cancel(2)])), "another request's cancellation");
        assert!(!cancelled_while_waiting(&call, &VecDeque::new()));
        let notification = initialized().to_string();
        assert!(!cancelled_while_waiting(&notification, &VecDeque::from([cancel(1)])), "only requests are cancelled");
    }
}
