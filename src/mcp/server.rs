//! The MCP server: requests in, answers and notifications out, against a
//! headless workspace of the files it was given.
//!
//! Each line is handled in turn on one thread, while another reads them.
//! After each request is answered, the bus is drained and subscribers hear
//! which resources, and whether the list of resources, changed.

use std::collections::{BTreeSet, VecDeque};
use std::io::{self, BufRead, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::mpsc;

use serde_json::{Map, Value, json};

use super::jsonrpc::{self, INTERNAL_ERROR, INVALID_PARAMS, Incoming, LEGACY_RESOURCE_NOT_FOUND, RequestId, RpcError};
use super::protocol::{self, RequestContext};
use super::resources::{self, DocumentChanges, ReadError};
use super::tools;
use crate::api::{Caller, HeadlessWorkspace, Workspace};
use crate::app::SharedLuaHost;
use crate::bus::Message;
/// Items in one page of a list.
pub const PAGE_SIZE: usize = 100;
/// How long clients may keep lists that change only with the plugins or
/// documents: they are told when those change.
const STABLE_TTL_MS: u64 = 60 * 60 * 1000;

/// The handshake session of a client speaking a revision before 2026-07-28.
struct Session {
    version: &'static str,
    client: String,
    /// Whether the client said `notifications/initialized`, after which
    /// the server may notify it.
    initialized: bool,
    /// Resources it subscribed to with `resources/subscribe`.
    subscribed: BTreeSet<String>,
}

/// A `subscriptions/listen` stream of the current revision: what it asked to hear.
struct Listener {
    /// The listen request's id, which every notification on it carries.
    id: RequestId,
    resources_list: bool,
    resources: BTreeSet<String>,
}

/// The server's state.
pub struct Server {
    workspace: HeadlessWorkspace,
    /// Kept so the methods plugins registered stay loaded.
    _plugin_host: SharedLuaHost,
    session: Option<Session>,
    listeners: Vec<Listener>,
    /// The bus has been delivered and looked at up to here.
    bus_cursor: u64,
    /// The documents last listed, to notice changes.
    document_ids: Vec<String>,
    page_size: usize,
}

impl Server {
    pub fn new(workspace: HeadlessWorkspace, plugin_host: SharedLuaHost) -> Self {
        let mut server = Server { workspace, _plugin_host: plugin_host, session: None, listeners: Vec::new(), bus_cursor: 0, document_ids: Vec::new(), page_size: PAGE_SIZE };
        // What happened while starting (files opening) is nobody's news.
        server.drain();
        server.document_ids = server.current_document_ids();
        server
    }

    /// Use pages of `size` items in lists.
    pub fn with_page_size(mut self, size: usize) -> Self {
        self.page_size = size.max(1);
        self
    }

    fn current_document_ids(&self) -> Vec<String> {
        self.workspace.documents().into_iter().map(|info| info.id).collect()
    }

    /// Handle one line from the client, writing what it causes.
    pub fn handle_line(&mut self, line: &str, out: &mut dyn Write) -> io::Result<()> {
        if line.trim().is_empty() {
            return Ok(());
        }
        match jsonrpc::parse(line) {
            Err(malformed) => jsonrpc::write_message(out, &jsonrpc::error(&malformed.id, &malformed.error)),
            Ok(Incoming::Response) => Ok(()),
            Ok(Incoming::Notification { method, params }) => {
                self.notification(&method, &params);
                Ok(())
            }
            Ok(Incoming::Request { id, method, params }) => self.request(&id, &method, &params, out),
        }
    }

    fn notification(&mut self, method: &str, params: &Map<String, Value>) {
        match method {
            "notifications/initialized" => {
                if let Some(session) = &mut self.session {
                    session.initialized = true;
                }
            }
            "notifications/cancelled" => {
                // Requests are answered in turn, so by now only a listen
                // stream is still in progress; anything else is done.
                let Some(id) = params.get("requestId") else { return };
                self.listeners.retain(|listener| &listener.id != id);
            }
            _ => {}
        }
    }

    fn request(&mut self, id: &RequestId, method: &str, params: &Map<String, Value>, out: &mut dyn Write) -> io::Result<()> {
        let outcome = catch_unwind(AssertUnwindSafe(|| self.answer(id, method, params, out)));
        let (context, reply) = match outcome {
            Ok(Ok(Some(answered))) => answered,
            Ok(Ok(None)) => {
                let delivered = self.drain();
                return self.notify(&delivered, out);
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => (None, Err(RpcError::new(INTERNAL_ERROR, format!("{method} failed inside the server; the error is on its standard error")))),
        };
        let message = match reply {
            Ok(result) => jsonrpc::result(id, decorate(result, method, context.as_ref())),
            Err(error) => jsonrpc::error(id, &error),
        };
        jsonrpc::write_message(out, &message)?;
        let delivered = self.drain();
        self.notify(&delivered, out)
    }

    /// Answer a request: the context it was made in (when it could be
    /// told) and its result, or nothing when it opened a listen stream,
    /// which is answered only when the server ends it.
    #[allow(clippy::type_complexity)]
    fn answer(&mut self, id: &RequestId, method: &str, params: &Map<String, Value>, out: &mut dyn Write) -> io::Result<Option<(Option<RequestContext>, Result<Value, RpcError>)>> {
        if method == "initialize" {
            return Ok(Some((None, Ok(self.initialize(params)))));
        }
        if method == "ping" {
            return Ok(Some((protocol::modern_context(params).ok().flatten(), Ok(json!({})))));
        }
        let context = match self.context(params) {
            Ok(context) => context,
            Err(error) => return Ok(Some((None, Err(error)))),
        };
        if method == "subscriptions/listen" && context.is_modern() {
            self.listen(id, params, out)?;
            return Ok(None);
        }
        let reply = self.dispatch(&context, method, params);
        Ok(Some((Some(context), reply)))
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
        self.session = Some(Session { version, client, initialized: false, subscribed: BTreeSet::new() });
        json!({
            "protocolVersion": version,
            "capabilities": protocol::capabilities(),
            "serverInfo": protocol::server_info(),
            "instructions": protocol::INSTRUCTIONS,
        })
    }

    /// Open a listen stream: acknowledge what it will hear.
    fn listen(&mut self, id: &RequestId, params: &Map<String, Value>, out: &mut dyn Write) -> io::Result<()> {
        let wanted = params.get("notifications").cloned().unwrap_or_else(|| json!({}));
        let resources: BTreeSet<String> = wanted["resourceSubscriptions"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect();
        let listener = Listener { id: id.clone(), resources_list: wanted["resourcesListChanged"] == true, resources };
        // Tools and prompts do not change, so their list changes are not agreed to.
        let mut agreed = Map::new();
        if listener.resources_list {
            agreed.insert("resourcesListChanged".into(), Value::Bool(true));
        }
        if !listener.resources.is_empty() {
            agreed.insert("resourceSubscriptions".into(), json!(listener.resources));
        }
        let acknowledged = json!({ "_meta": { (protocol::META_SUBSCRIPTION_ID): id }, "notifications": agreed });
        self.listeners.retain(|known| &known.id != id);
        self.listeners.push(listener);
        jsonrpc::write_message(out, &jsonrpc::notification("notifications/subscriptions/acknowledged", acknowledged))
    }

    fn dispatch(&mut self, context: &RequestContext, method: &str, params: &Map<String, Value>) -> Result<Value, RpcError> {
        let modern = context.is_modern();
        match method {
            "server/discover" => Ok(json!({ "supportedVersions": protocol::supported_versions(), "capabilities": protocol::capabilities(), "instructions": protocol::INSTRUCTIONS })),
            "tools/list" => {
                let (tools, next) = page(tools::list(&self.workspace, context.version), params, self.page_size)?;
                Ok(with_next(json!({ "tools": tools }), next))
            }
            "tools/call" => tools::call(&mut self.workspace, context, params),
            "resources/list" => {
                let (resources, next) = page(resources::list(&self.workspace), params, self.page_size)?;
                Ok(with_next(json!({ "resources": resources }), next))
            }
            "resources/templates/list" => Ok(json!({ "resourceTemplates": resources::templates() })),
            "resources/read" => {
                let uri = required_uri(params)?;
                let caller = Caller::Mcp(context.client.clone());
                match resources::read(&mut self.workspace, &caller, uri) {
                    Ok(contents) => Ok(json!({ "contents": [contents] })),
                    Err(ReadError::NotFound(message)) => {
                        let code = if modern { INVALID_PARAMS } else { LEGACY_RESOURCE_NOT_FOUND };
                        Err(RpcError::new(code, format!("Resource not found: {message}")).with_data(json!({ "uri": uri })))
                    }
                    Err(ReadError::Invalid(message)) => Err(RpcError::invalid_params(message).with_data(json!({ "uri": uri }))),
                    Err(ReadError::Failed(message)) => Err(RpcError::new(INTERNAL_ERROR, message).with_data(json!({ "uri": uri }))),
                }
            }
            "resources/subscribe" | "resources/unsubscribe" if !modern => {
                let uri = required_uri(params)?;
                resources::parse_uri(uri).map_err(RpcError::invalid_params)?;
                if let Some(session) = &mut self.session {
                    if method == "resources/subscribe" {
                        session.subscribed.insert(uri.to_string());
                    } else {
                        session.subscribed.remove(uri);
                    }
                }
                Ok(json!({}))
            }
            _ => Err(RpcError::method_not_found(method)),
        }
    }

    /// Deliver what was published since the last drain, and return it.
    fn drain(&mut self) -> Vec<Arc<Message>> {
        let bus = self.workspace.bus();
        let changes = bus.changed_since(self.bus_cursor);
        self.bus_cursor = bus.cursor();
        if changes.missed > 0 {
            eprintln!("theviewer mcp: {} bus messages went by unseen; subscribers may have missed changes", changes.missed);
        }
        changes.messages
    }

    /// Tell subscribers what the `delivered` messages changed: resources
    /// they watch, and the list of resources.
    fn notify(&mut self, delivered: &[Arc<Message>], out: &mut dyn Write) -> io::Result<()> {
        let mut changes = DocumentChanges::default();
        for message in delivered {
            changes.note(message);
        }
        let document_ids = self.current_document_ids();
        let documents_changed = document_ids != self.document_ids;
        self.document_ids = document_ids;

        if let Some(session) = self.session.as_ref().filter(|session| session.initialized) {
            if documents_changed {
                jsonrpc::write_message(out, &jsonrpc::notification("notifications/resources/list_changed", json!({})))?;
            }
            for uri in session.subscribed.iter().filter(|uri| changes.touches(&self.workspace, uri)) {
                jsonrpc::write_message(out, &jsonrpc::notification("notifications/resources/updated", json!({ "uri": uri })))?;
            }
        }
        for listener in &self.listeners {
            let tag = json!({ (protocol::META_SUBSCRIPTION_ID): listener.id });
            if documents_changed && listener.resources_list {
                jsonrpc::write_message(out, &jsonrpc::notification("notifications/resources/list_changed", json!({ "_meta": tag })))?;
            }
            for uri in listener.resources.iter().filter(|uri| changes.touches(&self.workspace, uri)) {
                jsonrpc::write_message(out, &jsonrpc::notification("notifications/resources/updated", json!({ "_meta": tag, "uri": uri })))?;
            }
        }
        Ok(())
    }
}

/// The `uri` parameter.
fn required_uri(params: &Map<String, Value>) -> Result<&str, RpcError> {
    params.get("uri").and_then(Value::as_str).ok_or_else(|| RpcError::invalid_params("the request needs a resource's uri"))
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
        // Change with the plugins and documents, which subscribers hear of.
        "server/discover" | "resources/templates/list" => Some(STABLE_TTL_MS),
        "tools/list" | "resources/list" | "resources/read" => Some(0),
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
/// for its id is already waiting behind it.
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
    use crate::api::test_support::workspace_with;
    use crate::mcp::jsonrpc::{METHOD_NOT_FOUND, PARSE_ERROR, UNSUPPORTED_PROTOCOL_VERSION};
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
    fn initialize_agrees_on_a_revision_and_offers_tools_and_resources() {
        let messages = exchange(&mut server(), &[initialize("2025-06-18"), initialized(), request(1, "ping", json!({}))]);
        let result = &response(&messages, 0)["result"];
        assert_eq!(result["protocolVersion"], "2025-06-18");
        assert_eq!(result["serverInfo"]["name"], "theviewer");
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["capabilities"]["resources"]["subscribe"], true);
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
        let input = "{oops\n[1,2]\n{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"no/such\",\"params\":{}}\n\n";
        let mut output = Vec::new();
        let mut server = server();
        let mut lines = input.to_string();
        lines.push_str(&format!("{}\n", request(6, "ping", json!({}))));
        serve(&mut server, io::Cursor::new(lines.into_bytes()), &mut output).unwrap();
        let messages: Vec<Value> = String::from_utf8(output).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!((messages[0]["id"].clone(), messages[0]["error"]["code"].clone()), (Value::Null, json!(PARSE_ERROR)));
        assert_eq!(messages[1]["error"]["code"], jsonrpc::INVALID_REQUEST);
        assert_eq!(response(&messages, 5)["error"]["code"], INVALID_PARAMS, "without a handshake even an unknown method has no context");
        assert_eq!(response(&messages, 6)["result"], json!({}), "still serving");
        let unknown = exchange(&mut self::server(), &[request(1, "no/such", modern(json!({})))]);
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
        assert_eq!(response(&messages, 2)["result"]["tools"][0]["name"], json!(tools::tool_name(crate::api::METHODS[10].name)));
        assert_eq!(response(&messages, 3)["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn a_handshake_subscriber_hears_of_changes_to_the_resources_it_watches() {
        let messages = exchange(
            &mut server(),
            &[
                initialize("2025-11-25"),
                initialized(),
                request(1, "resources/subscribe", json!({ "uri": "theviewer://doc/doc-1/bytes/0-4" })),
                request(2, "resources/subscribe", json!({ "uri": "theviewer://doc/doc-1/findings" })),
                request(3, "tools/call", json!({ "name": "bytes_write", "arguments": { "start": 0, "data": "4a" } })),
                request(4, "resources/unsubscribe", json!({ "uri": "theviewer://doc/doc-1/bytes/0-4" })),
                request(5, "tools/call", json!({ "name": "bytes_write", "arguments": { "start": 1, "data": "45" } })),
            ],
        );
        let updated: Vec<&Value> = messages.iter().filter(|message| message["method"] == "notifications/resources/updated").collect();
        assert_eq!(updated.len(), 3, "{messages:?}");
        let answer = messages.iter().position(|message| message["id"] == 3).unwrap();
        let first = messages.iter().position(|message| message["method"] == "notifications/resources/updated").unwrap();
        assert!(first > answer, "the answer comes first");
        assert_eq!(updated[2]["params"]["uri"], "theviewer://doc/doc-1/findings", "unsubscribed resources are not mentioned");
        assert_eq!(response(&messages, 3)["result"]["structuredContent"]["version"], 1);
    }

    #[test]
    fn a_listen_stream_is_acknowledged_tagged_and_ended_by_cancelling() {
        let mut server = server();
        let messages = exchange(
            &mut server,
            &[
                request(7, "subscriptions/listen", modern(json!({ "notifications": { "resourceSubscriptions": ["theviewer://doc/doc-1"], "promptsListChanged": true, "resourcesListChanged": true } }))),
                request(8, "tools/call", modern(json!({ "name": "bytes_insert", "arguments": { "at": 0, "data": "00" } }))),
                request(9, "tools/call", modern(json!({ "name": "documents_new", "arguments": { "name": "scratch" } }))),
            ],
        );
        // Cancelled once it is open: a cancellation read with it would stop it starting.
        let after = exchange(
            &mut server,
            &[
                json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": 7 } }),
                request(10, "tools/call", modern(json!({ "name": "bytes_insert", "arguments": { "doc": "doc-1", "at": 0, "data": "00" } }))),
            ],
        );
        let acknowledged = &messages[0];
        assert_eq!(acknowledged["method"], "notifications/subscriptions/acknowledged");
        assert_eq!(acknowledged["params"]["_meta"][protocol::META_SUBSCRIPTION_ID], 7);
        assert_eq!(acknowledged["params"]["notifications"], json!({ "resourceSubscriptions": ["theviewer://doc/doc-1"], "resourcesListChanged": true }), "prompts never change");
        let tagged: Vec<&Value> = messages.iter().filter(|message| message["params"]["_meta"][protocol::META_SUBSCRIPTION_ID] == 7).collect();
        let methods: Vec<&str> = tagged.iter().map(|message| message["method"].as_str().unwrap()).collect();
        assert_eq!(methods, ["notifications/subscriptions/acknowledged", "notifications/resources/updated", "notifications/resources/list_changed"]);
        assert!(messages.iter().chain(&after).all(|message| message["id"] != 7), "the stream is not answered while open, nor once cancelled");
        assert_eq!(after.len(), 1, "only the answer, nothing on the cancelled stream: {after:?}");
        assert_eq!(response(&after, 10)["result"]["isError"], false);
    }

    #[test]
    fn modern_requests_cannot_use_the_removed_subscribe() {
        let messages = exchange(&mut server(), &[request(1, "resources/subscribe", modern(json!({ "uri": "theviewer://doc/doc-1" })))]);
        assert_eq!(response(&messages, 1)["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn a_missing_resource_is_reported_in_each_revisions_code() {
        let modern_messages = exchange(&mut server(), &[request(1, "resources/read", modern(json!({ "uri": "theviewer://doc/doc-7" })))]);
        assert_eq!(response(&modern_messages, 1)["error"]["code"], INVALID_PARAMS);
        let legacy = exchange(&mut server(), &[initialize("2025-06-18"), request(1, "resources/read", json!({ "uri": "theviewer://doc/doc-7" }))]);
        assert_eq!(response(&legacy, 1)["error"]["code"], LEGACY_RESOURCE_NOT_FOUND);
        assert_eq!(response(&legacy, 1)["error"]["data"]["uri"], "theviewer://doc/doc-7");
    }

    #[test]
    fn resources_and_templates_are_listed_and_read() {
        let messages = exchange(
            &mut server(),
            &[
                request(1, "resources/list", modern(json!({}))),
                request(2, "resources/templates/list", modern(json!({}))),
                request(3, "resources/read", modern(json!({ "uri": "theviewer://doc/doc-1/bytes/0-5" }))),
            ],
        );
        assert_eq!(response(&messages, 1)["result"]["resources"][0]["uri"], "theviewer://doc/doc-1");
        assert!(response(&messages, 1)["result"]["nextCursor"].is_string(), "the reference notes take more than a page");
        assert_eq!(response(&messages, 2)["result"]["resourceTemplates"].as_array().unwrap().len(), 5);
        assert_eq!(response(&messages, 3)["result"]["contents"][0]["blob"], "aGVsbG8=");
    }

    #[test]
    fn a_request_with_a_cancellation_waiting_behind_it_is_not_started() {
        let call = request(1, "tools/call", modern(json!({ "name": "bytes_write", "arguments": { "start": 0, "data": "00" } }))).to_string();
        let cancel = |id: i64| Input::Line(json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": id, "reason": "changed my mind" } }).to_string());
        assert!(cancelled_while_waiting(&call, &VecDeque::from([Input::NotText, cancel(1)])));
        assert!(!cancelled_while_waiting(&call, &VecDeque::from([cancel(2)])), "another request's cancellation");
        assert!(!cancelled_while_waiting(&call, &VecDeque::new()));
        let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string();
        assert!(!cancelled_while_waiting(&notification, &VecDeque::from([cancel(1)])), "only requests are cancelled");
    }
}
