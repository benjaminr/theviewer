//! "Ask the file": a conversation with Claude about the open document.
//!
//! The assistant runs on a background thread and talks to the Messages API
//! over raw HTTP (there is no official Rust SDK), streaming its reply. It can
//! use tools to look at the file - read bytes, search, list findings, parse a
//! structure - and those tool calls are carried out on the UI thread, which
//! owns the document, through a request/reply channel.
//!
//! The conversation history is append-only: assistant turns are stored as the
//! complete content blocks that came back (thinking blocks included), so
//! follow-up questions resend them unchanged.

use std::io::{BufRead, BufReader};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use crate::api;

pub const MODEL: &str = "claude-opus-5-5";
const API_URL: &str = "https://api.anthropic.com/v1/messages";
const API_VERSION: &str = "2023-06-01";
/// Server-side refusal fallback, "default" form: the API reroutes a declined
/// request by refusal category without a model list to maintain.
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
/// OAuth bearer tokens need this beta header alongside them.
const OAUTH_BETA: &str = "oauth-2025-04-20";
const MAX_TOKENS: u32 = 64_000;
/// Tool round-trips allowed per question before the assistant is stopped.
const MAX_TOOL_ROUNDS: usize = 24;
/// Retries for rate limits, overload and transient server errors.
const MAX_RETRIES: u32 = 2;
/// Longest a tool result may be, so one call cannot flood the context.
pub const MAX_TOOL_RESULT_CHARS: usize = 24_000;

/// The request behind *Characterise*: a short question that names the tools
/// to work through, so the answer is grounded in measurements.
pub const CHARACTERISE_REQUEST: &str = "Characterise this file: what is it, how is it laid out, and what does each part contain? Start with analysis_overview and analysis_segments, check the main regions with analysis_statistics, analysis_compressibility, analysis_processor and analysis_text_encoding, look closer where something is unclear, and cite offsets.";

const SYSTEM_PROMPT: &str = "You are the analysis assistant inside theviewer, a binary file viewer and editor used for reverse engineering, firmware analysis and data recovery. The user is looking at a file and asks you about it.

Each question comes with a snapshot of what the user sees: the file's name and size, the cursor and selection, nearby findings from the app's detectors, the parsed structure at the cursor, reference notes on the formats enclosing the cursor, and a hex dump around the cursor. Use the tools to look further: read bytes or bits anywhere, search, decode numbers, list findings in a range, parse the structure at an offset or apply a template, detect and decode compressed data, dissect packets, map the whole file, split it into typed segments, measure a range's statistics, compressibility or text encoding, test a range for machine code, or read the reference notes on a format. Tool results are JSON; bytes in them are hex unless you ask for another encoding, and offsets are decimal numbers. When you explain a field or layout, cite the specification and section the notes give (for example RFC 791 §3.1). Look before you conclude; base claims on bytes you have seen, and say how sure you are when something is a guess.

Write offsets as 0x-prefixed hexadecimal (for example 0x1A40); the app turns them into links that jump to that place in the file, so cite the offset for every specific claim.

When the user asks for a template, or a template would answer the question better than prose, write one in a fenced block tagged `template`. The app offers to apply it. The template language: `endian little|big`; `struct Name { field: type ... }`; types u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 (suffix le/be to override endianness), char[N], bytes[N], cstring, utf16[N], nested struct names, arrays T[expr] and T[until_end]; lengths may be expressions over earlier fields (`bytes[len - 4]`, dotted names for nested fields); attributes after the type: `= value` for an expected value, `@ expr` for an absolute offset, `enum { 1 = \"Name\" }`, `display hex`; finish with `root Type` (or `root Type[until_end]`). Keep templates small and correct rather than speculative.

Be concise. Lead with the answer, then the evidence.";

/// How to authenticate with the API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credentials {
    ApiKey(String),
    /// OAuth access token from `ANTHROPIC_AUTH_TOKEN` or `ant auth`.
    Bearer(String),
}

/// The access token from an `ant auth login` session, if the CLI is installed
/// and logged in.
pub fn cli_login() -> Result<Credentials, String> {
    let output = std::process::Command::new("ant")
        .args(["auth", "print-credentials", "--access-token"])
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|_| "the ant CLI is not installed".to_string())?;
    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if output.status.success() && !token.is_empty() {
        Ok(Credentials::Bearer(token))
    } else {
        Err("not logged in with ant".to_string())
    }
}

/// Shown wherever Ask is unavailable.
pub const NO_KEY_MESSAGE: &str = "Add your Anthropic API key in Settings (Cmd+,) to use Ask.";

/// What the user sees, sent with each question.
#[derive(Clone, Debug, Default)]
pub struct FileContext {
    pub name: String,
    pub size: usize,
    pub cursor: usize,
    pub selection: Option<(usize, usize)>,
    pub view: String,
    pub findings: Vec<String>,
    pub structure: Option<String>,
    pub hex_dump: String,
    pub report: Option<String>,
    /// Reference notes on the formats enclosing the cursor, innermost first.
    pub references: Vec<String>,
}

impl FileContext {
    fn render(&self) -> String {
        let mut text = format!("File: {} ({} bytes)\nCursor: {:#x}\n", self.name, self.size, self.cursor);
        if let Some((start, len)) = self.selection {
            text.push_str(&format!("Selection: {start:#x}..{:#x} ({len} bytes)\n", start + len));
        }
        if !self.view.is_empty() {
            text.push_str(&format!("View: {}\n", self.view));
        }
        if let Some(report) = &self.report {
            text.push_str(&format!("\nWhole-file overview:\n{report}\n"));
        }
        if let Some(structure) = &self.structure {
            text.push_str(&format!("\nStructure at the cursor:\n{structure}\n"));
        }
        if !self.references.is_empty() {
            text.push_str("\nReference notes on the formats at the cursor:\n");
            for notes in &self.references {
                text.push_str(&format!("\n{}\n", notes.trim_end()));
            }
        }
        if !self.findings.is_empty() {
            text.push_str("\nFindings near the cursor:\n");
            for finding in &self.findings {
                text.push_str(&format!("- {finding}\n"));
            }
        }
        if !self.hex_dump.is_empty() {
            text.push_str(&format!("\nBytes around the cursor:\n{}\n", self.hex_dump));
        }
        text
    }
}

/// Whether Ask offers a method as a tool: every method that only reads,
/// except the API's description of itself, which the tool list already is.
fn offered_to_ask(method: &api::Method) -> bool {
    method.effect == api::Effect::Read && method.namespace() != "api"
}

/// The tool name for an API method. Tool names may hold only letters,
/// digits, `_` and `-`, so `bytes.read` becomes `bytes_read`.
pub fn tool_name(method_name: &str) -> String {
    method_name.replace('.', "_")
}

/// The tools offered to the model, generated from the API's method table.
/// Eager input streaming sends arguments as they are generated; the API then
/// leaves them unchecked, so every call is checked against the method's
/// types when it runs. The schemas are not strict: strict tools are limited
/// in number and in the schema features they accept.
pub fn tool_definitions() -> Value {
    let tools: Vec<Value> = api::METHODS
        .iter()
        .filter(|method| offered_to_ask(method))
        .map(|method| {
            let mut schema = (method.params)().to_value();
            if let Some(object) = schema.as_object_mut() {
                object.remove("$schema");
                object.remove("title");
            }
            json!({
                "name": tool_name(method.name),
                "description": method.summary,
                "eager_input_streaming": true,
                "input_schema": schema,
            })
        })
        .collect();
    Value::Array(tools)
}

/// A tool call from the model: the API method it names and its arguments.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolCall {
    /// The API method, such as `bytes.hexdump`.
    pub method: &'static str,
    pub params: Value,
}

impl ToolCall {
    /// The call the model made with tool `name`. Only the tools offered are
    /// accepted, and only with an object of arguments; the arguments
    /// themselves are checked when the method runs.
    pub fn parse(name: &str, input: &Value) -> Result<ToolCall, String> {
        let method = api::METHODS
            .iter()
            .find(|method| offered_to_ask(method) && tool_name(method.name) == name)
            .ok_or_else(|| format!("unknown tool '{name}'"))?;
        if !input.is_object() {
            return Err("arguments must be an object".to_string());
        }
        Ok(ToolCall { method: method.name, params: input.clone() })
    }

    /// Short description for the transcript, such as
    /// `bytes.hexdump {"len":64,"start":256}`.
    pub fn describe(&self) -> String {
        let arguments = self.params.as_object().filter(|object| !object.is_empty()).map(|_| format!(" {}", self.params)).unwrap_or_default();
        format!("{}{arguments}", self.method)
    }

    /// Run the call against `workspace`: the method's JSON result, or its
    /// error as JSON.
    pub fn run(&self, workspace: &mut dyn api::Workspace) -> Result<String, String> {
        api::call(workspace, self.method, self.params.clone()).map(|result| result.to_string()).map_err(|error| error.to_json().to_string())
    }
}

/// A classic 16-bytes-per-line hex dump with an ASCII column.
pub fn hex_dump(bytes: &[u8], base: usize) -> String {
    let mut out = String::new();
    for (row, chunk) in bytes.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", base + row * 16));
        for column in 0..16 {
            match chunk.get(column) {
                Some(byte) => out.push_str(&format!("{byte:02x} ")),
                None => out.push_str("   "),
            }
        }
        out.push(' ');
        out.extend(chunk.iter().map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' }));
        out.push('\n');
    }
    out
}

/// What the background thread tells the UI.
#[derive(Debug)]
pub enum Event {
    /// A request is about to be sent. On a retry, whatever the failed attempt
    /// already streamed should be discarded, as the reply starts over.
    AttemptStarted { retry: bool },
    /// More reply text for the current assistant turn.
    Text(String),
    /// A summary of the model's reasoning, shown collapsed.
    Thinking(String),
    /// The model wants a tool run; reply on the given channel with the
    /// result, or the error to report to the model.
    Tool { call: ToolCall, reply: Sender<Result<String, String>> },
    /// The model's arguments did not validate; shown in the transcript.
    ToolRejected(String),
    /// The reply is complete; `messages` is the updated history.
    Done { messages: Vec<Value>, note: Option<String> },
    Failed(String),
}

/// One entry in the visible transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Turn {
    User(String),
    Assistant(String),
    Reasoning(String),
    Tool(String),
    Note(String),
}

/// The conversation and any request in flight.
#[derive(Default)]
pub struct Assistant {
    /// The API history, append-only.
    messages: Vec<Value>,
    pub transcript: Vec<Turn>,
    events: Option<Receiver<Event>>,
    /// Where the current request attempt's output begins in the transcript.
    attempt_start: usize,
}

impl Assistant {
    pub fn is_busy(&self) -> bool {
        self.events.is_some()
    }

    /// Forget the conversation.
    pub fn clear(&mut self) {
        if !self.is_busy() {
            self.messages.clear();
            self.transcript.clear();
        }
    }

    /// Ask a question about the file. Fails at once if no credentials are
    /// available or a reply is still streaming.
    pub fn ask(&mut self, question: &str, context: &FileContext, credentials: Option<Credentials>) -> Result<(), String> {
        if self.is_busy() {
            return Err("Still answering the last question".to_string());
        }
        let credentials = credentials.ok_or(NO_KEY_MESSAGE)?;
        let content = format!("<snapshot>\n{}</snapshot>\n\n{question}", context.render());
        let mut messages = self.messages.clone();
        messages.push(json!({ "role": "user", "content": [{ "type": "text", "text": content }] }));
        // Each request attempt adds its own reply turn (see AttemptStarted).
        self.transcript.push(Turn::User(question.to_string()));
        let (sender, receiver) = mpsc::channel();
        self.events = Some(receiver);
        thread::spawn(move || {
            let outcome = run_conversation(&credentials, messages, &sender);
            let event = match outcome {
                Ok((messages, note)) => Event::Done { messages, note },
                Err(message) => Event::Failed(message),
            };
            let _ = sender.send(event);
        });
        Ok(())
    }

    /// Drain events. Tool calls are handed to `run_tool`, whose answer goes
    /// back to the model. Returns true when anything changed.
    pub fn poll(&mut self, mut run_tool: impl FnMut(&ToolCall) -> Result<String, String>) -> bool {
        // Take the receiver out while handling events, which update `self`.
        let Some(events) = self.events.take() else { return false };
        let mut changed = false;
        let mut finished = false;
        while let Ok(event) = events.try_recv() {
            changed = true;
            match event {
                Event::AttemptStarted { retry } => {
                    if retry {
                        self.transcript.truncate(self.attempt_start);
                    }
                    self.attempt_start = self.transcript.len();
                    self.transcript.push(Turn::Assistant(String::new()));
                }
                Event::Text(text) => self.append_reply(&text),
                Event::Thinking(text) => self.transcript.push(Turn::Reasoning(text)),
                Event::Tool { call, reply } => {
                    self.transcript.push(Turn::Tool(call.describe()));
                    let result = run_tool(&call).map(|output| truncate(&output, MAX_TOOL_RESULT_CHARS)).map_err(|error| truncate(&error, MAX_TOOL_RESULT_CHARS));
                    let _ = reply.send(result);
                }
                Event::ToolRejected(message) => self.transcript.push(Turn::Note(message)),
                Event::Done { messages, note } => {
                    self.messages = messages;
                    if let Some(note) = note {
                        self.transcript.push(Turn::Note(note));
                    }
                    finished = true;
                }
                Event::Failed(message) => {
                    self.transcript.push(Turn::Note(message));
                    finished = true;
                }
            }
        }
        if finished {
            self.transcript.retain(|turn| !matches!(turn, Turn::Assistant(text) if text.is_empty()));
        } else {
            self.events = Some(events);
        }
        changed
    }

    fn append_reply(&mut self, text: &str) {
        match self.transcript.last_mut() {
            Some(Turn::Assistant(reply)) => reply.push_str(text),
            _ => self.transcript.push(Turn::Assistant(text.to_string())),
        }
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let kept: String = text.chars().take(max_chars).collect();
    format!("{kept}\n[truncated: the result was longer than {max_chars} characters]")
}

/// The request body for one turn.
pub fn request_body(messages: &[Value]) -> Value {
    json!({
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "stream": true,
        "fallbacks": "default",
        "thinking": { "type": "adaptive", "display": "summarized" },
        "output_config": { "effort": "high" },
        // The system prompt and tool list never change, so they cache.
        "system": [{ "type": "text", "text": SYSTEM_PROMPT, "cache_control": { "type": "ephemeral" } }],
        "tools": tool_definitions(),
        "tool_choice": { "type": "auto" },
        "messages": messages,
    })
}

/// Run one question to completion: stream a reply, run any tools it asks for,
/// and continue until the model stops. Returns the updated history.
fn run_conversation(credentials: &Credentials, mut messages: Vec<Value>, events: &Sender<Event>) -> Result<(Vec<Value>, Option<String>), String> {
    for _ in 0..MAX_TOOL_ROUNDS {
        let reply = send_with_retries(credentials, &request_body(&messages), events)?;
        let stop_reason = reply.stop_reason.clone().unwrap_or_default();
        messages.push(json!({ "role": "assistant", "content": reply.blocks.clone() }));
        match stop_reason.as_str() {
            "tool_use" => {
                let results = run_tools(&reply.blocks, events)?;
                messages.push(json!({ "role": "user", "content": results }));
            }
            "refusal" => return Ok((messages, Some("Claude declined to answer this.".to_string()))),
            "max_tokens" => return Ok((messages, Some("The reply hit the length limit and was cut short.".to_string()))),
            _ => return Ok((messages, None)),
        }
    }
    Ok((messages, Some(format!("Stopped after {MAX_TOOL_ROUNDS} rounds of tool use."))))
}

/// Ask the UI thread to run each tool call and collect the results, all in
/// one user message.
fn run_tools(blocks: &[Value], events: &Sender<Event>) -> Result<Vec<Value>, String> {
    let mut results = Vec::new();
    for block in blocks.iter().filter(|b| b["type"] == "tool_use") {
        let id = block["id"].as_str().unwrap_or_default().to_string();
        let name = block["name"].as_str().unwrap_or_default();
        let result = match ToolCall::parse(name, &block["input"]) {
            Ok(call) => {
                let (reply_sender, reply_receiver) = mpsc::channel();
                events.send(Event::Tool { call, reply: reply_sender }).map_err(|_| "the window closed".to_string())?;
                match reply_receiver.recv_timeout(Duration::from_secs(120)).map_err(|_| "the tool did not answer".to_string())? {
                    Ok(output) => json!({ "type": "tool_result", "tool_use_id": id, "content": output }),
                    Err(error) => json!({ "type": "tool_result", "tool_use_id": id, "is_error": true, "content": error }),
                }
            }
            Err(message) => {
                let _ = events.send(Event::ToolRejected(format!("Invalid {name} call: {message}")));
                json!({ "type": "tool_result", "tool_use_id": id, "is_error": true, "content": format!("INVALID_JSON: {message}") })
            }
        };
        results.push(result);
    }
    Ok(results)
}

/// One streamed reply, reassembled.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Reply {
    pub blocks: Vec<Value>,
    pub stop_reason: Option<String>,
}

fn send_with_retries(credentials: &Credentials, body: &Value, events: &Sender<Event>) -> Result<Reply, String> {
    let mut attempt = 0;
    loop {
        let _ = events.send(Event::AttemptStarted { retry: attempt > 0 });
        match send_once(credentials, body, events) {
            Ok(reply) => return Ok(reply),
            Err(SendError::Retryable(message)) if attempt < MAX_RETRIES => {
                attempt += 1;
                thread::sleep(Duration::from_secs(2u64.pow(attempt)));
                let _ = message;
            }
            Err(SendError::Retryable(message) | SendError::Fatal(message)) => return Err(message),
        }
    }
}

enum SendError {
    Retryable(String),
    Fatal(String),
}

fn send_once(credentials: &Credentials, body: &Value, events: &Sender<Event>) -> Result<Reply, SendError> {
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30 * 60)))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut request = agent
        .post(API_URL)
        .header("content-type", "application/json")
        .header("anthropic-version", API_VERSION);
    request = match credentials {
        Credentials::ApiKey(key) => request.header("x-api-key", key).header("anthropic-beta", FALLBACK_BETA),
        Credentials::Bearer(token) => request
            .header("authorization", format!("Bearer {token}"))
            .header("anthropic-beta", format!("{OAUTH_BETA},{FALLBACK_BETA}")),
    };
    let response = request.send_json(body).map_err(|e| SendError::Retryable(format!("Could not reach the Claude API: {e}")))?;
    let status = response.status().as_u16();
    if status != 200 {
        let text = response.into_body().read_to_string().unwrap_or_default();
        let message = api_error_message(status, &text);
        return Err(if status == 429 || status == 529 || status >= 500 { SendError::Retryable(message) } else { SendError::Fatal(message) });
    }
    let reader = BufReader::new(response.into_body().into_reader());
    let mut stream = StreamState::default();
    for line in reader.lines() {
        let line = line.map_err(|e| SendError::Retryable(format!("The reply stream broke: {e}")))?;
        let Some(data) = line.strip_prefix("data:") else { continue };
        let Ok(event) = serde_json::from_str::<Value>(data.trim()) else { continue };
        for update in stream.apply(&event).map_err(SendError::Fatal)? {
            let _ = events.send(update);
        }
        if stream.finished {
            break;
        }
    }
    complete_reply(stream)
}

/// The reply, if the stream reached `message_stop`. A connection that closes
/// early leaves a partial reply (perhaps a tool call with no input), which
/// must not enter the history; it is retried instead.
fn complete_reply(stream: StreamState) -> Result<Reply, SendError> {
    if !stream.finished {
        return Err(SendError::Retryable("The reply stream ended before the reply was complete".to_string()));
    }
    Ok(stream.into_reply())
}

/// Turn an error response into a sentence for the user.
fn api_error_message(status: u16, body: &str) -> String {
    let detail = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["error"]["message"].as_str().map(str::to_string))
        .unwrap_or_else(|| body.chars().take(200).collect());
    match status {
        401 => format!("The API key was rejected ({detail})."),
        403 => format!("Not permitted: {detail}"),
        429 => format!("Rate limited; try again shortly ({detail})."),
        529 => "The API is overloaded; try again shortly.".to_string(),
        _ => format!("The Claude API returned {status}: {detail}"),
    }
}

/// Reassembles streamed content blocks exactly as the API sent them, so they
/// can be echoed back unchanged on the next turn.
#[derive(Default)]
struct StreamState {
    blocks: Vec<Value>,
    /// Raw JSON text of tool inputs, by block index.
    partial_inputs: Vec<String>,
    stop_reason: Option<String>,
    finished: bool,
}

impl StreamState {
    /// Apply one server-sent event; return what the UI should hear.
    fn apply(&mut self, event: &Value) -> Result<Vec<Event>, String> {
        let mut updates = Vec::new();
        match event["type"].as_str().unwrap_or_default() {
            "content_block_start" => {
                let index = event["index"].as_u64().unwrap_or(0) as usize;
                while self.blocks.len() <= index {
                    self.blocks.push(Value::Null);
                    self.partial_inputs.push(String::new());
                }
                self.blocks[index] = event["content_block"].clone();
            }
            "content_block_delta" => {
                let index = event["index"].as_u64().unwrap_or(0) as usize;
                let Some(block) = self.blocks.get_mut(index) else { return Ok(updates) };
                let delta = &event["delta"];
                match delta["type"].as_str().unwrap_or_default() {
                    "text_delta" => {
                        let text = delta["text"].as_str().unwrap_or_default();
                        append_string(block, "text", text);
                        updates.push(Event::Text(text.to_string()));
                    }
                    "thinking_delta" => append_string(block, "thinking", delta["thinking"].as_str().unwrap_or_default()),
                    "signature_delta" => append_string(block, "signature", delta["signature"].as_str().unwrap_or_default()),
                    "input_json_delta" => self.partial_inputs[index].push_str(delta["partial_json"].as_str().unwrap_or_default()),
                    _ => {}
                }
            }
            "content_block_stop" => {
                let index = event["index"].as_u64().unwrap_or(0) as usize;
                let Some(block) = self.blocks.get_mut(index) else { return Ok(updates) };
                match block["type"].as_str().unwrap_or_default() {
                    "tool_use" => {
                        let raw = &self.partial_inputs[index];
                        // An unparseable input stays as an empty object; the
                        // tool runner then rejects it as invalid.
                        block["input"] = if raw.trim().is_empty() { json!({}) } else { serde_json::from_str(raw).unwrap_or_else(|_| json!({})) };
                    }
                    "thinking" => {
                        let summary = block["thinking"].as_str().unwrap_or_default().trim().to_string();
                        if !summary.is_empty() {
                            updates.push(Event::Thinking(summary));
                        }
                    }
                    _ => {}
                }
            }
            "message_delta" => {
                if let Some(reason) = event["delta"]["stop_reason"].as_str() {
                    self.stop_reason = Some(reason.to_string());
                }
            }
            "message_stop" => self.finished = true,
            "error" => {
                let message = event["error"]["message"].as_str().unwrap_or("unknown error");
                return Err(format!("The Claude API reported an error: {message}"));
            }
            _ => {}
        }
        Ok(updates)
    }

    fn into_reply(self) -> Reply {
        Reply { blocks: self.blocks.into_iter().filter(|b| !b.is_null()).collect(), stop_reason: self.stop_reason }
    }
}

fn append_string(block: &mut Value, key: &str, text: &str) {
    let current = block[key].as_str().unwrap_or_default().to_string();
    block[key] = Value::String(current + text);
}

/// A piece of a reply for display: plain text, an offset link, or a template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    Text(String),
    Offset(usize, String),
    Template(String),
}

/// Split reply text into text, `0x…` offset links and ```template blocks.
pub fn segments(text: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("```template") {
        split_offsets(&rest[..start], &mut out);
        let after = &rest[start + "```template".len()..];
        let body_start = after.find('\n').map(|i| i + 1).unwrap_or(0);
        match after[body_start..].find("```") {
            Some(end) => {
                out.push(Segment::Template(after[body_start..body_start + end].trim_end().to_string()));
                rest = &after[body_start + end + 3..];
            }
            None => {
                // Still streaming: show the partial template as text.
                out.push(Segment::Text(rest[start..].to_string()));
                return out;
            }
        }
    }
    split_offsets(rest, &mut out);
    out
}

fn split_offsets(text: &str, out: &mut Vec<Segment>) {
    let bytes = text.as_bytes();
    let mut plain_start = 0;
    let mut at = 0;
    while at + 2 < bytes.len() {
        let boundary = at == 0 || !(bytes[at - 1] as char).is_ascii_alphanumeric();
        if boundary && bytes[at] == b'0' && (bytes[at + 1] == b'x' || bytes[at + 1] == b'X') {
            let digits = bytes[at + 2..].iter().take_while(|b| b.is_ascii_hexdigit()).count();
            let end = at + 2 + digits;
            let ends_cleanly = end == bytes.len() || !(bytes[end] as char).is_ascii_alphanumeric();
            if digits > 0 && digits <= 16 && ends_cleanly
                && let Ok(offset) = usize::from_str_radix(&text[at + 2..end], 16)
            {
                if plain_start < at {
                    out.push(Segment::Text(text[plain_start..at].to_string()));
                }
                out.push(Segment::Offset(offset, text[at..end].to_string()));
                plain_start = end;
                at = end;
                continue;
            }
        }
        at += 1;
    }
    if plain_start < text.len() {
        out.push(Segment::Text(text[plain_start..].to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(state: &mut StreamState, events: &[Value]) -> Vec<Event> {
        events.iter().flat_map(|e| state.apply(e).unwrap()).collect()
    }

    #[test]
    fn stream_reassembles_text_thinking_and_tool_blocks_verbatim() {
        let mut state = StreamState::default();
        let updates = feed(
            &mut state,
            &[
                json!({"type":"message_start","message":{"id":"msg_1"}}),
                json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}),
                json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"Look at "}}),
                json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"the header."}}),
                json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig=="}}),
                json!({"type":"content_block_stop","index":0}),
                json!({"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}),
                json!({"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"It is a PNG "}}),
                json!({"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"at 0x100."}}),
                json!({"type":"content_block_stop","index":1}),
                json!({"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_1","name":"read_bytes","input":{}}}),
                json!({"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"offset\": 256,"}}),
                json!({"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":" \"length\": 64}"}}),
                json!({"type":"content_block_stop","index":2}),
                json!({"type":"message_delta","delta":{"stop_reason":"tool_use"}}),
                json!({"type":"message_stop"}),
            ],
        );
        let reply = state.into_reply();
        assert_eq!(reply.stop_reason.as_deref(), Some("tool_use"));
        assert_eq!(reply.blocks[0], json!({"type":"thinking","thinking":"Look at the header.","signature":"sig=="}));
        assert_eq!(reply.blocks[1]["text"], "It is a PNG at 0x100.");
        assert_eq!(reply.blocks[2]["input"], json!({"offset":256,"length":64}));
        let texts: Vec<String> = updates.iter().filter_map(|u| if let Event::Text(t) = u { Some(t.clone()) } else { None }).collect();
        assert_eq!(texts.concat(), "It is a PNG at 0x100.");
        assert!(updates.iter().any(|u| matches!(u, Event::Thinking(t) if t == "Look at the header.")));
    }

    #[test]
    fn stream_errors_surface_as_failures() {
        let mut state = StreamState::default();
        let error = state.apply(&json!({"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}));
        assert!(error.unwrap_err().contains("Overloaded"));
    }

    #[test]
    fn a_stream_that_ends_without_message_stop_is_retried_not_kept() {
        let mut state = StreamState::default();
        state.apply(&json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"read_bytes","input":{}}})).unwrap();
        assert!(matches!(complete_reply(state), Err(SendError::Retryable(_))));
    }

    #[test]
    fn a_retried_reply_replaces_the_partial_text_instead_of_repeating_it() {
        let (sender, receiver) = mpsc::channel();
        let mut assistant = Assistant { events: Some(receiver), ..Default::default() };
        assistant.transcript.push(Turn::User("What is this?".into()));
        for event in [
            Event::AttemptStarted { retry: false },
            Event::Thinking("Looking".into()),
            Event::Text("It is a PN".into()),
            Event::AttemptStarted { retry: true },
            Event::Text("It is a PNG image.".into()),
            Event::Done { messages: Vec::new(), note: None },
        ] {
            sender.send(event).unwrap();
        }
        assistant.poll(|_| Ok(String::new()));
        assert_eq!(
            assistant.transcript,
            vec![Turn::User("What is this?".into()), Turn::Assistant("It is a PNG image.".into())]
        );
    }

    #[test]
    fn tools_are_generated_from_every_read_method_with_valid_names_and_schemas() {
        let tools = tool_definitions();
        let tools = tools.as_array().unwrap();
        let readers = api::METHODS.iter().filter(|method| method.effect == api::Effect::Read && method.namespace() != "api").count();
        assert_eq!(tools.len(), readers);
        for tool in tools {
            let name = tool["name"].as_str().unwrap();
            assert!(!name.is_empty() && name.len() <= 64, "{name}");
            assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'), "{name} breaks the tool name rules");
            assert!(!tool["description"].as_str().unwrap().is_empty());
            assert_eq!(tool["input_schema"]["type"], "object", "{name}");
            assert!(tool["input_schema"].get("$schema").is_none());
        }
        let names: Vec<&str> = tools.iter().map(|tool| tool["name"].as_str().unwrap()).collect();
        for earlier in ["bytes_hexdump", "search_find_all", "findings_query", "structure_parse", "analysis_overview", "analysis_statistics", "analysis_segments", "analysis_compressibility", "analysis_text_encoding", "reference_lookup", "analysis_processor"] {
            assert!(names.contains(&earlier), "the tool behind one of Ask's original eleven, {earlier}, is offered");
        }
        assert!(!names.contains(&"documents_open") && !names.contains(&"api_describe"), "only methods that read are offered");
    }

    #[test]
    fn tool_calls_name_an_offered_method_and_carry_an_object() {
        let call = ToolCall::parse("bytes_hexdump", &json!({"start": 16, "len": 4})).unwrap();
        assert_eq!(call.method, "bytes.hexdump");
        assert_eq!(call.describe(), r#"bytes.hexdump {"len":4,"start":16}"#);
        assert_eq!(ToolCall::parse("analysis_segments", &json!({})).unwrap().describe(), "analysis.segments");
        assert!(ToolCall::parse("format_disk", &json!({})).is_err());
        assert!(ToolCall::parse("documents_open", &json!({"path": "/etc/passwd"})).is_err(), "methods that change the view are not tools");
        assert!(ToolCall::parse("bytes_read", &json!([1, 2])).is_err());
    }

    #[test]
    fn a_tool_call_runs_its_method_and_reports_errors_as_json() {
        let mut workspace = crate::api::test_support::workspace_with("fw.bin", b"FWIM\x01\x02");
        let call = ToolCall::parse("bytes_read", &json!({"start": 0, "len": 4})).unwrap();
        let result: Value = serde_json::from_str(&call.run(&mut workspace).unwrap()).unwrap();
        assert_eq!(result["data"], "4657494d");
        let past_the_end = ToolCall::parse("bytes_read", &json!({"start": 4, "len": 9})).unwrap().run(&mut workspace).unwrap_err();
        assert!(past_the_end.contains("out_of_range"), "{past_the_end}");
        let truncated_input = ToolCall::parse("bytes_read", &json!({})).unwrap().run(&mut workspace).unwrap_err();
        assert!(truncated_input.contains("invalid_params"), "truncated eager input is rejected: {truncated_input}");
    }

    #[test]
    fn request_body_uses_the_current_model_and_settings() {
        let body = request_body(&[json!({"role":"user","content":"hi"})]);
        assert_eq!(body["model"], "claude-opus-5-5");
        assert_eq!(body["stream"], true);
        assert_eq!(body["fallbacks"], "default");
        assert_eq!(body["thinking"]["type"], "adaptive");
        assert_eq!(body["output_config"]["effort"], "high");
        assert_eq!(body["tool_choice"]["type"], "auto");
        assert!(body.get("temperature").is_none() && body["thinking"].get("budget_tokens").is_none());
        for tool in body["tools"].as_array().unwrap() {
            assert_eq!(tool["eager_input_streaming"], true);
            assert_eq!(tool["input_schema"]["additionalProperties"], false);
        }
    }

    #[test]
    fn replies_split_into_offset_links_and_templates() {
        let text = "Header at 0x1A40, not ax10 or 0xZZ.\n```template\nstruct R { a: u32 }\nroot R\n```\nDone 0x2.";
        let parts = segments(text);
        assert_eq!(parts[0], Segment::Text("Header at ".into()));
        assert_eq!(parts[1], Segment::Offset(0x1A40, "0x1A40".into()));
        assert_eq!(parts[2], Segment::Text(", not ax10 or 0xZZ.\n".into()));
        assert_eq!(parts[3], Segment::Template("struct R { a: u32 }\nroot R".into()));
        assert_eq!(parts[5], Segment::Offset(2, "0x2".into()));
        // An unfinished template while streaming stays as text.
        assert!(matches!(segments("x ```template\nstruct").last(), Some(Segment::Text(_))));
    }

    #[test]
    fn context_and_dumps_render_for_the_model() {
        let context = FileContext {
            name: "fw.bin".into(),
            size: 4096,
            cursor: 0x10,
            selection: Some((0x10, 4)),
            findings: vec!["0x0: PNG image".into()],
            hex_dump: hex_dump(b"\x89PNG\r\n\x1a\nhello", 0x100),
            references: vec!["User Datagram Protocol\nDatagrams between ports.\n".into()],
            ..Default::default()
        };
        let text = context.render();
        assert!(text.contains("Reference notes on the formats at the cursor:\n\nUser Datagram Protocol\nDatagrams between ports.\n"));
        assert!(text.contains("fw.bin (4096 bytes)") && text.contains("Selection: 0x10..0x14") && text.contains("- 0x0: PNG image"));
        assert!(text.contains("00000100  89 50 4e 47") && text.contains(".PNG....hello"));
        assert_eq!(truncate("abcdef", 3), "abc\n[truncated: the result was longer than 3 characters]");
        assert_eq!(api_error_message(401, r#"{"error":{"message":"invalid x-api-key"}}"#), "The API key was rejected (invalid x-api-key).");
    }

    #[test]
    fn asking_without_credentials_explains_how_to_set_them() {
        let mut assistant = Assistant::default();
        let error = assistant.ask("what is this?", &FileContext::default(), None).unwrap_err();
        assert!(error.contains("Settings"));
        assert!(!assistant.is_busy());
        assert!(assistant.transcript.is_empty(), "nothing is recorded for a question that was not sent");
    }
}
