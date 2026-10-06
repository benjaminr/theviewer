//! `theviewer mcp` driven over standard input and output, as an MCP client
//! such as Claude Code drives it.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// How long to wait for an answer before the test fails.
const PATIENCE: Duration = Duration::from_secs(30);

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("theviewer-mcp-stdio-{}-{name}", std::process::id()))
}

/// A plugin that offers one method, `probe.echo`.
const PROBE_PLUGIN: &str = r#"
theviewer.plugin{ name = "probe" }
theviewer.register_method{
  name = "probe.echo",
  summary = "Echo the text given.",
  params = { text = "string" },
  run = function(params, api) return { echoed = params.text } end,
}
"#;

/// The server, spoken to a line at a time.
struct Client {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    /// Notifications seen while waiting for answers.
    notifications: Vec<Value>,
    next_id: i64,
}

impl Client {
    fn start(args: &[&str]) -> Client {
        let mut child = Command::new(env!("CARGO_BIN_EXE_theviewer"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the theviewer binary runs");
        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        let stdin = child.stdin.take();
        Client { child, stdin, lines, notifications: Vec::new(), next_id: 1 }
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    /// The next message the server writes, which must be JSON.
    fn receive(&mut self, deadline: Instant) -> Option<Value> {
        let left = deadline.saturating_duration_since(Instant::now());
        let line = self.lines.recv_timeout(left).ok()?;
        Some(serde_json::from_str(&line).unwrap_or_else(|error| panic!("the server wrote a line that is not JSON ({error}): {line}")))
    }

    /// Send a request and wait for its answer, keeping notifications.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let deadline = Instant::now() + PATIENCE;
        loop {
            let message = self.receive(deadline).unwrap_or_else(|| panic!("no answer to {method}"));
            if message["id"] == id {
                return message;
            }
            assert!(message.get("id").is_none(), "an answer to another request: {message}");
            self.notifications.push(message);
        }
    }

    /// The result of calling a tool, which must have succeeded.
    fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        let answer = self.request("tools/call", json!({ "name": name, "arguments": arguments }));
        let result = answer["result"].clone();
        assert_eq!(result["isError"], false, "{name}: {answer}");
        result["structuredContent"].clone()
    }

    /// Wait for a notification of `method`, among those seen or to come.
    fn wait_for_notification(&mut self, method: &str, within: Duration) -> Option<Value> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(index) = self.notifications.iter().position(|message| message["method"] == method) {
                return Some(self.notifications.remove(index));
            }
            let message = self.receive(deadline)?;
            self.notifications.push(message);
        }
    }

    /// Close standard input and wait for the server to exit.
    fn finish(mut self) -> std::process::ExitStatus {
        drop(self.stdin.take());
        let deadline = Instant::now() + PATIENCE;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "the server did not exit when its input closed");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn tool_names(answer: &Value) -> Vec<String> {
    answer["result"]["tools"].as_array().unwrap().iter().map(|tool| tool["name"].as_str().unwrap().to_string()).collect()
}

#[test]
fn a_client_lists_calls_edits_reads_subscribes_and_disconnects() {
    let file = temp_path("sample.bin");
    std::fs::write(&file, b"\x89PNG\r\n\x1a\nsome more bytes").unwrap();
    let plugins = temp_path("plugins");
    let _ = std::fs::remove_dir_all(&plugins);
    std::fs::create_dir_all(&plugins).unwrap();
    std::fs::write(plugins.join("probe.lua"), PROBE_PLUGIN).unwrap();
    let mut client = Client::start(&["mcp", "--plugins", plugins.to_str().unwrap(), file.to_str().unwrap()]);

    let initialize = client.request("initialize", json!({ "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": { "name": "end-to-end", "version": "1" } }));
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(initialize["result"]["serverInfo"]["name"], "theviewer");
    client.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));

    let tools = client.request("tools/list", json!({}));
    let names = tool_names(&tools);
    assert!(names.contains(&"bytes_read".to_string()) && names.contains(&"bytes_write".to_string()));
    assert!(names.contains(&"probe_echo".to_string()), "a plugin's method is a tool: {names:?}");

    let read = client.call_tool("bytes_read", json!({ "start": 0, "len": 4 }));
    assert_eq!(read["data"], "89504e47");

    let subscribed = client.request("resources/subscribe", json!({ "uri": "theviewer://doc/doc-1/bytes/0-4" }));
    assert_eq!(subscribed["result"], json!({}));
    let written = client.call_tool("bytes_write", json!({ "start": 0, "data": "cafe" }));
    assert_eq!(written["version"], 1);
    let updated = client.wait_for_notification("notifications/resources/updated", PATIENCE).expect("the subscriber hears of the edit");
    assert_eq!(updated["params"]["uri"], "theviewer://doc/doc-1/bytes/0-4");
    assert_eq!(client.call_tool("bytes_read", json!({ "start": 0, "len": 4 }))["data"], "cafe4e47", "the edit is there to read");

    let resource = client.request("resources/read", json!({ "uri": "theviewer://doc/doc-1/bytes/0-4" }));
    assert_eq!(resource["result"]["contents"][0]["blob"], "yv5ORw==");
    let info = client.request("resources/read", json!({ "uri": "theviewer://doc/doc-1" }));
    let info: Value = serde_json::from_str(info["result"]["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!((info["modified"].clone(), info["name"].clone()), (json!(true), json!(file.file_name().unwrap().to_str().unwrap())));

    assert_eq!(client.call_tool("probe_echo", json!({ "text": "hi" }))["echoed"], "hi", "the plugin's method runs");

    let modern = client.request(
        "tools/call",
        json!({ "name": "bytes_read", "arguments": { "start": 0, "len": 2 }, "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} } }),
    );
    assert_eq!((modern["result"]["resultType"].clone(), modern["result"]["structuredContent"]["data"].clone()), (json!("complete"), json!("cafe")), "a request of the current revision is served too");

    let status = client.finish();
    assert!(status.success(), "the server exits cleanly when its input closes: {status}");
    assert_eq!(std::fs::read(&file).unwrap()[..4], *b"\x89PNG", "nothing is written to disk without documents_save");
    std::fs::remove_file(file).ok();
    std::fs::remove_dir_all(plugins).ok();
}

#[test]
fn a_file_that_cannot_be_opened_stops_the_server_with_a_message() {
    let output = Command::new(env!("CARGO_BIN_EXE_theviewer")).args(["mcp", "--plugins", "/no/such/dir", "/no/such/file.bin"]).stdin(Stdio::null()).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "nothing but MCP messages goes to standard output");
    assert!(String::from_utf8_lossy(&output.stderr).contains("/no/such/file.bin"));
}
