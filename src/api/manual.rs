//! The API reference, `docs/api.md`, written from the method table and the
//! topic table by `cargo run --bin api_docs`.
//!
//! The reference opens with the guide every caller needs (the ways in,
//! the conventions, effects and permissions, the journal, errors, jobs and
//! versioning), then lists each method with what its declaration says
//! about it (effect, MCP tool, how the journal, undo and replay treat its
//! calls) and its parameter and result tables, then the bus's topics. The
//! numbers it quotes (limits, timeouts, page sizes) are read from the
//! constants the code uses, so they cannot drift apart.

use std::fmt::Write;

use serde_json::Value;

use super::{Effect, ErrorCode, METHODS, Method, Move, Replay, Reverse, Undo, WritesFile, describe};
use crate::journal::{JournalLimits, Journalled};

/// The opening of the reference: what the API is, and how to call it.
const INTRODUCTION: &str = r#"theviewer has one data API: a table of methods over documents, bytes, bits, selections, findings, structures, templates, codecs, packets, analysis, the journal and recipes, each declared once with its name, its effect and the JSON schemas of its parameters and result. Every way into the program calls the same table:

| Way in | Calls methods as | Producer id |
| --- | --- | --- |
| Panels, menus, the command palette and shortcuts | the person at the keyboard | `panel` |
| Lua plugins (`theviewer.api.<namespace>.<method>{…}`) | the plugin, by file name | `plugin:acme_telemetry.lua` |
| Ask, the assistant | Ask | `ask` |
| MCP clients (`theviewer mcp FILE…`) | the client, by the name it gives | `mcp:claude-code` |
| The command line (`theviewer api METHOD …`) | the command line | `cli` |
| Recipes (the Run recipe window, `theviewer replay`, `recipes.run`) | the recipe, by name | `recipe:Telemetry frames` |

A method does the same whichever way it is called. Every call that changes something is recorded in the session's journal, by whom, which gives the History tab, undo across analysis steps, playback and recipes. Edits are labelled with their caller in the undo history ("XOR by mcp:claude-code") and published on the workspace bus as theirs.

This reference is generated from the method table by `cargo run --bin api_docs`. `api.describe` (on the command line, `theviewer api --describe`) returns the same table as JSON, with every schema in full and the methods plugins have registered.

## Calling the API

### From the command line

```sh
theviewer api bytes.read '{"start": 0, "len": 16}' firmware.bin
theviewer api analysis.overview firmware.bin
theviewer api --save bytes.write '{"start": 4, "data": "deadbeef"}' firmware.bin
theviewer api --save history.transaction '{"calls": [
    {"method": "bytes.write", "params": {"start": 0, "data": "7f454c46"}},
    {"method": "bytes.delete", "params": {"start": 64, "len": 16}}]}' firmware.bin
theviewer api --describe
```

`theviewer api [--save] METHOD ['{JSON PARAMS}'] [FILE]` opens FILE (when given) in a workspace of its own without a window, loads the plugins from `./plugins` and `~/.config/theviewer/plugins` (so their methods can be called too), makes the one call as `cli` and prints its result as JSON on standard output. A failed call prints the error as JSON on standard error and exits with status 1; a command line that cannot be understood exits with status 2. With `--save`, a call that left the file's document with unsaved edits is followed by `documents.save`, which writes them over FILE; without it the file is never changed. Every call is allowed: the file is the one you named. The call is the whole session, so a method whose effect is `job` prints only its job's id: use such methods from the window, from an MCP client, or in a recipe (`theviewer replay` waits for each job a step starts). Plugins' subscription handlers do not run here.

### From an MCP client

`theviewer mcp FILE…` serves the files over the Model Context Protocol on standard input and output. The core methods are tools named with underscores for dots (`bytes_read`), with `api_search`, `api_describe` and `api_call` to reach the rest; documents, their bytes, findings, facts and packet sets, and the reference notes, are resources. See [Using theviewer from MCP clients](mcp.md).

### From a Lua plugin

```lua
local head = theviewer.api.bytes.read{ start = 0, len = 16 }
theviewer.api.transform.apply{ selection = { range = { 0, 16 } }, operation = { op = "xor", key = "5a" } }
```

A plugin calls the API while one of its actions, subscription handlers or registered methods runs; an error is raised as a Lua error, `"<code>: <message>"`. See [Lua plugins](plugins.md).

### From Rust

```rust
use std::path::Path;
use std::sync::Arc;

use serde_json::json;
use theviewer::api::{self, Caller, HeadlessWorkspace, Workspace};

let mut workspace = HeadlessWorkspace::new(Arc::new(theviewer::app::build_registry()));
workspace.open_path(Path::new("capture.bin"))?;
let head = api::call(&mut workspace, &Caller::Cli, "bytes.read", json!({"start": 0, "len": 16}))?;
```

`api::call` checks the parameters against the method's schema, checks the caller's permission, runs the method and records the call in the journal. In the app, `ViewerApp::perform(method, params)` calls as the person and shows a failure in the status bar; `ViewerApp::perform_derived` also notes where parameters' values came from, for recipes. Callers that cannot wait for the person to confirm (Ask, plugins' handlers) use `api::call_or_hold`. Each namespace module (`theviewer::api::bytes`, `theviewer::api::search`…) also offers its methods as typed functions.
"#;

/// The conventions every method follows; `{max_call}` and the page sizes
/// are filled in from the code.
fn conventions() -> String {
    let max_call = mebibytes(super::MAX_CALL_BYTES);
    let default_page = super::values::DEFAULT_PAGE;
    let max_page = super::values::MAX_PAGE;
    let max_tool_text = mebibytes(crate::mcp::tools::MAX_RESULT_TEXT);
    format!(
        r#"## Conventions

**Documents.** Each open document has an id: `doc-1`, `doc-2` and so on. A method about a document takes `doc`: an id, the path of an open document, or `"current"`, which is also what an omitted `doc` means. `documents.list` lists the open documents. A document derived from another (a span opened on its own, a stream decompressed, an embedded file) is a document of its own, with its own id.

**Spans** are `start` and `len` in bytes, counted from 0. A span must lie inside its document, or the call fails with `out_of_range`; an omitted `len` runs to the end of the document. Where several spans are given or returned, each is a pair `[start, len]`.

**Bit spans** are `bit_start` and `bit_len`: the byte offset times 8 plus the bit within that byte, counted in the call's `order`, `"msb"` (the default: the most significant bit of each byte first) or `"lsb"`.

**Selections** are `{{"range": [start, len]}}`, `{{"ranges": [[start, len], …]}}`, or a column of every record, `{{"columns": {{"first_row_start": 32, "stride": 16, "column": 2, "width": 4, "rows": 10}}}}`. `selection.set` takes `null` to select nothing. A method that edits a `selection` uses the document's own selection when it is omitted, or the byte at the cursor when nothing is selected.

**Bytes** in JSON are compact lower-case hex (`"89504e47"`) unless the call's `encoding` asks for `"base64"` (standard, with padding) or `"text"` (UTF-8). Hex given to a method may hold spaces (`"de ad be ef"`). Bytes returned as text that are not UTF-8 become U+FFFD, so read binary data as hex or base64.

**Numbers.** Integers up to 2^53 are JSON numbers. Larger ones, such as a 64-bit value from `numbers.decode` or `bits.read`, are strings of decimal digits, since JSON numbers carry no more exactly.

**Pages.** A method that lists takes `limit` ({default_page} by default, at most {max_page} for most) and returns `next`, an opaque cursor: pass it back as `next` for the following page; it is absent after the last. The journal and the bus are followed rather than paged: `history.list` takes `since` and `events.poll` takes `cursor`, as their schemas say.

**Limits.** One call reads or returns at most {max_call}; ask for less, or a page at a time. Through MCP a tool's result carries at most {max_tool_text} of JSON text.

**Parameters are checked.** Parameters the method does not have, or of the wrong type, fail with `invalid_params` before anything runs. Omitted parameters count as `{{}}`.

**Versions.** Each document has a version, which every edit increases. A method that edits takes `expect_version` and returns the new `version`: when the document has changed since the version given, the call fails with `version_conflict` and changes nothing.
"#
    )
}

/// The effects, who may make which calls, and how they are confirmed.
fn effects_and_permissions() -> String {
    let timeout = crate::confirmations::CONFIRMATION_TIMEOUT.as_secs();
    format!(
        r#"## Effects and permissions

Each method has one effect, which says what calling it does and decides who may call it without asking:

| Effect | What a call does | Checked against the caller's permission | How the journal keeps it |
| --- | --- | --- | --- |
| `read` | Looks, and changes nothing. | No | In the ring of recent reads, which a later step can cite |
| `analysis` | Changes the session's analysis but no bytes and nothing on screen: packet sets and how they decode, published findings, a pinned template, a cancelled job. | No, unless it writes a file | As a step |
| `job` | Starts background work and returns `{{"job": …}}` at once; see [Jobs](#jobs). | No | As a step |
| `view` | Changes what is shown or open, but no bytes: the shape, folds, bookmarks, the selection and cursor, the document that is current. | Yes | As a step |
| `edit` | Changes a document's bytes, as one undoable step, or moves along the journal. | Yes | As a step |

A method that writes a file (`documents.save`, `documents.export`, `packets.export_pcap`, `recipes.save`, `history.save_recipe`, and others when given a `path`) needs leave to edit, whatever its effect: each such method's entry below says so.

**Who is asked.** The person at the keyboard (`panel`) may do anything. Any other caller is checked before a call that edits, changes the view or writes a file, against its setting under Settings › Permissions, kept per producer id:

| Setting | Meaning |
| --- | --- |
| Always allow | Its calls run without asking. |
| Always ask | A window shows the call in plain words ("Overwrite 4 bytes at 0x40 with DE AD BE EF") with Allow once, Always allow this client and Deny. This is the setting of a client not seen before. |
| Never allow | Its calls fail with `read_only`; it may still read. |

Calls wait for the person in the order they arrived; one not answered within {timeout} seconds is refused with `read_only`, saying so. Ask's tool calls and plugins' handlers are held while they wait. A call that must be confirmed but came by a way that cannot wait fails at once with `read_only` and `data.reason` set to `"needs_confirmation"`.

**Without a window** (`theviewer api`, `theviewer mcp`, `theviewer replay`) every call is allowed: the files are the ones the person named, and edits reach the disk only through `documents.save`.

**Edits.** Each call of an `edit` method is one undo step of its document, labelled with what it did and, for anyone but the person, who did it: "Overwrite 2 bytes by plugin:acme_telemetry.lua". `history.undo` and `history.redo` move through those steps; `history.transaction` runs several calls on one document as one step and reverses them all when one fails. Every change to the bytes is published on `document.edited`.

**Ask** offers as tools the methods whose effect is `read`, `analysis` or `edit` (the plugins' too), except `api.*` and `documents.save`; it does not change the view or start jobs.
"#
    )
}

/// How the journal, undo, going back, playback and recipes treat calls.
fn journal_section() -> String {
    let limits = JournalLimits::default();
    format!(
        r#"## The journal, undo and replay

Every call made through the API is recorded in the session's journal (the History tab shows it; `history.list` reads it):

* Each call of an `edit`, `view`, `job` or `analysis` method, by any caller, is a **step**, with a step number, its caller, its parameters, its result and a description in plain words; a call that failed or was refused is recorded too. A call refused because it must first be confirmed is recorded when the person allows it.
* **Reads** go into a ring of the last {reads} recent reads, numbered in the same sequence. When a later step used a value a read returned (a match's offset, a detected length field), the read is moved into the journal under its own number, so the step can cite it.
* Calls made inside another call (a transaction's, a recipe run's, those a plugin's method makes) are part of the outer call's step.
* The methods that read the journal or edit where its values came from (`history.list`, `history.make_anchor`…) are not journalled.
* Repeated calls of a setter that merges its repeats (`selection.set`, `cursor.set`, `view.set_shape`) by the same caller on the same document are merged into one step, so dragging a selection undoes as one step.

The journal keeps at most {entries} entries; very large parameters and results are kept as a summary, and a step whose parameters were summarised cannot be repeated exactly.

**Undoing a step.** A byte edit undoes through its document's own undo, so only while it is the document's last edit. A step that changed no bytes undoes through its **inverse**, which its method declares: the call that changes back what it changed (a shape, folds, a bookmark, the selection, the current document, the pinned template, a packet set's decoding, findings published), the call that removes what it made (a packet set), nothing at all (a read, a job, a file written), or no inverse. `history.inverse` says how a step would be undone now; `history.undo_step` undoes it.

**Going back** to step N (`history.go_back`) undoes every later step in effect, latest first. When one has no inverse, the document is brought back to how the session first saw it and steps 1 to N are run again. Either way the later steps stay in the journal, shown as undone, and are left out of recipes and playback.

**Replay.** Going back, playback and recipes repeat the steps of the analysis. Some steps are never repeated: moves along the journal itself, opening a document (what it opened is open already), writing a file, reloading plugins and starting or stopping a live source.

Each method's entry below says how the journal, undo and replay treat its calls. Methods plugins register are steps (or reads) as their effect says, are repeated by recipes, and keep nothing to undo them by beyond their byte edits.
"#,
        reads = limits.max_reads,
        entries = limits.max_entries,
    )
}

/// What each error code means and what to do about it.
const ERRORS: &[(ErrorCode, &str)] = &[
    (ErrorCode::InvalidParams, "The parameters do not match the method's schema, or ask for something impossible. The message says which, and what to give instead."),
    (ErrorCode::OutOfRange, "A span falls outside the document."),
    (ErrorCode::NotFound, "No such document, method, packet set, job, step, recipe or entry; or a recipe's anchor found nothing."),
    (ErrorCode::VersionConflict, "The document changed since `expect_version`; nothing was changed. Read again and retry."),
    (ErrorCode::ReadOnly, "The caller may not make this call: its permission is Never allow, the person declined it, nobody answered in time, or it must first be confirmed (`data.reason` is `\"needs_confirmation\"`). A plugin's handler that did not declare edits gets it too."),
    (ErrorCode::TooLarge, "Over a per-call limit; ask for less."),
    (ErrorCode::Cancelled, "A job was cancelled."),
    (ErrorCode::PluginFailed, "A plugin raised an error or used up its budget; the message is the plugin's."),
    (ErrorCode::Unavailable, "Something needed is missing or not possible here: tshark, a home folder, a live source without a window, a plugin that has been unloaded."),
];

/// The errors section.
fn errors_section() -> String {
    let mut out = String::from(
        "## Errors\n\nA failed call returns `{code, message, data}`: a code to act on, a message saying what went wrong and what to do next, and sometimes details. On the command line it is printed as JSON on standard error; in Lua it is raised as `\"<code>: <message>\"`; through MCP it is a tool result marked `isError`, so the model sees it and can try again.\n\n| Code | Meaning |\n| --- | --- |\n",
    );
    for (code, meaning) in ERRORS {
        let _ = writeln!(out, "| `{}` | {meaning} |", code_name(*code));
    }
    out.push_str(
        "\nSome errors carry `data`: an anchor of a recipe step that did not resolve gives `data.anchor` and `data.reason`; a `recipes.run` that stopped gives the run's report as `data.report`.\n",
    );
    out
}

/// Jobs: long work, followed to its end.
fn jobs_section() -> String {
    let wait_minutes = crate::journal::replay::JOB_WAIT_LIMIT.as_secs() / 60;
    format!(
        r#"## Jobs

A method whose effect is `job` starts work in the background and returns `{{"job": "report-3"}}` at once. Follow it with `jobs.status`, which gives its state (`running`, `cancelling`, `finished`, `failed` or `cancelled`), how far it has got (`done` of `total`, when it counts) and, once finished, `result`: what the method would have returned had it waited. The same arrives on the bus as `job.started`, `job.progress` and `job.finished`. `jobs.list` lists the last 100 jobs; `jobs.cancel` asks one to stop, and it ends as `cancelled` without a result as soon as it notices.

A recipe step that starts a job waits for it (up to {wait_minutes} minutes), and later steps can use its result through a step anchor whose path starts `job.`; see [Recipes](recipes.md).
"#
    )
}

/// Versioning and stability.
const VERSIONING: &str = r#"## Versions and stability

`api.version` returns the API's version, `"1.0"`. Within a major version changes only add: new methods, new optional parameters and new result fields, so a client written for 1.0 works with any 1.x. The methods in this reference are stable. Methods plugins register join the table at run time and are listed by `api.describe` as experimental: they change when their plugin does. A recipe records the major version it was made with (`"1.x"`) and warns when it runs under another.
"#;

/// The reference, `docs/api.md`, written from the method table.
pub fn reference_markdown() -> String {
    let description = describe();
    let mut out = String::new();
    let _ = writeln!(out, "# theviewer data API, version {}\n", description.version);
    out.push_str("<!-- Generated from the method table (src/api.rs and each module in src/api/) by `cargo run --bin api_docs`; the prose is in src/api/manual.rs. Do not edit by hand. -->\n\n");
    out.push_str(INTRODUCTION);
    out.push('\n');
    out.push_str(&conventions());
    out.push('\n');
    out.push_str(&effects_and_permissions());
    out.push('\n');
    out.push_str(&journal_section());
    out.push('\n');
    out.push_str(&errors_section());
    out.push('\n');
    out.push_str(&jobs_section());
    out.push('\n');
    out.push_str(VERSIONING);
    out.push_str(&methods_section());
    out.push_str(&topics_section(&description));
    out
}

/// The table of methods, then each method in full.
fn methods_section() -> String {
    let mut out = format!(
        "\n## Methods\n\n{} methods in {} namespaces. The MCP column says which are listed as tools of their own by `theviewer mcp` (every one is with `--all-tools`; the rest are reached with `api_call`).\n\n| Method | Effect | MCP | Summary |\n| --- | --- | --- | --- |\n",
        METHODS.len(),
        namespace_count(),
    );
    for method in METHODS.iter() {
        let listed = if is_core_tool(method.name) { "core" } else { "" };
        let _ = writeln!(out, "| [`{}`](#{}) | {} | {listed} | {} |", method.name, method.name.replace('.', ""), effect_name(method.effect), method.summary);
    }
    out.push_str("\nEach method's full JSON schemas are in `api.describe` (`theviewer api --describe`).\n");
    for method in METHODS.iter() {
        let _ = write!(out, "\n### {}\n\n{}\n\n", method.name, method.summary);
        let mcp = if is_core_tool(method.name) { "listed by default" } else { "through `api_call`, or with `--all-tools`" };
        let _ = writeln!(out, "**Effect:** `{}` · **MCP tool:** `{}`, {mcp}\n", effect_name(method.effect), crate::mcp::tools::tool_name(method.name));
        let _ = writeln!(out, "**History:** {}\n", history_of(method));
        let params = (method.params)().to_value();
        let result = (method.result)().to_value();
        out.push_str(&properties_table("Parameter", &params, "None."));
        out.push('\n');
        out.push_str(&properties_table("Result field", &result, "Nothing."));
    }
    out
}

/// The topics of the workspace bus, and each one's payload.
fn topics_section(description: &super::Description) -> String {
    let depth = crate::bus::MAX_CAUSE_DEPTH;
    let mut out = format!(
        r#"
## Topics

The workspace bus is where tools, panels, plugins and clients publish what they learn and what happens. Read it with `events.facts` (what is known about a document now) and `events.poll` (what was published after a cursor); plugins subscribe to topics with `theviewer.subscribe`, and MCP clients that subscribe to a resource hear when the facts behind it change.

There are two kinds of message. **Facts** are kept: the latest per topic, producer, document and key. A fact about an older version of its document counts as stale, unless the edits since did not touch its span, in which case it is carried forward with its offsets moved. **Events** are not kept: something happened.

Every message has an envelope: `id` (such as `evt-12`), `topic`, `kind`, `producer`, `document`, `version` (the document version it describes), `span` (`{{start, len}}`, the bytes it is about), `confidence` (0 to 1), `key` (which of a producer's facts on a topic it is), `caused_by` (the message whose handling published it) and the `payload` below; `events.facts` and `events.poll` add `stale` and `retracted`. A chain of messages more than {depth} reactions deep is dropped as a loop.

Plugins may publish any topic but those the app itself publishes (`document.opened`, `document.closed`, `document.edited`, `cursor.moved`, `selection.changed`, `job.started` and `job.finished`), with a payload that must fit the topic's schema, and their own topics, `x.<plugin>.<name>`, with any payload.

| Topic | Kind | Description |
| --- | --- | --- |
"#
    );
    for topic in &description.topics {
        let kind = serde_json::to_value(topic.kind).ok().and_then(|value| value.as_str().map(str::to_string)).unwrap_or_default();
        let _ = writeln!(out, "| [`{}`](#{}) | {kind} | {} |", topic.name, topic.name.replace('.', ""), topic.description);
    }
    for topic in &description.topics {
        let _ = write!(out, "\n### {}\n\n{}\n\n", topic.name, topic.description);
        out.push_str(&properties_table("Payload field", &topic.payload, "None."));
    }
    out
}

/// How the journal, undo and replay treat calls of `method`, in a sentence
/// or two.
fn history_of(method: &Method) -> String {
    match method.journal {
        Journalled::Skip => return "Not journalled: it reads the journal or edits where its values came from.".to_string(),
        Journalled::Read => return "Kept among the recent reads, which a later step can cite.".to_string(),
        Journalled::Step => {}
    }
    let mut parts = vec![if method.merge {
        "Journalled as a step; repeated calls by the same caller on the same document merge into one".to_string()
    } else {
        "Journalled as a step".to_string()
    }];
    match method.replay {
        Replay::Move(kind) => parts.push(format!("a move along the timeline ({}), never repeated", move_name(kind))),
        replay => {
            if let Some(undo) = undo_phrase(method) {
                parts.push(undo);
            }
            parts.push(replay_phrase(replay).to_string());
        }
    }
    let mut sentence = format!("{}.", parts.join("; "));
    match method.writes_file {
        WritesFile::No => {}
        WritesFile::Always => sentence.push_str(" Writes a file, so it needs leave to edit."),
        WritesFile::WhenGiven(param) => {
            let _ = write!(sentence, " Writes a file when `{param}` is given, which then needs leave to edit.");
        }
    }
    sentence
}

/// How a step of `method` is undone, when that is worth saying.
fn undo_phrase(method: &Method) -> Option<String> {
    let phrase = match method.undo {
        Undo::Reverses(reverse) => format!("undone by changing back {}", reversed(reverse)),
        Undo::Creates(resource) => format!("undone by `{}` on what it made, while no later step uses it", resource.remover),
        Undo::Irreversible => "it has no inverse, so going back past it runs the session's steps again".to_string(),
        Undo::Nothing(_) if method.effect == Effect::Edit && method.writes_file == WritesFile::No => "its bytes undo through the document's undo".to_string(),
        Undo::Nothing(why) => format!("nothing to undo: {why}"),
    };
    Some(phrase)
}

/// What a reversible step changes, which its inverse changes back.
fn reversed(reverse: Reverse) -> &'static str {
    match reverse {
        Reverse::Shape => "the shape the bytes are drawn in",
        Reverse::Folds => "the folds",
        Reverse::AddBookmark | Reverse::RemoveBookmark => "the bookmark at that offset",
        Reverse::Select | Reverse::MoveCursor => "the selection and cursor",
        Reverse::OpenDocument { .. } => "which document is current",
        Reverse::ClearTemplate | Reverse::PinTemplate => "the template pinned over the document (when the call pins or clears one)",
        Reverse::Decoding => "how the packet set decodes",
        Reverse::PublishFindings | Reverse::RetractFindings => "the findings its caller published under that key",
    }
}

/// Whether going back, playback and recipes repeat a step.
fn replay_phrase(replay: Replay) -> &'static str {
    match replay {
        Replay::Step => "repeated by going back, playback and recipes",
        Replay::OpensDocument { .. } => "not repeated: what it opened is open already",
        Replay::WritesFile => "not repeated: the file stays as written",
        Replay::Never | Replay::Move(_) => "never repeated",
    }
}

fn move_name(kind: Move) -> &'static str {
    match kind {
        Move::Undo => "the document's undo",
        Move::Redo => "the document's redo",
        Move::UndoStep => "undoing one step",
        Move::GoBack => "going back",
    }
}

/// Whether `theviewer mcp` lists the method as a tool by default.
fn is_core_tool(name: &str) -> bool {
    crate::mcp::tools::CORE.contains(&name)
}

fn namespace_count() -> usize {
    let mut namespaces: Vec<&str> = METHODS.iter().map(Method::namespace).collect();
    namespaces.dedup();
    namespaces.len()
}

fn effect_name(effect: Effect) -> String {
    serde_json::to_value(effect).ok().and_then(|value| value.as_str().map(str::to_string)).unwrap_or_default()
}

fn code_name(code: ErrorCode) -> String {
    serde_json::to_value(code).ok().and_then(|value| value.as_str().map(str::to_string)).unwrap_or_default()
}

/// `bytes` as "16 MiB" or "1 MiB".
fn mebibytes(bytes: usize) -> String {
    format!("{} MiB", bytes / (1024 * 1024))
}

/// A Markdown table of an object schema's properties: name, type, whether
/// required, and description.
fn properties_table(heading: &str, schema: &Value, when_empty: &str) -> String {
    let Some(properties) = schema["properties"].as_object().filter(|properties| !properties.is_empty()) else {
        return format!("{heading}s: {when_empty}\n");
    };
    let required: Vec<&str> = schema["required"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let mut out = format!("| {heading} | Type | Required | Description |\n| --- | --- | --- | --- |\n");
    for (name, property) in properties {
        let description = property["description"].as_str().or_else(|| referenced(property, schema)["description"].as_str()).unwrap_or_default();
        let required = if required.contains(&name.as_str()) { "yes" } else { "no" };
        let _ = writeln!(out, "| `{name}` | {} | {required} | {} |", type_label(property, schema), description.replace('\n', " ").replace('|', "\\|"));
    }
    out
}

/// The definition a `$ref` schema points to, or the schema itself.
fn referenced<'a>(schema: &'a Value, root: &'a Value) -> &'a Value {
    match schema["$ref"].as_str().and_then(|reference| reference.strip_prefix("#/$defs/")) {
        Some(name) => &root["$defs"][name],
        None => schema,
    }
}

/// The values an enumeration schema allows: an `enum`, or `oneOf` options
/// that are each a `const` or an `enum`.
fn enum_values(schema: &Value) -> Option<Vec<Value>> {
    if let Some(values) = schema["enum"].as_array() {
        return Some(values.clone());
    }
    let mut values = Vec::new();
    for option in schema["oneOf"].as_array()? {
        match (option.get("const"), option["enum"].as_array()) {
            (Some(constant), _) => values.push(constant.clone()),
            (None, Some(more)) => values.extend(more.iter().cloned()),
            (None, None) => return None,
        }
    }
    Some(values)
}

/// A short name for a schema's type, such as "integer", "array of string"
/// or `"hex" \| "base64"`, for the reference tables.
fn type_label(schema: &Value, root: &Value) -> String {
    if let Some(values) = enum_values(referenced(schema, root)) {
        return values.iter().map(|value| format!("`{value}`")).collect::<Vec<_>>().join(" \\| ");
    }
    if let Some(name) = schema["$ref"].as_str().and_then(|reference| reference.strip_prefix("#/$defs/")) {
        return name.to_string();
    }
    if let Some(options) = schema["anyOf"].as_array() {
        let labels: Vec<String> = options.iter().filter(|option| option["type"] != "null").map(|option| type_label(option, root)).collect();
        return labels.join(" or ");
    }
    let types: Vec<&str> = match &schema["type"] {
        Value::String(name) => vec![name.as_str()],
        Value::Array(names) => names.iter().filter_map(Value::as_str).filter(|name| *name != "null").collect(),
        _ => Vec::new(),
    };
    match types.as_slice() {
        ["array"] if schema.get("prefixItems").is_some() => "pair".to_string(),
        ["array"] => format!("array of {}", type_label(&schema["items"], root)),
        [] => "any".to_string(),
        names => names.join(" or "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_code_is_explained() {
        let codes = schemars::schema_for!(ErrorCode).to_value();
        let declared = super::enum_values(&codes).expect("the error codes are an enumeration");
        assert_eq!(declared.len(), ERRORS.len(), "each error code needs a line in ERRORS");
        for (code, _) in ERRORS {
            assert!(declared.contains(&Value::String(code_name(*code))), "{code:?}");
        }
    }

    #[test]
    fn each_method_says_how_the_history_treats_it() {
        let line = |name: &str| history_of(super::super::method(name).unwrap());
        assert!(line("bytes.write").contains("undo through the document's undo"));
        assert!(line("selection.set").contains("merge into one"));
        assert!(line("history.go_back").contains("a move along the timeline (going back)"));
        assert!(line("documents.save").contains("needs leave to edit"));
        assert!(line("history.make_anchor").starts_with("Not journalled"));
        assert!(line("bytes.read").starts_with("Kept among the recent reads"));
    }
}
