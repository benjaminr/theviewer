# theviewer data API, version 1.0

<!-- Generated from the method table (src/api.rs and each module in src/api/) by `cargo run --bin api_docs`; the prose is in src/api/manual.rs. Do not edit by hand. -->

theviewer has one data API: a table of methods over documents, bytes, bits, selections, findings, structures, templates, codecs, packets, analysis, the journal and recipes, each declared once with its name, its effect and the JSON schemas of its parameters and result. Every way into the program calls the same table:

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

`theviewer api [--save] METHOD ['{JSON PARAMS}'] [FILE]` opens FILE (when given) in a workspace of its own without a window, loads the plugins from `./plugins` and `~/.config/theviewer/plugins` (so their methods can be called too), makes the one call as `cli` and prints its result as JSON on standard output. A failed call prints the error as JSON on standard error and exits with status 1; a command line that cannot be understood exits with status 2. With `--save`, a call that left the file's document with unsaved edits is followed by `documents.save`, which writes them over FILE; without it the file is never changed. Every call is allowed: the file is the one you named. The call is the whole session, so a method whose effect is `job` prints only its job's id: use such methods from the window, from an MCP client, or in a recipe (`theviewer replay` waits for each job a step starts). Plugins' subscription handlers do not run here. The [command line guide](guide/command-line.md) covers the other commands.

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

`api::call` checks the parameters against the method's schema, checks the caller's permission, runs the method and records the call in the journal. In the app, `ViewerApp::perform(method, params)` calls as the person and shows a failure in the status bar; `ViewerApp::perform_derived` also notes where parameters' values came from, for recipes. Callers that cannot wait for the person to confirm (Ask, plugins' handlers) use `api::call_or_hold`. Each namespace module (`theviewer::api::bytes`, `theviewer::api::search`…) also offers its methods as typed functions. Building theviewer, its tests and how the code is laid out are in [docs/development.md](development.md).

## Conventions

**Documents.** Each open document has an id: `doc-1`, `doc-2` and so on. A method about a document takes `doc`: an id, the path of an open document, or `"current"`, which is also what an omitted `doc` means. `documents.list` lists the open documents. A document derived from another (a span opened on its own, a stream decompressed, an embedded file) is a document of its own, with its own id.

**Spans** are `start` and `len` in bytes, counted from 0. A span must lie inside its document, or the call fails with `out_of_range`; an omitted `len` runs to the end of the document. Where several spans are given or returned, each is a pair `[start, len]`.

**Bit spans** are `bit_start` and `bit_len`: the byte offset times 8 plus the bit within that byte, counted in the call's `order`, `"msb"` (the default: the most significant bit of each byte first) or `"lsb"`.

**Selections** are `{"range": [start, len]}`, `{"ranges": [[start, len], …]}`, or a column of every record, `{"columns": {"first_row_start": 32, "stride": 16, "column": 2, "width": 4, "rows": 10}}`. `selection.set` takes `null` to select nothing. A method that edits a `selection` uses the document's own selection when it is omitted, or the byte at the cursor when nothing is selected.

**Bytes** in JSON are compact lower-case hex (`"89504e47"`) unless the call's `encoding` asks for `"base64"` (standard, with padding) or `"text"` (UTF-8). Hex given to a method may hold spaces (`"de ad be ef"`). Bytes returned as text that are not UTF-8 become U+FFFD, so read binary data as hex or base64.

**Numbers.** Integers up to 2^53 are JSON numbers. Larger ones, such as a 64-bit value from `numbers.decode` or `bits.read`, are strings of decimal digits, since JSON numbers carry no more exactly.

**Pages.** A method that lists takes `limit` (100 by default, at most 10000 for most) and returns `next`, an opaque cursor: pass it back as `next` for the following page; it is absent after the last. The journal and the bus are followed rather than paged: `history.list` takes `since` and `events.poll` takes `cursor`, as their schemas say.

**Limits.** One call reads or returns at most 16 MiB; ask for less, or a page at a time. Through MCP a tool's result carries at most 1 MiB of JSON text.

**Parameters are checked.** Parameters the method does not have, or of the wrong type, fail with `invalid_params` before anything runs. Omitted parameters count as `{}`.

**Versions.** Each document has a version, which every edit increases. A method that edits takes `expect_version` and returns the new `version`: when the document has changed since the version given, the call fails with `version_conflict` and changes nothing.

## Effects and permissions

Each method has one effect, which says what calling it does and decides who may call it without asking:

| Effect | What a call does | Checked against the caller's permission | How the journal keeps it |
| --- | --- | --- | --- |
| `read` | Looks, and changes nothing. | No | In the ring of recent reads, which a later step can cite |
| `analysis` | Changes the session's analysis but no bytes and nothing on screen: packet sets and how they decode, published findings, a pinned template, a cancelled job. | No, unless it writes a file | As a step |
| `job` | Starts background work and returns `{"job": …}` at once; see [Jobs](#jobs). | No | As a step |
| `view` | Changes what is shown or open, but no bytes: the shape, folds, bookmarks, the selection and cursor, the document that is current. | Yes | As a step |
| `edit` | Changes a document's bytes, as one undoable step, or moves along the journal. | Yes | As a step |

A method that writes a file (`documents.save`, `documents.export`, `packets.export_pcap`, `recipes.save`, `history.save_recipe`, and others when given a `path`) needs leave to edit, whatever its effect: each such method's entry below says so.

**Who is asked.** The person at the keyboard (`panel`) may do anything. Any other caller is checked before a call that edits, changes the view or writes a file, against its setting under Settings › Permissions, kept per producer id:

| Setting | Meaning |
| --- | --- |
| Always allow | Its calls run without asking. |
| Always ask | A window shows the call in plain words ("Overwrite 4 bytes at 0x40 with DE AD BE EF") with Allow once, Always allow this client and Deny. This is the setting of a client not seen before. |
| Never allow | Its calls fail with `read_only`; it may still read. |

Calls wait for the person in the order they arrived; one not answered within 120 seconds is refused with `read_only`, saying so. Ask's tool calls and plugins' handlers are held while they wait. A call that must be confirmed but came by a way that cannot wait fails at once with `read_only` and `data.reason` set to `"needs_confirmation"`.

**Without a window** (`theviewer api`, `theviewer mcp`, `theviewer replay`) every call is allowed: the files are the ones the person named, and edits reach the disk only through `documents.save`.

**Edits.** Each call of an `edit` method is one undo step of its document, labelled with what it did and, for anyone but the person, who did it: "Overwrite 2 bytes by plugin:acme_telemetry.lua". `history.undo` and `history.redo` move through those steps; `history.transaction` runs several calls on one document as one step and reverses them all when one fails. Every change to the bytes is published on `document.edited`.

**Ask** offers as tools the methods whose effect is `read`, `analysis` or `edit` (the plugins' too), except `api.*` and `documents.save`; it does not change the view or start jobs.

## The journal, undo and replay

Every call made through the API is recorded in the session's journal (the History tab shows it; `history.list` reads it):

* Each call of an `edit`, `view`, `job` or `analysis` method, by any caller, is a **step**, with a step number, its caller, its parameters, its result and a description in plain words; a call that failed or was refused is recorded too. A call refused because it must first be confirmed is recorded when the person allows it.
* **Reads** go into a ring of the last 256 recent reads, numbered in the same sequence. When a later step used a value a read returned (a match's offset, a detected length field), the read is moved into the journal under its own number, so the step can cite it.
* Calls made inside another call (a transaction's, a recipe run's, those a plugin's method makes) are part of the outer call's step.
* The methods that read the journal or edit where its values came from (`history.list`, `history.make_anchor`…) are not journalled.
* Repeated calls of a setter that merges its repeats (`selection.set`, `cursor.set`, `view.set_shape`) by the same caller on the same document are merged into one step, so dragging a selection undoes as one step.

The journal keeps at most 10000 entries; very large parameters and results are kept as a summary, and a step whose parameters were summarised cannot be repeated exactly.

**Undoing a step.** A byte edit undoes through its document's own undo, so only while it is the document's last edit. A step that changed no bytes undoes through its **inverse**, which its method declares: the call that changes back what it changed (a shape, folds, a bookmark, the selection, the current document, the pinned template, a packet set's decoding, findings published), the call that removes what it made (a packet set), nothing at all (a read, a job, a file written), or no inverse. `history.inverse` says how a step would be undone now; `history.undo_step` undoes it.

**Going back** to step N (`history.go_back`) undoes every later step in effect, latest first. When one has no inverse, the document is brought back to how the session first saw it and steps 1 to N are run again. Either way the later steps stay in the journal, shown as undone, and are left out of recipes and playback.

**Notes.** `history.note` writes what the caller is doing and why into the journal, where it is, as an entry of its own by its caller, linked to the steps its text cites as `#12` (and those given). A note changes nothing: it is never undone, repeated, or undone by going back past it, and `history.undo_step` refuses it. `history.list` and `history.entry` give a note's `note` (its text and linked steps) and, on each step, the `notes` linked to it. `history.edit_note` and `history.delete_note` change a note in place and are not journalled; an edited note says when and by whom. Recipes made from the journal carry a note into the `note` of each step it links (unlinked notes are left out), and `history.export_notes` writes the notes out as Markdown.

**Replay.** Going back, playback and recipes repeat the steps of the analysis. Some steps are never repeated: moves along the journal itself, opening a document (what it opened is open already), writing a file, reloading plugins and starting or stopping a live source.

Each method's entry below says how the journal, undo and replay treat its calls. Methods plugins register are steps (or reads) as their effect says, are repeated by recipes, and keep nothing to undo them by beyond their byte edits.

## Errors

A failed call returns `{code, message, data}`: a code to act on, a message saying what went wrong and what to do next, and sometimes details. On the command line it is printed as JSON on standard error; in Lua it is raised as `"<code>: <message>"`; through MCP it is a tool result marked `isError`, so the model sees it and can try again.

| Code | Meaning |
| --- | --- |
| `invalid_params` | The parameters do not match the method's schema, or ask for something impossible. The message says which, and what to give instead. |
| `out_of_range` | A span falls outside the document. |
| `not_found` | No such document, method, packet set, job, step, recipe or entry; or a recipe's anchor found nothing. |
| `version_conflict` | The document changed since `expect_version`; nothing was changed. Read again and retry. |
| `read_only` | The caller may not make this call: its permission is Never allow, the person declined it, nobody answered in time, or it must first be confirmed (`data.reason` is `"needs_confirmation"`). A plugin's handler that did not declare edits gets it too. |
| `too_large` | Over a per-call limit; ask for less. |
| `cancelled` | A job was cancelled. |
| `plugin_failed` | A plugin raised an error or used up its budget; the message is the plugin's. |
| `unavailable` | Something needed is missing or not possible here: tshark, a home folder, a live source without a window, a plugin that has been unloaded. |

Some errors carry `data`: an anchor of a recipe step that did not resolve gives `data.anchor` and `data.reason`; a `recipes.run` that stopped gives the run's report as `data.report`.

## Jobs

A method whose effect is `job` starts work in the background and returns `{"job": "report-3"}` at once. Follow it with `jobs.status`, which gives its state (`running`, `cancelling`, `finished`, `failed` or `cancelled`), how far it has got (`done` of `total`, when it counts) and, once finished, `result`: what the method would have returned had it waited. The same arrives on the bus as `job.started`, `job.progress` and `job.finished`. `jobs.list` lists the last 100 jobs; `jobs.cancel` asks one to stop, and it ends as `cancelled` without a result as soon as it notices.

A recipe step that starts a job waits for it (up to 10 minutes), and later steps can use its result through a step anchor whose path starts `job.`; see [Recipes](recipes.md).

## Versions and stability

`api.version` returns the API's version, `"1.0"`. Within a major version changes only add: new methods, new optional parameters and new result fields, so a client written for 1.0 works with any 1.x. The methods in this reference are stable. Methods plugins register join the table at run time and are listed by `api.describe` as experimental: they change when their plugin does. A recipe records the major version it was made with (`"1.x"`) and warns when it runs under another.

## Methods

172 methods in 45 namespaces. The MCP column says which are listed as tools of their own by `theviewer mcp` (every one is with `--all-tools`; the rest are reached with `api_call`).

| Method | Effect | MCP | Summary |
| --- | --- | --- | --- |
| [`api.version`](#apiversion) | read |  | The API version: 1.0. Changes within a major version only add methods, optional parameters and result fields. |
| [`api.describe`](#apidescribe) | read |  | Every method with its summary, effect, stability and the JSON schemas of its parameters and result. |
| [`documents.list`](#documentslist) | read | core | The open documents, with their ids, names, paths, lengths and versions. |
| [`documents.info`](#documentsinfo) | read |  | One document's id, name, path, length, version and whether it has unsaved edits. |
| [`documents.open`](#documentsopen) | view | core | Open a file by path, or an open document by id, and make it current; a file already open is made current again. In the window, a parent of the document shown is gone back to, closing what was derived from it; that, or opening another file, is refused while what it closes has unsaved edits, unless the person at the window discards them. |
| [`documents.new`](#documentsnew) | view |  | Open a new, empty document and make it current; the window refuses while its document has unsaved edits, unless the person at the window discards them. |
| [`documents.save`](#documentssave) | edit | core | Save a document over its file, or to a path, with every edit made so far. |
| [`documents.derive`](#documentsderive) | view |  | Open bytes of a document (a span, several ranges one after another, or bytes given), or what a transform such as decompress or XOR makes of them, as a document of their own derived from it, and make it current; in the window, Back goes back to the parent. |
| [`documents.export`](#documentsexport) | edit |  | Write a span of a document (or several ranges one after another) to a file, or what decompresses at a span's start; the document is left as it is. |
| [`documents.open_source`](#documentsopen_source) | view |  | Open a file, URL, block device, serial port (serial:PORT@BAUD) or a process's memory region (pid:PID@ADDRESS) as a new document. The window reads a URL, device or region in the background and opens it when it arrives, and pid:PID lists a process's regions in the Live tab; headless, the bytes are read before the call returns. |
| [`bytes.read`](#bytesread) | read | core | Read a span of bytes, as hex by default, or as base64 or text. |
| [`bytes.hexdump`](#byteshexdump) | read | core | A classic hex dump of a span, 16 bytes per line with an ASCII column, at most 1 MiB. |
| [`bytes.write`](#byteswrite) | edit | core | Overwrite bytes in place with new ones, as one undoable step; the document keeps its length. |
| [`bytes.insert`](#bytesinsert) | edit |  | Insert bytes at an offset, as one undoable step; the bytes after it move along. |
| [`bytes.delete`](#bytesdelete) | edit |  | Remove a span of bytes, as one undoable step; the bytes after it move back. |
| [`bytes.replace`](#bytesreplace) | edit | core | Replace a span of bytes with new bytes of any length, as one undoable step. |
| [`bytes.move`](#bytesmove) | edit |  | Cut ranges out and put their bytes, one after another, at an offset counted before the cut, as one undoable step, and select them. |
| [`bits.read`](#bitsread) | read |  | Read a span of bits, most or least significant bit of each byte first, as a string of 0s and 1s and, up to 64 bits, as a number. |
| [`bits.write`](#bitswrite) | edit |  | Overwrite bits from any bit offset, most or least significant bit of each byte first, as one undoable step; the bits around them are kept. |
| [`bits.scan_periods`](#bitsscan_periods) | job |  | Start a search of a span for bit periods (frames that are not a whole number of bytes) and the sync word of the strongest, comparing the bits with themselves at every lag, as a job: the periods and sync words are job.finished's result, and in the window they fill the Bits panel. |
| [`bits.planes`](#bitsplanes) | job |  | Start splitting a span (at most 1 MiB) into its eight bit planes as a job, scoring how much shape each holds with rows of row_width bytes: the scores are job.finished's result, and in the window the planes fill the Bits panel. |
| [`bits.open_plane`](#bitsopen_plane) | view |  | Open one bit plane of a span (at most 1 MiB) as a derived document: bit k of every byte, as a byte of 0 or 255. |
| [`bits.detect_linecode`](#bitsdetect_linecode) | job |  | Start trying Manchester (both conventions), differential Manchester, 8b/10b and packed BCD at every bit alignment of a span (at most 64 KiB) as a job: the decodes, fewest invalid symbols first, and any BCD timestamps are job.finished's result, and in the window they fill the Bits panel. |
| [`bits.decode_linecode`](#bitsdecode_linecode) | view |  | Decode a span (at most 64 KiB) from a line code at a bit offset and open the decoded bytes as a derived document. |
| [`bits.rank_field`](#bitsrank_field) | read |  | Rank what a field of records holds (integers, floats, fixed point, timestamps, enums…) by how plausible its values are across the records. |
| [`bits.find_length_fields`](#bitsfind_length_fields) | job |  | Start a search of a span (at most 256 KiB, one message or a run of records) for numbers that are distances, as a job: length prefixes, tag-length-value chains and offset tables, best first, are job.finished's result, and in the window they fill the Bits panel. |
| [`transform.apply`](#transformapply) | edit | core | Apply an operation (XOR, invert, shift bits, swap byte order, number, compress, decompress and more) to every range of a selection, as one undoable step, and select what it produced. |
| [`transform.preview`](#transformpreview) | read |  | What transform.apply would write into each range of a selection, without changing anything. |
| [`history.undo`](#historyundo) | edit | core | Undo the document's last step, whoever made it, and put the cursor where it was. |
| [`history.redo`](#historyredo) | edit |  | Redo the last step undone, and put the cursor where it was. |
| [`history.transaction`](#historytransaction) | edit |  | Run several calls on one document as one undoable step; when one fails, every change the others made is reversed. |
| [`history.list`](#historylist) | read |  | The session's journal: each edit, view change and job made through the API, by any caller, in order, with its parameters, result, outcome and a description; optionally the recent reads too. Pass back next as since to follow it. |
| [`history.entry`](#historyentry) | read |  | One step of the journal, or one recent read, in full. |
| [`history.session`](#historysession) | read |  | What the journal's session ran with: when it started, the API version, the plugins loaded with their hashes, and each document as first seen, with its size and SHA-256. |
| [`history.inverse`](#historyinverse) | read |  | How a step of the journal would be undone now: the calls that undo it (the document's undo for its last edit, or the inverse of a view change, fold, bookmark, selection or document opened), nothing to undo (a job, a read, a file written), or why it cannot be. |
| [`history.undo_step`](#historyundo_step) | edit |  | Undo one step of the journal through its inverse (see history.inverse), whoever made it, as a step of its own; the step is then shown as undone and left out of recipes and playback. |
| [`history.go_back`](#historygo_back) | edit |  | Go back to a step of the journal (0 for before the first): undo every later step in effect, latest first, or, where one has no inverse, bring the document back to how the session first saw it and run the steps up to it again. The later steps stay in the journal, shown as undone. |
| [`history.save_recipe`](#historysave_recipe) | edit |  | Write the steps in effect (all, or up to a step) to a recipe file, *.theviewer-recipe.json, with the anchors and parameters recorded for its steps, to run on other files. |
| [`history.note`](#historynote) | analysis | core | Write a note in the history where you are now: what you are doing and why, by you, linked to the steps its text cites as #12 and those given; it changes nothing, is never undone or repeated, and is shown beside the steps it links. Returns its step number. |
| [`history.edit_note`](#historyedit_note) | read |  | Change a note's text and the steps it is linked to, in place; the note then says when and by whom it was edited. Only notes can be edited. |
| [`history.delete_note`](#historydelete_note) | read |  | Take a note out of the history; the steps it was linked to no longer list it. Only notes can be deleted. |
| [`history.export_notes`](#historyexport_notes) | read |  | The session's notes as Markdown, in the order written, each with the steps it cites (number, caller and description), returned or written to a path given (which needs leave to edit). |
| [`history.suggest_anchors`](#historysuggest_anchors) | read |  | Anchors that could stand for a step's literals in a recipe: search matches, structure fields and findings at the same offset in its document as it is now, the selection an earlier step set, and earlier steps' values equal to it, those that port to other files first. |
| [`history.make_anchor`](#historymake_anchor) | read |  | Turn the literal at a path of a step's params into an anchor in its derived_from, so a recipe made from it finds the value when it runs; a read it cites becomes a step of the journal. |
| [`history.make_parameter`](#historymake_parameter) | read |  | Turn the literal at a path of a step's params into a named recipe parameter, the person's to supply when the recipe runs, the literal its default. |
| [`history.clear_anchor`](#historyclear_anchor) | read |  | Clear the anchor at a path of a step's params, so a recipe made from it repeats the literal. |
| [`history.recipe`](#historyrecipe) | read |  | A recipe of the journal's successful steps (or those chosen, with the steps they cite), each recorded provenance as an anchor, parameters declared, steps numbered from 1 and the recorded document left out. |
| [`search.find`](#searchfind) | read | core | The next (or previous) occurrence of hex bytes, text, UTF-16 text or an integer from an offset. |
| [`search.find_all`](#searchfind_all) | read | core | Every occurrence of hex bytes, text, UTF-16 text or an integer in the document, a page at a time. |
| [`search.count`](#searchcount) | read |  | How many times hex bytes, text, UTF-16 text or an integer occur in the document, up to a cap. |
| [`numbers.decode`](#numbersdecode) | read | core | Read the bytes at an offset as integers, floats, fixed-point numbers and timestamps of each width and byte order. |
| [`selection.get`](#selectionget) | read |  | What is selected in a document: one range, several ranges or a column of every record. |
| [`selection.set`](#selectionset) | view |  | Select one range, several ranges or a column of every record in a document, or nothing. |
| [`cursor.get`](#cursorget) | read |  | The cursor's offset in a document. |
| [`cursor.set`](#cursorset) | view |  | Move the cursor to an offset, selecting nothing. |
| [`findings.query`](#findingsquery) | read | core | Run the detectors over a span and list what they recognise (signatures, compressed streams, counters, timestamps, text, structures), filtered by category, confidence and producer. |
| [`findings.publish`](#findingspublish) | analysis |  | Publish findings about a document on the bus as the caller's, for the views, Findings and every other tool to show; they replace the caller's earlier ones under the same key. |
| [`findings.retract`](#findingsretract) | analysis |  | Withdraw the findings the caller published under a key. |
| [`structure.parse`](#structureparse) | read | core | Parse the structure starting exactly at an offset (executables, images, archives, captures, ASN.1, filesystems) into a field tree, best match first. |
| [`structure.parsers`](#structureparsers) | read |  | The structure parsers available, built in and from plugins. |
| [`templates.list`](#templateslist) | read |  | The binary templates available: the built-in ones and the user's own. |
| [`templates.apply`](#templatesapply) | analysis | core | Apply a binary template, by name or as source text, at an offset and return its field tree and records; with pin, also show it as the template tool does. |
| [`templates.infer`](#templatesinfer) | analysis |  | Propose a template struct from several example records, from what varies between them; with pin, also apply it at the first record and show it as the template tool does. |
| [`templates.clear`](#templatesclear) | view |  | Withdraw the template pinned over a document: its records are no longer outlined, and it leaves template.applied. |
| [`codecs.list`](#codecslist) | read |  | The codecs available for decoding, built in and from plugins. |
| [`codecs.detect`](#codecsdetect) | read |  | The codecs whose header starts at an offset. |
| [`codecs.decode`](#codecsdecode) | read |  | Decode (decompress) a span with a codec and return the output. |
| [`codecs.probe`](#codecsprobe) | read | core | Try every built-in decompressor at the start of a span, headerless ones included, and list those that decode. |
| [`codecs.open_decoded`](#codecsopen_decoded) | view |  | Decompress the stream starting at an offset, with the first codec that decodes there or the one named, and open what it holds as a document derived from this one; in the window, Back (or opening the parent by id) returns. |
| [`packets.dissect_bytes`](#packetsdissect_bytes) | read | core | Dissect one packet, from a span or from hex bytes, into protocol layers and fields, a summary and its flow. |
| [`packets.detect_frames`](#packetsdetect_frames) | read |  | Find the protocol a set of frames of unknown format is, by trying every frame decoder on them. |
| [`packets.sets.create`](#packetssetscreate) | analysis | core | Take a set of packets from a document: a capture in it, a range cut into fixed records, by a length field, at a pattern or with the protocol framing, or the selection's ranges, with how to decode frames of unknown format; returns the set's id and what was worked out (the capture found, the framing), so the call can be made again exactly. |
| [`packets.sets.remove`](#packetssetsremove) | analysis |  | Forget a packet set: its id stops working and it leaves packets.sets.list. Its document is not changed. |
| [`packets.sets.list`](#packetssetslist) | read |  | The packet sets made, with their ids, documents, sources, packet counts and decoding. |
| [`packets.list`](#packetslist) | read |  | A set's packets the display filter keeps, a page at a time: each one's index, offset, length, summary columns, protocols and addresses. |
| [`packets.dissect`](#packetsdissect) | read | core | Dissect one packet of a set into protocol layers and fields, as the set decodes frames of unknown format. |
| [`packets.decode_as`](#packetsdecode_as) | analysis |  | Choose the protocol a set's frames of unknown format are decoded as, or detection, and a template for frames no protocol reads. |
| [`packets.export_pcap`](#packetsexport_pcap) | analysis |  | A set's packets (those a filter keeps) as a pcap file, returned or written to a path given (which needs leave to edit). |
| [`packets.conversations`](#packetsconversations) | read |  | The conversations in a set (the packets a filter keeps): each pair of endpoints with its transport, packets and bytes each way, and a filter for it. |
| [`packets.follow_stream`](#packetsfollow_stream) | read |  | The payloads of a packet's conversation in order, each with its direction, and the stream as text. |
| [`packets.find_captures`](#packetsfind_captures) | read |  | The captures inside a span of a document (pcap, pcapng, snoop, Network Monitor or ERF, or one of these compressed with gzip), each with its offset, format, link type and packets, for packets.sets.create. |
| [`packets.sets.add_packets`](#packetssetsadd_packets) | view |  | Add ranges of the document to a set as packets of their own, so packets can be gathered one at a time; the set then keeps its packets where they are. |
| [`packets.sets.refresh`](#packetssetsrefresh) | view |  | Find a set's packets again, the way they were found, in another document (the current one by default), which the set then belongs to. |
| [`packets.detect_length_field`](#packetsdetect_length_field) | read |  | Look for a length field that cuts a span into frames, with the protocol analysis's framing detection; returns it as packets.sets.create's length_field, or the best framing found instead. |
| [`packets.endpoints`](#packetsendpoints) | read |  | The addresses in a set (the packets a filter keeps), busiest first, with the packets and bytes each sent and received. |
| [`packets.extract`](#packetsextract) | analysis |  | Some of a set's packets' bytes one after another, returned or written to a path given (which needs leave to edit). |
| [`packets.delete`](#packetsdelete) | edit |  | Remove packets from the document (their whole capture records, so a capture stays readable), as one undoable step. |
| [`packets.fix_checksums`](#packetsfix_checksums) | edit |  | Recompute the IPv4 header, TCP and UDP checksums of some of a set's packets, as one undoable step. |
| [`packets.apply`](#packetsapply) | edit |  | Invert, fill or XOR some of a set's packets, or the same field of each, as one undoable step. |
| [`packets.write_field`](#packetswrite_field) | edit |  | Write a value (a number, or hex bytes as wide as the field) into a field of one packet, as one undoable step. |
| [`packets.columns.apply`](#packetscolumnsapply) | edit |  | Change the same columns (byte offsets) of every packet, or of some, laid out one packet per row: invert, fill, XOR, add, set, number or swap the byte order, as one undoable step. |
| [`packets.columns.delete`](#packetscolumnsdelete) | edit |  | Remove the same columns (byte offsets) from every packet, or from some, as one undoable step; length fields and checksums are not changed. |
| [`packets.columns.read`](#packetscolumnsread) | read |  | The same columns (byte offsets) of every packet, or of some, as hex lines or CSV. |
| [`packets.tshark_decode`](#packetstshark_decode) | job |  | Have Wireshark's tshark decode some of a set's packets (run locally with -n) as a background job; the protocols it named are the job's result, and in the window its layers merge into the Packets panel's. |
| [`analysis.overview`](#analysisoverview) | read | core | Map the whole document: a summary of what it is, its regions with offsets, likely record widths and confident findings. |
| [`analysis.overview_job`](#analysisoverview_job) | job | core | Start analysis.overview as a background job and return its id at once; the report arrives as job.finished's result and from jobs.status, for large files and clients that should not wait. |
| [`analysis.statistics`](#analysisstatistics) | read |  | Measure a span: entropy, chi-square, serial correlation, printable, zero and high-byte fractions, distinct values and a verdict. |
| [`analysis.segments`](#analysissegments) | read | core | Split the document into regions of one kind (text, tables, code, compressed, random, padding) and group them into types. |
| [`analysis.compressibility`](#analysiscompressibility) | read |  | Compress a span with several codecs and report the ratios, with a verdict: encrypted or random, already compressed, lossy media or structured. |
| [`analysis.text_encoding`](#analysistext_encoding) | read |  | Identify the character encoding of a span of text, with previews and the likely language. |
| [`analysis.processor`](#analysisprocessor) | read |  | Test whether a span is machine code, and for which processor, by disassembling samples for each architecture. |
| [`analysis.period_scan`](#analysisperiod_scan) | job |  | Start a scan of a window of bytes for repeating periods (record widths) as a background job; the periods found, best first, are job.finished's result, and in the window they fill the structure chart and are published on record_width.estimated. |
| [`reference.lookup`](#referencelookup) | read | core | The reference notes on a format or protocol, by id, finding id, layer name, port (udp/67) or number (port, IP protocol or EtherType): layout, field meanings and specifications. |
| [`reference.search`](#referencesearch) | read |  | Reference entries whose notes mention every word of a query, or that a port or number names. |
| [`reference.rfc`](#referencerfc) | read |  | The plain text of an RFC, or of one of its sections, fetched from the RFC Editor once and then kept in ~/.cache/theviewer/rfc. |
| [`reference.reload`](#referencereload) | view |  | Read the user's own reference notes again, and say which files could not be read. |
| [`reference.pick_alternative`](#referencepick_alternative) | view |  | Take another entry in place of a format guessed from a port, EtherType or IP protocol number, for the payload at an offset; the Reference panel shows it, and the entry's notes are returned. |
| [`events.facts`](#eventsfacts) | read |  | What the tools have learnt about a document and keep: the latest fact per topic, producer and key, by topic, producer or the bytes they cover, each marked stale when the document changed under it. |
| [`events.poll`](#eventspoll) | read |  | The messages (facts and events) published after a cursor, oldest first, optionally of some topics only; pass back next to keep up. |
| [`jobs.list`](#jobslist) | read |  | The background jobs tools and callers started (the last 100): what each does, who started it, whether it is running, how far it has got and how it ended. |
| [`jobs.status`](#jobsstatus) | read | core | One job's state, progress and outcome, and once it has finished, the result of a job a method started. |
| [`jobs.cancel`](#jobscancel) | analysis |  | Ask a running job to stop; it ends as cancelled, without a result, as soon as it notices. |
| [`statistics.analyse`](#statisticsanalyse) | job |  | Start the Statistics tool's measure of a span (at most 64 MiB) as a job: the ent randomness tests with a verdict, the byte histogram, entropy and compressibility along the span and the most repeated byte sequences are job.finished's result, and in the window they fill the Statistics tab. |
| [`strings.find`](#stringsfind) | job |  | Start the Strings tool's search of a span (at most 64 MiB) for runs of text at least min_chars long in the encodings chosen, as a job: the strings found (at most 200000), each with its offset, length, encoding, text and what it looks like (a URL, a path, a key…), are job.finished's result, and in the window they fill the Strings tab. |
| [`xor.recover_keys`](#xorrecover_keys) | read |  | Recover single-byte and repeating XOR keys for a span (at most 1 MiB) by letter frequency, index of coincidence and the key showing through zero padding, best first, with a preview of each decode and the likely key lengths; transform.apply with {"op": "xor"} applies one. |
| [`checksums.digests`](#checksumsdigests) | read |  | The digests of a span (at most 64 MiB): CRC-32, Adler-32, MD5, SHA-1, SHA-256, the 8- and 16-bit sums and the XOR of every byte. |
| [`checksums.find_stored`](#checksumsfind_stored) | read |  | Find a CRC, Adler or sum stored in a span (at most 64 MiB) that covers part of it, testing header and trailer fields, and the fields at the boundaries given, against the bytes before, after and around them. |
| [`checksums.solve_crc`](#checksumssolve_crc) | job |  | Start the CRC solver on records of equal length that each carry a stored CRC, as a job: every polynomial, init, xorout and reflection that reproduces all the stored values (like reveng), with the closest catalogue algorithm, is job.finished's result, and in the window it fills the CRC solver. |
| [`diff.run`](#diffrun) | job |  | Start a comparison of a document with another file as a job: the regions replaced, only in the document and only in the other file (inserted, deleted and changed, not just flipped bytes), with the bytes equal and changed, are job.finished's result, and in the window they fill the Diff tab and are outlined on the views. |
| [`disasm.set_arch`](#disasmset_arch) | view |  | Choose the architecture the Disassembly tab decodes as, or auto (the executable header's, else a guess from the bytes); headless there is no listing to change, and the choice is only returned. |
| [`crypto.scan_constants`](#cryptoscan_constants) | job |  | Start a scan of the whole document (an edited one's first 256 MiB) for well-known constants of crypto and compression code (AES S-boxes, hash initial values, CRC tables, deflate tables, Blowfish, DES, ChaCha, TEA, curve primes, Base64 alphabets) as a job: the matches are job.finished's result, and in the window they fill Crypto constants. |
| [`crypto.repeated_blocks`](#cryptorepeated_blocks) | job |  | Start a search of a span (at most 16 MiB) for random-looking 8- and 16-byte blocks that repeat, the mark of ECB-mode encryption, as a job: the verdict, the best block size and alignment, the most repeated blocks and the repeats along the span are job.finished's result, and in the window they fill the Crypto panel. |
| [`crypto.find_keys`](#cryptofind_keys) | job |  | Start a search of a span (the whole document by default, at most 64 MiB) for PEM blocks, DER certificates and keys, OpenSSH keys and random-looking runs that could be raw symmetric keys, as a job: what was found is job.finished's result, and in the window it fills the Crypto panel. |
| [`crypto.attack`](#cryptoattack) | job |  | Start attacks on simple ciphers over a span (at most 1 MiB): rolling XOR, XOR with the previous byte, ADD/SUB with a constant or repeating key, bit rotation, XOR combined with ADD and, with a crib, crib dragging, as a job: the decodes that look most like text or structured data are job.finished's result, and in the window they fill the Crypto panel. |
| [`compare.variation`](#comparevariation) | job |  | Start comparing a document with other files byte position by byte position, each from its own start offset, as a job: the regions that are constant, vary (and how many values) or move one way through the files like a counter are job.finished's result, and in the window they fill Compare. |
| [`compare.correlate`](#comparecorrelate) | job |  | Start a search of a document and other files for fields whose values follow a number known for each file (a temperature, a setting), as a job: the fields, best fit first, with the fitted line, are job.finished's result, and in the window they fill Compare. |
| [`compare.timeline`](#comparetimeline) | job |  | Start building the change timeline of the recording of a live source or watched file, as a job: where and how often it changed, snapshot by snapshot, is job.finished's result, and the window fills Compare with it; only the window records, so headless there is none. |
| [`dotplot.compute`](#dotplotcompute) | job |  | Start comparing every block of a span (at most 64 MiB) with every other, by shared 6-byte substrings or by byte histograms, as a job: the grid of similarities (repeated content shows as lines parallel to the diagonal) is job.finished's result, and in the window it fills the Dot plot. |
| [`images.find`](#imagesfind) | job |  | Start a search of a span (at most 64 MiB) for uncompressed images, trying 1-bit, 8-bit grey, RGB565, RGB and RGBA at widths from 16 to 2048 pixels, as a job: the regions whose rows resemble each other, best first, are job.finished's result (view.set_shape shows one), and in the window they fill Images. |
| [`trigrams.count`](#trigramscount) | job |  | Start counting every run of three bytes in a span (sampled beyond 16 MiB) as a job, labelled by segments, by the report's regions or not at all, with a part of it to pick out: the points of the trigram cube, most common first, and the region types they belong to are job.finished's result, and in the window they fill Trigrams. |
| [`firmware.identify`](#firmwareidentify) | job |  | Start identifying the processor of a span of headerless code (at most 64 MiB) as a job, disassembling samples as every supported architecture and ranking them by typical instructions, idioms and branch targets: the ranking is job.finished's result, and in the window it fills Firmware (analysis.processor is the quick read). |
| [`firmware.find_load_address`](#firmwarefind_load_address) | job |  | Start a search for the address a firmware image is loaded at (the address of offset 0, over the document's first 64 MiB) as a job: the bases that make most stored pointers land on the start of a string, as rbasefind does, are job.finished's result, and in the window they fill Firmware. |
| [`firmware.vector_tables`](#firmwarevector_tables) | job |  | Start a search of a span (the whole document by default, at most 64 MiB) for ARM Cortex-M vector tables as a job: each table's stack pointer, handlers and the flash base they imply are job.finished's result, and in the window they fill Firmware. |
| [`forensics.find_filesystems`](#forensicsfind_filesystems) | job |  | Start a search of the document (its first 256 MiB) for SquashFS, CramFS, JFFS2 and UBI images as a job: each image found, with its files, is job.finished's result, and in the window they fill Forensics. |
| [`forensics.open_entry`](#forensicsopen_entry) | view |  | Open one file (or volume) of the filesystem image at an offset of the document as a derived document, by its path in the image. |
| [`forensics.classify_blocks`](#forensicsclassify_blocks) | job |  | Start labelling every block of the document (its first 256 MiB) as padding, text, markup, machine code, compressed, random, raw image, PCM audio or table data as a job: the runs of one class, with the reason for each, are job.finished's result, and in the window they fill Forensics. |
| [`unpack.run`](#unpackrun) | job |  | Start extracting the archives and compressed streams in the document (its first 256 MiB) recursively, like binwalk -e, as a job: the tree of what was found, each node with its kind, size and where its bytes came from, is job.finished's result, and in the window it fills the Unpacked tab and the Size map. |
| [`unpack.open`](#unpackopen) | view |  | Open one node of the unpacked tree (by its path of child indices, as unpack.run gave it) as a derived document. |
| [`unpack.read`](#unpackread) | read |  | Read the bytes of one node of the unpacked tree, by its path of child indices, as hex by default, or as base64 or text. |
| [`unpack.save`](#unpacksave) | edit |  | Write the bytes of one node of the unpacked tree (by its path of child indices, as node) to a file; the document is left as it is. |
| [`characterise.profile_selection`](#characteriseprofile_selection) | job |  | Start compressing a sample of a span with deflate, bzip2, LZ4, zstd and an order-1 entropy coder as a job: the ratios and the verdict they give (encrypted or random, already compressed, lossy media or structured) are job.finished's result, and in the window they fill Characterise (analysis.compressibility is the quick read). |
| [`characterise.profile_file`](#characteriseprofile_file) | job |  | Start profiling the compressibility of the whole document as a job, overall and for up to 64 segments sampled along it: the verdicts are job.finished's result, and in the window they fill Characterise with a strip of verdicts. |
| [`characterise.streams`](#characterisestreams) | job |  | Start a search of the document (its first 256 MiB) for raw MP3/MP2 and AAC frames, H.264 and H.265 Annex B video and 16-bit PCM audio without a container as a job: the runs found are job.finished's result, and in the window they fill Characterise. |
| [`columns.profile`](#columnsprofile) | read |  | Profile the byte columns of fixed-size records from an offset (each column's kind, entropy and values) and group them into likely fields; in the window the Columns tool shows it. |
| [`protocol.analyse`](#protocolanalyse) | job |  | Start finding how a span is framed into messages (sync words, delimiters, length prefixes, fixed size) and what their header fields are, as a background job; the framing, messages and fields are job.finished's result and are published on frames.defined and fields.guessed. |
| [`protocol.choose_framing`](#protocolchoose_framing) | view |  | Split a span into messages with a framing (one protocol.analyse offered, or any other) and work out their fields again; the messages are published on frames.defined, and in the window the Protocol tool shows them. |
| [`report.run`](#reportrun) | job |  | Start explaining the whole document in plain words and mapping its regions, as a background job; the report and regions are job.finished's result and are published on regions.mapped, and in the window the Report tool and the file map show them. |
| [`structure_map.segment`](#structure_mapsegment) | job |  | Start splitting the document into stretches of uniform character, grouped into types (text, tables, compressed, padding…), as a background job; the segments are job.finished's result, and in the window the Structure map shows them. |
| [`structure_map.find_similar`](#structure_mapfind_similar) | job |  | Start finding every part of the document whose statistics resemble a span, as a background job; the regions at or above the threshold are job.finished's result, and in the window the Structure map lists them. |
| [`structure_map.tracks`](#structure_maptracks) | job |  | Start measuring entropy, compressibility, byte kinds and the local record width along the document, as a background job; the tracks are job.finished's result, and in the window the Structure map draws them. |
| [`learn.format`](#learnformat) | job |  | Start learning what the document and sample files of the same format share (a magic number, header fields) as a background job; a signature for the catalogue and a template draft are job.finished's result, and in the window the Learn tool shows them. |
| [`learn.save_catalogue`](#learnsave_catalogue) | edit |  | Write a learned signature to a new file in the user's catalogue folder, never over another, and load it. |
| [`learn.fuzzy_compare`](#learnfuzzy_compare) | job |  | Start hashing files with ssdeep and scoring how like the document each is, 0 to 100, as a background job; the scores are job.finished's result, and in the window the Learn tool lists them. |
| [`learn.fragments`](#learnfragments) | job |  | Start finding the blocks of the document that also occur in a file, as a background job; the shared fragments are job.finished's result, and in the window the Learn tool lists them. |
| [`alignment.run`](#alignmentrun) | job |  | Start clustering messages into probable types and aligning each type byte by byte, marking columns as constant, counter, length or variable, as a background job; the messages are a span cut into rows, or else those the protocol analysis published on frames.defined. The clusters are job.finished's result, and in the window the Alignment tool shows them. |
| [`view.get_shape`](#viewget_shape) | read |  | The shape a document's bytes are drawn in: the pixel format, pixels per row, the offset of the first pixel, a bit shift and the bytes skipped after each row. |
| [`view.set_shape`](#viewset_shape) | view |  | Change the shape a document's bytes are drawn in (the pixel format, pixels per row, the first pixel's offset and bit, the padding after each row); what is not given stays as it is. |
| [`view.fold`](#viewfold) | view |  | Skip ranges of a document in its views (the raster and the hex dump) without deleting them; a marker shows where each was. |
| [`view.unfold`](#viewunfold) | view |  | Show skipped bytes again: the skipped range starting at an offset, or all of them. |
| [`bookmarks.list`](#bookmarkslist) | read |  | A document's bookmarks, in offset order. |
| [`bookmarks.add`](#bookmarksadd) | view |  | Bookmark a byte or a span of a document with a name, replacing a bookmark at the same offset; the window keeps them beside the file. |
| [`bookmarks.remove`](#bookmarksremove) | view |  | Remove the bookmark at an offset. |
| [`plugins.reload`](#pluginsreload) | view |  | Load the Lua plugins again from disk, so the detectors, parsers, codecs and methods they register are the ones in their files now; the command line and MCP load them once, when they start. |
| [`sources.watch`](#sourceswatch) | view |  | Watch the window's file for changes on disk, reloading it and marking what changed, or stop watching it. |
| [`sources.record`](#sourcesrecord) | view |  | Keep every version of a document as it changes (the window's file or capture as it changes on disk, or after each edit), or stop keeping them. |
| [`sources.stop`](#sourcesstop) | view |  | Stop the window's serial capture. |
| [`sources.view_version`](#sourcesview_version) | view |  | Open a recorded version of a document as a document derived from it; the window marks what changed from the version before. |
| [`recipes.list`](#recipeslist) | read |  | The recipes saved in ~/.config/theviewer/recipes/: each one's name, description, steps and the parameters it asks for. |
| [`recipes.describe`](#recipesdescribe) | read |  | One recipe in full, by name or path, with what to know before running it here: another API version, a plugin missing or changed, a method this build lacks, or mistakes in its anchors. |
| [`recipes.save`](#recipessave) | read |  | Save a recipe in ~/.config/theviewer/recipes/, given whole or made from steps of this session's journal, to run later on other files. |
| [`recipes.preview`](#recipespreview) | read |  | What a recipe would do to a document, without changing anything: each step described with its anchors resolved on this file, and where the run would stop. |
| [`recipes.run`](#recipesrun) | edit |  | Run a recipe on a document, each step called as recipe:NAME with its anchors resolved on this file, waiting for the jobs steps start; its edits undo as one step, and the first failure stops it with which step and why. |

Each method's full JSON schemas are in `api.describe` (`theviewer api --describe`).

### api.version

The API version: 1.0. Changes within a major version only add methods, optional parameters and result fields.

**Effect:** `read` · **MCP tool:** `api_version`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `version` | string | yes | Major and minor version, such as "1.0". |

### api.describe

Every method with its summary, effect, stability and the JSON schemas of its parameters and result.

**Effect:** `read` · **MCP tool:** `api_describe`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `methods` | array of MethodDescription | yes |  |
| `topics` | array of TopicDescription | yes | The bus's topics, which `events.facts` and `events.poll` read. |
| `version` | string | yes |  |

### documents.list

The open documents, with their ids, names, paths, lengths and versions.

**Effect:** `read` · **MCP tool:** `documents_list`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `documents` | array of DocumentInfo | yes |  |

### documents.info

One document's id, name, path, length, version and whether it has unsaved edits.

**Effect:** `read` · **MCP tool:** `documents_info`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### documents.open

Open a file by path, or an open document by id, and make it current; a file already open is made current again. In the window, a parent of the document shown is gone back to, closing what was derived from it; that, or opening another file, is refused while what it closes has unsaved edits, unless the person at the window discards them.

**Effect:** `view` · **MCP tool:** `documents_open`, listed by default

**History:** Journalled as a step; undone by changing back which document is current; not repeated: what it opened is open already.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `discard_unsaved` | boolean | no | In the window, close documents with unsaved edits, losing them, as File › Open and Back do; only the person at the window may. |
| `doc` | string | no | Id of an open document to make current, such as a parent the window derived the document shown from. |
| `path` | string | no | Path of the file to open. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### documents.new

Open a new, empty document and make it current; the window refuses while its document has unsaved edits, unless the person at the window discards them.

**Effect:** `view` · **MCP tool:** `documents_new`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back which document is current; not repeated: what it opened is open already.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `discard_unsaved` | boolean | no | In the window, close documents with unsaved edits, losing them, as File › New does; only the person at the window may. |
| `name` | string | no | What to call the document ("untitled" by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### documents.save

Save a document over its file, or to a path, with every edit made so far.

**Effect:** `edit` · **MCP tool:** `documents_save`, listed by default

**History:** Journalled as a step; nothing to undo: it wrote a file, which stays as written; not repeated: the file stays as written. Writes a file, so it needs leave to edit.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `path` | string | no | Where to save; over the document's own file when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### documents.derive

Open bytes of a document (a span, several ranges one after another, or bytes given), or what a transform such as decompress or XOR makes of them, as a document of their own derived from it, and make it current; in the window, Back goes back to the parent.

**Effect:** `view` · **MCP tool:** `documents_derive`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back which document is current; not repeated: what it opened is open already.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `data` | string | no | The bytes themselves, written as `encoding` says, when they are not in the document as they are (a reassembled stream, say). |
| `doc` | string | no | Document id, path or "current" (the default): the parent. |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How `data` is written: hex (the default), base64 or text. |
| `len` | integer | no | Bytes to open from `start`; to the end of the document when omitted. |
| `name` | string | no | What to call the new document; the parent's name and the span when omitted. |
| `ranges` | array of pair | no | Several spans as [start, len], opened one after another (a selection of several ranges, or several packets). |
| `start` | integer | no | Offset of the first byte to open. |
| `transform` | Operation | no | An operation to apply to each span first, such as {"op": "decompress"} or {"op": "xor", "key": "5a"}. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### documents.export

Write a span of a document (or several ranges one after another) to a file, or what decompresses at a span's start; the document is left as it is.

**Effect:** `edit` · **MCP tool:** `documents_export`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: it wrote a file, which stays as written; not repeated: the file stays as written. Writes a file, so it needs leave to edit.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `decompress` | boolean | no | Write what the first codec that decodes at `start` makes of the bytes, instead of the bytes. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes to write, or to read the compressed stream from (at most 64 MiB); to the end of the document when omitted. |
| `path` | string | yes | The file to write. |
| `ranges` | array of pair | no | Several spans as [start, len], written one after another (a selection of several ranges); in place of `start` and `len`. |
| `start` | integer | no | Offset of the first byte to write, or of the compressed stream; give this or `ranges`. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `decompressed` | ExportedStream | no | The codec and stream, when the bytes were decompressed. |
| `path` | string | yes | The file written. |
| `written` | integer | yes | Bytes written. |

### documents.open_source

Open a file, URL, block device, serial port (serial:PORT@BAUD) or a process's memory region (pid:PID@ADDRESS) as a new document. The window reads a URL, device or region in the background and opens it when it arrives, and pid:PID lists a process's regions in the Live tab; headless, the bytes are read before the call returns.

**Effect:** `view` · **MCP tool:** `documents_open_source`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back which document is current; not repeated: what it opened is open already.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `uri` | string | yes | A path, an http(s) URL, a block device (/dev/disk2), serial:PORT@BAUD, pid:PID or pid:PID@ADDRESS. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `document` | DocumentInfo | no | The document opened, when it opened before the call returned. |
| `reading` | boolean | yes | Whether the window is still reading the bytes, and opens them when they arrive. |

### bytes.read

Read a span of bytes, as hex by default, or as base64 or text.

**Effect:** `read` · **MCP tool:** `bytes_read`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How to write the bytes: hex (the default), base64 or text. |
| `len` | integer | no | Bytes to read, at most 16 MiB; to the end of the document when omitted. |
| `start` | integer | yes | Offset of the first byte. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `data` | string | yes | The bytes, written as `encoding` says. |
| `doc` | string | yes | Id of the document read. |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | yes | How `data` is written. |
| `len` | integer | yes | Bytes read. |
| `start` | integer | yes | Offset of the first byte. |

### bytes.hexdump

A classic hex dump of a span, 16 bytes per line with an ASCII column, at most 1 MiB.

**Effect:** `read` · **MCP tool:** `bytes_hexdump`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes to show, at most 1 MiB; to the end of the document when omitted. |
| `start` | integer | yes | Offset of the first byte. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document read. |
| `dump` | string | yes | Lines of an offset, 16 hex bytes and their ASCII. |
| `len` | integer | yes | Bytes shown. |
| `start` | integer | yes | Offset of the first byte. |

### bytes.write

Overwrite bytes in place with new ones, as one undoable step; the document keeps its length.

**Effect:** `edit` · **MCP tool:** `bytes_write`, listed by default

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `coalesce` | boolean | no | Join the caller's previous step when that step wrote or inserted just the one byte at `start`, so a byte typed as two hex digits undoes as one step. |
| `data` | string | yes | The new bytes, written as `encoding` says; they must fit inside the document. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How `data` is written: hex (the default), base64 or text. |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `start` | integer | yes | Offset of the first byte to overwrite. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### bytes.insert

Insert bytes at an offset, as one undoable step; the bytes after it move along.

**Effect:** `edit` · **MCP tool:** `bytes_insert`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Offset to insert at; the document's length appends. |
| `coalesce` | boolean | no | Join the caller's previous step when that step wrote or inserted just the one byte at `at`. |
| `data` | string | yes | The bytes to insert, written as `encoding` says. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How `data` is written: hex (the default), base64 or text. |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### bytes.delete

Remove a span of bytes, as one undoable step; the bytes after it move back.

**Effect:** `edit` · **MCP tool:** `bytes_delete`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `len` | integer | yes | Bytes to remove. |
| `start` | integer | yes | Offset of the first byte to remove. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### bytes.replace

Replace a span of bytes with new bytes of any length, as one undoable step.

**Effect:** `edit` · **MCP tool:** `bytes_replace`, listed by default

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `data` | string | yes | The bytes to put in their place, written as `encoding` says. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How `data` is written: hex (the default), base64 or text. |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `len` | integer | yes | Bytes to take out; the new bytes may be longer or shorter. |
| `start` | integer | yes | Offset of the first byte to replace. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### bytes.move

Cut ranges out and put their bytes, one after another, at an offset counted before the cut, as one undoable step, and select them.

**Effect:** `edit` · **MCP tool:** `bytes_move`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `ranges` | array of pair | yes | The ranges to move, as [start, len]; their bytes land one after another, in document order. |
| `to` | integer | yes | Where the bytes land, as an offset counted before they are cut out; an offset inside a range lands them where that range began. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### bits.read

Read a span of bits, most or least significant bit of each byte first, as a string of 0s and 1s and, up to 64 bits, as a number.

**Effect:** `read` · **MCP tool:** `bits_read`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bit_len` | integer | yes | Bits to read, at most 1048576. |
| `bit_start` | integer | yes | Bit offset of the first bit: byte offset × 8 plus the bit within the byte, in `order`. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `order` | `"msb"` \| `"lsb"` | no | Which bit of each byte comes first: "msb" (the default) or "lsb". |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bit_len` | integer | yes | Bits read. |
| `bit_start` | integer | yes | Bit offset of the first bit. |
| `bits` | string | yes | The bits as "0" and "1", first bit first. |
| `doc` | string | yes | Id of the document read. |
| `order` | `"msb"` \| `"lsb"` | yes | Which bit of each byte came first. |
| `value` | NumberValue | no | The bits as an unsigned integer, first bit most significant, when there are at most 64. |

### bits.write

Overwrite bits from any bit offset, most or least significant bit of each byte first, as one undoable step; the bits around them are kept.

**Effect:** `edit` · **MCP tool:** `bits_write`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bit_start` | integer | yes | Bit offset of the first bit: byte offset × 8 plus the bit within the byte, in `order`. |
| `bits` | string | yes | The new bits as "0" and "1", first bit first; spaces and underscores are ignored. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `order` | `"msb"` \| `"lsb"` | no | Which bit of each byte comes first: "msb" (the default) or "lsb". |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### bits.scan_periods

Start a search of a span for bit periods (frames that are not a whole number of bytes) and the sync word of the strongest, comparing the bits with themselves at every lag, as a job: the periods and sync words are job.finished's result, and in the window they fill the Bits panel.

**Effect:** `job` · **MCP tool:** `bits_scan_periods`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes searched, at most 256 KiB and a quarter of max_period; as many as that from start when omitted. |
| `max_period` | integer | no | Longest period looked for, 8 to 8192 bits (1024 by default). |
| `order` | `"msb"` \| `"lsb"` | no | Which bit of each byte comes first: "msb" (the default) or "lsb". |
| `start` | integer | no | First offset searched (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### bits.planes

Start splitting a span (at most 1 MiB) into its eight bit planes as a job, scoring how much shape each holds with rows of row_width bytes: the scores are job.finished's result, and in the window the planes fill the Bits panel.

**Effect:** `job` · **MCP tool:** `bits_planes`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes split, at most 1 MiB; to the end of the document (or 1 MiB) when omitted. |
| `row_width` | integer | yes | Bytes per row, 1 to 1024, for scoring each plane by its left and upper neighbours. |
| `start` | integer | no | First offset split (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### bits.open_plane

Open one bit plane of a span (at most 1 MiB) as a derived document: bit k of every byte, as a byte of 0 or 255.

**Effect:** `view` · **MCP tool:** `bits_open_plane`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back which document is current; not repeated: what it opened is open already.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bit` | integer | yes | Which bit, 0 (least significant) to 7. |
| `doc` | string | no | Document id, path or "current" (the default): the parent. |
| `len` | integer | no | Bytes, at most 1 MiB; to the end of the document (or 1 MiB) when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### bits.detect_linecode

Start trying Manchester (both conventions), differential Manchester, 8b/10b and packed BCD at every bit alignment of a span (at most 64 KiB) as a job: the decodes, fewest invalid symbols first, and any BCD timestamps are job.finished's result, and in the window they fill the Bits panel.

**Effect:** `job` · **MCP tool:** `bits_detect_linecode`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes decoded, at most 64 KiB; to the end of the document (or 64 KiB) when omitted. |
| `order` | `"msb"` \| `"lsb"` | no | Which bit of each byte comes first: "msb" (the default) or "lsb". |
| `start` | integer | no | First offset decoded (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### bits.decode_linecode

Decode a span (at most 64 KiB) from a line code at a bit offset and open the decoded bytes as a derived document.

**Effect:** `view` · **MCP tool:** `bits_decode_linecode`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back which document is current; not repeated: what it opened is open already.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bit_offset` | integer | no | Bit to start at, 0 to 63 (0 by default). |
| `code` | `"differential_manchester"` \| `"nrzi"` \| `"8b10b"` \| `"gray_byte"` \| `"gray_word"` \| `"packed_bcd"` \| `"manchester_ieee"` \| `"manchester_thomas"` | yes | A line code, as the Bits tool decodes it. |
| `doc` | string | no | Document id, path or "current" (the default): the parent. |
| `len` | integer | no | Bytes decoded, at most 64 KiB; to the end of the document (or 64 KiB) when omitted. |
| `order` | `"msb"` \| `"lsb"` | no | Which bit of each byte comes first: "msb" (the default) or "lsb". |
| `start` | integer | no | First offset decoded (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `document` | DocumentInfo | yes | The derived document the decode was opened as. |
| `errors` | integer | yes |  |
| `symbols` | integer | yes | Symbols read, and the invalid ones among them. |

### bits.rank_field

Rank what a field of records holds (integers, floats, fixed point, timestamps, enums…) by how plausible its values are across the records.

**Effect:** `read` · **MCP tool:** `bits_rank_field`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `offset` | integer | yes | Offset of the field within each record. |
| `origin` | integer | yes | Document offset of the first record. |
| `stride` | integer | yes | Bytes per record. |
| `width` | integer | yes | Bytes in the field: 1, 2, 4 or 8. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `readings` | array of FieldReading | yes | The readings, most plausible first. |
| `records` | integer | yes | Records read (at most 4096). |

### bits.find_length_fields

Start a search of a span (at most 256 KiB, one message or a run of records) for numbers that are distances, as a job: length prefixes, tag-length-value chains and offset tables, best first, are job.finished's result, and in the window they fill the Bits panel.

**Effect:** `job` · **MCP tool:** `bits_find_length_fields`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the region, at most 256 KiB; to the end of the document (or 256 KiB) when omitted. |
| `start` | integer | no | First offset of the region (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### transform.apply

Apply an operation (XOR, invert, shift bits, swap byte order, number, compress, decompress and more) to every range of a selection, as one undoable step, and select what it produced.

**Effect:** `edit` · **MCP tool:** `transform_apply`, listed by default

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `operation` | Operation | yes | What to do to each selected range, such as {"op": "xor", "key": "5a"}. |
| `selection` | Selection | no | What to change: a range, several ranges or a column of every record. The document's selection when omitted, or the byte at the cursor when nothing is selected. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### transform.preview

What transform.apply would write into each range of a selection, without changing anything.

**Effect:** `read` · **MCP tool:** `transform_preview`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How to write the new bytes: hex (the default), base64 or text. |
| `operation` | Operation | yes | What to do to each selected range. |
| `selection` | Selection | no | What to change; the document's selection, or the byte at the cursor, when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document read. |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | yes | How each range's `data` is written. |
| `ranges` | array of PreviewRange | yes | Each selected range with its new bytes. |

### history.undo

Undo the document's last step, whoever made it, and put the cursor where it was.

**Effect:** `edit` · **MCP tool:** `history_undo`, listed by default

**History:** Journalled as a step; a move along the timeline (the document's undo), never repeated.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Where its earliest change was. |
| `doc` | string | yes | Id of the document. |
| `label` | string | no | The step undone or redone, when it was named. |
| `len` | integer | yes | The document's length afterwards. |
| `version` | integer | yes | The document's version afterwards. |

### history.redo

Redo the last step undone, and put the cursor where it was.

**Effect:** `edit` · **MCP tool:** `history_redo`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; a move along the timeline (the document's redo), never repeated.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Where its earliest change was. |
| `doc` | string | yes | Id of the document. |
| `label` | string | no | The step undone or redone, when it was named. |
| `len` | integer | yes | The document's length afterwards. |
| `version` | integer | yes | The document's version afterwards. |

### history.transaction

Run several calls on one document as one undoable step; when one fails, every change the others made is reversed.

**Effect:** `edit` · **MCP tool:** `history_transaction`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `calls` | array of TransactionCall | yes | The calls, run in order: edits, selection changes and reads. |
| `doc` | string | no | Document id, path or "current" (the default); every call must be about this document. |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `label` | string | no | What the step is called in the undo history; "N changes" when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `label` | string | yes | What the step is called in the undo history. |
| `len` | integer | yes | The document's length afterwards. |
| `results` | array of any | yes | Each call's result, in order. |
| `version` | integer | yes | The document's version afterwards. |

### history.list

The session's journal: each edit, view change and job made through the API, by any caller, in order, with its parameters, result, outcome and a description; optionally the recent reads too. Pass back next as since to follow it.

**Effect:** `read` · **MCP tool:** `history_list`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `include_reads` | boolean | no | Also list the recent reads still held, whose effect is `read`. |
| `limit` | integer | no | Most entries to return (100 when omitted). |
| `since` | integer | no | List the steps after this one (a `next` from before); from the first when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `dropped` | Dropped | yes | The oldest entries the journal no longer holds. |
| `entries` | array of JournalEntry | yes | The entries, in step order. |
| `last_step` | integer | no | The last step recorded or read in the session. |
| `next` | integer | no | The last step listed, to pass as `since` for the entries after it; none when this is all there is now. |
| `revision` | integer | yes | Changes whenever anything recorded changes (a read promoted into the journal takes its own, earlier, step number). |
| `undone` | array of UndoneBy | no | The steps listed that are undone, and by which step (an undo, an undo of the step itself, or going back to an earlier step). |

### history.entry

One step of the journal, or one recent read, in full.

**Effect:** `read` · **MCP tool:** `history_entry`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `step` | integer | yes | The step's number. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | string | yes | When the call was made, UTC, such as "2026-10-06T14:02:11Z". |
| `before` | any | no | What the step replaced, for its inverse (see [`undo::state_before`]): the view shape, bookmarks or selection as they were before it ran (before the first call it merged), when its method reverses a change. |
| `caller` | string | yes | Who called: `panel`, `plugin:sync.lua`, `ask`, `mcp:claude-code`, `cli` or `recipe:Telemetry frames`. |
| `derived_from` | object | no | Where parameters' values came from, by parameter path: the anchors a recipe made from this step uses in place of the literals. |
| `description` | string | yes | What the call did in plain words, the same text the confirmation window shows: "XOR 128 selected bytes with 5A". Empty for a read not promoted into the journal. |
| `doc` | string | no | The document the call was about: the one its `doc` named, or the current one. |
| `effect` | `"read"` \| `"edit"` \| `"view"` \| `"job"` \| `"analysis"` | yes | What calling a method does. |
| `merged` | integer | no | How many earlier calls of the same setter this one replaced. |
| `method` | string | yes | The method called, such as `packets.sets.create`. |
| `note` | Note | no | For a note (`history.note`): its text, the steps it links and when it was last edited. |
| `notes` | array of NoteOn | no | The notes linked to this step, oldest first, as `history.list` and `history.entry` give it: the reasoning beside the action. |
| `outcome` | Outcome | yes | How a recorded call ended. |
| `params` | any | yes | The parameters as given (or, when `params_summarised`, a summary). |
| `params_summarised` | boolean | no | Whether `params` were too large to keep and are a summary: such a step cannot be repeated exactly. |
| `result` | any | no | What the call returned (or, when `result_summarised`, a summary that keeps the ids of what it made); none when it failed. |
| `result_summarised` | boolean | no |  |
| `step` | integer | yes | The step's number, unique in the session and increasing; reads share the sequence, so the steps listed may skip numbers. |
| `version_after` | integer | no | Its version after (none when the call closed it). |
| `version_before` | integer | no | That document's version before the call. |

### history.session

What the journal's session ran with: when it started, the API version, the plugins loaded with their hashes, and each document as first seen, with its size and SHA-256.

**Effect:** `read` · **MCP tool:** `history_session`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `api_version` | string | yes | The API version, such as "1.0". |
| `documents` | array of RecordedDocument | yes | Each document a call was about, as it was the first time. |
| `plugins` | array of RecordedPlugin | yes | The plugin scripts loaded, as last loaded. |
| `started_at` | string | yes | When the session started, UTC. |

### history.inverse

How a step of the journal would be undone now: the calls that undo it (the document's undo for its last edit, or the inverse of a view change, fold, bookmark, selection or document opened), nothing to undo (a job, a read, a file written), or why it cannot be.

**Effect:** `read` · **MCP tool:** `history_inverse`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `step` | integer | yes | The step's number. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `inverse` | Inverse | yes | How it would be undone now. |
| `status` | StepStatus | yes | Where it stands: active, failed, undone (by a step) or a move along the history. |
| `step` | integer | yes |  |

### history.undo_step

Undo one step of the journal through its inverse (see history.inverse), whoever made it, as a step of its own; the step is then shown as undone and left out of recipes and playback.

**Effect:** `edit` · **MCP tool:** `history_undo_step`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; a move along the timeline (undoing one step), never repeated.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `step` | integer | yes | The step's number. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `calls` | array of InverseCall | yes | The calls that undid it, in order; none when it left nothing to undo. |
| `method` | string | yes | Its method. |
| `note` | string | no | Why nothing was called, when nothing was. |
| `step` | integer | yes | The step undone. |

### history.go_back

Go back to a step of the journal (0 for before the first): undo every later step in effect, latest first, or, where one has no inverse, bring the document back to how the session first saw it and run the steps up to it again. The later steps stay in the journal, shown as undone.

**Effect:** `edit` · **MCP tool:** `history_go_back`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; a move along the timeline (going back), never repeated.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `step` | integer | yes | The step to go back to: every later one is undone. 0 goes back to before the first step. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | The document brought back and replayed, when it was replayed. |
| `kept` | array of KeptStep | no | The later steps that changed what they changed for good (no inverse), and stay as they are. |
| `label` | string | no | What the one undo step the steps run again made on the document is called, when they edited it: one undo takes them all back. |
| `replayed` | RunReport | no | What running the steps again did, when they were. |
| `step` | integer | yes | The step gone back to: everything after it is undone. 0 is before the first step. |
| `undone` | array of integer | yes | The later steps undone, latest first. |
| `way` | `"undone"` \| `"replayed"` | yes | How going back reached the step. |

### history.save_recipe

Write the steps in effect (all, or up to a step) to a recipe file, *.theviewer-recipe.json, with the anchors and parameters recorded for its steps, to run on other files.

**Effect:** `edit` · **MCP tool:** `history_save_recipe`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: it wrote a file, which stays as written; not repeated: the file stays as written. Writes a file, so it needs leave to edit.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `description` | string | no | What it is for. |
| `name` | string | yes | What to call it. |
| `path` | string | yes | Where to write it; by convention its name ends in .theviewer-recipe.json. |
| `through` | integer | no | The last step to take; every step in effect when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes |  |
| `path` | string | yes |  |
| `steps` | array of integer | yes | The numbers of the steps it holds, in order. |

### history.note

Write a note in the history where you are now: what you are doing and why, by you, linked to the steps its text cites as #12 and those given; it changes nothing, is never undone or repeated, and is shown beside the steps it links. Returns its step number.

**Effect:** `analysis` · **MCP tool:** `history_note`, listed by default

**History:** Journalled as a note where it is written: it changes nothing, so it is never undone, repeated, or undone by going back past it.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `steps` | array of integer | no | More steps the note is about, beside those its text cites. |
| `text` | string | yes | What you are doing and why, at most 4 KiB; `#12` in it cites step 12 and links the note to it. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `step` | integer | yes | The note's own step number. |
| `steps` | array of integer | yes | The steps it is linked to, in step order. |

### history.edit_note

Change a note's text and the steps it is linked to, in place; the note then says when and by whom it was edited. Only notes can be edited.

**Effect:** `read` · **MCP tool:** `history_edit_note`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `step` | integer | yes | The note's step number. |
| `steps` | array of integer | no | The steps it is about beside those its text cites; those given when it was written (or last edited) when omitted, so `[]` links it only to the steps its text cites. |
| `text` | string | yes | What it says now; `#12` cites step 12. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `note` | Note | yes | The note as it is now. |
| `step` | integer | yes |  |

### history.delete_note

Take a note out of the history; the steps it was linked to no longer list it. Only notes can be deleted.

**Effect:** `read` · **MCP tool:** `history_delete_note`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `step` | integer | yes | The note's step number. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `note` | Note | yes | The note as it was. |
| `step` | integer | yes |  |

### history.export_notes

The session's notes as Markdown, in the order written, each with the steps it cites (number, caller and description), returned or written to a path given (which needs leave to edit).

**Effect:** `read` · **MCP tool:** `history_export_notes`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes. Writes a file when `path` is given, which then needs leave to edit.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `path` | string | no | Where to write the Markdown, such as notes.md; it is returned when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `markdown` | string | no | The Markdown, when no path was given. |
| `notes` | integer | yes | How many notes it holds. |
| `path` | string | no | The file written, when a path was given. |

### history.suggest_anchors

Anchors that could stand for a step's literals in a recipe: search matches, structure fields and findings at the same offset in its document as it is now, the selection an earlier step set, and earlier steps' values equal to it, those that port to other files first.

**Effect:** `read` · **MCP tool:** `history_suggest_anchors`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `path` | string | no | Only the literal at this path of its params, such as `start`; every integer when omitted. |
| `step` | integer | yes | The step whose literals to anchor. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `literals` | array of LiteralSuggestions | yes | Each literal, with the anchors that give the same value. |

### history.make_anchor

Turn the literal at a path of a step's params into an anchor in its derived_from, so a recipe made from it finds the value when it runs; a read it cites becomes a step of the journal.

**Effect:** `read` · **MCP tool:** `history_make_anchor`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `anchor` | Anchor | yes | The anchor, written bare: `{"find": {"hex": "7EA5"}, "nth": 0}`, `{"step": 12, "path": "result.at"}`, `{"param": "key"}`… |
| `path` | string | yes | The literal's path in the step's params, such as `start` or `selection.range[0]`. |
| `step` | integer | yes | The step whose literal to anchor. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `anchor` | Anchor | no | The anchor now at the path; none when it was cleared. |
| `path` | string | yes | The parameter's path, such as `selection.range[0]`. |
| `replaced` | Anchor | no | The anchor it replaced, if any. |
| `step` | integer | yes |  |
| `value` | any | yes | The literal the step was given there. |

### history.make_parameter

Turn the literal at a path of a step's params into a named recipe parameter, the person's to supply when the recipe runs, the literal its default.

**Effect:** `read` · **MCP tool:** `history_make_parameter`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `description` | string | no | What to supply, for the person running the recipe. |
| `name` | string | yes | The parameter's name: letters, digits, spaces, '_' or '-'. |
| `path` | string | yes | The literal's path in the step's params. |
| `step` | integer | yes | The step whose literal to make a parameter. |
| `type` | `"string"` \| `"integer"` \| `"number"` \| `"boolean"` | no | "string", "integer", "number" or "boolean"; the literal's type when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `anchor` | Anchor | no | The anchor now at the path; none when it was cleared. |
| `parameter` | RecipeParameter | yes | The parameter as a recipe declares it. |
| `path` | string | yes | The parameter's path, such as `selection.range[0]`. |
| `replaced` | Anchor | no | The anchor it replaced, if any. |
| `step` | integer | yes |  |
| `value` | any | yes | The literal the step was given there. |

### history.clear_anchor

Clear the anchor at a path of a step's params, so a recipe made from it repeats the literal.

**Effect:** `read` · **MCP tool:** `history_clear_anchor`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `path` | string | yes | The parameter's path in the step's params. |
| `step` | integer | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `anchor` | Anchor | no | The anchor now at the path; none when it was cleared. |
| `path` | string | yes | The parameter's path, such as `selection.range[0]`. |
| `replaced` | Anchor | no | The anchor it replaced, if any. |
| `step` | integer | yes |  |
| `value` | any | yes | The literal the step was given there. |

### history.recipe

A recipe of the journal's successful steps (or those chosen, with the steps they cite), each recorded provenance as an anchor, parameters declared, steps numbered from 1 and the recorded document left out.

**Effect:** `read` · **MCP tool:** `history_recipe`, through `api_call`, or with `--all-tools`

**History:** Not journalled: it reads the journal, or edits where its values came from or its notes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `description` | string | no | What it does, in the person's words. |
| `name` | string | yes | The recipe's name. |
| `steps` | array of integer | no | The steps to make it of (the earlier steps they cite are added); every step of the journal when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `api_version` | string | yes | The API version the steps were recorded against, by major version: "1.x". |
| `description` | string | no |  |
| `name` | string | yes |  |
| `parameters` | object | no | Values the person supplies when running it, by name, which `{"param": name}` anchors stand for. |
| `plugins` | array of RecordedPlugin | no | The plugins loaded when it was recorded; running it warns when one is missing or has changed. |
| `recipe` | integer | yes | The recipe format, 1. |
| `recorded_on` | FileIdentity | no | The file it was recorded on, to say when another is the same. |
| `steps` | array of RecipeStep | yes |  |

### search.find

The next (or previous) occurrence of hex bytes, text, UTF-16 text or an integer from an offset.

**Effect:** `read` · **MCP tool:** `search_find`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `backwards` | boolean | no | Search towards the start of the document. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `from` | integer | no | Offset to search from: the first match at or after it, or before it when searching backwards. |
| `little_endian` | boolean | no | For integers: store them little-endian (the default) or big-endian. |
| `mode` | `"hex"` \| `"text"` \| `"utf16"` \| `"integer"` | no | How to read the query: "hex", "text" (the default), "utf16" (little-endian) or "integer". |
| `query` | string | yes | Hex bytes such as "89 50 4E 47", text, or a decimal or 0x hex integer. |
| `wrap` | boolean | no | When nothing is found before the end (or, backwards, the start), search on from the other end. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | no | Offset of the match, or nothing when there is none. |

### search.find_all

Every occurrence of hex bytes, text, UTF-16 text or an integer in the document, a page at a time.

**Effect:** `read` · **MCP tool:** `search_find_all`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `limit` | integer | no | Most matches to return (100 by default). |
| `little_endian` | boolean | no | For integers: store them little-endian (the default) or big-endian. |
| `mode` | `"hex"` \| `"text"` \| `"utf16"` \| `"integer"` | no | How to read the query: "hex", "text" (the default), "utf16" (little-endian) or "integer". |
| `next` | string | no | The `next` cursor of the previous page. |
| `query` | string | yes | Hex bytes such as "89 50 4E 47", text, or a decimal or 0x hex integer. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `matches` | array of integer | yes | Offsets of the matches, in document order; matches may overlap. |
| `next` | string | no | Pass back as `next` for more matches; absent after the last. |

### search.count

How many times hex bytes, text, UTF-16 text or an integer occur in the document, up to a cap.

**Effect:** `read` · **MCP tool:** `search_count`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `cap` | integer | no | Stop counting here (100000 by default), so huge files stay quick. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `little_endian` | boolean | no | For integers: store them little-endian (the default) or big-endian. |
| `mode` | `"hex"` \| `"text"` \| `"utf16"` \| `"integer"` | no | How to read the query: "hex", "text" (the default), "utf16" (little-endian) or "integer". |
| `query` | string | yes | Hex bytes such as "89 50 4E 47", text, or a decimal or 0x hex integer. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capped` | boolean | yes | Whether counting stopped at the cap. |
| `count` | integer | yes |  |

### numbers.decode

Read the bytes at an offset as integers, floats, fixed-point numbers and timestamps of each width and byte order.

**Effect:** `read` · **MCP tool:** `numbers_decode`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Offset of the number's first byte. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `kind` | `"unsigned"` \| `"signed"` \| `"float"` \| `"unix_seconds"` \| `"unix_millis"` \| `"fixed_point"` \| `"file_time"` \| `"gps_seconds"` \| `"hfs_seconds"` \| `"dos_date_time"` | no | Only this kind of number, such as "unsigned", "float" or "unix_seconds". |
| `little_endian` | boolean | no | Only this byte order. |
| `width` | integer | no | Only this width in bytes: 1, 2, 4 or 8. Every width that fits when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Offset of the number's first byte. |
| `decodings` | array of Decoding | yes | Every interpretation asked for that fits before the end of the document. |

### selection.get

What is selected in a document: one range, several ranges or a column of every record.

**Effect:** `read` · **MCP tool:** `selection_get`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `ranges` | array of pair | yes | Every selected range as [start, len], in document order. |
| `selection` | Selection | no | The selection as the app holds it, or nothing when no bytes are selected. |
| `total_bytes` | integer | yes | Bytes selected in all. |

### selection.set

Select one range, several ranges or a column of every record in a document, or nothing.

**Effect:** `view` · **MCP tool:** `selection_set`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; repeated calls by the same caller on the same document merge into one; undone by changing back the selection and cursor; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `cursor` | integer | no | Where the cursor goes: the start or end of one of the selected ranges, which is then the range Shift extends from its other end (a column's cursor is at its end); the end of the last range when omitted. With nothing selected, any offset; the cursor stays when omitted. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `selection` | Selection | no | What to select: {"range": [start, len]}, {"ranges": [[start, len], …]} or {"columns": {…}}; null or omitted selects nothing. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `ranges` | array of pair | yes | Every selected range as [start, len], in document order. |
| `selection` | Selection | no | The selection as the app holds it, or nothing when no bytes are selected. |
| `total_bytes` | integer | yes | Bytes selected in all. |

### cursor.get

The cursor's offset in a document.

**Effect:** `read` · **MCP tool:** `cursor_get`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `offset` | integer | yes | Offset of the byte at the cursor. |

### cursor.set

Move the cursor to an offset, selecting nothing.

**Effect:** `view` · **MCP tool:** `cursor_set`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; repeated calls by the same caller on the same document merge into one; undone by changing back the selection and cursor; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `offset` | integer | yes | Offset to put the cursor at; the document's length is just past the last byte. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `offset` | integer | yes | Offset of the byte at the cursor. |

### findings.query

Run the detectors over a span and list what they recognise (signatures, compressed streams, counters, timestamps, text, structures), filtered by category, confidence and producer.

**Effect:** `read` · **MCP tool:** `findings_query`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `categories` | array of `"signature"` \| `"executable"` \| `"image"` \| `"archive"` \| `"document"` \| `"filesystem"` \| `"compressed"` \| `"encoding"` \| `"protocol"` \| `"structure"` \| `"timestamp"` \| `"counter"` \| `"offset_table"` \| `"float_array"` \| `"text"` \| `"high_entropy"` \| `"padding"` \| `"custom"` | no | Only findings of these categories, such as "compressed" or "timestamp". |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes scanned, at most 16 MiB; to the end of the document when omitted. |
| `limit` | integer | no | Most findings to return (100 by default). |
| `min_confidence` | number | no | Only findings at least this confident, 0 to 1 (0.5 by default). |
| `next` | string | no | The `next` cursor of the previous page. |
| `producers` | array of string | no | Only findings from these producers (a finding's `source`, such as "catalogue"). |
| `start` | integer | no | First offset scanned (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `findings` | array of Finding | yes | Findings in document order, overlaps resolved as the views show them. |
| `next` | string | no | Pass back as `next` for more findings; absent after the last. |

### findings.publish

Publish findings about a document on the bus as the caller's, for the views, Findings and every other tool to show; they replace the caller's earlier ones under the same key.

**Effect:** `analysis` · **MCP tool:** `findings_publish`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back the findings its caller published under that key; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `findings` | array of Finding | yes | The findings, in document offsets; they replace those the caller published before under the same key. |
| `key` | string | no | Tells apart several sets of findings one caller keeps (empty by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `findings` | integer | yes | Findings published (none for a retraction). |
| `producer` | string | yes | Who the findings are published as, such as "mcp:claude-code". |

### findings.retract

Withdraw the findings the caller published under a key.

**Effect:** `analysis` · **MCP tool:** `findings_retract`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back the findings its caller published under that key; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `key` | string | no | The key the findings were published under (empty by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `findings` | integer | yes | Findings published (none for a retraction). |
| `producer` | string | yes | Who the findings are published as, such as "mcp:claude-code". |

### structure.parse

Parse the structure starting exactly at an offset (executables, images, archives, captures, ASN.1, filesystems) into a field tree, best match first.

**Effect:** `read` · **MCP tool:** `structure_parse`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Offset where the structure starts. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `parser` | string | no | Only this parser, by id (see structure.parsers); every parser when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `structures` | array of Finding | yes | Every parse of the bytes, most confident first, each with its field tree in document offsets. Empty when no parser recognises them. |

### structure.parsers

The structure parsers available, built in and from plugins.

**Effect:** `read` · **MCP tool:** `structure_parsers`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `parsers` | array of ParserInfo | yes |  |

### templates.list

The binary templates available: the built-in ones and the user's own.

**Effect:** `read` · **MCP tool:** `templates_list`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `templates` | array of TemplateInfo | yes |  |

### templates.apply

Apply a binary template, by name or as source text, at an offset and return its field tree and records; with pin, also show it as the template tool does.

**Effect:** `analysis` · **MCP tool:** `templates_apply`, listed by default

**History:** Journalled as a step; undone by changing back the template pinned over the document (when the call pins or clears one); repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | no | Offset the template's root starts at (0 by default). |
| `doc` | string | no | Document id, path or "current" (the default). |
| `limit` | integer | no | Most records to return (100 by default). |
| `name` | string | no | A template from templates.list. |
| `next` | string | no | The `next` cursor of the previous page of records. |
| `pin` | boolean | no | Pin the parse as the template tool does: its records are outlined in the views and its structure published, in place of the last template pinned. |
| `source` | string | no | Template source text, as written in the template language. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `columns` | array of string | yes | Column names across all records, in order of first appearance. |
| `next` | string | no | Pass back as `next` for more records; absent after the last. |
| `records` | array of RecordResult | yes | One page of records. |
| `structure` | Finding | yes | The whole parse, with its field tree in document offsets. |
| `total_records` | integer | yes | Records in all. |
| `warnings` | array of string | yes | Problems met while applying, each with its template line. |

### templates.infer

Propose a template struct from several example records, from what varies between them; with pin, also apply it at the first record and show it as the template tool does.

**Effect:** `analysis` · **MCP tool:** `templates_infer`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back the template pinned over the document (when the call pins or clears one); repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | yes | Bytes of example records, several of them. |
| `pin` | boolean | no | Also apply the struct at `start` and pin it, as templates.apply with pin does. |
| `record_len` | integer | no | Bytes per record; guessed from what repeats when omitted. |
| `start` | integer | yes | First offset of the example records. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `record_len` | integer | yes |  |
| `records` | integer | yes | Example records it was inferred from. |
| `source` | string | yes | The struct proposed, as template source for templates.apply. |

### templates.clear

Withdraw the template pinned over a document: its records are no longer outlined, and it leaves template.applied.

**Effect:** `view` · **MCP tool:** `templates_clear`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back the template pinned over the document (when the call pins or clears one); repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `cleared` | boolean | yes | Whether a template was pinned there. |
| `doc` | string | yes | Id of the document. |

### codecs.list

The codecs available for decoding, built in and from plugins.

**Effect:** `read` · **MCP tool:** `codecs_list`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `codecs` | array of CodecInfo | yes |  |

### codecs.detect

The codecs whose header starts at an offset.

**Effect:** `read` · **MCP tool:** `codecs_detect`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Offset where the encoded data would start. |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `codecs` | array of CodecInfo | yes |  |

### codecs.decode

Decode (decompress) a span with a codec and return the output.

**Effect:** `read` · **MCP tool:** `codecs_decode`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `codec` | string | yes | Codec id from codecs.list, such as "zlib" or "gzip". |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How to write the output: hex (the default), base64 or text. |
| `len` | integer | no | Bytes of input, at most 16 MiB; to the end of the document when omitted. |
| `max_output` | integer | no | Most bytes of output, at most 16 MiB (the default). |
| `start` | integer | yes | Offset of the encoded data. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `codec` | string | yes |  |
| `complete` | boolean | yes | Whether the data ended cleanly. |
| `consumed` | integer | yes | Input bytes the encoded data occupied. |
| `consumed_exact` | boolean | yes | Whether `consumed` is exact rather than a buffered estimate. |
| `data` | string | yes | The output, written as `encoding` says. |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | yes | How bytes are written in JSON. |
| `output_len` | integer | yes |  |
| `truncated` | boolean | yes | Whether the output was cut at `max_output`. |

### codecs.probe

Try every built-in decompressor at the start of a span, headerless ones included, and list those that decode.

**Effect:** `read` · **MCP tool:** `codecs_probe`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes of input, at most 16 MiB; to the end of the document when omitted. |
| `max_output` | integer | no | Most bytes of output each decoder may produce, at most 16 MiB (the default). |
| `start` | integer | yes | Offset where compressed data might start. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `streams` | array of ProbedStream | yes | Decoders that read the data, headed ones first. |

### codecs.open_decoded

Decompress the stream starting at an offset, with the first codec that decodes there or the one named, and open what it holds as a document derived from this one; in the window, Back (or opening the parent by id) returns.

**Effect:** `view` · **MCP tool:** `codecs_open_decoded`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back which document is current; not repeated: what it opened is open already.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `codec` | `"zlib"` \| `"gzip"` \| `"deflate"` \| `"bzip2"` \| `"xz"` \| `"lzma"` \| `"zstd"` \| `"lz4"` | no | The codec to decode with; the first that decodes there when omitted. |
| `doc` | string | no | Document id, path or "current" (the default): the parent. |
| `start` | integer | yes | Offset where the compressed stream starts. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `codec` | `"zlib"` \| `"gzip"` \| `"deflate"` \| `"bzip2"` \| `"xz"` \| `"lzma"` \| `"zstd"` \| `"lz4"` | yes | The codec that decoded the stream. |
| `complete` | boolean | yes | Whether the stream ended cleanly. |
| `consumed` | integer | yes | Input bytes the stream occupied. |
| `document` | DocumentInfo | yes | The document opened, now current. |
| `truncated` | boolean | yes | Whether the output was cut at 64 MiB. |

### packets.dissect_bytes

Dissect one packet, from a span or from hex bytes, into protocol layers and fields, a summary and its flow.

**Effect:** `read` · **MCP tool:** `packets_dissect_bytes`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes` | string | no | The packet's bytes instead of a span, written as `encoding` says. |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | For frames of unknown format: the protocol to decode them as, such as "dns" or "modbus_tcp". |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How `bytes` is written: hex (the default), base64 or text. |
| `len` | integer | no | Bytes in the packet; to the end of the document when omitted. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | What the first byte is, such as "ethernet" or "raw_ip"; "unknown" (the default) reads an IP header if one is there. |
| `start` | integer | no | Offset of the packet's first byte. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `ether_type` | integer | no | The EtherType after the Ethernet header and any VLAN tags. |
| `flow` | Flow | no | Addresses and ports, for IP packets. |
| `layers` | array of Layer | yes | Protocol layers, outermost first; offsets are relative to the packet's first byte. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | yes | The link type used, after detection. |
| `notes` | array of string | yes | Problems met, such as truncation or a bad checksum. |
| `payload` | pair | no | The transport payload as [offset, len] within the packet. |
| `protocols` | array of string | yes | Lower-case names of every layer, as the packet filter uses them. |
| `summary` | Summary | yes | The packet list's columns. |

### packets.detect_frames

Find the protocol a set of frames of unknown format is, by trying every frame decoder on them.

**Effect:** `read` · **MCP tool:** `packets_detect_frames`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `frames` | array of FrameSpan | yes | The frames, at most 16 MiB in all; a sample of them is tried. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `detection` | FrameDetection | no | The protocol nearly every frame reads as in full, or nothing when none clearly does. |

### packets.sets.create

Take a set of packets from a document: a capture in it, a range cut into fixed records, by a length field, at a pattern or with the protocol framing, or the selection's ranges, with how to decode frames of unknown format; returns the set's id and what was worked out (the capture found, the framing), so the call can be made again exactly.

**Effect:** `analysis` · **MCP tool:** `packets_sets_create`, listed by default

**History:** Journalled as a step; undone by `packets.sets.remove` on what it made, while no later step uses it; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol frames of unknown format are decoded as; detected from a sample of them when omitted (unless `detect` is false). |
| `detect` | boolean | no | Whether to detect the protocol of frames of unknown format when `decode_as` is not given (true by default). |
| `doc` | string | no | Document id, path or "current" (the default). |
| `framing` | Framing | no | For `protocol_framing`: how the range is cut into messages; found by the protocol analysis when omitted. |
| `from` | `"capture"` \| `"split_fixed"` \| `"length_field"` \| `"pattern"` \| `"selection"` \| `"protocol_framing"` | yes | Where the packets come from. |
| `gunzip` | boolean | no | For `capture`: the capture at `start` is compressed with gzip. It is opened decompressed as a document of its own, derived from this one, and the set is taken from there. |
| `len` | integer | no | Bytes in the range; to the end of the document when omitted. |
| `length_field` | LengthFieldSpec | no | For `length_field`: where each frame's length is and what it counts. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | What every packet's first byte is, such as "ethernet" or "raw_ip"; each packet's own (its capture's, or frames of unknown format) when omitted. |
| `pattern` | string | no | For `pattern`: hex bytes with ?? for any byte (`AA 55 ?? 01`), or "text" in double quotes. |
| `pattern_mode` | `"starts_packet"` \| `"ends_packet"` \| `"separates"` | no | For `pattern`: where the pattern goes (it starts each packet by default). |
| `ranges` | array of pair | no | For `selection`: the ranges, each `[start, len]`; the document's selection when omitted. |
| `record_len` | integer | no | For `split_fixed`: bytes per record. |
| `start` | integer | no | Start of the range to split, or a capture's header (the first capture found when omitted); 0 by default. |
| `template` | string | no | Binary template source applied to each frame no protocol reads. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capped` | boolean | yes | Whether the source had more packets than a set holds. |
| `count` | integer | yes | Packets in the set. |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol chosen for frames of unknown format. |
| `description` | string | yes | How the packets were found. |
| `detect` | boolean | yes |  |
| `doc` | string | yes | The document its packets are in. |
| `framing` | Framing | no | The framing that cut the messages, for `protocol_framing`. |
| `from` | `"capture"` \| `"split_fixed"` \| `"length_field"` \| `"pattern"` \| `"selection"` \| `"protocol_framing"` | yes | Where a set's packets come from. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | The link every packet is read as, when one was chosen. |
| `name` | string | yes | Such as "pcap capture at 0x40". |
| `notes` | array of string | no | What the person should know about how the set was taken, such as a decompressed capture cut short. |
| `ranges` | array of pair | yes | Where the packets were taken from, as [start, len], once worked out (a capture found, the selection's ranges). |
| `set` | string | yes | The set's id, such as "set-1", for the other packet methods. |
| `template` | boolean | yes | Whether a template decodes frames no protocol reads. |
| `template_name` | string | no | The template's name when it was chosen by name, or "protocol" for the one the protocol analysis suggested. |

### packets.sets.remove

Forget a packet set: its id stops working and it leaves packets.sets.list. Its document is not changed.

**Effect:** `analysis` · **MCP tool:** `packets_sets_remove`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; it has no inverse, so going back past it runs the session's steps again; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `set` | string | yes | The set's id, from packets.sets.create. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `set` | string | yes |  |

### packets.sets.list

The packet sets made, with their ids, documents, sources, packet counts and decoding.

**Effect:** `read` · **MCP tool:** `packets_sets_list`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `sets` | array of SetInfo | yes |  |

### packets.list

A set's packets the display filter keeps, a page at a time: each one's index, offset, length, summary columns, protocols and addresses.

**Effect:** `read` · **MCP tool:** `packets_list`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `filter` | string | no | A display filter, as the Packets panel takes: protocol names, addresses, ports, `len > 60`, Wireshark field names and more. |
| `limit` | integer | no | Most packets to return (100 by default). |
| `next` | string | no | The `next` cursor of the previous page. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `detected` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol frames of unknown format were detected as, if they were. |
| `next` | string | no | Pass back as `next` for more; absent after the last. |
| `packets` | array of PacketEntry | yes |  |
| `set` | string | yes |  |
| `total` | integer | yes | Packets the filter keeps. |

### packets.dissect

Dissect one packet of a set into protocol layers and fields, as the set decodes frames of unknown format.

**Effect:** `read` · **MCP tool:** `packets_dissect`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `index` | integer | yes | The packet's index in the set. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `dissection` | DissectionResult | yes | Everything learned from one packet. |
| `index` | integer | yes |  |
| `len` | integer | yes |  |
| `offset` | integer | yes | Document offset of the packet's first byte; layer and field offsets count from it. |

### packets.decode_as

Choose the protocol a set's frames of unknown format are decoded as, or detection, and a template for frames no protocol reads.

**Effect:** `analysis` · **MCP tool:** `packets_decode_as`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back how the packet set decodes; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `detect` | boolean | no | Whether to detect the protocol when none is given (true by default). |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | What every packet's first byte is, such as "ethernet"; null for each packet's own; omitted, the set's link stays as it is. |
| `protocol` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol frames of unknown format are decoded as; omitted, they are detected (unless `detect` is false). |
| `set` | string | yes |  |
| `template` | string | no | Template source for frames no protocol reads, or "protocol" for the template the protocol analysis suggested for the document; omitted (with no template_name), the set's template is dropped. |
| `template_name` | string | no | A built-in or saved template, by name, for frames no protocol reads. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capped` | boolean | yes | Whether the source had more packets than a set holds. |
| `count` | integer | yes | Packets in the set. |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol chosen for frames of unknown format. |
| `description` | string | yes | How the packets were found. |
| `detect` | boolean | yes |  |
| `doc` | string | yes | The document its packets are in. |
| `framing` | Framing | no | The framing that cut the messages, for `protocol_framing`. |
| `from` | `"capture"` \| `"split_fixed"` \| `"length_field"` \| `"pattern"` \| `"selection"` \| `"protocol_framing"` | yes | Where a set's packets come from. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | The link every packet is read as, when one was chosen. |
| `name` | string | yes | Such as "pcap capture at 0x40". |
| `notes` | array of string | no | What the person should know about how the set was taken, such as a decompressed capture cut short. |
| `ranges` | array of pair | yes | Where the packets were taken from, as [start, len], once worked out (a capture found, the selection's ranges). |
| `set` | string | yes | The set's id, such as "set-1", for the other packet methods. |
| `template` | boolean | yes | Whether a template decodes frames no protocol reads. |
| `template_name` | string | no | The template's name when it was chosen by name, or "protocol" for the one the protocol analysis suggested. |

### packets.export_pcap

A set's packets (those a filter keeps) as a pcap file, returned or written to a path given (which needs leave to edit).

**Effect:** `analysis` · **MCP tool:** `packets_export_pcap`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: it wrote a file, which stays as written; not repeated: the file stays as written. Writes a file when `path` is given, which then needs leave to edit.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How the returned file is written: base64 (the default) or hex. |
| `filter` | string | no | Only the packets this display filter keeps. |
| `indices` | array of integer | no | Only these packets, by their index in the set (those of them the filter keeps, when one is given too). |
| `path` | string | no | Write the pcap file here instead of returning it; needs leave to edit, as writing a file does. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `count` | integer | yes | Packets written. |
| `data` | string | no | The file, when no path was given. |
| `len` | integer | yes | Bytes in the pcap file. |
| `path` | string | no | Where it was written, when a path was given. |

### packets.conversations

The conversations in a set (the packets a filter keeps): each pair of endpoints with its transport, packets and bytes each way, and a filter for it.

**Effect:** `read` · **MCP tool:** `packets_conversations`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `filter` | string | no | Only the packets this display filter keeps. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `conversations` | array of ConversationEntry | yes |  |

### packets.follow_stream

The payloads of a packet's conversation in order, each with its direction, and the stream as text.

**Effect:** `read` · **MCP tool:** `packets_follow_stream`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `index` | integer | yes | The packet's index in the set. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `conversation` | ConversationEntry | no | The conversation followed; absent when the packet has no addresses and ports, and so nothing to follow. |
| `parts` | array of StreamPart | yes | The payloads in order, each with who sent it. |
| `retransmissions` | integer | yes | TCP segments sent again and left out. |
| `text` | string | yes | The whole stream as text, each direction's turns marked. |
| `truncated` | boolean | yes | Whether the stream was longer than is kept. |

### packets.find_captures

The captures inside a span of a document (pcap, pcapng, snoop, Network Monitor or ERF, or one of these compressed with gzip), each with its offset, format, link type and packets, for packets.sets.create.

**Effect:** `read` · **MCP tool:** `packets_find_captures`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes looked in; to the end of the document when omitted, at most 128 MiB. |
| `start` | integer | no | First offset looked in (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `captures` | array of CaptureEntry | yes |  |

### packets.sets.add_packets

Add ranges of the document to a set as packets of their own, so packets can be gathered one at a time; the set then keeps its packets where they are.

**Effect:** `view` · **MCP tool:** `packets_sets_add_packets`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; it has no inverse, so going back past it runs the session's steps again; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `ranges` | array of pair | yes | The ranges to add, each `[start, len]`, one packet each. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capped` | boolean | yes | Whether the source had more packets than a set holds. |
| `count` | integer | yes | Packets in the set. |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol chosen for frames of unknown format. |
| `description` | string | yes | How the packets were found. |
| `detect` | boolean | yes |  |
| `doc` | string | yes | The document its packets are in. |
| `framing` | Framing | no | The framing that cut the messages, for `protocol_framing`. |
| `from` | `"capture"` \| `"split_fixed"` \| `"length_field"` \| `"pattern"` \| `"selection"` \| `"protocol_framing"` | yes | Where a set's packets come from. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | The link every packet is read as, when one was chosen. |
| `name` | string | yes | Such as "pcap capture at 0x40". |
| `notes` | array of string | no | What the person should know about how the set was taken, such as a decompressed capture cut short. |
| `ranges` | array of pair | yes | Where the packets were taken from, as [start, len], once worked out (a capture found, the selection's ranges). |
| `set` | string | yes | The set's id, such as "set-1", for the other packet methods. |
| `template` | boolean | yes | Whether a template decodes frames no protocol reads. |
| `template_name` | string | no | The template's name when it was chosen by name, or "protocol" for the one the protocol analysis suggested. |

### packets.sets.refresh

Find a set's packets again, the way they were found, in another document (the current one by default), which the set then belongs to.

**Effect:** `view` · **MCP tool:** `packets_sets_refresh`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; it has no inverse, so going back past it runs the session's steps again; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | The document to find the packets in: id, path or "current" (the default). |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capped` | boolean | yes | Whether the source had more packets than a set holds. |
| `count` | integer | yes | Packets in the set. |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol chosen for frames of unknown format. |
| `description` | string | yes | How the packets were found. |
| `detect` | boolean | yes |  |
| `doc` | string | yes | The document its packets are in. |
| `framing` | Framing | no | The framing that cut the messages, for `protocol_framing`. |
| `from` | `"capture"` \| `"split_fixed"` \| `"length_field"` \| `"pattern"` \| `"selection"` \| `"protocol_framing"` | yes | Where a set's packets come from. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | The link every packet is read as, when one was chosen. |
| `name` | string | yes | Such as "pcap capture at 0x40". |
| `notes` | array of string | no | What the person should know about how the set was taken, such as a decompressed capture cut short. |
| `ranges` | array of pair | yes | Where the packets were taken from, as [start, len], once worked out (a capture found, the selection's ranges). |
| `set` | string | yes | The set's id, such as "set-1", for the other packet methods. |
| `template` | boolean | yes | Whether a template decodes frames no protocol reads. |
| `template_name` | string | no | The template's name when it was chosen by name, or "protocol" for the one the protocol analysis suggested. |

### packets.detect_length_field

Look for a length field that cuts a span into frames, with the protocol analysis's framing detection; returns it as packets.sets.create's length_field, or the best framing found instead.

**Effect:** `read` · **MCP tool:** `packets_detect_length_field`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the span; to the end of the document when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `best_framing` | string | no | When no length field was found, the best framing found instead. |
| `coverage` | number | yes | Share of the span those frames cover, 0 to 1. |
| `description` | string | no | The field in words, such as "u16 big-endian length at +1". |
| `frames` | integer | yes | Frames the framing that found it cuts. |
| `length_field` | LengthFieldSpec | no | The length field, as packets.sets.create's length_field; absent when none was found. |

### packets.endpoints

The addresses in a set (the packets a filter keeps), busiest first, with the packets and bytes each sent and received.

**Effect:** `read` · **MCP tool:** `packets_endpoints`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `filter` | string | no | Only the packets this display filter keeps. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `endpoints` | array of EndpointEntry | yes |  |

### packets.extract

Some of a set's packets' bytes one after another, returned or written to a path given (which needs leave to edit).

**Effect:** `analysis` · **MCP tool:** `packets_extract`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: it wrote a file, which stays as written; not repeated: the file stays as written. Writes a file when `path` is given, which then needs leave to edit.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How the returned bytes are written: base64 (the default) or hex. |
| `field` | FieldSpan | no | Only this field of each packet (a transfer's data blocks without their headers, say), cut short where a packet ends; packets that end before it starts give nothing. |
| `indices` | array of integer | yes | The packets, by their index in the set, in the order wanted. |
| `path` | string | no | Write the bytes here instead of returning them; needs leave to edit, as writing a file does. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `count` | integer | yes | Packets taken. |
| `data` | string | no | The bytes, when no path was given. |
| `len` | integer | yes | Bytes taken. |
| `path` | string | no | Where they were written, when a path was given. |

### packets.delete

Remove packets from the document (their whole capture records, so a capture stays readable), as one undoable step.

**Effect:** `edit` · **MCP tool:** `packets_delete`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `indices` | array of integer | yes | The packets, by their index in the set. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.fix_checksums

Recompute the IPv4 header, TCP and UDP checksums of some of a set's packets, as one undoable step.

**Effect:** `edit` · **MCP tool:** `packets_fix_checksums`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `indices` | array of integer | yes | The packets, by their index in the set. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.apply

Invert, fill or XOR some of a set's packets, or the same field of each, as one undoable step.

**Effect:** `edit` · **MCP tool:** `packets_apply`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `field` | FieldSpan | no | Only this field of each packet; packets too short to hold it are left alone. |
| `indices` | array of integer | yes | The packets, by their index in the set. |
| `key` | string | no | Hex bytes for fill and XOR. |
| `op` | `"invert"` \| `"fill"` \| `"xor"` | yes | An operation on whole packets. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.write_field

Write a value (a number, or hex bytes as wide as the field) into a field of one packet, as one undoable step.

**Effect:** `edit` · **MCP tool:** `packets_write_field`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `index` | integer | yes | The packet's index in the set. |
| `len` | integer | yes |  |
| `little_endian` | boolean | no | Write a number least significant byte first (big-endian, network order, by default). |
| `offset` | integer | yes | Where the field is, from the packet's first byte. |
| `set` | string | yes |  |
| `value` | string | yes | A whole number (decimal or 0x hex), an IPv4 or IPv6 address, a MAC address, or exactly len hex bytes. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.columns.apply

Change the same columns (byte offsets) of every packet, or of some, laid out one packet per row: invert, fill, XOR, add, set, number or swap the byte order, as one undoable step.

**Effect:** `edit` · **MCP tool:** `packets_columns_apply`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `first` | integer | yes |  |
| `group` | integer | no | For swap: bytes in each group reversed (2, 4 or 8). |
| `indices` | array of integer | no |  |
| `key` | string | no | Hex bytes for fill, XOR and add. |
| `little_endian` | boolean | no | For set and counter: write numbers least significant byte first. |
| `op` | `"invert"` \| `"fill"` \| `"xor"` \| `"add"` \| `"set"` \| `"counter"` \| `"swap"` | yes | What a column operation does. |
| `record_headers` | boolean | no |  |
| `set` | string | yes |  |
| `shifts` | array of integer | no |  |
| `start` | integer | no | For counter: the first packet's number (0 by default). |
| `step` | integer | no | For counter: added for each packet after (1 by default). |
| `value` | string | no | For set: a number, or exactly as many hex bytes as columns. |
| `width` | integer | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.columns.delete

Remove the same columns (byte offsets) from every packet, or from some, as one undoable step; length fields and checksums are not changed.

**Effect:** `edit` · **MCP tool:** `packets_columns_delete`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `first` | integer | yes | The first column, a byte offset into each row. |
| `indices` | array of integer | no | Only these packets, by their index in the set, in row order; every packet when omitted. |
| `record_headers` | boolean | no | Rows start at each packet's capture record header rather than its data. |
| `set` | string | yes |  |
| `shifts` | array of integer | no | How far each row is shifted right to line the rows up, one per packet in `indices` (or per packet of the set); none by default. |
| `width` | integer | yes | Columns, at least 1. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.columns.read

The same columns (byte offsets) of every packet, or of some, as hex lines or CSV.

**Effect:** `read` · **MCP tool:** `packets_columns_read`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `first` | integer | yes |  |
| `format` | `"hex"` \| `"csv"` | no | How columns are written as text. |
| `indices` | array of integer | no |  |
| `record_headers` | boolean | no |  |
| `set` | string | yes |  |
| `shifts` | array of integer | no |  |
| `width` | integer | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `left_out` | integer | yes | Packets that reach the columns but were left out, past 16 MiB. |
| `packets` | integer | yes | Packets written. |
| `text` | string | yes |  |

### packets.tshark_decode

Have Wireshark's tshark decode some of a set's packets (run locally with -n) as a background job; the protocols it named are the job's result, and in the window its layers merge into the Packets panel's.

**Effect:** `job` · **MCP tool:** `packets_tshark_decode`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `filter` | string | no | Only the packets this display filter keeps. |
| `indices` | array of integer | no | Only these packets, by their index in the set; every packet (those the filter keeps) when omitted, at most 5,000. |
| `mode` | `"fill_gaps"` \| `"everything"` | no | How tshark's layers go with ours. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### analysis.overview

Map the whole document: a summary of what it is, its regions with offsets, likely record widths and confident findings.

**Effect:** `read` · **MCP tool:** `analysis_overview`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `max_findings` | integer | no | Most findings to include (all of them, up to 2000, by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `analysed` | integer | yes | Bytes actually analysed (large files are read up to a limit). |
| `entropy_bits_per_byte` | number | yes |  |
| `file` | string | yes | The file's path or name. |
| `findings` | array of ReportFinding | yes | Confident findings in file order. |
| `headline` | string | yes | One line on what the file is. |
| `record_widths` | array of RecordWidth | yes | Likely record widths, best first. |
| `regions` | array of ReportRegion | yes | The file's regions, from start to end. |
| `sentences` | array of ReportSentence | yes | What the report says about the file, each about a span of it. |
| `size` | integer | yes | Length in bytes. |

### analysis.overview_job

Start analysis.overview as a background job and return its id at once; the report arrives as job.finished's result and from jobs.status, for large files and clients that should not wait.

**Effect:** `job` · **MCP tool:** `analysis_overview_job`, listed by default

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `max_findings` | integer | no | Most findings to include (all of them, up to 2000, by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### analysis.statistics

Measure a span: entropy, chi-square, serial correlation, printable, zero and high-byte fractions, distinct values and a verdict.

**Effect:** `read` · **MCP tool:** `analysis_statistics`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the span; to the end of the document when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `analysed` | integer | yes | Bytes measured. |
| `chi_square` | number | yes |  |
| `chi_square_p` | number | yes | Chi-square p-value against uniformly random bytes. |
| `distinct_values` | integer | yes |  |
| `entropy` | number | yes | Shannon entropy, 0 to 8 bits per byte. |
| `explanation` | string | yes | Why, with the measurements behind it. |
| `high_fraction` | number | yes | Fraction of bytes of 0x80 or more. |
| `mean` | number | yes |  |
| `printable_fraction` | number | yes |  |
| `serial_correlation` | number | yes | Correlation of each byte with the next; 0 for random data. |
| `start` | integer | yes |  |
| `verdict` | string | yes | What the bytes look like, such as "Text" or "Compressed or encrypted". |
| `zero_fraction` | number | yes |  |

### analysis.segments

Split the document into regions of one kind (text, tables, code, compressed, random, padding) and group them into types.

**Effect:** `read` · **MCP tool:** `analysis_segments`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `limit` | integer | no | Most segments to return (100 by default). |
| `next` | string | no | The `next` cursor of the previous page. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `next` | string | no | Pass back as `next` for more regions; absent after the last. |
| `scanned_len` | integer | yes | Bytes segmented, from the start of the document. |
| `segments` | array of SegmentResult | yes | One page of the regions, in document order. |
| `types` | array of SegmentTypeResult | yes |  |

### analysis.compressibility

Compress a span with several codecs and report the ratios, with a verdict: encrypted or random, already compressed, lossy media or structured.

**Effect:** `read` · **MCP tool:** `analysis_compressibility`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the span; to the end of the document when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `entropy` | number | yes |  |
| `ratios` | array of CompressionRatio | yes |  |
| `reason` | string | yes | The measurements behind the verdict. |
| `sample_len` | integer | yes | Bytes sampled from the span. |
| `verdict` | string | yes | Such as "encrypted or random" or "structured binary/text". |

### analysis.text_encoding

Identify the character encoding of a span of text, with previews and the likely language.

**Effect:** `read` · **MCP tool:** `analysis_text_encoding`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the span; to the end of the document when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `encodings` | array of EncodingCandidate | yes | Encodings, most likely first. |
| `languages` | array of LanguageCandidate | yes | Languages of the text in the best encoding, most likely first. |
| `sample_len` | integer | yes |  |

### analysis.processor

Test whether a span is machine code, and for which processor, by disassembling samples for each architecture.

**Effect:** `read` · **MCP tool:** `analysis_processor`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the span; to the end of the document when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `candidates` | array of ProcessorCandidate | yes | Architectures, most likely first. |
| `looks_like_data` | boolean | yes | Whether no architecture is convincing. |
| `sampled_bytes` | integer | yes | Bytes disassembled per architecture. |
| `summary` | string | yes | One sentence on what was found. |

### analysis.period_scan

Start a scan of a window of bytes for repeating periods (record widths) as a background job; the periods found, best first, are job.finished's result, and in the window they fill the structure chart and are published on record_width.estimated.

**Effect:** `job` · **MCP tool:** `analysis_period_scan`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes scanned (192 KiB by default, at most 16 MiB). |
| `max_period` | integer | no | Longest period looked for, 2 to 16384 (4096 by default). |
| `start` | integer | no | First offset of the window scanned (0 by default; the window uses the view's origin). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### reference.lookup

The reference notes on a format or protocol, by id, finding id, layer name, port (udp/67) or number (port, IP protocol or EtherType): layout, field meanings and specifications.

**Effect:** `read` · **MCP tool:** `reference_lookup`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | A format id ("ipv4", "png"), finding id, packet layer name, port ("udp/67") or number (a port, IP protocol number or EtherType). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `entries` | array of FormatReference | yes | The entries the name stands for: one for an id or key, perhaps several for a port or number. |

### reference.search

Reference entries whose notes mention every word of a query, or that a port or number names.

**Effect:** `read` · **MCP tool:** `reference_search`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `limit` | integer | no | Most entries to return (100 by default). |
| `next` | string | no | The `next` cursor of the previous page. |
| `query` | string | no | Words the notes must all mention, a port such as "tcp/502", or a number; every entry when empty. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `entries` | array of EntrySummary | yes |  |
| `next` | string | no | Pass back as `next` for more entries; absent after the last. |

### reference.rfc

The plain text of an RFC, or of one of its sections, fetched from the RFC Editor once and then kept in ~/.cache/theviewer/rfc.

**Effect:** `read` · **MCP tool:** `reference_rfc`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `number` | integer | yes | The RFC's number, such as 768. |
| `section` | string | no | A section, such as "3.1"; the whole RFC when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `note` | string | no | Said when the section asked for was not found, so the whole RFC is given. |
| `number` | integer | yes |  |
| `text` | string | yes | The section's text, or the whole RFC's. |

### reference.reload

Read the user's own reference notes again, and say which files could not be read.

**Effect:** `view` · **MCP tool:** `reference_reload`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; it has no inverse, so going back past it runs the session's steps again; repeated by going back, playback and recipes.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `problems` | array of string | yes | Those that could not be, as "path: error". |
| `user_files` | integer | yes | The user's reference files that were read. |

### reference.pick_alternative

Take another entry in place of a format guessed from a port, EtherType or IP protocol number, for the payload at an offset; the Reference panel shows it, and the entry's notes are returned.

**Effect:** `view` · **MCP tool:** `reference_pick_alternative`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; it has no inverse, so going back past it runs the session's steps again; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Where the guessed payload starts. |
| `id` | string | yes | The entry to take instead, one of the guess's alternatives. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `entry` | FormatReference | yes | The notes on the entry taken. |
| `shown` | boolean | yes | Whether the Reference panel showed a guess there and took the entry in its place. |

### events.facts

What the tools have learnt about a document and keep: the latest fact per topic, producer and key, by topic, producer or the bytes they cover, each marked stale when the document changed under it.

**Effect:** `read` · **MCP tool:** `events_facts`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `producer` | string | no | Only facts from this producer, such as "tool:period-scan". |
| `span` | SpanParam | no | Only facts whose span overlaps these bytes. |
| `topic` | string | no | Only facts on this topic, such as "record_width.estimated". |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `facts` | array of MessageEntry | yes | The facts, by topic, producer and key. |

### events.poll

The messages (facts and events) published after a cursor, oldest first, optionally of some topics only; pass back next to keep up.

**Effect:** `read` · **MCP tool:** `events_poll`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `cursor` | integer | no | The `next` of the previous poll; omitted, every message still held. |
| `limit` | integer | no | Most messages to return (default 100, at most 1000). |
| `topics` | array of string | no | Only messages on these topics. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `messages` | array of MessageEntry | yes | Messages delivered after the cursor, oldest first. |
| `missed` | integer | yes | Messages delivered after the cursor but no longer held. |
| `next` | integer | yes | Pass back as `cursor` to get the messages after these. |

### jobs.list

The background jobs tools and callers started (the last 100): what each does, who started it, whether it is running, how far it has got and how it ended.

**Effect:** `read` · **MCP tool:** `jobs_list`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `jobs` | array of JobStatus | yes | The jobs remembered (the last 100), oldest first. |

### jobs.status

One job's state, progress and outcome, and once it has finished, the result of a job a method started.

**Effect:** `read` · **MCP tool:** `jobs_status`, listed by default

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | The job's id, such as "report-3", as `job.started` or a job method gave it. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `document` | string | no | The document it works on, if one. |
| `done` | integer | no | Units of work done, when the job counts them. |
| `job` | string | yes | Unique for the session, such as "report-3". |
| `outcome` | string | no | One line on what it found, or why it stopped, once it has. |
| `producer` | string | yes | Who started it, such as `tool:report` or `mcp:claude-code`. |
| `result` | any | no | What a job started through the API gives back once finished: the result the method would have returned. |
| `state` | `"running"` \| `"cancelling"` \| `"finished"` \| `"failed"` \| `"cancelled"` | yes | Where a job is. |
| `title` | string | yes | What the job does, such as "Report". |
| `total` | integer | no | Units of work in all, when known. |

### jobs.cancel

Ask a running job to stop; it ends as cancelled, without a result, as soon as it notices.

**Effect:** `analysis` · **MCP tool:** `jobs_cancel`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job cancelled stays cancelled; run it again instead; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | The job's id, such as "report-3", as `job.started` or a job method gave it. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `document` | string | no | The document it works on, if one. |
| `done` | integer | no | Units of work done, when the job counts them. |
| `job` | string | yes | Unique for the session, such as "report-3". |
| `outcome` | string | no | One line on what it found, or why it stopped, once it has. |
| `producer` | string | yes | Who started it, such as `tool:report` or `mcp:claude-code`. |
| `result` | any | no | What a job started through the API gives back once finished: the result the method would have returned. |
| `state` | `"running"` \| `"cancelling"` \| `"finished"` \| `"failed"` \| `"cancelled"` | yes | Where a job is. |
| `title` | string | yes | What the job does, such as "Report". |
| `total` | integer | no | Units of work in all, when known. |

### statistics.analyse

Start the Statistics tool's measure of a span (at most 64 MiB) as a job: the ent randomness tests with a verdict, the byte histogram, entropy and compressibility along the span and the most repeated byte sequences are job.finished's result, and in the window they fill the Statistics tab.

**Effect:** `job` · **MCP tool:** `statistics_analyse`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes measured, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `start` | integer | no | First offset measured (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### strings.find

Start the Strings tool's search of a span (at most 64 MiB) for runs of text at least min_chars long in the encodings chosen, as a job: the strings found (at most 200000), each with its offset, length, encoding, text and what it looks like (a URL, a path, a key…), are job.finished's result, and in the window they fill the Strings tab.

**Effect:** `job` · **MCP tool:** `strings_find`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encodings` | array of `"ascii"` \| `"utf8"` \| `"utf16le"` \| `"utf16be"` | no | The encodings looked for (ascii, utf8 and utf16le by default). |
| `len` | integer | no | Bytes searched, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `min_chars` | integer | no | Fewest characters in a string, 2 to 256 (6 by default). |
| `start` | integer | no | First offset searched (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### xor.recover_keys

Recover single-byte and repeating XOR keys for a span (at most 1 MiB) by letter frequency, index of coincidence and the key showing through zero padding, best first, with a preview of each decode and the likely key lengths; transform.apply with {"op": "xor"} applies one.

**Effect:** `read` · **MCP tool:** `xor_recover_keys`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes searched, at most 1 MiB; to the end of the document (or 1 MiB) when omitted. |
| `max_key` | integer | no | Longest key looked for, 1 to 256 bytes (32 by default). |
| `start` | integer | no | First offset of the suspect bytes (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `candidates` | array of KeyCandidate | yes | The keys proposed, best first. |
| `key_lengths` | array of KeyLength | yes | The likely key lengths, best first. |
| `len` | integer | yes | Bytes searched. |
| `start` | integer | yes | First offset searched. |

### checksums.digests

The digests of a span (at most 64 MiB): CRC-32, Adler-32, MD5, SHA-1, SHA-256, the 8- and 16-bit sums and the XOR of every byte.

**Effect:** `read` · **MCP tool:** `checksums_digests`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes digested, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `start` | integer | no | First offset digested (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `adler32` | string | yes |  |
| `crc32` | string | yes |  |
| `len` | integer | yes |  |
| `md5` | string | yes |  |
| `sha1` | string | yes |  |
| `sha256` | string | yes |  |
| `start` | integer | yes |  |
| `sum16` | string | yes |  |
| `sum8` | string | yes |  |
| `xor8` | string | yes |  |

### checksums.find_stored

Find a CRC, Adler or sum stored in a span (at most 64 MiB) that covers part of it, testing header and trailer fields, and the fields at the boundaries given, against the bytes before, after and around them.

**Effect:** `read` · **MCP tool:** `checksums_find_stored`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `boundaries` | array of integer | no | Document offsets where known fields start or end (the window passes those of the findings in the span), also tested as stored values and as the edges of covered ranges. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes searched, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `start` | integer | no | First offset searched (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `len` | integer | yes |  |
| `matches` | array of StoredChecksum | yes | The checksums that match, in the order found. |
| `start` | integer | yes |  |

### checksums.solve_crc

Start the CRC solver on records of equal length that each carry a stored CRC, as a job: every polynomial, init, xorout and reflection that reproduces all the stored values (like reveng), with the closest catalogue algorithm, is job.finished's result, and in the window it fills the CRC solver.

**Effect:** `job` · **MCP tool:** `checksums_solve_crc`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `count` | integer | yes | Records, at least 2; the first 256 are solved. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `offset` | integer | no | Offset of the CRC within each record, covering the bytes before it; the last bytes of each record when omitted. |
| `order` | `"big"` \| `"little"` \| `"either"` | no | Byte order of the stored CRC (either, by default). |
| `record_len` | integer | yes | Bytes in each record, CRC included. |
| `start` | integer | yes | Document offset of the first record. |
| `try_skips` | boolean | no | Also try leaving up to 4 leading bytes of each record out of the CRC. |
| `width` | integer | no | Bits in the CRC: 8, 16 (the default) or 32. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### diff.run

Start a comparison of a document with another file as a job: the regions replaced, only in the document and only in the other file (inserted, deleted and changed, not just flipped bytes), with the bytes equal and changed, are job.finished's result, and in the window they fill the Diff tab and are outlined on the views.

**Effect:** `job` · **MCP tool:** `diff_run`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `path` | string | yes | The file to compare it with. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### disasm.set_arch

Choose the architecture the Disassembly tab decodes as, or auto (the executable header's, else a guess from the bytes); headless there is no listing to change, and the choice is only returned.

**Effect:** `view` · **MCP tool:** `disasm_set_arch`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; it has no inverse, so going back past it runs the session's steps again; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `arch` | `"x86_64"` \| `"x86_32"` \| `"arm64"` \| `"arm32"` \| `"thumb"` \| `"riscv64"` \| `"riscv32"` \| `"mips32"` \| `"powerpc32"` \| `"auto"` | yes | The architecture, such as "thumb" or "x86_64", or "auto". |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `arch` | `"x86_64"` \| `"x86_32"` \| `"arm64"` \| `"arm32"` \| `"thumb"` \| `"riscv64"` \| `"riscv32"` \| `"mips32"` \| `"powerpc32"` \| `"auto"` | yes | The architecture chosen. |
| `shown` | boolean | yes | Whether a Disassembly tab was there to change (only in the window). |

### crypto.scan_constants

Start a scan of the whole document (an edited one's first 256 MiB) for well-known constants of crypto and compression code (AES S-boxes, hash initial values, CRC tables, deflate tables, Blowfish, DES, ChaCha, TEA, curve primes, Base64 alphabets) as a job: the matches are job.finished's result, and in the window they fill Crypto constants.

**Effect:** `job` · **MCP tool:** `crypto_scan_constants`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### crypto.repeated_blocks

Start a search of a span (at most 16 MiB) for random-looking 8- and 16-byte blocks that repeat, the mark of ECB-mode encryption, as a job: the verdict, the best block size and alignment, the most repeated blocks and the repeats along the span are job.finished's result, and in the window they fill the Crypto panel.

**Effect:** `job` · **MCP tool:** `crypto_repeated_blocks`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes searched; to the end of the document, or the search's limit, when omitted. |
| `start` | integer | no | First offset searched (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### crypto.find_keys

Start a search of a span (the whole document by default, at most 64 MiB) for PEM blocks, DER certificates and keys, OpenSSH keys and random-looking runs that could be raw symmetric keys, as a job: what was found is job.finished's result, and in the window it fills the Crypto panel.

**Effect:** `job` · **MCP tool:** `crypto_find_keys`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes searched; to the end of the document, or the search's limit, when omitted. |
| `start` | integer | no | First offset searched (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### crypto.attack

Start attacks on simple ciphers over a span (at most 1 MiB): rolling XOR, XOR with the previous byte, ADD/SUB with a constant or repeating key, bit rotation, XOR combined with ADD and, with a crib, crib dragging, as a job: the decodes that look most like text or structured data are job.finished's result, and in the window they fill the Crypto panel.

**Effect:** `job` · **MCP tool:** `crypto_attack`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `crib` | string | no | Known plaintext to drag across the data, as text with \xHH escapes, such as "PK\x03\x04". |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes decoded, at most 1 MiB; to the end of the document (or 1 MiB) when omitted. |
| `start` | integer | no | First offset of the suspect bytes (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### compare.variation

Start comparing a document with other files byte position by byte position, each from its own start offset, as a job: the regions that are constant, vary (and how many values) or move one way through the files like a counter are job.finished's result, and in the window they fill Compare.

**Effect:** `job` · **MCP tool:** `compare_variation`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default): the first file. |
| `files` | array of CompareFileParam | yes | The other files, at most 31; the first 64 MiB of each is read. |
| `start` | integer | no | Offset in the document that lines up with the files' starts (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### compare.correlate

Start a search of a document and other files for fields whose values follow a number known for each file (a temperature, a setting), as a job: the fields, best fit first, with the fitted line, are job.finished's result, and in the window they fill Compare.

**Effect:** `job` · **MCP tool:** `compare_correlate`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default): the first file. |
| `files` | array of CompareFileParam | yes | The other files, at most 63. |
| `from` | integer | no | Where the search starts, from each file's start (0 by default); 256 KiB are searched. |
| `start` | integer | no | Offset in the document that lines up with the files' starts (0 by default). |
| `values` | array of number | yes | The number known for each file, the document's first: one more than the files. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### compare.timeline

Start building the change timeline of the recording of a live source or watched file, as a job: where and how often it changed, snapshot by snapshot, is job.finished's result, and the window fills Compare with it; only the window records, so headless there is none.

**Effect:** `job` · **MCP tool:** `compare_timeline`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### dotplot.compute

Start comparing every block of a span (at most 64 MiB) with every other, by shared 6-byte substrings or by byte histograms, as a job: the grid of similarities (repeated content shows as lines parallel to the diagonal) is job.finished's result, and in the window it fills the Dot plot.

**Effect:** `job` · **MCP tool:** `dotplot_compute`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes plotted, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `mode` | `"k_grams"` \| `"histogram"` | no | How blocks are compared: "k_grams" (the default) or "histogram". |
| `start` | integer | no | First offset plotted (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### images.find

Start a search of a span (at most 64 MiB) for uncompressed images, trying 1-bit, 8-bit grey, RGB565, RGB and RGBA at widths from 16 to 2048 pixels, as a job: the regions whose rows resemble each other, best first, are job.finished's result (view.set_shape shows one), and in the window they fill Images.

**Effect:** `job` · **MCP tool:** `images_find`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes searched, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `start` | integer | no | First offset searched (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### trigrams.count

Start counting every run of three bytes in a span (sampled beyond 16 MiB) as a job, labelled by segments, by the report's regions or not at all, with a part of it to pick out: the points of the trigram cube, most common first, and the region types they belong to are job.finished's result, and in the window they fill Trigrams.

**Effect:** `job` · **MCP tool:** `trigrams_count`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `highlight` | pair | no | A part of the span, as [start, len], whose trigrams are picked out from the rest. |
| `labels` | `"nothing"` \| `"segments"` \| `"report_regions"` | no | What the points are labelled by (segments by default). |
| `len` | integer | no | Bytes counted; to the end of the document when omitted. Beyond 16 MiB the span is sampled. |
| `start` | integer | no | First offset counted (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### firmware.identify

Start identifying the processor of a span of headerless code (at most 64 MiB) as a job, disassembling samples as every supported architecture and ranking them by typical instructions, idioms and branch targets: the ranking is job.finished's result, and in the window it fills Firmware (analysis.processor is the quick read).

**Effect:** `job` · **MCP tool:** `firmware_identify`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes read, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `start` | integer | no | First offset read (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### firmware.find_load_address

Start a search for the address a firmware image is loaded at (the address of offset 0, over the document's first 64 MiB) as a job: the bases that make most stored pointers land on the start of a string, as rbasefind does, are job.finished's result, and in the window they fill Firmware.

**Effect:** `job` · **MCP tool:** `firmware_find_load_address`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `byte_order` | `"little"` \| `"big"` | no | Byte order of the pointers; both are tried when omitted. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `min_string_len` | integer | no | Shortest string counted as a pointer target, 4 to 64 (10 by default). |
| `step` | integer | no | Candidate bases are multiples of this, at least 0x10 (0x1000 by default). |
| `width` | integer | no | Bits in a stored pointer: 32 (the default) or 64. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### firmware.vector_tables

Start a search of a span (the whole document by default, at most 64 MiB) for ARM Cortex-M vector tables as a job: each table's stack pointer, handlers and the flash base they imply are job.finished's result, and in the window they fill Firmware.

**Effect:** `job` · **MCP tool:** `firmware_vector_tables`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes read, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `start` | integer | no | First offset read (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### forensics.find_filesystems

Start a search of the document (its first 256 MiB) for SquashFS, CramFS, JFFS2 and UBI images as a job: each image found, with its files, is job.finished's result, and in the window they fill Forensics.

**Effect:** `job` · **MCP tool:** `forensics_find_filesystems`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### forensics.open_entry

Open one file (or volume) of the filesystem image at an offset of the document as a derived document, by its path in the image.

**Effect:** `view` · **MCP tool:** `forensics_open_entry`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back which document is current; not repeated: what it opened is open already.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default): the parent. |
| `filesystem` | integer | yes | Document offset of the filesystem image, as forensics.find_filesystems gave it. |
| `path` | string | yes | The file's path in the image, such as "etc/passwd". |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### forensics.classify_blocks

Start labelling every block of the document (its first 256 MiB) as padding, text, markup, machine code, compressed, random, raw image, PCM audio or table data as a job: the runs of one class, with the reason for each, are job.finished's result, and in the window they fill Forensics.

**Effect:** `job` · **MCP tool:** `forensics_classify_blocks`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `block_size` | integer | no | Bytes per block, at least 256 (4096 by default). |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### unpack.run

Start extracting the archives and compressed streams in the document (its first 256 MiB) recursively, like binwalk -e, as a job: the tree of what was found, each node with its kind, size and where its bytes came from, is job.finished's result, and in the window it fills the Unpacked tab and the Size map.

**Effect:** `job` · **MCP tool:** `unpack_run`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### unpack.open

Open one node of the unpacked tree (by its path of child indices, as unpack.run gave it) as a derived document.

**Effect:** `view` · **MCP tool:** `unpack_open`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back which document is current; not repeated: what it opened is open already.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default): the parent. |
| `path` | array of integer | yes | Child indices from the root, such as [0, 2]; [] is the document itself. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### unpack.read

Read the bytes of one node of the unpacked tree, by its path of child indices, as hex by default, or as base64 or text.

**Effect:** `read` · **MCP tool:** `unpack_read`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | hex (the default), base64 or text. |
| `len` | integer | no | Bytes read, at most 16 MiB; to the end of the node when omitted. |
| `path` | array of integer | yes | Child indices from the root, such as [0, 2]. |
| `start` | integer | no | First offset in the node's bytes (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `data` | string | yes |  |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | yes | How bytes are written in JSON. |
| `name` | string | yes |  |
| `node_len` | integer | yes | Bytes in the whole node. |

### unpack.save

Write the bytes of one node of the unpacked tree (by its path of child indices, as node) to a file; the document is left as it is.

**Effect:** `edit` · **MCP tool:** `unpack_save`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: it wrote a file, which stays as written; not repeated: the file stays as written. Writes a file, so it needs leave to edit.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `node` | array of integer | yes | The node's child indices from the root, such as [0, 2]. |
| `path` | string | yes | The file to write. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | The node's name. |
| `path` | string | yes | The file written. |
| `written` | integer | yes | Bytes written. |

### characterise.profile_selection

Start compressing a sample of a span with deflate, bzip2, LZ4, zstd and an order-1 entropy coder as a job: the ratios and the verdict they give (encrypted or random, already compressed, lossy media or structured) are job.finished's result, and in the window they fill Characterise (analysis.compressibility is the quick read).

**Effect:** `job` · **MCP tool:** `characterise_profile_selection`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | yes | Bytes in the span; a sample of at most 256 KiB is compressed, slices spread along it. |
| `start` | integer | yes | First offset of the span (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### characterise.profile_file

Start profiling the compressibility of the whole document as a job, overall and for up to 64 segments sampled along it: the verdicts are job.finished's result, and in the window they fill Characterise with a strip of verdicts.

**Effect:** `job` · **MCP tool:** `characterise_profile_file`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### characterise.streams

Start a search of the document (its first 256 MiB) for raw MP3/MP2 and AAC frames, H.264 and H.265 Annex B video and 16-bit PCM audio without a container as a job: the runs found are job.finished's result, and in the window they fill Characterise.

**Effect:** `job` · **MCP tool:** `characterise_streams`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### columns.profile

Profile the byte columns of fixed-size records from an offset (each column's kind, entropy and values) and group them into likely fields; in the window the Columns tool shows it.

**Effect:** `read` · **MCP tool:** `columns_profile`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes of records to profile, every record counting (a selection); when omitted, the records run from `start` until they stop looking alike. |
| `record_len` | integer | yes | Bytes per record, 1 to 65536. |
| `start` | integer | no | Offset of the first record. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `columns` | array of ColumnResult | yes |  |
| `fields` | array of FieldResult | yes |  |
| `record_len` | integer | yes |  |
| `records` | integer | yes | Records profiled. |
| `start` | integer | yes |  |
| `template` | string | yes | The fields as a template, to apply with templates.apply. |

### protocol.analyse

Start finding how a span is framed into messages (sync words, delimiters, length prefixes, fixed size) and what their header fields are, as a background job; the framing, messages and fields are job.finished's result and are published on frames.defined and fields.guessed.

**Effect:** `job` · **MCP tool:** `protocol_analyse`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the stream, at most 16 MiB; to the end of the document when omitted. |
| `start` | integer | no | First offset of the stream (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### protocol.choose_framing

Split a span into messages with a framing (one protocol.analyse offered, or any other) and work out their fields again; the messages are published on frames.defined, and in the window the Protocol tool shows them.

**Effect:** `view` · **MCP tool:** `protocol_choose_framing`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; it has no inverse, so going back past it runs the session's steps again; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `framing` | Framing | yes | How the stream is cut into messages, as protocol.analyse gives it. |
| `len` | integer | no | Bytes in the stream, at most 16 MiB; to the end of the document when omitted. |
| `start` | integer | no | First offset of the stream (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `candidates` | array of FramingResult | yes | The framings found, best first. |
| `decodes_as` | string | no | The protocol the messages read as, such as "DNS", when they do. |
| `fields` | array of MessageField | yes | The header fields found by aligning the messages. |
| `framing` | FramingResult | no | The framing the messages were split with; absent when none was found. |
| `len` | integer | yes |  |
| `length_max` | integer | yes |  |
| `length_mean` | number | yes |  |
| `length_min` | integer | yes |  |
| `messages` | array of pair | yes | Each message as [start, len], in document offsets. |
| `start` | integer | yes |  |
| `template` | string | no | The fields as a template, when there are any. |
| `type_counts` | array of pair | yes | Messages per value of the message type field, when one was found. |

### report.run

Start explaining the whole document in plain words and mapping its regions, as a background job; the report and regions are job.finished's result and are published on regions.mapped, and in the window the Report tool and the file map show them.

**Effect:** `job` · **MCP tool:** `report_run`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### structure_map.segment

Start splitting the document into stretches of uniform character, grouped into types (text, tables, compressed, padding…), as a background job; the segments are job.finished's result, and in the window the Structure map shows them.

**Effect:** `job` · **MCP tool:** `structure_map_segment`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### structure_map.find_similar

Start finding every part of the document whose statistics resemble a span, as a background job; the regions at or above the threshold are job.finished's result, and in the window the Structure map lists them.

**Effect:** `job` · **MCP tool:** `structure_map_find_similar`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `histogram_weight` | number | no | 0 compares statistics only, 1 the coarse byte histogram only (0.5 by default). |
| `len` | integer | yes |  |
| `start` | integer | yes | The span to find more like. |
| `threshold` | number | no | Similarity a region needs, 0 to 1 (0.6 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### structure_map.tracks

Start measuring entropy, compressibility, byte kinds and the local record width along the document, as a background job; the tracks are job.finished's result, and in the window the Structure map draws them.

**Effect:** `job` · **MCP tool:** `structure_map_tracks`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### learn.format

Start learning what the document and sample files of the same format share (a magic number, header fields) as a background job; a signature for the catalogue and a template draft are job.finished's result, and in the window the Learn tool shows them.

**Effect:** `job` · **MCP tool:** `learn_format`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default): the first sample. |
| `paths` | array of string | yes | The other samples, files of the same format. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### learn.save_catalogue

Write a learned signature to a new file in the user's catalogue folder, never over another, and load it.

**Effect:** `edit` · **MCP tool:** `learn_save_catalogue`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: it wrote a file, which stays as written; not repeated: the file stays as written. Writes a file, so it needs leave to edit.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string | yes | Catalogue id the file is named after, such as "user/learned-51584631". |
| `toml` | string | yes | The catalogue entry, as learn.format gives it. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `path` | string | yes | The file written. |

### learn.fuzzy_compare

Start hashing files with ssdeep and scoring how like the document each is, 0 to 100, as a background job; the scores are job.finished's result, and in the window the Learn tool lists them.

**Effect:** `job` · **MCP tool:** `learn_fuzzy_compare`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default): what the files are compared with. |
| `paths` | array of string | yes | The files to compare. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### learn.fragments

Start finding the blocks of the document that also occur in a file, as a background job; the shared fragments are job.finished's result, and in the window the Learn tool lists them.

**Effect:** `job` · **MCP tool:** `learn_fragments`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `block` | integer | no | Block size in bytes, 16 to 65536 (512 by default); shared runs are found a whole block at a time. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `path` | string | yes | The file to look in. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### alignment.run

Start clustering messages into probable types and aligning each type byte by byte, marking columns as constant, counter, length or variable, as a background job; the messages are a span cut into rows, or else those the protocol analysis published on frames.defined. The clusters are job.finished's result, and in the window the Alignment tool shows them.

**Effect:** `job` · **MCP tool:** `alignment_run`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; nothing to undo: a job only adds results, which stay; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes of rows; needed with `start`. |
| `row_width` | integer | no | Bytes per row; needed with `start`. |
| `start` | integer | no | Messages laid out one per row: the first row's offset. When omitted, the messages the protocol analysis published on frames.defined. |
| `threshold` | number | no | Similarity, 0.1 to 0.95, above which clusters merge; higher splits more (0.5 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### view.get_shape

The shape a document's bytes are drawn in: the pixel format, pixels per row, the offset of the first pixel, a bit shift and the bytes skipped after each row.

**Effect:** `read` · **MCP tool:** `view_get_shape`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `shape` | ViewShape | yes | The shape its bytes are drawn in now. |

### view.set_shape

Change the shape a document's bytes are drawn in (the pixel format, pixels per row, the first pixel's offset and bit, the padding after each row); what is not given stays as it is.

**Effect:** `view` · **MCP tool:** `view_set_shape`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; repeated calls by the same caller on the same document merge into one; undone by changing back the shape the bytes are drawn in; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bit_offset` | integer | no | Extra bit shift after `offset`, 0 to 7. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `format` | `"bit1"` \| `"bit1lsb"` \| `"nibble4"` \| `"gray8"` \| `"class"` \| `"rgb565"` \| `"gray16le"` \| `"gray16be"` \| `"rgb8"` \| `"bgr8"` \| `"rgba8"` \| `"bgra8"` \| `"u16le"` \| `"u16be"` \| `"i16le"` \| `"i16be"` \| `"u32le"` \| `"u32be"` \| `"i32le"` \| `"i32be"` \| `"f32le"` \| `"f32be"` | no | How bytes are read as pixels, such as "gray8", "rgb565" or "bit1". |
| `offset` | integer | no | Document offset of the first pixel; at most the document's length. |
| `row_padding` | integer | no | Bytes skipped after each row's pixels. |
| `width` | integer | no | Pixels per row, 1 to 16384. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `shape` | ViewShape | yes | The shape its bytes are drawn in now. |

### view.fold

Skip ranges of a document in its views (the raster and the hex dump) without deleting them; a marker shows where each was.

**Effect:** `view` · **MCP tool:** `view_fold`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back the folds; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `ranges` | array of pair | yes | The spans to skip, as [start, len]; they join spans already skipped that they touch. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `folds` | array of pair | yes | Every span skipped now, as [start, len] in document order. |

### view.unfold

Show skipped bytes again: the skipped range starting at an offset, or all of them.

**Effect:** `view` · **MCP tool:** `view_unfold`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back the folds; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `all` | boolean | no | Show every skipped range again. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `start` | integer | no | Where the skipped range to show again starts. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `folds` | array of pair | yes | Every span skipped now, as [start, len] in document order. |

### bookmarks.list

A document's bookmarks, in offset order.

**Effect:** `read` · **MCP tool:** `bookmarks_list`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bookmarks` | array of BookmarkInfo | yes | Its bookmarks now, in offset order. |
| `doc` | string | yes | Id of the document. |

### bookmarks.add

Bookmark a byte or a span of a document with a name, replacing a bookmark at the same offset; the window keeps them beside the file.

**Effect:** `view` · **MCP tool:** `bookmarks_add`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back the bookmark at that offset; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes the bookmark covers; 0 marks just the offset. |
| `name` | string | yes | What to call it. |
| `start` | integer | yes | Offset of the bookmarked byte or span. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bookmarks` | array of BookmarkInfo | yes | Its bookmarks now, in offset order. |
| `doc` | string | yes | Id of the document. |

### bookmarks.remove

Remove the bookmark at an offset.

**Effect:** `view` · **MCP tool:** `bookmarks_remove`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back the bookmark at that offset; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `start` | integer | yes | Offset of the bookmark to remove. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bookmarks` | array of BookmarkInfo | yes | Its bookmarks now, in offset order. |
| `doc` | string | yes | Id of the document. |

### plugins.reload

Load the Lua plugins again from disk, so the detectors, parsers, codecs and methods they register are the ones in their files now; the command line and MCP load them once, when they start.

**Effect:** `view` · **MCP tool:** `plugins_reload`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; it has no inverse, so going back past it runs the session's steps again; never repeated.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `message` | string | yes | What happened, as the status bar says it. |

### sources.watch

Watch the window's file for changes on disk, reloading it and marking what changed, or stop watching it.

**Effect:** `view` · **MCP tool:** `sources_watch`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; it has no inverse, so going back past it runs the session's steps again; never repeated.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `enabled` | boolean | yes | On or off. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capturing` | boolean | yes | Whether a serial capture is receiving. |
| `reading` | boolean | yes | Whether bytes asked for (a URL, a device, a process region) are still being read. |
| `recording` | boolean | yes | Whether versions of the document are being recorded. |
| `versions` | integer | yes | Versions recorded so far. |
| `watching` | boolean | yes | Whether the window's file is watched for changes. |

### sources.record

Keep every version of a document as it changes (the window's file or capture as it changes on disk, or after each edit), or stop keeping them.

**Effect:** `view` · **MCP tool:** `sources_record`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; it has no inverse, so going back past it runs the session's steps again; never repeated.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `enabled` | boolean | yes | On or off. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capturing` | boolean | yes | Whether a serial capture is receiving. |
| `reading` | boolean | yes | Whether bytes asked for (a URL, a device, a process region) are still being read. |
| `recording` | boolean | yes | Whether versions of the document are being recorded. |
| `versions` | integer | yes | Versions recorded so far. |
| `watching` | boolean | yes | Whether the window's file is watched for changes. |

### sources.stop

Stop the window's serial capture.

**Effect:** `view` · **MCP tool:** `sources_stop`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; it has no inverse, so going back past it runs the session's steps again; never repeated.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capturing` | boolean | yes | Whether a serial capture is receiving. |
| `reading` | boolean | yes | Whether bytes asked for (a URL, a device, a process region) are still being read. |
| `recording` | boolean | yes | Whether versions of the document are being recorded. |
| `versions` | integer | yes | Versions recorded so far. |
| `watching` | boolean | yes | Whether the window's file is watched for changes. |

### sources.view_version

Open a recorded version of a document as a document derived from it; the window marks what changed from the version before.

**Effect:** `view` · **MCP tool:** `sources_view_version`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; undone by changing back which document is current; not repeated: what it opened is open already.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `index` | integer | yes | The version, counting from 0 for the first one recorded. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### recipes.list

The recipes saved in ~/.config/theviewer/recipes/: each one's name, description, steps and the parameters it asks for.

**Effect:** `read` · **MCP tool:** `recipes_list`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `dir` | string | yes | The folder recipes are kept in. |
| `recipes` | array of RecipeSummary | yes | The recipes saved there, by name. |

### recipes.describe

One recipe in full, by name or path, with what to know before running it here: another API version, a plugin missing or changed, a method this build lacks, or mistakes in its anchors.

**Effect:** `read` · **MCP tool:** `recipes_describe`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | no | A saved recipe's name, as recipes.list gives it. |
| `path` | string | no | A recipe file's path. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `path` | string | no | Its file. |
| `recipe` | Recipe | yes | A saved analysis, to run on other files. |
| `warnings` | array of string | yes | What to know before running it here. |

### recipes.save

Save a recipe in ~/.config/theviewer/recipes/, given whole or made from steps of this session's journal, to run later on other files.

**Effect:** `read` · **MCP tool:** `recipes_save`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite. Writes a file, so it needs leave to edit.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `description` | string | no | What it is for (in place of the recipe's own, when one is given). |
| `journal_steps` | array of integer | no | Steps of this session's journal (history.list gives them) to make the recipe of, as recorded; the failed ones are left out. |
| `name` | string | no | The recipe's name (in place of the recipe's own, when one is given). |
| `overwrite` | boolean | no | Replace a recipe saved under the same name. |
| `recipe` | Recipe | no | The recipe, as a *.theviewer-recipe.json file holds it. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes |  |
| `path` | string | yes | The file it was saved as. |
| `steps` | integer | yes | How many steps it has. |
| `warnings` | array of string | yes | What to know before running it. |

### recipes.preview

What a recipe would do to a document, without changing anything: each step described with its anchors resolved on this file, and where the run would stop.

**Effect:** `read` · **MCP tool:** `recipes_preview`, through `api_call`, or with `--all-tools`

**History:** Kept among the recent reads, which a later step can cite.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default) to run it on. |
| `name` | string | no | A saved recipe's name, as recipes.list gives it. |
| `parameters` | object | no | Values for the recipe's parameters, by name; text is read as the parameter's type. Those left out take their defaults. |
| `path` | string | no | A recipe file's path. |
| `recipe` | Recipe | no | The recipe itself. |
| `through_step` | integer | no | Stop after the step with this number. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `steps` | array of StepReport | yes | Each step run (or previewed), in order. |
| `stopped` | Stopped | no | Why the run stopped early, if it did. |
| `warnings` | array of string | no | Things to know that did not stop it: a plugin missing or changed, a different API version, another file than the one recorded on. |

### recipes.run

Run a recipe on a document, each step called as recipe:NAME with its anchors resolved on this file, waiting for the jobs steps start; its edits undo as one step, and the first failure stops it with which step and why.

**Effect:** `edit` · **MCP tool:** `recipes_run`, through `api_call`, or with `--all-tools`

**History:** Journalled as a step; its bytes undo through the document's undo; repeated by going back, playback and recipes.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default) to run it on. |
| `name` | string | no | A saved recipe's name, as recipes.list gives it. |
| `parameters` | object | no | Values for the recipe's parameters, by name; text is read as the parameter's type. Those left out take their defaults. |
| `path` | string | no | A recipe file's path. |
| `recipe` | Recipe | no | The recipe itself. |
| `through_step` | integer | no | Stop after the step with this number. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `steps` | array of StepReport | yes | Each step run (or previewed), in order. |
| `stopped` | Stopped | no | Why the run stopped early, if it did. |
| `warnings` | array of string | no | Things to know that did not stop it: a plugin missing or changed, a different API version, another file than the one recorded on. |

## Topics

The workspace bus is where tools, panels, plugins and clients publish what they learn and what happens. Read it with `events.facts` (what is known about a document now) and `events.poll` (what was published after a cursor); plugins subscribe to topics with `theviewer.subscribe`, and MCP clients that subscribe to a resource hear when the facts behind it change.

There are two kinds of message. **Facts** are kept: the latest per topic, producer, document and key. A fact about an older version of its document counts as stale, unless the edits since did not touch its span, in which case it is carried forward with its offsets moved. **Events** are not kept: something happened.

Every message has an envelope: `id` (such as `evt-12`), `topic`, `kind`, `producer`, `document`, `version` (the document version it describes), `span` (`{start, len}`, the bytes it is about), `confidence` (0 to 1), `key` (which of a producer's facts on a topic it is), `caused_by` (the message whose handling published it) and the `payload` below; `events.facts` and `events.poll` add `stale` and `retracted`. A chain of messages more than 8 reactions deep is dropped as a loop.

Plugins may publish any topic but those the app itself publishes (`document.opened`, `document.closed`, `document.edited`, `cursor.moved`, `selection.changed`, `job.started`, `job.progress`, `job.finished`, `journal.recorded` and `plugin.log`), with a payload that must fit the topic's schema, and their own topics, `x.<plugin>.<name>`, with any payload.

| Topic | Kind | Description |
| --- | --- | --- |
| [`document.opened`](#documentopened) | event | A document was opened, or replaced the one shown. |
| [`document.closed`](#documentclosed) | event | A document was closed or replaced; what was known about it is forgotten. |
| [`document.edited`](#documentedited) | event | The document's bytes changed: each change's offset, bytes removed and bytes inserted, undo and redo included. |
| [`cursor.moved`](#cursormoved) | event | The cursor moved in the main view. |
| [`view.jump`](#viewjump) | event | Someone asks the views to put the cursor on an offset and bring it into view (a link in a report or an answer, say). |
| [`pane.show`](#paneshow) | event | Someone asks the window to bring a pane forward, reopening it if it was closed. |
| [`view.pointed`](#viewpointed) | event | Bytes a panel points at (a field row under the pointer), which the views outline, or that it stopped pointing; published when it changes. |
| [`selection.changed`](#selectionchanged) | event | What is selected changed, in the main view or by a tool selecting bytes in the document. |
| [`findings.published`](#findingspublished) | fact | What one producer recognises in the document: the scan, signatures, templates, the structure map, crypto constants, a comparison, checksums or protocol messages. |
| [`structure.identified`](#structureidentified) | fact | A structure parsed at the cursor, or a template applied, with its field tree. |
| [`fields.decoded`](#fieldsdecoded) | fact | A packet dissected into protocol layers and fields, at document offsets: the packet viewer's chosen packet, which the Reference tab reads. |
| [`template.applied`](#templateapplied) | fact | A binary template applied to the document (or, retracted, cleared): its name, source and parse, which the views outline and the packet viewer's raw frames follow. |
| [`regions.mapped`](#regionsmapped) | fact | The file split into regions of one kind, from the report. |
| [`record_width.estimated`](#record_widthestimated) | fact | The length of the records the data repeats in, from the period scan. |
| [`frames.defined`](#framesdefined) | fact | Message or packet boundaries: from the protocol framing, a capture or the packet viewer's splitting rules. |
| [`fields.guessed`](#fieldsguessed) | fact | The fields the protocol analysis guessed in a stream's messages (constants, types, sequence numbers, lengths, checksums), with a template for them. |
| [`protocol.identified`](#protocolidentified) | fact | The protocol a set of frames or a payload is, and how that was decided. |
| [`reference.focus`](#referencefocus) | event | A tool asks the Reference tab to show a format or protocol. |
| [`template.apply_requested`](#templateapply_requested) | event | Someone asks for a template to be applied at the cursor (one Ask offered, say), as the Template tool would. |
| [`job.started`](#jobstarted) | event | Background work started. |
| [`job.progress`](#jobprogress) | event | How far background work that counts its work has got. |
| [`job.finished`](#jobfinished) | event | Background work finished, with a one-line outcome (and, for a job started through the API, its result), or was cancelled. |
| [`plugin.log`](#pluginlog) | event | A plugin logged a line, or one of its callbacks failed (in a background scan, say). |
| [`journal.recorded`](#journalrecorded) | event | A call was recorded in the session's journal (an edit, view change or job, by any caller, or a read kept because a later step used its result); history.entry gives it in full. |
| [`x.*`](#x) | event | A plugin's own topic, named x.<plugin>.<name>, with a payload of its choosing. |

### document.opened

A document was opened, or replaced the one shown.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `len` | integer | yes | Length in bytes. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for a document opened from a file. |

### document.closed

A document was closed or replaced; what was known about it is forgotten.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | The document's name. |

### document.edited

The document's bytes changed: each change's offset, bytes removed and bytes inserted, undo and redo included.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `complete` | boolean | yes | False when the edit log no longer held every change since the last message; spans described before then cannot be mapped forward. |
| `edits` | array of Edit | yes | The changes, oldest first, each with the version it made. |

### cursor.moved

The cursor moved in the main view.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `offset` | integer | yes | Document offset of the cursor. |

### view.jump

Someone asks the views to put the cursor on an offset and bring it into view (a link in a report or an answer, say).

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `offset` | integer | yes | Document offset for the cursor. |

### pane.show

Someone asks the window to bring a pane forward, reopening it if it was closed.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `pane` | string | yes | The pane: Raster, Inspector, Findings, HexDump, PeriodChart, or a tool such as Packets, Reference or Template. |

### view.pointed

Bytes a panel points at (a field row under the pointer), which the views outline, or that it stopped pointing; published when it changes.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes` | Span | no | The bytes, or nothing once nothing is pointed at. |

### selection.changed

What is selected changed, in the main view or by a tool selecting bytes in the document.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `cursor` | integer | yes | Document offset of the cursor. |
| `selection` | Selection | no | `None` when nothing is selected. |

### findings.published

What one producer recognises in the document: the scan, signatures, templates, the structure map, crypto constants, a comparison, checksums or protocol messages.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `findings` | array of Finding | yes | What was found, each with its offset, length, category and title. |

### structure.identified

A structure parsed at the cursor, or a template applied, with its field tree.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `fields` | array of Field | yes | The field tree, at document offsets. |
| `format` | string | yes | The parser or template's id, such as `parser:pcap` or `template:Header`. |
| `len` | integer | yes |  |
| `start` | integer | yes | Document offset of the structure's first byte. |
| `title` | string | yes | Such as "PNG image". |

### fields.decoded

A packet dissected into protocol layers and fields, at document offsets: the packet viewer's chosen packet, which the Reference tab reads.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `ether_type` | integer | no | The EtherType after the Ethernet header and any VLAN tags. |
| `flow` | Flow | no | Addresses, ports and transport, for an IP packet. |
| `layers` | array of Layer | yes | Protocol layers, outermost first, each with its fields; every offset is a document offset. |
| `payload` | Span | no | The transport payload's bytes in the document. |

### template.applied

A binary template applied to the document (or, retracted, cleared): its name, source and parse, which the views outline and the packet viewer's raw frames follow.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | The template's name. |
| `records` | integer | yes | Records it read from its outermost array. |
| `source` | string | yes | The template's source text, to apply it again; empty when not known. |
| `structure` | Finding | yes | The whole parse, with its field tree at document offsets. |

### regions.mapped

The file split into regions of one kind, from the report.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `regions` | array of MappedRegion | yes | The regions in document order. |

### record_width.estimated

The length of the records the data repeats in, from the period scan.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `alternatives` | array of integer | yes | The next best widths, best first. |
| `score` | number | yes | How alike records this far apart are, 0 to 1. |
| `width` | integer | yes | Bytes per record. |

### frames.defined

Message or packet boundaries: from the protocol framing, a capture or the packet viewer's splitting rules.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `frames` | array of FrameSpan | yes | The first [`MOST_FRAMES`] frames, in document order. |
| `framing` | Framing | no | The framing that cut them from the message's span, when one did, so a reader can split the span again (after an edit, or past the frames listed). |
| `origin` | string | yes | How they were found, such as "length prefix u16be" or "pcap capture at 0x40". |
| `total` | integer | yes | How many frames there are in all. |

### fields.guessed

The fields the protocol analysis guessed in a stream's messages (constants, types, sequence numbers, lengths, checksums), with a template for them.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `fields` | array of MessageField | yes | Each field's position in a message (from its end for a trailer), what it seems to be and example values. |
| `template` | string | no | A binary template reading the fields, when they make one. |

### protocol.identified

The protocol a set of frames or a payload is, and how that was decided.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `frames` | array of FrameSpan | yes | The frames it was found for; empty when it is about one payload, which the message's span gives. |
| `how` | string | yes | How it was decided, such as "read 30 of 32 sampled frames in full". |
| `protocol` | string | yes | Such as "DNS" or "Modbus/TCP". |

### reference.focus

A tool asks the Reference tab to show a format or protocol.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `key` | string | yes | A reference id, finding id or layer name. |

### template.apply_requested

Someone asks for a template to be applied at the cursor (one Ask offered, say), as the Template tool would.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `source` | string | yes | The template's source text. |

### job.started

Background work started.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Unique for the session, such as "period-scan-3". |
| `title` | string | yes | What the job does, such as "Period scan". |

### job.progress

How far background work that counts its work has got.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `done` | integer | yes | Units of work done (packets, blocks, bytes: the job's own). |
| `job` | string | yes | The id `job.started` gave. |
| `total` | integer | no | Units in all, when known. |

### job.finished

Background work finished, with a one-line outcome (and, for a job started through the API, its result), or was cancelled.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `cancelled` | boolean | no | Whether it stopped because it was cancelled. |
| `job` | string | yes | The id `job.started` gave. |
| `ok` | boolean | yes | Whether it produced a result. |
| `outcome` | string | yes | One line on what it found, or why it stopped. |
| `result` | any | no | For a job started through the API, the result the method gives. |
| `title` | string | yes |  |

### plugin.log

A plugin logged a line, or one of its callbacks failed (in a background scan, say).

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `level` | `"info"` \| `"error"` | yes | `error` for a failed callback, `info` for a line the plugin logged. |
| `plugin` | string | yes | The plugin's file name, such as `modbus_rtu.lua`. |
| `text` | string | yes |  |

### journal.recorded

A call was recorded in the session's journal (an edit, view change or job, by any caller, or a read kept because a later step used its result); history.entry gives it in full.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `caller` | string | yes | Who called it: `panel`, `plugin:sync.lua`, `ask`, `mcp:claude-code`, `cli` or `recipe:<name>`. |
| `description` | string | yes | What it did in plain words. |
| `method` | string | yes | The method called, such as `transform.apply`. |
| `ok` | boolean | yes | Whether it succeeded; a failed edit, view change or job is recorded with its error. |
| `step` | integer | yes | Its step number, for history.entry. |

### x.*

A plugin's own topic, named x.<plugin>.<name>, with a payload of its choosing.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | The topic, `x.<plugin>.<name>`. |
| `payload` | any | yes | Whatever the plugin published. |
