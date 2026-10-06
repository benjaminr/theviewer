# Shared knowledge, one data API, and MCP

Status: accepted; being built in the phases below.

## Why

theviewer's tools learn a great deal: the scan finds formats, the period
scan finds a record width, the protocol tool finds message boundaries, the
packet viewer identifies protocols, tshark decodes more, templates and the
Reference notes describe fields. Today each piece of knowledge reaches other
tools only where someone wired a direct link, by one panel reading another's
fields every frame. There are about twenty such links, each written once
and differently. Most panels react only while they are on screen. Plugins
can add detectors, parsers, codecs and actions, but they never hear about
anything and cannot offer what they learn to anything else.

Operations are spread the same way. The same edit can be reached from the
menus, the shortcuts, 109 palette commands, five Lua calls and Ask's eleven
read-only tools, each wired separately. None of the core types (findings,
fields, selections, packets) can be serialised.

This proposal has three parts that build on each other:

1. **Shared knowledge**: a workspace bus where tools, panels and plugins
   publish what they learn as typed facts on named topics, and subscribe to
   what others publish.
2. **One data API**: a versioned set of methods for documents, bytes, bits,
   selections, findings, structures, packets and edits, defined once with
   JSON schemas.
3. **Every way in uses it**: panels, Lua plugins, Ask, a command line and
   an MCP server are all clients of the same API and the same bus, so
   anything one can do or learn, all of them can.

## Principles

- **Defined once, exposed everywhere.** Each method and topic is declared in
  one table with its name, schemas, effect and description. Lua bindings,
  Ask's tools, MCP tools, the CLI and the reference documentation are
  generated from that table, never written by hand.
- **Facts, not chatter.** A topic carries typed facts with provenance:
  who produced it, about which document and version, over which bytes, and
  how confident it is. The latest fact per producer is kept, so a tool that
  starts late, or a panel that was hidden, catches up without replaying
  history.
- **Explicit and inspectable.** Every fact and every event can be listed and
  explained. A "Workspace" panel shows what is known, by whom and why.
- **Safe by default.** Reads are free. Edits are undoable transactions,
  checked against the document version, and labelled with who made them.
  Remote clients and plugins need permission to edit.
- **Boring transport.** The app has no async runtime and does not need one:
  JSON-RPC 2.0 over stdio and over a local HTTP socket, served from threads,
  with requests executed on the thread that owns the document.

## 1. Shared knowledge: the workspace bus

### Facts and events

There are two kinds of message:

- **Facts** are *retained*: the latest per `(topic, producer, document,
  key)` is kept until a newer one replaces it or the document version it
  describes is superseded. Examples: "bytes 0x100–0x5D0 are a pcap capture",
  "the record width is 48", "these 64 frames decode as DNS".
- **Events** are *transient*: something happened. Examples: "the selection
  changed", "an edit replaced 4 bytes at 0x40", "a job finished".

Every message has an envelope:

```json
{
  "topic": "structure.identified",
  "producer": "parser:pcap",
  "document": "doc-1",
  "version": 412,
  "span": { "start": 256, "len": 1232 },
  "confidence": 1.0,
  "key": "256",
  "caused_by": "evt-9182",
  "payload": { "format": "pcap", "title": "pcap capture", "fields": [] }
}
```

- `producer` is a stable id: a built-in tool (`tool:period-scan`), a parser
  or detector (`parser:pcap`), a plugin (`plugin:modbus_rtu.lua`), or a
  client (`mcp:claude-code`).
- `version` is the document version the fact describes. A fact about an
  older version is kept but marked stale: an edit elsewhere in a 4 GB file
  should not throw away what is known about unrelated regions. Facts with a
  `span` can be carried forward through edits that do not touch the span,
  using the document's edit log (see below).
- `caused_by` links reactions to what caused them, for the Workspace
  panel's "why" and to stop loops (see delivery rules).

### Topics (version 1)

| Topic | Kind | Published by today's… | Read by |
| --- | --- | --- | --- |
| `document.opened`, `document.closed` | event | app | everything |
| `document.edited` `{edits: [{at, removed, inserted}]}` | event | document | freshness, packets, templates, facts carried forward |
| `cursor.moved`, `selection.changed` | event | main view, hex, packets, grids | packets, reference, inspector, plugins |
| `view.pointed` (hovered bytes) | event (per frame) | reference, legend, grids | views |
| `findings.published` `{findings}` | fact per producer | scan, catalogue, plugins, crypto constants, diff, checksums, structure map | views, legend, findings, reference, Ask |
| `structure.identified` `{format, title, fields}` | fact | parsers, templates | inspector, reference, Ask |
| `regions.mapped` `{regions}` | fact | report, structure map | trigrams, size map, raster colours |
| `record_width.estimated` `{width, score}` | fact | period scan, bits | columns, raster, templates |
| `frames.defined` `{frames: [{start, len}], origin}` | fact | protocol framing, split, captures | packets, alignment, columns, plugins |
| `protocol.identified` `{frames or flow, protocol, how}` | fact | frame detection, port guesses, tshark, plugins | packets, reference, filter |
| `fields.decoded` `{layer, fields}` | fact | dissector, tshark, templates | reference, grids, filter |
| `template.applied` `{source, records}` | fact | template tool, Learn, Columns, Ask | views, packets raw frames |
| `reference.focus` `{key}` | event | packets tree, inspector | reference |
| `job.started`, `job.progress`, `job.finished` | event | every background job | status bar, Workspace panel |
| `plugin.log` `{level, text}` | event | plugins | status bar, Workspace panel (fixes errors in background scans going unseen) |

Topic names are lower case, dotted, and versioned with the API: adding a
topic or a payload field is a minor change, renaming or removing one is
major. Plugins may publish their own topics under `x.<plugin>.*`.

### Delivery

The app is a frame loop over one `ViewerApp`, and documents are read with
`&mut`. The bus fits that rather than fighting it:

- **One queue, drained once per frame** at a fixed point in `logic()`, in
  publication order. Background jobs publish through a cloneable,
  thread-safe `Publisher` (an `mpsc` sender), which replaces most of the
  ad-hoc result channels.
- **In-process consumers pull.** Panels read retained facts with typed
  queries (`bus.latest::<RecordWidth>(doc)`, `bus.facts_in(topic, span)`)
  and use `bus.changed_since(cursor)` to notice what is new. Nobody hands
  closures holding `&mut ViewerApp` to the bus.
- **Reactions run even when a panel is hidden.** A tool that must respond
  (packets re-splitting after an edit, templates re-applying) registers a
  reaction: a plain function `fn(&mut ViewerApp, &Event)` run from the drain
  step. This removes the "only while visible" behaviour.
- **Plugins and remote clients receive serialised messages** (see §3), each
  on their own queue with a bound. A slow consumer drops its oldest
  transient events and is told how many, but never loses retained facts:
  it can re-read them.
- **Loops are stopped by construction.** A reaction's messages carry
  `caused_by`. A chain deeper than 8, or a producer republishing an
  identical fact, is dropped and logged.

### The document edit log

`Document` keeps only a version counter today. It gains a bounded log of
edits `{version, at, removed, inserted}`, which is what `document.edited`
publishes. Facts and selections can be mapped forward through it: a finding
at 0x9000 moves to 0x9004 after a 4-byte insert at 0x100, rather than being
recomputed or lost.

### What changes for existing links

The links in the inventory become publications and subscriptions. For
example:

- The Packets panel's "follow the main selection" becomes a subscription to
  `selection.changed`. "Select in the document" becomes a publication. The
  `last_main_selection` echo check is replaced by `caused_by`.
- The protocol tool publishes `frames.defined` and its field guesses. Packets
  and Alignment read them, instead of reaching into
  `app.bench.tools.protocol`.
- Frame protocol detection (the "Decode frames as" work) publishes
  `protocol.identified`. A Lua plugin that recognises a private protocol can
  publish the same topic, and the packet viewer uses it like a built-in.
- Freshness subscribes to `document.edited` instead of polling versions.

## 2. The data API (version 1)

### Shape

Each method is declared once:

```rust
pub struct Method {
    pub name: &'static str,           // "bytes.read"
    pub summary: &'static str,
    pub effect: Effect,               // Read, Edit, View (UI only), Job
    pub stability: Stability,         // Stable, Experimental
    pub params: fn() -> Schema,       // JSON Schema of the params struct
    pub result: fn() -> Schema,
    pub run: fn(&mut Workspace, serde_json::Value) -> Result<serde_json::Value, ApiError>,
}
```

Params and results are ordinary Rust structs deriving `Serialize`,
`Deserialize` and `JsonSchema` (the `schemars` crate), so the schema and the
code cannot drift. Rust callers use the typed functions directly. JSON
callers go through `run`.

### Addressing and values

- **Documents** have ids (`doc-1`) and paths. The open document is `"current"`.
- **Spans** are `{doc, start, len}` in bytes. **Bit spans** are
  `{doc, bit_start, bit_len, order: "msb"|"lsb"}`.
- **Selections** are the app's model, serialised:
  `{"range": [start, len]}`, `{"ranges": [[s, l], …]}` or
  `{"columns": {first_row_start, stride, column, width, rows}}`.
- **Bytes in JSON** are hex strings by default. `encoding` may choose
  `base64` or `text` (UTF-8, with replacement characters marked).
- **Numbers** larger than 2^53 are strings.
- **Pagination**: list methods take `limit` and return `next` (an opaque cursor).
- **Limits**: one call reads or writes at most 16 MiB. Larger work is a job.

### Methods

Grouped by namespace, with the effect of each. Most wrap existing functions.

| Namespace | Methods | Effect | Built on |
| --- | --- | --- | --- |
| `documents` | `list`, `open`, `new`, `info`, `save`, `close`, `open_derived` | read / edit | `Document`, `open_derived` |
| `bytes` | `read`, `write` (overwrite), `insert`, `delete`, `replace`, `hexdump` | read / edit | `document.rs`, `assistant::hex_dump` |
| `bits` | `read`, `write`, `plane`, `scan_periods`, `find_sync` | read / edit | `bits.rs` |
| `transform` | `apply {selection, operation}` with the 19 operations (`invert`, `xor`, `shift_bits`, `compress`…), `preview` | edit / read | `selection_ops.rs` |
| `selection` / `cursor` | `get`, `set`, `select_matches` | view | `selection.rs`, `app.rs` |
| `search` | `find`, `find_all`, `count` (hex, text, UTF-16, integer) | read | `search.rs` |
| `numbers` | `decode {at, interpretation}`, `encode`, `rank_field` | read | `numeric.rs` |
| `findings` | `query {span, categories, min_confidence, producers}`, `publish`, `retract` | read / fact | registry, bus |
| `structure` | `parse {at, parser?}`, `parsers` | read | `Registry::parse_at` |
| `templates` | `list`, `apply {source or name, at}`, `infer` | read / fact | `templates.rs` |
| `codecs` | `list`, `detect`, `decode`, `encode`, `probe` | read | `compress.rs`, codec plugins |
| `packets` | `sets.create {from: capture, split_fixed, length_field, pattern, selection, protocol_framing}`, `list {set, filter}`, `dissect {set, index}`, `decode_as`, `edit_field`, `repair_checksums`, `export_pcap`, `conversations`, `follow_stream` | read / edit | `packets/*` |
| `analysis` | `overview`, `statistics`, `segments`, `entropy`, `periods`, `compressibility`, `text_encoding`, `processor` | read / job | headless, stats, segments… |
| `reference` | `lookup`, `search`, `rfc_section` | read | `reference.rs` |
| `history` | `undo`, `redo`, `transaction {calls}` | edit | `Document` groups |
| `events` | `subscribe {topics}`, `unsubscribe`, `poll {cursor}`, `facts {topic, span}` | read | bus |
| `jobs` | `status`, `cancel` | read | job registry |
| `plugins` | `list`, `reload`, and every method plugins register (below) | varies | `plugins.rs` |

### Edits

- **Each edit call is one undo step.** `history.transaction` runs several
  calls as one step, and all of them fail together.
- **`expect_version`** may be given on any edit. If the document has
  changed since, the call fails with `version_conflict` and nothing is
  changed. This gives safe concurrent use from MCP and plugins.
- **Edits are labelled with the caller** (for example "XOR by
  mcp:claude-code") in the undo history, and published on `document.edited`.

### Errors

Errors are typed: `{code, message, data}`. The codes are:

| Code | Meaning |
| --- | --- |
| `invalid_params` | The parameters don't match the schema |
| `out_of_range` | A span falls outside the document |
| `not_found` | No such document, set, method or entry |
| `version_conflict` | The document changed since `expect_version` |
| `read_only` | The caller may not edit |
| `too_large` | Over the per-call limit |
| `cancelled` | A job was cancelled |
| `plugin_failed` | A plugin raised an error or used up its budget |
| `unavailable` | For example tshark is not installed |

Messages say what to do next, in the style the app already uses.

### Long-running work

A method whose effect is `Job` returns `{job: "job-17"}` at once. Progress
and the result arrive on `job.progress` and `job.finished`, or through
`jobs.status`. `jobs.cancel` uses the cancellation flags the tshark and
serial code already have, extended to every job.

### Versioning

- The API is versioned as a whole: `api.version` returns `1.0`.
- Within a major version changes are additive only: new methods, new
  optional params, new result fields, new topics.
- Experimental methods are marked and may change.
- `api.describe` returns the full method and topic table with schemas. The
  reference documentation, `docs/api.md`, is generated from it, and a test
  fails if they differ.

## 3. Every way in

### Panels and built-in tools

Panels call the typed Rust functions behind each method, and publish and
subscribe on the bus. The palette, menus, shortcuts and context menu become
thin callers of methods. Today each of them is wired separately.

### Lua plugins

The existing `register_detector`, `register_parser`, `register_codec` and
`register_action` stay as they are. Plugins gain three things.

```lua
-- Call any API method, with the same names and params as everywhere else.
local head = theviewer.api.bytes.read{ start = 0, len = 16 }

-- React to what other tools learn.
theviewer.subscribe("frames.defined", function(event, api)
  local first = api.bytes.read{ start = event.payload.frames[1].start, len = 8 }
  if first:sub(1, 2) == "\x7e\x7e" then
    api.publish("protocol.identified", {
      frames = event.payload.frames, protocol = "acme-telemetry", how = "sync word"
    })
  end
end)

-- Offer a capability every client can call: panels, Ask and MCP.
theviewer.register_method{
  name = "acme.decode_frame",
  summary = "Decode one ACME telemetry frame",
  params = { start = "integer", len = "integer" },
  run = function(params, api) return { fields = decode(api, params) } end,
}
```

- **Subscription handlers** run on the plugin's own thread with the existing
  instruction and memory budgets. They receive a read-only `api` unless the
  plugin declares `edits = true` and the user has allowed it in Settings.
- **Methods a plugin registers** appear under `plugins` with their schema.
  They become Ask tools and MCP tools automatically. This is how "expose all
  plugins through MCP" works without per-plugin glue.
- **Detectors and parsers stay pure** (window in, findings out), because they
  run inside scans that must stay fast and parallel.

### Ask

Ask's tool list is generated from the method table, so it can use
everything, not just eleven read-only tools. Edits go through the same
permission as MCP: Ask proposes and you confirm, unless edits are allowed.

### Command line

- `theviewer api <method> '<json>' [FILE]` runs one call headlessly and
  prints JSON.
- `theviewer api --describe` prints the method table.

These make the API scriptable from shells and CI, building on `--report` and
`--json`.

### MCP server

Two ways to run it:

1. **Standalone**: `theviewer mcp [FILE…]` speaks MCP over stdio, with its
   own headless workspace. This is what Claude Code, Claude Desktop and
   other MCP clients launch. It needs no window and no permission prompt,
   because it works only on the files it was given.
2. **Attached to the running app**: when turned on in Settings, the app
   serves MCP over Streamable HTTP on `127.0.0.1` only, with a token kept
   in `~/.config/theviewer/`. A client then sees and edits what you are
   looking at, and the app shows "Connected: claude-code" in the status
   bar. It is off by default.

How MCP concepts map:

| MCP | theviewer |
| --- | --- |
| tools | every API method, including plugin-registered ones. Read-only methods are marked `readOnlyHint`; deleting and overwriting methods are marked `destructiveHint`. |
| resources | `theviewer://doc/{id}` (info), `theviewer://doc/{id}/bytes/{start}-{end}`, `theviewer://doc/{id}/findings`, `theviewer://doc/{id}/packets/{set}`, and `theviewer://reference/{id}` for the notes |
| resource subscriptions | bus topics: a client subscribed to a document's findings is notified when `findings.published` changes them |
| prompts | a few starting points, such as "Triage this file", "Find the record structure" and "Explain the packet at the cursor" |

**Implementation** is hand-written JSON-RPC 2.0, about the size of the
assistant module. It runs over stdio, and over HTTP with a small synchronous
server crate (for example `tiny_http`). Requests are queued to the UI
thread, exactly as Ask's tool calls are today (`Event::Tool` with a reply
channel). That avoids adding an async runtime. If the official Rust MCP SDK
later suits better, only the transport layer changes, not the method table.

The server targets the current MCP specification revision when it is built.
It is checked with the MCP Inspector and an end-to-end test that drives
`theviewer mcp` over stdio.

### Permissions

| Caller | Read | Edit |
| --- | --- | --- |
| Panels, palette, menus | yes | yes |
| Lua detectors and parsers | their window only | no |
| Lua subscriptions and methods | yes | when the plugin declares `edits = true` and Settings allows it |
| Ask | yes | proposes; you confirm, unless allowed in Settings |
| MCP, standalone | the files given | yes (the files are the client's own) |
| MCP, attached | yes | off until allowed in Settings, per client |

## Delivery plan

Each phase is useful on its own and keeps the app working.

1. **Foundations.**
   - Add serde and `JsonSchema` to the core types: `Finding`, `Field`,
     `Category`, `Selection`, `Operation`, `Packet`, the parts of
     `Dissection` that are not internal, and `Codec`.
   - Build the method table, with the read-only methods first.
   - Generate Ask's tools from it, replacing the hand-written eleven.
   - Add `theviewer api` and `api.describe`, and generate `docs/api.md`.
2. **The bus.**
   - Add retained facts, events, the per-frame drain, publishers for
     background jobs, and the document edit log.
   - Move four existing links onto it: selection following, findings
     producers, the record width to Columns, and Packets to Reference.
   - Add `plugin.log`, so background plugin errors are shown.
   - Add a Workspace panel listing facts and events.
3. **Edits and plugins.**
   - Add the edit methods with transactions, `expect_version` and labels.
   - Give Lua `theviewer.api`, `subscribe`, `publish` and `register_method`.
   - Add permissions in Settings.
4. **MCP.**
   - `theviewer mcp` over stdio, then the attached HTTP server with a token
     and permissions.
   - Map MCP resources and subscriptions onto the bus.
5. **Move the rest of the links.**
   - Move the remaining links onto the bus, including frame protocol
     detection, tshark and templates.
   - Retire the request fields and per-panel polling where the bus covers
     them.

## Decisions

1. **MCP**: standalone over stdio (`theviewer mcp FILE…`). Attaching to the
   running app over local HTTP may follow later.
2. **Edits by plugins, Ask and MCP clients** ask for confirmation in the app
   (or, for standalone MCP, are allowed for the files the client opened),
   with a per-client setting to always allow, always ask or never allow.
3. **Plugin language**: Lua only for now. The method table does not depend
   on it, so WebAssembly plugins could be added later.
4. **Schemas** are generated from the Rust types with `schemars`.
