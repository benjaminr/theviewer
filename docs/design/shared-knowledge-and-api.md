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
| `fields.guessed` `{fields, template}` (added in phase 5) | fact | protocol analysis | packets raw frames |
| `view.jump` `{offset}`, `pane.show` `{pane}`, `template.apply_requested` `{source}` (added in phase 5) | event | links in reports and answers, `show_panel`, plugins, clients | views, layout, template tool |
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

As built in phase 5:

- **Protocol framing.** The protocol analysis publishes `frames.defined`
  with the framing that cut the messages (so a reader can split the span
  again after an edit, or past the 10,000 frames a message lists), the
  new `fields.guessed` with its field guesses and template, and
  `protocol.identified`, all from its own thread and before `job.finished`.
  Packets' "From protocol framing" and Alignment read these facts; Packets
  waits for the analysis with a reaction to `job.finished`. The analysis is
  collected every frame, not only while its tab is drawn.
- **Regions.** The raster's and curves' colours, the size map, the
  trigrams' labels and the legend read `regions.mapped` (kept by a reaction
  as the views' copy); the report keeps `bench.regions` for its own tab and
  the file map.
- **Templates.** `template.applied` carries a template's name, source,
  record count and parse, and is withdrawn when cleared. The views outline
  whatever template it names, a plugin's or a client's included; the packet
  viewer's raw frames follow a template of the name they decode with when
  it is applied again with new source.
- **Hover.** `view.pointed` is published at the end of a frame when the
  bytes the panels point at change (not every frame), and the views outline
  what it last said; the per-frame gathering stays as it was.
- **Decoded fields.** The packet viewer publishes its chosen packet on
  `fields.decoded`, layers and fields at document offsets, when the cursor
  moves into a packet, when its detail changes and after an edit, whether
  or not the panel is showing. The Reference tab builds its stack from it
  (its own capture cache stays, for captures the viewer has not loaded);
  `panel_packets::layers_at` is gone. The grids still read the panel's own
  dissections, which they draw from.
- **Requests.** `dock.jump_to`, `dock.apply_template` and `pane_request`
  are gone: links publish `view.jump` and `template.apply_requested`, and
  `show_panel` publishes `pane.show`, each carried out by a reaction, so a
  plugin or client can ask for them too. `dock.tab`/`dock.open` stay: they
  are the dock's own state, which the layout reads.
- **Not on the bus yet:** the legend's emphasis (`emphasis_next`, local to
  the views), the Columns tab's record length, the Learn and Compare
  panels' inputs, the packet grids' column selection, and the assistant's
  tool calls (which already go through the API).

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

As built in phase 5: the bus keeps a registry of jobs. `Bus::start_job`
(the window's `start_job`) registers a job, publishes `job.started` and
returns a handle the work keeps, from any thread, to publish
`job.progress` (when it has moved on by 5%), check its cancellation flag
and finish; the registry follows what is delivered. The pattern and period
scans, the entropy strip, the report, unpacking, the protocol analysis,
packet dissection (progress per packet), tshark (whose own flag is the
job's), the structure map's three analyses and the trigrams are jobs; work
that is one long call checks the flag when it returns and drops its
result. `jobs.list`, `jobs.status` and `jobs.cancel` read and cancel them
in the window and headless alike. `analysis.overview_job` is the first
method whose effect is `job`: it reads the bytes, maps them on a thread,
and its report is `job.finished`'s `result` and `jobs.status`'s; the
synchronous `analysis.overview` stays for scripts that would rather wait.
A job outlives neither its process (the command line exits at once) nor
its document.

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

As built in phase 3: handlers run on the window's thread from the bus
drain, queued per handler (at most 256 waiting, the oldest dropped and
counted) and at most 64 a frame, each with the script's budgets, because
the document is only reachable there. A handler's edit that must be
confirmed is held in the confirmation window and its call returns
`{pending = true}` at once; the outcome goes to the plugin log. Actions are
run by the person, so their edits are not asked about. API errors are
raised as Lua errors, `"<code>: <message>"`.

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

As built in phase 4 (standalone only): the current revision was 2026-07-28,
which is stateless (each request carries its protocol version, client
capabilities and name in `_meta`; `server/discover`; `subscriptions/listen`
streams in place of `resources/subscribe`; log levels per request). Clients
of that era and of the `initialize` era (2025-11-25 back to 2024-11-05) are
both served, each in its own revision's terms. Tools are named with
underscores for dots; the built-in methods give their result schema as the
output schema. Resources are a document's info, bytes, findings and facts,
and the reference notes; `theviewer://doc/{id}/packets/{set}` came with
packet sets in phase 5. The server drains its headless workspace's bus
after every request and on a quarter-second timer, running plugins'
handlers as the window does, and maps what was delivered to resource
updates. `plugins.reload` is not a method yet; instead the server reloads a
plugin directory whose scripts changed, and announces the new tool list.
Requests are handled in turn on one thread, so cancellation stops only a
request not yet started, or a listen stream.

As built in phase 5: packet sets are in the API. `packets.sets.create`
takes everything that makes the set (its source and that source's
parameters, the link, "decode as", detection and a template) and returns
the set's id with what it worked out (the capture's offset, the
selection's ranges, the framing detected), so a recipe can repeat it
exactly. A set is found again after edits by the same recipe the packet
viewer uses, is announced on `frames.defined` keyed by its id, shows in the
window's Packets panel when it is about the document shown, and is the
resource `theviewer://doc/{id}/packets/{set}`, whose subscribers hear when
it is made, decoded anew or its document edited. The window's documents
have ids of their own: a derived document a new one, its parents theirs
while they wait (listed, readable and editable by id, with what is known
about them kept), and `documents.open {doc}` goes back to a parent.
`theviewer api --save METHOD …` saves the file after the call, so one
command (a `history.transaction`, say) edits and saves.

As built in phase 6: with 150 methods, listing each as a tool cost a client
about 200 KB of its model's context, so `tools/list` gives by default the
core methods (`CORE` in `src/mcp/tools.rs`: the files, bytes, search, the
overview, findings, structure, templates, packets, reference and edits),
the plugins' methods, and `api_search` (methods by words in their names
and summaries), `api_describe` (one method's schemas) and `api_call` (any
method, with the same permissions as its own tool), about 47 KB.
`theviewer mcp --all-tools` lists every method as before. `tools/call`
takes any method's tool name either way.

### Permissions

| Caller | Read | Edit |
| --- | --- | --- |
| Panels, palette, menus | yes | yes |
| Lua detectors and parsers | their window only | no |
| Lua subscriptions and methods | yes | when the plugin declares `edits = true` and Settings allows it |
| Ask | yes | proposes; you confirm, unless allowed in Settings |
| MCP, standalone | the files given | yes (the files are the client's own) |
| MCP, attached | yes | off until allowed in Settings, per client |

As built in phase 3: every call names its `Caller` (panel, plugin, Ask, MCP
client or command line). `api::call` checks a method whose effect is `edit`
or `view` against the workspace's `permission(caller, effect)`: the window
applies the caller's policy from Settings (allow, ask or deny; a new client
is asked about), a headless workspace allows everything. Callers that
cannot block use `api::call_or_hold`, which runs the call, refuses it, or
hands it to the workspace's `hold_for_confirmation` with a reply to run
when the person answers (or after two minutes, refused). Ask's tool calls,
plugins' handlers and the attached MCP server all go through it.

## 4. History, playback and recipes

Because every way in goes through the same methods, an analysis is a
sequence of method calls. Recording that sequence gives four things from one
mechanism:

- **History**: a list of what was done, in order, by whom.
- **Undo** across edits *and* analysis steps.
- **Playback**: stepping through an analysis again, watching each step.
- **Recipes**: a saved analysis applied to other files, from the app, the
  command line or MCP.

### Every action is a method call

Recording only works if nothing bypasses the API. Panels, menus, shortcuts,
the palette and the context menu call methods as `Caller::Panel`, the same
way Lua, Ask and MCP do. Where a panel does something no method expresses,
a method is added rather than a side path. The method's params must carry
everything needed to repeat the action (split parameters, link choice,
"decode as", the template), never state read silently from a panel. Methods
return the ids of what they create (packet sets, jobs, documents), so later
steps can refer to them.

### The journal

Each call is a journal entry:

```json
{
  "step": 14,
  "at": "2026-10-06T14:02:11Z",
  "caller": "panel",
  "method": "packets.sets.create",
  "params": { "doc": "doc-1", "from": "length_field", "start": 256, "len": 4096,
              "length_field": { "offset": 0, "encoding": "u16", "big_endian": true, "adjustment": 2 } },
  "doc": "doc-1",
  "version_before": 412,
  "version_after": 412,
  "result": { "set": "set-2", "frames": 61 },
  "derived_from": { "start": { "step": 12, "path": "result.matches[0].offset" } }
}
```

- **Edits, view changes, jobs and facts the user publishes are recorded.**
  Plain reads are kept only when a later step used their result, as the
  provenance of that value. Hovering and scrolling are not recorded.
- **The journal belongs to the session.** It is shown in a **History** tab:
  - each step has its caller and a plain description (the same text the
    confirmation window uses);
  - steps that changed the document are marked;
  - clicking a step shows the document and view as they were after it.

### Undo

- **Edits undo as now:** one labelled step at a time.
- **Steps that change no bytes** (a packet set, "decode as", an applied
  template) undo through their own inverse where one exists, such as
  removing the set or restoring the previous choice.
- **"Go back to step N"** works otherwise: start from the document as it
  was after step N, or from the original file, and replay steps 1 to N.
  Because steps are deterministic, the result is the same.

### Portable steps

An absolute offset such as 0x1F40 is right for one file and wrong for the
next. A parameter value may therefore be an *anchor* instead of a literal,
resolved when the step runs:

| Anchor | Means |
| --- | --- |
| `{"step": 12, "path": "result.matches[0].offset"}` | a value an earlier step returned |
| `{"find": {"hex": "7EA5"}, "nth": 0}` | where a search matches |
| `{"structure": "png", "field": "IHDR.width"}` | a parsed field's offset, length or value |
| `{"finding": {"category": "compressed", "nth": 0}}` | a finding's span |
| `{"selection": "current"}` | whatever is selected when the recipe runs |
| `{"param": "key"}` | a value the person supplies when running the recipe |

While recording, the journal notes where a value came from, when the app
knows it. For example, a split started from a search match records that
match as the anchor. In the History tab you can turn any literal into an
anchor, or into a named parameter.

### Recipes

A recipe is a saved journal, `*.theviewer-recipe.json`:

```json
{
  "recipe": 1,
  "api_version": "1.x",
  "name": "Telemetry frames",
  "description": "Split the capture after the header and decode the frames",
  "parameters": { "key": { "type": "string", "description": "XOR key, hex" } },
  "recorded_on": { "name": "flight-03.bin", "size": 1048576, "sha256": "…" },
  "plugins": [ { "name": "acme_telemetry.lua", "sha256": "…" } ],
  "steps": [ { "method": "…", "params": { }, "note": "…" } ]
}
```

- **Running a recipe** calls each step through `api::call` as
  `Caller::Recipe(name)`, with the same permission rules as any other
  caller. Before anything changes it shows a preview: what each step will do
  to this file, and which anchors resolved where.
- **Failure:** a step that fails, or an anchor that does not resolve, stops
  the run. The person can skip the step, fix it or stop, and edits so far
  undo as one step.
- **Places to run one:**
  - the History tab ("Save as recipe…", "Run recipe…"), with playback at a
    chosen speed or one step at a time;
  - `theviewer replay RECIPE FILE… [--param key=value] [--save | --out DIR]`
    for batches, writing a JSON report per file;
  - the API, as `recipes.run`, `recipes.list` and `recipes.describe`, and so
    Ask and MCP too.
- **Saving and sharing:** recipes live in `~/.config/theviewer/recipes/` and
  can be shared as files. A recipe names the API version and the plugins it
  used, and running it warns when a plugin is missing or has changed.

### What this asks of the earlier phases

- **Methods** are complete and return ids (see above).
- **The bus is not the journal.** The journal records *intent* (method
  calls); the bus records *effects* (facts and events). Playback replays
  the calls, and the bus republishes the effects as it does live.
- **Determinism.** A method with the same params on the same bytes, with
  the same plugins, gives the same result. Background jobs a step starts
  are awaited during replay (the `Job` effect gives the id to wait on).

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
6. **Every action through the API.**
   - Panels, menus, shortcuts, the palette and the context menu call
     methods as `Caller::Panel`, adding methods where something is missing,
     so nothing the person does bypasses the journal.
   - `docs/design/ui-actions.md` lists every action with its method and
     the area converting it.
   - **Foundation, as built:**
     - Each module under `src/api/` declares its own methods, call
       descriptions and examples. They are joined into one table, grouped
       by namespace.
     - `ViewerApp::perform` calls a method as the panel. `perform_later`
       does the same for panels whose state is lent out while drawing.
     - `Workspace::window` reaches the window for effects only it has.
     - The person's undo steps are named without "by panel".
     - Four actions are converted as patterns:
       - the Selection menu's operations, through `transform.apply`;
       - Go to and the width, through `cursor.set` and the new
         `view.set_shape`;
       - Detect width, through the new `analysis.period_scan` job;
       - splitting the selection into packets by row width, through
         `packets.sets.create`.
7. **History, playback and recipes.**
   - The journal, the History tab, undo across analysis steps and
     "go back to step N".
   - Anchors and parameters, recipes saved and run in the app, with
     `theviewer replay` and the `recipes.*` methods.
   - **Foundation, as built:** the journal, recorded in `api::call` for
     every caller and published on `journal.recorded`, its session header,
     `history.list`, `history.entry` and `history.session`, and the shared
     anchor, recipe and replay types. `docs/design/history-recipes.md`
     describes them and briefs the three areas building the rest.

## Decisions

1. **MCP**: standalone over stdio (`theviewer mcp FILE…`). Attaching to the
   running app over local HTTP may follow later.
2. **Edits by plugins, Ask and MCP clients** ask for confirmation in the app
   (or, for standalone MCP, are allowed for the files the client opened),
   with a per-client setting to always allow, always ask or never allow.
3. **Plugin language**: Lua only for now. The method table does not depend
   on it, so WebAssembly plugins could be added later.
4. **Schemas** are generated from the Rust types with `schemars`.
