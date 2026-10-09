# Using theviewer from MCP clients

`theviewer mcp FILE…` serves the files you name over the
[Model Context Protocol](https://modelcontextprotocol.io) on standard input
and output, without a window. Claude Code, Claude Desktop and any other MCP
client can then inspect and edit those files with the same
[data API](api.md) the window, Lua plugins and the command line use: read
bytes, search, parse structures, list findings, apply templates, take and
dissect packet sets, run the analysis tools, edit and undo.

- [Setting it up](#setting-it-up)
- [Options](#options)
- [Tools](#tools)
- [Resources](#resources)
- [Prompts](#prompts)
- [Plugins](#plugins)
- [What a client may change](#what-a-client-may-change)
- [Protocol revisions](#protocol-revisions)
- [Troubleshooting](#troubleshooting)

## Setting it up

Build theviewer first (see [docs/development.md](development.md)); the
examples use `/path/to/theviewer` for the binary. The server opens the
files named on its command line, in order; the last one is current. A file
that cannot be opened stops the server with a message, so a mistyped path
is never served as nothing. The client can open more with `documents_open`.

### Claude Code

```sh
claude mcp add theviewer -- /path/to/theviewer mcp /path/to/firmware.bin
```

Everything after `--` is the command Claude Code runs. Give several files to
serve several, and any of the [options](#options) before them:

```sh
claude mcp add theviewer -- /path/to/theviewer mcp --plugins ~/acme/plugins capture-1.bin capture-2.bin
```

### Claude Desktop

Add the server to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "theviewer": {
      "command": "/path/to/theviewer",
      "args": ["mcp", "/path/to/firmware.bin"]
    }
  }
}
```

Use absolute paths: the client starts the server in a folder of its own
choosing.

### Other clients

Any client that starts a server as a process and talks to it over standard
input and output works the same way: the command is the theviewer binary,
and the arguments are `mcp`, any options, then the files. The server sends
nothing but protocol messages on standard output.

## Options

| Option | Effect |
| --- | --- |
| `--plugins DIR` | Load plugins from DIR instead of `./plugins` and `~/.config/theviewer/plugins`. Give it more than once for several folders. |
| `--all-tools` | List every API method as a tool of its own, instead of the core set with `api_search`, `api_describe` and `api_call`. |
| `--output-schemas` | Give each built-in method's tool its result schema (`outputSchema`), for clients that check results against it. |
| `--legacy-current` | Make an omitted `doc` mean the current document, which every document opened or derived becomes, rather than the client's focus (see [Which document a call is about](#which-document-a-call-is-about)), as before clients had a focus. For one release. |

A client keeps every tool it is offered in its model's context, so the
tool list's size matters. With the plugins in this repository, the default
list is 30 tools and about 58 KB of JSON; `--all-tools` lists 184 tools in
about 370 KB; `--output-schemas` roughly doubles either.

## Tools

Each tool is an API method, named with underscores for dots (`bytes.read`
is `bytes_read`), whose input schema is the method's parameters. A call's
result is the method's JSON result, as text and (in revisions that have it)
as `structuredContent`. A call that fails is a result marked `isError`
whose text is the API error, `{code, message, data}`, so the model sees what
went wrong and can try again. One result carries at most 1 MiB of JSON;
past that the call fails with `too_large`, saying to ask for less.

### The core tools

By default the server lists the methods a model analysing a file reaches
for first:

| What for | Tools |
| --- | --- |
| Documents | `documents_list`, `documents_open`, `documents_save` |
| Bytes | `bytes_read`, `bytes_hexdump` |
| Searching | `search_find`, `search_find_all` |
| Values | `numbers_decode` |
| The whole file | `analysis_overview`, `analysis_overview_job`, `analysis_segments`, `jobs_status` |
| What is recognised | `findings_query`, `structure_parse`, `templates_apply`, `codecs_probe` |
| Packets | `packets_dissect_bytes`, `packets_sets_create`, `packets_dissect` |
| Reference notes | `reference_lookup` |
| Edits | `bytes_write`, `bytes_replace`, `transform_apply`, `history_undo` |
| Notes and values found | `history_note`, `vars_set` |

plus every method a plugin registers (see [Plugins](#plugins)), and three
that reach the rest of the API:

| Tool | Arguments | What it does |
| --- | --- | --- |
| `api_search` | `query` (words that must all appear in a method's name or summary; empty lists every method), optional `namespace` (such as `bits`, or `plugins` for the plugins' methods) and `limit` (30 by default) | Lists the matching methods with their name, summary and effect, and `total`. A method that also has a tool of its own says so in `tool`. |
| `api_describe` | `method` (such as `bits.scan_periods`) | One method's summary, effect, stability and the JSON schemas of its parameters and result. |
| `api_call` | `method` and `params` | Calls any method by name, exactly as its own tool would be called. |

So a model that needs the bit-level tools, the checksums, crypto, firmware
or forensics tools, or the packet sets' other methods finds them with
`api_search`, reads their parameters with `api_describe` and calls them
with `api_call`:

```json
{"name": "api_search", "arguments": {"query": "period"}}
{"name": "api_describe", "arguments": {"method": "bits.scan_periods"}}
{"name": "api_call", "arguments": {"method": "packets.list", "params": {"set": "set-1", "filter": "udp", "limit": 20}}}
```

`tools/call` also accepts any method's tool name (or its dotted name) when
it is not listed, so a client may call `bits_scan_periods` directly once it
knows of it. Every method and its schemas are in [docs/api.md](api.md).

With `--all-tools`, every method is listed as a tool and the three
tools above are not offered; the instructions the server gives the client at
the start say so too, naming the methods' own tools in their place.

### Noting your reasoning

`history_note` writes a note into the session's history, where the client
is in its work: what it is doing and why. `#12` in the text cites step 12
and links the note to it (`\#917` writes "#917" citing nothing), and
`steps` links more. `kind` says what it records: an `observation` (the
default), a `hypothesis`, a `decision`, a `fallback` (a gap worked round)
or a `conclusion`. The note is recorded as the client's
(`mcp:claude-code`), and it changes nothing: it is never undone or
repeated. A read it cites is kept as evidence, which recipes leave out. It
returns the note's own step number.

```json
{"name": "history_note", "arguments": {"text": "#4 found the sync word at 0x40; splitting the frames there next"}}
```

The server's instructions ask the model to note its reasoning as it goes,
so the person can follow it beside the steps in the History tab.
`history.list` gives each note's text and linked steps, and on each step
the notes linked to it; `{"limit": 1, "order": "newest"}` gives the last
step. Through `api_call`, `history.edit_note` and
`history.delete_note` change a note, and `history.export_notes` gives the
notes as Markdown (or writes them to a `path`). See
[History and recipes](guide/history-and-recipes.md#notes).

### Which document a call is about

A method about a document takes `doc`. When a call leaves it out, it means
the client's **focus**, which each client keeps for itself: the current document when the client first calls,
then the document it opens (`documents_open`) or activates
(`documents.activate`). Making a sheet (`documents.derive`, `unpack.open`,
`codecs.open_decoded`…) does not move the focus, and nor does naming a
document in one call, so the client's next call without `doc` is still
about the document it was working on. `documents_list` marks the focus
(`"focus": true`), and every call's journal entry names the document it
was about. `"current"` still names the document opened or made last, which
moves with every derive: pass ids rather than relying on it.

`unpack.open`, `unpack.read` and `unpack.save` find a node in the tree of
`tree_doc`, which defaults to the document `unpack.run` last ran on, so a
client opening one node after another need not repeat which document was
unpacked.

### Passing on what you found

Any parameter may be an anchor instead of a literal, resolved before the
call runs and recorded with it, so the history keeps where each value came
from and a recipe saved from the session finds the values again in the
next file (see [Recipes](recipes.md#anchors-at-call-time)):

- `{"$sheet": 7}` is the sheet step 7 made (`{"$sheet": "payload"}` the one
  labelled so), in place of its id;
- `{"$anchor": {"pick": {"step": 7, "list": "job.strings", "where": {"text":
  {"regex": "^NC500-"}}, "field": "text"}}}` is the first string step 7
  found that matches;
- `{"$anchor": {"of": {"find": {"text": "CONFIG:"}}, "then": [{"add": 7}]}}`
  is 7 bytes past a match;
- `{"$var": "serial"}` is the value bound with `vars_set`.

`vars_set {name, value}` binds a value found to a name, a clipboard with
provenance: given as an anchor, the binding keeps where the value came from.
Its `doc` says which document the anchor is found in (`{"$sheet":
"photo"}`), the client's focus when it is left out.

A sheet a `recipes.run` made is named by the run's step and the label its
recipe gave it, `{"$sheet": {"step": 12, "label": "firmware"}}`, since the
session may have a sheet of that label of its own.

```json
{"name": "vars_set", "arguments": {"name": "serial", "value": {"$anchor": {"pick": {"step": 7, "list": "job.strings", "where": {"text": {"regex": "^NC500-[0-9A-F]{8}$"}}, "field": "text"}}}}}
{"name": "transform_apply", "arguments": {"doc": {"$sheet": 9}, "selection": {"range": [0, 154]},
  "operation": {"op": "xor", "key": {"$anchor": {"of": {"var": "serial"}, "then": [{"encode": "text_to_hex"}]}}}}}
```

The server's instructions tell the model to name sheets with `$sheet`, to
bind values it finds with `vars_set`, and to pass them on with `$var`.
### Passing bytes on without reading them out

A method that produces bytes takes `output`, so its result need not come
back through the client to be used again: `"new"` opens it as a sheet
derived from the document it came from (`{"new": {"label": "payload"}}`
labels it), `"in_place"` puts it in place of what it came from, `"return"`
gives the bytes, and `{"file": path}` writes them. The sheet's id is
`result.output.doc`, for the next call's `doc`:

```json
{"method": "packets.extract", "params": {"set": "set-1", "indices": [4, 9, 2], "field_name": "dns.qry.name", "label": 1, "output": {"new": {"label": "labels"}}}}
{"method": "codecs.decode", "params": {"doc": "doc-2", "start": 0, "codec": "base32", "output": {"new": {"label": "half one"}}}}
{"method": "documents.derive", "params": {"sources": [{"doc": "doc-3"}, {"doc": "doc-5"}], "output": {"new": {"label": "archive"}}}}
```

Labelled sheets are named by their labels in a recipe saved from the
session. `crypto.apply` applies a `crypto.attack` candidate the same way.
See [Outputs](api.md#conventions).

### Annotations

From revision 2025-03-26 on, each tool carries annotations: a title such as
"Bytes › read"; `readOnlyHint` for methods whose effect is `read`;
`destructiveHint` for the edits that overwrite or remove (`bytes_write`,
`bytes_replace`, `bytes_delete`, `bits_write`, `transform_apply`,
`history_undo`, `history_redo`, `history_transaction`, `documents_save`),
for plugins' methods that change anything, and for `api_call`;
`idempotentHint` for reads and for calls that leave things as one call does
(`bytes_write`, `bits_write`, `selection_set`, `cursor_set`,
`documents_open`, `documents_save`); and `openWorldHint` false, since only
the files given and opened are reached.

### Packet sets and jobs

`packets_sets_create` takes a set of packets from a capture in the file, a
range split into fixed records, by a length field, at a pattern, from
ranges given, or with the protocol framing, and returns its id (`set-1`).
`packets_dissect` dissects one packet of the set into layers and fields;
through `api_call`, `packets.list` lists the set with the Packets panel's
filter language, and `packets.decode_as`, `packets.conversations`,
`packets.follow_stream`, `packets.extract` and `packets.export_pcap` work on
it.

A method whose effect is `job` returns `{"job": "…", "step": N}` at once:
`analysis_overview_job` maps a large file in the background, and
`jobs_status` gives its progress and, once it has finished, the result.
`jobs.list` and `jobs.cancel` (through `api_call`) cover every background
job. See [Jobs](api.md#jobs).

Polling `jobs_status` is not journalled and takes no step number. An anchor
on the job's result cites the step that started it, `step` above:
`{"$anchor": {"pick": {"step": N, "list": "job.strings", …}}}`. A `job.`
path on any other step is refused, naming the step that started the job
(see [Recipes](recipes.md#jobs-and-steps)).

### Which step a call became

Every successful result of a call the journal kept says which step it
became in `_meta.step`, a read's number included, so a note (`#N`) or an
anchor (`{"step": N, …}`) can cite it at once, without a `history.list`
after each call:

```json
{"content": [{"type": "text", "text": "{\"at\":64}"}], "isError": false, "_meta": {"step": 12}}
```

A call that is not journalled (`history.list`, `jobs_status`,
`history.make_anchor`…) has no `_meta.step`.

## Resources

| URI | Contents |
| --- | --- |
| `theviewer://doc/{id}` | The document's id, name, path, length, version and whether it has unsaved edits (JSON). |
| `theviewer://doc/{id}/bytes/{start}-{end}` | Bytes `start` up to, not including, `end`, at most 1 MiB, as a blob; add `?encoding=hex` for a hex dump as text. Offsets are decimal or `0x` hex. |
| `theviewer://doc/{id}/findings` | What the detectors recognise (the first 100 findings) and the findings tools, plugins and clients published about the document (JSON). |
| `theviewer://doc/{id}/facts` | Every fact the workspace bus keeps about the document, each marked stale once the document changed under it (JSON). |
| `theviewer://doc/{id}/packets/{set}` | A packet set made with `packets_sets_create`: the set and its first 1000 packets, each with its offset, length, summary and protocols (JSON). |
| `theviewer://reference/{id}` | The reference notes on a format or protocol: its layout, fields and specifications (Markdown). `reference_lookup` and `reference.search` find ids. |

`{id}` is a document's id (`doc-1`), the path of an open document, or
`current`. `resources/list` lists each open document's info, findings,
facts and packet sets, then every reference note; `resources/templates/list`
gives the URI forms above.

**Subscriptions.** A client subscribed to a resource is told
(`notifications/resources/updated`) when it changes: any resource of a
document when the document is edited, opened or closed; its findings when
findings are published or withdrawn; its facts when any fact about it is;
a packet set's when the set is made or decoded anew. The server also says
when the list of resources changes (a document opened or closed) and when
the list of tools changes (a plugin reloaded). Clients of revision
2026-07-28 ask for these with `subscriptions/listen`; earlier clients use
`resources/subscribe` and `resources/unsubscribe`.

## Prompts

| Prompt | Arguments | What it walks the model through |
| --- | --- | --- |
| `triage_file`, *Triage this file* | `doc` | An overview, then the findings, then the structure of each main region, ending in a table of the file's regions. |
| `find_record_structure`, *Find the record structure* | `doc`, `start` | The record width, where the records run, and a field table for one record, checked with a template. |
| `explain_packet`, *Explain the packet* | `doc`, `offset`, `len` | Dissecting the packet at an offset and explaining each layer and field from the reference notes. |

Every argument is optional; `doc` defaults to `current`. The prompts name
the core tools and reach other methods through `api_call`, so they work
with the default tool list.

## Plugins

The server loads the Lua plugins from `./plugins` (relative to the folder
the client starts it in) and `~/.config/theviewer/plugins`, or from the
folders given with `--plugins`. Their detectors, parsers and codecs work as
in the window, their subscription handlers run as the bus delivers messages
(after each request, and every quarter of a second between them), and every
method they register is listed as a tool of its own, with "(From
plugin:NAME.lua; experimental.)" at the end of its description. For
example, the shipped `acme_telemetry.lua` adds `acme_decode_frame`.

A changed, added or removed script is noticed within a second and every
plugin is loaded again; the client is told the tool list changed. What
plugins log is sent to the client as log messages (`notifications/message`,
with the plugin as `logger`), and written to standard error. See
[docs/plugins.md](plugins.md).

## What a client may change

The server works on the files you named and any the client opens. **Every
call is allowed, without asking**: they are your files, given to your
client. (In the window, other clients are asked first; see
[Ask and permissions](guide/ask-and-permissions.md).)

- Each edit is one undo step labelled with the client, such as
  "Overwrite 2 bytes by mcp:claude-code", so `history_undo` takes it back.
  The client's name is the one it gives, made lower case with dashes.
- Edits change only the open document. **Nothing is written to disk until
  the client calls `documents_save`**, which writes over the file or to a
  path it gives. Other methods that write files (`documents.export`,
  `packets.export_pcap`, `recipes.save`) do so only where the client says.
- Every call is recorded in the session's journal, so `history.list`
  shows what the client did, and `recipes.save` can keep it as a
  [recipe](recipes.md) to run on other files. The notes a client writes
  with `history_note` are recorded there too, as the client's.

## Protocol revisions

The server speaks the current revision, **2026-07-28**, in which every
request carries its protocol version, client capabilities and client name
in `_meta` and there is no handshake (`server/discover` describes the
server; `subscriptions/listen` opens a stream of notifications). It also
speaks the earlier revisions that begin with `initialize`: **2025-11-25,
2025-06-18, 2025-03-26 and 2024-11-05**. A client asking `initialize` for a
revision the server does not speak is offered 2025-11-25. Tool titles,
output schemas and structured results arrive from 2025-06-18; tool
annotations from 2025-03-26.

Lists (`tools/list`, `resources/list`) come in pages of 100, with
`nextCursor` for the next. Requests are answered in turn, one at a time.

## Troubleshooting

- **Logs go to standard error.** The server writes one line when a client
  connects ("theviewer mcp: claude-code connected, speaking 2025-06-18"),
  a line for each plugin that fails to load or is reloaded, and every line
  a plugin logs. Claude Code and Claude Desktop keep a server's standard
  error in their MCP logs.
- **The server stops at once.** A file it was given could not be opened;
  the message on standard error says which. Check that the paths are
  absolute.
- **A method is missing.** By default only the core tools are listed: ask
  the model to use `api_search`, or start the server with `--all-tools`.
- **The model's context fills up.** Leave out `--all-tools` and
  `--output-schemas`, which make the tool list about six and two times
  larger.
- **A plugin's tool is missing.** Look on standard error for a load error,
  and check the folder: the server loads `./plugins` relative to where the
  client starts it, so give `--plugins DIR` with an absolute path.
- **A result is too large.** Read less at a time: a shorter `len`, a
  smaller `limit`, or a page at a time with `next`.
- **Try it by hand.** `theviewer api METHOD '{…}' FILE` runs one method with
  the same results as the tool (see the
  [command line guide](guide/command-line.md)).
