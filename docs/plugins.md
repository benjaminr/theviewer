# Lua plugins

theviewer runs Lua 5.4 scripts as plugins. A script can teach the viewer
new things to recognise and decode, and take part in the analysis like any
other client of the [data API](api.md):

- **Detectors** scan a window of bytes and report findings.
- **Parsers** parse one structure at an offset into a field tree.
- **Codecs** decode and encode a block: a compression or an encoding such
  as base64.
- **Actions** are commands you run from the command palette.
- **The data API** (`theviewer.api`): read and edit the document, and call
  any method, from actions, handlers and methods.
- **The bus**: hear what other tools learn (`theviewer.subscribe`) and say
  what you learn (`theviewer.publish`).
- **Methods of your own** (`theviewer.register_method`), which panels, Ask,
  the command line, MCP clients, recipes and other plugins can call.

What a script registers appears exactly like the built-in equivalent: the
same highlights and findings list, the same Decompress and Probe buttons,
the same command palette, the same method table.

- [Installing a plugin](#installing-a-plugin)
- [The sandbox](#the-sandbox)
- [Detectors](#detectors)
- [Parsers](#parsers)
- [Codecs](#codecs)
- [The window object](#the-window-object)
- [Actions](#actions)
- [Naming the plugin: theviewer.plugin](#naming-the-plugin-theviewerplugin)
- [Calling the data API](#calling-the-data-api)
- [Subscribing to topics](#subscribing-to-topics)
- [Publishing](#publishing)
- [Registering methods](#registering-methods)
- [A worked example: acme_telemetry.lua](#a-worked-example-acme_telemetrylua)
- [Debugging](#debugging)
- [The shipped examples](#the-shipped-examples)

## Installing a plugin

Plugins are `*.lua` files in either of these folders:

- `plugins/` in the folder you start theviewer from;
- `~/.config/theviewer/plugins/`.

Each folder's scripts load in name order, `plugins/` first. Every way of
running theviewer loads them: the window, `theviewer api`, `theviewer
replay`, `--report` and `--json`, and `theviewer mcp` (which takes
`--plugins DIR` to load from other folders instead).

Each script runs once, when it loads, and registers what it offers. A
script with a syntax error, or one that fails while registering, is left
out with a message; every other script still loads. In the window the
status bar says "Some plugins failed to load: …".

**Reloading.** After editing a script, choose *View › Reload plugins* (or
*Reload plugins* in the command palette, or call `plugins.reload`). Every
script is dropped and loaded again from its folder, and the status bar
says how many loaded or which failed. `theviewer mcp` notices a changed,
added or removed script by itself within a second; `theviewer api` and
`theviewer replay` load the plugins once, when they start.

The `plugins/` folder in this repository ships six examples; see
[The shipped examples](#the-shipped-examples). Copy one, rename it and
change what it registers.

## The sandbox

Each script runs in a Lua state of its own:

- **Libraries:** `string`, `table`, `math` and `utf8`, and the base
  functions (`pairs`, `ipairs`, `pcall`, `error`, `select`, `tostring`,
  `tonumber`, `setmetatable`, `load` and the rest). There is no `io`, `os`,
  `package`, `require`, `debug` or `coroutine`, and no `dofile` or
  `loadfile`, so a plugin cannot reach files, the network, other programs
  or the environment.
- **`load`** accepts Lua source text only, never precompiled bytecode, and
  `string.dump` is removed.
- **Memory:** a script may allocate at most 64 MiB.
- **Instructions:** each callback (a scan, a parse, a handler, an action, a
  method) may run about 50 million Lua instructions; past that it is
  aborted with "plugin callback aborted after 50000000 instructions", so a
  `while true do end` cannot hang the viewer. The count starts again with
  every callback.
- **Errors** inside a callback are caught. Its result is discarded (no
  findings, `false` from `detect`, a failed decode, a `plugin_failed` error
  for a method's caller) and the error is logged with the script's name;
  see [Debugging](#debugging). Nothing a script does can crash the viewer.
- **`print`** writes to the plugin's log, like `theviewer.log`, never to
  standard output: its values are converted with `tostring` and joined by
  tabs into one line.

A script's callbacks are run one at a time: its Lua state is locked while
one runs.

## Detectors

```lua
theviewer.register_detector{
  id = "ntp-timestamps",          -- stable identifier, required
  name = "NTP timestamps",        -- shown in the UI; the id when omitted
  categories = { "Timestamp" },   -- what it can report; Custom when omitted
  scan = function(window, ctx)    -- required
    local findings = {}
    -- ... look at the window, append finding tables ...
    return findings               -- or nil
  end,
}
```

`scan` is called on background threads with a [window](#the-window-object)
of the document (the part being scanned, such as the bytes around what is
on screen) and a context table:

| Field | Meaning |
| --- | --- |
| `ctx.base` | The document offset of the window's first byte |
| `ctx.document_len` | The document's length |
| `ctx.strides` | Record strides worth testing (the row stride, detected periods) |

It returns a list of finding tables, or `nil`. Offsets in a finding are
**0-based and relative to the window**; the host adds `ctx.base`.

| Finding field | Meaning |
| --- | --- |
| `start` | The window offset of the first byte. Required. |
| `len` | Bytes spanned. Required. |
| `category` | One of the categories below; `Custom` when omitted or not recognised. |
| `title` | A short label, such as `"NTP timestamps"`. |
| `detail` | A longer description, for tooltips and the findings list. |
| `confidence` | 0 to 1, 1 when omitted. Below 0.5 the finding is drawn dimmed, and `findings.query` (unless given a lower `min_confidence`) and recipes' finding anchors leave it out. |
| `id` | The finding's id; the detector's id when omitted. |
| `fields` | A list of field tables, for the structure inspector (see [Parsers](#parsers)). |

**Categories:** `Signature`, `Executable`, `Image`, `Archive`, `Document`,
`Filesystem`, `Compressed`, `Encoding`, `Protocol`, `Structure`,
`Timestamp`, `Counter`, `OffsetTable`, `FloatArray`, `Text`,
`HighEntropy`, `Padding`, `Custom`. Case does not matter, and the label
the Findings list shows ("Offset tables", "Plugin findings" for `Custom`)
works too. (The API and recipes write the same categories in snake case,
`offset_table`; in a plugin write `OffsetTable`.)

`categories` in the registration says which categories the detector can
report.

Detectors stay pure: they see only their window and cannot call
`theviewer.api` or publish.

## Parsers

```lua
theviewer.register_parser{
  id = "tlv",
  name = "Generic TLV sequence",
  looks_like = function(window) return window:len() >= 16 end,
  parse = function(window, base)
    -- window starts at the offset being parsed; base is that offset in the document
    return { start = 0, len = 20, category = "Structure", title = "TLV", fields = { ... } }
  end,
}
```

`looks_like` must be cheap: it gets only the first 64 bytes, at every
offset a structure might start. `parse` gets the bytes from the offset on
and returns one finding table (as for detectors) or `nil`. Its `id` is the
parser's id in `structure.parsers` and `structure.parse`, and in recipes'
[structure anchors](recipes.md#structure-a-field-of-a-parsed-structure).

Field tables nest:

```lua
{ name = "header", offset = 0, len = 8, value = "", children = {
    { name = "magic",  offset = 0, len = 4, value = "PNG" },
    { name = "length", offset = 4, len = 4, value = "13" },
} }
```

| Field | Meaning |
| --- | --- |
| `name` | The field's name. Recipes name fields by dotted paths of these, so keep them stable. |
| `offset`, `len` | Where it is, relative to the window; the host adds `base`. |
| `value` | The value as text. A value that reads as an integer (decimal or `0x` hex) is a number to recipes. |
| `children` | Nested fields. |

## Codecs

```lua
theviewer.register_codec{
  id = "base64",
  name = "Base64 text",
  kind = "encoding",                                             -- or "compression"; encoding when omitted
  detect = function(window) return ... end,                      -- required
  decode = function(window, max_out) return data, consumed end,  -- required
  encode = function(data) return encoded end,                    -- optional
}
```

- `detect` gets the first 4096 bytes at the offset and says whether this
  codec applies. Codecs whose `detect` returns `false` are still tried by
  *Probe* and `codecs.probe`, which try every codec at the cursor.
- `decode` gets the bytes from the offset and the most it may return,
  `max_out`. It returns the decoded string, or `nil` when it cannot decode
  them, and optionally how many input bytes it `consumed`. Output past
  `max_out` is cut off and the result marked as cut. With `consumed` the
  viewer can replace exactly the encoded bytes in place; without it, the
  whole input is taken as consumed.
- `encode`, when given, turns a string back into its encoding, so a
  selection can be encoded in place.

## The window object

Detectors, parsers and codecs get the bytes as a read-only `window`:

| Method | Result |
| --- | --- |
| `window:len()` | The number of bytes. |
| `window:byte(i)` | The byte at **1-based** index `i` (Lua's convention), or `nil`. |
| `window:bytes(offset, len)` | A string of `len` bytes from 0-based `offset`, or `nil` past the end. |
| `window:u8(o)`, `u16le(o)`, `u16be(o)`, `u32le(o)`, `u32be(o)` | Unsigned integers at 0-based `o`, or `nil` past the end. |
| `window:u64le(o)`, `u64be(o)` | 64-bit values, as Lua integers (so above 2^63 they wrap to negative). |
| `window:i32le(o)`, `window:f32le(o)` | A signed 32-bit integer, an IEEE single. |
| `window:find(s, start)` | The 0-based offset of the plain string `s` at or after `start` (0 when omitted), or `nil`. |
| `window:find_hex("89 50 4E 47", start)` | The same, with the needle written as hex. |

Every offset but `byte`'s is 0-based.

## Actions

```lua
theviewer.register_action{
  id = "shout",
  title = "Upper-case the selected text",
  run = function(host)
    local start, len = host:selection()
    if not start then host:status("Select some text first") return end
    local text = theviewer.api.bytes.read{ start = start, len = len, encoding = "text" }
    theviewer.api.bytes.write{ start = start, data = text.data:upper(), encoding = "text" }
  end,
}
```

An action is listed in the command palette by its `title` (its `id` when
omitted), followed by the script's file name, and runs on the UI thread
when you choose it. `run` gets a handle
on the window:

| Method | Meaning |
| --- | --- |
| `host:document_len()` | The document's length. |
| `host:cursor()` | The cursor's offset. |
| `host:selection()` | `start, len`, or `nil` when nothing is selected. |
| `host:read(start, len)` | Bytes, as a string. |
| `host:replace(start, len, s)` | Replace a range with the string `s`, as one undoable edit. |
| `host:select(start, len)` | Set the selection. |
| `host:status(text)` | Show a message in the status bar. |

The handle is valid only while the action runs; a script that keeps it gets
an error if it uses it later.

An action may also call [the data API](#calling-the-data-api). You ran the
action, so its calls are allowed without asking, and its edits are labelled
with the plugin ("Overwrite 5 bytes by plugin:shout.lua"). The example uses
`encoding = "text"` because it edits text; for binary data use hex, the
default. Prefer the API for edits: a call through `theviewer.api` is recorded in the History tab
and can be part of a recipe, while `host:replace` changes the bytes
directly, as an undoable edit that the journal does not see.

## Naming the plugin: theviewer.plugin

```lua
theviewer.plugin{ name = "acme", edits = true }
```

Optional, once per script, while it loads:

- `name` (lower-case letters, digits and underscores) is the name the
  plugin's own methods and topics are named after: `acme.decode_frame`,
  `x.acme.frame_counts`. It defaults to the file's stem, lower case, with
  anything but letters and digits made `_`: `acme_telemetry.lua` is
  `acme_telemetry`.
- `edits = true` lets the plugin's subscription handlers edit and change
  the view, within the permission you give it under Settings › Permissions,
  where it is then listed. Without it, handlers only read.

Wherever the plugin is named as a caller (edit labels, the journal, the
bus, Settings), it is by its file name: `plugin:acme_telemetry.lua`.

## Calling the data API

```lua
local head = theviewer.api.bytes.read{ start = 0, len = 16 }
-- head = { doc = "doc-1", start = 0, len = 16, encoding = "hex", data = "89504e47…" }
theviewer.api.transform.apply{ selection = { range = { 0, 16 } }, operation = { op = "xor", key = "5a" } }
local widths = theviewer.api.events.facts{ topic = "record_width.estimated" }
local frame = theviewer.api.acme.decode_frame{ start = 8 }   -- another plugin's method
```

`theviewer.api.<namespace>.<method>{…}` calls a method of the
[data API](api.md) by the same name and with the same parameters as every
other client, the methods other plugins registered included. Parameters are
one table, and the result is a table.

**Values cross as JSON.**

- A table keyed `1..n` is an array; any other table is an object, its keys
  made strings. An empty table is an empty object: write
  `theviewer.array()` for an empty array (or `theviewer.array(t)` to mark
  a table as one).
- JSON `null` arrives as `nil`. Inside an array it leaves a hole, which
  goes back as `null`; at the end of an array it is lost.
- Integers stay integers; other numbers are floats.
- Strings must be UTF-8 text. Bytes go as hex strings (or base64, or text
  with `encoding = "text"`): `theviewer.hex(bytes)` turns a string of bytes
  into hex, and `theviewer.unhex(text)` turns hex back into bytes.
- Tables may nest 64 deep; an array may reach index 1,048,576.

**Errors.** A failed call raises a Lua error whose message is
`"<code>: <message>"`, such as `"out_of_range: offset 0x40 is past the end
of the document (16 bytes)"`. Catch it with `pcall` when failing is
expected:

```lua
local ok, result = pcall(theviewer.api.bytes.read, { start = offset, len = 2 })
if ok then ... else theviewer.log(result) end
```

The codes are in [docs/api.md](api.md#errors).

**Where it works.** The API works only while one of the plugin's own
callbacks runs on the window's side: an action, a subscription handler or a
registered method. Detectors, parsers and codecs stay pure, scanning on
background threads, and calling `theviewer.api` from them, or while the
script loads, raises an error ("theviewer.api and theviewer.publish work
only while an action, a subscription handler or a registered method runs").

**Who may change what:**

| Where the call is made | Reads | Edits, view changes and files written |
| --- | --- | --- |
| An action | Yes | Yes, without asking: you ran it |
| A subscription handler | Yes | Only when the plugin declares `edits = true`, and then as Settings › Permissions says for it |
| A registered method whose effect is `"edit"` | Yes | Yes: the call to it was already allowed |
| A registered method whose effect is `"read"` or `"analysis"` | Yes | No |

Methods whose effect is `analysis` (publishing findings, making packet
sets, pinning a template) are never asked about, so every callback may call
them. A call that is not allowed fails with `read_only`.

A handler's edit that must be confirmed is held for you in the
confirmation window, and the call returns `{ pending = true, message = … }`
straight away; once you answer, the plugin's log says "bytes.write was
allowed and made" or why not. Every edit is one undo step labelled with the
plugin, such as "Overwrite 2 bytes by plugin:acme_telemetry.lua".

## Subscribing to topics

```lua
theviewer.subscribe("frames.defined", function(message, api)
  local first = message.payload.frames[1]
  local head = api.bytes.read{ start = first.start, len = 2 }
  theviewer.log("first frame starts with " .. head.data)
end)
```

Call `theviewer.subscribe(topic, handler)` while the script loads. The
topic is one of the built-in topics in [docs/api.md](api.md#topics), or a
plugin's own, `x.<plugin>.<name>`; any other name is an error when the
script loads.

The handler runs for every message on the topic, whether or not any panel
is open, with two arguments:

- `message`, the envelope: `id` (`"evt-12"`), `topic`, `kind` (`"fact"` or
  `"event"`), `producer`, `document`, `version`, `span` (`{start, len}`),
  `confidence`, `key`, `caused_by`, `payload` (the topic's payload, as its
  schema in `api.describe` says), and `retracted = true` when a fact was
  withdrawn;
- `api`, which is `theviewer.api` with `publish` added.

**When handlers run.** In the window, handlers are queued per handler and
run after the frame's messages are delivered, at most 64 a frame; the rest
wait for the next frame. `theviewer mcp` runs them after each request and
every quarter of a second, at most 64 at a time. They do not run under
`theviewer api` or `theviewer replay`, which make their calls and end.

**Budgets.** Each handler call has the script's instruction and memory
budget: a runaway handler is stopped and logged, and the window carries on.
A handler that falls more than 256 messages behind loses its oldest, and the
log says how many were dropped.

**Loops.** What a handler publishes or edits is marked as caused by the
message it handled. A chain of reactions more than 8 deep is dropped as a
loop, and so is a fact identical to the one it would replace.

**Reading or editing.** A handler reads only, unless the plugin declares
`theviewer.plugin{ edits = true }`; see [Calling the data API](#calling-the-data-api).

## Publishing

```lua
api.publish("protocol.identified", { frames = frames, protocol = "ACME telemetry", how = "sync word" })
api.publish("x.acme.frame_counts", { total = 12, bad = 1 }, { key = "counts", span = { start = 16, len = 96 }, confidence = 0.9 })
```

`theviewer.publish(topic, payload, options)` (also `api.publish` in a
handler or method) publishes a message on the bus as the plugin
(`plugin:acme_telemetry.lua`), about the current document at its current
version. It works where the API does.

- **Built-in topics.** The payload must fit the topic's schema
  (`api.describe` lists each one, and so does [docs/api.md](api.md#topics)),
  or the call raises an `invalid_params` error saying what does not fit.
  The topics the app itself publishes are refused: `document.opened`,
  `document.closed`, `document.edited`, `cursor.moved`,
  `selection.changed`, `job.started` and `job.finished`. Change the
  document or the selection through `theviewer.api` instead.
- **The plugin's own topics** are `x.<plugin>.<name>` (lower-case letters,
  digits and underscores, the plugin's name as `theviewer.plugin` gave it),
  with any payload. Other plugins can subscribe to them, and so can the
  plugin itself; `events.poll` returns them to any client.
- **`options`** may give `key` (to keep several facts on one topic apart:
  each producer keeps one fact per topic, document and key), `span`
  (`{ start = …, len = … }`, the bytes it is about, which lets it be carried
  forward through edits elsewhere) and `confidence` (0 to 1).

A fact published again replaces the plugin's earlier one with the same
topic, document and key.

## Registering methods

```lua
theviewer.register_method{
  name = "acme.decode_frame",
  summary = "Decode the ACME telemetry frame at an offset.",
  params = { start = "integer", len = "integer?" },
  result = { sync = "boolean", kind = "integer?", length = "integer?" },
  effect = "read",
  run = function(params, api)
    local frame = api.bytes.read{ start = params.start, len = params.len or 4 }
    return { sync = frame.data:sub(1, 4) == "7ea5" }
  end,
}
```

Call it while the script loads. The method joins the API's table at once:

| Where | How it appears |
| --- | --- |
| `api.describe`, `theviewer api --describe` | Listed with its schemas, as `experimental` |
| Lua | `theviewer.api.acme.decode_frame{ start = 0 }`, from any plugin but its own |
| The command line | `theviewer api acme.decode_frame '{"start": 0}' capture.bin` |
| MCP | The tool `acme_decode_frame`, listed by default, its description ending "(From plugin:acme_telemetry.lua; experimental.)"; clients are told when the tool list changes |
| Ask | A tool, as the built-in methods are; an `edit` method asks first unless Ask is allowed to edit |
| Recipes | A step like any other; a recipe records the plugins loaded (name and source hash), and warns when one is missing or has changed |

| Field | Meaning |
| --- | --- |
| `name` | Required. `<plugin>.<name>`: the plugin's name (from `theviewer.plugin`, or the file's stem), a dot, and lower-case letters, digits and underscores. The plugin's name may not be one of the API's own namespaces (`bytes`, `packets`…). A name another plugin registered first is left out, with an error in the log. |
| `summary` | One sentence on what it does, for tool lists; "NAME, from a plugin." when omitted. |
| `params` | The parameters' schema; no parameters when omitted. |
| `result` | The result's schema, for `api.describe`; `{"type": "object"}` when omitted. Results are not checked against it. |
| `effect` | `"read"` (the default), `"analysis"` or `"edit"`. |
| `run` | Required. `function(params, api)`, returning a table that becomes the call's JSON result. |

**Schemas** are either a map of names to types, where `?` makes one
optional:

```lua
params = { start = "integer", len = "integer?", key = "string", raw = "boolean?" }
```

(the types are `integer`, `number`, `string`, `boolean`, `object` and
`array`; unknown parameters are refused), or a full JSON Schema, a table
with a `type`:

```lua
params = { type = "object", required = theviewer.array{ "start" },
           properties = { start = { type = "integer", minimum = 0 } }, additionalProperties = false }
```

A table whose `type` is a string is taken as a full JSON Schema, so a
simple map cannot have a parameter called `type`: write the full form for
that.

Calls are checked before `run` sees them: the required parameters are
there, no unknown ones (when the schema closes them), and each of the
right simple type. Other JSON Schema keywords (`minimum`, `enum`…) are
shown to callers but not checked. A call that fails the check is
`invalid_params`.

**Effects.**

- `"read"`: the method only reads. Its calls are kept among the recent
  reads, and its `api` cannot edit or change the view.
- `"analysis"`: it changes the session's analysis but no bytes (it
  publishes findings, makes a packet set): never asked about, journalled
  as a step, repeated by recipes. Its `api` cannot edit either.
- `"edit"`: it changes the document. A call to it asks the caller's
  permission like any edit (Ask's call shows in the confirmation window);
  once allowed, its `api` may edit without asking again. Each of its edits
  is labelled with the plugin.

Undoing a step of a plugin's method undoes its byte edits through the
document's undo; anything else it did is not undone.

**Errors.** An error `run` raises (a failed API call it did not catch
included) becomes a `plugin_failed` error for the caller, its message the
plugin's, and is logged. A method cannot call its own plugin's methods
through the API, since the script is busy running: call the Lua function
directly.

## A worked example: acme_telemetry.lua

[`plugins/acme_telemetry.lua`](../plugins/acme_telemetry.lua) is a plugin
for a made-up protocol, "ACME telemetry", whose frames start with the sync
word `7E A5`, then a type byte and a length byte. It listens to what other
tools learn, says what it recognises, and offers a method every client can
call:

```lua
theviewer.plugin{ name = "acme" }

local SYNC = "7ea5"
local SAMPLE = 16

local function starts_with_sync(api, start)
  local ok, head = pcall(api.bytes.read, { start = start, len = 2 })
  return ok and head.data == SYNC
end

theviewer.subscribe("frames.defined", function(message, api)
  local frames = message.payload.frames
  local looked, matched = 0, 0
  for index = 1, math.min(#frames, SAMPLE) do
    looked = looked + 1
    if starts_with_sync(api, frames[index].start) then matched = matched + 1 end
  end
  if looked >= 2 and matched * 4 >= looked * 3 then
    api.publish("protocol.identified", {
      frames = frames,
      protocol = "ACME telemetry",
      how = string.format("sync word 7E A5 at the start of %d of %d frames looked at", matched, looked),
    })
  end
end)

theviewer.register_method{
  name = "acme.decode_frame",
  summary = "Decode the ACME telemetry frame at an offset: whether it starts with the sync word 7E A5, its type and its length.",
  params = { start = "integer" },
  run = function(params, api)
    local frame = api.bytes.read{ start = params.start, len = 4 }
    local bytes = theviewer.unhex(frame.data)
    if #bytes < 4 or frame.data:sub(1, 4) ~= SYNC then return { sync = false } end
    return { sync = true, type = bytes:byte(3), length = bytes:byte(4) }
  end,
}
```

What happens:

1. `theviewer.plugin{ name = "acme" }` names the plugin `acme`, so its
   method is `acme.decode_frame`. It declares no edits: its handler only
   reads.
2. Whenever any tool defines frames (the protocol framing, the packet
   viewer's splitting rules, a capture, `packets.sets.create`), it
   publishes `frames.defined`, and the handler runs. It reads the first two
   bytes of up to 16 frames, using `pcall` so that a frame past the end of
   the document is passed over quietly.
3. When three in four of them start with the sync word, it publishes
   `protocol.identified`, whose payload must fit that topic's schema. The
   Workspace tab shows it as a fact from `plugin:acme_telemetry.lua`, with
   the `frames.defined` message that caused it, and every client can read
   it with `events.facts`. On files without the sync word it publishes
   nothing.
4. `acme.decode_frame` is a read: try it with
   `theviewer api acme.decode_frame '{"start": 8}' capture.bin`, which on
   such a frame prints `"sync": true`, `"type": 1` and `"length": 4`;
   through MCP it is the tool `acme_decode_frame`.

## Debugging

- **The log.** `theviewer.log(text)` (or `print(...)`) writes a line to
  the plugin's log;
  every callback error is written there too, with the script's name. Each
  line is published on the bus as `plugin.log`, with the plugin and a
  level (`info`, or `error` for failures).
- **The status bar** shows each error: "Plugin acme_telemetry.lua failed:
  …", and a load failure as "Some plugins failed to load: …".
- **The Workspace tab** lists the bus's recent messages: choose `plugin.log`
  in its topic menu to see only plugins' lines (errors in red), or another
  topic to see what your handler hears and what it published. Its facts
  list shows what your plugin has published; *why* beside a fact lists the
  messages that led to it.
- **`theviewer mcp`** writes every plugin's log line, and each script that
  fails to load, to standard error, and sends the lines to the client as
  log messages.
- **Try a method** from the command line: `theviewer api --describe` shows
  whether it registered and its schemas, and
  `theviewer api acme.decode_frame '{"start": 0}' FILE` runs it, printing a
  `plugin_failed` error with the Lua error if it fails.
- **Reload** after each change (*View › Reload plugins*).

## The shipped examples

| File | Registers | Shows |
| --- | --- | --- |
| `base64.lua` | the encoding codec `base64` | `detect` on a run of base64 characters, `decode` with `consumed`, `encode` |
| `xor_key.lua` | the encoding codec `xor-55` | a codec that is its own inverse and is reached only through Probe |
| `ntp_timestamps.lua` | the detector `ntp-timestamps` | strided numeric runs, confidence, dates in Lua |
| `tlv.lua` | the parser `tlv` | `looks_like` against `parse`, nested field trees |
| `uppercase_selection.lua` | the action `uppercase-selection` | reading, replacing and selecting through the action's handle |
| `acme_telemetry.lua` | a `frames.defined` handler and the method `acme.decode_frame` | hearing what other tools learn, publishing `protocol.identified`, and offering a method every client can call; see [above](#a-worked-example-acme_telemetrylua) |
