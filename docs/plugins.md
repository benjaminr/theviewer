# Lua plugins

theviewer loads Lua 5.4 scripts from plugin directories at start-up. A script
registers **detectors** (scan a window of bytes and report findings),
**parsers** (parse one structure at an offset into a field tree), **codecs**
(decode and encode a block, for compression or an encoding such as base64)
and **actions** (commands that edit the document). Everything a script
registers appears in the viewer exactly like the built-in equivalents: the
same highlights, the same findings list, the same Decompress and Probe
buttons, the same command palette.

Scripts can also call the data API (`theviewer.api`), react to what other
tools learn (`theviewer.subscribe`), say what they learn
(`theviewer.publish`) and offer methods of their own that panels, Ask, the
command line, MCP clients and other plugins can call (`theviewer.register_method`); see
[The data API, the bus and methods of your own](#the-data-api-the-bus-and-methods-of-your-own).

## Installing a plugin

Plugins are `*.lua` files in either of these directories, loaded in name
order:

- `plugins/` next to the working directory you launch the viewer from
- `~/.config/theviewer/plugins/`

The `plugins/` directory in this repository ships six examples that double
as a reference. Copy one, rename it, and change what it registers.

Each file runs once at load. Errors are reported per file: a script with a
syntax error, or one that fails while registering, is skipped with a message,
and every other script still loads. Reload from the Plugins menu after
editing a script.

## The `theviewer` global

### `theviewer.register_detector{ ... }`

```lua
theviewer.register_detector{
  id = "my-detector",           -- stable identifier, required
  name = "My detector",         -- shown in the UI, optional
  categories = { "Protocol" },  -- what it can report, optional
  scan = function(window, ctx)  -- required
    local findings = {}
    -- ... inspect window, append finding tables ...
    return findings             -- or nil
  end,
}
```

`scan` is called in the background with a *window* of the document (the bytes
around what is on screen, a few MiB at most) and a context table:

| field | meaning |
| --- | --- |
| `ctx.base` | document offset of `window` byte 0 |
| `ctx.document_len` | total document length |
| `ctx.strides` | candidate record strides worth testing (row stride, detected periods) |

Return a list of finding tables. Offsets in a finding are **0-based and
relative to the window**; the host adds `ctx.base` to turn them into document
offsets.

| finding field | meaning |
| --- | --- |
| `start` | window offset of the first byte, required |
| `len` | bytes spanned, required |
| `category` | one of the category names below; defaults to `Custom` |
| `title` | short label, e.g. `"NTP timestamps"` |
| `detail` | longer description for tooltips and the findings list |
| `confidence` | 0 to 1; below 0.5 the finding is drawn dimmed |
| `id` | overrides the detector id as the finding id |
| `fields` | list of field tables for the structure inspector (see parsers) |

Categories: `Signature`, `Executable`, `Image`, `Archive`, `Document`,
`Filesystem`, `Compressed`, `Encoding`, `Protocol`, `Structure`, `Timestamp`,
`Counter`, `OffsetTable`, `FloatArray`, `Text`, `HighEntropy`, `Padding`,
`Custom`.

### `theviewer.register_parser{ ... }`

```lua
theviewer.register_parser{
  id = "tlv",
  name = "Generic TLV sequence",
  looks_like = function(window) return window:u8(1) ~= nil end,
  parse = function(window, base)
    -- window starts at the offset being parsed; base is that document offset
    return { start = 0, len = 20, category = "Structure", title = "TLV", fields = { ... } }
  end,
}
```

`looks_like` must be cheap: it receives only the first 64 bytes and runs at
many offsets. `parse` receives the bytes from the offset onwards and returns
one finding table or `nil`. Field tables nest:

```lua
{ name = "header", offset = 0, len = 8, value = "", children = {
    { name = "magic",  offset = 0, len = 4, value = "PNG" },
    { name = "length", offset = 4, len = 4, value = "13" },
} }
```

Field offsets are window-relative too; the host adds `base`.

### `theviewer.register_codec{ ... }`

```lua
theviewer.register_codec{
  id = "base64",
  name = "Base64 text",
  kind = "encoding",                 -- or "compression"
  detect = function(window) return ... end,         -- header check on the bytes at the cursor
  decode = function(window, max_out) return data, consumed end,  -- data string or nil
  encode = function(data) return encoded end,       -- optional
}
```

`decode` must not return more than `max_out` bytes (the host truncates and
marks the result as cut if it does). Returning `consumed` lets the viewer
replace exactly the encoded bytes in place; without it the whole input is
assumed. Codecs whose `detect` returns false are still available from
*Probe*, which tries every codec at the cursor.

### `theviewer.register_action{ ... }`

```lua
theviewer.register_action{
  id = "uppercase-selection",
  title = "Uppercase the selected ASCII text",
  run = function(api)
    local start, len = api:selection()
    if not start then api:status("Select some text first") return end
    api:replace(start, len, api:read(start, len):upper())
  end,
}
```

Actions run on the UI thread with an `api` handle:

| method | meaning |
| --- | --- |
| `api:document_len()` | total bytes |
| `api:cursor()` | cursor offset |
| `api:selection()` | `start, len`, or `nil` when nothing is selected |
| `api:read(start, len)` | bytes as a string |
| `api:replace(start, len, s)` | replace a range; one undoable edit |
| `api:select(start, len)` | set the selection |
| `api:status(text)` | show a message in the status bar |

The handle is only valid during the call; using it afterwards raises an
error.

### `theviewer.log(text)`

Appends a line to the plugin log, shown in the Plugins menu.

## The data API, the bus and methods of your own

Plugins can do everything the other clients of the data API can (panels,
Ask, the command line): read and edit the document, hear what other tools
learn, say what they learn, and offer methods that every client can call.
The methods and topics are listed in [docs/api.md](api.md).

### `theviewer.plugin{ name = …, edits = … }`

```lua
theviewer.plugin{ name = "acme", edits = true }
```

Optional, once per script. `name` (lower-case letters, digits and
underscores) is what the plugin's own methods and topics are named after;
it defaults to the file name's stem, so `acme_telemetry.lua` is
`acme_telemetry`. `edits = true` lets the plugin's subscription handlers
edit, within the permission you give it under Settings › Permissions (see
below); without it they only read.

### `theviewer.api.<namespace>.<method>{ … }`

```lua
local head = theviewer.api.bytes.read{ start = 0, len = 16 }   -- { doc, start, len, encoding, data = "89504e47…" }
theviewer.api.transform.apply{ selection = { range = { 0, 16 } }, operation = { op = "xor", key = "5a" } }
local width = theviewer.api.events.facts{ topic = "record_width.estimated" }
```

Every method of the API, by the same name and with the same parameters as
everywhere else; methods other plugins registered are there too
(`theviewer.api.acme.decode_frame{ start = 0 }`). Parameters are one table
and the result is a table. Values cross as JSON: a table keyed `1..n` is
an array and any other table an object; `theviewer.array()` makes an empty
array. Bytes are hex strings unless you ask for `encoding = "base64"` or
`"text"`; `theviewer.hex(bytes)` and `theviewer.unhex(text)` convert.

A failed call **raises a Lua error** whose message is `"<code>: <message>"`,
such as `"out_of_range: offset 0x40 is past the end of the document"`.
Catch it with `pcall` when failing is expected:

```lua
local ok, result = pcall(theviewer.api.bytes.read, { start = offset, len = 2 })
if ok then ... else theviewer.log(result) end
```

The API works only while one of the plugin's own callbacks runs on the
window's side: an action, a subscription handler or a registered method.
Detectors, parsers and codecs stay pure: they see only their window of
bytes, on background threads, and calling `theviewer.api` from them (or
while the script loads) raises an error.

Who may change what:

| Where the call is made | Reads | Edits and view changes |
| --- | --- | --- |
| an action | yes | yes: you ran the action, so it is not asked about |
| a subscription handler | yes | only with `edits = true`, and then as Settings › Permissions says for the plugin |
| a registered method | yes | when its `effect` is `"edit"`: the call to it was already allowed |

A handler's edit that must be confirmed is held for you in the
confirmation window, and the call returns `{ pending = true, message = … }`
straight away; the outcome is written to the plugin log once you answer.
Every edit is one undo step labelled with the plugin, such as
"Overwrite 2 bytes by plugin:acme_telemetry.lua".

### `theviewer.subscribe(topic, function(message, api) … end)`

```lua
-- React to what other tools learn.
theviewer.subscribe("frames.defined", function(message, api)
  local first = message.payload.frames[1]
  local head = api.bytes.read{ start = first.start, len = 2 }
  if head.data == "7ea5" then
    api.publish("protocol.identified", {
      frames = message.payload.frames, protocol = "acme-telemetry", how = "sync word",
    })
  end
end)
```

Call it while the script loads. The handler runs for every message on the
topic, whether or not any panel is showing, with the message's envelope
(`id`, `topic`, `kind`, `producer`, `document`, `version`, `span`,
`confidence`, `key`, `caused_by` and `payload`) and `api`, which is
`theviewer.api` with `publish` added. Handlers are queued per handler and
run after the window delivers the frame's messages, a bounded number a
frame, with the script's instruction and memory budgets: a runaway handler
is stopped and logged, and the window carries on. A handler that falls more
than 256 messages behind loses its oldest and is told how many in the log.
What a handler publishes or edits is marked as caused by the message it
handled, so a chain that loops is stopped after 8 steps.

Topics are the built-in ones in [docs/api.md](api.md#topics) and plugins'
own, `x.<plugin>.<name>`.

### `theviewer.publish(topic, payload, options)`

```lua
api.publish("protocol.identified", { frames = frames, protocol = "acme-telemetry", how = "sync word" })
api.publish("x.acme.frame_counts", { total = 12, bad = 1 }, { key = "counts" })
```

Publishes as the plugin (`plugin:acme_telemetry.lua`), about the current
document. A built-in topic's payload must fit the topic's schema
(`api.describe` lists them), or the call raises an error saying what does
not fit. Topics the app itself publishes (`document.*`, `cursor.moved`,
`selection.changed`, `job.*`) are refused; change the document or the
selection through `theviewer.api` instead. A plugin's own topics are
`x.<plugin>.<name>`, with any payload; it can subscribe to them like any
other. `options` may give `key` (to keep several facts on one topic),
`span` (`{ start = …, len = … }`, the bytes it is about) and `confidence`
(0 to 1).

### `theviewer.register_method{ … }`

```lua
-- Offer a capability every client can call: panels, Ask, the command line
-- and other plugins.
theviewer.register_method{
  name = "acme.decode_frame",
  summary = "Decode one ACME telemetry frame.",
  params = { start = "integer", len = "integer?" },
  effect = "read",                                  -- or "edit"
  run = function(params, api)
    local frame = api.bytes.read{ start = params.start, len = params.len or 4 }
    return { sync = frame.data:sub(1, 4) == "7ea5", data = frame.data }
  end,
}
```

The method joins the API's table as soon as the plugin loads: `api.describe`
lists it (as experimental), Ask offers it as a tool, `theviewer api
acme.decode_frame '{"start": 0}' FILE` runs it, `theviewer mcp` offers it to
MCP clients as the tool `acme_decode_frame` (and tells them when a changed
script is reloaded), and other plugins call it as
`theviewer.api.acme.decode_frame{ … }`. Its name is `<plugin>.<name>`,
where `<plugin>` is the plugin's name, which may not be one of the API's own
namespaces.

`params` is a map of parameter names to types (`integer`, `number`,
`string`, `boolean`, `object`, `array`; a trailing `?` makes one optional)
or a full JSON schema (a table with `type = "object"`); calls are checked
against it before `run` sees them. `result` may give the result's schema
the same way. `run` returns a table, which becomes the call's JSON result;
an error it raises becomes a `plugin_failed` error for the caller. An
`effect = "edit"` method asks the caller's permission like any edit (Ask's
call to it shows in the confirmation window), and may then edit through
its `api`. A plugin cannot call its own methods through the API (call the
Lua function instead).

## The window object

Every callback that sees bytes gets a read-only `window`:

| method | result |
| --- | --- |
| `window:len()` | number of bytes |
| `window:byte(i)` | byte at **1-based** index `i` (Lua convention), or `nil` |
| `window:bytes(offset, len)` | a string of `len` bytes from 0-based `offset`, or `nil` |
| `window:u8(o)` `window:u16le(o)` `window:u16be(o)` `window:u32le(o)` `window:u32be(o)` | unsigned integers at 0-based `o`, or `nil` past the end |
| `window:u64le(o)` `window:u64be(o)` | 64-bit values (as Lua integers, so wrap above 2^63) |
| `window:i32le(o)` `window:f32le(o)` | signed 32-bit and IEEE float |
| `window:find(s, start)` | 0-based position of the plain substring `s` at or after `start`, or `nil` |
| `window:find_hex("89 50 4E 47", start)` | same, with the needle given as hex |

All offsets other than `byte` are 0-based.

## Sandbox and limits

Each script has its own Lua state with only the `string`, `table`, `math`
and `utf8` libraries plus the base functions. There is no `io`, `os`,
`package`, `debug`, `dofile` or `loadfile`, so a plugin cannot touch files,
the network or the environment. `load` accepts Lua source text only, never
precompiled bytecode, and `string.dump` is not available. A script may allocate at most 64 MiB, and a
single callback may run at most about 50 million instructions before it is
aborted with an error; a `while true do end` cannot hang the viewer.

Errors inside a callback are caught: the callback's result is discarded
(no findings, `false` from `detect`, a failed decode) and the message goes to
the plugin log with the script's name, where it is shown in the status bar.
Nothing a script does can panic the viewer.

## The shipped examples

| file | registers | shows |
| --- | --- | --- |
| `base64.lua` | encoding codec `base64` | `detect` on a run of base64 characters, decode with `consumed`, encode |
| `xor_key.lua` | encoding codec `xor-55` | a codec that is its own inverse and is only reachable via Probe |
| `ntp_timestamps.lua` | detector `ntp-timestamps` | strided numeric runs, confidence, date formatting in Lua |
| `tlv.lua` | parser `tlv` | `looks_like` versus `parse`, nested field trees |
| `uppercase_selection.lua` | action `uppercase-selection` | reading, replacing and selecting through the `api` handle |
| `acme_telemetry.lua` | a `frames.defined` handler and the method `acme.decode_frame` | hearing what other tools learn, publishing `protocol.identified`, and offering a method every client can call; it only reads, and on files without its sync word it publishes nothing |
