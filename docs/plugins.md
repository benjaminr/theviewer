# Lua plugins

theviewer loads Lua 5.4 scripts from plugin directories at start-up. A script
registers **detectors** (scan a window of bytes and report findings),
**parsers** (parse one structure at an offset into a field tree), **codecs**
(decode and encode a block, for compression or an encoding such as base64)
and **actions** (commands that edit the document). Everything a script
registers appears in the viewer exactly like the built-in equivalents: the
same highlights, the same findings list, the same Decompress and Probe
buttons, the same command palette.

## Installing a plugin

Plugins are `*.lua` files in either of these directories, loaded in name
order:

- `plugins/` next to the working directory you launch the viewer from
- `~/.config/theviewer/plugins/`

The `plugins/` directory in this repository ships five examples that double
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
