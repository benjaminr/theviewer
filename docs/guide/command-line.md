# Command line

`theviewer` opens a window by default. It can also print a report, run one
method of the data API, serve files to an MCP client, or run a recipe over
many files, all without a window.

```text
theviewer [FILE] [--format NAME] [--palette NAME] [--width PIXELS] [--offset BYTES]
          [--cursor BYTES] [--zoom FACTOR] [--detect] [--open] [--tool NAME] [--layout NAME]
theviewer FILE --report | --json
theviewer api [--save] METHOD ['{JSON PARAMS}'] [FILE]
theviewer api --describe
theviewer mcp [--plugins DIR]... [--all-tools] [--output-schemas] [FILE...]
theviewer replay RECIPE FILE... [--param KEY=VALUE]... [--save | --out DIR] [--json]
```

`theviewer --help` prints the same summary. A command line that cannot be
understood exits with code 2; a report, call or run that fails exits
with 1.

- [Opening a window](#opening-a-window)
- [Printing a report](#printing-a-report)
- [theviewer api](#theviewer-api)
- [theviewer mcp](#theviewer-mcp)
- [theviewer replay](#theviewer-replay)

## Opening a window

```sh
theviewer firmware.bin --format rgb8 --width 320 --offset 0x1000 --zoom 2
theviewer records.dat --detect
theviewer capture.bin --tool protocol --layout network
theviewer dump.bin --tool packets      # load the first capture, else the message framing
```

| Option | Effect |
| --- | --- |
| `--format NAME` | Pixel format: `bit1` `bit1lsb` `nibble4` `gray8` `class` `rgb565` `gray16le` `gray16be` `rgb8` `bgr8` `rgba8` `bgra8`, or a numeric heatmap: `u16le` `u16be` `i16le` `i16be` `u32le` `u32be` `i32le` `i32be` `f32le` `f32be` |
| `--palette NAME` | Palette for single-channel formats: `grey` `viridis` `inferno` `ocean` `amber` `diverging` |
| `--width PIXELS` | Pixels per row (512 unless Settings says otherwise) |
| `--offset BYTES` | Byte shown at the top left (decimal or `0x` hex) |
| `--cursor BYTES` | Where the cursor starts |
| `--zoom FACTOR` | Pixel scale, such as `2` or `0.5` |
| `--detect` | Look for the record width straight away |
| `--open` | Open the image, audio or video at the cursor |
| `--tool NAME` | Open a tool: `report` `reference` `structure-map` `size-map` `ask` `dot-plot` `trigrams` `images` `template` `columns` `protocol` `packets` `bits` `statistics` `characterise` `strings` `xor` `crypto` `checksums` `learn` `disassembly` `firmware` `unpacked` `forensics` `diff` `compare` `live` `workspace` `history` |
| `--layout NAME` | Start with a layout for this session: `overview` `network` `structure` `firmware` `signals` `forensics` `compare` `focus` (`default` is another name for `overview`), or the name of one you saved. An unknown name opens the Overview and says so in the status bar. The last session's arrangement is left as it is. |

Tools that need a run to show anything (Report, Unpacked, Statistics,
Protocol, Packets and Trigrams) start it when opened with `--tool`.

A file's own saved view (in `FILE.theviewer.toml` beside it, such as
`firmware.bin.theviewer.toml`) and these options take precedence over the
defaults in Settings.

## Printing a report

```sh
theviewer firmware.bin --report          # the report as text
theviewer firmware.bin --json > report.json
```

`--report` prints the file's [report](finding-structure.md#report) as text
and exits, without opening a window. `--json` prints it as JSON: the
summary, the regions, the likely record widths and the confident findings,
for scripts and CI.

## theviewer api

Everything theviewer can do to a file is a method of its data API: read
bytes, search, parse structures, list findings, make packet sets, edit,
undo, run any tool. `theviewer api` runs one method on a file and prints
its JSON result.

```sh
theviewer api bytes.read '{"start": 0, "len": 16}' firmware.bin
theviewer api analysis.overview firmware.bin
theviewer api --save bytes.write '{"start": 0, "data": "7f454c46"}' firmware.bin
theviewer api --describe
```

- The parameters are JSON; leave them out for a method that needs none.
  FILE can be left out too, for a method that needs no file, such as
  `api.version`.
- `--save` saves the file after the call, if the call changed it, so one
  command edits and saves. Use `history.transaction` for several edits in
  one call.
- A job method, one whose effect is `job` such as `report.run`, prints only
  its job id, as `{"job": "…"}`: the command exits without waiting for
  the result. Call the method's read form where there is one, such as
  `analysis.overview` rather than `analysis.overview_job`, or use
  `--report` or `--json` for the report.
- `--describe` lists every method with its parameters and result, plugins'
  methods included.
- An error is printed as JSON on standard error, with exit code 1.

Every call is allowed: the file is the one you named. Plugins load from
the usual places, so methods they register can be called too. The methods
are listed in [docs/api.md](../api.md).

## theviewer mcp

```sh
theviewer mcp firmware.bin
claude mcp add theviewer -- /path/to/theviewer mcp /path/to/firmware.bin
```

`theviewer mcp FILE…` serves the files you name over the [Model Context
Protocol](https://modelcontextprotocol.io) on standard input and output,
without a window, so Claude Code, Claude Desktop and other MCP clients can
inspect and edit them. It runs until the client closes the connection.

| Option | Effect |
| --- | --- |
| `--plugins DIR` | Load plugins from DIR instead of `./plugins` and `~/.config/theviewer/plugins`; give it more than once for several |
| `--all-tools` | List every API method as a tool. By default only the core methods and the plugins' are listed, with `api_search`, `api_describe` and `api_call` to reach the rest, which keeps the tool list a client holds in its model's context to about a quarter of the size |
| `--output-schemas` | List each tool's result schema too, which roughly doubles the tool list |

Every call is allowed, without asking, and nothing is written to disk
until the client saves. Setting it up in each client, the tools,
resources and prompts it offers, and the protocol revisions it speaks are
in [docs/mcp.md](../mcp.md).

## theviewer replay

```sh
theviewer replay "Telemetry frames" capture-*.bin --param key=5a --out decoded/
theviewer replay ./telemetry.theviewer-recipe.json a.bin b.bin --json
```

Runs a [recipe](history-and-recipes.md#recipes) on each FILE, each in a
workspace of its own. RECIPE is the name of one saved in
`~/.config/theviewer/recipes/`, or the path of a `.theviewer-recipe.json`
file.

| Option | Effect |
| --- | --- |
| `--param KEY=VALUE` | Give a value for one of the recipe's parameters; repeat for several |
| `--save` | Save each file the recipe ran to its end over itself, if the recipe changed it |
| `--out DIR` | Save each file the recipe ran to its end into DIR, under its own name, changed or not |
| `--json` | Print the reports as JSON |

Give `--save` or `--out`, not both. Without either, nothing is written:
the report is the point.

A report is printed per file: what each step did, or where and why it
stopped, and where the file was saved. A file the recipe stopped on is not
saved. The exit code is 1 when the recipe stopped on any file, or a file
could not be opened or saved. The report's JSON form and more examples are in
[docs/recipes.md](../recipes.md).
