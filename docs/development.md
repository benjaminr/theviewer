# Development

Building, testing and finding your way around the code. For the data API,
plugins and the MCP server, see [docs/api.md](api.md),
[docs/plugins.md](plugins.md) and [docs/mcp.md](mcp.md).

## Building and testing

```sh
cargo build --release
cargo test                  # unit tests, plus headless UI tests
cargo clippy --all-targets
cargo run --bin render_logo -- assets/logo.png   # redraw the logo
cargo run --bin api_docs                         # write docs/api.md from the method table
cargo run --bin import_catalog -- tika-mimetypes.xml   # regenerate catalog/tika.toml from Apache Tika
```

`tests/ui.rs`, `tests/tools.rs` and `tests/ui_recipes.rs` drive the real
application without a window, using `egui_kittest`. They click, drag and
type through the view, the toolbar, every tool, the panel layouts, the
settings and *Run recipe…*, so a change that breaks an interaction fails a
test. They use a temporary key store, never your Keychain. The tshark test
is skipped when tshark is not installed. `tests/api_cli.rs`,
`tests/replay_cli.rs` and `tests/mcp_stdio.rs` run `theviewer api`,
`theviewer replay` and `theviewer mcp` as separate processes, and the
`tests/reference_*.rs` files check that the reference notes cover what the
dissectors, parsers and signature catalogue find. A unit test fails when `docs/api.md` differs from what the
method table produces, so run `api_docs` after adding or changing a
method.

`check_reference` checks the built-in reference notes against their
sources; see [Checking the citations](guide/reference-notes.md#checking-the-citations).

## A corpus of real captures

`capture_corpus` tests the packet code against
Wireshark's sample captures and against tshark:

```sh
cargo run --release --bin capture_corpus -- fetch   # download the samples
cargo run --release --bin capture_corpus -- run     # read, dissect, compare, report
```

`fetch` downloads the captures linked from
[wiki.wireshark.org/SampleCaptures](https://wiki.wireshark.org/SampleCaptures)
(about 600 files, at most 50 MB each and 1.5 GB in all, one at a time with a
pause between them, backing off when the wiki asks) into
`~/.cache/theviewer/corpus/` (or `$THEVIEWER_CORPUS_DIR`), unpacks gzip,
bzip2, xz, zip and tar files, and records each file's URL, size and SHA-256
in `manifest.json`. Run again, it fetches only what is missing. The sample
captures carry no licence statement, so they stay in that cache: the tool
refuses a directory inside the source tree, nothing in the repository reads
them, and the tests use captures built by hand.

`run` reads the first 2,000 packets of every capture with our readers and
dissectors, filters, flows, pcap export, the Reference stack and the
detectors, catching and recording any panic with its file and packet, and
listing slow files. When tshark is installed it decodes the same packets and
compares them with ours: the innermost protocol, each layer's start and
length, and each field both name (mapped by hand in `corpus/compare.rs`),
then counts which protocols tshark found that we do not decode and whether
the reference notes name them by filter name, port, EtherType or IP
protocol. Reports go to the cache's `report/` directory: `summary.md`,
`coverage.csv`, `mismatches.csv` and `failures.csv`. They hold counts,
protocol filter names and our own layer and field names, never tshark's
text.

## How the code is organised

| Module | Responsibility |
| --- | --- |
| `document.rs` | Piece table over a memory-mapped file plus an append-only edit buffer: cheap edits on any size, undo and redo with named steps, and safe saving. |
| `raster.rs` | Turns bytes into pixels for a format, palette and row stride, in parallel. |
| `view.rs` `hex.rs` | The raster view (texture caching, scrolling, zoom, selection) and the inspector and hex dump. |
| `app.rs` | Application state, shortcuts, editing commands, toolbar, menus and background analysis. |
| `analysis.rs` `structure.rs` | Period scan, column entropy and the entropy map; the period chart. |
| `patterns.rs` | Pattern recognisers and how overlapping findings are resolved. |
| `plugin.rs` | The plugin traits, `Finding`, `Field`, `Category` and the `Registry`. |
| `catalog.rs` | The signature catalogue and its matching engine. |
| `parsers/` | Structure parsers for executables, images, archives, captures, ASN.1, disks and serialisation formats. |
| `plugins.rs` `plugins/` | The sandboxed Lua plugin host, and what scripts reach the data API and the bus through. |
| `compress.rs` `unpack.rs` | Stream detection, bounded decompression and compression; recursive extraction. |
| `media.rs` `player.rs` | Media detection and decoding; the image, audio and video viewer. |
| `explain.rs` `hilbert.rs` `region_colours.rs` | The whole-file report and map; the Hilbert and Morton curve layouts; colours by region, block class and entropy. |
| `columns.rs` `protocol.rs` `templates.rs` | Record profiling, protocol analysis, and the template language. |
| `packets.rs` `packets/` `panel_packets.rs` `panel_packets_view.rs` `panel_packets_grid.rs` `panel_packets_tshark.rs` | Packet sources (framing, pcap and pcapng, splits by width, length field or pattern), packets laid out as rows with column operations, dissection, conversations and streams, the filter language, pcap export and in-place editing, decoding with tshark; the packet viewer panel. |
| `corpus.rs` `corpus/` `bin/capture_corpus.rs` | The developer tool that fetches sample captures and compares our dissection with tshark's. |
| `stats.rs` `strings.rs` `xor.rs` | Statistics and randomness tests, strings, XOR key recovery. |
| `disasm.rs` `pointers.rs` `checksums.rs` `diff.rs` | Disassembly, the pointer graph, checksums, file comparison. |
| `sources.rs` `plot.rs` | Live sources, watching and recording; plots and bytes as audio. |
| `analysis_tools.rs` `analysis_stats.rs` `analysis_tabs.rs` `dock.rs` `workbench.rs` | The tool panels and the state behind them. |
| `assistant.rs` | *Ask*: a streaming Claude API client with tools, on a background thread. |
| `api.rs` `api/` | The data API: one table of methods with JSON schemas, run against the window or a headless workspace; Ask's tools, `theviewer api` and [docs/api.md](api.md) come from it. |
| `mcp.rs` `mcp/` | `theviewer mcp`: a hand-written, synchronous MCP server over stdio; tools from the method table, resources and subscriptions from the bus, prompts. |
| `journal/replay.rs` `journal/anchors.rs` `journal/recipe.rs` `recipes.rs` `recipes/` `api/recipes.rs` | Running steps again: the recipe runner and anchors, the recipe file, recipes on disk, `theviewer replay`, "Run recipe…" and `recipes.*`. |
| `journal.rs` `journal/` `panel_history.rs` | The journal of every call by caller, the timeline of steps in effect and undone, inverses, going back and playback; the History tab. |
| `bus.rs` `bus/` `panel_workspace.rs` | The workspace bus of retained facts and events that the tools share; the Workspace tab. |
| `reference.rs` `panel_reference.rs` `reference_check.rs` `bin/check_reference.rs` | The reference notes (built in from `reference/*.toml`, and your own), RFC fetching, the Reference tab, and the citation checker. |
| `api/permissions.rs` `confirmations.rs` | Who is calling the API and what each client may change; the window that asks you about a change. |
| `layout.rs` `layouts.rs` `packing.rs` | Dockable panels; recommended and saved layouts; toolbar packing and reordering. |
| `legend.rs` | The legend bar: the colouring in effect and each highlight layer, with toggles. |
| `freshness.rs` | Which document version each tool's result describes; refreshing cheap views after edits and marking the rest out of date. |
| `selection.rs` `selection_ops.rs` `selection_menu.rs` `selection_drag.rs` `folds.rs` | Range, column and multi-range selections; the byte operations on them; the Selection menu and floating toolbar; moving, resizing and nudging by hand; skipped (folded) ranges. |
| `search.rs` `bookmarks.rs` `findings.rs` `commands.rs` | Search, bookmarks and the sidecar file, the findings list, the command palette. |
| `settings.rs` `preferences.rs` `config.rs` | The settings window and API key storage; startup defaults; where settings live. |
| `theme.rs` `logo.rs` | Colours and shared widgets; the logo, drawn in code. |
| `vendor/egui_dock` | egui_dock 0.21.1 with one addition, wrapping tab bars (`TabBarStyle::wrap_tabs`). |
