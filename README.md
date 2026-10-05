<img src="assets/logo.png" alt="" width="96" align="right">

# theviewer

A fast binary viewer. Load any file, raster its bytes as pixels, then
reshape and edit the data until the structure shows itself.

- Memory-maps the file and renders only the rows on screen, so multi-gigabyte
  files open instantly and scroll at frame rate.
- Edits go into a piece table: insert, delete, overwrite, move and bit-shift
  are cheap on any file size, with unlimited undo and redo.
- Twelve pixel formats (1-bit through 32-bit colour, plus a "byte class"
  colouring), five colour palettes, arbitrary width, row padding, and a
  byte- or bit-level origin.
- A live hex dump and value inspector stay in sync with the raster view.
- Structure detection: a period scan proposes row widths, and an entropy
  strip beside the scrollbar shows where headers, text, tables and
  compressed data live.
- Pattern highlights: counters, timestamp sequences, text, float arrays,
  offset tables, file signatures, padding and compressed-looking regions are
  recognised in the visible region and listed in Findings. Outlining them in
  the raster and hex views is off by default; turn it on with *Patterns* or
  `H`, or for every start in Settings.
- Startup defaults: **Settings** (`Cmd+,`) chooses what a new window starts
  with: pattern highlights and which kinds to show, the findings list, pixel
  format, palette, width, zoom, and whether to detect the width when a file
  opens. They are saved in `~/.config/theviewer/preferences.json`. A file's
  remembered view and command-line options still take precedence.
- Compression: gzip, zlib, bzip2, xz, zstd and LZ4 streams are found and
  verified by trial decompression; any block can be decompressed into a new
  document or in place, and a selection can be compressed back.

## Build and run

Requires a Rust toolchain (`rustup`).

```sh
cargo build --release
./target/release/theviewer path/to/file.bin
./target/release/theviewer firmware.bin --format rgb8 --width 320 --offset 0x1000 --zoom 2
./target/release/theviewer records.dat --detect
./target/release/theviewer image.bin --cursor 0x7346
./target/release/theviewer --help
```

Files can also be dropped onto the window.

## Using it

**Find your way around.** `Cmd+K` opens the command palette: every action,
searchable, with its shortcut. Right-click anywhere in the raster or the hex
dump for the actions that apply to that byte or finding. The *Findings* panel
in the right-hand column lists everything detected around the view, filtered
by text, category and confidence; click an entry to select it, right-click
for Decompress or Bookmark. `Cmd+F` finds hex bytes, text, UTF-16 text or an
integer (`F3` and `Shift+F3` step through matches), `Cmd+G` goes to an
offset, and `Cmd+B` bookmarks the cursor or selection (`F2` cycles through
bookmarks). Bookmarks and the view shape are saved beside the file in
`name.theviewer.toml`, so a session survives a restart.

**Media.** When the cursor is on an image, audio or video stream, even one
buried inside a larger file, a *Media* group appears in the toolbar. Press
it, or `Cmd+Enter`, or right-click and choose *View image* / *Play audio* /
*Play video*. Images open in a viewer with fit and 1× to 8× zoom, drag to
pan, a pixel readout, and animated GIF playback (PNG, JPEG, GIF, BMP, WebP,
TIFF, ICO). Audio plays with a waveform you can click to seek (WAV, MP3,
FLAC, Ogg Vorbis, AAC, M4A, AIFF, CAF), decoded in pure Rust. Video (MP4,
MOV, WebM, Matroska, AVI, MPEG-TS, FLV, Ogg Theora) plays through `ffmpeg`
with synchronised sound, a seek bar and frame stepping; without `ffmpeg` the
window offers *Open externally* instead. `Space` plays and pauses, and *Save…*
writes the media bytes to a file. `--open` opens the media at `--cursor` on
launch.

**Arrange the workspace.** Every panel is a dockable pane: the view, the
inspector, findings, the hex dump, the period chart and each tool below.
Drag a pane's tab to any edge of another pane to split it, onto a pane's
tab bar to stack it as a tab, or out of the window to float it. The arrow
on each pane collapses it; the cross closes it, and *View › Panels* brings
it back. When a pane holds more tabs than fit across it, they wrap onto
extra rows rather than scrolling. The toolbar's control groups are packed
into as few rows as the window width allows, and keep their places while
you work. Drag a group by its caption or edge to put it somewhere else (a
line shows where it will land; drop below the last row to start a new
one). Your arrangement is saved in `~/.config/theviewer/toolbar.json`;
*View › Layout › Arrange toolbar automatically* goes back to packing.
*View › Layout* has presets (Default, Everything on the right, Tools on the
left, Focus on the view), and `--layout right` starts with one.
`Cmd+J` collapses or expands the tools. Your arrangement is saved in
`~/.config/theviewer/layout.json` and restored next time.

**The tools.** Open any of these from the *Tools* menu, the palette, or
*Analyse* in the right-click menu:

- **Report**: a plain-language overview of the whole file ("Firmware-like
  image: a gzip stream at 0x2100, a WAV at 0xA400…"), with every sentence
  linked to its bytes, and a coloured file map above the view.
- **Ask**: ask Claude (`claude-opus-5-5`) about the file (`Cmd+L`). It sees
  the cursor, selection, findings and nearby bytes, and can read, search,
  scan and parse the file itself through tools. Offsets in its answers are
  links; templates it writes can be applied with one click. Ask is off until
  you add an Anthropic API key in **Settings** (`Cmd+,`, or the *Add API
  key…* button on the Ask tab). On macOS the key is kept in your Keychain;
  elsewhere in `~/.config/theviewer/credentials`, readable only by you.
  `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and an `ant auth login` session
  also work. Server-side refusal fallbacks are enabled.
- **Template**: describe a structure in a small language
  (`struct Chunk { id: char[4]  len: u32  data: bytes[len] }`) and see it
  decoded as a field tree and a records table; or select a few records and
  *Infer from selection* to have one proposed. See `docs/templates.md`.
- **Columns**: for fixed-size records, a per-byte-position profile (constant,
  counter, low-cardinality, text, random) with the bytes grouped into likely
  fields; apply them as a template in one click.
- **Protocol**: for captures, serial logs and files of messages. Detects the
  framing (sync words, delimiters, length prefixes, fixed size), splits the
  stream into messages, and identifies message types, sequence numbers,
  lengths, timestamps and checksums across them.
- **Statistics**: byte histogram, the `ent` randomness tests (entropy,
  chi-square with p-value, serial correlation, Monte Carlo π) with a plain
  verdict such as "Compressed" or "Encrypted or random", a 256×256 byte-pair
  fingerprint, entropy and compressibility along the data, and the most
  repeated byte sequences.
- **Strings**: ASCII, UTF-8 and UTF-16 strings, tagged when they look like
  URLs, paths, IP addresses, UUIDs, versions, format strings or keys.
- **XOR**: recovers single-byte and repeating-key XOR keys; preview the
  decode as a document or apply it as an undoable edit.
- **Disassembly**: x86, ARM, RISC-V, MIPS and PowerPC via Capstone, with the
  architecture taken from ELF, PE or Mach-O headers or guessed from the
  bytes, and branch targets you can follow.
- **Unpacked**: recursive extraction of ZIP, tar and compressed streams into
  a browsable tree; open or save any node.
- **Checksums**: CRC-32, Adler-32, MD5, SHA-1, SHA-256 and simple sums of the
  selection, plus *Find the checksum*, which works out which stored value is
  a checksum over which bytes.
- **Diff**: compare with another file; inserts and deletes are found, not
  just flipped bytes, and the other file scrolls in step with this one.
- **Live**: open a URL, a serial port (`serial:/dev/cu.usbserial@115200`), a
  block device (`/dev/rdisk2`, needs sudo), or process memory (`pid:1234`,
  Linux only; macOS blocks it). Watch a file and see appended bytes
  highlighted as it grows, and record its history to step back through
  versions.

The View menu also offers a **Hilbert-curve layout**, which keeps nearby
bytes together in 2D so structure shows without choosing a width, and
**pointer arrows** from values that look like offsets to their targets.
*Plot selection* draws the bytes as a time series, histogram, X/Y scatter or
frequency spectrum,
and *Play selection as audio* plays any bytes as PCM at a chosen rate.

**Structure.** When the cursor lands on something a parser understands, the
inspector shows its field tree: executables (ELF, PE, Mach-O), images (PNG,
JPEG, GIF, BMP), archives (ZIP, tar, ar, cpio), packet captures, DER and
X.509, partition tables and filesystem superblocks, and schemaless
serialisations. Clicking a field selects its bytes; the path to the field
under the cursor is shown beside the title.

**Shape.** The toolbar's *Format* picks how bytes become pixels and, for
single-channel formats, which palette colours them. Drag the *Width* slider
to find the stride of repeating structures; the bytes-per-row readout updates
as you go. *Pad* skips extra bytes after each row. *Origin* sets which byte
(and bit) lands at the top-left pixel; *To cursor* aligns the view to the
selected byte.

**Navigate.** Click the raster or the hex dump to place the cursor. Drag to
select. Scroll for rows, Shift+scroll to pan sideways, ⌘+scroll or pinch to
zoom. The scrollbar on the right of the raster view shows the row under the
thumb while you drag.

**Edit.** Type hex digits to overwrite the byte at the cursor, or press
Insert to switch to insert mode. The *Byte at cursor* / *Selection* group
offers delete, fill, invert, reverse and bit-mirror. *Shift bits* moves the
selection's bit stream left or right across byte boundaries; *Move* cuts the
selection and re-inserts it elsewhere. Clicking a bit in the inspector flips
it. Everything is undoable.

**Save.** ⌘S writes to the original path through a temporary sibling file
and an atomic rename, then reopens it. ⇧⌘S saves elsewhere.

### Keyboard

| Keys | Action |
| --- | --- |
| `0–9` `A–F` | Type hex at the cursor |
| `Ins` | Toggle overwrite / insert mode |
| `← → ↑ ↓` | Move by a pixel / row (Shift extends the selection) |
| `PgUp` `PgDn` `Home` `End` | Move by a page / to the ends |
| `⌫` `Del` | Delete the selection or byte |
| `⌘Z` `⇧⌘Z` | Undo, redo |
| `⌘C` `⌘X` `⌘V` `⌘A` | Copy (as hex), cut, paste, select all |
| `[` `]` | Width −1 / +1 (Shift for 16) |
| `,` `.` | Origin −1 / +1 byte |
| `Alt+←` `Alt+→` | Origin −1 / +1 bit |
| `−` `+` | Zoom out / in |
| `⌘O` `⌘S` `⇧⌘S` `⌘N` | Open, save, save as, new |
| `Esc` | Clear the selection |
| `Cmd+K` | Command palette |
| `Cmd+F` `F3` `Shift+F3` | Find; next and previous match |
| `Cmd+G` | Go to offset |
| `Cmd+B` `F2` `Shift+F2` | Bookmark; next and previous bookmark |
| `Cmd+Enter` `Space` | Open the image, audio or video at the cursor; play and pause |
| `Cmd+J` `Cmd+L` | Collapse or expand the tools; ask Claude about the file |
| `Cmd+,` | Settings (startup defaults, API key) |
| `H` | Toggle pattern highlights |
| `Cmd+D` | Flip between a compressed block and its contents |
| `Cmd+E` | Extract the selection or stream to a file |
| `Cmd+[` | Back to the parent document |
| `?` | Keyboard shortcut window |

Shortcuts use Cmd on macOS; eframe maps them to Ctrl elsewhere.

## Extending it

Everything that recognises, parses or decodes bytes is a plugin behind the
traits in `src/plugin.rs`: `Detector` (scan a window, return findings),
`Parser` (parse a structure at an offset into a field tree) and
`CodecPlugin` (decode and encode a block). Built-ins register through the
same `Registry` as everything else, so the UI treats them identically.

- **Signature catalogue** (`src/catalog.rs`, `catalog/*.toml`): declarative
  signatures with offsets, masks, nested conditions and extent rules.
  `catalog/tika.toml` is generated from Apache Tika's mimetypes database by
  `cargo run --bin import_catalog`; `catalog/curated.toml` adds firmware,
  filesystems, bytecode, ROMs, protocols and more. Drop your own TOML files
  into `~/.config/theviewer/catalog/`.
- **Structure parsers** (`src/parsers/`): built on goblin, image, pcap-parser,
  etherparse, der-parser, x509-parser and mbrman.
- **Lua plugins** (`src/plugins.rs`, `plugins/*.lua`): scripts register
  detectors, parsers, codecs and palette actions through a small sandboxed
  API; see `docs/plugins.md`. *Reload plugins* in the View menu picks up
  changes without restarting.

## Architecture

| Module | Responsibility |
| --- | --- |
| `document.rs` | Piece table over a memory-mapped original plus an append-only edit buffer. Reads are a few `memcpy` calls; edits are O(pieces). Undo/redo records, atomic save. |
| `raster.rs` | Converts a byte window to RGBA pixels for a given format, palette and row stride. Rows are rasterised in parallel with rayon above a size threshold. |
| `ops.rs` | Pure byte and bit transformations (shift, invert, mirror) and hex parsing. |
| `plugin.rs` | The plugin traits (`Detector`, `Parser`, `CodecPlugin`), `Finding`, `Field`, `Category` and the `Registry`. |
| `catalog.rs` | Signature catalogue model, loader, Aho-Corasick matching engine and extent rules. |
| `parsers/` | Structure parsers for executables, images, archives, captures and protocols, ASN.1, disks and serialisation. |
| `plugins.rs` | Lua plugin host with a sandboxed API for detectors, parsers, codecs and actions. |
| `media.rs` | Media detection, image and GIF decoding, audio analysis (symphonia), and the `ffmpeg` video pipeline. |
| `player.rs` | The media window: image viewer, audio player with waveform, video player with audio sync. |
| `settings.rs` | API key storage (Keychain or private file) and the settings window. |
| `logo.rs` | The logo, drawn in code: window icon, empty view, and `cargo run --bin render_logo` for `assets/logo.png`. |
| `preferences.rs` `config.rs` | Startup defaults chosen in Settings; where settings files live. |
| `stats.rs` `strings.rs` `xor.rs` | Byte statistics and randomness tests, string extraction, XOR key recovery. |
| `columns.rs` `protocol.rs` | Record column profiling; protocol framing and field analysis. |
| `analysis_tools.rs` `analysis_stats.rs` | The dock tabs for those tools. |
| `layout.rs` | The dockable workspace (egui_dock): panes, presets, saving the arrangement. |
| `packing.rs` | Packs the toolbar's control groups into the fewest rows, and lets you drag them into your own order. |
| `vendor/egui_dock` | egui_dock 0.21.1 (MIT) with one addition, `TabBarStyle::wrap_tabs`, for multi-row tab bars. |
| `dock.rs` `workbench.rs` `analysis_tabs.rs` | The tools dock, its tabs, and the state behind them. |
| `assistant.rs` | "Ask the file": streaming Messages API client with tools, run on a background thread. |
| `templates.rs` | Template language, evaluator and struct inference. |
| `explain.rs` `hilbert.rs` | Whole-file report and file map; Hilbert-curve layout. |
| `unpack.rs` | Recursive extraction tree. |
| `disasm.rs` `pointers.rs` `checksums.rs` `diff.rs` | Disassembly, pointer graph, digests and checksum search, two-file diff. |
| `sources.rs` `plot.rs` | Live sources, watch mode and recording; plotting and bytes as audio. |
| `commands.rs` | The command table and the command palette. |
| `findings.rs` | The findings panel and bookmark list. |
| `search.rs` | Hex, text, UTF-16 and integer search over the document. |
| `bookmarks.rs` | Bookmarks and remembered shape, persisted in a sidecar TOML file. |
| `analysis.rs` | Period scan (autocorrelation with robust peak picking and harmonic marking), column entropy gain, block entropy map. All parallel with rayon. |
| `structure.rs` | The Structure panel: periodogram and candidate chips. |
| `compress.rs` | Header detection, verified stream scanning, bounded decompression (gzip, zlib, raw deflate, bzip2, xz, lzma, zstd, LZ4) and compression (zlib, gzip, deflate, bzip2, LZ4). Pure Rust. |
| `patterns.rs` | Pattern recognisers (strided sequence walker for counters, timestamps, offsets and floats; text, padding, entropy and signature scanners) and the evidence-based overlap resolution. |
| `app.rs` | Application state, shape maths, shortcuts, editing commands, toolbar, menus, status bar, help window, and the background analysis threads. |
| `view.rs` | The raster panel: texture caching, scrolling, zoom, selection overlay, pixel grid, scrollbar. |
| `hex.rs` | Inspector and hex dump panel. |
| `theme.rs` | Colour scheme and small shared widgets. |

The raster texture is rebuilt only when the document version, shape, scroll
position or visible row count changes; zooming is a free GPU scale with
nearest-neighbour filtering. The status bar shows the last raster time.

## Tests

```sh
cargo test
```

Unit tests cover the piece table (insert, delete, overwrite, undo, coalescing,
save round-trip), the rasteriser (bit order, layout, stride, palettes), the
analysis algorithms (recovering a known record length, flagging harmonics,
ignoring noise) and the bit-shift and parsing helpers.

`tests/ui.rs` drives the real application headlessly with `egui_kittest`:
clicking and dragging in the raster, typing hex, undo, insert mode, keyboard
navigation, every toolbar button, detect-width end to end, every format and
palette at extreme widths, offsets and zooms, toolbar packing and
reordering, settings, and an empty document. These exist so that no click
or key can panic the app. `tests/tools.rs` does the same for every tool in
the dock, the panel layouts, watch mode and the API key flow (with a
temporary key store, never the real Keychain).

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option.

Bundled third-party material keeps its own licence:
`catalog/tika.toml` is derived from Apache Tika (Apache-2.0, see
`catalog/LICENSE-tika.txt`), and `vendor/egui_dock` is a modified copy of
egui_dock (MIT, see `vendor/egui_dock/LICENSE`).
