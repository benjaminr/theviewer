# Every action through the API: the inventory

Status: phase 6 of `shared-knowledge-and-api.md`; the foundation is built, and
the four areas below convert the rest.

Phase 6 makes every action the person takes in the window a method call made
as `Caller::Panel`, so phase 7 can journal it, replay it and turn an analysis
into a recipe. This document lists every action in the window, the method
that expresses it, and the area that converts it. It ends with a brief for
each area's work.

## How an action becomes a method call

- **`ViewerApp::perform(method, params)`** (`src/actions.rs`) calls the
  method through `api::call` as `Caller::Panel` and returns its JSON result,
  including the ids of what it made (a packet set, a job, a document). When
  the call fails, the status bar says why. A panel with a better place for
  the error (its own note) shows it there as well, from `app.status`.
- **`perform_typed::<R>(method, params)`** takes any `Serialize` params (the
  method's own params struct, or `json!`) and returns the method's result
  struct.
- **`perform_later(method, params)`** is for a panel drawn with its state
  lent out (`panels::show`, `panels::with`, `with_state`) whose method writes
  that same state, as `packets.sets.create` does through `show_api_set`. A
  write made during the draw lands on the placeholder and is lost, so the
  call is held and run at the start of the next frame.
- **Parameters carry everything needed to repeat the action.** That means
  the selection acted on, the width set, how a set was split and decoded,
  and a tool's options. A method must never read state silently from a
  panel. The selection is passed explicitly, never left to "the document's
  selection".
- **Convert functions, not call sites.** When an action is a `ViewerApp`
  function called from several places (menus, palette, shortcuts, toolbar,
  context menu, other panels), convert the function's body. For example,
  `apply_operation`, `start_period_scan` and `change_width` cover every way
  in at once, and other areas' files need no edits.
- **Keep the app's own automatic work off the person's journal.** Work the
  app starts by itself goes to an internal function that does not call
  `perform`: the scan when a file opens, a layout's first capture, a
  refresh after an edit. For example, `scan_periods_from(…, "tool:period-scan")`
  sits beside `start_period_scan`.
- **Window-only effects.** A method whose effect only the window can
  complete (filling a chart, showing a panel) uses `workspace.window()`,
  which returns `Some(&mut ViewerApp)` in the window and `None` headless.
  Headless, the method does what it can, such as returning its result as
  the job's result. Adding a hook to the `Workspace` trait is a shared-hub
  edit; see the briefs.
- **The person's steps are named by what they did** ("Invert"); a client's
  carry its name ("Invert by mcp:claude-code"). See `Caller::label`.
- **Tests** prove the API path with `crate::actions::take_performed()`,
  which returns the `(method, params)` that `perform` called on this
  thread. They can also check that the bus or document shows `panel` as
  the producer.

## What is journalled

The design's rule (§4 "The journal") decides which actions need a method:

- **Journalled (J), a method call.** These are:
  - edits;
  - selection and cursor changes the person makes;
  - view-shape changes that affect analysis: pixel format, width, origin,
    bit shift, row padding and folds;
  - jobs started;
  - facts the person publishes: templates applied, findings pinned,
    bookmarks;
  - documents opened, made, derived, saved or exported;
  - packet sets, their decoding and their export.
- **View only (V), no method.** These stay direct:
  - zoom, scrolling, panning, hovering and emphasis;
  - panel layout, docking, tabs, collapsing headers and pane visibility;
  - palette (colours), row difference, curve layout and colours, overlay
    layers and highlight toggles;
  - media playback, plots and the help window;
  - settings and preferences (permissions and the API key must never be
    writable by clients);
  - the clipboard (copying only reads);
  - a tool's input fields until the tool runs (they become that method's
    params).
- **Drags and keys that repeat.** A drag sends one call when it ends
  (`drag_stopped`), not one a frame. Arrow-key cursor moves and slider
  steps each send a call. The journal (phase 7) merges consecutive calls of
  one view method into the last one.

Effects: `R` read, `E` edit, `V` view, `J` job (the method's `Effect`).

## Area A: Editing

Owns `src/api/edits.rs`, `src/api/selection.rs` and `src/api/search.rs`.

| Action | Where | Method | Journal |
| --- | --- | --- | --- |
| Invert, Reverse, Mirror bits, Fill, XOR/add/subtract, Shift or rotate bits, Swap byte order, Number as counter, Duplicate, Delete, Compress as, Decompress (selection) | Selection menu (raster/hex context menu, Findings, Packets), floating toolbar, toolbar Selection group, palette `edit.invert`/`edit.reverse`/`edit.mirror`/`edit.fill`/`edit.delete`, Del/Backspace with selection, toolbar Shift bits ◀▶ | `transform.apply {selection, operation}` (**done**, via `apply_operation`) | J |
| Insert before/after each range (I window) | `selection_menu::show_insert_dialog` | `transform.apply {insert_before\|insert_after}` (done via `apply_operation`) | J |
| Insert at cursor | toolbar Insert, I window "At cursor", palette `edit.insert` (`insert_from_fields`) | `bytes.insert {at, data}` | J |
| Type hex digits (overwrite or insert, nibble by nibble) | `app.rs type_hex_digit` | `bytes.write` / `bytes.insert`, NEW param `coalesce` | J |
| Backspace with nothing selected | `app.rs backspace` | `bytes.delete {start, len: 1}` | J |
| Toggle overwrite/insert typing | Ins, toolbar Typing, Edit menu, palette `edit.mode` | none (the typing calls say write or insert) | V |
| Toggle a bit of the cursor byte | inspector bit chips (`toggle_bit_at_cursor`) | `bits.write {bit_start, bits}` | J |
| Cut | Cmd+X, Edit menu, palette `edit.cut` | copy (V), then `transform.apply {delete}` | J |
| Copy, Copy as… | Cmd+C, Edit menu, Selection menu "Copy as" | none (reads) | V |
| Paste (replace selection, insert or overwrite at cursor) | Cmd+V, Edit menu, palette `edit.paste`, `Event::Paste` | `bytes.replace` / `bytes.insert` / `bytes.write` | J |
| Move selection by dragging it | `selection_drag.rs finish_drag` (`move_selection_to`) | NEW `bytes.move` | J |
| Move to… offset | Selection menu "Move to…" | NEW `bytes.move` | J |
| Move ◀▶ by N bytes | toolbar Move (`move_target`) | NEW `bytes.move` | J |
| Nudge with Alt+arrows | `selection_drag.rs nudge_selection` | NEW `bytes.move` (ranges), `transform.apply {rotate_bytes}` (columns) | J |
| Undo / Redo | Cmd+Z / Shift+Cmd+Z / Cmd+Y, Edit menu, toolbar, palette `edit.undo`/`edit.redo` | `history.undo` / `history.redo` | J |
| Select all | Cmd+A, Edit menu, palette `edit.select_all` | `selection.set {range: [0, len]}` | J |
| Click a byte; right-click (moves cursor first) | `view.rs click_byte`, `hex.rs show_hex_dump` | `cursor.set` | J |
| Shift+click, drag, Shift+drag, resize by an end | `view.rs begin_drag`, `selection_drag.rs` | `selection.set {range}` on release | J |
| Alt+drag column select | `view.rs begin_column_drag` | `selection.set {columns}` on release | J |
| Cmd+click / Cmd+drag / multi-select mode add or toggle | `view.rs add_to_selection_at`, `toggle_selection_range` | `selection.set {ranges}` (the panel computes the new ranges) | J |
| Multi-select mode on/off | M, toolbar, palette `edit.multi_select` | none | V |
| Arrow keys, Page Up/Down, Home/End (Shift extends) | `handle_shortcuts` (`move_cursor_by`, `set_cursor`) | `cursor.set` / `selection.set` | J |
| Esc clears secondary ranges | `handle_shortcuts` | `selection.set` | J |
| Find next / previous (wraps) | F3 / Shift+F3, toolbar Next/Prev/Enter, Go menu, palette `view.find_next`/`view.find_previous` | `search.find {query, mode, from, backwards}` then `selection.set` | J |
| All matches | toolbar "All matches" (`select_all_matches`) | `search.find_all` then `selection.set {ranges}` | J |
| Find field, mode, LE | toolbar Find, Cmd+F, palette `view.search` | none (become `search.*` params) | V |
| Select a field in the structure tree | `hex.rs show_field` | `selection.set` | J |
| Inspector number rows | `hex.rs show_inspector` | `numbers.decode` (read; there is no number editing) | V |
| Select a finding / Cmd+click it | Findings list, context menu "Select this finding" (`select_finding`; also the stream at the cursor, Reference fields and Structure map segments) | `selection.set` | J |
| Typing a value into a Selection menu field | key, fill, counter and move fields | none (params of the operation) | V |

**New methods (A):**

- `bytes.move {doc?, ranges: [[start, len]…], to, expect_version?}` (E).
  Cuts the ranges and puts them at `to`, counted before the cut
  (`selection_ops::moved_destination`), as one step, and selects the moved
  bytes. Lives in `edits.rs`.
- `bytes.write`/`bytes.insert` gain `coalesce: bool` (default false). This
  joins the previous step when that step wrote the same byte, so a typed
  byte (two nibbles) is one undo step. Lives in `edits.rs`.
- Optional: `search.find_and_select {query, mode, from, backwards}` (V), if
  two calls per F3 read badly. Lives in `search.rs`.

## Area B: Packets

Owns `src/api/packet_sets.rs` and `src/api/packets.rs`, plus the
`src/panel_packets*.rs` files.

| Action | Where | Method | Journal |
| --- | --- | --- | --- |
| Split the selection by row width | palette `tools.packets_rows`, context menu Packets, panel "From the selection" | `packets.sets.create {from: split_fixed, start, len, record_len, …decoding}` (**done** for palette and context menu, via `split_selection_by_row_width`; the panel's own button is not) | J |
| From protocol framing | panel, palette `tools.packets_framing`, context menu | `packets.sets.create {from: protocol_framing}`, waiting for the analysis job when none is published | J |
| Find captures | panel "Find captures" | NEW `packets.find_captures` | R |
| Open a capture (chip, context menu "Open capture at", Findings "Open in packet viewer") | `load_capture`, `open_capture_at` | `packets.sets.create {from: capture, start}`, NEW `gunzip` | J |
| Selection as one packet / Add selection as packet | panel, palette `tools.packets_selection`, context menu | NEW `packets.sets.add_packets {set, ranges}` | J |
| Split by length | panel DragValue + "Split by length" | `packets.sets.create {from: split_fixed}` | J |
| Split by delimiter (+ "starts each packet") | panel | `packets.sets.create {from: pattern, pattern, pattern_mode}` | J |
| Split rules form: fixed width, length field, pattern, range, skip; "Split" | `panel_packets_grid.rs show_split_rules` | `packets.sets.create {…}` (the form fields are params) | J |
| Auto-detect length field | split rules | NEW `packets.detect_length_field {start, len}` | R |
| Find them in this document (foreign set) | `show_status` | NEW `packets.sets.refresh {set, doc}` | J |
| Link override | panel link combo | `link` on create; NEW `link` on `packets.decode_as` | J |
| Decode frames as: Auto/Detect now, a protocol, Field guesses, Protocol template, a named template | `show_frame_decoding` | `packets.decode_as {set, protocol\|detect\|template}`; NEW `template_name`, `template: "protocol"` | J |
| Decode with tshark (shown or focused packets); Use tshark for everything | `panel_packets_tshark.rs`, detail | NEW `packets.tshark_decode {set, indices?, filter?, mode}` (job) | J |
| Cancel tshark | tshark controls | `jobs.cancel` | J |
| Display filter, Clear | `show_filter` | none in the panel (V); `filter` is a param of list, export and conversations | V |
| Click, Cmd+click or Shift+click a row, or a row label or cell in the grids | `show_table`, grid `click_cell` | `selection.set {range\|ranges}` on the packets' bytes (keeping the panel's producer, see the brief) | J |
| Sub-view tabs, layout List/Raster/Hex, grid colouring, pixel size, ASCII, align, headers | panel, grid | none | V |
| Click a layer or field (selects its bytes); "Reference" | detail tree | `selection.set`; `reference.lookup` (read) | J |
| Edit a field value ("Write") | `show_field_editor` | NEW `packets.write_field {set, index, offset, len, value, little_endian}` | J |
| Type hex in the packet hex editor | `handle_hex_keys` | `bytes.write {…, coalesce}` (A's param) | J |
| Packet hex editor cursor and arrows | hex editor | `cursor.set` on click; arrows V | J/V |
| Column ops: Invert, Fill, XOR, ADD, Set, Number, Swap 2/4/8 | `show_column_operations` | NEW `packets.columns.apply {set, first, width, indices?, op…}` | J |
| Delete column | grid | NEW `packets.columns.delete {set, first, width, indices?}` | J |
| Copy column hex/CSV | grid | NEW `packets.columns.read` (read) or V | V |
| Column/block selection in the grids | grid ruler, Alt+drag | none (params of column ops) | V |
| Export pcap (shown packets / selected packets) | `show_operations` | `packets.export_pcap {set, filter\|indices, path}`; NEW `indices` | J |
| Delete packets | `show_operations` | NEW `packets.delete {set, indices}` | J |
| Save bytes… / Open as document (packets) | `show_operations` | NEW `packets.extract {set, indices, path?}`; `documents.derive` (D) | J |
| Fix checksums | `show_operations` | NEW `packets.fix_checksums {set, indices}` | J |
| Invert / Fill / XOR packets (or one field of each) | `show_operations` | NEW `packets.apply {set, indices, op, key?, field?}` | J |
| Selection menu inside the panel | `show_operations` | `transform.apply` (A, done) | J |
| Open packet as document | detail | `documents.derive` (D) | J |
| Follow stream; conversation "Follow" | detail, conversations | `packets.follow_stream {set, index}` (read; the panel shows it) | V |
| Conversation / endpoint "Filter" | conversations, endpoints | none (sets the panel filter); NEW `packets.endpoints` (read) | V |
| Stream "Copy as text", "Hex" | stream | none | V |
| Stream "Open as document" | stream | `documents.derive` (D) with the stream's bytes, or NEW `packets.follow_stream {open: true}` | J |
| Packet viewer tab | palette `tools.packets`, Tools menu | none | V |

**New methods (B), all in `packet_sets.rs`:**

- Sets and sources:
  - `packets.find_captures {doc?, start?, len?}` (R) returns
    `{captures: [{offset, format, gzipped}]}`.
  - `packets.sets.create`: new `gunzip: bool` for a gzipped capture.
  - `packets.sets.add_packets {set, ranges}` (V).
  - `packets.sets.refresh {set, doc?}` (V).
  - `packets.detect_length_field {doc?, start, len}` (R) returns a
    `LengthFieldSpec`.
- Decoding:
  - `packets.decode_as`: new `link`, `template_name`, and `template:
    "protocol"`.
  - `packets.tshark_decode {set, indices?, filter?, mode: fill_gaps|everything}`
    (J).
- Editing:
  - `packets.write_field {set, index, offset, len, value, little_endian}` (E).
  - `packets.columns.apply {set, first, width, indices?, op: invert|fill|xor|add|set|counter|swap, key?, value?, start?, step?, group?, little_endian?}`
    (E).
  - `packets.columns.delete {set, first, width, indices?}` (E).
  - `packets.columns.read {set, first, width, indices?, format: hex|csv}` (R).
  - `packets.delete {set, indices}` (E).
  - `packets.fix_checksums {set, indices}` (E).
  - `packets.apply {set, indices, op: invert|fill|xor, key?, field?: {offset, len}}`
    (E).
- Export and reading:
  - `packets.export_pcap`: new `indices`.
  - `packets.extract {set, indices, path?}` (R; writing a file needs leave
    to edit, as export does).
  - `packets.endpoints {set, filter?}` (R).

## Area C: Analysis tools

Owns `src/api/tools.rs` (a namespace per tool), `src/api/analysis.rs`,
`src/api/structure.rs` (templates), `src/api/reference.rs` and
`src/api/findings.rs`, plus the tool panels.

| Action | Where | Method | Journal |
| --- | --- | --- | --- |
| Detect width / Rescan (period scan) | palette `analysis.detect`, View menu, context menu "Detect width from here", chart "Rescan", Guess image | `analysis.period_scan {start, len, max_period}` (**done**, via `start_period_scan`) | J |
| Period chart: candidate chip, periodogram click | `structure.rs` (`apply_period`) | `view.set_shape {width, row_padding}` (D converts `apply_period`) | J |
| Chart "Hide", "B max" | chart | none (params) | V |
| Template: Apply at cursor; Ask/Report "Apply at cursor"; Learn "Apply template"; Columns, Protocol "Apply as template"; context menu "Apply template here" | Template tab, `dock.rs template_offer`, others | `templates.apply {source\|name, at, pin: true}`. It must also fill the Template tab (`bench.template_*`). | J |
| Template: Infer from selection | Template tab, palette `tools.infer`, Tools and context menus (`infer_template`) | NEW `templates.infer {start, len, record_len?}` | J |
| Template: Clear | Template tab | NEW `templates.clear` | J |
| Template choice, source editor, record "#" click | Template tab | none (params); `selection.set` for the record | V/J |
| Columns: profile (record length, Use row width, Use detected) | `analysis_tools.rs show_columns` | NEW `columns.profile {start, record_len, max_records?}` (R) | R |
| Columns: field "+N" | Columns | `selection.set` | J |
| Protocol: Analyse selection / file | Protocol tab, palette `tools.protocol`, Tools menu, context menu | NEW `protocol.analyse {start, len}` (J) | J |
| Protocol: choose a framing chip | Protocol | NEW `protocol.choose_framing {framing}` (or `protocol.analyse {framing}`) | J |
| Protocol: Open in packet viewer | Protocol | `packets.sets.create {from: protocol_framing}` (B's method) | J |
| Protocol: message row | Protocol | `selection.set` | J |
| Align messages; cluster threshold; Open type N in packet viewer; cell click | `panel_alignment.rs` | NEW `alignment.run {threshold, start?, len?}` (J); `packets.sets.create {from: selection, ranges}`; `cursor.set` | J |
| Learn: Add samples, Remove, Learn | `panel_learn.rs` | NEW `learn.format {paths}` (J) (the sample list is its param) | J |
| Learn: Save to my catalogue | Learn | NEW `learn.save_catalogue {id, toml}` (E-like; writes a file) | J |
| Learn: fuzzy hash, Compare with files, Shared fragments, row click | Learn | NEW `learn.fuzzy_compare {paths}` (J), `learn.fragments {path, block}` (J); `cursor.set` | J |
| Report: Explain this file / Re-analyse / Run the report / file map right-click | Report tab, palette `tools.explain`, Tools menu, curve controls, Size map (`start_report`) | NEW `report.run` (J), which fills `bench.report` and `regions.mapped` (`analysis.overview_job` stays headless) | J |
| Report sentence "select", `0x…` links | `dock.rs linked_text`, Report | `selection.set` / `cursor.set` | J |
| Structure map: Segment file; Show on file map / Clear | `panel_structure_map.rs` | NEW `structure_map.segment` (J); `findings.publish` / `findings.retract {key}` | J |
| Structure map: Find similar (threshold, weight); Highlight all / Clear | Structure map, palette `tools.similar` | NEW `structure_map.find_similar {start, len, histogram_weight, threshold}` (J); `findings.publish/retract` | J |
| Structure map: Compute tracks; Use width here | Structure map | NEW `structure_map.tracks` (J); `view.set_shape {width}` | J |
| Statistics: Analyse | `analysis_stats.rs`, palette `tools.statistics`, context menu "Statistics of selection" | NEW `statistics.analyse {start, len}` (J) (`analysis.statistics` stays the quick read) | J |
| Statistics: plot click, repeat offset | Statistics | `cursor.set`; `selection.set` | J |
| Strings: Find (min chars, encodings) | `analysis_stats.rs show_strings`, context menu | NEW `strings.find {start, len, min_chars, encodings}` (J) | J |
| Strings: filter, "Only URLs…" | Strings | none (V; `filter` and `interesting_only` may also be params) | V |
| XOR: Find keys | `show_xor`, context menu "Find XOR key" | NEW `xor.recover_keys {start, len, max_key?}` (R) | R |
| XOR: Preview / Apply | XOR | `documents.derive {…, transform}` (D) / `transform.apply {xor}` | J |
| Size map: source, tile zoom, breadcrumb | `panel_treemap.rs` | none | V |
| Unpack everything; node Open / Save…; tile click | Unpacked tab, Size map, palette `tools.unpack` (`start_unpack`) | NEW `unpack.run` (J), `unpack.open {path}` (J), `unpack.read {path}` (R), `unpack.save {node, path}` (E, through the save dialog); `cursor.set` | J |
| Trigrams: Plot (labels, whole file) | `panel_trigram.rs` | NEW `trigrams.count {start, len, labels, whole_file}` (J) | J |
| Trigrams: camera, colouring, legend, dim | Trigrams | none | V |
| Trigrams: point or strip click | Trigrams | `cursor.set` | J |
| Characterise: Profile selection / whole file | `panel_characterise.rs` | `analysis.compressibility` (selection); NEW `characterise.profile_file` (J) | J |
| Characterise: media streams; Play; Extract… | Characterise | NEW `characterise.streams` (J); Play V; `documents.export` (D) | J |
| Characterise: identify encoding; Open as UTF-8 | Characterise | `analysis.text_encoding`; `documents.derive {…, transform}` (D) | J |
| Reference: stack at cursor, breadcrumb, browse, search, links | `panel_reference.rs` | `reference.lookup` / `reference.search` (reads) | V |
| Reference: field table or diagram click | Reference | `selection.set` | J |
| Reference: Show RFC / §; Reload your notes; Or perhaps | Reference | NEW `reference.rfc {number, section?}` (R); `reference.reload` (V); `reference.pick_alternative` (V) | V |
| Workspace panel: span link; why; topic filter | `panel_workspace.rs` | `selection.set` / `cursor.set`; the rest V | J/V |
| Bits: bit order; Find bit periods | `panel_bits.rs` | NEW `bits.scan_periods {start, len, order, max_period}` (J) | J |
| Bits: Use as width / Align view | Bits | `view.set_shape {format, width, offset, bit_offset}` (needs D's `format`) | J |
| Bits: Split into bit planes; open a plane | Bits | NEW `bits.planes {start, len, row_width}` (J); `bits.open_plane {start, len, bit}` (J) | J |
| Bits: Detect line code; Decode as + Open decoded | Bits | NEW `bits.detect_linecode` (J); `bits.decode_linecode {start, len, order, code, bit_offset}` (J, opens a derived document) | J |
| Bits: number types (field width) | Bits | NEW `bits.rank_field {origin, stride, offset, width}` (R) | R |
| Bits: Find length fields; row click | Bits | NEW `bits.find_length_fields {start, len}` (J); `selection.set` | J |
| Compare: add or remove files, start offsets | `panel_compare.rs` | none until a run (params `files: [{path, start}]`) | V |
| Compare: Compare N files; Find fields; Build timeline | Compare | NEW `compare.variation {files}` (J), `compare.correlate {files, values, from}` (J), `compare.timeline` (J) | J |
| Compare: row, heatmap or most-active click | Compare | `cursor.set` | J |
| Checksums: digests | `analysis_tabs.rs show_checksums` | NEW `checksums.digests {start, len}` (R) | R |
| Checksums: Find the checksum; match "show" | Checksums | NEW `checksums.find_stored {start, len}` (R); `findings.publish` + `selection.set` | J |
| CRC solver: inputs; Solve | `panel_crc_solver.rs` | NEW `checksums.solve_crc {source, start, record_len, count, width, order, position, offset, try_skips}` (J) | J |
| Crypto constants: Scan; Highlight / Clear; weak | `panel_crypto_constants.rs` | NEW `crypto.scan_constants` (J); `findings.publish/retract` | J |
| Crypto: repeated blocks; keys and certificates | `panel_crypto.rs` | NEW `crypto.repeated_blocks {start, len}` (J), `crypto.find_keys {start?, len?}` (J) | J |
| Crypto: crib, presets; Try cipher attacks | Crypto | NEW `crypto.attack {start, len, crib}` (J) | J |
| Crypto: Open decoded / Apply in place | Crypto | `documents.derive {…, transform}` (D) / `transform.apply` or `bytes.replace` | J |
| Dot plot: Plot (mode); click | `panel_dotplot.rs` | NEW `dotplot.compute {start, len, mode}` (J); `cursor.set` | J |
| Firmware: Identify processor | `panel_firmware.rs` | NEW `firmware.identify {start, len}` (J) (`analysis.processor` is the synchronous read) | J |
| Firmware: Disassemble as X; disassembly arch combo | Firmware, Disassembly tab | NEW `disasm.set_arch {arch}` (V) | J |
| Firmware: load address (width, order, step, min strings); vector tables | Firmware | NEW `firmware.find_load_address {…}` (J), `firmware.vector_tables {start?, len?}` (J) | J |
| Firmware and Disassembly jumps | Firmware, Disassembly | `cursor.set` | J |
| Forensics: filesystems; open entry; classify blocks | `panel_forensics.rs` | NEW `forensics.find_filesystems` (J), `forensics.open_entry {filesystem, entry}` (J), `forensics.classify_blocks {block_size?}` (J) | J |
| Images: Find; apply a result | `panel_image_finder.rs` | NEW `images.find {start, len}` (J); `view.set_shape {format, width, offset, bit_offset: 0, row_padding: 0}` (needs D's `format`) | J |
| Diff: Compare with file…; op row | `analysis_tabs.rs show_diff`, Tools menu, palette `tools.diff` | NEW `diff.run {path}` (J); `cursor.set` | J |
| Ask: send a question, suggestions, Characterise, Clear | `dock.rs show_assistant`, palette `tools.ask_characterise` | none: Ask's own tool calls are journalled as `Caller::Ask` | V |
| Ask: answer links and template offers | `dock.rs` | `cursor.set` / `templates.apply` | J |
| Findings list: filter, confidence, category chips | `findings.rs` | none | V |
| Opening a tool's tab | palette `tools.*`, Tools menu | none (V); the job it starts is a method | V |

**New methods (C):**

- In `tools.rs`, one namespace per tool:
  - `columns.profile`.
  - `protocol.analyse`, `protocol.choose_framing`.
  - `alignment.run`.
  - `learn.format`, `learn.save_catalogue`, `learn.fuzzy_compare`,
    `learn.fragments`.
  - `report.run`.
  - `structure_map.segment`, `structure_map.find_similar`,
    `structure_map.tracks`.
  - `statistics.analyse`.
  - `strings.find`.
  - `xor.recover_keys`.
  - `unpack.run`, `unpack.open`, `unpack.read`, `unpack.save`.
  - `trigrams.count`.
  - `characterise.profile_file`, `characterise.streams`.
  - `bits.scan_periods`, `bits.planes`, `bits.open_plane`,
    `bits.detect_linecode`, `bits.decode_linecode`, `bits.rank_field`,
    `bits.find_length_fields`.
  - `compare.variation`, `compare.correlate`, `compare.timeline`.
  - `checksums.digests`, `checksums.find_stored`, `checksums.solve_crc`.
  - `crypto.scan_constants`, `crypto.repeated_blocks`, `crypto.find_keys`,
    `crypto.attack`.
  - `dotplot.compute`.
  - `firmware.identify`, `firmware.find_load_address`,
    `firmware.vector_tables`.
  - `disasm.set_arch`.
  - `forensics.find_filesystems`, `forensics.open_entry`,
    `forensics.classify_blocks`.
  - `images.find`.
  - `diff.run`.

  `tools.rs` may be split into one file per tool (`src/api/tools/*.rs`).
  Area C owns all of them, so the split cannot conflict.
- In `structure.rs`: `templates.infer`, `templates.clear`, and making
  `templates.apply {pin}` fill the Template tab.
- In `reference.rs`: `reference.rfc`, `reference.reload`,
  `reference.pick_alternative`.

`bits.*` is a new namespace beside the existing `bits.read`/`bits.write`
(which are in `bytes.rs` and `edits.rs`). The table groups them by
namespace on its own, so C's `bits.*` in `tools.rs` needs no change to the
other files.

## Area D: Navigation, files and view

Owns `src/api/view.rs`, `src/api/documents.rs`, `src/api/codecs.rs` and
`src/api/application.rs`, plus `src/api/workspace.rs` (the `Workspace` trait
and its two implementations; see the briefs).

| Action | Where | Method | Journal |
| --- | --- | --- | --- |
| Go to offset | Cmd+G field, toolbar Go/Enter, palette `view.goto` | `cursor.set {offset}` (**done**, via `go_to`) | J |
| Width: slider, drag, presets, [ and ] | toolbar, shortcuts | `view.set_shape {width}` (**done**, via `change_width`) | J |
| Fit width | toolbar Fit, View menu, palette `view.fit` (`fit_width_requested` in `view.rs`) | `view.set_shape {width}` | J |
| Image layout presets (format + width + no padding) | toolbar Presets | `view.set_shape {format, width, row_padding: 0}` (NEW `format`) | J |
| Pixel format | toolbar Format combo, Settings "Apply to this window" | `view.set_shape {format}` (NEW) | J |
| Row padding | toolbar "pad" DragValue | `view.set_shape {row_padding}` | J |
| Origin byte and bit: DragValues, "To cursor" / Origin = cursor, Reset origin, `,` and `.`, Alt+←/→ (no selection), context menu "Set view origin here" | toolbar, View menu, palette `view.origin_cursor`/`view.origin_reset`, shortcuts (`align_view_to_cursor`, `reset_origin`, `adjust_bit_offset`) | `view.set_shape {offset, bit_offset}` | J |
| Guess image shape | View menu, toolbar Presets, palette `view.guess_image` | `view.set_shape {format, width}` (the scan through C's `analysis.period_scan`) | J |
| Apply a period (chart chip, periodogram, Structure map "Use width here") | `apply_period` | `view.set_shape {width, row_padding}` | J |
| Skip (fold) the selection | S, floating toolbar, Selection menu (`skip_selection`) | NEW `view.fold {ranges}` | J |
| Show skipped bytes again; Show every skipped range; "N skipped" | fold chip, context menu, status bar (`unfold`, `unfold_all`) | NEW `view.unfold {start?\|all}` | J |
| Palette, row difference, curve layout (Hilbert/Morton), curve colours, pixel values, colour by region, pointer arrows, file map, highlights (H), kinds, legend layers | toolbar, View menu, palette `view.*`, `analysis.patterns`, legend | none | V |
| Zoom (+/-, toolbar, wheel, pinch), scroll, pan, scrollbar, hover, entropy strip hover | everywhere | none | V |
| Entropy strip click, Hilbert/Morton click, file map click | `view.rs`, `workbench.rs` | `cursor.set` | J |
| Add bookmark (prompt), Bookmark… (context menu), Findings "Bookmark" | Cmd+B, Go menu, palette `bookmark.add` (`begin_bookmark` → `add_bookmark`) | NEW `bookmarks.add {start, len, name}` | J |
| Remove bookmark | Findings bookmarks "x" (`remove_bookmark`) | NEW `bookmarks.remove {start}` | J |
| Next / previous bookmark; click a bookmark | F2 / Shift+F2, Go menu, palette (`goto_bookmark`, `jump_to_bookmark`) | `selection.set` / `cursor.set` | J |
| Open file (dialog, Cmd+O, drop a file, palette `file.open`) | File menu, `handle_dropped_files`, `complete_file_action` | `documents.open {path}` | J |
| New empty document | Cmd+N, File menu, palette `file.new` | `documents.new` | J |
| Save / Save as | Cmd+S / Shift+Cmd+S, File menu, palette | `documents.save {path?}` | J |
| Extract selection or stream to file; extract decompressed; toolbar Extract › Save | Cmd+E, File menu, toolbar, Selection menu "Extract to file…", palette `file.extract*` | NEW `documents.export {start, len \| ranges, path, decompress?}` (the Selection menu's "Extract to file…" passes every selected range) | J |
| Copy extract / decompressed as hex | toolbar Extract | none (reads) | V |
| Open selection as document; open bytes as a derived document (for B and C) | Selection menu "Open as document" (`open_selection_as_document`) | NEW `documents.derive {start, len, name?, transform?}` | J |
| Back to parent | Cmd+[, Edit menu, status bar Back, palette `compress.back` | `documents.open {doc: parent id}` | J |
| Flip compressed / decompressed view | Cmd+D, Edit menu, toolbar, palette `compress.flip`, Findings "Decompress" | NEW `codecs.open_decoded {start, codec?}` (opens the derived document) / `documents.open {doc}` to flip back | J |
| Decompress in place | Edit menu, toolbar "In place", palette `compress.in_place`, context menu "Decompress" | `transform.apply {decompress}` (or NEW `codecs.decode {…, in_place}`) | J |
| Compress selection as codec; Re-pack with the last codec | Edit menu, toolbar, palette `compress.*` (`compress_selection`, `recompress_selection`) | `transform.apply {compress: codec}` | J |
| Probe for compression at cursor | Edit menu, toolbar Probe, palette `compress.probe`, context menu | `codecs.probe` (read) | V |
| Select the stream at the cursor | Edit menu, toolbar, palette `compress.select_stream` | `selection.set` | J |
| Open media at cursor; play/pause; close; viewer controls; plot; play as audio; audio format | Cmd+Enter, Space, toolbar Media, palette `media.*`, `tools.plot`, `tools.audio`, Tools menu, context menu | none | V |
| Reload plugins | View menu, palette `plugins.reload` | NEW `plugins.reload` | J |
| Open URL, device, serial port or process; process region | Live tab, palette `tools.live` | NEW `documents.open_source {uri}`, `sources.open_process_region {pid, index}` | J |
| Watch the file; record history; stop capture; view a recorded version | Live tab, Tools menu, palette `tools.watch` | NEW `sources.watch {enabled}`, `sources.record {enabled}`, `sources.stop`, `sources.view_version {index}` | J |
| Layouts (recommended, saved, restore last session, suggestions), panels, dock, Cmd+J | View/Layout menus, palette `layout.*`, `view.dock`, `analysis.chart`, `analysis.findings` | none | V |
| Settings window (all), Cmd+, palette `app.settings` | `settings.rs` | none (never a client-writable method) | V |
| Confirmation window (Allow once / Always / Deny) | `confirmations.rs` | none (answers a held call) | V |
| Command palette, Help, Keyboard shortcuts | Cmd+K, ?, Help menu | none | V |
| Rescan the visible region | palette `analysis.rescan` | none (recomputes what the views show) | V |

**New methods (D):**

- In `view.rs`:
  - `view.set_shape`/`view.get_shape`: new `format` (needs serde and
    `JsonSchema` on `raster::PixelFormat`).
  - `view.fold {ranges}` (V) and `view.unfold {start?, all?}` (V).
  - `bookmarks.add {start, len, name}` (V) and `bookmarks.remove {start}`
    (V), kept headless per document.
- In `documents.rs`:
  - `documents.export {start, len, path, decompress?}`: writes a file, so
    its effect is edit.
  - `documents.derive {start, len, name?, transform?}` (V): opens bytes, or
    their transform (a codec, an XOR), as a derived document and returns
    its id.
  - `documents.open_source {uri}` (V).
- In `codecs.rs`: `codecs.open_decoded {start, codec?}` (V).
- In `application.rs`:
  - `plugins.reload` (V).
  - `sources.watch`, `sources.record`, `sources.stop`,
    `sources.view_version`, `sources.open_process_region`.
- In `workspace.rs`:
  - `Workspace::open_derived(&mut self, parent: &str, bytes, name) -> Result<String, ApiError>`.
    In the window it calls `ViewerApp::open_derived`; headless it adds a
    document. B and C need it.
  - The `Workspace` side of folds and bookmarks.

## Counts

| Area | Rows | Of them view only (V) | Already converted | New methods |
| --- | --- | --- | --- | --- |
| A Editing | 30 | 6 | 2 rows (every Selection menu operation, from every way in) | 1, plus 1 new param (and 1 optional method) |
| B Packets | 37 | 8 | 1 row (split by row width, from the palette and context menu) | 14, plus 4 new params |
| C Analysis tools | 68 | 10 | 1 row (detect width, from every way in) | 53, plus making `templates.apply` fill the Template tab |
| D Navigation, files and view | 38 | 10 | 2 rows (go to, width) | 14, plus 1 new param and 1 `Workspace` hook |
| **Total** | **173** | **34** | **6** | **82** |

A row often stands for several controls that do one thing: a menu item, its
shortcut and its palette command, say. The appendix lists all 107 built-in
palette commands with their area and method.

## Cross-area dependencies

1. **D's `documents.derive` and `Workspace::open_derived`** are needed by B
   (Open packet or stream as document, Save bytes) and C (XOR Preview,
   Crypto and Characterise "Open decoded", plane, line-code, unpack and
   forensics entries). D lands them first, in its first commit. Until
   then, B and C keep calling `app.open_derived` directly for those rows,
   and convert them after merging D.
2. **D's `view.set_shape {format}`** is needed by C (Bits "Use as width" and
   "Align view", Images results). C passes `width`, `offset` and
   `bit_offset` now and adds `format` after D merges, or leaves those rows
   to the end.
3. **D converts `apply_period`.** C's chart and Structure map buttons call
   it and need no change.
4. **A's `coalesce` param on `bytes.write`** is used by B's packet hex
   editor. B converts that row after A merges, or calls `bytes.write`
   without it for now (each nibble is then its own undo step).
5. **B's `packets.sets.create {from: protocol_framing}`** is already there,
   and C's Protocol "Open in packet viewer" and Alignment clusters call it.
   No order is needed, but C must call it with `perform_later` when the
   Packets panel could be lent out.
6. **`findings.publish`/`retract`** (C owns `findings.rs`) replace
   `bench.pinned` for structure map, checksums, crypto constants and diff
   pins. No other area pins.

## Appendix: the palette

Every built-in palette command (`src/commands.rs`), with the area that owns it and its method. V means view only, with no method. A command that only opens a tool's tab is V; the tool's own buttons are in that area's table.

| Id | Title | Area | Method |
| --- | --- | --- | --- |
| `file.open` | Open file | D | `documents.open` |
| `file.save` | Save | D | `documents.save` |
| `file.save_as` | Save as | D | `documents.save {path}` |
| `file.new` | New empty document | D | `documents.new` |
| `file.extract` | Extract selection or stream to file | D | NEW `documents.export` |
| `file.extract_decompressed` | Extract decompressed contents to file | D | NEW `documents.export {decompress}` |
| `edit.undo` | Undo | A | `history.undo` |
| `edit.redo` | Redo | A | `history.redo` |
| `edit.copy` | Copy as hex | A | V |
| `edit.cut` | Cut | A | `transform.apply {delete}` |
| `edit.paste` | Paste | A | `bytes.replace`/`insert`/`write` |
| `edit.multi_select` | Multi-select mode: add sections with plain clicks and drags | A | V |
| `edit.select_all` | Select all | A | `selection.set` |
| `edit.delete` | Delete selection or byte | A | `transform.apply` (done) |
| `edit.insert` | Insert bytes at cursor | A | `bytes.insert` |
| `edit.fill` | Fill selection with pattern | A | `transform.apply` (done) |
| `edit.invert` | Invert bits in selection | A | `transform.apply` (done) |
| `edit.reverse` | Reverse bytes in selection | A | `transform.apply` (done) |
| `edit.mirror` | Mirror bits in each selected byte | A | `transform.apply` (done) |
| `edit.mode` | Toggle overwrite / insert typing | A | V |
| `view.zoom_in` | Zoom in | D | V |
| `view.zoom_out` | Zoom out | D | V |
| `view.fit` | Fit width to the window | D | `view.set_shape {width}` |
| `view.origin_cursor` | Set view origin to the cursor | D | `view.set_shape {offset}` |
| `view.origin_reset` | Reset view origin to 0 | D | `view.set_shape {offset, bit_offset}` |
| `view.goto` | Go to offset | D | `cursor.set` (done) |
| `view.search` | Find bytes or text | A | V (focuses the field) |
| `view.find_next` | Find next | A | `search.find` + `selection.set` |
| `view.find_previous` | Find previous | A | `search.find` + `selection.set` |
| `layout.overview` | Layout: Overview | D | V |
| `layout.network` | Layout: Network capture | D | V |
| `layout.structure` | Layout: File structure | D | V |
| `layout.firmware` | Layout: Firmware and code | D | V |
| `layout.signals` | Layout: Signals and bit streams | D | V |
| `layout.forensics` | Layout: Forensics and carving | D | V |
| `layout.compare` | Layout: Compare files | D | V |
| `layout.focus` | Layout: Focus on the view | D | V |
| `layout.last_session` | Layout: Restore last session | D | V |
| `view.guess_image` | Guess image shape | D | `view.set_shape {format, width}` |
| `analysis.detect` | Detect width (period scan) | C | `analysis.period_scan` (done) |
| `analysis.chart` | Toggle structure chart | D | V |
| `analysis.patterns` | Toggle highlights | D | V |
| `analysis.findings` | Toggle findings panel | D | V |
| `analysis.rescan` | Rescan the visible region | D | V |
| `compress.flip` | Flip compressed / decompressed view | D | NEW `codecs.open_decoded` |
| `compress.in_place` | Decompress in place | D | `transform.apply {decompress}` |
| `compress.probe` | Probe for compression at cursor | D | V (`codecs.probe` reads) |
| `compress.select_stream` | Select the stream at the cursor | D | `selection.set` |
| `compress.repack` | Re-pack selection with the last codec | D | `transform.apply {compress}` |
| `compress.zlib` | Compress selection as zlib | D | `transform.apply {compress}` |
| `compress.gzip` | Compress selection as gzip | D | `transform.apply {compress}` |
| `compress.back` | Back to the parent document | D | `documents.open {doc}` |
| `bookmark.add` | Bookmark the cursor or selection | D | NEW `bookmarks.add` |
| `bookmark.next` | Next bookmark | D | `selection.set`/`cursor.set` |
| `bookmark.previous` | Previous bookmark | D | `selection.set`/`cursor.set` |
| `plugins.reload` | Reload plugins | D | NEW `plugins.reload` |
| `media.open` | View image / play audio or video at the cursor | D | V |
| `media.toggle` | Play or pause media | D | V |
| `media.close` | Close the media window | D | V |
| `tools.explain` | Explain this file (report and file map) | C | NEW `report.run` |
| `tools.ask` | Ask Claude about this file | C | V |
| `tools.ask_characterise` | Characterise this file with Ask | C | V (Ask's calls are its own) |
| `tools.template` | Templates | C | V (opens the tab) |
| `tools.infer` | Infer a template from the selection | C | NEW `templates.infer` |
| `tools.disassemble` | Disassemble at the cursor | C | V (opens the tab) |
| `tools.unpack` | Unpack everything (recursive extraction) | C | NEW `unpack.run` |
| `tools.segments` | Segment the file into regions of one kind | C | V (opens the tab; its runs are the tool's methods) |
| `tools.similar` | Find more like the selection | C | V (opens the tab; its runs are the tool's methods) |
| `tools.trigrams` | Trigram cube: a 3D fingerprint of the bytes | C | V (opens the tab; its runs are the tool's methods) |
| `tools.sizemap` | Size map of regions or unpacked contents | C | V (opens the tab; its runs are the tool's methods) |
| `tools.dotplot` | Dot plot: compare the file with itself | C | V (opens the tab; its runs are the tool's methods) |
| `tools.images` | Find uncompressed images, fonts and framebuffers | C | V (opens the tab; its runs are the tool's methods) |
| `tools.firmware` | Firmware: identify the processor, load address and vector table | C | V (opens the tab; its runs are the tool's methods) |
| `tools.crc_solver` | Solve a custom CRC from several messages | C | V (opens the tab; its runs are the tool's methods) |
| `tools.forensics` | Find embedded filesystems and classify each block of the file | C | V (opens the tab; its runs are the tool's methods) |
| `tools.checksums` | Checksums and find-the-checksum | C | V (opens the tab; its runs are the tool's methods) |
| `tools.diff` | Compare with another file | C | V (opens the tab); its run is NEW `diff.run` |
| `tools.live` | Open a URL, device, serial port or process | D | V (opens the tab) |
| `tools.watch` | Watch the file for changes | D | NEW `sources.watch` |
| `tools.plot` | Plot the selection | D | V |
| `tools.audio` | Play the selection as audio | D | V |
| `view.dock` | Toggle the tools dock | D | V |
| `view.hilbert` | Toggle Hilbert-curve layout | D | V |
| `view.morton` | Toggle Morton (Z-order) curve layout | D | V |
| `view.curve_colours` | Cycle curve colours: bytes, entropy, region type, byte class | D | V |
| `view.pixel_values` | Toggle values inside pixels when zoomed in | D | V |
| `view.zoomed_out_regions` | Toggle colouring by region when zoomed out | D | V |
| `view.row_difference` | Cycle row difference: off, XOR or subtract the row above | D | V |
| `view.pointers` | Toggle pointer arrows | D | V |
| `tools.characterise` | Characterise: compressibility by codec, raw media streams, text encoding | C | V (opens the tab; its runs are the tool's methods) |
| `tools.learn` | Learn a format from samples; fuzzy-match files | C | V (opens the tab; its runs are the tool's methods) |
| `tools.statistics` | Byte statistics and randomness tests | C | NEW `statistics.analyse` |
| `tools.strings` | Find strings | C | V (opens the tab; its runs are the tool's methods) |
| `tools.bits` | Bits and encodings: bit periods, bit planes, line codes, number types, length fields | C | V (opens the tab; its runs are the tool's methods) |
| `tools.columns` | Profile record columns | C | V (opens the tab; its runs are the tool's methods) |
| `tools.protocol` | Analyse a message stream (protocol) | C | NEW `protocol.analyse` |
| `tools.packets` | Packet viewer: dissect, filter and export packets | B | V (opens the tab; its runs are the tool's methods) |
| `tools.reference` | Reference for the format at the cursor | C | V (opens the tab; its runs are the tool's methods) |
| `tools.workspace` | Workspace: what the tools have learnt, and what just happened | C | V (opens the tab; its runs are the tool's methods) |
| `tools.packets_framing` | Packets from the protocol framing | B | `packets.sets.create {from: protocol_framing}` |
| `tools.packets_selection` | Add the selection as a packet | B | NEW `packets.sets.add_packets` |
| `tools.packets_rows` | Split the selection into packets by row width | B | `packets.sets.create {from: split_fixed}` (done) |
| `tools.xor` | Recover XOR keys | C | V (opens the tab; its runs are the tool's methods) |
| `tools.compare` | Compare many files: variation, correlation and recording timeline | C | V (opens the tab; its runs are the tool's methods) |
| `tools.crypto` | Find encrypted blocks, keys and certificates; try simple ciphers | C | V (opens the tab; its runs are the tool's methods) |
| `app.settings` | Settings (API key) | D | V |
| `help.keys` | Keyboard shortcuts | D | V |

## Area briefs

### Shared rules for all four areas

- **Your files.**
  - Your `src/api/<namespace>.rs` files: add each method's row to
    `METHODS`, an example of it to `examples()`, a plain description to
    `describe_call` when it edits or changes the view, and tests in that
    module.
  - Your UI files, listed below.
  - Each new method belongs to one area and one file, as listed above.
    Calling another area's existing method needs no edit to its file.
- **Shared hubs.** Edit only these lines in these files:
  - `src/app.rs`: only the menu, shortcut, toolbar or context-menu lines
    for your own actions, and the bodies of the `ViewerApp` functions your
    actions use. Prefer converting the function over its call sites. New
    `ViewerApp` helpers go in your own files (`impl ViewerApp` blocks are
    allowed in any module), not in `app.rs`.
  - `src/commands.rs`: only your own palette lines, and only when the
    function they call cannot be converted instead.
  - `src/selection_menu.rs`: area A's file; others call its functions.
  - `src/api.rs`: do not edit. The parts list is complete. A new module of
    your own, if `tools.rs` is split, goes under `src/api/tools/` and is
    declared from `tools.rs`.
  - `src/api/workspace.rs`: area D owns it. A, B or C may add a `Workspace`
    method only when a method must work headless and `workspace.window()`
    will not do. Add it with a default implementation, at the end of the
    trait, in a block commented with your area, and implement it in the
    two `impl` blocks at their ends.
  - `src/bus/topics.rs`: new topics are rare. Add one only when a fact
    must reach other tools, at the end of the table, and say so in your
    report.
  - `docs/api.md`: never edit it by hand. Regenerate it with
    `cargo run --bin api_docs` before each commit. At merge, conflicts in
    it are resolved by regenerating, never by hand.
  - `src/actions.rs`: do not edit. Ask the foundation's owner if you need
    more from `perform`.
- **The pattern to copy.** These are the four examples:
  - A: `ViewerApp::apply_operation` in `src/selection_menu.rs`, with its
    tests at the end of that file.
  - B: `split_selection_by_row_width` and `current_decoding` in
    `src/panel_packets.rs`, with tests
    `splitting_the_selection_by_row_width_*`.
  - C: `analysis.period_scan` in `src/api/analysis.rs`, with
    `start_period_scan` and `scan_periods_from` in `src/app.rs` and tests
    `a_period_scan_job_*` and `detecting_the_width_*`.
  - D: `view.set_shape` in `src/api/view.rs`, with `go_to` and
    `change_width` in `src/app.rs` and tests at the end of `src/app.rs`.

  For each one, the UI calls `perform` (or `perform_later`) with params
  that say everything, behaviour is unchanged, and a test proves the API
  path was taken.
- **Tests expected** for each converted action:
  - `take_performed()` shows the method and its full params;
  - what the person sees is unchanged (bytes, selection, status text,
    panel state);
  - a failure is said where it was before.

  For each new method:
  - an example in `examples()`, which checks the params and result
    against the schemas;
  - a headless test of its behaviour, including refusals with the right
    error code.

  Test names describe behaviour, in British English.
- **Build and verify** with your own target directory and debuginfo off:

  ```
  CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
    CARGO_TARGET_DIR=target-agents/<area> cargo test
  ```

  Run `cargo clippy --all-targets` and make it clean before each commit.
  Make no release builds. Commits are one-line messages in the repository's
  style, with no trailers.

### A: Editing

- **Your files:**
  - `src/api/edits.rs`, `src/api/selection.rs` and `src/api/search.rs`;
  - `src/selection_menu.rs` and `src/selection_drag.rs`;
  - in `src/view.rs` and `src/hex.rs`, the click, drag and typing handlers
    only;
  - `src/hex.rs` `show_inspector` and `show_field`.
- **Your `src/app.rs` functions:** `type_hex_digit`, `backspace`, `paste`,
  `cut`, `insert_from_fields`/`insert_bytes_at_cursor`, `move_target`,
  `toggle_bit_at_cursor`, `undo`, `redo`, `select_all`, `move_cursor_by`,
  `set_cursor` callers in `handle_shortcuts`, `find_next`,
  `find_previous`, `select_all_matches` and `select_pattern` (now `select_finding`, with `reveal_finding` only bringing it into view).
- **Do not convert** `set_cursor`, `restore_selection` or `set_selection`
  themselves. The API's own `cursor.set` and `selection.set` use them.
  Convert their callers that are the person's actions.
- **Drags:** keep the drag local and call `selection.set` (or
  `bytes.move`) once, on release.
- **Typing:** a byte typed as two nibbles must stay one undo step. Add
  `coalesce` to `bytes.write`/`bytes.insert` first.
- **New methods:** `bytes.move`, and `coalesce` on `bytes.write` and
  `bytes.insert`. Optionally `search.find_and_select`.

### B: Packets

- **Your files:**
  - `src/api/packet_sets.rs` and `src/api/packets.rs`;
  - `src/panel_packets.rs`, `src/panel_packets_view.rs`,
    `src/panel_packets_grid.rs` and `src/panel_packets_tshark.rs`;
  - `src/packets/*` as the methods need;
  - `packets_context_menu` in `src/app.rs`.
- **Every source the panel offers becomes `packets.sets.create`**, so the
  panel always shows an API set and `state.api_set` names it. The methods
  on a set (decode as, export, delete, columns) then take that id.
- **The panel is drawn with its state lent out.** An action taken while
  drawing that creates a set or changes its decoding calls `perform_later`
  (see `src/actions.rs`), never `perform`.
- **Packet selections** published by the panel keep the panel's producer
  (`claim_main_selection`), or following the selection loops. When the
  panel calls `selection.set`, re-claim the selection afterwards, or add a
  `producer`-preserving path inside your own files.
- **Indices** in params are set indices, never positions in the filtered
  list.
- **Byte operations over several packets** stay one undo step, one
  `document.replace` over the covering span, as they are today.
- **New methods:** the list under Area B above.
- **Depends on** D's `documents.derive` (opening a packet or stream as a
  document) and A's `coalesce` (the hex editor). Convert those rows last.

### C: Analysis tools

- **Your files:**
  - `src/api/tools.rs` (and `src/api/tools/*` if you split it),
    `src/api/analysis.rs`, `src/api/structure.rs`, `src/api/reference.rs`
    and `src/api/findings.rs`;
  - the tool panels: `src/analysis_tools.rs`, `src/analysis_stats.rs`,
    `src/analysis_tabs.rs`, `src/panel_bits.rs`, `src/panel_compare.rs`,
    `src/panel_crc_solver.rs`, `src/panel_crypto*.rs`,
    `src/panel_dotplot.rs`, `src/panel_firmware.rs`,
    `src/panel_forensics.rs`, `src/panel_image_finder.rs`,
    `src/panel_alignment.rs`, `src/panel_learn.rs`,
    `src/panel_structure_map.rs`, `src/panel_treemap.rs`,
    `src/panel_trigram.rs`, `src/panel_characterise.rs`,
    `src/panel_reference.rs` and `src/panel_workspace.rs`;
  - `src/structure.rs`;
  - in `src/workbench.rs`, the Report, Template and Unpacked tabs;
  - the Ask panel's link and template-offer handling in `src/dock.rs`;
  - `src/findings.rs`, except its bookmark rows (D) and its selection
    rows. Those call A's `select_finding`, which A converts.
- **Each tool's run becomes a job method.** Its params are the explicit
  span (`start`, `len`) and the tool's options, never the live selection
  read inside the method. Each tool keeps its default span (selection,
  else whole file or from the cursor) in the UI and passes it. The result
  is the job's result, and in the window the panel is filled as now. Use
  `workspace.window()` as `analysis.period_scan` does.
- **Results that today live only in panel state** stay there. The method's
  job result must carry them too, so a headless or MCP caller gets them.
- **Pins** that go to `bench.pinned` without a fact become
  `findings.publish {key}`/`findings.retract {key}`, so they are on the
  bus and journalled.
- **Work the app starts by itself** stays off `perform`: a refresh, a
  computation while a tab is drawn, a stale-result recompute. Only the
  person's clicks call `perform`.
- **New methods:** the list under Area C above.
- **Depends on** D's `documents.derive` (each "Open decoded" or "Open"
  row) and `view.set_shape {format}` (Bits and Images). Convert those rows
  last.

### D: Navigation, files and view

- **Your files:**
  - `src/api/view.rs`, `src/api/documents.rs`, `src/api/codecs.rs`,
    `src/api/application.rs` and `src/api/workspace.rs`;
  - `src/raster.rs` (serde for `PixelFormat`);
  - `src/bookmarks.rs`, `src/folds.rs`, `src/layouts.rs`, `src/layout.rs`,
    `src/dialogs.rs`, `src/sources.rs` (the UI), `src/settings.rs` and
    `src/legend.rs`;
  - in `src/workbench.rs`, the Live tab, file map, curve and media parts;
  - `src/dock.rs`, except the Ask link and template handling (C);
  - the toolbar's Format, Width, Origin, Zoom, Go to and Compression
    groups, and the File, Go and View menus in `src/app.rs`.
- **Your `src/app.rs` functions:** `open_dialog`/`complete_file_action`,
  `save`, `save_as_dialog`, `new_document`, `export_dialog`,
  `export_bytes_to`, `export_decompressed_to`, `back_to_parent` (callers
  only: the API's `documents.open` uses it), `toggle_compressed_view`,
  `decompress_in_place`, `compress_selection`, `recompress_selection`,
  `select_stream_at_cursor`, `align_view_to_cursor`, `reset_origin`,
  `adjust_bit_offset`, `apply_period`, `guess_image_shape`,
  `skip_selection`, `unfold`, `unfold_all`, `begin_bookmark`,
  `add_bookmark`, `remove_bookmark`, `goto_bookmark`, `jump_to_bookmark`,
  `reload_plugins`, `handle_dropped_files`, and the `fit_width_requested`
  handling in `src/view.rs`.
- **Land `documents.derive` and `Workspace::open_derived` first, in your
  first commit, and tell the lead.** B and C wait for it.
- **Keep `set_width`, `load_path` and `open_derived` as the internal
  setters** the API itself uses, as `set_width` is now. Convert the
  person's actions to call `perform`.
- **Settings, layouts, zoom and media** stay direct: the table marks them
  V.
- **New methods:** the list under Area D above.
