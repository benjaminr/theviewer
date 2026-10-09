# Changelog

All notable changes to theviewer are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-10-09

Worksheets: every file and every sheet made from one stays open, and steps
pass what they make and find to one another through an `output` parameter,
sheet anchors, variables and *Send to*, so a recipe saved from the History
tab replays on the next file. Notes in the History tab keep your reasoning.
Also built-in text codecs, packet filter expressions, AES, FAT volumes, PDF
and EXIF, checksum verification, and many fixes from working six CTF-style
challenges from start to finish.

### Added

**Worksheets**
- Every file opened and every sheet made from one (a decompressed stream,
  an unpacked node, a bit plane, a selection) stays open, one shown at a
  time, each with its own cursor, selection, shape and analysis. See
  [Worksheets](docs/guide/worksheets.md).
- The **worksheet strip** under the toolbar shows the active sheet's
  ancestry, its children under `▸` and the other files; `*` marks unsaved
  edits, and `×` or a middle-click closes a sheet with those derived from
  it. The **tree of sheets** (*≡ Tree*, `Shift+Cmd+T`, the Workspace tab)
  lists every sheet with the step that made it, with *Show*, *Compare with
  active*, *Close* and *Label…*; recipes name a sheet by its label.
- `Cmd+W` closes the sheet shown and those derived from it, asking first
  about unsaved edits; *File › Close other worksheets*; `Ctrl+Tab` and
  `Ctrl+Shift+Tab` cycle the sheets; the window title names the sheet.
- The tools' results are kept with each sheet. Strings, XOR, Crypto and
  Unpacked go on showing another sheet's results, saying whose (*From
  payload (doc-4) · Show it*), and the packet viewer reads, writes and
  draws only on the sheet its packets came from.
- `documents.activate` and `documents.close` (a sheet and every sheet
  derived from it); `documents.list` and `documents.info` give `parent`,
  `made_by` and label, and each journal entry the sheets it `made`.
- `diff.run` compares a document with another open one, given as `other`,
  and the Diff tab compares the sheet shown with another, without writing
  either to a file.

**Passing values between tools**
- **Send to.** Right-click a string, a key, a decode, a finding, a field in
  the Reference tab or the Inspector, a value the Inspector reads, a packet
  or the selection to send it to a new worksheet, a variable (named for
  what it is: `key`, a field's name, a string's label, `url`, `path`,
  `email` or `id`) or an open tool's input (the XOR and Selection keys, the
  Find needle, the AES key and crib, the CRC solver's records, the line
  code offset). *Copy value* and *Copy anchor* copy it. *Use as key*, *Open
  as worksheet* on findings, and dragging a row onto a field do the same.
- **Bound fields.** A field filled from another tool shows a chip of the
  value and where it came from (`NC500-2F357657 · from step 7, string
  /^NC500-/ ×`), and its step records the anchor, so a recipe finds the
  value again on the next file; × keeps it as a literal.
- **Output toggles** on the Selection menu's XOR, add, subtract and
  Decompress and on the XOR and Crypto tabs' *Apply*: in place, or a new
  labelled worksheet.
- The History tab's **Sheets** view groups the steps under the sheets they
  ran on, with where each anchored value came from and how many documents
  and literal offsets a recipe could not anchor (*Suggest anchors…*). Its
  footer lists the variables bound, with *+* to bind the selection.

**Analysis notes**
- **Notes in the History tab:** the box at its foot adds one where you
  are (`Cmd+Enter` or *Add note*), and each step's *Note* button starts one
  about that step. `#12` links to step 12 (`\#917` does not). Notes are
  edited and deleted from their cards, *Notes only* shows just them, and a
  note is never undone, played back or gone back past.
- **Kinds:** `observation`, `hypothesis`, `decision`, `fallback` and
  `conclusion`, shown as tags.
- *Export notes…* saves them as Markdown, titled by the input file, each
  cited step described in plain words, ending with every fallback.
- A read a note cites is kept as evidence, dimmed in the tab and left out
  of recipes unless an anchor cites it. A recipe carries each note on the
  first step it cites, "As recorded on <file>:".
- `history.note`, `history.edit_note`, `history.delete_note` and
  `history.export_notes`; `history.list` and `history.entry` give the
  notes. The MCP server lists `history_note` among its core tools.

**Recipes and the API**
- **One `output` parameter** on the methods that produce bytes:
  `"in_place"`, `"new"` (a sheet; `{"new": {"label": "payload"}}` labels
  it), `"return"` or `{"file": path}`. The result says where in `output`,
  and the journal, undo and recipes treat each call as its output says.
  Taken by `transform.apply`, `codecs.decode`, `crypto.decrypt`,
  `documents.derive` (which joins several documents' ranges with
  `sources`), `bits.open_plane`, `bits.decode_linecode`, `unpack.open`,
  `forensics.open_entry`, `packets.extract` and `packets.follow_stream`.
- **`crypto.apply`** applies a `crypto.attack` candidate, by job and index,
  or an operation, over a span; a recipe applies the candidate of the
  attack its own step ran.
- **Recipes keep the steps that make sheets** and name what they made with
  sheet anchors: `{"sheet": {"step": 2}}`, `{"sheet": "payload"}` (a step's
  `makes` label) or `{"sheet": "input"}`. Those steps return `output:
  {doc, label?, len}`, and `recipes.run` lists the sheets made.
- **Anchors at call time.** Any caller may pass `{"$anchor": …}`, `{"$var":
  "serial"}` or `{"$sheet": 7}` in place of a parameter's value; the call
  resolves it, and the journal keeps both, so a recipe saved from an MCP
  session finds its values again.
- **Pick, then and var anchors.** `pick` chooses an item from an earlier
  step's list (`where` with `regex`, `equals`, `contains`, `min`, `max`,
  `tag`, `all`, `any`; `sort`; `nth`; `[field=value]` and `..key` in its
  path); `then` works on another anchor's value, with arithmetic, `slice`,
  `int`, `hex`, `text_to_hex`, `hex_to_text`, `match`, `after`, `before`,
  `split` and `format`; `var` reads a variable. `part: "end"` gives the
  offset past a match, and `{"structure": "template:NAME"}` reads a pinned
  template.
- **Variables:** `vars.set`, `vars.list` and `vars.clear`, journalled and
  replayed, and in the MCP server's core tools.
- **A step's `expect`**: a path in its params, result or job that must be
  present, or match a regular expression, or the run stops there.
- *Make parameter* gives a parameter an anchor as its `default_anchor`, and
  `history.suggest_anchors` offers picks for literals from earlier lists.
- **Recipe format 2**, written only when a recipe needs it; both read.
- Through MCP, a result's `_meta.step` is its journal step, and a method
  that starts a job returns `{job, step}`.
- `theviewer replay --save-sheets DIR` and `--allow-writes`, and
  `--plugins DIR` for `replay` and `api` as for `mcp`.
- `history.list {order: "newest"}`; `unpack.open`, `.read` and `.save`
  name a node by path (`"bin/novacamd"`) and take `tree_doc`;
  `bytes.insert` takes `start` as well as `at`.

**Codecs and crypto**
- **Built-in text codecs:** base32, base64, base64url, hex text, DEC SIXBIT
  (`sixbit`) and AIS 6-bit (`ais6`), by id in `codecs.decode`,
  `codecs.open_decoded` and `transform.apply`, without a plugin.
  `codecs.detect`, *Probe* and `codecs.probe` find them, and `codecs.probe`
  tries every plugin codec too.
- **AES:** `crypto.decrypt` and `crypto.open_decrypted` decrypt AES-128,
  -192 and -256 in ECB, CBC or CTR mode, trying several `keys` and keeping
  the first with valid PKCS#7 padding; the Crypto panel has *Decrypt
  (AES)*.
- `transform.apply` takes rolling XOR, XOR with the previous byte, XOR then
  add, add then XOR and rotation; each `crypto.attack` candidate carries
  the `operation` that applies it, and the Crypto panel's *Apply* is that
  step.
- `crypto.attack` lists the key bytes a crib reveals (`key_fragments`) even
  when the key is longer than the crib, and proposes repeating XOR keys
  without one. `xor.recover_keys` gives each candidate a `rank`.

**Packets**
- **Filter expressions:** `and`, `or`, `not` and brackets; quoted text;
  `tcp.port` and `ip.addr` for either end; DNS flag bits; HTTP request,
  status and header fields; numbers for named values; `contains` and
  `matches`; and template fields (`template.type==60`).
- **Sorting and de-duplicating** by any column or field, in the Packets
  panel and `packets.list` (`sort`, `descending`, `dedupe`);
  `packets.conversations` and `packets.endpoints` sort too.
- `packets.extract` takes a field by name (`field_name`, one `label` of a
  DNS name), a `limit`, and without `indices` the packets a `filter`,
  `sort` and `dedupe` list. *Only the chosen field* saves or opens one
  field of each selected packet, reassembling a file sent in blocks.
- **HTTP bodies:** `packets.http_bodies` and *Open body as document* give
  each body de-chunked and decompressed.
- **Resynchronising splits:** `resync` and `sync` in a length field find
  their place again at the sync word; the protocol analysis finds sync
  word and length framing.

**Forensics and formats**
- FAT12, FAT16 and FAT32 volumes, in a disk's partitions too, with long
  names, DOS times and deleted files recovered, each entry's clusters and
  ranges, and the boot sector's geometry; `forensics.open_entry` opens
  them.
- ZIP entry flags, and a `password` for `unpack.run` and the Unpacked tab
  to decrypt ZipCrypto.
- EXIF tags in JPEGs; a PDF parser listing objects, streams with their
  filters, and embedded files; JSON members as fields.

**Checksums and structure**
- **`checksums.verify`** lists the records whose stored checksum a
  `model` rejects, and **`checksums.compute`** computes one over a span;
  `checksums.solve_crc` takes a packet `set` and `filter`.
- Template fields read only `if` a condition holds, and `==` and `!=`.
- `bits.detect_linecode` gives each decode its error-free stretches and
  names codes that tie with the best; `columns.profile` names fields by
  where they start (`field_7`).

### Changed

- **Back keeps the derived sheet open.** Back (`Cmd+[`, *Back*, *Back
  out*, `Cmd+D` where no stream is at the cursor) shows the parent and
  leaves the child open. *Decompress* is offered in every sheet, so a
  stream in a stream can be followed down, and deriving twice gives
  siblings.
- **File › Open adds a worksheet** rather than closing the others, as do
  *File › New*, `documents.open`, `documents.new` and
  `documents.open_source`; opening a file already open shows it again.
- **An omitted `doc` means the caller's focus.** At the window, and for
  plugins and Ask, that is the document shown. For MCP clients and the
  command line it is the one they last opened or activated: making a sheet
  no longer moves it. Journal entries now name their document, and
  `theviewer mcp --legacy-current` keeps the old meaning for one release.
- **A replay refuses unknown document ids.** A step naming a document that
  is neither the run's input nor a sheet the run made stops the run,
  format 1 recipes too; a step with no `doc` runs on the input.
  `theviewer replay` runs steps that write files only with
  `--allow-writes`.
- **`jobs.status` polls are not journalled** and take no step number, so
  an anchor on a job's result cites the step that started it.
- **Recipe saves fail rather than keep stale literals.** An anchor citing a
  step the recipe cannot hold, or a recipe that would not replay, is
  refused, naming the step, and the History tab says why before saving.
  A `$anchor`, `$var` or `$sheet` that is not an anchor is refused rather
  than passed on as a literal.
- **Packets are numbered from 0 in the API**, `packets.columns.read` and
  the `packets.follow_stream` text included; the Packets panel's *No.*
  still counts from 1.
- **`bytes.read` returns a short read** past the end of a document, with
  `len` and `short`, rather than failing.
- A packet filter naming an unknown field is refused with the names it was
  close to, rather than matching nothing.
- A recipe run's edits undo as one step of each document it edited.
- `packets.extract` is a read when it returns its bytes.
- `codecs.decode`'s and `crypto.decrypt`'s `data` is left out when the
  bytes went elsewhere; `codecs.open_decoded` takes any codec id.
- The literal-offsets replay warning is given only when a recipe has one.
- `alignment.run` samples a long set of messages evenly rather than taking
  the first 256.
- `Esc` closes the image, sound or video being viewed.
- The example plugin `base64.lua` registers its codec as `base64-lua`, so
  it no longer shadows the built-in `base64`.

### Fixed

**Recipes and the window**
- Recipes saved from a session that derived documents did not replay, and
  `history.recipe` and `history.save_recipe` kept different steps; every
  recipe now comes from one builder.
- A recipe made from the Strings tab searched the next file over the
  recorded file's length; it now searches the whole file.
- `Cmd+Enter` in a text field opened the media at the cursor, and the
  floating selection toolbar covered an image being viewed.

**Crypto**
- `xor.recover_keys` ranked a single byte that flips the text's case above
  a word key, and an over-fitted multiple above the true shorter key, and
  gave a `score` its own order contradicted.
- `crypto.find_keys` found a raw key ending in a padding-like byte a byte
  early.
- A key pinned by a crib lost the crib as its reason when found without it
  too.

**Packets**
- `X contains Y` read as three words, and a DNS flag tshark gives in words
  was not found by number.
- Fields tshark decoded never reached the filters or `packets.dissect`.
- A conversation's first packet was given as 0 or its place among those
  kept.
- The protocol analysis ranked short or out-of-step length chains above a
  sync word, and took address bytes for the message type.
- A split's description said "1 frames"; a split that lost its place said
  the frames cover every byte.

**Forensics**
- An encrypted ZIP showed ciphertext as a member's content and dropped
  deflated members; each is now listed as encrypted.

**Heuristics**
- `analysis.overview` headlines a partitioned disk as a disk image, and
  frames headed by a sync word as framed messages, not machine code.
- A Cortex-M vector table counts towards Thumb, so a small firmware image
  is not taken for x86.
- `protocol.analyse`'s template reads a type's own fields only in that
  type, even when frames are cut short, and keeps a `trailer` out of the
  payload.
- `templates.infer` reads a timestamp as one field, a span to the end of
  its record, a NUL-padded name whole, a few-valued column as a `kind` and
  a number below 2^24 as a u32.
- `columns.profile` keeps a repeating or backwards counter whole, finds a
  Unix time at an odd offset, and no longer guesses floats from three
  records.
- `checksums.find_stored` finds a one-byte sum before padding, not only as
  the last byte, and `bits.scan_periods` no longer takes the idle between
  bursts for the sync word.
- Float arrays are no longer found in bit-packed radio samples, nor icons,
  TrueType fonts and Targa images at any zero run.
- A timestamp finding's title said "u32 LE LE", and `findings.publish`
  refused a finding without `fields`.

## [0.3.1] - 2026-10-07

### Fixed

- Arrows in labels and buttons ("← Back to the cursor", the recipe
  preview, the follow-stream legend) draw instead of boxes.
- A decompressed stream's toolbar, *Back* and the API's document list name
  the file it came from rather than "untitled".
- A packet picked in the packet list shows its innermost protocol, such as
  DNS, in the Reference tab rather than its record header.
- The Reference tab no longer adds a format guessed from bytes a packet
  dissector has already read, such as a DNS name taken for CBOR.
- The recipes guide's finding anchor example uses an id that exists.

## [0.3.0] - 2026-10-07

A packet viewer, reference notes on about 260 formats and protocols, a
data API with a command line and an MCP server, and a history of every
step that can be saved as a recipe and run on other files. The README is
now short, with a [user guide](docs/guide/README.md) for the detail.

### Added

**Layouts and the workspace**
- A *Layout* menu with recommended layouts for each kind of work (Overview,
  Network capture, File structure, Firmware and code, Signals and bit
  streams, Forensics and carving, Compare files, Focus on the view), each
  opening only the tools it needs.
- Layouts you save by name, with Update, Rename and Delete; *Last session*;
  a choice of what opens at start; and a layout suggested in the status
  bar for each file that opens as a capture, an executable, a disk image or
  another known format. `--layout` takes any of them for one session.
- The main view's tab is now *Bits*, with *Packets* beside it.
- A legend bar above the view and the hex dump, listing the colouring in
  effect and every highlight layer, each of which can be hidden.
- Every view keeps up with edits: cheap ones refresh themselves; the rest
  say *Out of date* with a *Refresh* button.

**Viewing and selecting**
- Column selections (`Alt`+drag), multi-range selections (`Cmd`+click and
  *All matches*) and a multi-select mode (`M`), shared by the raster, the
  hex dump and the packet viewer.
- One *Selection* menu in every view, the findings list and a floating
  toolbar: XOR, add and subtract a key, rotate bits, swap byte order,
  number records, duplicate, copy as a C array or Base64 and more, on any
  selection as one undo step.
- Moving, resizing and nudging selections by hand, and *Skip* to fold bytes
  out of the views.
- Numeric heatmaps of 16- and 32-bit integers and 32-bit floats, a sixth
  palette (diverging), Morton (Z-order) curves, curve colours by entropy,
  region type or byte class, colouring by region when zoomed out, a row
  difference view, and hex values inside pixels (off by default).

**New tools**
- *Structure map*: segments, *Find more like this* and feature tracks.
- *Trigrams*: a rotatable 3D cloud of byte triples, coloured by region.
- *Size map*: what takes up the space, as nested rectangles.
- *Characterise*: compressibility by codec, raw media streams, and text
  encoding and language; *Characterise with Ask*.
- *Learn*: learn a format's signature and header template from samples,
  and fuzzy-match files and shared fragments.

**Packet viewer**
- A *Packets* tab: packet lists from captures, the protocol framing or the
  selection, with dissection, conversations, endpoints, *Follow stream*,
  filters and pcap export.
- Captures in pcap, pcapng, Sun snoop, Network Monitor 2.x and Endace ERF,
  and captures compressed whole with gzip, found anywhere in a file.
- Link types: Ethernet, raw IP, Linux cooked capture, BSD and OpenBSD
  loopback, PPP, Cisco HDLC, 802.11 and radiotap, and LLC/SNAP.
- Dissectors for ARP, IPv4, IPv6 with its extension headers, whole ICMP
  and ICMPv6 messages, TCP, UDP, DNS (with authority, additional and EDNS
  records), HTTP, NTP (with extension fields), Modbus/TCP, MQTT, SNMP v1,
  v2c and v3, DHCP and BOOTP, TFTP, TPKT with COTP and S7comm, the NetBIOS
  session service with SMB1 and SMB2/3, and RTP and RTCP.
- Splitting frames out of any range by a fixed width, a length field (with
  auto-detection) or a pattern with `??` wildcards.
- *Decode frames as*: frames of unknown format are tested against each
  decoder and decoded as the protocol that reads nearly all of them, or as
  the protocol or template you choose. Settings can turn detection off.
- Raster and hex grids with one packet per row, column selections across
  packets, and fields named by the decoded protocol.
- Editing packets in place, by byte or by field, *Fix checksums*, and
  deleting, saving or transforming several packets at once.
- Filters by Wireshark field names (`ip.ttl==64`, `dns.qry.name~example`).
- Optional decoding with Wireshark's tshark, merged where our dissectors
  stop, with settings to use it always and say where it is.

**Reference notes**
- A *Reference* tab explaining each format around the cursor: how it is
  organised, its specifications, an RFC-style header diagram, and the live
  fields with their meaning. Field explanations on hover in the Inspector
  and the packet trees.
- Notes on about 260 file formats, protocols, capture formats and streams,
  with ports, EtherTypes and IP protocol numbers.
- RFC sections fetched from the RFC Editor when you click, and kept in
  `~/.cache/theviewer/rfc`.
- Wireshark display-filter names for protocols and fields, copied on
  click and found by search.
- A guess at an undissected payload from its port, EtherType or IP
  protocol; *Browse all…* with search by name, key or port.
- Your own notes in `~/.config/theviewer/reference/`.
- `check_reference`, which checks the notes' RFC titles, sections, ports,
  links and Wireshark names against their sources.

**Data API, bus and automation**
- A data API: one table of methods with JSON schemas for reading, editing,
  search, structures, findings, packets, jobs, the view and every tool, run
  against the window or without one. Every action in the window goes
  through it. Described in [docs/api.md](docs/api.md).
- `theviewer api METHOD [PARAMS] [FILE]` runs one method from the shell;
  `--save` saves its edits, and `--describe` lists every method.
- A workspace bus where tools publish what they learn (findings,
  structures, regions, record widths, frames, protocols, jobs, plugin
  logs), so they use each other's results even while hidden; a *Workspace*
  tab showing those facts and recent events.
- Background jobs with ids, progress and cancellation.
- Edits from plugins, Ask and other clients, each one undo step labelled
  with its caller, with *Settings › Permissions* (always allow, always ask,
  never allow) and a window asking you to allow each change.
- Lua plugins can call the data API, subscribe to the bus, publish facts
  and register methods of their own.
- `theviewer mcp`, an MCP server for Claude Code, Claude Desktop and other
  clients, with tools, resources, subscriptions and prompts. It lists the
  core methods and the plugins' as tools, with `api_search`,
  `api_describe` and `api_call` to reach the rest; `--all-tools` lists
  every method and `--output-schemas` adds result schemas. See
  [docs/mcp.md](docs/mcp.md).
- Ask can use every method that reads or edits, plugins' included, and is
  sent the reference notes for the formats at the cursor.

**History and recipes**
- A journal of every step by every caller, and a *History* tab to read it:
  undo any step, go back to one, and play steps back at the speed you
  choose.
- Recipes: saved runs of steps with anchors (a search match, a structure
  field, a finding, the selection, an earlier step's result) and
  parameters, recorded as you work or set by hand.
- *Run recipe…* to preview a recipe on this file and run it as one undo
  step; `theviewer replay` to run one over many files. See
  [docs/recipes.md](docs/recipes.md).

**Development**
- `capture_corpus`, a developer tool that runs the packet code over
  Wireshark's sample captures and compares it with tshark.

### Changed

- *View › Layout*'s presets are replaced by the *Layout* menu. `--layout
  default` still opens the Overview; `--layout right` and `--layout left`
  are gone.
- The toolbar's groups fill each row before starting the next, in the
  order you dragged them into.
- Signature scans are much faster: a 35 MB fuzzed file that took minutes
  now scans in a fifth of a second, and nested ranges over repetitive bytes
  can no longer hang a scan.
- Numeric sequences are checked against nearby counters only, so windows of
  many short runs scan in moments.
- A signature with a specific magic now beats one anchored on a byte or
  two, so a PDF is no longer taken for MATLAB source.
- Undo steps are named after what made them and who did it.
- `--help` prints the usage to standard output and exits 0, and an unknown
  `--tool` name is reported in the status bar rather than ignored.
- A plugin's `print` writes to its log rather than standard output, and an
  action's `host:replace` edits through the API, so the edit is in the
  history and can go into a recipe.

### Fixed

- A TCP payload is taken for HTTP only when it starts with a whole request
  or status line, so RTSP, SIP and the middle of a stream are left alone.
- The first fragment of a fragmented IP packet is no longer decoded as a
  transport header of an incomplete message.
- A DNS message stops being read after more questions than are present,
  rather than taking the rest for answers.
- An OS/2 bitmap's width, height and bit depth are read at their real
  offsets.
- Nudging ranges a byte apart no longer scrambles the bytes between them.
- Row padding and field offsets beyond what fits are refused rather than
  overflowing.
- Undoing a step, or going back, is all or nothing: a failure part-way puts
  back what was undone.
- A `null` inside an array is passed back from Lua as `null`.
- Piping the command line's output into a reader that stops early, such
  as `head`, no longer panics.

## [0.2.0] - 2026-10-05

About twenty new analysis tools for unknown data, firmware, protocols and
crypto, plus a headless mode for scripts.

### Added

- *Dot plot*, *Images* (uncompressed picture finder), *Firmware*
  (processor, load address and Cortex-M vector tables), crypto constants,
  *Solve a custom CRC* and *Align messages*.
- *Bits*: bit-level frame lengths and sync words, bit planes, line codes,
  number-type guessing and length-field discovery.
- *Crypto*: ECB detection, key and certificate finding, and attacks on
  simple ciphers.
- *Compare*: variation, correlation and recording timelines across many
  files.
- *Forensics*: SquashFS, CramFS, JFFS2 and UBI unpacking, and block
  classification for carving.
- `theviewer FILE --report` and `--json`.

### Fixed

- A malformed DER BIT STRING could crash the scan; one faulty detector or
  parser can no longer fail a whole scan.

## [0.1.2] - 2026-10-05

### Fixed

- File dialogs no longer freeze the window: they open as a sheet while the
  app keeps running.
- *Compare with file…* switches to the Diff tab, so the comparison always
  finishes and shows.

## [0.1.1] - 2026-10-05

The first published release.

### Added

- Raster view in twelve pixel formats, with a hex dump and value inspector.
- Record-width detection, pattern detection, a signature catalogue and
  field trees for executables, images, archives, captures, certificates,
  disks and schemaless formats.
- Embedded media and compressed streams opened where they sit.
- Columns, Protocol, Template, Statistics, Strings, XOR, Disassembly,
  Unpacked, Checksums, Diff and Live tools, and *Ask*.
- Dockable panels, a rearrangeable toolbar and startup defaults.

### Changed

- The file report no longer lists bare magic-number matches as objects.
- *Columns* profiles from the cursor's record to the end of the table.

[0.4.0]: https://github.com/benjaminr/theviewer/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/benjaminr/theviewer/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/benjaminr/theviewer/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/benjaminr/theviewer/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/benjaminr/theviewer/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/benjaminr/theviewer/releases/tag/v0.1.1
