# Changelog

All notable changes to theviewer are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Notes in the history.** Write what you are doing and why into the
  History tab as you work: the box at its foot adds a note where you are
  (`Cmd+Enter` or *Add note*), and each step's *Note* button starts one
  about that step. A note is a card among the steps, with who wrote it and
  when, and `#12` in it is a link that scrolls to step 12 and highlights it.
  Notes can be edited and deleted from their cards, *Notes only* shows just
  them, and *Export notes…* saves them as Markdown with the steps they cite.
  A note changes nothing: it is never undone, played back or gone back
  past.
- `history.note`, `history.edit_note`, `history.delete_note` and
  `history.export_notes` in the API. `history.list` and `history.entry`
  give each note's text and linked steps, and on each step the notes
  linked to it.
- The MCP server lists `history_note` among its core tools and asks the
  model to note its reasoning as it works.
- A recipe made from the history carries the notes linked to each step in
  that step's `note`.
- **Packet filters as expressions.** `and`/`&&`, `or`/`||`, `not`/`!` and
  brackets; `"quoted text"`; `tcp.port`, `udp.port` and `ip.addr` for
  either end; the DNS flag bits (`dns.flags.response==0`); the parts of an
  HTTP request or status line and any HTTP header (`http.request.method`,
  `http.content_encoding`); and numbers for named values
  (`dns.qry.type==16`).
- **Template fields in filters:** `template.type==60`, or `type==60` when
  the name is the template's; the packet summary shows up to twelve of a
  template's fields.
- **Sorting and de-duplicating packets** by any column or field, in the
  Packets panel (*Sort by*, *Desc.*, *Unique*) and in `packets.list`
  (`sort`, `descending`, `dedupe`). Packets opened, saved or exported
  together come out in the order shown.
- `packets.extract` takes a field by name (`field_name`), at each packet's
  own offset and length, and one `label` of a DNS name.
- **HTTP bodies.** `packets.http_bodies` and the Follow stream view's *Open
  body as document* give each request's and response's body put together,
  de-chunked and decompressed (gzip, deflate).
- **Resynchronising length-field splits.** `resync` and `sync` in
  `packets.sets.create`'s `length_field` find the place again at the sync
  word after a stray byte or a frame cut short, and the description lists
  the stretches skipped.
- **Sync word and length framing** in the protocol analysis, which
  `packets.detect_length_field` returns with its sync word.
- `packets.conversations` and `packets.endpoints` take `sort` (packets,
  bytes, address or first packet).
- `bytes.insert` takes `start` as well as `at`.
- **Recipes keep the steps that make sheets.** `documents.derive`,
  `codecs.open_decoded`, `bits.open_plane`, `bits.decode_linecode`,
  `unpack.open`, `forensics.open_entry`, `crypto.open_decrypted`,
  `packets.sets.create` with `gunzip` and `packets.http_bodies` with `open`
  make a new document, a sheet, from another; a recipe now repeats them and
  names what they made with a `sheet` anchor: `{"sheet": {"step": 2}}`
  (the sheet step 2 made), `{"sheet": "payload"}` (one a step labelled with
  its `makes`) or `{"sheet": "input"}` (the run's document).
- Each of those methods returns the sheet as `output: {doc, label?, len}`
  (`outputs` for several), beside its other fields, and `api.describe`
  lists their `outputs`.
- `documents.list` and `documents.info` give a derived document's
  `parent` and `made_by` (the step, method and parameters that made it),
  and each journal entry the sheets it `made`.
- **Recipe format 2**, written only when a recipe needs it: sheet anchors,
  a step's `makes` label and `inputs`. Recipes without them are written as
  format 1, as before, and this build reads both.
- The report of a recipe run lists the `sheets` it made.
- `theviewer replay --save-sheets DIR` saves each sheet a run made, and
  `--allow-writes` lets steps that write files run; `theviewer replay` and
  `theviewer api` take `--plugins DIR`, as `theviewer mcp` does.
- **Anchors at call time.** Every caller (the person's panels, Ask,
  plugins, MCP clients, the command line) may pass an anchor in place of
  any parameter's value: `{"$anchor": …}`, `{"$var": "serial"}` or
  `{"$sheet": 7}` / `{"$sheet": "payload"}`. The call resolves it against
  the session before the method runs, and the journal keeps both the value
  and the anchor, so a recipe saved from an MCP session finds its values
  again without `history.make_anchor`.
- **Pick, then and var anchors.** `pick` chooses an item from a list in an
  earlier step's result by what it holds (`where` with `regex`, `equals`,
  `contains`, `min`, `max`, `tag`, `all` and `any`; `sort`; `nth`;
  `field`), naming the step by number or as `"@label"`; `then` works on
  another anchor's value (`add`, `sub`, `mul`, `and`, `text_to_hex`,
  `hex_to_text`, `int`, `slice`, `len`); `var` reads a variable.
- **Variables.** `vars.set {name, value}` binds a value found to a name,
  journalled and replayed, and undone by putting back the value before;
  `vars.list` lists them with where each came from, and `vars.clear` clears
  one or all. In a recipe, a `vars.set` keeps its anchor, so the value is
  found again on the next file.
- *Make parameter* (`history.make_parameter`) on a value an anchor found
  makes a parameter whose default is that anchor (`default_anchor`): the
  recipe finds the value unless one is given.
- `history.suggest_anchors` offers picks for literals found in lists
  earlier steps returned (strings, keys, candidates): by a pattern of the
  text's shape, by the item's tag, or by its place.
- **Each caller has a focus**, the document an omitted `doc` means for it:
  the current document when it first calls, then the one it opens or
  activates. `documents.activate` moves it, `documents.list` marks it
  (`focus`), and `output: {"new": {"focus": true}}` moves it to the sheet
  made.
- `unpack.open`, `unpack.read` and `unpack.save` take `tree_doc`, the
  document unpacked, which defaults to the one `unpack.run` last ran on.
- The MCP server lists `vars_set` among its core tools, and its
  instructions ask the model to name sheets with `{"$sheet": N}`, bind the
  values it finds with `vars_set` and pass them on with `{"$var": name}`.
- `theviewer mcp --legacy-current` makes an omitted `doc` mean the current
  document for one more release.
- **One `output` parameter** on the methods that produce bytes, saying
  where they go: `"in_place"` (an undoable edit of what they came from),
  `"new"` (a sheet derived from it; `{"new": {"label": "payload"}}` labels
  it, and a recipe names it by the label), `"return"` (in the result) or
  `{"file": path}` (which needs leave to edit). Each result says where in
  `output`: `{doc, label, len}`, `{version, len, ranges}`,
  `{len, encoding, data}` or `{path, len}`. `api.describe` lists each
  method's outputs and default, and a call is journalled, undone and kept
  by recipes as its output says.
  - `transform.apply`: in place by default; `new` and `return`.
  - `codecs.decode`: returned by default; `new` and `in_place`. It takes
    any codec `codecs.list` lists, plugins' included, or the first built-in
    decompressor that decodes there when none is named; so does
    `codecs.open_decoded`.
  - `documents.derive`: a new sheet by default; `file`. It joins ranges of
    several documents with `sources: [{doc, ranges}]`.
  - `bits.open_plane` and `bits.decode_linecode`: `return` beside `new`.
  - `unpack.open` and `forensics.open_entry`: `return` and `file` beside
    `new`.
  - `packets.extract`: `new` (a sheet of the set's document) and `file`
    beside `return`. Without `indices` it takes the packets
    `packets.list` lists with `filter`, `sort` and `dedupe`, in that
    order, so a recipe extracts the same packets of another capture.
  - `packets.follow_stream`: `new`, with `direction` to take one side's
    bytes.
  - `crypto.decrypt`: `new`, `in_place` and `file` beside `return`.
- **`crypto.apply`** applies a `crypto.attack` candidate, by its job and
  index, or an operation, over a span: to a new sheet by default, or in
  place, returned or to a file. A recipe applies the candidate of the
  attack its own step ran.

### Changed

- A recipe run no longer takes the first document id its steps name for
  the file it runs on. A step naming a document by an id that is neither
  the run's input nor a sheet the run made stops the run (format 1 recipes
  too); a step with no `doc`, or `"current"`, runs on the input.
- `theviewer replay` refuses a step that writes a file (such as
  `documents.export`) unless given `--allow-writes`.
- A recipe run's edits undo as one step of each document it edited, sheets
  included, rather than only of the input.
- `documents.derive`, `bits.open_plane`, `unpack.open` and
  `forensics.open_entry` return the new document's fields with `output`
  beside them; `packets.sets.create` returns the set's with `output` when
  it opened a decompressed capture.
- **An omitted `doc` means the caller's focus**, not the current document.
  At the window nothing changes: the person's focus is the document shown,
  and plugins and Ask, which act for the person, follow it. For MCP
  clients and the command line, deriving a document, opening a node or
  decompressing a stream no longer moves where their next call without
  `doc` goes; `"current"` still names the document opened
  or made last. Every journal entry's `params` now name the document.
- A value marked `$anchor`, `$var` or `$sheet` that is not an anchor is
  refused rather than passed to the method as a literal.
- Recipes that use pick, then or var anchors, or a parameter whose default
  is an anchor, are written as format 2.
- `transform.preview`, `codecs.open_decoded`, `crypto.open_decrypted`,
  `documents.export`, `unpack.read` and `unpack.save` stay, as shorthands
  for the method they name with an `output`. `transform.apply`,
  `codecs.decode`, `crypto.decrypt`, `packets.extract` and
  `packets.follow_stream` results gain `output`; `codecs.decode`'s and
  `crypto.decrypt`'s `data` is left out when the bytes went elsewhere, and
  `bits.decode_linecode`'s `document` when they were returned.
- `packets.extract` is a read when it returns its bytes, kept among the
  recent reads rather than as a step; written to a file it is still a step
  that needs leave to edit.
- `codecs.open_decoded`'s `codec` is the codec's id as a string, any
  `codecs.list` lists, where it was one of the built-in decompressors.

- A filter naming a field the packets cannot have is refused with the
  names it was close to, rather than matching nothing.
- `bytes.read` past the end of a document returns the bytes there are,
  with `len` and `short`, rather than failing.
- Packets are counted from 0 everywhere in the API: `packets.columns.read`
  and the `packets.follow_stream` text now number them by their index, as
  the other methods do. The Packets panel's *No.* still counts from 1.
- `alignment.run` clusters an even sample of a long set of messages and
  puts every other message into the type it is most like, rather than
  looking at only the first 256; the result's notes say so.

### Fixed

- Recipes saved from a session that derived documents did not replay:
  the steps that made the documents were left out, later steps kept their
  session's ids (`doc-4`), and the replay ran such a step on the input, or
  stopped. `history.recipe`, `history.save_recipe`, `recipes.save` and the
  History tab now share one builder, which keeps the steps that make
  sheets, takes each step's document from the journal rather than its
  params (often none), takes the recorded file from the documents' lineage
  rather than the first id named, and names every document as a sheet
  anchor, at any parameter path.
- A recipe that would not replay (a step on a second file, or on a sheet
  made outside the history or by a step it leaves out) is refused, naming
  the step and why; the History tab says so before asking where to save.
- `history.recipe` and `history.save_recipe` kept different steps.
- `packets.follow_stream` and a filtered `packets.conversations` gave a
  conversation's first packet as 0, or as its place among the packets
  kept, rather than its index in the set.
- Fields tshark decoded never reached the API's filters or
  `packets.dissect`.
- A length-field split that lost its place said "the frames cover every
  byte"; it now says where frames stop starting with the sync word.
- The protocol analysis ranked a few-message u16 length chain, or a chain
  out of step with the sync word, above a sync word explaining nearly every
  byte; called address bytes the message type and missed the type after
  them; and gave its template two fields of the same name.
- `transform.apply` and `documents.derive` take rolling XOR, XOR with the
  previous byte, XOR then add, add then XOR and per-byte rotation, and each
  `crypto.attack` candidate carries the `operation` that applies it. The
  Crypto panel's *Apply* is now a `transform.apply` step a recipe repeats.
- `crypto.attack` with a crib lists the key bytes the crib reveals
  (`key_fragments`), *key prefix at offset 0* first, even when the key is
  longer than the crib and no decode comes of them.
- `crypto.decrypt` and `crypto.open_decrypted` decrypt AES-128, AES-192
  and AES-256 in ECB, CBC or CTR mode, with PKCS#7 padding; the Crypto
  panel has a Decrypt (AES) section, and *Use this key* beside a raw key
  found fills in its key.

### Fixed

- `xor.recover_keys` and the XOR tab fold a long key that nearly repeats a
  shorter one (one column solved wrongly) to that shorter key, offer both,
  and rank the shorter first when they score alike.
- `crypto.find_keys` reports a raw key with a zero at its edge, beside
  zero padding, at its aligned offset, and the alignment one byte along as
  an alternative, rather than only the earlier one.
- Forensics reads FAT12, FAT16 and FAT32 volumes, inside a disk image's
  partitions too, with long names, DOS times and deleted files recovered
  on a contiguous assumption; `forensics.open_entry` opens them.
- The FAT boot sector shows sectors per FAT, hidden sectors, media, the
  serial number and the FAT, root and data offsets, and takes its type from
  the cluster count.
- JPEG field trees show EXIF tags; a new PDF parser lists objects, streams
  with their filters and offsets, and embedded files.
- The ZIP field tree shows each entry's flags: encrypted, data descriptor,
  UTF-8 names. `unpack.run` takes a `password`, and the Unpacked tab a
  password field, to decrypt ZipCrypto entries.

### Fixed

- Unpacking an encrypted ZIP lists every member, marked "encrypted
  (ZipCrypto)" or "encrypted (AES)" with no content, instead of showing
  ciphertext as the file and dropping deflated members; a member that does
  not inflate is kept with the error.

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

[0.3.1]: https://github.com/benjaminr/theviewer/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/benjaminr/theviewer/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/benjaminr/theviewer/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/benjaminr/theviewer/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/benjaminr/theviewer/releases/tag/v0.1.1
