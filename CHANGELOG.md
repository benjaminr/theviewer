# Changelog

All notable changes to theviewer are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.3.0]: https://github.com/benjaminr/theviewer/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/benjaminr/theviewer/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/benjaminr/theviewer/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/benjaminr/theviewer/releases/tag/v0.1.1
