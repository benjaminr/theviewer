# Finding structure

Most unknown files are made of a few kinds of part: headers, tables of
fixed-size records, text, code, compressed or encrypted blobs and padding.
These tools find those parts, name them and turn them into something you
can apply.

- [Detect the record width](#detect-the-record-width)
- [Findings](#findings)
- [Report](#report)
- [Structure map](#structure-map)
- [Columns](#columns)
- [Templates](#templates)
- [Learn a new format](#learn-a-new-format)
- [The signature catalogue](#the-signature-catalogue)

## Detect the record width

Press *Detect width* in the toolbar's *Analysis* group (or right-click and
*Detect width from here*). theviewer scans for repeating periods and
suggests record sizes; pick one and the data lines up into columns. *Chart*
shows the period chart, a bar for each candidate width. Settings can detect
the width whenever a file opens, and `--detect` does it from the command
line.

The [Structure map's](#structure-map) *Feature tracks* show the best record
width at each point along the file, for files whose records change size
part-way through. The [Bits tool](tools.md#bits) finds frame
lengths in bits, for data that is not byte-aligned.

## Findings

The **Findings** panel lists everything the detectors recognised:
counters, timestamps, offset tables, float arrays, text, padding, file
signatures, compressed streams, crypto constants, and what tools, plugins,
Ask and other clients pinned. Each kind has a chip with its count; click a
chip to show or hide that kind, and use the filter box and *min confidence*
slider to narrow the list.

Click a finding to select its bytes; `Cmd`+click adds it to the selection.
Right-click it for *Select*, the
[Selection menu](viewing-and-editing.md#changing-bytes), *Decompress* for a
stream, *View / play* for an image or other media, *Open in packet viewer*
for a capture, and *Bookmark*. Right-clicking a byte of a finding in the
view offers *Select this finding* too.

Settings chooses which kinds are shown by default; hidden kinds are left
out of both the highlights and the list.

## Report

**Report** (*Tools › Explain this file*) describes the whole file in plain
sentences, part by part, each linked to its bytes: "At 0x2770, a zlib
stream of 5.7 KiB (94.9 KiB decompressed)". It also draws a coloured map of
the file above the view (turn it off with *File map above the view* in the tab, or *View › File
map*), and
the views colour themselves by its regions when zoomed out. *Re-analyse*
runs it again after edits.

The same report is printed on the command line by `theviewer FILE
--report`, or as JSON with `--json`; see [Command line](command-line.md).

## Structure map

**Structure map** has three parts:

- **Segments** splits the file into regions of one kind (text, tables,
  code, compressed, padding and so on), with boundaries on the real edges.
  It groups similar regions into types and colours them on a strip and on
  the file map. *Show on file map* pins the segments as findings; pinned
  segments follow edits.
- **Find more like this** (*Find similar*) scores every part of the file
  against the selection and highlights the matches; *Highlight all* pins them as
  findings.
- **Feature tracks** draws, at each point along the file, the entropy,
  compressibility, printable and zero bytes, the mix of byte kinds and the
  best record width. *Use width here* applies that width.

## Columns

For a table of fixed-size records, **Columns** profiles each byte position
across the records, from the cursor's record to the end of the table. Each
position is marked as constant, counter, rising, a few values, text, random
or mixed, and the positions are joined into the fields they add up to:
counters, timestamps, offsets, lengths, flags and so on. One
click applies them as a template. It takes its record length from the width
the period scan found.

![The Columns tool under the raster view: one bar per byte position, coloured by kind, with the fields it found listed below](../images/columns.png)

## Templates

**Template** decodes a structure you describe in a small language, such
as:

```text
struct Chunk { id: char[4]  len: u32  data: bytes[len] }
```

You see it decoded as a tree and a table, and outlined in the views. *Apply
at cursor* decodes the structure there (at the selection's start when there
is one); *Infer from selection* proposes one from a few selected records;
*Clear* removes it. Columns, Protocol,
Ask and plugins can all offer templates you apply in one click. Your own
templates live in `~/.config/theviewer/templates/`. The language is
described in [docs/templates.md](../templates.md).

## Learn a new format

Give **Learn** a few samples of an unknown format and it finds what they
share: magic bytes, fixed fields, a length field. It then writes a
catalogue entry, so the format is recognised from now on (*Save to my
catalogue* keeps it in `~/.config/theviewer/catalog/`), and a template for
its header.

*Fuzzy match* compares files by an ssdeep-compatible fuzzy hash and finds
the fragments they share.

## The signature catalogue

theviewer recognises about 600 file signatures, from Apache Tika's
database plus a curated set covering firmware, filesystems, bytecode, ROMs
and protocols. Add your own as TOML files in `~/.config/theviewer/catalog/`,
in the form used by `catalog/curated.toml` (offsets, masks, nested
conditions and length rules).
