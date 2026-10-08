# Worksheets

A **worksheet**, or sheet, is a document open in the window. Every file you
open is a sheet, and so is everything you make from one: a decompressed
stream, a node unpacked, a bit plane, a selection opened as a document of
its own, the bytes a packet carries. The window shows one sheet at a time,
the **active** one; the others stay open behind it, each where you left it.

Each sheet remembers where it came from. A file you open is a **root**; a
sheet made from another is its **child**, and knows the step that made it.
Deriving twice from the same sheet gives two children side by side, and
nothing you do to one closes another.

## The worksheet strip

The strip under the toolbar shows where you are:

```
≡ Tree  firmware.bin ▸ zlib@0x12e40 ▸ plane 0*  ×  │  capture.pcapng
```

- The **trail** is the active sheet's ancestry, its root first. Click any
  sheet in it to show it; the sheets below it stay open.
- **▸** after a sheet drops down its children, so the siblings of the next
  sheet in the trail are a click away, and the sheets below the one shown
  are too.
- After the separator come the **other roots**: the other files open.
- `*` marks a sheet with unsaved edits.
- **×**, or a middle-click on a sheet, closes it with every sheet derived
  from it. Right-click a sheet for *Show*, *Compare with active*, *Label…*
  and *Close*.

A derived sheet is named after its parent and what made it
(`firmware.bin › zlib@0x12e40`); the strip and the title leave the parent's
name off, as it is just before it in the trail. With one file open, the
strip is a single short line.

## Going back and forth

- **Back** (`Cmd+[`, *Back* in the status bar, *Back out* in the
  Compression group, *Edit › Back to parent document*) shows the sheet the
  active one came from. The child stays open: show it again from the strip
  and it is as you left it, with its cursor, selection, shape and scroll
  position.
- `Cmd+D` decompresses the stream at the cursor into a new sheet, and where
  no stream is at the cursor in a derived sheet, goes back.
- `Ctrl+Tab` and `Ctrl+Shift+Tab` show the next and previous open sheet.
- *File › Open* adds the file as a new root beside the sheets open. A file
  already open is shown again (and read from disk again if it has unsaved
  edits, which are lost).

## Closing sheets

`Cmd+W` (*File › Close worksheet*) closes the active sheet and every sheet
derived from it, and shows its parent. *File › Close other worksheets*
closes everything but the active sheet and the sheets it came from, as
opening a file used to.

When one of the sheets closing has unsaved edits, the window asks first:
*Close and lose the edits* or *Cancel*. Through the API, `documents.close`
refuses instead, naming the sheets with unsaved edits; only the person at
the window may pass `discard_unsaved`.

## The tree of sheets

*≡ Tree* in the strip, `Shift+Cmd+T`, or the *Worksheets* section at the top
of the Workspace tab lists every open sheet as a tree, each with the step
that made it (`#3`), its size and the method that made it. Pick a sheet,
then:

- **Show** makes it the active sheet (a double-click does too).
- **Compare with active** compares the active sheet with it in the Diff
  tab (`diff.run` with `other`).
- **Close** closes it and the sheets derived from it.
- **Label…** gives it a short name, such as `payload`. The strip and the
  title show the label, the API lists it, and a recipe saved from the
  history names the sheet by it. Only a sheet a step made can be labelled,
  and no two open sheets alike.

## What the tools keep for each sheet

What the tools worked out about a sheet is kept with it: the report and the
file map, the findings, pinned outlines, templates, statistics, the
disassembly, checksums and the comparison. Show the sheet again and they
are there again, without running anything.

Tools whose results come from a job (Strings, XOR, Crypto, Unpacked) keep
their results for each sheet too, and go on showing another sheet's results
until the active sheet has its own. A line above them then says whose they
are, `From firmware.bin (doc-1) · Show it`, and *Show it* shows that sheet.
Clicking a result of another sheet shows that sheet and selects the bytes
there; applying a key or a decode works on that sheet, not the one shown.

The packet viewer remembers the sheet its packets were read from. While
another sheet is shown, it says so and offers *Show it* and *Find them in
this document*; edits it makes, selections and documents it opens are made
in its own sheet, and its outlines and its layer in the legend are drawn
only on that sheet.

## Saved with each file

Each root file's bookmarks and view shape are saved beside it, in its
sidecar file, whichever sheet is shown. A derived sheet has no file of its
own: save it with *File › Save as…* while it is shown.

## From the API

Every sheet is a document with an id (`doc-4`). `documents.list` lists them
all with their `parent`, `made_by` and `label`; `documents.activate` shows
one; `documents.close` closes one with those derived from it. For the person
at the window the focus, which an omitted `doc` means, is the active sheet;
MCP clients and the command line keep a focus of their own, which showing a
sheet in the window does not move. See [docs/api.md](../api.md).
