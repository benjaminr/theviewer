# Viewing and editing

theviewer draws a file's bytes as pixels, row by row, beside a hex dump and
an inspector that follow the cursor. This page covers how to shape that
view, how to select bytes, and how to change them.

- [The raster view](#the-raster-view)
- [Width, origin and zoom](#width-origin-and-zoom)
- [Curve layouts, row difference and other views](#curve-layouts-row-difference-and-other-views)
- [The legend bar](#the-legend-bar)
- [Hex dump and inspector](#hex-dump-and-inspector)
- [Moving around](#moving-around)
- [Selecting bytes](#selecting-bytes)
- [Changing bytes](#changing-bytes)
- [Skipping bytes out of the view](#skipping-bytes-out-of-the-view)
- [Compressed streams and embedded media](#compressed-streams-and-embedded-media)
- [Undo, saving and the sidecar file](#undo-saving-and-the-sidecar-file)

## The raster view

The main view's tab is **Bits**, with **Packets** beside it, so the bytes
and the packets they hold are one click apart.

Each byte becomes a pixel. The strip beside the scrollbar maps the whole
file by entropy: dark for empty space, teal for structured data, amber to
white for compressed or encrypted data. A coloured file map above the view
shows the report's regions once the file has been explained (*View › File
map* turns it on and off).

**Pixel formats.** Choose one in the toolbar's *Format* group:

- Eleven formats, from 1-bit to 32-bit colour: 1-bit (MSB or LSB first),
  4-bit, 8-bit grey, 16-bit grey in either byte order, RGB565, RGB, BGR,
  RGBA and BGRA.
- *Byte class*, which colours zeros, text, control bytes and high bytes
  differently.
- Numeric heatmaps of 16- and 32-bit integers and 32-bit floats, in either
  byte order. They scale to the visible values (the 1st to 99th
  percentile) and centre on zero for signed types.

Single-channel formats and the unsigned heatmaps take one of six palettes:
grey, viridis, inferno, ocean, amber and diverging. Signed heatmaps always
use the diverging palette, so zero is neutral.

## Width, origin and zoom

**Width.** Drag the *Width* slider, type a number, or step it with `[` and
`]` (`Shift` steps by 16). *Presets* offers common widths and image
layouts such as *QVGA 320 RGB565* or *1-bit 128 (LCD)*; *pad* adds padding
at the end of each row.
*Fit* (in the *Zoom* group) sets the width to fill the view. *Detect
width* (in the *Analysis* group) looks for repeating patterns and suggests
record sizes; pick one and the data snaps into columns. See [Finding structure](finding-structure.md#detect-the-record-width).

**Origin.** The byte shown at the top left can start anywhere, down to the
bit. *To cursor* (or *View › Origin = cursor*) makes the cursor the top-left
pixel, and *View › Reset origin* goes back to 0. `,` and `.` move the origin
a byte; `Alt+←` and `Alt+→` move it a bit when nothing is selected.

**Zoom.** `-` and `+`, `Cmd` with the scroll wheel, or a pinch. Zoomed in
far enough, template and structure fields are outlined and named. *View ›
Show values inside pixels when zoomed in* writes each byte's hex value
inside its pixel; it is off by default, and Settings can turn it on for
every start.

**Zoomed out below 1×**, the view colours each part by what it is (the
report's regions, or block class and entropy) rather than showing noise.
*View › Colour by region when zoomed out* turns this off.

*Guess image shape* (in *Presets* and the View menu) uses the detected
period and a format that divides it, for raw images and framebuffers.

## Curve layouts, row difference and other views

- **Hilbert and Morton curves.** *View › Layout: Hilbert curve* or
  *Layout: Morton (Z-order) curve* lays the file out along a curve, which shows structure without
  choosing a width. *View › Curve colours* colours them by bytes, entropy,
  region type or byte class.
- **Row difference.** *View › Row difference* (the *Δ* menu in the
  toolbar) XORs or subtracts the row above. The constant fields of
  fixed-size records turn dark, so the fields that change stand out.
- **Pointer arrows.** *View › Pointer arrows* draws arrows from values that
  look like offsets to the bytes they point at.
- **Pattern highlights.** `H` turns highlights of detected patterns on and
  off over the view and the hex dump. *Kinds* in the toolbar chooses which
  kinds to show.

## The legend bar

A legend bar above the view, and a condensed one over the hex dump, always
says how the pixels are coloured. It lists every highlight drawn: the
selection, the cursor, search matches, bookmarks, pattern kinds, structure
fields, and the findings pinned by each tool. Click a layer to hide or show
it. Point at one to pick out exactly its highlights.

## Hex dump and inspector

The **Hex** panel shows the bytes around the cursor, coloured by byte
class, with ASCII beside them. The **Inspector** shows the byte at the
cursor as every common number type (u8 to u64, signed and unsigned, floats,
both byte orders, the bits), and the field tree of any structure it
recognises: a PNG chunk, an ELF header, a ZIP entry and so on. Pointing at
a field explains it from the [reference notes](reference-notes.md); its
*Reference* button opens the Reference tab on that format.

Field trees cover executables (ELF, PE, Mach-O), images (PNG, JPEG with
its EXIF tags, GIF, BMP), archives (ZIP, with each entry's flags, tar, ar,
cpio), PDF documents (objects, streams with their filters, embedded
files), packet captures, DER and X.509 certificates, partition tables and
filesystems (a FAT boot sector with the FAT, root directory and data
offsets it implies), and schemaless formats such as Protocol Buffers,
CBOR and MessagePack.

## Moving around

- Click a pixel or a hex byte to put the cursor there.
- Arrow keys move by a pixel or a row; `PgUp`, `PgDn`, `Home` and `End`
  move by a page or to either end. Scroll moves by rows, `Shift`+scroll pans.
- `Cmd+G` goes to an offset (decimal or `0x` hex).
- `Cmd+F` finds bytes, text or a number; `F3` and `Shift+F3` go to the next
  and previous match.
- `Cmd+B` bookmarks the cursor or selection; `F2` and `Shift+F2` go to the
  next and previous bookmark.
- `Cmd+K` opens the command palette, which lists every action with its
  shortcut. Right-click a byte for the actions that apply to it.

## Selecting bytes

The raster, the hex dump and the [packet viewer](packets.md) show and
change the same selection.

- **A range:** drag, or `Shift` with the arrow keys or a click.
- **A column of every record:** `Alt`+drag selects the same bytes in every
  record, in the raster or the hex dump.
- **Several ranges at once:** `Cmd`+click or `Cmd`+drag adds a search
  match, a finding, a packet or a range (again to remove it). *All matches*
  in the Find box selects every match.
- **Multi-select mode:** *Multi-select* in the toolbar, or `M`, turns on a
  mode where plain clicks and drags add sections and clicking a section
  takes it out again. `Esc` clears them and leaves the mode.

**Moving a selection by hand.** Drag a selection to move its bytes to the
caret (`Esc` cancels). Drag its first or last byte to resize it. With a
selection, `Alt+←` and `Alt+→` nudge its bytes a byte left or right, and
`Alt+↑` and `Alt+↓` a row up or down.

## Changing bytes

**Typing.** Type `0`–`9` and `A`–`F` over the byte at the cursor. `Ins`
switches between overwrite and insert. `I` inserts bytes before, after or at
the cursor. `Delete` deletes the selection or the byte at the cursor;
`Backspace` deletes the selection or the byte before the cursor. `Cmd+C`
copies as hex, `Cmd+X` cuts and `Cmd+V` pastes.

**The Selection menu.** One *Selection* menu appears in the right-click
menus of the view and the hex dump, in the findings list, in the packet
viewer and in the small toolbar that floats beside a selection. It offers:

- insert before or after, delete, fill, invert;
- XOR, add or subtract a key;
- reverse, mirror bits, shift or rotate bits across byte boundaries;
- swap byte order, number records as a counter;
- move, duplicate, skip (see below);
- copy as hex, a C array or Base64; extract to a file; open as a document;
- compress (zlib, gzip, raw deflate, bzip2 or LZ4) and decompress.

Each works on a range, on every record of a column and on every range of a
multi-range selection, as one undo step. The toolbar's *Byte at cursor*,
*Shift bits* and *Move* groups offer the common ones directly.

## Skipping bytes out of the view

`S` (*Skip*) folds the selection out of the view and the hex dump without
deleting it. A marker shows where the bytes were; click it to show them
again. The right-click menu has *Show skipped bytes again* and *Show every
skipped range*.

## Compressed streams and embedded media

gzip, zlib, raw deflate, bzip2, xz, lzma, zstd and LZ4 streams are found
and checked by test decompression.

- *Decompress* (`Cmd+D`) opens the stream at the cursor as a new
  [worksheet](worksheets.md). It works in a sheet opened this way too, so a
  stream inside a stream is followed down a level at a time. *Back out*, or
  `Cmd+[` (*Edit › Back to parent document*), shows the sheet it came from
  again; `Cmd+D` where no stream is at the cursor does the same. The
  decompressed sheet stays open, in the worksheet strip under the toolbar,
  so you can go back to it as you left it; `Cmd+W` closes it.
- *Edit › Decompress here in place* replaces the stream with what it holds.
- *Edit › Compress selection as* compresses a selection back (zlib, gzip,
  raw deflate, bzip2 or LZ4), and *Re-pack selection with the last codec* in the palette
  repeats the last one.
- *Probe for compression at cursor* says which codecs decode at the
  cursor, and how much.

Images (PNG, JPEG, GIF including animation, BMP, WebP, TIFF, ICO), audio
(WAV, MP3, FLAC, Ogg Vorbis, Ogg Opus, AAC, M4A, AIFF, CAF) and video
(MP4, QuickTime, WebM, Matroska, AVI, MPEG-TS, FLV, Ogg Theora) open where
they sit: put the cursor on one and press `Cmd+Enter`, or use the *Media*
group that appears in the toolbar. `Space` plays and pauses, and `Esc`
closes the viewer. Images and audio are decoded by theviewer itself;
video, and HEIF and AVIF stills, need `ffmpeg` and `ffprobe` on the
`PATH`.

![An embedded PNG opened in the media viewer, with its header highlighted in the hex dump](../images/media.png)

Any selection, stream or embedded file can be saved with `Cmd+E` (*File ›
Extract selection or stream to file…*), or as its decompressed contents
with *File › Extract decompressed contents to file…*.

*Tools › Plot selection* draws bytes as a time series, histogram, scatter
or frequency spectrum, and *Play selection as audio* plays any bytes as
sound, in the format chosen under *Tools › Audio format*.

## Undo, saving and the sidecar file

- Undo is unlimited, on files of any size: edits are recorded, not copied.
  Each step is named after what made it (*Undo XOR by ask*), and the
  [History tab](history-and-recipes.md) shows every step by everyone.
- `Cmd+S` saves safely through a temporary file. `Shift+Cmd+S` saves as.
- Bookmarks and the view's shape (format, palette, width, origin, row
  padding and zoom) are saved beside the file, in a sidecar named after it
  (`firmware.bin.theviewer.toml` for `firmware.bin`), so you can pick up
  where you left off.
- Every view keeps up with edits. Segments, an applied template, record
  columns, checksums and a small trigram cloud work themselves out again a
  moment after the last edit. Tools whose results take longer show *Out of
  date* with a *Refresh* button instead, and their tab is marked with •, so
  nothing stale is shown without saying so.
