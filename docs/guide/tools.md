# The tools

theviewer has 29 tool tabs. Open one from the *Tools* menu, the command
palette (`Cmd+K`), *Analyse* in the right-click menu, or `--tool NAME` on
the command line. Each one is a panel you can dock anywhere; the
[recommended layouts](layouts-and-workspace.md) open the ones each kind of
work needs.

The tabs come in five groups:

| Group | Tabs |
| --- | --- |
| The whole file | [Report](#report), [Reference](#reference), [Structure map](#structure-map), [Size map](#size-map), [Ask](#ask), [Dot plot](#dot-plot), [Trigrams](#trigrams), [Images](#images), [Workspace](#workspace), [History](#history) |
| Records and messages | [Template](#template), [Columns](#columns), [Protocol](#protocol), [Packets](#packets), [Bits](#bits) |
| Content | [Statistics](#statistics), [Characterise](#characterise), [Strings](#strings), [XOR](#xor), [Crypto](#crypto), [Checksums](#checksums), [Learn](#learn) |
| Code, images and other files | [Disassembly](#disassembly), [Firmware](#firmware), [Unpacked](#unpacked), [Forensics](#forensics), [Diff](#diff), [Compare](#compare) |
| Live data | [Live](#live) |

## The whole file

### Report

A plain-language overview of the whole file, with every sentence linked to
its bytes, and a coloured map of the file above the view. See [Finding
structure](finding-structure.md#report).

### Reference

Explains the format at the cursor: its layers, specifications, a header
diagram and the live fields. See [Reference notes](reference-notes.md).

### Structure map

*Segments* splits the file into regions of one kind; *Find more like this*
scores the file against the selection; *Feature tracks* draws entropy,
compressibility, byte kinds and the best record width along the file. See
[Finding structure](finding-structure.md#structure-map).

### Size map

Nested rectangles sized by what takes up the space: the report's regions,
or the unpacked contents with archives and filesystems inside each other.
Click to jump or open; right-click to zoom into a container.

### Ask

Ask Claude about the file. See [Ask Claude and permissions](ask-and-permissions.md).

### Dot plot

The file compared with itself on a grid. Repeated sections show as
diagonal lines and uniform regions as blocks, so structure shows without
choosing a width. Click a point to jump to either copy.

### Trigrams

A rotatable 3D cloud of byte triples. Text, machine code, tables and
compressed data each make a recognisable shape, a sharper fingerprint than
byte pairs.

- Points are coloured by the region type they come from (from segmentation
  or the report).
- Hovering a type in the legend highlights its points, and its regions on a
  strip of the file under the cube; its tick box shows or hides it.
- Plot the whole file with a selection to see where the selection's bytes
  sit against the rest.
- Click a point to jump into a region of its type.

### Images

Finds uncompressed pictures, fonts, splash screens and framebuffers by
trying widths and pixel formats across the file. Click a result to show it
in the view at the right width and format.

### Workspace

What the tools have learnt about the file and shared with each other, and
what just happened. See [Layouts and the workspace](layouts-and-workspace.md#the-workspace-tab).

### History

Every step of the analysis, by whom: undo one, go back to one, play them
back or save them as a recipe. See [History and recipes](history-and-recipes.md).

## Records and messages

### Template

Describe a structure in a small language and see it decoded as a tree and
a table. See [Finding structure](finding-structure.md#templates) and
[docs/templates.md](../templates.md).

### Columns

For a table of fixed-size records: a profile of each byte position and the
fields it adds up to, applied as a template in one click. See [Finding
structure](finding-structure.md#columns).

### Protocol

For captures, serial logs and streams of messages. It finds the framing
(sync words, delimiters, length prefixes or a fixed size), splits the
messages, and identifies types, sequence numbers, lengths, timestamps and
checksums. If the first framing is wrong, pick another from its chips.

*Align messages* groups the messages into types and lines them up, so
constant, counting and length fields line up even when messages differ in
length.

When the messages are a protocol the [packet viewer](packets.md)
dissects, the tab says so; *Open in packet viewer* takes them there.

### Packets

A packet list for captures and message streams: dissection, filters,
conversations, streams, editing, tshark and pcap export. See
[Packets](packets.md).

### Bits

For data that is not byte-aligned or not plain binary:

- finds frame lengths in bits (such as a 37-bit radio frame) and their
  sync words;
- shows each bit plane as an image;
- decodes Manchester, differential Manchester, NRZI, 8b/10b, Gray code and
  BCD, picking the decoder and bit offset automatically;
- guesses what the field at the cursor holds (integer, float, fixed-point
  or a timestamp, and which byte order);
- finds length prefixes, tag-length-value chains and offset tables.

## Content

### Statistics

A byte histogram; randomness tests (entropy, chi-square, serial
correlation, Monte Carlo π) with a plain verdict; a byte-pair fingerprint;
entropy along the file; and the most repeated sequences. Right-click a
selection for *Analyse › Statistics of selection*.

### Characterise

- **Compressibility** compresses the selection or the whole file with
  several codecs and reads the pattern: encrypted or random, already
  compressed, lossy media, or structured data.
- **Media streams** finds raw MP3, AAC, H.264, H.265 and PCM audio with no
  container, to play or extract.
- **Text** identifies the character encoding (UTF-8 and UTF-16,
  Windows-1252, Shift-JIS, EUC-JP, GBK, Big5, EUC-KR, KOI8-R, EBCDIC) and
  the language.

### Strings

ASCII, UTF-8 and UTF-16 strings, tagged when they look like URLs, paths, IP
addresses, UUIDs, versions or keys.

### XOR

Recovers single-byte and repeating XOR keys. Preview the result, or apply
it as an edit.

### Crypto

- Finds well-known crypto and compression constants (AES tables, SHA and
  MD5 constants, CRC tables, Blowfish, DES, ChaCha, curve primes, Base64
  alphabets), which show where a firmware does its cryptography.
- Spots ECB-style encryption from repeated cipher blocks.
- Finds PEM and DER certificates and keys, OpenSSH keys and likely raw
  keys.
- Tries rolling XOR, ADD, rotation and combined ciphers, or drags a known
  plaintext such as `PK\x03\x04` across the data to reveal the key.

Decodes open as a document or apply as an edit.

### Checksums

- CRC-32, Adler-32, MD5, SHA-1, SHA-256 and simple sums of a selection.
- *Find the checksum* works out which stored value checks which bytes.
- *Solve a custom CRC* takes several messages with their stored checksums
  and works out the CRC's width, polynomial, initial value, reflection and
  final XOR, naming the standard algorithm when there is one.

### Learn

Learns a new format from a few samples, and fuzzy-matches files and shared
fragments. See [Finding structure](finding-structure.md#learn-a-new-format).

## Code, images and other files

### Disassembly

x86, ARM, RISC-V, MIPS and PowerPC, with the architecture read from
executable headers or guessed, and branch targets you can follow.
Right-click a byte for *Analyse › Disassemble here*.

### Firmware

For a raw firmware image:

- which processor the code is for, judged by disassembling samples for each
  architecture;
- the address it was built to load at, found by matching pointers to the
  strings they point to;
- any ARM Cortex-M vector table, with the stack pointer, the reset and fault
  handlers, and the flash address the image was built for.

### Unpacked

Extracts ZIP, tar, compressed streams and embedded filesystems (SquashFS,
CramFS, JFFS2 and UBI volumes) recursively into a tree you can browse,
open or save. *Tools › Unpack everything* starts it.

### Forensics

Lists the embedded filesystems in the file with their files, and
classifies every block (padding, text, markup, machine code, compressed,
random, raw image, audio, tables) as a coloured strip, for carving
fragments that have no headers.

### Diff

Compares with another file (*Tools › Compare with file…*), finding
inserted and deleted bytes rather than only changed ones, and scrolls both
together.

### Compare

Many files at once: captures, firmware versions, saved states.

- **Variation:** which byte ranges stay constant, vary or count up across
  them.
- **Correlation:** which fields follow a value you enter for each file,
  such as a temperature or a setting.
- **Timeline:** for a live recording, which bytes changed when.

## Live data

### Live

Opens a URL, a serial port (`serial:/dev/cu.usbserial@115200`), a block
device (`/dev/rdisk2`, needs sudo) or process memory (`pid:1234`, Linux
only). It can watch a file as it grows (also *Tools › Watch file for
changes*) and record its history, for Compare's timeline.
