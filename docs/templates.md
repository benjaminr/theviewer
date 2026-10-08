# Binary templates

A template describes the layout of some bytes. Applying it (in the Template
tool, at the start of the selection or else at the cursor) produces a field
tree in the structure inspector (click a field to select its bytes) and, for
arrays of structs, a table with one row per record.

Your own templates are the `*.tpl` files directly in
`~/.config/theviewer/templates/`, each named by its file's stem. The viewer
has six built in, from `templates/` in the source tree: "RIFF", "PNG",
"BMP", "ZIP local files", "ELF64 header" (with its program headers) and
"Fixed-size records". Built-in templates are listed first, and a name is
looked up case-insensitively, first match first, so a file of your own
named like a built-in one (`png.tpl`) is hidden behind it. A file of your
own that does not parse is left out of the Template tool's menu;
`templates.list` shows it with its error.

## A first example

```
// Comments run to the end of the line.
endian little

struct Header {
    magic: char[4] = "RIFF"     // expected value: a mismatch is reported, not fatal
    size: u32
    kind: char[4]
}

struct Chunk {
    id: char[4]
    len: u32
    data: bytes[len]            // a length taken from an earlier field
    pad: bytes[len % 2]         // arithmetic is allowed
}

struct File {
    header: Header
    chunks: Chunk[until_end]    // repeat until the data runs out
}

root File
```

## Statements

| Statement | Meaning |
| --- | --- |
| `endian little` / `endian big` | Byte order for the numeric fields that follow. It may appear at the top level or inside a struct, and applies to everything written after it. |
| `struct Name { … }` | Defines a struct. Structs may be defined in any order and refer to each other. |
| `root Name` | The struct applied at the cursor. `root Name[until_end]` or `root Name[10]` applies an array. Without a `root` line the last struct defined is used. |

Fields are written `name: type`, usually one per line, though line breaks
do not matter: `struct A { x: u8 y: u16 }` is fine. Semicolons and commas
between fields are allowed but not needed. Several `root` lines may be
given; the last wins.

`endian` is a setting that carries on through the rest of the source,
across struct boundaries; the default is little. `endian`, `display`, `if`,
`enum` and `until_end` are keywords only where they make sense, so they
can also be field names.

## Types

| Type | Size | Shown as |
| --- | --- | --- |
| `u8` `u16` `u32` `u64` | 1, 2, 4, 8 | unsigned decimal |
| `i8` `i16` `i32` `i64` | 1, 2, 4, 8 | signed decimal |
| `f32` `f64` | 4, 8 | floating point |
| `u32le`, `u32be`, `f64be`, … | | the same, with an explicit byte order (any numeric type takes `le` or `be`) |
| `char[N]` | N | quoted ASCII; trailing NULs are trimmed, other bytes escaped as `\xNN` |
| `bytes[N]` | N | a hex preview of the first 16 bytes and the length |
| `cstring` | up to and including the NUL | quoted text |
| `utf16[N]` (or `utf16le[N]`), `utf16be[N]` | 2 × N | quoted text of N UTF-16 code units, trailing NULs trimmed |
| `StructName` | the struct's size | a nested field tree |

`N` may be any expression (see below).

## Arrays

| Form | Meaning |
| --- | --- |
| `T[expr]` | exactly `expr` elements |
| `T[until_end]` | elements until the data runs out |

Arrays of numbers (`u16[count]`) are read in one pass and shown as
`N × u16: [first 8 values, …]`; up to 64 elements are also listed
individually. Arrays of strings and byte blocks (`char[4][n]`,
`cstring[until_end]`) are shown as "N items".

Arrays of structs list every element and feed the **records table**: the
first array of structs at the shallowest depth becomes the table, one row
per element and one column per leaf field (nested fields are named with
dots, e.g. `header.size`; an array inside a record is one column holding
its text). A record keeps at most 64 columns; the table's columns are
every record's, in the order they first appear. The Template tool shows the
first 5000 rows.

An `until_end` array stops when the data runs out, at an element that is
cut short or invalid (with a warning), at an element of no size (which
would repeat for ever), or at the limits below. An `until_end` array of
structs also stops, quietly, at the first element whose **first field**
fails its expected value. This is how the ZIP template stops at the central
directory:

```
struct LocalFile {
    signature: u32 = 0x04034b50
    …
}
root LocalFile[until_end]
```

## Expressions

Lengths, counts and offsets are integer expressions:

- decimal or hexadecimal literals: `16`, `0x10`, `1_000`
- names of earlier fields in the same struct or any enclosing one: `len`
- dotted names into nested structs: `header.size`, `info.image_size`
- `+ - * / %` with the usual precedence, unary minus and parentheses:
  `bytes[(count + 1) * 2]`, `pad: bytes[len % 2]`
- one comparison, `==` or `!=`, below the arithmetic: 1 when it holds,
  else 0. `bytes[len - 4 * (kind == 0x81)]` takes 4 off only for type 0x81.

A field must be read before it is used ("unknown field 'x' (fields must
come before they are used)"). A float used as a number is cut to an integer;
the elements of an array cannot be named. Unknown names, text used as a
number, division by zero, overflow and negative lengths and offsets are
reported as warnings.

## Field attributes

Attributes follow the type, in any order:

| Attribute | Meaning |
| --- | --- |
| `= 42`, `= 0x1F`, `= -1` | Expected integer. A mismatch adds "(expected 42)" to the value, and a warning. (An expected value on a float or an array never matches.) |
| `= "RIFF"`, `= "\x89PNG\r\n\x1a\n"` | Expected bytes for `char`, `bytes`, `cstring` and `utf16` fields. Escapes: `\xNN \n \r \t \0 \\ \"`. A `char` or `bytes` field is compared byte for byte, trailing NULs included; a `utf16` field by its text. |
| `@ expr` | Read the field at an absolute offset, counted from where the template was applied. The field does not move the read position, so the fields after it continue where they were. |
| `enum { 1 = "Data", 2 = "Code" }` | Labels for values: the field shows `2 (Code)`. |
| `if expr` | Read the field only when `expr` is not 0, such as `if kind == 0x81` for a field only one message type carries. A field left out takes no bytes, shows nowhere, and cannot be named by the fields after it. |
| `display hex` | Show an integer as decimal and hex: `26 (0x1A)` (negative values stay decimal). `display decimal` is the default. |

Example using `@`, from the BMP template:

```
struct Bmp {
    file: FileHeader
    info: InfoHeader
    pixels: bytes[info.image_size] @ file.data_offset
}
```

## When the data does not fit

Templates never stop the viewer, whatever the bytes contain:

- A field that runs past the end of the data is reported (`line 12: 'data'
  at 0x40 needs 512 bytes but only 100 remain`) and ends its struct, up to
  the nearest array: the array keeps the elements that parsed (a cut-short
  element is shown but not added to the records table) and ends, and the
  struct around it continues. An array of numbers that does not fit keeps
  the values that do, with a warning, and the struct carries on.
- A `cstring` with no NUL before the end is reported.
- An expected value that does not match is reported and evaluation carries on.
- At most 100,000 fields are created, arrays are capped at a million
  elements, structs and arrays nest at most 32 deep, and at most 200
  warnings are kept. A template sees at most 16 MiB from where it is
  applied: `until_end` means the end of that.

Warnings name the template line that caused them (all but the one saying
the field limit was reached).

## Inferring a template

Select a few records and choose **Infer from selection** in the Template
tool. The viewer guesses the record length from the strongest repeating
period in the selection (or takes the view's row width), infers a struct,
and applies it at the start of the selection. (`templates.infer` also takes
the record length as `record_len`.) Each column of the records is
classified:

| Field | Evidence |
| --- | --- |
| `magic: char[N] = "…"` | the same printable text (3 or more characters) in every record |
| `text: char[N]` | printable text that varies |
| `constant_N: uW = V` | the same number in every record |
| `offset: uW` | 4 bytes or more; increases by a multiple of the record length each record, or always increases from above 0; always points inside the file |
| `counter: uW` | changes by the same small step each record (up to 4096, not a multiple of 256; it may count down) |
| `value_f32: f32` | 4 bytes, at least 4 records, a sensible floating-point value (0, or between 1e-6 and 1e9 in size) in every record |
| `unknown_N: bytes[K]` | nothing recognisable; adjacent unknown bytes are merged |

`N` in a name is the field's offset within the record; a second `counter`
or `offset` is `counter_2`, `offset_2` and so on. Text is looked for first;
then numbers are tried at widths 4, 8, 2 and 1 bytes on their natural
alignment within the record, each little endian then big endian
(big-endian fields are written `u32be`). With fewer than two whole records
there is nothing to compare, and the result is one `unknown_0` field. Each
line carries a comment with the evidence, and the result is a normal
template you can edit:

```
// Inferred from 200 records of 24 bytes. Rename fields as you learn what they mean.
endian little

struct Record {
    magic: char[4] = "REC1"              // the same text in every record
    counter: u32                         // +1 each record
    offset: u32                          // increases by 24 each record and always points inside the file
    value_f32: f32                       // varies, always a sensible float
    unknown_16: bytes[8]                 // no pattern found
}

root Record[until_end]
```

## Templates and the API

The Template tool works through four methods of the [data API](api.md),
which Ask, plugins, MCP clients, recipes and the command line can call too:

| Method | Effect | What it does |
| --- | --- | --- |
| `templates.list` | read | The templates: each one's `name`, its `origin` (`builtin` or `user`) and, for a file that does not parse, its `error`. |
| `templates.apply` | analysis | Applies a template by `name` or as `source` text at offset `at` (0 by default) and returns the field tree (`structure`), the records table a page at a time (`columns`, `records`, `total_records`, `next`) and the `warnings`. With `pin: true` it also shows the template as the Template tool does: its records are outlined in the views and it is published as `template.applied` (and `structure.identified`), in place of the template pinned before. |
| `templates.infer` | analysis | Proposes a template struct from the example records at `start`, `len` bytes long (with `record_len`, or guessed), as `source`; with `pin: true` it also applies it at `start` and pins it. |
| `templates.clear` | view | Withdraws the template pinned over a document. |

```sh
theviewer api templates.apply '{"name": "PNG"}' image.png
theviewer api templates.apply '{"source": "struct R { id: u16 value: f32 }\nroot R[until_end]", "at": 64, "limit": 10}' data.bin
```

A call that pins is a step of the journal that can be undone: undoing it
puts back the template pinned before (or clears it), and undoing
`templates.clear` pins the template again. A call that does not pin only
returns fields and leaves nothing to undo. In the Template tool, *Apply at
cursor* calls `templates.apply` with the editor's source and `pin`,
*Infer from selection* calls `templates.infer` with `pin`, and *Clear*
calls `templates.clear`; a template pinned by anyone else (a plugin, Ask, a
recipe) shows in the tool the same way.
