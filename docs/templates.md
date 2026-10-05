# Binary templates

A template describes the layout of some bytes. Applying it at the cursor
produces a field tree in the structure inspector (click a field to select its
bytes) and, for arrays of structs, a table with one row per record.

Templates live in `~/.config/theviewer/templates/*.tpl`. The viewer ships
examples for RIFF, PNG, BMP, ZIP local entries, the ELF64 header and generic
fixed-size records (see `templates/` in the source tree).

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

Fields are written `name: type`, one per line. Semicolons and commas between
fields are allowed but not needed.

## Types

| Type | Size | Shown as |
| --- | --- | --- |
| `u8` `u16` `u32` `u64` | 1, 2, 4, 8 | unsigned decimal |
| `i8` `i16` `i32` `i64` | 1, 2, 4, 8 | signed decimal |
| `f32` `f64` | 4, 8 | floating point |
| `u32le`, `u32be`, `f64be`, … | | the same, with an explicit byte order |
| `char[N]` | N | quoted ASCII; trailing NULs are trimmed, other bytes escaped as `\xNN` |
| `bytes[N]` | N | a hex preview of the first 16 bytes and the length |
| `cstring` | up to and including the NUL | quoted text |
| `utf16[N]`, `utf16be[N]` | 2 × N | quoted text of N UTF-16 code units |
| `StructName` | the struct's size | a nested field tree |

`N` may be any expression (see below).

## Arrays

| Form | Meaning |
| --- | --- |
| `T[expr]` | exactly `expr` elements |
| `T[until_end]` | elements until the data runs out |

Arrays of numbers (`u16[count]`) are read in one pass; up to 64 elements are
also listed individually. Arrays of structs list every element and feed the
**records table**: the outermost array of structs in the template becomes the
table, one row per element and one column per leaf field (nested fields are
named with dots, e.g. `header.size`).

An `until_end` array of structs also stops, quietly, at the first element
whose **first field** fails its expected value. This is how the ZIP template
stops at the central directory:

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

A field must be read before it is used. Unknown names, text used as a number,
division by zero, overflow and negative lengths are reported as warnings.

## Field attributes

Attributes follow the type, in any order:

| Attribute | Meaning |
| --- | --- |
| `= 42`, `= 0x1F`, `= -1` | Expected number. |
| `= "RIFF"`, `= "\x89PNG\r\n\x1a\n"` | Expected bytes for `char`, `bytes`, `cstring` and `utf16` fields. Escapes: `\xNN \n \r \t \0 \\ \"`. |
| `@ expr` | Read the field at an absolute offset, counted from where the template was applied. The field does not move the read position, so the fields after it continue where they were. |
| `enum { 1 = "Data", 2 = "Code" }` | Labels for values: the field shows `2 (Code)`. |
| `display hex` | Show a number as decimal and hex: `26 (0x1A)`. `display decimal` is the default. |

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
  at 0x40 needs 512 bytes but only 100 remain`) and ends its branch. An array
  keeps the elements that parsed and ends; the struct around it continues.
- An expected value that does not match is reported and evaluation carries on.
- At most 100,000 fields are created, arrays are capped at a million
  elements, and structs nest at most 32 deep.

Every warning names the template line that caused it.

## Inferring a template

Select a few records (or let the viewer guess the record length from the
strongest repeating period) and choose **Infer template**. Each column of the
records is classified:

| Field | Evidence |
| --- | --- |
| `magic: char[N] = "…"` | the same printable text in every record |
| `text: char[N]` | printable text that varies |
| `constant_N: uW = V` | the same number in every record |
| `counter: uW` | changes by the same small step each record |
| `offset: uW` | increases by a multiple of the record length, or always increases, and always points inside the file |
| `value_f32: f32` | a sensible floating-point value in every record |
| `unknown_N: bytes[K]` | nothing recognisable; adjacent unknown bytes are merged |

`N` in a name is the field's offset within the record. Fields are tried at
widths 4, 8, 2 and 1 bytes on their natural alignment, little endian before
big endian (big-endian fields are written `u32be`). Each line carries a
comment with the evidence, and the result is a normal template you can edit:

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
