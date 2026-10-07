# Recipes

A recipe is a saved analysis: a list of [data API](api.md) calls, recorded
from the session's journal or written by hand, that can be run again on
other files. Values that differ from file to file (where the frames start,
which set a step made, the key to XOR with) are **anchors**, found when the
step runs, or **parameters**, given by whoever runs it.

This is the reference for the file format, the anchors and the ways of
running a recipe. For using them in the window (the History tab, *Recipe
values*, *Run recipe…*), see the guide's
[History and recipes](guide/history-and-recipes.md).

- [A recipe file](#a-recipe-file)
- [Format 2](#format-2)
- [Steps and documents](#steps-and-documents)
- [Parameters](#parameters)
- [Anchors](#anchors)
- [Recording a recipe](#recording-a-recipe)
- [Running a recipe](#running-a-recipe)
- [theviewer replay](#theviewer-replay)
- [The recipes methods](#the-recipes-methods)
- [Permissions](#permissions)
- [Failures, undo and warnings](#failures-undo-and-warnings)
- [A worked example](#a-worked-example)

## A recipe file

A recipe is a JSON file whose name ends in `.theviewer-recipe.json`. The
ones you keep are in `~/.config/theviewer/recipes/`, where `recipes.list`,
the *Run recipe…* window and `theviewer replay "NAME"` find them by name;
a recipe file anywhere else is used by its path.

```json
{
  "recipe": 1,
  "api_version": "1.x",
  "name": "Telemetry frames",
  "description": "Split the frames at the sync word and decode them",
  "parameters": {
    "sync": { "type": "string", "description": "The sync word that starts each frame, as hex", "default": "7E A5" }
  },
  "recorded_on": { "name": "flight-03.bin", "size": 64, "sha256": "cf1099…f4a5" },
  "plugins": [ { "name": "acme_telemetry.lua", "sha256": "…" } ],
  "steps": [
    { "step": 1, "method": "packets.sets.create",
      "params": { "from": "pattern", "pattern": { "$anchor": { "param": "sync" } },
                  "start": { "$anchor": { "find": { "hex": "7ea5" }, "nth": 0 } } },
      "note": "Split where the first frame starts" },
    { "step": 2, "method": "packets.decode_as",
      "params": { "set": { "$anchor": { "step": 1, "path": "result.set" } },
                  "template": "struct Frame { sync: u16be display hex\n kind: u8\n len: u8\n payload: bytes[len] }\nroot Frame" } }
  ]
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `recipe` | yes | The file format: `1`, or `2` for a recipe that uses what only format 2 can say (see [Format 2](#format-2)). A recipe of a later format is refused, with a message to update theviewer. |
| `api_version` | yes | The API's major version the steps were recorded against, `"1.x"`. Running under another major version warns. |
| `name` | yes | The recipe's name, which may not be empty. `recipes.list`, `theviewer replay "NAME"` and the edit labels ("… by recipe:Telemetry frames") use it. |
| `description` | no | What it is for. |
| `parameters` | no | The values it asks for when it runs, by name; see [Parameters](#parameters). |
| `recorded_on` | no | The file it was recorded on: `name`, `size` and `sha256` (left out for a file over 256 MiB). Running on another file warns. In format 2 it is `inputs.input.recorded_on`. |
| `inputs` | no | Format 2: the documents it runs on, by name, each with the file it was `recorded_on`. `input` is the one it is run on. |
| `plugins` | no | The plugins loaded when it was recorded, each `name` and `sha256` of its source. Running without one, or with a changed one, warns. |
| `steps` | yes | The calls, in order; see below. |

Each step is:

| Field | Required | Meaning |
| --- | --- | --- |
| `step` | yes | The step's number: 1, 2, 3… in a recipe made from the journal, or any increasing numbers in one written by hand. Step anchors name steps by it. |
| `method` | yes | The method to call, such as `packets.sets.create`, a plugin's (`acme.decode_frame`) included. |
| `params` | no | Its parameters: literals, except where a value is marked as an anchor. |
| `note` | no | What the step is for, in your words. A recipe made from the history fills it from the notes linked to the step (see [Making the recipe](#making-the-recipe)). |
| `makes` | no | Format 2: a label for the sheet the step makes, which later steps name as `{"sheet": "label"}`. |

The JSON Schema of the file is the `recipe` parameter's in
`api.describe` (`recipes.save` takes a recipe whole).

## Format 2

Format 2 adds what format 1 cannot say: [sheet anchors](#sheet-a-document-of-the-run),
[pick](#pick-an-item-chosen-from-an-earlier-steps-list),
[then](#then-a-value-transformed) and [var](#var-a-variable) anchors, a
parameter's `default_anchor`, a step's `makes` label, and `inputs`. A
recipe is written as format 2 only when it uses one of them, so a recipe
that needs none of them is still format 1 and runs on older builds; this
build reads both.

```json
{
  "recipe": 2, "api_version": "1.x", "name": "NovaCam triage",
  "inputs": { "input": { "recorded_on": { "name": "novacam_2.1.0.upd", "size": 1612, "sha256": "…" } } },
  "steps": [
    { "step": 1, "method": "documents.derive", "makes": "payload",
      "params": { "ranges": [[24, 252], [280, 252]] }, "note": "strip the CRC trailers" },
    { "step": 2, "method": "unpack.run", "params": { "doc": { "$anchor": { "sheet": "payload" } } } },
    { "step": 3, "method": "unpack.open", "params": { "doc": { "$anchor": { "sheet": { "step": 1 } } }, "path": [0, 1] } },
    { "step": 4, "method": "strings.find", "params": { "doc": { "$anchor": { "sheet": { "step": 3 } } } } }
  ]
}
```

## Steps and documents

A recipe runs on one document, its **input**: the one it is run on (the
file given to `theviewer replay`, the document named by `recipes.run`'s
`doc`, or the current one). A step with no `doc` (when its method takes
one), or with `"current"`, runs on the input.

Steps that make a document from another make **sheets**:
`documents.derive`, `codecs.open_decoded`, `bits.open_plane`,
`bits.decode_linecode`, `unpack.open`, `forensics.open_entry`,
`crypto.open_decrypted`, and `packets.sets.create` with `gunzip` or
`packets.http_bodies` with `open`. A recipe repeats them, and later steps
name what they made with a sheet anchor: `{"$anchor": {"sheet": {"step": 2}}}`
for the sheet step 2 made, `{"$anchor": {"sheet": "payload"}}` for the one a
step labelled with its `makes`, and `{"$anchor": {"sheet": "input"}}` for
the input, at any parameter path. Each such method returns the sheet it made
as `output: {doc, label?, len}` (or `outputs`, a list, for one that may make
several), which is how the run knows it.

A document named by its id (`"doc-4"`) is taken as it is, and must be the
input or a sheet the run made: a step naming any other id stops the run
before it calls anything, rather than running on some other document. Ids
belong to the session that made them, so a recipe made from the journal
never names a document by id.

## Parameters

```json
"parameters": {
  "key":    { "type": "string",  "description": "XOR key, hex" },
  "header": { "type": "integer", "description": "Bytes before the first frame", "default": 16 }
}
```

A parameter has a `type` (`string`, `integer`, `number` or `boolean`), a
`description` for whoever runs it, and an optional `default`. A step uses
one through a param anchor, `{"$anchor": {"param": "key"}}`.

A parameter's default may be an anchor instead, `default_anchor`: the value
is then found on each file unless one is given, and `default` says what it
found when the recipe was recorded (format 2).

```json
"parameters": {
  "serial": { "type": "string", "description": "The unit's serial", "default": "NC500-8D98EE98",
              "default_anchor": { "pick": { "step": 4, "list": "job.strings", "where": { "text": { "regex": "^NC500-" } }, "field": "text" } } }
}
```

*Make parameter* (`history.make_parameter`) on a literal an anchor found,
such as the `value` of a `vars.set` bound from a pick, makes such a
parameter: the person running the recipe may give the serial, and the
recipe finds it when they do not.

When a recipe runs:

- a value given as text (as `theviewer replay --param key=5a` and the *Run
  recipe…* window give them) is read as the declared type: an integer in
  decimal or `0x` hex, a number, `true`/`yes`/`1` or `false`/`no`/`0`;
- a parameter not given takes its default, or what its `default_anchor`
  finds when the step that uses it runs; one with neither must be given,
  or the run stops before its first step, saying which;
- a value for a parameter the recipe neither declares nor uses is refused,
  as it is most likely a typing mistake ("the recipe 'Telemetry frames' has
  no parameter 'syn' (it has sync)").

## Anchors

Any value at any depth of a step's `params` may be an anchor: an object
with the single key `$anchor`. Everything else is a literal, so a literal
object that happens to look like an anchor (a `selection`, say) is never
taken for one.

```json
{ "method": "selection.set",
  "params": { "selection": { "range": [ { "$anchor": { "find": { "text": "PK" }, "nth": 1 } }, 30 ] } } }
```

Each anchor is resolved against the step's document just before the step is
called, in the order its params list them; the step's report gives each
anchor's path and the value it resolved to. An anchor that does not resolve
stops the run, with an error saying which anchor failed and why, carrying
the anchor as `data.anchor` and the path as `data.path`.

In a journal entry's `derived_from` (which maps parameter paths to anchors)
and in `history.make_anchor`'s `anchor`, anchors are written bare, without
the `$anchor` key.

Two shorthands mark the commonest anchors: `{"$var": "serial"}` is
`{"$anchor": {"var": "serial"}}`, and `{"$sheet": 7}` or `{"$sheet":
"payload"}` is a sheet anchor. A value marked with `$anchor`, `$var` or
`$sheet` that is not an anchor is refused rather than passed on as a
literal.

### Anchors at call time

Every caller may pass anchors in a call's params, not only recipes: the
person's panels, Ask, plugins, MCP clients and the command line. The call
resolves them against the live session before the method runs (the `doc`'s
first, so the others are found in the document it names), runs on the
values, and records both: the journal entry keeps the values in `params`
and the anchors in `derived_from`. A recipe made from the session then uses
the anchors, so a client gets portable recipes without `history.make_anchor`
round trips.

```json
{"method": "strings.find", "params": {"doc": {"$sheet": 6}, "min_chars": 5}}
{"method": "vars.set", "params": {"name": "serial", "value": {"$anchor": {"pick": {"step": 7,
   "list": "job.strings", "where": {"text": {"regex": "^NC500-[0-9A-F]{8}$"}}, "field": "text"}}}}}
{"method": "transform.apply", "params": {"doc": {"$sheet": 9}, "selection": {"range": [0, 154]},
   "operation": {"op": "xor", "key": {"$anchor": {"of": {"var": "serial"}, "then": [{"encode": "text_to_hex"}]}}}}}
```

Live, a step or pick anchor reads the journal's entry for its step (a read
it cites becomes a step of the journal, and a job's list is its finished
result, waited for if need be); a sheet anchor names the sheet a step of the
session made, or the open document labelled so; `{"sheet": "input"}` is the
file the caller's focus descends from. `recipes.save`, `recipes.preview`,
`recipes.run` and `history.transaction` leave the anchors inside the recipe
or calls they carry to be resolved when those run.

### Variables

`vars.set {name, value}` binds a value to a name, and later calls read it
with `{"$var": name}`: a clipboard with provenance. Bound from an anchor,
the step keeps the anchor, so in a recipe the `vars.set` finds the value
again on the next file and every step that reads the variable gets that
file's value. `vars.list` lists the variables with the step that bound each
and where its value came from; `vars.clear` removes one or all. Undoing a
`vars.set` puts back the value bound before, or removes the binding.

### Step: a value an earlier step was given or returned

```json
{ "step": 1, "path": "result.set" }
{ "step": 3, "path": "result.matches[0].offset" }
{ "step": 2, "path": "params.start" }
{ "step": 4, "path": "job.candidates[0].period" }
```

The value at `path` in what step `step` of *this run* was given and
returned. The path starts with `params.` (its parameters, anchors
resolved), `result.` (what it returned) or `job.` (for a step that started
a job: the result the job finished with, which the run waits for). After
that come dotted keys and `[n]` indices from 0. The step must come earlier
in the recipe and have run; a step anchor naming a later step, or one not
in the recipe, is a mistake the recipe's warnings point out.

### Find: where a search matches

```json
{ "find": { "hex": "7ea5" }, "nth": 0 }
{ "find": { "text": "IEND" }, "nth": 2, "part": "len" }
```

The `nth` match (from 0, the default) of the bytes (`hex`) or UTF-8 text
(`text`), searching the whole document from its start, overlapping matches
included, as `search.find_all` counts them. `part` gives the match's
offset (`"offset"`, the default), its length (`"len"`), or the match as a
range, `{"range": [offset, len]}` (`"value"`), as `selection.set` and the
edits take it.

### Structure: a field of a parsed structure

```json
{ "structure": "png", "field": "IHDR.width", "part": "value" }
{ "structure": "png", "field": "chunks.IDAT[1].data" }
```

`structure` is the parser's id (`structure.parsers` lists them: `png`,
`jpeg`, `elf`, `zip`, `mbr`, `serial.cbor`…) or the id of a finding with a field tree. The structure is
the one that parser recognises at offset 0 of the document, or else the
first found among the document's findings in its first 16 MiB.

`field` is the field names from the structure's root, joined with dots.
When siblings share a name, the second and later are written `name[n]`,
counting from 0 (`IDAT[1]` is the second `IDAT`). As a shorthand the first
name may be one at any depth: `IHDR.width` finds the first field called
`IHDR`, depth first, then its child `width`. Names may hold spaces
(`bit depth`).

`part` gives the field's offset (the default), its length (`"len"`), or its
value (`"value"`): a number when the parser's text for it reads as an
integer (decimal or `0x` hex), otherwise that text.

### Finding: a span something recognised

```json
{ "finding": { "category": "compressed", "nth": 0 } }
{ "finding": { "id": "image/png", "nth": 1 }, "part": "len" }
```

The `nth` (from 0, in offset order) of the findings the Findings list would
show in the document's first 16 MiB (confidence 0.5 or more) that are of
`category` (a finding category in snake case: `compressed`, `image`,
`timestamp`, `offset_table`…) and whose id starts with `id`, or whose id's
part after its kind does (`image/png` finds `signature:image/png`). The
Findings list and `findings.query` show each finding's id; a zlib or other
compressed stream is `compressed-streams`, so the category `compressed`
finds it. Give `category`, `id` or both. `part` gives the finding's start (the default), its length,
or `{"range": [start, len]}`.

### Selection: what is selected when the step runs

```json
{ "selection": "current" }
{ "selection": "current", "part": "len" }
```

What is selected in the step's document when the step runs, as
`selection.set` takes it (the default, and `"value"`), or its first range's
start (`"offset"`) or length (`"len"`). Nothing selected stops the run.
In a recipe that selects bytes in an earlier step, this is what that step
selected.

### Param: a value given when the recipe runs

```json
{ "param": "key" }
```

The value given for the recipe's parameter, or its default; see
[Parameters](#parameters).

### Sheet: a document of the run

```json
{ "sheet": { "step": 2 } }
{ "sheet": { "step": 5, "nth": 1 } }
{ "sheet": "payload" }
{ "sheet": "input" }
```

The id, in this run, of the sheet step `step` made (its `nth` from 0, for a
step that made several), of the sheet a step labelled `payload` with its
`makes`, or of the run's input (`"input"`). The step must come earlier and
have made it; a sheet anchor naming a later step, or a label no earlier
step gives, is a mistake the recipe's warnings point out. A `doc` that is a
sheet anchor is resolved first, so the step's other anchors are found in
that sheet. In a preview, a sheet not yet made is shown as waiting for its
step, and the anchors to be found in it with it.

| Anchor | JSON | Resolves to |
| --- | --- | --- |
| Step | `{"step": 3, "path": "result.at"}` | a value an earlier step was given or returned |
| Find | `{"find": {"hex": "7ea5"}, "nth": 0}` | where a search matches |
| Structure | `{"structure": "png", "field": "IHDR.width"}` | a parsed field's offset, length or value |
| Finding | `{"finding": {"category": "compressed"}}` | a finding's span |
| Selection | `{"selection": "current"}` | what is selected when the step runs |
| Param | `{"param": "key"}` | a value given when the recipe runs |
| Sheet | `{"sheet": {"step": 3}}`, `{"sheet": "payload"}`, `{"sheet": "input"}` | the sheet step 3 made, the sheet labelled payload, or the run's input |
| Pick | `{"pick": {"step": 5, "list": "job.strings", "where": {"text": {"regex": "^NC500-"}}, "field": "text"}}` | an item chosen by what it holds from a list in a step's result |
| Then | `{"of": ANCHOR, "then": [{"add": 16}, {"encode": "text_to_hex"}]}` | a value another anchor finds, transformed |
| Var | `{"var": "serial"}` | the value last bound to a variable with `vars.set` |

### Pick: an item chosen from an earlier step's list

```json
{ "pick": { "step": 5, "list": "job.strings", "where": { "text": { "regex": "^NC500-[0-9A-F]{8}$" } }, "field": "text" } }
{ "pick": { "step": 9, "list": "result.candidates", "where": { "key": { "regex": "^([0-9a-f]{2}){1,8}$" } }, "field": "key" } }
{ "pick": { "step": "@rootfs", "list": "job.children", "where": { "name": { "equals": "config.enc" } }, "field": "path" } }
```

An item of a list in what an earlier step was given or returned, chosen by
what it holds rather than where it is, so it is found again in a list of
another length or order:

- `step` is the earlier step, by number, or as `"@label"` for the step that
  made the sheet labelled so;
- `list` is the list's path in the step's `{"params", "result", "job"}`, as
  a step anchor's path is written (`job.strings`, `result.candidates`);
- `where` keeps the items that pass: each key a field of the item (a path)
  with a test, `regex`, `equals`, `contains` (text or a list), `min` or
  `max`, every test given holding, or a value the field equals; `tag` a
  tag the item has (its `tag`, or one of its `tags`); `all` and `any`
  lists of such conditions. Every item when omitted;
- `sort` orders those kept, `{"by": "score", "order": "descending"}`
  (ascending when `order` is omitted), before `nth` (from 0) chooses one;
- `field` is the value to give inside the chosen item; the whole item when
  omitted.

A pick that keeps no item, or fewer than `nth + 1`, does not resolve and
says how many passed. In a preview, a pick waits for its step as a step
anchor does.

### Then: a value transformed

```json
{ "of": { "structure": "mbr", "field": "partition table.partition 1.starting LBA", "part": "value" }, "then": [ { "mul": 512 } ] }
{ "of": { "find": { "hex": "53594e434c4f4700" } }, "then": [ { "add": 16 } ] }
{ "of": { "var": "serial" }, "then": [ { "encode": "text_to_hex" } ] }
```

What the anchor `of` finds, through each operation of `then` in turn:

| Operation | Gives |
| --- | --- |
| `{"add": 16}`, `{"sub": 4}`, `{"mul": 512}` | the integer (or text read as one) plus, minus or times the number |
| `{"and": 255}` | the integer with only the mask's bits kept |
| `{"encode": "text_to_hex"}` | text as the hex of its UTF-8 bytes: `"NC5"` is `"4e4335"` |
| `{"encode": "hex_to_text"}` | hex as the UTF-8 text its bytes spell |
| `"int"` | text read as an integer, decimal or `0x` hex |
| `{"slice": [start]}`, `{"slice": [start, len]}` | part of a text (by characters) or a list |
| `"len"` | the length of a text (in characters) or a list |

### Var: a variable

```json
{ "var": "serial" }
```

The value last bound to the variable with `vars.set`, in the session or by
an earlier step of the run (see [Variables](#variables)). A variable no
earlier step of the recipe binds is a mistake the recipe's warnings point
out; in a preview, a variable an earlier step would bind waits for it.

## Recording a recipe

Every call that changes something is a step of the session's journal, by
whoever made it: the person, Ask, a plugin, an MCP client, the command
line or a recipe. A recipe made from the journal repeats those steps.

**What is journalled.** Each call of an `edit`, `view`, `job` or
`analysis` method is a step, with its parameters and result. Reads go into
a ring of recent reads; a read that a later step cites (its value was used)
is moved into the journal under its own number. Calls made inside another
call are part of that call's step. See
[The journal, undo and replay](api.md#the-journal-undo-and-replay).

**Which steps a recipe takes.** The successful steps in effect, and among
them the steps that make sheets (`documents.derive`, `unpack.open`…; see
[Steps and documents](#steps-and-documents)). Undone, failed and refused
steps are left out, as are moves along the history (`history.undo`,
`history.go_back`…), steps that opened a file or a source or a new document
(`documents.open`, `.new`, `.open_source`: those are the recipe's input,
not its steps), steps that wrote a file, `plugins.reload` and the live
sources' switches. A step that cites an earlier step through a step anchor
brings that step along, and so does a step that runs on a sheet: the step
that made it comes too, when it is in effect.

`history.recipe`, `history.save_recipe`, `recipes.save` and the History
tab's *Save to my recipes* and *Save as recipe…* all make the recipe with
one builder, so they keep the same steps.

**Provenance.** Where the window knows where a value came from, it records
it on the step as an anchor (in the entry's `derived_from`):

- a selection made with *Find next* or *All matches* records which match of
  the Find box's needle it was (a find anchor; past 100,000 matches, the
  search step that found it), and *All matches* each of up to 256 matches;
- selecting a finding records the finding (a finding anchor), and clicking
  a structure field its path (a structure anchor);
- a call on the one selected range (`start`/`len`, or `ranges`) records the
  selection (a selection anchor);
- a packet set split by a length field that `packets.detect_length_field`
  found cites that read (step anchors on `result.length_field.…`);
- a width set from a scanned period cites the `analysis.period_scan` job
  (`job.candidates[k].period`).

A semantic anchor (a match, a field, a finding, the selection) is preferred
to a step anchor when both apply, as it finds the value again in another
file.

**Clients** (MCP, Ask, Lua plugins) carry no provenance in their calls: a
call's params are the method's own. A client that used an earlier result
says so afterwards:

| Method | What it does |
| --- | --- |
| `history.suggest_anchors {step, path?}` | For each integer literal of the step's params (or the one at `path`), and each text an earlier step's list holds, the anchors that give the same value now: matches of searches earlier steps made, structure fields and findings at that offset, the selection an earlier step set, picks from lists earlier steps returned (by a pattern of the text's shape, the item's tag, or its place), and earlier steps' values equal to it, those that port to other files first. |
| `history.make_anchor {step, path, anchor}` | Turns the literal at `path` into `anchor` (written bare). A read the anchor cites becomes a step of the journal. |
| `history.make_parameter {step, path, name, description?, type?}` | Turns the literal into the parameter `name`, its default the literal, its type the literal's unless given; when an anchor found the literal, that anchor becomes its `default_anchor`. |
| `history.clear_anchor {step, path}` | Turns it back into the literal. |
| `history.recipe {name, description?, steps?}` | The recipe these make, without saving it. |

The History tab's *Recipe values* does the same by hand.

**Making the recipe.** A recipe made from the journal (`history.recipe`,
`recipes.save` with `journal_steps`, `history.save_recipe`, and the History
tab's *Save to my recipes* and *Save as recipe…*):

- turns each literal with a recorded anchor into `{"$anchor": …}` (a path
  the params no longer hold, because they were summarised, stays literal);
- numbers the steps 1, 2, 3… and renumbers step anchors to match; a step
  anchor that cites a step the recipe does not hold stays literal;
- declares each parameter a param anchor uses, with the type and default
  from the literal, or as `history.make_parameter` gave them;
- takes each step's document from the journal, which recorded the one the
  call ran on, not from its params, which often name none;
- takes for the recorded document the file the steps' documents all come
  from, by the sheets' lineage (a sheet's parent, its parent's, and so on),
  not the first document a step names; leaves it out of a step's `doc`, so
  the step runs on the run's input, and names it `{"sheet": "input"}` at
  any other path;
- names every other document, at any parameter path, by a sheet anchor on
  the step that made it (by the label it gave, when it gave one). A step
  naming a document no step of the recipe made (one opened from a second
  file, a sheet made outside the history or by a step left out or undone)
  fails the recipe, with an error naming the step, the document and why,
  and the problems as `data.problems`; the History tab shows it before
  asking where to save;
- records the API version, the plugins loaded and that file;
- is written as format 1 unless it needs [format 2](#format-2);
- leaves out the notes written with `history.note` as steps, and puts each
  note's text into the `note` of every step it is linked to, several notes
  on one step joined by a blank line. A step the note cites as `#12` is
  renumbered as the recipe numbers it, or written as "session step 12" when
  the recipe does not hold it. A note linked to none of the recipe's steps
  is left out: the recipe's `description` is what you give when you save
  it.

## Running a recipe

There are four ways, all through the same runner:

| Where | How |
| --- | --- |
| The window | *File › Run recipe…* (also in the palette and the History tab): pick a recipe, fill in its parameters, **Preview**, then **Run**. |
| The command line | `theviewer replay RECIPE FILE…`; see below. |
| Any API client | `recipes.preview` and `recipes.run`; see [below](#the-recipes-methods). |
| The History tab | Going back to a step and playback run the journal's own steps through the runner. |

A run goes like this:

1. **The document** is the run's input (see [Steps and documents](#steps-and-documents)).
   The sheets each step makes are kept, by step and by label, for later
   steps' sheet anchors.
2. **The parameters** are read and checked; the defaults fill in the rest.
3. **Each step's anchors** are resolved on this document, in order.
4. **The call** is made as `recipe:NAME`, so it is journalled and its edits
   are labelled "… by recipe:NAME".
5. **A job** the step starts is waited for, up to 10 minutes, and its
   result kept for later `job.` step anchors.
6. **The first failure stops the run**: a step whose anchor does not
   resolve, or whose call fails. The report says which step and why.
7. **The run's edits undo as one step** of each document it edited, the
   input and each sheet, "Recipe steps by recipe:NAME", whether the run
   completed or stopped.

A **preview** (`recipes.preview`, the window's Preview) resolves and
describes each step on this file without calling anything. It goes on past
a problem, marking each step that would fail; the first is where the run
would stop. A step anchor cannot be known until its step has run, so the
preview shows it as waiting for that step.

The report, as `recipes.run` returns it and `theviewer replay --json`
prints it per file:

```json
{
  "steps": [
    {
      "step": 1,
      "method": "packets.sets.create",
      "params": { "doc": "doc-1", "from": "pattern", "pattern": "7E A5", "start": 40 },
      "description": "Call packets.sets.create with {…}",
      "anchors": [
        { "path": "pattern", "anchor": { "param": "sync" }, "value": "7E A5" },
        { "path": "start", "anchor": { "find": { "hex": "7ea5" }, "nth": 0 }, "value": 40 }
      ],
      "outcome": "ok",
      "result": { "set": "set-1", "count": 9, "…": "…" },
      "journal_step": 1
    }
  ],
  "warnings": [ "this is not the file the recipe was recorded on (flight-03.bin, 64 bytes); …" ]
}
```

| Field | Meaning |
| --- | --- |
| `steps` | Each step run (or previewed), in order: its number, method, the params it was called with (anchors resolved), what it did in words, each anchor's path and value, `outcome` (`"ok"` or `{"error": {code, message, data}}`), its `result`, the journal step it was recorded as (`journal_step`, absent when the run was itself inside a call such as `recipes.run`), and, for a step that started a job, the job's final status as `job`. |
| `stopped` | Present when the run stopped early: the `step` and its `error`. |
| `warnings` | What to know that did not stop it; see [Failures, undo and warnings](#failures-undo-and-warnings). |
| `sheets` | The sheets the run made, in order: each one's `step`, `doc`, `label` (when its step gave one), `name` and `len`. |

## theviewer replay

```text
theviewer replay RECIPE FILE... [--param KEY=VALUE]... [--save | --out DIR] [--save-sheets DIR] [--allow-writes] [--plugins DIR]... [--json]
```

Runs the recipe on each FILE in turn, each in a workspace of its own with
the plugins from the usual places loaded. RECIPE is a recipe file's path
(anything ending in `.theviewer-recipe.json`, with a folder in it, or
naming an existing file), or
the name of one in `~/.config/theviewer/recipes/`: its file name, or the
name inside it, in any case.

| Option | Effect |
| --- | --- |
| `--param KEY=VALUE` | A value for one of the recipe's parameters, read as its type. Repeat it for several. |
| `--save` | Save each file the recipe ran to its end over itself, when the run changed it. |
| `--out DIR` | Save each file the recipe ran to its end into DIR (made if need be), under its own name, whether or not it changed. |
| `--save-sheets DIR` | Save each sheet the run made into DIR (made if need be), as `FILE.stepN.LABEL.bin` (LABEL being the sheet's label, or its id), whether or not the run completed. |
| `--allow-writes` | Let steps that write a file run (`documents.export`, `unpack.save`, `packets.extract` with a `path`…). Without it such a step stops the run, as a recipe from someone else could write anywhere. |
| `--plugins DIR` | Load plugins from DIR instead of `./plugins` and `~/.config/theviewer/plugins`. Repeat it for several. |
| `--json` | Print the reports as JSON, `{"recipe": NAME, "files": [...]}`. |

Give `--save` or `--out`, not both. Without either, no file is changed: the
report is the point. A file the recipe stopped on is never saved.

The text output is a line per file, then its warnings and where it was
saved:

```text
flight-04.bin: Telemetry frames — 2 steps ran
  warning: this is not the file the recipe was recorded on (flight-03.bin, 64 bytes); its anchors find their values here, but literal offsets may not fit
  saved to decoded/flight-04.bin
noise.bin: Telemetry frames — Stopped at step 1 (packets.sets.create): the parameter start: the 1st match of hex 7ea5 did not resolve: doc-1 has no 1st match of hex 7ea5: it does not occur
  warning: this is not the file the recipe was recorded on (flight-03.bin, 64 bytes); its anchors find their values here, but literal offsets may not fit
```

With `--json`, each entry of `files` is `{file, report, saved?, error?,
sheets_saved?}`: the file as given, the [report](#running-a-recipe) (absent
when the file could not be opened), where it was saved, the error that
stopped it opening or saving, and where each sheet was saved with
`--save-sheets`.

**Exit status.** 0 when the recipe ran to its end on every file (and each
was saved if asked); 1 when it stopped on any file, a file could not be
opened or saved, or the recipe could not be found or read; 2 when the
command line could not be understood (no files, an unknown option, both
`--save` and `--out`).

Each step runs as `recipe:NAME`, and every step is allowed, the files being
the ones you named, but for writing files, which needs `--allow-writes`.

## The recipes methods

| Method | Effect | What it does |
| --- | --- | --- |
| `recipes.list` | read | The recipes in `~/.config/theviewer/recipes/`: each one's name, description, path, number of steps and parameters, or why its file could not be read. |
| `recipes.describe {name \| path}` | read | One recipe in full, with its warnings for this API and these plugins. |
| `recipes.save {recipe \| journal_steps, name?, description?, overwrite?}` | read, writes a file | Saves a recipe among yours, given whole or made from journal steps (with their anchors, as above). `name` and `description` replace the recipe's own; an existing recipe of that name is replaced only with `overwrite`. Returns its path and warnings. |
| `recipes.preview {name \| path \| recipe, doc?, parameters?, through_step?}` | read | The run's report without calling anything. |
| `recipes.run {name \| path \| recipe, doc?, parameters?, through_step?}` | edit | Runs it. A run that stops fails with the stopped step's error code, a message giving the summary, and the report as `data.report`. |

`history.save_recipe {path, name, description?, through?}` writes the
steps in effect (up to step `through`) to a recipe file at `path`, and
`history.recipe` returns a recipe without saving it. Every parameter is in
[docs/api.md](api.md#recipeslist).

## Permissions

`recipes.run` is an `edit`, so it is checked against its caller's setting
under Settings › Permissions like any edit, and each step is called as
`recipe:NAME`. Who may do what is decided by who started the run:

- **The person**, by pressing Run after the preview in the window, or by
  going back or playing steps in the History tab: the run is consented to,
  and its steps are not asked about one by one.
- **A client the person allowed when asked**, with *Allow once* or
  *Always allow this client* (the confirmation window lists the recipe's
  steps: "Run the recipe 'Telemetry frames' on the current document: 2
  steps (packets.sets.create, packets.decode_as)"): the same, since the
  person has seen what it will do.
- **A client its setting allows without asking:** each step is checked
  against that client's setting too, so a recipe can do no more than its
  caller may; a step the setting does not allow stops the run.
- **A client set to *Never allow*:** the run is refused, as any edit is.

`recipes.save` and `history.save_recipe` write files, so they need leave to
edit. On the command line (`theviewer api`, `theviewer replay`) and through
`theviewer mcp`, every call is allowed.

## Failures, undo and warnings

**A failure stops the run** at the step that failed, and later steps do not
run. So does a step that names a document by an id that is neither the
run's input nor a sheet the run made ("step 1 (bytes.insert) names doc-3 at
doc, which is neither this run's input (doc-1) nor a sheet one of its steps
made…"): it does not run on the input instead. The report's `stopped` gives the step and the error; an anchor that
did not resolve says which anchor, at which path, and why ("the parameter
start: the 1st match of hex 7ea5 did not resolve: doc-1 has no 1st match
of hex 7ea5: it does not occur").

**Undo.** Whether it completed or stopped, everything the run changed in
the document's bytes is one undo step, "Recipe steps by recipe:NAME", so
one *Undo* (or `history.undo`) takes it all back. In the journal, a
`recipes.run` (which the window's Run also calls) is one step, with the
recipe's steps inside it; `theviewer replay` records each step as a step
of its own.

**Warnings** do not stop a run. They are given by `recipes.describe`,
`recipes.save`, the preview and the run:

- the recipe was recorded with another major version of the API;
- a plugin it was recorded with is not loaded ("steps that use it will
  fail"), or has changed since ("its steps may give other results");
- a step calls a method this theviewer does not have;
- this is not the file it was recorded on (a different size, or a different
  SHA-256 when both are known): its anchors find their values here, but its
  literal offsets may not fit;
- mistakes in the recipe itself: a step or sheet anchor naming a step that
  does not come before it, a sheet label no earlier step gives, a parameter
  used but not declared, two steps with one number.

## A worked example

ACME telemetry captures start with a header whose length varies from file
to file, then frames that each start with the sync word `7E A5`, a type
byte, a length byte and the payload. The aim: split any such capture into
its frames and decode them, whatever its header.

**1. Record it.** On `flight-03.bin`, whose frames start at offset 16, an
MCP client (or you, in the window) searches for the sync word, takes the
packets from there and decodes them with a template:

```json
{"name": "api_call", "arguments": {"method": "search.find", "params": {"query": "7E A5", "mode": "hex"}}}
{"name": "packets_sets_create", "arguments": {"from": "pattern", "pattern": "7E A5", "start": 16}}
{"name": "api_call", "arguments": {"method": "packets.decode_as", "params": {"set": "set-1",
  "template": "struct Frame { sync: u16be display hex\n kind: u8\n len: u8\n payload: bytes[len] }\nroot Frame"}}}
```

The search returned `{"at": 16}`, the set is `set-1`, and `history.list`
shows two steps: 2 (`packets.sets.create`) and 3 (`packets.decode_as`);
the search is a read, kept among the recent reads.

**2. Generalise it.** The literals 16 and `set-1` suit this file only. Ask
what could stand for the 16:

```json
{"method": "history.suggest_anchors", "params": {"step": 2, "path": "start"}}
```

```json
{"literals": [{"path": "start", "value": 16, "anchor": null, "suggestions": [
  {"anchor": {"find": {"hex": "7ea5"}, "nth": 0}, "reason": "the 1st match of 7ea5"},
  {"anchor": {"step": 1, "path": "result.at"}, "reason": "result.at of step 1 (search.find)"}]}]}
```

Take the first match of the sync word, which ports to any file; make the
set the one step 2 made; and let whoever runs it give another sync word:

```json
{"method": "history.make_anchor", "params": {"step": 2, "path": "start", "anchor": {"find": {"hex": "7ea5"}, "nth": 0}}}
{"method": "history.make_anchor", "params": {"step": 3, "path": "set", "anchor": {"step": 2, "path": "result.set"}}}
{"method": "history.make_parameter", "params": {"step": 2, "path": "pattern", "name": "sync",
  "description": "The sync word that starts each frame, as hex"}}
```

**3. Save it.**

```json
{"method": "recipes.save", "params": {"name": "Telemetry frames", "journal_steps": [2, 3]}}
```

This writes `~/.config/theviewer/recipes/Telemetry frames.theviewer-recipe.json`,
the file shown [at the top](#a-recipe-file) (but with no plugins, as
none were loaded, and without the `description` and `note`, which
`recipes.save` takes and you can also add by hand): the steps renumbered 1 and 2, the
offset a find anchor, the set a step anchor on step 1's result, and the
sync word a parameter whose default is the literal it replaced.

**4. Run it on another file.** `flight-04.bin` has a 40-byte header:

```sh
theviewer replay "Telemetry frames" flight-04.bin noise.bin --out decoded/
```

```text
flight-04.bin: Telemetry frames — 2 steps ran
  warning: this is not the file the recipe was recorded on (flight-03.bin, 64 bytes); its anchors find their values here, but literal offsets may not fit
  saved to decoded/flight-04.bin
noise.bin: Telemetry frames — Stopped at step 1 (packets.sets.create): the parameter start: the 1st match of hex 7ea5 did not resolve: doc-1 has no 1st match of hex 7ea5: it does not occur
  warning: this is not the file the recipe was recorded on (flight-03.bin, 64 bytes); its anchors find their values here, but literal offsets may not fit
```

On `flight-04.bin` the find anchor resolved to 40 and the set held 9
frames; `noise.bin` has no sync word, so the run stopped at step 1, nothing
was saved for it, and the exit status is 1. With `--json`, each step's
`anchors` show where each value came from. In the window, the same recipe
is under *File › Run recipe…*, where the preview shows the 40 before
anything runs.
