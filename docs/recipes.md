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
| `recipe` | yes | The file format, `1`. A recipe of a later format is refused, with a message to update theviewer. |
| `api_version` | yes | The API's major version the steps were recorded against, `"1.x"`. Running under another major version warns. |
| `name` | yes | The recipe's name, which may not be empty. `recipes.list`, `theviewer replay "NAME"` and the edit labels ("… by recipe:Telemetry frames") use it. |
| `description` | no | What it is for. |
| `parameters` | no | The values it asks for when it runs, by name; see [Parameters](#parameters). |
| `recorded_on` | no | The file it was recorded on: `name`, `size` and `sha256` (left out for a file over 256 MiB). Running on another file warns. |
| `plugins` | no | The plugins loaded when it was recorded, each `name` and `sha256` of its source. Running without one, or with a changed one, warns. |
| `steps` | yes | The calls, in order; see below. |

Each step is:

| Field | Required | Meaning |
| --- | --- | --- |
| `step` | yes | The step's number: 1, 2, 3… in a recipe made from the journal, or any increasing numbers in one written by hand. Step anchors name steps by it. |
| `method` | yes | The method to call, such as `packets.sets.create`, a plugin's (`acme.decode_frame`) included. |
| `params` | no | Its parameters: literals, except where a value is marked as an anchor. |
| `note` | no | What the step is for, in your words. |

The JSON Schema of the file is the `recipe` parameter's in
`api.describe` (`recipes.save` takes a recipe whole).

## Steps and documents

A recipe runs on one document: the one it is run on (the file given to
`theviewer replay`, the document named by `recipes.run`'s `doc`, or the
current one). A step's `doc` that names the document the recipe was
recorded on means the run's document: a step with no `doc`, with
`"current"`, or with the id that the first step naming a document names
(`"doc-1"` as recorded). Recipes made from the journal leave the recorded
document's `doc` out altogether.

A step's other `doc` values are kept as written. A document an earlier step
opened (`documents.derive`, `codecs.open_decoded`) is best named by a step
anchor on that step's result, such as
`{"$anchor": {"step": 2, "path": "result.doc"}}`.

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

When a recipe runs:

- a value given as text (as `theviewer replay --param key=5a` and the *Run
  recipe…* window give them) is read as the declared type: an integer in
  decimal or `0x` hex, a number, `true`/`yes`/`1` or `false`/`no`/`0`;
- a parameter not given takes its default; one with no default must be
  given, or the run stops before its first step, saying which;
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
{ "finding": { "id": "zlib", "nth": 1 }, "part": "len" }
```

The `nth` (from 0, in offset order) of the findings the Findings list would
show in the document's first 16 MiB (confidence 0.5 or more) that are of
`category` (a finding category in snake case: `compressed`, `image`,
`timestamp`, `offset_table`…) and whose id starts with `id`, or whose id's
part after its kind does (`zlib` finds `stream:zlib`). Give `category`,
`id` or both. `part` gives the finding's start (the default), its length,
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

**Which steps a recipe takes.** The successful steps in effect: undone,
failed and refused steps are left out, as are moves along the history
(`history.undo`, `history.go_back`…), steps that opened a document or wrote
a file, `plugins.reload` and the live sources' switches. A step that cites
an earlier step through a step anchor brings that step along.

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
| `history.suggest_anchors {step, path?}` | For each integer literal of the step's params (or the one at `path`), the anchors that give the same value now: matches of searches earlier steps made, structure fields and findings at that offset, the selection an earlier step set, and earlier steps' values equal to it, those that port to other files first. |
| `history.make_anchor {step, path, anchor}` | Turns the literal at `path` into `anchor` (written bare). A read the anchor cites becomes a step of the journal. |
| `history.make_parameter {step, path, name, description?, type?}` | Turns the literal into the parameter `name`, its default the literal, its type the literal's unless given. |
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
- drops a `doc` that names the recorded document, so each step runs on the
  run's document;
- records the API version, the plugins loaded and the file the first step
  was about.

## Running a recipe

There are four ways, all through the same runner:

| Where | How |
| --- | --- |
| The window | *File › Run recipe…* (also in the palette and the History tab): pick a recipe, fill in its parameters, **Preview**, then **Run**. |
| The command line | `theviewer replay RECIPE FILE…`; see below. |
| Any API client | `recipes.preview` and `recipes.run`; see [below](#the-recipes-methods). |
| The History tab | Going back to a step and playback run the journal's own steps through the runner. |

A run goes like this:

1. **The document** is the run's (see [Steps and documents](#steps-and-documents)).
2. **The parameters** are read and checked; the defaults fill in the rest.
3. **Each step's anchors** are resolved on this document, in order.
4. **The call** is made as `recipe:NAME`, so it is journalled and its edits
   are labelled "… by recipe:NAME".
5. **A job** the step starts is waited for, up to 10 minutes, and its
   result kept for later `job.` step anchors.
6. **The first failure stops the run**: a step whose anchor does not
   resolve, or whose call fails. The report says which step and why.
7. **The run's edits undo as one step** of the document, "Recipe steps by
   recipe:NAME", whether the run completed or stopped.

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

## theviewer replay

```text
theviewer replay RECIPE FILE... [--param KEY=VALUE]... [--save | --out DIR] [--json]
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
```

With `--json`, each entry of `files` is `{file, report, saved?, error?}`:
the file as given, the [report](#running-a-recipe) (absent when the file
could not be opened), where it was saved, and the error that stopped it
opening or saving.

**Exit status.** 0 when the recipe ran to its end on every file (and each
was saved if asked); 1 when it stopped on any file, a file could not be
opened or saved, or the recipe could not be found or read; 2 when the
command line could not be understood (no files, an unknown option, both
`--save` and `--out`).

Each step runs as `recipe:NAME`, and every step is allowed: the files are
the ones you named.

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
- **A client the person allowed when asked** (the confirmation window
  lists the recipe's steps: "Run the recipe 'Telemetry frames' on the
  current document: 2 steps (packets.sets.create, packets.decode_as)"): the
  same, since the person has seen what it will do.
- **A client its setting allows without asking:** each step is checked
  against that client's setting too, so a recipe can do no more than its
  caller may; a step the setting does not allow stops the run.

`recipes.save` and `history.save_recipe` write files, so they need leave to
edit. On the command line (`theviewer api`, `theviewer replay`) and through
`theviewer mcp`, every call is allowed.

## Failures, undo and warnings

**A failure stops the run** at the step that failed, and later steps do not
run. The report's `stopped` gives the step and the error; an anchor that
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
- mistakes in the recipe itself: a step anchor naming a step that does not
  come before it, a parameter used but not declared, two steps with one
  number.

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
