# Worksheets, explicit outputs and bound values

Status: proposal, not yet built. Written against main at 2379cc1 (analysis
notes included); line numbers refer to that commit.

The evidence is six CTF-style challenges solved with theviewer over MCP
(`theviewer-demo/ctf/*/REPORT.md`): every one of them failed to replay its
recipe on a second file, and most retyped values found by one tool into
another.

## 0. Summary

Six things, each a generalisation of something that already exists:

1. **Worksheets** are documents with a recorded lineage. The window's
   `parents` stack becomes a set of parked sheets with one active; Back
   shows the parent and no longer closes the child; siblings become
   possible.
2. **A step that makes a sheet is a real step.** The journal records the
   sheets each step made; recipes keep those steps and name their output
   with a `sheet` anchor, never a literal `doc-N`.
3. **Values flow through anchors, live as well as in recipes.**
   `{"$anchor": …}` is accepted at call time by every caller. New anchor
   kinds: `sheet` (the sheet step N made), `pick` (the first string
   matching a regex, the top key), `then` (arithmetic and conversions),
   and `var` (`$serial`, bound with `vars.set`).
4. **One output parameter.** `output: "in_place" | "new" | "return" |
   {"file": …}` on every method that produces bytes; existing method
   names stay as aliases.
5. **Each caller has a focus.** An omitted `doc` means that caller's focus
   sheet; making a new sheet never moves it, so the default no longer
   flips under an MCP client.
6. **A recipe is a DAG of sheets and steps**, written as format 2 only
   when it uses the new constructs. The History tab can group steps under
   the sheet they ran on.

## 1. How it works today, and why recipes fail

### 1.1 Documents

- `Workspace` (`src/api/workspace.rs:69`): `resolve()` (`:200`) maps a
  missing `doc` or `"current"` to one `current_document()` shared by every
  caller. `open_derived` (`:124`) returns an id and makes it current;
  neither the trait nor `DocumentInfo` (`:41`) records the parent or how
  the sheet was made.
- `HeadlessWorkspace` (`:261`, used by MCP): `add_document` (`:312`)
  always sets current (`:322`), so every derive flips the default for the
  next call (disk-forensics #10, firmware-update F4). `open_derived`
  (`:491`) checks the parent exists, then forgets it.
- The window shows one document: `ParentDocument` (`src/app.rs:86`), the
  `parents` stack (`:246`), `Identity::{New, Derived, Back, Same}`
  (`:106`) deciding what `install_document` (`:2428`) closes.
  `back_to_parent` (`:2457`) pops and closes the child; through the API
  `switch_to` (`workspace.rs:691`) to a parent closes everything below it.
  Deriving twice from one parent nests the second under the first.
- `Workbench::document_changed` (`src/workbench.rs:217`) throws away every
  panel's results when the shown document changes.
- The packet viewer's `foreign_document` (`src/panel_packets.rs:286`) knows
  only that its packets describe some other document, not which; byte
  tools it drives act on whatever is current.

### 1.2 Methods

`.opens_document(derives)` (`src/api.rs:263`) sets
`Replay::OpensDocument`. It is used by `documents.open`, `.new`,
`.open_source`, `.derive`, `codecs.open_decoded`, `bits.open_plane`,
`bits.decode_linecode`, `unpack.open`, `forensics.open_entry` and
`sources.view_version`. Their results differ: `result.id` for some,
`result.document.id` for others (the docs' `result.doc` matches neither).

### 1.3 Journal, anchors, recipes

- Reads go into a ring (`src/journal.rs:97`) and become steps only when
  cited (`promote`, `:870`).
- `JournalEntry` (`:163`) records `doc`, but `params` keep what the caller
  sent, often no `doc`.
- `Anchor` (`src/journal/anchors.rs:59`): Step, Find, Structure, Finding,
  Selection, Param.
- `replayable_entries` (`src/journal/timeline.rs:943`) keeps only
  `Replay::Step`.
- `recorded_document()` (`src/journal/replay.rs:256`) takes the first
  `doc` any step names as the run's document; `prepare()` (`:350`) maps
  omitted, `"current"` and that id to the run document and passes any
  other id through. `drop_recorded_doc` (`provenance.rs:470`) strips only
  the recorded doc.

### 1.4 Root causes

| # | Cause | Where | Reports |
|---|---|---|---|
| R1 | Sheet-making steps are `OpensDocument`, dropped from recipes | `timeline.rs:943`, `api.rs:263` | all six |
| R2 | Later steps keep literal `doc-4` | `provenance.rs:470` | firmware F1, malware #3, radio F1 |
| R3 | The first named id becomes the run's file, even a derived one, so steps silently edit the input | `replay.rs:256` | proto #1, dns #1 (edited the pcapng), radio |
| R4 | A step without `doc` replays on the input even when it ran on a derived sheet | `recipe.rs`, `replay.rs:350` | firmware (`unpack.run {}` on the container) |
| R5 | Values found by reads cannot be bound; MCP sends no provenance; anchors can't say "first string matching", "top key", "+16", "text as hex key" | `anchors.rs:59` | firmware F2, dns #2, disk #3 |
| R6 | One current for every caller, flipped by every open | `workspace.rs:200,322` | disk #10, firmware F4 |
| R7 | Byte results come back only as hex, round-tripped through `derive {data}`, losing lineage | various | dns #6, proto #12, malware #2 |
| R8 | `history.recipe` and `history.save_recipe` keep different steps | `api/history.rs` | dns #10 |

## 2. The worksheet model

A **worksheet** ("sheet" in code and UI) is an open document plus its
lineage. API ids stay `doc-N` and "document" stays the API noun.

```rust
pub struct Lineage {
    pub parent: Option<String>,        // None: a root, opened from a file, URL or new
    pub made_by: Option<MadeBy>,
}
pub struct MadeBy {
    pub step: Option<u64>,             // the journal step that made it
    pub method: String,
    pub params: Value,                 // as called, anchors resolved
    pub span: Option<Vec<(u64, u64)>>, // ranges of the parent it came from
    pub label: Option<String>,         // a short name: "payload"
}
```

`DocumentInfo` gains `parent`, `made_by`, `label` and `focus` (additive,
API 1.1); `documents.list {tree: true}` nests them.

**Window.** `ParentDocument` becomes `ParkedSheet` with a `Lineage`;
`parents` becomes `parked`, with no ordering meaning. The active sheet's
state stays in `ViewerApp`'s fields, so the many `self.document` uses are
unchanged.

- `activate(id)` parks the active sheet and un-parks `id`, keeping cursor,
  shape, top row and cached analysis; it closes nothing.
- `open_derived` parks the active sheet and installs the child with its
  parent; siblings work.
- Back (Cmd+[, status bar, *Back out*) activates the parent; the child
  stays open.
- Close sheet (Cmd+W, `documents.close`) closes a sheet and its
  descendants, asking when any has unsaved edits.
- Opening a file adds a root rather than closing the others (File › Open
  offers "Close other worksheets").
- Panel results that came from jobs are kept per sheet; a panel showing
  another sheet's results says so ("From payload (doc-4) · Show it").
- The packet viewer's `foreign_document` becomes `source_sheet`; actions
  it drives pass that `doc`, and overlays draw only on that sheet.

**Headless.** `OpenDocument` gains its lineage; a derive does not move
focus.

## 3. Explicit inputs and outputs

### 3.1 Today

| Method | In place | New sheet | Returns bytes | File |
|---|---|---|---|---|
| `transform.apply` | only | via `documents.derive {transform}` | `transform.preview` | – |
| `documents.derive` | – | only | – | `documents.export` |
| `codecs.decode` | – | – | only | – |
| `codecs.open_decoded` | – | only | – | – |
| `bits.decode_linecode`, `bits.open_plane` | – | only | – | – |
| `unpack.open` / `.read` / `.save` | – | open | read | save |
| `forensics.open_entry` | – | only | – | – |
| `packets.extract` | – | – | yes | path |
| `packets.follow_stream` | – | – | yes | – |
| `xor.recover_keys`, `crypto.attack` | – | – (window only) | preview | – |

### 3.2 One parameter

A shared module `src/api/output.rs`:

```jsonc
"output": "in_place"                                     // undoable edit of the input
"output": "new"                                          // a new sheet, not focused
"output": {"new": {"label": "payload", "focus": false}}
"output": "return"                                       // bytes in the result
"output": {"file": "/path/out.bin"}                      // needs leave to edit
```

- Every such result gains `"output": {"doc": "doc-5", "label": …, "len":
  …}` (new) or `{"version": 7}` (in place), so later steps have one stable
  path, `result.output.doc`.
- `Method` gains `outputs: Outputs { allowed, default }`, published by
  `api.describe` and read by the journal to tell whether a call made a
  sheet (replacing `opens_document(true)`).
- `output::deliver(ws, caller, input, produced, &output)` does the edit,
  the derive, the return or the write; each method computes its bytes and
  calls it.

Defaults keep today's behaviour:

| Method | Default | Gains |
|---|---|---|
| `transform.apply` | `in_place` | `new`, `return` (absorbs `transform.preview`) |
| `documents.derive` | `new` | `file`; `sources: [{doc, ranges}]` to join sheets |
| `codecs.decode` | `return` | `new`, `in_place`; any codec, plugins' included |
| `codecs.open_decoded` | alias of `codecs.decode {output: "new"}` | – |
| `bits.decode_linecode`, `bits.open_plane` | `new` | `return` |
| `unpack.open` | `new` | `tree_doc`, defaulting to the sheet `unpack.run` ran on |
| `forensics.open_entry` | `new` | `return`, `file` |
| `packets.extract` | `return` | `new` (parent: the set's source sheet), `file` |
| `packets.follow_stream` | `return` | `new` |
| `crypto.attack`, `xor.recover_keys` | unchanged | `crypto.apply {candidate \| operation, output}` |

## 4. Piping and binding

### 4.1 Anchors at call time

`api::call_as` resolves `{"$anchor": …}` anywhere in params before
deserialising, against the live session, and records them as the entry's
`derived_from`, with the resolved literals in `params`. The journal always
has both the value and where it came from, so MCP clients get provenance
without `history.make_anchor` round trips. Shorthands: `{"$var": "serial"}`
and `{"$sheet": 7}` / `{"$sheet": "payload"}`.

### 4.2 New anchor kinds

| Anchor | JSON | Resolves to |
|---|---|---|
| Sheet | `{"sheet": {"step": 3}}`, `{"sheet": "payload"}`, `{"sheet": "input"}` | the sheet step 3 made, the sheet labelled payload, or the run's input |
| Pick | `{"pick": {"step": 5, "list": "job.strings", "where": {"text": {"regex": "^NC500-"}}, "nth": 0, "field": "text"}}` | an item chosen by a predicate from a list in a step's result |
| Then | `{"of": ANCHOR, "then": [{"add": 16}, {"mul": 512}, {"encode": "text_to_hex"}]}` | a value transformed |
| Var | `{"var": "serial"}` | the latest value bound to `serial` before this step |

`where` takes `regex`, `equals`, `contains`, `min`, `max` and `tag`,
combined with `all` and `any`; `sort` comes before `nth`. A step may also
be named by the label of the sheet it made (`{"step": "@payload"}`).

### 4.3 Variables

`vars.set {name, value}` (journalled, replayed, undone by removing the
binding), `vars.list`, `vars.clear`. A variable is a clipboard with
provenance: in a recipe its `vars.set` keeps the anchor and so finds the
value again on the next file. *Make parameter* can turn it into a
parameter whose default is the anchor.

```jsonc
{"method": "strings.find", "params": {"doc": {"$sheet": "rootfs"}}}
{"method": "vars.set", "params": {"name": "serial", "value": {"$anchor": {"pick": {"step": 7,
   "list": "job.strings", "where": {"text": {"regex": "^NC500-[0-9A-F]{8}$"}}, "field": "text"}}}}}
{"method": "transform.apply", "params": {"doc": {"$sheet": "config"}, "selection": {"range": [0, 192]},
   "operation": {"op": "xor", "key": {"$anchor": {"of": {"var": "serial"}, "then": [{"encode": "text_to_hex"}]}}},
   "output": {"new": {"label": "config.plain"}}}}
```

### 4.4 In the window

Every result row (strings, keys, candidates, findings, fields, packets,
matches, bookmarks, the selection) can build a **Carry**: a value with its
anchor, bytes with their sheet and ranges, or a sheet.

1. **Send to…** on right-click and in the shared Selection menu: New
   worksheet, Variable…, or a compatible input of any open tool (XOR key,
   offset, range, crib, CRC records).
2. **Use as…** buttons where one target dominates: *Use as key* on a
   candidate or string, *Open as worksheet* on a finding.
3. **Drag and drop** onto input fields, later.

A bound field shows a chip in place of a text box, such as
`[NC500-2F357657 · from step 7, string /^NC500-/ ✕]`; ✕ unbinds and keeps
the literal. The panel passes the anchor through the existing
`perform_derived` (`src/actions.rs:43`).

## 5. Recipes become pipelines

### 5.1 Recording

- New `Replay::MakesSheet`, kept by recipes, playback and go back like
  `Step`; set when a call used `output: "new"`. `documents.open`, `.new`
  and `.open_source` stay inputs, not steps. Going back within a session
  reuses a sheet a step made if it is still open and unedited.
- `JournalEntry` gains `made: Vec<String>`, and `doc` is always explicit
  (§6). Building a recipe rewrites every doc-valued param: the root is
  dropped; an id in a kept step's `made` becomes a `sheet` anchor (by
  label when there is one); any other id fails the save with the step and
  the reason. `history.recipe` and `save_recipe` share one builder (R8).
- The recorded root is the root of the lineage the kept steps' sheets
  descend from, not the first id named (R3). A step's doc comes from
  `entry.doc`, not its params (R4).
- The runner resolves `sheet` anchors through a map of the sheets each
  step made, refuses an unknown literal id instead of running it on the
  input (format 1 too), opens undo groups per sheet edited, lists the
  sheets it made, and gains `--save-sheets DIR` and `--allow-writes`.

### 5.2 Format 2

```jsonc
{
  "recipe": 2, "api_version": "1.x", "name": "NovaCam triage",
  "inputs": {"input": {"recorded_on": {"name": "novacam_2.0.3.upd", "size": 412160, "sha256": "…"}}},
  "steps": [
    {"step": 1, "method": "documents.derive", "makes": "reassembled",
     "params": {"ranges": [/* anchored */]}, "note": "strip CRC trailers"},
    {"step": 2, "method": "unpack.run", "params": {"doc": {"$anchor": {"sheet": "reassembled"}}}},
    {"step": 3, "method": "unpack.open", "makes": "rootfs",
     "params": {"tree_doc": {"$anchor": {"sheet": "reassembled"}},
                "path": {"$anchor": {"pick": {"step": 2, "list": "job.nodes", "where": {"name": {"equals": "rootfs"}}, "field": "path"}}}}},
    {"step": 4, "method": "strings.find", "params": {"doc": {"$anchor": {"sheet": "rootfs"}}}},
    {"step": 5, "method": "vars.set", "params": {"name": "serial", "value": {"$anchor": {"pick": {}}}}},
    {"step": 6, "method": "transform.apply", "makes": "config.plain",
     "params": {"doc": {"$anchor": {"sheet": "rootfs"}},
                "operation": {"op": "xor", "key": {"$anchor": {"of": {"var": "serial"}, "then": [{"encode": "text_to_hex"}]}}},
                "output": "new"}}
  ]
}
```

The writer emits format 1 unless the recipe uses a new anchor, `makes`
or several inputs; the reader accepts both.

### 5.3 The failing replays

| Report | Failure | Fixed by |
|---|---|---|
| firmware-update F1, F2, F4 | derives dropped; literal ids; key retyped; `unpack.run {}` on the container | MakesSheet, sheet anchors, `entry.doc`, pick/var/`text_to_hex`, `tree_doc` |
| radio-remote F1 | derive and line decode dropped; `doc-2` fell back to `doc-1` | MakesSheet, sheet anchors, unknown ids refused |
| packed-malware #3 | `doc-3`, `doc-5` not found | as above, plus `crypto.apply` / `crypto.decrypt {output}` |
| dns-exfil #1, #10 | an insert ran on the capture; inconsistent step lists | R3, one builder, `packets.extract {output: "new"}`, `derive {sources}`, key by `pick` |
| proprietary-protocol #1 | step 10 ran on the main document | R3, sheet anchors, `pick` over packets |
| disk-forensics #2, #3, #10 | carve dropped; no offset arithmetic; current flipped | MakesSheet, `then`, focus |

### 5.4 History tab

A **Sheets** view beside *Show undone* and *Notes only*:

```
 History                     [Steps | Sheets]  [Show undone] [Notes only]  [Save as recipe…]
 ─────────────────────────────────────────────────────────────────────────────────────────
 ▾ novacam_2.0.3.upd  (input)
     #1  documents.derive  ranges ×6 (anchored)            ──▶ reassembled
     ▾ reassembled  (doc-2, 401 KiB)                                   [Show]
         #2  unpack.run                                         job · 14 nodes
         #3  unpack.open  rootfs  (pick: name = rootfs)    ──▶ rootfs
         ▾ rootfs  (doc-3)                                            [Show]
             #4  strings.find                                    job · 312 strings
             #5  $serial = "NC500-2F357657"   ← pick #4 /^NC500-/
             #6  transform.apply xor key=$serial → new         ──▶ config.plain
             ┆ note 7: the factory note says the config key is the serial (#4, #5)
             ▸ config.plain  (doc-4)                                   [Show]
 ─────────────────────────────────────────────────────────────────────────────────────────
 ⚠ 0 unresolved documents · 2 literal offsets (Suggest anchors…)
```

A step that would not replay gets a warning before saving. Notes may cite
a sheet label (`#payload`); notes linked to a sheet-making step go into
its recipe `note` as for any step.

## 6. Focus, for MCP and the API

- The workspace keeps a focus per caller. Before a method that takes a
  document runs, an omitted `doc` is filled in with the caller's focus, so
  journal entries always carry `doc`.
- Focus moves when a call passes `doc`, on `documents.open` /
  `documents.activate`, and on `output: {"new": {"focus": true}}`; making
  a sheet does not move it.
- The panel's focus is the window's active sheet, so nothing changes for
  the person at the window.
- `"current"` remains, meaning the window's active sheet (or headless
  current), and is documented as the thing agents should not use.
- Sheet-making results include `output.doc`; `documents.list` marks the
  caller's focus; errors on a default document name the sheet used.
- The MCP instructions tell clients to pass `{"$sheet": N}` and
  `{"$var": "x"}` and to bind discovered values with `vars.set`;
  `vars_set` and `documents_list` join the core tools beside
  `history_note`.

## 7. Compatibility

API 1.1, additive: `output`, `DocumentInfo` lineage and focus, `vars.*`,
`documents.close` and `.activate`, the new anchors, `sources` on derive.

Behaviour changes, in the changelog and the API conventions:

1. An omitted `doc` means the caller's focus. Nothing changes at the
   window; for MCP and CLI clients a derive no longer redirects later
   calls (the reported bug).
2. In the window, Back and `documents.open {doc}` no longer close derived
   sheets, and File › Open no longer closes the others.
3. A replay step naming an unknown document id fails instead of running on
   the input.

`theviewer mcp --legacy-current` restores the old default for one release.
`codecs.open_decoded`, `transform.preview`, `documents.export`,
`unpack.read` and `unpack.save` stay as documented shorthands. Format 1
recipes run unchanged apart from the R3 safety fix; `recipes.upgrade`
rewrites literal ids that match an earlier step's result as sheet anchors.

## 8. Window sketches

**Worksheet strip**, under the toolbar:

```
┌───────────────────────────────────────────────────────────────────────────────────────┐
│ [≡ Tree] novacam.upd ▸ reassembled ▸ rootfs ▸ [config.plain*] │ ▸ capture.pcapng  (+) │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

The trail is the active sheet's ancestry (click to activate; descendants
stay open), siblings drop down from each `▸`, other roots follow `│`, `*`
is unsaved, middle-click closes a subtree.

**Tree** (≡ Tree, Cmd+Shift+T, and a section of the Workspace tab):

```
 Worksheets
 ▾ novacam_2.0.3.upd                    412 KiB   file
   ▾ reassembled                 #1     401 KiB   documents.derive 6 ranges
     ▾ rootfs                    #3     188 KiB   unpack.open /rootfs
       ● config.plain*           #6       192 B   transform.apply xor $serial
       ○ plane 0                 #9      188 KiB  bits.open_plane
 ▾ capture.pcapng                        1.1 MiB  file
     ○ dns-chunks                #12       4 KiB  packets.extract 41 pkts
 [Show] [Compare with active] [Close] [Label…]
```

**Output toggle**, in the Selection menu, the XOR and Crypto rows and the
Decompress group:

```
 Transform selection ───────────────────────────
  Operation [XOR ▾]  Key [ NC500-2F357657 · $serial  ✕ ]  as [text ▾]
  Output    (•) In place   ( ) New worksheet [label: config.plain ]
  [Preview]                                            [Apply ⏎]
```

**Send to…** on a result row:

```
 Strings ─ rootfs (doc-3) ───────────────────────────────────────
  0x01A40  ascii  NC500-2F357657           serial   [Use as key]
                   ├ Send to ▸ ─┬ XOR tab · key
                   │             ├ Transform · key
                   │             ├ Search · needle
                   │             ├ Variable…            → $serial
                   │             └ New worksheet (bytes)
                   └ Copy value / Copy anchor
```

**Variables**, a footer in the History tab:

```
 Variables:  $serial = "NC500-2F357657" (#5)   $key = 65ffb335 (#14)   [+]
```

## 9. Phases

Each ends with the full tests passing. Acceptance runs a harness
(`theviewer-demo/ctf/check_all.sh`) that solves each challenge, saves a
recipe, replays it on the variant and compares the flag.

| Phase | What | Main files | Acceptance |
|---|---|---|---|
| 0 | Shared types, inert: `Lineage`, `MadeBy`, `DocumentInfo` fields, `JournalEntry.made`, `Outputs`, `Replay::MakesSheet` | `api/workspace.rs`, `api.rs`, `journal.rs`, `journal/timeline.rs` | tests pass |
| 1 | Lineage and recipe correctness, headless (R1–R4, R8) | `journal/{provenance,recipe,replay,anchors,timeline}.rs`, `api/{documents,codecs,history}.rs`, `api/tools/{bits,unpack,forensics}.rs`, replay flags | saved recipes keep every derive; replays pass the old failure points; a bad id fails instead of editing the input |
| 2 | Bindings and focus (R5, R6): call-time anchors, pick/then/var, `vars.*`, per-caller focus, `tree_doc`, MCP instructions | `api.rs` (`call_as`), `journal/anchors.rs`, new `api/vars.rs`, `api/workspace.rs`, `mcp/*` | firmware's recipe recovers the variant's flag through `$serial`; dns-exfil's key by `pick`; F4 passes without `doc` |
| 3 | The `output` parameter (R7): `output::deliver`, ported methods, `crypto.apply`, aliases | new `api/output.rs`, `api/{edits,codecs,documents}.rs`, `api/packet_sets*`, `api/tools/{bits,unpack,forensics,crypto}.rs`, `selection_ops.rs` | dns-exfil with no hex round trips, replaying on the variant |
| 4 | Worksheets in the window: parking, activate, close, Back keeps the child, strip and tree, per-sheet results, packet viewer's `source_sheet` | `app.rs`, `impl Workspace for ViewerApp`, `api/documents.rs` (window branch), `workbench.rs`, `panel_packets*.rs`, `legend.rs`, new `sheets.rs` | siblings, Back keeps the child, switching keeps the place, closing an unsaved child asks |
| 5 | Binding UI and the pipeline History: Carry, Send to…, Use as…, bound chips, Output toggles, Sheets view, variables, save warnings | new `send_to.rs`, `selection_menu.rs`, the Strings/XOR/Crypto/Bits/Checksums panels, `panel_history.rs`, `actions.rs` | firmware-update and radio-remote solved in the window alone, their recipes replaying on the variants |

Phase 0 merges first. Phases 1 and 4 can run in parallel (4 edits only
`impl Workspace for ViewerApp` in `workspace.rs`). Phases 2 and 3 can run
in parallel after 1. Phase 5 comes after 2, 3 and 4.

## 10. Alternatives considered

- **A fully multi-document window with split panes.** Right eventually,
  but every panel assumes `app.document`; parking reuses `ParentDocument`
  and gets most of the value. Split view can come later through *Compare
  with active*.
- **Separate methods per mode** (`transform.apply_new`): today's sprawl;
  one parameter is easier to learn and to describe.
- **Only step anchors, no pick or var:** paths into results
  (`job.strings[37].text`) are brittle and unreadable, and do not survive
  a different file.
- **Inferring bindings automatically** when a value equals an earlier
  result: kept as a suggestion (`history.suggest_anchors`), never a silent
  rewrite.
- **Explicit DAG edges in the recipe format:** steps plus sheet anchors
  already form the DAG, and `makes` labels keep it readable.
