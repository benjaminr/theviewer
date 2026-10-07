# History, playback and recipes: the plan

Status: phase 7 of `shared-knowledge-and-api.md` (§4). The foundation is
built; three areas build the rest in parallel, as briefed below.

Phase 6 made every action the person takes a method call. Phase 7 records
those calls in a **journal**, which gives history, undo across analysis
steps, playback, and recipes that run on other files.

## What the foundation built

### The journal (`src/journal.rs`)

- **One per session**, on the workspace: `Workspace::journal()` and
  `journal_mut()`, for the window (`ViewerApp::journal`) and
  `HeadlessWorkspace` alike.
- **Recorded in `api::call`**, `call_permitted` and `call_or_hold`
  (`run_journalled` in `src/api.rs`), so every caller is covered: panels,
  plugins, Ask, MCP clients, the command line and recipes
  (`Caller::Recipe(name)`, published as `recipe:<name>`).
  - **Edits, view changes and jobs** are entries, whether they succeed or
    fail. A failed one keeps its error as `outcome`. A call the caller's
    policy denies is recorded as refused. A call held for confirmation is
    recorded when it runs, not before.
  - **Reads** go into a ring of recent reads (256 by default). They take
    step numbers from the same sequence as entries, so the steps listed
    may skip numbers. `journal::promote(ws, step)` moves a read into the
    journal under its own number when a later step used its result.
  - **Not recorded:**
    - calls inside another call (a transaction's, or those a plugin method
      makes); the outer call is the step;
    - `history.*` reads;
    - unknown methods and failed reads;
    - the app's own work, which does not call the API.
  - **Merging.** Consecutive `selection.set`, `cursor.set` and
    `view.set_shape` calls by the same caller on the same document replace
    the last one. The kept entry counts them in `merged`.
- **Bounded** (`JournalLimits`):
  - 10,000 entries and about 64 MiB, beyond which the oldest are dropped
    and counted in `dropped {entries, through_step}`;
  - parameters over 1 MiB and results over 64 KiB are kept as a summary
    (`params_summarised`, `result_summarised`). The summary cuts strings
    at 1,024 characters and arrays at 32 items, and keeps every field, so
    ids survive. A step with summarised params cannot be repeated exactly.
- **Reading it:** `entries()`, `since(step)`, `entry(step)`, `reads()`,
  `read(step)`, `last_step()`, `revision()` (changes on every record,
  merge, promotion or drop) and `dropped()`.
- **Published** on the bus as `journal.recorded {step, method, caller,
  description, ok}`, about the step's document. A promotion is published
  too, with its earlier step number.
- **Session header** (`JournalSession`), from `history.session`:
  - `started_at` and `api_version`;
  - `documents`: each document a call was about, the first time
    (`{id, version, file: {name, size, sha256}}`), as it was before the
    call ran, and not hashed over 256 MiB. The hash is worked out on a
    thread of its own, so the call does not wait for it;
    `RecordedDocument::file()` waits for it when it is needed;
  - `plugins`: `[{name, sha256}]` of the scripts loaded. The window, `theviewer
    api`, and `theviewer mcp` note them on every load and reload
    (`LuaHost::script_digests`, `journal::plugins_of`).
- **Provenance in:** `api::call_derived(ws, caller, method, params,
  derived_from)` and `ViewerApp::perform_derived(method, params,
  derived_from)` attach `derived_from` (parameter path → anchor) to the
  call's entry. Provenance a call never took (an unknown method, a held
  call) is discarded.

A journal entry:

```json
{
  "step": 14,
  "at": "2026-10-06T14:02:11Z",
  "caller": "panel",
  "method": "packets.sets.create",
  "effect": "view",
  "description": "Split 4096 bytes at 0x100 into packets by a length field",
  "params": { "doc": "doc-1", "from": "length_field", "start": 256, "len": 4096 },
  "doc": "doc-1",
  "version_before": 412,
  "version_after": 412,
  "outcome": "ok",
  "result": { "set": "set-2", "frames": 61 },
  "derived_from": { "start": { "step": 12, "path": "result.matches[0].offset" } }
}
```

A failed entry has `"outcome": {"error": {"code": "out_of_range", "message":
"…"}}` and no `result`. `params_summarised`, `result_summarised` and
`merged` appear only when set. `JournalEntry::changed_document()` says
whether the bytes changed, and `Caller::from_producer(&entry.caller)`
gives back the `Caller`.

### Shared types (`src/journal/anchors.rs`, `recipe.rs`, `replay.rs`)

- **`Anchor`** is untagged. Each kind has its own required key:

  | Kind | JSON |
  | --- | --- |
  | `Step` | `{"step": 12, "path": "result.matches[0].offset"}` |
  | `Find` | `{"find": {"hex": "7EA5"} \| {"text": "PK"}, "nth": 0, "part"?: "offset" \| "len"}` |
  | `Structure` | `{"structure": "png", "field": "IHDR.width", "part"?: "offset" \| "len" \| "value"}` |
  | `Finding` | `{"finding": {"category"?: "compressed", "id"?: "zlib", "nth": 0}, "part"?: …}` |
  | `Selection` | `{"selection": "current", "part"?: …}` |
  | `Param` | `{"param": "key"}` |

  `part` defaults to the offset. For a selection it defaults to the
  selection itself.
- **Marking an anchor in a step's params.** Any value at any depth of a
  recipe step's `params` may be `{"$anchor": ANCHOR}`: an object with that
  one key. Everything else is a literal, so a literal object that looks
  like an anchor stays a literal. In `derived_from`, anchors are bare.
  - `ParamValue::{Literal, Anchor}` with `from_json` and `to_json`;
  - `marked(anchor)`, `as_anchor(value)` and `anchors_in(params)` (with
    paths);
  - `parse_path`, `value_at` and `replace_at` for paths such as
    `matches[0].offset`. A step anchor's path starts at its entry, so it
    begins with `result.` or `params.`.
- **`Anchor::resolve(&self, &mut ResolveContext) -> Result<Value,
  ApiError>`** is a stub that returns `unavailable`. `ResolveContext` holds
  the workspace, the run's document, the earlier steps of the run by
  number as `{"params", "result"}`, and the parameters given.
- **`Recipe`**, the `*.theviewer-recipe.json` file (`RECIPE_FORMAT` 1,
  `RECIPE_EXTENSION`):
  - `{recipe, api_version: "1.x", name, description, parameters: {name:
    {type, description, default?}}, recorded_on?: {name, size, sha256},
    plugins: [{name, sha256}], steps: [{step, method, params, note?}]}`;
  - each step keeps the number it was recorded as, which step anchors
    name;
  - `Recipe::from_journal(name, &session, entries)` makes literal steps of
    the successful entries in step order, with the session's plugins and
    the first step's document as `recorded_on`.
- **The replay entry point**, stubbed (it stops at the first step as
  `unavailable`):

  ```rust
  pub fn journal::replay::run(workspace: &mut dyn Workspace, steps: &[RecipeStep], options: &ReplayOptions) -> RunReport
  ```

  - `ReplayOptions {caller, parameters, doc, through_step, preview,
    checked_as}`, made by `ReplayOptions::new(caller)` (`checked_as` is
    whose policy each step is checked against, `None` when the person
    allowed the whole run);
  - `RunReport {steps: [StepReport {step, method, params, description,
    anchors: [{path, anchor, value}], outcome, result?, journal_step?}],
    stopped?: {step, error}, warnings}`, with `completed()`.

### Methods (`src/api/history.rs`, effect read)

- `history.list {since?, limit?, include_reads?}` returns `{entries, next,
  last_step, revision, dropped}`. Pass `next` back as `since`.
- `history.entry {step}` returns an entry, or a read still held.
- `history.session` returns the header.

`history.undo`, `history.redo` and `history.transaction` stay in
`src/api/edits.rs`.

### Also

- `documents.export` takes `ranges`, like `documents.derive`. The
  Selection menu's "Extract to file…" calls it through
  `save_dialog_then_call`, and `FileAction::SaveBytes` is gone.
- Empty modules are declared for each area, so no area edits a `mod` line
  or the method table:
  - `src/panel_history.rs` and `src/journal/timeline.rs` (A);
  - `src/recipes.rs` and `src/api/recipes.rs` (B);
  - `src/journal/provenance.rs` and `src/api/provenance.rs` (C).

## Area briefs

### Shared rules

- **Shared hubs.**
  - `src/journal.rs` is the foundation's. Don't edit it. Extend the
    journal from your own submodule: a child module may reach its private
    fields, and may add `impl Journal` blocks. If you truly need a change
    to the core, such as a new field, send it to the lead.
  - `src/api.rs`, `src/actions.rs`, `src/api/permissions.rs` and
    `src/api/workspace.rs`: don't edit them. Every module is already in
    the method table.
  - `src/journal/anchors.rs`, `recipe.rs` and `replay.rs` are B's after
    the foundation. Their types are shared: change them only by adding
    (new optional fields, new anchor kinds), and say so in your report.
  - `src/bus/topics.rs`: no new topics are expected.
  - `src/app.rs`, `src/dock.rs`, `src/commands.rs` and `src/main.rs`: only
    your own lines (a menu item, a dock tab, a palette command, the
    `replay` subcommand). New `ViewerApp` helpers go in `impl ViewerApp`
    blocks in your own files.
  - `docs/api.md`: regenerate it with `cargo run --bin api_docs` before
    each commit. Resolve conflicts in it by regenerating, never by hand.
- **Methods.** Each method has an example in its module's `examples()`, a
  `describe_call` line if it edits or changes the view, and tests.
  Methods that change only the journal or recipes have effect `read` if
  they change nothing the person sees in the document, and `view`
  otherwise.
- **Tests.** Name them by behaviour, in British English. Prove the API
  path with `take_performed()` and the journal (`ws.journal()`), and test
  headless and in the window.
- **Build** with your own target directory and debuginfo off
  (`CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
  CARGO_PROFILE_TEST_DEBUG=0 CARGO_TARGET_DIR=target-agents/p7<area>`).
  Make `cargo test` and `cargo clippy --all-targets` clean before each
  commit. Make no release builds. Commit messages are one line, with no
  trailers.

### A: The History tab, undo across steps, going back, playback

- **Your files:**
  - `src/panel_history.rs` (the tab);
  - `src/journal/timeline.rs` (inverses, going back, what happens to later
    steps);
  - `src/api/history.rs` (from now on, for new `history.*` methods such as
    `history.go_back {step}` and `history.undo_step {step}`);
  - your own lines in `src/dock.rs` (the History tab) and `src/app.rs`.
- **The tab:**
  - follows the journal through `since(last_seen)`, re-reading when
    `revision()` changes (a promotion inserts an earlier step);
  - shows each step's caller, description and outcome, marks steps that
    changed the document (`changed_document()`), and shows failed steps
    with their errors;
  - clicking a step shows the document and view as they were after it.
- **Undo of steps that change no bytes:** packet sets, "decode as",
  templates and similar undo through their inverse methods where one
  exists (removing the set, restoring the previous choice). Keep a table
  of inverses in `timeline.rs`. Byte edits undo as now
  (`history.undo`).
- **Going back to step N and playback** call `journal::replay::run` with
  the steps up to N (`ReplayOptions::through_step`), from the document as
  it was after N, or from the original file. The session header's
  `documents` say which file and hash that was. Steps made by replaying
  are recorded like any others. Decide in `timeline.rs` how the journal
  shows a branch: truncate, or mark the steps after N as undone.
- **"Save as recipe…" and "Run recipe…"** in the tab call B's functions;
  "Turn into anchor" and "Make a parameter" call C's.
- **Depends on:**
  - B's `replay::run` for going back and playback. Build the tab, undo
    through inverses and the controls first, and test going back once B
    has merged;
  - C's operations for the anchor buttons.

### B: Anchors, the runner, recipes on disk, `theviewer replay`, `recipes.*`

- **Your files:**
  - `src/journal/replay.rs`: implement `run`;
  - `src/journal/anchors.rs`: implement `Anchor::resolve`;
  - `src/journal/recipe.rs`;
  - `src/recipes.rs`: saving and loading in `~/.config/theviewer/recipes/`,
    listing, and plugin and version checks;
  - `src/api/recipes.rs`: `recipes.list`, `recipes.describe`,
    `recipes.run` and `recipes.save`;
  - the `replay` lines in `src/main.rs`:
    `theviewer replay RECIPE FILE… [--param key=value] [--save | --out
    DIR]`, writing a `RunReport` as JSON for each file.
- **The runner:**
  - resolves each step's `{"$anchor"}` values, recording them in
    `StepReport.anchors`;
  - calls the step through `api::call` as `options.caller`;
  - keeps `{params, result}` per step number for later step anchors;
  - waits for the jobs that steps start;
  - stops at the first failure or anchor that does not resolve, with
    `stopped`;
  - `preview` resolves and describes without calling;
  - warns about a missing or changed plugin, a different API major
    version, or another file than `recorded_on`;
  - undoes the run's edits as one step on failure, where the design asks
    for it.
- **Documents:** a step's `doc` that named the recorded document means
  the run's document (`options.doc`, or the current one). Decide this in
  the runner and document it in `recipe.rs`.
- **Permissions:** in the window, a recipe the person starts has its
  preview as its confirmation. Decide how its calls are allowed (a
  `ReplayOptions` field, say) and say so in your report. Headless, every
  call is allowed.
- **Depends on:** nothing to start. Test anchored recipes with
  hand-written `{"$anchor"}` values. C's capture is needed only for
  end-to-end tests of recorded recipes.

### C: Provenance while recording, and turning literals into anchors

- **Your files:**
  - `src/journal/provenance.rs`;
  - `src/api/provenance.rs`: methods in the `history` namespace, such as
    `history.set_anchor {step, path, anchor}` and
    `history.make_parameter {step, path, name}`;
  - the call sites that pass `derived_from`. A call site changes from
    `perform` to `perform_derived`, or from `api::call` to
    `api::call_derived`. These are the only lines you change in other
    areas' files.
- **Capture:**
  - where the app knows where a value came from (a split started from a
    search match, a template applied at a finding, a jump from an earlier
    result, a value read through the API and then used), pass
    `derived_from` with the anchor;
  - for a value from an earlier read, call `journal::promote(ws, step)`
    first and cite `Anchor::Step {step, path}`;
  - for clients (MCP, Ask, Lua), decide whether a call may carry
    provenance in band, and if so how, and document it.
- **Editing:** set or clear one parameter's anchor in an entry's
  `derived_from`. A named parameter is `Anchor::Param`, whose type and
  default the recipe takes from the literal.
- **The recipe with anchors:** add a function beside
  `Recipe::from_journal` (in `provenance.rs`, as an `impl Recipe` block or
  a free function) that replaces each literal at a `derived_from` path
  with `{"$anchor": …}`. It declares `parameters` for `Param` anchors and
  drops a `doc` that names the recorded document.
- **Depends on:** nothing to start. B resolves what you capture. Agree
  with B on any new anchor kind (by adding to `anchors.rs`, reported).

## Order and merging

1. The three areas start together.
2. B's `replay::run` and `Anchor::resolve` unblock A's going back and
   playback tests, and recorded-recipe tests end to end.
3. C's capture makes recipes from real sessions portable. A's buttons call
   C's operations once C has merged.

The only expected conflicts are:

- `docs/api.md`, which is regenerated;
- own lines in `src/app.rs` and `src/dock.rs`.
