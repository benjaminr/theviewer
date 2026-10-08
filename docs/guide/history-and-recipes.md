# History and recipes

Every step you take is recorded: by hand, through Ask, a plugin or an MCP
client. The **History** tab shows those steps. Undo any one of them, go
back to an earlier point, watch them played again, or save them as a
**recipe** to run on the next file.

- [The History tab](#the-history-tab)
- [Notes](#notes)
- [Undoing a step and going back](#undoing-a-step-and-going-back)
- [Playing steps back](#playing-steps-back)
- [Recipes](#recipes)
- [Recipe values: anchors and parameters](#recipe-values-anchors-and-parameters)
- [Saving a recipe](#saving-a-recipe)
- [Running a recipe in the window](#running-a-recipe-in-the-window)
- [Running a recipe over many files](#running-a-recipe-over-many-files)

## The History tab

Open it from the *History* item in the Tools menu, the palette, or the
*Overview* layout, where it sits beside the Report.

Each edit, view change, packet set and job is a numbered step, with who
took it and what it did, in words: "Overwrite 2 bytes at 0x2 with 41 42".
Marks beside a step say more:

- **bytes:** it changed the document's bytes;
- **failed** or **refused:** it did not happen (point at the mark for why);
- **×3:** several moves in a row, kept as one step;
- **undone by …:** a later step undid it; the text is struck through;
- **evidence:** a read kept only because a note cites it, dimmed (see
  [Notes](#notes)).

A step is described in plain words, its sheets by their labels and its
packet sets by their names, rather than by ids such as `doc-2` and `set-1`.

Who took a step is shown as `panel` for you, `ask`, `plugin:NAME`,
`mcp:CLIENT`, `cli` for `theviewer api`, or `recipe:NAME` for a recipe's
run.

The caller menu shows one caller's steps only (*every caller* shows them
all), *Show undone* hides or shows the steps that were undone, and *Notes
only* shows just the notes.

Click a step for its details: its parameters, its result, and how it would
be undone. *Show bytes* selects the bytes it touched.

## Notes

Write down what you are doing and why as you go. A **note** goes into the
history where you are, among the steps, so the reasoning sits beside the
actions it explains.

- Type it in the box at the foot of the History tab ("Note what you're
  doing and why…") and press **Add note** or `Cmd+Enter`.
- **Note** on a step (or *Write a note about it* in its menu) starts a note
  with `#12 `, linking it to that step.
- `#12` anywhere in a note links it to step 12. The steps must be in the
  history; a note about something missing is refused, and its text stays in
  the box. To write a number that is not a step, such as packet 917, put a
  backslash before it: `\#917` reads "#917" and links nothing.
- The menu beside **Add note** says what kind of note it is: an
  **observation** (what a step showed, and the choice unless you pick
  another), a **hypothesis**, a **decision**, a **fallback** (a gap the
  tools could not fill, worked round with a literal, a plugin or work done
  elsewhere) or a **conclusion**. Clients pass `kind` to `history.note`.

**Evidence.** A note can cite a read, such as the overview or a search,
that no step used. That read is kept in the history as **evidence**,
dimmed and tagged, so the note's link still works, but it is not a step of
the analysis: recipes leave it out, and undoing a sheet the read looked at
does not stop the recipe being saved. A read whose value a later step uses
through an anchor is a step of the recipe as before.

A note is shown as a card with a different background: who wrote it, the
time, its kind, then the text, in which each `#12` is a link. Click it to scroll to
step 12 and highlight it (the filters are cleared if they hide it). A step
with notes about it shows a *note 14* link back to each.

A note changes nothing. It is never undone, *Go back to here* and playback
pass over it, and it is not a step of a recipe. *Edit* and *Delete* on its
card change it or take it out; an edited note is marked *edited*, with
when and by whom. Editing and deleting are not steps of their own.

Ask, plugins and MCP clients write notes too, through `history.note`, and
they are shown as theirs (`mcp:claude-code`). The MCP server asks a model
to note its reasoning as it works, so you can follow what it was thinking.

**Notes in recipes.** Saving the history as a recipe puts each note into
the `note` of the first recipe step it is linked to, with its `#12`s
renumbered as the recipe numbers the steps, and the other steps it is
linked to say "See the note on step 3." Each starts "As recorded on
capture.bin:", so a run on another file does not present the values the
note quotes as that file's. A note about evidence alone goes on the next
step of the recipe; a note linked to no step of the recipe is otherwise
left out.

**Exporting.** *Export notes…* saves the notes as Markdown: a title naming
the file the session started from, the sheets made by their labels and
when the session started, then each note in the order written, with its
kind and the steps it cites. Each cited step says what it did in plain
words, where its values came from (the anchors, such as "the 1st match of
hex 7EA5"), what it returned in a few words, and whether it is evidence.
The notes end with a list of every fallback. `history.export_notes` gives
the same text to clients.

The history, notes included, lasts as long as the session: it is not saved
when you quit. Export the notes to keep them.

## Undoing a step and going back

Right-click a step, or use the buttons in its details:

- **Undo this step** undoes that one step, even when it is not the last.
  A byte edit undoes as the document's own undo does, so only while it is
  the document's last edit. A step that changed no bytes (a packet set, a
  *Decode frames as* choice, a template, a view change) undoes through its
  inverse, so only while no later step changed the same thing.
- **Go back to here** undoes every step after this one. Those steps stay in
  the list, shown as undone, and are left out of recipes and playback.
  Steps you take afterwards follow on from here.

When a later step cannot be undone directly, going back replays instead:
the document is brought back to how the session first saw it, and the
steps up to here are run again. The result is the same, and the edits run
again make one undo step of the document.

Undoing is all or nothing. If one of the undos fails part-way, what was
undone so far is put back, so the document still matches the list.

`Cmd+Z` and `Shift+Cmd+Z` still undo and redo the document's last edit,
and the History tab marks those steps too.

## Playing steps back

*Play steps … to …* replays a range of steps as you watch. *▶ Play* goes
back to before the first step of the range, then runs each step again.
Choose the speed: one step at a time (press *Next step*), or a step a
second, two a second or six a second, with *Pause* and *Resume*. *Stop*
ends playback where it is. *Play from here* in a step's menu starts the
range at that step.

The line under the controls names the next step, or says where and why
playback stopped.

## Recipes

A **recipe** is a saved run of steps, kept as a
`*.theviewer-recipe.json` file. It lets you repeat an analysis on the next
file: open the capture, split it on the sync word, decode the frames as
the right protocol, XOR the payload with the key, save.

Recipes you keep are in `~/.config/theviewer/recipes/`. A recipe is a
plain file, so you can share it with others. The file format, every kind
of anchor and the details of `theviewer replay` are in
[docs/recipes.md](../recipes.md).

A recipe names the API version and the plugins it was recorded with.
Running it warns you if a plugin is missing or has changed, if a method is
unknown, or if the file is not the one it was recorded on.

## Recipe values: anchors and parameters

An offset that suits one file is wrong for the next. So a value in a
recipe step can be an **anchor**, found when the step runs:

- the nth match of some bytes or text;
- a field of a parsed structure, such as the `IHDR.width` of a PNG;
- the nth finding of a kind, such as the first compressed stream;
- whatever is selected when the recipe runs;
- a value an earlier step was given or returned;
- an item picked from a list an earlier step returned by what it holds,
  such as the first string that looks like a serial, or the best XOR key
  of at most 8 bytes;
- another anchor's value worked on: an offset plus a header's length, a
  sector number times 512, a serial written as hex for a key;
- a **variable**, a value bound by name with `vars.set`;
- a **parameter** you give each time you run it, such as a key.

Clients (Ask, plugins, MCP clients) pass anchors in place of values as
they call, such as `{"$sheet": 7}` for the sheet step 7 made or
`{"$var": "serial"}`, and the history keeps both the value and the anchor.
A variable keeps where its value came from, so in a recipe the step that
bound it finds it again on the next file.

Many anchors are recorded for you as you work. A selection made with *Find
next* or *All matches* remembers which match it was; selecting a finding
remembers the finding; clicking a structure field remembers its path; and
packets taken from the selection remember the selection.

For the rest, open a step's **Recipe values** (in its details, or
*Recipe values…* in its menu). It lists each value a recipe would repeat:

- **Use …** turns the value into one of the anchors offered for it, such
  as *Use the 2nd match of …* or *Use where png field IHDR.width starts*;
- **Make a parameter** turns it into a parameter, under the name typed in
  *Parameter name*; a value an anchor found keeps that anchor as the
  parameter's default, so the recipe finds it unless you give one;
- **Clear anchor** turns it back into the value as recorded.

## Saving a recipe

In the History tab, type a name in *Recipe name* (it is *My analysis* if
you leave it empty), then:

- **Save to my recipes** keeps the steps in effect among your recipes, to
  run from *Run recipe…*;
- **Save as recipe…** saves them as a file wherever you choose;
- **Save up to here as recipe…**, in a step's menu, saves only the steps up
  to that one.

Only the steps in effect are saved: undone, failed and refused steps, moves
along the history, notes, and steps that opened a file or saved one are
left out. The notes linked to a step become its note in the recipe (see
[Notes](#notes)).

**Sheets.** A step that makes a new document from another, a **sheet**
(opening the selection as a document, decompressing a stream, opening an
unpacked file, decoding a line code, or any call through the API whose
`output` was `"new"`), is kept. The steps after it that work on the sheet
name it by the step that made it, or by its label (the one the call gave
it, or one given with *Label…* in the [tree of sheets](worksheets.md#the-tree-of-sheets)),
not by its id in this session, so on the next file they work on the sheet made
there, not on the file itself. Each step is saved on the document it
actually ran on, and the recipe's file is the one its sheets all came from.

If a step would not replay, nothing is saved and the History tab says
which step and why: a step on a second file you opened, or on a sheet made
by a step that was undone or by a panel outside the history. Save the
steps up to before it (*Save up to here as recipe…*), or redo the work
through steps the history records.

## Running a recipe in the window

*File › Run recipe…* (also in the palette and the History tab) lists your
recipes:

1. Pick the recipe and fill in its parameters.
2. Press **Preview**. It shows each step on this file and where its
   anchors landed, and changes nothing. If a step would fail, it says where
   the run would stop.
3. Press **Run**, which is enabled once the preview shows every step can
   run. It does every step without asking about each one, because you have
   seen the preview.

One *Undo* takes all of a run's edits back, as "Recipe steps by
recipe:NAME".

Ask, plugins and MCP clients run recipes through `recipes.run`. That is an
edit, so [Settings › Permissions](ask-and-permissions.md#who-may-change-the-file)
applies to the client that starts the run:

- **Always ask:** the confirmation window lists the recipe's steps. If you
  allow the run (*Allow once* or *Always allow this client*), the whole run
  is allowed and you are not asked about its steps.
- **Always allow:** the run starts without asking, and each step is
  checked against that client's setting as it runs, so a recipe can do no
  more than the client could.
- **Never allow:** the run is refused.

## Running a recipe over many files

From the command line:

```sh
theviewer replay "Telemetry frames" capture-*.bin --param key=5a --out decoded/ --json
```

Each file opens in a workspace of its own, and you get a report per file:
what each step did, or where and why it stopped. With `--json` the report
is JSON. Without `--save` or `--out`, no file is changed.

- `--save` saves each file the recipe changed over itself; a file it left
  unchanged is not written.
- `--out DIR` saves every file the recipe ran to its end into DIR, under
  its own name, changed or not, and makes DIR if needed.

A file the recipe stopped on is not saved. The exit code is non-zero when
the recipe stopped on any file, or a file could not be opened or saved.
`--param KEY=VALUE` gives a parameter, and can be repeated.

- `--save-sheets DIR` saves each sheet the recipe made, such as an
  unpacked file or a decoded stream, into DIR.
- `--allow-writes` lets steps that write files run. Without it, a recipe
  that would write one (perhaps one someone sent you) stops there.
- `--plugins DIR` loads plugins from DIR instead of the usual places. See
[Command line](command-line.md#theviewer-replay) and
[docs/recipes.md](../recipes.md).
