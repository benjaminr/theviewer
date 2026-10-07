# History and recipes

Every step you take is recorded: by hand, through Ask, a plugin or an MCP
client. The **History** tab shows those steps. Undo any one of them, go
back to an earlier point, watch them played again, or save them as a
**recipe** to run on the next file.

- [The History tab](#the-history-tab)
- [Undoing a step and going back](#undoing-a-step-and-going-back)
- [Playing steps back](#playing-steps-back)
- [Recipes](#recipes)
- [Recipe values: anchors and parameters](#recipe-values-anchors-and-parameters)
- [Saving a recipe](#saving-a-recipe)
- [Running a recipe in the window](#running-a-recipe-in-the-window)
- [Running a recipe over many files](#running-a-recipe-over-many-files)

## The History tab

Open it from *Tools › History*, the palette, or the *Overview* layout,
where it sits beside the Report.

Each edit, view change, packet set and job is a numbered step, with who
took it and what
it did, in words: "Overwrite 2 bytes at 0x2 with 41 42". Marks beside a
step say more:

- **bytes:** it changed the document's bytes;
- **failed** or **refused:** it did not happen (point at the mark for why);
- **×3:** several moves in a row, kept as one step;
- **undone by …:** a later step undid it; the text is struck through.

Who took a step is shown as `panel` for you, `ask`, `plugin:NAME`,
`mcp:CLIENT`, `cli` for `theviewer api`, or `recipe:NAME` for a recipe's
run.

The caller menu shows one caller's steps only, and *Show undone* hides or
shows the steps that were undone.

Click a step for its details: its parameters, its result, and how it would
be undone. *Show bytes* selects the bytes it touched.

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
- a **parameter** you give each time you run it, such as a key.

Many anchors are recorded for you as you work. A selection made with *Find
next* or *All matches* remembers which match it was; selecting a finding
remembers the finding; clicking a structure field remembers its path; and
packets taken from the selection remember the selection.

For the rest, open a step's **Recipe values** (in its details, or
*Recipe values…* in its menu). It lists each value a recipe would repeat:

- **Use …** turns the value into one of the anchors offered for it, such
  as *Use the 2nd match of …* or *Use where png field IHDR.width starts*;
- **Make a parameter** turns it into a parameter, under the name typed in
  *Parameter name*;
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
along the history, and steps that only opened or saved files are left out.

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
applies: the confirmation window lists the recipe's steps, and each step is
still checked against that client's setting.

## Running a recipe over many files

From the command line:

```sh
theviewer replay "Telemetry frames" capture-*.bin --param key=5a --out decoded/ --json
```

Each file opens in a workspace of its own, and you get a report per file:
what each step did, or where and why it stopped. With `--json` the report
is JSON. With `--save` each changed file is saved over itself, and with
`--out DIR` into DIR. A file the recipe stopped on is not saved, and the
exit code is then non-zero. See [Command line](command-line.md#theviewer-replay)
and [docs/recipes.md](../recipes.md).
