# theviewer user guide

The [README](../../README.md) gives a quick tour. These pages cover each
part of theviewer in full. Shortcuts are written with `Cmd`, as on macOS;
use `Ctrl` on Linux and Windows.

| Page | What it covers |
| --- | --- |
| [Worksheets](worksheets.md) | Files and the sheets made from them open side by side: the worksheet strip, Back, the tree of sheets, closing, labels, and what the tools keep for each sheet |
| [Viewing and editing](viewing-and-editing.md) | Pixel formats, width, origin and zoom, curve layouts, the legend, hex and inspector, selections, the byte operations, skipping bytes, compressed streams and media, undo and saving |
| [Finding structure](finding-structure.md) | Detecting the record width, Findings, Report, Structure map, Columns, Templates, Learn and the signature catalogue |
| [Packets](packets.md) | The packet viewer: captures, splitting frames, dissection, *Decode frames as*, filters with Wireshark names, grids, editing, conversations and streams, tshark, export |
| [Reference notes](reference-notes.md) | The Reference tab, RFC sections, guesses from the port, browsing, Wireshark names, your own notes, checking citations |
| [The tools](tools.md) | Every tool tab, in a short section each |
| [Layouts and the workspace](layouts-and-workspace.md) | Arranging panels, recommended and saved layouts, the toolbar, what the tools share, the Workspace tab |
| [History and recipes](history-and-recipes.md) | The History tab, undoing a step, going back, playback, anchors and parameters, saving and running recipes |
| [Ask Claude, and who may change the file](ask-and-permissions.md) | Ask, its key, permissions for Ask, plugins and clients, the confirmation window |
| [Command line](command-line.md) | Window options, `--report` and `--json`, `theviewer api`, `theviewer mcp`, `theviewer replay` |
| [Settings and files](settings-and-files.md) | Every setting, where things are saved, adding your own formats, templates and plugins |

For people building on theviewer:

- [docs/api.md](../api.md): every method of the data API.
- [docs/plugins.md](../plugins.md): writing Lua plugins.
- [docs/templates.md](../templates.md): the template language.
- [docs/mcp.md](../mcp.md): using theviewer from Claude Code and other MCP
  clients.
- [docs/recipes.md](../recipes.md): the recipe file format, anchors and
  `theviewer replay`.
- [docs/development.md](../development.md): building, testing and how the
  code is organised.
