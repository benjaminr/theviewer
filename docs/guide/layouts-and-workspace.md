# Layouts and the workspace

Arrange the panels the way your work needs, start from a layout made for
the kind of file in front of you, and see what the tools have worked out
between them.

- [Arranging panels](#arranging-panels)
- [Recommended layouts](#recommended-layouts)
- [Your own layouts](#your-own-layouts)
- [What opens at start](#what-opens-at-start)
- [The toolbar](#the-toolbar)
- [What the tools share](#what-the-tools-share)
- [The Workspace tab](#the-workspace-tab)

## Arranging panels

Every panel can be moved:

- **Split or stack:** drag a panel's tab to the edge of another panel to
  put it beside that one, or onto its tab bar to stack it there.
- **Float:** drag it out of the window.
- **Collapse or close:** the arrow collapses a panel and the cross closes
  it. *View › Panels* brings a closed panel back. Only the **Bits** view
  cannot be closed.
- **Fold the tools away:** `Cmd+J` (*View › Collapse or expand tools*)
  folds all the tools away and back.

Panels with many tabs wrap them onto extra rows.

## Recommended layouts

The **Layout** menu has a recommended layout for each kind of analysis.
Each one opens only the tools that work needs, so the tab bars stay short;
any other tool is still in *Tools* and *View › Panels*. Each is also in the
command palette, as *Layout: Overview* and so on.

| Layout | `--layout` | Opens with |
| --- | --- | --- |
| Overview | `overview` | Report, Reference, Structure map, Size map, Strings, Statistics, Characterise, Ask and History under the view; Inspector, Findings and Hex beside it |
| Network capture | `network` | Packets in front; Protocol, Strings, Statistics, Live and Ask below; Reference, Inspector and Findings beside, with Hex |
| File structure | `structure` | Template, Structure map, Columns, Unpacked, Learn and Report below; Inspector, Reference and Findings beside, with Hex |
| Firmware and code | `firmware` | Firmware, Disassembly, Strings, Crypto, Unpacked, Images, Checksums and Ask below; Inspector, Findings and Reference beside, with Hex |
| Signals and bit streams | `signals` | Bits, the period chart, Columns, Trigrams, Dot plot, Statistics, XOR and Live below; Hex, Inspector and Findings beside |
| Forensics and carving | `forensics` | Forensics, Images, Unpacked, Strings, Size map and Report below; Findings (in front) and Inspector beside, with Hex |
| Compare files | `compare` | Compare, Diff and Statistics below; Hex, Inspector and Findings beside |
| Focus on the view | `focus` | Just the view, the hex and the inspector |

Every layout keeps the **Bits** view with **Packets** beside it. The
*Network capture* layout also loads the first capture in the file into
Packets.

**Suggestions.** When a file opens as a capture, an executable, a disk
image or another known format, the status bar offers the layout made for
it; **Switch** opens it and **Dismiss** keeps yours. *Layout › Suggest a
layout for each file* turns the offers off.

## Your own layouts

Arrange the panels, type a name under **Yours** in the Layout menu and
press **Save** (**Replace** if a layout of that name exists). Each saved layout has:

- **Update:** replace it with the current arrangement;
- **Rename;**
- **Delete:** press it twice.

Saved layouts are JSON files in `~/.config/theviewer/layouts/`. Open one
from the command line with `--layout "Its name"`; a name that matches no
layout opens the Overview instead and says so in the status bar.

**Last session** brings back the arrangement as it was when theviewer last
closed; so does *Layout: Restore last session* in the command palette.

## What opens at start

*Layout › When theviewer opens* chooses what a new window starts with: the
last session (the default), a recommended layout, or one of yours.
`--layout NAME` starts with a layout for that session only, and leaves the
last session's arrangement as it was.

## The toolbar

The toolbar's groups (*Format*, *Width*, *Origin*, *Zoom*, *Go to*, *Find*,
*Insert at cursor*, *Byte at cursor* and so on) pack themselves into as few
rows as the window allows. Drag a group by its caption to change their
order (drop it below the last row to move it to the end); the groups still
fill each row before starting the next. *Layout › Arrange toolbar
automatically* goes back to the automatic order.

## What the tools share

Tools publish what they learn on a shared workspace bus, so others can use
it without being on screen:

- the scan's findings, and findings pinned by tools, plugins, Ask and
  other clients;
- the structure at the cursor, and any template applied;
- the report's regions, and the record width the period scan found;
- frames from the Protocol tool or Packets, and the protocol they turn out
  to be (detected, guessed from a port, or named by tshark);
- background jobs starting, progressing and finishing;
- plugin log lines;
- every edit, cursor move and selection.

So *Columns* takes its record length from the published width; *Packets*
follows the selection and takes the Protocol tool's messages and field
guesses; *Align messages*, at the foot of the Protocol tab, takes the same
messages; *Reference* reads the layers
of the packet chosen in Packets; and the views colour by the report's
regions and outline any template applied. All of this works even while
the tools are hidden.

Background jobs (scans, the report, unpacking, protocol analysis,
dissection, tshark and more) each have an id, report their progress and
can be cancelled from a plugin or a client as well as from their tool.

## The Workspace tab

The **Workspace** tab (open it from *View › Panels* or the command palette)
lists what is known, by topic and by whom. Facts
that describe the file before its last edit are dimmed; what an edit did
not touch moves with it instead. Click a span to select those bytes, and
*why* to see what led to a fact. Below is a log of recent events, filtered
by topic.

Plugins and clients of the data API read the same facts and events with
`events.facts` and `events.poll`; see [docs/api.md](../api.md).
