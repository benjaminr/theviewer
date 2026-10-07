# Settings and files

- [Settings](#settings)
- [Where things are saved](#where-things-are-saved)
- [Adding your own formats, templates and plugins](#adding-your-own-formats-templates-and-plugins)

## Settings

Open **Settings** with `Cmd+,` or *File › Settings…*. It has four parts.

**When the viewer starts.** What a new window starts with:

- pattern highlights, and which kinds of pattern to show (hidden kinds are
  left out of the highlights and Findings);
- whether the findings list is open;
- whether to show values inside pixels when zoomed in;
- the width, and whether to detect it when a file opens;
- the pixel format, palette and zoom.

*Use this window's settings* takes the current window's choices as the
defaults, *Apply to this window* applies the defaults now, and *Reset* goes
back to the built-in ones. The toolbar and View menu change only the
window you are in; a file's own saved view and the command-line options
still take precedence.

**Wireshark (tshark).** *Use tshark when installed* decodes listed packets
with tshark as soon as they are read, and *tshark at* says where it is when
it is not found by itself. Under *Frames*, *Detect the protocol of split
frames* chooses whether new frame sets are decoded as the protocol they
look like. See [Packets](packets.md).

**Permissions.** What Ask, plugins and other clients may change. See [Who
may change the file](ask-and-permissions.md#who-may-change-the-file).

**Anthropic API key.** The key for Ask. See [Setting up a
key](ask-and-permissions.md#setting-up-a-key).

The Layout menu holds two more choices, kept with the settings: *When
theviewer opens* and *Suggest a layout for each file*. See [Layouts and
the workspace](layouts-and-workspace.md).

## Where things are saved

| File | Holds |
| --- | --- |
| `~/.config/theviewer/preferences.json` | Settings: startup defaults, tshark, permissions, the layout to open with |
| `~/.config/theviewer/credentials` | API key (not on macOS, which uses the Keychain) |
| `~/.config/theviewer/layout.json` | Panel arrangement as the last session left it |
| `~/.config/theviewer/layouts/` | Layouts you saved by name |
| `~/.config/theviewer/toolbar.json` | Toolbar order, if you rearranged it |
| `~/.config/theviewer/recipes/` | Your recipes |
| `~/.config/theviewer/reference/` | Your own reference notes |
| `~/.config/theviewer/catalog/` | Your own file signatures, including those Learn saved |
| `~/.config/theviewer/templates/` | Your own templates |
| `~/.config/theviewer/plugins/` | Your Lua plugins |
| `~/.cache/theviewer/rfc/` | RFC text fetched for the Reference tab |
| `~/.cache/theviewer/wireshark/` | tshark's protocol and field names, kept by `check_reference` |
| `FILE.theviewer.toml` beside each file, such as `firmware.bin.theviewer.toml` | Bookmarks and the view settings for that file |

Nothing in `~/.cache/theviewer/` is needed: delete it and it is fetched
again when asked for.

## Adding your own formats, templates and plugins

Everything that recognises, parses or decodes bytes is a plugin, and the
built-in ones use the same interfaces as yours.

- **Signatures:** add TOML files to `~/.config/theviewer/catalog/`, in the
  form used by `catalog/curated.toml`: offsets, masks, nested conditions
  and length rules. [Learn](finding-structure.md#learn-a-new-format) can
  write one for you.
- **Templates:** describe structures in the template language; see
  [docs/templates.md](../templates.md).
- **Reference notes:** see [Your own notes](reference-notes.md#your-own-notes).
- **Lua plugins:** scripts add detectors, parsers, codecs and actions
  through a small sandboxed API. They can call every method of the data
  API, react to what other tools publish and publish what they learn, and
  register methods of their own that Ask, the command line and MCP clients
  can call. Put them in `~/.config/theviewer/plugins/` (or `plugins/` in the
  working directory); *View › Reload plugins* picks up changes. An error in
  a plugin, even in a background scan, is shown in the status bar, and the
  lines a plugin logs appear in the Workspace tab's log of recent events. See
  [docs/plugins.md](../plugins.md) and the examples in `plugins/`.
- **Rust:** implement `Detector`, `Parser` or `CodecPlugin` from
  `src/plugin.rs` and register it in the `Registry`.
