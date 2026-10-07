# Ask Claude, and who may change the file

*Ask* answers questions about the file in front of you, and can make
changes when you ask it to. Plugins and other programs can do the same
through the data API. This page covers setting Ask up and deciding what
each of them may change.

- [Asking about a file](#asking-about-a-file)
- [Setting up a key](#setting-up-a-key)
- [Who may change the file](#who-may-change-the-file)
- [The confirmation window](#the-confirmation-window)
- [The command line and MCP](#the-command-line-and-mcp)

## Asking about a file

Press `Cmd+L` (or *Tools › Ask about this file…*) and ask a question such
as "what format is this?" or "which field is the length?". Right-click a
byte for *Analyse › Ask about this…*.

Claude (`claude-opus-5-5`) sees the cursor, the selection, nearby findings
and the bytes around them, and the [reference notes](reference-notes.md)
on the formats at the cursor. It can read, search and parse more of the
file itself, and use the same methods the tools use: the file overview,
segmentation, statistics, compressibility, text encoding, processor
detection, any format's reference notes (by name or by port) and the
methods your plugins add.

- Offsets in its answers are links that move the cursor.
- Templates it writes can be applied with one click.
- *Characterise with Ask* (in the Tools menu) asks it to work through the
  analysis tools and describe the whole file.

When you ask it to change something ("XOR the selection with 5A", "fix the
length field"), it can edit too, with the same operations you have. Each
change waits for you to allow it (see below), is one undo step, and is
labelled in the Edit menu as Ask's, such as *Undo XOR by ask*.

## Setting up a key

Ask is off until you add an Anthropic API key in **Settings** (`Cmd+,`),
under *Anthropic API key*. *Save key* stores it, *Test key* checks it, and
*Remove key* forgets it.

- On macOS the key is kept in your Keychain.
- Elsewhere it is kept in `~/.config/theviewer/credentials`, readable only
  by you.
- The `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` environment variables,
  or an `ant auth login` session, also work.

Nothing is sent anywhere unless you ask a question. Then Claude is sent
the question, a snapshot around the cursor, and the bytes it chooses to
read.

## Who may change the file

You edit freely. Plugins, Ask and other clients of the data API can always
read, but what they may change is up to you.

**Settings › Permissions** lists each one: Ask, every plugin that declared
it edits, and any client that has asked before. Each has three choices:

| Choice | Means |
| --- | --- |
| *Always allow* | It edits and changes the view without asking. |
| *Always ask* | A window asks you about each change. This is the default, and a client not seen before is asked about. |
| *Never allow* | It may not edit or change the view; reading is still allowed. |

Every change a client makes is one undo step, labelled with what it did
and who did it ("Overwrite 4 bytes by plugin:acme_telemetry.lua"), so
*Undo* always takes it back, and the [History tab](history-and-recipes.md)
lists it. A client can also say which version of the file it expects, so a
change based on bytes that have changed since is refused instead of
applied.

## The confirmation window

When a client set to ask wants to change the document or the selection, a
window titled *Allow this change?* says who it is and what the change is,
in plain words: "Ask wants to change the document: XOR 128 selected bytes
with 5A", or "Overwrite 4 bytes at 0x40 with DE AD BE EF".

- **Allow once** makes the change.
- **Always allow this client** makes it and stops asking (change this
  later under Settings › Permissions).
- **Deny** refuses it, and the client is told.

Nothing waits on the window: you can keep working. A request nobody
answers is refused after two minutes. Several requests are answered in
the order they came. For a recipe run, the window lists the recipe's steps.

## The command line and MCP

On the command line (`theviewer api`, `theviewer replay`) and through the
MCP server (`theviewer mcp`), every call is allowed without asking: the
files are the ones you named. See [Command line](command-line.md) and
[docs/mcp.md](../mcp.md).
