# theviewer data API, version 1.0

<!-- Generated from the method table in src/api.rs by `cargo run --bin api_docs`. Do not edit by hand. -->

Every method can be called from the command line (`theviewer api METHOD '{json params}' FILE`), Lua plugins call them as `theviewer.api.<namespace>.<method>{…}`, Ask uses the methods that read or edit as its tools, and `theviewer mcp FILE…` offers every method to MCP clients such as Claude Code as a tool named with underscores for dots (`bytes_read`), with resources for each document (`theviewer://doc/{id}`, its `bytes/{start}-{end}`, `findings` and `facts`) and the reference notes (`theviewer://reference/{id}`). Documents are named by id (`doc-1`), by path or as `"current"`, which an omitted `doc` also means. Spans are `start` and `len` in bytes; an omitted `len` runs to the end of the document. Bytes are hex strings unless `encoding` says `base64` or `text`. List methods take `limit` and return `next`, a cursor to pass back for the next page. One call reads or returns at most 16 MiB.

Methods whose effect is `edit` change the document. Each call is one undo step, labelled with what it did and who called it ("XOR by mcp:claude-code"), and published on `document.edited` as the caller's. Any edit takes `expect_version`: when the document has changed since, the call fails with `version_conflict` and changes nothing. `history.transaction` runs several calls as one step and reverses them all when one fails. In the app, an edit or view change from a plugin, Ask or another client is checked against that client's setting under Settings › Permissions (always allow, always ask, never allow; a new client is asked about): when it asks, a window shows the change for the person to allow once, always allow or deny. On the command line and through `theviewer mcp` every call is allowed: the files are the ones the person named. Methods plugins register join the table at run time; `api.describe` lists them as experimental.

Errors are `{code, message, data}`, with these codes:

| Code | Meaning |
| --- | --- |
| `invalid_params` | The parameters don't match the schema |
| `out_of_range` | A span falls outside the document |
| `not_found` | No such document, method or entry |
| `version_conflict` | The document changed since `expect_version` |
| `read_only` | The caller may not edit |
| `too_large` | Over the per-call limit |
| `cancelled` | A job was cancelled |
| `plugin_failed` | A plugin raised an error or used up its budget |
| `unavailable` | Something needed is missing, such as tshark |

## Methods

| Method | Effect | Summary |
| --- | --- | --- |
| [`api.version`](#apiversion) | read | The API version: 1.0. Changes within a major version only add methods, optional parameters and result fields. |
| [`api.describe`](#apidescribe) | read | Every method with its summary, effect, stability and the JSON schemas of its parameters and result. |
| [`documents.list`](#documentslist) | read | The open documents, with their ids, names, paths, lengths and versions. |
| [`documents.info`](#documentsinfo) | read | One document's id, name, path, length, version and whether it has unsaved edits. |
| [`documents.open`](#documentsopen) | view | Open a file by path and make it the current document; a file already open is made current again. |
| [`documents.new`](#documentsnew) | view | Open a new, empty document and make it current; the window refuses while its document has unsaved edits. |
| [`documents.save`](#documentssave) | edit | Save a document over its file, or to a path, with every edit made so far. |
| [`bytes.read`](#bytesread) | read | Read a span of bytes, as hex by default, or as base64 or text. |
| [`bytes.hexdump`](#byteshexdump) | read | A classic hex dump of a span, 16 bytes per line with an ASCII column, at most 1 MiB. |
| [`bytes.write`](#byteswrite) | edit | Overwrite bytes in place with new ones, as one undoable step; the document keeps its length. |
| [`bytes.insert`](#bytesinsert) | edit | Insert bytes at an offset, as one undoable step; the bytes after it move along. |
| [`bytes.delete`](#bytesdelete) | edit | Remove a span of bytes, as one undoable step; the bytes after it move back. |
| [`bytes.replace`](#bytesreplace) | edit | Replace a span of bytes with new bytes of any length, as one undoable step. |
| [`bits.read`](#bitsread) | read | Read a span of bits, most or least significant bit of each byte first, as a string of 0s and 1s and, up to 64 bits, as a number. |
| [`bits.write`](#bitswrite) | edit | Overwrite bits from any bit offset, most or least significant bit of each byte first, as one undoable step; the bits around them are kept. |
| [`transform.apply`](#transformapply) | edit | Apply an operation (XOR, invert, shift bits, swap byte order, number, compress, decompress and more) to every range of a selection, as one undoable step, and select what it produced. |
| [`transform.preview`](#transformpreview) | read | What transform.apply would write into each range of a selection, without changing anything. |
| [`history.undo`](#historyundo) | edit | Undo the document's last step, whoever made it, and put the cursor where it was. |
| [`history.redo`](#historyredo) | edit | Redo the last step undone, and put the cursor where it was. |
| [`history.transaction`](#historytransaction) | edit | Run several calls on one document as one undoable step; when one fails, every change the others made is reversed. |
| [`search.find`](#searchfind) | read | The next (or previous) occurrence of hex bytes, text, UTF-16 text or an integer from an offset. |
| [`search.find_all`](#searchfind_all) | read | Every occurrence of hex bytes, text, UTF-16 text or an integer in the document, a page at a time. |
| [`search.count`](#searchcount) | read | How many times hex bytes, text, UTF-16 text or an integer occur in the document, up to a cap. |
| [`numbers.decode`](#numbersdecode) | read | Read the bytes at an offset as integers, floats, fixed-point numbers and timestamps of each width and byte order. |
| [`selection.get`](#selectionget) | read | What is selected in a document: one range, several ranges or a column of every record. |
| [`cursor.get`](#cursorget) | read | The cursor's offset in a document. |
| [`selection.set`](#selectionset) | view | Select one range, several ranges or a column of every record in a document, or nothing. |
| [`cursor.set`](#cursorset) | view | Move the cursor to an offset, selecting nothing. |
| [`findings.query`](#findingsquery) | read | Run the detectors over a span and list what they recognise (signatures, compressed streams, counters, timestamps, text, structures), filtered by category, confidence and producer. |
| [`findings.publish`](#findingspublish) | read | Publish findings about a document on the bus as the caller's, for the views, Findings and every other tool to show; they replace the caller's earlier ones under the same key. |
| [`findings.retract`](#findingsretract) | read | Withdraw the findings the caller published under a key. |
| [`structure.parse`](#structureparse) | read | Parse the structure starting exactly at an offset (executables, images, archives, captures, ASN.1, filesystems) into a field tree, best match first. |
| [`structure.parsers`](#structureparsers) | read | The structure parsers available, built in and from plugins. |
| [`templates.list`](#templateslist) | read | The binary templates available: the built-in ones and the user's own. |
| [`templates.apply`](#templatesapply) | read | Apply a binary template, by name or as source text, at an offset and return its field tree and records; with pin, also show it as the template tool does. |
| [`codecs.list`](#codecslist) | read | The codecs available for decoding, built in and from plugins. |
| [`codecs.detect`](#codecsdetect) | read | The codecs whose header starts at an offset. |
| [`codecs.decode`](#codecsdecode) | read | Decode (decompress) a span with a codec and return the output. |
| [`codecs.probe`](#codecsprobe) | read | Try every built-in decompressor at the start of a span, headerless ones included, and list those that decode. |
| [`packets.dissect_bytes`](#packetsdissect_bytes) | read | Dissect one packet, from a span or from hex bytes, into protocol layers and fields, a summary and its flow. |
| [`packets.detect_frames`](#packetsdetect_frames) | read | Find the protocol a set of frames of unknown format is, by trying every frame decoder on them. |
| [`analysis.overview`](#analysisoverview) | read | Map the whole document: a summary of what it is, its regions with offsets, likely record widths and confident findings. |
| [`analysis.overview_job`](#analysisoverview_job) | job | Start analysis.overview as a background job and return its id at once; the report arrives as job.finished's result and from jobs.status, for large files and clients that should not wait. |
| [`analysis.statistics`](#analysisstatistics) | read | Measure a span: entropy, chi-square, serial correlation, printable, zero and high-byte fractions, distinct values and a verdict. |
| [`analysis.segments`](#analysissegments) | read | Split the document into regions of one kind (text, tables, code, compressed, random, padding) and group them into types. |
| [`analysis.compressibility`](#analysiscompressibility) | read | Compress a span with several codecs and report the ratios, with a verdict: encrypted or random, already compressed, lossy media or structured. |
| [`analysis.text_encoding`](#analysistext_encoding) | read | Identify the character encoding of a span of text, with previews and the likely language. |
| [`analysis.processor`](#analysisprocessor) | read | Test whether a span is machine code, and for which processor, by disassembling samples for each architecture. |
| [`reference.lookup`](#referencelookup) | read | The reference notes on a format or protocol, by id, finding id, layer name, port (udp/67) or number (port, IP protocol or EtherType): layout, field meanings and specifications. |
| [`reference.search`](#referencesearch) | read | Reference entries whose notes mention every word of a query, or that a port or number names. |
| [`events.facts`](#eventsfacts) | read | What the tools have learnt about a document and keep: the latest fact per topic, producer and key, by topic, producer or the bytes they cover, each marked stale when the document changed under it. |
| [`jobs.list`](#jobslist) | read | The background jobs tools and callers started (the last 100): what each does, who started it, whether it is running, how far it has got and how it ended. |
| [`jobs.status`](#jobsstatus) | read | One job's state, progress and outcome, and once it has finished, the result of a job a method started. |
| [`jobs.cancel`](#jobscancel) | read | Ask a running job to stop; it ends as cancelled, without a result, as soon as it notices. |
| [`events.poll`](#eventspoll) | read | The messages (facts and events) published after a cursor, oldest first, optionally of some topics only; pass back next to keep up. |

Each method's full JSON schemas are in `theviewer api --describe`.

### api.version

The API version: 1.0. Changes within a major version only add methods, optional parameters and result fields.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `version` | string | yes | Major and minor version, such as "1.0". |

### api.describe

Every method with its summary, effect, stability and the JSON schemas of its parameters and result.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `methods` | array of MethodDescription | yes |  |
| `topics` | array of TopicDescription | yes | The bus's topics, which `events.facts` and `events.poll` read. |
| `version` | string | yes |  |

### documents.list

The open documents, with their ids, names, paths, lengths and versions.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `documents` | array of DocumentInfo | yes |  |

### documents.info

One document's id, name, path, length, version and whether it has unsaved edits.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### documents.open

Open a file by path and make it the current document; a file already open is made current again.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `path` | string | yes | Path of the file to open. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### documents.new

Open a new, empty document and make it current; the window refuses while its document has unsaved edits.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | no | What to call the document ("untitled" by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### documents.save

Save a document over its file, or to a path, with every edit made so far.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `path` | string | no | Where to save; over the document's own file when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### bytes.read

Read a span of bytes, as hex by default, or as base64 or text.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How to write the bytes: hex (the default), base64 or text. |
| `len` | integer | no | Bytes to read, at most 16 MiB; to the end of the document when omitted. |
| `start` | integer | yes | Offset of the first byte. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `data` | string | yes | The bytes, written as `encoding` says. |
| `doc` | string | yes | Id of the document read. |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | yes | How `data` is written. |
| `len` | integer | yes | Bytes read. |
| `start` | integer | yes | Offset of the first byte. |

### bytes.hexdump

A classic hex dump of a span, 16 bytes per line with an ASCII column, at most 1 MiB.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes to show, at most 1 MiB; to the end of the document when omitted. |
| `start` | integer | yes | Offset of the first byte. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document read. |
| `dump` | string | yes | Lines of an offset, 16 hex bytes and their ASCII. |
| `len` | integer | yes | Bytes shown. |
| `start` | integer | yes | Offset of the first byte. |

### bytes.write

Overwrite bytes in place with new ones, as one undoable step; the document keeps its length.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `data` | string | yes | The new bytes, written as `encoding` says; they must fit inside the document. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How `data` is written: hex (the default), base64 or text. |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `start` | integer | yes | Offset of the first byte to overwrite. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### bytes.insert

Insert bytes at an offset, as one undoable step; the bytes after it move along.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Offset to insert at; the document's length appends. |
| `data` | string | yes | The bytes to insert, written as `encoding` says. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How `data` is written: hex (the default), base64 or text. |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### bytes.delete

Remove a span of bytes, as one undoable step; the bytes after it move back.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `len` | integer | yes | Bytes to remove. |
| `start` | integer | yes | Offset of the first byte to remove. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### bytes.replace

Replace a span of bytes with new bytes of any length, as one undoable step.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `data` | string | yes | The bytes to put in their place, written as `encoding` says. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How `data` is written: hex (the default), base64 or text. |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `len` | integer | yes | Bytes to take out; the new bytes may be longer or shorter. |
| `start` | integer | yes | Offset of the first byte to replace. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### bits.read

Read a span of bits, most or least significant bit of each byte first, as a string of 0s and 1s and, up to 64 bits, as a number.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bit_len` | integer | yes | Bits to read, at most 1048576. |
| `bit_start` | integer | yes | Bit offset of the first bit: byte offset × 8 plus the bit within the byte, in `order`. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `order` | `"msb"` \| `"lsb"` | no | Which bit of each byte comes first: "msb" (the default) or "lsb". |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bit_len` | integer | yes | Bits read. |
| `bit_start` | integer | yes | Bit offset of the first bit. |
| `bits` | string | yes | The bits as "0" and "1", first bit first. |
| `doc` | string | yes | Id of the document read. |
| `order` | `"msb"` \| `"lsb"` | yes | Which bit of each byte came first. |
| `value` | NumberValue | no | The bits as an unsigned integer, first bit most significant, when there are at most 64. |

### bits.write

Overwrite bits from any bit offset, most or least significant bit of each byte first, as one undoable step; the bits around them are kept.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bit_start` | integer | yes | Bit offset of the first bit: byte offset × 8 plus the bit within the byte, in `order`. |
| `bits` | string | yes | The new bits as "0" and "1", first bit first; spaces and underscores are ignored. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `order` | `"msb"` \| `"lsb"` | no | Which bit of each byte comes first: "msb" (the default) or "lsb". |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### transform.apply

Apply an operation (XOR, invert, shift bits, swap byte order, number, compress, decompress and more) to every range of a selection, as one undoable step, and select what it produced.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `operation` | Operation | yes | What to do to each selected range, such as {"op": "xor", "key": "5a"}. |
| `selection` | Selection | no | What to change: a range, several ranges or a column of every record. The document's selection when omitted, or the byte at the cursor when nothing is selected. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | yes | What the step is called in the undo history, such as "XOR by mcp:claude-code". |
| `len` | integer | yes | The document's length after the edit. |
| `ranges` | array of pair | yes | Where the new bytes are, as [start, len]: one range per range changed. |
| `version` | integer | yes | The document's version after the edit; pass it as expect_version to the next. |

### transform.preview

What transform.apply would write into each range of a selection, without changing anything.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How to write the new bytes: hex (the default), base64 or text. |
| `operation` | Operation | yes | What to do to each selected range. |
| `selection` | Selection | no | What to change; the document's selection, or the byte at the cursor, when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document read. |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | yes | How each range's `data` is written. |
| `ranges` | array of PreviewRange | yes | Each selected range with its new bytes. |

### history.undo

Undo the document's last step, whoever made it, and put the cursor where it was.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Where its earliest change was. |
| `doc` | string | yes | Id of the document. |
| `label` | string | no | The step undone or redone, when it was named. |
| `len` | integer | yes | The document's length afterwards. |
| `version` | integer | yes | The document's version afterwards. |

### history.redo

Redo the last step undone, and put the cursor where it was.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Where its earliest change was. |
| `doc` | string | yes | Id of the document. |
| `label` | string | no | The step undone or redone, when it was named. |
| `len` | integer | yes | The document's length afterwards. |
| `version` | integer | yes | The document's version afterwards. |

### history.transaction

Run several calls on one document as one undoable step; when one fails, every change the others made is reversed.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `calls` | array of TransactionCall | yes | The calls, run in order: edits, selection changes and reads. |
| `doc` | string | no | Document id, path or "current" (the default); every call must be about this document. |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `label` | string | no | What the step is called in the undo history; "N changes" when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `label` | string | yes | What the step is called in the undo history. |
| `len` | integer | yes | The document's length afterwards. |
| `results` | array of any | yes | Each call's result, in order. |
| `version` | integer | yes | The document's version afterwards. |

### search.find

The next (or previous) occurrence of hex bytes, text, UTF-16 text or an integer from an offset.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `backwards` | boolean | no | Search towards the start of the document. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `from` | integer | no | Offset to search from: the first match at or after it, or before it when searching backwards. |
| `little_endian` | boolean | no | For integers: store them little-endian (the default) or big-endian. |
| `mode` | `"hex"` \| `"text"` \| `"utf16"` \| `"integer"` | no | How to read the query: "hex", "text" (the default), "utf16" (little-endian) or "integer". |
| `query` | string | yes | Hex bytes such as "89 50 4E 47", text, or a decimal or 0x hex integer. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | no | Offset of the match, or nothing when there is none. |

### search.find_all

Every occurrence of hex bytes, text, UTF-16 text or an integer in the document, a page at a time.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `limit` | integer | no | Most matches to return (100 by default). |
| `little_endian` | boolean | no | For integers: store them little-endian (the default) or big-endian. |
| `mode` | `"hex"` \| `"text"` \| `"utf16"` \| `"integer"` | no | How to read the query: "hex", "text" (the default), "utf16" (little-endian) or "integer". |
| `next` | string | no | The `next` cursor of the previous page. |
| `query` | string | yes | Hex bytes such as "89 50 4E 47", text, or a decimal or 0x hex integer. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `matches` | array of integer | yes | Offsets of the matches, in document order; matches may overlap. |
| `next` | string | no | Pass back as `next` for more matches; absent after the last. |

### search.count

How many times hex bytes, text, UTF-16 text or an integer occur in the document, up to a cap.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `cap` | integer | no | Stop counting here (100000 by default), so huge files stay quick. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `little_endian` | boolean | no | For integers: store them little-endian (the default) or big-endian. |
| `mode` | `"hex"` \| `"text"` \| `"utf16"` \| `"integer"` | no | How to read the query: "hex", "text" (the default), "utf16" (little-endian) or "integer". |
| `query` | string | yes | Hex bytes such as "89 50 4E 47", text, or a decimal or 0x hex integer. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capped` | boolean | yes | Whether counting stopped at the cap. |
| `count` | integer | yes |  |

### numbers.decode

Read the bytes at an offset as integers, floats, fixed-point numbers and timestamps of each width and byte order.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Offset of the number's first byte. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `kind` | `"unsigned"` \| `"signed"` \| `"float"` \| `"unix_seconds"` \| `"unix_millis"` \| `"fixed_point"` \| `"file_time"` \| `"gps_seconds"` \| `"hfs_seconds"` \| `"dos_date_time"` | no | Only this kind of number, such as "unsigned", "float" or "unix_seconds". |
| `little_endian` | boolean | no | Only this byte order. |
| `width` | integer | no | Only this width in bytes: 1, 2, 4 or 8. Every width that fits when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Offset of the number's first byte. |
| `decodings` | array of Decoding | yes | Every interpretation asked for that fits before the end of the document. |

### selection.get

What is selected in a document: one range, several ranges or a column of every record.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `ranges` | array of pair | yes | Every selected range as [start, len], in document order. |
| `selection` | Selection | no | The selection as the app holds it, or nothing when no bytes are selected. |
| `total_bytes` | integer | yes | Bytes selected in all. |

### cursor.get

The cursor's offset in a document.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `offset` | integer | yes | Offset of the byte at the cursor. |

### selection.set

Select one range, several ranges or a column of every record in a document, or nothing.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `selection` | Selection | no | What to select: {"range": [start, len]}, {"ranges": [[start, len], …]} or {"columns": {…}}; null or omitted selects nothing. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `ranges` | array of pair | yes | Every selected range as [start, len], in document order. |
| `selection` | Selection | no | The selection as the app holds it, or nothing when no bytes are selected. |
| `total_bytes` | integer | yes | Bytes selected in all. |

### cursor.set

Move the cursor to an offset, selecting nothing.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `offset` | integer | yes | Offset to put the cursor at; the document's length is just past the last byte. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `offset` | integer | yes | Offset of the byte at the cursor. |

### findings.query

Run the detectors over a span and list what they recognise (signatures, compressed streams, counters, timestamps, text, structures), filtered by category, confidence and producer.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `categories` | array of `"signature"` \| `"executable"` \| `"image"` \| `"archive"` \| `"document"` \| `"filesystem"` \| `"compressed"` \| `"encoding"` \| `"protocol"` \| `"structure"` \| `"timestamp"` \| `"counter"` \| `"offset_table"` \| `"float_array"` \| `"text"` \| `"high_entropy"` \| `"padding"` \| `"custom"` | no | Only findings of these categories, such as "compressed" or "timestamp". |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes scanned, at most 16 MiB; to the end of the document when omitted. |
| `limit` | integer | no | Most findings to return (100 by default). |
| `min_confidence` | number | no | Only findings at least this confident, 0 to 1 (0.5 by default). |
| `next` | string | no | The `next` cursor of the previous page. |
| `producers` | array of string | no | Only findings from these producers (a finding's `source`, such as "catalogue"). |
| `start` | integer | no | First offset scanned (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `findings` | array of Finding | yes | Findings in document order, overlaps resolved as the views show them. |
| `next` | string | no | Pass back as `next` for more findings; absent after the last. |

### findings.publish

Publish findings about a document on the bus as the caller's, for the views, Findings and every other tool to show; they replace the caller's earlier ones under the same key.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `findings` | array of Finding | yes | The findings, in document offsets; they replace those the caller published before under the same key. |
| `key` | string | no | Tells apart several sets of findings one caller keeps (empty by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `findings` | integer | yes | Findings published (none for a retraction). |
| `producer` | string | yes | Who the findings are published as, such as "mcp:claude-code". |

### findings.retract

Withdraw the findings the caller published under a key.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `key` | string | no | The key the findings were published under (empty by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `findings` | integer | yes | Findings published (none for a retraction). |
| `producer` | string | yes | Who the findings are published as, such as "mcp:claude-code". |

### structure.parse

Parse the structure starting exactly at an offset (executables, images, archives, captures, ASN.1, filesystems) into a field tree, best match first.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Offset where the structure starts. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `parser` | string | no | Only this parser, by id (see structure.parsers); every parser when omitted. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `structures` | array of Finding | yes | Every parse of the bytes, most confident first, each with its field tree in document offsets. Empty when no parser recognises them. |

### structure.parsers

The structure parsers available, built in and from plugins.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `parsers` | array of ParserInfo | yes |  |

### templates.list

The binary templates available: the built-in ones and the user's own.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `templates` | array of TemplateInfo | yes |  |

### templates.apply

Apply a binary template, by name or as source text, at an offset and return its field tree and records; with pin, also show it as the template tool does.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | no | Offset the template's root starts at (0 by default). |
| `doc` | string | no | Document id, path or "current" (the default). |
| `limit` | integer | no | Most records to return (100 by default). |
| `name` | string | no | A template from templates.list. |
| `next` | string | no | The `next` cursor of the previous page of records. |
| `pin` | boolean | no | Pin the parse as the template tool does: its records are outlined in the views and its structure published, in place of the last template pinned. |
| `source` | string | no | Template source text, as written in the template language. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `columns` | array of string | yes | Column names across all records, in order of first appearance. |
| `next` | string | no | Pass back as `next` for more records; absent after the last. |
| `records` | array of RecordResult | yes | One page of records. |
| `structure` | Finding | yes | The whole parse, with its field tree in document offsets. |
| `total_records` | integer | yes | Records in all. |
| `warnings` | array of string | yes | Problems met while applying, each with its template line. |

### codecs.list

The codecs available for decoding, built in and from plugins.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `codecs` | array of CodecInfo | yes |  |

### codecs.detect

The codecs whose header starts at an offset.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | yes | Offset where the encoded data would start. |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `codecs` | array of CodecInfo | yes |  |

### codecs.decode

Decode (decompress) a span with a codec and return the output.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `codec` | string | yes | Codec id from codecs.list, such as "zlib" or "gzip". |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How to write the output: hex (the default), base64 or text. |
| `len` | integer | no | Bytes of input, at most 16 MiB; to the end of the document when omitted. |
| `max_output` | integer | no | Most bytes of output, at most 16 MiB (the default). |
| `start` | integer | yes | Offset of the encoded data. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `codec` | string | yes |  |
| `complete` | boolean | yes | Whether the data ended cleanly. |
| `consumed` | integer | yes | Input bytes the encoded data occupied. |
| `consumed_exact` | boolean | yes | Whether `consumed` is exact rather than a buffered estimate. |
| `data` | string | yes | The output, written as `encoding` says. |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | yes | How bytes are written in JSON. |
| `output_len` | integer | yes |  |
| `truncated` | boolean | yes | Whether the output was cut at `max_output`. |

### codecs.probe

Try every built-in decompressor at the start of a span, headerless ones included, and list those that decode.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes of input, at most 16 MiB; to the end of the document when omitted. |
| `max_output` | integer | no | Most bytes of output each decoder may produce, at most 16 MiB (the default). |
| `start` | integer | yes | Offset where compressed data might start. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `streams` | array of ProbedStream | yes | Decoders that read the data, headed ones first. |

### packets.dissect_bytes

Dissect one packet, from a span or from hex bytes, into protocol layers and fields, a summary and its flow.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes` | string | no | The packet's bytes instead of a span, written as `encoding` says. |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | For frames of unknown format: the protocol to decode them as, such as "dns" or "modbus_tcp". |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How `bytes` is written: hex (the default), base64 or text. |
| `len` | integer | no | Bytes in the packet; to the end of the document when omitted. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | What the first byte is, such as "ethernet" or "raw_ip"; "unknown" (the default) reads an IP header if one is there. |
| `start` | integer | no | Offset of the packet's first byte. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `ether_type` | integer | no | The EtherType after the Ethernet header and any VLAN tags. |
| `flow` | Flow | no | Addresses and ports, for IP packets. |
| `layers` | array of Layer | yes | Protocol layers, outermost first; offsets are relative to the packet's first byte. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | yes | The link type used, after detection. |
| `notes` | array of string | yes | Problems met, such as truncation or a bad checksum. |
| `payload` | pair | no | The transport payload as [offset, len] within the packet. |
| `protocols` | array of string | yes | Lower-case names of every layer, as the packet filter uses them. |
| `summary` | Summary | yes | The packet list's columns. |

### packets.detect_frames

Find the protocol a set of frames of unknown format is, by trying every frame decoder on them.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `frames` | array of FrameSpan | yes | The frames, at most 16 MiB in all; a sample of them is tried. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `detection` | FrameDetection | no | The protocol nearly every frame reads as in full, or nothing when none clearly does. |

### analysis.overview

Map the whole document: a summary of what it is, its regions with offsets, likely record widths and confident findings.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `max_findings` | integer | no | Most findings to include (all of them, up to 2000, by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `analysed` | integer | yes | Bytes actually analysed (large files are read up to a limit). |
| `entropy_bits_per_byte` | number | yes |  |
| `file` | string | yes | The file's path or name. |
| `findings` | array of ReportFinding | yes | Confident findings in file order. |
| `headline` | string | yes | One line on what the file is. |
| `record_widths` | array of RecordWidth | yes | Likely record widths, best first. |
| `regions` | array of ReportRegion | yes | The file's regions, from start to end. |
| `sentences` | array of ReportSentence | yes | What the report says about the file, each about a span of it. |
| `size` | integer | yes | Length in bytes. |

### analysis.overview_job

Start analysis.overview as a background job and return its id at once; the report arrives as job.finished's result and from jobs.status, for large files and clients that should not wait.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `max_findings` | integer | no | Most findings to include (all of them, up to 2000, by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### analysis.statistics

Measure a span: entropy, chi-square, serial correlation, printable, zero and high-byte fractions, distinct values and a verdict.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the span; to the end of the document when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `analysed` | integer | yes | Bytes measured. |
| `chi_square` | number | yes |  |
| `chi_square_p` | number | yes | Chi-square p-value against uniformly random bytes. |
| `distinct_values` | integer | yes |  |
| `entropy` | number | yes | Shannon entropy, 0 to 8 bits per byte. |
| `explanation` | string | yes | Why, with the measurements behind it. |
| `high_fraction` | number | yes | Fraction of bytes of 0x80 or more. |
| `mean` | number | yes |  |
| `printable_fraction` | number | yes |  |
| `serial_correlation` | number | yes | Correlation of each byte with the next; 0 for random data. |
| `start` | integer | yes |  |
| `verdict` | string | yes | What the bytes look like, such as "Text" or "Compressed or encrypted". |
| `zero_fraction` | number | yes |  |

### analysis.segments

Split the document into regions of one kind (text, tables, code, compressed, random, padding) and group them into types.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `limit` | integer | no | Most segments to return (100 by default). |
| `next` | string | no | The `next` cursor of the previous page. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `next` | string | no | Pass back as `next` for more regions; absent after the last. |
| `scanned_len` | integer | yes | Bytes segmented, from the start of the document. |
| `segments` | array of SegmentResult | yes | One page of the regions, in document order. |
| `types` | array of SegmentTypeResult | yes |  |

### analysis.compressibility

Compress a span with several codecs and report the ratios, with a verdict: encrypted or random, already compressed, lossy media or structured.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the span; to the end of the document when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `entropy` | number | yes |  |
| `ratios` | array of CompressionRatio | yes |  |
| `reason` | string | yes | The measurements behind the verdict. |
| `sample_len` | integer | yes | Bytes sampled from the span. |
| `verdict` | string | yes | Such as "encrypted or random" or "structured binary/text". |

### analysis.text_encoding

Identify the character encoding of a span of text, with previews and the likely language.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the span; to the end of the document when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `encodings` | array of EncodingCandidate | yes | Encodings, most likely first. |
| `languages` | array of LanguageCandidate | yes | Languages of the text in the best encoding, most likely first. |
| `sample_len` | integer | yes |  |

### analysis.processor

Test whether a span is machine code, and for which processor, by disassembling samples for each architecture.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the span; to the end of the document when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `candidates` | array of ProcessorCandidate | yes | Architectures, most likely first. |
| `looks_like_data` | boolean | yes | Whether no architecture is convincing. |
| `sampled_bytes` | integer | yes | Bytes disassembled per architecture. |
| `summary` | string | yes | One sentence on what was found. |

### reference.lookup

The reference notes on a format or protocol, by id, finding id, layer name, port (udp/67) or number (port, IP protocol or EtherType): layout, field meanings and specifications.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | A format id ("ipv4", "png"), finding id, packet layer name, port ("udp/67") or number (a port, IP protocol number or EtherType). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `entries` | array of FormatReference | yes | The entries the name stands for: one for an id or key, perhaps several for a port or number. |

### reference.search

Reference entries whose notes mention every word of a query, or that a port or number names.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `limit` | integer | no | Most entries to return (100 by default). |
| `next` | string | no | The `next` cursor of the previous page. |
| `query` | string | no | Words the notes must all mention, a port such as "tcp/502", or a number; every entry when empty. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `entries` | array of EntrySummary | yes |  |
| `next` | string | no | Pass back as `next` for more entries; absent after the last. |

### events.facts

What the tools have learnt about a document and keep: the latest fact per topic, producer and key, by topic, producer or the bytes they cover, each marked stale when the document changed under it.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `producer` | string | no | Only facts from this producer, such as "tool:period-scan". |
| `span` | SpanParam | no | Only facts whose span overlaps these bytes. |
| `topic` | string | no | Only facts on this topic, such as "record_width.estimated". |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `facts` | array of MessageEntry | yes | The facts, by topic, producer and key. |

### jobs.list

The background jobs tools and callers started (the last 100): what each does, who started it, whether it is running, how far it has got and how it ended.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `jobs` | array of JobStatus | yes | The jobs remembered (the last 100), oldest first. |

### jobs.status

One job's state, progress and outcome, and once it has finished, the result of a job a method started.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | The job's id, such as "report-3", as `job.started` or a job method gave it. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `document` | string | no | The document it works on, if one. |
| `done` | integer | no | Units of work done, when the job counts them. |
| `job` | string | yes | Unique for the session, such as "report-3". |
| `outcome` | string | no | One line on what it found, or why it stopped, once it has. |
| `producer` | string | yes | Who started it, such as `tool:report` or `mcp:claude-code`. |
| `result` | any | no | What a job started through the API gives back once finished: the result the method would have returned. |
| `state` | `"running"` \| `"cancelling"` \| `"finished"` \| `"failed"` \| `"cancelled"` | yes | Where a job is. |
| `title` | string | yes | What the job does, such as "Report". |
| `total` | integer | no | Units of work in all, when known. |

### jobs.cancel

Ask a running job to stop; it ends as cancelled, without a result, as soon as it notices.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | The job's id, such as "report-3", as `job.started` or a job method gave it. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `document` | string | no | The document it works on, if one. |
| `done` | integer | no | Units of work done, when the job counts them. |
| `job` | string | yes | Unique for the session, such as "report-3". |
| `outcome` | string | no | One line on what it found, or why it stopped, once it has. |
| `producer` | string | yes | Who started it, such as `tool:report` or `mcp:claude-code`. |
| `result` | any | no | What a job started through the API gives back once finished: the result the method would have returned. |
| `state` | `"running"` \| `"cancelling"` \| `"finished"` \| `"failed"` \| `"cancelled"` | yes | Where a job is. |
| `title` | string | yes | What the job does, such as "Report". |
| `total` | integer | no | Units of work in all, when known. |

### events.poll

The messages (facts and events) published after a cursor, oldest first, optionally of some topics only; pass back next to keep up.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `cursor` | integer | no | The `next` of the previous poll; omitted, every message still held. |
| `limit` | integer | no | Most messages to return (default 100, at most 1000). |
| `topics` | array of string | no | Only messages on these topics. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `messages` | array of MessageEntry | yes | Messages delivered after the cursor, oldest first. |
| `missed` | integer | yes | Messages delivered after the cursor but no longer held. |
| `next` | integer | yes | Pass back as `cursor` to get the messages after these. |

## Topics

What tools, panels and plugins publish on the workspace bus. Facts are kept, the latest per producer, document and key, and count as stale once the document has changed since (unless the edits did not touch their span, which carries them forward); events are not kept. Every message has an envelope: `id`, `topic`, `kind`, `producer`, `document`, `version`, `span`, `confidence`, `key`, `caused_by` and the `payload` below.

| Topic | Kind | Description |
| --- | --- | --- |
| [`document.opened`](#documentopened) | event | A document was opened, or replaced the one shown. |
| [`document.closed`](#documentclosed) | event | A document was closed or replaced; what was known about it is forgotten. |
| [`document.edited`](#documentedited) | event | The document's bytes changed: each change's offset, bytes removed and bytes inserted, undo and redo included. |
| [`cursor.moved`](#cursormoved) | event | The cursor moved in the main view. |
| [`view.jump`](#viewjump) | event | Someone asks the views to put the cursor on an offset and bring it into view (a link in a report or an answer, say). |
| [`pane.show`](#paneshow) | event | Someone asks the window to bring a pane forward, reopening it if it was closed. |
| [`view.pointed`](#viewpointed) | event | Bytes a panel points at (a field row under the pointer), which the views outline, or that it stopped pointing; published when it changes. |
| [`selection.changed`](#selectionchanged) | event | What is selected changed, in the main view or by a tool selecting bytes in the document. |
| [`findings.published`](#findingspublished) | fact | What one producer recognises in the document: the scan, signatures, templates, the structure map, crypto constants, a comparison, checksums or protocol messages. |
| [`structure.identified`](#structureidentified) | fact | A structure parsed at the cursor, or a template applied, with its field tree. |
| [`fields.decoded`](#fieldsdecoded) | fact | A packet dissected into protocol layers and fields, at document offsets: the packet viewer's chosen packet, which the Reference tab reads. |
| [`template.applied`](#templateapplied) | fact | A binary template applied to the document (or, retracted, cleared): its name, source and parse, which the views outline and the packet viewer's raw frames follow. |
| [`regions.mapped`](#regionsmapped) | fact | The file split into regions of one kind, from the report. |
| [`record_width.estimated`](#record_widthestimated) | fact | The length of the records the data repeats in, from the period scan. |
| [`frames.defined`](#framesdefined) | fact | Message or packet boundaries: from the protocol framing, a capture or the packet viewer's splitting rules. |
| [`fields.guessed`](#fieldsguessed) | fact | The fields the protocol analysis guessed in a stream's messages (constants, types, sequence numbers, lengths, checksums), with a template for them. |
| [`protocol.identified`](#protocolidentified) | fact | The protocol a set of frames or a payload is, and how that was decided. |
| [`reference.focus`](#referencefocus) | event | A tool asks the Reference tab to show a format or protocol. |
| [`template.apply_requested`](#templateapply_requested) | event | Someone asks for a template to be applied at the cursor (one Ask offered, say), as the Template tool would. |
| [`job.started`](#jobstarted) | event | Background work started. |
| [`job.progress`](#jobprogress) | event | How far background work that counts its work has got. |
| [`job.finished`](#jobfinished) | event | Background work finished, with a one-line outcome (and, for a job started through the API, its result), or was cancelled. |
| [`plugin.log`](#pluginlog) | event | A plugin logged a line, or one of its callbacks failed (in a background scan, say). |
| [`x.*`](#x*) | event | A plugin's own topic, named x.<plugin>.<name>, with a payload of its choosing. |

### document.opened

A document was opened, or replaced the one shown.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `len` | integer | yes | Length in bytes. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for a document opened from a file. |

### document.closed

A document was closed or replaced; what was known about it is forgotten.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | The document's name. |

### document.edited

The document's bytes changed: each change's offset, bytes removed and bytes inserted, undo and redo included.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `complete` | boolean | yes | False when the edit log no longer held every change since the last message; spans described before then cannot be mapped forward. |
| `edits` | array of Edit | yes | The changes, oldest first, each with the version it made. |

### cursor.moved

The cursor moved in the main view.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `offset` | integer | yes | Document offset of the cursor. |

### view.jump

Someone asks the views to put the cursor on an offset and bring it into view (a link in a report or an answer, say).

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `offset` | integer | yes | Document offset for the cursor. |

### pane.show

Someone asks the window to bring a pane forward, reopening it if it was closed.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `pane` | string | yes | The pane: Raster, Inspector, Findings, HexDump, PeriodChart, or a tool such as Packets, Reference or Template. |

### view.pointed

Bytes a panel points at (a field row under the pointer), which the views outline, or that it stopped pointing; published when it changes.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes` | Span | no | The bytes, or nothing once nothing is pointed at. |

### selection.changed

What is selected changed, in the main view or by a tool selecting bytes in the document.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `cursor` | integer | yes | Document offset of the cursor. |
| `selection` | Selection | no | `None` when nothing is selected. |

### findings.published

What one producer recognises in the document: the scan, signatures, templates, the structure map, crypto constants, a comparison, checksums or protocol messages.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `findings` | array of Finding | yes | What was found, each with its offset, length, category and title. |

### structure.identified

A structure parsed at the cursor, or a template applied, with its field tree.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `fields` | array of Field | yes | The field tree, at document offsets. |
| `format` | string | yes | The parser or template's id, such as `parser:pcap` or `template:Header`. |
| `len` | integer | yes |  |
| `start` | integer | yes | Document offset of the structure's first byte. |
| `title` | string | yes | Such as "PNG image". |

### fields.decoded

A packet dissected into protocol layers and fields, at document offsets: the packet viewer's chosen packet, which the Reference tab reads.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `ether_type` | integer | no | The EtherType after the Ethernet header and any VLAN tags. |
| `flow` | Flow | no | Addresses, ports and transport, for an IP packet. |
| `layers` | array of Layer | yes | Protocol layers, outermost first, each with its fields; every offset is a document offset. |
| `payload` | Span | no | The transport payload's bytes in the document. |

### template.applied

A binary template applied to the document (or, retracted, cleared): its name, source and parse, which the views outline and the packet viewer's raw frames follow.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | The template's name. |
| `records` | integer | yes | Records it read from its outermost array. |
| `source` | string | yes | The template's source text, to apply it again; empty when not known. |
| `structure` | Finding | yes | The whole parse, with its field tree at document offsets. |

### regions.mapped

The file split into regions of one kind, from the report.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `regions` | array of MappedRegion | yes | The regions in document order. |

### record_width.estimated

The length of the records the data repeats in, from the period scan.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `alternatives` | array of integer | yes | The next best widths, best first. |
| `score` | number | yes | How alike records this far apart are, 0 to 1. |
| `width` | integer | yes | Bytes per record. |

### frames.defined

Message or packet boundaries: from the protocol framing, a capture or the packet viewer's splitting rules.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `frames` | array of FrameSpan | yes | The first [`MOST_FRAMES`] frames, in document order. |
| `framing` | Framing | no | The framing that cut them from the message's span, when one did, so a reader can split the span again (after an edit, or past the frames listed). |
| `origin` | string | yes | How they were found, such as "length prefix u16be" or "pcap capture at 0x40". |
| `total` | integer | yes | How many frames there are in all. |

### fields.guessed

The fields the protocol analysis guessed in a stream's messages (constants, types, sequence numbers, lengths, checksums), with a template for them.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `fields` | array of MessageField | yes | Each field's position in a message (from its end for a trailer), what it seems to be and example values. |
| `template` | string | no | A binary template reading the fields, when they make one. |

### protocol.identified

The protocol a set of frames or a payload is, and how that was decided.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `frames` | array of FrameSpan | yes | The frames it was found for; empty when it is about one payload, which the message's span gives. |
| `how` | string | yes | How it was decided, such as "read 30 of 32 sampled frames in full". |
| `protocol` | string | yes | Such as "DNS" or "Modbus/TCP". |

### reference.focus

A tool asks the Reference tab to show a format or protocol.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `key` | string | yes | A reference id, finding id or layer name. |

### template.apply_requested

Someone asks for a template to be applied at the cursor (one Ask offered, say), as the Template tool would.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `source` | string | yes | The template's source text. |

### job.started

Background work started.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Unique for the session, such as "period-scan-3". |
| `title` | string | yes | What the job does, such as "Period scan". |

### job.progress

How far background work that counts its work has got.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `done` | integer | yes | Units of work done (packets, blocks, bytes: the job's own). |
| `job` | string | yes | The id `job.started` gave. |
| `total` | integer | no | Units in all, when known. |

### job.finished

Background work finished, with a one-line outcome (and, for a job started through the API, its result), or was cancelled.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `cancelled` | boolean | no | Whether it stopped because it was cancelled. |
| `job` | string | yes | The id `job.started` gave. |
| `ok` | boolean | yes | Whether it produced a result. |
| `outcome` | string | yes | One line on what it found, or why it stopped. |
| `result` | any | no | For a job started through the API, the result the method gives. |
| `title` | string | yes |  |

### plugin.log

A plugin logged a line, or one of its callbacks failed (in a background scan, say).

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `level` | `"info"` \| `"error"` | yes | `error` for a failed callback, `info` for a line the plugin logged. |
| `plugin` | string | yes | The plugin's file name, such as `modbus_rtu.lua`. |
| `text` | string | yes |  |

### x.*

A plugin's own topic, named x.<plugin>.<name>, with a payload of its choosing.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | The topic, `x.<plugin>.<name>`. |
| `payload` | any | yes | Whatever the plugin published. |
