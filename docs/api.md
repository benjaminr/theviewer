# theviewer data API, version 1.0

<!-- Generated from the method table (src/api.rs and each module in src/api/) by `cargo run --bin api_docs`. Do not edit by hand. -->

Every method can be called from the command line (`theviewer api METHOD '{json params}' FILE`; with `--save`, the file is saved with the call's edits, so `--save history.transaction` edits and saves in one command), Lua plugins call them as `theviewer.api.<namespace>.<method>{…}`, Ask uses the methods that read or edit as its tools, and `theviewer mcp FILE…` offers every method to MCP clients such as Claude Code as a tool named with underscores for dots (`bytes_read`), with resources for each document (`theviewer://doc/{id}`, its `bytes/{start}-{end}`, `findings`, `facts` and `packets/{set}`) and the reference notes (`theviewer://reference/{id}`). Documents are named by id (`doc-1`), by path or as `"current"`, which an omitted `doc` also means. Spans are `start` and `len` in bytes; an omitted `len` runs to the end of the document. Bytes are hex strings unless `encoding` says `base64` or `text`. List methods take `limit` and return `next`, a cursor to pass back for the next page. One call reads or returns at most 16 MiB.

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
| [`documents.open`](#documentsopen) | view | Open a file by path, or an open document by id, and make it current; a file already open is made current again. In the window, a parent of the document shown is gone back to, closing what was derived from it; that, or opening another file, is refused while what it closes has unsaved edits, unless the person at the window discards them. |
| [`documents.new`](#documentsnew) | view | Open a new, empty document and make it current; the window refuses while its document has unsaved edits, unless the person at the window discards them. |
| [`documents.save`](#documentssave) | edit | Save a document over its file, or to a path, with every edit made so far. |
| [`documents.derive`](#documentsderive) | view | Open bytes of a document (a span, several ranges one after another, or bytes given), or what a transform such as decompress or XOR makes of them, as a document of their own derived from it, and make it current; in the window, Back goes back to the parent. |
| [`documents.export`](#documentsexport) | edit | Write a span of a document to a file, or what decompresses at its start; the document is left as it is. |
| [`documents.open_source`](#documentsopen_source) | view | Open a file, URL, block device, serial port (serial:PORT@BAUD) or a process's memory region (pid:PID@ADDRESS) as a new document. The window reads a URL, device or region in the background and opens it when it arrives, and pid:PID lists a process's regions in the Live tab; headless, the bytes are read before the call returns. |
| [`bytes.read`](#bytesread) | read | Read a span of bytes, as hex by default, or as base64 or text. |
| [`bytes.hexdump`](#byteshexdump) | read | A classic hex dump of a span, 16 bytes per line with an ASCII column, at most 1 MiB. |
| [`bytes.write`](#byteswrite) | edit | Overwrite bytes in place with new ones, as one undoable step; the document keeps its length. |
| [`bytes.insert`](#bytesinsert) | edit | Insert bytes at an offset, as one undoable step; the bytes after it move along. |
| [`bytes.delete`](#bytesdelete) | edit | Remove a span of bytes, as one undoable step; the bytes after it move back. |
| [`bytes.replace`](#bytesreplace) | edit | Replace a span of bytes with new bytes of any length, as one undoable step. |
| [`bytes.move`](#bytesmove) | edit | Cut ranges out and put their bytes, one after another, at an offset counted before the cut, as one undoable step, and select them. |
| [`bits.read`](#bitsread) | read | Read a span of bits, most or least significant bit of each byte first, as a string of 0s and 1s and, up to 64 bits, as a number. |
| [`bits.write`](#bitswrite) | edit | Overwrite bits from any bit offset, most or least significant bit of each byte first, as one undoable step; the bits around them are kept. |
| [`bits.scan_periods`](#bitsscan_periods) | job | Start a search of a span for bit periods (frames that are not a whole number of bytes) and the sync word of the strongest, comparing the bits with themselves at every lag, as a job: the periods and sync words are job.finished's result, and in the window they fill the Bits panel. |
| [`bits.planes`](#bitsplanes) | job | Start splitting a span (at most 1 MiB) into its eight bit planes as a job, scoring how much shape each holds with rows of row_width bytes: the scores are job.finished's result, and in the window the planes fill the Bits panel. |
| [`bits.open_plane`](#bitsopen_plane) | view | Open one bit plane of a span (at most 1 MiB) as a derived document: bit k of every byte, as a byte of 0 or 255. |
| [`bits.detect_linecode`](#bitsdetect_linecode) | job | Start trying Manchester (both conventions), differential Manchester, 8b/10b and packed BCD at every bit alignment of a span (at most 64 KiB) as a job: the decodes, fewest invalid symbols first, and any BCD timestamps are job.finished's result, and in the window they fill the Bits panel. |
| [`bits.decode_linecode`](#bitsdecode_linecode) | view | Decode a span (at most 64 KiB) from a line code at a bit offset and open the decoded bytes as a derived document. |
| [`bits.rank_field`](#bitsrank_field) | read | Rank what a field of records holds (integers, floats, fixed point, timestamps, enums…) by how plausible its values are across the records. |
| [`bits.find_length_fields`](#bitsfind_length_fields) | job | Start a search of a span (at most 256 KiB, one message or a run of records) for numbers that are distances, as a job: length prefixes, tag-length-value chains and offset tables, best first, are job.finished's result, and in the window they fill the Bits panel. |
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
| [`selection.set`](#selectionset) | view | Select one range, several ranges or a column of every record in a document, or nothing. |
| [`cursor.get`](#cursorget) | read | The cursor's offset in a document. |
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
| [`codecs.open_decoded`](#codecsopen_decoded) | view | Decompress the stream starting at an offset, with the first codec that decodes there or the one named, and open what it holds as a document derived from this one; in the window, Back (or opening the parent by id) returns. |
| [`packets.dissect_bytes`](#packetsdissect_bytes) | read | Dissect one packet, from a span or from hex bytes, into protocol layers and fields, a summary and its flow. |
| [`packets.detect_frames`](#packetsdetect_frames) | read | Find the protocol a set of frames of unknown format is, by trying every frame decoder on them. |
| [`packets.sets.create`](#packetssetscreate) | read | Take a set of packets from a document: a capture in it, a range cut into fixed records, by a length field, at a pattern or with the protocol framing, or the selection's ranges, with how to decode frames of unknown format; returns the set's id and what was worked out (the capture found, the framing), so the call can be made again exactly. |
| [`packets.sets.list`](#packetssetslist) | read | The packet sets made, with their ids, documents, sources, packet counts and decoding. |
| [`packets.list`](#packetslist) | read | A set's packets the display filter keeps, a page at a time: each one's index, offset, length, summary columns, protocols and addresses. |
| [`packets.dissect`](#packetsdissect) | read | Dissect one packet of a set into protocol layers and fields, as the set decodes frames of unknown format. |
| [`packets.decode_as`](#packetsdecode_as) | read | Choose the protocol a set's frames of unknown format are decoded as, or detection, and a template for frames no protocol reads. |
| [`packets.export_pcap`](#packetsexport_pcap) | read | A set's packets (those a filter keeps) as a pcap file, returned or written to a path given (which needs leave to edit). |
| [`packets.conversations`](#packetsconversations) | read | The conversations in a set (the packets a filter keeps): each pair of endpoints with its transport, packets and bytes each way, and a filter for it. |
| [`packets.follow_stream`](#packetsfollow_stream) | read | The payloads of a packet's conversation in order, each with its direction, and the stream as text. |
| [`packets.find_captures`](#packetsfind_captures) | read | The captures inside a span of a document (pcap, pcapng, snoop, Network Monitor or ERF, or one of these compressed with gzip), each with its offset, format, link type and packets, for packets.sets.create. |
| [`packets.sets.add_packets`](#packetssetsadd_packets) | view | Add ranges of the document to a set as packets of their own, so packets can be gathered one at a time; the set then keeps its packets where they are. |
| [`packets.sets.refresh`](#packetssetsrefresh) | view | Find a set's packets again, the way they were found, in another document (the current one by default), which the set then belongs to. |
| [`packets.detect_length_field`](#packetsdetect_length_field) | read | Look for a length field that cuts a span into frames, with the protocol analysis's framing detection; returns it as packets.sets.create's length_field, or the best framing found instead. |
| [`packets.endpoints`](#packetsendpoints) | read | The addresses in a set (the packets a filter keeps), busiest first, with the packets and bytes each sent and received. |
| [`packets.extract`](#packetsextract) | read | Some of a set's packets' bytes one after another, returned or written to a path given (which needs leave to edit). |
| [`packets.delete`](#packetsdelete) | edit | Remove packets from the document (their whole capture records, so a capture stays readable), as one undoable step. |
| [`packets.fix_checksums`](#packetsfix_checksums) | edit | Recompute the IPv4 header, TCP and UDP checksums of some of a set's packets, as one undoable step. |
| [`packets.apply`](#packetsapply) | edit | Invert, fill or XOR some of a set's packets, or the same field of each, as one undoable step. |
| [`packets.write_field`](#packetswrite_field) | edit | Write a value (a number, or hex bytes as wide as the field) into a field of one packet, as one undoable step. |
| [`packets.columns.apply`](#packetscolumnsapply) | edit | Change the same columns (byte offsets) of every packet, or of some, laid out one packet per row: invert, fill, XOR, add, set, number or swap the byte order, as one undoable step. |
| [`packets.columns.delete`](#packetscolumnsdelete) | edit | Remove the same columns (byte offsets) from every packet, or from some, as one undoable step; length fields and checksums are not changed. |
| [`packets.columns.read`](#packetscolumnsread) | read | The same columns (byte offsets) of every packet, or of some, as hex lines or CSV. |
| [`packets.tshark_decode`](#packetstshark_decode) | job | Have Wireshark's tshark decode some of a set's packets (run locally with -n) as a background job; the protocols it named are the job's result, and in the window its layers merge into the Packets panel's. |
| [`analysis.overview`](#analysisoverview) | read | Map the whole document: a summary of what it is, its regions with offsets, likely record widths and confident findings. |
| [`analysis.overview_job`](#analysisoverview_job) | job | Start analysis.overview as a background job and return its id at once; the report arrives as job.finished's result and from jobs.status, for large files and clients that should not wait. |
| [`analysis.statistics`](#analysisstatistics) | read | Measure a span: entropy, chi-square, serial correlation, printable, zero and high-byte fractions, distinct values and a verdict. |
| [`analysis.segments`](#analysissegments) | read | Split the document into regions of one kind (text, tables, code, compressed, random, padding) and group them into types. |
| [`analysis.compressibility`](#analysiscompressibility) | read | Compress a span with several codecs and report the ratios, with a verdict: encrypted or random, already compressed, lossy media or structured. |
| [`analysis.text_encoding`](#analysistext_encoding) | read | Identify the character encoding of a span of text, with previews and the likely language. |
| [`analysis.processor`](#analysisprocessor) | read | Test whether a span is machine code, and for which processor, by disassembling samples for each architecture. |
| [`analysis.period_scan`](#analysisperiod_scan) | job | Start a scan of a window of bytes for repeating periods (record widths) as a background job; the periods found, best first, are job.finished's result, and in the window they fill the structure chart and are published on record_width.estimated. |
| [`reference.lookup`](#referencelookup) | read | The reference notes on a format or protocol, by id, finding id, layer name, port (udp/67) or number (port, IP protocol or EtherType): layout, field meanings and specifications. |
| [`reference.search`](#referencesearch) | read | Reference entries whose notes mention every word of a query, or that a port or number names. |
| [`events.facts`](#eventsfacts) | read | What the tools have learnt about a document and keep: the latest fact per topic, producer and key, by topic, producer or the bytes they cover, each marked stale when the document changed under it. |
| [`events.poll`](#eventspoll) | read | The messages (facts and events) published after a cursor, oldest first, optionally of some topics only; pass back next to keep up. |
| [`jobs.list`](#jobslist) | read | The background jobs tools and callers started (the last 100): what each does, who started it, whether it is running, how far it has got and how it ended. |
| [`jobs.status`](#jobsstatus) | read | One job's state, progress and outcome, and once it has finished, the result of a job a method started. |
| [`jobs.cancel`](#jobscancel) | read | Ask a running job to stop; it ends as cancelled, without a result, as soon as it notices. |
| [`statistics.analyse`](#statisticsanalyse) | job | Start the Statistics tool's measure of a span (at most 64 MiB) as a job: the ent randomness tests with a verdict, the byte histogram, entropy and compressibility along the span and the most repeated byte sequences are job.finished's result, and in the window they fill the Statistics tab. |
| [`strings.find`](#stringsfind) | job | Start the Strings tool's search of a span (at most 64 MiB) for runs of text at least min_chars long in the encodings chosen, as a job: the strings found (at most 200000), each with its offset, length, encoding, text and what it looks like (a URL, a path, a key…), are job.finished's result, and in the window they fill the Strings tab. |
| [`xor.recover_keys`](#xorrecover_keys) | read | Recover single-byte and repeating XOR keys for a span (at most 1 MiB) by letter frequency, index of coincidence and the key showing through zero padding, best first, with a preview of each decode and the likely key lengths; transform.apply with {"op": "xor"} applies one. |
| [`checksums.digests`](#checksumsdigests) | read | The digests of a span (at most 64 MiB): CRC-32, Adler-32, MD5, SHA-1, SHA-256, the 8- and 16-bit sums and the XOR of every byte. |
| [`checksums.find_stored`](#checksumsfind_stored) | read | Find a CRC, Adler or sum stored in a span (at most 64 MiB) that covers part of it, testing header and trailer fields, and the fields at the boundaries given, against the bytes before, after and around them. |
| [`checksums.solve_crc`](#checksumssolve_crc) | job | Start the CRC solver on records of equal length that each carry a stored CRC, as a job: every polynomial, init, xorout and reflection that reproduces all the stored values (like reveng), with the closest catalogue algorithm, is job.finished's result, and in the window it fills the CRC solver. |
| [`diff.run`](#diffrun) | job | Start a comparison of a document with another file as a job: the regions replaced, only in the document and only in the other file (inserted, deleted and changed, not just flipped bytes), with the bytes equal and changed, are job.finished's result, and in the window they fill the Diff tab and are outlined on the views. |
| [`disasm.set_arch`](#disasmset_arch) | view | Choose the architecture the Disassembly tab decodes as, or auto (the executable header's, else a guess from the bytes); headless there is no listing to change, and the choice is only returned. |
| [`crypto.scan_constants`](#cryptoscan_constants) | job | Start a scan of the whole document (an edited one's first 256 MiB) for well-known constants of crypto and compression code (AES S-boxes, hash initial values, CRC tables, deflate tables, Blowfish, DES, ChaCha, TEA, curve primes, Base64 alphabets) as a job: the matches are job.finished's result, and in the window they fill Crypto constants. |
| [`crypto.repeated_blocks`](#cryptorepeated_blocks) | job | Start a search of a span (at most 16 MiB) for random-looking 8- and 16-byte blocks that repeat, the mark of ECB-mode encryption, as a job: the verdict, the best block size and alignment, the most repeated blocks and the repeats along the span are job.finished's result, and in the window they fill the Crypto panel. |
| [`crypto.find_keys`](#cryptofind_keys) | job | Start a search of a span (the whole document by default, at most 64 MiB) for PEM blocks, DER certificates and keys, OpenSSH keys and random-looking runs that could be raw symmetric keys, as a job: what was found is job.finished's result, and in the window it fills the Crypto panel. |
| [`crypto.attack`](#cryptoattack) | job | Start attacks on simple ciphers over a span (at most 1 MiB): rolling XOR, XOR with the previous byte, ADD/SUB with a constant or repeating key, bit rotation, XOR combined with ADD and, with a crib, crib dragging, as a job: the decodes that look most like text or structured data are job.finished's result, and in the window they fill the Crypto panel. |
| [`compare.variation`](#comparevariation) | job | Start comparing a document with other files byte position by byte position, each from its own start offset, as a job: the regions that are constant, vary (and how many values) or move one way through the files like a counter are job.finished's result, and in the window they fill Compare. |
| [`compare.correlate`](#comparecorrelate) | job | Start a search of a document and other files for fields whose values follow a number known for each file (a temperature, a setting), as a job: the fields, best fit first, with the fitted line, are job.finished's result, and in the window they fill Compare. |
| [`compare.timeline`](#comparetimeline) | job | Start building the change timeline of the recording of a live source or watched file, as a job: where and how often it changed, snapshot by snapshot, is job.finished's result, and the window fills Compare with it; only the window records, so headless there is none. |
| [`view.get_shape`](#viewget_shape) | read | The shape a document's bytes are drawn in: the pixel format, pixels per row, the offset of the first pixel, a bit shift and the bytes skipped after each row. |
| [`view.set_shape`](#viewset_shape) | view | Change the shape a document's bytes are drawn in (the pixel format, pixels per row, the first pixel's offset and bit, the padding after each row); what is not given stays as it is. |
| [`view.fold`](#viewfold) | view | Skip ranges of a document in its views (the raster and the hex dump) without deleting them; a marker shows where each was. |
| [`view.unfold`](#viewunfold) | view | Show skipped bytes again: the skipped range starting at an offset, or all of them. |
| [`bookmarks.list`](#bookmarkslist) | read | A document's bookmarks, in offset order. |
| [`bookmarks.add`](#bookmarksadd) | view | Bookmark a byte or a span of a document with a name, replacing a bookmark at the same offset; the window keeps them beside the file. |
| [`bookmarks.remove`](#bookmarksremove) | view | Remove the bookmark at an offset. |
| [`plugins.reload`](#pluginsreload) | view | Load the Lua plugins again from disk, so the detectors, parsers, codecs and methods they register are the ones in their files now; the command line and MCP load them once, when they start. |
| [`sources.watch`](#sourceswatch) | view | Watch the window's file for changes on disk, reloading it and marking what changed, or stop watching it. |
| [`sources.record`](#sourcesrecord) | view | Keep every version of a document as it changes (the window's file or capture as it changes on disk, or after each edit), or stop keeping them. |
| [`sources.stop`](#sourcesstop) | view | Stop the window's serial capture. |
| [`sources.view_version`](#sourcesview_version) | view | Open a recorded version of a document as a document derived from it; the window marks what changed from the version before. |

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

Open a file by path, or an open document by id, and make it current; a file already open is made current again. In the window, a parent of the document shown is gone back to, closing what was derived from it; that, or opening another file, is refused while what it closes has unsaved edits, unless the person at the window discards them.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `discard_unsaved` | boolean | no | In the window, close documents with unsaved edits, losing them, as File › Open and Back do; only the person at the window may. |
| `doc` | string | no | Id of an open document to make current, such as a parent the window derived the document shown from. |
| `path` | string | no | Path of the file to open. |

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

Open a new, empty document and make it current; the window refuses while its document has unsaved edits, unless the person at the window discards them.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `discard_unsaved` | boolean | no | In the window, close documents with unsaved edits, losing them, as File › New does; only the person at the window may. |
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

### documents.derive

Open bytes of a document (a span, several ranges one after another, or bytes given), or what a transform such as decompress or XOR makes of them, as a document of their own derived from it, and make it current; in the window, Back goes back to the parent.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `data` | string | no | The bytes themselves, written as `encoding` says, when they are not in the document as they are (a reassembled stream, say). |
| `doc` | string | no | Document id, path or "current" (the default): the parent. |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How `data` is written: hex (the default), base64 or text. |
| `len` | integer | no | Bytes to open from `start`; to the end of the document when omitted. |
| `name` | string | no | What to call the new document; the parent's name and the span when omitted. |
| `ranges` | array of pair | no | Several spans as [start, len], opened one after another (a selection of several ranges, or several packets). |
| `start` | integer | no | Offset of the first byte to open. |
| `transform` | Operation | no | An operation to apply to each span first, such as {"op": "decompress"} or {"op": "xor", "key": "5a"}. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### documents.export

Write a span of a document to a file, or what decompresses at its start; the document is left as it is.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `decompress` | boolean | no | Write what the first codec that decodes at `start` makes of the bytes, instead of the bytes. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes to write, or to read the compressed stream from (at most 64 MiB); to the end of the document when omitted. |
| `path` | string | yes | The file to write. |
| `start` | integer | yes | Offset of the first byte to write, or of the compressed stream. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `decompressed` | ExportedStream | no | The codec and stream, when the bytes were decompressed. |
| `path` | string | yes | The file written. |
| `written` | integer | yes | Bytes written. |

### documents.open_source

Open a file, URL, block device, serial port (serial:PORT@BAUD) or a process's memory region (pid:PID@ADDRESS) as a new document. The window reads a URL, device or region in the background and opens it when it arrives, and pid:PID lists a process's regions in the Live tab; headless, the bytes are read before the call returns.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `uri` | string | yes | A path, an http(s) URL, a block device (/dev/disk2), serial:PORT@BAUD, pid:PID or pid:PID@ADDRESS. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `document` | DocumentInfo | no | The document opened, when it opened before the call returned. |
| `reading` | boolean | yes | Whether the window is still reading the bytes, and opens them when they arrive. |

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
| `coalesce` | boolean | no | Join the caller's previous step when that step wrote or inserted just the one byte at `start`, so a byte typed as two hex digits undoes as one step. |
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
| `coalesce` | boolean | no | Join the caller's previous step when that step wrote or inserted just the one byte at `at`. |
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

### bytes.move

Cut ranges out and put their bytes, one after another, at an offset counted before the cut, as one undoable step, and select them.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `expect_version` | integer | no | Fail with version_conflict, changing nothing, unless the document is at this version. |
| `ranges` | array of pair | yes | The ranges to move, as [start, len]; their bytes land one after another, in document order. |
| `to` | integer | yes | Where the bytes land, as an offset counted before they are cut out; an offset inside a range lands them where that range began. |

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

### bits.scan_periods

Start a search of a span for bit periods (frames that are not a whole number of bytes) and the sync word of the strongest, comparing the bits with themselves at every lag, as a job: the periods and sync words are job.finished's result, and in the window they fill the Bits panel.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes searched, at most 256 KiB and a quarter of max_period; as many as that from start when omitted. |
| `max_period` | integer | no | Longest period looked for, 8 to 8192 bits (1024 by default). |
| `order` | `"msb"` \| `"lsb"` | no | Which bit of each byte comes first: "msb" (the default) or "lsb". |
| `start` | integer | no | First offset searched (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### bits.planes

Start splitting a span (at most 1 MiB) into its eight bit planes as a job, scoring how much shape each holds with rows of row_width bytes: the scores are job.finished's result, and in the window the planes fill the Bits panel.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes split, at most 1 MiB; to the end of the document (or 1 MiB) when omitted. |
| `row_width` | integer | yes | Bytes per row, 1 to 1024, for scoring each plane by its left and upper neighbours. |
| `start` | integer | no | First offset split (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### bits.open_plane

Open one bit plane of a span (at most 1 MiB) as a derived document: bit k of every byte, as a byte of 0 or 255.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bit` | integer | yes | Which bit, 0 (least significant) to 7. |
| `doc` | string | no | Document id, path or "current" (the default): the parent. |
| `len` | integer | no | Bytes, at most 1 MiB; to the end of the document (or 1 MiB) when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

### bits.detect_linecode

Start trying Manchester (both conventions), differential Manchester, 8b/10b and packed BCD at every bit alignment of a span (at most 64 KiB) as a job: the decodes, fewest invalid symbols first, and any BCD timestamps are job.finished's result, and in the window they fill the Bits panel.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes decoded, at most 64 KiB; to the end of the document (or 64 KiB) when omitted. |
| `order` | `"msb"` \| `"lsb"` | no | Which bit of each byte comes first: "msb" (the default) or "lsb". |
| `start` | integer | no | First offset decoded (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### bits.decode_linecode

Decode a span (at most 64 KiB) from a line code at a bit offset and open the decoded bytes as a derived document.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bit_offset` | integer | no | Bit to start at, 0 to 63 (0 by default). |
| `code` | `"differential_manchester"` \| `"nrzi"` \| `"8b10b"` \| `"gray_byte"` \| `"gray_word"` \| `"packed_bcd"` \| `"manchester_ieee"` \| `"manchester_thomas"` | yes | A line code, as the Bits tool decodes it. |
| `doc` | string | no | Document id, path or "current" (the default): the parent. |
| `len` | integer | no | Bytes decoded, at most 64 KiB; to the end of the document (or 64 KiB) when omitted. |
| `order` | `"msb"` \| `"lsb"` | no | Which bit of each byte comes first: "msb" (the default) or "lsb". |
| `start` | integer | no | First offset decoded (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `document` | DocumentInfo | yes | The derived document the decode was opened as. |
| `errors` | integer | yes |  |
| `symbols` | integer | yes | Symbols read, and the invalid ones among them. |

### bits.rank_field

Rank what a field of records holds (integers, floats, fixed point, timestamps, enums…) by how plausible its values are across the records.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `offset` | integer | yes | Offset of the field within each record. |
| `origin` | integer | yes | Document offset of the first record. |
| `stride` | integer | yes | Bytes per record. |
| `width` | integer | yes | Bytes in the field: 1, 2, 4 or 8. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `readings` | array of FieldReading | yes | The readings, most plausible first. |
| `records` | integer | yes | Records read (at most 4096). |

### bits.find_length_fields

Start a search of a span (at most 256 KiB, one message or a run of records) for numbers that are distances, as a job: length prefixes, tag-length-value chains and offset tables, best first, are job.finished's result, and in the window they fill the Bits panel.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the region, at most 256 KiB; to the end of the document (or 256 KiB) when omitted. |
| `start` | integer | no | First offset of the region (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

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
| `wrap` | boolean | no | When nothing is found before the end (or, backwards, the start), search on from the other end. |

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

### selection.set

Select one range, several ranges or a column of every record in a document, or nothing.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `cursor` | integer | no | Where the cursor goes: the start or end of one of the selected ranges, which is then the range Shift extends from its other end (a column's cursor is at its end); the end of the last range when omitted. With nothing selected, any offset; the cursor stays when omitted. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `selection` | Selection | no | What to select: {"range": [start, len]}, {"ranges": [[start, len], …]} or {"columns": {…}}; null or omitted selects nothing. |

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

### codecs.open_decoded

Decompress the stream starting at an offset, with the first codec that decodes there or the one named, and open what it holds as a document derived from this one; in the window, Back (or opening the parent by id) returns.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `codec` | `"zlib"` \| `"gzip"` \| `"deflate"` \| `"bzip2"` \| `"xz"` \| `"lzma"` \| `"zstd"` \| `"lz4"` | no | The codec to decode with; the first that decodes there when omitted. |
| `doc` | string | no | Document id, path or "current" (the default): the parent. |
| `start` | integer | yes | Offset where the compressed stream starts. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `codec` | `"zlib"` \| `"gzip"` \| `"deflate"` \| `"bzip2"` \| `"xz"` \| `"lzma"` \| `"zstd"` \| `"lz4"` | yes | The codec that decoded the stream. |
| `complete` | boolean | yes | Whether the stream ended cleanly. |
| `consumed` | integer | yes | Input bytes the stream occupied. |
| `document` | DocumentInfo | yes | The document opened, now current. |
| `truncated` | boolean | yes | Whether the output was cut at 64 MiB. |

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

### packets.sets.create

Take a set of packets from a document: a capture in it, a range cut into fixed records, by a length field, at a pattern or with the protocol framing, or the selection's ranges, with how to decode frames of unknown format; returns the set's id and what was worked out (the capture found, the framing), so the call can be made again exactly.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol frames of unknown format are decoded as; detected from a sample of them when omitted (unless `detect` is false). |
| `detect` | boolean | no | Whether to detect the protocol of frames of unknown format when `decode_as` is not given (true by default). |
| `doc` | string | no | Document id, path or "current" (the default). |
| `framing` | Framing | no | For `protocol_framing`: how the range is cut into messages; found by the protocol analysis when omitted. |
| `from` | `"capture"` \| `"split_fixed"` \| `"length_field"` \| `"pattern"` \| `"selection"` \| `"protocol_framing"` | yes | Where the packets come from. |
| `gunzip` | boolean | no | For `capture`: the capture at `start` is compressed with gzip. It is opened decompressed as a document of its own, derived from this one, and the set is taken from there. |
| `len` | integer | no | Bytes in the range; to the end of the document when omitted. |
| `length_field` | LengthFieldSpec | no | For `length_field`: where each frame's length is and what it counts. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | What every packet's first byte is, such as "ethernet" or "raw_ip"; each packet's own (its capture's, or frames of unknown format) when omitted. |
| `pattern` | string | no | For `pattern`: hex bytes with ?? for any byte (`AA 55 ?? 01`), or "text" in double quotes. |
| `pattern_mode` | `"starts_packet"` \| `"ends_packet"` \| `"separates"` | no | For `pattern`: where the pattern goes (it starts each packet by default). |
| `ranges` | array of pair | no | For `selection`: the ranges, each `[start, len]`; the document's selection when omitted. |
| `record_len` | integer | no | For `split_fixed`: bytes per record. |
| `start` | integer | no | Start of the range to split, or a capture's header (the first capture found when omitted); 0 by default. |
| `template` | string | no | Binary template source applied to each frame no protocol reads. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capped` | boolean | yes | Whether the source had more packets than a set holds. |
| `count` | integer | yes | Packets in the set. |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol chosen for frames of unknown format. |
| `description` | string | yes | How the packets were found. |
| `detect` | boolean | yes |  |
| `doc` | string | yes | The document its packets are in. |
| `framing` | Framing | no | The framing that cut the messages, for `protocol_framing`. |
| `from` | `"capture"` \| `"split_fixed"` \| `"length_field"` \| `"pattern"` \| `"selection"` \| `"protocol_framing"` | yes | Where a set's packets come from. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | The link every packet is read as, when one was chosen. |
| `name` | string | yes | Such as "pcap capture at 0x40". |
| `notes` | array of string | no | What the person should know about how the set was taken, such as a decompressed capture cut short. |
| `ranges` | array of pair | yes | Where the packets were taken from, as [start, len], once worked out (a capture found, the selection's ranges). |
| `set` | string | yes | The set's id, such as "set-1", for the other packet methods. |
| `template` | boolean | yes | Whether a template decodes frames no protocol reads. |
| `template_name` | string | no | The template's name when it was chosen by name, or "protocol" for the one the protocol analysis suggested. |

### packets.sets.list

The packet sets made, with their ids, documents, sources, packet counts and decoding.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `sets` | array of SetInfo | yes |  |

### packets.list

A set's packets the display filter keeps, a page at a time: each one's index, offset, length, summary columns, protocols and addresses.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `filter` | string | no | A display filter, as the Packets panel takes: protocol names, addresses, ports, `len > 60`, Wireshark field names and more. |
| `limit` | integer | no | Most packets to return (100 by default). |
| `next` | string | no | The `next` cursor of the previous page. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `detected` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol frames of unknown format were detected as, if they were. |
| `next` | string | no | Pass back as `next` for more; absent after the last. |
| `packets` | array of PacketEntry | yes |  |
| `set` | string | yes |  |
| `total` | integer | yes | Packets the filter keeps. |

### packets.dissect

Dissect one packet of a set into protocol layers and fields, as the set decodes frames of unknown format.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `index` | integer | yes | The packet's index in the set. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `dissection` | DissectionResult | yes | Everything learned from one packet. |
| `index` | integer | yes |  |
| `len` | integer | yes |  |
| `offset` | integer | yes | Document offset of the packet's first byte; layer and field offsets count from it. |

### packets.decode_as

Choose the protocol a set's frames of unknown format are decoded as, or detection, and a template for frames no protocol reads.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `detect` | boolean | no | Whether to detect the protocol when none is given (true by default). |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | What every packet's first byte is, such as "ethernet"; null for each packet's own; omitted, the set's link stays as it is. |
| `protocol` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol frames of unknown format are decoded as; omitted, they are detected (unless `detect` is false). |
| `set` | string | yes |  |
| `template` | string | no | Template source for frames no protocol reads, or "protocol" for the template the protocol analysis suggested for the document; omitted (with no template_name), the set's template is dropped. |
| `template_name` | string | no | A built-in or saved template, by name, for frames no protocol reads. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capped` | boolean | yes | Whether the source had more packets than a set holds. |
| `count` | integer | yes | Packets in the set. |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol chosen for frames of unknown format. |
| `description` | string | yes | How the packets were found. |
| `detect` | boolean | yes |  |
| `doc` | string | yes | The document its packets are in. |
| `framing` | Framing | no | The framing that cut the messages, for `protocol_framing`. |
| `from` | `"capture"` \| `"split_fixed"` \| `"length_field"` \| `"pattern"` \| `"selection"` \| `"protocol_framing"` | yes | Where a set's packets come from. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | The link every packet is read as, when one was chosen. |
| `name` | string | yes | Such as "pcap capture at 0x40". |
| `notes` | array of string | no | What the person should know about how the set was taken, such as a decompressed capture cut short. |
| `ranges` | array of pair | yes | Where the packets were taken from, as [start, len], once worked out (a capture found, the selection's ranges). |
| `set` | string | yes | The set's id, such as "set-1", for the other packet methods. |
| `template` | boolean | yes | Whether a template decodes frames no protocol reads. |
| `template_name` | string | no | The template's name when it was chosen by name, or "protocol" for the one the protocol analysis suggested. |

### packets.export_pcap

A set's packets (those a filter keeps) as a pcap file, returned or written to a path given (which needs leave to edit).

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How the returned file is written: base64 (the default) or hex. |
| `filter` | string | no | Only the packets this display filter keeps. |
| `indices` | array of integer | no | Only these packets, by their index in the set (those of them the filter keeps, when one is given too). |
| `path` | string | no | Write the pcap file here instead of returning it; needs leave to edit, as writing a file does. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `count` | integer | yes | Packets written. |
| `data` | string | no | The file, when no path was given. |
| `len` | integer | yes | Bytes in the pcap file. |
| `path` | string | no | Where it was written, when a path was given. |

### packets.conversations

The conversations in a set (the packets a filter keeps): each pair of endpoints with its transport, packets and bytes each way, and a filter for it.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `filter` | string | no | Only the packets this display filter keeps. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `conversations` | array of ConversationEntry | yes |  |

### packets.follow_stream

The payloads of a packet's conversation in order, each with its direction, and the stream as text.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `index` | integer | yes | The packet's index in the set. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `conversation` | ConversationEntry | no | The conversation followed; absent when the packet has no addresses and ports, and so nothing to follow. |
| `parts` | array of StreamPart | yes | The payloads in order, each with who sent it. |
| `retransmissions` | integer | yes | TCP segments sent again and left out. |
| `text` | string | yes | The whole stream as text, each direction's turns marked. |
| `truncated` | boolean | yes | Whether the stream was longer than is kept. |

### packets.find_captures

The captures inside a span of a document (pcap, pcapng, snoop, Network Monitor or ERF, or one of these compressed with gzip), each with its offset, format, link type and packets, for packets.sets.create.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes looked in; to the end of the document when omitted, at most 128 MiB. |
| `start` | integer | no | First offset looked in (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `captures` | array of CaptureEntry | yes |  |

### packets.sets.add_packets

Add ranges of the document to a set as packets of their own, so packets can be gathered one at a time; the set then keeps its packets where they are.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `ranges` | array of pair | yes | The ranges to add, each `[start, len]`, one packet each. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capped` | boolean | yes | Whether the source had more packets than a set holds. |
| `count` | integer | yes | Packets in the set. |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol chosen for frames of unknown format. |
| `description` | string | yes | How the packets were found. |
| `detect` | boolean | yes |  |
| `doc` | string | yes | The document its packets are in. |
| `framing` | Framing | no | The framing that cut the messages, for `protocol_framing`. |
| `from` | `"capture"` \| `"split_fixed"` \| `"length_field"` \| `"pattern"` \| `"selection"` \| `"protocol_framing"` | yes | Where a set's packets come from. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | The link every packet is read as, when one was chosen. |
| `name` | string | yes | Such as "pcap capture at 0x40". |
| `notes` | array of string | no | What the person should know about how the set was taken, such as a decompressed capture cut short. |
| `ranges` | array of pair | yes | Where the packets were taken from, as [start, len], once worked out (a capture found, the selection's ranges). |
| `set` | string | yes | The set's id, such as "set-1", for the other packet methods. |
| `template` | boolean | yes | Whether a template decodes frames no protocol reads. |
| `template_name` | string | no | The template's name when it was chosen by name, or "protocol" for the one the protocol analysis suggested. |

### packets.sets.refresh

Find a set's packets again, the way they were found, in another document (the current one by default), which the set then belongs to.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | The document to find the packets in: id, path or "current" (the default). |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capped` | boolean | yes | Whether the source had more packets than a set holds. |
| `count` | integer | yes | Packets in the set. |
| `decode_as` | `"ethernet"` \| `"raw_ip"` \| `"dns"` \| `"snmp"` \| `"ntp"` \| `"modbus_tcp"` \| `"mqtt"` \| `"tls"` \| `"dhcp"` \| `"tftp"` \| `"rtp"` \| `"rtcp"` \| `"http"` \| `"dns_over_tcp"` \| `"tpkt"` \| `"nbss"` | no | The protocol chosen for frames of unknown format. |
| `description` | string | yes | How the packets were found. |
| `detect` | boolean | yes |  |
| `doc` | string | yes | The document its packets are in. |
| `framing` | Framing | no | The framing that cut the messages, for `protocol_framing`. |
| `from` | `"capture"` \| `"split_fixed"` \| `"length_field"` \| `"pattern"` \| `"selection"` \| `"protocol_framing"` | yes | Where a set's packets come from. |
| `link` | `"ethernet"` \| `"raw_ip"` \| `"linux_sll"` \| `"linux_sll2"` \| `"bsd_loopback"` \| `"open_bsd_loopback"` \| `"ppp"` \| `"ppp_hdlc"` \| `"ieee80211"` \| `"radiotap"` \| `"unknown"` | no | The link every packet is read as, when one was chosen. |
| `name` | string | yes | Such as "pcap capture at 0x40". |
| `notes` | array of string | no | What the person should know about how the set was taken, such as a decompressed capture cut short. |
| `ranges` | array of pair | yes | Where the packets were taken from, as [start, len], once worked out (a capture found, the selection's ranges). |
| `set` | string | yes | The set's id, such as "set-1", for the other packet methods. |
| `template` | boolean | yes | Whether a template decodes frames no protocol reads. |
| `template_name` | string | no | The template's name when it was chosen by name, or "protocol" for the one the protocol analysis suggested. |

### packets.detect_length_field

Look for a length field that cuts a span into frames, with the protocol analysis's framing detection; returns it as packets.sets.create's length_field, or the best framing found instead.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes in the span; to the end of the document when omitted. |
| `start` | integer | no | First offset (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `best_framing` | string | no | When no length field was found, the best framing found instead. |
| `coverage` | number | yes | Share of the span those frames cover, 0 to 1. |
| `description` | string | no | The field in words, such as "u16 big-endian length at +1". |
| `frames` | integer | yes | Frames the framing that found it cuts. |
| `length_field` | LengthFieldSpec | no | The length field, as packets.sets.create's length_field; absent when none was found. |

### packets.endpoints

The addresses in a set (the packets a filter keeps), busiest first, with the packets and bytes each sent and received.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `filter` | string | no | Only the packets this display filter keeps. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `endpoints` | array of EndpointEntry | yes |  |

### packets.extract

Some of a set's packets' bytes one after another, returned or written to a path given (which needs leave to edit).

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `encoding` | `"hex"` \| `"base64"` \| `"text"` | no | How the returned bytes are written: base64 (the default) or hex. |
| `indices` | array of integer | yes | The packets, by their index in the set, in the order wanted. |
| `path` | string | no | Write the bytes here instead of returning them; needs leave to edit, as writing a file does. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `count` | integer | yes | Packets taken. |
| `data` | string | no | The bytes, when no path was given. |
| `len` | integer | yes | Bytes taken. |
| `path` | string | no | Where they were written, when a path was given. |

### packets.delete

Remove packets from the document (their whole capture records, so a capture stays readable), as one undoable step.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `indices` | array of integer | yes | The packets, by their index in the set. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.fix_checksums

Recompute the IPv4 header, TCP and UDP checksums of some of a set's packets, as one undoable step.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `indices` | array of integer | yes | The packets, by their index in the set. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.apply

Invert, fill or XOR some of a set's packets, or the same field of each, as one undoable step.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `field` | FieldSpan | no | Only this field of each packet; packets too short to hold it are left alone. |
| `indices` | array of integer | yes | The packets, by their index in the set. |
| `key` | string | no | Hex bytes for fill and XOR. |
| `op` | `"invert"` \| `"fill"` \| `"xor"` | yes | An operation on whole packets. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.write_field

Write a value (a number, or hex bytes as wide as the field) into a field of one packet, as one undoable step.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `index` | integer | yes | The packet's index in the set. |
| `len` | integer | yes |  |
| `little_endian` | boolean | no | Write a number least significant byte first (big-endian, network order, by default). |
| `offset` | integer | yes | Where the field is, from the packet's first byte. |
| `set` | string | yes |  |
| `value` | string | yes | A whole number (decimal or 0x hex), an IPv4 or IPv6 address, a MAC address, or exactly len hex bytes. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.columns.apply

Change the same columns (byte offsets) of every packet, or of some, laid out one packet per row: invert, fill, XOR, add, set, number or swap the byte order, as one undoable step.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `first` | integer | yes |  |
| `group` | integer | no | For swap: bytes in each group reversed (2, 4 or 8). |
| `indices` | array of integer | no |  |
| `key` | string | no | Hex bytes for fill, XOR and add. |
| `little_endian` | boolean | no | For set and counter: write numbers least significant byte first. |
| `op` | `"invert"` \| `"fill"` \| `"xor"` \| `"add"` \| `"set"` \| `"counter"` \| `"swap"` | yes | What a column operation does. |
| `record_headers` | boolean | no |  |
| `set` | string | yes |  |
| `shifts` | array of integer | no |  |
| `start` | integer | no | For counter: the first packet's number (0 by default). |
| `step` | integer | no | For counter: added for each packet after (1 by default). |
| `value` | string | no | For set: a number, or exactly as many hex bytes as columns. |
| `width` | integer | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.columns.delete

Remove the same columns (byte offsets) from every packet, or from some, as one undoable step; length fields and checksums are not changed.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `first` | integer | yes | The first column, a byte offset into each row. |
| `indices` | array of integer | no | Only these packets, by their index in the set, in row order; every packet when omitted. |
| `record_headers` | boolean | no | Rows start at each packet's capture record header rather than its data. |
| `set` | string | yes |  |
| `shifts` | array of integer | no | How far each row is shifted right to line the rows up, one per packet in `indices` (or per packet of the set); none by default. |
| `width` | integer | yes | Columns, at least 1. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bytes_removed` | integer | yes | Bytes removed from the document. |
| `checksums` | array of string | yes | For packets.fix_checksums: each checksum rewritten, such as "UDP". |
| `doc` | string | yes | Id of the document edited. |
| `label` | string | no | What the step is called in the undo history; absent when nothing needed changing. |
| `len` | integer | yes |  |
| `packets` | integer | yes | Packets changed. |
| `ranges` | array of pair | yes | The document ranges changed, as [start, len]. |
| `version` | integer | yes | The document's version and length after the change. |

### packets.columns.read

The same columns (byte offsets) of every packet, or of some, as hex lines or CSV.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `first` | integer | yes |  |
| `format` | `"hex"` \| `"csv"` | no | How columns are written as text. |
| `indices` | array of integer | no |  |
| `record_headers` | boolean | no |  |
| `set` | string | yes |  |
| `shifts` | array of integer | no |  |
| `width` | integer | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `left_out` | integer | yes | Packets that reach the columns but were left out, past 16 MiB. |
| `packets` | integer | yes | Packets written. |
| `text` | string | yes |  |

### packets.tshark_decode

Have Wireshark's tshark decode some of a set's packets (run locally with -n) as a background job; the protocols it named are the job's result, and in the window its layers merge into the Packets panel's.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `filter` | string | no | Only the packets this display filter keeps. |
| `indices` | array of integer | no | Only these packets, by their index in the set; every packet (those the filter keeps) when omitted, at most 5,000. |
| `mode` | `"fill_gaps"` \| `"everything"` | no | How tshark's layers go with ours. |
| `set` | string | yes |  |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

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

### analysis.period_scan

Start a scan of a window of bytes for repeating periods (record widths) as a background job; the periods found, best first, are job.finished's result, and in the window they fill the structure chart and are published on record_width.estimated.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes scanned (192 KiB by default, at most 16 MiB). |
| `max_period` | integer | no | Longest period looked for, 2 to 16384 (4096 by default). |
| `start` | integer | no | First offset of the window scanned (0 by default; the window uses the view's origin). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

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

### statistics.analyse

Start the Statistics tool's measure of a span (at most 64 MiB) as a job: the ent randomness tests with a verdict, the byte histogram, entropy and compressibility along the span and the most repeated byte sequences are job.finished's result, and in the window they fill the Statistics tab.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes measured, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `start` | integer | no | First offset measured (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### strings.find

Start the Strings tool's search of a span (at most 64 MiB) for runs of text at least min_chars long in the encodings chosen, as a job: the strings found (at most 200000), each with its offset, length, encoding, text and what it looks like (a URL, a path, a key…), are job.finished's result, and in the window they fill the Strings tab.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `encodings` | array of `"ascii"` \| `"utf8"` \| `"utf16le"` \| `"utf16be"` | no | The encodings looked for (ascii, utf8 and utf16le by default). |
| `len` | integer | no | Bytes searched, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `min_chars` | integer | no | Fewest characters in a string, 2 to 256 (6 by default). |
| `start` | integer | no | First offset searched (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### xor.recover_keys

Recover single-byte and repeating XOR keys for a span (at most 1 MiB) by letter frequency, index of coincidence and the key showing through zero padding, best first, with a preview of each decode and the likely key lengths; transform.apply with {"op": "xor"} applies one.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes searched, at most 1 MiB; to the end of the document (or 1 MiB) when omitted. |
| `max_key` | integer | no | Longest key looked for, 1 to 256 bytes (32 by default). |
| `start` | integer | no | First offset of the suspect bytes (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `candidates` | array of KeyCandidate | yes | The keys proposed, best first. |
| `key_lengths` | array of KeyLength | yes | The likely key lengths, best first. |
| `len` | integer | yes | Bytes searched. |
| `start` | integer | yes | First offset searched. |

### checksums.digests

The digests of a span (at most 64 MiB): CRC-32, Adler-32, MD5, SHA-1, SHA-256, the 8- and 16-bit sums and the XOR of every byte.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes digested, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `start` | integer | no | First offset digested (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `adler32` | string | yes |  |
| `crc32` | string | yes |  |
| `len` | integer | yes |  |
| `md5` | string | yes |  |
| `sha1` | string | yes |  |
| `sha256` | string | yes |  |
| `start` | integer | yes |  |
| `sum16` | string | yes |  |
| `sum8` | string | yes |  |
| `xor8` | string | yes |  |

### checksums.find_stored

Find a CRC, Adler or sum stored in a span (at most 64 MiB) that covers part of it, testing header and trailer fields, and the fields at the boundaries given, against the bytes before, after and around them.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `boundaries` | array of integer | no | Document offsets where known fields start or end (the window passes those of the findings in the span), also tested as stored values and as the edges of covered ranges. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes searched, at most 64 MiB; to the end of the document (or 64 MiB) when omitted. |
| `start` | integer | no | First offset searched (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `len` | integer | yes |  |
| `matches` | array of StoredChecksum | yes | The checksums that match, in the order found. |
| `start` | integer | yes |  |

### checksums.solve_crc

Start the CRC solver on records of equal length that each carry a stored CRC, as a job: every polynomial, init, xorout and reflection that reproduces all the stored values (like reveng), with the closest catalogue algorithm, is job.finished's result, and in the window it fills the CRC solver.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `count` | integer | yes | Records, at least 2; the first 256 are solved. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `offset` | integer | no | Offset of the CRC within each record, covering the bytes before it; the last bytes of each record when omitted. |
| `order` | `"big"` \| `"little"` \| `"either"` | no | Byte order of the stored CRC (either, by default). |
| `record_len` | integer | yes | Bytes in each record, CRC included. |
| `start` | integer | yes | Document offset of the first record. |
| `try_skips` | boolean | no | Also try leaving up to 4 leading bytes of each record out of the CRC. |
| `width` | integer | no | Bits in the CRC: 8, 16 (the default) or 32. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### diff.run

Start a comparison of a document with another file as a job: the regions replaced, only in the document and only in the other file (inserted, deleted and changed, not just flipped bytes), with the bytes equal and changed, are job.finished's result, and in the window they fill the Diff tab and are outlined on the views.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `path` | string | yes | The file to compare it with. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### disasm.set_arch

Choose the architecture the Disassembly tab decodes as, or auto (the executable header's, else a guess from the bytes); headless there is no listing to change, and the choice is only returned.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `arch` | `"x86_64"` \| `"x86_32"` \| `"arm64"` \| `"arm32"` \| `"thumb"` \| `"riscv64"` \| `"riscv32"` \| `"mips32"` \| `"powerpc32"` \| `"auto"` | yes | The architecture, such as "thumb" or "x86_64", or "auto". |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `arch` | `"x86_64"` \| `"x86_32"` \| `"arm64"` \| `"arm32"` \| `"thumb"` \| `"riscv64"` \| `"riscv32"` \| `"mips32"` \| `"powerpc32"` \| `"auto"` | yes | The architecture chosen. |
| `shown` | boolean | yes | Whether a Disassembly tab was there to change (only in the window). |

### crypto.scan_constants

Start a scan of the whole document (an edited one's first 256 MiB) for well-known constants of crypto and compression code (AES S-boxes, hash initial values, CRC tables, deflate tables, Blowfish, DES, ChaCha, TEA, curve primes, Base64 alphabets) as a job: the matches are job.finished's result, and in the window they fill Crypto constants.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### crypto.repeated_blocks

Start a search of a span (at most 16 MiB) for random-looking 8- and 16-byte blocks that repeat, the mark of ECB-mode encryption, as a job: the verdict, the best block size and alignment, the most repeated blocks and the repeats along the span are job.finished's result, and in the window they fill the Crypto panel.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes searched; to the end of the document, or the search's limit, when omitted. |
| `start` | integer | no | First offset searched (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### crypto.find_keys

Start a search of a span (the whole document by default, at most 64 MiB) for PEM blocks, DER certificates and keys, OpenSSH keys and random-looking runs that could be raw symmetric keys, as a job: what was found is job.finished's result, and in the window it fills the Crypto panel.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes searched; to the end of the document, or the search's limit, when omitted. |
| `start` | integer | no | First offset searched (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### crypto.attack

Start attacks on simple ciphers over a span (at most 1 MiB): rolling XOR, XOR with the previous byte, ADD/SUB with a constant or repeating key, bit rotation, XOR combined with ADD and, with a crib, crib dragging, as a job: the decodes that look most like text or structured data are job.finished's result, and in the window they fill the Crypto panel.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `crib` | string | no | Known plaintext to drag across the data, as text with \xHH escapes, such as "PK\x03\x04". |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes decoded, at most 1 MiB; to the end of the document (or 1 MiB) when omitted. |
| `start` | integer | no | First offset of the suspect bytes (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### compare.variation

Start comparing a document with other files byte position by byte position, each from its own start offset, as a job: the regions that are constant, vary (and how many values) or move one way through the files like a counter are job.finished's result, and in the window they fill Compare.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default): the first file. |
| `files` | array of CompareFileParam | yes | The other files, at most 31; the first 64 MiB of each is read. |
| `start` | integer | no | Offset in the document that lines up with the files' starts (0 by default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### compare.correlate

Start a search of a document and other files for fields whose values follow a number known for each file (a temperature, a setting), as a job: the fields, best fit first, with the fitted line, are job.finished's result, and in the window they fill Compare.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default): the first file. |
| `files` | array of CompareFileParam | yes | The other files, at most 63. |
| `from` | integer | no | Where the search starts, from each file's start (0 by default); 256 KiB are searched. |
| `start` | integer | no | Offset in the document that lines up with the files' starts (0 by default). |
| `values` | array of number | yes | The number known for each file, the document's first: one more than the files. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### compare.timeline

Start building the change timeline of the recording of a live source or watched file, as a job: where and how often it changed, snapshot by snapshot, is job.finished's result, and the window fills Compare with it; only the window records, so headless there is none.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Follow it with jobs.status, or on job.progress and job.finished. |

### view.get_shape

The shape a document's bytes are drawn in: the pixel format, pixels per row, the offset of the first pixel, a bit shift and the bytes skipped after each row.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `shape` | ViewShape | yes | The shape its bytes are drawn in now. |

### view.set_shape

Change the shape a document's bytes are drawn in (the pixel format, pixels per row, the first pixel's offset and bit, the padding after each row); what is not given stays as it is.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `bit_offset` | integer | no | Extra bit shift after `offset`, 0 to 7. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `format` | `"bit1"` \| `"bit1lsb"` \| `"nibble4"` \| `"gray8"` \| `"class"` \| `"rgb565"` \| `"gray16le"` \| `"gray16be"` \| `"rgb8"` \| `"bgr8"` \| `"rgba8"` \| `"bgra8"` \| `"u16le"` \| `"u16be"` \| `"i16le"` \| `"i16be"` \| `"u32le"` \| `"u32be"` \| `"i32le"` \| `"i32be"` \| `"f32le"` \| `"f32be"` | no | How bytes are read as pixels, such as "gray8", "rgb565" or "bit1". |
| `offset` | integer | no | Document offset of the first pixel; at most the document's length. |
| `row_padding` | integer | no | Bytes skipped after each row's pixels. |
| `width` | integer | no | Pixels per row, 1 to 16384. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `shape` | ViewShape | yes | The shape its bytes are drawn in now. |

### view.fold

Skip ranges of a document in its views (the raster and the hex dump) without deleting them; a marker shows where each was.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `ranges` | array of pair | yes | The spans to skip, as [start, len]; they join spans already skipped that they touch. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `folds` | array of pair | yes | Every span skipped now, as [start, len] in document order. |

### view.unfold

Show skipped bytes again: the skipped range starting at an offset, or all of them.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `all` | boolean | no | Show every skipped range again. |
| `doc` | string | no | Document id, path or "current" (the default). |
| `start` | integer | no | Where the skipped range to show again starts. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | yes | Id of the document. |
| `folds` | array of pair | yes | Every span skipped now, as [start, len] in document order. |

### bookmarks.list

A document's bookmarks, in offset order.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bookmarks` | array of BookmarkInfo | yes | Its bookmarks now, in offset order. |
| `doc` | string | yes | Id of the document. |

### bookmarks.add

Bookmark a byte or a span of a document with a name, replacing a bookmark at the same offset; the window keeps them beside the file.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `len` | integer | no | Bytes the bookmark covers; 0 marks just the offset. |
| `name` | string | yes | What to call it. |
| `start` | integer | yes | Offset of the bookmarked byte or span. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bookmarks` | array of BookmarkInfo | yes | Its bookmarks now, in offset order. |
| `doc` | string | yes | Id of the document. |

### bookmarks.remove

Remove the bookmark at an offset.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `start` | integer | yes | Offset of the bookmark to remove. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `bookmarks` | array of BookmarkInfo | yes | Its bookmarks now, in offset order. |
| `doc` | string | yes | Id of the document. |

### plugins.reload

Load the Lua plugins again from disk, so the detectors, parsers, codecs and methods they register are the ones in their files now; the command line and MCP load them once, when they start.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `message` | string | yes | What happened, as the status bar says it. |

### sources.watch

Watch the window's file for changes on disk, reloading it and marking what changed, or stop watching it.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `enabled` | boolean | yes | On or off. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capturing` | boolean | yes | Whether a serial capture is receiving. |
| `reading` | boolean | yes | Whether bytes asked for (a URL, a device, a process region) are still being read. |
| `recording` | boolean | yes | Whether versions of the document are being recorded. |
| `versions` | integer | yes | Versions recorded so far. |
| `watching` | boolean | yes | Whether the window's file is watched for changes. |

### sources.record

Keep every version of a document as it changes (the window's file or capture as it changes on disk, or after each edit), or stop keeping them.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `enabled` | boolean | yes | On or off. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capturing` | boolean | yes | Whether a serial capture is receiving. |
| `reading` | boolean | yes | Whether bytes asked for (a URL, a device, a process region) are still being read. |
| `recording` | boolean | yes | Whether versions of the document are being recorded. |
| `versions` | integer | yes | Versions recorded so far. |
| `watching` | boolean | yes | Whether the window's file is watched for changes. |

### sources.stop

Stop the window's serial capture.

Parameters: None.

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `capturing` | boolean | yes | Whether a serial capture is receiving. |
| `reading` | boolean | yes | Whether bytes asked for (a URL, a device, a process region) are still being read. |
| `recording` | boolean | yes | Whether versions of the document are being recorded. |
| `versions` | integer | yes | Versions recorded so far. |
| `watching` | boolean | yes | Whether the window's file is watched for changes. |

### sources.view_version

Open a recorded version of a document as a document derived from it; the window marks what changed from the version before.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `doc` | string | no | Document id, path or "current" (the default). |
| `index` | integer | yes | The version, counting from 0 for the first one recorded. |

| Result field | Type | Required | Description |
| --- | --- | --- | --- |
| `current` | boolean | yes | Whether this is the current document. |
| `id` | string | yes | Stable id, such as "doc-1". |
| `len` | integer | yes | Length in bytes. |
| `modified` | boolean | yes | Whether there are edits not saved. |
| `name` | string | yes | File name, or the name of a derived document. |
| `path` | string | no | Path on disk, for documents opened from a file. |
| `version` | integer | yes | Incremented on every edit. |

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
