# theviewer data API, version 1.0

<!-- Generated from the method table in src/api.rs by `cargo run --bin api_docs`. Do not edit by hand. -->

Every method can be called from the command line (`theviewer api METHOD '{json params}' FILE`), and Ask uses the read methods as its tools. Documents are named by id (`doc-1`), by path or as `"current"`, which an omitted `doc` also means. Spans are `start` and `len` in bytes; an omitted `len` runs to the end of the document. Bytes are hex strings unless `encoding` says `base64` or `text`. List methods take `limit` and return `next`, a cursor to pass back for the next page. One call reads or returns at most 16 MiB.

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
| [`bytes.read`](#bytesread) | read | Read a span of bytes, as hex by default, or as base64 or text. |
| [`bytes.hexdump`](#byteshexdump) | read | A classic hex dump of a span, 16 bytes per line with an ASCII column, at most 1 MiB. |
| [`bits.read`](#bitsread) | read | Read a span of bits, most or least significant bit of each byte first, as a string of 0s and 1s and, up to 64 bits, as a number. |
| [`search.find`](#searchfind) | read | The next (or previous) occurrence of hex bytes, text, UTF-16 text or an integer from an offset. |
| [`search.find_all`](#searchfind_all) | read | Every occurrence of hex bytes, text, UTF-16 text or an integer in the document, a page at a time. |
| [`search.count`](#searchcount) | read | How many times hex bytes, text, UTF-16 text or an integer occur in the document, up to a cap. |
| [`numbers.decode`](#numbersdecode) | read | Read the bytes at an offset as integers, floats, fixed-point numbers and timestamps of each width and byte order. |
| [`selection.get`](#selectionget) | read | What is selected in a document: one range, several ranges or a column of every record. |
| [`cursor.get`](#cursorget) | read | The cursor's offset in a document. |
| [`findings.query`](#findingsquery) | read | Run the detectors over a span and list what they recognise (signatures, compressed streams, counters, timestamps, text, structures), filtered by category, confidence and producer. |
| [`structure.parse`](#structureparse) | read | Parse the structure starting exactly at an offset (executables, images, archives, captures, ASN.1, filesystems) into a field tree, best match first. |
| [`structure.parsers`](#structureparsers) | read | The structure parsers available, built in and from plugins. |
| [`templates.list`](#templateslist) | read | The binary templates available: the built-in ones and the user's own. |
| [`templates.apply`](#templatesapply) | read | Apply a binary template, by name or as source text, at an offset and return its field tree and records, without pinning it. |
| [`codecs.list`](#codecslist) | read | The codecs available for decoding, built in and from plugins. |
| [`codecs.detect`](#codecsdetect) | read | The codecs whose header starts at an offset. |
| [`codecs.decode`](#codecsdecode) | read | Decode (decompress) a span with a codec and return the output. |
| [`codecs.probe`](#codecsprobe) | read | Try every built-in decompressor at the start of a span, headerless ones included, and list those that decode. |
| [`packets.dissect_bytes`](#packetsdissect_bytes) | read | Dissect one packet, from a span or from hex bytes, into protocol layers and fields, a summary and its flow. |
| [`packets.detect_frames`](#packetsdetect_frames) | read | Find the protocol a set of frames of unknown format is, by trying every frame decoder on them. |
| [`analysis.overview`](#analysisoverview) | read | Map the whole document: a summary of what it is, its regions with offsets, likely record widths and confident findings. |
| [`analysis.statistics`](#analysisstatistics) | read | Measure a span: entropy, chi-square, serial correlation, printable, zero and high-byte fractions, distinct values and a verdict. |
| [`analysis.segments`](#analysissegments) | read | Split the document into regions of one kind (text, tables, code, compressed, random, padding) and group them into types. |
| [`analysis.compressibility`](#analysiscompressibility) | read | Compress a span with several codecs and report the ratios, with a verdict: encrypted or random, already compressed, lossy media or structured. |
| [`analysis.text_encoding`](#analysistext_encoding) | read | Identify the character encoding of a span of text, with previews and the likely language. |
| [`analysis.processor`](#analysisprocessor) | read | Test whether a span is machine code, and for which processor, by disassembling samples for each architecture. |
| [`reference.lookup`](#referencelookup) | read | The reference notes on a format or protocol, by id, finding id, layer name, port (udp/67) or number (port, IP protocol or EtherType): layout, field meanings and specifications. |
| [`reference.search`](#referencesearch) | read | Reference entries whose notes mention every word of a query, or that a port or number names. |
| [`events.facts`](#eventsfacts) | read | What the tools have learnt about a document and keep: the latest fact per topic, producer and key, by topic, producer or the bytes they cover, each marked stale when the document changed under it. |
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

Apply a binary template, by name or as source text, at an offset and return its field tree and records, without pinning it.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `at` | integer | no | Offset the template's root starts at (0 by default). |
| `doc` | string | no | Document id, path or "current" (the default). |
| `limit` | integer | no | Most records to return (100 by default). |
| `name` | string | no | A template from templates.list. |
| `next` | string | no | The `next` cursor of the previous page of records. |
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
| [`selection.changed`](#selectionchanged) | event | What is selected changed, in the main view or by a tool selecting bytes in the document. |
| [`findings.published`](#findingspublished) | fact | What one producer recognises in the document: the scan, signatures, templates, the structure map, crypto constants, a comparison, checksums or protocol messages. |
| [`structure.identified`](#structureidentified) | fact | A structure parsed at the cursor, or a template applied, with its field tree. |
| [`regions.mapped`](#regionsmapped) | fact | The file split into regions of one kind, from the report. |
| [`record_width.estimated`](#record_widthestimated) | fact | The length of the records the data repeats in, from the period scan. |
| [`frames.defined`](#framesdefined) | fact | Message or packet boundaries: from the protocol framing, a capture or the packet viewer's splitting rules. |
| [`protocol.identified`](#protocolidentified) | fact | The protocol a set of frames or a payload is, and how that was decided. |
| [`reference.focus`](#referencefocus) | event | A tool asks the Reference tab to show a format or protocol. |
| [`job.started`](#jobstarted) | event | Background work started. |
| [`job.finished`](#jobfinished) | event | Background work finished, with a one-line outcome. |
| [`plugin.log`](#pluginlog) | event | A plugin logged a line, or one of its callbacks failed (in a background scan, say). |

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
| `origin` | string | yes | How they were found, such as "length prefix u16be" or "pcap capture at 0x40". |
| `total` | integer | yes | How many frames there are in all. |

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

### job.started

Background work started.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | Unique for the session, such as "period-scan-3". |
| `title` | string | yes | What the job does, such as "Period scan". |

### job.finished

Background work finished, with a one-line outcome.

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `job` | string | yes | The id `job.started` gave. |
| `ok` | boolean | yes | Whether it produced a result. |
| `outcome` | string | yes | One line on what it found, or why it stopped. |
| `title` | string | yes |  |

### plugin.log

A plugin logged a line, or one of its callbacks failed (in a background scan, say).

| Payload field | Type | Required | Description |
| --- | --- | --- | --- |
| `level` | `"info"` \| `"error"` | yes | `error` for a failed callback, `info` for a line the plugin logged. |
| `plugin` | string | yes | The plugin's file name, such as `modbus_rtu.lua`. |
| `text` | string | yes |  |
