# Packets

The **Packets** tab is a packet viewer for captures and message streams.
It lists packets, dissects them layer by layer, filters them, follows
conversations, and lets you edit them in place. It sits beside the main
view, and follows the same selection.

![The Network capture layout: the packet list with a DNS packet dissected, the Reference tab and the hex dump](../images/packets.png)

- [Where packets come from](#where-packets-come-from)
- [Splitting frames out of a file](#splitting-frames-out-of-a-file)
- [What is dissected](#what-is-dissected)
- [Decode frames as](#decode-frames-as)
- [Filters](#filters)
- [Packets as rows: the raster and hex grids](#packets-as-rows-the-raster-and-hex-grids)
- [Editing packets](#editing-packets)
- [Conversations, endpoints and streams](#conversations-endpoints-and-streams)
- [More protocols with tshark](#more-protocols-with-tshark)
- [Export](#export)

## Where packets come from

Open it from *Tools › Packet viewer*, *Open in packet viewer* in the
Protocol tab or the findings list, *Open type N in packet viewer* in the
Protocol tab's *Align messages*, or *Packets* in the right-click menu. The *Network capture* layout puts it in front, and
`--tool packets` opens it with the first capture loaded.

A set of packets can come from:

- **A capture in the file.** *Find captures* lists pcap, pcapng, Sun snoop
  (RFC 1761), Microsoft Network Monitor 2.x and Endace ERF captures found
  anywhere in the document, and captures compressed whole with gzip (read
  from a decompressed copy of at most 128 MiB).
- **The protocol framing.** *From protocol framing* takes the messages the
  [Protocol tool](tools.md#protocol) split out, with its field
  guesses.
- **The selection.** *From the selection* offers *Selection as one
  packet*, *Split by row width* (each record a packet), *Split by length*
  and *Split by delimiter*. The right-click menu's *Packets* has *Add
  selection as packet* and *Split selection by row width*.
- **A split.** Any range cut into frames; see below.

Captures may use Ethernet, raw IP, Linux cooked capture, BSD and OpenBSD
loopback, PPP, Cisco HDLC, 802.11 with or without radiotap, and LLC/SNAP on
802.3 frames.

## Splitting frames out of a file

*Split into frames* cuts the selection, or the whole document, into frames,
optionally skipping some bytes first:

- **Fixed width:** every frame the same length.
- **Length field:** where it sits, its width (u8, u16, u32 or LEB128) and
  byte order, whether it counts the whole frame, the bytes after it or the
  payload after a header, a constant to add, and the longest frame to
  believe. *Auto-detect* fills these in from
  the protocol tool.
- **Pattern:** bytes such as `AA 55 ?? 01`, `0D 0A` or `"GET "` (`??` is
  any byte) that start each frame, end it, or sit between frames.

The frame count and the shortest, mean and longest lengths are shown.

## What is dissected

Each packet is dissected into layers with every field at its bytes:
Ethernet, VLAN, ARP, IPv4, IPv6 (with its extension headers), ICMP and
ICMPv6 (with the packet an error quotes, and neighbour discovery), TCP, UDP,
DNS (with authority, additional and EDNS records), HTTP, NTP, Modbus/TCP,
MQTT, SNMP v1, v2c and v3, DHCP and BOOTP, TFTP (following each transfer to
its new ports), TPKT with COTP and S7comm, the NetBIOS session service with
SMB1 and SMB2/3, and RTP and RTCP. Split frames can also be read as TLS
records, through [Decode frames as](#decode-frames-as). The first fragment
of a fragmented IP packet is shown as fragment data, with a note.

Selecting a packet or a field selects its bytes in the view, and moving the
cursor in the view into a packet selects that packet and the field under
the cursor. Pointing at a field explains it from the [reference
notes](reference-notes.md); its *Reference* button opens the Reference tab
on that layer, and picking a layer turns the tab to it.

## Decode frames as

Frames split from the file, taken from the protocol framing or added from
the selection carry no link type and no ports, so nothing says what they
are. The packet viewer finds out.

It tries each of its decoders (Ethernet, raw IP, DNS, DNS with a TCP length
prefix, SNMP, NTP, Modbus/TCP, MQTT, TLS records, DHCP, TFTP, TPKT with COTP
and S7comm, the NetBIOS session service with SMB, RTP, RTCP and HTTP) on up
to 64 frames spread through the set. It decodes the frames as the one that
reads at least 80% of them (and at least two) from first byte to nearly the
last.

- A decoder that only reads a short prefix of each frame does not count.
- The looser protocols (MQTT, NTP, TFTP, RTP) must also show values real
  traffic has, and are never taken from a single frame.
- A set of one frame is taken only when it is read to its last byte.
- When nothing fits, the frames keep their field guesses.

The status line above the list says what happened, such as *decoded as DNS
(detected, 61 of 64 sampled)*.

The *Decode frames as* choice overrides it for the set: *Auto*, any
protocol by name, *Field guesses*, or a template. A frame the chosen
protocol does not read falls back to the template or the field guesses,
with a note, and the status line counts how many were read and what
detection would have picked. Decoded frames are listed, filtered and
explained like the same protocol on its port: `dns.qry.name~example` finds
DNS messages split from a file.

Turn off *Detect the protocol of split frames* in Settings to start every
set on its field guesses instead; *Detect now* in the choice then runs
detection for that set. The Protocol tab also says when the messages its
framing found are a protocol the packet viewer dissects.

## Filters

Type a filter and press *Filter*. A filter is a list of terms separated by
spaces, and a packet must match them all:

| Term | Shows packets that… |
| --- | --- |
| `tcp`, `dns`, `arp` … | contain that protocol |
| `proto:dhcp` | contain that protocol, by our name or tshark's filter name |
| `port:53` | use that port at either end |
| `ip:10.0.0.2` | come from or go to that address |
| `len>60` (also `<`, `>=`, `<=`, `=`) | have that many bytes |
| `hex:DEADBEEF` | contain those bytes |
| `ip.ttl==64` (also `!=`, `<`, `<=`, `>`, `>=`) | have a field, by its Wireshark name, with that value |
| `dns.qry.name~example` | have a field that contains that text (`~` means contains) |
| `ip.ttl` | have that field at all |
| any other word | mention it in their summary, ignoring case |

Wireshark field names reach our own fields through the Wireshark names in
the [reference notes](reference-notes.md#wireshark-names), and tshark's
fields directly once packets are decoded with it.

## Packets as rows: the raster and hex grids

Show the packets as a list, or as a *Raster* or *Hex* grid with one packet
per row, so fields line up in columns.

- *Raster* draws each packet as one row of pixels (byte class or a palette,
  any pixel size, hex inside the pixels when zoomed in if you want it).
  *Hex* writes the same rows as hex, with ASCII beside them.
- Rows can be aligned on the packet start, a pattern, or the packet's end.
- A strip above the columns marks each byte offset by kind, as the
  [Columns tool](finding-structure.md#columns) does: constant, counter,
  rising, few values, text, random or mixed.
- Once the frames are decoded as a protocol, hovering a column or a byte
  names the field it holds (*Transaction ID (DNS)*), and a selection of
  columns lists the fields it spans.

Click a byte to select it in the view. Drag across packets to select a
block (a range of packets by a range of byte offsets), or click the ruler
(or `Alt`+click) to select whole columns. Then invert, fill, XOR, add to,
set, number, byte-swap, copy (as hex or CSV) or delete those bytes in every
packet of the selection at once, as one undoable edit.

## Editing packets

Edit a packet in its hex dump, or click a field and type a new value
(ports, lengths, addresses, flags). *Fix checksums* then recomputes the
IPv4, TCP and UDP checksums.

Select several packets with `Shift` or `Cmd`+click to delete them (a
capture's records go with them, so it stays readable), save their bytes,
open them as a document, or invert, fill or XOR them, whole or one field in
each.

Every change is an ordinary edit you can undo. The list is found and
dissected again a moment after any edit, wherever it was made.

## Conversations, endpoints and streams

*Conversations* lists each pair of endpoints with its packets and bytes;
*Follow* shows only that conversation's packets. *Endpoints* lists every
address. *Follow stream* shows the payloads of both directions in order,
as text or hex; *Copy as text* copies them and *Open as document* opens
them as a document of their own.

## More protocols with tshark

theviewer does not need Wireshark, but when it is installed, *Decode with
tshark* hands the shown packets (or, from the detail view, one packet) to
its command-line dissector, tshark. tshark's layers are added where ours
stop: a Kerberos, LDAP or X11 packet that we list as UDP or TCP payload
gains its own layer, with every field at its exact bytes. Pointing at or
clicking a field selects it in the view, and the Reference tab follows it
like any other layer. Such layers carry a small *tshark* tag; the packet
list shows tshark's protocol, and `proto:dhcp` filters by any protocol
tshark named. Where our dissector found no addresses, tshark's IP, TCP and
UDP fields fill in the source, destination and flow.

*Use tshark for everything* shows tshark's layers in place of ours.

**What runs, and when.** tshark runs on this computer only, always with
`-n` (no name lookups), on a temporary pcap of the packets, in the
background with a time limit and a *Cancel* button. It never runs unless
you click the button or turn on *Use tshark when installed* in Settings,
where you can also say where tshark is when it is not on the `PATH` or in
the usual install locations. Results are dropped when the document is
edited.

## Export

*Export pcap…* saves the shown packets as a pcap file Wireshark opens, or
only the selected ones when several are selected.
*Save bytes…* saves the selected packets' bytes, and *Open as document*
opens them as a document of their own. With a field chosen in the detail
and *only the chosen field* ticked, both take just that field from each
packet, one after another, cut short where a packet ends: choose a TFTP
data block's data, select every data packet, and *Open as document*
reassembles the file that was sent.
