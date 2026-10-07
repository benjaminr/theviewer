# Reference notes

You do not need a specification open beside you. The **Reference** tab
says what the bytes at the cursor are, how that format is organised, what
each field means, and which RFC or document defines it. Its notes cover
about 260 file formats, protocols, capture formats and streams.

![The Reference tab with the cursor in a DNS message: the path pcap › Ethernet › IPv4 › UDP › DNS, and the header drawn as an RFC-style diagram](../images/reference.png)

- [What the tab shows](#what-the-tab-shows)
- [Reading the RFC](#reading-the-rfc)
- [Guesses from the port](#guesses-from-the-port)
- [Browsing every note](#browsing-every-note)
- [Wireshark names](#wireshark-names)
- [Your own notes](#your-own-notes)
- [Checking the citations](#checking-the-citations)

## What the tab shows

The tab lists every known format enclosing the cursor, outermost first, as
a path you can click. Inside a DNS packet of a capture it reads *pcap
capture › Ethernet › IPv4 › UDP › DNS*. For the chosen format it shows:

- how the data is organised, and which formats it carries;
- the specifications that define it, linked to the RFC or document section;
- an RFC-style diagram of the header, 32 bits a row, each field a box over
  its bytes;
- a table of this instance's fields, with offset, length, current value and
  what the field means.

Pointing at a row or a box outlines its bytes in the view; clicking selects
them.

The same explanations appear when you point at fields in the Inspector's
structure tree and in [Packets](packets.md). Their *Reference* buttons open
the tab on that format, and picking a layer in Packets turns the tab to
it. *Ask* is sent the notes on the formats at the cursor too, and can look
up any other format's notes, by name or by port (`udp/67`, or just `502`).

## Reading the RFC

*Show §3.1* (or *Show RFC*) fetches that section of the RFC from the RFC
Editor and shows it in the tab. Nothing is fetched until you click. The
text is kept in `~/.cache/theviewer/rfc`, so it is read from there next
time.

## Guesses from the port

When a packet's payload is not dissected, the tab still names what it
probably is, from the port (or the EtherType, or the IP protocol number)
the notes list for each protocol. An SSH packet's encrypted payload on TCP
port 22 shows as *SSH banner?*, with the reason on hover. The question mark
marks it as a guess: there is no field table, only the notes on what that
port usually carries. When several protocols share the port, the others
are offered beside it.

## Browsing every note

*Browse all…* lists every note under its group (Link layer, Transport,
Images, Archives and so on), with a search box that matches names, keys
and summaries, or ports: `udp/67` or `502` finds what runs there.

## Wireshark names

The notes give each protocol and field its Wireshark display-filter name
where Wireshark has one: the IPv4 notes say *Wireshark: `ip`*, and the
*Time to live* field `ip.ttl`. The names appear under a note's heading, in
a column of the field table and in field tooltips. Clicking one copies it
for a Wireshark or tshark filter.

The search box finds notes by these names too (`dhcp`, `ip.ttl`), and the
[packet filter](packets.md#filters) accepts them: `ip.ttl==64`. Only the
names are taken from Wireshark; the notes' own text is written for this
project.

## Your own notes

Put TOML files in `~/.config/theviewer/reference/`, in the same form as the
built-in ones (the `reference/*.toml` files in the source tree). They are
read at startup, and *Reload your notes* in the *Browse all* list reads
them again. An entry with the `id` of a built-in one replaces it; any other
is added. A file that cannot be read is skipped, and the list says which
and why.

A minimal entry:

```toml
[[format]]
id = "telemetry"
name = "Lab telemetry"
keys = ["Telemetry"]
group = "Industrial control"
ports = ["udp/9999"]
summary = "Readings from the bench rig."
organisation = "A 2-byte sensor id, then a 4-byte big-endian reading."

[[format.specs]]
document = "Rig manual 2.1"
title = "Bench rig telemetry"
url = "https://example.com/rig-manual.pdf"
```

## Checking the citations

`check_reference` is a separate program, built from the source tree, that
checks every built-in note against its sources:

```sh
cargo run --bin check_reference
cargo run --bin check_reference -- --offline
```

It checks that each cited RFC exists, has the title given and is not
obsoleted (a warning); that each cited section is found in the RFC's text;
that each port is registered with the IANA to something like the protocol
(a warning); that every link is https; and that every Wireshark name is one
that `tshark -G protocols` or `tshark -G fields` lists.

The RFC Editor's index, the IANA registry and RFC text are kept in
`~/.cache/theviewer/rfc`, and tshark's names in
`~/.cache/theviewer/wireshark`. `--offline` uses only what is kept there.
Without tshark or kept names, the Wireshark names are skipped with a note.
Errors make it exit non-zero.
