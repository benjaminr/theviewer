//! tshark's dissection as the viewer's layers, and merged into ours.
//!
//! [`to_layers`] turns a [`TsharkPacket`] into [`Layer`]s whose fields carry
//! exact byte positions within the frame, so they highlight and select like
//! the viewer's own. Each layer is named so the Reference tab finds its
//! notes where there are any. [`merge`] then adds tshark's layers to our
//! dissection: only where ours stops decoding ([`TsharkMode::FillGaps`]), or
//! in place of ours ([`TsharkMode::Everything`]).
//!
//! tshark dissects some protocols from data it put together itself (a TCP
//! stream reassembled from several segments, a decompressed body). Their
//! positions refer to that data, not to the frame, and PDML does not say
//! which, so a protocol that starts before the one it is carried in, or ends
//! past the frame, is left out of the layers and mentioned in a note.

use super::dissect::{Dissection, Layer, WiresharkNames};
use super::tshark::{TsharkField, TsharkPacket, TsharkProtocol, is_data_protocol};
use crate::plugin::Field;
use crate::reference;

/// How much of a packet tshark decodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TsharkMode {
    /// Only the layers ours leaves as undecoded data.
    #[default]
    FillGaps,
    /// Every layer, in place of ours.
    Everything,
}

/// tshark's layers for one frame.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TsharkLayers {
    pub layers: Vec<Layer>,
    /// The tshark filter name of each layer, such as `dhcp`.
    pub filter_names: Vec<String>,
    /// Wireshark's names for each layer and its fields.
    pub wireshark_names: Vec<WiresharkNames>,
    /// The whole protocol stack tshark named, for the packet filter.
    pub protocols: Vec<String>,
    pub notes: Vec<String>,
}

/// tshark's layers for a frame of `frame_len` bytes.
pub fn to_layers(packet: &TsharkPacket, frame_len: usize) -> TsharkLayers {
    let mut out = TsharkLayers { protocols: packet.protocols.clone(), notes: packet.notes.clone(), ..TsharkLayers::default() };
    let mut previous_start = 0;
    for protocol in &packet.layers {
        let Some(start) = protocol.position else { continue };
        let end = start.saturating_add(protocol.size);
        if protocol.size == 0 {
            continue;
        }
        if start < previous_start || end > frame_len {
            out.notes.push(format!("tshark decoded {} from data it reassembled or decompressed, so it is not shown against this frame's bytes", short_name(protocol)));
            continue;
        }
        previous_start = start;
        let mut names = WiresharkNames { protocol: protocol.name.clone(), fields: Vec::new() };
        let fields = to_fields(&protocol.fields, frame_len, &[], &mut names.fields);
        out.layers.push(Layer { name: layer_name(protocol), offset: start, len: protocol.size, fields });
        out.filter_names.push(protocol.name.clone());
        out.wireshark_names.push(names);
    }
    out
}

/// Fields that sit within the frame; a field without bytes of its own (a
/// generated value or a heading) gives way to its children that have some.
/// Each kept field's filter name is noted in `names` under its path, the
/// field holding them being at `parent`.
fn to_fields(fields: &[TsharkField], frame_len: usize, parent: &[usize], names: &mut Vec<(Vec<usize>, String)>) -> Vec<Field> {
    let mut out: Vec<Field> = Vec::new();
    for field in fields {
        match field.position {
            Some(start) if field.size > 0 && start.saturating_add(field.size) <= frame_len => {
                let path: Vec<usize> = parent.iter().copied().chain([out.len()]).collect();
                let children = to_fields(&field.children, frame_len, &path, names);
                if !field.name.is_empty() {
                    names.push((path, field.name.clone()));
                }
                let (name, value) = name_and_value(field);
                out.push(Field::new(name, start, field.size, value).with_children(children));
            }
            _ => {
                // The children take this field's place among its siblings.
                let mut promoted_names = Vec::new();
                let children = to_fields(&field.children, frame_len, &[], &mut promoted_names);
                for (mut path, name) in promoted_names {
                    path[0] += out.len();
                    names.push((parent.iter().copied().chain(path).collect(), name));
                }
                out.extend(children);
            }
        }
    }
    out
}

/// A field's name and value from its display line: "Time to Live: 64"
/// becomes ("Time to Live", "64"), and a bit field's leading picture
/// ("0100 .... = Version: 4") is dropped.
fn name_and_value(field: &TsharkField) -> (String, String) {
    let display = strip_bit_picture(field.display.trim());
    if let Some((name, value)) = display.split_once(": ") {
        return (name.to_string(), value.to_string());
    }
    if display.is_empty() {
        return (field.name.clone(), field.show.clone());
    }
    let value = if field.show != display { field.show.clone() } else { String::new() };
    (display.to_string(), value)
}

fn strip_bit_picture(display: &str) -> &str {
    match display.split_once(" = ") {
        Some((picture, rest)) if !picture.is_empty() && picture.chars().all(|c| matches!(c, '0' | '1' | '.' | ' ')) => rest,
        _ => display,
    }
}

/// The protocol's long name: its title up to the first comma, keeping a
/// trailing note in brackets ("Dynamic Host Configuration Protocol (Discover)").
fn long_name(protocol: &TsharkProtocol) -> &str {
    let title = protocol.title.trim();
    let name = title.split(", ").next().unwrap_or(title);
    if name.is_empty() { &protocol.name } else { name }
}

/// A short name for the packet list, such as "DHCP": the reference notes'
/// short name when there are notes, else tshark's filter name in capitals.
pub fn short_name(protocol: &TsharkProtocol) -> String {
    match reference::lookup(&protocol.name).or_else(|| reference::lookup(long_name(protocol))) {
        Some(notes) => notes.short_name().to_string(),
        None => protocol.name.to_uppercase(),
    }
}

/// The layer's name, chosen so the Reference tab can look its notes up by
/// it: the long name when the notes know it, else a name of the notes that
/// tshark's filter name leads to, else the long name.
fn layer_name(protocol: &TsharkProtocol) -> String {
    let long = long_name(protocol);
    if reference::lookup(long).is_some() {
        return long.to_string();
    }
    match reference::lookup(&protocol.name) {
        Some(notes) if reference::lookup(&notes.name).is_some_and(|found| found.id == notes.id) => notes.name.clone(),
        Some(_) => protocol.name.to_uppercase(),
        None => long.to_string(),
    }
}

/// Whether one of our layers holds bytes we did not decode: payload, data,
/// padding or a header that could not be read.
pub fn is_undecoded(layer: &Layer) -> bool {
    matches!(layer.fields.as_slice(), [only] if matches!(only.name.as_str(), "Data" | "Padding" | "Bytes") && only.offset == layer.offset && only.len == layer.len)
}

/// Our dissection with tshark's layers added as `mode` says. Layers that
/// came from tshark are listed in [`Dissection::tshark_layers`].
pub fn merge(ours: Dissection, theirs: &TsharkLayers, mode: TsharkMode) -> Dissection {
    let mut merged = ours;
    merged.tshark_protocols = theirs.protocols.clone();
    let all = theirs.layers.iter().zip(&theirs.wireshark_names);
    let chosen: Vec<(Layer, &WiresharkNames)> = match mode {
        TsharkMode::Everything => all.map(|(layer, names)| (layer.clone(), names)).collect(),
        TsharkMode::FillGaps => {
            let decoded_end = merged.layers.iter().filter(|layer| !is_undecoded(layer)).map(|layer| layer.offset + layer.len).max().unwrap_or(0);
            all.filter(|(layer, names)| layer.offset >= decoded_end && !is_data_protocol(&names.protocol)).map(|(layer, names)| (layer.clone(), names)).collect()
        }
    };
    if chosen.is_empty() {
        if mode == TsharkMode::Everything {
            merged.notes.extend(theirs.notes.iter().map(|note| format!("tshark: {note}")));
        }
        return merged;
    }
    let mut layers: Vec<(Layer, Option<&WiresharkNames>)> = match mode {
        TsharkMode::Everything => Vec::new(),
        TsharkMode::FillGaps => merged
            .layers
            .drain(..)
            .filter(|layer| !is_undecoded(layer) || !chosen.iter().any(|(added, _)| overlaps(layer, added)))
            .map(|layer| (layer, None))
            .collect(),
    };
    layers.extend(chosen.iter().map(|(layer, names)| (layer.clone(), Some(*names))));
    layers.sort_by_key(|(layer, _)| layer.offset);
    merged.tshark_layers = layers.iter().enumerate().filter(|(_, (_, names))| names.is_some()).map(|(index, _)| index).collect();
    merged.tshark_names = layers.iter().filter_map(|(_, names)| names.cloned()).collect();
    merged.layers = layers.into_iter().map(|(layer, _)| layer).collect();
    if let Some((top, names)) = chosen.iter().rev().find(|(_, names)| !is_data_protocol(&names.protocol)) {
        let protocol = TsharkProtocol { name: names.protocol.clone(), title: top.name.clone(), ..TsharkProtocol::default() };
        merged.summary.protocol = short_name(&protocol);
        merged.summary.info = top.name.clone();
    }
    merged.notes.extend(theirs.notes.iter().map(|note| format!("tshark: {note}")));
    merged
}

fn overlaps(a: &Layer, b: &Layer) -> bool {
    a.offset < b.offset + b.len && b.offset < a.offset + a.len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packets::{LinkKind, dissect};

    fn field(name: &str, display: &str, position: usize, size: usize) -> TsharkField {
        TsharkField { name: name.to_string(), display: display.to_string(), show: String::new(), value: String::new(), position: Some(position), size, children: Vec::new() }
    }

    fn protocol(name: &str, title: &str, position: usize, size: usize, fields: Vec<TsharkField>) -> TsharkProtocol {
        TsharkProtocol { name: name.to_string(), title: title.to_string(), position: Some(position), size, fields }
    }

    /// An Ethernet, IPv4 and UDP packet from 68 to 67 with a 12-byte payload,
    /// which our dissector leaves as payload.
    fn udp_frame() -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [0xFF; 6]).ipv4([0, 0, 0, 0], [255, 255, 255, 255], 64).udp(68, 67);
        let mut frame = Vec::new();
        builder.write(&mut frame, &[1, 1, 6, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]).unwrap();
        frame
    }

    /// What tshark might say about [`udp_frame`]: the same three headers and
    /// a "bootish" protocol in the payload.
    fn tshark_view() -> TsharkPacket {
        let mut flags = field("bootish.flags", "Flags: 0x0000", 52, 2);
        flags.children = vec![field("bootish.flags.bc", "0... .... .... .... = Broadcast flag: Unicast", 52, 2)];
        TsharkPacket {
            number: 1,
            captured_len: 54,
            protocols: ["eth", "ethertype", "ip", "udp", "bootish"].map(String::from).to_vec(),
            layers: vec![
                protocol("eth", "Ethernet II, Src: 02:00:00:00:00:01", 0, 14, vec![field("eth.dst", "Destination: ff:ff:ff:ff:ff:ff", 0, 6)]),
                protocol("ip", "Internet Protocol Version 4, Src: 0.0.0.0", 14, 20, vec![field("ip.ttl", "Time to Live: 64", 22, 1)]),
                protocol("udp", "User Datagram Protocol, Src Port: 68", 34, 8, vec![field("udp.srcport", "Source Port: 68", 34, 2)]),
                protocol(
                    "bootish",
                    "Bootish Protocol (Request)",
                    42,
                    12,
                    vec![
                        field("bootish.op", "Message type: Boot Request (1)", 42, 1),
                        field("bootish.id", "Transaction ID: 0x12345678", 46, 4),
                        TsharkField { name: "bootish.secs".into(), display: "Seconds: 0".into(), position: Some(46), size: 0, ..TsharkField::default() },
                        field("bootish.beyond", "Beyond: 1", 60, 2),
                        flags,
                    ],
                ),
            ],
            notes: vec!["Odd flags".to_string()],
        }
    }

    #[test]
    fn tshark_fields_become_fields_with_exact_frame_positions() {
        let layers = to_layers(&tshark_view(), 54);
        assert_eq!(layers.filter_names, vec!["eth", "ip", "udp", "bootish"]);
        let bootish = &layers.layers[3];
        assert_eq!((bootish.name.as_str(), bootish.offset, bootish.len), ("Bootish Protocol (Request)", 42, 12));
        let names: Vec<(&str, &str, usize, usize)> = bootish.fields.iter().map(|f| (f.name.as_str(), f.value.as_str(), f.offset, f.len)).collect();
        assert_eq!(
            names,
            vec![("Message type", "Boot Request (1)", 42, 1), ("Transaction ID", "0x12345678", 46, 4), ("Flags", "0x0000", 52, 2)],
            "fields without bytes or beyond the frame are left out"
        );
        assert_eq!(bootish.fields[2].children[0].name, "Broadcast flag", "the bit picture is dropped from the name");
        let names = &layers.wireshark_names[3];
        assert_eq!(names.protocol, "bootish");
        assert_eq!(names.field(&[1]), Some("bootish.id"));
        assert_eq!(names.field(&[2, 0]), Some("bootish.flags.bc"), "a child's path goes through its parent");
    }

    #[test]
    fn a_heading_without_bytes_gives_its_place_and_names_to_its_children() {
        let mut heading = TsharkField { name: String::new(), display: "Timestamps".into(), position: Some(42), size: 0, ..TsharkField::default() };
        heading.children = vec![field("bootish.first", "First: 1", 44, 2), field("bootish.second", "Second: 2", 46, 2)];
        let mut view = tshark_view();
        view.layers[3].fields = vec![field("bootish.op", "Op: 1", 42, 1), heading];
        let layers = to_layers(&view, 54);
        let fields: Vec<&str> = layers.layers[3].fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(fields, vec!["Op", "First", "Second"]);
        assert_eq!(layers.wireshark_names[3].field(&[2]), Some("bootish.second"));
    }

    #[test]
    fn layers_are_named_so_the_reference_notes_are_found() {
        let layers = to_layers(&tshark_view(), 54);
        assert!(reference::lookup(&layers.layers[2].name).is_some_and(|notes| notes.id == "udp"), "{}", layers.layers[2].name);
        assert!(reference::lookup(&layers.layers[1].name).is_some_and(|notes| notes.id == "ipv4"), "ip leads to the IPv4 notes: {}", layers.layers[1].name);
    }

    #[test]
    fn a_protocol_from_reassembled_data_is_noted_rather_than_misplaced() {
        let mut view = tshark_view();
        view.layers.push(protocol("http", "Hypertext Transfer Protocol", 0, 300, Vec::new()));
        let layers = to_layers(&view, 54);
        assert_eq!(layers.layers.len(), 4);
        assert!(layers.notes.iter().any(|note| note.contains("HTTP") && note.contains("reassembled")), "{:?}", layers.notes);
    }

    #[test]
    fn filling_gaps_adds_only_what_our_dissector_left_as_payload() {
        let frame = udp_frame();
        let ours = dissect(&frame, LinkKind::Ethernet);
        assert_eq!(ours.layers.last().map(|l| l.name.as_str()), Some("Payload"));
        let merged = merge(ours.clone(), &to_layers(&tshark_view(), frame.len()), TsharkMode::FillGaps);
        let names: Vec<&str> = merged.layers.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, vec!["Ethernet II", "Internet Protocol version 4", "User Datagram Protocol", "Bootish Protocol (Request)"]);
        assert_eq!(merged.tshark_layers, vec![3]);
        assert_eq!(merged.wireshark_names(3).map(|names| names.protocol.as_str()), Some("bootish"));
        assert_eq!(merged.wireshark_names(2), None, "our own layers have no tshark names");
        assert_eq!(merged.summary.protocol, "BOOTISH");
        assert_eq!(merged.summary.info, "Bootish Protocol (Request)");
        assert_eq!(merged.summary.source, ours.summary.source, "addresses stay ours");
        assert!(merged.tshark_protocols.contains(&"bootish".to_string()));
        assert_eq!(merged.notes, vec!["tshark: Odd flags".to_string()]);
        assert_eq!(merged.protocols, ours.protocols, "our protocol list is unchanged for the filter");
    }

    #[test]
    fn using_tshark_for_everything_replaces_our_layers() {
        let frame = udp_frame();
        let merged = merge(dissect(&frame, LinkKind::Ethernet), &to_layers(&tshark_view(), frame.len()), TsharkMode::Everything);
        assert_eq!(merged.layers.len(), 4);
        assert_eq!(merged.tshark_layers, vec![0, 1, 2, 3]);
        assert_eq!(merged.layers[1].fields[0].name, "Time to Live");
    }

    #[test]
    fn a_packet_tshark_adds_nothing_to_is_left_as_ours() {
        let frame = udp_frame();
        let ours = dissect(&frame, LinkKind::Ethernet);
        let mut view = tshark_view();
        view.layers.truncate(3);
        view.notes.clear();
        let merged = merge(ours.clone(), &to_layers(&view, frame.len()), TsharkMode::FillGaps);
        assert_eq!(merged.layers, ours.layers);
        assert!(merged.tshark_layers.is_empty());
        assert_eq!(merged.summary, ours.summary);
    }

    #[test]
    fn only_data_padding_and_unreadable_layers_count_as_undecoded() {
        let frame = udp_frame();
        let ours = dissect(&frame, LinkKind::Ethernet);
        let undecoded: Vec<bool> = ours.layers.iter().map(is_undecoded).collect();
        assert_eq!(undecoded, vec![false, false, false, true]);
    }
}
