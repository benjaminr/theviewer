//! Pure helpers for editing packets in place: turning typed values into
//! field bytes, recomputing IPv4, TCP and UDP checksums, and applying one
//! operation to many byte ranges at once.
//!
//! The panel turns the results into undoable document edits; nothing here
//! touches the document.

use std::net::{Ipv4Addr, Ipv6Addr};

use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice, TcpHeaderSlice, UdpHeaderSlice};

use super::dissect::Dissection;
use crate::plugin::Field;

const IPV4_LAYER: &str = "Internet Protocol version 4";
const IPV6_LAYER: &str = "Internet Protocol version 6";
const TCP_LAYER: &str = "Transmission Control Protocol";
const UDP_LAYER: &str = "User Datagram Protocol";
const IPV4_CHECKSUM_OFFSET: usize = 10;
const TCP_CHECKSUM_OFFSET: usize = 16;
const UDP_CHECKSUM_OFFSET: usize = 6;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
/// Widest field edited as a number.
const MAX_INTEGER_BYTES: usize = 8;

// ---------------------------------------------------------------------------
// Field values
// ---------------------------------------------------------------------------

/// Whether a field's name or value says it is little endian, such as a
/// template field of type `u16le` or a guess of kind "length u16 LE".
/// Network protocol fields are big endian.
pub fn field_is_little_endian(field: &Field) -> bool {
    let text = format!("{} {}", field.name, field.value);
    text.split(|c: char| !c.is_ascii_alphanumeric()).any(is_little_endian_word)
}

/// "LE", "little", or a type name such as `u16le`, `i32le` or `f64le`.
fn is_little_endian_word(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    if lower == "le" || lower == "little" {
        return true;
    }
    let Some(stem) = lower.strip_suffix("le") else { return false };
    let Some(width) = stem.strip_prefix(['u', 'i', 'f']) else { return false };
    !width.is_empty() && width.chars().all(|c| c.is_ascii_digit())
}

/// The bytes for `text` typed into a field of `len` bytes: a whole number
/// (decimal or `0x` hex), an IPv4 or IPv6 address, a MAC address, or exactly
/// `len` hex bytes.
pub fn encode_value(text: &str, len: usize, little_endian: bool) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("Type a value first.".to_string());
    }
    if len == 4
        && let Ok(address) = text.parse::<Ipv4Addr>()
    {
        return Ok(address.octets().to_vec());
    }
    if len == 16
        && let Ok(address) = text.parse::<Ipv6Addr>()
    {
        return Ok(address.octets().to_vec());
    }
    if len == 6
        && let Some(mac) = parse_mac(text)
    {
        return Ok(mac.to_vec());
    }
    if len <= MAX_INTEGER_BYTES
        && let Some(value) = parse_integer(text)
    {
        return integer_bytes(value, len, little_endian);
    }
    match super::parse_hex(text) {
        Ok(bytes) if bytes.len() == len => Ok(bytes),
        Ok(bytes) => Err(format!("The field holds {len} bytes, but {} hex bytes were given.", bytes.len())),
        Err(_) => Err(format!("Type a number (such as 53 or 0x35), an address, or exactly {len} hex bytes.")),
    }
}

fn parse_integer(text: &str) -> Option<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse::<u64>().ok(),
    }
}

fn integer_bytes(value: u64, len: usize, little_endian: bool) -> Result<Vec<u8>, String> {
    if len == 0 {
        return Err("The field has no bytes to write.".to_string());
    }
    let bits = len * 8;
    if bits < 64 && value >> bits != 0 {
        return Err(format!("{value} does not fit in {len} byte{}; the largest is {}.", if len == 1 { "" } else { "s" }, (1u64 << bits) - 1));
    }
    let big = value.to_be_bytes();
    let mut bytes = big[8 - len..].to_vec();
    if little_endian {
        bytes.reverse();
    }
    Ok(bytes)
}

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = text.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (byte, part) in mac.iter_mut().zip(parts) {
        if part.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

/// A checksum that needs rewriting: where (in the packet) and with what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repair {
    pub offset: usize,
    pub bytes: [u8; 2],
    /// Which checksum, for the status line.
    pub what: &'static str,
}

/// The IPv4 header, TCP and UDP checksums of a dissected packet that do not
/// match its bytes. A UDP checksum of zero over IPv4 means "not used" and is
/// left alone.
pub fn checksum_repairs(packet: &[u8], dissection: &Dissection) -> Vec<Repair> {
    let mut repairs = Vec::new();
    let layer_at = |name: &str| dissection.layers.iter().find(|layer| layer.name == name).map(|layer| layer.offset);
    let transport = |repairs: &mut Vec<Repair>, addresses: Addresses, end: usize| {
        if let Some(at) = layer_at(TCP_LAYER) {
            repairs.extend(tcp_repair(packet, at, end, addresses));
        }
        if let Some(at) = layer_at(UDP_LAYER) {
            repairs.extend(udp_repair(packet, at, end, addresses));
        }
    };
    if let Some(at) = layer_at(IPV4_LAYER)
        && let Ok(header) = Ipv4HeaderSlice::from_slice(&packet[at..])
    {
        let computed = header.to_header().calc_header_checksum();
        if computed != header.header_checksum() {
            repairs.push(Repair { offset: at + IPV4_CHECKSUM_OFFSET, bytes: computed.to_be_bytes(), what: "IPv4 header" });
        }
        let total = header.total_len() as usize;
        let end = if total >= header.slice().len() { (at + total).min(packet.len()) } else { packet.len() };
        transport(&mut repairs, Addresses::V4(header.source(), header.destination()), end);
    } else if let Some(at) = layer_at(IPV6_LAYER)
        && let Ok(header) = Ipv6HeaderSlice::from_slice(&packet[at..])
    {
        let end = (at + IPV6_HEADER_LEN + header.payload_length() as usize).min(packet.len());
        transport(&mut repairs, Addresses::V6(header.source(), header.destination()), end);
    }
    repairs
}

/// The addresses that go into a TCP or UDP pseudo-header.
#[derive(Clone, Copy)]
enum Addresses {
    V4([u8; 4], [u8; 4]),
    V6([u8; 16], [u8; 16]),
}

fn tcp_repair(packet: &[u8], at: usize, end: usize, addresses: Addresses) -> Option<Repair> {
    let segment = packet.get(at..end)?;
    let header = TcpHeaderSlice::from_slice(segment).ok()?;
    let payload = &segment[header.slice().len()..];
    let computed = match addresses {
        Addresses::V4(source, destination) => header.calc_checksum_ipv4_raw(source, destination, payload).ok()?,
        Addresses::V6(source, destination) => header.calc_checksum_ipv6_raw(source, destination, payload).ok()?,
    };
    (computed != header.checksum()).then_some(Repair { offset: at + TCP_CHECKSUM_OFFSET, bytes: computed.to_be_bytes(), what: "TCP" })
}

fn udp_repair(packet: &[u8], at: usize, end: usize, addresses: Addresses) -> Option<Repair> {
    let datagram = packet.get(at..end)?;
    let header = UdpHeaderSlice::from_slice(datagram).ok()?;
    let length = header.length() as usize;
    let udp_end = if length >= UDP_HEADER_LEN { length.min(datagram.len()) } else { datagram.len() };
    let payload = &datagram[UDP_HEADER_LEN..udp_end];
    let stored = header.checksum();
    let computed = match addresses {
        Addresses::V4(_, _) if stored == 0 => return None,
        Addresses::V4(source, destination) => header.to_header().calc_checksum_ipv4_raw(source, destination, payload).ok()?,
        Addresses::V6(source, destination) => header.to_header().calc_checksum_ipv6_raw(source, destination, payload).ok()?,
    };
    (computed != stored).then_some(Repair { offset: at + UDP_CHECKSUM_OFFSET, bytes: computed.to_be_bytes(), what: "UDP" })
}

// ---------------------------------------------------------------------------
// Operations over many ranges
// ---------------------------------------------------------------------------

/// A same-length change applied to each range on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ByteOperation {
    Invert,
    /// Repeat the pattern from the start of each range.
    Fill(Vec<u8>),
    /// XOR with the key, restarting at the start of each range.
    Xor(Vec<u8>),
}

impl ByteOperation {
    pub fn label(&self) -> &'static str {
        match self {
            ByteOperation::Invert => "Inverted",
            ByteOperation::Fill(_) => "Filled",
            ByteOperation::Xor(_) => "XORed",
        }
    }

    pub fn apply(&self, bytes: &mut [u8]) {
        match self {
            ByteOperation::Invert => bytes.iter_mut().for_each(|byte| *byte = !*byte),
            ByteOperation::Fill(pattern) if !pattern.is_empty() => {
                for (byte, value) in bytes.iter_mut().zip(pattern.iter().cycle()) {
                    *byte = *value;
                }
            }
            ByteOperation::Xor(key) if !key.is_empty() => {
                for (byte, value) in bytes.iter_mut().zip(key.iter().cycle()) {
                    *byte ^= *value;
                }
            }
            ByteOperation::Fill(_) | ByteOperation::Xor(_) => {}
        }
    }
}

/// Ranges `(offset, len)` sorted, with empty ones dropped and overlapping or
/// touching ones merged.
pub fn merge_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.retain(|&(_, len)| len > 0);
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, len) in ranges {
        let end = start.saturating_add(len);
        match merged.last_mut() {
            Some((last_start, last_len)) if start <= *last_start + *last_len => {
                *last_len = (*last_start + *last_len).max(end) - *last_start;
            }
            _ => merged.push((start, len)),
        }
    }
    merged
}

/// The smallest `(offset, len)` covering every range.
pub fn covering_span(ranges: &[(usize, usize)]) -> Option<(usize, usize)> {
    let start = ranges.iter().map(|&(offset, _)| offset).min()?;
    let end = ranges.iter().map(|&(offset, len)| offset.saturating_add(len)).max()?;
    Some((start, end - start))
}

/// Apply `operation` to each range inside `span` (whose first byte is at
/// document offset `span_start`). Ranges may overlap; each is changed once,
/// in order.
pub fn apply_to_ranges(span: &mut [u8], span_start: usize, ranges: &[(usize, usize)], operation: &ByteOperation) {
    for &(offset, len) in ranges {
        let Some(start) = offset.checked_sub(span_start) else { continue };
        let end = (start + len).min(span.len());
        if start < end {
            operation.apply(&mut span[start..end]);
        }
    }
}

/// `span` with the (merged) `ranges` cut out.
pub fn without_ranges(span: &[u8], span_start: usize, ranges: &[(usize, usize)]) -> Vec<u8> {
    let mut kept = Vec::with_capacity(span.len());
    let mut at = 0;
    for &(offset, len) in &merge_ranges(ranges.to_vec()) {
        let start = offset.saturating_sub(span_start).min(span.len());
        let end = (start + len).min(span.len());
        kept.extend_from_slice(&span[at.min(start)..start]);
        at = at.max(end);
    }
    kept.extend_from_slice(&span[at.min(span.len())..]);
    kept
}

/// Where `offset` moves once the (merged) `deleted` ranges are removed, or
/// `None` when it lies inside one of them.
pub fn offset_after_deletion(offset: usize, deleted: &[(usize, usize)]) -> Option<usize> {
    let mut removed_before = 0;
    for &(start, len) in deleted {
        if offset >= start && offset < start + len {
            return None;
        }
        if start + len <= offset {
            removed_before += len;
        }
    }
    Some(offset - removed_before)
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use super::*;
    use crate::packets::{LinkKind, dissect};

    #[test]
    fn typed_numbers_are_written_in_the_field_byte_order() {
        assert_eq!(encode_value("53", 2, false), Ok(vec![0x00, 0x35]));
        assert_eq!(encode_value("0x0800", 2, false), Ok(vec![0x08, 0x00]));
        assert_eq!(encode_value("258", 2, true), Ok(vec![0x02, 0x01]));
        assert!(encode_value("70000", 2, false).unwrap_err().contains("65535"));
        assert_eq!(encode_value("10.0.0.9", 4, false), Ok(vec![10, 0, 0, 9]));
        assert_eq!(encode_value("02:00:00:00:00:aa", 6, false), Ok(vec![2, 0, 0, 0, 0, 0xAA]));
        assert_eq!(encode_value("de ad be ef 00 11 22 33 44", 9, false), Ok(vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0x11, 0x22, 0x33, 0x44]));
        assert!(encode_value("de ad", 9, false).unwrap_err().contains("9 bytes"));
        assert!(encode_value("", 2, false).is_err());
    }

    #[test]
    fn little_endian_fields_are_recognised_by_their_type_name() {
        assert!(field_is_little_endian(&Field::new("length u16 LE", 0, 2, "")));
        assert!(field_is_little_endian(&Field::new("count", 0, 2, "u32le 5")));
        assert!(!field_is_little_endian(&Field::new("Source port", 0, 2, "53")));
        assert!(!field_is_little_endian(&Field::new("Handle", 0, 2, "file")));
    }

    #[test]
    fn edited_ipv4_and_udp_headers_get_their_checksums_repaired() {
        let builder = PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).udp(1000, 53);
        let mut packet = Vec::new();
        builder.write(&mut packet, b"query").unwrap();
        assert!(checksum_repairs(&packet, &dissect(&packet, LinkKind::RawIp)).is_empty(), "a fresh packet needs nothing");
        let original = packet.clone();
        packet[8] = 3; // TTL
        packet[20 + 1] = 54; // destination port low byte
        let repairs = checksum_repairs(&packet, &dissect(&packet, LinkKind::RawIp));
        let what: Vec<&str> = repairs.iter().map(|r| r.what).collect();
        assert_eq!(what, vec!["IPv4 header", "UDP"]);
        for repair in &repairs {
            packet[repair.offset..repair.offset + 2].copy_from_slice(&repair.bytes);
        }
        assert!(checksum_repairs(&packet, &dissect(&packet, LinkKind::RawIp)).is_empty());
        assert_ne!(packet, original);
    }

    #[test]
    fn an_edited_tcp_segment_over_ipv6_gets_its_checksum_repaired() {
        let builder = PacketBuilder::ipv6([1; 16], [2; 16], 64).tcp(5000, 80, 1, 1024);
        let mut packet = Vec::new();
        builder.write(&mut packet, b"hello").unwrap();
        let last = packet.len() - 1;
        packet[last] = b'O';
        let repairs = checksum_repairs(&packet, &dissect(&packet, LinkKind::RawIp));
        assert_eq!(repairs.len(), 1);
        assert_eq!((repairs[0].what, repairs[0].offset), ("TCP", 40 + 16));
    }

    #[test]
    fn operations_apply_to_each_range_restarting_the_key() {
        let mut span = vec![0u8; 10];
        apply_to_ranges(&mut span, 100, &[(100, 3), (105, 3)], &ByteOperation::Xor(vec![1, 2]));
        assert_eq!(span, vec![1, 2, 1, 0, 0, 1, 2, 1, 0, 0]);
        apply_to_ranges(&mut span, 100, &[(108, 5)], &ByteOperation::Invert);
        assert_eq!(&span[8..], &[0xFF, 0xFF]);
        apply_to_ranges(&mut span, 100, &[(100, 2)], &ByteOperation::Fill(vec![0xAB]));
        assert_eq!(&span[..2], &[0xAB, 0xAB]);
    }

    #[test]
    fn deleting_ranges_cuts_them_out_and_moves_later_offsets_back() {
        let span: Vec<u8> = (0..10).collect();
        let deleted = merge_ranges(vec![(17, 2), (12, 2), (13, 2)]);
        assert_eq!(deleted, vec![(12, 3), (17, 2)]);
        assert_eq!(without_ranges(&span, 10, &deleted), vec![0, 1, 5, 6, 9]);
        assert_eq!(offset_after_deletion(16, &deleted), Some(13));
        assert_eq!(offset_after_deletion(13, &deleted), None);
        assert_eq!(offset_after_deletion(11, &deleted), Some(11));
        assert_eq!(covering_span(&deleted), Some((12, 7)));
    }
}
