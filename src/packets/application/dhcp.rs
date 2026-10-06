//! DHCP and BOOTP (RFC 2131, RFC 2132, RFC 951) on UDP ports 67 and 68.
//!
//! Every message has BOOTP's fixed 236-byte layout; DHCP adds the magic
//! cookie at byte 236 and a list of options after it, one of which (53)
//! says what kind of DHCP message it is.

use std::net::Ipv4Addr;

use crate::plugin::Field;

use super::{AppLayer, u16_at, u32_at};

/// The fixed BOOTP fields before the magic cookie.
const BOOTP_FIXED_LEN: usize = 236;
/// BOOTP (RFC 951) ends with a 64-byte vendor area.
const BOOTP_VENDOR_AREA_LEN: usize = 64;
const MAGIC_COOKIE: u32 = 0x6382_5363;
const OPTIONS_START: usize = BOOTP_FIXED_LEN + 4;
const OP_REQUEST: u8 = 1;
const OP_REPLY: u8 = 2;
/// The longest hardware address the 16-byte chaddr field holds.
const MAX_HARDWARE_ADDRESS_LEN: u8 = 16;
const HARDWARE_TYPE_ETHERNET: u8 = 1;
const BROADCAST_FLAG: u16 = 0x8000;

const OPTION_PAD: u8 = 0;
const OPTION_END: u8 = 255;
const OPTION_MESSAGE_TYPE: u8 = 53;
/// Most options listed.
const MAX_OPTIONS: usize = 128;
/// Bytes of an option's value shown as hex.
const VALUE_PREVIEW_BYTES: usize = 16;

fn message_type_name(kind: u8) -> &'static str {
    match kind {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        9 => "Force Renew",
        10 => "Lease query",
        11 => "Lease Unassigned",
        12 => "Lease Unknown",
        13 => "Lease Active",
        _ => "Unknown",
    }
}

fn option_name(code: u8) -> &'static str {
    match code {
        1 => "Subnet Mask",
        2 => "Time Offset",
        3 => "Router",
        4 => "Time Server",
        6 => "Domain Name Server",
        12 => "Host Name",
        15 => "Domain Name",
        28 => "Broadcast Address",
        42 => "Network Time Protocol Servers",
        43 => "Vendor-Specific Information",
        44 => "NetBIOS over TCP/IP Name Server",
        50 => "Requested IP Address",
        51 => "IP Address Lease Time",
        52 => "Option Overload",
        53 => "DHCP Message Type",
        54 => "DHCP Server Identifier",
        55 => "Parameter Request List",
        56 => "Message",
        57 => "Maximum DHCP Message Size",
        58 => "Renewal Time Value",
        59 => "Rebinding Time Value",
        60 => "Vendor class identifier",
        61 => "Client identifier",
        66 => "TFTP Server Name",
        67 => "Bootfile name",
        81 => "Client Fully Qualified Domain Name",
        82 => "Agent Information Option",
        119 => "Domain Search",
        121 => "Classless Static Route",
        _ => "Unknown",
    }
}

fn address(bytes: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::from(u32_at(bytes, at).unwrap_or_default())
}

fn hardware_address(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
}

/// Text from a zero-padded field, or "not given" when it is empty.
fn padded_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());
    if end == 0 { "not given".to_string() } else { String::from_utf8_lossy(&bytes[..end]).into_owned() }
}

/// An option's value in words, by its code.
fn option_value(code: u8, value: &[u8]) -> String {
    let addresses = || value.as_chunks::<4>().0.iter().map(|&octets| Ipv4Addr::from(octets).to_string()).collect::<Vec<_>>().join(", ");
    let seconds = || u32_at(value, 0).map_or_else(|| super::super::hex_preview(value, VALUE_PREVIEW_BYTES), |seconds| format!("{seconds} s"));
    match code {
        OPTION_MESSAGE_TYPE if value.len() == 1 => format!("{} ({})", value[0], message_type_name(value[0])),
        1 | 3 | 4 | 6 | 28 | 42 | 44 | 50 | 54 if !value.is_empty() && value.len().is_multiple_of(4) => addresses(),
        51 | 58 | 59 if value.len() == 4 => seconds(),
        57 if value.len() == 2 => u16_at(value, 0).unwrap_or_default().to_string(),
        12 | 15 | 56 | 60 | 66 | 67 => String::from_utf8_lossy(value).trim_end_matches('\0').to_string(),
        55 => value.iter().map(u8::to_string).collect::<Vec<_>>().join(", "),
        61 if value.len() == 7 && value[0] == HARDWARE_TYPE_ETHERNET => format!("Ethernet {}", hardware_address(&value[1..])),
        _ => super::super::hex_preview(value, VALUE_PREVIEW_BYTES),
    }
}

/// The options from `at`: their fields, the DHCP message type if one was
/// given, and where the options end.
fn options(payload: &[u8], mut at: usize) -> (Vec<Field>, Option<u8>, usize) {
    let mut fields = Vec::new();
    let mut message_type = None;
    while fields.len() < MAX_OPTIONS {
        let Some(&code) = payload.get(at) else { break };
        if code == OPTION_PAD {
            at += 1;
            continue;
        }
        if code == OPTION_END {
            fields.push(Field::new("Option (255) End", at, 1, "end of options"));
            at += 1;
            break;
        }
        let Some(&len) = payload.get(at + 1) else { break };
        let Some(value) = payload.get(at + 2..at + 2 + len as usize) else { break };
        if code == OPTION_MESSAGE_TYPE {
            message_type = value.first().copied();
        }
        fields.push(Field::new(format!("Option ({code}) {}", option_name(code)), at, 2 + len as usize, option_value(code, value)));
        at += 2 + len as usize;
    }
    (fields, message_type, at)
}

/// A DHCP or BOOTP message, or `None` when the bytes are not one.
pub fn dissect_dhcp(payload: &[u8]) -> Option<AppLayer> {
    if payload.len() < BOOTP_FIXED_LEN {
        return None;
    }
    let op = payload[0];
    let hardware_type = payload[1];
    let hardware_len = payload[2];
    if !matches!(op, OP_REQUEST | OP_REPLY) || hardware_len > MAX_HARDWARE_ADDRESS_LEN {
        return None;
    }
    let transaction = u32_at(payload, 4)?;
    let flags = u16_at(payload, 10)?;
    let client_hardware = &payload[28..28 + hardware_len as usize];
    let mut fields = vec![
        Field::new("Message type", 0, 1, format!("{op} ({})", if op == OP_REQUEST { "Boot Request" } else { "Boot Reply" })),
        Field::new("Hardware type", 1, 1, format!("{hardware_type}{}", if hardware_type == HARDWARE_TYPE_ETHERNET { " (Ethernet)" } else { "" })),
        Field::new("Hardware address length", 2, 1, hardware_len.to_string()),
        Field::new("Hops", 3, 1, payload[3].to_string()),
        Field::new("Transaction ID", 4, 4, format!("{transaction:#010x}")),
        Field::new("Seconds elapsed", 8, 2, u16_at(payload, 8)?.to_string()),
        Field::new("Bootp flags", 10, 2, format!("{flags:#06x} ({})", if flags & BROADCAST_FLAG != 0 { "broadcast" } else { "unicast" })),
        Field::new("Client IP address", 12, 4, address(payload, 12).to_string()),
        Field::new("Your (client) IP address", 16, 4, address(payload, 16).to_string()),
        Field::new("Next server IP address", 20, 4, address(payload, 20).to_string()),
        Field::new("Relay agent IP address", 24, 4, address(payload, 24).to_string()),
        Field::new("Client hardware address", 28, 16, hardware_address(client_hardware)),
        Field::new("Server host name", 44, 64, padded_text(&payload[44..108])),
        Field::new("Boot file name", 108, 128, padded_text(&payload[108..236])),
    ];
    let has_cookie = u32_at(payload, BOOTP_FIXED_LEN) == Some(MAGIC_COOKIE);
    let (message_type, len) = if has_cookie {
        fields.push(Field::new("Magic cookie", BOOTP_FIXED_LEN, 4, format!("{MAGIC_COOKIE:#010x} (DHCP)")));
        let (option_fields, message_type, mut end) = options(payload, OPTIONS_START);
        fields.extend(option_fields);
        // Zeros after the End option are Pad options filling out the message.
        let rest = &payload[end..];
        if !rest.is_empty() && rest.iter().all(|&byte| byte == OPTION_PAD) {
            fields.push(Field::new("Option (0) Padding", end, rest.len(), format!("{} bytes", rest.len())));
            end = payload.len();
        }
        (message_type, end)
    } else {
        (None, (BOOTP_FIXED_LEN + BOOTP_VENDOR_AREA_LEN).min(payload.len()))
    };
    let info = match message_type {
        Some(kind) => format!("DHCP {} - Transaction ID {transaction:#x}", message_type_name(kind)),
        None if op == OP_REQUEST => format!("Boot Request from {}", hardware_address(client_hardware)),
        None => format!("Boot Reply to {}", hardware_address(client_hardware)),
    };
    Some(AppLayer { name: "DHCP", key: "dhcp", len, fields, info })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DHCP Discover from 02:00:00:00:00:01 asking for a router and DNS servers.
    fn discover() -> Vec<u8> {
        let mut message = vec![0u8; BOOTP_FIXED_LEN];
        message[0] = OP_REQUEST;
        message[1] = HARDWARE_TYPE_ETHERNET;
        message[2] = 6;
        message[4..8].copy_from_slice(&0x3D1D_0001u32.to_be_bytes());
        message[10] = 0x80;
        message[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(&[53, 1, 1]);
        message.extend_from_slice(&[50, 4, 192, 168, 1, 100]);
        message.extend_from_slice(&[55, 3, 1, 3, 6]);
        message.extend_from_slice(&[0, 0]); // pad
        message.push(OPTION_END);
        message
    }

    fn field<'a>(layer: &'a AppLayer, name: &str) -> &'a Field {
        layer.fields.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no field {name} in {:?}", layer.fields))
    }

    #[test]
    fn a_dhcp_discover_names_its_type_transaction_and_options() {
        let mut message = discover();
        let end = message.len();
        message.extend_from_slice(&[0; 20]); // padding after the End option
        let layer = dissect_dhcp(&message).expect("DHCP");
        assert_eq!(layer.info, "DHCP Discover - Transaction ID 0x3d1d0001");
        assert_eq!(layer.len, message.len(), "the padding belongs to the message");
        assert_eq!((field(&layer, "Option (0) Padding").offset, field(&layer, "Option (0) Padding").len), (end, 20));
        assert_eq!(field(&layer, "Client hardware address").value, "02:00:00:00:00:01");
        assert_eq!(field(&layer, "Bootp flags").value, "0x8000 (broadcast)");
        assert_eq!(field(&layer, "Option (53) DHCP Message Type").value, "1 (Discover)");
        assert_eq!(field(&layer, "Option (50) Requested IP Address").value, "192.168.1.100");
        assert_eq!(field(&layer, "Option (55) Parameter Request List").value, "1, 3, 6");
    }

    #[test]
    fn a_bootp_message_without_the_cookie_is_still_read() {
        let mut message = discover();
        message.truncate(BOOTP_FIXED_LEN);
        message.extend_from_slice(&[0; BOOTP_VENDOR_AREA_LEN]);
        let layer = dissect_dhcp(&message).expect("BOOTP");
        assert_eq!(layer.info, "Boot Request from 02:00:00:00:00:01");
        assert_eq!(layer.len, BOOTP_FIXED_LEN + BOOTP_VENDOR_AREA_LEN);
    }

    #[test]
    fn short_messages_bad_ops_and_options_cut_short_are_handled() {
        let message = discover();
        assert!(dissect_dhcp(&message[..100]).is_none());
        let mut bad_op = message.clone();
        bad_op[0] = 3;
        assert!(dissect_dhcp(&bad_op).is_none());
        // An option claiming more bytes than remain ends the list.
        let mut cut = message[..OPTIONS_START].to_vec();
        cut.extend_from_slice(&[53, 1, 3, 12, 40, b'h']);
        let layer = dissect_dhcp(&cut).expect("DHCP");
        assert_eq!(layer.info, "DHCP Request - Transaction ID 0x3d1d0001");
        assert_eq!(layer.len, OPTIONS_START + 3);
    }
}
