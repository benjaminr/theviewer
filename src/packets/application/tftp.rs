//! TFTP (RFC 1350, with options from RFC 2347): read and write requests to
//! UDP port 69, then data, acknowledgements and errors between the
//! client's port and one the server chose.

use crate::plugin::Field;

use super::{AppLayer, u16_at};

const OPCODE_READ_REQUEST: u16 = 1;
const OPCODE_WRITE_REQUEST: u16 = 2;
const OPCODE_DATA: u16 = 3;
const OPCODE_ACK: u16 = 4;
const OPCODE_ERROR: u16 = 5;
const OPCODE_OPTION_ACK: u16 = 6;
/// The largest block (RFC 2348 allows up to 65464 bytes).
const MAX_BLOCK_SIZE: usize = 65_464;
/// Most option name and value pairs listed.
const MAX_OPTIONS: usize = 16;
/// Longest file name, mode or option text read.
const MAX_TEXT: usize = 512;
/// Bytes of a data block shown as hex.
const DATA_PREVIEW_BYTES: usize = 16;

fn opcode_name(opcode: u16) -> &'static str {
    match opcode {
        OPCODE_READ_REQUEST => "Read Request",
        OPCODE_WRITE_REQUEST => "Write Request",
        OPCODE_DATA => "Data Packet",
        OPCODE_ACK => "Acknowledgement",
        OPCODE_ERROR => "Error Code",
        OPCODE_OPTION_ACK => "Option Acknowledgement",
        _ => "Unknown",
    }
}

fn error_name(code: u16) -> &'static str {
    match code {
        0 => "Not defined",
        1 => "File not found",
        2 => "Access violation",
        3 => "Disk full or allocation exceeded",
        4 => "Illegal TFTP Operation",
        5 => "Unknown transfer ID",
        6 => "File already exists",
        7 => "No such user",
        8 => "Option negotiation failed",
        _ => "Unknown",
    }
}

/// A zero-terminated string at `at`: its text and the bytes it takes,
/// terminator included. Control characters make it `None`.
fn zero_terminated(payload: &[u8], at: usize) -> Option<(String, usize)> {
    let rest = payload.get(at..)?;
    let end = rest.iter().take(MAX_TEXT).position(|&byte| byte == 0)?;
    let text = &rest[..end];
    if text.iter().any(|&byte| byte < 0x20 || byte == 0x7F) {
        return None;
    }
    Some((String::from_utf8_lossy(text).into_owned(), end + 1))
}

/// Whether `mode` is one RFC 1350 defines.
fn is_transfer_mode(mode: &str) -> bool {
    ["netascii", "octet", "mail"].iter().any(|known| known.eq_ignore_ascii_case(mode))
}

/// Option name and value pairs from `at` to the end: their fields, a
/// summary such as "blksize=1428" and where they end.
fn options(payload: &[u8], mut at: usize) -> Option<(Vec<Field>, Vec<String>)> {
    let mut fields = Vec::new();
    let mut summary = Vec::new();
    while at < payload.len() && fields.len() < MAX_OPTIONS {
        let (name, name_len) = zero_terminated(payload, at)?;
        let (value, value_len) = zero_terminated(payload, at + name_len)?;
        fields.push(Field::new(format!("Option: {name}"), at, name_len + value_len, value.clone()));
        summary.push(format!("{name}={value}"));
        at += name_len + value_len;
    }
    Some((fields, summary))
}

/// A TFTP packet, or `None` when the bytes are not one.
pub fn dissect_tftp(payload: &[u8]) -> Option<AppLayer> {
    let opcode = u16_at(payload, 0)?;
    let mut fields = vec![Field::new("Opcode", 0, 2, format!("{opcode} ({})", opcode_name(opcode)))];
    let info = match opcode {
        OPCODE_READ_REQUEST | OPCODE_WRITE_REQUEST => {
            let (file, file_len) = zero_terminated(payload, 2)?;
            let (mode, mode_len) = zero_terminated(payload, 2 + file_len)?;
            if file.is_empty() || !is_transfer_mode(&mode) {
                return None;
            }
            fields.push(Field::new("Filename", 2, file_len, file.clone()));
            fields.push(Field::new("Mode", 2 + file_len, mode_len, mode.clone()));
            let (option_fields, summary) = options(payload, 2 + file_len + mode_len)?;
            fields.extend(option_fields);
            let options_text = if summary.is_empty() { String::new() } else { format!(", {}", summary.join(", ")) };
            format!("{}, File: {file}, Transfer type: {mode}{options_text}", opcode_name(opcode))
        }
        OPCODE_DATA => {
            let block = u16_at(payload, 2)?;
            let data = &payload[4..];
            if data.len() > MAX_BLOCK_SIZE {
                return None;
            }
            fields.push(Field::new("Block", 2, 2, block.to_string()));
            fields.push(Field::new("Data", 4, data.len(), format!("{} bytes: {}", data.len(), super::super::hex_preview(data, DATA_PREVIEW_BYTES))));
            format!("Data Packet, Block: {block}")
        }
        OPCODE_ACK => {
            let block = u16_at(payload, 2)?;
            if payload.len() != 4 {
                return None;
            }
            fields.push(Field::new("Block", 2, 2, block.to_string()));
            format!("Acknowledgement, Block: {block}")
        }
        OPCODE_ERROR => {
            let code = u16_at(payload, 2)?;
            let (message, message_len) = zero_terminated(payload, 4)?;
            fields.push(Field::new("Error code", 2, 2, format!("{code} ({})", error_name(code))));
            fields.push(Field::new("Error message", 4, message_len, message.clone()));
            format!("Error Code, Code: {}, Message: {message}", error_name(code))
        }
        OPCODE_OPTION_ACK => {
            let (option_fields, summary) = options(payload, 2)?;
            if option_fields.is_empty() {
                return None;
            }
            fields.extend(option_fields);
            format!("Option Acknowledgement, {}", summary.join(", "))
        }
        _ => return None,
    };
    Some(AppLayer { name: "TFTP", key: "tftp", len: payload.len(), fields, info })
}

/// Whether `payload` is a read or write request, which opens a transfer.
pub fn is_request(payload: &[u8]) -> bool {
    matches!(u16_at(payload, 0), Some(OPCODE_READ_REQUEST | OPCODE_WRITE_REQUEST)) && dissect_tftp(payload).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_request(file: &str, mode: &str, options: &[(&str, &str)]) -> Vec<u8> {
        let mut packet = OPCODE_READ_REQUEST.to_be_bytes().to_vec();
        for text in [file, mode].into_iter().chain(options.iter().flat_map(|(name, value)| [*name, *value])) {
            packet.extend_from_slice(text.as_bytes());
            packet.push(0);
        }
        packet
    }

    #[test]
    fn a_read_request_names_its_file_mode_and_options() {
        let packet = read_request("pxelinux.0", "octet", &[("blksize", "1428"), ("tsize", "0")]);
        let layer = dissect_tftp(&packet).expect("TFTP");
        assert_eq!(layer.info, "Read Request, File: pxelinux.0, Transfer type: octet, blksize=1428, tsize=0");
        assert_eq!(layer.fields[1].value, "pxelinux.0");
        assert_eq!((layer.fields[2].offset, layer.fields[2].len), (13, 6));
        assert_eq!(layer.fields[3].name, "Option: blksize");
        assert!(is_request(&packet));
    }

    #[test]
    fn data_acknowledgement_error_and_option_acknowledgement_packets_are_read() {
        let mut data = vec![0, 3, 0, 7];
        data.extend_from_slice(&[0xAA; 512]);
        assert_eq!(dissect_tftp(&data).expect("data").info, "Data Packet, Block: 7");
        assert_eq!(dissect_tftp(&[0, 4, 0, 7]).expect("ack").info, "Acknowledgement, Block: 7");
        let error = b"\x00\x05\x00\x01missing.bin\x00";
        assert_eq!(dissect_tftp(error).expect("error").info, "Error Code, Code: File not found, Message: missing.bin");
        let option_ack = b"\x00\x06blksize\x001428\x00";
        assert_eq!(dissect_tftp(option_ack).expect("oack").info, "Option Acknowledgement, blksize=1428");
        assert!(!is_request(&data));
    }

    #[test]
    fn malformed_packets_are_not_tftp() {
        assert!(dissect_tftp(&[0]).is_none());
        assert!(dissect_tftp(&[0, 9, 0, 1]).is_none(), "unknown opcode");
        assert!(dissect_tftp(&read_request("a", "binary", &[])).is_none(), "unknown mode");
        assert!(dissect_tftp(b"\x00\x01file-without-terminator").is_none());
        assert!(dissect_tftp(&[0, 4, 0, 1, 0]).is_none(), "an acknowledgement is four bytes");
        assert!(dissect_tftp(b"\x00\x06blksize\x00").is_none(), "an option without a value");
        let request = read_request("boot.img", "netascii", &[]);
        for cut in 0..request.len() {
            assert!(dissect_tftp(&request[..cut]).is_none(), "cut at {cut}");
        }
    }
}
