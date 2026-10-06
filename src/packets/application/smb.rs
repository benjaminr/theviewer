//! The NetBIOS Session Service (RFC 1002 section 4.3) on TCP port 139, the
//! same four-byte framing on port 445, and the headers of the SMB messages
//! inside: SMB1 ([MS-CIFS] 2.2.3.1) and SMB2/3 ([MS-SMB2] 2.2.1, 2.2.41).
//! Only headers are read, not each command's body.

use crate::plugin::Field;

use super::{AppLayer, u16_at};

const NBSS_HEADER_LEN: usize = 4;
const NBSS_SESSION_MESSAGE: u8 = 0x00;
const NBSS_SESSION_REQUEST: u8 = 0x81;
const NBSS_POSITIVE_RESPONSE: u8 = 0x82;
const NBSS_NEGATIVE_RESPONSE: u8 = 0x83;
const NBSS_RETARGET_RESPONSE: u8 = 0x84;
const NBSS_KEEP_ALIVE: u8 = 0x85;
/// The flags bit that adds a 17th bit to the length.
const NBSS_LENGTH_EXTENSION: u8 = 0x01;
/// An encoded NetBIOS name: a length byte of 32, 32 letters, a zero.
const NETBIOS_NAME_LEN: usize = 34;
const NETBIOS_ENCODED_LEN: u8 = 32;

const SMB1_HEADER_LEN: usize = 32;
const SMB2_HEADER_LEN: usize = 64;
const SMB2_TRANSFORM_HEADER_LEN: usize = 52;
const SMB1_PROTOCOL: [u8; 4] = [0xFF, b'S', b'M', b'B'];
const SMB2_PROTOCOL: [u8; 4] = [0xFE, b'S', b'M', b'B'];
const SMB2_TRANSFORM_PROTOCOL: [u8; 4] = [0xFD, b'S', b'M', b'B'];
const SMB2_COMPRESSION_PROTOCOL: [u8; 4] = [0xFC, b'S', b'M', b'B'];
const SMB1_FLAGS_REPLY: u8 = 0x80;
/// Flags2 bit saying the status is a 32-bit NTSTATUS.
const SMB1_FLAGS2_NT_STATUS: u16 = 0x4000;
const SMB2_FLAGS_RESPONSE: u32 = 0x0000_0001;
const SMB2_FLAGS_ASYNC: u32 = 0x0000_0002;
const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;
/// Most messages of an SMB2 compound listed.
const MAX_COMPOUND: usize = 16;

fn u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    let mut eight = [0u8; 8];
    eight.copy_from_slice(bytes.get(at..at + 8)?);
    Some(u64::from_le_bytes(eight))
}

fn nbss_type_name(kind: u8) -> &'static str {
    match kind {
        NBSS_SESSION_MESSAGE => "Session message",
        NBSS_SESSION_REQUEST => "Session request",
        NBSS_POSITIVE_RESPONSE => "Positive session response",
        NBSS_NEGATIVE_RESPONSE => "Negative session response",
        NBSS_RETARGET_RESPONSE => "Retarget session response",
        NBSS_KEEP_ALIVE => "Session keep-alive",
        _ => "Unknown",
    }
}

fn negative_response_reason(code: u8) -> &'static str {
    match code {
        0x80 => "Not listening on called name",
        0x81 => "Not listening for calling name",
        0x82 => "Called name not present",
        0x83 => "Called name present, but insufficient resources",
        0x8F => "Unspecified error",
        _ => "Unknown",
    }
}

/// Names of NTSTATUS codes met in SMB traffic.
fn nt_status_name(status: u32) -> Option<&'static str> {
    Some(match status {
        0x0000_0000 => "STATUS_SUCCESS",
        0x0000_0103 => "STATUS_PENDING",
        0x0000_010B => "STATUS_NOTIFY_CLEANUP",
        0x0000_010C => "STATUS_NOTIFY_ENUM_DIR",
        0x8000_0005 => "STATUS_BUFFER_OVERFLOW",
        0x8000_0006 => "STATUS_NO_MORE_FILES",
        0xC000_000D => "STATUS_INVALID_PARAMETER",
        0xC000_000F => "STATUS_NO_SUCH_FILE",
        0xC000_0010 => "STATUS_INVALID_DEVICE_REQUEST",
        0xC000_0011 => "STATUS_END_OF_FILE",
        0xC000_0016 => "STATUS_MORE_PROCESSING_REQUIRED",
        0xC000_0022 => "STATUS_ACCESS_DENIED",
        0xC000_0023 => "STATUS_BUFFER_TOO_SMALL",
        0xC000_0033 => "STATUS_OBJECT_NAME_INVALID",
        0xC000_0034 => "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC000_0035 => "STATUS_OBJECT_NAME_COLLISION",
        0xC000_003A => "STATUS_OBJECT_PATH_NOT_FOUND",
        0xC000_0043 => "STATUS_SHARING_VIOLATION",
        0xC000_006D => "STATUS_LOGON_FAILURE",
        0xC000_00BB => "STATUS_NOT_SUPPORTED",
        0xC000_00CC => "STATUS_BAD_NETWORK_NAME",
        0xC000_0120 => "STATUS_CANCELLED",
        0xC000_0128 => "STATUS_FILE_CLOSED",
        0xC000_0225 => "STATUS_NOT_FOUND",
        0xC000_0203 => "STATUS_USER_SESSION_DELETED",
        0xC000_035C => "STATUS_NETWORK_SESSION_EXPIRED",
        _ => return None,
    })
}

fn nt_status_text(status: u32) -> String {
    match nt_status_name(status) {
        Some(name) => format!("{status:#010x} ({name})"),
        None => format!("{status:#010x}"),
    }
}

/// ", Error: …" for a status that is not success (nor pending), as
/// Wireshark's packet list shows it.
fn error_suffix(status: u32) -> String {
    match status {
        0 | 0x0000_0103 => String::new(),
        other => format!(", Error: {}", nt_status_name(other).map_or_else(|| format!("{other:#010x}"), str::to_string)),
    }
}

fn smb1_command_name(command: u8) -> &'static str {
    match command {
        0x00 => "Create Directory",
        0x01 => "Delete Directory",
        0x02 => "Open",
        0x04 => "Close",
        0x06 => "Delete",
        0x07 => "Rename",
        0x08 => "Query Information",
        0x0A => "Read",
        0x0B => "Write",
        0x10 => "Check Directory",
        0x24 => "Locking AndX",
        0x25 => "Trans",
        0x2B => "Echo",
        0x2D => "Open AndX",
        0x2E => "Read AndX",
        0x2F => "Write AndX",
        0x32 => "Trans2",
        0x34 => "Find Close2",
        0x71 => "Tree Disconnect",
        0x72 => "Negotiate Protocol",
        0x73 => "Session Setup AndX",
        0x74 => "Logoff AndX",
        0x75 => "Tree Connect AndX",
        0xA0 => "NT Trans",
        0xA2 => "NT Create AndX",
        0xA4 => "NT Cancel",
        _ => "Unknown command",
    }
}

fn smb2_command_name(command: u16) -> &'static str {
    match command {
        0 => "Negotiate Protocol",
        1 => "Session Setup",
        2 => "Session Logoff",
        3 => "Tree Connect",
        4 => "Tree Disconnect",
        5 => "Create",
        6 => "Close",
        7 => "Flush",
        8 => "Read",
        9 => "Write",
        10 => "Lock",
        11 => "Ioctl",
        12 => "Cancel",
        13 => "KeepAlive",
        14 => "Find",
        15 => "Notify",
        16 => "GetInfo",
        17 => "SetInfo",
        18 => "Break",
        _ => "Unknown command",
    }
}

/// The 16-byte NetBIOS name hidden in a 34-byte encoded one (RFC 1001
/// section 14.1): each byte as two letters from 'A', a nibble each. Returns
/// the name, trimmed, with its suffix byte, such as "SERVER<20>".
fn netbios_name(encoded: &[u8]) -> Option<String> {
    if encoded.len() != NETBIOS_NAME_LEN || encoded[0] != NETBIOS_ENCODED_LEN || encoded[NETBIOS_NAME_LEN - 1] != 0 {
        return None;
    }
    let mut name = Vec::with_capacity(16);
    for pair in encoded[1..33].as_chunks::<2>().0 {
        let (high, low) = (pair[0].wrapping_sub(b'A'), pair[1].wrapping_sub(b'A'));
        if high > 15 || low > 15 {
            return None;
        }
        name.push((high << 4) | low);
    }
    let suffix = name[15];
    let text = String::from_utf8_lossy(&name[..15]).trim_end().to_string();
    Some(format!("{text}<{suffix:02x}>"))
}

/// A NetBIOS session service message, or (with `direct_tcp`, on port 445)
/// the four-byte framing alone, followed by the SMB header it carries.
pub fn dissect_netbios_session(payload: &[u8], direct_tcp: bool) -> Vec<AppLayer> {
    let Some(header) = payload.get(..NBSS_HEADER_LEN) else { return Vec::new() };
    let kind = header[0];
    let flags = header[1];
    // On 445 the length takes all three bytes after the zero type byte.
    let length = if direct_tcp {
        u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize
    } else {
        u16_at(header, 2).unwrap_or_default() as usize | (((flags & NBSS_LENGTH_EXTENSION) as usize) << 16)
    };
    let valid = match (direct_tcp, kind) {
        (true, NBSS_SESSION_MESSAGE) => true,
        (false, NBSS_SESSION_MESSAGE | NBSS_SESSION_REQUEST | NBSS_POSITIVE_RESPONSE | NBSS_NEGATIVE_RESPONSE | NBSS_RETARGET_RESPONSE | NBSS_KEEP_ALIVE) => flags & !NBSS_LENGTH_EXTENSION == 0,
        _ => false,
    };
    if !valid {
        return Vec::new();
    }
    let end = (NBSS_HEADER_LEN + length).min(payload.len());
    let mut fields = vec![Field::new("Message type", 0, 1, format!("{kind:#04x} ({})", nbss_type_name(kind)))];
    if direct_tcp {
        fields.push(Field::new("Length", 1, 3, length.to_string()));
    } else {
        fields.push(Field::new("Flags", 1, 1, format!("{flags:#04x}")));
        fields.push(Field::new("Length", 2, 2, length.to_string()));
    }
    let mut info = nbss_type_name(kind).to_string();
    match kind {
        NBSS_SESSION_REQUEST => {
            let called = payload.get(4..4 + NETBIOS_NAME_LEN).and_then(netbios_name);
            let calling = payload.get(4 + NETBIOS_NAME_LEN..4 + 2 * NETBIOS_NAME_LEN).and_then(netbios_name);
            if let Some(called) = &called {
                fields.push(Field::new("Called name", 4, NETBIOS_NAME_LEN, called.clone()));
            }
            if let Some(calling) = &calling {
                fields.push(Field::new("Calling name", 4 + NETBIOS_NAME_LEN, NETBIOS_NAME_LEN, calling.clone()));
            }
            if let (Some(called), Some(calling)) = (called, calling) {
                info = format!("Session request, to {called} from {calling}");
            }
        }
        NBSS_NEGATIVE_RESPONSE => {
            if let Some(&code) = payload.get(NBSS_HEADER_LEN) {
                fields.push(Field::new("Error code", NBSS_HEADER_LEN, 1, format!("{code:#04x} ({})", negative_response_reason(code))));
                info = format!("Negative session response, {}", negative_response_reason(code));
            }
        }
        _ => {}
    }
    let carries_smb = kind == NBSS_SESSION_MESSAGE;
    let header_only = if carries_smb { NBSS_HEADER_LEN } else { end };
    let mut layers = vec![AppLayer { name: "NetBIOS Session Service", key: "nbss", len: header_only, fields, info }];
    if carries_smb {
        let message = &payload[NBSS_HEADER_LEN..end];
        layers.extend(smb_messages(message, NBSS_HEADER_LEN));
    }
    layers
}

/// The SMB layers of one message starting at `base` in the payload.
fn smb_messages(message: &[u8], base: usize) -> Vec<AppLayer> {
    let mut layers = match message.get(..4) {
        Some(protocol) if protocol == SMB1_PROTOCOL => smb1_header(message).into_iter().collect(),
        Some(protocol) if protocol == SMB2_PROTOCOL => smb2_compound(message),
        Some(protocol) if protocol == SMB2_TRANSFORM_PROTOCOL => smb2_transform_header(message).into_iter().collect(),
        Some(protocol) if protocol == SMB2_COMPRESSION_PROTOCOL => vec![smb2_compression_header(message)],
        _ => Vec::new(),
    };
    for layer in &mut layers {
        super::shift_fields(&mut layer.fields, base);
    }
    layers
}

/// The SMB1 header ([MS-CIFS] 2.2.3.1).
fn smb1_header(message: &[u8]) -> Option<AppLayer> {
    if message.len() < SMB1_HEADER_LEN {
        return None;
    }
    let command = message[4];
    let flags = message[9];
    let flags2 = u16_le(message, 10)?;
    let is_reply = flags & SMB1_FLAGS_REPLY != 0;
    let status_value = u32_le(message, 5)?;
    let status = if flags2 & SMB1_FLAGS2_NT_STATUS != 0 {
        nt_status_text(status_value)
    } else {
        format!("DOS error class {}, code {}", message[5], u16_le(message, 7)?)
    };
    let fields = vec![
        Field::new("Protocol", 0, 4, "\\xFFSMB"),
        Field::new("Command", 4, 1, format!("{command:#04x} ({})", smb1_command_name(command))),
        Field::new("Status", 5, 4, status),
        Field::new("Flags", 9, 1, format!("{flags:#04x} ({})", if is_reply { "reply" } else { "request" })),
        Field::new("Flags2", 10, 2, format!("{flags2:#06x}")),
        Field::new("Process ID high", 12, 2, u16_le(message, 12)?.to_string()),
        Field::new("Security features", 14, 8, super::super::hex_preview(&message[14..22], 8)),
        Field::new("Tree ID", 24, 2, u16_le(message, 24)?.to_string()),
        Field::new("Process ID", 26, 2, u16_le(message, 26)?.to_string()),
        Field::new("User ID", 28, 2, u16_le(message, 28)?.to_string()),
        Field::new("Multiplex ID", 30, 2, u16_le(message, 30)?.to_string()),
    ];
    let direction = if is_reply { "Response" } else { "Request" };
    let error = if is_reply && flags2 & SMB1_FLAGS2_NT_STATUS != 0 { error_suffix(status_value) } else { String::new() };
    let info = format!("SMB {} {direction}{error}", smb1_command_name(command));
    Some(AppLayer { name: "SMB", key: "smb", len: message.len(), fields, info })
}

/// Each SMB2 header of a compound, chained by the next-command offset; the
/// last layer's info names them all.
fn smb2_compound(message: &[u8]) -> Vec<AppLayer> {
    let mut layers: Vec<AppLayer> = Vec::new();
    let mut at = 0;
    while layers.len() < MAX_COMPOUND {
        let Some((mut layer, next)) = smb2_header(&message[at..]) else { break };
        super::shift_fields(&mut layer.fields, at);
        layers.push(layer);
        match next {
            Some(next) => at += next,
            None => break,
        }
    }
    let infos: Vec<String> = layers.iter().map(|layer| layer.info.clone()).collect();
    if let Some(last) = layers.last_mut() {
        last.info = infos.join("; ");
    }
    layers
}

/// One SMB2 header ([MS-SMB2] 2.2.1). Returns its layer, covering the
/// message, and the offset of the next message of a compound.
fn smb2_header(message: &[u8]) -> Option<(AppLayer, Option<usize>)> {
    if message.len() < SMB2_HEADER_LEN || message[..4] != SMB2_PROTOCOL || u16_le(message, 4)? as usize != SMB2_HEADER_LEN {
        return None;
    }
    let status = u32_le(message, 8)?;
    let command = u16_le(message, 12)?;
    let credits = u16_le(message, 14)?;
    let flags = u32_le(message, 16)?;
    let next_command = u32_le(message, 20)? as usize;
    let message_id = u64_le(message, 24)?;
    let session_id = u64_le(message, 40)?;
    let is_response = flags & SMB2_FLAGS_RESPONSE != 0;
    let flag_names: Vec<&str> = [(SMB2_FLAGS_RESPONSE, "response"), (SMB2_FLAGS_ASYNC, "async"), (SMB2_FLAGS_SIGNED, "signed")]
        .into_iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| name)
        .collect();
    let mut fields = vec![
        Field::new("Protocol ID", 0, 4, "\\xFESMB"),
        Field::new("Header length", 4, 2, SMB2_HEADER_LEN.to_string()),
        Field::new("Credit charge", 6, 2, u16_le(message, 6)?.to_string()),
        Field::new("Status", 8, 4, if is_response { nt_status_text(status) } else { format!("{status:#010x} (channel sequence)") }),
        Field::new("Command", 12, 2, format!("{command} ({})", smb2_command_name(command))),
        Field::new(if is_response { "Credit response" } else { "Credit request" }, 14, 2, credits.to_string()),
        Field::new("Flags", 16, 4, format!("{flags:#010x}{}", if flag_names.is_empty() { String::new() } else { format!(" ({})", flag_names.join(", ")) })),
        Field::new("Chain offset", 20, 4, next_command.to_string()),
        Field::new("Message ID", 24, 8, message_id.to_string()),
    ];
    if flags & SMB2_FLAGS_ASYNC != 0 {
        fields.push(Field::new("Async ID", 32, 8, format!("{:#x}", u64_le(message, 32)?)));
    } else {
        fields.push(Field::new("Process ID", 32, 4, format!("{:#010x}", u32_le(message, 32)?)));
        fields.push(Field::new("Tree ID", 36, 4, format!("{:#010x}", u32_le(message, 36)?)));
    }
    fields.push(Field::new("Session ID", 40, 8, format!("{session_id:#018x}")));
    fields.push(Field::new("Signature", 48, 16, super::super::hex_preview(&message[48..64], 16)));
    // A next-command offset must move forwards past this header, in eights.
    let next = (next_command >= SMB2_HEADER_LEN && next_command.is_multiple_of(8) && next_command < message.len()).then_some(next_command);
    let len = next.unwrap_or(message.len());
    let direction = if is_response { "Response" } else { "Request" };
    let error = if is_response { error_suffix(status) } else { String::new() };
    let info = format!("SMB2 {} {direction}{error}", smb2_command_name(command));
    Some((AppLayer { name: "SMB2", key: "smb2", len, fields, info }, next))
}

/// The SMB3 transform header ([MS-SMB2] 2.2.41) of an encrypted message.
fn smb2_transform_header(message: &[u8]) -> Option<AppLayer> {
    if message.len() < SMB2_TRANSFORM_HEADER_LEN {
        return None;
    }
    let session_id = u64_le(message, 44)?;
    let fields = vec![
        Field::new("Protocol ID", 0, 4, "\\xFDSMB"),
        Field::new("Signature", 4, 16, super::super::hex_preview(&message[4..20], 16)),
        Field::new("Nonce", 20, 16, super::super::hex_preview(&message[20..36], 16)),
        Field::new("Original message size", 36, 4, u32_le(message, 36)?.to_string()),
        Field::new("Encryption flags", 42, 2, format!("{:#06x}", u16_le(message, 42)?)),
        Field::new("Session ID", 44, 8, format!("{session_id:#018x}")),
    ];
    let info = format!("SMB3 Encrypted message, Session ID {session_id:#x}");
    Some(AppLayer { name: "SMB2", key: "smb2", len: message.len(), fields, info })
}

/// The SMB3 compression transform header ([MS-SMB2] 2.2.42): its protocol
/// ID; what follows depends on the algorithm.
fn smb2_compression_header(message: &[u8]) -> AppLayer {
    let fields = vec![Field::new("Protocol ID", 0, 4, "\\xFCSMB")];
    AppLayer { name: "SMB2", key: "smb2", len: message.len(), fields, info: "SMB3 Compressed message".to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An SMB2 header for `command` with message ID `message_id`.
    fn smb2(command: u16, is_response: bool, status: u32, message_id: u64) -> Vec<u8> {
        let mut header = vec![0u8; SMB2_HEADER_LEN];
        header[..4].copy_from_slice(&SMB2_PROTOCOL);
        header[4] = SMB2_HEADER_LEN as u8;
        header[8..12].copy_from_slice(&status.to_le_bytes());
        header[12..14].copy_from_slice(&command.to_le_bytes());
        header[14] = 1;
        header[16] = u8::from(is_response);
        header[24..32].copy_from_slice(&message_id.to_le_bytes());
        header[36..40].copy_from_slice(&5u32.to_le_bytes());
        header[40..48].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        header
    }

    /// `body` behind the four-byte framing of port 445.
    fn framed(body: &[u8]) -> Vec<u8> {
        let mut payload = vec![0, 0, (body.len() >> 8) as u8, body.len() as u8];
        payload.extend_from_slice(body);
        payload
    }

    fn field<'a>(layer: &'a AppLayer, name: &str) -> &'a Field {
        layer.fields.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no field {name} in {:?}", layer.fields))
    }

    #[test]
    fn an_smb2_negotiate_request_on_port_445_shows_its_framing_and_header() {
        let mut body = smb2(0, false, 0, 0);
        body.extend_from_slice(&[0x24, 0, 2, 0]);
        let payload = framed(&body);
        let layers = dissect_netbios_session(&payload, true);
        assert_eq!(layers.len(), 2);
        assert_eq!((layers[0].name, layers[0].len), ("NetBIOS Session Service", 4));
        assert_eq!(field(&layers[0], "Length").value, body.len().to_string());
        let smb = &layers[1];
        assert_eq!(smb.info, "SMB2 Negotiate Protocol Request");
        assert_eq!(smb.len, body.len());
        let message_id = field(smb, "Message ID");
        assert_eq!((message_id.offset, message_id.len), (4 + 24, 8));
        assert_eq!(field(smb, "Tree ID").value, "0x00000005");
        assert_eq!(field(smb, "Session ID").value, "0x1122334455667788");
    }

    #[test]
    fn an_smb2_error_response_and_a_compound_are_described_like_wireshark() {
        let response = smb2(1, true, 0xC000_0016, 1);
        assert_eq!(dissect_netbios_session(&framed(&response), true)[1].info, "SMB2 Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED");
        let mut first = smb2(5, false, 0, 4);
        first[20] = 72; // the next message starts 72 bytes on
        first.extend_from_slice(&[0; 8]);
        let second = smb2(16, false, 0, 5);
        let layers = dissect_netbios_session(&framed(&[first, second].concat()), true);
        assert_eq!(layers.len(), 3);
        assert_eq!(layers[1].len, 72);
        assert_eq!(field(&layers[2], "Message ID").offset, 4 + 72 + 24);
        assert_eq!(layers[2].info, "SMB2 Create Request; SMB2 GetInfo Request");
    }

    #[test]
    fn an_smb1_negotiate_on_port_139_and_a_session_request_are_read() {
        let mut smb1 = vec![0u8; SMB1_HEADER_LEN];
        smb1[..4].copy_from_slice(&SMB1_PROTOCOL);
        smb1[4] = 0x72;
        smb1[10..12].copy_from_slice(&SMB1_FLAGS2_NT_STATUS.to_le_bytes());
        smb1[30] = 9;
        let payload = framed(&smb1);
        let layers = dissect_netbios_session(&payload, false);
        assert_eq!(layers[1].info, "SMB Negotiate Protocol Request");
        assert_eq!(field(&layers[1], "Multiplex ID").value, "9");
        assert_eq!(field(&layers[0], "Flags").value, "0x00");

        // "SERVER" padded with spaces and suffix 0x20, then "CLIENT" with 0x00.
        let encode = |name: &str, suffix: u8| {
            let mut raw: Vec<u8> = format!("{name:<15}").into_bytes();
            raw.push(suffix);
            let mut encoded = vec![NETBIOS_ENCODED_LEN];
            for byte in raw {
                encoded.extend_from_slice(&[b'A' + (byte >> 4), b'A' + (byte & 0x0F)]);
            }
            encoded.push(0);
            encoded
        };
        let mut request = vec![NBSS_SESSION_REQUEST, 0, 0, 68];
        request.extend(encode("SERVER", 0x20));
        request.extend(encode("CLIENT", 0x00));
        let layers = dissect_netbios_session(&request, false);
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].info, "Session request, to SERVER<20> from CLIENT<00>");
        assert_eq!(layers[0].len, request.len());
    }

    #[test]
    fn foreign_or_truncated_bytes_give_no_smb_layers_and_never_panic() {
        assert!(dissect_netbios_session(&[0x42, 0, 0, 0], false).is_empty(), "unknown message type");
        assert!(dissect_netbios_session(&[0x81, 0], false).is_empty());
        assert!(dissect_netbios_session(&[0x85, 0, 0, 0], true).is_empty(), "port 445 carries session messages only");
        let whole = framed(&smb2(8, false, 0, 3));
        for cut in 0..whole.len() {
            let layers = dissect_netbios_session(&whole[..cut], true);
            assert!(layers.len() <= 1, "a cut SMB2 header is not read (cut at {cut})");
        }
        let mut state = 0x1234_5678u32;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let mut bytes = whole.clone();
            let at = state as usize % bytes.len();
            bytes[at] = (state >> 8) as u8;
            let _ = dissect_netbios_session(&bytes, state.is_multiple_of(2));
        }
    }
}
