//! ISO transport over TCP port 102: TPKT (RFC 1006), the connection-oriented
//! transport protocol COTP inside it (ISO 8073 / ITU-T X.224), and the
//! header of a Siemens S7comm message carried in COTP data.
//!
//! S7comm has no published specification; its header layout here is the
//! one established by public research and open-source tools.

use crate::plugin::Field;

use super::{AppLayer, u16_at};

const TPKT_VERSION: u8 = 3;
const TPKT_HEADER_LEN: usize = 4;
/// A TPKT packet holds at least its header and a COTP header of three bytes.
const TPKT_MIN_LENGTH: usize = 7;

const COTP_CONNECTION_REQUEST: u8 = 0xE0;
const COTP_CONNECTION_CONFIRM: u8 = 0xD0;
const COTP_DISCONNECT_REQUEST: u8 = 0x80;
const COTP_DISCONNECT_CONFIRM: u8 = 0xC0;
const COTP_DATA: u8 = 0xF0;
const COTP_EXPEDITED_DATA: u8 = 0x10;
const COTP_DATA_ACK: u8 = 0x60;
const COTP_EXPEDITED_ACK: u8 = 0x20;
const COTP_REJECT: u8 = 0x50;
const COTP_ERROR: u8 = 0x70;
/// The end-of-transmission bit of a data TPDU's number byte.
const COTP_EOT: u8 = 0x80;
const COTP_PARAMETER_TPDU_SIZE: u8 = 0xC0;
const COTP_PARAMETER_CALLING_TSAP: u8 = 0xC1;
const COTP_PARAMETER_CALLED_TSAP: u8 = 0xC2;
/// The header bytes after the length indicator of a disconnect confirm:
/// the code and the destination and source references.
const COTP_REFERENCES_LEN: usize = 5;
/// Connection requests and confirms add their class, disconnect requests
/// their reason.
const COTP_REFERENCES_AND_ONE_LEN: usize = 6;
/// Most COTP parameters listed.
const COTP_MAX_PARAMETERS: usize = 16;

const S7_PROTOCOL_ID: u8 = 0x32;
const S7_HEADER_LEN: usize = 10;
/// Acknowledgements add an error class and code.
const S7_ACK_HEADER_LEN: usize = 12;
const ROSCTR_JOB: u8 = 1;
const ROSCTR_ACK: u8 = 2;
const ROSCTR_ACK_DATA: u8 = 3;
const ROSCTR_USERDATA: u8 = 7;
const S7_FUNCTION_SETUP: u8 = 0xF0;
const S7_FUNCTION_READ_VAR: u8 = 0x04;
const S7_FUNCTION_WRITE_VAR: u8 = 0x05;
/// A read or write item addressed by area, as most are: its specification
/// type 0x12, length 10 and syntax ID 0x10 (S7ANY).
const S7_ITEM_LEN: usize = 12;
const S7_ITEM_SYNTAX_ANY: u8 = 0x10;
/// Most read or write items listed.
const S7_MAX_ITEMS: usize = 32;
/// The userdata parameter header 0x00 0x01 0x12.
const S7_USERDATA_HEAD: [u8; 3] = [0x00, 0x01, 0x12];
/// Bytes of a data block shown as hex.
const DATA_PREVIEW_BYTES: usize = 16;

fn cotp_type_name(code: u8) -> &'static str {
    match code {
        COTP_CONNECTION_REQUEST => "CR Connect Request",
        COTP_CONNECTION_CONFIRM => "CC Connect Confirm",
        COTP_DISCONNECT_REQUEST => "DR Disconnect Request",
        COTP_DISCONNECT_CONFIRM => "DC Disconnect Confirm",
        COTP_DATA => "DT Data",
        COTP_EXPEDITED_DATA => "ED Expedited Data",
        COTP_DATA_ACK => "AK Data Acknowledgement",
        COTP_EXPEDITED_ACK => "EA Expedited Acknowledgement",
        COTP_REJECT => "RJ Reject",
        COTP_ERROR => "ER TPDU Error",
        _ => "Unknown",
    }
}

fn rosctr_name(rosctr: u8) -> &'static str {
    match rosctr {
        ROSCTR_JOB => "Job",
        ROSCTR_ACK => "Ack",
        ROSCTR_ACK_DATA => "Ack_Data",
        ROSCTR_USERDATA => "Userdata",
        _ => "Unknown",
    }
}

fn s7_function_name(function: u8) -> &'static str {
    match function {
        0x00 => "CPU services",
        S7_FUNCTION_SETUP => "Setup communication",
        S7_FUNCTION_READ_VAR => "Read Var",
        S7_FUNCTION_WRITE_VAR => "Write Var",
        0x1A => "Request download",
        0x1B => "Download block",
        0x1C => "Download ended",
        0x1D => "Start upload",
        0x1E => "Upload",
        0x1F => "End upload",
        0x28 => "PI-Service",
        0x29 => "PLC Stop",
        _ => "Unknown function",
    }
}

fn s7_area_name(area: u8) -> &'static str {
    match area {
        0x03 => "System info of 200 family",
        0x05 => "System flags of 200 family",
        0x06 => "Analog inputs of 200 family",
        0x07 => "Analog outputs of 200 family",
        0x1C => "Counter (C)",
        0x1D => "Timer (T)",
        0x1E => "IEC counter (200 family)",
        0x1F => "IEC timer (200 family)",
        0x80 => "Direct peripheral access (P)",
        0x81 => "Inputs (I)",
        0x82 => "Outputs (Q)",
        0x83 => "Flags (M)",
        0x84 => "Data blocks (DB)",
        0x85 => "Instance data blocks (DI)",
        0x86 => "Local data (L)",
        0x87 => "Unknown yet (V)",
        _ => "Unknown area",
    }
}

fn userdata_group_name(group: u8) -> &'static str {
    match group {
        0x0 => "Mode-transition",
        0x1 => "Programmer commands",
        0x2 => "Cyclic data",
        0x3 => "Block functions",
        0x4 => "CPU functions",
        0x5 => "Security",
        0x6 => "PBC BSEND/BRECV",
        0x7 => "Time functions",
        0xF => "NC programming",
        _ => "Unknown",
    }
}

fn userdata_method_name(kind: u8) -> &'static str {
    match kind {
        0x0 => "Push",
        0x4 => "Request",
        0x8 => "Response",
        _ => "Unknown",
    }
}

/// TPKT, the COTP TPDU inside it and, in a data TPDU, the S7comm header:
/// the layers found, outermost first; none when the bytes are not TPKT.
pub fn dissect_tpkt(payload: &[u8]) -> Vec<AppLayer> {
    let (Some(&version), Some(&reserved), Some(length)) = (payload.first(), payload.get(1), u16_at(payload, 2)) else { return Vec::new() };
    let length = length as usize;
    if version != TPKT_VERSION || reserved != 0 || length < TPKT_MIN_LENGTH {
        return Vec::new();
    }
    let end = length.min(payload.len());
    let tpkt = AppLayer {
        name: "TPKT",
        key: "tpkt",
        len: TPKT_HEADER_LEN,
        fields: vec![Field::new("Version", 0, 1, version.to_string()), Field::new("Reserved", 1, 1, reserved.to_string()), Field::new("Length", 2, 2, length.to_string())],
        info: format!("TPKT, Version: {version}, Length: {length}"),
    };
    let mut layers = vec![tpkt];
    let Some((cotp, user_data_at)) = cotp_tpdu(payload, TPKT_HEADER_LEN, end) else { return layers };
    let cotp_end = cotp.len + TPKT_HEADER_LEN;
    let is_data = user_data_at.is_some();
    layers.push(cotp);
    if is_data && let Some(s7) = s7comm(payload, cotp_end, end) {
        layers.push(s7);
    }
    layers
}

/// The COTP TPDU at `at`, ending by `end`. Returns its layer and, for a data
/// TPDU, where the user data starts.
fn cotp_tpdu(payload: &[u8], at: usize, end: usize) -> Option<(AppLayer, Option<usize>)> {
    let li = *payload.get(at)? as usize;
    let header_end = at + 1 + li;
    if li < 2 || header_end > end {
        return None;
    }
    let code_byte = payload[at + 1];
    let code = code_byte & 0xF0;
    let mut fields = vec![
        Field::new("Length indicator", at, 1, li.to_string()),
        Field::new("PDU type", at + 1, 1, format!("{code:#04x} ({})", cotp_type_name(code))),
    ];
    let mut user_data_at = None;
    let info = match code {
        COTP_CONNECTION_REQUEST | COTP_CONNECTION_CONFIRM | COTP_DISCONNECT_REQUEST | COTP_DISCONNECT_CONFIRM => {
            let needed = if code == COTP_DISCONNECT_CONFIRM { COTP_REFERENCES_LEN } else { COTP_REFERENCES_AND_ONE_LEN };
            if li < needed {
                return None;
            }
            let destination = u16_at(payload, at + 2)?;
            let source = u16_at(payload, at + 4)?;
            fields.push(Field::new("Destination reference", at + 2, 2, format!("{destination:#06x}")));
            fields.push(Field::new("Source reference", at + 4, 2, format!("{source:#06x}")));
            let third = if li >= COTP_REFERENCES_AND_ONE_LEN { payload[at + 6] } else { 0 };
            let parameters_at = match code {
                COTP_CONNECTION_REQUEST | COTP_CONNECTION_CONFIRM => {
                    fields.push(Field::new("Class", at + 6, 1, format!("{} (options {:#x})", third >> 4, third & 0x0F)));
                    at + 7
                }
                COTP_DISCONNECT_REQUEST => {
                    fields.push(Field::new("Reason", at + 6, 1, format!("{third:#04x}")));
                    at + 7
                }
                _ => at + 6,
            };
            fields.extend(cotp_parameters(payload, parameters_at, header_end));
            format!("{} TPDU src-ref: {source:#06x} dst-ref: {destination:#06x}", &cotp_type_name(code)[..2])
        }
        COTP_DATA => {
            let number = *payload.get(at + 2)?;
            fields.push(Field::new("TPDU number", at + 2, 1, (number & !COTP_EOT).to_string()));
            fields.push(Field::new("EOT", at + 2, 1, if number & COTP_EOT != 0 { "yes, the last data unit" } else { "no, more follow" }));
            user_data_at = Some(header_end);
            format!("DT TPDU ({}){}", number & !COTP_EOT, if number & COTP_EOT != 0 { " EOT" } else { "" })
        }
        _ if cotp_type_name(code) != "Unknown" => format!("{} TPDU", &cotp_type_name(code)[..2]),
        _ => return None,
    };
    let len = header_end - at;
    Some((AppLayer { name: "COTP", key: "cotp", len, fields, info }, user_data_at))
}

/// The parameters of a connection TPDU: type, length and value each.
fn cotp_parameters(payload: &[u8], mut at: usize, end: usize) -> Vec<Field> {
    let mut fields = Vec::new();
    while at + 2 <= end && fields.len() < COTP_MAX_PARAMETERS {
        let code = payload[at];
        let len = payload[at + 1] as usize;
        let Some(value) = payload.get(at + 2..at + 2 + len).filter(|_| at + 2 + len <= end) else { break };
        let field = match code {
            COTP_PARAMETER_TPDU_SIZE if len == 1 => Field::new("TPDU size", at, 2 + len, format!("{} bytes", 1u32.checked_shl(value[0] as u32).unwrap_or_default())),
            COTP_PARAMETER_CALLING_TSAP => Field::new("Calling TSAP", at, 2 + len, super::super::hex_preview(value, DATA_PREVIEW_BYTES)),
            COTP_PARAMETER_CALLED_TSAP => Field::new("Called TSAP", at, 2 + len, super::super::hex_preview(value, DATA_PREVIEW_BYTES)),
            other => Field::new(format!("Parameter {other:#04x}"), at, 2 + len, super::super::hex_preview(value, DATA_PREVIEW_BYTES)),
        };
        fields.push(field);
        at += 2 + len;
    }
    fields
}

/// The S7comm message at `at`, ending by `end`, or `None` when it is not one.
fn s7comm(payload: &[u8], at: usize, end: usize) -> Option<AppLayer> {
    let message = payload.get(at..end)?;
    if message.first() != Some(&S7_PROTOCOL_ID) || message.len() < S7_HEADER_LEN {
        return None;
    }
    let rosctr = message[1];
    if !matches!(rosctr, ROSCTR_JOB | ROSCTR_ACK | ROSCTR_ACK_DATA | ROSCTR_USERDATA) {
        return None;
    }
    let header_len = if matches!(rosctr, ROSCTR_ACK | ROSCTR_ACK_DATA) { S7_ACK_HEADER_LEN } else { S7_HEADER_LEN };
    if message.len() < header_len {
        return None;
    }
    let parameter_len = u16_at(message, 6)? as usize;
    let data_len = u16_at(message, 8)? as usize;
    let mut fields = vec![
        Field::new("Protocol ID", at, 1, format!("{S7_PROTOCOL_ID:#04x}")),
        Field::new("ROSCTR", at + 1, 1, format!("{rosctr} ({})", rosctr_name(rosctr))),
        Field::new("Redundancy identification", at + 2, 2, format!("{:#06x}", u16_at(message, 2)?)),
        Field::new("PDU reference", at + 4, 2, u16_at(message, 4)?.to_string()),
        Field::new("Parameter length", at + 6, 2, parameter_len.to_string()),
        Field::new("Data length", at + 8, 2, data_len.to_string()),
    ];
    let mut error = String::new();
    if header_len == S7_ACK_HEADER_LEN {
        let (class, code) = (message[10], message[11]);
        fields.push(Field::new("Error class", at + 10, 1, format!("{class:#04x}")));
        fields.push(Field::new("Error code", at + 11, 1, format!("{code:#04x}")));
        if class != 0 || code != 0 {
            error = format!(" -> Errorcode:[{:#06x}]", u16::from_be_bytes([class, code]));
        }
    }
    let parameters_at = header_len;
    let parameters = message.get(parameters_at..parameters_at + parameter_len);
    let mut function_text = String::new();
    if let Some(parameters) = parameters.filter(|p| !p.is_empty()) {
        let (parameter_field, text) = if rosctr == ROSCTR_USERDATA { userdata_parameters(parameters, at + parameters_at) } else { job_parameters(parameters, at + parameters_at) };
        fields.push(parameter_field);
        function_text = text;
    }
    let data_at = parameters_at + parameter_len;
    if data_len > 0
        && let Some(data) = message.get(data_at..(data_at + data_len).min(message.len()))
    {
        fields.push(Field::new("Data", at + data_at, data.len(), format!("{} bytes: {}", data.len(), super::super::hex_preview(data, DATA_PREVIEW_BYTES))));
    }
    let len = (header_len + parameter_len + data_len).min(message.len());
    let info = format!("ROSCTR:[{:<10}] {function_text}{error}", rosctr_name(rosctr)).trim_end().to_string();
    Some(AppLayer { name: "S7comm", key: "s7comm", len, fields, info })
}

/// The parameter block of a job or acknowledgement: its function and, for
/// setup, read and write, what it asks for. Returns the field and the
/// packet list's text, such as "Function:[Read Var]".
fn job_parameters(parameters: &[u8], at: usize) -> (Field, String) {
    let function = parameters[0];
    let mut children = vec![Field::new("Function", at, 1, format!("{function:#04x} ({})", s7_function_name(function)))];
    match function {
        S7_FUNCTION_SETUP if parameters.len() >= 8 => {
            let number = |offset: usize| u16_at(parameters, offset).unwrap_or_default().to_string();
            children.push(Field::new("Max AmQ (parallel jobs with ack) calling", at + 2, 2, number(2)));
            children.push(Field::new("Max AmQ (parallel jobs with ack) called", at + 4, 2, number(4)));
            children.push(Field::new("PDU length", at + 6, 2, number(6)));
        }
        S7_FUNCTION_READ_VAR | S7_FUNCTION_WRITE_VAR if parameters.len() >= 2 => {
            let count = parameters[1] as usize;
            children.push(Field::new("Item count", at + 1, 1, count.to_string()));
            children.extend(read_write_items(parameters, at, count));
        }
        _ => {}
    }
    let field = Field::new("Parameter", at, parameters.len(), s7_function_name(function)).with_children(children);
    (field, format!("Function:[{}]", s7_function_name(function)))
}

/// The items of a read or write request, each addressing an area. A
/// response lists only the count, so nothing more is read from it.
fn read_write_items(parameters: &[u8], at: usize, count: usize) -> Vec<Field> {
    let mut items = Vec::new();
    let mut offset = 2;
    while items.len() < count.min(S7_MAX_ITEMS) {
        let Some(item) = parameters.get(offset..offset + S7_ITEM_LEN) else { break };
        if item[2] != S7_ITEM_SYNTAX_ANY {
            break;
        }
        let length = u16_at(item, 4).unwrap_or_default();
        let db = u16_at(item, 6).unwrap_or_default();
        let area = item[8];
        let address = u32::from_be_bytes([0, item[9], item[10], item[11]]);
        let start = at + offset;
        let db_text = if area == 0x84 { format!("DB{db} ") } else { String::new() };
        let value = format!("{db_text}{} byte {}, bit {}, {length} units of type {:#04x}", s7_area_name(area), address >> 3, address & 0x07, item[3]);
        items.push(Field::new(format!("Item {}", items.len()), start, S7_ITEM_LEN, value).with_children(vec![
            Field::new("Area", start + 8, 1, format!("{area:#04x} ({})", s7_area_name(area))),
            Field::new("DB number", start + 6, 2, db.to_string()),
            Field::new("Address", start + 9, 3, format!("{:#08x} (byte {}, bit {})", address, address >> 3, address & 0x07)),
        ]));
        offset += S7_ITEM_LEN;
    }
    items
}

/// The parameter block of a userdata message: its method, function group
/// and subfunction.
fn userdata_parameters(parameters: &[u8], at: usize) -> (Field, String) {
    if parameters.len() < 8 || parameters[..3] != S7_USERDATA_HEAD {
        return (Field::new("Parameter", at, parameters.len(), super::super::hex_preview(parameters, DATA_PREVIEW_BYTES)), String::new());
    }
    let kind = parameters[5] >> 4;
    let group = parameters[5] & 0x0F;
    let subfunction = parameters[6];
    let children = vec![
        Field::new("Type", at + 5, 1, format!("{kind:#x} ({})", userdata_method_name(kind))),
        Field::new("Function group", at + 5, 1, format!("{group:#x} ({})", userdata_group_name(group))),
        Field::new("Subfunction", at + 6, 1, format!("{subfunction:#04x}")),
        Field::new("Sequence number", at + 7, 1, parameters[7].to_string()),
    ];
    let text = format!("Function:[{}] -> [{}]", userdata_method_name(kind), userdata_group_name(group));
    (Field::new("Parameter", at, parameters.len(), text.clone()).with_children(children), text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cotp_and_more` inside a TPKT header.
    fn tpkt(cotp_and_more: &[u8]) -> Vec<u8> {
        let length = (TPKT_HEADER_LEN + cotp_and_more.len()) as u16;
        let mut packet = vec![TPKT_VERSION, 0];
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(cotp_and_more);
        packet
    }

    fn field<'a>(layer: &'a AppLayer, name: &str) -> &'a Field {
        layer.fields.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no field {name} in {:?}", layer.fields))
    }

    #[test]
    fn a_cotp_connection_request_lists_its_references_and_tsaps() {
        let cotp = [17, 0xE0, 0, 0, 0, 1, 0, 0xC0, 1, 0x0A, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2];
        let packet = tpkt(&cotp);
        let layers = dissect_tpkt(&packet);
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].len, TPKT_HEADER_LEN);
        let cotp = &layers[1];
        assert_eq!(cotp.len, 18);
        assert_eq!(cotp.info, "CR TPDU src-ref: 0x0001 dst-ref: 0x0000");
        assert_eq!(field(cotp, "TPDU size").value, "1024 bytes");
        assert_eq!(field(cotp, "Called TSAP").value, "01 02");
        assert_eq!(field(cotp, "Calling TSAP").offset, 4 + 10);
    }

    #[test]
    fn an_s7_setup_communication_job_is_named_like_wireshark() {
        let mut more = vec![2, 0xF0, 0x80];
        more.extend_from_slice(&[0x32, 1, 0, 0, 0, 7, 0, 8, 0, 0]);
        more.extend_from_slice(&[0xF0, 0, 0, 1, 0, 1, 0x01, 0xE0]);
        let packet = tpkt(&more);
        let layers = dissect_tpkt(&packet);
        let names: Vec<&str> = layers.iter().map(|layer| layer.name).collect();
        assert_eq!(names, ["TPKT", "COTP", "S7comm"]);
        assert_eq!(field(&layers[1], "EOT").value, "yes, the last data unit");
        let s7 = &layers[2];
        assert_eq!(s7.info, "ROSCTR:[Job       ] Function:[Setup communication]");
        assert_eq!(s7.len, 18);
        let parameter = field(s7, "Parameter");
        assert_eq!(parameter.children[3].value, "480");
        assert_eq!(field(s7, "PDU reference").value, "7");
    }

    #[test]
    fn an_s7_read_request_lists_its_items_and_an_error_acknowledgement_its_code() {
        let mut more = vec![2, 0xF0, 0x80];
        more.extend_from_slice(&[0x32, 1, 0, 0, 0, 9, 0, 14, 0, 0]);
        more.extend_from_slice(&[0x04, 1, 0x12, 10, 0x10, 0x02, 0, 4, 0, 1, 0x84, 0, 0, 0x50]);
        let layers = dissect_tpkt(&tpkt(&more));
        let s7 = &layers[2];
        assert_eq!(s7.info, "ROSCTR:[Job       ] Function:[Read Var]");
        let item = &field(s7, "Parameter").children[2];
        assert_eq!(item.value, "DB1 Data blocks (DB) byte 10, bit 0, 4 units of type 0x02");
        assert_eq!(item.children[0].value, "0x84 (Data blocks (DB))");

        let mut ack = vec![2, 0xF0, 0x80];
        ack.extend_from_slice(&[0x32, 3, 0, 0, 0, 9, 0, 2, 0, 0, 0x81, 0x04, 0x04, 0x01]);
        let layers = dissect_tpkt(&tpkt(&ack));
        assert_eq!(layers[2].info, "ROSCTR:[Ack_Data  ] Function:[Read Var] -> Errorcode:[0x8104]");
    }

    #[test]
    fn foreign_and_truncated_bytes_give_no_layers_or_stop_where_they_must() {
        assert!(dissect_tpkt(b"GET / HTTP/1.1\r\n").is_empty());
        assert!(dissect_tpkt(&[3, 0, 0, 4]).is_empty(), "a TPKT shorter than its contents can be");
        // A TPKT whose COTP length indicator runs past the packet.
        assert_eq!(dissect_tpkt(&tpkt(&[40, 0xE0, 0, 0])).len(), 1);
        // Data that is not S7comm stays user data of COTP.
        assert_eq!(dissect_tpkt(&tpkt(&[2, 0xF0, 0x80, 0x61, 0x62])).len(), 2);
        let mut whole = vec![2, 0xF0, 0x80];
        whole.extend_from_slice(&[0x32, 1, 0, 0, 0, 9, 0, 14, 0, 0]);
        whole.extend_from_slice(&[0x04, 1, 0x12, 10, 0x10, 0x02, 0, 4, 0, 1, 0x84, 0, 0, 0x50]);
        let whole = tpkt(&whole);
        for cut in 0..whole.len() {
            let _ = dissect_tpkt(&whole[..cut]);
        }
        let mut state = 0x0BAD_F00Du32;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let mut bytes = whole.clone();
            let at = state as usize % bytes.len();
            bytes[at] = (state >> 8) as u8;
            let _ = dissect_tpkt(&bytes);
        }
    }
}
