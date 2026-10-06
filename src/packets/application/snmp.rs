//! SNMP versions 1, 2c and 3 (RFC 1157, RFC 3416, RFC 3412): BER-encoded
//! messages on UDP ports 161 and 162.
//!
//! A message is a SEQUENCE of the version and, for v1 and v2c, the
//! community and a PDU; for v3, the global header, the security parameters
//! and a scoped PDU (or its encrypted form). The PDU lists a request ID,
//! error status and index, and variable bindings of object identifiers and
//! values.
//!
//! As in Wireshark, a field for a single value covers the value's content,
//! and a field for a structure (the PDU, a binding) its whole element.

use crate::plugin::Field;

use super::AppLayer;

/// Most variable bindings listed.
const MAX_BINDINGS: usize = 64;
/// Most object identifiers named in the packet list's info.
const INFO_OIDS: usize = 8;
/// Most arcs in one object identifier.
const MAX_OID_ARCS: usize = 128;
/// Bytes of a value shown as hex.
const VALUE_PREVIEW_BYTES: usize = 16;

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_IP_ADDRESS: u8 = 0x40;
const TAG_COUNTER32: u8 = 0x41;
const TAG_GAUGE32: u8 = 0x42;
const TAG_TIMETICKS: u8 = 0x43;
const TAG_OPAQUE: u8 = 0x44;
const TAG_COUNTER64: u8 = 0x46;
const TAG_NO_SUCH_OBJECT: u8 = 0x80;
const TAG_NO_SUCH_INSTANCE: u8 = 0x81;
const TAG_END_OF_MIB_VIEW: u8 = 0x82;

const PDU_GET_BULK: u8 = 0xA5;
const PDU_TRAP_V1: u8 = 0xA4;

const VERSION_1: i64 = 0;
const VERSION_2C: i64 = 1;
const VERSION_3: i64 = 3;

/// msgFlags bits (RFC 3412 section 6.4).
const FLAG_AUTHENTICATED: u8 = 0x01;
const FLAG_PRIVATE: u8 = 0x02;
const FLAG_REPORTABLE: u8 = 0x04;

/// One BER element: its tag, where it starts, and where its content lies.
#[derive(Clone, Copy, Debug)]
struct Tlv {
    tag: u8,
    at: usize,
    content_at: usize,
    content_len: usize,
}

impl Tlv {
    fn end(&self) -> usize {
        self.content_at + self.content_len
    }

    fn len(&self) -> usize {
        self.end() - self.at
    }

    fn content<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.content_at..self.end()]
    }
}

/// The BER element at `at`, which must end by `limit`. Single-byte tags and
/// definite lengths of up to four bytes are accepted; SNMP uses no others.
fn read_tlv(bytes: &[u8], at: usize, limit: usize) -> Option<Tlv> {
    let tag = *bytes.get(at)?;
    if tag & 0x1F == 0x1F {
        return None;
    }
    let first = *bytes.get(at + 1)? as usize;
    let (header_len, content_len) = if first < 0x80 {
        (2, first)
    } else {
        let count = first & 0x7F;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for index in 0..count {
            len = (len << 8) | *bytes.get(at + 2 + index)? as usize;
        }
        (2 + count, len)
    };
    let content_at = at + header_len;
    let end = content_at.checked_add(content_len)?;
    (end <= limit.min(bytes.len())).then_some(Tlv { tag, at, content_at, content_len })
}

/// The element at `at` if it has tag `tag`.
fn expect(bytes: &[u8], at: usize, limit: usize, tag: u8) -> Option<Tlv> {
    read_tlv(bytes, at, limit).filter(|tlv| tlv.tag == tag)
}

/// A two's-complement integer of up to eight bytes.
fn integer(content: &[u8]) -> Option<i64> {
    if content.is_empty() || content.len() > 8 {
        return None;
    }
    let mut value: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for &byte in content {
        value = (value << 8) | byte as i64;
    }
    Some(value)
}

/// An unsigned integer of up to eight bytes (a leading zero byte allowed).
fn unsigned(content: &[u8]) -> Option<u64> {
    let content = if content.len() == 9 && content[0] == 0 { &content[1..] } else { content };
    if content.is_empty() || content.len() > 8 {
        return None;
    }
    Some(content.iter().fold(0u64, |value, &byte| (value << 8) | byte as u64))
}

/// An object identifier in dotted form, or `None` when an arc is too large
/// or the last one unfinished.
pub(super) fn object_identifier(content: &[u8]) -> Option<String> {
    let mut arcs: Vec<u64> = Vec::new();
    let mut value: u64 = 0;
    let mut pending = false;
    for &byte in content {
        if value > u64::MAX >> 7 || arcs.len() > MAX_OID_ARCS {
            return None;
        }
        value = (value << 7) | (byte & 0x7F) as u64;
        pending = byte & 0x80 != 0;
        if !pending {
            if arcs.is_empty() {
                let first = (value / 40).min(2);
                arcs.push(first);
                arcs.push(value - first * 40);
            } else {
                arcs.push(value);
            }
            value = 0;
        }
    }
    if pending || arcs.is_empty() {
        return None;
    }
    Some(arcs.iter().map(u64::to_string).collect::<Vec<_>>().join("."))
}

/// An OCTET STRING as text when it is printable, else as hex.
fn octet_string(content: &[u8]) -> String {
    let printable = content.iter().all(|&byte| (0x20..0x7F).contains(&byte) || byte == b'\t' || byte == b'\r' || byte == b'\n');
    if printable && !content.is_empty() {
        String::from_utf8_lossy(content).into_owned()
    } else if content.is_empty() {
        "(empty)".to_string()
    } else {
        super::super::hex_preview(content, VALUE_PREVIEW_BYTES)
    }
}

/// TimeTicks (hundredths of a second) as days, hours, minutes and seconds.
fn time_ticks(ticks: u64) -> String {
    let seconds = ticks / 100;
    let (days, hours, minutes) = (seconds / 86_400, seconds / 3_600 % 24, seconds / 60 % 60);
    format!("{ticks} ({days}d {hours:02}:{minutes:02}:{:02}.{:02})", seconds % 60, ticks % 100)
}

/// A variable binding's value, by its tag.
fn value_text(tlv: &Tlv, bytes: &[u8]) -> String {
    let content = tlv.content(bytes);
    let number = || unsigned(content).map_or_else(|| super::super::hex_preview(content, VALUE_PREVIEW_BYTES), |value| value.to_string());
    match tlv.tag {
        TAG_INTEGER => integer(content).map_or_else(|| super::super::hex_preview(content, VALUE_PREVIEW_BYTES), |value| format!("INTEGER {value}")),
        TAG_OCTET_STRING => format!("OCTET STRING {}", octet_string(content)),
        TAG_NULL => "NULL".to_string(),
        TAG_OID => format!("OID {}", object_identifier(content).unwrap_or_else(|| "(malformed)".to_string())),
        TAG_IP_ADDRESS if content.len() == 4 => format!("IpAddress {}", std::net::Ipv4Addr::new(content[0], content[1], content[2], content[3])),
        TAG_COUNTER32 => format!("Counter32 {}", number()),
        TAG_GAUGE32 => format!("Gauge32 {}", number()),
        TAG_TIMETICKS => unsigned(content).map_or_else(|| "TimeTicks (malformed)".to_string(), |ticks| format!("TimeTicks {}", time_ticks(ticks))),
        TAG_OPAQUE => format!("Opaque {}", super::super::hex_preview(content, VALUE_PREVIEW_BYTES)),
        TAG_COUNTER64 => format!("Counter64 {}", number()),
        TAG_NO_SUCH_OBJECT => "noSuchObject".to_string(),
        TAG_NO_SUCH_INSTANCE => "noSuchInstance".to_string(),
        TAG_END_OF_MIB_VIEW => "endOfMibView".to_string(),
        other => format!("tag {other:#04x}: {}", super::super::hex_preview(content, VALUE_PREVIEW_BYTES)),
    }
}

/// The PDU's name as Wireshark's packet list gives it.
fn pdu_name(tag: u8) -> &'static str {
    match tag {
        0xA0 => "get-request",
        0xA1 => "get-next-request",
        0xA2 => "get-response",
        0xA3 => "set-request",
        PDU_TRAP_V1 => "trap",
        PDU_GET_BULK => "getBulkRequest",
        0xA6 => "informRequest",
        0xA7 => "snmpV2-trap",
        0xA8 => "report",
        _ => "unknown PDU",
    }
}

fn is_pdu_tag(tag: u8) -> bool {
    (0xA0..=0xA8).contains(&tag)
}

fn error_status_name(status: i64) -> &'static str {
    match status {
        0 => "noError",
        1 => "tooBig",
        2 => "noSuchName",
        3 => "badValue",
        4 => "readOnly",
        5 => "genErr",
        6 => "noAccess",
        7 => "wrongType",
        8 => "wrongLength",
        9 => "wrongEncoding",
        10 => "wrongValue",
        11 => "noCreation",
        12 => "inconsistentValue",
        13 => "resourceUnavailable",
        14 => "commitFailed",
        15 => "undoFailed",
        16 => "authorizationError",
        17 => "notWritable",
        18 => "inconsistentName",
        _ => "unknown",
    }
}

fn version_name(version: i64) -> &'static str {
    match version {
        VERSION_1 => "SNMPv1",
        VERSION_2C => "SNMPv2c",
        VERSION_3 => "SNMPv3",
        _ => "unknown version",
    }
}

fn integer_field(name: &str, tlv: &Tlv, bytes: &[u8]) -> Option<(Field, i64)> {
    let value = integer(tlv.content(bytes))?;
    Some((Field::new(name, tlv.content_at, tlv.content_len, value.to_string()), value))
}

/// An SNMP message, or `None` when the bytes are not one.
/// Bytes on an SNMP port that start like a message but do not parse in full
/// (test suites send many) are still named, with what can be read of them.
pub fn dissect_snmp(payload: &[u8]) -> Option<AppLayer> {
    whole_message(payload).or_else(|| malformed_message(payload))
}

/// A message that parses from its first byte to its last.
fn whole_message(payload: &[u8]) -> Option<AppLayer> {
    let message = expect(payload, 0, payload.len(), TAG_SEQUENCE)?;
    let end = message.end();
    let version_tlv = expect(payload, message.content_at, end, TAG_INTEGER)?;
    let version = integer(version_tlv.content(payload))?;
    let mut fields = vec![Field::new("version", version_tlv.content_at, version_tlv.content_len, format!("{version} ({})", version_name(version)))];
    let info = match version {
        VERSION_1 | VERSION_2C => community_message(payload, version_tlv.end(), end, &mut fields)?,
        VERSION_3 => v3_message(payload, version_tlv.end(), end, &mut fields)?,
        _ => return None,
    };
    Some(AppLayer { name: "SNMP", key: "snmp", len: end, fields, info })
}

/// A message whose outer SEQUENCE and version can be read, but nothing
/// whole after them: its version, and the rest marked malformed.
fn malformed_message(payload: &[u8]) -> Option<AppLayer> {
    if payload.first() != Some(&TAG_SEQUENCE) {
        return None;
    }
    // The outer length may be what is wrong, so only its size is read.
    let first_length_byte = *payload.get(1)?;
    let header_len = if first_length_byte < 0x80 { 2 } else { 2 + (first_length_byte & 0x7F) as usize };
    let version_tlv = expect(payload, header_len, payload.len(), TAG_INTEGER)?;
    let version = integer(version_tlv.content(payload))?;
    if !matches!(version, VERSION_1 | VERSION_2C | VERSION_3) {
        return None;
    }
    let fields = vec![
        Field::new("version", version_tlv.content_at, version_tlv.content_len, format!("{version} ({})", version_name(version))),
        Field::new("Bytes", version_tlv.end(), payload.len() - version_tlv.end(), "the rest of the message, which does not parse"),
    ];
    Some(AppLayer { name: "SNMP", key: "snmp", len: payload.len(), fields, info: format!("Malformed {} message", version_name(version)) })
}

/// The community and PDU of a v1 or v2c message, added to `fields`.
/// Returns the packet list's info.
fn community_message(payload: &[u8], at: usize, end: usize, fields: &mut Vec<Field>) -> Option<String> {
    let community = expect(payload, at, end, TAG_OCTET_STRING)?;
    fields.push(Field::new("community", community.content_at, community.content_len, String::from_utf8_lossy(community.content(payload)).into_owned()));
    let (pdu, info) = pdu(payload, community.end(), end)?;
    fields.push(pdu);
    Some(info)
}

/// The header, security parameters and scoped PDU of a v3 message, added to
/// `fields`. Returns the packet list's info.
fn v3_message(payload: &[u8], at: usize, end: usize, fields: &mut Vec<Field>) -> Option<String> {
    let global = expect(payload, at, end, TAG_SEQUENCE)?;
    let (global_field, flags) = global_data(payload, &global)?;
    fields.push(global_field);
    let security = expect(payload, global.end(), end, TAG_OCTET_STRING)?;
    fields.push(security_parameters(payload, &security));
    let data = read_tlv(payload, security.end(), end)?;
    if data.tag == TAG_OCTET_STRING {
        let len = data.content_len;
        fields.push(Field::new("encryptedPDU", data.content_at, data.content_len, format!("{len} encrypted bytes")));
        return Some("encryptedPDU: privKey unknown".to_string());
    }
    if data.tag != TAG_SEQUENCE {
        return None;
    }
    let engine = expect(payload, data.content_at, data.end(), TAG_OCTET_STRING)?;
    let context = expect(payload, engine.end(), data.end(), TAG_OCTET_STRING)?;
    let (pdu, info) = pdu(payload, context.end(), data.end())?;
    let flag_note = if flags & FLAG_PRIVATE != 0 { " (privacy flag set, yet not encrypted)" } else { "" };
    fields.push(
        Field::new("msgData", data.at, data.len(), format!("scoped PDU{flag_note}")).with_children(vec![
            Field::new("contextEngineID", engine.content_at, engine.content_len, super::super::hex_preview(engine.content(payload), VALUE_PREVIEW_BYTES)),
            Field::new("contextName", context.content_at, context.content_len, octet_string(context.content(payload))),
            pdu,
        ]),
    );
    Some(info)
}

/// msgGlobalData: message ID, maximum size, flags and security model.
/// Returns the field and the flags.
fn global_data(payload: &[u8], global: &Tlv) -> Option<(Field, u8)> {
    let id = expect(payload, global.content_at, global.end(), TAG_INTEGER)?;
    let max_size = expect(payload, id.end(), global.end(), TAG_INTEGER)?;
    let flags_tlv = expect(payload, max_size.end(), global.end(), TAG_OCTET_STRING)?;
    let model = expect(payload, flags_tlv.end(), global.end(), TAG_INTEGER)?;
    let flags = flags_tlv.content(payload).first().copied().unwrap_or_default();
    let flag_names: Vec<&str> = [(FLAG_AUTHENTICATED, "auth"), (FLAG_PRIVATE, "priv"), (FLAG_REPORTABLE, "reportable")]
        .into_iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| name)
        .collect();
    let (id_field, message_id) = integer_field("msgID", &id, payload)?;
    let (max_size_field, _) = integer_field("msgMaxSize", &max_size, payload)?;
    let (model_field, security_model) = integer_field("msgSecurityModel", &model, payload)?;
    let children = vec![
        id_field,
        max_size_field,
        Field::new("msgFlags", flags_tlv.content_at, flags_tlv.content_len, format!("{flags:#04x} ({})", if flag_names.is_empty() { "none".to_string() } else { flag_names.join(", ") })),
        model_field,
    ];
    let value = format!("message {message_id}, security model {security_model}");
    Some((Field::new("msgGlobalData", global.at, global.len(), value).with_children(children), flags))
}

/// msgSecurityParameters, decoded as the User-based Security Model's
/// SEQUENCE (RFC 3414) when it is one.
fn security_parameters(payload: &[u8], security: &Tlv) -> Field {
    let field = Field::new("msgSecurityParameters", security.at, security.len(), format!("{} bytes", security.content_len));
    let Some(usm) = expect(payload, security.content_at, security.end(), TAG_SEQUENCE) else { return field };
    let names = ["msgAuthoritativeEngineID", "msgAuthoritativeEngineBoots", "msgAuthoritativeEngineTime", "msgUserName", "msgAuthenticationParameters", "msgPrivacyParameters"];
    let mut children = Vec::new();
    let mut at = usm.content_at;
    let mut user = String::new();
    for name in names {
        let Some(tlv) = read_tlv(payload, at, usm.end()) else { break };
        let content = tlv.content(payload);
        let value = match tlv.tag {
            TAG_INTEGER => integer(content).map_or_else(String::new, |value| value.to_string()),
            _ if name == "msgUserName" => octet_string(content),
            _ => super::super::hex_preview(content, VALUE_PREVIEW_BYTES),
        };
        if name == "msgUserName" {
            user = value.clone();
        }
        children.push(Field::new(name, tlv.content_at, tlv.content_len, value));
        at = tlv.end();
    }
    let value = if user.is_empty() { field.value.clone() } else { format!("user {user}") };
    Field { value, ..field }.with_children(children)
}

/// A PDU at `at`: its field, and the packet list's info naming the PDU and
/// its object identifiers.
fn pdu(payload: &[u8], at: usize, end: usize) -> Option<(Field, String)> {
    let pdu = read_tlv(payload, at, end)?;
    if !is_pdu_tag(pdu.tag) {
        return None;
    }
    let name = pdu_name(pdu.tag);
    let (mut children, bindings_at) = if pdu.tag == PDU_TRAP_V1 { trap_v1_header(payload, &pdu)? } else { request_header(payload, &pdu)? };
    let bindings = expect(payload, bindings_at, pdu.end(), TAG_SEQUENCE)?;
    let (binding_fields, oids) = variable_bindings(payload, &bindings);
    let count = binding_fields.len();
    children.push(Field::new("variable-bindings", bindings.at, bindings.len(), format!("{count} items")).with_children(binding_fields));
    let shown: Vec<&str> = oids.iter().take(INFO_OIDS).map(String::as_str).collect();
    let more = if oids.len() > INFO_OIDS { " …" } else { "" };
    let info = format!("{name} {}{more}", shown.join(" ")).trim_end().to_string();
    let field = Field::new("PDU", pdu.at, pdu.len(), format!("{name} ({:#04x})", pdu.tag)).with_children(children);
    Some((field, info))
}

/// The request ID and the error status and index (or, for GetBulk, the
/// non-repeaters and maximum repetitions). Returns them and where the
/// variable bindings start.
fn request_header(payload: &[u8], pdu: &Tlv) -> Option<(Vec<Field>, usize)> {
    let request = expect(payload, pdu.content_at, pdu.end(), TAG_INTEGER)?;
    let first = expect(payload, request.end(), pdu.end(), TAG_INTEGER)?;
    let second = expect(payload, first.end(), pdu.end(), TAG_INTEGER)?;
    let (request_field, _) = integer_field("request-id", &request, payload)?;
    let mut children = vec![request_field];
    if pdu.tag == PDU_GET_BULK {
        children.push(integer_field("non-repeaters", &first, payload)?.0);
        children.push(integer_field("max-repetitions", &second, payload)?.0);
    } else {
        let status = integer(first.content(payload))?;
        children.push(Field::new("error-status", first.content_at, first.content_len, format!("{status} ({})", error_status_name(status))));
        children.push(integer_field("error-index", &second, payload)?.0);
    }
    Some((children, second.end()))
}

/// An SNMPv1 trap's enterprise, agent address, trap numbers and time stamp.
/// Returns them and where the variable bindings start.
fn trap_v1_header(payload: &[u8], pdu: &Tlv) -> Option<(Vec<Field>, usize)> {
    let enterprise = expect(payload, pdu.content_at, pdu.end(), TAG_OID)?;
    let agent = expect(payload, enterprise.end(), pdu.end(), TAG_IP_ADDRESS)?;
    let generic = expect(payload, agent.end(), pdu.end(), TAG_INTEGER)?;
    let specific = expect(payload, generic.end(), pdu.end(), TAG_INTEGER)?;
    let stamp = expect(payload, specific.end(), pdu.end(), TAG_TIMETICKS)?;
    let children = vec![
        Field::new("enterprise", enterprise.content_at, enterprise.content_len, object_identifier(enterprise.content(payload))?),
        Field::new("agent-addr", agent.content_at, agent.content_len, value_text(&agent, payload).trim_start_matches("IpAddress ").to_string()),
        integer_field("generic-trap", &generic, payload)?.0,
        integer_field("specific-trap", &specific, payload)?.0,
        Field::new("time-stamp", stamp.content_at, stamp.content_len, value_text(&stamp, payload).trim_start_matches("TimeTicks ").to_string()),
    ];
    Some((children, stamp.end()))
}

/// Each binding of an object identifier to a value, and the identifiers.
fn variable_bindings(payload: &[u8], bindings: &Tlv) -> (Vec<Field>, Vec<String>) {
    let mut fields = Vec::new();
    let mut oids = Vec::new();
    let mut at = bindings.content_at;
    while fields.len() < MAX_BINDINGS {
        let Some(binding) = expect(payload, at, bindings.end(), TAG_SEQUENCE) else { break };
        let Some(name) = expect(payload, binding.content_at, binding.end(), TAG_OID) else { break };
        let Some(value) = read_tlv(payload, name.end(), binding.end()) else { break };
        let oid = object_identifier(name.content(payload)).unwrap_or_else(|| "(malformed)".to_string());
        let text = value_text(&value, payload);
        fields.push(Field::new(format!("varbind {}", fields.len()), binding.at, binding.len(), format!("{oid} = {text}")).with_children(vec![
            Field::new("Object name", name.content_at, name.content_len, oid.clone()),
            Field::new("Value", value.content_at, value.content_len, text),
        ]));
        oids.push(oid);
        at = binding.end();
    }
    (fields, oids)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A BER element with a short-form length.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, content.len() as u8];
        out.extend_from_slice(content);
        out
    }

    fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    /// The OID 1.3.6.1.2.1.1.5.0 (sysName.0).
    const SYS_NAME: [u8; 8] = [0x2B, 6, 1, 2, 1, 1, 5, 0];

    fn get_request(version: u8, community: &str) -> Vec<u8> {
        let binding = tlv(TAG_SEQUENCE, &concat(&[tlv(TAG_OID, &SYS_NAME), tlv(TAG_NULL, &[])]));
        let pdu = tlv(0xA0, &concat(&[tlv(TAG_INTEGER, &[0x12, 0x34]), tlv(TAG_INTEGER, &[0]), tlv(TAG_INTEGER, &[0]), tlv(TAG_SEQUENCE, &binding)]));
        tlv(TAG_SEQUENCE, &concat(&[tlv(TAG_INTEGER, &[version]), tlv(TAG_OCTET_STRING, community.as_bytes()), pdu]))
    }

    fn field<'a>(fields: &'a [Field], name: &str) -> &'a Field {
        fields.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no field {name} in {fields:?}"))
    }

    #[test]
    fn a_v2c_get_request_names_its_community_and_object() {
        let message = get_request(1, "public");
        let layer = dissect_snmp(&message).expect("SNMP");
        assert_eq!(layer.info, "get-request 1.3.6.1.2.1.1.5.0");
        assert_eq!(layer.len, message.len());
        assert_eq!(field(&layer.fields, "version").value, "1 (SNMPv2c)");
        let community = field(&layer.fields, "community");
        assert_eq!(community.value, "public");
        assert_eq!(&message[community.offset..community.offset + community.len], b"public", "a value field covers its content, as in Wireshark");
        let pdu = field(&layer.fields, "PDU");
        assert_eq!(field(&pdu.children, "request-id").value, "4660");
        assert_eq!(field(&pdu.children, "error-status").value, "0 (noError)");
        let binding = &field(&pdu.children, "variable-bindings").children[0];
        assert_eq!(binding.value, "1.3.6.1.2.1.1.5.0 = NULL");
    }

    #[test]
    fn a_response_shows_typed_values_and_long_form_lengths_are_read() {
        let bindings = concat(&[
            tlv(TAG_SEQUENCE, &concat(&[tlv(TAG_OID, &SYS_NAME), tlv(TAG_OCTET_STRING, b"router")])),
            tlv(TAG_SEQUENCE, &concat(&[tlv(TAG_OID, &[0x2B, 6, 1, 2, 1, 1, 3, 0]), tlv(TAG_TIMETICKS, &[0x01, 0x00, 0x00])])),
        ]);
        let pdu = tlv(0xA2, &concat(&[tlv(TAG_INTEGER, &[1]), tlv(TAG_INTEGER, &[0]), tlv(TAG_INTEGER, &[0]), tlv(TAG_SEQUENCE, &bindings)]));
        let body = concat(&[tlv(TAG_INTEGER, &[0]), tlv(TAG_OCTET_STRING, b"private"), pdu]);
        // The outer SEQUENCE uses a (permitted, if not minimal) long-form length.
        let mut message = vec![TAG_SEQUENCE, 0x81, body.len() as u8];
        message.extend_from_slice(&body);
        let layer = dissect_snmp(&message).expect("SNMP");
        assert_eq!(layer.info, "get-response 1.3.6.1.2.1.1.5.0 1.3.6.1.2.1.1.3.0");
        let bindings = &field(&field(&layer.fields, "PDU").children, "variable-bindings").children;
        assert_eq!(bindings[0].value, "1.3.6.1.2.1.1.5.0 = OCTET STRING router");
        assert_eq!(bindings[1].children[1].value, "TimeTicks 65536 (0d 00:10:55.36)");
    }

    #[test]
    fn a_v1_trap_lists_its_enterprise_and_agent() {
        let pdu = tlv(
            PDU_TRAP_V1,
            &concat(&[
                tlv(TAG_OID, &[0x2B, 6, 1, 4, 1, 9]),
                tlv(TAG_IP_ADDRESS, &[192, 0, 2, 1]),
                tlv(TAG_INTEGER, &[6]),
                tlv(TAG_INTEGER, &[1]),
                tlv(TAG_TIMETICKS, &[0x10]),
                tlv(TAG_SEQUENCE, &[]),
            ]),
        );
        let message = tlv(TAG_SEQUENCE, &concat(&[tlv(TAG_INTEGER, &[0]), tlv(TAG_OCTET_STRING, b"public"), pdu]));
        let layer = dissect_snmp(&message).expect("SNMP");
        assert_eq!(layer.info, "trap");
        let pdu = field(&layer.fields, "PDU");
        assert_eq!(field(&pdu.children, "enterprise").value, "1.3.6.1.4.1.9");
        assert_eq!(field(&pdu.children, "agent-addr").value, "192.0.2.1");
    }

    #[test]
    fn a_v3_message_shows_its_header_user_and_either_its_scoped_or_encrypted_pdu() {
        let global = tlv(TAG_SEQUENCE, &concat(&[tlv(TAG_INTEGER, &[0x01, 0x00]), tlv(TAG_INTEGER, &[0x05, 0xDC]), tlv(TAG_OCTET_STRING, &[0x07]), tlv(TAG_INTEGER, &[3])]));
        let usm = tlv(
            TAG_SEQUENCE,
            &concat(&[
                tlv(TAG_OCTET_STRING, &[0x80, 0, 0x1F, 0x88]),
                tlv(TAG_INTEGER, &[2]),
                tlv(TAG_INTEGER, &[0x10]),
                tlv(TAG_OCTET_STRING, b"admin"),
                tlv(TAG_OCTET_STRING, &[0xAA; 12]),
                tlv(TAG_OCTET_STRING, &[0xBB; 8]),
            ]),
        );
        let security = tlv(TAG_OCTET_STRING, &usm);
        let encrypted = tlv(TAG_SEQUENCE, &concat(&[tlv(TAG_INTEGER, &[3]), global.clone(), security.clone(), tlv(TAG_OCTET_STRING, &[0xCC; 20])]));
        let layer = dissect_snmp(&encrypted).expect("SNMPv3");
        assert_eq!(layer.info, "encryptedPDU: privKey unknown");
        assert_eq!(field(&layer.fields, "msgSecurityParameters").value, "user admin");
        assert!(field(&layer.fields, "msgGlobalData").children[2].value.contains("auth, priv, reportable"));

        let inner = get_request(1, "x");
        // The PDU of a v2c request, re-used inside a scoped PDU.
        let pdu_at = 2 + 3 + 3;
        let scoped = tlv(TAG_SEQUENCE, &concat(&[tlv(TAG_OCTET_STRING, &[0x80, 0, 0x1F, 0x88]), tlv(TAG_OCTET_STRING, b""), inner[pdu_at..].to_vec()]));
        let plain = tlv(TAG_SEQUENCE, &concat(&[tlv(TAG_INTEGER, &[3]), global, security, scoped]));
        let layer = dissect_snmp(&plain).expect("SNMPv3");
        assert_eq!(layer.info, "get-request 1.3.6.1.2.1.1.5.0");
    }

    #[test]
    fn truncated_messages_are_named_malformed_and_foreign_bytes_are_not_snmp() {
        let message = get_request(1, "public");
        for cut in 0..message.len() {
            let info = dissect_snmp(&message[..cut]).map(|layer| layer.info);
            let expected = if cut >= 5 { Some("Malformed SNMPv2c message".to_string()) } else { None };
            assert_eq!(info, expected, "cut at {cut}");
        }
        assert!(dissect_snmp(&get_request(2, "public")).is_none(), "version 2 does not exist");
        assert!(dissect_snmp(b"\x31\x03\x02\x01\x01").is_none(), "a SET, not a SEQUENCE");
        let malformed = dissect_snmp(b"\x30\x03\x02\x01\x01").expect("a message without a PDU");
        assert_eq!(malformed.fields[1].name, "Bytes");
        assert!(object_identifier(&[0x2B, 0x86]).is_none(), "an unfinished arc");
        assert!(object_identifier(&[0xFF; 12]).is_none(), "an arc too large for 64 bits");
    }

    #[test]
    fn arbitrary_bytes_never_make_the_snmp_parser_panic() {
        let mut state = 0x2545_F491u32;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        let valid = get_request(1, "public");
        for round in 0..20_000 {
            let mut message = if round % 2 == 0 { valid.clone() } else { (0..(next() % 80) as usize).map(|_| next() as u8).collect() };
            if !message.is_empty() {
                let at = next() as usize % message.len();
                message[at] = next() as u8;
            }
            let _ = dissect_snmp(&message);
        }
    }
}
