//! The TLS record layer (RFC 5246 §6.2, RFC 8446 §5.1): each record a
//! content type, a legacy version and a length, then that many bytes. Only
//! the framing is read; handshake messages are named by their type, and
//! what is encrypted is left as it is.

use crate::plugin::Field;

use super::{AppLayer, u16_at};

const RECORD_HEADER_LEN: usize = 5;
/// A record holds at most 2^14 bytes of plaintext, and up to 2048 bytes
/// more once compressed or encrypted.
const MAX_RECORD_LEN: usize = 16_384 + 2048;
/// Most records listed.
const MAX_RECORDS: usize = 64;
const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;
/// Every TLS and SSL 3.0 version starts with 3.
const VERSION_MAJOR: u8 = 3;
/// The newest minor version written in a record header (TLS 1.3 writes 3).
const MAX_VERSION_MINOR: u8 = 4;

/// A record's name, as the reference notes name each kind.
fn record_name(content: u8, handshake_type: Option<u8>) -> &'static str {
    match content {
        CONTENT_CHANGE_CIPHER_SPEC => "ChangeCipherSpec",
        CONTENT_ALERT => "Alert",
        CONTENT_APPLICATION_DATA => "ApplicationData",
        _ => match handshake_type {
            Some(1) => "ClientHello",
            Some(2) => "ServerHello",
            Some(4) => "NewSessionTicket",
            Some(8) => "EncryptedExtensions",
            Some(11) => "Certificate",
            Some(12) => "ServerKeyExchange",
            Some(13) => "CertificateRequest",
            Some(14) => "ServerHelloDone",
            Some(15) => "CertificateVerify",
            Some(16) => "ClientKeyExchange",
            Some(20) => "Finished",
            _ => "handshake",
        },
    }
}

fn version_name(minor: u8) -> &'static str {
    match minor {
        0 => "SSL 3.0",
        1 => "TLS 1.0",
        2 => "TLS 1.1",
        _ => "TLS 1.2",
    }
}

/// The content type and fragment length of a whole record at `at`.
fn record_header(payload: &[u8], at: usize) -> Option<(u8, u8, usize)> {
    let content = *payload.get(at)?;
    let major = *payload.get(at + 1)?;
    let minor = *payload.get(at + 2)?;
    let len = u16_at(payload, at + 3)? as usize;
    let whole = at + RECORD_HEADER_LEN + len <= payload.len();
    let valid = (CONTENT_CHANGE_CIPHER_SPEC..=CONTENT_APPLICATION_DATA).contains(&content) && major == VERSION_MAJOR && minor <= MAX_VERSION_MINOR && (1..=MAX_RECORD_LEN).contains(&len);
    (valid && whole).then_some((content, minor, len))
}

/// A run of whole TLS records from the first byte, or `None` when the
/// first is not one. A record cut short ends the run.
pub fn dissect_tls(payload: &[u8]) -> Option<AppLayer> {
    let (_, first_minor, _) = record_header(payload, 0)?;
    let mut fields = Vec::new();
    let mut names: Vec<&str> = Vec::new();
    let mut at = 0;
    while fields.len() < MAX_RECORDS {
        let Some((content, minor, len)) = record_header(payload, at) else { break };
        let handshake_type = (content == CONTENT_HANDSHAKE).then(|| payload[at + RECORD_HEADER_LEN]);
        let name = record_name(content, handshake_type);
        fields.push(Field::new(name, at, RECORD_HEADER_LEN + len, format!("{}, {len} bytes", version_name(minor))));
        if names.last() != Some(&name) {
            names.push(name);
        }
        at += RECORD_HEADER_LEN + len;
    }
    let info = format!("{} {}", version_name(first_minor), names.join(", "));
    Some(AppLayer { name: "TLS", key: "tls", len: at, fields, info })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(content: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![content, 3, 3];
        bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn a_run_of_records_lists_each_by_its_kind_and_stops_at_one_cut_short() {
        let mut bytes = record(CONTENT_HANDSHAKE, &[2, 0, 0, 2, 3, 3]);
        bytes.extend(record(CONTENT_CHANGE_CIPHER_SPEC, &[1]));
        bytes.extend(record(CONTENT_APPLICATION_DATA, &[0xAA; 40]));
        let whole = bytes.len();
        bytes.extend_from_slice(&[CONTENT_APPLICATION_DATA, 3, 3, 0, 50, 1, 2]);
        let layer = dissect_tls(&bytes).expect("TLS");
        let names: Vec<&str> = layer.fields.iter().map(|field| field.name.as_str()).collect();
        assert_eq!(names, ["ServerHello", "ChangeCipherSpec", "ApplicationData"]);
        assert_eq!(layer.len, whole, "the record cut short is left over");
        assert_eq!(layer.info, "TLS 1.2 ServerHello, ChangeCipherSpec, ApplicationData");
    }

    #[test]
    fn bytes_that_are_not_a_whole_record_are_not_tls() {
        assert!(dissect_tls(&[CONTENT_HANDSHAKE, 3, 1, 0, 10, 1]).is_none(), "cut short");
        assert!(dissect_tls(&record(0x30, &[1, 2])).is_none(), "an unknown content type");
        assert!(dissect_tls(&[CONTENT_ALERT, 2, 0, 0, 2, 1, 0]).is_none(), "not version 3");
    }
}
