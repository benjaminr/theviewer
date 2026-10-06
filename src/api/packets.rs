//! `packets.*`: dissecting a packet's bytes into protocol layers, and
//! finding the protocol of frames of unknown format. Packet sets come later.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::values::{self, ByteEncoding};
use super::workspace::{self, Workspace};
use super::{ApiError, MAX_CALL_BYTES};
use crate::packets::flows::Flow;
use crate::packets::frames::{self, FrameProtocol};
use crate::packets::{self, Layer, LinkKind, RawFrames, Summary};

/// Parameters of `packets.dissect_bytes`. Give the packet as a span of the
/// document (`start`, `len`) or as `bytes`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DissectParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Offset of the packet's first byte.
    #[serde(default)]
    pub start: Option<u64>,
    /// Bytes in the packet; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// The packet's bytes instead of a span, written as `encoding` says.
    #[serde(default)]
    pub bytes: Option<String>,
    /// How `bytes` is written: hex (the default), base64 or text.
    #[serde(default)]
    pub encoding: ByteEncoding,
    /// What the first byte is, such as "ethernet" or "raw_ip"; "unknown" (the
    /// default) reads an IP header if one is there.
    #[serde(default)]
    pub link: LinkKind,
    /// For frames of unknown format: the protocol to decode them as, such as "dns" or "modbus_tcp".
    #[serde(default)]
    pub decode_as: Option<FrameProtocol>,
}

/// Everything learned from one packet.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DissectionResult {
    /// The link type used, after detection.
    pub link: LinkKind,
    /// Protocol layers, outermost first; offsets are relative to the packet's first byte.
    pub layers: Vec<Layer>,
    /// The packet list's columns.
    pub summary: Summary,
    /// Lower-case names of every layer, as the packet filter uses them.
    pub protocols: Vec<String>,
    /// Addresses and ports, for IP packets.
    pub flow: Option<Flow>,
    /// The transport payload as [offset, len] within the packet.
    pub payload: Option<(u64, u64)>,
    /// The EtherType after the Ethernet header and any VLAN tags.
    pub ether_type: Option<u16>,
    /// Problems met, such as truncation or a bad checksum.
    pub notes: Vec<String>,
}

/// One frame of a set, as a span of the document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrameSpan {
    pub start: u64,
    pub len: u64,
}

/// Parameters of `packets.detect_frames`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectFramesParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// The frames, at most 16 MiB in all; a sample of them is tried.
    pub frames: Vec<FrameSpan>,
}

/// A protocol found for a set of frames.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FrameDetection {
    /// Pass as `decode_as` to packets.dissect_bytes.
    pub protocol: FrameProtocol,
    pub label: String,
    /// Sampled frames the protocol read in full.
    pub matched: u64,
    /// Frames tried.
    pub sampled: u64,
}

/// The result of `packets.detect_frames`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DetectFramesResult {
    /// The protocol nearly every frame reads as in full, or nothing when none clearly does.
    pub detection: Option<FrameDetection>,
}

pub fn dissect_bytes(workspace: &mut dyn Workspace, params: DissectParams) -> Result<DissectionResult, ApiError> {
    let bytes = match (&params.bytes, params.start) {
        (Some(text), None) => {
            if params.len.is_some() {
                return Err(ApiError::invalid_params("len goes with start; give the packet as bytes or as a span, not both"));
            }
            let bytes = values::decode_bytes(text, params.encoding)?;
            values::check_call_size(bytes.len())?;
            bytes
        }
        (None, Some(start)) => {
            let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
            let (start, len) = values::span_within(document.len(), start, params.len)?;
            values::check_call_size(len)?;
            document.read_range(start, len)
        }
        _ => return Err(ApiError::invalid_params("give the packet as bytes or as a span from start, not both")),
    };
    let raw = RawFrames { decode_as: params.decode_as, ..RawFrames::default() };
    let dissection = packets::dissect_with(&bytes, params.link, &raw);
    Ok(DissectionResult {
        link: dissection.link,
        layers: dissection.layers,
        summary: dissection.summary,
        protocols: dissection.protocols.iter().map(|protocol| protocol.to_string()).collect(),
        flow: dissection.flow,
        payload: dissection.payload.map(|(offset, len)| (offset as u64, len as u64)),
        ether_type: dissection.ether_type,
        notes: dissection.notes,
    })
}

pub fn detect_frames(workspace: &mut dyn Workspace, params: DetectFramesParams) -> Result<DetectFramesResult, ApiError> {
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let mut total = 0usize;
    let mut frames = Vec::with_capacity(params.frames.len());
    for frame in &params.frames {
        let (start, len) = values::span_within(document.len(), frame.start, Some(frame.len))?;
        total = total.saturating_add(len);
        values::check_size(total, MAX_CALL_BYTES, "the frames")?;
        frames.push(document.read_range(start, len));
    }
    let slices: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    let detection = frames::detect_frame_protocol(&slices).map(|found| FrameDetection {
        protocol: found.protocol,
        label: found.protocol.label().to_string(),
        matched: found.matched as u64,
        sampled: found.sampled as u64,
    });
    Ok(DetectFramesResult { detection })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::test_support::workspace_with;
    use crate::api::ErrorCode;
    use crate::api::test_support::call;

    fn ethernet_udp(payload: &[u8]) -> Vec<u8> {
        let builder = etherparse::PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]).ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64).udp(4000, 5000);
        let mut frame = Vec::new();
        builder.write(&mut frame, payload).unwrap();
        frame
    }

    /// A DNS query for example.com.
    fn dns_query(id: u16) -> Vec<u8> {
        let mut message = id.to_be_bytes().to_vec();
        message.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        message.extend(b"\x07example\x03com\x00");
        message.extend([0, 1, 0, 1]);
        message
    }

    #[test]
    fn a_frame_in_the_document_is_dissected_into_layers_and_a_flow() {
        let frame = ethernet_udp(b"ping");
        let mut workspace = workspace_with("a.bin", &frame);
        let dissected = call(&mut workspace, "packets.dissect_bytes", json!({"start": 0, "link": "ethernet"})).unwrap();
        let names: Vec<&str> = dissected["layers"].as_array().unwrap().iter().map(|layer| layer["name"].as_str().unwrap()).collect();
        assert!(names.len() >= 3, "{names:?}");
        assert_eq!(dissected["flow"]["source"]["address"], "10.0.0.2");
        assert_eq!(dissected["flow"]["destination"]["port"], 5000);
        assert!(dissected["protocols"].as_array().unwrap().contains(&json!("udp")));
    }

    #[test]
    fn hex_bytes_are_dissected_as_the_protocol_asked_for() {
        let mut workspace = workspace_with("a.bin", b"");
        let hex = crate::ops::to_compact_hex(&dns_query(7));
        let dissected = call(&mut workspace, "packets.dissect_bytes", json!({"bytes": hex, "decode_as": "dns"})).unwrap();
        assert!(dissected["protocols"].as_array().unwrap().contains(&json!("dns")), "{dissected}");
        assert_eq!(call(&mut workspace, "packets.dissect_bytes", json!({})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "packets.dissect_bytes", json!({"bytes": "00", "start": 0})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn the_protocol_of_a_set_of_frames_is_detected() {
        let mut bytes = Vec::new();
        let mut frames = Vec::new();
        for id in 0..4 {
            let message = dns_query(id);
            frames.push(json!({"start": bytes.len(), "len": message.len()}));
            bytes.extend(message);
        }
        let mut workspace = workspace_with("a.bin", &bytes);
        let detected = call(&mut workspace, "packets.detect_frames", json!({"frames": frames})).unwrap();
        assert_eq!(detected["detection"]["protocol"], "dns", "{detected}");
        let outside = call(&mut workspace, "packets.detect_frames", json!({"frames": [{"start": 0, "len": 10_000}]}));
        assert_eq!(outside.unwrap_err().code, ErrorCode::OutOfRange);
    }
}
