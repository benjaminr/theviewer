//! `packets.tshark_decode`: some of a set's packets decoded by Wireshark's
//! tshark, run locally with `-n` on a background thread as a job. The job's
//! result names the protocols tshark found in each packet; in the window,
//! when the set is the one the Packets panel shows, its layers are merged
//! into the panel's as the panel's own "Decode with tshark" does.

use std::sync::atomic::AtomicUsize;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::super::jobs::JobStartedResult;
use super::super::workspace::Workspace;
use super::super::{ApiError, Caller};
use super::{decode as decode_set, filtered, packet_indices, with_set};
use crate::packets::tshark::find_tshark;
use crate::packets::tshark_layers::TsharkMode;
use crate::panel_packets_tshark::{self as panel_tshark, MAX_TSHARK_PACKETS, Request};

/// How tshark's layers go with ours.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TsharkUse {
    /// Only where ours leaves undecoded data.
    #[default]
    FillGaps,
    /// Every layer, in place of ours.
    Everything,
}

impl TsharkUse {
    pub fn mode(self) -> TsharkMode {
        match self {
            TsharkUse::FillGaps => TsharkMode::FillGaps,
            TsharkUse::Everything => TsharkMode::Everything,
        }
    }

    pub fn of(mode: TsharkMode) -> TsharkUse {
        match mode {
            TsharkMode::FillGaps => TsharkUse::FillGaps,
            TsharkMode::Everything => TsharkUse::Everything,
        }
    }
}

/// Parameters of `packets.tshark_decode`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TsharkParams {
    pub set: String,
    /// Only these packets, by their index in the set; every packet (those
    /// the filter keeps) when omitted, at most 5,000.
    #[serde(default)]
    pub indices: Option<Vec<u64>>,
    /// Only the packets this display filter keeps.
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub mode: TsharkUse,
}

/// One packet's protocols, as tshark named them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TsharkPacket {
    pub index: u64,
    /// The protocol stack, outermost first, by tshark's filter names.
    pub protocols: Vec<String>,
}

/// What `packets.tshark_decode`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TsharkResult {
    pub packets: Vec<TsharkPacket>,
    /// What tshark warned of, if anything.
    pub warning: Option<String>,
}

pub fn decode(workspace: &mut dyn Workspace, caller: &Caller, params: TsharkParams) -> Result<JobStartedResult, ApiError> {
    let (doc, version, indices, requests, raw) = with_set(workspace, &params.set, |stored, document| {
        decode_set(stored, document);
        let decoded = stored.decoded.as_ref().expect("decoded");
        let mut chosen = filtered(stored, decoded, params.filter.as_deref())?;
        if let Some(indices) = &params.indices {
            let wanted: std::collections::HashSet<usize> = packet_indices(stored, indices)?.into_iter().collect();
            chosen.retain(|index| wanted.contains(index));
        }
        chosen.truncate(MAX_TSHARK_PACKETS);
        let requests: Vec<Request> = chosen
            .iter()
            .map(|&index| {
                let packet = &stored.packets.packets[index];
                let link = decoded.dissections[index].link;
                let link_type = if stored.info.link.is_none() { packet.link_type } else { link.pcap_link_type() };
                Request { index, bytes: decoded.bytes[index].clone(), original_len: packet.len, timestamp: packet.timestamp, link_type, link }
            })
            .collect();
        Ok((stored.info.doc.clone(), document.version(), chosen, requests, decoded.raw.clone()))
    })?;
    if requests.is_empty() {
        return Err(ApiError::invalid_params("no packets to decode: the filter or indices leave none"));
    }
    if let Some(app) = workspace.window()
        && app.bench.panels.packets.api_set.as_deref() == Some(params.set.as_str())
    {
        return Ok(JobStartedResult { job: panel_tshark::start_for(app, Some(indices), params.mode.mode()) });
    }
    let job = workspace.bus().start_job("tshark", "Decoding with tshark", caller.producer(), Some((doc, version)));
    let started = JobStartedResult { job: job.id().to_string() };
    let mode = params.mode.mode();
    std::thread::spawn(move || {
        let Some(program) = find_tshark(None) else {
            return job.finish(false, panel_tshark::NOT_FOUND);
        };
        match panel_tshark::run(&program, requests, &raw, mode, &job, &AtomicUsize::new(0)) {
            Ok(finished) => job.finish_with(true, format!("{} packets decoded", finished.packets.len()), serde_json::to_value(finished.result()).ok()),
            Err(error) => job.finish(false, error),
        }
    });
    Ok(started)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn decoding_with_tshark_starts_a_job_and_refuses_an_empty_choice_of_packets() {
        let mut workspace = workspace_with("traffic.bin", &super::super::tests::dns_capture(2));
        call(&mut workspace, "packets.sets.create", json!({"from": "capture"})).unwrap();
        let started = call(&mut workspace, "packets.tshark_decode", json!({"set": "set-1", "indices": [1], "mode": "everything"})).unwrap();
        assert!(started["job"].as_str().is_some_and(|job| job.starts_with("tshark-")), "{started}");
        let none = call(&mut workspace, "packets.tshark_decode", json!({"set": "set-1", "filter": "tcp"})).unwrap_err();
        assert_eq!(none.code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "packets.tshark_decode", json!({"set": "set-1", "indices": [7]})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "packets.tshark_decode", json!({"set": "set-2"})).unwrap_err().code, ErrorCode::NotFound);
    }
}
