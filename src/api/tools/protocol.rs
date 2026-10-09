//! `protocol.*`: finding how a stream of messages is framed and what their
//! header fields are, as the Protocol tool does.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::analysis_tools::{self, ProtocolView};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller, values};
use crate::protocol::{self, Framing, MessageField};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("protocol.analyse", Job, caller analyse, AnalyseParams, JobStartedResult, "Start finding how a span is framed into messages (sync words, delimiters, length prefixes, fixed size) and what their header fields are, as a background job; the framing, messages and fields are job.finished's result and are published on frames.defined and fields.guessed."),
    method!("protocol.choose_framing", View, choose_framing, ChooseFramingParams, ProtocolResult, "Split a span into messages with a framing (one protocol.analyse offered, or any other) and work out their fields again; the messages are published on frames.defined, and in the window the Protocol tool shows them."),
];

/// An example call of each of [`METHODS`].
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("protocol.analyse", json!({"start": 0, "len": 200})),
        ("protocol.choose_framing", json!({"start": 0, "len": 200, "framing": {"kind": "fixed_size", "len": 20}})),
    ]
}

/// What a call to one of this module's methods would do, in plain words.
pub(super) fn describe_call(_workspace: &mut dyn Workspace, method: &str, params: &serde_json::Value) -> Option<String> {
    match method {
        "protocol.choose_framing" => {
            let framing: Framing = serde_json::from_value(params.get("framing")?.clone()).ok()?;
            Some(format!("Split the messages by {}", framing.describe()))
        }
        _ => None,
    }
}

/// Largest span handed to protocol analysis.
pub const PROTOCOL_LIMIT: usize = 16 * 1024 * 1024;
/// Framings `protocol.analyse` offers.
pub const FRAMING_CANDIDATES: usize = 8;

/// Parameters of `protocol.analyse`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyseParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset of the stream (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes in the stream, at most 16 MiB; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
}

/// Parameters of `protocol.choose_framing`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChooseFramingParams {
    /// Document id, path or "current" (left out: the caller's focus).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset of the stream (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes in the stream, at most 16 MiB; to the end of the document when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// How the stream is cut into messages, as protocol.analyse gives it.
    pub framing: Framing,
}

/// One framing the analysis found.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FramingResult {
    pub framing: Framing,
    /// Such as "sync word A5 5A".
    pub description: String,
    /// Messages it splits the stream into.
    pub messages: usize,
    /// Fraction of the stream it explains.
    pub coverage: f64,
}

/// What protocol analysis found in a stream.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProtocolResult {
    pub start: u64,
    pub len: u64,
    /// The framing the messages were split with; absent when none was found.
    pub framing: Option<FramingResult>,
    /// The framings found, best first.
    pub candidates: Vec<FramingResult>,
    /// Each message as [start, len], in document offsets.
    pub messages: Vec<(u64, u64)>,
    /// The header fields found by aligning the messages.
    pub fields: Vec<MessageField>,
    pub length_min: usize,
    pub length_max: usize,
    pub length_mean: f64,
    /// Messages per value of the message type field, when one was found.
    pub type_counts: Vec<(String, usize)>,
    /// The protocol the messages read as, such as "DNS", when they do.
    pub decodes_as: Option<String>,
    /// The fields as a template, when there are any.
    pub template: Option<String>,
}

impl ProtocolResult {
    pub fn of(view: &ProtocolView) -> Self {
        let candidate = |candidate: &protocol::FramingCandidate| FramingResult {
            framing: candidate.framing.clone(),
            description: candidate.framing.describe(),
            messages: candidate.messages,
            coverage: candidate.coverage,
        };
        let report = &view.report;
        ProtocolResult {
            start: view.base as u64,
            len: view.bytes().len() as u64,
            framing: report.framing.as_ref().map(candidate),
            candidates: view.candidates.iter().map(candidate).collect(),
            messages: report.messages.iter().map(|message| ((view.base + message.offset) as u64, message.len as u64)).collect(),
            fields: report.fields.clone(),
            length_min: report.length_min,
            length_max: report.length_max,
            length_mean: report.length_mean,
            type_counts: report.type_counts.clone(),
            decodes_as: view.messages_decode_as.map(|detection| detection.protocol.label().to_string()),
            template: protocol::to_template(report),
        }
    }
}

/// The stream `doc`, `start` and `len` name: its document's id and
/// version, where it starts and its bytes.
fn stream(workspace: &mut dyn Workspace, doc: Option<&str>, start: u64, len: Option<u64>) -> Result<(String, u64, usize, Vec<u8>), ApiError> {
    let id = workspace::resolve(workspace, doc)?;
    let version = workspace::info(workspace, &id)?.version;
    let (_, document) = workspace::document(workspace, Some(&id))?;
    let (start, len) = values::span_within(document.len(), start, len)?;
    values::check_size(len, PROTOCOL_LIMIT, "the stream")?;
    Ok((id, version, start, document.read_range(start, len)))
}

/// `protocol.analyse`: in the window the Protocol tool's own analysis runs
/// (see `analysis_tools::analyse_protocol_from`) and shows what it finds;
/// elsewhere the same analysis runs on a thread.
pub fn analyse(workspace: &mut dyn Workspace, caller: &Caller, params: AnalyseParams) -> Result<JobStartedResult, ApiError> {
    let (id, version, start, bytes) = stream(workspace, params.doc.as_deref(), params.start, params.len)?;
    if let Some(app) = workspace.window()
        && app.document_id() == id
    {
        return Ok(JobStartedResult::started(analysis_tools::analyse_protocol_from(app, start, bytes.len(), &caller.producer())));
    }
    let publisher = workspace.bus().publisher();
    let job = workspace.bus().start_job("protocol", "Protocol analysis", caller.producer(), Some((id.clone(), version)));
    let started = JobStartedResult::started(job.id().to_string());
    std::thread::spawn(move || analysis_tools::run_protocol_analysis(start, bytes, &job, &publisher, (id, version)));
    Ok(started)
}

pub fn choose_framing(workspace: &mut dyn Workspace, params: ChooseFramingParams) -> Result<ProtocolResult, ApiError> {
    let (id, version, start, bytes) = stream(workspace, params.doc.as_deref(), params.start, params.len)?;
    if let Some(app) = workspace.window()
        && app.document_id() == id
    {
        return Ok(ProtocolResult::of(analysis_tools::show_protocol_framing(app, start, bytes, params.framing)));
    }
    let view = ProtocolView::with_framing(start, bytes, params.framing);
    for draft in analysis_tools::framing_facts(&view) {
        workspace.bus().publish(draft.about(id.clone(), version));
    }
    Ok(ProtocolResult::of(&view))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::analysis_tools::PROTOCOL_PRODUCER;
    use crate::api::test_support::{call, workspace_with};
    use crate::api::{ErrorCode, Workspace};

    /// Messages of 12 bytes, each starting with the sync word A5 5A and a counter.
    fn messages() -> Vec<u8> {
        (0..40u8).flat_map(|index| [0xA5, 0x5A, index, 8, 1, 2, 3, 4, index.wrapping_mul(13), 6, 7, 8]).collect()
    }

    fn finished(workspace: &mut crate::api::HeadlessWorkspace, job: &serde_json::Value) -> serde_json::Value {
        let begun = std::time::Instant::now();
        loop {
            workspace.bus().deliver_all();
            let status = call(workspace, "jobs.status", json!({"job": job})).unwrap();
            if status["state"] != "running" || begun.elapsed() > std::time::Duration::from_secs(20) {
                return status;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn analysing_a_stream_finds_its_framing_and_publishes_its_messages() {
        let mut workspace = workspace_with("capture.bin", &messages());
        let started = call(&mut workspace, "protocol.analyse", json!({})).unwrap();
        let status = finished(&mut workspace, &started["job"]);
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["producer"], "panel");
        let result = &status["result"];
        assert_eq!(result["messages"].as_array().unwrap().len(), 40, "{result}");
        let frames = call(&mut workspace, "events.facts", json!({"topic": "frames.defined", "producer": PROTOCOL_PRODUCER})).unwrap();
        assert_eq!(frames["facts"][0]["payload"]["total"], 40, "{frames}");
    }

    #[test]
    fn a_chosen_framing_splits_the_stream_again() {
        let mut workspace = workspace_with("capture.bin", &messages());
        let chosen = call(&mut workspace, "protocol.choose_framing", json!({"start": 0, "len": 480, "framing": {"kind": "fixed_size", "len": 24}})).unwrap();
        assert_eq!(chosen["messages"].as_array().unwrap().len(), 20);
        assert_eq!(chosen["framing"]["framing"], json!({"kind": "fixed_size", "len": 24}));
        let frames = call(&mut workspace, "events.facts", json!({"topic": "frames.defined", "producer": PROTOCOL_PRODUCER})).unwrap();
        assert_eq!(frames["facts"][0]["payload"]["total"], 20);
    }

    #[test]
    fn a_stream_past_the_end_or_a_framing_of_another_kind_is_refused() {
        let mut workspace = workspace_with("capture.bin", &messages());
        assert_eq!(call(&mut workspace, "protocol.analyse", json!({"start": 1000})).unwrap_err().code, ErrorCode::OutOfRange);
        let unknown = call(&mut workspace, "protocol.choose_framing", json!({"framing": {"kind": "telepathy"}})).unwrap_err();
        assert_eq!(unknown.code, ErrorCode::InvalidParams);
    }
}
