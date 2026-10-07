//! `bits.*` (beside `bits.read` and `bits.write`): the Bits tool's
//! analyses below the byte: bit periods and sync words, bit planes, line
//! codes, number types for a record field and length fields.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, DocumentInfo, Workspace};
use crate::api::{ApiError, Caller};
use crate::bits::BitOrder;
use crate::linecode::LineCode;
use crate::panel_bits::{self, LengthFieldsResult, LineCodeResult, PeriodsResult, PlanesResult};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("bits.scan_periods", Job, caller scan_periods, ScanPeriodsParams, JobStartedResult, "Start a search of a span for bit periods (frames that are not a whole number of bytes) and the sync word of the strongest, comparing the bits with themselves at every lag, as a job: the periods and sync words are job.finished's result, and in the window they fill the Bits panel."),
    method!("bits.planes", Job, caller planes, PlanesParams, JobStartedResult, "Start splitting a span (at most 1 MiB) into its eight bit planes as a job, scoring how much shape each holds with rows of row_width bytes: the scores are job.finished's result, and in the window the planes fill the Bits panel."),
    method!("bits.open_plane", View, open_plane, OpenPlaneParams, DocumentInfo, "Open one bit plane of a span (at most 1 MiB) as a derived document: bit k of every byte, as a byte of 0 or 255."),
    method!("bits.detect_linecode", Job, caller detect_linecode, LineCodeParams, JobStartedResult, "Start trying Manchester (both conventions), differential Manchester, 8b/10b and packed BCD at every bit alignment of a span (at most 64 KiB) as a job: the decodes, fewest invalid symbols first, and any BCD timestamps are job.finished's result, and in the window they fill the Bits panel."),
    method!("bits.decode_linecode", View, decode_linecode, DecodeLineCodeParams, DecodedDocument, "Decode a span (at most 64 KiB) from a line code at a bit offset and open the decoded bytes as a derived document."),
    method!("bits.rank_field", Read, rank_field, RankFieldParams, RankedField, "Rank what a field of records holds (integers, floats, fixed point, timestamps, enums…) by how plausible its values are across the records."),
    method!("bits.find_length_fields", Job, caller find_length_fields, LengthFieldsParams, JobStartedResult, "Start a search of a span (at most 256 KiB, one message or a run of records) for numbers that are distances, as a job: length prefixes, tag-length-value chains and offset tables, best first, are job.finished's result, and in the window they fill the Bits panel."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("bits.scan_periods", json!({"start": 0, "len": 256, "order": "msb", "max_period": 64})),
        ("bits.planes", json!({"start": 0, "len": 256, "row_width": 16})),
        ("bits.detect_linecode", json!({"start": 0, "len": 256, "order": "lsb"})),
        ("bits.rank_field", json!({"origin": 0, "stride": 16, "offset": 4, "width": 4})),
        ("bits.find_length_fields", json!({"start": 0, "len": 256})),
        ("bits.decode_linecode", json!({"start": 0, "len": 64, "code": "nrzi", "bit_offset": 1})),
        ("bits.open_plane", json!({"start": 0, "len": 16, "bit": 7})),
    ]
}

/// Longest bit period that may be asked for.
pub const MOST_MAX_PERIOD: usize = 8192;
/// Fewest bits of a period that may be asked for.
pub const FEWEST_MAX_PERIOD: usize = 8;
/// Latest bit a line code may start at in the first byte(s).
pub const MOST_BIT_OFFSET: usize = 63;
/// Field widths the number-type ranking takes, in bytes.
pub const FIELD_WIDTHS: [usize; 4] = [1, 2, 4, 8];

/// A line code, as the Bits tool decodes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LineCodeName {
    /// IEEE 802.3: a 0 is high-then-low.
    ManchesterIeee,
    /// G. E. Thomas: a 1 is high-then-low.
    ManchesterThomas,
    DifferentialManchester,
    Nrzi,
    #[serde(rename = "8b10b")]
    EightBTenB,
    GrayByte,
    GrayWord,
    PackedBcd,
}

impl LineCodeName {
    pub fn of(code: LineCode) -> Self {
        match code {
            LineCode::ManchesterIeee => LineCodeName::ManchesterIeee,
            LineCode::ManchesterThomas => LineCodeName::ManchesterThomas,
            LineCode::DifferentialManchester => LineCodeName::DifferentialManchester,
            LineCode::Nrzi => LineCodeName::Nrzi,
            LineCode::EightBTenB => LineCodeName::EightBTenB,
            LineCode::GrayByte => LineCodeName::GrayByte,
            LineCode::GrayWord => LineCodeName::GrayWord,
            LineCode::PackedBcd => LineCodeName::PackedBcd,
        }
    }

    pub fn code(self) -> LineCode {
        match self {
            LineCodeName::ManchesterIeee => LineCode::ManchesterIeee,
            LineCodeName::ManchesterThomas => LineCode::ManchesterThomas,
            LineCodeName::DifferentialManchester => LineCode::DifferentialManchester,
            LineCodeName::Nrzi => LineCode::Nrzi,
            LineCodeName::EightBTenB => LineCode::EightBTenB,
            LineCodeName::GrayByte => LineCode::GrayByte,
            LineCodeName::GrayWord => LineCode::GrayWord,
            LineCodeName::PackedBcd => LineCode::PackedBcd,
        }
    }
}

/// Parameters of `bits.scan_periods`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanPeriodsParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset searched (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes searched, at most 256 KiB and a quarter of max_period; as many as that from start when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Which bit of each byte comes first: "msb" (the default) or "lsb".
    #[serde(default)]
    pub order: BitOrder,
    /// Longest period looked for, 8 to 8192 bits (1024 by default).
    #[serde(default)]
    pub max_period: Option<usize>,
}

/// A bit period found.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BitPeriodFound {
    /// Period in bits.
    pub period: usize,
    /// Fraction of bits equal to the bit one period later.
    pub agreement: f32,
    /// How far that rises above the baseline, in robust deviations.
    pub prominence: f32,
    /// The stronger period this one is a multiple of, if any.
    pub multiple_of: Option<usize>,
}

/// A sync word starting each frame.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SyncWord {
    /// Frame length in bits.
    pub period: usize,
    /// Bit offset of its first occurrence from the start of the span.
    pub bit_offset: usize,
    /// The word, as 0s and 1s.
    pub bits: String,
    /// Fraction of frames where it matches exactly.
    pub match_fraction: f64,
    /// Frames compared.
    pub frames: usize,
}

/// What `bits.scan_periods`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BitPeriods {
    pub start: u64,
    pub order: BitOrder,
    /// Bits examined.
    pub bits: usize,
    /// Agreement with no structure at all.
    pub baseline: f32,
    /// The periods, fundamentals before their multiples, strongest first.
    pub periods: Vec<BitPeriodFound>,
    /// The sync words of the strongest fundamentals.
    pub syncs: Vec<SyncWord>,
}

impl BitPeriods {
    fn of(result: &PeriodsResult) -> Self {
        BitPeriods {
            start: result.start as u64,
            order: result.scan.order,
            bits: result.scan.bits,
            baseline: result.scan.baseline,
            periods: result
                .scan
                .candidates
                .iter()
                .map(|candidate| BitPeriodFound { period: candidate.period, agreement: candidate.agreement, prominence: candidate.prominence, multiple_of: candidate.multiple_of })
                .collect(),
            syncs: result
                .syncs
                .iter()
                .map(|sync| SyncWord { period: sync.period, bit_offset: sync.bit_offset, bits: sync.bits_text(), match_fraction: sync.match_fraction, frames: sync.frames })
                .collect(),
        }
    }
}

/// Parameters of `bits.planes`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanesParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset split (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes split, at most 1 MiB; to the end of the document (or 1 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Bytes per row, 1 to 1024, for scoring each plane by its left and upper neighbours.
    pub row_width: usize,
}

/// How much shape one bit plane holds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PlaneFound {
    /// Bit position, 0 the least significant.
    pub bit: u32,
    /// "constant", "structured", "faint structure" or "noise".
    pub verdict: String,
    pub ones_fraction: f64,
    /// Entropy of the bit alone, 0 to 1.
    pub entropy: f64,
    /// What the left and upper neighbours tell about the bit, 0 to 1.
    pub structure: f64,
}

/// What `bits.planes`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BitPlanes {
    pub start: u64,
    pub len: u64,
    pub row_width: usize,
    /// One per bit, the least significant first.
    pub planes: Vec<PlaneFound>,
}

impl BitPlanes {
    fn of(result: &PlanesResult) -> Self {
        BitPlanes {
            start: result.start as u64,
            len: result.len as u64,
            row_width: result.row_width,
            planes: result
                .scores
                .iter()
                .map(|score| PlaneFound { bit: score.bit, verdict: score.verdict().to_string(), ones_fraction: score.ones_fraction, entropy: score.entropy, structure: score.structure })
                .collect(),
        }
    }
}

/// Parameters of `bits.open_plane`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenPlaneParams {
    /// Document id, path or "current" (the default): the parent.
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes, at most 1 MiB; to the end of the document (or 1 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Which bit, 0 (least significant) to 7.
    pub bit: u32,
}

/// Parameters of `bits.detect_linecode`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LineCodeParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset decoded (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes decoded, at most 64 KiB; to the end of the document (or 64 KiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Which bit of each byte comes first: "msb" (the default) or "lsb".
    #[serde(default)]
    pub order: BitOrder,
}

/// One line-code decode.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LineCodeDecode {
    pub code: LineCodeName,
    /// Bit the decode starts at.
    pub bit_offset: usize,
    /// Symbols read, and the invalid ones among them.
    pub symbols: usize,
    pub errors: usize,
    /// Bytes the decode gives.
    pub decoded_len: usize,
}

/// A packed BCD timestamp.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BcdTimestampFound {
    pub offset: u64,
    /// "YYYY-MM-DD hh:mm:ss".
    pub text: String,
}

/// What `bits.detect_linecode`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LineCodes {
    pub start: u64,
    pub len: u64,
    pub order: BitOrder,
    /// The decodes, lowest error rate first.
    pub decodes: Vec<LineCodeDecode>,
    pub timestamps: Vec<BcdTimestampFound>,
}

impl LineCodes {
    fn of(result: &LineCodeResult) -> Self {
        LineCodes {
            start: result.start as u64,
            len: result.len as u64,
            order: result.order,
            decodes: result
                .decodes
                .iter()
                .map(|decode| LineCodeDecode { code: LineCodeName::of(decode.code), bit_offset: decode.bit_offset, symbols: decode.symbols, errors: decode.errors, decoded_len: decode.bytes.len() })
                .collect(),
            timestamps: result.timestamps.iter().map(|stamp| BcdTimestampFound { offset: (result.start + stamp.offset) as u64, text: stamp.text.clone() }).collect(),
        }
    }
}

/// Parameters of `bits.decode_linecode`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecodeLineCodeParams {
    /// Document id, path or "current" (the default): the parent.
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset decoded (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes decoded, at most 64 KiB; to the end of the document (or 64 KiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Which bit of each byte comes first: "msb" (the default) or "lsb".
    #[serde(default)]
    pub order: BitOrder,
    pub code: LineCodeName,
    /// Bit to start at, 0 to 63 (0 by default).
    #[serde(default)]
    pub bit_offset: usize,
}

/// The result of `bits.decode_linecode`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DecodedDocument {
    /// The derived document the decode was opened as.
    pub document: DocumentInfo,
    /// Symbols read, and the invalid ones among them.
    pub symbols: usize,
    pub errors: usize,
}

/// Parameters of `bits.rank_field`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RankFieldParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Document offset of the first record.
    pub origin: u64,
    /// Bytes per record.
    pub stride: usize,
    /// Offset of the field within each record.
    pub offset: usize,
    /// Bytes in the field: 1, 2, 4 or 8.
    pub width: usize,
}

/// One reading of a field.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FieldReading {
    /// Such as "u16 little-endian" or "float32 big-endian".
    pub interpretation: String,
    /// Plausibility, 0 to 1.
    pub score: f64,
    pub reason: String,
    /// The first records' values, so read.
    pub samples: Vec<String>,
}

/// The result of `bits.rank_field`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RankedField {
    /// Records read (at most 4096).
    pub records: usize,
    /// The readings, most plausible first.
    pub readings: Vec<FieldReading>,
}

/// Parameters of `bits.find_length_fields`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LengthFieldsParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset of the region (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes in the region, at most 256 KiB; to the end of the document (or 256 KiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
}

/// A way numbers in the region explain it as lengths.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LengthHypothesis {
    /// What it is, such as "u16 big-endian length at +2 counting the rest".
    pub description: String,
    pub score: f64,
    /// Fraction of the region it explains.
    pub coverage: f64,
    /// The span it explains, as document offset and length.
    pub start: u64,
    pub len: u64,
    /// An example of it in the data.
    pub example: String,
}

/// What `bits.find_length_fields`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LengthFields {
    pub start: u64,
    pub len: u64,
    /// The hypotheses, best first.
    pub hypotheses: Vec<LengthHypothesis>,
}

impl LengthFields {
    fn of(result: &LengthFieldsResult) -> Self {
        LengthFields {
            start: result.start as u64,
            len: result.len as u64,
            hypotheses: result
                .hypotheses
                .iter()
                .map(|hypothesis| {
                    let (start, len) = hypothesis.span(result.len);
                    LengthHypothesis {
                        description: hypothesis.describe(),
                        score: hypothesis.score(result.len),
                        coverage: hypothesis.coverage(result.len),
                        start: (result.start + start) as u64,
                        len: len as u64,
                        example: hypothesis.example(),
                    }
                })
                .collect(),
        }
    }
}

/// `bits.scan_periods`: read the span now and scan it on a thread.
pub fn scan_periods(workspace: &mut dyn Workspace, caller: &Caller, params: ScanPeriodsParams) -> Result<JobStartedResult, ApiError> {
    let max_period = params.max_period.unwrap_or(panel_bits::DEFAULT_MAX_PERIOD);
    if !(FEWEST_MAX_PERIOD..=MOST_MAX_PERIOD).contains(&max_period) {
        return Err(ApiError::invalid_params(format!("a longest period of {max_period} bits is outside {FEWEST_MAX_PERIOD} to {MOST_MAX_PERIOD}")));
    }
    let limit = panel_bits::period_scan_bytes(max_period);
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, limit, "the span searched")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_bits::await_periods);
    let (start, order) = (span.start, params.order);
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("bit-periods", "Bit periods"),
        &span,
        deliver,
        move |_| panel_bits::find_periods(&bytes, start, order, max_period),
        |result| Summary::of(format!("{} bit periods", result.scan.candidates.len()), BitPeriods::of(result)),
    ))
}

/// `bits.planes`: read the span now and split it on a thread.
pub fn planes(workspace: &mut dyn Workspace, caller: &Caller, params: PlanesParams) -> Result<JobStartedResult, ApiError> {
    if !(1..=panel_bits::PREVIEW_MAX_WIDTH).contains(&params.row_width) {
        return Err(ApiError::invalid_params(format!("a row of {} bytes is outside 1 to {}", params.row_width, panel_bits::PREVIEW_MAX_WIDTH)));
    }
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, panel_bits::PLANE_BYTES, "the span split")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_bits::await_planes);
    let (start, row_width) = (span.start, params.row_width);
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("bit-planes", "Bit planes"),
        &span,
        deliver,
        move |_| panel_bits::split_planes(&bytes, start, row_width),
        |result| Summary::of("8 planes", BitPlanes::of(result)),
    ))
}

pub fn open_plane(workspace: &mut dyn Workspace, params: OpenPlaneParams) -> Result<DocumentInfo, ApiError> {
    if params.bit > 7 {
        return Err(ApiError::invalid_params(format!("bit {} is not one of a byte's, 0 to 7", params.bit)));
    }
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, panel_bits::PLANE_BYTES, "the span")?;
    let plane = crate::bits::bit_plane(&tool_jobs::read(workspace, &span)?, params.bit);
    let name = format!("{} › bit plane {}@{:#x}", workspace::info(workspace, &span.doc)?.name, params.bit, span.start);
    let id = workspace.open_derived(&span.doc, plane, &name)?;
    workspace::info(workspace, &id)
}

/// `bits.detect_linecode`: read the span now and try every code on a thread.
pub fn detect_linecode(workspace: &mut dyn Workspace, caller: &Caller, params: LineCodeParams) -> Result<JobStartedResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, panel_bits::LINECODE_BYTES, "the span decoded")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_bits::await_linecodes);
    let (start, order) = (span.start, params.order);
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("line-codes", "Line codes"),
        &span,
        deliver,
        move |_| panel_bits::detect_linecodes(&bytes, start, order),
        |result| Summary::of(format!("{} decodes", result.decodes.len()), LineCodes::of(result)),
    ))
}

pub fn decode_linecode(workspace: &mut dyn Workspace, params: DecodeLineCodeParams) -> Result<DecodedDocument, ApiError> {
    if params.bit_offset > MOST_BIT_OFFSET {
        return Err(ApiError::invalid_params(format!("bit offset {} is past {MOST_BIT_OFFSET}", params.bit_offset)));
    }
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, panel_bits::LINECODE_BYTES, "the span decoded")?;
    let code = params.code.code();
    let decoded = crate::linecode::decode(&tool_jobs::read(workspace, &span)?, params.order, params.bit_offset, code);
    let name = format!("{} › {}+{}@{:#x}", workspace::info(workspace, &span.doc)?.name, code.label(), params.bit_offset, span.start);
    let (symbols, errors) = (decoded.symbols, decoded.errors);
    let id = workspace.open_derived(&span.doc, decoded.bytes, &name)?;
    Ok(DecodedDocument { document: workspace::info(workspace, &id)?, symbols, errors })
}

pub fn rank_field(workspace: &mut dyn Workspace, params: RankFieldParams) -> Result<RankedField, ApiError> {
    if !FIELD_WIDTHS.contains(&params.width) {
        return Err(ApiError::invalid_params(format!("a field of {} bytes is not one of 1, 2, 4 or 8", params.width)));
    }
    if params.stride == 0 || params.offset + params.width > params.stride {
        return Err(ApiError::invalid_params(format!("a {}-byte field at +{} does not fit in records of {} bytes", params.width, params.offset, params.stride)));
    }
    let (_, document) = workspace::document(workspace, params.doc.as_deref())?;
    let (origin, _) = crate::api::values::span_within(document.len(), params.origin, Some(0))?;
    let records = document.read_range(origin, params.stride.saturating_mul(panel_bits::NUMBER_RECORDS));
    let ranked = crate::numeric::rank_field(&records, params.stride, params.offset, params.width).map_err(|error| ApiError::invalid_params(error.to_string()))?;
    Ok(RankedField {
        records: records.len() / params.stride,
        readings: ranked
            .into_iter()
            .map(|entry| FieldReading { interpretation: entry.interpretation.label().to_string(), score: entry.score, reason: entry.reason, samples: entry.samples })
            .collect(),
    })
}

/// `bits.find_length_fields`: read the region now and search it on a thread.
pub fn find_length_fields(workspace: &mut dyn Workspace, caller: &Caller, params: LengthFieldsParams) -> Result<JobStartedResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, crate::tlv::MAX_REGION, "the region")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(panel_bits::await_lengths);
    let start = span.start;
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("length-fields", "Length fields"),
        &span,
        deliver,
        move |_| panel_bits::find_lengths(&bytes, start),
        |result| Summary::of(format!("{} hypotheses", result.hypotheses.len()), LengthFields::of(result)),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    /// Frames of 37 bits, each starting with the sync word 1011001.
    fn frames_of_37_bits() -> Vec<u8> {
        let mut bits = Vec::new();
        let mut state = 0x1234_5678u32;
        for _ in 0..600 {
            bits.extend([1, 0, 1, 1, 0, 0, 1]);
            for _ in 0..30 {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                bits.push((state & 1) as u8);
            }
        }
        bits.chunks(8).map(|byte| byte.iter().fold(0u8, |value, &bit| value << 1 | bit) << (8 - byte.len())).collect()
    }

    #[test]
    fn a_37_bit_frame_and_its_sync_word_are_found() {
        let mut workspace = workspace_with("frames.bin", &frames_of_37_bits());
        let status = run_job(&mut workspace, "bits.scan_periods", json!({"max_period": 128}));
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["result"]["periods"][0]["period"], 37, "{status}");
        assert_eq!(status["result"]["syncs"][0]["period"], 37);
        assert_eq!(call(&mut workspace, "bits.scan_periods", json!({"max_period": 4})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn a_picture_hidden_in_the_low_bit_is_its_structured_plane_and_opens_as_a_document() {
        let bytes: Vec<u8> = (0..64 * 64).map(|index: usize| ((index * 37 % 251) as u8 & 0xFE) | u8::from((index % 64) < 32)).collect();
        let mut workspace = workspace_with("hidden.bin", &bytes);
        let status = run_job(&mut workspace, "bits.planes", json!({"row_width": 64}));
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["result"]["planes"][0]["verdict"], "structured", "{status}");
        let opened = call(&mut workspace, "bits.open_plane", json!({"bit": 0, "len": 128})).unwrap();
        assert_eq!(opened["name"], "hidden.bin › bit plane 0@0x0");
        assert_eq!(opened["len"], 128);
        let plane = call(&mut workspace, "bytes.read", json!({"doc": opened["id"], "start": 0, "len": 2})).unwrap();
        assert_eq!(plane["data"], "ffff");
        assert_eq!(call(&mut workspace, "bits.open_plane", json!({"bit": 8})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "bits.planes", json!({"row_width": 0})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn manchester_bits_are_detected_and_decoded_into_a_document() {
        let message = b"Manchester encoded message, again and again. ".repeat(4);
        let bits: Vec<u8> = message.iter().flat_map(|byte| (0..8).rev().flat_map(move |shift| if byte >> shift & 1 == 1 { [0u8, 1] } else { [1, 0] })).collect();
        let encoded: Vec<u8> = bits.chunks(8).map(|byte| byte.iter().fold(0u8, |value, &bit| value << 1 | bit)).collect();
        let mut workspace = workspace_with("line.bin", &encoded);
        let status = run_job(&mut workspace, "bits.detect_linecode", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        assert_eq!(status["result"]["decodes"][0]["code"], "manchester_ieee", "{status}");
        let decoded = call(&mut workspace, "bits.decode_linecode", json!({"code": "manchester_ieee"})).unwrap();
        assert_eq!(decoded["errors"], 0);
        let text = call(&mut workspace, "bytes.read", json!({"doc": decoded["document"]["id"], "start": 0, "len": 10, "encoding": "text"})).unwrap();
        assert_eq!(text["data"], "Manchester");
        assert_eq!(call(&mut workspace, "bits.decode_linecode", json!({"code": "morse"})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn a_counting_field_reads_as_an_integer_and_a_field_outside_the_record_is_refused() {
        let records: Vec<u8> = (0..200u32).flat_map(|index| [b"HDR!".as_slice(), &index.to_le_bytes(), &[0u8; 8]].concat()).collect();
        let mut workspace = workspace_with("records.bin", &records);
        let ranked = call(&mut workspace, "bits.rank_field", json!({"origin": 0, "stride": 16, "offset": 4, "width": 4})).unwrap();
        assert_eq!(ranked["records"], 200);
        assert_eq!(ranked["readings"][0]["interpretation"], "u32 LE", "{ranked}");
        assert_eq!(call(&mut workspace, "bits.rank_field", json!({"origin": 0, "stride": 16, "offset": 14, "width": 4})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "bits.rank_field", json!({"origin": 0, "stride": 16, "offset": 0, "width": 3})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn a_chain_of_tag_length_value_records_is_explained_as_length_fields() {
        let mut region = Vec::new();
        for index in 0..40u8 {
            let value = vec![index; usize::from(index % 7) + 3];
            region.push(0x10 + index % 4);
            region.push(value.len() as u8);
            region.extend(value);
        }
        let mut workspace = workspace_with("tlv.bin", &region);
        let status = run_job(&mut workspace, "bits.find_length_fields", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        let best = &status["result"]["hypotheses"][0];
        assert!(best["coverage"].as_f64().unwrap() > 0.99, "{best}");
        assert_eq!(call(&mut workspace, "bits.find_length_fields", json!({"len": 300 * 1024})).unwrap_err().code, ErrorCode::OutOfRange);
    }
}
