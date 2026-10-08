//! `checksums.*`: the Checksums tool's digests of a span and its search for
//! a checksum stored in the data, and the CRC solver's search for the CRC
//! parameters behind records that each carry one.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::{self, Workspace};
use crate::api::{ApiError, Caller, values};
use crate::checksums::ChecksumMatch;
use crate::crc_solver::{self, CrcParams, CrcPosition, CrcSolution, CrcWidth, SolverOptions, StoredOrder};
use crate::panel_crc_solver::SolveOutcome;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("checksums.digests", Read, digests, DigestsParams, DigestsResult, "The digests of a span (at most 64 MiB): CRC-32, Adler-32, MD5, SHA-1, SHA-256, the 8- and 16-bit sums and the XOR of every byte."),
    method!("checksums.find_stored", Read, find_stored, FindStoredParams, StoredChecksums, "Find a CRC, Adler or sum stored in a span (at most 64 MiB) that covers part of it, testing header and trailer fields, and the fields at the boundaries given, against the bytes before, after and around them."),
    method!("checksums.solve_crc", Job, caller solve_crc, SolveCrcParams, JobStartedResult, "Start the CRC solver on records that each carry a stored CRC (fixed-length records, or a packet set's packets of any lengths), as a job: every polynomial, init, xorout and reflection that reproduces all the stored values (like reveng), with the closest catalogue algorithm, is job.finished's result, and in the window it fills the CRC solver."),
    method!("checksums.verify", Read, verify, VerifyParams, VerifyResult, "Check the checksum stored in each record (a packet set's packets, filtered, or fixed-length records) against a model (an algorithm by name, or a CRC's parameters as solve_crc gives them) and list the records whose value is wrong."),
    method!("checksums.compute", Read, compute, ComputeParams, ComputeResult, "Compute a checksum of a span with a model (an algorithm by name, or a CRC's parameters as solve_crc gives them): its value, and its bytes as they would be stored."),
];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("checksums.digests", json!({"start": 0, "len": 64})),
        ("checksums.find_stored", json!({"start": 0, "len": 64, "boundaries": [8]})),
        ("checksums.solve_crc", json!({"start": 0, "record_len": 16, "count": 4, "width": 16, "order": "either", "try_skips": false})),
        ("checksums.verify", json!({"records": {"start": 0, "record_len": 16, "count": 4}, "model": {"algorithm": "sum8"}})),
        ("checksums.compute", json!({"start": 0, "len": 9, "model": {"algorithm": "CRC-16/XMODEM"}})),
    ]
}

/// Most bytes digested or searched for a stored checksum.
pub const CHECKSUM_LIMIT: usize = 64 * 1024 * 1024;
/// Most bytes of records the CRC solver reads.
pub const SOLVE_LIMIT: usize = crate::api::MAX_CALL_BYTES;

/// Parameters of `checksums.digests`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DigestsParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset digested (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes digested, at most 64 MiB; to the end of the document (or 64 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
}

/// The result of `checksums.digests`, every digest as lower-case hex.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DigestsResult {
    pub start: u64,
    pub len: u64,
    pub crc32: String,
    pub adler32: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sum8: String,
    pub sum16: String,
    pub xor8: String,
    /// The one-byte sum as a number, for an anchor to do sums with.
    pub sum8_value: u8,
    /// The 16-bit sum as a number.
    pub sum16_value: u16,
    /// The XOR of every byte as a number.
    pub xor8_value: u8,
}

/// Parameters of `checksums.find_stored`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindStoredParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset searched (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes searched, at most 64 MiB; to the end of the document (or 64 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// Document offsets where known fields start or end (the window passes
    /// those of the findings in the span), also tested as stored values and
    /// as the edges of covered ranges.
    #[serde(default)]
    pub boundaries: Vec<u64>,
}

/// A checksum found stored in the data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StoredChecksum {
    /// Such as "CRC-32" or "Adler-32".
    pub algorithm: String,
    /// "little", "big", or empty for a single byte.
    pub endian: String,
    /// Document offset of the stored value.
    pub value_offset: u64,
    pub value_len: u64,
    /// Document offset of the bytes it covers.
    pub covered_start: u64,
    pub covered_len: u64,
}

impl StoredChecksum {
    fn of(found: &ChecksumMatch) -> Self {
        StoredChecksum {
            algorithm: found.algorithm.to_string(),
            endian: found.endian.to_string(),
            value_offset: found.value_offset as u64,
            value_len: found.value_len as u64,
            covered_start: found.covered_start as u64,
            covered_len: found.covered_len as u64,
        }
    }
}

/// The result of `checksums.find_stored`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StoredChecksums {
    pub start: u64,
    pub len: u64,
    /// The checksums that match, in the order found.
    pub matches: Vec<StoredChecksum>,
}

/// Byte order of the stored CRC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CrcOrder {
    Big,
    Little,
    /// Try both.
    #[default]
    Either,
}

impl CrcOrder {
    pub fn of(order: StoredOrder) -> Self {
        match order {
            StoredOrder::Big => CrcOrder::Big,
            StoredOrder::Little => CrcOrder::Little,
            StoredOrder::Either => CrcOrder::Either,
        }
    }

    fn stored_order(self) -> StoredOrder {
        match self {
            CrcOrder::Big => StoredOrder::Big,
            CrcOrder::Little => StoredOrder::Little,
            CrcOrder::Either => StoredOrder::Either,
        }
    }
}

/// Parameters of `checksums.solve_crc`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SolveCrcParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// Document offset of the first record.
    #[serde(default)]
    pub start: u64,
    /// Bytes in each record, CRC included.
    #[serde(default)]
    pub record_len: usize,
    /// Records, at least 2; the first 256 are solved.
    #[serde(default)]
    pub count: usize,
    /// A packet set whose packets are the records, of any lengths, in
    /// place of `start`, `record_len` and `count`.
    #[serde(default)]
    pub set: Option<String>,
    /// With `set`, a display filter choosing its packets.
    #[serde(default)]
    pub filter: Option<String>,
    /// Bits in the CRC: 8, 16 (the default) or 32.
    #[serde(default)]
    pub width: Option<u32>,
    /// Byte order of the stored CRC (either, by default).
    #[serde(default)]
    pub order: CrcOrder,
    /// Offset of the CRC within each record, covering the bytes before it;
    /// the last bytes of each record when omitted.
    #[serde(default)]
    pub offset: Option<usize>,
    /// Also try leaving up to 4 leading bytes of each record out of the CRC.
    #[serde(default)]
    pub try_skips: bool,
}

/// One parameter set that reproduces every stored CRC.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CrcSolutionResult {
    /// The parameters in reveng's notation.
    pub params: String,
    pub width: u32,
    pub poly: u32,
    pub init: u32,
    pub refin: bool,
    pub refout: bool,
    pub xorout: u32,
    /// Leading bytes of each record the CRC does not cover.
    pub skip: usize,
    pub big_endian: bool,
    /// The catalogue algorithm sharing the polynomial, if any.
    pub named: Option<String>,
    /// Whether every parameter matches that catalogue algorithm.
    pub exact: bool,
    /// Whether another init with a matching xorout fits these records too.
    pub init_ambiguous: bool,
}

impl CrcSolutionResult {
    fn of(solution: &CrcSolution) -> Self {
        let params = &solution.params;
        CrcSolutionResult {
            params: params.to_text(),
            width: params.width,
            poly: params.poly,
            init: params.init,
            refin: params.refin,
            refout: params.refout,
            xorout: params.xorout,
            skip: solution.skip,
            big_endian: solution.big_endian,
            named: solution.named.as_ref().map(|named| named.name.to_string()),
            exact: solution.named.as_ref().is_some_and(|named| named.exact),
            init_ambiguous: solution.init_ambiguous,
        }
    }
}

/// What `checksums.solve_crc`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CrcSolveResult {
    /// Document offset of the first record.
    pub start: u64,
    /// Bytes in each record; 0 when a set's packets differ in length.
    pub record_len: usize,
    /// Records solved.
    pub records: usize,
    /// The parameter sets that fit, exact catalogue matches first.
    pub solutions: Vec<CrcSolutionResult>,
    /// Caveats: records ignored, ambiguity, truncation.
    pub notes: Vec<String>,
    /// Why the solver could not finish, when it could not.
    pub error: Option<String>,
}

impl CrcSolveResult {
    /// The solver's outcome as an API caller collects it.
    pub fn of(outcome: &SolveOutcome) -> Self {
        let (solutions, notes, error) = match &outcome.result {
            Ok(report) => (report.solutions.iter().map(CrcSolutionResult::of).collect(), report.notes.clone(), None),
            Err(error) => (Vec::new(), Vec::new(), Some(error.to_string())),
        };
        CrcSolveResult { start: outcome.start as u64, record_len: outcome.record_len, records: outcome.records, solutions, notes, error }
    }
}

pub fn digests(workspace: &mut dyn Workspace, params: DigestsParams) -> Result<DigestsResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, CHECKSUM_LIMIT, "the span digested")?;
    let digests = crate::checksums::digests(&tool_jobs::read(workspace, &span)?);
    Ok(DigestsResult {
        start: span.start as u64,
        len: span.len as u64,
        crc32: format!("{:08x}", digests.crc32),
        adler32: format!("{:08x}", digests.adler32),
        md5: digests.md5,
        sha1: digests.sha1,
        sha256: digests.sha256,
        sum8: format!("{:02x}", digests.sum8),
        sum16: format!("{:04x}", digests.sum16),
        xor8: format!("{:02x}", digests.xor8),
        sum8_value: digests.sum8,
        sum16_value: digests.sum16,
        xor8_value: digests.xor8,
    })
}

pub fn find_stored(workspace: &mut dyn Workspace, params: FindStoredParams) -> Result<StoredChecksums, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, CHECKSUM_LIMIT, "the span searched")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let boundaries: Vec<usize> = params
        .boundaries
        .iter()
        .filter_map(|&boundary| usize::try_from(boundary).ok()?.checked_sub(span.start))
        .filter(|&boundary| boundary > 0 && boundary < span.len)
        .collect();
    let matches = crate::checksums::find_checksums(&bytes, span.start, &[], &boundaries).iter().map(StoredChecksum::of).collect();
    Ok(StoredChecksums { start: span.start as u64, len: span.len as u64, matches })
}

/// The solver's options for `params`, or why they cannot be.
fn solver_options(params: &SolveCrcParams) -> Result<SolverOptions, ApiError> {
    let width = match params.width.unwrap_or(16) {
        8 => CrcWidth::W8,
        16 => CrcWidth::W16,
        32 => CrcWidth::W32,
        other => return Err(ApiError::invalid_params(format!("a CRC of {other} bits is not one the solver knows; use 8, 16 or 32"))),
    };
    let position = params.offset.map_or(CrcPosition::End, CrcPosition::Offset);
    let max_skip = if params.try_skips { crc_solver::DEFAULT_MAX_SKIP } else { 0 };
    Ok(SolverOptions { width, position, order: params.order.stored_order(), max_skip, ..SolverOptions::default() })
}

/// `checksums.solve_crc`: read the records now and solve on a thread.
pub fn solve_crc(workspace: &mut dyn Workspace, caller: &Caller, params: SolveCrcParams) -> Result<JobStartedResult, ApiError> {
    let options = solver_options(&params)?;
    if let Some(set) = &params.set {
        return solve_crc_of_set(workspace, caller, set, params.filter.as_deref(), options);
    }
    if params.record_len == 0 {
        return Err(ApiError::invalid_params("a record must be at least 1 byte long"));
    }
    if params.count < 2 {
        return Err(ApiError::invalid_params(format!("the solver needs at least 2 records, not {}", params.count)));
    }
    let count = params.count.min(crc_solver::MAX_MESSAGES);
    let len = params.record_len.checked_mul(count).ok_or_else(|| ApiError::invalid_params("the records are too long to read"))?;
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, Some(len as u64), SOLVE_LIMIT, "the records")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(crate::panel_crc_solver::await_solve);
    let (start, record_len) = (span.start, params.record_len);
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("crc-solver", "CRC solver"),
        &span,
        deliver,
        move |_| crate::panel_crc_solver::solve_records(&bytes, start, record_len, &options),
        |outcome| match &outcome.result {
            Ok(report) => Summary::of(format!("{} parameter sets", report.solutions.len()), CrcSolveResult::of(outcome)),
            Err(error) => Summary { ok: false, outcome: error.to_string(), result: serde_json::to_value(CrcSolveResult::of(outcome)).unwrap_or_default() },
        },
    ))
}

/// `checksums.solve_crc` on a packet set's packets, which may differ in length.
fn solve_crc_of_set(workspace: &mut dyn Workspace, caller: &Caller, set: &str, filter: Option<&str>, options: SolverOptions) -> Result<JobStartedResult, ApiError> {
    let (span, records) = set_records(workspace, set, filter)?;
    if records.len() < 2 {
        return Err(ApiError::invalid_params(format!("the solver needs at least 2 records, and {set} has {} the filter keeps", records.len())));
    }
    let first_len = records[0].bytes.len();
    let record_len = if records.iter().all(|record| record.bytes.len() == first_len) { first_len } else { 0 };
    let messages: Vec<Vec<u8>> = records.into_iter().map(|record| record.bytes).collect();
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(crate::panel_crc_solver::await_solve);
    let start = span.start;
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("crc-solver", "CRC solver"),
        &span,
        deliver,
        move |_| {
            let slices: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
            SolveOutcome { start, record_len, records: slices.len(), result: crc_solver::solve(&slices, &options) }
        },
        |outcome| match &outcome.result {
            Ok(report) => Summary::of(format!("{} parameter sets", report.solutions.len()), CrcSolveResult::of(outcome)),
            Err(error) => Summary { ok: false, outcome: error.to_string(), result: serde_json::to_value(CrcSolveResult::of(outcome)).unwrap_or_default() },
        },
    ))
}

/// A checksum to compute or check: one of `checksums.find_stored`'s
/// algorithms or a catalogue CRC by name, or a CRC's parameters as
/// `checksums.solve_crc` gives them (one of its solutions can be passed as
/// it is), and where each record stores its value.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChecksumModel {
    /// "sum8", "xor8", "sum16", "sum32", "CRC-32", "Adler-32",
    /// "CRC-16/CCITT", "CRC-16/ARC", or a catalogue CRC such as
    /// "CRC-16/XMODEM"; in place of `width` and `poly`.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// A CRC's bits: 8, 16 or 32.
    #[serde(default)]
    pub width: Option<u32>,
    /// A CRC's polynomial, without its top bit.
    #[serde(default)]
    pub poly: Option<u32>,
    #[serde(default)]
    pub init: u32,
    #[serde(default)]
    pub refin: bool,
    #[serde(default)]
    pub refout: bool,
    #[serde(default)]
    pub xorout: u32,
    /// Leading bytes of each record the checksum leaves out (0 by default).
    #[serde(default)]
    pub skip: usize,
    /// Whether the stored value is big-endian (the default).
    #[serde(default)]
    pub big_endian: Option<bool>,
    /// Offset of the stored value in each record, after the bytes it
    /// covers; the last bytes of each record when omitted.
    #[serde(default)]
    pub offset: Option<usize>,
}

/// A model made ready to compute with.
struct Checker {
    /// The model in words.
    name: String,
    /// Bytes of the stored value.
    width: usize,
    compute: Box<dyn Fn(&[u8]) -> u64>,
    skip: usize,
    big_endian: bool,
    offset: Option<usize>,
}

impl ChecksumModel {
    fn checker(&self) -> Result<Checker, ApiError> {
        let (name, width, compute): (String, usize, Box<dyn Fn(&[u8]) -> u64>) = match (&self.algorithm, self.width, self.poly) {
            (Some(name), _, _) => {
                if let Some((name, width, compute)) = crate::checksums::named_algorithm(name) {
                    (name.to_string(), width, Box::new(compute))
                } else {
                    let entry = crc_solver::CATALOGUE
                        .iter()
                        .find(|entry| entry.name.eq_ignore_ascii_case(name.trim()))
                        .ok_or_else(|| ApiError::invalid_params(format!("there is no checksum '{name}'; name one of find_stored's (sum8, CRC-32, …) or a catalogue CRC such as CRC-16/XMODEM, or give width and poly")))?;
                    let params = entry.params;
                    (entry.name.to_string(), (params.width / 8) as usize, Box::new(move |bytes: &[u8]| params.compute(bytes) as u64))
                }
            }
            (None, Some(width @ (8 | 16 | 32)), Some(poly)) => {
                let params = CrcParams { width, poly, init: self.init, refin: self.refin, refout: self.refout, xorout: self.xorout };
                (params.to_text(), (width / 8) as usize, Box::new(move |bytes: &[u8]| params.compute(bytes) as u64))
            }
            (None, Some(width), Some(_)) => return Err(ApiError::invalid_params(format!("a CRC of {width} bits is not one the model takes; use 8, 16 or 32"))),
            _ => return Err(ApiError::invalid_params("give the model's algorithm by name, or a CRC's width and poly (as solve_crc gives them)")),
        };
        Ok(Checker { name, width, compute, skip: self.skip, big_endian: self.big_endian.unwrap_or(true), offset: self.offset })
    }
}

impl Checker {
    /// The stored value of `record` and the value computed over the bytes
    /// it covers, or `None` when the record is too short to hold them.
    fn check(&self, record: &[u8]) -> Option<(u64, u64)> {
        let at = match self.offset {
            Some(offset) => offset,
            None => record.len().checked_sub(self.width)?,
        };
        let stored = record.get(at..at.checked_add(self.width)?)?;
        let covered = record.get(self.skip..at).filter(|covered| !covered.is_empty())?;
        let fold = |value: u64, byte: &u8| (value << 8) | u64::from(*byte);
        let stored = if self.big_endian { stored.iter().fold(0, fold) } else { stored.iter().rev().fold(0, fold) };
        Some((stored, (self.compute)(covered)))
    }

    fn hex(&self, value: u64) -> String {
        format!("{value:0width$x}", width = self.width * 2)
    }

    /// `value` as the bytes a record stores, in hex.
    fn stored_bytes(&self, value: u64) -> String {
        let bytes = value.to_be_bytes();
        let mut stored = bytes[8 - self.width..].to_vec();
        if !self.big_endian {
            stored.reverse();
        }
        stored.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Fixed-length records in a document.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FixedRecords {
    /// Document offset of the first record (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes in each record, stored value included.
    pub record_len: usize,
    pub count: usize,
}

/// Parameters of `checksums.verify`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyParams {
    /// With `records`, the document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// A packet set whose packets are the records.
    #[serde(default)]
    pub set: Option<String>,
    /// With `set`, a display filter choosing its packets.
    #[serde(default)]
    pub filter: Option<String>,
    /// Fixed-length records of the document, in place of `set`.
    #[serde(default)]
    pub records: Option<FixedRecords>,
    pub model: ChecksumModel,
}

/// A record whose stored checksum is wrong.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BadRecord {
    /// The packet's index in the set, or the record's number.
    pub index: u64,
    /// Document offset of the record.
    pub offset: u64,
    pub len: u64,
    /// The value stored, and the value computed, as hex numbers.
    pub stored: String,
    pub computed: String,
}

/// The result of `checksums.verify`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VerifyResult {
    /// The model in words.
    pub model: String,
    /// Records checked.
    pub checked: usize,
    /// Records whose stored value is right.
    pub good: usize,
    /// Records too short to hold a value where the model looks.
    pub short: usize,
    /// The records whose stored value is wrong, in order.
    pub bad: Vec<BadRecord>,
}

/// Parameters of `checksums.compute`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComputeParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset covered (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes covered; to the end of the document (or 64 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// The checksum; its `skip` and `offset` are not used.
    pub model: ChecksumModel,
}

/// The result of `checksums.compute`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ComputeResult {
    pub start: u64,
    pub len: u64,
    /// The model in words.
    pub model: String,
    pub value: u64,
    /// The value as a hex number.
    pub hex: String,
    /// The value's bytes as stored, in the model's byte order, as hex.
    pub stored: String,
}

/// One record to check: where it is and its bytes.
struct Record {
    index: usize,
    offset: usize,
    bytes: Vec<u8>,
}

/// Most records `checksums.verify` and `checksums.solve_crc` read from a set.
const MOST_SET_RECORDS: usize = 100_000;

/// The packets of `set` that `filter` keeps, as records, with the span of
/// the document they lie in.
fn set_records(workspace: &mut dyn Workspace, set: &str, filter: Option<&str>) -> Result<(tool_jobs::ToolSpan, Vec<Record>), ApiError> {
    use crate::api::packet_sets;
    let sets = packet_sets::list_sets(workspace, values::NoParams::default())?;
    let doc = sets
        .sets
        .iter()
        .find(|info| info.set == set)
        .map(|info| info.doc.clone())
        .ok_or_else(|| ApiError::not_found(format!("there is no packet set '{set}'; packets.sets.list lists them")))?;
    let mut places: Vec<(usize, usize, usize)> = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let asked = serde_json::json!({"set": set, "filter": filter, "limit": values::MAX_PAGE, "next": next});
        let params: packet_sets::ListParams = serde_json::from_value(asked).map_err(|error| ApiError::invalid_params(format!("listing {set}: {error}")))?;
        let page = packet_sets::list(workspace, params)?;
        places.extend(page.packets.iter().map(|packet| (packet.index as usize, packet.offset as usize, packet.len as usize)));
        match page.next {
            Some(cursor) if places.len() < MOST_SET_RECORDS => next = Some(cursor),
            _ => break,
        }
    }
    places.truncate(MOST_SET_RECORDS);
    let total: usize = places.iter().map(|&(_, _, len)| len).sum();
    values::check_size(total, CHECKSUM_LIMIT, "the packets")?;
    let version = workspace::info(workspace, &doc)?.version;
    let (_, document) = workspace::document(workspace, Some(&doc))?;
    let records: Vec<Record> = places.iter().map(|&(index, offset, len)| Record { index, offset, bytes: document.read_range(offset, len) }).collect();
    let start = places.iter().map(|&(_, offset, _)| offset).min().unwrap_or(0);
    let end = places.iter().map(|&(_, offset, len)| offset + len).max().unwrap_or(start);
    Ok((tool_jobs::ToolSpan { doc, version, start, len: end - start }, records))
}

/// `count` records of `record_len` bytes at `start` of a document.
fn fixed_records(workspace: &mut dyn Workspace, doc: Option<&str>, fixed: &FixedRecords) -> Result<Vec<Record>, ApiError> {
    if fixed.record_len == 0 || fixed.count == 0 {
        return Err(ApiError::invalid_params("give records of at least 1 byte, and at least 1 of them"));
    }
    let len = fixed.record_len.checked_mul(fixed.count).ok_or_else(|| ApiError::invalid_params("the records are too long to read"))?;
    let span = tool_jobs::span(workspace, doc, fixed.start, Some(len as u64), CHECKSUM_LIMIT, "the records")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    Ok(bytes
        .chunks_exact(fixed.record_len)
        .enumerate()
        .map(|(index, record)| Record { index, offset: span.start + index * fixed.record_len, bytes: record.to_vec() })
        .collect())
}

pub fn verify(workspace: &mut dyn Workspace, params: VerifyParams) -> Result<VerifyResult, ApiError> {
    let checker = params.model.checker()?;
    let records = match (&params.set, &params.records) {
        (Some(set), None) => set_records(workspace, set, params.filter.as_deref())?.1,
        (None, Some(fixed)) if params.filter.is_none() => fixed_records(workspace, params.doc.as_deref(), fixed)?,
        (None, Some(_)) => return Err(ApiError::invalid_params("a filter chooses a set's packets; give set with it, not records")),
        _ => return Err(ApiError::invalid_params("give the records to check as a packet set (set) or as fixed-length records (records), one of them")),
    };
    let mut result = VerifyResult { model: checker.name.clone(), checked: records.len(), good: 0, short: 0, bad: Vec::new() };
    for record in &records {
        match checker.check(&record.bytes) {
            None => result.short += 1,
            Some((stored, computed)) if stored == computed => result.good += 1,
            Some((stored, computed)) => result.bad.push(BadRecord {
                index: record.index as u64,
                offset: record.offset as u64,
                len: record.bytes.len() as u64,
                stored: checker.hex(stored),
                computed: checker.hex(computed),
            }),
        }
    }
    Ok(result)
}

pub fn compute(workspace: &mut dyn Workspace, params: ComputeParams) -> Result<ComputeResult, ApiError> {
    let checker = params.model.checker()?;
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, CHECKSUM_LIMIT, "the span covered")?;
    let value = (checker.compute)(&tool_jobs::read(workspace, &span)?);
    Ok(ComputeResult { start: span.start as u64, len: span.len as u64, hex: checker.hex(value), stored: checker.stored_bytes(value), model: checker.name, value })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn the_digests_of_a_span_are_the_well_known_ones() {
        let mut workspace = workspace_with("a.bin", b"123456789 and more");
        let digests = call(&mut workspace, "checksums.digests", json!({"start": 0, "len": 9})).unwrap();
        assert_eq!(digests["crc32"], "cbf43926", "the CRC-32 check value");
        assert_eq!(digests["md5"], "25f9e794323b453885f5181f1b624d0b");
        assert_eq!(call(&mut workspace, "checksums.digests", json!({"start": 9, "len": 100})).unwrap_err().code, ErrorCode::OutOfRange);
    }

    #[test]
    fn a_trailing_crc_is_found_covering_the_bytes_before_it() {
        let mut record = b"some header and a payload worth checking".to_vec();
        let crc = crate::checksums::crc32(&record);
        record.extend(crc.to_le_bytes());
        let mut workspace = workspace_with("a.bin", &record);
        let found = call(&mut workspace, "checksums.find_stored", json!({})).unwrap();
        let first = &found["matches"][0];
        assert_eq!((first["algorithm"].as_str(), first["value_offset"].as_u64(), first["covered_len"].as_u64()), (Some("CRC-32"), Some(40), Some(40)), "{found}");
        assert_eq!(call(&mut workspace, "checksums.find_stored", json!({"start": 100})).unwrap_err().code, ErrorCode::OutOfRange);
    }

    /// Records of 12 bytes, each ending with its CRC-16/XMODEM.
    fn xmodem_records() -> Vec<u8> {
        let params = crate::crc_solver::CATALOGUE.iter().find(|entry| entry.name == "CRC-16/XMODEM").map(|entry| entry.params).expect("XMODEM in the catalogue");
        (0..8u8)
            .flat_map(|index| {
                let mut record: Vec<u8> = (0..10).map(|byte: u8| byte.wrapping_mul(7).wrapping_add(index * 13)).collect();
                let crc = params.compute(&record) as u16;
                record.extend(crc.to_be_bytes());
                record
            })
            .collect()
    }

    #[test]
    fn the_solver_names_the_crc_behind_records_that_end_with_one() {
        let mut workspace = workspace_with("records.bin", &xmodem_records());
        let status = run_job(&mut workspace, "checksums.solve_crc", json!({"start": 0, "record_len": 12, "count": 8, "width": 16}));
        assert_eq!(status["state"], "finished", "{status}");
        let solutions = status["result"]["solutions"].as_array().unwrap();
        assert!(solutions.iter().any(|solution| solution["named"] == "CRC-16/XMODEM" && solution["exact"] == true), "{status}");
        assert_eq!(status["result"]["records"], 8);
    }

    #[test]
    fn a_solve_with_too_few_records_an_unknown_width_or_records_past_the_end_is_refused() {
        let mut workspace = workspace_with("records.bin", &xmodem_records());
        let refuse = |workspace: &mut crate::api::HeadlessWorkspace, params| call(workspace, "checksums.solve_crc", params).unwrap_err().code;
        assert_eq!(refuse(&mut workspace, json!({"start": 0, "record_len": 12, "count": 1})), ErrorCode::InvalidParams);
        assert_eq!(refuse(&mut workspace, json!({"start": 0, "record_len": 12, "count": 4, "width": 12})), ErrorCode::InvalidParams);
        assert_eq!(refuse(&mut workspace, json!({"start": 0, "record_len": 12, "count": 9})), ErrorCode::OutOfRange);
        assert_eq!(refuse(&mut workspace, json!({"start": 0, "record_len": 0, "count": 4})), ErrorCode::InvalidParams);
    }

    /// Frames of a u16 length (of what follows it), a type, a payload whose
    /// length goes with the type and a big-endian CRC-16/XMODEM over the
    /// type and payload; frame 3 may have a byte flipped on the wire.
    fn bus(corrupted: bool) -> Vec<u8> {
        let params = crate::crc_solver::CATALOGUE.iter().find(|entry| entry.name == "CRC-16/XMODEM").map(|entry| entry.params).unwrap();
        let mut stream = Vec::new();
        for index in 0..8u8 {
            let mut body = vec![[0x01, 0x81][index as usize % 2]];
            body.extend((0..[0, 6][index as usize % 2]).map(|byte: u8| byte.wrapping_mul(31).wrapping_add(index * 7)));
            let crc = params.compute(&body) as u16;
            if corrupted && index == 3 {
                body[1] ^= 0x10;
            }
            stream.extend(((body.len() + 2) as u16).to_be_bytes());
            stream.extend(body);
            stream.extend(crc.to_be_bytes());
        }
        stream
    }

    fn bus_set(workspace: &mut crate::api::HeadlessWorkspace) -> String {
        let created = call(workspace, "packets.sets.create", json!({"from": "length_field", "length_field": {"offset": 0}, "detect": false})).unwrap();
        assert_eq!(created["count"], 8, "{created}");
        created["set"].as_str().unwrap().to_string()
    }

    #[test]
    fn verifying_a_sets_crcs_lists_the_frame_corrupted_on_the_wire() {
        let mut workspace = workspace_with("bus.bin", &bus(true));
        let set = bus_set(&mut workspace);
        let model = json!({"algorithm": "CRC-16/XMODEM", "skip": 2});
        let verified = call(&mut workspace, "checksums.verify", json!({"set": set, "model": model})).unwrap();
        assert_eq!((verified["checked"].as_u64(), verified["good"].as_u64()), (Some(8), Some(7)), "{verified}");
        assert_eq!(verified["bad"].as_array().unwrap().len(), 1, "{verified}");
        assert_eq!(verified["bad"][0]["index"], 3, "{verified}");
        let telemetry = call(&mut workspace, "checksums.verify", json!({"set": set, "filter": "len > 6", "model": model})).unwrap();
        assert_eq!(telemetry["checked"], 4, "the filter chooses the packets: {telemetry}");
        let solved = json!({"width": 16, "poly": 0x1021, "init": 0, "refin": false, "refout": false, "xorout": 0, "skip": 2, "big_endian": true, "params": "…", "named": "CRC-16/XMODEM", "exact": true, "init_ambiguous": false});
        let by_solution = call(&mut workspace, "checksums.verify", json!({"set": set, "model": solved})).unwrap();
        assert_eq!(by_solution["bad"], verified["bad"], "a solve_crc solution is a model as it is");
    }

    #[test]
    fn a_crc_computed_over_a_span_is_the_catalogue_check_value() {
        let mut workspace = workspace_with("a.bin", b"123456789 and more");
        let computed = call(&mut workspace, "checksums.compute", json!({"start": 0, "len": 9, "model": {"algorithm": "CRC-16/XMODEM"}})).unwrap();
        assert_eq!((computed["value"].as_u64(), computed["hex"].as_str(), computed["stored"].as_str()), (Some(0x31C3), Some("31c3"), Some("31c3")), "{computed}");
        let little = call(&mut workspace, "checksums.compute", json!({"start": 0, "len": 9, "model": {"algorithm": "crc-32", "big_endian": false}})).unwrap();
        assert_eq!((little["hex"].as_str(), little["stored"].as_str()), (Some("cbf43926"), Some("2639f4cb")), "{little}");
        assert_eq!(call(&mut workspace, "checksums.compute", json!({"model": {"algorithm": "CRC-99/NONE"}})).unwrap_err().code, ErrorCode::InvalidParams);
        assert_eq!(call(&mut workspace, "checksums.compute", json!({"model": {}})).unwrap_err().code, ErrorCode::InvalidParams);
    }

    #[test]
    fn the_solver_takes_a_sets_frames_of_different_lengths() {
        let mut workspace = workspace_with("bus.bin", &bus(false));
        let set = bus_set(&mut workspace);
        let intact = run_job(&mut workspace, "checksums.solve_crc", json!({"set": set, "width": 16, "try_skips": true}));
        assert_eq!(intact["state"], "finished", "{intact}");
        assert_eq!(intact["result"]["record_len"], 0, "the frames differ in length: {intact}");
        let solutions = intact["result"]["solutions"].as_array().unwrap();
        assert!(solutions.iter().any(|solution| solution["named"] == "CRC-16/XMODEM" && solution["skip"] == 2), "{intact}");
    }

    #[test]
    fn the_one_byte_sum_is_also_given_as_a_number() {
        let mut workspace = workspace_with("a.bin", &[0xAA, 0x2D, 0x74, 0xB5, 0x27, 0x01, 0x19, 0x52]);
        let digests = call(&mut workspace, "checksums.digests", json!({})).unwrap();
        assert_eq!((digests["sum8"].as_str(), digests["sum8_value"].as_u64()), (Some("93"), Some(147)), "{digests}");
    }
}
