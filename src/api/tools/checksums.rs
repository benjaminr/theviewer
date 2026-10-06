//! `checksums.*`: the Checksums tool's digests of a span and its search for
//! a checksum stored in the data, and the CRC solver's search for the CRC
//! parameters behind records that each carry one.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::Workspace;
use crate::api::{ApiError, Caller};
use crate::checksums::ChecksumMatch;
use crate::crc_solver::{self, CrcPosition, CrcSolution, CrcWidth, SolverOptions, StoredOrder};
use crate::panel_crc_solver::SolveOutcome;

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[
    method!("checksums.digests", Read, digests, DigestsParams, DigestsResult, "The digests of a span (at most 64 MiB): CRC-32, Adler-32, MD5, SHA-1, SHA-256, the 8- and 16-bit sums and the XOR of every byte."),
    method!("checksums.find_stored", Read, find_stored, FindStoredParams, StoredChecksums, "Find a CRC, Adler or sum stored in a span (at most 64 MiB) that covers part of it, testing header and trailer fields, and the fields at the boundaries given, against the bytes before, after and around them."),
    method!("checksums.solve_crc", Job, caller solve_crc, SolveCrcParams, JobStartedResult, "Start the CRC solver on records of equal length that each carry a stored CRC, as a job: every polynomial, init, xorout and reflection that reproduces all the stored values (like reveng), with the closest catalogue algorithm, is job.finished's result, and in the window it fills the CRC solver."),
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
    pub start: u64,
    /// Bytes in each record, CRC included.
    pub record_len: usize,
    /// Records, at least 2; the first 256 are solved.
    pub count: usize,
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
}
