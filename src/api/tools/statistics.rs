//! `statistics.analyse`: the Statistics tool's full measure of a span, run
//! as a job: the `ent` tests, the byte histogram, entropy and
//! compressibility along the span and its most repeated sequences.
//! `analysis.statistics` stays the quick read of the numbers alone.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary};
use crate::analysis_stats::{self, StatsResult};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::Workspace;
use crate::api::{ApiError, Caller};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[method!(
    "statistics.analyse",
    Job,
    caller analyse,
    AnalyseParams,
    JobStartedResult,
    "Start the Statistics tool's measure of a span (at most 64 MiB) as a job: the ent randomness tests with a verdict, the byte histogram, entropy and compressibility along the span and the most repeated byte sequences are job.finished's result, and in the window they fill the Statistics tab."
)];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("statistics.analyse", json!({"start": 0, "len": 256}))]
}

/// Parameters of `statistics.analyse`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyseParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset measured (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes measured, at most 64 MiB; to the end of the document (or 64 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
}

/// A byte sequence found many times in the span.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RepeatedSequence {
    /// The sequence, as hex.
    pub bytes: String,
    /// How many times it occurs.
    pub count: u64,
    /// Document offsets of its first occurrences, up to 16.
    pub offsets: Vec<u64>,
}

/// What `statistics.analyse`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StatisticsAnalysis {
    /// First offset measured.
    pub start: u64,
    /// Bytes measured.
    pub len: u64,
    /// What the data most likely is, such as "Text" or "Encrypted or random".
    pub verdict: String,
    /// Why, in a sentence.
    pub explanation: String,
    /// Shannon entropy in bits per byte, 0 to 8.
    pub entropy: f64,
    pub chi_square: f64,
    pub chi_square_p: f64,
    /// Mean byte value (127.5 for random data).
    pub mean: f64,
    /// Monte Carlo estimate of pi (3.14159… for random data).
    pub monte_carlo_pi: f64,
    /// Serial correlation of consecutive bytes (0 for random data).
    pub serial_correlation: f64,
    pub printable_fraction: f64,
    pub zero_fraction: f64,
    /// Fraction of bytes at or above 0x80.
    pub high_fraction: f64,
    pub distinct_values: u64,
    /// How many times each byte value occurs, 0x00 first.
    pub histogram: Vec<u64>,
    /// Entropy (bits per byte) along the span, as [offset within the span, entropy].
    pub entropy_along: Vec<(u64, f32)>,
    /// Compressed size over size along the span, as [offset within the span, ratio].
    pub compressibility_along: Vec<(u64, f32)>,
    /// The most repeated byte sequences, most frequent first.
    pub repeats: Vec<RepeatedSequence>,
}

impl StatisticsAnalysis {
    /// The tool's result as an API caller collects it.
    pub fn of(result: &StatsResult) -> Self {
        let stats = &result.stats;
        StatisticsAnalysis {
            start: result.start as u64,
            len: result.len as u64,
            verdict: result.verdict.label.to_string(),
            explanation: result.verdict.explanation.clone(),
            entropy: stats.entropy,
            chi_square: stats.chi_square,
            chi_square_p: stats.chi_square_p,
            mean: stats.mean,
            monte_carlo_pi: stats.monte_carlo_pi,
            serial_correlation: stats.serial_correlation,
            printable_fraction: stats.printable_fraction,
            zero_fraction: stats.zero_fraction,
            high_fraction: stats.high_fraction,
            distinct_values: stats.distinct_values as u64,
            histogram: stats.histogram.to_vec(),
            entropy_along: result.entropy.iter().map(|&(offset, entropy)| (offset as u64, entropy)).collect(),
            compressibility_along: result.compressibility.iter().map(|&(offset, ratio)| (offset as u64, ratio)).collect(),
            repeats: result
                .repeats
                .iter()
                .map(|repeat| RepeatedSequence {
                    bytes: crate::ops::to_hex_string(&repeat.bytes),
                    count: repeat.count as u64,
                    offsets: repeat.first_offsets.iter().map(|&offset| (result.start + offset) as u64).collect(),
                })
                .collect(),
        }
    }
}

/// `statistics.analyse`: read the span now and measure it on a thread.
pub fn analyse(workspace: &mut dyn Workspace, caller: &Caller, params: AnalyseParams) -> Result<JobStartedResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, analysis_stats::SCAN_LIMIT, "the span measured")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(analysis_stats::await_statistics);
    let start = span.start;
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("statistics", "Byte statistics"),
        &span,
        deliver,
        move |_| analysis_stats::measure(&bytes, start),
        |result| Summary::of(result.verdict.label, StatisticsAnalysis::of(result)),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn measuring_text_judges_it_text_and_lists_its_repeats() {
        let mut workspace = workspace_with("notes.txt", &b"The quick brown fox jumps over the lazy dog. ".repeat(200));
        let status = run_job(&mut workspace, "statistics.analyse", json!({"start": 0, "len": 4000}));
        assert_eq!(status["state"], "finished", "{status}");
        let result = &status["result"];
        assert_eq!((result["verdict"].as_str(), result["len"].as_u64()), (Some("Text"), Some(4000)));
        assert_eq!(result["histogram"].as_array().unwrap().len(), 256);
        assert_eq!(result["histogram"][b' ' as usize].as_u64(), Some(800), "every space counted");
        assert!(!result["repeats"].as_array().unwrap().is_empty());
        assert_eq!(status["producer"], "panel");
    }

    #[test]
    fn a_span_past_the_end_or_over_the_limit_is_refused() {
        let mut workspace = workspace_with("a.bin", &[0u8; 64]);
        assert_eq!(call(&mut workspace, "statistics.analyse", json!({"start": 65})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "statistics.analyse", json!({"len": 65})).unwrap_err().code, ErrorCode::OutOfRange);
        assert_eq!(call(&mut workspace, "statistics.analyse", json!({"width": 2})).unwrap_err().code, ErrorCode::InvalidParams);
    }
}
