//! `dotplot.compute`: the Dot plot's comparison of every block of a span
//! with every other.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::tool_jobs::{self, Summary};
use crate::api::jobs::JobStartedResult;
use crate::api::workspace::Workspace;
use crate::api::{ApiError, Caller};
use crate::dotplot::{DotPlot, SimilarityMode};

/// This module's methods, in the order `api.describe` lists them within
/// their namespace. A new method is added here, and only here.
pub(super) const METHODS: &[crate::api::Method] = &[method!(
    "dotplot.compute",
    Job,
    caller compute,
    DotPlotParams,
    JobStartedResult,
    "Start comparing every block of a span (at most 64 MiB) with every other, by shared 6-byte substrings or by byte histograms, as a job: the grid of similarities (repeated content shows as lines parallel to the diagonal) is job.finished's result, and in the window it fills the Dot plot."
)];

/// An example call of each of [`METHODS`], run in order on a fresh
/// document by the API's tests, whose results must fit the result schema.
#[cfg(test)]
pub(super) fn examples() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    vec![("dotplot.compute", json!({"start": 0, "mode": "histogram"}))]
}

/// Most bytes plotted.
pub const DOT_PLOT_LIMIT: usize = 64 * 1024 * 1024;

/// How two blocks are compared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DotPlotMode {
    /// Shared 6-byte substrings.
    #[default]
    KGrams,
    /// Byte-value histograms.
    Histogram,
}

impl DotPlotMode {
    pub fn of(mode: SimilarityMode) -> Self {
        match mode {
            SimilarityMode::KGrams => DotPlotMode::KGrams,
            SimilarityMode::Histogram => DotPlotMode::Histogram,
        }
    }

    fn similarity(self) -> SimilarityMode {
        match self {
            DotPlotMode::KGrams => SimilarityMode::KGrams,
            DotPlotMode::Histogram => SimilarityMode::Histogram,
        }
    }
}

/// Parameters of `dotplot.compute`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DotPlotParams {
    /// Document id, path or "current" (the default).
    #[serde(default)]
    pub doc: Option<String>,
    /// First offset plotted (0 by default).
    #[serde(default)]
    pub start: u64,
    /// Bytes plotted, at most 64 MiB; to the end of the document (or 64 MiB) when omitted.
    #[serde(default)]
    pub len: Option<u64>,
    /// How blocks are compared: "k_grams" (the default) or "histogram".
    #[serde(default)]
    pub mode: DotPlotMode,
}

/// What `dotplot.compute`'s job finishes with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DotPlotResult {
    pub start: u64,
    pub len: u64,
    pub mode: DotPlotMode,
    /// Blocks along each side; none when the span was too short.
    pub cells: usize,
    /// Bytes per block.
    pub block_size: usize,
    /// Row by row, cells × cells similarities from 0 to 1.
    pub values: Vec<f32>,
}

impl DotPlotResult {
    fn of(plot: &DotPlot) -> Self {
        DotPlotResult { start: plot.start as u64, len: plot.len as u64, mode: DotPlotMode::of(plot.mode), cells: plot.cells, block_size: plot.block_size, values: plot.values.clone() }
    }
}

/// `dotplot.compute`: read the span now and compare its blocks on a thread.
pub fn compute(workspace: &mut dyn Workspace, caller: &Caller, params: DotPlotParams) -> Result<JobStartedResult, ApiError> {
    let span = tool_jobs::span(workspace, params.doc.as_deref(), params.start, params.len, DOT_PLOT_LIMIT, "the span plotted")?;
    let bytes = tool_jobs::read(workspace, &span)?;
    let deliver = tool_jobs::window_showing(workspace, &span.doc).map(crate::panel_dotplot::await_plot);
    let (start, mode) = (span.start, params.mode.similarity());
    Ok(tool_jobs::spawn(
        workspace,
        &caller.producer(),
        ("dot-plot", "Dot plot"),
        &span,
        deliver,
        move |_| crate::dotplot::compute(&bytes, start, mode),
        |plot| Summary::of(format!("{} × {} blocks", plot.cells, plot.cells), DotPlotResult::of(plot)),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tool_jobs::test_support::run_job;
    use crate::api::ErrorCode;
    use crate::api::test_support::{call, workspace_with};

    #[test]
    fn a_repeated_half_is_alike_off_the_diagonal() {
        let half: Vec<u8> = (0..8192u32).map(|index| (index.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        let mut workspace = workspace_with("twice.bin", &[half.clone(), half].concat());
        let status = run_job(&mut workspace, "dotplot.compute", json!({}));
        assert_eq!(status["state"], "finished", "{status}");
        let result = &status["result"];
        let cells = result["cells"].as_u64().unwrap() as usize;
        assert!(cells >= 2);
        let values = result["values"].as_array().unwrap();
        assert_eq!(values.len(), cells * cells);
        let off_diagonal = values[cells / 2].as_f64().unwrap();
        assert!(off_diagonal > 0.9, "the first block is like the first of the second half: {off_diagonal}");
        assert_eq!(call(&mut workspace, "dotplot.compute", json!({"mode": "pixels"})).unwrap_err().code, ErrorCode::InvalidParams);
    }
}
