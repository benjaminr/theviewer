//! Analysis without a window: `theviewer --report FILE` prints what the
//! Report tab would show, and `--json` prints the same as JSON for scripts,
//! CI jobs and batch triage.

use std::collections::HashSet;
use std::path::Path;

use schemars::JsonSchema;
use serde::Serialize;

use crate::analysis;
use crate::document::Document;
use crate::explain;
use crate::plugin::{Registry, ScanContext};
use crate::stats;
use crate::workbench::ANALYSIS_READ_LIMIT;

/// Findings below this confidence are chance matches and left out.
const MIN_FINDING_CONFIDENCE: f32 = 0.5;
/// Bytes from the start of the file searched for a record width.
const PERIOD_SCAN_BYTES: usize = 192 * 1024;
/// Longest record width considered.
const MAX_PERIOD: usize = 4096;
/// Record widths reported, best first.
const PERIODS_REPORTED: usize = 5;
/// Most findings reported, so huge files still give readable output.
const MAX_FINDINGS: usize = 2000;

/// Everything the headless report says about a file.
#[derive(Debug, Serialize, JsonSchema)]
pub struct FileReport {
    /// The file's path or name.
    pub file: String,
    /// Length in bytes.
    pub size: usize,
    /// Bytes actually analysed (large files are read up to a limit).
    pub analysed: usize,
    pub entropy_bits_per_byte: f64,
    /// One line on what the file is.
    pub headline: String,
    /// What the report says about the file, each about a span of it.
    pub sentences: Vec<ReportSentence>,
    /// The file's regions, from start to end.
    pub regions: Vec<ReportRegion>,
    /// Likely record widths, best first.
    pub record_widths: Vec<RecordWidth>,
    /// Confident findings in file order.
    pub findings: Vec<ReportFinding>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ReportSentence {
    pub text: String,
    pub start: usize,
    pub len: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ReportRegion {
    pub start: usize,
    pub len: usize,
    pub kind: String,
    pub label: String,
    pub detail: String,
    /// Identified by a parser or verified decoder, rather than a statistical guess.
    pub confident: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct RecordWidth {
    pub bytes: usize,
    /// Similarity at that width, 0 to 1.
    pub score: f32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ReportFinding {
    pub start: usize,
    pub len: usize,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub confidence: f32,
}

/// Analyse the file at `path` with `registry`, as the Report tab does.
pub fn analyse(path: &Path, registry: &Registry) -> Result<FileReport, String> {
    let mut document = Document::open(path).map_err(|error| format!("could not open {}: {error:#}", path.display()))?;
    let size = document.len();
    let bytes = document.read_range(0, ANALYSIS_READ_LIMIT);
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    Ok(analyse_bytes(&bytes, &path.display().to_string(), &name, size, registry))
}

/// Analyse bytes already in memory: the first `bytes.len()` of a file called
/// `name` (shown as `file`) that is `size` bytes long.
pub fn analyse_bytes(bytes: &[u8], file: &str, name: &str, size: usize, registry: &Registry) -> FileReport {
    let regions = explain::map_file(bytes, registry);
    let report = explain::explain(bytes, name, &regions);
    FileReport {
        file: file.to_string(),
        size,
        analysed: bytes.len(),
        entropy_bits_per_byte: stats::byte_stats(bytes).entropy,
        headline: report.headline,
        sentences: report
            .sentences
            .into_iter()
            .map(|sentence| ReportSentence { text: sentence.text, start: sentence.start, len: sentence.len })
            .collect(),
        regions: regions
            .into_iter()
            .map(|region| ReportRegion {
                start: region.start,
                len: region.len,
                kind: region.kind.label().to_string(),
                label: region.label,
                detail: region.detail,
                confident: region.confident,
            })
            .collect(),
        record_widths: record_widths(bytes),
        findings: confident_findings(bytes, registry),
    }
}

/// The likeliest record widths, from the start of the data.
fn record_widths(bytes: &[u8]) -> Vec<RecordWidth> {
    let window = &bytes[..bytes.len().min(PERIOD_SCAN_BYTES)];
    analysis::scan_periods(window, 0, MAX_PERIOD)
        .candidates
        .into_iter()
        .filter(|candidate| candidate.multiple_of.is_none())
        .take(PERIODS_REPORTED)
        .map(|candidate| RecordWidth { bytes: candidate.period, score: candidate.score })
        .collect()
}

/// Every finding confident enough to report, in file order, without repeats
/// from overlapping scan windows.
fn confident_findings(bytes: &[u8], registry: &Registry) -> Vec<ReportFinding> {
    let mut seen = HashSet::new();
    let mut findings = Vec::new();
    for (start, end) in explain::scan_windows(bytes.len()) {
        let context = ScanContext { base: start, document_len: bytes.len(), strides: Vec::new() };
        for finding in registry.scan(&bytes[start..end], &context) {
            if finding.confidence < MIN_FINDING_CONFIDENCE || !seen.insert((finding.id.clone(), finding.start)) {
                continue;
            }
            findings.push(ReportFinding {
                start: finding.start,
                len: finding.len,
                category: finding.category.label().to_string(),
                title: finding.title,
                detail: finding.detail,
                confidence: finding.confidence,
            });
        }
    }
    findings.sort_by_key(|finding| (finding.start, finding.len));
    findings.truncate(MAX_FINDINGS);
    findings
}

/// The report as JSON.
pub fn render_json(report: &FileReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|error| format!("{{\"error\": \"{error}\"}}"))
}

/// The report as plain text, for reading in a terminal.
pub fn render_text(report: &FileReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}\n", report.file));
    out.push_str(&format!("{}\n\n", report.headline));
    let analysed = if report.analysed < report.size {
        format!(" (first {} bytes analysed)", report.analysed)
    } else {
        String::new()
    };
    out.push_str(&format!(
        "{} bytes{analysed}, entropy {:.2} bits per byte\n\n",
        report.size, report.entropy_bits_per_byte
    ));
    for sentence in &report.sentences {
        out.push_str(&format!("- {}\n", sentence.text));
    }
    if !report.record_widths.is_empty() {
        let widths: Vec<String> = report.record_widths.iter().map(|w| format!("{} B ({:.2})", w.bytes, w.score)).collect();
        out.push_str(&format!("\nLikely record widths: {}\n", widths.join(", ")));
    }
    if !report.findings.is_empty() {
        out.push_str(&format!("\nFindings ({}):\n", report.findings.len()));
        for finding in &report.findings {
            out.push_str(&format!(
                "  {:#010x}  {:>8} B  {:<18} {}{}\n",
                finding.start,
                finding.len,
                finding.category,
                finding.title,
                if finding.detail.is_empty() { String::new() } else { format!(" · {}", finding.detail) },
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::{self, Codec};

    fn sample_file(name: &str) -> std::path::PathBuf {
        let mut bytes = b"HEADER v1\0".to_vec();
        for i in 0..400u32 {
            bytes.extend_from_slice(&i.to_le_bytes());
            bytes.extend_from_slice(b"RECORD--");
            bytes.extend_from_slice(&[0, 0, 0, 0]);
        }
        bytes.extend_from_slice(&compress::compress(Codec::Gzip, &b"log line ".repeat(500)).unwrap());
        let path = std::env::temp_dir().join(format!("theviewer-headless-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn a_report_names_the_records_and_the_compressed_stream() {
        let path = sample_file("report.bin");
        let report = analyse(&path, &crate::app::build_registry()).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(report.record_widths.iter().any(|w| w.bytes == 16), "{:?}", report.record_widths);
        assert!(report.findings.iter().any(|f| f.category == "Compressed streams"), "{:?}", report.findings);
        assert!(report.findings.iter().all(|f| f.confidence >= MIN_FINDING_CONFIDENCE));
        let json: serde_json::Value = serde_json::from_str(&render_json(&report)).expect("valid JSON");
        assert_eq!(json["size"], report.size);
        assert!(render_text(&report).contains("Likely record widths: 16 B"));
    }

    #[test]
    fn a_missing_file_is_a_clear_error() {
        let error = analyse(Path::new("/no/such/file.bin"), &crate::app::build_registry()).unwrap_err();
        assert!(error.contains("could not open /no/such/file.bin"), "{error}");
    }
}
