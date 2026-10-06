//! Panel for the CRC parameter solver: choose how the document is cut into
//! records and where each record's CRC sits, solve on a background thread,
//! and list every parameter set that fits.

use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui::{self, RichText, Ui};

use crate::app::ViewerApp;
use crate::crc_solver::{self, CrcSolution, CrcWidth, SolveError, SolveReport, SolverOptions, StoredOrder};
use crate::ops;
use crate::theme;

/// How often the panel repaints while a solve runs.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Width of the numeric text fields.
const NUMBER_FIELD_WIDTH: f32 = 80.0;

/// Where the records come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RecordSource {
    /// The selection, one record per raster row.
    #[default]
    SelectionRows,
    /// Fixed-length records from a start offset.
    FixedLength,
}

/// Where the CRC sits in each record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PositionChoice {
    #[default]
    End,
    Offset,
}

/// Which covered ranges to try.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CoverageChoice {
    /// The whole record before the CRC, and with up to four leading bytes skipped.
    #[default]
    TryHeaderSkips,
    /// Only the whole record before the CRC.
    WholeRecord,
}

/// A finished solve and what it was run on.
pub struct SolveOutcome {
    /// Document offset of the first record.
    pub start: usize,
    pub record_len: usize,
    pub records: usize,
    pub result: Result<SolveReport, SolveError>,
}

/// Everything the CRC solver panel keeps between frames.
#[derive(Default)]
pub struct CrcSolverState {
    pub source: RecordSource,
    pub start_text: String,
    pub record_len_text: String,
    /// Empty means "as many as fit".
    pub count_text: String,
    pub width: CrcWidth,
    pub position: PositionChoice,
    pub offset_text: String,
    pub order: StoredOrder,
    pub coverage: CoverageChoice,
    pending: Option<Receiver<SolveOutcome>>,
    pub outcome: Option<SolveOutcome>,
    /// Why the last "Solve" could not start.
    pub input_error: Option<String>,
}

/// Records chosen for a solve: document offset, record length, count.
struct RecordPlan {
    start: usize,
    record_len: usize,
    count: usize,
}

/// Show the CRC solver panel.
pub fn show_crc_solver(state: &mut CrcSolverState, app: &mut ViewerApp, ui: &mut Ui) {
    poll(state);
    ui.label(
        RichText::new("Finds the CRC algorithm behind records that each end with (or contain) a stored CRC: polynomial, init, xorout and reflection, like reveng.")
            .color(theme::TEXT_DIM),
    );
    show_record_inputs(state, app, ui);
    show_crc_inputs(state, ui);
    ui.horizontal(|ui| {
        let busy = state.pending.is_some();
        if ui.add_enabled(!busy, egui::Button::new("Solve")).clicked() {
            start_solve(state, app);
        }
        if busy {
            ui.spinner();
            ui.label(RichText::new("Searching CRC parameters…").color(theme::TEXT_DIM));
            ui.ctx().request_repaint_after(POLL_INTERVAL);
        }
    });
    if let Some(error) = &state.input_error {
        ui.label(RichText::new(error).color(theme::DANGER));
    }
    if let Some(outcome) = &state.outcome {
        ui.separator();
        show_outcome(outcome, ui);
    }
}

fn poll(state: &mut CrcSolverState) {
    let Some(receiver) = &state.pending else { return };
    match receiver.try_recv() {
        Ok(outcome) => {
            state.outcome = Some(outcome);
            state.pending = None;
        }
        Err(mpsc::TryRecvError::Disconnected) => {
            state.pending = None;
            state.input_error = Some("The solver stopped unexpectedly.".to_string());
        }
        Err(mpsc::TryRecvError::Empty) => {}
    }
}

fn show_record_inputs(state: &mut CrcSolverState, app: &ViewerApp, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Records").strong());
        ui.radio_value(&mut state.source, RecordSource::SelectionRows, "Selection, one per row");
        ui.radio_value(&mut state.source, RecordSource::FixedLength, "Fixed length");
    });
    match state.source {
        RecordSource::SelectionRows => {
            let hint = match app.selection() {
                Some((start, len)) => {
                    let stride = app.shape.row_stride().max(1);
                    format!("{} records of {stride} bytes from {start:#x}", len / stride)
                }
                None => "Select the records first; each raster row is one record.".to_string(),
            };
            ui.label(RichText::new(hint).small().color(theme::TEXT_DIM));
        }
        RecordSource::FixedLength => {
            ui.horizontal_wrapped(|ui| {
                number_field(ui, "Start", &mut state.start_text, "0x0");
                number_field(ui, "Length", &mut state.record_len_text, "bytes");
                number_field(ui, "Count", &mut state.count_text, "all");
            });
        }
    }
}

fn show_crc_inputs(state: &mut CrcSolverState, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("CRC").strong());
        ui.selectable_value(&mut state.width, CrcWidth::W8, "8-bit");
        ui.selectable_value(&mut state.width, CrcWidth::W16, "16-bit");
        ui.selectable_value(&mut state.width, CrcWidth::W32, "32-bit");
        ui.separator();
        ui.selectable_value(&mut state.order, StoredOrder::Either, "either order");
        ui.selectable_value(&mut state.order, StoredOrder::Big, "big-endian");
        ui.selectable_value(&mut state.order, StoredOrder::Little, "little-endian");
    });
    ui.horizontal_wrapped(|ui| {
        ui.radio_value(&mut state.position, PositionChoice::End, "Last bytes of each record");
        ui.radio_value(&mut state.position, PositionChoice::Offset, "At offset");
        if state.position == PositionChoice::Offset {
            ui.add(egui::TextEdit::singleline(&mut state.offset_text).desired_width(NUMBER_FIELD_WIDTH).hint_text("in record"));
        }
        ui.separator();
        coverage_checkbox(ui, &mut state.coverage);
    });
}

/// A labelled number field accepting decimal or 0x-prefixed hex.
fn number_field(ui: &mut Ui, label: &str, text: &mut String, hint: &str) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(text).desired_width(NUMBER_FIELD_WIDTH).hint_text(hint));
}

/// A checkbox choosing whether leading header bytes may be outside the CRC.
fn coverage_checkbox(ui: &mut Ui, coverage: &mut CoverageChoice) {
    let mut try_skips = *coverage == CoverageChoice::TryHeaderSkips;
    let label = format!("Also try skipping up to {} header bytes", crc_solver::DEFAULT_MAX_SKIP);
    if ui.checkbox(&mut try_skips, label).changed() {
        *coverage = if try_skips { CoverageChoice::TryHeaderSkips } else { CoverageChoice::WholeRecord };
    }
}

/// The person asks for a solve of the records chosen with the options set:
/// `checksums.solve_crc`, carried out once the panel is drawn.
fn start_solve(state: &mut CrcSolverState, app: &mut ViewerApp) {
    state.input_error = None;
    match solve_params(state, app) {
        Ok(params) => app.perform_later("checksums.solve_crc", params),
        Err(message) => state.input_error = Some(message),
    }
}

/// The parameters of `checksums.solve_crc` for the panel's inputs, or why
/// they cannot be worked out.
fn solve_params(state: &CrcSolverState, app: &ViewerApp) -> Result<serde_json::Value, String> {
    let plan = record_plan(state, app)?;
    let offset = match state.position {
        PositionChoice::End => None,
        PositionChoice::Offset => Some(parse_field(&state.offset_text, "CRC offset", 0)?),
    };
    Ok(serde_json::json!({
        "start": plan.start,
        "record_len": plan.record_len,
        "count": plan.count,
        "width": state.width.bits(),
        "order": crate::api::tools::checksums::CrcOrder::of(state.order),
        "offset": offset,
        "try_skips": state.coverage == CoverageChoice::TryHeaderSkips,
    }))
}

/// Solve the records in `bytes` (from document offset `start`), each
/// `record_len` bytes long.
pub(crate) fn solve_records(bytes: &[u8], start: usize, record_len: usize, options: &SolverOptions) -> SolveOutcome {
    let records = records_from_bytes(bytes, record_len);
    let result = crc_solver::solve(&records, options);
    SolveOutcome { start, record_len, records: records.len(), result }
}

/// Wait for a solve `checksums.solve_crc` started, to show it in the
/// panel; returns where the outcome is sent.
pub(crate) fn await_solve(app: &mut ViewerApp) -> mpsc::Sender<SolveOutcome> {
    let (sender, receiver) = mpsc::channel();
    let state = &mut app.bench.panels.crc_solver;
    state.pending = Some(receiver);
    state.outcome = None;
    state.input_error = None;
    sender
}

/// Work out which bytes to read from the inputs.
fn record_plan(state: &CrcSolverState, app: &ViewerApp) -> Result<RecordPlan, String> {
    let document_len = app.document.len();
    let (start, record_len, available) = match state.source {
        RecordSource::SelectionRows => {
            let (start, len) = app.selection().ok_or("Select the records first (or choose fixed-length records).")?;
            let stride = app.shape.row_stride();
            (start, stride, len)
        }
        RecordSource::FixedLength => {
            let start = parse_field(&state.start_text, "start offset", 0)?;
            let record_len = parse_field(&state.record_len_text, "record length", 0)?;
            (start, record_len, document_len.saturating_sub(start))
        }
    };
    if record_len == 0 {
        return Err("The record length must be at least 1 byte.".to_string());
    }
    if start >= document_len {
        return Err(format!("The start offset {start:#x} is past the end of the file ({document_len:#x})."));
    }
    let fitting = available / record_len;
    let requested = if state.source == RecordSource::FixedLength && !state.count_text.trim().is_empty() {
        parse_field(&state.count_text, "record count", 0)?
    } else {
        fitting
    };
    let count = requested.min(fitting).min(crc_solver::MAX_MESSAGES);
    if count < 2 {
        return Err(format!("Need at least 2 whole records of {record_len} bytes; found {count}."));
    }
    Ok(RecordPlan { start, record_len, count })
}

/// Parse a decimal or hex field; empty gives `default`.
fn parse_field(text: &str, what: &str, default: usize) -> Result<usize, String> {
    if text.trim().is_empty() {
        return Ok(default);
    }
    ops::parse_offset(text).ok_or_else(|| format!("The {what} \"{}\" is not a number (use decimal or 0x hex).", text.trim()))
}

/// Cut `bytes` into whole records of `record_len` bytes, dropping a short tail.
fn records_from_bytes(bytes: &[u8], record_len: usize) -> Vec<&[u8]> {
    if record_len == 0 {
        return Vec::new();
    }
    bytes.chunks_exact(record_len).collect()
}

fn show_outcome(outcome: &SolveOutcome, ui: &mut Ui) {
    ui.label(
        RichText::new(format!("{} records of {} bytes from {:#x}", outcome.records, outcome.record_len, outcome.start))
            .small()
            .color(theme::TEXT_DIM),
    );
    let report = match &outcome.result {
        Ok(report) => report,
        Err(error) => {
            ui.label(RichText::new(error.to_string()).color(theme::DANGER));
            return;
        }
    };
    for note in &report.notes {
        ui.label(RichText::new(note).small().color(theme::TEXT_DIM));
    }
    if report.solutions.is_empty() {
        ui.label(RichText::new("No CRC parameters reproduce every stored value. Check the record boundaries, the CRC position and width.").color(theme::TEXT_DIM));
        return;
    }
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("{} consistent parameter sets", report.solutions.len())).strong());
        if ui.button("Copy all").clicked() {
            let text: Vec<String> = report.solutions.iter().map(CrcSolution::describe).collect();
            ui.ctx().copy_text(text.join("\n"));
        }
    });
    egui::ScrollArea::vertical().id_salt("crc-solver-results").show(ui, |ui| {
        for solution in &report.solutions {
            show_solution(solution, ui);
        }
    });
}

fn show_solution(solution: &CrcSolution, ui: &mut Ui) {
    theme::group(ui, &solution_caption(solution), |ui| {
        ui.vertical(|ui| {
            ui.monospace(solution.params.to_text());
            let order = if solution.big_endian { "big-endian" } else { "little-endian" };
            let mut detail = format!("stored {order}, covers each record after skipping {} bytes", solution.skip);
            if solution.init_ambiguous {
                detail.push_str("; init and xorout trade off for these records");
            }
            ui.label(RichText::new(detail).small().color(theme::TEXT_DIM));
        });
        if ui.button("Copy").clicked() {
            ui.ctx().copy_text(solution.describe());
        }
    });
}

fn solution_caption(solution: &CrcSolution) -> String {
    match &solution.named {
        Some(named) if named.exact => named.name.to_string(),
        Some(named) => format!("Like {} ({})", named.name, named.differences),
        None => "Unnamed CRC".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_cut_whole_and_a_short_tail_is_dropped() {
        let bytes: Vec<u8> = (0..10).collect();
        let records = records_from_bytes(&bytes, 4);
        assert_eq!(records, vec![&[0u8, 1, 2, 3][..], &[4, 5, 6, 7][..]]);
        assert!(records_from_bytes(&bytes, 0).is_empty());
    }

    #[test]
    fn number_fields_accept_hex_and_decimal_and_explain_bad_input() {
        assert_eq!(parse_field("0x10", "start offset", 0), Ok(16));
        assert_eq!(parse_field("  ", "start offset", 7), Ok(7));
        let error = parse_field("ten", "record length", 0).expect_err("not a number");
        assert!(error.contains("record length"));
    }

    /// Records of 12 bytes, each ending with its CRC-16/XMODEM, big-endian.
    fn xmodem_records() -> Vec<u8> {
        let params = crc_solver::CATALOGUE.iter().find(|entry| entry.name == "CRC-16/XMODEM").map(|entry| entry.params).expect("XMODEM in the catalogue");
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
    fn solving_is_a_crc_solver_job_with_every_input_in_its_step_that_fills_the_panel() {
        use serde_json::json;
        let mut app = ViewerApp::new(crate::app::Launch::default());
        app.open_bytes(xmodem_records(), "records.bin".to_string());
        crate::actions::take_performed();
        // Drawn with its state lent out, as the panel is.
        let mut state = std::mem::take(&mut app.bench.panels.crc_solver);
        state.source = RecordSource::FixedLength;
        state.start_text = "0".to_string();
        state.record_len_text = "12".to_string();
        state.coverage = CoverageChoice::WholeRecord;
        start_solve(&mut state, &mut app);
        app.bench.panels.crc_solver = state;
        assert!(crate::actions::take_performed().is_empty(), "carried out once the panel is drawn");
        app.perform_waiting_actions();
        let expected = json!({"start": 0, "record_len": 12, "count": 8, "width": 16, "order": "either", "offset": null, "try_skips": false});
        assert_eq!(crate::actions::take_performed(), [("checksums.solve_crc".to_string(), expected)]);
        let receiver = app.bench.panels.crc_solver.pending.as_ref().expect("the panel waits for the solve");
        let outcome = receiver.recv_timeout(std::time::Duration::from_secs(30)).expect("the solve finishes");
        let report = outcome.result.expect("solved");
        assert!(report.solutions.iter().any(|solution| solution.named.as_ref().is_some_and(|named| named.name == "CRC-16/XMODEM")));
    }

    #[test]
    fn records_that_cannot_be_solved_are_explained_in_the_panel_without_a_step() {
        let mut app = ViewerApp::new(crate::app::Launch::default());
        app.open_bytes(xmodem_records(), "records.bin".to_string());
        crate::actions::take_performed();
        let mut state = CrcSolverState { source: RecordSource::FixedLength, record_len_text: "60".to_string(), ..Default::default() };
        start_solve(&mut state, &mut app);
        app.perform_waiting_actions();
        assert!(crate::actions::take_performed().is_empty());
        assert_eq!(state.input_error.as_deref(), Some("Need at least 2 whole records of 60 bytes; found 1."));
    }
}
