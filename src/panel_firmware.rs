//! Dock panel for firmware analysis: which processor the code is for, where
//! the image is loaded, and ARM Cortex-M vector tables.
//!
//! Each section runs its analysis on a background thread and shows the
//! result once it arrives; results are clickable and jump to the bytes they
//! describe.

use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui::{self, RichText, Sense, Ui};

use crate::analysis_tabs::ArchChoice;
use crate::app::ViewerApp;
use crate::base_address::{self, BaseSearchOptions, BaseSearchReport, ByteOrder, PointerWidth};
use crate::cortex_m::VectorTable;
use crate::cpu_detect::CpuReport;
use crate::disasm::Arch;
use crate::theme;

/// Largest range read for any of the analyses.
const SCAN_LIMIT: usize = crate::api::tools::firmware::FIRMWARE_LIMIT;
/// How often to look for a finished job while one is running.
const PENDING_REPAINT: Duration = Duration::from_millis(100);
/// Largest step offered for the load address search.
const MAX_STEP: u64 = crate::api::tools::firmware::MOST_STEP;
/// Range of string lengths offered for the load address search.
const MIN_STRING_LEN_RANGE: std::ops::RangeInclusive<usize> = crate::api::tools::firmware::MIN_STRING_LENS;
/// Width of the confidence bars.
const CONFIDENCE_BAR_WIDTH: f32 = 90.0;
/// Height of the scrolling vector table listing.
const VECTOR_LIST_HEIGHT: f32 = 220.0;

/// A background analysis and its last result, tagged with the document
/// version it was computed for so stale results can be flagged.
struct Job<T> {
    pending: Option<Receiver<T>>,
    result: Option<(u64, T)>,
    pending_version: u64,
}

impl<T> Default for Job<T> {
    fn default() -> Self {
        Job { pending: None, result: None, pending_version: 0 }
    }
}

impl<T: Send + 'static> Job<T> {
    /// Wait for a result about document version `version`; returns where it is sent.
    fn awaited(&mut self, version: u64) -> mpsc::Sender<T> {
        let (sender, receiver) = mpsc::channel();
        self.pending = Some(receiver);
        self.pending_version = version;
        sender
    }

    /// Collect a finished result, if any.
    fn poll(&mut self) {
        if let Some(receiver) = &self.pending
            && let Ok(result) = receiver.try_recv()
        {
            self.result = Some((self.pending_version, result));
            self.pending = None;
        }
    }

    fn is_pending(&self) -> bool {
        self.pending.is_some()
    }
}

/// State of the firmware panel.
#[derive(Default)]
pub struct FirmwareState {
    processor: Job<CpuReport>,
    load_address: Job<BaseSearchReport>,
    vector_tables: Job<Vec<VectorTable>>,
    /// Options for the load address search.
    pub base_options: BaseSearchOptions,
}

impl FirmwareState {
    /// Forget results tied to the previous document, keeping the options.
    pub fn document_changed(&mut self) {
        *self = FirmwareState { base_options: self.base_options.clone(), ..Default::default() };
    }

    fn any_pending(&self) -> bool {
        self.processor.is_pending() || self.load_address.is_pending() || self.vector_tables.is_pending()
    }
}

/// Something the user asked for, applied after the UI is laid out.
enum Action {
    Jump(usize),
    Disassemble(Arch),
}

pub fn show_firmware(state: &mut FirmwareState, app: &mut ViewerApp, ui: &mut Ui) {
    state.processor.poll();
    state.load_address.poll();
    state.vector_tables.poll();
    if state.any_pending() {
        ui.ctx().request_repaint_after(PENDING_REPAINT);
    }

    let mut actions = Vec::new();
    egui::ScrollArea::vertical().id_salt("firmware-panel").show(ui, |ui| {
        egui::CollapsingHeader::new(RichText::new("Processor").strong()).id_salt("firmware-processor").default_open(true).show(ui, |ui| {
            show_processor(state, app, ui, &mut actions);
        });
        egui::CollapsingHeader::new(RichText::new("Load address").strong()).id_salt("firmware-load-address").default_open(true).show(ui, |ui| {
            show_load_address(state, app, ui, &mut actions);
        });
        egui::CollapsingHeader::new(RichText::new("Vector table").strong()).id_salt("firmware-vector-table").default_open(true).show(ui, |ui| {
            show_vector_tables(state, app, ui, &mut actions);
        });
    });

    for action in actions {
        match action {
            Action::Jump(offset) => app.jump_found(offset),
            Action::Disassemble(arch) => {
                if crate::analysis_tabs::set_disassembly_arch(app, ArchChoice::Fixed(arch)) {
                    app.status = format!("Disassembly set to {}", arch.label());
                }
            }
        }
    }
}

/// Wait for a ranking `firmware.identify` started; returns where it is sent.
pub(crate) fn await_processor(app: &mut ViewerApp) -> mpsc::Sender<CpuReport> {
    let version = app.document.version();
    app.bench.panels.firmware.processor.awaited(version)
}

/// Wait for a search `firmware.find_load_address` started; returns where it is sent.
pub(crate) fn await_load_address(app: &mut ViewerApp) -> mpsc::Sender<BaseSearchReport> {
    let version = app.document.version();
    app.bench.panels.firmware.load_address.awaited(version)
}

/// Wait for a search `firmware.vector_tables` started; returns where it is sent.
pub(crate) fn await_vector_tables(app: &mut ViewerApp) -> mpsc::Sender<Vec<VectorTable>> {
    let version = app.document.version();
    app.bench.panels.firmware.vector_tables.awaited(version)
}

/// The selection, else the whole file, capped at [`SCAN_LIMIT`].
fn selection_or_file(app: &ViewerApp) -> (usize, usize, &'static str) {
    match app.selection() {
        Some((start, len)) => (start, len.min(SCAN_LIMIT), "selection"),
        None => (0, app.document.len().min(SCAN_LIMIT), "whole file"),
    }
}

fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).small().color(theme::TEXT_DIM)
}

/// A note shown when a result was computed for an earlier version of the document.
fn stale_note(ui: &mut Ui, result_version: u64, app: &ViewerApp) {
    if result_version != app.document.version() {
        ui.label(dim("The document has changed since this ran; run it again for current results."));
    }
}

/// A monospace offset that reports a click.
fn offset_link(ui: &mut Ui, offset: usize) -> bool {
    ui.add(egui::Label::new(RichText::new(format!("{offset:#010x}")).monospace().color(theme::ACCENT)).sense(Sense::click()))
        .on_hover_text("Jump to this offset")
        .clicked()
}

// ---------------------------------------------------------------------------
// Processor
// ---------------------------------------------------------------------------

/// The person identifies the processor of the selection, else the whole
/// file: `firmware.identify`, carried out once the panel is drawn.
fn start_processor(app: &mut ViewerApp) {
    let (start, len, _) = selection_or_file(app);
    app.perform_later("firmware.identify", serde_json::json!({ "start": start, "len": len }));
}

fn show_processor(state: &mut FirmwareState, app: &mut ViewerApp, ui: &mut Ui, actions: &mut Vec<Action>) {
    let (_, len, what) = selection_or_file(app);
    ui.horizontal_wrapped(|ui| {
        let button = ui.add_enabled(!state.processor.is_pending(), egui::Button::new(format!("Identify processor in {what} ({})", crate::compress::human_bytes(len))));
        if button.clicked() {
            start_processor(app);
        }
        if state.processor.is_pending() {
            ui.spinner();
        }
    });
    let Some((version, report)) = &state.processor.result else {
        ui.label(dim(
            "Disassembles samples of headerless code as every supported architecture and ranks them by typical instructions, prologue and return idioms, plausible branch targets and instruction mix.",
        ));
        return;
    };
    stale_note(ui, *version, app);
    let summary_colour = if report.looks_like_data { theme::TEXT_DIM } else { theme::ACCENT };
    ui.label(RichText::new(&report.summary).color(summary_colour));
    if report.windows > 0 {
        ui.label(dim(format!("{} windows, {} sampled per architecture", report.windows, crate::compress::human_bytes(report.sampled_bytes))));
    }
    egui::Grid::new("firmware-processor-grid").num_columns(4).spacing([10.0, 4.0]).striped(true).show(ui, |ui| {
        for candidate in &report.candidates {
            ui.label(RichText::new(candidate.arch.label()).strong());
            ui.add(egui::ProgressBar::new(candidate.confidence).desired_width(CONFIDENCE_BAR_WIDTH).text(format!("{:.0}%", candidate.confidence * 100.0)));
            ui.horizontal(|ui| {
                if ui.small_button(format!("Disassemble as {}", candidate.arch.label())).clicked() {
                    actions.push(Action::Disassemble(candidate.arch));
                }
                if ui.small_button("Show code").on_hover_text("Jump to the sampled window that looked most like this architecture").clicked() {
                    actions.push(Action::Jump(candidate.best_window_offset));
                }
            });
            ui.label(dim(&candidate.reason));
            ui.end_row();
        }
    });
}

// ---------------------------------------------------------------------------
// Load address
// ---------------------------------------------------------------------------

/// The person searches for the load address of the whole file (the base is
/// the address of offset 0) with the options set: `firmware.find_load_address`.
fn start_load_address(state: &FirmwareState, app: &mut ViewerApp) {
    let options = &state.base_options;
    let params = serde_json::json!({
        "width": options.width.bytes() * 8,
        "byte_order": options.byte_order.map(crate::api::tools::firmware::PointerOrder::of),
        "step": options.step,
        "min_string_len": options.min_string_len,
    });
    app.perform_later("firmware.find_load_address", params);
}

fn show_load_address(state: &mut FirmwareState, app: &mut ViewerApp, ui: &mut Ui, actions: &mut Vec<Action>) {
    let len = app.document.len().min(SCAN_LIMIT);
    let options = &mut state.base_options;
    ui.horizontal_wrapped(|ui| {
        egui::ComboBox::from_id_salt("firmware-pointer-width").selected_text(options.width.label()).show_ui(ui, |ui| {
            ui.selectable_value(&mut options.width, PointerWidth::Bits32, PointerWidth::Bits32.label());
            ui.selectable_value(&mut options.width, PointerWidth::Bits64, PointerWidth::Bits64.label());
        });
        let order_label = options.byte_order.map(ByteOrder::label).unwrap_or("both byte orders");
        egui::ComboBox::from_id_salt("firmware-byte-order").selected_text(order_label).show_ui(ui, |ui| {
            ui.selectable_value(&mut options.byte_order, None, "both byte orders");
            for order in ByteOrder::ALL {
                ui.selectable_value(&mut options.byte_order, Some(order), order.label());
            }
        });
        ui.label("step");
        ui.add(egui::DragValue::new(&mut options.step).range(base_address::MIN_STEP..=MAX_STEP).hexadecimal(1, false, false).prefix("0x"));
        ui.label("strings of at least");
        ui.add(egui::DragValue::new(&mut options.min_string_len).range(MIN_STRING_LEN_RANGE).suffix(" chars"));
    });
    ui.horizontal(|ui| {
        let button = ui.add_enabled(!state.load_address.is_pending(), egui::Button::new(format!("Find load address of the whole file ({})", crate::compress::human_bytes(len))));
        if button.clicked() {
            start_load_address(state, app);
        }
        if state.load_address.is_pending() {
            ui.spinner();
        }
    });
    let Some((version, report)) = &state.load_address.result else {
        ui.label(dim(
            "Finds the base address that makes the most stored pointers land on the start of a string, as rbasefind does. Candidate bases are multiples of the step.",
        ));
        return;
    };
    stale_note(ui, *version, app);
    let summary_colour = if report.is_convincing() { theme::ACCENT } else { theme::TEXT_DIM };
    ui.label(RichText::new(&report.summary).color(summary_colour));
    ui.label(dim(format!("{} strings and {} pointer-like values considered", report.strings_considered, report.pointers_considered)));
    for candidate in &report.candidates {
        ui.horizontal_wrapped(|ui| {
            ui.monospace(RichText::new(format!("{:#010x}", candidate.base)).color(theme::ACCENT));
            ui.label(format!(
                "{} strings, {} pointers, {} {}",
                candidate.matched_strings,
                candidate.references,
                candidate.width.label(),
                candidate.byte_order.label()
            ));
        });
        ui.horizontal_wrapped(|ui| {
            ui.add_space(ui.spacing().indent);
            for example in &candidate.examples {
                let pointer = ui.small_button(format!("{:#x}", example.pointer_offset)).on_hover_text("Jump to the stored pointer");
                if pointer.clicked() {
                    actions.push(Action::Jump(example.pointer_offset));
                }
                ui.label(dim("→"));
                let string = ui.small_button(format!("{:#x}", example.string_offset)).on_hover_text("Jump to the string it points at");
                if string.clicked() {
                    actions.push(Action::Jump(example.string_offset));
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Vector table
// ---------------------------------------------------------------------------

/// The person looks for vector tables in the whole file: `firmware.vector_tables`.
fn start_vector_tables(app: &mut ViewerApp) {
    let len = app.document.len().min(SCAN_LIMIT);
    app.perform_later("firmware.vector_tables", serde_json::json!({ "start": 0, "len": len }));
}

fn show_vector_tables(state: &mut FirmwareState, app: &mut ViewerApp, ui: &mut Ui, actions: &mut Vec<Action>) {
    let len = app.document.len().min(SCAN_LIMIT);
    ui.horizontal(|ui| {
        let button = ui.add_enabled(!state.vector_tables.is_pending(), egui::Button::new(format!("Find Cortex-M vector tables ({})", crate::compress::human_bytes(len))));
        if button.clicked() {
            start_vector_tables(app);
        }
        if state.vector_tables.is_pending() {
            ui.spinner();
        }
    });
    let Some((version, tables)) = &state.vector_tables.result else {
        ui.label(dim(
            "Looks on 128-byte boundaries for an initial stack pointer in SRAM followed by Thumb reset and exception handlers, and guesses the flash base from the reset handler.",
        ));
        return;
    };
    stale_note(ui, *version, app);
    if tables.is_empty() {
        ui.label(dim("No Cortex-M vector table found."));
        return;
    }
    let document_len = app.document.len();
    for (table_index, table) in tables.iter().enumerate() {
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Table at").strong());
            if offset_link(ui, table.offset) {
                actions.push(Action::Jump(table.offset));
            }
            ui.label(format!(
                "stack pointer {:#010x}, reset {:#010x}, {} handlers, flash base {:#x}",
                table.initial_stack_pointer, table.reset_handler, table.valid_vectors, table.inferred_flash_base
            ));
            if !table.base_consistent {
                ui.label(RichText::new("(handlers fall outside the file under this base)").small().color(theme::DANGER));
            }
        });
        egui::ScrollArea::vertical().id_salt(("firmware-vectors", table_index)).max_height(VECTOR_LIST_HEIGHT).show(ui, |ui| {
            egui::Grid::new(("firmware-vector-grid", table_index)).num_columns(3).spacing([12.0, 2.0]).striped(true).show(ui, |ui| {
                for entry in &table.entries {
                    if offset_link(ui, entry.offset) {
                        actions.push(Action::Jump(entry.offset));
                    }
                    ui.label(&entry.name);
                    ui.horizontal(|ui| {
                        let colour = if entry.value == 0 { theme::TEXT_DIM } else { theme::TEXT };
                        ui.monospace(RichText::new(format!("{:#010x}", entry.value)).color(colour));
                        if let Some(handler) = table.handler_offset(entry, document_len)
                            && ui.small_button("Go to handler").on_hover_text(format!("File offset {handler:#x} under the inferred base")).clicked()
                        {
                            actions.push(Action::Jump(handler));
                        }
                    });
                    ui.end_row();
                }
            });
        });
    }
}

/// A tiny Cortex-M image: a vector table at 0x0800_0000, Thumb code after
/// it, and strings referenced by a pointer table.
#[cfg(test)]
pub(crate) fn cortex_m_image() -> Vec<u8> {
    let mut words: Vec<u32> = vec![0x2000_2000, 0x0800_0101, 0x0800_0103, 0x0800_0105, 0x0800_0107, 0x0800_0109, 0x0800_010B];
    words.extend([0, 0, 0, 0, 0x0800_010D, 0, 0, 0x0800_010F, 0x0800_0111]);
    let mut image: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let thumb: [u16; 6] = [0xB5F0, 0x4604, 0x2000, 0x6821, 0x1840, 0xBDF0];
    while image.len() < 0x2000 {
        image.extend(thumb.iter().flat_map(|halfword| halfword.to_le_bytes()));
        image.extend(0x4770u16.to_le_bytes());
    }
    let mut pointers = Vec::new();
    for index in 0..16 {
        pointers.push(0x0800_0000 + image.len() as u32);
        image.extend(format!("diagnostic message {index}\0").as_bytes());
    }
    image.extend(pointers.iter().flat_map(|pointer| pointer.to_le_bytes()));
    image
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::app::Launch;

    /// Longest a background job may take in these tests.
    const JOB_TIMEOUT: Duration = Duration::from_secs(10);

    /// Lay the panel out until no job is pending, or fail after [`JOB_TIMEOUT`].
    fn run_until_idle(state: &mut FirmwareState, app: &mut ViewerApp, context: &egui::Context) {
        let started = Instant::now();
        loop {
            let mut output = context.run_ui(egui::RawInput::default(), |ui| show_firmware(state, app, ui));
            // No renderer consumes the font atlas here.
            output.textures_delta.clear();
            if !state.any_pending() {
                return;
            }
            assert!(started.elapsed() < JOB_TIMEOUT, "firmware jobs did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn panel_runs_all_three_analyses_as_jobs_of_the_person_s_and_shows_results() {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(cortex_m_image(), "firmware.bin".to_string());
        crate::actions::take_performed();
        let context = egui::Context::default();
        start_processor(&mut app);
        start_load_address(&FirmwareState::default(), &mut app);
        start_vector_tables(&mut app);
        app.perform_waiting_actions();
        let len = cortex_m_image().len();
        assert_eq!(
            crate::actions::take_performed(),
            [
                ("firmware.identify".to_string(), serde_json::json!({"start": 0, "len": len})),
                ("firmware.find_load_address".to_string(), serde_json::json!({"width": 32, "byte_order": null, "step": base_address::DEFAULT_STEP, "min_string_len": base_address::DEFAULT_MIN_STRING_LEN})),
                ("firmware.vector_tables".to_string(), serde_json::json!({"start": 0, "len": len})),
            ]
        );
        let mut state = std::mem::take(&mut app.bench.panels.firmware);
        assert!(state.any_pending());
        run_until_idle(&mut state, &mut app, &context);

        let (_, processor) = state.processor.result.as_ref().expect("processor result");
        assert_eq!(processor.best().map(|candidate| candidate.arch), Some(Arch::Thumb), "{}", processor.summary);
        let (_, load_address) = state.load_address.result.as_ref().expect("load address result");
        assert_eq!(load_address.best().map(|candidate| candidate.base), Some(0x0800_0000), "{}", load_address.summary);
        let (_, tables) = state.vector_tables.result.as_ref().expect("vector table result");
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].initial_stack_pointer, 0x2000_2000);
    }

    #[test]
    fn document_change_forgets_results_but_keeps_options() {
        let mut state = FirmwareState::default();
        state.base_options.step = 0x100;
        state.vector_tables.result = Some((1, Vec::new()));
        state.document_changed();
        assert!(state.vector_tables.result.is_none());
        assert_eq!(state.base_options.step, 0x100);
    }
}
