//! The Learn panel: learn a signature and a template from sample files, and
//! find files that resemble this one with ssdeep fuzzy hashes and shared
//! fragments.
//!
//! The current document is always the first sample and the file every other
//! file is compared with. Files are chosen with non-blocking dialogs and read
//! on background threads; learning, hashing and fragment matching run on
//! background threads too, and the panel collects each result on a later
//! frame.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText, Ui};

use crate::app::ViewerApp;
use crate::compress::human_bytes;
use crate::fuzzy::{self, FuzzyHash, SharedFragment};
use crate::api::tools::learn::{MAX_FILE_BYTES, run_comparison, run_fragments, run_learning};
use crate::learn::LearnedFormat;
use crate::theme;

/// How often to look for finished work while something is pending.
const PENDING_REPAINT: Duration = Duration::from_millis(100);
/// Tallest a code view grows before it scrolls, in points.
const CODE_VIEW_HEIGHT: f32 = 220.0;
/// Tallest the fragment list grows before it scrolls, in points.
const FRAGMENT_LIST_HEIGHT: f32 = 240.0;
/// Fragments listed for one file.
const MAX_LISTED_FRAGMENTS: usize = 2000;
/// Error messages kept on screen.
const MAX_MESSAGES: usize = 5;
/// Scores at or above this are drawn in the accent colour.
const STRONG_SIMILARITY: u32 = 50;

const JOB_ENDED_EARLY: &str = "The background job stopped without a result.";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// A file read from disk, up to [`MAX_FILE_BYTES`].
#[derive(Debug)]
pub(crate) struct LoadedFile {
    pub(crate) path: PathBuf,
    pub(crate) name: String,
    pub(crate) bytes: Arc<[u8]>,
    /// The file's full length, which may exceed `bytes`.
    pub(crate) file_len: u64,
}

impl LoadedFile {
    fn is_truncated(&self) -> bool {
        self.file_len > self.bytes.len() as u64
    }
}

/// A file compared with the document by fuzzy hash.
pub(crate) struct ComparedFile {
    pub(crate) file: LoadedFile,
    pub(crate) hash: FuzzyHash,
}

/// Identifies the document's contents, so results can be recomputed when it
/// changes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DocumentKey {
    path: Option<PathBuf>,
    version: u64,
    len: usize,
}

impl DocumentKey {
    fn of(app: &ViewerApp) -> Self {
        DocumentKey { path: app.document.path().map(Path::to_path_buf), version: app.document.version(), len: app.document.len() }
    }
}

/// Shared fragments between the document and one compared file.
struct FragmentReport {
    document: DocumentKey,
    file_name: String,
    fragments: Vec<SharedFragment>,
}

type LoadedFiles = Vec<Result<LoadedFile, String>>;
type ComparedFiles = Vec<Result<ComparedFile, String>>;

/// State of the Learn panel.
#[derive(Default)]
pub struct LearnState {
    samples: Vec<LoadedFile>,
    sample_dialog: Option<ManyFilesRequest>,
    sample_loading: Option<Receiver<LoadedFiles>>,
    learning: Option<Receiver<Result<LearnedFormat, String>>>,
    learned: Option<LearnedFormat>,
    saved_to: Option<PathBuf>,

    document_hash: Option<(DocumentKey, FuzzyHash)>,
    hashing: Option<(DocumentKey, Receiver<FuzzyHash>)>,
    compare_dialog: Option<ManyFilesRequest>,
    compare_loading: Option<Receiver<ComparedFiles>>,
    compared: Vec<ComparedFile>,
    /// Index into `compared` of the file chosen for fragment matching.
    chosen: Option<usize>,
    fragments_pending: Option<Receiver<Result<FragmentReport, String>>>,
    fragments: Option<FragmentReport>,

    messages: Vec<String>,
}

impl LearnState {
    fn is_busy(&self) -> bool {
        self.sample_dialog.is_some()
            || self.sample_loading.is_some()
            || self.learning.is_some()
            || self.hashing.is_some()
            || self.compare_dialog.is_some()
            || self.compare_loading.is_some()
            || self.fragments_pending.is_some()
    }

    fn report(&mut self, message: impl Into<String>) {
        self.messages.push(message.into());
        if self.messages.len() > MAX_MESSAGES {
            let excess = self.messages.len() - MAX_MESSAGES;
            self.messages.drain(..excess);
        }
    }
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

/// Draw the Learn panel.
pub fn show_learn(state: &mut LearnState, app: &mut ViewerApp, ui: &mut Ui) {
    poll_background_work(state, app);
    if state.is_busy() {
        ui.ctx().request_repaint_after(PENDING_REPAINT);
    }
    if !state.messages.is_empty() {
        for message in &state.messages {
            ui.label(RichText::new(message).small().color(theme::DANGER));
        }
        if ui.small_button("Dismiss").clicked() {
            state.messages.clear();
        }
        ui.separator();
    }
    let mut jump = None;
    egui::ScrollArea::vertical().id_salt("learn-panel").show(ui, |ui| {
        egui::CollapsingHeader::new(RichText::new("Learn a format").strong())
            .default_open(true)
            .show(ui, |ui| show_learning(state, app, ui));
        egui::CollapsingHeader::new(RichText::new("Fuzzy match").strong())
            .default_open(true)
            .show(ui, |ui| jump = show_fuzzy(state, app, ui));
    });
    if let Some(offset) = jump {
        app.go_to_offset(offset);
    }
}

fn show_learning(state: &mut LearnState, app: &mut ViewerApp, ui: &mut Ui) {
    ui.label(RichText::new("Give two or more files of the same format. The open document is the first sample.").small().color(theme::TEXT_DIM));
    show_samples(state, app, ui);
    ui.horizontal(|ui| {
        let can_add = state.sample_dialog.is_none() && state.sample_loading.is_none();
        if ui.add_enabled(can_add, egui::Button::new("Add samples…")).clicked() {
            state.sample_dialog = Some(ManyFilesRequest::open(rfd::AsyncFileDialog::new().set_title("Add samples of the same format")));
        }
        let can_learn = !state.samples.is_empty() && state.learning.is_none() && !app.document.is_empty();
        if ui.add_enabled(can_learn, egui::Button::new("Learn")).clicked() {
            ask_to_learn(state, app);
        }
        if state.sample_loading.is_some() {
            ui.spinner();
            ui.label(RichText::new("Reading samples…").small().color(theme::TEXT_DIM));
        }
        if state.learning.is_some() {
            ui.spinner();
            ui.label(RichText::new("Learning…").small().color(theme::TEXT_DIM));
        }
    });
    let Some(learned) = &state.learned else { return };
    ui.separator();
    ui.label(RichText::new("What the samples share").strong());
    code_view(ui, "learn-summary", &learned.summary);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Catalogue entry").strong());
        if ui.small_button("Copy").clicked() {
            ui.ctx().copy_text(learned.catalogue_toml.clone());
        }
    });
    code_view(ui, "learn-catalogue", &learned.catalogue_toml);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Template draft").strong());
        if ui.small_button("Copy").clicked() {
            ui.ctx().copy_text(learned.template.clone());
        }
    });
    code_view(ui, "learn-template", &learned.template);

    let mut save = false;
    let mut apply = false;
    ui.horizontal(|ui| {
        save = ui.button("Save to my catalogue").on_hover_text("Write the entry to a new file in your catalogue folder and reload").clicked();
        apply = ui.button("Apply template").on_hover_text("Apply the template draft at the start of the document").clicked();
    });
    if let Some(path) = &state.saved_to {
        ui.label(RichText::new(format!("Saved to {}", path.display())).small().color(theme::ACCENT));
    }
    if save {
        save_learned(state, app);
    }
    if apply && let Some(learned) = &state.learned {
        let template = learned.template.clone();
        app.apply_template_from_tool(&template, 0);
    }
}

fn show_samples(state: &mut LearnState, app: &ViewerApp, ui: &mut Ui) {
    let mut removed = None;
    egui::Grid::new("learn-samples").num_columns(3).striped(true).spacing([12.0, 4.0]).show(ui, |ui| {
        ui.label(RichText::new(format!("{} (open document)", app.display_name())).color(theme::ACCENT));
        ui.monospace(human_bytes(app.document.len()));
        ui.label("");
        ui.end_row();
        for (index, sample) in state.samples.iter().enumerate() {
            ui.label(&sample.name);
            let size = human_bytes(sample.file_len as usize);
            ui.monospace(if sample.is_truncated() { format!("{size} (first {} read)", human_bytes(MAX_FILE_BYTES)) } else { size });
            if ui.small_button("Remove").clicked() {
                removed = Some(index);
            }
            ui.end_row();
        }
    });
    if let Some(index) = removed {
        state.samples.remove(index);
    }
}

/// A read-only, scrollable monospace view of `text`.
fn code_view(ui: &mut Ui, id: &str, text: &str) {
    let mut view: &str = text;
    egui::ScrollArea::vertical().id_salt(id).max_height(CODE_VIEW_HEIGHT).show(ui, |ui| {
        ui.add(egui::TextEdit::multiline(&mut view).code_editor().desired_width(f32::INFINITY).desired_rows(1));
    });
}

/// Draw the fuzzy-match section; returns an offset to jump to when a
/// fragment is clicked.
fn show_fuzzy(state: &mut LearnState, app: &mut ViewerApp, ui: &mut Ui) -> Option<usize> {
    ensure_document_hash(state, app);
    show_document_hash(state, app, ui);
    ui.horizontal(|ui| {
        let can_add = state.compare_dialog.is_none() && state.compare_loading.is_none();
        if ui.add_enabled(can_add, egui::Button::new("Compare with files…")).clicked() {
            state.compare_dialog = Some(ManyFilesRequest::open(rfd::AsyncFileDialog::new().set_title("Compare with files")));
        }
        if !state.compared.is_empty() && ui.button("Clear").clicked() {
            state.compared.clear();
            state.chosen = None;
            state.fragments = None;
        }
        if state.compare_loading.is_some() {
            ui.spinner();
            ui.label(RichText::new("Hashing files…").small().color(theme::TEXT_DIM));
        }
    });
    show_similarity_table(state, ui);
    show_fragments(state, app, ui)
}

fn show_document_hash(state: &LearnState, app: &ViewerApp, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label("This document:");
        match &state.document_hash {
            Some((_, hash)) => {
                let text = hash.to_string();
                ui.add(egui::Label::new(RichText::new(&text).monospace().small()).wrap());
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(text);
                }
            }
            None => {
                ui.spinner();
            }
        }
    });
    if app.document.len() > MAX_FILE_BYTES {
        ui.label(RichText::new(format!("Hashes cover the first {} of each file.", human_bytes(MAX_FILE_BYTES))).small().color(theme::TEXT_DIM));
    }
}

/// Compared files, most similar first, with their scores.
fn show_similarity_table(state: &mut LearnState, ui: &mut Ui) {
    if state.compared.is_empty() {
        return;
    }
    let document_hash = state.document_hash.as_ref().map(|(_, hash)| hash);
    let mut rows: Vec<(usize, Option<u32>)> =
        state.compared.iter().enumerate().map(|(index, compared)| (index, document_hash.map(|hash| fuzzy::compare(hash, &compared.hash)))).collect();
    rows.sort_by_key(|&(index, score)| (std::cmp::Reverse(score), index));
    egui::Grid::new("learn-similarity").num_columns(3).striped(true).spacing([12.0, 4.0]).show(ui, |ui| {
        ui.label(RichText::new("Score").small().color(theme::TEXT_DIM));
        ui.label(RichText::new("File").small().color(theme::TEXT_DIM));
        ui.label(RichText::new("Size").small().color(theme::TEXT_DIM));
        ui.end_row();
        for (index, score) in rows {
            let compared = &state.compared[index];
            let (score_text, colour) = match score {
                Some(score) => (score.to_string(), score_colour(score)),
                None => ("…".to_string(), theme::TEXT_DIM),
            };
            ui.label(RichText::new(score_text).monospace().color(colour));
            let selected = state.chosen == Some(index);
            if ui.selectable_label(selected, &compared.file.name).on_hover_text(compared.hash.to_string()).clicked() {
                state.chosen = Some(index);
            }
            ui.monospace(human_bytes(compared.file.file_len as usize));
            ui.end_row();
        }
    });
}

fn score_colour(score: u32) -> Color32 {
    match score {
        0 => theme::TEXT_DIM,
        score if score >= STRONG_SIMILARITY => theme::ACCENT,
        _ => theme::TEXT,
    }
}

/// The shared-fragments controls and list for the chosen file.
fn show_fragments(state: &mut LearnState, app: &mut ViewerApp, ui: &mut Ui) -> Option<usize> {
    if state.compared.is_empty() {
        return None;
    }
    ui.separator();
    ui.horizontal(|ui| {
        let chosen_name = state.chosen.and_then(|index| state.compared.get(index)).map(|compared| compared.file.name.clone());
        let can_search = chosen_name.is_some() && state.fragments_pending.is_none();
        if ui.add_enabled(can_search, egui::Button::new("Shared fragments")).on_hover_text("Find blocks of this document that also occur in the chosen file").clicked() {
            start_fragment_search(state, app);
        }
        match chosen_name {
            Some(name) => ui.label(RichText::new(format!("with {name}")).small().color(theme::TEXT_DIM)),
            None => ui.label(RichText::new("Choose a file in the table first.").small().color(theme::TEXT_DIM)),
        };
        if state.fragments_pending.is_some() {
            ui.spinner();
        }
    });
    let report = state.fragments.as_ref()?;
    if report.document != DocumentKey::of(app) {
        ui.label(RichText::new("The document has changed since these fragments were found.").small().color(theme::CURSOR));
    }
    let total: usize = report.fragments.iter().map(|fragment| fragment.len).sum();
    ui.label(
        RichText::new(format!(
            "{} shared fragments with {}, {} in all ({}-byte blocks)",
            report.fragments.len(),
            report.file_name,
            human_bytes(total),
            fuzzy::DEFAULT_FRAGMENT_BLOCK
        ))
        .small(),
    );
    let mut jump = None;
    egui::ScrollArea::vertical().id_salt("learn-fragments").max_height(FRAGMENT_LIST_HEIGHT).show(ui, |ui| {
        for fragment in report.fragments.iter().take(MAX_LISTED_FRAGMENTS) {
            let text = format!("0x{:08x} here ↔ 0x{:08x} there  {}", fragment.offset_here, fragment.offset_there, human_bytes(fragment.len));
            if ui.selectable_label(false, RichText::new(text).monospace().small()).on_hover_text("Go to this fragment in the document").clicked() {
                jump = Some(fragment.offset_here);
            }
        }
        if report.fragments.len() > MAX_LISTED_FRAGMENTS {
            ui.label(RichText::new(format!("… and {} more", report.fragments.len() - MAX_LISTED_FRAGMENTS)).small().color(theme::TEXT_DIM));
        }
    });
    jump
}

// ---------------------------------------------------------------------------
// Background work
// ---------------------------------------------------------------------------

/// A multi-file open dialog that does not block the window, like
/// [`crate::dialogs::FileRequest`] but answering with several paths.
/// (The same helper is private to `panel_compare`.)
struct ManyFilesRequest {
    receiver: Receiver<Option<Vec<PathBuf>>>,
}

impl ManyFilesRequest {
    fn open(dialog: rfd::AsyncFileDialog) -> Self {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let chosen = pollster::block_on(dialog.pick_files()).map(|handles| handles.iter().map(|handle| handle.path().to_path_buf()).collect());
            let _ = sender.send(chosen);
        });
        ManyFilesRequest { receiver }
    }

    /// `Some(answer)` once answered; `Some(None)` when cancelled.
    fn poll(&self) -> Option<Option<Vec<PathBuf>>> {
        match self.receiver.try_recv() {
            Ok(answer) => Some(answer),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(None),
        }
    }
}

/// The result of a job, once it has finished; `Err` when its thread ended
/// without answering.
fn take_finished<T>(pending: &mut Option<Receiver<T>>) -> Option<Result<T, TryRecvError>> {
    let receiver = pending.as_ref()?;
    match receiver.try_recv() {
        Ok(result) => {
            *pending = None;
            Some(Ok(result))
        }
        Err(TryRecvError::Empty) => None,
        Err(TryRecvError::Disconnected) => {
            *pending = None;
            Some(Err(TryRecvError::Disconnected))
        }
    }
}

/// Answer the dialog's request by reading the chosen files on a thread.
fn take_dialog_answer(dialog: &mut Option<ManyFilesRequest>) -> Option<Vec<PathBuf>> {
    let answer = dialog.as_ref()?.poll()?;
    *dialog = None;
    answer
}

fn poll_background_work(state: &mut LearnState, app: &mut ViewerApp) {
    if let Some(paths) = take_dialog_answer(&mut state.sample_dialog) {
        state.sample_loading = Some(spawn_job(move || paths.iter().map(|path| read_file(path)).collect()));
    }
    match take_finished(&mut state.sample_loading) {
        Some(Ok(loaded)) => {
            for result in loaded {
                match result {
                    Ok(file) => state.samples.push(file),
                    Err(message) => state.report(message),
                }
            }
        }
        Some(Err(_)) => state.report(JOB_ENDED_EARLY),
        None => {}
    }
    match take_finished(&mut state.learning) {
        Some(Ok(Ok(learned))) => {
            state.learned = Some(learned);
            state.saved_to = None;
        }
        Some(Ok(Err(message))) => state.report(message),
        Some(Err(_)) => state.report(JOB_ENDED_EARLY),
        None => {}
    }
    poll_document_hash(state);
    if let Some(paths) = take_dialog_answer(&mut state.compare_dialog) {
        app.perform_later("learn.fuzzy_compare", serde_json::json!({ "paths": paths }));
    }
    match take_finished(&mut state.compare_loading) {
        Some(Ok(loaded)) => {
            for result in loaded {
                match result {
                    Ok(compared) => state.compared.push(compared),
                    Err(message) => state.report(message),
                }
            }
        }
        Some(Err(_)) => state.report(JOB_ENDED_EARLY),
        None => {}
    }
    match take_finished(&mut state.fragments_pending) {
        Some(Ok(Ok(report))) => state.fragments = Some(report),
        Some(Ok(Err(message))) => state.report(message),
        Some(Err(_)) => state.report(JOB_ENDED_EARLY),
        None => {}
    }
}

fn poll_document_hash(state: &mut LearnState) {
    let Some((key, receiver)) = &state.hashing else { return };
    match receiver.try_recv() {
        Ok(hash) => {
            state.document_hash = Some((key.clone(), hash));
            state.hashing = None;
        }
        Err(TryRecvError::Empty) => {}
        Err(TryRecvError::Disconnected) => {
            state.hashing = None;
            state.report(JOB_ENDED_EARLY);
        }
    }
}

/// Run `job` on a thread; its result arrives on the returned receiver.
fn spawn_job<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static) -> Receiver<T> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(job());
    });
    receiver
}

/// Read up to [`MAX_FILE_BYTES`] of `path`, noting its full length.
pub(crate) fn read_file(path: &Path) -> Result<LoadedFile, String> {
    let name = path.file_name().map_or_else(|| path.display().to_string(), |name| name.to_string_lossy().into_owned());
    let file = File::open(path).map_err(|error| format!("Could not open {name}: {error}"))?;
    let file_len = file.metadata().map_err(|error| format!("Could not read the size of {name}: {error}"))?.len();
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES as u64).read_to_end(&mut bytes).map_err(|error| format!("Could not read {name}: {error}"))?;
    Ok(LoadedFile { path: path.to_path_buf(), name, bytes: bytes.into(), file_len })
}

/// The document's leading bytes, capped like added files.
fn document_bytes(app: &mut ViewerApp) -> Arc<[u8]> {
    app.document.read_range(0, MAX_FILE_BYTES).into()
}

/// Hash the document again whenever its contents change.
fn ensure_document_hash(state: &mut LearnState, app: &mut ViewerApp) {
    let key = DocumentKey::of(app);
    let current = state.document_hash.as_ref().is_some_and(|(hashed, _)| *hashed == key);
    // One hash at a time; a stale one is replaced once it finishes.
    if current || state.hashing.is_some() {
        return;
    }
    let bytes = document_bytes(app);
    state.hashing = Some((key, spawn_job(move || fuzzy::fuzzy_hash(&bytes))));
}

/// Save the learned signature to the person's catalogue, through
/// `learn.save_catalogue`, and say where it went or why it could not.
fn save_learned(state: &mut LearnState, app: &mut ViewerApp) {
    let Some(learned) = &state.learned else { return };
    let params = serde_json::json!({ "id": learned.id, "toml": learned.catalogue_toml });
    match app.perform("learn.save_catalogue", params) {
        Ok(saved) => state.saved_to = saved["path"].as_str().map(PathBuf::from),
        Err(error) => state.report(error.message),
    }
}

/// Ask to learn the format of the document and the samples, through
/// `learn.format`.
fn ask_to_learn(state: &LearnState, app: &mut ViewerApp) {
    let paths: Vec<&Path> = state.samples.iter().map(|sample| sample.path.as_path()).collect();
    app.perform_later("learn.format", serde_json::json!({ "paths": paths }));
}

/// Ask for the shared fragments of the document and the file chosen in
/// the table, through `learn.fragments`.
fn start_fragment_search(state: &mut LearnState, app: &mut ViewerApp) {
    let Some(compared) = state.chosen.and_then(|index| state.compared.get(index)) else { return };
    let params = serde_json::json!({ "path": compared.file.path, "block": fuzzy::DEFAULT_FRAGMENT_BLOCK });
    app.perform_later("learn.fragments", params);
}

/// Start a job of `producer`'s about the document shown.
fn start_job_as(app: &mut ViewerApp, kind: &str, title: &str, producer: &str) -> crate::bus::JobHandle {
    let document = Some((app.document_id(), app.document.version()));
    app.bus.start_job(kind, title, producer, document)
}

/// Learn what the document and the files at `paths` share, as
/// `producer`'s job, and show it here: what `learn.format` does in the
/// window. Returns the job.
pub fn learn_as(app: &mut ViewerApp, paths: Vec<PathBuf>, producer: &str) -> String {
    let document = document_bytes(app);
    let document_len = app.document.len() as u64;
    let job = start_job_as(app, "learn", "Learning a format", producer);
    let id = job.id().to_string();
    app.bench.panels.learn.learning = Some(spawn_job(move || run_learning(document, document_len, &paths, &job)));
    id
}

/// Hash the files at `paths` and score them against the document, as
/// `producer`'s job, adding them to the table here: what
/// `learn.fuzzy_compare` does in the window. Returns the job.
pub fn compare_as(app: &mut ViewerApp, paths: Vec<PathBuf>, producer: &str) -> String {
    let document = document_bytes(app);
    let job = start_job_as(app, "fuzzy-compare", "Comparing files", producer);
    let id = job.id().to_string();
    app.bench.panels.learn.compare_loading = Some(spawn_job(move || run_comparison(&document, &paths, &job)));
    id
}

/// Find the blocks of the document that occur in the file at `path`, as
/// `producer`'s job, and list them here: what `learn.fragments` does in
/// the window. Returns the job.
pub fn fragments_as(app: &mut ViewerApp, path: PathBuf, block: usize, producer: &str) -> String {
    let document = DocumentKey::of(app);
    let here = document_bytes(app);
    let job = start_job_as(app, "fragments", "Finding shared fragments", producer);
    let id = job.id().to_string();
    let state = &mut app.bench.panels.learn;
    state.fragments = None;
    state.fragments_pending = Some(spawn_job(move || {
        let (file_name, fragments) = run_fragments(&here, &path, block, &job)?;
        Ok(FragmentReport { document, file_name, fragments })
    }));
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("theviewer-learn-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }


    /// A "QXF1" file: magic, version, u32 LE total length, varied body.
    fn qxf_sample(version: u8, total_len: usize) -> Vec<u8> {
        let mut bytes = b"QXF1".to_vec();
        bytes.push(version);
        bytes.extend_from_slice(&(total_len as u32).to_le_bytes());
        let mut state = total_len as u32 | 1;
        while bytes.len() < total_len {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            bytes.push((state >> 16) as u8);
        }
        bytes
    }

    use serde_json::json;

    use crate::actions::take_performed;

    /// Draw the panel once in a headless frame, with its state lent out as
    /// the window does, after carrying out the actions asked for while drawing.
    fn draw_app_frame(ctx: &egui::Context, app: &mut ViewerApp) {
        app.perform_waiting_actions();
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| crate::panels::show(app, ui, |panels| &mut panels.learn, show_learn));
        output.textures_delta.clear();
    }

    /// Draw frames until the panel has no background work, or give up.
    fn draw_app_until_idle(ctx: &egui::Context, app: &mut ViewerApp) {
        for _ in 0..3000 {
            draw_app_frame(ctx, app);
            if !app.bench.panels.learn.is_busy() && app.actions_after_drawing.is_empty() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("background work did not finish");
    }

    #[test]
    fn learning_comparing_and_finding_fragments_are_the_person_s_steps_shown_in_the_panel() {
        let dir = scratch_dir("steps");
        std::fs::create_dir_all(&dir).unwrap();
        let document = qxf_sample(1, 6000);
        let (two, three, related_path) = (dir.join("two.qxf"), dir.join("three.qxf"), dir.join("related.bin"));
        std::fs::write(&two, qxf_sample(2, 7000)).unwrap();
        std::fs::write(&three, qxf_sample(3, 5100)).unwrap();
        // A file that embeds part of the document at another offset.
        let mut related = vec![0x5Au8; 300];
        related.extend_from_slice(&document[1024..5120]);
        std::fs::write(&related_path, &related).unwrap();
        let ctx = egui::Context::default();
        let mut app = ViewerApp::new(crate::app::Launch::default());
        app.open_bytes(document, "one.qxf".to_string());
        app.run_bus();
        take_performed();

        let state = &mut app.bench.panels.learn;
        state.samples.push(read_file(&two).unwrap());
        state.samples.push(read_file(&three).unwrap());
        let state = std::mem::take(&mut app.bench.panels.learn);
        ask_to_learn(&state, &mut app);
        app.bench.panels.learn = state;
        app.perform_later("learn.fuzzy_compare", json!({"paths": [related_path]}));
        draw_app_until_idle(&ctx, &mut app);
        let state = &app.bench.panels.learn;
        assert!(state.messages.is_empty(), "{:?}", state.messages);
        assert_eq!(state.learned.as_ref().map(|learned| learned.id.as_str()), Some("user/learned-51584631"));
        assert_eq!(state.compared.len(), 1);
        assert!(state.document_hash.is_some());

        let mut state = std::mem::take(&mut app.bench.panels.learn);
        state.chosen = Some(0);
        start_fragment_search(&mut state, &mut app);
        app.bench.panels.learn = state;
        draw_app_until_idle(&ctx, &mut app);
        let report = app.bench.panels.learn.fragments.as_ref().expect("fragments");
        assert_eq!(report.fragments, vec![SharedFragment { offset_here: 1024, offset_there: 300, len: 4096 }]);
        assert_eq!(
            take_performed(),
            [
                ("learn.format".to_string(), json!({"paths": [two, three]})),
                ("learn.fuzzy_compare".to_string(), json!({"paths": [related_path]})),
                ("learn.fragments".to_string(), json!({"path": related_path, "block": fuzzy::DEFAULT_FRAGMENT_BLOCK})),
            ]
        );
        let mut state = std::mem::take(&mut app.bench.panels.learn);
        save_learned(&mut state, &mut app);
        let saved = state.saved_to.clone().expect("saved to the catalogue");
        let learned = state.learned.clone().unwrap();
        assert_eq!(take_performed(), [("learn.save_catalogue".to_string(), json!({"id": learned.id, "toml": learned.catalogue_toml}))]);
        assert_eq!(std::fs::read_to_string(&saved).unwrap(), learned.catalogue_toml);
        let _ = std::fs::remove_file(saved);
        let producers: Vec<String> = app.bus.jobs().list().into_iter().filter(|job| job.title != "Pattern scan").map(|job| job.producer).collect();
        assert!(producers.iter().filter(|producer| *producer == "panel").count() >= 3, "{producers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reading_a_file_records_its_full_length() {
        let dir = scratch_dir("read");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.bin");
        std::fs::write(&path, b"QXF1\x01\x09\x00\x00\x00").unwrap();
        let file = read_file(&path).unwrap();
        assert_eq!((file.name.as_str(), file.file_len, file.bytes.len(), file.is_truncated()), ("sample.bin", 9, 9, false));
        assert!(read_file(&dir.join("missing.bin")).unwrap_err().contains("missing.bin"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
