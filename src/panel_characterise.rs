//! Characterise panel: what kind of data a region holds, from three angles.
//!
//! * **Compressibility**: ratios from several codecs and a verdict
//!   ([`crate::codec_profile`]), for the selection or sampled along the
//!   whole file with a strip of verdicts.
//! * **Media streams**: raw MP3/AAC/H.264/H.265/PCM runs
//!   ([`crate::elementary`]), which can be selected, played or extracted.
//! * **Text**: ranked encodings with previews and the language
//!   ([`crate::charset`]), which can be opened decoded as UTF-8.
//!
//! All analysis runs on background threads; results remember the document
//! version they were computed for so stale ones are flagged.

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Color32, CornerRadius, RichText, Sense, Stroke, Ui, vec2};

use crate::app::{DialogKind, FileAction, ViewerApp};
use crate::charset::{self, TextEncoding, TextReport};
use crate::codec_profile::{self, Profile, SegmentProfile, Verdict};
use crate::compress::human_bytes;
use crate::elementary::{self, StreamKind, StreamRun};
use crate::media::{MediaFormat, MediaKind};
use crate::player::MediaRequest;
use crate::plugin::Category;
use crate::theme;

/// Largest prefix of the document scanned for media streams.
const STREAM_SCAN_LIMIT: usize = 256 * 1024 * 1024;
/// Most bytes handed to the player, written to a file or decoded as text.
const MAX_EXTRACT: usize = 512 * 1024 * 1024;
/// Bytes examined from the cursor when nothing is selected.
const TEXT_WINDOW: usize = 4096;
/// How often to look for a finished background job.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const STRIP_HEIGHT: f32 = 22.0;
const LIST_HEIGHT: f32 = 220.0;
/// Languages listed after the encodings.
const LANGUAGES_SHOWN: usize = 3;
/// Finding source name used for runs selected from this panel.
const SOURCE: &str = "builtin.elementary_streams";

/// Identifies the document a result was computed from, to flag stale results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DocumentKey {
    len: usize,
    version: u64,
}

impl DocumentKey {
    fn of(app: &ViewerApp) -> Self {
        DocumentKey { len: app.document.len(), version: app.document.version() }
    }
}

struct CompressionResult {
    key: DocumentKey,
    /// What was profiled, e.g. "selection 0x100..0x900".
    scope: String,
    profile: Profile,
    /// Per-segment profiles for a whole-file run; empty for a selection.
    segments: Vec<SegmentProfile>,
}

struct StreamScan {
    key: DocumentKey,
    scanned_len: usize,
    runs: Vec<StreamRun>,
}

struct TextResult {
    key: DocumentKey,
    start: usize,
    len: usize,
    report: TextReport,
}

#[derive(Default)]
pub struct CharacteriseState {
    compression_pending: Option<Receiver<CompressionResult>>,
    compression: Option<CompressionResult>,
    streams_pending: Option<Receiver<StreamScan>>,
    streams: Option<StreamScan>,
    text_pending: Option<Receiver<TextResult>>,
    text: Option<TextResult>,
}

impl CharacteriseState {
    fn is_busy(&self) -> bool {
        self.compression_pending.is_some() || self.streams_pending.is_some() || self.text_pending.is_some()
    }

    /// Collect any finished background results.
    fn poll(&mut self) {
        if let Some(result) = take_ready(&mut self.compression_pending) {
            self.compression = Some(result);
        }
        if let Some(result) = take_ready(&mut self.streams_pending) {
            self.streams = Some(result);
        }
        if let Some(result) = take_ready(&mut self.text_pending) {
            self.text = Some(result);
        }
    }
}

/// The result from `pending` if it has arrived; clears `pending` when it
/// has, or when the worker went away without sending one.
fn take_ready<T>(pending: &mut Option<Receiver<T>>) -> Option<T> {
    let receiver = pending.as_ref()?;
    match receiver.try_recv() {
        Ok(result) => {
            *pending = None;
            Some(result)
        }
        Err(mpsc::TryRecvError::Empty) => None,
        Err(mpsc::TryRecvError::Disconnected) => {
            *pending = None;
            None
        }
    }
}

/// Run `work` on a background thread and return where its result arrives.
fn spawn<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Receiver<T> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(work());
    });
    receiver
}

pub fn show_characterise(state: &mut CharacteriseState, app: &mut ViewerApp, ui: &mut Ui) {
    state.poll();
    if state.is_busy() {
        ui.ctx().request_repaint_after(POLL_INTERVAL);
    }
    egui::ScrollArea::vertical().id_salt("characterise-panel").show(ui, |ui| {
        egui::CollapsingHeader::new(RichText::new("Compressibility").strong()).id_salt("characterise-compressibility").default_open(true).show(ui, |ui| {
            show_compressibility(state, app, ui);
        });
        egui::CollapsingHeader::new(RichText::new("Media streams").strong()).id_salt("characterise-streams").default_open(true).show(ui, |ui| {
            show_streams(state, app, ui);
        });
        egui::CollapsingHeader::new(RichText::new("Text").strong()).id_salt("characterise-text").default_open(true).show(ui, |ui| {
            show_text(state, app, ui);
        });
    });
}

/// "(document changed …)" when the document has changed since a result was computed.
fn stale_marker(ui: &mut Ui, key: DocumentKey, app: &ViewerApp) {
    if key != DocumentKey::of(app) {
        ui.label(RichText::new("(document changed since this result)").small().color(theme::CURSOR));
    }
}

fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).small().color(theme::TEXT_DIM)
}

// ---------------------------------------------------------------------------
// Compressibility
// ---------------------------------------------------------------------------

fn verdict_colour(verdict: Verdict) -> Color32 {
    match verdict {
        Verdict::TooSmall => theme::OUTLINE,
        Verdict::EncryptedOrRandom => Category::HighEntropy.colour(),
        Verdict::AlreadyCompressed => Category::Compressed.colour(),
        Verdict::LossyMedia => Category::Image.colour(),
        Verdict::Structured => Category::Structure.colour(),
    }
}

/// Read the sample ranges of a region and join them.
fn read_sample(app: &mut ViewerApp, start: usize, len: usize, budget: usize) -> Vec<u8> {
    codec_profile::sample_ranges(start, len, budget).into_iter().flat_map(|(offset, len)| app.document.read_range(offset, len)).collect()
}

fn start_selection_profile(state: &mut CharacteriseState, app: &mut ViewerApp, start: usize, len: usize) {
    let key = DocumentKey::of(app);
    let sample = read_sample(app, start, len, codec_profile::MAX_SAMPLE);
    let scope = format!("selection {start:#x}..{:#x} ({})", start + len, human_bytes(len));
    state.compression_pending = Some(spawn(move || CompressionResult { key, scope, profile: codec_profile::profile_sample(&sample), segments: Vec::new() }));
}

fn start_whole_file_profile(state: &mut CharacteriseState, app: &mut ViewerApp) {
    let key = DocumentKey::of(app);
    let overall = read_sample(app, 0, key.len, codec_profile::MAX_SAMPLE);
    let segments: Vec<(usize, usize, Vec<u8>)> = codec_profile::segment_bounds(key.len, codec_profile::MAX_SEGMENTS)
        .into_iter()
        .map(|(offset, len)| (offset, len, read_sample(app, offset, len, codec_profile::SEGMENT_SAMPLE)))
        .collect();
    let scope = format!("whole file ({}), sampled along its length", human_bytes(key.len));
    state.compression_pending = Some(spawn(move || CompressionResult { key, scope, profile: codec_profile::profile_sample(&overall), segments: codec_profile::profile_segments(segments) }));
}

fn show_compressibility(state: &mut CharacteriseState, app: &mut ViewerApp, ui: &mut Ui) {
    let idle = state.compression_pending.is_none();
    ui.horizontal_wrapped(|ui| {
        let selection = app.selection();
        let label = match selection {
            Some((_, len)) => format!("Profile selection ({})", human_bytes(len)),
            None => "Profile selection".to_string(),
        };
        if ui.add_enabled(idle && selection.is_some(), egui::Button::new(label)).on_disabled_hover_text("Select some bytes first").clicked()
            && let Some((start, len)) = selection
        {
            start_selection_profile(state, app, start, len);
        }
        if ui.add_enabled(idle && !app.document.is_empty(), egui::Button::new("Profile whole file")).clicked() {
            start_whole_file_profile(state, app);
        }
        if !idle {
            ui.spinner();
        }
        if let Some(result) = &state.compression {
            stale_marker(ui, result.key, app);
        }
    });
    let Some(result) = &state.compression else {
        ui.label(
            RichText::new("Compresses a sample with deflate, bzip2, LZ4, zstd and an order-1 entropy coder. The pattern of gains tells encrypted, already compressed, lossy media and structured data apart.")
                .color(theme::TEXT_DIM),
        );
        return;
    };
    ui.label(dim(format!("{}: {} sampled", result.scope, human_bytes(result.profile.sample_len))));
    verdict_line(ui, &result.profile);
    ratio_table(ui, &result.profile);
    if !result.segments.is_empty() {
        ui.add_space(4.0);
        ui.label(dim("Verdict along the file (click to jump):"));
        if let Some(offset) = verdict_strip(ui, &result.segments) {
            app.jump_to_offset(offset);
        }
        verdict_legend(ui, &result.segments);
    }
}

fn verdict_line(ui: &mut Ui, profile: &Profile) {
    ui.horizontal_wrapped(|ui| {
        theme::swatch(ui, verdict_colour(profile.verdict), profile.verdict.label());
        ui.label(dim(profile.reason.as_str()));
    });
}

fn ratio_table(ui: &mut Ui, profile: &Profile) {
    if profile.ratios.is_empty() {
        return;
    }
    let best = profile.best().map(|(probe, _)| probe);
    egui::Grid::new("characterise-ratio-grid").num_columns(4).striped(true).spacing([14.0, 2.0]).show(ui, |ui| {
        for heading in ["Codec", "Size", "Ratio", "Gain"] {
            ui.label(dim(heading));
        }
        ui.end_row();
        for ratio in &profile.ratios {
            let colour = if Some(ratio.probe) == best { theme::ACCENT } else { theme::TEXT };
            ui.label(RichText::new(ratio.probe.label()).color(colour)).on_hover_text(ratio.probe.description());
            match &ratio.compressed {
                Ok(size) => {
                    ui.monospace(human_bytes(*size));
                    ui.monospace(format!("{:.3}", ratio.ratio(profile.sample_len).unwrap_or(0.0)));
                    ui.monospace(format!("{:+.1}%", ratio.gain(profile.sample_len).unwrap_or(0.0) * 100.0));
                }
                Err(message) => {
                    ui.label(RichText::new("failed").color(theme::DANGER)).on_hover_text(message.as_str());
                    ui.label("");
                    ui.label("");
                }
            }
            ui.end_row();
        }
    });
}

/// One band per segment, coloured by verdict; returns an offset when clicked.
fn verdict_strip(ui: &mut Ui, segments: &[SegmentProfile]) -> Option<usize> {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), STRIP_HEIGHT), Sense::click());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(3), theme::BACKGROUND);
    let total = segments.last().map_or(1, |segment| segment.offset + segment.len).max(1) as f32;
    let x_of = |offset: usize| rect.min.x + rect.width() * offset as f32 / total;
    for segment in segments {
        let (left, right) = (x_of(segment.offset), x_of(segment.offset + segment.len).max(x_of(segment.offset) + 1.0));
        let band = egui::Rect::from_min_max(egui::pos2(left, rect.min.y), egui::pos2(right, rect.max.y));
        painter.rect_filled(band, CornerRadius::ZERO, verdict_colour(segment.profile.verdict));
    }
    painter.rect_stroke(rect, CornerRadius::same(3), Stroke::new(1.0, theme::OUTLINE), egui::StrokeKind::Inside);
    let offset_at = |x: f32| (((x - rect.min.x) / rect.width()).clamp(0.0, 1.0) * total) as usize;
    let hovered = response.hover_pos().map(|pos| offset_at(pos.x));
    let clicked = response.clicked().then(|| response.interact_pointer_pos()).flatten().map(|pos| offset_at(pos.x));
    if let Some(offset) = hovered
        && let Some(segment) = segments.iter().find(|segment| (segment.offset..segment.offset + segment.len).contains(&offset))
    {
        response.on_hover_text(format!("{:#x}..{:#x}: {}\n{}", segment.offset, segment.offset + segment.len, segment.profile.verdict.label(), segment.profile.reason));
    }
    clicked.and_then(|offset| segments.iter().find(|segment| (segment.offset..segment.offset + segment.len).contains(&offset)).map(|segment| segment.offset))
}

fn verdict_legend(ui: &mut Ui, segments: &[SegmentProfile]) {
    ui.horizontal_wrapped(|ui| {
        for verdict in Verdict::ALL {
            let bytes: usize = segments.iter().filter(|segment| segment.profile.verdict == verdict).map(|segment| segment.len).sum();
            if bytes > 0 {
                theme::swatch(ui, verdict_colour(verdict), &format!("{} ({})", verdict.label(), human_bytes(bytes)));
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Media streams
// ---------------------------------------------------------------------------

fn start_stream_scan(state: &mut CharacteriseState, app: &mut ViewerApp) {
    let key = DocumentKey::of(app);
    let bytes = app.document.read_range(0, key.len.min(STREAM_SCAN_LIMIT));
    state.streams_pending = Some(spawn(move || StreamScan { key, scanned_len: bytes.len(), runs: elementary::find_streams(&bytes) }));
}

/// What the user asked for in the streams section this frame.
enum StreamAction {
    Select(usize),
    Play(usize),
    Extract(usize),
}

fn show_streams(state: &mut CharacteriseState, app: &mut ViewerApp, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        let size = human_bytes(app.document.len().min(STREAM_SCAN_LIMIT));
        if ui.add_enabled(state.streams_pending.is_none(), egui::Button::new(format!("Scan for media streams ({size})"))).clicked() {
            start_stream_scan(state, app);
        }
        if state.streams_pending.is_some() {
            ui.spinner();
        }
        if let Some(scan) = &state.streams {
            stale_marker(ui, scan.key, app);
        }
    });
    let Some(scan) = &state.streams else {
        ui.label(RichText::new("Finds MP3/MP2 and AAC frames, H.264 and H.265 Annex B video and raw 16-bit PCM audio that have no container.").color(theme::TEXT_DIM));
        return;
    };
    if scan.runs.is_empty() {
        ui.label(dim(format!("No raw media streams in the first {}.", human_bytes(scan.scanned_len))));
        return;
    }
    let action = stream_list(ui, &scan.runs);
    let Some(action) = action else { return };
    let run_index = match action {
        StreamAction::Select(index) | StreamAction::Play(index) | StreamAction::Extract(index) => index,
    };
    let run = scan.runs[run_index].clone();
    match action {
        StreamAction::Select(_) => app.select_pattern(&run.to_finding(SOURCE, 0)),
        StreamAction::Play(_) => play_run(app, &run),
        StreamAction::Extract(_) => extract_run(app, &run),
    }
}

fn stream_list(ui: &mut Ui, runs: &[StreamRun]) -> Option<StreamAction> {
    let mut action = None;
    let row_height = ui.text_style_height(&egui::TextStyle::Body) + 8.0;
    egui::ScrollArea::vertical().id_salt("characterise-streams-list").max_height(LIST_HEIGHT).show_rows(ui, row_height, runs.len(), |ui, rows| {
        for index in rows {
            let run = &runs[index];
            ui.horizontal(|ui| {
                if ui.link(RichText::new(format!("{:#010x}", run.start)).monospace()).on_hover_text("Select the stream").clicked() {
                    action = Some(StreamAction::Select(index));
                }
                ui.monospace(RichText::new(format!("{:>9}", human_bytes(run.len))).color(theme::TEXT_DIM));
                let why_not = if run.kind.is_audio() { "The player cannot decode this audio format; extract it instead" } else { "Raw video cannot be played without a container; extract it instead" };
                if ui.add_enabled(run.playable_as.is_some(), egui::Button::new("Play").small()).on_disabled_hover_text(why_not).clicked() {
                    action = Some(StreamAction::Play(index));
                }
                if ui.add(egui::Button::new("Extract…").small()).on_hover_text("Save the stream's bytes to a file").clicked() {
                    action = Some(StreamAction::Extract(index));
                }
                theme::swatch(ui, run.kind.category().colour(), &run.title);
                ui.add(egui::Label::new(dim(run.detail.as_str())).truncate());
            });
        }
    });
    action
}

/// Open an audio run in the media window; PCM is wrapped as WAV first.
fn play_run(app: &mut ViewerApp, run: &StreamRun) {
    let Some(name) = run.playable_as else {
        app.status = format!("{} cannot be played directly; extract it instead", run.kind.label());
        return;
    };
    let mut bytes = app.document.read_range(run.start, run.len.min(MAX_EXTRACT));
    if let Some(layout) = run.pcm {
        bytes = elementary::wav_from_pcm(&bytes, layout, elementary::ASSUMED_SAMPLE_RATE);
        app.status = format!("Playing PCM at {:#x} as WAV, assuming {} Hz", run.start, elementary::ASSUMED_SAMPLE_RATE);
    } else {
        app.status = format!("Playing {} at {:#x}", run.kind.label(), run.start);
    }
    let format = MediaFormat { kind: MediaKind::Audio, name };
    app.media.open(MediaRequest { format, start: run.start, bytes, source_name: app.display_name() });
}

fn extension_for(kind: StreamKind, title: &str) -> &'static str {
    match kind {
        StreamKind::MpegAudio if title.starts_with("MP2") => "mp2",
        StreamKind::MpegAudio if title.starts_with("MP1") => "mp1",
        StreamKind::MpegAudio => "mp3",
        StreamKind::Adts => "aac",
        StreamKind::H264 => "h264",
        StreamKind::H265 => "h265",
        StreamKind::Pcm => "pcm",
    }
}

fn extract_run(app: &mut ViewerApp, run: &StreamRun) {
    let bytes = app.document.read_range(run.start, run.len.min(MAX_EXTRACT));
    let file_name = format!("stream_{:x}.{}", run.start, extension_for(run.kind, &run.title));
    let dialog = rfd::AsyncFileDialog::new().set_title("Extract media stream").set_file_name(&file_name);
    let name = format!("{} at {:#x}", run.kind.label(), run.start);
    app.ask_for_file(DialogKind::Save, dialog, FileAction::SaveBytes { name, bytes: Arc::new(bytes) });
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

/// The selection, or [`TEXT_WINDOW`] bytes from the cursor.
fn text_target(app: &ViewerApp) -> (usize, usize) {
    app.selection().unwrap_or_else(|| (app.cursor, TEXT_WINDOW.min(app.document.len().saturating_sub(app.cursor))))
}

fn start_text_analysis(state: &mut CharacteriseState, app: &mut ViewerApp) {
    let key = DocumentKey::of(app);
    let (start, len) = text_target(app);
    let sample = app.document.read_range(start, len.min(charset::MAX_TEXT_SAMPLE));
    state.text_pending = Some(spawn(move || TextResult { key, start, len, report: charset::characterise_text(&sample) }));
}

fn show_text(state: &mut CharacteriseState, app: &mut ViewerApp, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        let label = if app.selection().is_some() { "Identify selection's encoding" } else { "Identify encoding at cursor" };
        let has_bytes = text_target(app).1 > 0;
        if ui.add_enabled(state.text_pending.is_none() && has_bytes, egui::Button::new(label)).clicked() {
            start_text_analysis(state, app);
        }
        if state.text_pending.is_some() {
            ui.spinner();
        }
        if let Some(result) = &state.text {
            stale_marker(ui, result.key, app);
        }
    });
    let Some(result) = &state.text else {
        ui.label(
            RichText::new("Scores ASCII, UTF-8, UTF-16, Windows-1252, Shift-JIS, EUC-JP, GBK, Big5, EUC-KR, KOI8-R and EBCDIC for the selection (or 4 KiB at the cursor), then names the language.")
                .color(theme::TEXT_DIM),
        );
        return;
    };
    ui.label(dim(format!("{:#x}..{:#x}: {} examined", result.start, result.start + result.len, human_bytes(result.report.sample_len))));
    language_line(ui, &result.report);
    let open = encoding_table(ui, &result.report);
    if let Some(encoding) = open {
        let (start, len) = (result.start, result.len);
        open_decoded(app, start, len, encoding);
    }
}

fn language_line(ui: &mut Ui, report: &TextReport) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Language:").color(theme::TEXT_DIM));
        if report.languages.is_empty() {
            ui.label(dim("not enough text to tell"));
        }
        for guess in report.languages.iter().take(LANGUAGES_SHOWN) {
            ui.label(RichText::new(format!("{} {:.0}%", guess.language.label(), guess.confidence * 100.0)).color(theme::ACCENT)).on_hover_text(guess.reason.as_str());
        }
    });
}

/// The ranked encodings; returns one when its "Open" button is clicked.
fn encoding_table(ui: &mut Ui, report: &TextReport) -> Option<TextEncoding> {
    let mut open = None;
    egui::Grid::new("characterise-encoding-grid").num_columns(4).striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
        for heading in ["Encoding", "Confidence", "", "Preview"] {
            ui.label(dim(heading));
        }
        ui.end_row();
        for guess in &report.encodings {
            let valid = guess.confidence > 0.0;
            let colour = if valid { theme::TEXT } else { theme::TEXT_DIM };
            let mut label = guess.encoding.label().to_string();
            if guess.has_bom {
                label.push_str(" (BOM)");
            }
            ui.label(RichText::new(label).color(colour)).on_hover_text(guess.reason.as_str());
            ui.monospace(RichText::new(format!("{:>3.0}%", guess.confidence * 100.0)).color(colour));
            if ui.add_enabled(valid, egui::Button::new("Open as UTF-8").small()).on_hover_text("Decode the region with this encoding and open it as a new document").clicked() {
                open = Some(guess.encoding);
            }
            ui.add(egui::Label::new(RichText::new(guess.preview.as_str()).monospace().color(colour)).truncate());
            ui.end_row();
        }
    });
    open
}

fn open_decoded(app: &mut ViewerApp, start: usize, len: usize, encoding: TextEncoding) {
    let bytes = app.document.read_range(start, len.min(MAX_EXTRACT));
    let text = charset::decode(&bytes, encoding);
    let name = format!("{} › {}@{start:#x} as UTF-8", app.display_name(), encoding.label());
    app.open_derived(text.into_bytes(), name);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec_profile::Probe;

    #[test]
    fn extracted_streams_get_an_extension_for_their_format() {
        assert_eq!(extension_for(StreamKind::MpegAudio, "MP2 audio, 192 kbit/s"), "mp2");
        assert_eq!(extension_for(StreamKind::MpegAudio, "MP3 audio, 128 kbit/s"), "mp3");
        assert_eq!(extension_for(StreamKind::H265, "H.265 video"), "h265");
    }

    #[test]
    fn a_finished_job_is_collected_once_and_a_vanished_one_is_cleared() {
        let mut pending = Some(spawn(|| 7));
        let mut collected = None;
        for _ in 0..200 {
            if let Some(value) = take_ready(&mut pending) {
                collected = Some(value);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(collected, Some(7));
        assert!(pending.is_none());

        let (sender, receiver) = mpsc::channel::<u8>();
        drop(sender);
        let mut vanished = Some(receiver);
        assert_eq!(take_ready(&mut vanished), None);
        assert!(vanished.is_none());
    }

    #[test]
    fn every_verdict_has_a_distinct_colour() {
        let colours: std::collections::HashSet<_> = Verdict::ALL.iter().map(|&verdict| verdict_colour(verdict)).collect();
        assert_eq!(colours.len(), Verdict::ALL.len());
    }

    #[test]
    fn the_probe_list_matches_the_ratio_table_headings() {
        assert!(Probe::ALL.iter().all(|probe| !probe.label().is_empty() && !probe.description().is_empty()));
    }
}
