//! Dock panel: find uncompressed images in the selection or the whole file
//! ([`crate::image_finder::find_images`]) and apply one to the view.
//!
//! Applying a candidate sets the pixel format, the width and the view origin
//! so the image appears upright at the top of the raster, and moves the
//! cursor to its first byte.

use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, RichText, Ui};

use crate::app::ViewerApp;
use crate::image_finder::{self, ImageCandidate};
use crate::theme;

/// Largest range searched; anything beyond is left out.
const IMAGE_SEARCH_LIMIT: usize = 64 * 1024 * 1024;
/// How often to look for finished results while a search runs.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Width of the score bar drawn before each candidate.
const SCORE_BAR_WIDTH: f32 = 36.0;
/// Height of the score bar.
const SCORE_BAR_HEIGHT: f32 = 8.0;

/// Everything the image finder panel keeps between frames.
#[derive(Default)]
pub struct ImageFinderState {
    pending: Option<Receiver<Vec<ImageCandidate>>>,
    /// Candidates from the last search, best first.
    pub candidates: Option<Vec<ImageCandidate>>,
    /// Index of the candidate last applied to the view.
    pub applied: Option<usize>,
}

/// The selection, else the whole file, capped, with a word for which.
fn scope(app: &ViewerApp) -> (usize, usize, &'static str) {
    match app.selection() {
        Some((start, len)) => (start, len.min(IMAGE_SEARCH_LIMIT), "selection"),
        None => (0, app.document.len().min(IMAGE_SEARCH_LIMIT), "whole file"),
    }
}

pub(crate) fn start_search(state: &mut ImageFinderState, app: &mut ViewerApp) {
    app.note_tool_result(crate::dock::DockTab::Images);
    let (start, len, _) = scope(app);
    let bytes = app.document.read_range(start, len);
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        // The receiver may be gone if the panel was closed; nothing to do then.
        let _ = sender.send(image_finder::find_images(&bytes, start));
    });
    state.pending = Some(receiver);
    state.applied = None;
}

fn poll(state: &mut ImageFinderState, ctx: &egui::Context) {
    let Some(receiver) = &state.pending else { return };
    match receiver.try_recv() {
        Ok(candidates) => {
            state.candidates = Some(candidates);
            state.pending = None;
        }
        Err(mpsc::TryRecvError::Empty) => ctx.request_repaint_after(POLL_INTERVAL),
        Err(mpsc::TryRecvError::Disconnected) => state.pending = None,
    }
}

/// Show a candidate in the raster: its format and width, with the view
/// origin on its first pixel, and the cursor there too.
pub fn apply_candidate(app: &mut ViewerApp, candidate: &ImageCandidate) {
    app.shape.format = candidate.format;
    app.set_width(candidate.width);
    app.shape.row_padding = 0;
    app.shape.bit_offset = 0;
    app.shape.byte_offset = candidate.start.min(app.document.len());
    app.top_row = 0;
    app.pan_x = 0.0;
    app.clamp_top_row();
    app.jump_to_offset(candidate.start);
    app.status = format!("Showing {}", candidate.description());
}

/// Show the image finder panel.
pub fn show_image_finder(state: &mut ImageFinderState, app: &mut ViewerApp, ui: &mut Ui) {
    poll(state, ui.ctx());
    let (_, len, what) = scope(app);
    ui.horizontal_wrapped(|ui| {
        let searching = state.pending.is_some();
        if ui
            .add_enabled(!searching, egui::Button::new(format!("Find images in {what} ({})", crate::compress::human_bytes(len))))
            .clicked()
        {
            start_search(state, app);
        }
        if searching {
            ui.spinner();
            ui.label(RichText::new("Sweeping widths and pixel formats…").color(theme::TEXT_DIM));
        }
    });

    let Some(candidates) = &state.candidates else {
        ui.label(
            RichText::new(
                "Looks for uncompressed bitmaps such as fonts, splash screens and framebuffers: tries 1-bit, 8-bit grey, RGB565, RGB and RGBA at widths from 16 to 2048 pixels, and ranks regions where each row resembles the next. Click a result to show it.",
            )
            .color(theme::TEXT_DIM),
        );
        return;
    };
    if candidates.is_empty() {
        ui.label(RichText::new("No uncompressed images found.").color(theme::TEXT_DIM));
        return;
    }
    ui.label(RichText::new(format!("{} candidates, best first", candidates.len())).small().color(theme::TEXT_DIM));

    let mut chosen = None;
    egui::ScrollArea::vertical().id_salt("image-finder-results").show(ui, |ui| {
        for (index, candidate) in candidates.iter().enumerate() {
            ui.horizontal(|ui| {
                score_bar(ui, candidate.score);
                let label = RichText::new(candidate.description()).monospace();
                let response = ui
                    .selectable_label(state.applied == Some(index), label)
                    .on_hover_text(format!("{} bytes per row; click to show it in the view", candidate.row_bytes()));
                if response.clicked() {
                    chosen = Some(index);
                }
            });
        }
    });
    if let Some(index) = chosen {
        apply_candidate(app, &candidates[index]);
        state.applied = Some(index);
    }
}

/// A small horizontal bar filled in proportion to a 0..1 score.
fn score_bar(ui: &mut Ui, score: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(SCORE_BAR_WIDTH, SCORE_BAR_HEIGHT), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 2.0, theme::SURFACE_RAISED);
    let mut filled = rect;
    filled.set_width(rect.width() * score.clamp(0.0, 1.0));
    painter.rect_filled(filled, 2.0, theme::ACCENT);
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    use super::*;
    use crate::app::Launch;
    use crate::document::Document;
    use crate::raster::PixelFormat;

    /// Longest a background job may take in a test.
    const JOB_TIMEOUT: Duration = Duration::from_secs(20);
    const IMAGE_START: usize = 32 * 1024;
    const IMAGE_WIDTH: usize = 160;
    const IMAGE_HEIGHT: usize = 90;

    type PanelHarness = Harness<'static, (ImageFinderState, ViewerApp)>;

    /// Random bytes around a smooth RGB picture.
    fn file_with_picture() -> Vec<u8> {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut noise = |len: usize| -> Vec<u8> {
            (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    (state >> 32) as u8
                })
                .collect()
        };
        let mut picture = Vec::new();
        for y in 0..IMAGE_HEIGHT {
            for x in 0..IMAGE_WIDTH {
                let (fx, fy) = (x as f32, y as f32);
                picture.push((128.0 + 100.0 * (fx / 9.0).sin()) as u8);
                picture.push((128.0 + 100.0 * (fy / 7.0).cos()) as u8);
                picture.push((128.0 + 60.0 * (fx / 5.0).sin() * (fy / 11.0).cos()) as u8);
            }
        }
        let before = noise(IMAGE_START);
        let after = noise(16 * 1024);
        [before, picture, after].concat()
    }

    fn harness_for(bytes: Vec<u8>) -> PanelHarness {
        let mut app = ViewerApp::new(Launch::default());
        app.document = Document::from_bytes(bytes);
        Harness::new_ui_state(
            |ui, (state, app): &mut (ImageFinderState, ViewerApp)| show_image_finder(state, app, ui),
            (ImageFinderState::default(), app),
        )
    }

    #[test]
    fn clicking_a_found_image_shows_it_in_the_view() {
        let mut harness = harness_for(file_with_picture());
        harness.step();
        harness.get_by_label_contains("Find images in whole file").click();
        harness.step();
        let started = Instant::now();
        while harness.state().0.pending.is_some() && started.elapsed() < JOB_TIMEOUT {
            thread::sleep(POLL_INTERVAL / 5);
            harness.step();
        }
        harness.step();
        let best = harness.state().0.candidates.as_ref().and_then(|found| found.first().cloned()).expect("a candidate");
        harness.get_by_label(&best.description()).click();
        harness.step();
        let app = &harness.state().1;
        assert_eq!(app.shape.format, PixelFormat::Rgb8);
        assert_eq!(app.shape.width, IMAGE_WIDTH);
        assert_eq!(app.shape.byte_offset, best.start);
        assert_eq!(app.cursor, best.start);
        assert!(best.start.abs_diff(IMAGE_START) < PixelFormat::Rgb8.bytes_per_pixel(), "{}", best.description());
        assert_eq!(harness.state().0.applied, Some(0));
    }
}
