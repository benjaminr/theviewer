//! Dock panel: a self-similarity dot plot of the selection or the whole file.
//!
//! The plot is computed on a background thread ([`crate::dotplot::compute`])
//! and shown as a texture. Hovering a cell names the two blocks it compares;
//! a click jumps to the block on the horizontal axis and a right-click to the
//! block on the vertical axis. The cursor's block is marked on both axes.

use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Color32, ColorImage, Rect, RichText, Sense, Stroke, TextureHandle, TextureOptions, Ui, pos2, vec2};

use crate::app::ViewerApp;
use crate::dotplot::{self, DotPlot, SimilarityMode};
use crate::raster::Palette;
use crate::theme;

/// Largest range plotted; anything beyond is left out.
const DOT_PLOT_LIMIT: usize = 64 * 1024 * 1024;
/// How often to look for a finished plot while one is being computed.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Smallest side, in points, the plot is drawn at.
const MIN_PLOT_SIDE: f32 = 120.0;
/// Space kept below the plot for the caption.
const PLOT_BOTTOM_MARGIN: f32 = 8.0;
/// Exponent applied to similarities before colouring, so faint likeness shows.
const CONTRAST_GAMMA: f32 = 0.5;
/// Opacity of the cursor's crosshair, out of 255.
const CROSSHAIR_ALPHA: u8 = 140;

/// Everything the dot plot panel keeps between frames.
#[derive(Default)]
pub struct DotPlotState {
    /// The similarity measure used for the next plot.
    pub mode: SimilarityMode,
    pending: Option<Receiver<DotPlot>>,
    /// The most recent finished plot.
    pub plot: Option<DotPlot>,
    texture: Option<TextureHandle>,
}

/// The selection, else the whole file, capped, with a word for which.
fn scope(app: &ViewerApp) -> (usize, usize, &'static str) {
    match app.selection() {
        Some((start, len)) => (start, len.min(DOT_PLOT_LIMIT), "selection"),
        None => (0, app.document.len().min(DOT_PLOT_LIMIT), "whole file"),
    }
}

fn start_plot(state: &mut DotPlotState, app: &mut ViewerApp) {
    let (start, len, _) = scope(app);
    let bytes = app.document.read_range(start, len);
    let mode = state.mode;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        // The receiver may be gone if the panel was closed; nothing to do then.
        let _ = sender.send(dotplot::compute(&bytes, start, mode));
    });
    state.pending = Some(receiver);
}

fn poll(state: &mut DotPlotState, ctx: &egui::Context) {
    let Some(receiver) = &state.pending else { return };
    match receiver.try_recv() {
        Ok(plot) => {
            state.texture = (!plot.is_empty()).then(|| similarity_texture(ctx, &plot));
            state.plot = Some(plot);
            state.pending = None;
        }
        Err(mpsc::TryRecvError::Empty) => ctx.request_repaint_after(POLL_INTERVAL),
        Err(mpsc::TryRecvError::Disconnected) => state.pending = None,
    }
}

/// One pixel per cell, coloured with the Inferno ramp after a gamma lift.
fn similarity_texture(ctx: &egui::Context, plot: &DotPlot) -> TextureHandle {
    let lut = Palette::Inferno.lut();
    let pixels: Vec<Color32> = plot
        .values
        .iter()
        .map(|&value| lut[(value.clamp(0.0, 1.0).powf(CONTRAST_GAMMA) * 255.0).round() as usize])
        .collect();
    ctx.load_texture("dot-plot", ColorImage::new([plot.cells, plot.cells], pixels), TextureOptions::NEAREST)
}

/// Show the dot plot panel.
pub fn show_dot_plot(state: &mut DotPlotState, app: &mut ViewerApp, ui: &mut Ui) {
    poll(state, ui.ctx());
    let (_, len, what) = scope(app);
    ui.horizontal_wrapped(|ui| {
        if ui.button(format!("Plot {what} ({})", crate::compress::human_bytes(len))).clicked() {
            start_plot(state, app);
        }
        egui::ComboBox::from_id_salt("dot-plot-mode").selected_text(state.mode.label()).show_ui(ui, |ui| {
            for mode in SimilarityMode::ALL {
                ui.selectable_value(&mut state.mode, mode, mode.label()).on_hover_text(mode.description());
            }
        });
        if state.pending.is_some() {
            ui.spinner();
            ui.label(RichText::new("Comparing blocks…").color(theme::TEXT_DIM));
        }
    });

    let (Some(plot), Some(texture)) = (&state.plot, &state.texture) else {
        let message = if state.plot.as_ref().is_some_and(DotPlot::is_empty) {
            "Too few bytes to plot; select a larger range."
        } else {
            "Compares every part of the data with every other. Repeated content shows as lines parallel to the diagonal, long runs of one kind of data as bright squares. Click a cell to jump to that block."
        };
        ui.label(RichText::new(message).color(theme::TEXT_DIM));
        return;
    };

    ui.label(
        RichText::new(format!(
            "{} · {} × {} blocks of {} from {:#x} · click jumps to the column's block, right-click to the row's",
            plot.mode.label(),
            plot.cells,
            plot.cells,
            crate::compress::human_bytes(plot.block_size),
            plot.start
        ))
        .small()
        .color(theme::TEXT_DIM),
    );

    let side = ui.available_width().min(ui.available_height() - PLOT_BOTTOM_MARGIN).max(MIN_PLOT_SIDE);
    let (rect, response) = ui.allocate_exact_size(vec2(side, side), Sense::click());
    let painter = ui.painter_at(rect);
    painter.image(texture.id(), rect, Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)), Color32::WHITE);
    draw_cursor_crosshair(&painter, rect, plot, app.cursor);

    let cell_at = |position: egui::Pos2| {
        let column = ((position.x - rect.min.x) / side * plot.cells as f32) as usize;
        let row = ((position.y - rect.min.y) / side * plot.cells as f32) as usize;
        (row.min(plot.cells - 1), column.min(plot.cells - 1))
    };
    let mut jump = None;
    if let Some(position) = response.interact_pointer_pos()
        && let (row, column) = cell_at(position)
        && let Some((row_offset, column_offset)) = plot.cell_offsets(row, column)
    {
        if response.clicked() {
            jump = Some((column_offset, row_offset));
        } else if response.secondary_clicked() {
            jump = Some((row_offset, column_offset));
        }
    }
    if let Some(position) = response.hover_pos() {
        let (row, column) = cell_at(position);
        if let Some((row_offset, column_offset)) = plot.cell_offsets(row, column) {
            response.on_hover_text(format!(
                "Block at {column_offset:#x} (column) vs block at {row_offset:#x} (row): {:.0}% alike",
                plot.value(row, column) * 100.0
            ));
        }
    }
    if let Some((target, other)) = jump {
        app.jump_to_offset(target);
        app.status = format!("Jumped to {target:#x}; the compared block is at {other:#x}");
    }
}

/// Mark the block holding the cursor on both axes.
fn draw_cursor_crosshair(painter: &egui::Painter, rect: Rect, plot: &DotPlot, cursor: usize) {
    if cursor < plot.start || cursor >= plot.start + plot.len || plot.block_size == 0 {
        return;
    }
    let index = (cursor - plot.start) / plot.block_size;
    let cell = rect.width() / plot.cells as f32;
    let centre = (index as f32 + 0.5) * cell;
    let colour = Color32::from_rgba_unmultiplied(theme::CURSOR.r(), theme::CURSOR.g(), theme::CURSOR.b(), CROSSHAIR_ALPHA);
    let stroke = Stroke::new(1.0, colour);
    painter.vline(rect.min.x + centre, rect.y_range(), stroke);
    painter.hline(rect.x_range(), rect.min.y + centre, stroke);
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    use super::*;
    use crate::app::Launch;
    use crate::document::Document;

    /// Longest a background job may take in a test.
    const JOB_TIMEOUT: Duration = Duration::from_secs(20);

    type PanelHarness = Harness<'static, (DotPlotState, ViewerApp)>;

    fn harness_for(bytes: Vec<u8>) -> PanelHarness {
        let mut app = ViewerApp::new(Launch::default());
        app.document = Document::from_bytes(bytes);
        Harness::new_ui_state(|ui, (state, app): &mut (DotPlotState, ViewerApp)| show_dot_plot(state, app, ui), (DotPlotState::default(), app))
    }

    fn plot_whole_file(harness: &mut PanelHarness) {
        harness.step();
        harness.get_by_label_contains("Plot whole file").click();
        harness.step();
        let started = Instant::now();
        while harness.state().0.pending.is_some() && started.elapsed() < JOB_TIMEOUT {
            thread::sleep(POLL_INTERVAL / 5);
            harness.step();
        }
        harness.step();
    }

    #[test]
    fn plotting_the_whole_file_from_the_button_draws_a_full_grid() {
        let bytes: Vec<u8> = (0..64 * 1024u32).map(|index| (index % 251) as u8).collect();
        let mut harness = harness_for(bytes);
        plot_whole_file(&mut harness);
        let plot = harness.state().0.plot.as_ref().expect("a finished plot");
        assert_eq!(plot.cells, dotplot::MAX_CELLS);
        assert!(harness.state().0.texture.is_some());
    }

    #[test]
    fn an_empty_document_explains_that_there_is_nothing_to_plot() {
        let mut harness = harness_for(Vec::new());
        plot_whole_file(&mut harness);
        assert!(harness.query_by_label_contains("Too few bytes").is_some());
    }
}
