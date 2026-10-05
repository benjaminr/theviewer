//! Bottom panel showing the period scan: a periodogram you can click, and the
//! ranked candidate widths it produced.

use eframe::egui::{self, Align2, FontId, Rect, RichText, Sense, Stroke, Ui, pos2, vec2};

use crate::analysis::Candidate;
use crate::app::ViewerApp;
use crate::theme;

const PLOT_HEIGHT: f32 = 110.0;

pub fn show_structure_panel(app: &mut ViewerApp, ui: &mut Ui) {
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Structure").strong());
        match &app.period_scan {
            Some(scan) => {
                ui.label(
                    RichText::new(format!(
                        "period scan of {} KiB from {:#x}, lags 1–{}",
                        scan.window_len / 1024,
                        scan.window_start,
                        scan.scores.len().saturating_sub(1)
                    ))
                    .color(theme::TEXT_DIM),
                );
            }
            None if app.scan_pending => {
                ui.spinner();
                ui.label(RichText::new("scanning…").color(theme::TEXT_DIM));
            }
            None => {
                ui.label(RichText::new("no scan yet").color(theme::TEXT_DIM));
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("Hide").on_hover_text("Hide panel").clicked() {
                app.close_panel(crate::layout::Pane::PeriodChart);
            }
            if ui.button("Rescan").on_hover_text("Scan again from the current origin").clicked() {
                app.start_period_scan();
            }
            ui.add(egui::DragValue::new(&mut app.scan_max_period).range(16..=16384).suffix(" B max"))
                .on_hover_text("Largest period to test. Larger is slower.");
            if app.scan_pending && app.period_scan.is_some() {
                ui.spinner();
            }
        });
    });

    let Some(scan) = app.period_scan.clone() else {
        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "Detect width scans the bytes after the view origin for repeating periods. \
                 Peaks in the chart are candidate row strides; click one to apply it.",
            )
            .color(theme::TEXT_DIM),
        );
        return;
    };

    // ---- candidate chips --------------------------------------------------
    ui.horizontal_wrapped(|ui| {
        if scan.candidates.is_empty() {
            ui.label(RichText::new("No clear period. Try a different origin, a larger max period, or look at the entropy strip for a structured region.").color(theme::TEXT_DIM));
        }
        for candidate in scan.candidates.iter().take(10) {
            let (width, padding) = app.width_for_period(candidate.period);
            let mut label = format!("{} B = {} px", candidate.period, width);
            if padding > 0 {
                label.push_str(&format!(" +{padding}"));
            }
            if let Some(base) = candidate.multiple_of {
                label.push_str(&format!("  (×{})", candidate.period / base));
            }
            let text = if candidate.multiple_of.is_some() {
                RichText::new(label).color(theme::TEXT_DIM)
            } else {
                RichText::new(label).color(theme::TEXT)
            };
            let response = ui.button(text).on_hover_ui(|ui| describe_candidate(ui, candidate));
            if response.clicked() {
                app.apply_period(candidate.period);
            }
        }
    });

    // ---- periodogram --------------------------------------------------------
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), PLOT_HEIGHT), Sense::click_and_drag());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, theme::BACKGROUND);
    let lags = scan.scores.len();
    if lags < 3 || rect.width() < 10.0 {
        return;
    }
    let scores = &scan.scores[1..];
    let (low, high) = scores.iter().fold((f32::MAX, f32::MIN), |(lo, hi), &s| (lo.min(s), hi.max(s)));
    let span = (high - low).max(1e-6);
    let plot = rect.shrink2(vec2(6.0, 6.0));
    let x_of = |lag: usize| plot.min.x + (lag as f32 - 1.0) / (lags as f32 - 2.0).max(1.0) * plot.width();
    let y_of = |score: f32| plot.max.y - (score - low) / span * plot.height();

    // Baseline.
    let baseline_y = y_of(scan.baseline);
    painter.line_segment(
        [pos2(plot.min.x, baseline_y), pos2(plot.max.x, baseline_y)],
        Stroke::new(1.0, theme::OUTLINE),
    );

    // Curve: one segment per horizontal pixel, taking the max within the bucket.
    let columns = plot.width().max(1.0) as usize;
    let mut points = Vec::with_capacity(columns + 1);
    for column in 0..=columns {
        let lag_start = 1 + column * (lags - 1) / (columns + 1);
        let lag_end = (1 + (column + 1) * (lags - 1) / (columns + 1)).max(lag_start + 1).min(lags);
        let best = scan.scores[lag_start..lag_end].iter().copied().fold(f32::MIN, f32::max);
        points.push(pos2(plot.min.x + column as f32 / columns as f32 * plot.width(), y_of(best)));
    }
    painter.add(egui::Shape::line(points, Stroke::new(1.0, theme::ACCENT_DIM)));

    // Candidate markers.
    for candidate in &scan.candidates {
        let x = x_of(candidate.period);
        let colour = if candidate.multiple_of.is_some() { theme::TEXT_DIM } else { theme::ACCENT };
        painter.line_segment([pos2(x, y_of(candidate.score)), pos2(x, plot.max.y)], Stroke::new(1.0, colour));
        painter.circle_filled(pos2(x, y_of(candidate.score)), 3.0, colour);
    }

    // Hover readout and click-to-apply.
    if let Some(pointer) = response.hover_pos() {
        let fraction = ((pointer.x - plot.min.x) / plot.width()).clamp(0.0, 1.0);
        let lag = (1.0 + fraction * (lags as f32 - 2.0)).round() as usize;
        let lag = lag.clamp(1, lags - 1);
        let score = scan.scores[lag];
        let x = x_of(lag);
        painter.line_segment([pos2(x, plot.min.y), pos2(x, plot.max.y)], Stroke::new(1.0, theme::CURSOR));
        let (width, padding) = app.width_for_period(lag);
        let label = format!("{lag} B  score {score:.3}  = {width} px{}", if padding > 0 { format!(" +{padding} pad") } else { String::new() });
        let anchor = if x > rect.center().x { Align2::RIGHT_TOP } else { Align2::LEFT_TOP };
        let offset = if x > rect.center().x { -6.0 } else { 6.0 };
        let galley = painter.layout_no_wrap(label, FontId::proportional(12.0), theme::TEXT);
        let text_rect = anchor.anchor_size(pos2(x + offset, rect.min.y + 4.0), galley.size());
        painter.rect_filled(text_rect.expand(3.0), 3.0, theme::SURFACE_RAISED);
        painter.galley(text_rect.min, galley, theme::TEXT);
        if response.clicked() {
            app.apply_period(lag);
        }
    }
    let _ = Rect::NOTHING;
}

fn describe_candidate(ui: &mut Ui, candidate: &Candidate) {
    ui.label(format!("Period {} bytes", candidate.period));
    ui.label(format!("Similarity {:.3}", candidate.score));
    ui.label(format!("Prominence {:.1} σ above baseline", candidate.prominence));
    ui.label(format!("Column entropy gain {:.2} bits/byte", candidate.column_gain));
    if let Some(base) = candidate.multiple_of {
        ui.label(format!("A multiple of the {base} byte period"));
    }
    ui.label(RichText::new("Click to set the width (and padding if the period is not a whole number of pixels)").color(theme::TEXT_DIM));
}
