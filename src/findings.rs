//! The findings panel: everything detected in and around the view, filtered
//! by text, category and confidence, plus the file's bookmarks.

use eframe::egui::{self, RichText, Sense, Ui, vec2};

use crate::app::ViewerApp;
use crate::plugin::{Category, Finding};
use crate::theme;

const LIST_HEIGHT: f32 = 220.0;
const MAX_ROWS: usize = 500;

/// Filter state kept by the app.
pub struct FindingsFilter {
    pub text: String,
    pub min_confidence: f32,
}

impl Default for FindingsFilter {
    fn default() -> Self {
        FindingsFilter { text: String::new(), min_confidence: 0.0 }
    }
}

fn passes(filter: &FindingsFilter, finding: &Finding) -> bool {
    if finding.confidence < filter.min_confidence {
        return false;
    }
    if filter.text.is_empty() {
        return true;
    }
    let haystack = format!("{} {} {} {}", finding.title, finding.detail, finding.id, finding.category.label()).to_lowercase();
    filter.text.split_whitespace().all(|word| haystack.contains(&word.to_lowercase()))
}

pub fn show_findings_panel(app: &mut ViewerApp, ui: &mut Ui) {
    let counts = app.pattern_counts();
    let total: usize = counts.iter().sum();
    let mut open = app.pattern_list_open;
    ui.horizontal(|ui| {
        let header = format!("Findings ({total})");
        if ui.selectable_label(open, RichText::new(header).strong()).clicked() {
            open = !open;
        }
        if !app.bookmarks.bookmarks.is_empty() {
            ui.label(RichText::new(format!("{} bookmarks", app.bookmarks.bookmarks.len())).small().color(theme::TEXT_DIM));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new("click to select · right-click for actions").small().color(theme::TEXT_DIM));
        });
    });
    app.pattern_list_open = open;
    if !open {
        return;
    }

    // Filters: text, confidence, and category chips that double as toggles.
    ui.horizontal(|ui| {
        ui.add(egui::TextEdit::singleline(&mut app.findings_filter.text).hint_text("filter…").desired_width(160.0));
        ui.label(RichText::new("min confidence").small().color(theme::TEXT_DIM));
        ui.add(egui::Slider::new(&mut app.findings_filter.min_confidence, 0.0..=1.0).show_value(false).fixed_decimals(1));
        ui.label(RichText::new(format!("{:.1}", app.findings_filter.min_confidence)).small());
    });
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(4.0, 4.0);
        for category in Category::ALL {
            let count = counts[category.index()];
            if count == 0 {
                continue;
            }
            let enabled = app.pattern_kinds[category.index()];
            let text = RichText::new(format!("{} {count}", category.label())).small().color(if enabled {
                theme::TEXT
            } else {
                theme::TEXT_DIM
            });
            let (rect, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
            ui.painter().rect_filled(rect, 2.0, if enabled { category.colour() } else { theme::OUTLINE });
            if ui.selectable_label(enabled, text).on_hover_text("Click to show or hide this category").clicked() {
                app.pattern_kinds[category.index()] = !enabled;
            }
        }
    });

    let visible: Vec<Finding> = app
        .patterns_in(0, usize::MAX)
        .filter(|finding| passes(&app.findings_filter, finding))
        .cloned()
        .collect();
    let mut chosen: Option<Finding> = None;
    let mut decompress: Option<Finding> = None;
    let mut bookmark: Option<Finding> = None;
    let mut play: Option<Finding> = None;
    let mut capture: Option<usize> = None;
    egui::ScrollArea::vertical().id_salt("findings-list").max_height(LIST_HEIGHT).show(ui, |ui| {
        for finding in visible.iter().take(MAX_ROWS) {
            let row = ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
                ui.painter().rect_filled(rect, 2.0, finding.category.colour());
                ui.monospace(RichText::new(format!("{:#010x}", finding.start)).color(theme::TEXT_DIM));
                let colour = if finding.weak() { theme::TEXT_DIM } else { theme::TEXT };
                let title = RichText::new(&finding.title).color(colour);
                let label = ui.add(egui::Label::new(title).sense(Sense::click()));
                if !finding.detail.is_empty() {
                    ui.add(egui::Label::new(RichText::new(&finding.detail).small().color(theme::TEXT_DIM)).truncate());
                }
                label
            });
            let label = row.inner;
            if label.clicked() {
                chosen = Some(finding.clone());
            }
            label.on_hover_text(finding.description()).context_menu(|ui| {
                if ui.button("Select").clicked() {
                    chosen = Some(finding.clone());
                    ui.close();
                }
                if finding.category == Category::Compressed && ui.button("Decompress").clicked() {
                    decompress = Some(finding.clone());
                    ui.close();
                }
                if matches!(finding.category, Category::Image | Category::Signature | Category::Document) && ui.button("View / play").clicked() {
                    play = Some(finding.clone());
                    ui.close();
                }
                if (finding.id == "pcap" || finding.id == "pcapng") && ui.button("Open in packet viewer").clicked() {
                    capture = Some(finding.start);
                    ui.close();
                }
                if ui.button("Bookmark").clicked() {
                    bookmark = Some(finding.clone());
                    ui.close();
                }
            });
        }
        if visible.len() > MAX_ROWS {
            ui.label(RichText::new(format!("… and {} more; narrow the filter", visible.len() - MAX_ROWS)).color(theme::TEXT_DIM));
        }
        if visible.is_empty() {
            ui.label(RichText::new("Nothing matches the filter in the scanned region").color(theme::TEXT_DIM));
        }
    });

    if let Some(finding) = chosen {
        app.select_pattern(&finding);
    }
    if let Some(finding) = decompress {
        app.select_pattern(&finding);
        app.toggle_compressed_view();
    }
    if let Some(finding) = play {
        app.set_cursor(finding.start, false);
        app.open_media();
    }
    if let Some(start) = capture {
        crate::panel_packets::open_capture_at(app, start);
    }
    if let Some(finding) = bookmark {
        app.add_bookmark(finding.start, finding.len, finding.title.clone());
    }

    show_bookmarks(app, ui);
    ui.separator();
}

fn show_bookmarks(app: &mut ViewerApp, ui: &mut Ui) {
    if app.bookmarks.bookmarks.is_empty() {
        return;
    }
    ui.label(RichText::new("Bookmarks").strong());
    let mut jump: Option<usize> = None;
    let mut remove: Option<usize> = None;
    egui::ScrollArea::vertical().id_salt("bookmark-list").max_height(120.0).show(ui, |ui| {
        for bookmark in app.bookmarks.bookmarks.clone() {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
                ui.painter().rect_filled(rect, 2.0, theme::CURSOR);
                ui.monospace(RichText::new(format!("{:#010x}", bookmark.offset)).color(theme::TEXT_DIM));
                if ui.add(egui::Label::new(&bookmark.name).sense(Sense::click())).on_hover_text(&bookmark.note).clicked() {
                    jump = Some(bookmark.offset);
                }
                if ui.small_button("x").on_hover_text("Remove bookmark").clicked() {
                    remove = Some(bookmark.offset);
                }
            });
        }
    });
    if let Some(offset) = jump {
        app.jump_to_bookmark(offset);
    }
    if let Some(offset) = remove {
        app.remove_bookmark(offset);
    }
}
