//! The findings panel: everything detected in and around the view, filtered
//! by text, category and confidence, plus the file's bookmarks.

use eframe::egui::{self, RichText, Sense, Ui, vec2};

use crate::app::ViewerApp;
use crate::bus::topics::FindingsPublished;
use crate::legend::{LayerKind, PinnedGroup};
use crate::plugin::{Category, Finding};
use crate::theme;

const LIST_HEIGHT: f32 = 220.0;
const MAX_ROWS: usize = 500;
/// How the producers of the window's own tools start. Their findings are
/// `bench.pinned` mirrored on the bus, so they are drawn from there, once.
const TOOL_PRODUCER_PREFIX: &str = "tool:";

impl ViewerApp {
    /// The findings callers published about the document shown with
    /// `findings.publish`: the person's pins, plugins', Ask's, MCP clients'
    /// and recipes'. They are read from the bus's facts, so publishing again
    /// under a key replaces a caller's findings, `findings.retract` removes
    /// them, and they go with the document. Oldest first, with who
    /// published them.
    pub fn published_findings(&self) -> Vec<(&str, &Finding)> {
        let document = self.document_id();
        let mut facts: Vec<_> = self
            .bus
            .facts()
            .filter(|fact| fact.draft.document.as_deref() == Some(document.as_str()) && !fact.producer().starts_with(TOOL_PRODUCER_PREFIX))
            .filter_map(|fact| fact.payload_as::<FindingsPublished>().map(|published| (fact.id, fact.producer(), published)))
            .collect();
        facts.sort_by_key(|(id, _, _)| *id);
        facts.into_iter().flat_map(|(_, producer, published)| published.findings.iter().map(move |finding| (producer, finding))).collect()
    }

    /// Every pinned finding with the legend group it is drawn in: the
    /// tools' pins, then the findings callers published. A published
    /// finding joins the group its id names (a segment, a checksum), or
    /// the Published group.
    pub fn pinned_findings(&self) -> Vec<(PinnedGroup, &Finding)> {
        let pinned = self.bench.pinned.iter().map(|finding| (PinnedGroup::of(&finding.id), finding));
        let published = self.published_findings().into_iter().map(|(_, finding)| {
            let group = match PinnedGroup::of(&finding.id) {
                PinnedGroup::Other => PinnedGroup::Published,
                group => group,
            };
            (group, finding)
        });
        pinned.chain(published).collect()
    }

    /// The pinned findings whose groups are shown.
    pub fn shown_pinned_findings(&self) -> Vec<&Finding> {
        self.pinned_findings().into_iter().filter(|(group, _)| self.layer_visible(LayerKind::Pinned(*group))).map(|(_, finding)| finding).collect()
    }
}

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
            ui.label(RichText::new("click to select · Cmd-click to add · right-click for actions").small().color(theme::TEXT_DIM));
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
    let mut added: Option<Finding> = None;
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
                if ui.input(|input| input.modifiers.command) {
                    added = Some(finding.clone());
                } else {
                    chosen = Some(finding.clone());
                }
            }
            label.on_hover_text(finding.description()).context_menu(|ui| {
                if ui.button("Select").clicked() {
                    chosen = Some(finding.clone());
                    ui.close();
                }
                // The operations act on the finding (or on the selection it is part of).
                if !app.is_selected(finding.start) {
                    app.select_finding(finding);
                }
                crate::selection_menu::menu_button(app, ui);
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
        app.select_finding(&finding);
    }
    if let Some(finding) = added {
        let len = finding.len.min(app.document.len().saturating_sub(finding.start));
        app.toggle_selection_range(finding.start, len);
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

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::api::{self, Caller};
    use crate::app::Launch;
    use crate::bus::Topic;

    fn app_with(bytes: &[u8]) -> ViewerApp {
        let mut app = ViewerApp::new(Launch::default());
        app.open_bytes(bytes.to_vec(), "test.bin".to_string());
        app.run_bus();
        app
    }

    fn finding(id: &str, start: usize, len: usize) -> Value {
        json!({"id": id, "source": "test", "category": "custom", "start": start, "len": len, "title": id, "detail": "", "confidence": 1.0, "fields": []})
    }

    fn publish(app: &mut ViewerApp, caller: &Caller, key: &str, findings: Vec<Value>) {
        api::call(app, caller, "findings.publish", json!({"findings": findings, "key": key})).unwrap();
        app.run_bus();
    }

    fn outlined(app: &mut ViewerApp) -> Vec<(usize, usize)> {
        let mut ranges = app.layer_ranges(LayerKind::Pinned(PinnedGroup::Published), 0, usize::MAX);
        ranges.sort_unstable();
        ranges
    }

    #[test]
    fn findings_published_by_the_person_a_plugin_or_a_client_are_outlined_and_listed() {
        let mut app = app_with(&[0u8; 256]);
        publish(&mut app, &Caller::Panel, "", vec![finding("mine", 0, 4)]);
        publish(&mut app, &Caller::Plugin("sync_word.lua".into()), "sync", vec![finding("sync", 16, 2)]);
        publish(&mut app, &Caller::Mcp("claude-code".into()), "", vec![finding("claude", 32, 8)]);
        assert_eq!(outlined(&mut app), [(0, 4), (16, 2), (32, 8)]);
        let producers: Vec<&str> = app.published_findings().into_iter().map(|(producer, _)| producer).collect();
        assert_eq!(producers, ["panel", "plugin:sync_word.lua", "mcp:claude-code"], "oldest first, with who published them");
        assert!(app.patterns_in(0, usize::MAX).any(|listed| listed.id == "claude"), "listed with the findings");
        assert!(app.active_layers().iter().any(|layer| layer.kind == LayerKind::Pinned(PinnedGroup::Published) && layer.count == "3"));
    }

    #[test]
    fn publishing_again_under_a_key_replaces_and_retracting_removes() {
        let mut app = app_with(&[0u8; 256]);
        let plugin = Caller::Plugin("sync_word.lua".into());
        publish(&mut app, &plugin, "sync", vec![finding("sync", 16, 2), finding("sync", 48, 2)]);
        publish(&mut app, &plugin, "sync", vec![finding("sync", 80, 2)]);
        publish(&mut app, &plugin, "other", vec![finding("other", 100, 1)]);
        assert_eq!(outlined(&mut app), [(80, 2), (100, 1)], "the same key replaces, another key is kept beside it");
        api::call(&mut app, &plugin, "findings.retract", json!({"key": "sync"})).unwrap();
        app.run_bus();
        assert_eq!(outlined(&mut app), [(100, 1)]);
        app.open_bytes(vec![0; 256], "other.bin".to_string());
        app.run_bus();
        assert!(app.published_findings().is_empty(), "they go with the document");
    }

    #[test]
    fn a_published_finding_joins_the_group_its_id_names_and_is_never_published_again() {
        let mut app = app_with(&[0u8; 256]);
        publish(&mut app, &Caller::Panel, "segment:", vec![finding("segment:0", 0, 64)]);
        assert_eq!(app.layer_ranges(LayerKind::Pinned(PinnedGroup::Segments), 0, usize::MAX), [(0, 64)]);
        assert!(app.bench.pinned.is_empty(), "kept apart from the tools' own pins");
        let cursor = app.bus.cursor();
        app.run_bus();
        app.run_bus();
        let again = app.bus.changed_since(cursor).messages.into_iter().filter(|message| message.topic() == Topic::FindingsPublished).count();
        assert_eq!(again, 0, "the window does not publish them again");
        assert_eq!(app.bus.facts().filter(|fact| fact.topic() == Topic::FindingsPublished).count(), 1);
    }
}
