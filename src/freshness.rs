//! Keeping derived views in step with edits.
//!
//! Every tool that computes something from the document's bytes notes the
//! document version its result describes. After an edit, once the document
//! has been still for a moment, the cheap ones (segments, an applied
//! template, record columns, a small trigram cloud) work themselves out
//! again; the expensive ones (the report, dot plot, statistics, unpacked
//! tree, image finder, comparison and the like) show an "Out of date —
//! Refresh" chip instead, and their tab is marked, so stale results are
//! never shown silently. The packet viewer follows the document itself.
//!
//! Edits are heard of through the bus's `document.edited`, whether or not
//! any tool is showing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText, Ui};

use crate::app::ViewerApp;
use crate::bus::Message;
use crate::dock::DockTab;
use crate::theme;

/// How long the document must stay unchanged before cheap views refresh.
pub const SETTLE_TIME: Duration = Duration::from_millis(400);
/// Largest document whose trigram cloud is counted again automatically.
const TRIGRAM_AUTOMATIC_LIMIT: usize = 4 * 1024 * 1024;

/// How a tool catches up with an edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refresh {
    /// Worked out again by itself a moment after the last edit.
    Automatic,
    /// Marked out of date, with a Refresh chip.
    OnRequest,
}

/// The document versions the tools' results describe, and when the
/// document last changed.
#[derive(Debug, Default)]
pub struct Freshness {
    described: HashMap<DockTab, u64>,
    changed_at: Option<Instant>,
}

impl Freshness {
    /// A tool's result now describes document version `version`.
    pub fn note(&mut self, tab: DockTab, version: u64) {
        self.described.insert(tab, version);
    }

    /// A tool's result was thrown away.
    pub fn forget(&mut self, tab: DockTab) {
        self.described.remove(&tab);
    }

    /// The document was replaced: no result describes it.
    pub fn forget_all(&mut self) {
        self.described.clear();
        self.changed_at = None;
    }

    /// The version `tab`'s result describes, if it has one.
    pub fn described(&self, tab: DockTab) -> Option<u64> {
        self.described.get(&tab).copied()
    }

    /// The document was just edited.
    fn edited(&mut self) {
        self.changed_at = Some(Instant::now());
    }

    /// How long until the edits count as settled, or `None` once they do.
    fn time_to_settle(&self) -> Option<Duration> {
        let waited = self.changed_at?.elapsed();
        (waited < SETTLE_TIME).then(|| SETTLE_TIME - waited)
    }
}

impl ViewerApp {
    /// `tab`'s result now describes the document as it is.
    pub fn note_tool_result(&mut self, tab: DockTab) {
        let version = self.document.version();
        self.bench.freshness.note(tab, version);
    }

    /// How `tab` catches up with edits, or `None` for tools that do not
    /// keep results of the bytes (or follow the document themselves).
    pub fn refresh_kind(&self, tab: DockTab) -> Option<Refresh> {
        match tab {
            DockTab::StructureMap | DockTab::Template | DockTab::Columns | DockTab::Checksums => Some(Refresh::Automatic),
            DockTab::Trigrams if self.document.len() <= TRIGRAM_AUTOMATIC_LIMIT => Some(Refresh::Automatic),
            DockTab::Trigrams | DockTab::Report | DockTab::DotPlot | DockTab::Statistics | DockTab::Unpacked | DockTab::Images | DockTab::Compare | DockTab::Protocol | DockTab::Strings | DockTab::Xor | DockTab::Diff => {
                Some(Refresh::OnRequest)
            }
            _ => None,
        }
    }

    /// Whether `tab` shows a result computed before the latest edit.
    pub fn tool_out_of_date(&self, tab: DockTab) -> bool {
        self.refresh_kind(tab).is_some() && self.bench.freshness.described(tab).is_some_and(|version| version != self.document.version())
    }

    /// Work `tab`'s result out again from the document as it is now.
    pub fn refresh_tool(&mut self, tab: DockTab) {
        match tab {
            DockTab::Report => self.start_report(),
            DockTab::Unpacked => self.start_unpack(),
            DockTab::Statistics => crate::analysis_stats::start_statistics(self),
            DockTab::Strings => crate::analysis_stats::start_strings(self),
            DockTab::Protocol => crate::analysis_tools::start_protocol(self),
            DockTab::Template => self.reapply_template(),
            DockTab::Columns => self.bench.tools.columns = None,
            DockTab::Checksums => {
                // Digests are worked out again when shown; a checksum search
                // of the old bytes is dropped rather than shown stale.
                self.bench.analysis.digests = None;
                self.bench.analysis.checksum_matches = None;
            }
            DockTab::Xor => crate::analysis_stats::refresh_xor(self),
            DockTab::Diff => {
                if let Some(other) = self.bench.analysis.diff_other_sheet.clone() {
                    crate::analysis_tabs::start_diff_with_sheet(self, &other);
                } else if let Some(path) = self.bench.analysis.diff_other.clone() {
                    crate::analysis_tabs::start_diff(self, path.into());
                }
            }
            DockTab::StructureMap => crate::panels::with(self, |p| &mut p.structure_map, crate::panel_structure_map::refresh),
            DockTab::DotPlot => crate::panels::with(self, |p| &mut p.dot_plot, crate::panel_dotplot::start_plot),
            DockTab::Images => crate::panels::with(self, |p| &mut p.images, crate::panel_image_finder::start_search),
            DockTab::Compare => crate::panels::with(self, |p| &mut p.compare, crate::panel_compare::refresh),
            DockTab::Trigrams => crate::panels::with(self, |p| &mut p.trigrams, crate::panel_trigram::start_counting),
            _ => return,
        }
        // Noted now, so a refresh that finishes later is not asked for twice.
        self.note_tool_result(tab);
    }

    /// Once the document has been still for a moment after an edit, bring
    /// the cheap views up to date. Called every frame.
    pub fn follow_edits(&mut self, ctx: &egui::Context) {
        if let Some(wait) = self.bench.freshness.time_to_settle() {
            ctx.request_repaint_after(wait);
            return;
        }
        let automatic: Vec<DockTab> = DockTab::ALL
            .into_iter()
            .filter(|&tab| self.refresh_kind(tab) == Some(Refresh::Automatic) && self.tool_out_of_date(tab))
            .collect();
        for tab in automatic {
            self.refresh_tool(tab);
        }
    }
}

/// The reaction to `document.edited`: start waiting for the edits to settle.
pub fn note_edit(app: &mut ViewerApp, _message: &Arc<Message>) {
    app.bench.freshness.edited();
}

/// Above a tool whose result is older than the document: a chip saying so,
/// with Refresh (or, for a tool that refreshes itself, a note that it will).
pub fn show_out_of_date_chip(app: &mut ViewerApp, ui: &mut Ui, tab: DockTab) {
    if !app.tool_out_of_date(tab) {
        return;
    }
    let automatic = app.refresh_kind(tab) == Some(Refresh::Automatic);
    let mut refresh = false;
    egui::Frame::new()
        .fill(theme::CURSOR.gamma_multiply(0.18))
        .stroke(egui::Stroke::new(1.0, theme::CURSOR))
        .corner_radius(4)
        .inner_margin(egui::Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if automatic {
                    ui.label(RichText::new("Edited — updating when the edits settle…").small().color(theme::CURSOR));
                } else {
                    ui.label(RichText::new("Out of date").small().strong().color(theme::CURSOR))
                        .on_hover_text("The document has been edited since this was worked out");
                    refresh = ui.small_button("Refresh").on_hover_text("Work this out again from the document as it is now").clicked();
                }
            });
        });
    if refresh {
        app.refresh_tool(tab);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_remember_the_version_they_describe_until_the_document_is_replaced() {
        let mut freshness = Freshness::default();
        assert_eq!(freshness.described(DockTab::Report), None);
        freshness.note(DockTab::Report, 7);
        assert_eq!(freshness.described(DockTab::Report), Some(7));
        freshness.forget(DockTab::Report);
        assert_eq!(freshness.described(DockTab::Report), None);
        freshness.note(DockTab::Statistics, 3);
        freshness.forget_all();
        assert_eq!(freshness.described(DockTab::Statistics), None);
    }

    #[test]
    fn edits_count_as_settled_once_the_document_has_been_still_for_a_moment() {
        let mut freshness = Freshness::default();
        assert_eq!(freshness.time_to_settle(), None, "nothing edited yet");
        freshness.edited();
        assert!(freshness.time_to_settle().is_some_and(|wait| wait <= SETTLE_TIME));
        freshness.changed_at = Instant::now().checked_sub(SETTLE_TIME);
        assert_eq!(freshness.time_to_settle(), None);
    }

    #[test]
    fn an_edit_heard_of_on_the_bus_starts_the_wait_whether_or_not_a_tool_is_showing() {
        let mut app = ViewerApp::new(crate::app::Launch::default());
        app.document = crate::document::Document::from_bytes(vec![0; 16]);
        app.run_bus();
        assert_eq!(app.bench.freshness.time_to_settle(), None);
        app.document.overwrite(0, b"x");
        assert_eq!(app.bench.freshness.time_to_settle(), None, "not heard of until the bus is delivered");
        app.run_bus();
        assert!(app.bench.freshness.time_to_settle().is_some(), "document.edited was heard");
        app.run_bus();
        app.bench.freshness.changed_at = Instant::now().checked_sub(SETTLE_TIME);
        app.run_bus();
        assert_eq!(app.bench.freshness.time_to_settle(), None, "no new edit, so still settled");
    }
}
