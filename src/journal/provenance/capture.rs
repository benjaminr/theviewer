//! Capturing provenance in the window: the anchors of values the person
//! took from a search match, a finding, a structure field or the
//! selection, for the call their action makes.
//!
//! An action that makes one call through `ViewerApp::perform` runs inside
//! [`ViewerApp::with_provenance`], which is what
//! `ViewerApp::perform_derived` does for a call made directly: the call's
//! journal entry carries the anchors as `derived_from`.

use serde_json::Value;

use super::{finding_anchor, findings_up_to, needle_of, nth_match, pair_anchors, selection_anchors, structure_anchor, with_part};
use crate::app::ViewerApp;
use crate::journal::anchors::{Anchor, Part};
use crate::journal::{self, DerivedFrom};
use crate::plugin::Finding;
use crate::selection::Selection;

/// Most matches "All matches" anchors one by one; more are left literal.
const MOST_MATCHES_ANCHORED: usize = 256;

/// Where `selection.set` takes the range it selects.
const SELECTED_RANGE: &str = "selection.range";

impl ViewerApp {
    /// Run `action`, which makes one call through the API, so that call's
    /// journal entry carries `derived_from`; what `perform_derived` does for
    /// a call made directly.
    pub fn with_provenance<T>(&mut self, derived_from: DerivedFrom, action: impl FnOnce(&mut ViewerApp) -> T) -> T {
        if derived_from.is_empty() {
            return action(self);
        }
        self.journal.set_pending_provenance(derived_from);
        let done = action(self);
        // An action that called nothing leaves nothing for the next call.
        self.journal.take_pending_provenance();
        done
    }

    /// Where a selected match of the Find box's query at `at` came from: the
    /// nth match of the needle, or, past [`super::MOST_MATCHES_COUNTED`]
    /// matches, the `search.find` read that found it (moved into the
    /// journal).
    pub fn match_provenance(&mut self, at: usize) -> DerivedFrom {
        let Ok(bytes) = crate::search::needle_for(self.search_mode, &self.search_text, self.search_little_endian) else { return DerivedFrom::new() };
        if let Some(nth) = nth_match(&mut self.document, &bytes, at) {
            let found = Anchor::Find { find: needle_of(self.search_mode, &self.search_text, &bytes), nth, part: None };
            return pair_anchors(SELECTED_RANGE, found.clone(), Some(with_part(&found, Part::Len)));
        }
        let read = self.journal.reads().next_back().filter(|read| read.method == "search.find" && read.result.as_ref().and_then(|result| result["at"].as_u64()) == Some(at as u64));
        let Some(step) = read.map(|read| read.step) else { return DerivedFrom::new() };
        if !journal::promote(self, step) {
            return DerivedFrom::new();
        }
        pair_anchors(SELECTED_RANGE, Anchor::Step { step, path: "result.at".into() }, None)
    }

    /// Where each of the matches of the Find box's query at `matches`,
    /// selected together as ranges, came from: the nth match of the
    /// needle, for up to [`MOST_MATCHES_ANCHORED`] matches that do not
    /// touch (touching ones are merged into one range).
    pub fn all_matches_provenance(&mut self, matches: &[usize]) -> DerivedFrom {
        let Ok(bytes) = crate::search::needle_for(self.search_mode, &self.search_text, self.search_little_endian) else { return DerivedFrom::new() };
        let apart = matches.windows(2).all(|pair| pair[0] + bytes.len() < pair[1]);
        if matches.len() > MOST_MATCHES_ANCHORED || !apart {
            return DerivedFrom::new();
        }
        let needle = needle_of(self.search_mode, &self.search_text, &bytes);
        let mut derived_from = DerivedFrom::new();
        for nth in 0..matches.len() {
            let found = Anchor::Find { find: needle.clone(), nth, part: None };
            let path = if matches.len() == 1 { SELECTED_RANGE.to_string() } else { format!("selection.ranges[{nth}]") };
            derived_from.extend(pair_anchors(&path, found.clone(), Some(with_part(&found, Part::Len))));
        }
        derived_from
    }

    /// Where the selection of `finding`'s bytes, `start` and `len`, came
    /// from: the finding, as `findings.query` counts it.
    pub fn finding_provenance(&mut self, finding: &Finding, start: usize, len: usize) -> DerivedFrom {
        if start != finding.start || finding.end() > crate::api::MAX_CALL_BYTES {
            return DerivedFrom::new();
        }
        let doc = self.document_id();
        let findings = findings_up_to(self, &doc, finding.end());
        let Some(anchor) = finding_anchor(&findings, finding) else { return DerivedFrom::new() };
        let len_anchor = (len == finding.len).then(|| with_part(&anchor, Part::Len));
        pair_anchors(SELECTED_RANGE, anchor, len_anchor)
    }

    /// Where the selection of a field of the structure at the cursor,
    /// `start` and `len`, came from: the field, when a parser recognised
    /// the structure.
    pub fn field_provenance(&self, structure: &Finding, start: usize, len: usize) -> DerivedFrom {
        let by_a_parser = self.registry.parsers().iter().any(|parser| parser.id() == structure.id);
        let Some(anchor) = structure_anchor(structure, start, len).filter(|_| by_a_parser) else { return DerivedFrom::new() };
        let len_anchor = (len > 0).then(|| with_part(&anchor, Part::Len));
        pair_anchors(SELECTED_RANGE, anchor, len_anchor)
    }

    /// Where a call's span came from when it is the one range selected:
    /// `ranges: [[start, len]]` or `start` and `len` equal to the
    /// selection. A step that selected it went through `selection.set`, so
    /// a recipe selects it again before this step.
    pub fn selection_call_provenance(&self, params: &Value) -> DerivedFrom {
        let Some(Selection::Range(start, len)) = self.current_selection() else { return DerivedFrom::new() };
        let range = serde_json::json!([[start, len]]);
        if params.get("ranges") == Some(&range) {
            return selection_anchors("ranges[0][0]", "ranges[0][1]");
        }
        if params.get("start") == Some(&serde_json::json!(start)) && params.get("len") == Some(&serde_json::json!(len)) {
            return selection_anchors("start", "len");
        }
        DerivedFrom::new()
    }

    /// Where a split's `length_field` came from: each of its settings equal
    /// to what the latest `packets.detect_length_field` found, cited from
    /// that step (a read moved into the journal). Its `max_frame` is the
    /// person's own.
    pub fn length_field_provenance(&mut self, params: &Value) -> DerivedFrom {
        let Some(given) = params.get("length_field").and_then(Value::as_object) else { return DerivedFrom::new() };
        let journal = &self.journal;
        let latest = journal.entries().chain(journal.reads()).filter(|entry| entry.method == "packets.detect_length_field" && entry.outcome.is_ok()).max_by_key(|entry| entry.step);
        let Some((step, found)) = latest.and_then(|entry| Some((entry.step, entry.result.as_ref()?.get("length_field")?.as_object()?.clone()))) else { return DerivedFrom::new() };
        let derived_from: DerivedFrom = given
            .iter()
            .filter(|(key, value)| key.as_str() != "max_frame" && found.get(key.as_str()) == Some(value))
            .map(|(key, _)| (format!("length_field.{key}"), Anchor::Step { step, path: format!("result.length_field.{key}") }))
            .collect();
        if derived_from.is_empty() || !journal::promote(self, step) {
            return DerivedFrom::new();
        }
        derived_from
    }

    /// Where a width set from a scanned period came from: that candidate of
    /// the `analysis.period_scan` step whose result the structure chart
    /// shows, as `job.candidates[k].period` (its job's result), when one
    /// row is exactly `period` bytes wide with no padding.
    pub fn period_provenance(&self, period: usize, width: usize, row_padding: usize) -> DerivedFrom {
        let Some(scan) = self.period_scan.as_ref().filter(|_| width == period && row_padding == 0) else { return DerivedFrom::new() };
        let Some(candidate) = scan.candidates.iter().position(|candidate| candidate.period == period) else { return DerivedFrom::new() };
        let scanned = self.journal.entries().rev().find(|entry| entry.method == "analysis.period_scan" && entry.outcome.is_ok());
        let Some(step) = scanned.filter(|entry| entry.params["start"].as_u64().unwrap_or(0) == scan.window_start as u64).map(|entry| entry.step) else { return DerivedFrom::new() };
        DerivedFrom::from([("width".to_string(), Anchor::Step { step, path: format!("job.candidates[{candidate}].period") })])
    }
}
