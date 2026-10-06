//! Skipped (folded) ranges: bytes left out of the raster and the hex dump
//! without being deleted.
//!
//! Folds are view state, not edits. The views lay bytes out in "view
//! offsets", which are document offsets with the folded bytes taken out, and
//! draw a marker where each fold sits; clicking it unfolds. With no folds
//! the two kinds of offset are the same, so everything here is a no-op.

use crate::document::Document;

/// The folded ranges of the document, as `(start, len)` in document offsets,
/// sorted and not overlapping.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Folds {
    ranges: Vec<(usize, usize)>,
    /// Changes whenever the folds do, so cached pictures know to redraw.
    generation: u64,
}

impl Folds {
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The folded ranges in document order.
    pub fn ranges(&self) -> &[(usize, usize)] {
        &self.ranges
    }

    /// Changes whenever a range is folded or unfolded.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Bytes folded away in total.
    pub fn hidden_bytes(&self) -> usize {
        self.ranges.iter().map(|&(_, len)| len).sum()
    }

    /// Fold `[start, start + len)`, merging with folds it touches.
    pub fn fold(&mut self, start: usize, len: usize) {
        if len == 0 {
            return;
        }
        let mut ranges = std::mem::take(&mut self.ranges);
        ranges.push((start, len));
        self.ranges = crate::selection::normalise_ranges(ranges);
        self.generation += 1;
    }

    /// Unfold the fold starting at `start`. Returns whether there was one.
    pub fn unfold(&mut self, start: usize) -> bool {
        let before = self.ranges.len();
        self.ranges.retain(|&(fold_start, _)| fold_start != start);
        let changed = self.ranges.len() != before;
        if changed {
            self.generation += 1;
        }
        changed
    }

    /// Unfold everything.
    pub fn clear(&mut self) {
        if !self.ranges.is_empty() {
            self.ranges.clear();
            self.generation += 1;
        }
    }

    /// Cut the folds to a document of `document_len` bytes (after an edit
    /// shortened it), dropping those wholly past the end.
    pub fn clamp_to(&mut self, document_len: usize) {
        let before = self.ranges.clone();
        self.ranges.retain(|&(start, _)| start < document_len);
        for range in &mut self.ranges {
            range.1 = range.1.min(document_len - range.0);
        }
        if self.ranges != before {
            self.generation += 1;
        }
    }

    /// The fold holding document offset `offset`, if any.
    pub fn fold_containing(&self, offset: usize) -> Option<(usize, usize)> {
        self.ranges.iter().copied().find(|&(start, len)| offset >= start && offset < start + len)
    }

    /// The view offset of document offset `offset`. A folded byte maps to
    /// where its fold's marker sits.
    pub fn to_view(&self, offset: usize) -> usize {
        let mut hidden = 0;
        for &(start, len) in &self.ranges {
            if offset >= start + len {
                hidden += len;
            } else if offset >= start {
                return start - hidden;
            } else {
                break;
            }
        }
        offset - hidden
    }

    /// The document offset of view offset `view`: the first byte shown at
    /// or after it.
    pub fn to_document(&self, view: usize) -> usize {
        let mut offset = view;
        for &(start, len) in &self.ranges {
            if start <= offset {
                offset += len;
            } else {
                break;
            }
        }
        offset
    }

    /// How many bytes the views lay out for a document of `document_len`.
    pub fn view_len(&self, document_len: usize) -> usize {
        let hidden: usize = self.ranges.iter().map(|&(start, len)| len.min(document_len.saturating_sub(start))).sum();
        document_len.saturating_sub(hidden)
    }

    /// The visible parts of document range `[start, start + len)` as view
    /// ranges, one per piece between folds.
    pub fn view_ranges(&self, start: usize, len: usize) -> Vec<(usize, usize)> {
        if self.ranges.is_empty() {
            return vec![(start, len)];
        }
        let end = start + len;
        let mut pieces = Vec::new();
        let mut from = start;
        for &(fold_start, fold_len) in &self.ranges {
            let fold_end = fold_start + fold_len;
            if fold_end <= from {
                continue;
            }
            if fold_start >= end {
                break;
            }
            if fold_start > from {
                pieces.push((self.to_view(from), fold_start - from));
            }
            from = fold_end;
        }
        if from < end {
            pieces.push((self.to_view(from), end - from));
        }
        pieces
    }

    /// Read the bytes laid out from view offset `view_start` into `out`,
    /// skipping folded ranges. Bytes past the end of the document are zero.
    pub fn read_view(&self, document: &mut Document, view_start: usize, out: &mut [u8]) {
        if self.ranges.is_empty() {
            document.read_into(view_start, out);
            return;
        }
        let mut offset = self.to_document(view_start);
        let mut filled = 0;
        while filled < out.len() {
            let next_fold = self.ranges.iter().copied().find(|&(start, len)| start + len > offset);
            let run = match next_fold {
                Some((start, len)) if start <= offset => {
                    offset = start + len;
                    continue;
                }
                Some((start, _)) => (start - offset).min(out.len() - filled),
                None => out.len() - filled,
            };
            document.read_into(offset, &mut out[filled..filled + run]);
            filled += run;
            offset += run;
        }
    }

    /// The folds whose markers fall in view range `[view_start, view_end]`,
    /// as `(view offset, (start, len))`.
    pub fn markers_in(&self, view_start: usize, view_end: usize) -> Vec<(usize, (usize, usize))> {
        self.ranges
            .iter()
            .map(|&range| (self.to_view(range.0), range))
            .filter(|&(view, _)| view >= view_start && view <= view_end)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folds(ranges: &[(usize, usize)]) -> Folds {
        let mut folds = Folds::default();
        for &(start, len) in ranges {
            folds.fold(start, len);
        }
        folds
    }

    #[test]
    fn with_no_folds_view_and_document_offsets_are_the_same() {
        let none = Folds::default();
        assert_eq!(none.to_view(1234), 1234);
        assert_eq!(none.to_document(1234), 1234);
        assert_eq!(none.view_len(100), 100);
        assert_eq!(none.view_ranges(5, 3), vec![(5, 3)]);
    }

    #[test]
    fn folded_bytes_are_taken_out_of_the_layout() {
        let folds = folds(&[(10, 5), (30, 10)]);
        assert_eq!(folds.view_len(100), 85);
        assert_eq!(folds.to_view(9), 9);
        assert_eq!(folds.to_view(12), 10, "a folded byte maps to its marker");
        assert_eq!(folds.to_view(15), 10);
        assert_eq!(folds.to_view(45), 30);
        assert_eq!(folds.to_document(9), 9);
        assert_eq!(folds.to_document(10), 15, "the marker is followed by the byte after the fold");
        assert_eq!(folds.to_document(30), 45);
        for view in 0..85 {
            assert_eq!(folds.to_view(folds.to_document(view)), view);
        }
    }

    #[test]
    fn a_range_across_a_fold_shows_as_the_pieces_either_side() {
        let folds = folds(&[(10, 5)]);
        assert_eq!(folds.view_ranges(8, 10), vec![(8, 2), (10, 3)]);
        assert!(folds.view_ranges(11, 2).is_empty(), "wholly folded");
    }

    #[test]
    fn reading_the_view_skips_folded_bytes() {
        let mut document = Document::from_bytes((0u8..20).collect());
        let folds = folds(&[(2, 3), (10, 5)]);
        let mut out = [0xFFu8; 14];
        folds.read_view(&mut document, 0, &mut out);
        assert_eq!(out, [0, 1, 5, 6, 7, 8, 9, 15, 16, 17, 18, 19, 0, 0]);
        let mut tail = [0u8; 3];
        folds.read_view(&mut document, 6, &mut tail);
        assert_eq!(tail, [9, 15, 16]);
    }

    #[test]
    fn folds_merge_unfold_and_are_cut_to_the_document() {
        let mut folds = folds(&[(10, 5), (14, 6)]);
        assert_eq!(folds.ranges(), &[(10, 10)]);
        let generation = folds.generation();
        assert!(folds.unfold(10));
        assert!(folds.is_empty());
        assert!(folds.generation() > generation);
        folds.fold(90, 20);
        folds.clamp_to(100);
        assert_eq!(folds.ranges(), &[(90, 10)]);
        folds.clamp_to(50);
        assert!(folds.is_empty());
    }

    #[test]
    fn markers_sit_at_the_view_offset_of_each_fold() {
        let folds = folds(&[(10, 5), (30, 10)]);
        assert_eq!(folds.markers_in(0, 100), vec![(10, (10, 5)), (25, (30, 10))]);
        assert_eq!(folds.markers_in(11, 24), vec![]);
    }
}
