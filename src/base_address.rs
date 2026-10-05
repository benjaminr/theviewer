//! Firmware load (base) address recovery, in the manner of rbasefind.
//!
//! A raw firmware image refers to its own strings by absolute address. If the
//! image is loaded at base `B`, a pointer `p` to the string starting at file
//! offset `s` satisfies `p = B + s`. So every pair of (pointer-like value,
//! string start) votes for `B = p - s`, and the true base collects far more
//! votes than any accidental one.
//!
//! Checking every pair is quadratic. Because candidate bases are multiples of
//! a step (0x1000 by default), `p - s` can only be a candidate when
//! `p ≡ s (mod step)`, so strings are bucketed by their offset modulo the
//! step and each pointer only votes with the strings in its own bucket. The
//! votes are then counted, and the best bases are refined by rescanning the
//! image to count every pointer slot (not just distinct values) and collect
//! example references to show the user.

use std::collections::{HashMap, HashSet};

use crate::strings::{self, Encoding};

/// Smallest step accepted; finer steps make the vote count explode.
pub const MIN_STEP: u64 = 0x10;
/// Default step between candidate bases.
pub const DEFAULT_STEP: u64 = 0x1000;
/// Default minimum string length, as in rbasefind.
pub const DEFAULT_MIN_STRING_LEN: usize = 10;
/// Default number of candidates returned.
pub const DEFAULT_MAX_CANDIDATES: usize = 10;

/// Most string starts considered.
const MAX_STRINGS: usize = 50_000;
/// Most distinct pointer-like values considered.
const MAX_DISTINCT_POINTERS: usize = 500_000;
/// Most votes cast, which bounds memory (8 bytes per vote) and time.
const MAX_VOTES: usize = 8_000_000;
/// A base needs at least this many matching strings to be reported at all.
const MIN_MATCHES: usize = 2;
/// Below this many matches a base is reported as weak.
const CONVINCING_MATCHES: usize = 10;
/// Example references kept per candidate.
const MAX_EXAMPLES: usize = 8;

/// Byte order of the stored pointers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    pub const ALL: [ByteOrder; 2] = [ByteOrder::Little, ByteOrder::Big];

    pub fn label(self) -> &'static str {
        match self {
            ByteOrder::Little => "little endian",
            ByteOrder::Big => "big endian",
        }
    }
}

/// Size of the stored pointers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PointerWidth {
    Bits32,
    Bits64,
}

impl PointerWidth {
    pub fn bytes(self) -> usize {
        match self {
            PointerWidth::Bits32 => 4,
            PointerWidth::Bits64 => 8,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PointerWidth::Bits32 => "32-bit",
            PointerWidth::Bits64 => "64-bit",
        }
    }
}

/// What to search for.
#[derive(Clone, Debug, PartialEq)]
pub struct BaseSearchOptions {
    pub width: PointerWidth,
    /// `None` tries both byte orders.
    pub byte_order: Option<ByteOrder>,
    /// Candidate bases are multiples of this; raised to [`MIN_STEP`].
    pub step: u64,
    /// Shortest ASCII string counted as a pointer target.
    pub min_string_len: usize,
    pub max_candidates: usize,
}

impl Default for BaseSearchOptions {
    fn default() -> Self {
        BaseSearchOptions {
            width: PointerWidth::Bits32,
            byte_order: None,
            step: DEFAULT_STEP,
            min_string_len: DEFAULT_MIN_STRING_LEN,
            max_candidates: DEFAULT_MAX_CANDIDATES,
        }
    }
}

/// One stored pointer that hits a string under a candidate base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointerExample {
    /// File offset of the stored pointer.
    pub pointer_offset: usize,
    /// File offset of the string it points at.
    pub string_offset: usize,
}

/// A possible load address and the evidence for it.
#[derive(Clone, Debug, PartialEq)]
pub struct BaseCandidate {
    /// Address of file offset 0.
    pub base: u64,
    pub byte_order: ByteOrder,
    pub width: PointerWidth,
    /// Distinct strings pointed at.
    pub matched_strings: usize,
    /// Pointer slots that point at a string (a string can be used many times).
    pub references: usize,
    pub examples: Vec<PointerExample>,
}

/// The outcome of a search.
#[derive(Clone, Debug, PartialEq)]
pub struct BaseSearchReport {
    /// Best first; empty when nothing matched.
    pub candidates: Vec<BaseCandidate>,
    pub strings_considered: usize,
    /// Distinct pointer-like values, summed over the byte orders tried.
    pub pointers_considered: usize,
    /// True when a limit cut the search short, so counts are lower bounds.
    pub truncated: bool,
    /// One sentence for the user.
    pub summary: String,
}

impl BaseSearchReport {
    pub fn best(&self) -> Option<&BaseCandidate> {
        self.candidates.first()
    }

    /// Whether the best candidate explains enough strings to trust.
    pub fn is_convincing(&self) -> bool {
        self.best().is_some_and(|best| best.matched_strings >= CONVINCING_MATCHES)
    }
}

/// Find likely load addresses for the firmware image `bytes`, whose first
/// byte is file offset 0. Never panics; returns an empty candidate list with
/// an explanation when there is nothing to match.
pub fn find_base_address(bytes: &[u8], options: &BaseSearchOptions) -> BaseSearchReport {
    let step = options.step.max(MIN_STEP);
    let string_starts: Vec<u64> = strings::extract(bytes, 0, options.min_string_len.max(1), &[Encoding::Ascii], MAX_STRINGS)
        .into_iter()
        .map(|found| found.offset as u64)
        .collect();
    if string_starts.is_empty() {
        return empty_report(0, 0, false, format!("No ASCII strings of {} or more characters, so there is nothing for pointers to hit.", options.min_string_len));
    }
    let buckets = bucket_by_residue(&string_starts, step);
    let string_set: HashSet<u64> = string_starts.iter().copied().collect();

    let orders: Vec<ByteOrder> = match options.byte_order {
        Some(order) => vec![order],
        None => ByteOrder::ALL.to_vec(),
    };
    let mut candidates = Vec::new();
    let mut pointers_considered = 0;
    let mut truncated = string_starts.len() >= MAX_STRINGS;
    for order in orders {
        let layout = Layout { width: options.width, order };
        let (pointers, pointers_truncated) = distinct_pointer_values(bytes, layout);
        pointers_considered += pointers.len();
        let (votes, votes_truncated) = tally_votes(&pointers, &buckets, step);
        truncated |= pointers_truncated || votes_truncated;
        for (base, matched_strings) in top_bases(votes, options.max_candidates) {
            candidates.push(refine(bytes, layout, base, matched_strings, &string_set));
        }
    }
    candidates.sort_by(|a, b| b.matched_strings.cmp(&a.matched_strings).then(b.references.cmp(&a.references)).then(a.base.cmp(&b.base)));
    candidates.truncate(options.max_candidates);

    let summary = summarise(&candidates, string_starts.len(), pointers_considered, truncated);
    BaseSearchReport { candidates, strings_considered: string_starts.len(), pointers_considered, truncated, summary }
}

fn empty_report(strings_considered: usize, pointers_considered: usize, truncated: bool, summary: String) -> BaseSearchReport {
    BaseSearchReport { candidates: Vec::new(), strings_considered, pointers_considered, truncated, summary }
}

fn summarise(candidates: &[BaseCandidate], strings: usize, pointers: usize, truncated: bool) -> String {
    let limit_note = if truncated { " A size limit was reached, so counts are lower bounds." } else { "" };
    match candidates.first() {
        None => format!(
            "No base makes {MIN_MATCHES} or more pointers hit string starts ({strings} strings, {pointers} pointer-like values). \
             The image may be position independent, compressed, or need a finer step.{limit_note}"
        ),
        Some(best) if best.matched_strings < CONVINCING_MATCHES => format!(
            "Weak evidence: the best base {:#x} explains only {} strings; treat it as a guess.{limit_note}",
            best.base, best.matched_strings
        ),
        Some(best) => format!(
            "Likely base {:#x} ({} {}): {} strings referenced by {} pointers.{limit_note}",
            best.base,
            best.width.label(),
            best.byte_order.label(),
            best.matched_strings,
            best.references
        ),
    }
}

// ---------------------------------------------------------------------------
// Pointer values
// ---------------------------------------------------------------------------

/// How pointers are stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Layout {
    width: PointerWidth,
    order: ByteOrder,
}

impl Layout {
    /// Values at every naturally aligned slot, with their file offsets.
    fn values<'a>(&self, bytes: &'a [u8]) -> impl Iterator<Item = (usize, u64)> + 'a {
        let width = self.width.bytes();
        let order = self.order;
        bytes.chunks_exact(width).enumerate().map(move |(index, chunk)| (index * width, read_value(chunk, order)))
    }
}

fn read_value(chunk: &[u8], order: ByteOrder) -> u64 {
    let fold = |value: u64, &byte: &u8| (value << 8) | byte as u64;
    match order {
        ByteOrder::Big => chunk.iter().fold(0, fold),
        ByteOrder::Little => chunk.iter().rev().fold(0, fold),
    }
}

/// Whether a stored value could be a pointer at all. Zero, all-ones and
/// values whose bytes are all printable (pieces of strings) are not.
fn could_be_pointer(value: u64, width: PointerWidth) -> bool {
    let all_ones = match width {
        PointerWidth::Bits32 => u32::MAX as u64,
        PointerWidth::Bits64 => u64::MAX,
    };
    let printable = value.to_le_bytes()[..width.bytes()].iter().all(|byte| byte.is_ascii_graphic() || *byte == b' ');
    value != 0 && value != all_ones && !printable
}

/// Distinct pointer-like values, sorted so truncation is deterministic.
fn distinct_pointer_values(bytes: &[u8], layout: Layout) -> (Vec<u64>, bool) {
    let mut seen = HashSet::new();
    let mut truncated = false;
    for (_, value) in layout.values(bytes) {
        if !could_be_pointer(value, layout.width) {
            continue;
        }
        if seen.len() >= MAX_DISTINCT_POINTERS && !seen.contains(&value) {
            truncated = true;
            break;
        }
        seen.insert(value);
    }
    let mut values: Vec<u64> = seen.into_iter().collect();
    values.sort_unstable();
    (values, truncated)
}

// ---------------------------------------------------------------------------
// Voting
// ---------------------------------------------------------------------------

/// String starts grouped by their offset modulo `step`.
fn bucket_by_residue(string_starts: &[u64], step: u64) -> HashMap<u64, Vec<u64>> {
    let mut buckets: HashMap<u64, Vec<u64>> = HashMap::new();
    for &start in string_starts {
        buckets.entry(start % step).or_default().push(start);
    }
    buckets
}

/// One vote per (pointer, string) pair whose difference is a step-aligned
/// base. Returns the votes and whether [`MAX_VOTES`] cut them short.
fn tally_votes(pointers: &[u64], buckets: &HashMap<u64, Vec<u64>>, step: u64) -> (Vec<u64>, bool) {
    let mut votes = Vec::new();
    for &pointer in pointers {
        let Some(strings) = buckets.get(&(pointer % step)) else { continue };
        for &string_start in strings {
            if string_start > pointer {
                continue;
            }
            if votes.len() >= MAX_VOTES {
                return (votes, true);
            }
            votes.push(pointer - string_start);
        }
    }
    (votes, false)
}

/// The `limit` bases with the most votes (at least [`MIN_MATCHES`]), best first.
fn top_bases(mut votes: Vec<u64>, limit: usize) -> Vec<(u64, usize)> {
    votes.sort_unstable();
    let mut counted: Vec<(u64, usize)> = Vec::new();
    for base in votes {
        match counted.last_mut() {
            Some((last, count)) if *last == base => *count += 1,
            _ => counted.push((base, 1)),
        }
    }
    counted.retain(|&(_, count)| count >= MIN_MATCHES);
    counted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    counted.truncate(limit);
    counted
}

/// Recount a candidate over every pointer slot and collect examples.
fn refine(bytes: &[u8], layout: Layout, base: u64, matched_strings: usize, string_set: &HashSet<u64>) -> BaseCandidate {
    let mut references = 0;
    let mut examples = Vec::new();
    for (offset, value) in layout.values(bytes) {
        let Some(target) = value.checked_sub(base) else { continue };
        if !could_be_pointer(value, layout.width) || !string_set.contains(&target) {
            continue;
        }
        references += 1;
        if examples.len() < MAX_EXAMPLES {
            examples.push(PointerExample { pointer_offset: offset, string_offset: target as usize });
        }
    }
    BaseCandidate { base, byte_order: layout.order, width: layout.width, matched_strings, references, examples }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLASH_BASE: u64 = 0x0800_0000;
    const IMAGE_LEN: usize = 64 * 1024;
    const POINTER_TABLE: usize = 0x200;
    const STRING_AREA: usize = 0x8000;
    const STRING_COUNT: usize = 40;

    /// Deterministic pseudo-random words standing in for code.
    fn noise_words(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }

    /// An image loaded at `base` holding NUL-terminated messages and a table
    /// of pointers to them, the rest filled with code-like noise.
    fn firmware_image(base: u64, order: ByteOrder, width: PointerWidth) -> (Vec<u8>, Vec<usize>) {
        let mut image = noise_words(IMAGE_LEN, 0xC0FFEE);
        // Noise must not contain accidental long strings.
        for byte in image.iter_mut() {
            if byte.is_ascii_graphic() {
                *byte |= 0x80;
            }
        }
        let mut string_offsets = Vec::new();
        let mut at = STRING_AREA;
        for index in 0..STRING_COUNT {
            let message = format!("error {index}: sensor timeout on channel\0");
            image[at..at + message.len()].copy_from_slice(message.as_bytes());
            string_offsets.push(at);
            at += message.len() + 3;
        }
        let width_bytes = width.bytes();
        for (slot, &offset) in string_offsets.iter().enumerate() {
            let value = base + offset as u64;
            let encoded: Vec<u8> = match (order, width) {
                (ByteOrder::Little, PointerWidth::Bits32) => (value as u32).to_le_bytes().to_vec(),
                (ByteOrder::Big, PointerWidth::Bits32) => (value as u32).to_be_bytes().to_vec(),
                (ByteOrder::Little, PointerWidth::Bits64) => value.to_le_bytes().to_vec(),
                (ByteOrder::Big, PointerWidth::Bits64) => value.to_be_bytes().to_vec(),
            };
            let position = POINTER_TABLE + slot * width_bytes;
            image[position..position + width_bytes].copy_from_slice(&encoded);
        }
        (image, string_offsets)
    }

    #[test]
    fn finds_a_little_endian_image_loaded_at_flash_base() {
        let (image, strings) = firmware_image(FLASH_BASE, ByteOrder::Little, PointerWidth::Bits32);
        let report = find_base_address(&image, &BaseSearchOptions::default());
        let best = report.best().expect("a candidate");
        assert_eq!(best.base, FLASH_BASE, "{:?}", report.candidates);
        assert_eq!(best.byte_order, ByteOrder::Little);
        assert_eq!(best.width, PointerWidth::Bits32);
        assert_eq!(best.matched_strings, STRING_COUNT);
        assert_eq!(best.references, STRING_COUNT);
        assert_eq!(best.examples[0], PointerExample { pointer_offset: POINTER_TABLE, string_offset: strings[0] });
        assert!(report.summary.contains("0x8000000"), "{}", report.summary);
        assert!(report.is_convincing());
    }

    #[test]
    fn finds_a_big_endian_image_when_both_orders_are_tried() {
        let (image, _) = firmware_image(FLASH_BASE, ByteOrder::Big, PointerWidth::Bits32);
        let report = find_base_address(&image, &BaseSearchOptions::default());
        let best = report.best().expect("a candidate");
        assert_eq!((best.base, best.byte_order), (FLASH_BASE, ByteOrder::Big));
    }

    #[test]
    fn finds_a_64_bit_image_when_asked_for_64_bit_pointers() {
        let base = 0xFFFF_0000_4000_0000;
        let (image, _) = firmware_image(base, ByteOrder::Little, PointerWidth::Bits64);
        let options = BaseSearchOptions { width: PointerWidth::Bits64, byte_order: Some(ByteOrder::Little), ..BaseSearchOptions::default() };
        let report = find_base_address(&image, &options);
        assert_eq!(report.best().map(|c| c.base), Some(base), "{:?}", report.candidates);
    }

    #[test]
    fn a_base_of_zero_is_found_when_pointers_are_file_offsets() {
        let (image, _) = firmware_image(0, ByteOrder::Little, PointerWidth::Bits32);
        let report = find_base_address(&image, &BaseSearchOptions::default());
        assert_eq!(report.best().map(|c| c.base), Some(0));
    }

    #[test]
    fn a_base_off_the_step_is_missed_until_the_step_is_refined() {
        let base = FLASH_BASE + 0x100;
        let (image, _) = firmware_image(base, ByteOrder::Little, PointerWidth::Bits32);
        let coarse = find_base_address(&image, &BaseSearchOptions::default());
        assert_ne!(coarse.best().map(|c| c.base), Some(base));
        let fine = find_base_address(&image, &BaseSearchOptions { step: 0x100, ..BaseSearchOptions::default() });
        assert_eq!(fine.best().map(|c| c.base), Some(base));
    }

    #[test]
    fn no_strings_or_no_pointers_gives_an_empty_explained_report() {
        for image in [Vec::new(), vec![0u8; 4096], vec![0xFFu8; 4096]] {
            let report = find_base_address(&image, &BaseSearchOptions::default());
            assert!(report.candidates.is_empty());
            assert!(!report.summary.is_empty());
        }
        // Strings but no pointers to them.
        let mut image = vec![0u8; 8192];
        image[100..140].copy_from_slice(b"a lonely string with no pointer to it!!\0");
        let report = find_base_address(&image, &BaseSearchOptions::default());
        assert!(report.candidates.is_empty());
        assert!(report.summary.starts_with("No base"), "{}", report.summary);
    }

    #[test]
    fn a_tiny_step_is_raised_to_the_minimum_without_panicking() {
        let (image, _) = firmware_image(FLASH_BASE, ByteOrder::Little, PointerWidth::Bits32);
        let report = find_base_address(&image, &BaseSearchOptions { step: 0, ..BaseSearchOptions::default() });
        assert_eq!(report.best().map(|c| c.base), Some(FLASH_BASE));
    }

    #[test]
    fn values_are_read_in_the_requested_byte_order() {
        assert_eq!(read_value(&[0x01, 0x02, 0x03, 0x04], ByteOrder::Little), 0x0403_0201);
        assert_eq!(read_value(&[0x01, 0x02, 0x03, 0x04], ByteOrder::Big), 0x0102_0304);
        assert!(!could_be_pointer(u32::from_le_bytes(*b"abcd") as u64, PointerWidth::Bits32));
        assert!(could_be_pointer(0x0800_1234, PointerWidth::Bits32));
    }
}
