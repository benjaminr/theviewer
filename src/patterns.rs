//! Recognises familiar structures in raw bytes so the viewer can highlight
//! them: counters, timestamp sequences, text, float arrays, offset tables,
//! file signatures, padding and compressed-looking regions.
//!
//! Every detector works on a window of bytes plus the document offset the
//! window starts at, and returns [`Pattern`]s in document coordinates.

use std::collections::HashMap;
use std::sync::Arc;

use rayon::prelude::*;

use crate::analysis::shannon_entropy;
use crate::compress;
use crate::plugin::{Category, Detector, Finding, ScanContext};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PatternKind {
    Signature,
    Compressed,
    Timestamp,
    Counter,
    OffsetTable,
    FloatArray,
    Utf16Text,
    AsciiText,
    HighEntropy,
    Padding,
}

impl PatternKind {
    pub const ALL: [PatternKind; 10] = [
        PatternKind::Signature,
        PatternKind::Compressed,
        PatternKind::Timestamp,
        PatternKind::Counter,
        PatternKind::OffsetTable,
        PatternKind::FloatArray,
        PatternKind::Utf16Text,
        PatternKind::AsciiText,
        PatternKind::HighEntropy,
        PatternKind::Padding,
    ];

    pub fn label(self) -> &'static str {
        match self {
            PatternKind::Signature => "File signature",
            PatternKind::Compressed => "Compressed streams",
            PatternKind::Timestamp => "Timestamps",
            PatternKind::Counter => "Counters",
            PatternKind::OffsetTable => "Offset tables",
            PatternKind::FloatArray => "Float arrays",
            PatternKind::Utf16Text => "UTF-16 text",
            PatternKind::AsciiText => "ASCII text",
            PatternKind::HighEntropy => "High entropy",
            PatternKind::Padding => "Padding",
        }
    }

    pub fn index(self) -> usize {
        PatternKind::ALL.iter().position(|&kind| kind == self).unwrap_or(0)
    }

    /// Cap on how many patterns of this kind a scan reports, so a text file
    /// does not produce ten thousand string highlights.
    fn cap(self) -> usize {
        match self {
            PatternKind::AsciiText | PatternKind::Utf16Text => 1500,
            PatternKind::Padding => 1000,
            _ => 800,
        }
    }

    /// The plugin-level category this kind maps to.
    pub fn category(self) -> Category {
        match self {
            PatternKind::Signature => Category::Signature,
            PatternKind::Compressed => Category::Compressed,
            PatternKind::Timestamp => Category::Timestamp,
            PatternKind::Counter => Category::Counter,
            PatternKind::OffsetTable => Category::OffsetTable,
            PatternKind::FloatArray => Category::FloatArray,
            PatternKind::Utf16Text | PatternKind::AsciiText => Category::Text,
            PatternKind::HighEntropy => Category::HighEntropy,
            PatternKind::Padding => Category::Padding,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    fn label(self) -> &'static str {
        match self {
            Endian::Little => "LE",
            Endian::Big => "BE",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pattern {
    pub kind: PatternKind,
    /// Document offset of the first byte.
    pub start: usize,
    /// Bytes spanned, including gaps between strided elements.
    pub len: usize,
    /// Distance between elements for sequence patterns, else 0.
    pub stride: usize,
    /// Number of elements for sequence patterns, else 0.
    pub count: usize,
    /// Bytes per element for sequence patterns, else 0.
    pub element: usize,
    /// True when another interpretation is about as likely (for example a
    /// timestamp before 2011, whose bits also form a plausible float).
    pub weak: bool,
    pub description: String,
}

impl Pattern {
    pub fn end(&self) -> usize {
        self.start + self.len
    }

    pub fn contains(&self, offset: usize) -> bool {
        offset >= self.start && offset < self.end()
    }
}

/// Convert an internal pattern to the plugin-level finding type.
impl From<Pattern> for Finding {
    fn from(pattern: Pattern) -> Finding {
        let (title, detail) = split_description(&pattern.description);
        let id = pattern.kind.label().to_ascii_lowercase().replace(' ', "-");
        let mut finding = Finding::new(id, "builtin", pattern.kind.category(), pattern.start, pattern.len)
            .title(title)
            .detail(detail)
            .confidence(if pattern.weak { 0.3 } else { 1.0 });
        if pattern.count > 0 {
            finding = finding.sequence(pattern.stride, pattern.count, pattern.element);
        }
        finding
    }
}

/// Descriptions read "Thing: details" or "Thing, details"; split them so the
/// findings panel can show a short title.
fn split_description(description: &str) -> (String, String) {
    if let Some((title, detail)) = description.split_once(": ") {
        return (title.to_string(), detail.to_string());
    }
    if let Some((title, detail)) = description.split_once(", ") {
        return (title.to_string(), detail.to_string());
    }
    (description.to_string(), String::new())
}

/// Each built-in scanner as a plugin, so the registry treats them exactly like
/// third-party ones.
struct BuiltinDetector {
    id: &'static str,
    name: &'static str,
    categories: &'static [Category],
    run: fn(&[u8], &ScanContext) -> Vec<Pattern>,
}

impl Detector for BuiltinDetector {
    fn id(&self) -> &str {
        self.id
    }

    fn name(&self) -> &str {
        self.name
    }

    fn categories(&self) -> Vec<Category> {
        self.categories.to_vec()
    }

    fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding> {
        (self.run)(window, context).into_iter().map(Finding::from).collect()
    }
}

fn run_sequences(window: &[u8], context: &ScanContext) -> Vec<Pattern> {
    scan_numeric_sequences(window, context, &candidate_strides(context))
}

fn run_compressed(window: &[u8], context: &ScanContext) -> Vec<Pattern> {
    scan_compressed(window, context.base)
}

fn run_signatures(window: &[u8], context: &ScanContext) -> Vec<Pattern> {
    scan_signatures(window, context.base)
}

fn run_text(window: &[u8], context: &ScanContext) -> Vec<Pattern> {
    scan_text(window, context.base)
}

fn run_padding(window: &[u8], context: &ScanContext) -> Vec<Pattern> {
    scan_padding(window, context.base)
}

fn run_entropy(window: &[u8], context: &ScanContext) -> Vec<Pattern> {
    scan_high_entropy(window, context.base)
}

/// The built-in detectors, ready to register.
pub fn builtin_detectors() -> Vec<Arc<dyn Detector>> {
    let detectors = [
        BuiltinDetector {
            id: "builtin.sequences",
            name: "Numeric sequences",
            categories: &[Category::Counter, Category::Timestamp, Category::OffsetTable, Category::FloatArray],
            run: run_sequences,
        },
        BuiltinDetector {
            id: "builtin.compressed",
            name: "Compressed streams",
            categories: &[Category::Compressed],
            run: run_compressed,
        },
        BuiltinDetector {
            id: "builtin.signatures",
            name: "Basic file signatures",
            categories: &[Category::Signature],
            run: run_signatures,
        },
        BuiltinDetector { id: "builtin.text", name: "Text", categories: &[Category::Text], run: run_text },
        BuiltinDetector { id: "builtin.padding", name: "Padding", categories: &[Category::Padding], run: run_padding },
        BuiltinDetector {
            id: "builtin.entropy",
            name: "High entropy regions",
            categories: &[Category::HighEntropy],
            run: run_entropy,
        },
    ];
    detectors.into_iter().map(|d| Arc::new(d) as Arc<dyn Detector>).collect()
}

fn candidate_strides(context: &ScanContext) -> Vec<usize> {
    let mut strides: Vec<usize> = COMMON_STRIDES.to_vec();
    strides.extend(context.strides.iter().copied().filter(|&s| s > 0 && s <= 4096));
    strides.sort_unstable();
    strides.dedup();
    strides
}

/// Reconcile findings from different detectors after a registry scan: a
/// verified compressed stream outranks a bare signature at the same offset
/// and explains any high-entropy region it covers; exact duplicates (same
/// id, start and length from different detectors) collapse to the most
/// confident; and each category is capped so one kind cannot swamp the rest.
pub fn resolve_overlaps(findings: &mut Vec<Finding>) {
    let streams: Vec<(usize, usize)> = findings
        .iter()
        .filter(|f| f.category == Category::Compressed)
        .map(|f| (f.start, f.end()))
        .collect();
    findings.retain(|finding| match finding.category {
        Category::Signature => !streams.iter().any(|&(start, _)| start == finding.start),
        Category::HighEntropy => {
            let covered: usize = streams
                .iter()
                .map(|&(s, e)| e.min(finding.end()).saturating_sub(s.max(finding.start)))
                .sum();
            covered * 5 < finding.len * 4
        }
        _ => true,
    });
    findings.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(a.id.cmp(&b.id))
            .then(a.len.cmp(&b.len))
            .then(b.confidence.total_cmp(&a.confidence))
    });
    findings.dedup_by(|a, b| a.start == b.start && a.len == b.len && a.id == b.id);
    let mut counts = [0usize; Category::ALL.len()];
    findings.retain(|finding| {
        let slot = &mut counts[finding.category.index()];
        *slot += 1;
        *slot <= finding.category.cap()
    });
    findings.sort_by(|a, b| a.start.cmp(&b.start).then(a.category.cmp(&b.category)));
}

const COMMON_STRIDES: [usize; 11] = [4, 8, 12, 16, 20, 24, 32, 48, 64, 128, 256];
const MAX_PATTERNS: usize = 6000;

/// Run every detector over `window` and return patterns sorted by start.
pub fn scan(window: &[u8], context: &ScanContext) -> Vec<Pattern> {
    let strides = candidate_strides(context);

    let (numeric, (streams, (signatures, (text, (padding, entropy))))) = rayon::join(
        || scan_numeric_sequences(window, context, &strides),
        || {
            rayon::join(
                || scan_compressed(window, context.base),
                || {
                    rayon::join(
                        || scan_signatures(window, context.base),
                        || {
                            rayon::join(
                                || scan_text(window, context.base),
                                || rayon::join(|| scan_padding(window, context.base), || scan_high_entropy(window, context.base)),
                            )
                        },
                    )
                },
            )
        },
    );

    // A verified stream outranks the bare signature at the same offset, and
    // explains any high-entropy region it covers.
    let stream_starts: Vec<usize> = streams.iter().map(|p| p.start).collect();
    let signatures: Vec<Pattern> = signatures.into_iter().filter(|p| !stream_starts.contains(&p.start)).collect();
    let entropy: Vec<Pattern> = entropy
        .into_iter()
        .filter(|region| {
            let covered: usize = streams
                .iter()
                .map(|s| s.end().min(region.end()).saturating_sub(s.start.max(region.start)))
                .sum();
            covered * 5 < region.len * 4
        })
        .collect();

    let mut patterns = numeric;
    patterns.extend(streams);
    patterns.extend(signatures);
    patterns.extend(text);
    patterns.extend(padding);
    patterns.extend(entropy);
    apply_caps(&mut patterns);
    patterns.sort_by_key(|pattern| (pattern.start, pattern.kind));
    patterns
}

fn apply_caps(patterns: &mut Vec<Pattern>) {
    let mut counts = [0usize; PatternKind::ALL.len()];
    patterns.retain(|pattern| {
        let slot = &mut counts[pattern.kind.index()];
        *slot += 1;
        *slot <= pattern.kind.cap()
    });
    patterns.truncate(MAX_PATTERNS);
}

// ---------------------------------------------------------------------------
// Numeric sequences: counters, timestamps, offset tables, float arrays
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Element {
    size: usize,
    endian: Endian,
}

impl Element {
    #[inline]
    fn read(self, bytes: &[u8]) -> u64 {
        let mut value = 0u64;
        match self.endian {
            Endian::Little => {
                for &byte in bytes[..self.size].iter().rev() {
                    value = (value << 8) | byte as u64;
                }
            }
            Endian::Big => {
                for &byte in &bytes[..self.size] {
                    value = (value << 8) | byte as u64;
                }
            }
        }
        value
    }

    fn label(self) -> String {
        format!("u{} {}", self.size * 8, self.endian.label())
    }
}

/// One accepted run of elements, in window coordinates.
struct Run {
    start: usize,
    stride: usize,
    count: usize,
    first: u64,
    last: u64,
}

/// Walk every phase of `stride` and collect runs where `accept(prev, next)`
/// holds between consecutive elements, with a per-run state `S` that the
/// predicate may refine (for example a counter's fixed delta).
fn find_runs<S: Copy + Default>(
    window: &[u8],
    element: Element,
    stride: usize,
    min_count: usize,
    accept: impl Fn(u64, u64, &mut S) -> bool,
    start_state: impl Fn(u64, u64) -> Option<S>,
    finish: impl Fn(Run, S) -> Option<Pattern>,
) -> Vec<Pattern> {
    let mut found = Vec::new();
    let n = window.len();
    if stride == 0 || n < element.size {
        return found;
    }
    for phase in 0..stride.min(n) {
        let mut pos = phase;
        if pos + element.size > n {
            continue;
        }
        let mut prev = element.read(&window[pos..]);
        let mut run_start = pos;
        let mut run_first = prev;
        let mut count = 1;
        let mut state: Option<S> = None;
        loop {
            let next = pos + stride;
            if next + element.size > n {
                break;
            }
            let value = element.read(&window[next..]);
            let accepted = match state.as_mut() {
                Some(s) => accept(prev, value, s),
                None => {
                    run_start = pos;
                    run_first = prev;
                    count = 1;
                    state = start_state(prev, value);
                    state.is_some()
                }
            };
            if accepted {
                count += 1;
            } else {
                if count >= min_count
                    && let Some(s) = state
                    && let Some(pattern) = finish(Run { start: run_start, stride, count, first: run_first, last: prev }, s)
                {
                    found.push(pattern);
                }
                // The previous element may begin a new run with this one.
                run_start = pos;
                run_first = prev;
                count = 1;
                state = start_state(prev, value);
                if state.is_some() {
                    count = 2;
                }
            }
            prev = value;
            pos = next;
        }
        if count >= min_count
            && let Some(s) = state
            && let Some(pattern) = finish(Run { start: run_start, stride, count, first: run_first, last: prev }, s)
        {
            found.push(pattern);
        }
    }
    found
}

fn counter_delta_ok(delta: i64, size: usize) -> bool {
    let limit: u64 = match size {
        1 => 16,
        2 => 256,
        _ => 65_536,
    };
    // `unsigned_abs` because a 64-bit delta can be exactly `i64::MIN`.
    delta != 0 && delta.unsigned_abs() <= limit
}

fn signed_delta(prev: u64, next: u64, size: usize) -> i64 {
    let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
    let wrapped = next.wrapping_sub(prev) & mask;
    if size >= 8 {
        wrapped as i64
    } else {
        let half = 1u64 << (size * 8 - 1);
        if wrapped >= half { wrapped as i64 - (1i64 << (size * 8)) } else { wrapped as i64 }
    }
}

fn scan_counters(window: &[u8], base: usize, element: Element, stride: usize) -> Vec<Pattern> {
    let min_count = if element.size == 1 { 8 } else { 4 };
    let size = element.size;
    find_runs(
        window,
        element,
        stride,
        min_count,
        |prev, next, delta: &mut i64| signed_delta(prev, next, size) == *delta,
        |prev, next| {
            let delta = signed_delta(prev, next, size);
            counter_delta_ok(delta, size).then_some(delta)
        },
        |run, delta| {
            // Demote readings that a narrower counter explains just as well:
            // a step that is a multiple of 256 means the lowest byte never
            // changes, and a u16 or u64 whose top byte never changes is a
            // narrower counter beside a constant field. Four-byte fields are
            // common enough to keep even when their upper bytes are constant.
            let top_shift = 8 * (size as u32 - 1);
            let top_constant = size > 1 && (run.first >> top_shift) == (run.last >> top_shift);
            let weak = (size > 1 && delta.rem_euclid(256) == 0) || (matches!(size, 2 | 8) && top_constant);
            let mut description = format!(
                "Counter {} {:+} every {} B, {} values: {} to {}",
                element.label(),
                delta,
                run.stride,
                run.count,
                run.first,
                run.last
            );
            if size == 4
                && let (Some(first), Some(last)) =
                    (TimeFormat::UnixSeconds.to_unix_seconds(run.first), TimeFormat::UnixSeconds.to_unix_seconds(run.last))
            {
                description.push_str(&format!(" (as Unix time: {} to {})", format_unix_seconds(first), format_unix_seconds(last)));
            }
            Some(Pattern {
                kind: PatternKind::Counter,
                start: base + run.start,
                len: (run.count - 1) * run.stride + size,
                stride: run.stride,
                count: run.count,
                element: size,
                weak,
                description,
            })
        },
    )
}

// Unix time range treated as plausible: 2000-01-01 to 2040-01-01.
const UNIX_MIN: u64 = 946_684_800;
const UNIX_MAX: u64 = 2_208_988_800;
/// Before 2011-01-01 a 32-bit Unix time is also a plausible f32 bit pattern.
const UNIX_FLOAT_AMBIGUITY_END: u64 = 1_293_840_000;
const MAX_TIMESTAMP_GAP_SECONDS: u64 = 366 * 24 * 3600;
/// Random values land in increasing order by chance (1 in k! for a run of
/// k), so a timestamp run needs six values before it counts.
const MIN_TIMESTAMP_RUN: usize = 6;
/// Runs shorter than this are reported but marked weak.
const CONFIDENT_TIMESTAMP_RUN: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeFormat {
    UnixSeconds,
    UnixMillis,
    FileTime,
}

impl TimeFormat {
    pub fn label(self) -> &'static str {
        match self {
            TimeFormat::UnixSeconds => "Unix seconds",
            TimeFormat::UnixMillis => "Unix milliseconds",
            TimeFormat::FileTime => "Windows FILETIME",
        }
    }

    /// Convert a raw value to Unix seconds if it falls in the plausible range.
    pub fn to_unix_seconds(self, value: u64) -> Option<u64> {
        let seconds = match self {
            TimeFormat::UnixSeconds => value,
            TimeFormat::UnixMillis => value / 1000,
            TimeFormat::FileTime => {
                const EPOCH_DIFFERENCE: u64 = 11_644_473_600;
                (value / 10_000_000).checked_sub(EPOCH_DIFFERENCE)?
            }
        };
        (UNIX_MIN..UNIX_MAX).contains(&seconds).then_some(seconds)
    }

    fn element_size(self) -> usize {
        match self {
            TimeFormat::UnixSeconds => 4,
            TimeFormat::UnixMillis | TimeFormat::FileTime => 8,
        }
    }
}

fn scan_timestamps(window: &[u8], base: usize, format: TimeFormat, endian: Endian, stride: usize) -> Vec<Pattern> {
    let element = Element { size: format.element_size(), endian };
    let pair_ok = |prev: u64, next: u64| {
        let (Some(a), Some(b)) = (format.to_unix_seconds(prev), format.to_unix_seconds(next)) else {
            return false;
        };
        b >= a && b - a <= MAX_TIMESTAMP_GAP_SECONDS
    };
    // State: (first delta, whether every delta so far equals it). A perfectly
    // regular clock is more often a counter in disguise.
    find_runs(
        window,
        element,
        stride,
        MIN_TIMESTAMP_RUN,
        |prev, next, (first_delta, constant): &mut (u64, bool)| {
            *constant &= next.wrapping_sub(prev) == *first_delta;
            pair_ok(prev, next)
        },
        |prev, next| pair_ok(prev, next).then_some((next.wrapping_sub(prev), true)),
        |run, (_, constant_delta)| {
            let first = format.to_unix_seconds(run.first)?;
            let last = format.to_unix_seconds(run.last)?;
            // A constant value in range is a fixed field, not a clock.
            if first == last {
                return None;
            }
            let ambiguous_with_float = format == TimeFormat::UnixSeconds && first < UNIX_FLOAT_AMBIGUITY_END;
            Some(Pattern {
                kind: PatternKind::Timestamp,
                start: base + run.start,
                len: (run.count - 1) * run.stride + element.size,
                stride: run.stride,
                count: run.count,
                element: element.size,
                weak: ambiguous_with_float || constant_delta || run.count < CONFIDENT_TIMESTAMP_RUN,
                description: format!(
                    "{} ({}) every {} B, {} values: {} to {}",
                    format.label(),
                    element.label(),
                    run.stride,
                    run.count,
                    format_unix_seconds(first),
                    format_unix_seconds(last)
                ),
            })
        },
    )
}

fn scan_offset_tables(window: &[u8], base: usize, document_len: usize, element: Element, stride: usize) -> Vec<Pattern> {
    let limit = document_len as u64;
    let pair_ok = move |prev: u64, next: u64| prev > 0 && next > prev && next < limit;
    find_runs(
        window,
        element,
        stride,
        4,
        |prev, next, _: &mut ()| pair_ok(prev, next),
        |prev, next| pair_ok(prev, next).then_some(()),
        |run, ()| {
            Some(Pattern {
                kind: PatternKind::OffsetTable,
                start: base + run.start,
                len: (run.count - 1) * run.stride + element.size,
                stride: run.stride,
                count: run.count,
                element: element.size,
                weak: false,
                description: format!(
                    "Increasing in-file offsets ({}) every {} B, {} entries: {:#x} to {:#x}",
                    element.label(),
                    run.stride,
                    run.count,
                    run.first,
                    run.last
                ),
            })
        },
    )
}

fn plausible_f32(bits: u32) -> bool {
    let value = f32::from_bits(bits);
    value == 0.0 || (value.is_finite() && (1e-6..=1e9).contains(&value.abs()))
}

fn plausible_f64(bits: u64) -> bool {
    let value = f64::from_bits(bits);
    value == 0.0 || (value.is_finite() && (1e-9..=1e12).contains(&value.abs()))
}

fn scan_float_arrays(window: &[u8], base: usize, element: Element, stride: usize) -> Vec<Pattern> {
    let size = element.size;
    let plausible = move |bits: u64| if size == 4 { plausible_f32(bits as u32) } else { plausible_f64(bits) };
    // State: (values seen, non-zero values). Runs that are mostly zero are
    // padding rather than data, and all-equal runs carry no information.
    let min_count = if size == 4 { 8 } else { 6 };
    find_runs(
        window,
        element,
        stride,
        min_count,
        move |_prev, next, (seen, nonzero): &mut (usize, usize)| {
            *seen += 1;
            *nonzero += usize::from(next != 0);
            plausible(next)
        },
        move |prev, next| {
            (plausible(prev) && plausible(next)).then_some((2, usize::from(prev != 0) + usize::from(next != 0)))
        },
        |run, (seen, nonzero)| {
            if nonzero * 2 < seen || run.first == run.last {
                return None;
            }
            let (first, last) = if size == 4 {
                (f32::from_bits(run.first as u32) as f64, f32::from_bits(run.last as u32) as f64)
            } else {
                (f64::from_bits(run.first), f64::from_bits(run.last))
            };
            Some(Pattern {
                kind: PatternKind::FloatArray,
                start: base + run.start,
                len: (run.count - 1) * run.stride + size,
                stride: run.stride,
                count: run.count,
                element: size,
                weak: false,
                description: format!(
                    "f{} {} values every {} B, {} of them: {:.4} to {:.4}",
                    size * 8,
                    element.endian.label(),
                    run.stride,
                    run.count,
                    first,
                    last
                ),
            })
        },
    )
}

/// Run all numeric detectors in parallel, then resolve overlaps so that one
/// region is explained once, by the most specific interpretation.
fn scan_numeric_sequences(window: &[u8], context: &ScanContext, strides: &[usize]) -> Vec<Pattern> {
    let base = context.base;
    let endians = [Endian::Little, Endian::Big];

    enum Job {
        Counter(Element, usize),
        Timestamp(TimeFormat, Endian, usize),
        Offsets(Element, usize),
        Floats(Element, usize),
    }
    let mut jobs = Vec::new();
    for &stride in strides {
        for endian in endians {
            for size in [8usize, 4, 2, 1] {
                // Element arrays always use the element size as the stride;
                // wider strides look for fields inside records.
                if stride >= size {
                    jobs.push(Job::Counter(Element { size, endian }, stride));
                }
            }
            if stride >= 4 {
                jobs.push(Job::Timestamp(TimeFormat::UnixSeconds, endian, stride));
                jobs.push(Job::Offsets(Element { size: 4, endian }, stride));
                jobs.push(Job::Floats(Element { size: 4, endian }, stride));
            }
            if stride >= 8 {
                jobs.push(Job::Timestamp(TimeFormat::UnixMillis, endian, stride));
                jobs.push(Job::Offsets(Element { size: 8, endian }, stride));
                jobs.push(Job::Floats(Element { size: 8, endian }, stride));
            }
        }
        if stride >= 8 {
            jobs.push(Job::Timestamp(TimeFormat::FileTime, Endian::Little, stride));
        }
    }
    // Contiguous element arrays for sizes smaller than the smallest common stride.
    for endian in endians {
        for size in [1usize, 2] {
            jobs.push(Job::Counter(Element { size, endian }, size));
        }
    }

    let mut candidates: Vec<Pattern> = jobs
        .par_iter()
        .flat_map_iter(|job| match *job {
            Job::Counter(element, stride) => scan_counters(window, base, element, stride),
            Job::Timestamp(format, endian, stride) => scan_timestamps(window, base, format, endian, stride),
            Job::Offsets(element, stride) => scan_offset_tables(window, base, context.document_len, element, stride),
            Job::Floats(element, stride) => scan_float_arrays(window, base, element, stride),
        })
        .collect();

    // A wide monotonic field whose movement comes from a narrower counter
    // inside it (a counter byte with noise below it reads as an ever
    // increasing "timestamp") is explained by that counter: demote it.
    // Counters are grouped by stride and sorted by start, so each wide field
    // is checked only against the counters that could overlap it; checking
    // every pair took minutes on windows with tens of thousands of each.
    let mut counters_by_stride: HashMap<usize, Vec<(usize, usize, usize, usize)>> = HashMap::new();
    for counter in candidates.iter().filter(|c| c.kind == PatternKind::Counter && !c.weak) {
        counters_by_stride.entry(counter.stride).or_default().push((counter.start, counter.end(), counter.element, counter.count));
    }
    let mut longest_counter: HashMap<usize, usize> = HashMap::new();
    for (stride, counters) in &mut counters_by_stride {
        counters.sort_unstable();
        longest_counter.insert(*stride, counters.iter().map(|&(start, end, _, _)| end - start).max().unwrap_or(0));
    }
    for candidate in &mut candidates {
        if !matches!(candidate.kind, PatternKind::Timestamp | PatternKind::OffsetTable) {
            continue;
        }
        let Some(counters) = counters_by_stride.get(&candidate.stride) else { continue };
        let earliest_start = candidate.start.saturating_sub(longest_counter[&candidate.stride]);
        let from = counters.partition_point(|&(start, ..)| start < earliest_start);
        let to = counters.partition_point(|&(start, ..)| start < candidate.end());
        let stride = candidate.stride;
        let explained = counters[from..to].iter().any(|&(start, end, element, count)| {
            if element >= candidate.element || count * 2 < candidate.count {
                return false;
            }
            // Same stride: compare where the counter sits within the wide field.
            let offset_in_field = (start % stride + stride - candidate.start % stride) % stride;
            let overlaps = start < candidate.end() && end > candidate.start;
            overlaps && offset_in_field + element <= candidate.element
        });
        if explained {
            candidate.weak = true;
        }
    }

    // Evidence score: more elements is better, specific kinds count for more,
    // and interpretations that are misaligned or ambiguous are discounted.
    let score = |pattern: &Pattern| -> f32 {
        let kind_weight = match pattern.kind {
            PatternKind::Timestamp => 3.0,
            PatternKind::Counter if pattern.element == 1 => 1.5,
            PatternKind::Counter => 2.0,
            PatternKind::OffsetTable => 1.5,
            _ => 1.0,
        };
        let misaligned = pattern.element > 0 && !pattern.start.is_multiple_of(pattern.element);
        let alignment = if misaligned { 0.5 } else { 1.0 };
        let certainty = if pattern.weak { 0.3 } else { 1.0 };
        // Bytes explained per stride: a u16 read out of every f32 explains half
        // as much as the float array itself.
        let density = pattern.element as f32 / pattern.stride.max(pattern.element).max(1) as f32;
        pattern.count as f32 * kind_weight * density * alignment * certainty
    };
    let size_rank = |element: usize| match element {
        4 => 0,
        8 => 1,
        2 => 2,
        _ => 3,
    };
    candidates.sort_by(|a, b| {
        score(b)
            .total_cmp(&score(a))
            .then(size_rank(a.element).cmp(&size_rank(b.element)))
            .then(b.len.cmp(&a.len))
    });

    // Overlap is judged on the bytes a pattern actually reads: a strided
    // field only occupies `element` bytes every `stride`, so two fields of the
    // same record never conflict even though their spans coincide.
    let mut covered = vec![false; window.len()];
    let mut accepted = Vec::new();
    for pattern in candidates {
        let element_ranges = |pattern: &Pattern| -> Vec<std::ops::Range<usize>> {
            if pattern.count > 0 && pattern.stride > pattern.element {
                (0..pattern.count)
                    .map(|k| {
                        let start = pattern.start - base + k * pattern.stride;
                        start..(start + pattern.element).min(window.len())
                    })
                    .collect()
            } else {
                std::iter::once(pattern.start - base..pattern.end() - base).collect()
            }
        };
        let ranges = element_ranges(&pattern);
        let occupied: usize = ranges.iter().map(|r| r.len()).sum();
        let already: usize = ranges.iter().map(|r| covered[r.clone()].iter().filter(|&&c| c).count()).sum();
        // Strong readings tolerate a quarter overlap; weak ones barely any.
        let limit = if pattern.weak { occupied / 10 } else { occupied / 4 };
        if already > limit {
            continue;
        }
        for range in ranges {
            covered[range].fill(true);
        }
        accepted.push(pattern);
    }
    accepted
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

const MIN_TEXT_CHARS: usize = 6;

fn is_text_byte(byte: u8) -> bool {
    (0x20..0x7F).contains(&byte) || matches!(byte, b'\t' | b'\n' | b'\r')
}

fn preview(bytes: &[u8]) -> String {
    let text: String = bytes.iter().take(48).map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { ' ' }).collect();
    if bytes.len() > 48 { format!("{text}…") } else { text }
}

fn scan_text(window: &[u8], base: usize) -> Vec<Pattern> {
    let mut found = Vec::new();
    // ASCII runs.
    let mut start = None;
    for (index, &byte) in window.iter().enumerate() {
        match (is_text_byte(byte), start) {
            (true, None) => start = Some(index),
            (false, Some(s)) => {
                if index - s >= MIN_TEXT_CHARS {
                    found.push(ascii_pattern(window, base, s, index));
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start
        && window.len() - s >= MIN_TEXT_CHARS
    {
        found.push(ascii_pattern(window, base, s, window.len()));
    }

    // UTF-16LE: printable byte followed by zero, repeated.
    let mut index = 0;
    while index + 1 < window.len() {
        let mut end = index;
        while end + 1 < window.len() && (0x20..0x7F).contains(&window[end]) && window[end + 1] == 0 {
            end += 2;
        }
        let chars = (end - index) / 2;
        if chars >= MIN_TEXT_CHARS {
            let text: String = window[index..end].iter().step_by(2).take(48).map(|&b| b as char).collect();
            found.push(Pattern {
                kind: PatternKind::Utf16Text,
                start: base + index,
                len: end - index,
                stride: 2,
                count: chars,
                element: 2,
                weak: false,
                description: format!("UTF-16LE text, {chars} chars: \"{text}\""),
            });
            index = end;
        } else {
            index += 1;
        }
    }
    found
}

fn ascii_pattern(window: &[u8], base: usize, start: usize, end: usize) -> Pattern {
    Pattern {
        kind: PatternKind::AsciiText,
        start: base + start,
        len: end - start,
        stride: 1,
        count: end - start,
        element: 1,
        weak: false,
        description: format!("ASCII text, {} chars: \"{}\"", end - start, preview(&window[start..end])),
    }
}

// ---------------------------------------------------------------------------
// Compressed streams
// ---------------------------------------------------------------------------

fn scan_compressed(window: &[u8], base: usize) -> Vec<Pattern> {
    compress::scan_streams(window, base)
        .into_iter()
        .map(|stream| Pattern {
            kind: PatternKind::Compressed,
            start: stream.start,
            len: stream.compressed_len,
            stride: 0,
            count: 0,
            element: 0,
            weak: false,
            description: stream.describe(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Padding, entropy, signatures
// ---------------------------------------------------------------------------

const MIN_PADDING_RUN: usize = 32;

fn scan_padding(window: &[u8], base: usize) -> Vec<Pattern> {
    let mut found = Vec::new();
    let mut start = 0;
    while start < window.len() {
        let byte = window[start];
        let mut end = start + 1;
        while end < window.len() && window[end] == byte {
            end += 1;
        }
        if end - start >= MIN_PADDING_RUN {
            found.push(Pattern {
                kind: PatternKind::Padding,
                start: base + start,
                len: end - start,
                stride: 1,
                count: end - start,
                element: 1,
                weak: false,
                description: format!("Padding: 0x{byte:02X} repeated {} times", end - start),
            });
        }
        start = end;
    }
    found
}

const ENTROPY_BLOCK: usize = 1024;
/// Random bytes in a 1 KiB block average about 7.8 bits; real data rarely
/// exceeds 7 unless compressed or encrypted.
const HIGH_ENTROPY_BITS: f32 = 7.4;
const MIN_HIGH_ENTROPY_RUN: usize = 2048;

fn scan_high_entropy(window: &[u8], base: usize) -> Vec<Pattern> {
    let blocks: Vec<f32> = window.par_chunks(ENTROPY_BLOCK).map(shannon_entropy).collect();
    let mut found = Vec::new();
    let mut index = 0;
    while index < blocks.len() {
        if blocks[index] < HIGH_ENTROPY_BITS {
            index += 1;
            continue;
        }
        let mut end = index;
        while end < blocks.len() && blocks[end] >= HIGH_ENTROPY_BITS {
            end += 1;
        }
        let start_byte = index * ENTROPY_BLOCK;
        let end_byte = (end * ENTROPY_BLOCK).min(window.len());
        if end_byte - start_byte >= MIN_HIGH_ENTROPY_RUN {
            let mean = blocks[index..end].iter().sum::<f32>() / (end - index) as f32;
            found.push(Pattern {
                kind: PatternKind::HighEntropy,
                start: base + start_byte,
                len: end_byte - start_byte,
                stride: 0,
                count: 0,
                element: 0,
                weak: false,
                description: format!(
                    "High entropy ({mean:.2} bits/byte) over {} KiB: likely compressed, encrypted or random",
                    (end_byte - start_byte) / 1024
                ),
            });
        }
        index = end;
    }
    found
}

struct Signature {
    bytes: &'static [u8],
    name: &'static str,
}

const SIGNATURES: &[Signature] = &[
    Signature { bytes: b"\x89PNG\r\n\x1a\n", name: "PNG image" },
    Signature { bytes: b"\xFF\xD8\xFF", name: "JPEG image" },
    Signature { bytes: b"GIF87a", name: "GIF image" },
    Signature { bytes: b"GIF89a", name: "GIF image" },
    Signature { bytes: b"PK\x03\x04", name: "ZIP archive entry" },
    Signature { bytes: b"PK\x05\x06", name: "ZIP end of central directory" },
    Signature { bytes: b"\x1F\x8B\x08", name: "gzip stream" },
    Signature { bytes: b"BZh", name: "bzip2 stream" },
    Signature { bytes: b"\xFD7zXZ\x00", name: "xz stream" },
    Signature { bytes: b"7z\xBC\xAF\x27\x1C", name: "7-Zip archive" },
    Signature { bytes: b"\x28\xB5\x2F\xFD", name: "Zstandard frame" },
    Signature { bytes: b"\x04\x22\x4D\x18", name: "LZ4 frame" },
    Signature { bytes: b"\x7FELF", name: "ELF executable" },
    Signature { bytes: b"\xFE\xED\xFA\xCE", name: "Mach-O 32-bit" },
    Signature { bytes: b"\xFE\xED\xFA\xCF", name: "Mach-O 64-bit" },
    Signature { bytes: b"\xCF\xFA\xED\xFE", name: "Mach-O 64-bit (LE)" },
    Signature { bytes: b"\xCA\xFE\xBA\xBE", name: "Mach-O universal / Java class" },
    Signature { bytes: b"%PDF-", name: "PDF document" },
    Signature { bytes: b"RIFF", name: "RIFF container (WAV, AVI, WebP)" },
    Signature { bytes: b"SQLite format 3\x00", name: "SQLite database" },
    Signature { bytes: b"OggS", name: "Ogg container" },
    Signature { bytes: b"fLaC", name: "FLAC audio" },
    Signature { bytes: b"II*\x00", name: "TIFF image (LE)" },
    Signature { bytes: b"MM\x00*", name: "TIFF image (BE)" },
    Signature { bytes: b"\xD4\xC3\xB2\xA1", name: "pcap capture" },
    Signature { bytes: b"\xA1\xB2\xC3\xD4", name: "pcap capture (BE)" },
    Signature { bytes: b"\x0A\x0D\x0D\x0A", name: "pcapng section" },
    Signature { bytes: b"\x00asm", name: "WebAssembly module" },
    Signature { bytes: b"\x1A\x45\xDF\xA3", name: "Matroska / WebM" },
    Signature { bytes: b"#!/", name: "Script shebang" },
    Signature { bytes: b"<?xml", name: "XML document" },
    Signature { bytes: b"\xEF\xBB\xBF", name: "UTF-8 byte order mark" },
];

fn scan_signatures(window: &[u8], base: usize) -> Vec<Pattern> {
    let mut found = Vec::new();
    // Index signatures by first byte so each position does little work.
    let mut by_first: Vec<Vec<&Signature>> = vec![Vec::new(); 256];
    for signature in SIGNATURES {
        by_first[signature.bytes[0] as usize].push(signature);
    }
    for (index, &byte) in window.iter().enumerate() {
        for signature in &by_first[byte as usize] {
            if window[index..].starts_with(signature.bytes) {
                found.push(Pattern {
                    kind: PatternKind::Signature,
                    start: base + index,
                    len: signature.bytes.len(),
                    stride: 0,
                    count: 0,
                    element: 0,
                    weak: false,
                    description: format!("{} signature", signature.name),
                });
            }
        }
        if byte == b'M' && window[index..].starts_with(b"MZ") && is_pe_header(&window[index..]) {
            found.push(Pattern {
                kind: PatternKind::Signature,
                start: base + index,
                len: 2,
                stride: 0,
                count: 0,
                element: 0,
                weak: false,
                description: "Windows PE executable (MZ header with PE signature)".to_string(),
            });
        }
    }
    found
}

/// An "MZ" stub is only a PE file when the pointer at 0x3C reaches "PE\0\0".
fn is_pe_header(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 {
        return false;
    }
    let pe_offset = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    bytes.get(pe_offset..pe_offset + 4) == Some(b"PE\0\0")
}

// ---------------------------------------------------------------------------
// Time formatting (UTC, proleptic Gregorian) without a date crate
// ---------------------------------------------------------------------------

/// Format Unix seconds as `YYYY-MM-DD HH:MM:SS UTC`.
pub fn format_unix_seconds(seconds: u64) -> String {
    let CivilTime { year, month, day, hour, minute, second } = CivilTime::of_unix_seconds(seconds);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

/// Format Unix seconds as an RFC 3339 UTC timestamp to the second,
/// `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_unix_seconds_rfc3339(seconds: u64) -> String {
    let CivilTime { year, month, day, hour, minute, second } = CivilTime::of_unix_seconds(seconds);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// A moment in UTC as calendar date and time of day.
struct CivilTime {
    year: i64,
    month: u32,
    day: u32,
    hour: u64,
    minute: u64,
    second: u64,
}

impl CivilTime {
    fn of_unix_seconds(seconds: u64) -> CivilTime {
        let (year, month, day) = civil_from_days((seconds / 86_400) as i64);
        let in_day = seconds % 86_400;
        CivilTime { year, month, day, hour: in_day / 3600, minute: (in_day % 3600) / 60, second: in_day % 60 }
    }
}

/// Howard Hinnant's days-to-civil algorithm.
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Timestamp readings of the bytes at the cursor, for the inspector.
pub fn timestamp_readings(bytes: &[u8]) -> Vec<(String, String)> {
    let mut readings = Vec::new();
    if bytes.len() >= 4 {
        let four = [bytes[0], bytes[1], bytes[2], bytes[3]];
        for (label, value) in [("u32 LE", u32::from_le_bytes(four)), ("u32 BE", u32::from_be_bytes(four))] {
            if let Some(seconds) = TimeFormat::UnixSeconds.to_unix_seconds(value as u64) {
                readings.push((format!("{label} as Unix time"), format_unix_seconds(seconds)));
            }
        }
    }
    if bytes.len() >= 8 {
        let eight: [u8; 8] = bytes[..8].try_into().expect("checked length");
        let little = u64::from_le_bytes(eight);
        if let Some(seconds) = TimeFormat::UnixMillis.to_unix_seconds(little) {
            readings.push(("u64 LE as Unix ms".to_string(), format_unix_seconds(seconds)));
        }
        if let Some(seconds) = TimeFormat::FileTime.to_unix_seconds(little) {
            readings.push(("u64 LE as FILETIME".to_string(), format_unix_seconds(seconds)));
        }
    }
    readings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(len: usize) -> ScanContext {
        ScanContext { base: 0, document_len: len, strides: vec![12] }
    }

    fn xorshift(state: &mut u32) -> u8 {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        (*state >> 24) as u8
    }

    fn of_kind(patterns: &[Pattern], kind: PatternKind) -> Vec<&Pattern> {
        patterns.iter().filter(|p| p.kind == kind).collect()
    }

    #[test]
    fn a_window_of_many_short_rising_runs_is_scanned_in_reasonable_time() {
        // u32 values 1, 2, 3, 4, 100 over and over: every five values make a
        // short counter and a short offset table, tens of thousands of each
        // in one window. Checking each table against every counter took
        // minutes; checking it against the counters near it takes moments.
        let window: Vec<u8> = (0..2usize << 20).step_by(4).flat_map(|at| [1u32, 2, 3, 4, 100][(at / 4) % 5].to_le_bytes()).collect();
        let started = std::time::Instant::now();
        let patterns = scan_numeric_sequences(&window, &context(window.len()), &[4]);
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "took {:?}", started.elapsed());
        assert!(!of_kind(&patterns, PatternKind::Counter).is_empty());
    }

    #[test]
    fn finds_a_u32_counter_inside_fixed_size_records() {
        let mut data = Vec::new();
        for i in 0u32..200 {
            data.extend_from_slice(&i.to_le_bytes());
            data.extend_from_slice(&0xBEEFu16.to_le_bytes());
            data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        }
        let patterns = scan(&data, &context(data.len()));
        let counters = of_kind(&patterns, PatternKind::Counter);
        let counter = counters.iter().find(|p| p.stride == 12 && p.start == 0).unwrap_or_else(|| panic!("stride-12 counter in {counters:?}"));
        assert_eq!(counter.count, 200);
        assert!(counter.description.contains("u32 LE +1"), "{}", counter.description);
    }

    #[test]
    fn a_counter_byte_with_noise_below_it_is_not_a_timestamp() {
        // Records: AA 55 <counter> <61 random bytes>. Read big-endian from
        // offset 1, each record looks like an ever-increasing 2015 timestamp.
        let mut state = 0x9E37_79B9u32;
        let data: Vec<u8> = (0..65536)
            .map(|i| match i % 64 {
                0 => 0xAA,
                1 => 0x55,
                2 => (i / 64) as u8,
                _ => xorshift(&mut state),
            })
            .collect();
        let patterns = scan(&data, &ScanContext { base: 0, document_len: data.len(), strides: vec![64] });
        let counters = of_kind(&patterns, PatternKind::Counter);
        assert!(
            counters.iter().any(|p| p.start == 2 && p.stride == 64 && p.element == 1 && p.count == 1024),
            "counters: {counters:?}, timestamps: {:?}",
            of_kind(&patterns, PatternKind::Timestamp)
        );
        // Short chance runs may appear, but only as weak readings.
        let timestamps: Vec<_> = of_kind(&patterns, PatternKind::Timestamp).into_iter().filter(|p| !p.weak).collect();
        assert!(timestamps.is_empty(), "{timestamps:?}");
    }

    #[test]
    fn finds_monotonic_unix_timestamps() {
        let mut data = vec![0u8; 16];
        let mut t = 1_700_000_000u32;
        for k in 0..10u32 {
            data.extend_from_slice(&t.to_le_bytes());
            data.extend_from_slice(&[0xAA; 4]);
            // Irregular intervals, as in a real log. A perfectly regular clock
            // is reported as a counter with a Unix-time note instead.
            t += 30 + (k * k * 7) % 100;
        }
        let patterns = scan(&data, &context(data.len()));
        let stamps = of_kind(&patterns, PatternKind::Timestamp);
        let stamp = stamps.first().expect("a timestamp run");
        assert_eq!(stamp.start, 16);
        assert_eq!(stamp.count, 10);
        assert!(stamp.description.contains("2023-11-14"), "{}", stamp.description);
    }

    #[test]
    fn a_timestamp_title_names_its_byte_order_once() {
        let mut data = Vec::new();
        let mut t = 1_700_000_000u32;
        for k in 0..10u32 {
            data.extend_from_slice(&t.to_le_bytes());
            data.extend_from_slice(&[0xAA; 4]);
            t += 30 + (k * k * 7) % 100;
        }
        let patterns = scan(&data, &context(data.len()));
        let stamps = of_kind(&patterns, PatternKind::Timestamp);
        let finding = Finding::from(stamps[0].clone());
        assert!(finding.title.starts_with("Unix seconds (u32 LE) every 8 B"), "{}", finding.title);
    }

    #[test]
    fn finds_ascii_and_utf16_text_and_padding() {
        let mut data = vec![0u8; 64];
        data.extend_from_slice(b"Hello, binary world!");
        data.extend_from_slice(&[0xFF; 40]);
        for ch in "wide text".encode_utf16() {
            data.extend_from_slice(&ch.to_le_bytes());
        }
        let patterns = scan(&data, &context(data.len()));
        let ascii = of_kind(&patterns, PatternKind::AsciiText);
        assert_eq!(ascii.len(), 1);
        assert_eq!(ascii[0].start, 64);
        assert_eq!(ascii[0].len, 20);
        let wide = of_kind(&patterns, PatternKind::Utf16Text);
        assert_eq!(wide.len(), 1);
        assert!(wide[0].description.contains("wide text"));
        let padding = of_kind(&patterns, PatternKind::Padding);
        assert_eq!(padding.len(), 2);
    }

    #[test]
    fn finds_float_arrays_and_offset_tables() {
        let mut data = Vec::new();
        for i in 0..32 {
            data.extend_from_slice(&((i as f32) * 0.25 + 1.0).to_le_bytes());
        }
        let float_end = data.len();
        for i in 1..12u32 {
            data.extend_from_slice(&(i * i * 5 + 100).to_be_bytes());
        }
        data.extend_from_slice(&[0u8; 2048]);
        let patterns = scan(&data, &context(data.len()));
        let floats = of_kind(&patterns, PatternKind::FloatArray);
        assert!(floats.iter().any(|p| p.start == 0 && p.len == float_end), "{floats:?}");
        let tables = of_kind(&patterns, PatternKind::OffsetTable);
        assert!(tables.iter().any(|p| p.start == float_end && p.count == 11), "{tables:?}");
    }

    #[test]
    fn finds_file_signatures_including_pe_only_with_a_valid_pointer() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        data.extend_from_slice(&[0u8; 8]);
        let mz_at = data.len();
        let mut pe = vec![0u8; 0x80];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C..0x40].copy_from_slice(&0x60u32.to_le_bytes());
        pe[0x60..0x64].copy_from_slice(b"PE\0\0");
        data.extend_from_slice(&pe);
        data.extend_from_slice(b"MZ not a pe file");
        let patterns = scan(&data, &context(data.len()));
        let signatures = of_kind(&patterns, PatternKind::Signature);
        assert!(signatures.iter().any(|p| p.start == 8 && p.description.contains("PNG")));
        let pe_hits: Vec<_> = signatures.iter().filter(|p| p.description.contains("PE")).collect();
        assert_eq!(pe_hits.len(), 1);
        assert_eq!(pe_hits[0].start, mz_at);
    }

    #[test]
    fn pcapng_section_headers_are_recognised_by_their_real_magic() {
        let mut data = vec![0u8; 16];
        data.extend_from_slice(&[0x0A, 0x0D, 0x0D, 0x0A, 0x1C, 0, 0, 0, 0x4D, 0x3C, 0x2B, 0x1A]);
        data.extend_from_slice(&[0u8; 16]);
        let patterns = scan(&data, &context(data.len()));
        let signatures = of_kind(&patterns, PatternKind::Signature);
        assert!(signatures.iter().any(|p| p.start == 16 && p.description.contains("pcapng")), "{signatures:?}");
    }

    #[test]
    fn verified_streams_replace_signatures_and_entropy_regions() {
        let mut text = Vec::new();
        for i in 0..2000 {
            text.extend_from_slice(format!("line {i} of some very compressible text\n").as_bytes());
        }
        let packed = compress::compress(compress::Codec::Gzip, &text).unwrap();
        let mut data = vec![0u8; 256];
        let at = data.len();
        data.extend_from_slice(&packed);
        data.extend_from_slice(&[0u8; 256]);
        let patterns = scan(&data, &context(data.len()));
        let streams = of_kind(&patterns, PatternKind::Compressed);
        assert_eq!(streams.len(), 1, "{patterns:?}");
        assert_eq!((streams[0].start, streams[0].len), (at, packed.len()));
        assert!(streams[0].description.starts_with("gzip stream"), "{}", streams[0].description);
        assert!(of_kind(&patterns, PatternKind::Signature).is_empty(), "signature should be subsumed");
        assert!(of_kind(&patterns, PatternKind::HighEntropy).is_empty(), "entropy region should be subsumed");
    }

    #[test]
    fn flags_high_entropy_regions() {
        let mut state = 0x2545_F491u32;
        let mut data = vec![0u8; 4096];
        data.extend((0..8192).map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        }));
        let patterns = scan(&data, &context(data.len()));
        let regions = of_kind(&patterns, PatternKind::HighEntropy);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].start, 4096);
    }

    #[test]
    fn random_bytes_produce_few_numeric_false_positives() {
        let mut state = 0x1234_5678u32;
        let data: Vec<u8> = (0..65536)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect();
        let patterns = scan(&data, &context(data.len()));
        let numeric = patterns
            .iter()
            .filter(|p| matches!(p.kind, PatternKind::Counter | PatternKind::Timestamp | PatternKind::OffsetTable | PatternKind::FloatArray))
            .count();
        assert!(numeric <= 3, "{numeric} numeric patterns in noise: {:?}", patterns.iter().filter(|p| p.kind != PatternKind::HighEntropy).collect::<Vec<_>>());
    }

    #[test]
    fn extreme_64_bit_deltas_do_not_overflow() {
        let mut data = Vec::new();
        for value in [0u64, 1 << 63, 0, 1 << 63, 0, 1 << 63] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        let patterns = scan(&data, &context(data.len()));
        assert!(of_kind(&patterns, PatternKind::Counter).is_empty());
    }

    #[test]
    fn builtin_detectors_report_through_the_plugin_api() {
        let mut data = Vec::new();
        for i in 0u32..500 {
            data.extend_from_slice(&i.to_le_bytes());
            data.extend_from_slice(&[0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03]);
        }
        let context = ScanContext { base: 0, document_len: data.len(), strides: vec![24] };
        let detectors = builtin_detectors();
        assert_eq!(detectors.len(), 6);
        let sequences = detectors.iter().find(|d| d.id() == "builtin.sequences").unwrap();
        let findings = sequences.scan(&data, &context);
        let counter = findings
            .iter()
            .find(|f| f.category == Category::Counter)
            .unwrap_or_else(|| panic!("a counter finding in {:?}", findings.iter().map(|f| (f.category, f.start, f.description())).collect::<Vec<_>>()));
        assert_eq!(counter.source, "builtin");
        assert_eq!(counter.sequence.map(|s| s.stride), Some(24));
        assert!(counter.title.starts_with("Counter"), "{}", counter.title);
    }

    #[test]
    fn overlap_resolution_prefers_verified_streams() {
        let mut findings = vec![
            Finding::new("sig", "a", Category::Signature, 100, 3).title("gzip"),
            Finding::new("stream", "b", Category::Compressed, 100, 5000).title("gzip stream"),
            Finding::new("entropy", "c", Category::HighEntropy, 0, 6000).title("entropy"),
            Finding::new("sig", "a", Category::Signature, 100, 3).title("gzip"),
        ];
        resolve_overlaps(&mut findings);
        let categories: Vec<Category> = findings.iter().map(|f| f.category).collect();
        assert_eq!(categories, vec![Category::Compressed]);
    }

    #[test]
    fn formats_unix_time_as_utc() {
        assert_eq!(format_unix_seconds(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_unix_seconds(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(format_unix_seconds(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_unix_seconds_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_seconds_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn inspector_readings_only_report_plausible_dates() {
        let readings = timestamp_readings(&1_700_000_000u32.to_le_bytes());
        assert_eq!(readings.len(), 1);
        assert_eq!(readings[0].0, "u32 LE as Unix time");
        assert!(timestamp_readings(&[0, 0, 0, 0]).is_empty());
    }
}




