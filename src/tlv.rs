//! Length fields, tag-length-value chains and offset tables.
//!
//! Many formats describe their own layout with numbers that equal distances:
//! a length prefix that counts the bytes after it, a chain of
//! (tag, length, value) records each saying where the next begins, or a
//! table of offsets to structures further on. These hypotheses are tested
//! directly: read a number, follow it, and see whether it lands exactly
//! where it should, again and again.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use rayon::prelude::*;

/// Largest region walked for chains and offset tables.
pub const MAX_REGION: usize = 256 * 1024;
/// Length prefixes are looked for in the first this many bytes of the region.
const MAX_PREFIX_OFFSET: usize = 64;
/// Constants added to a length before it matches (−4..=4).
const ADJUSTMENTS: std::ops::RangeInclusive<i64> = -4..=4;
/// Chains may start a few bytes into the region, after a small header.
const MAX_CHAIN_START: usize = 8;
/// Tag widths tried for chains (0: plain length-prefixed chunks).
const TAG_WIDTHS: [usize; 4] = [0, 1, 2, 4];
/// Fewest records for a believable chain or offset table.
const MIN_RECORDS: usize = 3;
/// Records shorter than this on average are degenerate walks over padding.
const MIN_MEAN_RECORD: usize = 3;
/// Most records followed in one walk.
const MAX_WALK_RECORDS: usize = 100_000;
/// Records kept as an example walk.
const EXAMPLE_STEPS: usize = 8;
/// Most hypotheses returned.
const MAX_HYPOTHESES: usize = 30;
/// Longest LEB128 varint read (enough for a u64).
const MAX_VARINT_BYTES: usize = 10;

/// How a length (or offset) is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LengthEncoding {
    U8,
    U16Le,
    U16Be,
    U32Le,
    U32Be,
    /// Unsigned LEB128 varint (protobuf, WebAssembly, DWARF).
    Leb128,
}

impl LengthEncoding {
    pub const ALL: [LengthEncoding; 6] = [LengthEncoding::U8, LengthEncoding::U16Le, LengthEncoding::U16Be, LengthEncoding::U32Le, LengthEncoding::U32Be, LengthEncoding::Leb128];

    pub fn label(self) -> &'static str {
        match self {
            LengthEncoding::U8 => "u8",
            LengthEncoding::U16Le => "u16 LE",
            LengthEncoding::U16Be => "u16 BE",
            LengthEncoding::U32Le => "u32 LE",
            LengthEncoding::U32Be => "u32 BE",
            LengthEncoding::Leb128 => "LEB128",
        }
    }

    /// Read a value at `position`: (value, bytes used), or `None` past the end
    /// or for an unterminated varint.
    pub fn read(self, bytes: &[u8], position: usize) -> Option<(u64, usize)> {
        let fixed = |width: usize, little_endian: bool| -> Option<(u64, usize)> {
            let field = bytes.get(position..position.checked_add(width)?)?;
            let fold = |value: u64, &byte: &u8| (value << 8) | u64::from(byte);
            let value = if little_endian { field.iter().rev().fold(0, fold) } else { field.iter().fold(0, fold) };
            Some((value, width))
        };
        match self {
            LengthEncoding::U8 => fixed(1, true),
            LengthEncoding::U16Le => fixed(2, true),
            LengthEncoding::U16Be => fixed(2, false),
            LengthEncoding::U32Le => fixed(4, true),
            LengthEncoding::U32Be => fixed(4, false),
            LengthEncoding::Leb128 => read_leb128(bytes.get(position..)?),
        }
    }

    /// A penalty for encodings that match by chance more easily.
    fn chance_penalty(self) -> f64 {
        match self {
            LengthEncoding::U8 | LengthEncoding::Leb128 => 0.9,
            _ => 1.0,
        }
    }
}

/// Decode an unsigned LEB128 varint: (value, bytes used).
pub fn read_leb128(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for (index, &byte) in bytes.iter().take(MAX_VARINT_BYTES).enumerate() {
        value |= u64::from(byte & 0x7F).checked_shl(7 * index as u32).unwrap_or(0);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

/// A field whose value (plus `adjustment`) equals the number of bytes after it to the end of the region.
#[derive(Clone, Debug, PartialEq)]
pub struct LengthPrefix {
    /// Region-relative offset of the field.
    pub offset: usize,
    pub encoding: LengthEncoding,
    /// Bytes the field occupies.
    pub width: usize,
    pub value: u64,
    /// value + adjustment = bytes from the end of the field to the end of the region.
    pub adjustment: i64,
}

/// Find length prefixes near the start of `region` that count the rest of it.
pub fn find_length_prefixes(region: &[u8]) -> Vec<LengthPrefix> {
    let mut found = Vec::new();
    for offset in 0..region.len().min(MAX_PREFIX_OFFSET) {
        for encoding in LengthEncoding::ALL {
            let Some((value, width)) = encoding.read(region, offset) else { continue };
            let remaining = (region.len() - offset - width) as i64;
            let adjustment = remaining - value as i64;
            // A tiny value matching a tiny remainder is coincidence, not a length.
            const MIN_LENGTH: u64 = 2;
            if value >= MIN_LENGTH && ADJUSTMENTS.contains(&adjustment) {
                found.push(LengthPrefix { offset, encoding, width, value, adjustment });
            }
        }
    }
    found
}

/// One record of a chain walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlvStep {
    /// Region-relative offset of the record.
    pub offset: usize,
    pub tag: u64,
    /// The stored length.
    pub length: u64,
    /// Bytes of value that follow the header.
    pub value_len: usize,
}

/// A way of reading a region as consecutive (tag, length, value) records.
#[derive(Clone, Debug, PartialEq)]
pub struct TlvChain {
    /// Region-relative offset of the first record.
    pub start: usize,
    /// Bytes of tag before the length (0: none).
    pub tag_width: usize,
    pub encoding: LengthEncoding,
    /// Whether the stored length counts the tag and length bytes too.
    pub counts_header: bool,
    /// Added to the stored length to get the value length.
    pub adjustment: i64,
    pub records: usize,
    /// Bytes consumed by the walk.
    pub covered: usize,
    /// Whether the walk ends exactly at the end of the region.
    pub exact: bool,
    /// The tag, when every record has the same one (a framed message stream).
    pub constant_tag: Option<u64>,
    /// The first few records.
    pub example: Vec<TlvStep>,
}

/// Parameters of one chain hypothesis.
#[derive(Clone, Copy, Debug)]
struct ChainRule {
    start: usize,
    tag_width: usize,
    encoding: LengthEncoding,
    counts_header: bool,
    adjustment: i64,
}

/// Find ways of walking `region` as a chain of length-prefixed records, best first.
pub fn find_tlv_chains(region: &[u8]) -> Vec<TlvChain> {
    let region = &region[..region.len().min(MAX_REGION)];
    let rules: Vec<ChainRule> = (0..MAX_CHAIN_START.min(region.len()))
        .flat_map(|start| TAG_WIDTHS.into_iter().map(move |tag_width| (start, tag_width)))
        .flat_map(|(start, tag_width)| LengthEncoding::ALL.into_iter().map(move |encoding| (start, tag_width, encoding)))
        .flat_map(|(start, tag_width, encoding)| [false, true].into_iter().map(move |counts_header| (start, tag_width, encoding, counts_header)))
        .flat_map(|(start, tag_width, encoding, counts_header)| ADJUSTMENTS.map(move |adjustment| ChainRule { start, tag_width, encoding, counts_header, adjustment }))
        .collect();
    let walks: Vec<(u64, TlvChain)> = rules.par_iter().filter_map(|rule| walk_chain(region, *rule)).collect();

    // Several rules can produce the same boundaries; keep the best-scoring one of each.
    let mut best_by_walk: HashMap<u64, TlvChain> = HashMap::new();
    for (fingerprint, chain) in walks {
        let score = chain_score(&chain, region.len());
        match best_by_walk.get(&fingerprint) {
            Some(existing) if chain_score(existing, region.len()) >= score => {}
            _ => {
                best_by_walk.insert(fingerprint, chain);
            }
        }
    }
    let mut chains: Vec<TlvChain> = best_by_walk.into_values().collect();
    chains.sort_by(|a, b| chain_score(b, region.len()).total_cmp(&chain_score(a, region.len())).then(a.start.cmp(&b.start)));
    chains.truncate(MAX_HYPOTHESES);
    chains
}

/// Follow one rule from its start. Returns a fingerprint of the record
/// boundaries and the chain, or `None` for a walk too short or degenerate.
fn walk_chain(region: &[u8], rule: ChainRule) -> Option<(u64, TlvChain)> {
    let end = region.len();
    let mut position = rule.start;
    let mut records = 0usize;
    let mut example = Vec::new();
    let mut first_tag: Option<u64> = None;
    let mut tags_constant = true;
    let mut hasher = DefaultHasher::new();
    while position < end && records < MAX_WALK_RECORDS {
        let Some(step) = read_record(region, position, rule) else { break };
        let next = position + rule.tag_width + header_length_width(region, position, rule)? + step.value_len;
        if next > end {
            break;
        }
        match first_tag {
            None => first_tag = Some(step.tag),
            Some(tag) => tags_constant &= tag == step.tag,
        }
        position.hash(&mut hasher);
        if example.len() < EXAMPLE_STEPS {
            example.push(step);
        }
        records += 1;
        position = next;
        let degenerate = records >= 64 && (position - rule.start) < records * MIN_MEAN_RECORD;
        if degenerate {
            return None;
        }
    }
    let covered = position - rule.start;
    if records < MIN_RECORDS || covered < records * MIN_MEAN_RECORD {
        return None;
    }
    let chain = TlvChain {
        start: rule.start,
        tag_width: rule.tag_width,
        encoding: rule.encoding,
        counts_header: rule.counts_header,
        adjustment: rule.adjustment,
        records,
        covered,
        exact: position == end,
        constant_tag: if tags_constant && rule.tag_width > 0 { first_tag } else { None },
        example,
    };
    Some((hasher.finish(), chain))
}

/// Bytes taken by the length field of the record at `position`.
fn header_length_width(region: &[u8], position: usize, rule: ChainRule) -> Option<usize> {
    rule.encoding.read(region, position + rule.tag_width).map(|(_, width)| width)
}

/// Read the tag and length of the record at `position` under `rule`.
fn read_record(region: &[u8], position: usize, rule: ChainRule) -> Option<TlvStep> {
    let tag_bytes = region.get(position..position.checked_add(rule.tag_width)?)?;
    let tag = tag_bytes.iter().fold(0u64, |tag, &byte| (tag << 8) | u64::from(byte));
    let (length, width) = rule.encoding.read(region, position + rule.tag_width)?;
    let header = (rule.tag_width + width) as i64;
    let length_signed = i64::try_from(length).ok()?;
    let value_len = if rule.counts_header { length_signed - header } else { length_signed } + rule.adjustment;
    let value_len = usize::try_from(value_len).ok()?;
    Some(TlvStep { offset: position, tag, length, value_len })
}

/// Plausibility of a chain, 0..1: coverage dominates, then exactness, record
/// count and simplicity of the rule.
pub fn chain_score(chain: &TlvChain, region_len: usize) -> f64 {
    const INEXACT_FACTOR: f64 = 0.7;
    const RECORDS_FOR_FULL_CONFIDENCE: f64 = 8.0;
    const ADJUSTMENT_COST: f64 = 0.04;
    const COUNTS_HEADER_COST: f64 = 0.02;
    const START_COST: f64 = 0.02;
    const TAG_WIDTH_COST: f64 = 0.005;
    // When two readings walk identically, the wider length field also
    // explains the zero bytes above a narrower one.
    const LENGTH_WIDTH_BONUS: f64 = 0.002;
    let coverage = chain.covered as f64 / region_len.max(1) as f64;
    let exactness = if chain.exact { 1.0 } else { INEXACT_FACTOR };
    let confidence = (chain.records as f64 / RECORDS_FOR_FULL_CONFIDENCE).min(1.0);
    let simplicity = 1.0
        - ADJUSTMENT_COST * chain.adjustment.unsigned_abs() as f64
        - if chain.counts_header { COUNTS_HEADER_COST } else { 0.0 }
        - START_COST * chain.start as f64
        - TAG_WIDTH_COST * chain.tag_width as f64
        + LENGTH_WIDTH_BONUS * fixed_width(chain.encoding) as f64;
    (coverage * coverage * exactness * confidence * simplicity * chain.encoding.chance_penalty()).min(1.0)
}

// ---------------------------------------------------------------------------
// Offset tables
// ---------------------------------------------------------------------------

/// What an offset is measured from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OffsetBase {
    /// From the start of the file.
    Absolute,
    /// From the start of the region (the selection or table).
    Region,
    /// From the position of the offset field itself.
    SelfRelative,
}

impl OffsetBase {
    pub fn label(self) -> &'static str {
        match self {
            OffsetBase::Absolute => "file offset",
            OffsetBase::Region => "region-relative",
            OffsetBase::SelfRelative => "self-relative",
        }
    }
}

/// A run of values that point forward to later places in the region.
#[derive(Clone, Debug, PartialEq)]
pub struct OffsetTable {
    /// Region-relative offset of the first entry.
    pub offset: usize,
    pub encoding: LengthEncoding,
    pub base: OffsetBase,
    pub entries: usize,
    /// Region-relative targets of the first entries.
    pub targets: Vec<usize>,
    /// Whether every target starts with the same byte, like a run of structures.
    pub shared_signature: bool,
}

impl OffsetTable {
    /// Bytes the table occupies.
    pub fn len(&self) -> usize {
        self.entries * fixed_width(self.encoding)
    }

    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    pub fn score(&self) -> f64 {
        const ENTRIES_FOR_FULL_CONFIDENCE: f64 = 8.0;
        const SIGNATURE_BONUS: f64 = 1.3;
        const BASE_SCORE: f64 = 0.6;
        let confidence = (self.entries as f64 / ENTRIES_FOR_FULL_CONFIDENCE).min(1.0);
        let signature = if self.shared_signature { SIGNATURE_BONUS } else { 1.0 };
        (BASE_SCORE * confidence * signature).min(1.0)
    }
}

fn fixed_width(encoding: LengthEncoding) -> usize {
    match encoding {
        LengthEncoding::U8 | LengthEncoding::Leb128 => 1,
        LengthEncoding::U16Le | LengthEncoding::U16Be => 2,
        LengthEncoding::U32Le | LengthEncoding::U32Be => 4,
    }
}

/// Find tables of 16- and 32-bit offsets in `region` (which starts at file
/// offset `region_base`) whose values point forward, past the table, to
/// increasing places inside the region.
pub fn find_offset_tables(region: &[u8], region_base: usize) -> Vec<OffsetTable> {
    let region = &region[..region.len().min(MAX_REGION)];
    let encodings = [LengthEncoding::U16Le, LengthEncoding::U16Be, LengthEncoding::U32Le, LengthEncoding::U32Be];
    let bases = [OffsetBase::Absolute, OffsetBase::Region, OffsetBase::SelfRelative];
    let mut tables: Vec<OffsetTable> = encodings
        .par_iter()
        .flat_map_iter(|&encoding| bases.iter().flat_map(move |&base| scan_offset_runs(region, region_base, encoding, base)))
        .collect();
    tables.sort_by(|a, b| b.score().total_cmp(&a.score()).then(b.entries.cmp(&a.entries)).then(a.offset.cmp(&b.offset)));
    tables.truncate(MAX_HYPOTHESES);
    tables
}

/// Resolve an offset value to a region-relative position.
fn resolve(value: u64, base: OffsetBase, field_position: usize, region_base: usize) -> Option<usize> {
    let value = usize::try_from(value).ok()?;
    match base {
        OffsetBase::Absolute => value.checked_sub(region_base),
        OffsetBase::Region => Some(value),
        OffsetBase::SelfRelative => field_position.checked_add(value),
    }
}

/// Runs of aligned values that resolve to strictly increasing positions inside the region.
fn scan_offset_runs(region: &[u8], region_base: usize, encoding: LengthEncoding, base: OffsetBase) -> Vec<OffsetTable> {
    let width = fixed_width(encoding);
    let mut tables = Vec::new();
    let mut run: Vec<usize> = Vec::new();
    let mut run_start = 0;
    let mut position = 0;
    let finish = |run: &mut Vec<usize>, run_start: usize, tables: &mut Vec<OffsetTable>| {
        if let Some(table) = table_from_run(region, run_start, width, encoding, base, run) {
            tables.push(table);
        }
        run.clear();
    };
    while position + width <= region.len() {
        let target = encoding.read(region, position).and_then(|(value, _)| resolve(value, base, position, region_base)).filter(|&target| target < region.len());
        let extends = target.is_some_and(|target| run.last().is_none_or(|&last| target > last));
        match (target, extends) {
            (Some(target), true) => {
                if run.is_empty() {
                    run_start = position;
                }
                run.push(target);
            }
            (Some(target), false) => {
                finish(&mut run, run_start, &mut tables);
                run_start = position;
                run.push(target);
            }
            (None, _) => finish(&mut run, run_start, &mut tables),
        }
        position += width;
    }
    finish(&mut run, run_start, &mut tables);
    tables
}

/// Turn a run of targets into a table if it is long enough, points past
/// itself and is not a counter.
fn table_from_run(region: &[u8], start: usize, width: usize, encoding: LengthEncoding, base: OffsetBase, targets: &[usize]) -> Option<OffsetTable> {
    /// Equal small steps between targets mean a counter, not offsets.
    const COUNTER_STEP: usize = 4;
    if targets.len() < MIN_RECORDS {
        return None;
    }
    let table_end = start + targets.len() * width;
    if targets[0] < table_end {
        return None;
    }
    let steps: Vec<usize> = targets.windows(2).map(|pair| pair[1] - pair[0]).collect();
    if steps.iter().all(|&step| step == steps[0] && step <= COUNTER_STEP) {
        return None;
    }
    let first_byte = region[targets[0]];
    let shared_signature = targets.iter().all(|&target| region[target] == first_byte) && first_byte != 0;
    Some(OffsetTable { offset: start, encoding, base, entries: targets.len(), targets: targets.iter().take(EXAMPLE_STEPS).copied().collect(), shared_signature })
}

// ---------------------------------------------------------------------------
// All hypotheses together
// ---------------------------------------------------------------------------

/// One explanation of the region's layout.
#[derive(Clone, Debug, PartialEq)]
pub enum Hypothesis {
    Prefix(LengthPrefix),
    Chain(TlvChain),
    Offsets(OffsetTable),
}

impl Hypothesis {
    /// Plausibility, 0..1.
    pub fn score(&self, region_len: usize) -> f64 {
        const PREFIX_BASE: f64 = 0.5;
        const ADJUSTMENT_COST: f64 = 0.05;
        match self {
            Hypothesis::Prefix(prefix) => {
                let simplicity = 1.0 - ADJUSTMENT_COST * prefix.adjustment.unsigned_abs() as f64;
                PREFIX_BASE * simplicity * prefix.encoding.chance_penalty()
            }
            Hypothesis::Chain(chain) => chain_score(chain, region_len),
            Hypothesis::Offsets(table) => table.score(),
        }
    }

    /// Region-relative (start, length) of what the hypothesis explains.
    pub fn span(&self, region_len: usize) -> (usize, usize) {
        match self {
            Hypothesis::Prefix(prefix) => (prefix.offset, region_len - prefix.offset),
            Hypothesis::Chain(chain) => (chain.start, chain.covered),
            Hypothesis::Offsets(table) => (table.offset, table.len()),
        }
    }

    /// Fraction of the region explained.
    pub fn coverage(&self, region_len: usize) -> f64 {
        self.span(region_len).1 as f64 / region_len.max(1) as f64
    }

    /// A one-line description.
    pub fn describe(&self) -> String {
        match self {
            Hypothesis::Prefix(prefix) => format!(
                "{} length {} at +{} counts the rest{}",
                prefix.encoding.label(),
                prefix.value,
                prefix.offset,
                signed_suffix(prefix.adjustment)
            ),
            Hypothesis::Chain(chain) => {
                let tag = match (chain.tag_width, chain.constant_tag) {
                    (0, _) => "no tag".to_string(),
                    (width, Some(tag)) => format!("{width}-byte tag {tag:#x} on every record"),
                    (width, None) => format!("{width}-byte tag"),
                };
                format!(
                    "{} records: {tag}, {} length{}{}{}, from +{}",
                    chain.records,
                    chain.encoding.label(),
                    if chain.counts_header { " including header" } else { "" },
                    signed_suffix(chain.adjustment),
                    if chain.exact { ", ends exactly" } else { "" },
                    chain.start
                )
            }
            Hypothesis::Offsets(table) => format!(
                "{} {} offsets ({}) at +{} pointing forward{}",
                table.entries,
                table.encoding.label(),
                table.base.label(),
                table.offset,
                if table.shared_signature { " to look-alike structures" } else { "" }
            ),
        }
    }

    /// An example walk: region-relative offsets the hypothesis visits.
    pub fn example(&self) -> String {
        match self {
            Hypothesis::Prefix(prefix) => format!("+{} → end", prefix.offset + prefix.width),
            Hypothesis::Chain(chain) => chain
                .example
                .iter()
                .map(|step| format!("+{} [{:x}] {}", step.offset, step.tag, step.value_len))
                .collect::<Vec<_>>()
                .join(" → "),
            Hypothesis::Offsets(table) => table.targets.iter().map(|target| format!("+{target}")).collect::<Vec<_>>().join(", "),
        }
    }
}

fn signed_suffix(adjustment: i64) -> String {
    if adjustment == 0 { String::new() } else { format!(" {adjustment:+}") }
}

/// Every hypothesis for `region` (at file offset `region_base`), best first.
pub fn analyse(region: &[u8], region_base: usize) -> Vec<Hypothesis> {
    let region = &region[..region.len().min(MAX_REGION)];
    let mut hypotheses: Vec<Hypothesis> = find_tlv_chains(region).into_iter().map(Hypothesis::Chain).collect();
    hypotheses.extend(find_length_prefixes(region).into_iter().map(Hypothesis::Prefix));
    hypotheses.extend(find_offset_tables(region, region_base).into_iter().map(Hypothesis::Offsets));
    let region_len = region.len();
    hypotheses.sort_by(|a, b| b.score(region_len).total_cmp(&a.score(region_len)));
    hypotheses.truncate(MAX_HYPOTHESES);
    hypotheses
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records of (1-byte tag, u16 BE length, value).
    fn tlv_region() -> Vec<u8> {
        let mut region = Vec::new();
        for (index, length) in [5u16, 12, 0, 30, 7, 19, 3, 44, 9, 2].iter().enumerate() {
            region.push(0x10 + index as u8);
            region.extend(length.to_be_bytes());
            region.extend((0..*length).map(|byte| (byte as u8).wrapping_mul(31).wrapping_add(index as u8)));
        }
        region
    }

    #[test]
    fn leb128_varints_decode() {
        assert_eq!(read_leb128(&[0x05]), Some((5, 1)));
        assert_eq!(read_leb128(&[0xE5, 0x8E, 0x26]), Some((624_485, 3)));
        assert_eq!(read_leb128(&[0x80, 0x80]), None, "unterminated");
        assert_eq!(read_leb128(&[0xFF; 20]), None, "too long");
    }

    #[test]
    fn a_tlv_region_is_walked_exactly() {
        let region = tlv_region();
        let chains = find_tlv_chains(&region);
        let best = chains.first().expect("a chain");
        assert_eq!((best.tag_width, best.encoding, best.counts_header, best.adjustment), (1, LengthEncoding::U16Be, false, 0));
        assert!(best.exact);
        assert_eq!(best.records, 10);
        assert_eq!(best.covered, region.len());
        assert_eq!(best.example[1], TlvStep { offset: 8, tag: 0x11, length: 12, value_len: 12 });
    }

    #[test]
    fn lengths_that_include_the_header_are_found() {
        // u32 LE length counting itself, no tag, like RIFF-style chunks with an inclusive size.
        let mut region = Vec::new();
        for length in [10u32, 25, 8, 40, 13] {
            region.extend(length.to_le_bytes());
            region.extend(vec![0xAB; length as usize - 4]);
        }
        let best = find_tlv_chains(&region).into_iter().next().expect("a chain");
        assert!(best.exact);
        assert_eq!(best.records, 5);
        assert_eq!(best.encoding, LengthEncoding::U32Le);
        assert!(best.counts_header || best.adjustment == -4);
    }

    #[test]
    fn a_length_prefix_counting_the_rest_is_found() {
        let mut region = vec![0x7E, 0x01];
        let body = b"payload of some length";
        region.extend((body.len() as u16 + 2).to_le_bytes()); // counts a 2-byte trailer too
        region.extend(body);
        region.extend([0xCA, 0xFE]);
        let found = find_length_prefixes(&region);
        assert!(found.iter().any(|p| p.offset == 2 && p.encoding == LengthEncoding::U16Le && p.adjustment == 0), "{found:?}");
    }

    #[test]
    fn an_offset_table_to_look_alike_structures_is_found() {
        // Header: four u32 LE region-relative offsets, then four records starting with 'R'.
        let mut region = vec![0u8; 16];
        let mut targets = Vec::new();
        for length in [20usize, 33, 12, 50] {
            targets.push(region.len());
            region.push(b'R');
            region.extend(vec![0x11; length - 1]);
        }
        for (index, &target) in targets.iter().enumerate() {
            region[index * 4..index * 4 + 4].copy_from_slice(&(target as u32).to_le_bytes());
        }
        let tables = find_offset_tables(&region, 0x1000);
        let table = tables.iter().find(|t| t.base == OffsetBase::Region && t.encoding == LengthEncoding::U32Le).expect("table found");
        assert_eq!(table.entries, 4);
        assert!(table.shared_signature);
        assert_eq!(table.targets, targets);
    }

    #[test]
    fn analysis_ranks_the_exact_chain_first() {
        let region = tlv_region();
        let hypotheses = analyse(&region, 0);
        assert!(matches!(&hypotheses[0], Hypothesis::Chain(chain) if chain.exact && chain.records == 10));
        assert!((hypotheses[0].coverage(region.len()) - 1.0).abs() < f64::EPSILON);
        assert!(hypotheses[0].describe().contains("10 records"));
    }

    #[test]
    fn random_or_empty_regions_do_not_panic() {
        assert!(analyse(&[], 0).is_empty());
        let mut state = 12345u64;
        let noise: Vec<u8> = (0..4096)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect();
        let hypotheses = analyse(&noise, 0);
        assert!(hypotheses.iter().all(|h| h.score(noise.len()) < 0.9));
    }
}
