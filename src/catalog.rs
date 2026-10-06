//! Signature catalogue: a data model for magic-byte signatures, a TOML
//! loader, and a matching engine built on one Aho-Corasick automaton.
//!
//! Entries come from two embedded files, `catalog/tika.toml` (imported from
//! Apache Tika's mimetypes database by `src/bin/import_catalog.rs`) and
//! `catalog/curated.toml` (hand-written, with extents), plus any TOML files
//! the user drops into a directory passed to [`Catalog::load_dir`].
//!
//! Matching semantics follow Tika: a signature has several *alternatives*
//! (any one may match); an alternative lists *matches* that must all hold;
//! each match may carry *children*, of which at least one must hold. All
//! offsets are relative to the candidate start of the file, which lets a hit
//! anywhere in a window be reported as "a file of this type begins here".

use std::collections::HashMap;
use std::path::Path;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind as AcMatchKind};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::plugin::{Category, Detector, Finding, ScanContext};

/// Bytes of literal positions each parallel scan task covers.
const SCAN_CHUNK: usize = 128 * 1024;
/// How far a chunk's search runs past its end, to catch literals that start
/// inside the chunk but finish after it. Longer than any catalogue literal.
const MAX_LITERAL_OVERLAP: usize = 1024;
/// The detector only reports findings at least this confident; weaker hits
/// (two-byte magics and the like) fire constantly in ordinary data.
const DETECTOR_MIN_CONFIDENCE: f32 = 0.5;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// One recognisable file type or structure.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SignatureDef {
    /// Stable identifier, e.g. `image/png` or `firmware/uimage`.
    pub id: String,
    pub name: String,
    /// A [`Category`] name, e.g. "Image". Defaults to "Signature".
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    /// Tika-style priority; higher wins when two signatures match at the same offset.
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// Overrides the computed confidence (0 to 1) when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    /// Alternatives; any one matching is enough.
    #[serde(default)]
    pub magic: Vec<Alternative>,
    /// How long the matched block is. Without one, the finding spans the magic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extent: Option<ExtentDef>,
}

fn default_category() -> String {
    "Signature".to_string()
}

fn default_priority() -> u32 {
    50
}

/// A set of matches that must all hold. In TOML an alternative is written
/// either as a single match table, or as `{ matches = [...] }`.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Alternative {
    pub matches: Vec<MatchDef>,
}

impl<'de> Deserialize<'de> for Alternative {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Multi {
                #[serde(alias = "all")]
                matches: Vec<MatchDef>,
            },
            Single(MatchDef),
        }
        Ok(match Raw::deserialize(deserializer)? {
            Raw::Multi { matches } => Alternative { matches },
            Raw::Single(single) => Alternative { matches: vec![single] },
        })
    }
}

/// Where a match may begin, relative to the candidate file start. A fixed
/// offset is written as a number; a range as `"0..8192"` (inclusive).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[derive(Default)]
pub struct OffsetDef {
    pub start: u64,
    pub end: u64,
}


impl OffsetDef {
    pub fn fixed(offset: u64) -> Self {
        OffsetDef { start: offset, end: offset }
    }

    pub fn is_fixed(&self) -> bool {
        self.start == self.end
    }
}

impl Serialize for OffsetDef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.is_fixed() {
            serializer.serialize_u64(self.start)
        } else {
            serializer.serialize_str(&format!("{}..{}", self.start, self.end))
        }
    }
}

impl<'de> Deserialize<'de> for OffsetDef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Fixed(u64),
            Text(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Fixed(offset) => Ok(OffsetDef::fixed(offset)),
            Raw::Text(text) => parse_offset_text(&text).map_err(serde::de::Error::custom),
        }
    }
}

fn parse_offset_text(text: &str) -> Result<OffsetDef, String> {
    let text = text.trim();
    let parse_one = |part: &str| -> Result<u64, String> {
        let part = part.trim();
        if let Some(hex) = part.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).map_err(|e| format!("bad hex offset '{part}': {e}"))
        } else {
            part.parse().map_err(|e| format!("bad offset '{part}': {e}"))
        }
    };
    if let Some((start, end)) = text.split_once("..") {
        let (start, end) = (parse_one(start)?, parse_one(end)?);
        if end < start {
            return Err(format!("offset range '{text}' ends before it starts"));
        }
        Ok(OffsetDef { start, end })
    } else if let Some((start, end)) = text.split_once(':') {
        Ok(OffsetDef { start: parse_one(start)?, end: parse_one(end)? })
    } else {
        Ok(OffsetDef::fixed(parse_one(text)?))
    }
}

/// How the `bytes`/`string` value of a match is interpreted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    /// `bytes` is hex (or `string` is literal text).
    #[default]
    Bytes,
    String,
    Big16,
    Big32,
    Little16,
    Little32,
    /// Host order; treated as little endian.
    Host16,
    Host32,
}

/// Reads the real match offset from a field in the file (e.g. PE's
/// `e_lfanew`), to which the match's own `offset` is then added.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerDef {
    pub offset: u64,
    /// 1, 2, 4 or 8.
    pub size: u8,
    #[serde(default)]
    pub endian: Endian,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    #[default]
    Little,
    Big,
}

/// One comparison against the bytes.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MatchDef {
    #[serde(default)]
    pub offset: OffsetDef,
    /// Hex, e.g. `"89504e47"`. Spaces allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    /// Literal text, used when `bytes` is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub string: Option<String>,
    /// Hex mask ANDed with both the value and the data before comparing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask: Option<String>,
    #[serde(default, skip_serializing_if = "is_default_kind")]
    pub kind: MatchKind,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignore_case: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer: Option<PointerDef>,
    /// At least one child must also match (Tika semantics).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<MatchDef>,
}

fn is_default_kind(kind: &MatchKind) -> bool {
    *kind == MatchKind::Bytes
}

/// Rule for the length of a matched block.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExtentDef {
    Fixed {
        len: u64,
    },
    /// `value_at(offset) * multiply + add`.
    Field {
        offset: u64,
        size: u8,
        #[serde(default)]
        endian: Endian,
        #[serde(default)]
        add: i64,
        #[serde(default = "one")]
        multiply: u64,
    },
    /// Up to and including the terminator (hex), searched within `limit` bytes.
    Until {
        bytes: String,
        #[serde(default = "default_until_limit")]
        limit: u64,
    },
    /// `value_at(offset_a) * value_at(offset_b)`; SQLite stores a page size
    /// of 1 to mean 65536, which `one_means_65536` handles.
    Product {
        offset_a: u64,
        size_a: u8,
        offset_b: u64,
        size_b: u8,
        #[serde(default)]
        endian: Endian,
        #[serde(default)]
        one_means_65536: bool,
    },
    /// RIFF: little endian size at 4, plus the 8-byte header.
    Riff,
    PngChunks,
    Mp4Boxes,
    ZipLocal,
    /// ID3v2: 28-bit syncsafe size at 6, plus the 10-byte header.
    Id3v2,
}

fn one() -> u64 {
    1
}

fn default_until_limit() -> u64 {
    1 << 20
}

/// Top-level shape of a catalogue TOML file.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CatalogFile {
    #[serde(default, rename = "signature")]
    pub signatures: Vec<SignatureDef>,
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

/// Parse hex with optional `0x` prefix and spaces.
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(format!("hex '{text}' has an odd number of digits"));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|e| format!("bad hex '{text}': {e}")))
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Compiled form
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct CompiledMatch {
    start: usize,
    end: usize,
    value: Vec<u8>,
    /// Same length as `value`; `None` means every bit matters.
    mask: Option<Vec<u8>>,
    ignore_case: bool,
    pointer: Option<PointerDef>,
    children: Vec<CompiledMatch>,
}

impl CompiledMatch {
    /// Longest leading run of fully-significant bytes, usable as a literal.
    fn literal_prefix(&self) -> &[u8] {
        if self.ignore_case || self.pointer.is_some() {
            return &[];
        }
        match &self.mask {
            None => &self.value,
            Some(mask) => {
                let run = mask.iter().take_while(|&&m| m == 0xFF).count();
                &self.value[..run]
            }
        }
    }

    fn has_conditions(&self) -> bool {
        !self.children.is_empty()
    }
}

#[derive(Clone, Debug)]
struct CompiledAlternative {
    matches: Vec<CompiledMatch>,
    /// Index into `matches` of the match used to anchor the search.
    anchor: usize,
    anchor_literal_len: usize,
    /// Fully significant bytes checked across every top-level match.
    verified_bytes: usize,
    /// More than the anchor literal is checked.
    extra_conditions: bool,
    /// Furthest byte any fixed-offset match reaches, for the default extent.
    magic_end: usize,
}

#[derive(Clone, Debug)]
struct CompiledSignature {
    def: usize,
    category: Category,
    alternatives: Vec<CompiledAlternative>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Target {
    signature: usize,
    alternative: usize,
}

/// The run of starts last tried for a ranged anchor, so the next occurrence
/// of its literal, a byte or so later, skips the starts already decided.
/// Without it a literal repeated through megabytes is re-checked hundreds of
/// times per byte.
#[derive(Clone, Copy, Debug)]
struct TriedStarts {
    /// Lowest and highest start tried; every start between was tried.
    low: usize,
    high: usize,
    /// Whether the lowest start matched, which ended that run of tries.
    matched_at_low: bool,
}

/// A compiled, searchable catalogue.
pub struct Catalog {
    defs: Vec<SignatureDef>,
    compiled: Vec<CompiledSignature>,
    automaton: Option<AhoCorasick>,
    automaton_targets: Vec<Target>,
    ci_automaton: Option<AhoCorasick>,
    ci_targets: Vec<Target>,
    brute: Vec<Target>,
    /// Alternatives with no usable anchor (reported, never matched).
    skipped: usize,
}

impl Default for Catalog {
    fn default() -> Self {
        Catalog::builtin()
    }
}

const TIKA_TOML: &str = include_str!("../catalog/tika.toml");
const CURATED_TOML: &str = include_str!("../catalog/curated.toml");

/// Cap on candidate starts tried for an anchor with a ranged offset.
const MAX_RANGED_CANDIDATES: usize = 512;

impl Catalog {
    /// The embedded catalogue. Panics only if the embedded files are broken,
    /// which the tests check.
    pub fn builtin() -> Self {
        let mut defs = Vec::new();
        for (name, text) in [("curated.toml", CURATED_TOML), ("tika.toml", TIKA_TOML)] {
            match parse_toml(text) {
                Ok(file) => defs.extend(file.signatures),
                Err(error) => panic!("embedded catalogue {name} is invalid: {error}"),
            }
        }
        Catalog::compile(defs).unwrap_or_else(|error| panic!("embedded catalogue failed to compile: {error}"))
    }

    /// An empty catalogue, to which [`Catalog::add_toml`] adds entries.
    pub fn empty() -> Self {
        Catalog::compile(Vec::new()).expect("empty catalogue compiles")
    }

    pub fn from_toml(text: &str) -> Result<Self, String> {
        Catalog::compile(parse_toml(text)?.signatures)
    }

    /// Add every entry from a TOML string and recompile.
    pub fn add_toml(&mut self, text: &str) -> Result<usize, String> {
        let file = parse_toml(text)?;
        let added = file.signatures.len();
        let mut defs = std::mem::take(&mut self.defs);
        defs.extend(file.signatures);
        *self = Catalog::compile(defs)?;
        Ok(added)
    }

    /// Add every `*.toml` file in `dir`. Returns the number of entries added;
    /// the error names the file and entry that failed.
    pub fn load_dir(&mut self, dir: &Path) -> Result<usize, String> {
        let mut added = 0;
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| format!("reading {}: {e}", dir.display()))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        entries.sort();
        for path in entries {
            let text = std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
            added += self.add_toml(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(added)
    }

    pub fn len(&self) -> usize {
        self.defs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    pub fn definitions(&self) -> &[SignatureDef] {
        &self.defs
    }

    pub fn definition(&self, id: &str) -> Option<&SignatureDef> {
        self.defs.iter().find(|def| def.id == id)
    }

    /// Alternatives that could not be anchored and are never matched.
    pub fn skipped_alternatives(&self) -> usize {
        self.skipped
    }

    /// How the alternatives are searched for, for diagnostics.
    pub fn stats(&self) -> CatalogStats {
        let literal_lengths = |targets: &[Target]| {
            targets
                .iter()
                .map(|t| self.compiled[t.signature].alternatives[t.alternative].anchor_literal_len)
                .fold([0usize; 5], |mut counts, len| {
                    counts[len.min(4)] += 1;
                    counts
                })
        };
        CatalogStats {
            signatures: self.defs.len(),
            literal_anchors: self.automaton_targets.len(),
            literal_anchor_lengths: literal_lengths(&self.automaton_targets),
            case_insensitive_anchors: self.ci_targets.len(),
            brute_anchors: self.brute.len(),
            skipped_alternatives: self.skipped,
        }
    }

    fn compile(defs: Vec<SignatureDef>) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(defs.len());
        let mut literals: Vec<Vec<u8>> = Vec::new();
        let mut automaton_targets = Vec::new();
        let mut ci_literals: Vec<Vec<u8>> = Vec::new();
        let mut ci_targets = Vec::new();
        let mut brute = Vec::new();
        let mut skipped = 0;

        for (def_index, def) in defs.iter().enumerate() {
            let category = Category::from_name(&def.category)
                .ok_or_else(|| format!("entry '{}': unknown category '{}'", def.id, def.category))?;
            let mut alternatives = Vec::new();
            for (alt_index, alternative) in def.magic.iter().enumerate() {
                let matches: Vec<CompiledMatch> = alternative
                    .matches
                    .iter()
                    .map(compile_match)
                    .collect::<Result<_, _>>()
                    .map_err(|e| format!("entry '{}': {e}", def.id))?;
                if matches.is_empty() {
                    skipped += 1;
                    continue;
                }
                let Some(compiled_alt) = compile_alternative(matches) else {
                    skipped += 1;
                    continue;
                };
                let target = Target { signature: compiled.len(), alternative: alternatives.len() };
                let anchor = &compiled_alt.matches[compiled_alt.anchor];
                let literal = anchor.literal_prefix();
                if literal.len() >= 2 {
                    literals.push(literal.to_vec());
                    automaton_targets.push(target);
                } else if anchor.ignore_case && anchor.value.len() >= 2 && anchor.mask.is_none() {
                    ci_literals.push(anchor.value.clone());
                    ci_targets.push(target);
                } else if anchor.start == anchor.end && anchor.pointer.is_none() {
                    brute.push(target);
                } else {
                    skipped += 1;
                    let _ = alt_index;
                    continue;
                }
                alternatives.push(compiled_alt);
            }
            compiled.push(CompiledSignature { def: def_index, category, alternatives });
        }

        let build = |patterns: &[Vec<u8>]| -> Result<Option<AhoCorasick>, String> {
            if patterns.is_empty() {
                return Ok(None);
            }
            AhoCorasickBuilder::new()
                .match_kind(AcMatchKind::Standard)
                .ascii_case_insensitive(false)
                .build(patterns)
                .map(Some)
                .map_err(|e| format!("building automaton: {e}"))
        };
        let automaton = build(&literals)?;
        let ci_automaton = if ci_literals.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(AcMatchKind::Standard)
                    .ascii_case_insensitive(true)
                    .build(&ci_literals)
                    .map_err(|e| format!("building case-insensitive automaton: {e}"))?,
            )
        };

        Ok(Catalog { defs, compiled, automaton, automaton_targets, ci_automaton, ci_targets, brute, skipped })
    }

    // -----------------------------------------------------------------------
    // Scanning
    // -----------------------------------------------------------------------

    /// Find every signature in `window`, whose first byte sits at document
    /// offset `base`. Findings are sorted by start.
    pub fn scan(&self, window: &[u8], base: usize) -> Vec<Finding> {
        self.scan_remembering(window, base, true, 0.0)
    }

    /// [`Catalog::scan`] for signatures at least `min_confidence` sure, the
    /// others not even tried: weak two-byte magics such as `//` would
    /// otherwise match all through a file only to be thrown away.
    pub fn scan_confident(&self, window: &[u8], base: usize, min_confidence: f32) -> Vec<Finding> {
        self.scan_remembering(window, base, true, min_confidence)
    }

    /// [`Catalog::scan`], optionally without remembering the starts tried
    /// for ranged anchors, which the tests use to show it changes nothing.
    fn scan_remembering(&self, window: &[u8], base: usize, remember_tried: bool, min_confidence: f32) -> Vec<Finding> {
        use rayon::prelude::*;

        // Literal positions are split into chunks searched in parallel. Each
        // chunk's search runs a little past its end so a literal straddling the
        // boundary is still seen, but only literals that *start* inside the
        // chunk count; verification always uses the whole window, so results
        // are identical to a single pass.
        let chunk_starts: Vec<usize> = (0..window.len().max(1)).step_by(SCAN_CHUNK).collect();
        let partial: Vec<HashMap<usize, Hit>> = chunk_starts
            .par_iter()
            .map(|&lo| {
                let hi = (lo + SCAN_CHUNK).min(window.len());
                let mut hits = HashMap::new();
                self.scan_chunk(window, lo, hi, &mut hits, remember_tried, min_confidence);
                hits
            })
            .collect();

        let mut hits: HashMap<usize, Hit> = HashMap::new();
        for chunk_hits in partial {
            for (start, hit) in chunk_hits {
                match hits.get(&start) {
                    Some(existing) if !hit.beats(existing) => {}
                    _ => {
                        hits.insert(start, hit);
                    }
                }
            }
        }

        let mut findings: Vec<Finding> = hits.into_iter().map(|(start, hit)| self.finding(window, base, start, hit)).collect();
        findings.sort_by(|a, b| a.start.cmp(&b.start).then(b.confidence.total_cmp(&a.confidence)));
        findings
    }

    /// Search literal positions in `lo..hi` of `window`.
    fn scan_chunk(&self, window: &[u8], lo: usize, hi: usize, hits: &mut HashMap<usize, Hit>, remember_tried: bool, min_confidence: f32) {
        let search_end = (hi + MAX_LITERAL_OVERLAP).min(window.len());
        let haystack = &window[lo..search_end];
        let automata = [(&self.automaton, &self.automaton_targets), (&self.ci_automaton, &self.ci_targets)];
        let mut tried: HashMap<Target, TriedStarts> = HashMap::new();
        for (automaton, targets) in automata {
            let Some(automaton) = automaton else { continue };
            for found in automaton.find_overlapping_iter(haystack) {
                let position = lo + found.start();
                if position >= hi {
                    continue;
                }
                let target = targets[found.pattern().as_usize()];
                if self.confidence(target) < min_confidence {
                    continue;
                }
                if !remember_tried {
                    tried.clear();
                }
                self.try_anchor(window, position, target, hits, &mut tried);
            }
        }
        for &target in &self.brute {
            if self.confidence(target) < min_confidence {
                continue;
            }
            let alternative = &self.compiled[target.signature].alternatives[target.alternative];
            let anchor = &alternative.matches[alternative.anchor];
            let span = anchor.start + anchor.value.len();
            if window.len() < span {
                continue;
            }
            let last = (window.len() - span).min(hi.saturating_sub(1));
            for candidate in lo..=last {
                if match_at(window, anchor, candidate) {
                    self.try_candidate(window, candidate, target, hits);
                }
            }
        }
    }

    fn try_anchor(&self, window: &[u8], literal_pos: usize, target: Target, hits: &mut HashMap<usize, Hit>, tried: &mut HashMap<Target, TriedStarts>) {
        let alternative = &self.compiled[target.signature].alternatives[target.alternative];
        let anchor = &alternative.matches[alternative.anchor];
        if anchor.start == anchor.end {
            if literal_pos >= anchor.start {
                self.try_candidate(window, literal_pos - anchor.start, target, hits);
            }
            return;
        }
        // Ranged anchor: the file could start anywhere that puts the literal
        // inside the range. Try nearby starts first, bounded. Starts an
        // earlier occurrence already tried are skipped: they either failed,
        // or the lowest of them matched and is recorded, which ends the
        // search here as it did there.
        let first = literal_pos.saturating_sub(anchor.end);
        let last = literal_pos.saturating_sub(anchor.start);
        let earlier = tried.get(&target).copied();
        let mut candidate = last;
        let mut count = 0;
        let mut matched = false;
        loop {
            if count >= MAX_RANGED_CANDIDATES || candidate < first {
                break;
            }
            if let Some(earlier) = earlier.filter(|earlier| (earlier.low..=earlier.high).contains(&candidate)) {
                if earlier.matched_at_low {
                    matched = true;
                    candidate = earlier.low;
                    break;
                }
                count += candidate - earlier.low + 1;
                match earlier.low.checked_sub(1) {
                    Some(below) => candidate = below,
                    None => break,
                }
                continue;
            }
            if self.try_candidate(window, candidate, target, hits) {
                matched = true;
                break;
            }
            count += 1;
            match candidate.checked_sub(1) {
                Some(below) => candidate = below,
                None => break,
            }
        }
        // `candidate` is now the lowest start decided by this search (or one
        // below it when the search ran out).
        let low = if matched { candidate } else { (candidate + 1).min(last) };
        if low > last {
            return;
        }
        let run = match earlier {
            // Joined to the earlier run, which this one reached into or met,
            // unless this one matched above it: that match must stay the run's
            // lowest start.
            Some(earlier) if !(matched && low > earlier.low) && low <= earlier.high.saturating_add(1) && last >= earlier.low => TriedStarts { low: low.min(earlier.low), high: last.max(earlier.high), matched_at_low: if low <= earlier.low { matched } else { earlier.matched_at_low } },
            _ => TriedStarts { low, high: last, matched_at_low: matched },
        };
        tried.insert(target, run);
    }

    /// How sure a hit on `target` would be.
    fn confidence(&self, target: Target) -> f32 {
        let signature = &self.compiled[target.signature];
        let alternative = &signature.alternatives[target.alternative];
        self.defs[signature.def].confidence.unwrap_or_else(|| default_confidence(alternative))
    }

    /// Verify the whole alternative at `candidate` and record a hit.
    fn try_candidate(&self, window: &[u8], candidate: usize, target: Target, hits: &mut HashMap<usize, Hit>) -> bool {
        let signature = &self.compiled[target.signature];
        let alternative = &signature.alternatives[target.alternative];
        if !alternative.matches.iter().all(|m| match_at(window, m, candidate)) {
            return false;
        }
        let def = &self.defs[signature.def];
        let confidence = self.confidence(target);
        let hit = Hit {
            signature: target.signature,
            alternative: target.alternative,
            priority: def.priority,
            literal_len: alternative.anchor_literal_len,
            confidence,
        };
        match hits.get(&candidate) {
            Some(existing) if !hit.beats(existing) => {}
            _ => {
                hits.insert(candidate, hit);
            }
        }
        true
    }

    fn finding(&self, window: &[u8], base: usize, start: usize, hit: Hit) -> Finding {
        let signature = &self.compiled[hit.signature];
        let alternative = &signature.alternatives[hit.alternative];
        let def = &self.defs[signature.def];
        let extent = def.extent.as_ref().and_then(|rule| compute_extent(rule, &window[start..]));
        let len = extent.unwrap_or(alternative.magic_end).max(1);

        let mut detail_parts = Vec::new();
        if let Some(mime) = &def.mime {
            detail_parts.push(mime.clone());
        }
        if !def.extensions.is_empty() {
            detail_parts.push(format!(".{}", def.extensions.join(" .")));
        }
        if extent.is_some() {
            detail_parts.push(format!("{} bytes", len));
        }
        Finding::new(format!("signature:{}", def.id), "catalog", signature.category, base + start, len)
            .title(def.name.clone())
            .detail(detail_parts.join(" · "))
            .confidence(hit.confidence)
    }
}

/// Diagnostic counts from [`Catalog::stats`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CatalogStats {
    pub signatures: usize,
    pub literal_anchors: usize,
    /// Index = anchor literal length (4 means four or more).
    pub literal_anchor_lengths: [usize; 5],
    pub case_insensitive_anchors: usize,
    pub brute_anchors: usize,
    pub skipped_alternatives: usize,
}

#[derive(Clone, Copy, Debug)]
struct Hit {
    signature: usize,
    alternative: usize,
    priority: u32,
    literal_len: usize,
    confidence: f32,
}

/// Anchors this short match all sorts of data by chance, such as Tika's
/// MATLAB signature, a lone `%` at the start, which every PDF also has.
const WEAK_ANCHOR_BYTES: usize = 2;

impl Hit {
    fn is_weak(&self) -> bool {
        self.literal_len <= WEAK_ANCHOR_BYTES
    }

    /// A hit on a specific magic beats one on a byte or two whatever their
    /// priorities; otherwise the higher priority wins, then the longer anchor.
    fn beats(&self, other: &Hit) -> bool {
        (!self.is_weak(), self.priority, self.literal_len, self.confidence) > (!other.is_weak(), other.priority, other.literal_len, other.confidence)
    }
}

impl Detector for Catalog {
    fn id(&self) -> &str {
        "catalog"
    }

    fn name(&self) -> &str {
        "Signature catalogue"
    }

    fn categories(&self) -> Vec<Category> {
        Category::ALL.to_vec()
    }

    fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding> {
        let mut findings = self.scan_confident(window, context.base, DETECTOR_MIN_CONFIDENCE);
        for finding in &mut findings {
            let room = context.document_len.saturating_sub(finding.start).max(1);
            finding.len = finding.len.min(room);
        }
        findings
    }
}

/// Confidence from how many bytes were actually verified and whether anything
/// beyond one literal was checked. Two verified bytes plus a weak condition
/// still fire by chance in a few hundred kilobytes of noise, so they stay
/// below 0.5 and draw dimmed.
fn default_confidence(alternative: &CompiledAlternative) -> f32 {
    let verified = alternative.verified_bytes;
    let extra = alternative.extra_conditions;
    match (verified, extra) {
        (4.., true) => 1.0,
        (4.., false) => 0.8,
        (3, true) => 0.6,
        (3, false) => 0.45,
        (_, true) => 0.45,
        _ => 0.3,
    }
}

// ---------------------------------------------------------------------------
// Compilation helpers
// ---------------------------------------------------------------------------

fn parse_toml(text: &str) -> Result<CatalogFile, String> {
    toml::from_str(text).map_err(|e| e.to_string())
}

fn compile_match(def: &MatchDef) -> Result<CompiledMatch, String> {
    let (value, mask) = compile_value(def)?;
    if value.is_empty() {
        return Err("match has no value".to_string());
    }
    if def.pointer.is_some_and(|p| !matches!(p.size, 1 | 2 | 4 | 8)) {
        return Err("pointer size must be 1, 2, 4 or 8".to_string());
    }
    let children = def.children.iter().map(compile_match).collect::<Result<_, _>>()?;
    Ok(CompiledMatch {
        start: def.offset.start as usize,
        end: def.offset.end as usize,
        value,
        mask,
        ignore_case: def.ignore_case,
        pointer: def.pointer,
        children,
    })
}

/// Turn a match's value into bytes plus an optional mask of the same length.
fn compile_value(def: &MatchDef) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
    let text = def.bytes.as_deref().or(def.string.as_deref()).unwrap_or("");
    let value = match def.kind {
        MatchKind::Bytes => {
            if def.bytes.is_some() {
                parse_hex(text)?
            } else {
                text.as_bytes().to_vec()
            }
        }
        MatchKind::String => text.as_bytes().to_vec(),
        MatchKind::Big16 => (parse_number(text)? as u16).to_be_bytes().to_vec(),
        MatchKind::Big32 => (parse_number(text)? as u32).to_be_bytes().to_vec(),
        MatchKind::Little16 | MatchKind::Host16 => (parse_number(text)? as u16).to_le_bytes().to_vec(),
        MatchKind::Little32 | MatchKind::Host32 => (parse_number(text)? as u32).to_le_bytes().to_vec(),
    };
    let mask = match &def.mask {
        None => None,
        Some(mask_text) => {
            let mut mask = match def.kind {
                MatchKind::Bytes | MatchKind::String => parse_hex(mask_text)?,
                MatchKind::Big16 => (parse_number(mask_text)? as u16).to_be_bytes().to_vec(),
                MatchKind::Big32 => (parse_number(mask_text)? as u32).to_be_bytes().to_vec(),
                MatchKind::Little16 | MatchKind::Host16 => (parse_number(mask_text)? as u16).to_le_bytes().to_vec(),
                MatchKind::Little32 | MatchKind::Host32 => (parse_number(mask_text)? as u32).to_le_bytes().to_vec(),
            };
            mask.resize(value.len(), 0xFF);
            if mask.iter().all(|&m| m == 0xFF) { None } else { Some(mask) }
        }
    };
    let value = match &mask {
        Some(mask) => value.iter().zip(mask).map(|(v, m)| v & m).collect(),
        None => value,
    };
    Ok((value, mask))
}

fn parse_number(text: &str) -> Result<u64, String> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("bad number '{text}': {e}"))
    } else {
        text.parse().map_err(|e| format!("bad number '{text}': {e}"))
    }
}

/// Choose the anchor: the top-level match with the longest literal prefix.
fn compile_alternative(matches: Vec<CompiledMatch>) -> Option<CompiledAlternative> {
    let anchor = (0..matches.len()).max_by_key(|&i| {
        let m = &matches[i];
        let literal = m.literal_prefix().len();
        // Prefer fixed offsets, then longer literals, then plain values.
        (literal.min(64) * 4 + usize::from(m.start == m.end) * 2, usize::from(!m.ignore_case))
    })?;
    let anchor_match = &matches[anchor];
    let anchor_literal_len = if anchor_match.ignore_case && anchor_match.mask.is_none() {
        anchor_match.value.len()
    } else {
        anchor_match.literal_prefix().len()
    };
    let extra_conditions = matches.len() > 1
        || anchor_match.has_conditions()
        || anchor_match.value.len() > anchor_literal_len
        || anchor_match.pointer.is_some();
    let magic_end = matches
        .iter()
        .filter(|m| m.pointer.is_none())
        .map(|m| m.start + m.value.len())
        .max()
        .unwrap_or(1);
    let verified_bytes = matches
        .iter()
        .map(|m| match &m.mask {
            None => m.value.len(),
            Some(mask) => mask.iter().filter(|&&b| b == 0xFF).count(),
        })
        .sum();
    Some(CompiledAlternative { matches, anchor, anchor_literal_len, verified_bytes, extra_conditions, magic_end })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

fn read_unsigned(bytes: &[u8], size: usize, endian: Endian) -> Option<u64> {
    let slice = bytes.get(..size)?;
    let mut value = 0u64;
    match endian {
        Endian::Big => {
            for &b in slice {
                value = (value << 8) | b as u64;
            }
        }
        Endian::Little => {
            for &b in slice.iter().rev() {
                value = (value << 8) | b as u64;
            }
        }
    }
    Some(value)
}

fn bytes_equal(data: &[u8], value: &[u8], mask: Option<&[u8]>, ignore_case: bool) -> bool {
    if data.len() < value.len() {
        return false;
    }
    match (mask, ignore_case) {
        (None, false) => &data[..value.len()] == value,
        (None, true) => data[..value.len()].eq_ignore_ascii_case(value),
        (Some(mask), _) => data.iter().zip(value).zip(mask).all(|((d, v), m)| d & m == *v),
    }
}

/// Does `m` hold for a file starting at `candidate`?
fn match_at(window: &[u8], m: &CompiledMatch, candidate: usize) -> bool {
    let (start, end) = match m.pointer {
        None => (m.start, m.end),
        Some(pointer) => {
            let Some(pointed) = window
                .get(candidate + pointer.offset as usize..)
                .and_then(|slice| read_unsigned(slice, pointer.size as usize, pointer.endian))
            else {
                return false;
            };
            let target = pointed as usize;
            (target + m.start, target + m.end)
        }
    };
    let first = candidate + start;
    let last = candidate + end;
    if first >= window.len() {
        return false;
    }
    let mut position = first;
    while position <= last && position + m.value.len() <= window.len() {
        if bytes_equal(&window[position..], &m.value, m.mask.as_deref(), m.ignore_case) {
            // Children are placed from the candidate, not from where this
            // value was found, so their answer is the same at every place:
            // decide it once rather than again for each place.
            return m.children.is_empty() || m.children.iter().any(|child| match_at(window, child, candidate));
        }
        position += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// Extents
// ---------------------------------------------------------------------------

/// Length of the block starting at `bytes[0]`, if the rule can determine it.
fn compute_extent(rule: &ExtentDef, bytes: &[u8]) -> Option<usize> {
    let len = match rule {
        ExtentDef::Fixed { len } => *len as usize,
        ExtentDef::Field { offset, size, endian, add, multiply } => {
            let value = read_unsigned(bytes.get(*offset as usize..)?, *size as usize, *endian)?;
            let scaled = value.checked_mul(*multiply)?;
            (scaled as i128 + *add as i128).try_into().ok().filter(|&n: &usize| n > 0)?
        }
        ExtentDef::Until { bytes: terminator, limit } => {
            let terminator = parse_hex(terminator).ok()?;
            let limit = (*limit as usize).min(bytes.len());
            let position = bytes[..limit].windows(terminator.len()).position(|w| w == terminator)?;
            position + terminator.len()
        }
        ExtentDef::Product { offset_a, size_a, offset_b, size_b, endian, one_means_65536 } => {
            let mut a = read_unsigned(bytes.get(*offset_a as usize..)?, *size_a as usize, *endian)?;
            let b = read_unsigned(bytes.get(*offset_b as usize..)?, *size_b as usize, *endian)?;
            if *one_means_65536 && a == 1 {
                a = 65536;
            }
            let product = a.checked_mul(b)?;
            usize::try_from(product).ok().filter(|&n| n > 0)?
        }
        ExtentDef::Riff => read_unsigned(bytes.get(4..)?, 4, Endian::Little)? as usize + 8,
        ExtentDef::PngChunks => walk_png(bytes)?,
        ExtentDef::Mp4Boxes => walk_mp4(bytes)?,
        ExtentDef::ZipLocal => walk_zip(bytes)?,
        ExtentDef::Id3v2 => {
            let size = bytes.get(6..10)?;
            if size.iter().any(|&b| b & 0x80 != 0) {
                return None;
            }
            let syncsafe = size.iter().fold(0usize, |acc, &b| (acc << 7) | b as usize);
            syncsafe + 10 + usize::from(bytes[5] & 0x10 != 0) * 10
        }
    };
    Some(len)
}

fn walk_png(bytes: &[u8]) -> Option<usize> {
    let mut position = 8;
    loop {
        let length = read_unsigned(bytes.get(position..)?, 4, Endian::Big)? as usize;
        let kind = bytes.get(position + 4..position + 8)?;
        position = position.checked_add(12 + length)?;
        if kind == b"IEND" {
            return Some(position);
        }
        if position > bytes.len() + (1 << 30) {
            return None;
        }
    }
}

fn walk_mp4(bytes: &[u8]) -> Option<usize> {
    let mut position = 0;
    let mut boxes = 0;
    while position + 8 <= bytes.len() {
        let size = read_unsigned(&bytes[position..], 4, Endian::Big)? as usize;
        let size = match size {
            0 => return Some(bytes.len()),
            1 => read_unsigned(bytes.get(position + 8..)?, 8, Endian::Big)? as usize,
            n => n,
        };
        if size < 8 {
            return None;
        }
        position = position.checked_add(size)?;
        boxes += 1;
        if position >= bytes.len() {
            break;
        }
    }
    (boxes > 0).then_some(position)
}

fn walk_zip(bytes: &[u8]) -> Option<usize> {
    let mut position = 0;
    let mut entries = 0;
    while bytes.get(position..position + 4)? == b"PK\x03\x04" {
        let header = bytes.get(position..position + 30)?;
        let flags = read_unsigned(&header[6..], 2, Endian::Little)?;
        let compressed = read_unsigned(&header[18..], 4, Endian::Little)? as usize;
        let name_len = read_unsigned(&header[26..], 2, Endian::Little)? as usize;
        let extra_len = read_unsigned(&header[28..], 2, Endian::Little)? as usize;
        if flags & 0x08 != 0 {
            // Sizes live in a data descriptor after the data; stop here.
            return Some(position + 30 + name_len + extra_len);
        }
        position = position.checked_add(30 + name_len + extra_len + compressed)?;
        entries += 1;
        if position >= bytes.len() {
            break;
        }
    }
    // Central directory follows; include it if it is in view.
    if bytes.get(position..position + 4) == Some(b"PK\x01\x02")
        && let Some(end) = bytes[position..].windows(4).position(|w| w == b"PK\x05\x06") {
            let eocd = position + end;
            let comment_len = read_unsigned(bytes.get(eocd + 20..)?, 2, Endian::Little)? as usize;
            return Some(eocd + 22 + comment_len);
        }
    (entries > 0).then_some(position)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xorshift(state: &mut u32) -> u8 {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        (*state >> 24) as u8
    }

    fn noise(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed;
        (0..len).map(|_| xorshift(&mut state)).collect()
    }

    fn put(buffer: &mut [u8], at: usize, bytes: &[u8]) {
        buffer[at..at + bytes.len()].copy_from_slice(bytes);
    }

    #[test]
    fn embedded_catalogue_loads_and_is_large() {
        let catalog = Catalog::builtin();
        // Tika defines magic for about 450 of its 1,700 types; the rest are
        // glob-only and are not imported.
        assert!(catalog.len() > 500, "only {} entries", catalog.len());
        assert!(catalog.definition("image/png").is_some());
        assert!(catalog.definition("firmware/uimage").is_some());
        let skipped = catalog.skipped_alternatives();
        assert!(skipped < catalog.len() / 10, "{skipped} alternatives could not be anchored");
    }

    #[test]
    fn finds_known_signatures_at_their_exact_offsets() {
        let catalog = Catalog::builtin();
        let mut buffer = noise(70_000, 0x1234_5678);
        put(&mut buffer, 0, b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR");
        put(&mut buffer, 100, b"\x7fELF\x02\x01\x01\x00");
        put(&mut buffer, 300, b"PK\x03\x04\x14\x00\x00\x00\x08\x00");
        // A tar block at 1000 has "ustar" at 257 within it.
        let tar_at = 1000;
        put(&mut buffer, tar_at, b"file.txt");
        put(&mut buffer, tar_at + 257, b"ustar\x0000");
        // An ISO image block at 20000 has CD001 at 0x8001 within it.
        let iso_at = 20000;
        put(&mut buffer, iso_at + 0x8001, b"CD001\x01");
        put(&mut buffer, 5000, &[0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00]);

        let findings = catalog.scan(&buffer, 0);
        let at = |offset: usize| -> Vec<&Finding> { findings.iter().filter(|f| f.start == offset && f.confidence >= 0.5).collect() };
        assert!(at(0).iter().any(|f| f.title.contains("PNG") && f.category == Category::Image), "{:?}", at(0));
        assert!(at(100).iter().any(|f| f.category == Category::Executable && f.title.to_lowercase().contains("elf")), "{:?}", at(100));
        assert!(at(300).iter().any(|f| f.category == Category::Archive), "{:?}", at(300));
        assert!(at(tar_at).iter().any(|f| f.category == Category::Archive && f.title.to_lowercase().contains("tar")), "{:?}", at(tar_at));
        assert!(at(iso_at).iter().any(|f| f.category == Category::Filesystem), "{:?}", at(iso_at));
        assert!(at(5000).iter().any(|f| f.id.contains("pcap")), "{:?}", at(5000));
    }

    #[test]
    fn a_pdf_is_a_pdf_even_though_it_starts_like_matlab_source() {
        let catalog = Catalog::builtin();
        // "%PDF-" then a binary comment line: also a "%" with "\n%" soon after,
        // which is all Tika's higher-priority MATLAB signature asks for.
        let pdf = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        let findings = catalog.scan(pdf, 0);
        let at_start: Vec<&str> = findings.iter().filter(|f| f.start == 0).map(|f| f.id.as_str()).collect();
        assert_eq!(at_start, ["signature:application/pdf"]);
        // A file that is only "%" lines is still taken for MATLAB.
        let matlab = b"% plot the signal\n% then its spectrum\nx = 1;\n";
        let ids: Vec<String> = catalog.scan(matlab, 0).into_iter().filter(|f| f.start == 0).map(|f| f.id).collect();
        assert_eq!(ids, ["signature:text/x-matlab"]);
    }

    #[test]
    fn mbr_needs_both_the_boot_marker_and_a_valid_status_byte() {
        let catalog = Catalog::builtin();
        let mut sector = vec![0u8; 512];
        put(&mut sector, 510, &[0x55, 0xAA]);
        sector[0x1BE] = 0x80;
        let findings = catalog.scan(&sector, 0);
        assert!(findings.iter().any(|f| f.id == "signature:partition/mbr"), "{findings:?}");
        sector[0x1BE] = 0x7F;
        let findings = catalog.scan(&sector, 0);
        assert!(!findings.iter().any(|f| f.id == "signature:partition/mbr"), "{findings:?}");
    }

    #[test]
    fn field_extents_report_the_block_length() {
        let catalog = Catalog::builtin();
        // uImage: magic, then a 4-byte big endian data size at 12; block = 64 + size.
        let mut image = vec![0u8; 200];
        put(&mut image, 0, &[0x27, 0x05, 0x19, 0x56]);
        put(&mut image, 12, &100u32.to_be_bytes());
        let findings = catalog.scan(&image, 4096);
        let uimage = findings.iter().find(|f| f.id == "signature:firmware/uimage").expect("uimage");
        assert_eq!((uimage.start, uimage.len), (4096, 164));

        // A RIFF extent from the curated WAVE entry.
        let mut wave = vec![0u8; 64];
        put(&mut wave, 0, b"RIFF");
        put(&mut wave, 4, &40u32.to_le_bytes());
        put(&mut wave, 8, b"WAVEfmt ");
        let findings = catalog.scan(&wave, 0);
        let riff = findings.iter().find(|f| f.id.contains("wav") || f.title.to_lowercase().contains("wave")).expect("wave");
        assert_eq!(riff.len, 48);
    }

    #[test]
    fn noise_produces_no_confident_findings() {
        let catalog = Catalog::builtin();
        let buffer = noise(64 * 1024, 0x9E37_79B9);
        let findings = catalog.scan(&buffer, 0);
        let confident: Vec<&Finding> = findings.iter().filter(|f| f.confidence >= 0.5).collect();
        assert!(confident.is_empty(), "{confident:?}");
    }

    #[test]
    fn toml_model_round_trips_and_rejects_bad_entries() {
        let text = r#"
[[signature]]
id = "test/thing"
name = "Thing"
category = "Structure"
extent = { kind = "field", offset = 4, size = 2, endian = "big", add = 8 }
magic = [
  { offset = 0, bytes = "41 42 43 44" },
  { matches = [ { offset = "8..16", string = "XYZ" }, { offset = 2, bytes = "01", mask = "0f" } ] },
]
"#;
        let catalog = Catalog::from_toml(text).unwrap();
        assert_eq!(catalog.len(), 1);
        let mut buffer = vec![0u8; 64];
        put(&mut buffer, 0, b"ABCD");
        put(&mut buffer, 4, &20u16.to_be_bytes());
        let findings = catalog.scan(&buffer, 0);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].len, 28);
        assert_eq!(findings[0].category, Category::Structure);

        // Second alternative: ranged string plus a masked byte.
        let mut buffer = vec![0u8; 64];
        put(&mut buffer, 12, b"XYZ");
        buffer[2] = 0xF1;
        let findings = catalog.scan(&buffer, 0);
        assert_eq!(findings.len(), 1, "{findings:?}");
        buffer[2] = 0xF2;
        assert!(catalog.scan(&buffer, 0).is_empty());

        assert!(Catalog::from_toml("[[signature]]\nid='x'\nname='x'\ncategory='Nope'\nmagic=[{bytes='00'}]").is_err());
        assert!(Catalog::from_toml("[[signature]]\nid='x'\nname='x'\nmagic=[{bytes='0'}]").is_err());
    }

    #[test]
    fn remembering_tried_starts_finds_exactly_what_trying_them_all_finds() {
        let catalog = Catalog::builtin();
        let mut buffers: Vec<Vec<u8>> = vec![
            noise(200_000, 0x5eed_1234),
            vec![0u8; 100_000],
            b"0\x84\x00\x00\x01\x00".repeat(20_000),
            b"%\n%PDF-1.4\n".repeat(5_000),
            b"<?xml version=\"1.0\"?><a>ustar</a>\n".repeat(3_000),
        ];
        // Known signatures among repetitive bytes, so matches and misses mix.
        let mut mixed = b"MZ\x90\x00PE\x00\x00".repeat(10_000);
        put(&mut mixed, 4_000, b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR");
        put(&mut mixed, 30_000 + 257, b"ustar\x0000");
        buffers.push(mixed);
        let summary = |findings: Vec<Finding>| -> Vec<(usize, String)> { findings.into_iter().map(|f| (f.start, f.id)).collect() };
        for (index, buffer) in buffers.iter().enumerate() {
            assert_eq!(summary(catalog.scan_remembering(buffer, 0, true, 0.0)), summary(catalog.scan_remembering(buffer, 0, false, 0.0)), "buffer {index}");
        }
    }

    #[test]
    fn scanning_for_confident_signatures_keeps_every_confident_finding() {
        let catalog = Catalog::builtin();
        let mut buffer = b"// a comment\n/* another */\n;; and one more\n".repeat(2_000);
        put(&mut buffer, 10_000, b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR");
        put(&mut buffer, 20_000, b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n");
        let confident = |findings: Vec<Finding>| -> Vec<(usize, String)> { findings.into_iter().filter(|f| f.confidence >= DETECTOR_MIN_CONFIDENCE).map(|f| (f.start, f.id)).collect() };
        let everything = catalog.scan(&buffer, 0);
        assert!(everything.iter().any(|f| f.confidence < DETECTOR_MIN_CONFIDENCE), "the comments do match weak signatures");
        assert_eq!(confident(catalog.scan_confident(&buffer, 0, DETECTOR_MIN_CONFIDENCE)), confident(everything));
        assert!(catalog.scan_confident(&buffer, 0, DETECTOR_MIN_CONFIDENCE).iter().all(|f| f.confidence >= DETECTOR_MIN_CONFIDENCE));
    }

    #[test]
    fn a_literal_repeated_through_a_large_window_is_scanned_in_moments() {
        let catalog = Catalog::builtin();
        // Every byte pair here starts literals that ranged signatures anchor on.
        let buffer = b"0\x84\x00\x00\x01\x00\x02\x01".repeat(256 * 1024);
        let started = std::time::Instant::now();
        catalog.scan(&buffer, 0);
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "took {:?}", started.elapsed());
    }

    #[test]
    fn nested_range_matches_over_repetitive_bytes_are_decided_quickly() {
        // A match anywhere in 4 KiB whose child may also be anywhere in 4 KiB,
        // and whose grandchild never holds, over 8 KiB of zeros: trying the
        // children again at every place the parent matched took hours.
        let ranged = |value: u8, children: Vec<CompiledMatch>| CompiledMatch { start: 0, end: 4096, value: vec![value], mask: None, ignore_case: false, pointer: None, children };
        let rule = ranged(0x00, vec![ranged(0x00, vec![ranged(0xFF, Vec::new())])]);
        let zeros = vec![0u8; 8192];
        let started = std::time::Instant::now();
        assert!(!match_at(&zeros, &rule, 0));
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "took {:?}", started.elapsed());
        let mut with_marker = zeros.clone();
        with_marker[3000] = 0xFF;
        assert!(match_at(&with_marker, &rule, 0), "the grandchild is found anywhere in its range");
    }

    #[test]
    fn pointer_matches_follow_a_field_in_the_file() {
        let catalog = Catalog::builtin();
        let mut pe = vec![0u8; 0x100];
        put(&mut pe, 0, b"MZ");
        put(&mut pe, 0x3C, &0x80u32.to_le_bytes());
        put(&mut pe, 0x80, b"PE\0\0");
        let findings = catalog.scan(&pe, 0);
        let hit = findings.iter().find(|f| f.id == "signature:executable/pe").expect("pe");
        assert!(hit.confidence >= 0.9);
        put(&mut pe, 0x80, b"XX\0\0");
        assert!(!catalog.scan(&pe, 0).iter().any(|f| f.id == "signature:executable/pe"));
    }

    /// Not a correctness test: prints how long a 4 MiB scan takes.
    /// Run with `cargo test --release --lib catalog -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn timing_of_a_four_mebibyte_scan() {
        let catalog = Catalog::builtin();
        let buffer = noise(4 * 1024 * 1024, 0xDEAD_BEEF);
        eprintln!("stats: {:?}", catalog.stats());
        let started = std::time::Instant::now();
        let findings = catalog.scan(&buffer, 0);
        let elapsed = started.elapsed();
        eprintln!("4 MiB scan: {elapsed:?}, {} findings ({} with confidence >= 0.5)", findings.len(), findings.iter().filter(|f| f.confidence >= 0.5).count());
        let mut by_id: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for finding in &findings {
            *by_id.entry(finding.id.as_str()).or_default() += 1;
        }
        let mut top: Vec<_> = by_id.into_iter().collect();
        top.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        eprintln!("most frequent: {:?}", &top[..top.len().min(8)]);
    }

    #[test]
    fn hex_and_offset_parsing() {
        assert_eq!(parse_hex("0x89504e47").unwrap(), vec![0x89, 0x50, 0x4e, 0x47]);
        assert_eq!(parse_hex("89 50 4E 47").unwrap(), vec![0x89, 0x50, 0x4e, 0x47]);
        assert!(parse_hex("abc").is_err());
        assert_eq!(parse_offset_text("0..64").unwrap(), OffsetDef { start: 0, end: 64 });
        assert_eq!(parse_offset_text("0x8001").unwrap(), OffsetDef::fixed(0x8001));
        assert!(parse_offset_text("10..2").is_err());
    }
}
