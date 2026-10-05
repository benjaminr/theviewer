//! Processor architecture identification for raw, headerless blobs such as
//! firmware dumps, in the spirit of cpu_rec but without training corpora.
//!
//! Sampled windows of the input are disassembled with every architecture the
//! viewer supports (see [`crate::disasm::Arch`]) and each architecture is
//! scored on four independent signals:
//!
//! 1. **Typical instructions**: the fraction of bytes that decode to the
//!    instructions compilers emit constantly on that architecture. Validity
//!    alone is useless for dense encodings such as ARM and Thumb, which
//!    decode almost any bytes.
//! 2. **Idioms**: prologues, epilogues and returns that are characteristic
//!    of the architecture, such as ARM `push {.., lr}` / `bx lr`, x86-64
//!    `push rbp; mov rbp, rsp`, RISC-V `ret`, MIPS `jr $ra`, PowerPC `blr`.
//!    Function entries and exits are scored separately and the weaker of the
//!    two counts, because misread data of another architecture often mimics
//!    one of them (MIPS `addiu $sp` reads as a Thumb `pop {.., pc}`) but
//!    rarely both.
//! 3. **Branch plausibility**: branch targets of real code land inside the
//!    blob and on instruction boundaries; those of misread data scatter.
//! 4. **Diversity**: real code uses a handful of mnemonics most of the time,
//!    but more than one or two of them.
//!
//! Windows that are padding, plain text or high-entropy (compressed or
//! encrypted) are not sampled: dense encodings decode them all too happily.
//! The result is a ranked list with a confidence and a short reason for each
//! architecture. Input that looks like data for every architecture is
//! reported as such rather than forced onto the least bad guess.

use std::collections::{HashMap, HashSet};
use std::ops::Range;

use rayon::prelude::*;

use crate::disasm::{self, Arch, Instruction};

/// Bytes in one sampled window.
const WINDOW_LEN: usize = 4096;
/// Most windows disassembled per architecture, which bounds the time taken.
const MAX_WINDOWS: usize = 12;
/// Evenly spaced positions considered before padding windows are dropped.
const CANDIDATE_POSITIONS: usize = 96;
/// Windows start on this alignment so fixed-width encodings stay in step.
const WINDOW_ALIGNMENT: usize = 16;
/// Inputs shorter than this are not worth guessing at.
const MIN_SAMPLE_LEN: usize = 64;

/// A window where one byte value makes up more than this share is padding.
const PADDING_DOMINANCE: f32 = 0.5;
/// A window with fewer distinct byte values than this is padding or a fill.
const MIN_DISTINCT_BYTES: usize = 16;
/// Above this Shannon entropy (bits per byte) a window is compressed or
/// encrypted; machine code stays well below it.
const HIGH_ENTROPY_BITS: f32 = 7.5;
/// A window with more than this share of printable ASCII is text.
const TEXT_DOMINANCE: f32 = 0.9;

/// Weights of the four signals in the final confidence; they sum to 1.
const WEIGHT_TYPICAL: f32 = 0.40;
const WEIGHT_IDIOMS: f32 = 0.30;
const WEIGHT_BRANCHES: f32 = 0.15;
const WEIGHT_DIVERSITY: f32 = 0.15;

/// Below this best confidence, the input is reported as data.
const DATA_THRESHOLD: f32 = 0.6;
/// When the top two are closer than this, the reason says it is a close call.
const AMBIGUITY_MARGIN: f32 = 0.05;

/// Weighted entry (or exit) idiom hits per KiB that earn the full score.
const IDIOMS_PER_KIB_FOR_FULL_SCORE: f32 = 1.0;
const BYTES_PER_KIB: f32 = 1024.0;
/// Weight of an idiom whose encoding is long or highly specific.
const STRONG_IDIOM: f32 = 1.0;
/// Weight of an idiom that misread data produces now and then.
const MEDIUM_IDIOM: f32 = 0.5;
/// Weight of an idiom with a short encoding that random bytes often produce.
const WEAK_IDIOM: f32 = 0.2;

/// Fewer branches than this say little either way about plausibility.
const MIN_BRANCHES: usize = 4;
/// Branch score given when there are too few branches to judge.
const NEUTRAL_BRANCH_SCORE: f32 = 0.25;
/// Credit for a target inside the blob but outside the sampled window,
/// where its alignment can be checked but its boundary cannot.
const OUTSIDE_WINDOW_CREDIT: f32 = 0.5;

/// Mnemonics whose share of all instructions measures concentration.
const TOP_MNEMONICS: usize = 12;
/// Distinct mnemonics at which the variety part of diversity is full.
const DISTINCT_MNEMONICS_FOR_FULL_SCORE: usize = 8;
/// Weight of a valid but unusual instruction in the typical fraction.
const UNUSUAL_INSTRUCTION_WEIGHT: f32 = 0.25;

/// The condition field of an unconditional (always) 32-bit ARM instruction.
const ARM_CONDITION_ALWAYS: u8 = 0xE;
/// x86 one-byte opcodes that are REX prefixes in 64-bit mode (inc/dec in 32-bit).
const X86_REX_PREFIXES: std::ops::RangeInclusive<u8> = 0x40..=0x4F;

/// How well one architecture explains the sampled bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct ArchCandidate {
    pub arch: Arch,
    /// 0 to 1.
    pub confidence: f32,
    /// One line explaining the score.
    pub reason: String,
    /// Fraction of sampled bytes in typical instructions, 0 to 1.
    pub typical_fraction: f32,
    /// Prologue, epilogue and return idioms seen.
    pub idioms: usize,
    /// How plausible branch targets are, 0 to 1.
    pub branch_plausibility: f32,
    /// Concentrated but varied mnemonic use, 0 to 1.
    pub diversity: f32,
    /// Document offset of the window that looked most like this architecture.
    pub best_window_offset: usize,
}

/// Ranked architecture guesses for a blob.
#[derive(Clone, Debug, PartialEq)]
pub struct CpuReport {
    /// Every architecture, best first. Empty only when the input is too short.
    pub candidates: Vec<ArchCandidate>,
    /// True when no architecture is convincing.
    pub looks_like_data: bool,
    /// Windows disassembled per architecture.
    pub windows: usize,
    /// Bytes disassembled per architecture.
    pub sampled_bytes: usize,
    /// One sentence for the user.
    pub summary: String,
}

impl CpuReport {
    /// The winning architecture, unless the input looks like data.
    pub fn best(&self) -> Option<&ArchCandidate> {
        if self.looks_like_data { None } else { self.candidates.first() }
    }
}

/// Identify the architecture of the code in `bytes`, which sit at document
/// offset `base_offset`. Samples at most [`MAX_WINDOWS`] windows of
/// [`WINDOW_LEN`] bytes, so the time taken does not grow with the input.
pub fn identify_architecture(bytes: &[u8], base_offset: usize) -> CpuReport {
    if bytes.len() < MIN_SAMPLE_LEN {
        return CpuReport {
            candidates: Vec::new(),
            looks_like_data: true,
            windows: 0,
            sampled_bytes: 0,
            summary: format!("Too few bytes to judge: {} given, at least {MIN_SAMPLE_LEN} needed.", bytes.len()),
        };
    }
    let windows = sample_windows(bytes);
    if windows.is_empty() {
        return CpuReport {
            candidates: Arch::ALL.iter().map(|&arch| no_evidence(arch, base_offset)).collect(),
            looks_like_data: true,
            windows: 0,
            sampled_bytes: 0,
            summary: "Every sampled window is padding, text or high-entropy (compressed or encrypted) data, so there is no code to judge."
                .to_string(),
        };
    }
    let sampled_bytes = windows.iter().map(|range| range.len()).sum();
    let mut candidates: Vec<ArchCandidate> =
        Arch::ALL.par_iter().map(|&arch| score_architecture(arch, bytes, &windows, base_offset)).collect();
    candidates.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));

    let best = candidates[0].confidence;
    let runner_up = candidates.get(1).map(|c| c.confidence).unwrap_or(0.0);
    let looks_like_data = best < DATA_THRESHOLD;
    let summary = if looks_like_data {
        format!(
            "No architecture stands out (best {:.0}%): this looks like data, compressed or encrypted bytes, or code for an unsupported processor.",
            best * 100.0
        )
    } else if best - runner_up < AMBIGUITY_MARGIN {
        format!(
            "Close call between {} ({:.0}%) and {} ({:.0}%); disassemble both and compare.",
            candidates[0].arch.label(),
            best * 100.0,
            candidates[1].arch.label(),
            runner_up * 100.0
        )
    } else {
        format!("Most likely {} ({:.0}% confidence).", candidates[0].arch.label(), best * 100.0)
    };
    CpuReport { candidates, looks_like_data, windows: windows.len(), sampled_bytes, summary }
}

fn no_evidence(arch: Arch, base_offset: usize) -> ArchCandidate {
    ArchCandidate {
        arch,
        confidence: 0.0,
        reason: "no code-like bytes sampled".to_string(),
        typical_fraction: 0.0,
        idioms: 0,
        branch_plausibility: 0.0,
        diversity: 0.0,
        best_window_offset: base_offset,
    }
}

// ---------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------

/// Byte ranges to disassemble: the whole input when small, otherwise evenly
/// spaced windows, skipping those that cannot be code.
fn sample_windows(bytes: &[u8]) -> Vec<Range<usize>> {
    let positions: Vec<usize> = if bytes.len() <= WINDOW_LEN * MAX_WINDOWS {
        (0..bytes.len()).step_by(WINDOW_LEN).collect()
    } else {
        let last_start = bytes.len() - WINDOW_LEN;
        (0..CANDIDATE_POSITIONS).map(|index| align_down(last_start * index / (CANDIDATE_POSITIONS - 1), WINDOW_ALIGNMENT)).collect()
    };
    let mut windows: Vec<Range<usize>> = positions
        .into_iter()
        .map(|start| start..(start + WINDOW_LEN).min(bytes.len()))
        .filter(|range| range.len() >= MIN_SAMPLE_LEN && could_be_code(&bytes[range.clone()]))
        .collect();
    windows.dedup();
    evenly_pick(windows, MAX_WINDOWS)
}

fn align_down(value: usize, alignment: usize) -> usize {
    value - value % alignment
}

/// Whether a window is worth disassembling: not a fill (zeros, 0xFF erased
/// flash, a repeated byte), not text and not compressed or encrypted.
fn could_be_code(window: &[u8]) -> bool {
    if window.is_empty() {
        return false;
    }
    let mut counts = [0usize; 256];
    for &byte in window {
        counts[byte as usize] += 1;
    }
    let len = window.len() as f32;
    let most_common = counts.iter().copied().max().unwrap_or(0) as f32;
    let distinct = counts.iter().filter(|&&count| count > 0).count();
    let is_padding = most_common > len * PADDING_DOMINANCE || distinct < MIN_DISTINCT_BYTES;
    let printable: usize = window.iter().filter(|&&byte| is_text_byte(byte)).count();
    let is_text = printable as f32 > len * TEXT_DOMINANCE;
    let is_high_entropy = shannon_entropy(&counts, len) > HIGH_ENTROPY_BITS;
    !(is_padding || is_text || is_high_entropy)
}

fn is_text_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0)
}

/// Entropy in bits per byte of a byte histogram covering `len` bytes.
fn shannon_entropy(counts: &[usize; 256], len: f32) -> f32 {
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f32 / len;
            -probability * probability.log2()
        })
        .sum()
}

/// At most `limit` items, spread evenly over `items`.
fn evenly_pick<T: Clone>(items: Vec<T>, limit: usize) -> Vec<T> {
    if items.len() <= limit {
        return items;
    }
    (0..limit).map(|index| items[index * items.len() / limit].clone()).collect()
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// Whether an idiom marks the start or the end of a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdiomKind {
    Entry,
    Exit,
}

/// Evidence gathered from one or more windows for one architecture.
#[derive(Default)]
struct Tally {
    bytes: usize,
    typical_bytes: f32,
    entry_weight: f32,
    exit_weight: f32,
    idioms: usize,
    branches: usize,
    branch_credit: f32,
    mnemonics: HashMap<String, usize>,
}

impl Tally {
    fn merge(&mut self, other: Tally) {
        self.bytes += other.bytes;
        self.typical_bytes += other.typical_bytes;
        self.entry_weight += other.entry_weight;
        self.exit_weight += other.exit_weight;
        self.idioms += other.idioms;
        self.branches += other.branches;
        self.branch_credit += other.branch_credit;
        for (mnemonic, count) in other.mnemonics {
            *self.mnemonics.entry(mnemonic).or_default() += count;
        }
    }

    fn typical_fraction(&self) -> f32 {
        if self.bytes == 0 { 0.0 } else { (self.typical_bytes / self.bytes as f32).min(1.0) }
    }

    /// The weaker of the entry and exit idiom densities, each saturating at
    /// [`IDIOMS_PER_KIB_FOR_FULL_SCORE`].
    fn idiom_score(&self) -> f32 {
        if self.bytes == 0 {
            return 0.0;
        }
        let density = |weight: f32| (weight * BYTES_PER_KIB / self.bytes as f32 / IDIOMS_PER_KIB_FOR_FULL_SCORE).min(1.0);
        density(self.entry_weight).min(density(self.exit_weight))
    }

    fn branch_plausibility(&self) -> f32 {
        if self.branches < MIN_BRANCHES { NEUTRAL_BRANCH_SCORE } else { self.branch_credit / self.branches as f32 }
    }

    /// Share of instructions taken by the most common mnemonics, scaled down
    /// when only a few distinct mnemonics appear at all.
    fn diversity(&self) -> f32 {
        let total: usize = self.mnemonics.values().sum();
        if total == 0 {
            return 0.0;
        }
        let mut counts: Vec<usize> = self.mnemonics.values().copied().collect();
        counts.sort_unstable_by(|a, b| b.cmp(a));
        let concentration = counts.iter().take(TOP_MNEMONICS).sum::<usize>() as f32 / total as f32;
        let variety = (counts.len() as f32 / DISTINCT_MNEMONICS_FOR_FULL_SCORE as f32).min(1.0);
        concentration * variety
    }

    fn confidence(&self) -> f32 {
        let score = WEIGHT_TYPICAL * self.typical_fraction()
            + WEIGHT_IDIOMS * self.idiom_score()
            + WEIGHT_BRANCHES * self.branch_plausibility()
            + WEIGHT_DIVERSITY * self.diversity();
        score.clamp(0.0, 1.0)
    }
}

fn score_architecture(arch: Arch, bytes: &[u8], windows: &[Range<usize>], base_offset: usize) -> ArchCandidate {
    let mut total = Tally::default();
    let mut best_window: Option<(f32, usize)> = None;
    for window in windows {
        let tally = match tally_window(arch, bytes, window.clone()) {
            Ok(tally) => tally,
            Err(message) => {
                let mut candidate = no_evidence(arch, base_offset);
                candidate.reason = format!("the disassembler could not start: {message}");
                return candidate;
            }
        };
        let window_score = tally.confidence();
        if best_window.is_none_or(|(score, _)| window_score > score) {
            best_window = Some((window_score, window.start));
        }
        total.merge(tally);
    }
    let best_window_start = best_window.map(|(_, start)| start).unwrap_or(0);
    let candidate = ArchCandidate {
        arch,
        confidence: total.confidence(),
        reason: String::new(),
        typical_fraction: total.typical_fraction(),
        idioms: total.idioms,
        branch_plausibility: total.branch_plausibility(),
        diversity: total.diversity(),
        best_window_offset: base_offset + best_window_start,
    };
    ArchCandidate { reason: describe(&candidate, total.branches), ..candidate }
}

fn describe(candidate: &ArchCandidate, branches: usize) -> String {
    let branch_text = if branches < MIN_BRANCHES {
        "too few branches to judge".to_string()
    } else {
        format!("{:.0}% of {branches} branch targets plausible", candidate.branch_plausibility * 100.0)
    };
    let mix = match candidate.diversity {
        d if d >= 0.6 => "a code-like instruction mix",
        d if d >= 0.3 => "a mixed instruction mix",
        _ => "a scattered or repetitive instruction mix",
    };
    format!(
        "{:.0}% typical instructions, {} prologue/return idioms, {branch_text}, {mix}",
        candidate.typical_fraction * 100.0,
        candidate.idioms
    )
}

fn tally_window(arch: Arch, bytes: &[u8], window: Range<usize>) -> Result<Tally, String> {
    let slice = &bytes[window.clone()];
    // Addresses are file offsets: the load address is unknown, and relative
    // branches do not depend on it.
    let instructions = disasm::disassemble(arch, slice, window.start, window.start as u64, slice.len())?;
    let boundaries: HashSet<u64> = instructions.iter().map(|instruction| instruction.address).collect();
    let mut tally = Tally { bytes: slice.len(), ..Tally::default() };
    let mut previous: Option<&Instruction> = None;
    for instruction in &instructions {
        if instruction.is_data() || is_implausible(&instruction.mnemonic) {
            previous = None;
            continue;
        }
        let weight = if is_typical(arch, instruction) { 1.0 } else { UNUSUAL_INSTRUCTION_WEIGHT };
        tally.typical_bytes += instruction.len as f32 * weight;
        *tally.mnemonics.entry(instruction.mnemonic.clone()).or_default() += 1;

        match idiom(arch, previous, instruction) {
            Some((IdiomKind::Entry, weight)) => {
                tally.idioms += 1;
                tally.entry_weight += weight;
            }
            Some((IdiomKind::Exit, weight)) => {
                tally.idioms += 1;
                tally.exit_weight += weight;
            }
            None => {}
        }
        if let Some(target) = instruction.branch_target {
            tally.branches += 1;
            tally.branch_credit += branch_credit(arch, target, &window, bytes.len(), &boundaries);
        }
        previous = Some(instruction);
    }
    Ok(tally)
}

/// 1 for a target on an instruction boundary inside the window, partial
/// credit for an aligned target elsewhere in the blob, 0 otherwise.
fn branch_credit(arch: Arch, target: u64, window: &Range<usize>, blob_len: usize, boundaries: &HashSet<u64>) -> f32 {
    if target >= blob_len as u64 {
        return 0.0;
    }
    let inside_window = target >= window.start as u64 && target < window.end as u64;
    if inside_window {
        return if boundaries.contains(&target) { 1.0 } else { 0.0 };
    }
    if target.is_multiple_of(arch.min_instruction_len() as u64) { OUTSIDE_WINDOW_CREDIT } else { 0.0 }
}

/// Whether `instruction` (after `previous`) is a characteristic function
/// entry or exit on `arch`, and how specific its encoding is.
fn idiom(arch: Arch, previous: Option<&Instruction>, instruction: &Instruction) -> Option<(IdiomKind, f32)> {
    use IdiomKind::{Entry, Exit};
    let mnemonic = instruction.mnemonic.as_str();
    let operands = instruction.operands.as_str();
    let follows = |wanted_mnemonic: &str, wanted_operands: &str| {
        previous.is_some_and(|p| p.mnemonic == wanted_mnemonic && p.operands == wanted_operands)
    };
    let found = match arch {
        Arch::X86_64 => match mnemonic {
            "mov" if operands == "rbp, rsp" && follows("push", "rbp") => (Entry, STRONG_IDIOM),
            "endbr64" => (Entry, STRONG_IDIOM),
            "sub" if operands.starts_with("rsp, ") => (Entry, MEDIUM_IDIOM),
            "leave" => (Exit, MEDIUM_IDIOM),
            "ret" => (Exit, WEAK_IDIOM),
            _ => return None,
        },
        Arch::X86_32 => match mnemonic {
            "mov" if operands == "ebp, esp" && follows("push", "ebp") => (Entry, STRONG_IDIOM),
            "sub" if operands.starts_with("esp, ") => (Entry, MEDIUM_IDIOM),
            "leave" => (Exit, MEDIUM_IDIOM),
            "ret" => (Exit, WEAK_IDIOM),
            _ => return None,
        },
        Arch::Arm64 => match mnemonic {
            "stp" if operands.starts_with("x29, x30") => (Entry, STRONG_IDIOM),
            "ldp" if operands.starts_with("x29, x30") => (Exit, STRONG_IDIOM),
            "ret" => (Exit, STRONG_IDIOM),
            _ => return None,
        },
        Arch::Arm32 => match mnemonic {
            "push" if operands.contains("lr}") => (Entry, STRONG_IDIOM),
            "pop" if operands.contains("pc}") => (Exit, STRONG_IDIOM),
            "bx" if operands == "lr" => (Exit, STRONG_IDIOM),
            _ => return None,
        },
        // 16-bit push/pop encodings are common in random halfwords, so they
        // count for less than the exact `bx lr` (0x4770).
        Arch::Thumb => match mnemonic {
            "push" | "push.w" if operands.contains("lr}") => (Entry, WEAK_IDIOM),
            "pop" | "pop.w" if operands.contains("pc}") => (Exit, WEAK_IDIOM),
            "bx" if operands == "lr" => (Exit, STRONG_IDIOM),
            _ => return None,
        },
        Arch::RiscV64 | Arch::RiscV32 => match mnemonic.trim_start_matches("c.") {
            "addi" if operands.starts_with("sp, sp, -") || operands.starts_with("sp, -") => (Entry, MEDIUM_IDIOM),
            "addi16sp" if operands.contains('-') => (Entry, MEDIUM_IDIOM),
            "sd" | "sw" | "sdsp" | "swsp" if operands.starts_with("ra, ") => (Entry, MEDIUM_IDIOM),
            "ret" => (Exit, STRONG_IDIOM),
            "jr" if operands == "ra" => (Exit, STRONG_IDIOM),
            _ => return None,
        },
        Arch::Mips32 => match mnemonic {
            "addiu" if operands.starts_with("$sp, $sp, -") => (Entry, STRONG_IDIOM),
            "sw" if operands.starts_with("$ra, ") => (Entry, MEDIUM_IDIOM),
            "jr" if operands == "$ra" => (Exit, STRONG_IDIOM),
            _ => return None,
        },
        Arch::PowerPc32 => match mnemonic {
            "stwu" if operands.starts_with("r1, -") => (Entry, STRONG_IDIOM),
            "mflr" => (Entry, STRONG_IDIOM),
            "mtlr" => (Exit, STRONG_IDIOM),
            "blr" => (Exit, STRONG_IDIOM),
            _ => return None,
        },
    };
    Some(found)
}

// The two classifiers below mirror the private ones in `disasm.rs`; they are
// duplicated rather than exported so that module's interface stays unchanged.

/// Whether an instruction is one compilers emit constantly on `arch`.
fn is_typical(arch: Arch, instruction: &Instruction) -> bool {
    let mnemonic = instruction.mnemonic.as_str();
    let one_of = |list: &[&str]| list.contains(&mnemonic);
    match arch {
        Arch::X86_64 | Arch::X86_32 => {
            // In 32-bit mode the REX prefixes of 64-bit code decode as
            // one-byte inc/dec; many of them are evidence for x86-64.
            let rex_as_inc_dec = arch == Arch::X86_32
                && instruction.len == 1
                && instruction.bytes.first().is_some_and(|byte| X86_REX_PREFIXES.contains(byte));
            !rex_as_inc_dec
                && (one_of(&[
                    "mov", "push", "pop", "call", "ret", "jmp", "lea", "add", "sub", "cmp", "test", "xor", "and", "or", "nop", "movzx",
                    "movsx", "movsxd", "imul", "shl", "shr", "sar", "leave", "endbr64", "inc", "dec", "neg", "not", "movq", "movd",
                    "movss", "movsd", "movaps", "movups", "cdqe", "cqo",
                ]) || mnemonic.starts_with('j')
                    || mnemonic.starts_with("cmov")
                    || mnemonic.starts_with("set"))
        }
        Arch::Arm64 => {
            one_of(&[
                "stp", "ldp", "mov", "ldr", "str", "ldrb", "strb", "ldrh", "strh", "ldur", "stur", "add", "sub", "adds", "subs", "bl",
                "b", "br", "blr", "cbz", "cbnz", "tbz", "tbnz", "ret", "adrp", "adr", "cmp", "cmn", "orr", "and", "eor", "lsl", "lsr",
                "asr", "movz", "movk", "movn", "csel", "cset", "csinc", "nop", "madd", "mul", "udiv", "sdiv", "sxtw", "uxtb", "tst",
                "ubfx", "sbfx",
            ]) || mnemonic.starts_with("b.")
        }
        Arch::Arm32 => {
            // Real ARM code is overwhelmingly unconditional.
            let condition = instruction.bytes.get(3).map(|byte| byte >> 4);
            condition == Some(ARM_CONDITION_ALWAYS)
                && one_of(&[
                    "push", "pop", "mov", "ldr", "str", "ldrb", "strb", "add", "sub", "bl", "b", "bx", "cmp", "orr", "and", "lsl", "lsr",
                    "mvn", "ldm", "stm", "blx",
                ])
        }
        Arch::Thumb => one_of(&[
            "push", "pop", "mov", "movs", "ldr", "str", "ldrb", "strb", "add", "adds", "sub", "subs", "bl", "b", "bx", "blx", "cmp",
            "beq", "bne", "cbz", "cbnz", "lsls", "lsrs", "ands", "orrs", "it", "ldr.w", "str.w",
        ]),
        Arch::RiscV64 | Arch::RiscV32 => {
            let base = mnemonic.trim_start_matches("c.");
            [
                "addi", "addiw", "sd", "ld", "sw", "lw", "jal", "jalr", "beq", "bne", "blt", "bge", "bltu", "bgeu", "auipc", "lui", "add",
                "sub", "li", "mv", "ret", "j", "nop", "slli", "srli", "andi", "beqz", "bnez", "sdsp", "ldsp", "swsp", "lwsp", "addi16sp",
                "addi4spn", "jr",
            ]
            .contains(&base)
        }
        Arch::Mips32 => one_of(&[
            "addiu", "lw", "sw", "jal", "jr", "nop", "lui", "ori", "beq", "bne", "move", "addu", "subu", "sll", "srl", "lb", "sb", "slt",
            "sltu", "b", "beqz", "bnez", "li", "jalr",
        ]),
        Arch::PowerPc32 => one_of(&[
            "stwu", "mflr", "mtlr", "stw", "lwz", "addi", "li", "lis", "bl", "blr", "mr", "cmpwi", "cmplwi", "beq", "bne", "b", "ori",
            "stmw", "lmw", "add", "subf", "rlwinm", "nop",
        ]),
    }
}

/// Instructions that are valid but almost never appear in ordinary code, so
/// decoding data as them is evidence against an architecture.
fn is_implausible(mnemonic: &str) -> bool {
    const RARE: [&str; 22] = [
        "in", "out", "insb", "insd", "outsb", "outsd", "hlt", "cli", "sti", "lock", "bound", "into", "aaa", "aas", "daa", "das", "arpl",
        "les", "lds", "salc", "fwait", "udf",
    ];
    RARE.contains(&mnemonic) || mnemonic.starts_with("ud") || mnemonic.starts_with("invalid")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Repeat `block` until `len` bytes are filled, as a stand-in for a code section.
    fn repeat_to(block: &[u8], len: usize) -> Vec<u8> {
        block.iter().copied().cycle().take(len).collect()
    }

    fn words_le(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn words_be(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_be_bytes()).collect()
    }

    fn halfwords_le(halfwords: &[u16]) -> Vec<u8> {
        halfwords.iter().flat_map(|halfword| halfword.to_le_bytes()).collect()
    }

    /// Deterministic pseudo-random bytes (xorshift).
    fn noise(len: usize, seed: u32) -> Vec<u8> {
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

    fn thumb_functions() -> Vec<u8> {
        halfwords_le(&[
            // push {r4-r7, lr}; mov r4, r0; mov r5, r1; movs r0, #0
            0xB5F0, 0x4604, 0x460D, 0x2000,
            // loop: ldr r1, [r4]; adds r0, r0, r1; adds r4, #1; subs r5, #1; bne loop; pop {r4-r7, pc}
            0x6821, 0x1840, 0x3401, 0x3D01, 0xD1FA, 0xBDF0,
            // cmp r1, #0; beq +2; subs r0, r0, r1; bx lr; movs r0, #0; bx lr
            0x2900, 0xD001, 0x1A40, 0x4770, 0x2000, 0x4770,
            // push {r3-r5, lr}; ldr r3, [pc, #12]; ldr r4, [r3]; strb r5, [r4]; movs r0, #1; pop {r3-r5, pc}
            0xB538, 0x4B03, 0x681C, 0x7025, 0x2001, 0xBD38,
        ])
    }

    fn arm_functions() -> Vec<u8> {
        words_le(&[
            0xE92D4010, // push {r4, lr}
            0xE1A04000, // mov r4, r0
            0xE5940000, // ldr r0, [r4]
            0xE2800001, // add r0, r0, #1
            0xE5840000, // str r0, [r4]
            0xE3500000, // cmp r0, #0
            0x1AFFFFFA, // bne back to the ldr
            0xE8BD8010, // pop {r4, pc}
            0xE0800001, // add r0, r0, r1
            0xE12FFF1E, // bx lr
            0xE92D4010, // push {r4, lr}
            0xEBFFFFFB, // bl to the add above
            0xE8BD8010, // pop {r4, pc}
        ])
    }

    fn arm64_functions() -> Vec<u8> {
        words_le(&[
            0xA9BF7BFD, // stp x29, x30, [sp, #-16]!
            0x910003FD, // mov x29, sp
            0x11000400, // add w0, w0, #1
            0x8B010000, // add x0, x0, x1
            0xF9400000, // ldr x0, [x0]
            0xA8C17BFD, // ldp x29, x30, [sp], #16
            0xD65F03C0, // ret
            0x97FFFFF9, // bl back to the stp
        ])
    }

    fn x86_64_functions() -> Vec<u8> {
        [
            &[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x89, 0x7D, 0xFC, 0x8B, 0x45, 0xFC, 0x83, 0xC0, 0x01, 0x48, 0x83, 0xC4, 0x20, 0x5D, 0xC3][..],
            &[0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0x7D, 0xF8, 0x48, 0x8B, 0x45, 0xF8, 0x48, 0x8B, 0x00, 0x5D, 0xC3][..],
            // push rbp; mov rbp, rsp; call (back to the start of the block); xor eax, eax; pop rbp; ret
            &[0x55, 0x48, 0x89, 0xE5, 0xE8, 0xBC, 0xFF, 0xFF, 0xFF, 0x31, 0xC0, 0x5D, 0xC3][..],
        ]
        .concat()
    }

    fn riscv_functions() -> Vec<u8> {
        words_le(&[
            0xFF010113, // addi sp, sp, -16
            0x00112623, // sw ra, 12(sp)
            0x00050793, // mv a5, a0
            0x00F585B3, // add a1, a1, a5
            0x00C12083, // lw ra, 12(sp)
            0x01010113, // addi sp, sp, 16
            0x00008067, // ret
        ])
    }

    fn mips_functions() -> Vec<u8> {
        words_be(&[
            0x27BDFFE0, // addiu $sp, $sp, -32
            0xAFBF001C, // sw $ra, 28($sp)
            0xAFB00018, // sw $s0, 24($sp)
            0x00808025, // move $s0, $a0
            0x8E020000, // lw $v0, 0($s0)
            0x24420001, // addiu $v0, $v0, 1
            0xAE020000, // sw $v0, 0($s0)
            0x8FBF001C, // lw $ra, 28($sp)
            0x8FB00018, // lw $s0, 24($sp)
            0x03E00008, // jr $ra
            0x27BD0020, // addiu $sp, $sp, 32
        ])
    }

    fn powerpc_functions() -> Vec<u8> {
        words_be(&[
            0x9421FFF0, // stwu r1, -16(r1)
            0x7C0802A6, // mflr r0
            0x90010014, // stw r0, 20(r1)
            0x38630001, // addi r3, r3, 1
            0x80010014, // lwz r0, 20(r1)
            0x7C0803A6, // mtlr r0
            0x38210010, // addi r1, r1, 16
            0x4E800020, // blr
        ])
    }

    fn scores(report: &CpuReport) -> Vec<(Arch, f32)> {
        report.candidates.iter().map(|c| (c.arch, c.confidence)).collect()
    }

    #[test]
    fn each_architectures_own_code_ranks_it_first() {
        let cases: [(&[Arch], Vec<u8>); 7] = [
            (&[Arch::Thumb], thumb_functions()),
            (&[Arch::Arm32], arm_functions()),
            (&[Arch::Arm64], arm64_functions()),
            (&[Arch::X86_64], x86_64_functions()),
            (&[Arch::RiscV32, Arch::RiscV64], riscv_functions()),
            (&[Arch::Mips32], mips_functions()),
            (&[Arch::PowerPc32], powerpc_functions()),
        ];
        for (expected, block) in cases {
            let blob = repeat_to(&block, 8192);
            let report = identify_architecture(&blob, 0);
            let best = report.best().unwrap_or_else(|| panic!("{expected:?} judged as data: {:?}", scores(&report)));
            assert!(expected.contains(&best.arch), "expected {expected:?}, got {:?}: {:?}", best.arch, scores(&report));
            assert!(!best.reason.is_empty());
            assert_eq!(report.candidates.len(), Arch::ALL.len());
        }
    }

    #[test]
    fn random_bytes_are_reported_as_data() {
        let report = identify_architecture(&noise(64 * 1024, 0x5EED), 0);
        assert!(report.looks_like_data, "{:?}", scores(&report));
        assert!(report.best().is_none());
        assert!(report.summary.contains("data"));
    }

    #[test]
    fn english_text_is_reported_as_data() {
        let text = b"The quick brown fox jumps over the lazy dog. Firmware strings, menus and error messages are not code. ";
        let report = identify_architecture(&repeat_to(text, 16 * 1024), 0);
        assert!(report.looks_like_data, "{:?}", scores(&report));
    }

    #[test]
    fn padding_and_erased_flash_have_no_code_to_judge() {
        for fill in [0x00u8, 0xFF] {
            let report = identify_architecture(&vec![fill; 32 * 1024], 0);
            assert!(report.looks_like_data);
            assert_eq!(report.windows, 0);
            assert!(report.candidates.iter().all(|c| c.confidence == 0.0));
        }
    }

    #[test]
    fn too_short_input_returns_no_candidates_without_panicking() {
        for len in [0, 1, 7, MIN_SAMPLE_LEN - 1] {
            let report = identify_architecture(&vec![0x4Au8; len], 0);
            assert!(report.candidates.is_empty());
            assert!(report.looks_like_data);
        }
    }

    #[test]
    fn large_inputs_are_sampled_within_the_window_budget() {
        let mut blob = noise(4 * 1024 * 1024, 7);
        let code = repeat_to(&thumb_functions(), 2 * 1024 * 1024);
        blob[1024 * 1024..3 * 1024 * 1024].copy_from_slice(&code);
        let report = identify_architecture(&blob, 0x100);
        assert!(report.windows <= MAX_WINDOWS);
        assert!(report.sampled_bytes <= MAX_WINDOWS * WINDOW_LEN);
        let best = report.best().expect("half the file is Thumb code");
        assert_eq!(best.arch, Arch::Thumb, "{:?}", scores(&report));
        // The most convincing window lies inside the code, in document offsets.
        assert!((0x100 + 1024 * 1024..0x100 + 3 * 1024 * 1024).contains(&best.best_window_offset));
    }

    #[test]
    fn thumb_is_told_apart_from_arm_and_x86_64_from_x86() {
        let thumb = identify_architecture(&repeat_to(&thumb_functions(), 8192), 0);
        let arm_rank = thumb.candidates.iter().position(|c| c.arch == Arch::Arm32).unwrap();
        assert!(arm_rank > 0);
        let x86 = identify_architecture(&repeat_to(&x86_64_functions(), 8192), 0);
        let first = &x86.candidates[0];
        let x86_32 = x86.candidates.iter().find(|c| c.arch == Arch::X86_32).unwrap();
        assert_eq!(first.arch, Arch::X86_64);
        assert!(first.confidence > x86_32.confidence);
        assert!(first.idioms > 0);
    }

    #[test]
    fn numeric_tables_and_low_entropy_data_are_reported_as_data() {
        let floats: Vec<u8> = (0..8192).flat_map(|i| ((i as f32 * 0.01).sin() * 100.0).to_le_bytes()).collect();
        let records: Vec<u8> = (0u32..8192).flat_map(|i| [i.to_le_bytes(), (i * 7 % 1000).to_le_bytes()].concat()).collect();
        let six_bit: Vec<u8> = noise(32 * 1024, 9).iter().map(|byte| byte & 0x3F).collect();
        for (name, blob) in [("floats", floats), ("records", records), ("six-bit", six_bit)] {
            let report = identify_architecture(&blob, 0);
            assert!(report.looks_like_data, "{name}: {:?}", scores(&report));
        }
    }

    #[test]
    fn real_machine_code_from_the_test_binary_is_identified() {
        let own = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let (arch, entry, _) = disasm::detect_arch(&own).expect("the test binary has a header");
        let map = disasm::AddressMap::from_executable(&own).expect("address map");
        let at = map.offset_of(entry).expect("entry inside the file");
        let code = &own[at.saturating_sub(128 * 1024)..(at + 128 * 1024).min(own.len())];
        let report = identify_architecture(code, 0);
        let best = report.best().unwrap_or_else(|| panic!("judged as data: {:?}", scores(&report)));
        assert_eq!(best.arch, arch, "{:?}", scores(&report));
    }
}
