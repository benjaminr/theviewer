//! CRC parameter solver, in the spirit of `reveng`: given several messages
//! that each carry a stored CRC, find the CRC parameters (polynomial, initial
//! value, final XOR and reflection) that reproduce every stored value.
//!
//! The search works in the Rocksoft model (the register is never reflected;
//! `refin` reverses each input byte, `refout` reverses the final register).
//! A CRC is affine in its input, which gives two shortcuts:
//!
//! 1. **Polynomial first.** For two messages of equal length, init and xorout
//!    cancel: `crc(a) ^ crc(b) = crc₀(a ^ b)`, the plain CRC with init and
//!    xorout zero. That makes the generator divide the GF(2) polynomial
//!    `D(x)·xʷ + C(x)` built from the XOR of the messages (`D`) and of their
//!    stored values (`C`). The GCD over several pairs usually *is* the
//!    generator; otherwise every polynomial of the width (8 and 16 bits) or a
//!    catalogue of known ones (32 bits) is tested against it.
//! 2. **Init and xorout second.** With the polynomial fixed, each message
//!    gives `width` linear equations in the bits of init and xorout, solved
//!    by Gaussian elimination over GF(2).
//!
//! Each candidate is verified by recomputing every message's CRC. The search
//! is bounded by a time budget and gives up with an explanation instead of
//! running on.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

/// Most messages examined; the rest are ignored (and a note says so).
pub const MAX_MESSAGES: usize = 256;
/// Longest stretch of bytes a CRC may cover.
pub const MAX_COVERED_LEN: usize = 4096;
/// Default number of leading header or sync bytes the solver tries skipping.
pub const DEFAULT_MAX_SKIP: usize = 4;
/// Default limit on the wall-clock time of one solve.
pub const DEFAULT_TIME_BUDGET: Duration = Duration::from_secs(4);
/// Most solutions reported.
const MAX_SOLUTIONS: usize = 64;
/// Most equal-length message pairs used to pin down the polynomial.
const MAX_PAIRS: usize = 16;
/// Polynomials tried between two checks of the deadline.
const DEADLINE_CHECK_INTERVAL: u32 = 256;
/// The standard input for catalogue "check" values.
pub const CHECK_INPUT: &[u8] = b"123456789";
/// Bits in a byte.
const BYTE_BITS: u32 = 8;

// ---------------------------------------------------------------------------
// Parameters and computation
// ---------------------------------------------------------------------------

/// The width of the stored CRC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CrcWidth {
    W8,
    #[default]
    W16,
    W32,
}

impl CrcWidth {
    /// Width in bits.
    pub fn bits(self) -> u32 {
        match self {
            CrcWidth::W8 => 8,
            CrcWidth::W16 => 16,
            CrcWidth::W32 => 32,
        }
    }

    /// Width in bytes.
    pub fn bytes(self) -> usize {
        (self.bits() / BYTE_BITS) as usize
    }
}

/// A CRC algorithm in the Rocksoft model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CrcParams {
    /// Width in bits: 8, 16 or 32.
    pub width: u32,
    /// Generator polynomial without its top (xʷ) term.
    pub poly: u32,
    /// Initial register value.
    pub init: u32,
    /// Whether each input byte is bit-reversed.
    pub refin: bool,
    /// Whether the final register is bit-reversed.
    pub refout: bool,
    /// Value XORed into the result.
    pub xorout: u32,
}

impl CrcParams {
    /// Mask of the low `width` bits.
    pub fn mask(&self) -> u32 {
        width_mask(self.width)
    }

    /// The CRC of `data`.
    pub fn compute(&self, data: &[u8]) -> u32 {
        let mut register = self.init & self.mask();
        for &byte in data {
            let byte = if self.refin { byte.reverse_bits() } else { byte };
            register = feed_byte_bitwise(register, byte, self.poly, self.width);
        }
        if self.refout {
            register = reflect(register, self.width);
        }
        (register ^ self.xorout) & self.mask()
    }

    /// The CRC of the standard check string "123456789".
    pub fn check(&self) -> u32 {
        self.compute(CHECK_INPUT)
    }

    /// The parameters in `reveng` notation, e.g.
    /// `width=16 poly=0x8005 init=0xffff refin=true refout=true xorout=0x0000`.
    pub fn to_text(&self) -> String {
        let digits = (self.width / 4) as usize;
        format!(
            "width={} poly=0x{:0digits$x} init=0x{:0digits$x} refin={} refout={} xorout=0x{:0digits$x} check=0x{:0digits$x}",
            self.width,
            self.poly,
            self.init,
            self.refin,
            self.refout,
            self.xorout,
            self.check(),
        )
    }
}

impl fmt::Display for CrcParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_text())
    }
}

/// Mask of the low `width` bits (width 1..=32).
fn width_mask(width: u32) -> u32 {
    if width >= u32::BITS { u32::MAX } else { (1u32 << width) - 1 }
}

/// Reverse the low `width` bits of `value`.
fn reflect(value: u32, width: u32) -> u32 {
    value.reverse_bits() >> (u32::BITS - width)
}

/// Shift one byte (most significant bit first) into a non-reflected register.
fn feed_byte_bitwise(register: u32, byte: u8, poly: u32, width: u32) -> u32 {
    let mask = width_mask(width);
    let top_bit = 1u32 << (width - 1);
    let mut register = register ^ ((byte as u32) << (width - BYTE_BITS));
    for _ in 0..BYTE_BITS {
        register = if register & top_bit != 0 { (register << 1) ^ poly } else { register << 1 };
        register &= mask;
    }
    register
}

/// The plain CRC (init 0, no reflection, xorout 0) of already-prepared bytes.
fn plain_crc(data: &[u8], poly: u32, width: u32) -> u32 {
    data.iter().fold(0, |register, &byte| feed_byte_bitwise(register, byte, poly, width))
}

// ---------------------------------------------------------------------------
// Catalogue
// ---------------------------------------------------------------------------

/// A named CRC algorithm with its published check value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogueEntry {
    pub name: &'static str,
    pub params: CrcParams,
    /// CRC of "123456789".
    pub check: u32,
}

const fn entry(name: &'static str, width: u32, poly: u32, init: u32, reflected: bool, xorout: u32, check: u32) -> CatalogueEntry {
    CatalogueEntry { name, params: CrcParams { width, poly, init, refin: reflected, refout: reflected, xorout }, check }
}

/// Well-known CRC algorithms (from the reveng catalogue).
pub const CATALOGUE: &[CatalogueEntry] = &[
    entry("CRC-8/SMBUS", 8, 0x07, 0x00, false, 0x00, 0xF4),
    entry("CRC-8/I-432-1", 8, 0x07, 0x00, false, 0x55, 0xA1),
    entry("CRC-8/ROHC", 8, 0x07, 0xFF, true, 0x00, 0xD0),
    entry("CRC-8/MAXIM-DOW", 8, 0x31, 0x00, true, 0x00, 0xA1),
    entry("CRC-8/NRSC-5", 8, 0x31, 0xFF, false, 0x00, 0xF7),
    entry("CRC-8/AUTOSAR", 8, 0x2F, 0xFF, false, 0xFF, 0xDF),
    entry("CRC-8/CDMA2000", 8, 0x9B, 0xFF, false, 0x00, 0xDA),
    entry("CRC-8/DVB-S2", 8, 0xD5, 0x00, false, 0x00, 0xBC),
    entry("CRC-8/SAE-J1850", 8, 0x1D, 0xFF, false, 0xFF, 0x4B),
    entry("CRC-8/BLUETOOTH", 8, 0xA7, 0x00, true, 0x00, 0x26),
    entry("CRC-16/IBM-3740 (CCITT-FALSE)", 16, 0x1021, 0xFFFF, false, 0x0000, 0x29B1),
    entry("CRC-16/XMODEM", 16, 0x1021, 0x0000, false, 0x0000, 0x31C3),
    entry("CRC-16/KERMIT", 16, 0x1021, 0x0000, true, 0x0000, 0x2189),
    entry("CRC-16/IBM-SDLC (X-25)", 16, 0x1021, 0xFFFF, true, 0xFFFF, 0x906E),
    entry("CRC-16/MCRF4XX", 16, 0x1021, 0xFFFF, true, 0x0000, 0x6F91),
    entry("CRC-16/GENIBUS", 16, 0x1021, 0xFFFF, false, 0xFFFF, 0xD64E),
    entry("CRC-16/SPI-FUJITSU (AUG-CCITT)", 16, 0x1021, 0x1D0F, false, 0x0000, 0xE5CC),
    entry("CRC-16/MODBUS", 16, 0x8005, 0xFFFF, true, 0x0000, 0x4B37),
    entry("CRC-16/ARC", 16, 0x8005, 0x0000, true, 0x0000, 0xBB3D),
    entry("CRC-16/USB", 16, 0x8005, 0xFFFF, true, 0xFFFF, 0xB4C8),
    entry("CRC-16/MAXIM-DOW", 16, 0x8005, 0x0000, true, 0xFFFF, 0x44C2),
    entry("CRC-16/UMTS (BUYPASS)", 16, 0x8005, 0x0000, false, 0x0000, 0xFEE8),
    entry("CRC-16/CMS", 16, 0x8005, 0xFFFF, false, 0x0000, 0xAEE7),
    entry("CRC-16/DNP", 16, 0x3D65, 0x0000, true, 0xFFFF, 0xEA82),
    entry("CRC-16/DECT-X", 16, 0x0589, 0x0000, false, 0x0000, 0x007F),
    entry("CRC-16/T10-DIF", 16, 0x8BB7, 0x0000, false, 0x0000, 0xD0DB),
    entry("CRC-32/ISO-HDLC", 32, 0x04C1_1DB7, 0xFFFF_FFFF, true, 0xFFFF_FFFF, 0xCBF4_3926),
    entry("CRC-32/BZIP2", 32, 0x04C1_1DB7, 0xFFFF_FFFF, false, 0xFFFF_FFFF, 0xFC89_1918),
    entry("CRC-32/MPEG-2", 32, 0x04C1_1DB7, 0xFFFF_FFFF, false, 0x0000_0000, 0x0376_E6E7),
    entry("CRC-32/CKSUM", 32, 0x04C1_1DB7, 0x0000_0000, false, 0xFFFF_FFFF, 0x765E_7680),
    entry("CRC-32/JAMCRC", 32, 0x04C1_1DB7, 0xFFFF_FFFF, true, 0x0000_0000, 0x340B_C6D9),
    entry("CRC-32/ISCSI (CRC-32C)", 32, 0x1EDC_6F41, 0xFFFF_FFFF, true, 0xFFFF_FFFF, 0xE306_9283),
    entry("CRC-32/BASE91-D", 32, 0xA833_982B, 0xFFFF_FFFF, true, 0xFFFF_FFFF, 0x8731_5576),
    entry("CRC-32/AUTOSAR", 32, 0xF4AC_FB13, 0xFFFF_FFFF, true, 0xFFFF_FFFF, 0x1697_D06A),
    entry("CRC-32/AIXM", 32, 0x8141_41AB, 0x0000_0000, false, 0x0000_0000, 0x3010_BF7F),
    entry("CRC-32/XFER", 32, 0x0000_00AF, 0x0000_0000, false, 0x0000_0000, 0xBD0B_E338),
    entry("CRC-32/CD-ROM-EDC", 32, 0x8001_801B, 0x0000_0000, true, 0x0000_0000, 0x6EC2_EDC4),
];

/// How a solution relates to the catalogue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedMatch {
    pub name: &'static str,
    /// True when every parameter matches the catalogue entry.
    pub exact: bool,
    /// What differs, empty when exact.
    pub differences: String,
}

/// The catalogue entry closest to `params`: identical, else same polynomial
/// and reflection, else same polynomial.
pub fn closest_named(params: &CrcParams) -> Option<NamedMatch> {
    let same_width = CATALOGUE.iter().filter(|e| e.params.width == params.width && e.params.poly == params.poly);
    let mut best: Option<(u32, &CatalogueEntry)> = None;
    for candidate in same_width {
        let distance = parameter_distance(&candidate.params, params);
        if best.is_none_or(|(d, _)| distance < d) {
            best = Some((distance, candidate));
        }
    }
    let (distance, found) = best?;
    Some(NamedMatch { name: found.name, exact: distance == 0, differences: describe_differences(&found.params, params) })
}

/// How many of init, xorout and reflection differ, reflection weighted most.
fn parameter_distance(a: &CrcParams, b: &CrcParams) -> u32 {
    const REFLECTION_WEIGHT: u32 = 4;
    let reflection = u32::from(a.refin != b.refin || a.refout != b.refout) * REFLECTION_WEIGHT;
    reflection + u32::from(a.init != b.init) + u32::from(a.xorout != b.xorout)
}

fn describe_differences(named: &CrcParams, found: &CrcParams) -> String {
    let digits = (named.width / 4) as usize;
    let mut parts = Vec::new();
    if named.refin != found.refin || named.refout != found.refout {
        parts.push(format!("reflection {}/{} instead of {}/{}", found.refin, found.refout, named.refin, named.refout));
    }
    if named.init != found.init {
        parts.push(format!("init 0x{:0digits$x} instead of 0x{:0digits$x}", found.init, named.init));
    }
    if named.xorout != found.xorout {
        parts.push(format!("xorout 0x{:0digits$x} instead of 0x{:0digits$x}", found.xorout, named.xorout));
    }
    parts.join(", ")
}

// ---------------------------------------------------------------------------
// Options and results
// ---------------------------------------------------------------------------

/// Where the stored CRC sits in each message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CrcPosition {
    /// The last `width / 8` bytes; the CRC covers everything before them.
    #[default]
    End,
    /// At this offset from the message start; the CRC covers the bytes before it.
    Offset(usize),
}

/// Byte order of the stored CRC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum StoredOrder {
    Big,
    Little,
    /// Try both.
    #[default]
    Either,
}

impl StoredOrder {
    fn candidates(self, width: CrcWidth) -> &'static [bool] {
        const BIG_ONLY: &[bool] = &[true];
        const LITTLE_ONLY: &[bool] = &[false];
        const BOTH: &[bool] = &[true, false];
        match (self, width) {
            (_, CrcWidth::W8) | (StoredOrder::Big, _) => BIG_ONLY,
            (StoredOrder::Little, _) => LITTLE_ONLY,
            (StoredOrder::Either, _) => BOTH,
        }
    }
}

/// What to search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolverOptions {
    pub width: CrcWidth,
    pub position: CrcPosition,
    pub order: StoredOrder,
    /// Try skipping 0..=max_skip leading bytes of each message (sync words,
    /// headers outside the CRC).
    pub max_skip: usize,
    pub time_budget: Duration,
}

impl Default for SolverOptions {
    fn default() -> Self {
        SolverOptions {
            width: CrcWidth::default(),
            position: CrcPosition::default(),
            order: StoredOrder::default(),
            max_skip: DEFAULT_MAX_SKIP,
            time_budget: DEFAULT_TIME_BUDGET,
        }
    }
}

/// One set of parameters that reproduces every stored CRC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrcSolution {
    pub params: CrcParams,
    /// Leading bytes of each message not covered by the CRC.
    pub skip: usize,
    /// Whether the stored CRC is big-endian.
    pub big_endian: bool,
    /// The closest catalogue algorithm, if any shares the polynomial.
    pub named: Option<NamedMatch>,
    /// True when the messages cannot fully separate init from xorout (for
    /// example when they all have the same length, or when the polynomial has
    /// a factor x + 1); another init with a matching xorout fits too.
    pub init_ambiguous: bool,
}

impl CrcSolution {
    /// A one-line description for listing and copying.
    pub fn describe(&self) -> String {
        let order = if self.big_endian { "big-endian" } else { "little-endian" };
        let mut text = format!("{} · skip {} · stored {order}", self.params.to_text(), self.skip);
        if let Some(named) = &self.named {
            if named.exact {
                text.push_str(&format!(" · {}", named.name));
            } else {
                text.push_str(&format!(" · like {} ({})", named.name, named.differences));
            }
        }
        if self.init_ambiguous {
            text.push_str(" · init/xorout not separable");
        }
        text
    }
}

/// Everything a solve found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SolveReport {
    /// Consistent parameter sets, exact catalogue matches first.
    pub solutions: Vec<CrcSolution>,
    /// Caveats: messages ignored, ambiguity, truncation.
    pub notes: Vec<String>,
    /// Candidate polynomials tested: the work the search did.
    pub polynomials_tried: u64,
}

/// Why a solve could not run or finish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SolveError {
    TooFewMessages { found: usize },
    MessageTooShort { index: usize, len: usize, needed: usize },
    MessageTooLong { index: usize, covered: usize },
    TimedOut { budget: Duration, polynomials_tried: u64 },
}

impl fmt::Display for SolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SolveError::TooFewMessages { found } => {
                write!(formatter, "need at least 2 messages with a stored CRC, found {found}; four or more give a reliable answer")
            }
            SolveError::MessageTooShort { index, len, needed } => write!(
                formatter,
                "message {index} is {len} bytes, too short for the CRC position (needs at least {needed} bytes)"
            ),
            SolveError::MessageTooLong { index, covered } => write!(
                formatter,
                "message {index} would have the CRC cover {covered} bytes; the solver handles at most {MAX_COVERED_LEN}"
            ),
            SolveError::TimedOut { budget, polynomials_tried } => write!(
                formatter,
                "gave up after {:.1} s ({polynomials_tried} polynomials tried); give it more messages of the same length so the polynomial can be solved for directly",
                budget.as_secs_f32()
            ),
        }
    }
}

impl std::error::Error for SolveError {}

// ---------------------------------------------------------------------------
// Solving
// ---------------------------------------------------------------------------

/// A message prepared for one search configuration.
struct Prepared {
    /// Covered bytes, each bit-reversed when `refin`.
    data: Vec<u8>,
    /// Stored CRC, bit-reversed when `refout`, so it compares with the register.
    target: u32,
}

/// One combination of skip, byte order and reflection being searched.
#[derive(Clone, Copy)]
struct Setup {
    width: u32,
    skip: usize,
    big_endian: bool,
    reflected: bool,
}

/// Search state shared by every setup.
struct Search {
    deadline: Instant,
    budget: Duration,
    polynomials_tried: u64,
    found: BTreeMap<(CrcParams, usize, bool), CrcSolution>,
}

impl Search {
    fn out_of_time(&self) -> Result<(), SolveError> {
        if Instant::now() >= self.deadline {
            Err(SolveError::TimedOut { budget: self.budget, polynomials_tried: self.polynomials_tried })
        } else {
            Ok(())
        }
    }
}

/// Find every CRC parameter set that reproduces the stored CRC of each message.
pub fn solve(messages: &[&[u8]], options: &SolverOptions) -> Result<SolveReport, SolveError> {
    let mut notes = Vec::new();
    if messages.len() > MAX_MESSAGES {
        notes.push(format!("Used the first {MAX_MESSAGES} of {} messages.", messages.len()));
    }
    let messages = &messages[..messages.len().min(MAX_MESSAGES)];
    if messages.len() < 2 {
        return Err(SolveError::TooFewMessages { found: messages.len() });
    }
    validate_lengths(messages, options)?;

    let mut search = Search {
        deadline: Instant::now() + options.time_budget,
        budget: options.time_budget,
        polynomials_tried: 0,
        found: BTreeMap::new(),
    };
    let width = options.width.bits();
    for skip in 0..=options.max_skip {
        if !covers_at_least_one_byte(messages, options, skip) {
            break;
        }
        for &big_endian in options.order.candidates(options.width) {
            for reflected in [false, true] {
                let setup = Setup { width, skip, big_endian, reflected };
                search_setup(messages, options, setup, &mut search)?;
            }
        }
    }

    let mut solutions: Vec<CrcSolution> = search.found.into_values().collect();
    solutions.sort_by_key(|s| (!s.named.as_ref().is_some_and(|n| n.exact), s.init_ambiguous, s.skip, !s.big_endian));
    if solutions.len() > MAX_SOLUTIONS {
        notes.push(format!("Showing {MAX_SOLUTIONS} of {} consistent parameter sets; more messages narrow it down.", solutions.len()));
        solutions.truncate(MAX_SOLUTIONS);
    }
    if solutions.iter().any(|s| s.init_ambiguous) {
        notes.push(
            "Some init and xorout bits cannot be told apart from these messages (messages of more different lengths help): other inits with a matching xorout fit too. Shown with a catalogue match where one fits, else xorout = 0.".to_string(),
        );
    }
    if messages.len() < 4 && !solutions.is_empty() {
        notes.push("Few messages: some of these solutions may be coincidences.".to_string());
    }
    Ok(SolveReport { solutions, notes, polynomials_tried: search.polynomials_tried })
}

/// Check every message can hold the CRC and that the covered range is bounded.
fn validate_lengths(messages: &[&[u8]], options: &SolverOptions) -> Result<(), SolveError> {
    let crc_bytes = options.width.bytes();
    for (index, message) in messages.iter().enumerate() {
        let needed = match options.position {
            CrcPosition::End => crc_bytes + 1,
            CrcPosition::Offset(offset) => offset.max(1).saturating_add(crc_bytes),
        };
        if message.len() < needed {
            return Err(SolveError::MessageTooShort { index, len: message.len(), needed });
        }
        let covered = covered_end(message.len(), options);
        if covered > MAX_COVERED_LEN {
            return Err(SolveError::MessageTooLong { index, covered });
        }
    }
    Ok(())
}

/// End (exclusive) of the bytes the CRC covers.
fn covered_end(message_len: usize, options: &SolverOptions) -> usize {
    match options.position {
        CrcPosition::End => message_len - options.width.bytes(),
        CrcPosition::Offset(offset) => offset,
    }
}

fn covers_at_least_one_byte(messages: &[&[u8]], options: &SolverOptions, skip: usize) -> bool {
    messages.iter().all(|m| covered_end(m.len(), options) > skip)
}

/// The stored CRC of a message.
fn stored_value(message: &[u8], options: &SolverOptions, big_endian: bool) -> u32 {
    let start = match options.position {
        CrcPosition::End => message.len() - options.width.bytes(),
        CrcPosition::Offset(offset) => offset,
    };
    let bytes = &message[start..start + options.width.bytes()];
    let fold = |value: u32, &byte: &u8| (value << BYTE_BITS) | byte as u32;
    if big_endian { bytes.iter().fold(0, fold) } else { bytes.iter().rev().fold(0, fold) }
}

fn prepare(messages: &[&[u8]], options: &SolverOptions, setup: Setup) -> Vec<Prepared> {
    messages
        .iter()
        .map(|message| {
            let covered = &message[setup.skip..covered_end(message.len(), options)];
            let data = if setup.reflected { covered.iter().map(|b| b.reverse_bits()).collect() } else { covered.to_vec() };
            let stored = stored_value(message, options, setup.big_endian);
            let target = if setup.reflected { reflect(stored, setup.width) } else { stored };
            Prepared { data, target }
        })
        .collect()
}

/// Search one setup and record every verified solution.
fn search_setup(messages: &[&[u8]], options: &SolverOptions, setup: Setup, search: &mut Search) -> Result<(), SolveError> {
    let prepared = prepare(messages, options, setup);
    let candidates = match polynomial_constraint(&prepared, setup.width) {
        PolyConstraint::Inconsistent => return Ok(()),
        PolyConstraint::Exactly(poly) => vec![poly],
        PolyConstraint::DividesGcd(gcd) => enumerate_divisors(&gcd, setup.width, search)?,
        PolyConstraint::Unconstrained => enumerate_unconstrained(setup.width, search)?,
    };
    for (count, poly) in candidates.into_iter().enumerate() {
        if (count as u32).is_multiple_of(DEADLINE_CHECK_INTERVAL) {
            search.out_of_time()?;
        }
        search.polynomials_tried += 1;
        if let Some(solution) = solve_for_poly(messages, options, &prepared, setup, poly) {
            if search.found.len() >= MAX_SOLUTIONS * 2 {
                break;
            }
            search.found.insert((solution.params, solution.skip, solution.big_endian), solution);
        }
    }
    Ok(())
}

/// What the equal-length message pairs say about the polynomial.
enum PolyConstraint {
    /// Two identical covered ranges carry different CRCs: no CRC fits.
    Inconsistent,
    /// The pairs determine the polynomial.
    Exactly(u32),
    /// The polynomial (with its xʷ term) divides this GF(2) polynomial.
    DividesGcd(Gf2Poly),
    /// No usable equal-length pairs.
    Unconstrained,
}

fn polynomial_constraint(prepared: &[Prepared], width: u32) -> PolyConstraint {
    let mut gcd: Option<Gf2Poly> = None;
    for (a, b) in equal_length_pairs(prepared) {
        let difference: Vec<u8> = a.data.iter().zip(&b.data).map(|(x, y)| x ^ y).collect();
        let crc_difference = a.target ^ b.target;
        if difference.iter().all(|&byte| byte == 0) {
            if crc_difference != 0 {
                return PolyConstraint::Inconsistent;
            }
            continue;
        }
        let pair_poly = Gf2Poly::from_message_and_crc(&difference, crc_difference, width);
        let next = match gcd.take() {
            None => pair_poly,
            Some(previous) => previous.gcd(pair_poly),
        };
        match next.degree() {
            Some(degree) if degree < width as usize => return PolyConstraint::Inconsistent,
            Some(degree) if degree == width as usize => return PolyConstraint::Exactly(next.low_word() as u32 & width_mask(width)),
            _ => gcd = Some(next),
        }
    }
    match gcd {
        Some(gcd) => PolyConstraint::DividesGcd(gcd),
        None => PolyConstraint::Unconstrained,
    }
}

/// Pairs of messages with equal covered length, shortest lengths first.
fn equal_length_pairs(prepared: &[Prepared]) -> Vec<(&Prepared, &Prepared)> {
    let mut by_length: BTreeMap<usize, Vec<&Prepared>> = BTreeMap::new();
    for message in prepared {
        by_length.entry(message.data.len()).or_default().push(message);
    }
    let mut pairs = Vec::new();
    for group in by_length.values() {
        let Some((first, rest)) = group.split_first() else { continue };
        for other in rest {
            pairs.push((*first, *other));
            if pairs.len() >= MAX_PAIRS {
                return pairs;
            }
        }
    }
    pairs
}

/// Every generator of `width` bits that divides `gcd`: all polynomials for
/// 8 and 16 bits, the catalogue's for 32.
fn enumerate_divisors(gcd: &Gf2Poly, width: u32, search: &mut Search) -> Result<Vec<u32>, SolveError> {
    let mut found = Vec::new();
    for (count, poly) in candidate_polys(width).enumerate() {
        if (count as u32).is_multiple_of(DEADLINE_CHECK_INTERVAL) {
            search.out_of_time()?;
        }
        if gcd.divisible_by(poly, width) {
            found.push(poly);
        }
    }
    Ok(found)
}

fn enumerate_unconstrained(width: u32, search: &mut Search) -> Result<Vec<u32>, SolveError> {
    search.out_of_time()?;
    Ok(candidate_polys(width).collect())
}

/// Polynomials worth trying without other evidence: every odd one for 8 and
/// 16 bits (a generator without the constant term is degenerate), the
/// catalogue's for 32 bits.
fn candidate_polys(width: u32) -> Box<dyn Iterator<Item = u32>> {
    if width <= 16 {
        Box::new((1..=width_mask(width)).step_by(2))
    } else {
        let mut polys: Vec<u32> = CATALOGUE.iter().filter(|e| e.params.width == width).map(|e| e.params.poly).collect();
        polys.sort_unstable();
        polys.dedup();
        Box::new(polys.into_iter())
    }
}

/// Solve init and xorout for a polynomial and verify the result.
fn solve_for_poly(messages: &[&[u8]], options: &SolverOptions, prepared: &[Prepared], setup: Setup, poly: u32) -> Option<CrcSolution> {
    let mut system = LinearSystem::new(2 * setup.width);
    for message in prepared {
        add_message_equations(&mut system, message, poly, setup.width)?;
    }
    let ambiguous = system.rank() < 2 * setup.width;
    let (init, xorout) = if ambiguous {
        preferred_ambiguous_solution(&system, messages, options, setup, poly)?
    } else {
        split_unknowns(system.solve(), setup)
    };
    let params = CrcParams { width: setup.width, poly, init, refin: setup.reflected, refout: setup.reflected, xorout };
    if !verify(messages, options, setup, &params) {
        return None;
    }
    let named = closest_named(&params);
    Some(CrcSolution { params, skip: setup.skip, big_endian: setup.big_endian, named, init_ambiguous: ambiguous })
}

/// Add the `width` equations one message gives:
/// `plain_crc(data) ^ shift(init, len) ^ xorout' = target`, where xorout' is
/// xorout as seen in the register (reflected when `refout`).
/// Unknown bits 0..width are init, width..2·width are xorout'.
fn add_message_equations(system: &mut LinearSystem, message: &Prepared, poly: u32, width: u32) -> Option<()> {
    let columns = shift_columns(poly, width, message.data.len());
    let constant = plain_crc(&message.data, poly, width) ^ message.target;
    for bit in 0..width {
        let mut coefficients = 1u64 << (width + bit);
        for (unknown, column) in columns.iter().enumerate() {
            if column >> bit & 1 == 1 {
                coefficients |= 1u64 << unknown;
            }
        }
        let rhs = constant >> bit & 1 == 1;
        if !system.add(coefficients, rhs) {
            return None;
        }
    }
    Some(())
}

/// Columns of the linear map "advance the register through `len` zero
/// bytes": column k is the image of the register value with only bit k set.
fn shift_columns(poly: u32, width: u32, len: usize) -> Vec<u32> {
    // x^(8·len) mod P is the register "1" after len zero bytes.
    let mut power = 1u32;
    for _ in 0..len {
        power = feed_byte_bitwise(power, 0, poly, width);
    }
    let top_bit = 1u32 << (width - 1);
    let mut columns = Vec::with_capacity(width as usize);
    let mut column = power;
    for _ in 0..width {
        columns.push(column);
        column = if column & top_bit != 0 { (column << 1) ^ poly } else { column << 1 };
        column &= width_mask(width);
    }
    columns
}

/// Split the solved unknown vector into init and xorout.
fn split_unknowns(solution: u64, setup: Setup) -> (u32, u32) {
    let mask = width_mask(setup.width) as u64;
    let init = (solution & mask) as u32;
    let register_xorout = ((solution >> setup.width) & mask) as u32;
    let xorout = if setup.reflected { reflect(register_xorout, setup.width) } else { register_xorout };
    (init, xorout)
}

/// When init and xorout trade off, prefer a catalogue algorithm that fits,
/// then xorout = 0, then init = 0.
fn preferred_ambiguous_solution(
    system: &LinearSystem,
    messages: &[&[u8]],
    options: &SolverOptions,
    setup: Setup,
    poly: u32,
) -> Option<(u32, u32)> {
    let named = CATALOGUE.iter().find(|e| {
        e.params.width == setup.width && e.params.poly == poly && e.params.refin == setup.reflected && verify(messages, options, setup, &e.params)
    });
    if let Some(entry) = named {
        return Some((entry.params.init, entry.params.xorout));
    }
    let mut zero_xorout = system.clone();
    let xorout_zero_consistent = (0..setup.width).all(|bit| zero_xorout.add(1u64 << (setup.width + bit), false));
    if xorout_zero_consistent {
        return Some(split_unknowns(zero_xorout.solve(), setup));
    }
    Some(split_unknowns(system.solve(), setup))
}

/// Recompute every message's CRC with `params`.
fn verify(messages: &[&[u8]], options: &SolverOptions, setup: Setup, params: &CrcParams) -> bool {
    messages.iter().all(|message| {
        let covered = &message[setup.skip..covered_end(message.len(), options)];
        params.compute(covered) == stored_value(message, options, setup.big_endian)
    })
}

// ---------------------------------------------------------------------------
// Linear algebra over GF(2)
// ---------------------------------------------------------------------------

/// A system of linear equations over GF(2) in up to 64 unknowns, kept in
/// echelon form: each stored row's highest set bit is its pivot.
#[derive(Clone)]
struct LinearSystem {
    unknowns: u32,
    /// Row with its right-hand side, indexed by pivot bit.
    pivots: Vec<Option<(u64, bool)>>,
}

impl LinearSystem {
    fn new(unknowns: u32) -> Self {
        LinearSystem { unknowns, pivots: vec![None; unknowns as usize] }
    }

    /// Add an equation; false if it contradicts the ones already added.
    fn add(&mut self, mut coefficients: u64, mut rhs: bool) -> bool {
        while coefficients != 0 {
            let pivot = (u64::BITS - 1 - coefficients.leading_zeros()) as usize;
            match self.pivots[pivot] {
                Some((row, row_rhs)) => {
                    coefficients ^= row;
                    rhs ^= row_rhs;
                }
                None => {
                    self.pivots[pivot] = Some((coefficients, rhs));
                    return true;
                }
            }
        }
        !rhs
    }

    fn rank(&self) -> u32 {
        self.pivots.iter().filter(|p| p.is_some()).count() as u32
    }

    /// One solution, with free unknowns set to zero.
    fn solve(&self) -> u64 {
        let mut solution = 0u64;
        for bit in 0..self.unknowns as usize {
            if let Some((row, rhs)) = self.pivots[bit] {
                let others = row & !(1u64 << bit) & solution;
                let value = rhs ^ (others.count_ones() % 2 == 1);
                if value {
                    solution |= 1u64 << bit;
                }
            }
        }
        solution
    }
}

/// A polynomial over GF(2); bit i of the words is the coefficient of xⁱ.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Gf2Poly {
    words: Vec<u64>,
}

impl Gf2Poly {
    /// `D(x)·xʷ + C(x)`: the message bits (first bit highest) shifted up by
    /// the width, plus the CRC.
    fn from_message_and_crc(message: &[u8], crc: u32, width: u32) -> Self {
        let message_bits = message.len() * BYTE_BITS as usize;
        let total_bits = message_bits + width as usize;
        let mut poly = Gf2Poly { words: vec![0; total_bits.div_ceil(64)] };
        for (index, &byte) in message.iter().enumerate() {
            for bit in 0..BYTE_BITS as usize {
                if byte >> (7 - bit) & 1 == 1 {
                    let position_in_stream = index * BYTE_BITS as usize + bit;
                    poly.set_bit(message_bits - 1 - position_in_stream + width as usize);
                }
            }
        }
        poly.words[0] ^= crc as u64;
        poly
    }

    fn set_bit(&mut self, bit: usize) {
        self.words[bit / 64] |= 1u64 << (bit % 64);
    }

    fn bit(&self, bit: usize) -> bool {
        self.words.get(bit / 64).is_some_and(|w| w >> (bit % 64) & 1 == 1)
    }

    fn low_word(&self) -> u64 {
        self.words.first().copied().unwrap_or(0)
    }

    fn degree(&self) -> Option<usize> {
        let top = self.words.iter().rposition(|&w| w != 0)?;
        Some(top * 64 + (63 - self.words[top].leading_zeros() as usize))
    }

    /// self ^= other · x^shift
    fn xor_shifted(&mut self, other: &Gf2Poly, shift: usize) {
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        for (index, &word) in other.words.iter().enumerate() {
            let target = index + word_shift;
            if target < self.words.len() {
                self.words[target] ^= word << bit_shift;
            }
            if bit_shift != 0 && target + 1 < self.words.len() {
                self.words[target + 1] ^= word >> (64 - bit_shift);
            }
        }
    }

    /// The remainder of self divided by `divisor` (which must be non-zero).
    fn remainder(mut self, divisor: &Gf2Poly) -> Gf2Poly {
        let Some(divisor_degree) = divisor.degree() else { return self };
        while let Some(degree) = self.degree() {
            if degree < divisor_degree {
                break;
            }
            self.xor_shifted(divisor, degree - divisor_degree);
        }
        self
    }

    fn gcd(self, other: Gf2Poly) -> Gf2Poly {
        let (mut a, mut b) = (self, other);
        while b.degree().is_some() {
            let remainder = a.remainder(&b);
            a = b;
            b = remainder;
        }
        a
    }

    /// Whether `xʷ + poly` divides self, by long division bit by bit.
    fn divisible_by(&self, poly: u32, width: u32) -> bool {
        let Some(degree) = self.degree() else { return true };
        let generator = (1u64 << width) | poly as u64;
        let mut remainder = 0u64;
        for bit in (0..=degree).rev() {
            remainder = (remainder << 1) | u64::from(self.bit(bit));
            if remainder >> width & 1 == 1 {
                remainder ^= generator;
            }
        }
        remainder == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn catalogue(name: &str) -> CrcParams {
        CATALOGUE.iter().find(|e| e.name == name).expect("catalogue entry").params
    }

    /// Deterministic pseudo-random bytes (a linear congruential generator).
    fn pseudo_random_bytes(seed: u32, len: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (state >> 16) as u8
            })
            .collect()
    }

    /// Messages of `sync + payload + CRC`, the CRC over sync and payload.
    fn messages_with_trailer(params: &CrcParams, count: usize, lengths: &[usize], big_endian: bool, header: &[u8], skip: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                let len = lengths[index % lengths.len()];
                let mut message = header.to_vec();
                message.extend(pseudo_random_bytes(index as u32 + 7, len));
                let crc = params.compute(&message[skip..]);
                let bytes = (params.width / 8) as usize;
                let mut encoded: Vec<u8> = (0..bytes).map(|i| (crc >> (8 * i)) as u8).collect();
                if big_endian {
                    encoded.reverse();
                }
                message.extend(encoded);
                message
            })
            .collect()
    }

    fn as_slices(messages: &[Vec<u8>]) -> Vec<&[u8]> {
        messages.iter().map(Vec::as_slice).collect()
    }

    fn options(width: CrcWidth) -> SolverOptions {
        SolverOptions { width, ..SolverOptions::default() }
    }

    #[test]
    fn every_catalogue_entry_reproduces_its_published_check_value() {
        for entry in CATALOGUE {
            assert_eq!(entry.params.check(), entry.check, "{} check value", entry.name);
        }
    }

    #[test]
    fn existing_checksum_helpers_agree_with_the_catalogue() {
        let data = b"some message bytes";
        assert_eq!(catalogue("CRC-16/IBM-3740 (CCITT-FALSE)").compute(data), crate::checksums::crc16_ccitt(data) as u32);
        assert_eq!(catalogue("CRC-16/ARC").compute(data), crate::checksums::crc16_arc(data) as u32);
        assert_eq!(catalogue("CRC-32/ISO-HDLC").compute(data), crate::checksums::crc32(data));
    }

    #[test]
    fn names_modbus_from_twenty_messages_with_a_modbus_trailer() {
        let modbus = catalogue("CRC-16/MODBUS");
        let messages = messages_with_trailer(&modbus, 20, &[12, 12, 17, 9], false, &[], 0);
        let report = solve(&as_slices(&messages), &options(CrcWidth::W16)).expect("solves");
        let best = report.solutions.first().expect("a solution");
        assert_eq!(best.params, modbus);
        assert!(!best.big_endian);
        assert_eq!(best.skip, 0);
        assert_eq!(best.named.as_ref().map(|n| (n.name, n.exact)), Some(("CRC-16/MODBUS", true)));
    }

    #[test]
    fn finds_modbus_within_the_time_budget_when_no_two_messages_share_a_length() {
        let modbus = catalogue("CRC-16/MODBUS");
        let lengths: Vec<usize> = (6..18).collect();
        let messages = messages_with_trailer(&modbus, lengths.len(), &lengths, false, &[], 0);
        // The work is checked rather than the time, which a busy machine
        // stretches: at most the 32,768 odd 16-bit polynomials in each of the
        // 20 setups (skips 0 to 4, either byte order, reflected or not), a
        // search that fits the default budget on an idle machine.
        let generous = SolverOptions { time_budget: Duration::from_secs(120), ..options(CrcWidth::W16) };
        let report = solve(&as_slices(&messages), &generous).expect("solves");
        assert!(report.solutions.iter().any(|s| s.params == modbus));
        assert!(report.polynomials_tried <= 20 * 32_768, "{} polynomials tried", report.polynomials_tried);
    }

    #[test]
    fn names_ccitt_false_when_every_message_has_the_same_length() {
        let ccitt = catalogue("CRC-16/IBM-3740 (CCITT-FALSE)");
        let messages = messages_with_trailer(&ccitt, 8, &[20], true, &[], 0);
        let report = solve(&as_slices(&messages), &options(CrcWidth::W16)).expect("solves");
        let best = report.solutions.first().expect("a solution");
        assert_eq!(best.params, ccitt);
        assert!(best.big_endian);
        assert!(best.init_ambiguous, "same-length messages cannot separate init from xorout");
        assert!(report.notes.iter().any(|n| n.contains("cannot be told apart")));
    }

    #[test]
    fn finds_crc32_over_messages_with_a_sync_word_outside_the_crc() {
        let crc32 = catalogue("CRC-32/ISO-HDLC");
        let messages = messages_with_trailer(&crc32, 10, &[30, 41, 30, 52], false, &[0xA5, 0x5A], 2);
        let report = solve(&as_slices(&messages), &options(CrcWidth::W32)).expect("solves");
        let found = report.solutions.iter().find(|s| s.named.as_ref().is_some_and(|n| n.exact)).expect("named solution");
        assert_eq!(found.params, crc32);
        assert_eq!(found.skip, 2);
        assert_eq!(found.named.as_ref().map(|n| n.name), Some("CRC-32/ISO-HDLC"));
    }

    #[test]
    fn finds_crc32c_from_its_polynomial_algebraically() {
        let crc32c = catalogue("CRC-32/ISCSI (CRC-32C)");
        let messages = messages_with_trailer(&crc32c, 12, &[24, 24, 31], true, &[], 0);
        let report = solve(&as_slices(&messages), &options(CrcWidth::W32)).expect("solves");
        assert_eq!(report.solutions.first().map(|s| s.params), Some(crc32c));
    }

    #[test]
    fn finds_an_uncatalogued_32_bit_polynomial_from_equal_length_pairs() {
        let custom = CrcParams { width: 32, poly: 0x1234_5679, init: 0xDEAD_BEEF, refin: false, refout: false, xorout: 0x0F0F_0F0F };
        let messages = messages_with_trailer(&custom, 12, &[16, 16, 16, 23], true, &[], 0);
        let report = solve(&as_slices(&messages), &SolverOptions { order: StoredOrder::Big, max_skip: 0, ..options(CrcWidth::W32) }).expect("solves");
        let best = report.solutions.first().expect("a solution");
        assert_eq!(best.params, custom);
        assert!(best.named.is_none());
    }

    #[test]
    fn finds_maxim_8_bit_crc_and_names_it() {
        let maxim = catalogue("CRC-8/MAXIM-DOW");
        let messages = messages_with_trailer(&maxim, 16, &[7, 7, 7, 11], true, &[], 0);
        let report = solve(&as_slices(&messages), &options(CrcWidth::W8)).expect("solves");
        let best = report.solutions.first().expect("a solution");
        assert_eq!(best.named.as_ref().map(|n| n.name), Some("CRC-8/MAXIM-DOW"));
        assert_eq!(best.params, maxim);
    }

    #[test]
    fn finds_crc_stored_at_a_fixed_offset_before_a_trailer() {
        let xmodem = catalogue("CRC-16/XMODEM");
        let messages: Vec<Vec<u8>> = (0..10)
            .map(|index| {
                let mut message = pseudo_random_bytes(index, 10);
                let crc = xmodem.compute(&message);
                message.extend([(crc >> 8) as u8, crc as u8, 0x0D, 0x0A]);
                message
            })
            .collect();
        let solver_options = SolverOptions { position: CrcPosition::Offset(10), ..options(CrcWidth::W16) };
        let report = solve(&as_slices(&messages), &solver_options).expect("solves");
        assert!(report.solutions.iter().any(|s| s.params == xmodem && s.big_endian));
    }

    #[test]
    fn identifies_a_modified_init_as_close_to_the_named_algorithm() {
        let mut variant = catalogue("CRC-16/KERMIT");
        variant.init = 0x1234;
        let messages = messages_with_trailer(&variant, 12, &[10, 14, 10, 19], false, &[], 0);
        let report = solve(&as_slices(&messages), &SolverOptions { max_skip: 0, ..options(CrcWidth::W16) }).expect("solves");
        let best = report.solutions.iter().find(|s| s.params == variant).expect("variant found");
        let named = best.named.as_ref().expect("closest name");
        assert_eq!(named.name, "CRC-16/KERMIT");
        assert!(!named.exact);
        assert!(named.differences.contains("init"));
    }

    #[test]
    fn reports_nothing_for_messages_with_random_trailers() {
        let messages: Vec<Vec<u8>> = (0..12).map(|index| pseudo_random_bytes(index, 14)).collect();
        let report = solve(&as_slices(&messages), &options(CrcWidth::W16)).expect("runs");
        assert!(report.solutions.is_empty(), "found {:?}", report.solutions.first());
    }

    #[test]
    fn refuses_a_single_message() {
        let message = vec![1u8, 2, 3, 4];
        assert_eq!(solve(&[&message], &options(CrcWidth::W16)), Err(SolveError::TooFewMessages { found: 1 }));
    }

    #[test]
    fn refuses_messages_too_short_to_hold_the_crc() {
        let short = [1u8, 2];
        let long = [1u8, 2, 3, 4, 5, 6];
        let error = solve(&[&long, &short], &options(CrcWidth::W32)).expect_err("too short");
        assert!(matches!(error, SolveError::MessageTooShort { index: 1, .. }));
        assert!(error.to_string().contains("too short"));
    }

    #[test]
    fn gives_up_with_a_clear_message_when_out_of_time() {
        let messages: Vec<Vec<u8>> = (0..6).map(|index| pseudo_random_bytes(index, 10 + index as usize)).collect();
        let solver_options = SolverOptions { time_budget: Duration::ZERO, ..options(CrcWidth::W16) };
        let error = solve(&as_slices(&messages), &solver_options).expect_err("times out");
        assert!(error.to_string().contains("gave up"));
    }

    #[test]
    fn handles_empty_and_degenerate_input_without_panicking() {
        assert!(solve(&[], &options(CrcWidth::W8)).is_err());
        let zeros = vec![0u8; 8];
        let report = solve(&[&zeros, &zeros, &zeros], &options(CrcWidth::W8)).expect("runs");
        assert!(report.solutions.len() <= MAX_SOLUTIONS);
    }

    #[test]
    fn gf2_gcd_recovers_a_common_factor() {
        let generator = Gf2Poly { words: vec![0b1_0000_0111] }; // x⁸ + x² + x + 1
        let mut product_a = Gf2Poly { words: vec![0; 2] };
        product_a.xor_shifted(&generator, 0);
        product_a.xor_shifted(&generator, 3); // generator · (x³ + 1)
        let mut product_b = Gf2Poly { words: vec![0; 2] };
        product_b.xor_shifted(&generator, 1); // generator · x
        let gcd = product_a.gcd(product_b);
        assert_eq!(gcd.degree(), Some(8));
        assert_eq!(gcd.low_word(), 0b1_0000_0111);
    }
}
