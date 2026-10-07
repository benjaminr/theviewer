//! Attacks on simple byte-level obfuscation beyond plain XOR.
//!
//! [`crate::xor`] recovers single-byte and repeating-key XOR. Malware and
//! firmware also use rolling XOR keys, XOR with the previous byte, ADD/SUB
//! with a constant or short key, bit rotation, and XOR combined with ADD.
//! Each family is searched exhaustively (the key spaces are tiny) and every
//! decode is scored by how plausible the result is as plaintext:
//!
//! * text: printable bytes with English-like letter frequencies;
//! * structure: binary formats are rich in zero bytes;
//! * entropy drop: a position-dependent cipher hides the plaintext's skewed
//!   byte distribution, and the right key brings it back;
//! * a known file signature at offset 0.
//!
//! Crib dragging slides a known plaintext (such as `PK\x03\x04`) across the
//! data under XOR. Where the crib really sits, the bytes revealed are the
//! keystream, and if they are part of a short repeating key the rest of the
//! data decodes plausibly with it.
//!
//! Every [`Transform`] describes the *decoding* step, applied to the bytes as
//! they are in the file, with position 0 at the start of the slice.

use crate::xor;

/// Most bytes decoded and scored per candidate; longer input is sampled from
/// its start.
pub const SAMPLE_BYTES: usize = 64 * 1024;
/// Bytes used for the first pass over large key spaces.
const PROBE_BYTES: usize = 512;
/// Most crib positions tried.
pub const MAX_CRIB_OFFSETS: usize = 16 * 1024;
/// Longest repeating key tried under a crib.
pub const MAX_CRIB_KEY_LEN: usize = 64;
/// Longest crib accepted.
pub const MAX_CRIB_LEN: usize = 256;
/// Repeating-key lengths (from the index of coincidence) tried per search.
const LENGTHS_TO_TRY: usize = 3;
/// Longest repeating ADD key tried.
const MAX_ADD_KEY_LEN: usize = 16;
/// Best candidates per family kept for full scoring.
const KEEP_PER_FAMILY: usize = 4;
/// Columns need at least this many bytes for a key byte to be solved.
const MIN_COLUMN_BYTES: usize = 8;
/// Key bytes not pinned by a crib are solved only from columns at least this
/// long; shorter columns let any key look plausible.
const MIN_FREE_COLUMN_BYTES: usize = 32;
/// Largest share any one character may add to the text score; even the
/// space is under 20% of English text.
const MAX_CHARACTER_SHARE: f64 = 0.2;
/// Zero fraction at which binary data counts as fully structured.
const FULL_STRUCTURE_ZEROS: f64 = 0.4;
/// Weight of the entropy drop and of a known signature in the score.
const ENTROPY_DROP_WEIGHT: f64 = 0.3;
const MAGIC_WEIGHT: f64 = 0.3;
/// A signature at offset 0 only counts when the rest of the decode is at
/// least this plausible (a crib can force any signature into place).
const MAGIC_MIN_CONTENT: f64 = 0.3;
/// A crib position is rejected when the key bytes it pins lose more than
/// this share of their columns' best plausibility: at the true position the
/// crib agrees with what the data says on its own.
const MAX_PINNED_LOSS: f64 = 0.2;
/// A candidate must beat the undecoded data's score by this much.
const MIN_IMPROVEMENT: f64 = 0.15;
/// And reach this score at all.
const MIN_SCORE: f64 = 0.45;
/// Characters in a candidate preview.
const PREVIEW_CHARS: usize = 64;
/// Crib positions past the start reported as key fragments because the
/// key bytes they reveal read as text.
const MAX_TEXT_FRAGMENTS: usize = 3;
/// Bytes compared when deciding two candidates decode identically.
const DEDUPLICATION_BYTES: usize = 4096;

/// Known plaintext offered as one-click cribs: label and bytes.
pub const PRESET_CRIBS: [(&str, &[u8]); 8] = [
    ("MZ", b"MZ"),
    ("ELF", b"\x7fELF"),
    ("ZIP", b"PK\x03\x04"),
    ("PDF", b"%PDF-"),
    ("PNG", b"\x89PNG\r\n\x1a\n"),
    ("XML", b"<?xml"),
    ("http", b"http"),
    ("JSON", b"{\""),
];

/// Signatures recognised at offset 0 of a decode, with their names.
const MAGICS: [(&[u8], &str); 10] = [
    (b"MZ", "PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"%PDF-", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"<?xml", "XML document"),
    (b"#!/", "script"),
    (b"\x1f\x8b\x08", "gzip stream"),
];

/// Which byte feeds into the next key byte when XORing with the previous byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Feedback {
    /// `out[i] = in[i] ^ in[i-1] ^ key`: undoes `c[i] = p[i] ^ c[i-1] ^ key`.
    Ciphertext,
    /// `out[i] = in[i] ^ out[i-1] ^ key`: undoes `c[i] = p[i] ^ p[i-1] ^ key`.
    Plaintext,
}

/// One decoding step. Positions count from the start of the decoded slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transform {
    /// `out[i] = in[i] ^ (start + i·step)`.
    RollingXor { start: u8, step: u8 },
    /// XOR with the previous byte (see [`Feedback`]) and a constant; the byte
    /// before position 0 is taken as zero.
    XorPrevious { feedback: Feedback, key: u8 },
    /// `out[i] = in[i] + key[i % len]` (wrapping): undoes SUB with the key, or
    /// ADD with its negation.
    Add { key: Vec<u8> },
    /// Rotate each byte left by `bits` (1 to 7).
    RotateLeft { bits: u32 },
    /// `out = (in ^ xor) + add`.
    XorThenAdd { xor: u8, add: u8 },
    /// `out = (in + add) ^ xor`.
    AddThenXor { add: u8, xor: u8 },
    /// `out[i] = in[i] ^ key[i % len]`.
    RepeatingXor { key: Vec<u8> },
}

impl Transform {
    /// Decode `bytes`. Applying the transform never fails; an empty key
    /// leaves the bytes unchanged.
    pub fn apply(&self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Transform::RollingXor { start, step } => bytes.iter().enumerate().map(|(i, &byte)| byte ^ rolling_key(*start, *step, i)).collect(),
            Transform::XorPrevious { feedback, key } => xor_previous(bytes, *feedback, *key),
            Transform::Add { key } => repeat_key(bytes, key, u8::wrapping_add),
            Transform::RotateLeft { bits } => bytes.iter().map(|byte| byte.rotate_left(*bits)).collect(),
            Transform::XorThenAdd { xor, add } => bytes.iter().map(|byte| (byte ^ xor).wrapping_add(*add)).collect(),
            Transform::AddThenXor { add, xor } => bytes.iter().map(|byte| byte.wrapping_add(*add) ^ xor).collect(),
            Transform::RepeatingXor { key } => repeat_key(bytes, key, |byte, key_byte| byte ^ key_byte),
        }
    }

    /// A short description, e.g. "rolling XOR: key 0x37 + 3·i".
    pub fn describe(&self) -> String {
        match self {
            Transform::RollingXor { start, step } => format!("rolling XOR: key {start:#04x} + {step}·i"),
            Transform::XorPrevious { feedback: Feedback::Ciphertext, key } => format!("XOR with previous input byte, then {key:#04x}"),
            Transform::XorPrevious { feedback: Feedback::Plaintext, key } => format!("XOR with previous output byte, then {key:#04x}"),
            Transform::Add { key } if key.len() == 1 => {
                format!("add {:#04x} (undoes subtract {:#04x}, or add {:#04x})", key[0], key[0], key[0].wrapping_neg())
            }
            Transform::Add { key } => format!("add repeating key {} ({} bytes)", hex(key), key.len()),
            Transform::RotateLeft { bits } => format!("rotate each byte left {bits} (= right {})", 8 - bits),
            Transform::XorThenAdd { xor, add } => format!("XOR {xor:#04x}, then add {add:#04x}"),
            Transform::AddThenXor { add, xor } => format!("add {add:#04x}, then XOR {xor:#04x}"),
            Transform::RepeatingXor { key } => format!("XOR with repeating key {} ({} bytes)", hex(key), key.len()),
        }
    }
}

/// A ranked decode.
#[derive(Clone, Debug, PartialEq)]
pub struct CipherCandidate {
    pub transform: Transform,
    /// Higher is better; see [`Plausibility::score`].
    pub score: f64,
    pub printable_fraction: f64,
    /// Bits per byte of the decoded sample.
    pub entropy: f32,
    /// A file signature the decode starts with.
    pub magic: Option<&'static str>,
    /// First decoded bytes, unprintable ones as '.'.
    pub preview: String,
    /// Why the candidate was proposed.
    pub reason: String,
}

/// How plausible decoded bytes are as plaintext.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Plausibility {
    /// English-text likeness, 0 to about 1.
    pub text: f64,
    /// Zero-rich binary structure, 0 to about 1.
    pub structure: f64,
    pub printable_fraction: f64,
    pub entropy: f32,
    /// Share of the input's entropy removed (0 to 1).
    pub entropy_drop: f64,
    pub magic: Option<&'static str>,
    /// `max(text, structure)` plus weighted entropy drop and a signature
    /// bonus (only when the content is plausible in its own right).
    pub score: f64,
}

/// What [`attack`] searches.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AttackOptions {
    /// Known plaintext to drag across the data, if any.
    pub crib: Option<Vec<u8>>,
    /// Most candidates returned.
    pub max_results: usize,
}

/// A crib position whose keystream decodes the data plausibly.
#[derive(Clone, Debug, PartialEq)]
pub struct CribHit {
    /// Where the crib sits in the data.
    pub offset: usize,
    /// The repeating XOR key, aligned so `key[0]` decodes byte 0.
    pub key: Vec<u8>,
    /// Mean per-byte plausibility of the decode (0 to 1).
    pub score: f64,
}

/// Run every attack on `bytes` and return the most plausible decodes, best
/// first. Only decodes clearly more plausible than the input are returned.
/// Bounded: at most [`SAMPLE_BYTES`] are examined.
pub fn attack(bytes: &[u8], options: &AttackOptions) -> Vec<CipherCandidate> {
    let sample = &bytes[..bytes.len().min(SAMPLE_BYTES)];
    if sample.is_empty() {
        return Vec::new();
    }
    let original_entropy = crate::analysis::shannon_entropy(sample);
    let baseline = plausibility(sample, original_entropy).score;

    let mut proposals: Vec<(Transform, String)> = Vec::new();
    proposals.extend(rolling_xor_proposals(sample));
    proposals.extend(xor_previous_proposals(sample));
    proposals.extend(substitution_proposals(sample));
    proposals.extend(repeating_add_proposals(sample));
    proposals.extend(magic_crib_proposals(sample));
    if let Some(crib) = options.crib.as_deref().filter(|crib| !crib.is_empty()) {
        proposals.extend(crib_proposals(sample, crib, MAX_CRIB_OFFSETS));
    }

    let mut candidates: Vec<(CipherCandidate, Vec<u8>)> = proposals
        .into_iter()
        .map(|(transform, reason)| {
            let decoded = transform.apply(sample);
            let rating = plausibility(&decoded, original_entropy);
            let candidate = CipherCandidate {
                score: rating.score,
                printable_fraction: rating.printable_fraction,
                entropy: rating.entropy,
                magic: rating.magic,
                preview: preview(&decoded),
                reason,
                transform,
            };
            (candidate, decoded)
        })
        .filter(|(candidate, _)| candidate.score >= MIN_SCORE && candidate.score >= baseline + MIN_IMPROVEMENT)
        .collect();
    candidates.sort_by(|a, b| b.0.score.total_cmp(&a.0.score));
    let mut kept: Vec<(CipherCandidate, Vec<u8>)> = Vec::new();
    for (candidate, decoded) in candidates {
        let prefix = &decoded[..decoded.len().min(DEDUPLICATION_BYTES)];
        if kept.iter().any(|(_, other)| &other[..other.len().min(DEDUPLICATION_BYTES)] == prefix) {
            continue;
        }
        kept.push((candidate, decoded));
        if kept.len() >= options.max_results.max(1) {
            break;
        }
    }
    kept.into_iter().map(|(candidate, _)| candidate).collect()
}

/// Score decoded bytes as plaintext. `original_entropy` is the entropy of the
/// bytes before decoding, for the entropy-drop term.
pub fn plausibility(decoded: &[u8], original_entropy: f32) -> Plausibility {
    let counts = byte_counts(decoded);
    let n = decoded.len().max(1) as f64;
    let text = text_score(&counts, n);
    let structure = structure_score(&counts, n);
    let printable = counts.iter().enumerate().filter(|&(value, _)| is_printable(value as u8)).map(|(_, &count)| count as f64).sum::<f64>();
    let entropy = crate::analysis::shannon_entropy(decoded);
    let entropy_drop = if original_entropy > 0.0 { ((original_entropy - entropy) / original_entropy).clamp(0.0, 1.0) as f64 } else { 0.0 };
    let content = text.max(structure);
    let magic = magic_at_start(decoded);
    let magic_bonus = if magic.is_some() && content >= MAGIC_MIN_CONTENT { MAGIC_WEIGHT } else { 0.0 };
    let score = content + ENTROPY_DROP_WEIGHT * entropy_drop + magic_bonus;
    Plausibility { text, structure, printable_fraction: printable / n, entropy, entropy_drop, magic, score }
}

/// Parse crib text: literal characters plus the escapes `\xHH`, `\n`, `\r`,
/// `\t`, `\0` and `\\`.
pub fn parse_crib(text: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            let mut buffer = [0u8; 4];
            bytes.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            continue;
        }
        match characters.next() {
            Some('x') => {
                let digits: String = characters.by_ref().take(2).collect();
                let value = u8::from_str_radix(&digits, 16).map_err(|_| format!("crib escape \\x{digits} needs two hex digits, as in \\x7f"))?;
                bytes.push(value);
            }
            Some('n') => bytes.push(b'\n'),
            Some('r') => bytes.push(b'\r'),
            Some('t') => bytes.push(b'\t'),
            Some('0') => bytes.push(0),
            Some('\\') => bytes.push(b'\\'),
            Some(other) => return Err(format!("unknown crib escape \\{other}; use \\xHH, \\n, \\r, \\t, \\0 or \\\\")),
            None => return Err("crib ends with a lone backslash".to_string()),
        }
    }
    if bytes.is_empty() {
        return Err("crib is empty".to_string());
    }
    if bytes.len() > MAX_CRIB_LEN {
        return Err(format!("crib is {} bytes; at most {MAX_CRIB_LEN} are allowed", bytes.len()));
    }
    Ok(bytes)
}

/// Crib text that [`parse_crib`] turns back into `bytes`.
pub fn crib_text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| match byte {
            b'\\' => "\\\\".to_string(),
            0x20..0x7F => (byte as char).to_string(),
            _ => format!("\\x{byte:02x}"),
        })
        .collect()
}

/// Slide `crib` across the first [`MAX_CRIB_OFFSETS`] positions of `bytes`
/// under XOR and return the positions whose keystream, as a repeating key,
/// decodes the data most plausibly, best first.
pub fn crib_drag(bytes: &[u8], crib: &[u8], top: usize) -> Vec<CribHit> {
    crib_drag_within(bytes, crib, MAX_CRIB_OFFSETS, top)
}

/// Key bytes a crib reveals where it sits: the data XOR the crib.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyFragment {
    /// Where the crib sits in the data.
    pub offset: usize,
    /// The key bytes under the crib: the key's first bytes when the crib
    /// sits at offset 0.
    pub keystream: Vec<u8>,
    /// What the fragment is and how to use it.
    pub reason: String,
}

/// The key bytes `crib` reveals at offset 0, and at up to
/// [`MAX_TEXT_FRAGMENTS`] other offsets where they read as text (keys are
/// often a serial number or a password). Crib dragging only proposes a
/// decode when a repeating key no longer than the crib, or one the data's
/// period suggests, makes the whole span plausible; a longer key leaves no
/// decode, but these fragments are still the start of the answer.
pub fn crib_key_fragments(bytes: &[u8], crib: &[u8]) -> Vec<KeyFragment> {
    let sample = &bytes[..bytes.len().min(SAMPLE_BYTES)];
    if crib.is_empty() || sample.len() < crib.len() {
        return Vec::new();
    }
    let keystream_at = |offset: usize| -> Vec<u8> { sample[offset..offset + crib.len()].iter().zip(crib).map(|(byte, plain)| byte ^ plain).collect() };
    let crib_label = crib_text(crib);
    let start = keystream_at(0);
    let mut fragments = vec![KeyFragment {
        offset: 0,
        reason: format!(
            "key prefix at offset 0: if the data starts with \"{crib_label}\", the key's first {} bytes are {}{}; a longer key goes on from there",
            crib.len(),
            hex(&start),
            quoted_if_text(&start)
        ),
        keystream: start,
    }];
    let last_offset = (sample.len() - crib.len()).min(MAX_CRIB_OFFSETS.saturating_sub(1));
    let text_offsets = (1..=last_offset).filter(|&offset| reads_as_key_text(&keystream_at(offset), crib)).take(MAX_TEXT_FRAGMENTS);
    fragments.extend(text_offsets.map(|offset| {
        let keystream = keystream_at(offset);
        KeyFragment {
            offset,
            reason: format!(
                "key bytes at offset {offset:#x}: \"{crib_label}\" there leaves {}{}, which reads as text; where they fall in the key depends on its length",
                hex(&keystream),
                quoted_if_text(&keystream)
            ),
            keystream,
        }
    }));
    fragments
}

/// Whether a keystream looks like part of a text key: printable, not one
/// repeated character, and not the crib itself (which is what zero bytes
/// under it give).
fn reads_as_key_text(keystream: &[u8], crib: &[u8]) -> bool {
    keystream.iter().all(|&byte| (0x20..0x7F).contains(&byte)) && keystream.iter().any(|&byte| byte != keystream[0]) && keystream != crib
}

/// ` ("text")` when every byte is printable, else nothing.
fn quoted_if_text(bytes: &[u8]) -> String {
    if bytes.iter().all(|&byte| (0x20..0x7F).contains(&byte)) { format!(" (\"{}\")", String::from_utf8_lossy(bytes)) } else { String::new() }
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

fn byte_counts(bytes: &[u8]) -> [u32; 256] {
    let mut counts = [0u32; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    counts
}

fn is_printable(byte: u8) -> bool {
    (0x20..0x7F).contains(&byte) || matches!(byte, b'\n' | b'\r' | b'\t')
}

/// How much one byte looks like English text (0 to 1).
fn text_weight(byte: u8) -> f64 {
    // English letters, most frequent first.
    const LETTER_ORDER: &[u8] = b"etaoinshrdlcumwfgypbvkjxqz";
    match byte {
        b' ' => 1.0,
        b'a'..=b'z' => {
            let rank = LETTER_ORDER.iter().position(|&letter| letter == byte).unwrap_or(LETTER_ORDER.len());
            0.95 - rank as f64 * 0.02
        }
        b'A'..=b'Z' => 0.45,
        b'0'..=b'9' | b'\n' | b'\r' | b'\t' => 0.3,
        0x21..=0x7E => 0.2,
        _ => 0.0,
    }
}

/// Weight of a zero byte when scoring byte by byte, as binary structure.
const ZERO_WEIGHT: f64 = 0.6;

/// Per-byte plausibility used where scores must add up column by column.
fn byte_weight(byte: u8) -> f64 {
    if byte == 0 { ZERO_WEIGHT } else { text_weight(byte) }
}

/// Text-likeness of byte counts, each character capped at an English-like share.
fn text_score(counts: &[u32; 256], n: f64) -> f64 {
    let cap = n * MAX_CHARACTER_SHARE;
    counts.iter().enumerate().map(|(value, &count)| text_weight(value as u8) * (count as f64).min(cap)).sum::<f64>() / n
}

/// Zero-richness of byte counts, as evidence of binary structure.
fn structure_score(counts: &[u32; 256], n: f64) -> f64 {
    let zeros = counts[0] as f64 / n;
    (zeros / FULL_STRUCTURE_ZEROS).min(1.0) * 0.85
}

/// The better of the text and structure scores.
fn content_score(counts: &[u32; 256], n: f64) -> f64 {
    text_score(counts, n).max(structure_score(counts, n))
}

fn magic_at_start(decoded: &[u8]) -> Option<&'static str> {
    MAGICS.iter().find(|(magic, _)| decoded.starts_with(magic)).map(|&(_, name)| name)
}

/// Counts after mapping every byte value through `map`.
fn mapped_counts(counts: &[u32; 256], map: impl Fn(u8) -> u8) -> [u32; 256] {
    let mut mapped = [0u32; 256];
    for (value, &count) in counts.iter().enumerate() {
        mapped[map(value as u8) as usize] += count;
    }
    mapped
}

fn preview(decoded: &[u8]) -> String {
    decoded.iter().take(PREVIEW_CHARS).map(|&byte| if (0x20..0x7F).contains(&byte) { byte as char } else { '.' }).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Keep the `keep` best-scoring items.
fn best_of<T>(mut scored: Vec<(f64, T)>, keep: usize) -> Vec<T> {
    scored.sort_by(|a, b| b.0.total_cmp(&a.0));
    scored.into_iter().take(keep).map(|(_, item)| item).collect()
}

// ---------------------------------------------------------------------------
// Transforms
// ---------------------------------------------------------------------------

fn rolling_key(start: u8, step: u8, position: usize) -> u8 {
    start.wrapping_add(step.wrapping_mul(position as u8))
}

fn xor_previous(bytes: &[u8], feedback: Feedback, key: u8) -> Vec<u8> {
    let mut previous = 0u8;
    bytes
        .iter()
        .map(|&byte| {
            let out = byte ^ previous ^ key;
            previous = match feedback {
                Feedback::Ciphertext => byte,
                Feedback::Plaintext => out,
            };
            out
        })
        .collect()
}

fn repeat_key(bytes: &[u8], key: &[u8], combine: impl Fn(u8, u8) -> u8) -> Vec<u8> {
    if key.is_empty() {
        return bytes.to_vec();
    }
    bytes.iter().enumerate().map(|(i, &byte)| combine(byte, key[i % key.len()])).collect()
}

/// The shortest key that repeats to give `key`.
fn minimal_period(key: &[u8]) -> Vec<u8> {
    (1..=key.len())
        .find(|&period| key.len().is_multiple_of(period) && key.iter().enumerate().all(|(i, &byte)| byte == key[i % period]))
        .map_or_else(|| key.to_vec(), |period| key[..period].to_vec())
}

// ---------------------------------------------------------------------------
// Families
// ---------------------------------------------------------------------------

/// Every (start, step) pair scored on a probe, step 0 (plain XOR) excluded.
fn rolling_xor_proposals(sample: &[u8]) -> Vec<(Transform, String)> {
    let probe = &sample[..sample.len().min(PROBE_BYTES)];
    let n = probe.len() as f64;
    let mut scored = Vec::new();
    for step in 1..=255u8 {
        for start in 0..=255u8 {
            let mut counts = [0u32; 256];
            for (i, &byte) in probe.iter().enumerate() {
                counts[(byte ^ rolling_key(start, step, i)) as usize] += 1;
            }
            scored.push((content_score(&counts, n), Transform::RollingXor { start, step }));
        }
    }
    best_of(scored, KEEP_PER_FAMILY).into_iter().map(|transform| (transform, "rolling XOR search".to_string())).collect()
}

fn xor_previous_proposals(sample: &[u8]) -> Vec<(Transform, String)> {
    let probe = &sample[..sample.len().min(PROBE_BYTES * 8)];
    let n = probe.len() as f64;
    let mut scored = Vec::new();
    for feedback in [Feedback::Ciphertext, Feedback::Plaintext] {
        for key in 0..=255u8 {
            let decoded = xor_previous(probe, feedback, key);
            scored.push((content_score(&byte_counts(&decoded), n), Transform::XorPrevious { feedback, key }));
        }
    }
    best_of(scored, KEEP_PER_FAMILY).into_iter().map(|transform| (transform, "XOR with previous byte search".to_string())).collect()
}

/// Byte-for-byte substitutions, scored from the byte histogram alone: ADD a
/// constant, rotation, and XOR combined with ADD. Combinations equivalent to
/// plain XOR (add 0 or 0x80) or plain ADD (XOR 0) are left out.
fn substitution_proposals(sample: &[u8]) -> Vec<(Transform, String)> {
    let counts = byte_counts(sample);
    let n = sample.len() as f64;
    let score = |transform: Transform| {
        let mapped = match &transform {
            Transform::Add { key } => mapped_counts(&counts, |byte| byte.wrapping_add(key[0])),
            Transform::RotateLeft { bits } => mapped_counts(&counts, |byte| byte.rotate_left(*bits)),
            Transform::XorThenAdd { xor, add } => mapped_counts(&counts, |byte| (byte ^ xor).wrapping_add(*add)),
            Transform::AddThenXor { add, xor } => mapped_counts(&counts, |byte| byte.wrapping_add(*add) ^ xor),
            _ => counts,
        };
        (content_score(&mapped, n), transform)
    };
    let adds: Vec<_> = (1..=255u8).map(|add| score(Transform::Add { key: vec![add] })).collect();
    let rotations: Vec<_> = (1..8u32).map(|bits| score(Transform::RotateLeft { bits })).collect();
    let mut combined = Vec::new();
    for xor in 1..=255u8 {
        for add in (1..=255u8).filter(|&add| add != 0x80) {
            combined.push(score(Transform::XorThenAdd { xor, add }));
            combined.push(score(Transform::AddThenXor { add, xor }));
        }
    }
    let mut proposals: Vec<(Transform, String)> = Vec::new();
    proposals.extend(best_of(adds, KEEP_PER_FAMILY).into_iter().map(|transform| (transform, "ADD/SUB constant search".to_string())));
    proposals.extend(best_of(rotations, KEEP_PER_FAMILY).into_iter().map(|transform| (transform, "bit rotation search".to_string())));
    proposals.extend(best_of(combined, KEEP_PER_FAMILY).into_iter().map(|transform| (transform, "XOR and ADD search".to_string())));
    proposals
}

/// ADD with a repeating key: key lengths from the index of coincidence
/// (which ADD leaves unchanged, like XOR), each column solved on its own.
fn repeating_add_proposals(sample: &[u8]) -> Vec<(Transform, String)> {
    xor::guess_key_lengths(sample, MAX_ADD_KEY_LEN)
        .into_iter()
        .map(|(len, _)| len)
        .filter(|&len| len >= 2 && sample.len() / len >= MIN_COLUMN_BYTES)
        .take(LENGTHS_TO_TRY)
        .map(|len| {
            let key: Vec<u8> = (0..len).map(|column| solve_add_column(sample, column, len)).collect();
            let key = minimal_period(&key);
            (Transform::Add { key }, format!("repeating ADD key, length {len} by index of coincidence"))
        })
        .filter(|(transform, _)| matches!(transform, Transform::Add { key } if key.len() > 1))
        .collect()
}

fn solve_add_column(sample: &[u8], column: usize, len: usize) -> u8 {
    let counts = byte_counts(&sample.iter().skip(column).step_by(len).copied().collect::<Vec<u8>>());
    let n = counts.iter().sum::<u32>().max(1) as f64;
    (0..=255u8)
        .map(|add| (content_score(&mapped_counts(&counts, |byte| byte.wrapping_add(add)), n), add))
        .max_by(|a, b| a.0.total_cmp(&b.0))
        .map_or(0, |(_, add)| add)
}

/// Known file signatures tried as cribs at offset 0 only.
fn magic_crib_proposals(sample: &[u8]) -> Vec<(Transform, String)> {
    MAGICS.iter().flat_map(|(magic, name)| crib_proposals_named(sample, magic, 1, &format!("{name} signature at offset 0"))).collect()
}

fn crib_proposals(sample: &[u8], crib: &[u8], max_offsets: usize) -> Vec<(Transform, String)> {
    crib_proposals_named(sample, crib, max_offsets, &format!("crib \"{}\"", crib_text(crib)))
}

fn crib_proposals_named(sample: &[u8], crib: &[u8], max_offsets: usize, label: &str) -> Vec<(Transform, String)> {
    crib_drag_within(sample, crib, max_offsets, KEEP_PER_FAMILY)
        .into_iter()
        .map(|hit| {
            let reason = format!("{label} at {:#x} gives a {}-byte key", hit.offset, hit.key.len());
            (Transform::RepeatingXor { key: hit.key }, reason)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Crib dragging
// ---------------------------------------------------------------------------

/// Per-column plausibility of every key byte for one key length.
struct ColumnTable {
    len: usize,
    /// `scores[column * 256 + key]`: summed byte weight of the column decoded with `key`.
    scores: Vec<f64>,
    /// Best key byte for each column, and its score.
    best: Vec<(u8, f64)>,
}

impl ColumnTable {
    fn build(sample: &[u8], len: usize, weights: &[f64; 256]) -> ColumnTable {
        let mut scores = vec![0.0; len * 256];
        for column in 0..len {
            let counts = byte_counts(&sample.iter().skip(column).step_by(len).copied().collect::<Vec<u8>>());
            let present: Vec<(usize, f64)> = counts.iter().enumerate().filter(|&(_, &count)| count > 0).map(|(value, &count)| (value, count as f64)).collect();
            for key in 0..256 {
                scores[column * 256 + key] = present.iter().map(|&(value, count)| count * weights[value ^ key]).sum();
            }
        }
        let best = (0..len)
            .map(|column| {
                let row = &scores[column * 256..(column + 1) * 256];
                let (key, &score) = row.iter().enumerate().max_by(|a, b| a.1.total_cmp(b.1)).unwrap_or((0, &0.0));
                (key as u8, score)
            })
            .collect();
        ColumnTable { len, scores, best }
    }

    fn score(&self, column: usize, key: u8) -> f64 {
        self.scores[column * 256 + key as usize]
    }

    /// Total plausibility with the crib's keystream pinning some columns and
    /// the best key byte in the others, and the resulting key; `None` if the
    /// keystream contradicts itself at this key length, or if the pinned key
    /// bytes are much worse than the best ones for their columns.
    fn evaluate(&self, keystream: &[u8], offset: usize) -> Option<(f64, Vec<u8>)> {
        let mut key: Vec<Option<u8>> = vec![None; self.len];
        for (j, &key_byte) in keystream.iter().enumerate() {
            let slot = &mut key[(offset + j) % self.len];
            match slot {
                Some(existing) if *existing != key_byte => return None,
                _ => *slot = Some(key_byte),
            }
        }
        let mut total = 0.0;
        let mut pinned_best = 0.0;
        let mut pinned_actual = 0.0;
        let mut resolved = Vec::with_capacity(self.len);
        for (column, pinned) in key.iter().enumerate() {
            let key_byte = pinned.unwrap_or(self.best[column].0);
            let score = self.score(column, key_byte);
            if pinned.is_some() {
                pinned_best += self.best[column].1;
                pinned_actual += score;
            }
            total += score;
            resolved.push(key_byte);
        }
        let pinned_loss = if pinned_best > 0.0 { 1.0 - pinned_actual / pinned_best } else { 1.0 };
        (pinned_loss <= MAX_PINNED_LOSS).then_some((total, resolved))
    }
}

/// Key lengths worth trying under a crib of `crib_len` bytes: every length
/// the crib pins down completely, plus the likeliest longer ones by index of
/// coincidence (longer free lengths would overfit).
fn crib_key_lengths(sample: &[u8], crib_len: usize) -> Vec<usize> {
    let longest_pinned = MAX_CRIB_KEY_LEN.min(sample.len() / MIN_COLUMN_BYTES);
    let longest_free = MAX_CRIB_KEY_LEN.min(sample.len() / MIN_FREE_COLUMN_BYTES);
    let mut lengths: Vec<usize> = (1..=crib_len.min(longest_pinned)).collect();
    for (len, _) in xor::guess_key_lengths(sample, longest_free).into_iter().take(LENGTHS_TO_TRY) {
        if !lengths.contains(&len) {
            lengths.push(len);
        }
    }
    lengths
}

fn crib_drag_within(bytes: &[u8], crib: &[u8], max_offsets: usize, top: usize) -> Vec<CribHit> {
    let sample = &bytes[..bytes.len().min(SAMPLE_BYTES)];
    if crib.is_empty() || crib.len() > MAX_CRIB_LEN || sample.len() < crib.len() {
        return Vec::new();
    }
    let weights: [f64; 256] = std::array::from_fn(|value| byte_weight(value as u8));
    let tables: Vec<ColumnTable> = crib_key_lengths(sample, crib.len()).into_iter().map(|len| ColumnTable::build(sample, len, &weights)).collect();
    let n = sample.len() as f64;
    let last_offset = (sample.len() - crib.len()).min(max_offsets.saturating_sub(1));
    let mut hits: Vec<CribHit> = Vec::new();
    for offset in 0..=last_offset {
        let keystream: Vec<u8> = sample[offset..offset + crib.len()].iter().zip(crib).map(|(byte, plain)| byte ^ plain).collect();
        let best = tables
            .iter()
            .filter_map(|table| table.evaluate(&keystream, offset))
            .max_by(|a, b| a.0.total_cmp(&b.0).then(b.1.len().cmp(&a.1.len())));
        if let Some((total, key)) = best {
            hits.push(CribHit { offset, key: minimal_period(&key), score: total / n });
        }
    }
    hits.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.offset.cmp(&b.offset)));
    let mut unique: Vec<CribHit> = Vec::new();
    for hit in hits {
        if unique.iter().any(|other| other.key == hit.key) {
            continue;
        }
        unique.push(hit);
        if unique.len() >= top {
            break;
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENGLISH: &str = "It was the best of times, it was the worst of times, it was the age of wisdom, \
        it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, \
        it was the season of Light, it was the season of Darkness, it was the spring of hope, it was \
        the winter of despair, we had everything before us, we had nothing before us, we were all going \
        direct to Heaven, we were all going direct the other way. In short, the period was so far like \
        the present period, that some of its noisiest authorities insisted on its being received, for \
        good or for evil, in the superlative degree of comparison only.";

    fn noise(len: usize, seed: u32) -> Vec<u8> {
        let mut state = seed.max(1);
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }

    fn options() -> AttackOptions {
        AttackOptions { crib: None, max_results: 10 }
    }

    /// The best candidate decodes `cipher` back to `plain`.
    fn assert_recovered(cipher: &[u8], plain: &[u8], options: &AttackOptions) {
        let candidates = attack(cipher, options);
        let best = candidates.first().expect("at least one candidate");
        assert_eq!(best.transform.apply(cipher), plain, "best was {} ({})", best.transform.describe(), best.reason);
    }

    #[test]
    fn rolling_xor_of_english_text_is_recovered() {
        let plain = ENGLISH.as_bytes();
        let cipher: Vec<u8> = plain.iter().enumerate().map(|(i, &byte)| byte ^ rolling_key(0x37, 3, i)).collect();
        assert_recovered(&cipher, plain, &options());
    }

    #[test]
    fn xor_with_previous_ciphertext_byte_is_undone() {
        let plain = ENGLISH.as_bytes();
        let mut previous = 0u8;
        let cipher: Vec<u8> = plain
            .iter()
            .map(|&byte| {
                previous = byte ^ previous ^ 0x5A;
                previous
            })
            .collect();
        assert_recovered(&cipher, plain, &options());
    }

    #[test]
    fn subtracting_a_constant_is_undone_by_adding_it() {
        let plain = ENGLISH.as_bytes();
        let cipher: Vec<u8> = plain.iter().map(|byte| byte.wrapping_sub(0x2C)).collect();
        assert_recovered(&cipher, plain, &options());
    }

    #[test]
    fn repeating_add_key_is_recovered() {
        let plain = ENGLISH.repeat(3);
        let key = [0x11u8, 0x9C, 0x42];
        let cipher: Vec<u8> = plain.bytes().enumerate().map(|(i, byte)| byte.wrapping_sub(key[i % 3])).collect();
        assert_recovered(&cipher, plain.as_bytes(), &options());
    }

    #[test]
    fn rotated_bytes_are_rotated_back() {
        let plain = ENGLISH.as_bytes();
        let cipher: Vec<u8> = plain.iter().map(|byte| byte.rotate_left(3)).collect();
        assert_recovered(&cipher, plain, &options());
    }

    #[test]
    fn combined_xor_and_add_is_undone() {
        let plain = ENGLISH.as_bytes();
        // Encoder: subtract 0x21, then XOR 0xA5; decoder: XOR 0xA5, then add 0x21.
        let cipher: Vec<u8> = plain.iter().map(|byte| byte.wrapping_sub(0x21) ^ 0xA5).collect();
        assert_recovered(&cipher, plain, &options());
    }

    #[test]
    fn zip_crib_reveals_a_five_byte_repeating_key() {
        let mut plain = b"PK\x03\x04\x14\x00\x00\x00\x08\x00".to_vec();
        plain.extend(ENGLISH.repeat(2).bytes());
        let key = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x42];
        let cipher = xor::apply(&plain, &key, 0);
        let hits = crib_drag(&cipher, b"PK\x03\x04", 5);
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[0].key, key);
        let candidates = attack(&cipher, &AttackOptions { crib: Some(b"PK\x03\x04".to_vec()), max_results: 10 });
        assert!(candidates.iter().any(|candidate| candidate.transform == Transform::RepeatingXor { key: key.to_vec() } && candidate.magic == Some("ZIP archive")));
    }

    #[test]
    fn crib_dragged_to_its_position_in_the_middle_reveals_the_key() {
        let plain = format!("{ENGLISH} See http://example.org for more. {ENGLISH}");
        let key = [0x13u8, 0x37, 0x99];
        let cipher = xor::apply(plain.as_bytes(), &key, 0);
        let hits = crib_drag(&cipher, b"http://", 3);
        assert_eq!(hits[0].offset, plain.find("http://").unwrap());
        assert_eq!(hits[0].key, key);
    }

    #[test]
    fn a_crib_shorter_than_the_key_still_gives_the_key_s_first_bytes() {
        let config = "[camera]\nmodel = NovaCam NC-500\nserial = NC500-8D51266C\nrtsp_port = 554\n[cloud]\n\
            admin_token = 3f9a0c2e71b84d65\nrecovery_flag = FLAG{8d51266c8ea1f897}\n";
        let serial = b"NC500-8D51266C";
        let cipher = xor::apply(config.as_bytes(), serial, 0);
        let decodes = attack(&cipher, &AttackOptions { crib: Some(b"[camera]".to_vec()), max_results: 10 });
        assert!(!decodes.iter().any(|candidate| candidate.transform == Transform::RepeatingXor { key: serial.to_vec() }), "too short to solve a 14-byte key");
        let fragments = crib_key_fragments(&cipher, b"[camera]");
        assert_eq!((fragments[0].offset, fragments[0].keystream.as_slice()), (0, b"NC500-8D".as_slice()));
        assert!(fragments[0].reason.starts_with("key prefix at offset 0") && fragments[0].reason.contains("\"NC500-8D\""), "{}", fragments[0].reason);
        assert!(fragments.iter().all(|fragment| fragment.offset == 0 || fragment.keystream.iter().all(u8::is_ascii_graphic)), "{fragments:?}");
    }

    #[test]
    fn key_fragments_need_the_crib_to_fit_and_skip_zeros_that_echo_the_crib() {
        assert!(crib_key_fragments(b"ab", b"abc").is_empty());
        let mut data = vec![0xEEu8; 8];
        data.extend([0u8; 16]);
        let fragments = crib_key_fragments(&data, b"[camera]");
        assert_eq!(fragments.len(), 1, "zeros under the crib give the crib back, not a key: {fragments:?}");
    }

    #[test]
    fn random_data_yields_no_confident_decode() {
        let data = noise(16 * 1024, 21);
        let candidates = attack(&data, &AttackOptions { crib: Some(b"MZ".to_vec()), max_results: 10 });
        assert!(candidates.is_empty(), "{:?}", candidates.iter().map(|c| c.transform.describe()).collect::<Vec<_>>());
    }

    #[test]
    fn plain_text_is_not_decoded_further() {
        assert!(attack(ENGLISH.as_bytes(), &options()).is_empty());
    }

    #[test]
    fn crib_escapes_are_parsed_and_round_trip() {
        assert_eq!(parse_crib("PK\\x03\\x04").unwrap(), b"PK\x03\x04");
        assert_eq!(parse_crib("a\\n\\\\b\\0").unwrap(), b"a\n\\b\0");
        assert!(parse_crib("\\xZZ").unwrap_err().contains("hex"));
        assert!(parse_crib("").is_err());
        assert!(parse_crib("bad\\").is_err());
        for (_, crib) in PRESET_CRIBS {
            assert_eq!(parse_crib(&crib_text(crib)).unwrap(), crib);
        }
    }

    #[test]
    fn transforms_never_panic_and_empty_input_gives_nothing() {
        assert!(attack(&[], &options()).is_empty());
        assert!(crib_drag(b"ab", b"abc", 3).is_empty());
        for transform in [
            Transform::RollingXor { start: 1, step: 255 },
            Transform::XorPrevious { feedback: Feedback::Plaintext, key: 9 },
            Transform::Add { key: vec![] },
            Transform::RepeatingXor { key: vec![] },
            Transform::RotateLeft { bits: 7 },
        ] {
            assert_eq!(transform.apply(&[]), Vec::<u8>::new());
            assert_eq!(transform.apply(&[1, 2, 3]).len(), 3);
        }
        let _ = attack(&noise(3, 1), &AttackOptions { crib: Some(vec![0; 300]), max_results: 0 });
    }
}
