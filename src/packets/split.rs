//! Splitting a byte range into frames by rule: a length field inside each
//! frame, or every occurrence of a byte pattern (with `??` wildcards, or
//! quoted text). Fixed-width records live in [`super::sources::split_fixed`].
//!
//! Each rule is a pure function returning a [`PacketSet`] whose offsets are
//! document offsets, and whose recipe finds the frames again after an edit.

use std::fmt;

use super::sources::{Recipe, SourceError};
use super::{LinkKind, MAX_PACKETS, Packet, PacketSet};
use crate::protocol::Framing;

/// Longest LEB128 encoding of a 64-bit value.
const MAX_LEB128_BYTES: usize = 10;
/// Bits of value each LEB128 byte carries, and the flag saying more follow.
const LEB128_VALUE_BITS: u32 = 7;
const LEB128_CONTINUES: u8 = 0x80;
/// Longest pattern accepted, in bytes.
pub const MAX_PATTERN_LEN: usize = 256;

// ---------------------------------------------------------------------------
// Length fields
// ---------------------------------------------------------------------------

/// How a frame's length field is stored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LengthEncoding {
    U8,
    #[default]
    U16,
    U32,
    /// Unsigned LEB128: seven bits per byte, low bits first, the top bit set
    /// on every byte but the last.
    Leb128,
}

impl LengthEncoding {
    pub const ALL: [LengthEncoding; 4] = [LengthEncoding::U8, LengthEncoding::U16, LengthEncoding::U32, LengthEncoding::Leb128];

    pub fn label(self) -> &'static str {
        match self {
            LengthEncoding::U8 => "u8",
            LengthEncoding::U16 => "u16",
            LengthEncoding::U32 => "u32",
            LengthEncoding::Leb128 => "LEB128",
        }
    }

    /// Bytes a fixed-width field takes, or `None` for LEB128.
    pub fn fixed_width(self) -> Option<usize> {
        match self {
            LengthEncoding::U8 => Some(1),
            LengthEncoding::U16 => Some(2),
            LengthEncoding::U32 => Some(4),
            LengthEncoding::Leb128 => None,
        }
    }

    /// Whether byte order matters for this encoding.
    pub fn has_byte_order(self) -> bool {
        matches!(self, LengthEncoding::U16 | LengthEncoding::U32)
    }
}

/// What the length field's value counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LengthCounts {
    /// The whole frame, from its first byte.
    WholeFrame,
    /// The bytes after the length field.
    #[default]
    AfterField,
    /// The payload after a header of `header_len` bytes.
    Payload { header_len: usize },
}

impl LengthCounts {
    pub fn label(self) -> &'static str {
        match self {
            LengthCounts::WholeFrame => "whole frame",
            LengthCounts::AfterField => "bytes after the field",
            LengthCounts::Payload { .. } => "payload after a header",
        }
    }
}

/// Where a length field sits in each frame and what it means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LengthField {
    /// Offset of the field from the start of each frame.
    pub offset: usize,
    pub encoding: LengthEncoding,
    pub big_endian: bool,
    pub counts: LengthCounts,
    /// Added to the counted length (negative to subtract), for fields that
    /// count a trailer too or leave out a checksum.
    pub adjustment: i64,
    /// Longest frame believed; a longer length ends the chain.
    pub max_frame: usize,
    /// Whether, and how, the chain finds its place again after a frame
    /// that does not fit.
    pub resync: Resync,
}

/// Longest frame believed by default.
pub const DEFAULT_MAX_FRAME: usize = 64 * 1024;
/// Longest sync word a length-field split resynchronises at.
pub const MAX_SYNC_LEN: usize = 8;
/// Frames looked at from the start to learn the sync word they share.
const SYNC_LEARNING_FRAMES: usize = 16;
/// Fewest times a learnt sync word must occur in the bytes to be believed.
const SYNC_LEARNING_AGREEMENT: usize = 3;

impl Default for LengthField {
    fn default() -> Self {
        LengthField { offset: 0, encoding: LengthEncoding::U16, big_endian: true, counts: LengthCounts::AfterField, adjustment: 0, max_frame: DEFAULT_MAX_FRAME, resync: Resync::Off }
    }
}

/// How a length-field split finds its place again when it loses it: at a
/// length that cannot be right, a frame that runs past the end, or (with a
/// sync word) a frame that does not start with the sync word.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Resync {
    /// Stop at the first frame that does not fit.
    #[default]
    Off,
    /// Resynchronise at the sync word the first frames share, in the bytes
    /// before the length field, or (when they share none) at the next
    /// place two plausible frames follow one another.
    Learn,
    /// Resynchronise at this sync word, which starts every frame.
    Sync(SyncWord),
}

/// A sync word of up to [`MAX_SYNC_LEN`] bytes, kept by value so a length
/// field stays `Copy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncWord {
    bytes: [u8; MAX_SYNC_LEN],
    len: u8,
}

impl SyncWord {
    /// A sync word of `bytes`, or `None` when it is empty or too long.
    pub fn new(bytes: &[u8]) -> Option<SyncWord> {
        if bytes.is_empty() || bytes.len() > MAX_SYNC_LEN {
            return None;
        }
        let mut word = SyncWord { bytes: [0; MAX_SYNC_LEN], len: bytes.len() as u8 };
        word.bytes[..bytes.len()].copy_from_slice(bytes);
        Some(word)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The bytes as spaced hex, such as "A5 5A".
    pub fn describe(&self) -> String {
        self.as_slice().iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(" ")
    }
}

impl LengthField {
    /// A short description, such as "u16 BE at +1 counting bytes after the field".
    pub fn describe(&self) -> String {
        let order = if self.encoding.has_byte_order() { if self.big_endian { " BE" } else { " LE" } } else { "" };
        let counts = match self.counts {
            LengthCounts::Payload { header_len } => format!("payload after a {header_len}-byte header"),
            other => other.label().to_string(),
        };
        let adjustment = match self.adjustment {
            0 => String::new(),
            more if more > 0 => format!(" + {more}"),
            less => format!(" - {}", less.unsigned_abs()),
        };
        format!("{}{order} at +{} counting {counts}{adjustment}", self.encoding.label(), self.offset)
    }

    /// The field's value and the number of bytes it takes, read from the
    /// start of `frame`, or `None` when the frame is too short to hold it
    /// (or a LEB128 value runs on too long).
    pub fn read(&self, frame: &[u8]) -> Option<(u64, usize)> {
        let field = frame.get(self.offset..)?;
        match self.encoding.fixed_width() {
            Some(width) => read_uint(field, width, self.big_endian).map(|value| (value, width)),
            None => read_leb128(field),
        }
    }

    /// The length of the frame starting at `frame[0]`.
    pub fn frame_length(&self, frame: &[u8]) -> Result<usize, FrameProblem> {
        let Some((value, field_len)) = self.read(frame) else { return Err(FrameProblem::FieldCutShort) };
        let field_end = self.offset + field_len;
        let counted_from = match self.counts {
            LengthCounts::WholeFrame => 0,
            LengthCounts::AfterField => field_end,
            LengthCounts::Payload { header_len } => header_len,
        };
        let length = counted_from as i128 + value as i128 + self.adjustment as i128;
        if length < field_end.max(1) as i128 || length > self.max_frame as i128 {
            return Err(FrameProblem::Implausible { length });
        }
        Ok(length as usize)
    }
}

/// Why a frame's length could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameProblem {
    /// The bytes end before the length field does.
    FieldCutShort,
    /// The length is shorter than the field itself, or longer than the
    /// longest frame believed.
    Implausible { length: i128 },
}

/// Read a `width`-byte unsigned integer from the start of `bytes`.
fn read_uint(bytes: &[u8], width: usize, big_endian: bool) -> Option<u64> {
    let slice = bytes.get(..width)?;
    let mut value = 0u64;
    for index in 0..width {
        let byte = if big_endian { slice[index] } else { slice[width - 1 - index] };
        value = (value << 8) | u64::from(byte);
    }
    Some(value)
}

/// Read an unsigned LEB128 value from the start of `bytes`, with the number
/// of bytes it took. `None` when the bytes end mid-value or it overflows.
pub fn read_leb128(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, &byte) in bytes.iter().take(MAX_LEB128_BYTES).enumerate() {
        let shift = index as u32 * LEB128_VALUE_BITS;
        let bits = u64::from(byte & !LEB128_CONTINUES);
        if shift >= u64::BITS || (bits << shift) >> shift != bits {
            return None;
        }
        value |= bits << shift;
        if byte & LEB128_CONTINUES == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

/// How a chain of length-prefixed frames came to an end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainEnd {
    /// Every byte belongs to a frame.
    DataEnded,
    /// Bytes are left over that are too few to hold a length field.
    FieldCutShort { offset: usize },
    /// A length was out of range.
    Implausible { offset: usize, length: i128 },
    /// A frame's length runs past the end of the data.
    RunsPastEnd { offset: usize, length: usize },
    /// The set reached [`MAX_PACKETS`].
    Capped,
}

impl fmt::Display for ChainEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainEnd::DataEnded => write!(f, "the frames cover every byte"),
            ChainEnd::FieldCutShort { offset } => write!(f, "stopped at {offset:#x}: too few bytes left for a length field"),
            ChainEnd::Implausible { offset, length } => write!(f, "stopped at {offset:#x}: a length of {length} is implausible"),
            ChainEnd::RunsPastEnd { offset, length } => write!(f, "stopped at {offset:#x}: a {length}-byte frame runs past the end"),
            ChainEnd::Capped => write!(f, "stopped at the packet cap"),
        }
    }
}

/// Follow a chain of frames through `bytes`, each giving its own length in
/// `field`. Returns `(offset, len)` within `bytes` for each frame, and how
/// the chain ended.
pub fn chain_frames(bytes: &[u8], field: &LengthField) -> (Vec<(usize, usize)>, ChainEnd) {
    let mut frames = Vec::new();
    let mut position = 0usize;
    while position < bytes.len() {
        if frames.len() >= MAX_PACKETS {
            return (frames, ChainEnd::Capped);
        }
        let length = match field.frame_length(&bytes[position..]) {
            Ok(length) => length,
            Err(FrameProblem::FieldCutShort) => return (frames, ChainEnd::FieldCutShort { offset: position }),
            Err(FrameProblem::Implausible { length }) => return (frames, ChainEnd::Implausible { offset: position, length }),
        };
        if length > bytes.len() - position {
            return (frames, ChainEnd::RunsPastEnd { offset: position, length });
        }
        frames.push((position, length));
        position += length;
    }
    (frames, ChainEnd::DataEnded)
}

/// A chain of frames followed with resynchronisation: the frames, how the
/// chain ended, and where it lost its place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResyncedChain {
    /// `(offset, len)` within the bytes of each frame.
    pub frames: Vec<(usize, usize)>,
    pub end: ChainEnd,
    /// `(offset, len)` of each stretch skipped to find the place again.
    pub lost: Vec<(usize, usize)>,
    /// Frames cut short because the next one's sync word came first.
    pub cut_short: usize,
    /// The sync word used, given or learnt.
    pub sync: Option<SyncWord>,
}

/// Follow a chain of frames as [`chain_frames`] does, but find the place
/// again after a frame that does not fit, as `field.resync` says, rather
/// than stopping there.
///
/// With a sync word, bytes that do not start with it are skipped to the
/// next one, and a frame whose length runs over the next frame's sync word
/// is cut short there (a frame cut off on the wire, say). Without one, a
/// length that cannot be right is skipped a byte at a time to the next
/// place where two plausible frames follow one another.
pub fn chain_frames_resyncing(bytes: &[u8], field: &LengthField) -> ResyncedChain {
    let sync = match field.resync {
        Resync::Off => return no_resync(bytes, field),
        Resync::Sync(word) => Some(word),
        Resync::Learn => learn_sync(bytes, field),
    };
    let mut chain = ResyncedChain { frames: Vec::new(), end: ChainEnd::DataEnded, lost: Vec::new(), cut_short: 0, sync };
    let sync = sync.as_ref().map(SyncWord::as_slice);
    let mut position = 0usize;
    while position < bytes.len() {
        if chain.frames.len() >= MAX_PACKETS {
            chain.end = ChainEnd::Capped;
            break;
        }
        if let Some(sync) = sync
            && !bytes[position..].starts_with(sync)
        {
            let next = find_bytes(bytes, sync, position + 1).unwrap_or(bytes.len());
            chain.lost.push((position, next - position));
            position = next;
            continue;
        }
        let length = match field.frame_length(&bytes[position..]) {
            Ok(length) if length <= bytes.len() - position => length,
            Err(FrameProblem::FieldCutShort) if sync.is_none() => {
                chain.end = ChainEnd::FieldCutShort { offset: position };
                break;
            }
            // Too few bytes left for the field after a sync word, a length
            // that cannot be right, or a frame that runs past the end.
            _ => {
                let next = match sync {
                    Some(sync) => find_bytes(bytes, sync, position + 1),
                    None => next_plausible_frame(bytes, field, position + 1),
                }
                .unwrap_or(bytes.len());
                chain.lost.push((position, next - position));
                position = next;
                continue;
            }
        };
        let mut length = length;
        let next = position + length;
        if let Some(sync) = sync
            && next < bytes.len()
            && !bytes[next..].starts_with(sync)
            && let Some(inner) = find_bytes(&bytes[..next], sync, position + sync.len())
        {
            length = inner - position;
            chain.cut_short += 1;
        }
        chain.frames.push((position, length));
        position += length;
    }
    chain
}

/// [`chain_frames`] as a [`ResyncedChain`] that never lost its place.
fn no_resync(bytes: &[u8], field: &LengthField) -> ResyncedChain {
    let (frames, end) = chain_frames(bytes, field);
    ResyncedChain { frames, end, lost: Vec::new(), cut_short: 0, sync: None }
}

/// The first place at or after `from` where `needle` occurs.
fn find_bytes(bytes: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= bytes.len() {
        return None;
    }
    bytes[from..].windows(needle.len()).position(|window| window == needle).map(|at| from + at)
}

/// The first place at or after `from` where a frame with a plausible length
/// fits, and either ends the bytes or is followed by another that does.
fn next_plausible_frame(bytes: &[u8], field: &LengthField, from: usize) -> Option<usize> {
    let fits = |at: usize| field.frame_length(bytes.get(at..)?).ok().filter(|&length| length <= bytes.len() - at);
    (from..bytes.len()).find(|&at| fits(at).is_some_and(|length| at + length == bytes.len() || fits(at + length).is_some()))
}

/// The sync word the first frames share before their length field: the
/// longest run of leading bytes (at most [`MAX_SYNC_LEN`], and at least two
/// unless the field is at offset 1) that the first two frames start with
/// and that occurs at least [`SYNC_LEARNING_AGREEMENT`] times in the bytes.
pub fn learn_sync(bytes: &[u8], field: &LengthField) -> Option<SyncWord> {
    let longest = field.offset.min(MAX_SYNC_LEN);
    if longest == 0 {
        return None;
    }
    let sample = &bytes[..bytes.len().min(field.max_frame.saturating_mul(SYNC_LEARNING_FRAMES))];
    let (frames, _) = chain_frames(sample, field);
    let starts: Vec<&[u8]> = frames.iter().take(SYNC_LEARNING_FRAMES).map(|&(offset, len)| &sample[offset..offset + len]).collect();
    let first = starts.first()?;
    let shortest = if longest == 1 { 1 } else { 2 };
    (shortest..=longest.min(first.len())).rev().find_map(|len| {
        let prefix = &first[..len];
        let shared = starts.iter().take_while(|start| start.starts_with(prefix)).count();
        (shared >= 2 && occurrences(bytes, prefix) >= SYNC_LEARNING_AGREEMENT).then(|| SyncWord::new(prefix)).flatten()
    })
}

/// How many times `needle` occurs in `bytes`, without overlaps.
fn occurrences(bytes: &[u8], needle: &[u8]) -> usize {
    let mut count = 0;
    let mut from = 0;
    while let Some(at) = find_bytes(bytes, needle, from) {
        count += 1;
        from = at + needle.len();
    }
    count
}

/// `bytes` (at document offset `base`) cut into frames by a length field,
/// finding the place again as `field.resync` says.
pub fn split_by_length_field(bytes: &[u8], base: usize, field: &LengthField, link: LinkKind) -> Result<PacketSet, SourceError> {
    if bytes.is_empty() {
        return Err(SourceError::EmptyRange);
    }
    let chain = chain_frames_resyncing(bytes, field);
    if chain.frames.is_empty() {
        let at_document = shift_chain_end(chain.end, base);
        let lost = if chain.lost.is_empty() { String::new() } else { " (and no frame was found by resynchronising)".to_string() };
        return Err(SourceError::NoFrames { reason: format!("no frame could be read with a {}: {at_document}{lost}", field.describe()) });
    }
    let covered: usize = chain.frames.iter().map(|&(_, len)| len).sum();
    let mut description = format!("{} frames by a {}", chain.frames.len(), field.describe());
    if let Some(sync) = chain.sync {
        description.push_str(&format!(", resynchronising at {}", sync.describe()));
    } else if field.resync != Resync::Off {
        description.push_str(", resynchronising at plausible lengths");
    }
    description.push_str(&format!(" · {covered} of {} bytes", bytes.len()));
    if !chain.lost.is_empty() {
        let lost_bytes: usize = chain.lost.iter().map(|&(_, len)| len).sum();
        let shown: Vec<String> = chain.lost.iter().take(LOST_STRETCHES_SHOWN).map(|&(offset, len)| format!("{len} at {:#x}", base + offset)).collect();
        let more = if chain.lost.len() > LOST_STRETCHES_SHOWN { format!(" and {} more", chain.lost.len() - LOST_STRETCHES_SHOWN) } else { String::new() };
        description.push_str(&format!(" · lost its place {} times, skipping {lost_bytes} bytes ({}{more})", chain.lost.len(), shown.join(", ")));
    }
    if chain.cut_short > 0 {
        description.push_str(&format!(" · {} frames cut short by the next sync word", chain.cut_short));
    }
    match (chain.end, chain.lost.is_empty()) {
        (ChainEnd::DataEnded, false) => description.push_str(" · the frames and the stretches skipped cover every byte"),
        (end, _) => description.push_str(&format!(" · {}", shift_chain_end(end, base))),
    }
    if field.resync == Resync::Off
        && let Some(warning) = drift_warning(bytes, base, field, &chain.frames)
    {
        description.push_str(&format!(" · {warning}"));
    }
    let mut set = PacketSet::new(format!("length field at {base:#x}"), description);
    set.capped = chain.end == ChainEnd::Capped;
    set.recipe = Recipe::LengthField { start: base, len: bytes.len(), field: *field, link };
    for (index, (offset, len)) in chain.frames.into_iter().enumerate() {
        set.push(Packet::new(base + offset, len, link, format!("frame {index}")));
    }
    Ok(set)
}

/// Lost stretches named in a set's description.
const LOST_STRETCHES_SHOWN: usize = 3;

/// When the first frames share a sync word, some later frames do not
/// start with it, and it occurs in the bytes more often than frames start
/// with it, the chain has probably lost its place: say where, and how to
/// find it again.
fn drift_warning(bytes: &[u8], base: usize, field: &LengthField, frames: &[(usize, usize)]) -> Option<String> {
    let sync = learn_sync(bytes, field)?;
    let word = sync.as_slice();
    let strays: Vec<usize> = frames.iter().enumerate().filter(|&(_, &(offset, _))| !bytes[offset..].starts_with(word)).map(|(index, _)| index).collect();
    let &first = strays.first()?;
    let starting = frames.len() - strays.len();
    let found = occurrences(bytes, word);
    if found <= starting {
        return None;
    }
    Some(format!(
        "{} occurs {found} times but starts only {starting} frames; frame {first} at {:#x} is the first not to start with it, so the split has probably lost its place there: give resync to find it again",
        sync.describe(),
        base + frames[first].0
    ))
}

/// The same chain ending with its offset counted in the document.
fn shift_chain_end(end: ChainEnd, base: usize) -> ChainEnd {
    match end {
        ChainEnd::FieldCutShort { offset } => ChainEnd::FieldCutShort { offset: base + offset },
        ChainEnd::Implausible { offset, length } => ChainEnd::Implausible { offset: base + offset, length },
        ChainEnd::RunsPastEnd { offset, length } => ChainEnd::RunsPastEnd { offset: base + offset, length },
        other => other,
    }
}

/// A protocol framing's length prefix as a length field, or `None` when the
/// framing is not length-prefixed (or uses a width this rule cannot read).
/// An adjustment that equals the end of the field becomes "counts the bytes
/// after the field". A sync word before the length becomes the field's
/// resynchronisation.
pub fn length_field_from_framing(framing: &Framing) -> Option<LengthField> {
    let (offset, width, big_endian, adjustment, resync) = match framing {
        Framing::LengthPrefixed { offset, width, big_endian, adjustment } => (*offset, *width, *big_endian, *adjustment, Resync::Off),
        Framing::SyncLength { bytes, offset, width, big_endian, adjustment } => (*offset, *width, *big_endian, *adjustment, Resync::Sync(SyncWord::new(bytes)?)),
        _ => return None,
    };
    let encoding = match width {
        1 => LengthEncoding::U8,
        2 => LengthEncoding::U16,
        4 => LengthEncoding::U32,
        _ => return None,
    };
    let field_end = (offset + width) as i64;
    let (counts, adjustment) = if adjustment >= field_end { (LengthCounts::AfterField, adjustment - field_end) } else { (LengthCounts::WholeFrame, adjustment) };
    Some(LengthField { offset, encoding, big_endian, counts, adjustment, max_frame: DEFAULT_MAX_FRAME, resync })
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

/// Bytes to look for, where `None` matches any byte.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BytePattern {
    pub cells: Vec<Option<u8>>,
}

impl BytePattern {
    /// Read a pattern: hex bytes with `??` for any byte (`AA 55 ?? 01`,
    /// `0x0D0A`), or text in double quotes (`"GET "`).
    pub fn parse(text: &str) -> Result<BytePattern, String> {
        let trimmed = text.trim();
        if let Some(inner) = trimmed.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) {
            return BytePattern::from_cells(inner.bytes().map(Some).collect());
        }
        let without_prefix = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
        let digits: Vec<char> = without_prefix.chars().filter(|c| !c.is_whitespace()).collect();
        if let Some(bad) = digits.iter().find(|c| !c.is_ascii_hexdigit() && **c != '?') {
            return Err(format!("'{bad}' is not a hex digit or ?; give hex such as AA 55 ?? 01, or \"text\" in quotes"));
        }
        if !digits.len().is_multiple_of(2) {
            return Err("the pattern has an odd number of digits; each byte needs two (?? for any byte)".to_string());
        }
        let mut cells = Vec::with_capacity(digits.len() / 2);
        for pair in digits.as_chunks::<2>().0 {
            let cell = match pair {
                ['?', '?'] => None,
                [high, low] if *high != '?' && *low != '?' => Some(hex_value(*high) << 4 | hex_value(*low)),
                _ => return Err("a wildcard must cover a whole byte: write ??".to_string()),
            };
            cells.push(cell);
        }
        BytePattern::from_cells(cells)
    }

    fn from_cells(cells: Vec<Option<u8>>) -> Result<BytePattern, String> {
        if cells.is_empty() {
            return Err("the pattern is empty".to_string());
        }
        if cells.len() > MAX_PATTERN_LEN {
            return Err(format!("the pattern is longer than {MAX_PATTERN_LEN} bytes"));
        }
        if cells.iter().all(Option::is_none) {
            return Err("the pattern needs at least one byte that is not ??".to_string());
        }
        Ok(BytePattern { cells })
    }

    pub fn len(&self) -> usize {
        self.cells.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// The pattern as hex, with `??` for wildcards.
    pub fn describe(&self) -> String {
        self.cells.iter().map(|cell| cell.map_or_else(|| "??".to_string(), |byte| format!("{byte:02X}"))).collect::<Vec<_>>().join(" ")
    }

    /// Whether the pattern matches `bytes` at `at`.
    pub fn matches_at(&self, bytes: &[u8], at: usize) -> bool {
        let Some(window) = at.checked_add(self.cells.len()).and_then(|end| bytes.get(at..end)) else { return false };
        window.iter().zip(&self.cells).all(|(byte, cell)| cell.is_none_or(|wanted| wanted == *byte))
    }

    /// The first match at or after `from`.
    pub fn find_from(&self, bytes: &[u8], from: usize) -> Option<usize> {
        let (anchor, anchor_byte) = self.cells.iter().enumerate().find_map(|(index, cell)| cell.map(|byte| (index, byte)))?;
        let last_start = bytes.len().checked_sub(self.cells.len())?;
        let mut at = from;
        while at <= last_start {
            let next = bytes[at + anchor..=last_start + anchor].iter().position(|&byte| byte == anchor_byte)?;
            let candidate = at + next;
            if self.matches_at(bytes, candidate) {
                return Some(candidate);
            }
            at = candidate + 1;
        }
        None
    }

    /// Every match, without overlaps, at most `limit` of them.
    pub fn find_all(&self, bytes: &[u8], limit: usize) -> Vec<usize> {
        let mut hits = Vec::new();
        let mut from = 0;
        while hits.len() < limit
            && let Some(at) = self.find_from(bytes, from)
        {
            hits.push(at);
            from = at + self.cells.len();
        }
        hits
    }
}

fn hex_value(digit: char) -> u8 {
    digit.to_digit(16).unwrap_or(0) as u8
}

/// Where a pattern goes relative to the frames it splits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PatternMode {
    /// A sync word: each frame starts with the pattern.
    #[default]
    StartsFrame,
    /// A terminator: each frame ends with the pattern (such as `0D 0A`).
    EndsFrame,
    /// A separator between frames, kept in neither.
    Separates,
}

impl PatternMode {
    pub const ALL: [PatternMode; 3] = [PatternMode::StartsFrame, PatternMode::EndsFrame, PatternMode::Separates];

    pub fn label(self) -> &'static str {
        match self {
            PatternMode::StartsFrame => "starts each frame (sync word)",
            PatternMode::EndsFrame => "ends each frame (terminator)",
            PatternMode::Separates => "sits between frames (dropped)",
        }
    }
}

/// `bytes` (at document offset `base`) cut at every match of `pattern`.
/// Bytes before the first sync word, or after the last terminator, form a
/// frame of their own; empty frames are skipped.
pub fn split_by_pattern(bytes: &[u8], base: usize, pattern: &BytePattern, mode: PatternMode, link: LinkKind) -> Result<PacketSet, SourceError> {
    if bytes.is_empty() {
        return Err(SourceError::EmptyRange);
    }
    if pattern.is_empty() {
        return Err(SourceError::EmptyDelimiter);
    }
    let hits = pattern.find_all(bytes, MAX_PACKETS + 1);
    let shown = pattern.describe();
    if hits.is_empty() {
        return Err(SourceError::DelimiterNotFound { delimiter: shown });
    }
    let pieces = pattern_pieces(&hits, pattern.len(), bytes.len(), mode);
    let mut set = PacketSet::new(format!("split at {shown}"), format!("{} matches of {shown}, which {}", hits.len(), mode.label()));
    set.recipe = Recipe::Pattern { start: base, len: bytes.len(), pattern: pattern.clone(), mode, link };
    for (index, (start, end)) in pieces.into_iter().enumerate() {
        if !set.push(Packet::new(base + start, end - start, link, format!("frame {index}"))) {
            break;
        }
    }
    Ok(set)
}

/// The non-empty `(start, end)` pieces that the matches at `hits` cut
/// `total` bytes into.
pub fn pattern_pieces(hits: &[usize], pattern_len: usize, total: usize, mode: PatternMode) -> Vec<(usize, usize)> {
    let mut boundaries: Vec<(usize, usize)> = Vec::with_capacity(hits.len() + 1);
    let mut start = 0;
    for &hit in hits {
        let (end, next_start) = match mode {
            PatternMode::StartsFrame => (hit, hit),
            PatternMode::EndsFrame => (hit + pattern_len, hit + pattern_len),
            PatternMode::Separates => (hit, hit + pattern_len),
        };
        if end > start {
            boundaries.push((start, end.min(total)));
        }
        start = next_start;
    }
    if start < total {
        boundaries.push((start, total));
    }
    boundaries
}

// ---------------------------------------------------------------------------
// Summaries
// ---------------------------------------------------------------------------

/// The number of frames in a set and the spread of their lengths.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FrameLengths {
    pub count: usize,
    pub min: usize,
    pub mean: f64,
    pub max: usize,
}

impl fmt::Display for FrameLengths {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} frames · length min {} / mean {:.1} / max {}", self.count, self.min, self.mean, self.max)
    }
}

/// Count and length spread of a set's packets, or `None` when it is empty.
pub fn frame_lengths(set: &PacketSet) -> Option<FrameLengths> {
    let lengths = set.packets.iter().map(|packet| packet.len);
    let min = lengths.clone().min()?;
    let max = lengths.clone().max()?;
    let total: u128 = lengths.map(|len| len as u128).sum();
    Some(FrameLengths { count: set.len(), min, mean: total as f64 / set.len() as f64, max })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(set: &PacketSet) -> Vec<(usize, usize)> {
        set.packets.iter().map(|packet| (packet.offset, packet.len)).collect()
    }

    /// Frames of a sync byte, a u16 BE payload length and the payload.
    fn u16_be_payload_stream(payloads: &[&[u8]]) -> Vec<u8> {
        let mut stream = Vec::new();
        for payload in payloads {
            stream.push(0xAA);
            stream.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            stream.extend_from_slice(payload);
        }
        stream
    }

    #[test]
    fn a_u16_big_endian_length_counting_the_payload_splits_frames_of_any_size() {
        let stream = u16_be_payload_stream(&[b"abc", b"", b"0123456789"]);
        let field = LengthField { offset: 1, ..LengthField::default() };
        let set = split_by_length_field(&stream, 0x100, &field, LinkKind::Unknown).expect("frames");
        assert_eq!(ranges(&set), vec![(0x100, 6), (0x106, 3), (0x109, 13)]);
        assert!(set.description.contains("cover every byte"), "{}", set.description);
        assert_eq!(set.recipe, Recipe::LengthField { start: 0x100, len: stream.len(), field, link: LinkKind::Unknown });
    }

    #[test]
    fn a_u8_length_counting_the_whole_frame_includes_the_header() {
        let stream = [3u8, 1, 2, 2, 9, 4, 0, 0, 0];
        let field = LengthField { offset: 0, encoding: LengthEncoding::U8, counts: LengthCounts::WholeFrame, ..LengthField::default() };
        let set = split_by_length_field(&stream, 0, &field, LinkKind::Unknown).expect("frames");
        assert_eq!(ranges(&set), vec![(0, 3), (3, 2), (5, 4)]);
    }

    #[test]
    fn a_leb128_length_reads_multi_byte_values() {
        assert_eq!(read_leb128(&[0xE5, 0x8E, 0x26]), Some((624_485, 3)));
        assert_eq!(read_leb128(&[0x80]), None, "the value runs off the end");
        let mut stream = vec![0x81, 0x01];
        stream.extend(std::iter::repeat_n(7u8, 129));
        stream.extend_from_slice(&[0x02, 1, 2]);
        let field = LengthField { encoding: LengthEncoding::Leb128, ..LengthField::default() };
        let set = split_by_length_field(&stream, 0, &field, LinkKind::Unknown).expect("frames");
        assert_eq!(ranges(&set), vec![(0, 131), (131, 3)]);
    }

    #[test]
    fn a_payload_length_after_a_header_and_an_adjustment_are_added() {
        // Header of 4 bytes: type, flags, u16 LE payload length; then a 1-byte checksum not counted.
        let stream = [1u8, 0, 2, 0, b'h', b'i', 0xCC, 2, 0, 1, 0, b'x', 0xDD];
        let field = LengthField { offset: 2, big_endian: false, counts: LengthCounts::Payload { header_len: 4 }, adjustment: 1, ..LengthField::default() };
        let set = split_by_length_field(&stream, 0, &field, LinkKind::Unknown).expect("frames");
        assert_eq!(ranges(&set), vec![(0, 7), (7, 6)]);
    }

    #[test]
    fn an_implausible_or_overlong_length_stops_the_chain_cleanly() {
        let mut stream = u16_be_payload_stream(&[b"ok", b"fine"]);
        stream.extend_from_slice(&[0xAA, 0xFF, 0xFF, 1, 2]);
        let field = LengthField { offset: 1, max_frame: 1000, ..LengthField::default() };
        let set = split_by_length_field(&stream, 0, &field, LinkKind::Unknown).expect("the good frames");
        assert_eq!(set.len(), 2);
        assert!(set.description.contains("implausible"), "{}", set.description);

        let (frames, end) = chain_frames(&[0xAA, 0x00, 0x09, 1, 2], &field);
        assert!(frames.is_empty());
        assert_eq!(end, ChainEnd::RunsPastEnd { offset: 0, length: 12 });
        let whole = LengthField { counts: LengthCounts::WholeFrame, ..field };
        assert!(matches!(chain_frames(&[0xAA, 0, 1, 5], &whole).1, ChainEnd::Implausible { length: 1, .. }), "shorter than its own field");
        assert!(matches!(split_by_length_field(&[0xAA], 0, &field, LinkKind::Unknown), Err(SourceError::NoFrames { .. })));
        assert_eq!(split_by_length_field(&[], 0, &field, LinkKind::Unknown), Err(SourceError::EmptyRange));
    }

    /// Frames of A5 5A, a u8 length counting what follows it, a byte and a
    /// payload, with a stray zero byte after every `stray_every`th frame and
    /// the bytes `lead_in` first.
    fn sync_stream(frames: usize, stray_every: usize, lead_in: &[u8]) -> Vec<u8> {
        let mut stream = lead_in.to_vec();
        for index in 0..frames {
            let payload_len = 3 + index % 5;
            stream.extend([0xA5, 0x5A, (payload_len + 1) as u8, index as u8]);
            stream.extend(std::iter::repeat_n(0x11 * (index % 3) as u8 + 1, payload_len));
            if stray_every > 0 && index % stray_every == stray_every - 1 {
                stream.push(0x00);
            }
        }
        stream
    }

    fn sync_field(resync: Resync) -> LengthField {
        LengthField { offset: 2, encoding: LengthEncoding::U8, resync, ..LengthField::default() }
    }

    #[test]
    fn a_stray_byte_between_frames_loses_the_chain_unless_it_resynchronises() {
        let stream = sync_stream(60, 7, &[]);
        let lost = split_by_length_field(&stream, 0, &sync_field(Resync::Off), LinkKind::Unknown).expect("frames");
        assert!(lost.len() < 60, "without resync the chain reads the stray byte as a frame's start");
        assert!(lost.description.contains("lost its place") && lost.description.contains("A5 5A"), "and says so: {}", lost.description);

        let found = split_by_length_field(&stream, 0, &sync_field(Resync::Learn), LinkKind::Unknown).expect("frames");
        assert_eq!(found.len(), 60, "{}", found.description);
        assert!(found.packets.iter().all(|packet| stream[packet.offset..].starts_with(&[0xA5, 0x5A])));
        assert!(found.description.contains("resynchronising at A5 5A"), "{}", found.description);
        assert!(found.description.contains("lost its place 8 times, skipping 8 bytes (1 at 0x"), "the stretches skipped are said: {}", found.description);
        assert!(!found.description.contains("cover every byte ·") && found.description.contains("stretches skipped cover every byte"));
    }

    #[test]
    fn a_given_sync_word_skips_a_lead_in_and_cuts_a_frame_cut_short_on_the_wire() {
        let mut stream = sync_stream(10, 0, &[0x33, 0x01, 0xFF]);
        // Frame 4 is cut off after six bytes, and the next frame follows at once.
        let starts: Vec<usize> = (0..stream.len() - 1).filter(|&at| stream[at..].starts_with(&[0xA5, 0x5A])).collect();
        let cut_at = starts[4] + 6;
        stream.drain(cut_at..starts[5]);
        let field = sync_field(Resync::Sync(SyncWord::new(&[0xA5, 0x5A]).unwrap()));
        let set = split_by_length_field(&stream, 0x40, &field, LinkKind::Unknown).expect("frames");
        assert_eq!(set.len(), 10, "{}", set.description);
        assert_eq!((set.packets[0].offset, set.packets[4].len), (0x43, 6));
        assert!(set.description.contains("3 at 0x40") && set.description.contains("1 frames cut short"), "{}", set.description);
    }

    #[test]
    fn without_a_sync_word_an_implausible_length_is_skipped_to_the_next_plausible_frames() {
        let mut stream = u16_be_payload_stream(&[b"ok", b"fine"]);
        stream.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        stream.extend(u16_be_payload_stream(&[b"again", b"and more"]));
        let field = LengthField { offset: 1, max_frame: 1000, resync: Resync::Learn, ..LengthField::default() };
        let set = split_by_length_field(&stream, 0, &field, LinkKind::Unknown).expect("frames");
        assert_eq!(set.len(), 4, "{}", set.description);
        let plain = LengthField { offset: 0, encoding: LengthEncoding::U8, counts: LengthCounts::WholeFrame, max_frame: 10, resync: Resync::Learn, ..LengthField::default() };
        let set = split_by_length_field(&[3, 1, 2, 0xF0, 2, 9, 4, 0, 0, 0], 0, &plain, LinkKind::Unknown).expect("frames");
        assert_eq!(ranges(&set), vec![(0, 3), (4, 2), (6, 4)], "{}", set.description);
    }

    #[test]
    fn a_detected_length_prefix_becomes_a_length_field_counting_after_the_field() {
        let after = length_field_from_framing(&Framing::LengthPrefixed { offset: 1, width: 2, big_endian: true, adjustment: 3 }).expect("a field");
        assert_eq!((after.offset, after.encoding, after.counts, after.adjustment), (1, LengthEncoding::U16, LengthCounts::AfterField, 0));
        let whole = length_field_from_framing(&Framing::LengthPrefixed { offset: 0, width: 1, big_endian: true, adjustment: 0 }).expect("a field");
        assert_eq!((whole.counts, whole.adjustment), (LengthCounts::WholeFrame, 0));
        assert_eq!(length_field_from_framing(&Framing::FixedSize { len: 8 }), None);
        let synced = length_field_from_framing(&Framing::SyncLength { bytes: vec![0xA5, 0x5A], offset: 2, width: 1, big_endian: true, adjustment: 5 }).expect("a field");
        assert_eq!((synced.counts, synced.adjustment), (LengthCounts::AfterField, 2));
        assert_eq!(synced.resync, Resync::Sync(SyncWord::new(&[0xA5, 0x5A]).unwrap()), "the sync word comes along to find the place again");
    }

    #[test]
    fn auto_detection_finds_the_length_field_of_a_synthetic_stream() {
        let payloads: Vec<Vec<u8>> = (0..60u8).map(|index| (0..(index % 13 + 2)).map(|byte| byte.wrapping_mul(37).wrapping_add(index)).collect()).collect();
        let slices: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        let stream = u16_be_payload_stream(&slices);
        let candidates = crate::protocol::detect_framing(&stream, 8);
        let field = candidates.iter().find_map(|candidate| length_field_from_framing(&candidate.framing)).expect("a length-prefixed candidate");
        assert_eq!((field.offset, field.encoding, field.big_endian), (1, LengthEncoding::U16, true));
        let set = split_by_length_field(&stream, 0, &field, LinkKind::Unknown).expect("frames");
        assert_eq!(set.len(), 60);
    }

    #[test]
    fn patterns_parse_hex_wildcards_and_quoted_text() {
        assert_eq!(BytePattern::parse("AA 55 ?? 01").expect("pattern").cells, vec![Some(0xAA), Some(0x55), None, Some(0x01)]);
        assert_eq!(BytePattern::parse("0x0d0a").expect("pattern").cells, vec![Some(0x0D), Some(0x0A)]);
        assert_eq!(BytePattern::parse("\"GET \"").expect("pattern").describe(), "47 45 54 20");
        assert!(BytePattern::parse("?? ??").unwrap_err().contains("at least one"));
        assert!(BytePattern::parse("A?").unwrap_err().contains("whole byte"));
        assert!(BytePattern::parse("abc").unwrap_err().contains("odd"));
        assert!(BytePattern::parse("zz").is_err());
        assert!(BytePattern::parse("").is_err());
    }

    #[test]
    fn a_wildcard_pattern_matches_any_byte_in_its_place() {
        let pattern = BytePattern::parse("?? 55").expect("pattern");
        assert_eq!(pattern.find_all(b"\x01\x55\x02\x55\x55", 10), vec![0, 2]);
        assert_eq!(pattern.find_from(b"\x55", 0), None);
    }

    #[test]
    fn a_sync_word_starts_each_frame_and_a_terminator_ends_each_frame() {
        let bytes = b"xxAA?1AA?2";
        let sync = BytePattern::parse("\"AA\"").expect("pattern");
        let set = split_by_pattern(bytes, 0, &sync, PatternMode::StartsFrame, LinkKind::Unknown).expect("frames");
        assert_eq!(ranges(&set), vec![(0, 2), (2, 4), (6, 4)]);

        let lines = b"one\r\ntwo\r\n\r\nrest";
        let terminator = BytePattern::parse("0D 0A").expect("pattern");
        let set = split_by_pattern(lines, 10, &terminator, PatternMode::EndsFrame, LinkKind::Unknown).expect("frames");
        let texts: Vec<&[u8]> = set.packets.iter().map(|p| &lines[p.offset - 10..p.end() - 10]).collect();
        assert_eq!(texts, vec![&b"one\r\n"[..], b"two\r\n", b"\r\n", b"rest"]);

        let set = split_by_pattern(lines, 0, &terminator, PatternMode::Separates, LinkKind::Unknown).expect("frames");
        assert_eq!(set.len(), 3, "empty pieces between separators are skipped");
        assert!(matches!(split_by_pattern(lines, 0, &BytePattern::parse("FF").unwrap(), PatternMode::Separates, LinkKind::Unknown), Err(SourceError::DelimiterNotFound { .. })));
    }

    #[test]
    fn frame_lengths_summarise_count_min_mean_and_max() {
        let set = super::super::sources::split_fixed(0, 25, 10, LinkKind::Unknown).expect("records");
        let summary = frame_lengths(&set).expect("lengths");
        assert_eq!((summary.count, summary.min, summary.max), (3, 5, 10));
        assert!((summary.mean - 25.0 / 3.0).abs() < 1e-9);
        assert_eq!(frame_lengths(&PacketSet::new("", "")), None);
    }

    #[test]
    fn a_pattern_split_is_found_again_from_its_recipe() {
        let pattern = BytePattern::parse("7E").expect("pattern");
        let set = split_by_pattern(b"\x7Eab\x7Ec", 4, &pattern, PatternMode::StartsFrame, LinkKind::Unknown).expect("frames");
        let again = set.recipe.rebuild(b"\x7Ea\x7Ebc\x7E", 4).expect("frames");
        assert_eq!(ranges(&again), vec![(4, 2), (6, 3), (9, 1)]);
    }
}
