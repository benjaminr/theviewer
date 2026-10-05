//! Line-code decoders: undo the encodings used on wires, radio links and
//! storage media so the payload underneath can be read.
//!
//! Each decoder reads a bit stream (from bytes, in either bit order, from a
//! bit offset) and returns the decoded bytes together with how many symbols
//! were invalid. Codes with redundancy (Manchester, 8b/10b, BCD) can then be
//! compared by error rate to pick the right decoder and alignment
//! automatically; codes without redundancy (NRZI, Gray) are decoded on
//! request only.

use crate::bits::{BitOrder, BitStream};

/// Most error positions kept per decode.
const MAX_REPORTED_POSITIONS: usize = 1000;
/// Most BCD timestamps reported.
const MAX_TIMESTAMPS: usize = 1000;
/// Fewest symbols needed before an error rate is meaningful.
const MIN_SYMBOLS_FOR_RANKING: usize = 8;
/// Error-rate penalty per step of code complexity when ranking. Simpler codes
/// can masquerade as richer ones (every Manchester stream is also valid
/// 8b/10b), so on a near tie the simpler explanation wins.
const COMPLEXITY_PENALTY: f64 = 0.005;

/// A line code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LineCode {
    /// IEEE 802.3: a 0 is high-then-low (`10`), a 1 is low-then-high (`01`).
    ManchesterIeee,
    /// G. E. Thomas: a 1 is high-then-low (`10`), a 0 is low-then-high (`01`).
    ManchesterThomas,
    /// Differential Manchester: always a mid-cell transition; a transition at
    /// the start of the cell encodes 0, none encodes 1.
    DifferentialManchester,
    /// NRZI (NRZ-M): a transition encodes 1, no transition encodes 0.
    Nrzi,
    /// IBM 8b/10b with running disparity.
    EightBTenB,
    /// Reflected binary Gray code, one value per byte.
    GrayByte,
    /// Reflected binary Gray code, one value per big-endian 16-bit word.
    GrayWord,
    /// Packed BCD: two decimal digits per byte.
    PackedBcd,
}

impl LineCode {
    pub const ALL: [LineCode; 8] = [
        LineCode::ManchesterIeee,
        LineCode::ManchesterThomas,
        LineCode::DifferentialManchester,
        LineCode::Nrzi,
        LineCode::EightBTenB,
        LineCode::GrayByte,
        LineCode::GrayWord,
        LineCode::PackedBcd,
    ];

    pub fn label(self) -> &'static str {
        match self {
            LineCode::ManchesterIeee => "Manchester (IEEE 802.3)",
            LineCode::ManchesterThomas => "Manchester (G. E. Thomas)",
            LineCode::DifferentialManchester => "Differential Manchester",
            LineCode::Nrzi => "NRZI",
            LineCode::EightBTenB => "8b/10b",
            LineCode::GrayByte => "Gray code (bytes)",
            LineCode::GrayWord => "Gray code (16-bit words)",
            LineCode::PackedBcd => "Packed BCD",
        }
    }

    /// Whether invalid symbols can be detected, so the error rate means something.
    pub fn checkable(self) -> bool {
        matches!(self, LineCode::ManchesterIeee | LineCode::ManchesterThomas | LineCode::DifferentialManchester | LineCode::EightBTenB | LineCode::PackedBcd)
    }

    /// Rank of the code from simplest to richest, used to break near ties.
    fn complexity(self) -> usize {
        match self {
            LineCode::Nrzi | LineCode::GrayByte | LineCode::GrayWord => 0,
            LineCode::ManchesterIeee => 0,
            LineCode::ManchesterThomas => 1,
            LineCode::DifferentialManchester => 2,
            LineCode::EightBTenB => 3,
            LineCode::PackedBcd => 4,
        }
    }

    /// Bits per input symbol; alignments 0..this are worth trying.
    pub fn symbol_bits(self) -> usize {
        match self {
            LineCode::ManchesterIeee | LineCode::ManchesterThomas | LineCode::DifferentialManchester => 2,
            LineCode::Nrzi => 1,
            LineCode::EightBTenB => 10,
            LineCode::GrayByte | LineCode::PackedBcd => 8,
            LineCode::GrayWord => 16,
        }
    }
}

/// The outcome of decoding with one line code at one bit offset.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodeResult {
    pub code: LineCode,
    pub order: BitOrder,
    pub bit_offset: usize,
    /// Decoded payload. For BCD, ASCII digits with `?` for invalid nibbles.
    pub bytes: Vec<u8>,
    /// Input symbols read.
    pub symbols: usize,
    /// Invalid symbols (and, for 8b/10b, disparity errors).
    pub errors: usize,
    /// Input bit positions (from the start of the data) of the first errors.
    pub error_positions: Vec<usize>,
    /// 8b/10b only: input bit positions of K28.5 comma symbols.
    pub commas: Vec<usize>,
    /// 8b/10b only: control (K) symbols seen, which are left out of `bytes`.
    pub control_symbols: usize,
}

impl DecodeResult {
    fn new(code: LineCode, order: BitOrder, bit_offset: usize) -> Self {
        DecodeResult { code, order, bit_offset, bytes: Vec::new(), symbols: 0, errors: 0, error_positions: Vec::new(), commas: Vec::new(), control_symbols: 0 }
    }

    /// Fraction of symbols that were invalid (0 for codes that cannot tell).
    pub fn error_rate(&self) -> f64 {
        if self.symbols == 0 { 1.0 } else { self.errors as f64 / self.symbols as f64 }
    }

    /// Error rate plus the complexity penalty: lower ranks first.
    fn ranking_cost(&self) -> f64 {
        self.error_rate() + self.code.complexity() as f64 * COMPLEXITY_PENALTY
    }

    fn record_error(&mut self, position: usize) {
        self.errors += 1;
        if self.error_positions.len() < MAX_REPORTED_POSITIONS {
            self.error_positions.push(position);
        }
    }
}

/// The bits of `bytes` from `bit_offset` on, one `bool` per bit.
pub fn unpack_bits(bytes: &[u8], order: BitOrder, bit_offset: usize) -> Vec<bool> {
    let stream = BitStream::from_bytes(bytes, order);
    (bit_offset.min(stream.len())..stream.len()).map(|index| stream.bit(index)).collect()
}

/// Pack bits into bytes, first bit into the most significant position. A
/// final partial byte is dropped.
pub fn pack_bits(bits: &[bool]) -> Vec<u8> {
    bits.as_chunks::<8>().0.iter().map(|chunk| chunk.iter().fold(0u8, |byte, &bit| (byte << 1) | u8::from(bit))).collect()
}

/// Decode `bytes` with `code`, reading bits in `order` from `bit_offset`.
pub fn decode(bytes: &[u8], order: BitOrder, bit_offset: usize, code: LineCode) -> DecodeResult {
    let bits = unpack_bits(bytes, order, bit_offset);
    let mut result = DecodeResult::new(code, order, bit_offset);
    match code {
        LineCode::ManchesterIeee => decode_manchester(&bits, false, &mut result),
        LineCode::ManchesterThomas => decode_manchester(&bits, true, &mut result),
        LineCode::DifferentialManchester => decode_differential_manchester(&bits, &mut result),
        LineCode::Nrzi => decode_nrzi(&bits, &mut result),
        LineCode::EightBTenB => decode_8b10b(&bits, &mut result),
        LineCode::GrayByte => decode_gray_bytes(&pack_bits(&bits), &mut result),
        LineCode::GrayWord => decode_gray_words(&pack_bits(&bits), &mut result),
        LineCode::PackedBcd => decode_packed_bcd(&pack_bits(&bits), &mut result),
    }
    result
}

/// Try every checkable code at every alignment within one symbol and rank
/// the results, lowest error rate first. Results with too few symbols are left out.
pub fn auto_detect(bytes: &[u8], order: BitOrder) -> Vec<DecodeResult> {
    let mut results: Vec<DecodeResult> = LineCode::ALL
        .iter()
        .filter(|code| code.checkable())
        .flat_map(|&code| (0..code.symbol_bits()).map(move |offset| decode(bytes, order, offset, code)))
        .filter(|result| result.symbols >= MIN_SYMBOLS_FOR_RANKING)
        .collect();
    results.sort_by(|a, b| a.ranking_cost().total_cmp(&b.ranking_cost()).then(b.symbols.cmp(&a.symbols)));
    results
}

/// The best checkable decode, if any decode has a usable number of symbols.
pub fn best_decode(bytes: &[u8], order: BitOrder) -> Option<DecodeResult> {
    auto_detect(bytes, order).into_iter().next()
}

// ---------------------------------------------------------------------------
// Manchester and friends
// ---------------------------------------------------------------------------

fn decode_manchester(bits: &[bool], thomas: bool, result: &mut DecodeResult) {
    let mut decoded = Vec::with_capacity(bits.len() / 2);
    for (index, &[first, second]) in bits.as_chunks::<2>().0.iter().enumerate() {
        result.symbols += 1;
        if first == second {
            result.record_error(result.bit_offset + index * 2);
        }
        // IEEE: 01 is a 1. Thomas: 10 is a 1.
        decoded.push(if thomas { first } else { second });
    }
    result.bytes = pack_bits(&decoded);
}

fn decode_differential_manchester(bits: &[bool], result: &mut DecodeResult) {
    let mut decoded = Vec::with_capacity(bits.len() / 2);
    // The line level before the first cell is unknown; assume the opposite
    // of its first half, which reads the first cell as a 0.
    let mut previous_level = !bits.first().copied().unwrap_or(false);
    for (index, &[first, second]) in bits.as_chunks::<2>().0.iter().enumerate() {
        result.symbols += 1;
        if first == second {
            result.record_error(result.bit_offset + index * 2);
        }
        decoded.push(first == previous_level);
        previous_level = second;
    }
    result.bytes = pack_bits(&decoded);
}

fn decode_nrzi(bits: &[bool], result: &mut DecodeResult) {
    let mut previous = false;
    let decoded: Vec<bool> = bits
        .iter()
        .map(|&level| {
            let transition = level != previous;
            previous = level;
            transition
        })
        .collect();
    result.symbols = bits.len();
    result.bytes = pack_bits(&decoded);
}

// ---------------------------------------------------------------------------
// Gray code and BCD
// ---------------------------------------------------------------------------

/// Convert a reflected binary Gray code value to binary.
pub fn gray_to_binary(gray: u16) -> u16 {
    let mut binary = gray;
    let mut shift = gray >> 1;
    while shift != 0 {
        binary ^= shift;
        shift >>= 1;
    }
    binary
}

fn decode_gray_bytes(bytes: &[u8], result: &mut DecodeResult) {
    result.symbols = bytes.len();
    result.bytes = bytes.iter().map(|&byte| gray_to_binary(u16::from(byte)) as u8).collect();
}

fn decode_gray_words(bytes: &[u8], result: &mut DecodeResult) {
    result.symbols = bytes.len() / 2;
    result.bytes = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .flat_map(|&pair| gray_to_binary(u16::from_be_bytes(pair)).to_be_bytes())
        .collect();
}

fn decode_packed_bcd(bytes: &[u8], result: &mut DecodeResult) {
    let mut digits = Vec::with_capacity(bytes.len() * 2);
    for (index, &byte) in bytes.iter().enumerate() {
        for nibble in [byte >> 4, byte & 0x0F] {
            result.symbols += 1;
            if nibble <= 9 {
                digits.push(b'0' + nibble);
            } else {
                digits.push(b'?');
                result.record_error(result.bit_offset + index * 8);
            }
        }
    }
    result.bytes = digits;
}

/// The value of one packed BCD byte, or `None` if either nibble is above 9.
pub fn bcd_value(byte: u8) -> Option<u8> {
    let (high, low) = (byte >> 4, byte & 0x0F);
    (high <= 9 && low <= 9).then_some(high * 10 + low)
}

/// A packed BCD date and time found in the data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BcdTimestamp {
    /// Byte offset of the first byte.
    pub offset: usize,
    /// "YYYY-MM-DD hh:mm:ss", the century guessed (00–69 → 20xx).
    pub text: String,
}

/// Find six-byte packed BCD timestamps laid out YY MM DD hh mm ss.
pub fn find_bcd_timestamps(bytes: &[u8]) -> Vec<BcdTimestamp> {
    const TIMESTAMP_BYTES: usize = 6;
    const CENTURY_PIVOT: u8 = 70;
    let mut found = Vec::new();
    let mut offset = 0;
    while offset + TIMESTAMP_BYTES <= bytes.len() && found.len() < MAX_TIMESTAMPS {
        let Some(fields) = bytes[offset..offset + TIMESTAMP_BYTES].iter().map(|&byte| bcd_value(byte)).collect::<Option<Vec<u8>>>() else {
            offset += 1;
            continue;
        };
        let [year, month, day, hour, minute, second] = [fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]];
        let plausible = (1..=12).contains(&month) && (1..=31).contains(&day) && hour <= 23 && minute <= 59 && second <= 59;
        if !plausible {
            offset += 1;
            continue;
        }
        let century = if year < CENTURY_PIVOT { 2000 } else { 1900 };
        let text = format!("{}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}", century + u32::from(year));
        found.push(BcdTimestamp { offset, text });
        offset += TIMESTAMP_BYTES;
    }
    found
}

// ---------------------------------------------------------------------------
// 8b/10b
// ---------------------------------------------------------------------------

/// 5b/6b codes (abcdei, `a` in the most significant bit) for EDCBA = 0..31,
/// as (running disparity negative, running disparity positive).
const FIVE_SIX: [(u8, u8); 32] = [
    (0b100111, 0b011000),
    (0b011101, 0b100010),
    (0b101101, 0b010010),
    (0b110001, 0b110001),
    (0b110101, 0b001010),
    (0b101001, 0b101001),
    (0b011001, 0b011001),
    (0b111000, 0b000111),
    (0b111001, 0b000110),
    (0b100101, 0b100101),
    (0b010101, 0b010101),
    (0b110100, 0b110100),
    (0b001101, 0b001101),
    (0b101100, 0b101100),
    (0b011100, 0b011100),
    (0b010111, 0b101000),
    (0b011011, 0b100100),
    (0b100011, 0b100011),
    (0b010011, 0b010011),
    (0b110010, 0b110010),
    (0b001011, 0b001011),
    (0b101010, 0b101010),
    (0b011010, 0b011010),
    (0b111010, 0b000101),
    (0b110011, 0b001100),
    (0b100110, 0b100110),
    (0b010110, 0b010110),
    (0b110110, 0b001001),
    (0b001110, 0b001110),
    (0b101110, 0b010001),
    (0b011110, 0b100001),
    (0b101011, 0b010100),
];
/// The 6b code of K.28, which differs from D.28.
const K28_SIX: (u8, u8) = (0b001111, 0b110000);
/// 3b/4b codes (fghj) for data symbols, HGF = 0..7 (7 is the primary form).
const THREE_FOUR_DATA: [(u8, u8); 8] = [
    (0b1011, 0b0100),
    (0b1001, 0b1001),
    (0b0101, 0b0101),
    (0b1100, 0b0011),
    (0b1101, 0b0010),
    (0b1010, 0b1010),
    (0b0110, 0b0110),
    (0b1110, 0b0001),
];
/// The alternate D.x.A7 code, used to avoid runs of five equal bits.
const THREE_FOUR_ALTERNATE_7: (u8, u8) = (0b0111, 0b1000);
/// 3b/4b codes for control symbols.
const THREE_FOUR_CONTROL: [(u8, u8); 8] = [
    (0b1011, 0b0100),
    (0b0110, 0b1001),
    (0b1010, 0b0101),
    (0b1100, 0b0011),
    (0b1101, 0b0010),
    (0b0101, 0b1010),
    (0b1001, 0b0110),
    (0b0111, 0b1000),
];
/// Control symbols that exist besides K.28.x: K.23.7, K.27.7, K.29.7, K.30.7.
const OTHER_CONTROL_SYMBOLS: [u8; 4] = [0xF7, 0xFB, 0xFD, 0xFE];
/// The comma symbol K.28.5 (byte value 0xBC).
pub const K28_5: u8 = 0xBC;
/// Bits in an 8b/10b symbol.
const SYMBOL_BITS: usize = 10;

/// Pick the code for the current running disparity.
fn by_disparity(codes: (u8, u8), positive: bool) -> u8 {
    if positive { codes.1 } else { codes.0 }
}

/// The running disparity after sending a sub-block: unbalanced sub-blocks flip it.
fn disparity_after(code: u8, bits: u32, positive: bool) -> bool {
    let ones = code.count_ones();
    if ones * 2 == bits { positive } else { ones * 2 > bits }
}

/// Encode one symbol with 8b/10b. Returns the 10-bit code (`a` in bit 9) and
/// the new running disparity, or `None` for a control value that does not exist.
pub fn encode_8b10b(value: u8, control: bool, positive: bool) -> Option<(u16, bool)> {
    let low = value & 0x1F;
    let high = value >> 5;
    if control && low != 28 && !OTHER_CONTROL_SYMBOLS.contains(&value) {
        return None;
    }
    let six_codes = if control && low == 28 { K28_SIX } else { FIVE_SIX[low as usize] };
    let six = by_disparity(six_codes, positive);
    let middle = disparity_after(six, 6, positive);
    let four_codes = if control {
        THREE_FOUR_CONTROL[high as usize]
    } else if high == 7 && uses_alternate_7(low, middle) {
        THREE_FOUR_ALTERNATE_7
    } else {
        THREE_FOUR_DATA[high as usize]
    };
    let four = by_disparity(four_codes, middle);
    let end = disparity_after(four, 4, middle);
    Some(((u16::from(six) << 4) | u16::from(four), end))
}

/// D.x.A7 replaces D.x.P7 where the primary form would make five equal bits in a row.
fn uses_alternate_7(low: u8, positive: bool) -> bool {
    if positive { matches!(low, 11 | 13 | 14) } else { matches!(low, 17 | 18 | 20) }
}

/// What a 10-bit code decodes to.
#[derive(Clone, Copy, Debug, Default)]
struct CodeEntry {
    value: u8,
    control: bool,
    /// Valid when the running disparity before it is negative.
    from_negative: bool,
    /// Valid when the running disparity before it is positive.
    from_positive: bool,
}

/// A table of all 1024 10-bit codes, built by encoding every symbol.
fn decode_table() -> Vec<Option<CodeEntry>> {
    let mut table: Vec<Option<CodeEntry>> = vec![None; 1 << SYMBOL_BITS];
    for control in [false, true] {
        for value in 0..=255u8 {
            for positive in [false, true] {
                let Some((code, _)) = encode_8b10b(value, control, positive) else { continue };
                let entry = table[code as usize].get_or_insert(CodeEntry { value, control, ..Default::default() });
                if positive {
                    entry.from_positive = true;
                } else {
                    entry.from_negative = true;
                }
            }
        }
    }
    table
}

fn decode_8b10b(bits: &[bool], result: &mut DecodeResult) {
    let table = decode_table();
    let mut positive = false;
    let mut first = true;
    for (index, chunk) in bits.as_chunks::<SYMBOL_BITS>().0.iter().enumerate() {
        result.symbols += 1;
        let position = result.bit_offset + index * SYMBOL_BITS;
        let code = chunk.iter().fold(0u16, |code, &bit| (code << 1) | u16::from(bit));
        let Some(entry) = table[code as usize] else {
            result.record_error(position);
            positive = resynchronised_disparity(code, positive);
            continue;
        };
        // The disparity before the first symbol is unknown, so accept either.
        let disparity_ok = first || if positive { entry.from_positive } else { entry.from_negative };
        if !disparity_ok {
            result.record_error(position);
        }
        first = false;
        positive = resynchronised_disparity(code, positive);
        if entry.control {
            result.control_symbols += 1;
            if entry.value == K28_5 {
                result.commas.push(position);
            }
        } else {
            result.bytes.push(entry.value);
        }
    }
}

/// The running disparity after a 10-bit code: more ones leaves it positive,
/// fewer leaves it negative, balanced leaves it unchanged.
fn resynchronised_disparity(code: u16, positive: bool) -> bool {
    match code.count_ones().cmp(&5) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => positive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits_of(bytes: &[u8]) -> Vec<bool> {
        unpack_bits(bytes, BitOrder::MsbFirst, 0)
    }

    fn manchester_ieee(bytes: &[u8]) -> Vec<u8> {
        let encoded: Vec<bool> = bits_of(bytes).iter().flat_map(|&bit| if bit { [false, true] } else { [true, false] }).collect();
        pack_bits(&encoded)
    }

    fn encode_stream_8b10b(symbols: &[(u8, bool)]) -> Vec<bool> {
        let mut positive = false;
        let mut bits = Vec::new();
        for &(value, control) in symbols {
            let (code, next) = encode_8b10b(value, control, positive).expect("valid symbol");
            positive = next;
            bits.extend((0..10).rev().map(|shift| (code >> shift) & 1 == 1));
        }
        bits
    }

    /// Pack bits, padding the final byte with zeros.
    fn pack_padded(bits: &[bool]) -> Vec<u8> {
        let mut padded = bits.to_vec();
        padded.resize(bits.len().div_ceil(8) * 8, false);
        pack_bits(&padded)
    }

    #[test]
    fn manchester_encoded_bytes_decode_back_without_errors() {
        let payload = b"Hello, line codes!".to_vec();
        let decoded = decode(&manchester_ieee(&payload), BitOrder::MsbFirst, 0, LineCode::ManchesterIeee);
        assert_eq!(decoded.bytes, payload);
        assert_eq!(decoded.errors, 0);
        let thomas = decode(&manchester_ieee(&payload), BitOrder::MsbFirst, 0, LineCode::ManchesterThomas);
        assert_eq!(thomas.bytes, payload.iter().map(|byte| !byte).collect::<Vec<u8>>(), "the other convention inverts every bit");
    }

    #[test]
    fn auto_detect_finds_manchester_and_its_alignment() {
        let payload: Vec<u8> = (0..200u32).map(|index| (index * 37 % 251) as u8).collect();
        let mut bits = vec![true];
        bits.extend(bits_of(&manchester_ieee(&payload)));
        let best = best_decode(&pack_padded(&bits), BitOrder::MsbFirst).expect("a decode");
        assert_eq!(best.code, LineCode::ManchesterIeee);
        assert_eq!(best.bit_offset, 1);
        assert!(best.errors <= 3, "only the zero padding after the payload is invalid");
        assert_eq!(&best.bytes[..payload.len()], &payload[..]);
    }

    #[test]
    fn differential_manchester_decodes_transitions() {
        // Encode 1,0,1,1,0 from level low: mid-cell transition always, a
        // start-of-cell transition for a 0.
        let message = [true, false, true, true, false, false, true, false];
        let mut level = false;
        let mut line = Vec::new();
        for &bit in &message {
            if !bit {
                level = !level;
            }
            line.push(level);
            level = !level;
            line.push(level);
        }
        let mut result = DecodeResult::new(LineCode::DifferentialManchester, BitOrder::MsbFirst, 0);
        decode_differential_manchester(&line, &mut result);
        assert_eq!(result.errors, 0);
        // The first cell's reference is unknown and reads as 0; the rest are exact.
        assert_eq!(result.bytes[0] & 0x7F, 0b0011_0010 & 0x7F);
    }

    #[test]
    fn nrzi_marks_transitions_as_ones() {
        // Levels 0 1 1 0 0 0 1 1 → transitions 0 1 0 1 0 0 1 0.
        let decoded = decode(&[0b0110_0011], BitOrder::MsbFirst, 0, LineCode::Nrzi);
        assert_eq!(decoded.bytes, vec![0b0101_0010]);
    }

    #[test]
    fn eight_b_ten_b_round_trips_data_symbols_and_finds_commas() {
        let mut symbols = vec![(K28_5, true)];
        symbols.extend((0..=255u8).map(|value| (value, false)));
        symbols.push((K28_5, true));
        let bits = encode_stream_8b10b(&symbols);
        let decoded = decode(&pack_padded(&bits), BitOrder::MsbFirst, 0, LineCode::EightBTenB);
        assert_eq!(decoded.errors, 0, "errors at {:?}", decoded.error_positions);
        assert_eq!(decoded.bytes, (0..=255u8).collect::<Vec<u8>>());
        assert_eq!(decoded.commas, vec![0, 257 * 10]);
    }

    #[test]
    fn known_8b10b_codes_match_the_standard() {
        // K.28.5 from negative disparity is 001111 1010; D.21.5 is 101010 1010.
        assert_eq!(encode_8b10b(K28_5, true, false).map(|(code, _)| code), Some(0b0011111010));
        assert_eq!(encode_8b10b(0xB5, false, false).map(|(code, _)| code), Some(0b1010101010));
        assert_eq!(encode_8b10b(0x00, true, false), None, "K.0.0 does not exist");
    }

    #[test]
    fn eight_b_ten_b_reports_invalid_symbols() {
        let mut bits = encode_stream_8b10b(&[(1, false), (2, false)]);
        bits.extend([false; 10]); // ten zeros is never a valid symbol
        let decoded = decode(&pack_padded(&bits), BitOrder::MsbFirst, 0, LineCode::EightBTenB);
        assert_eq!(decoded.errors, 1);
        assert_eq!(decoded.error_positions, vec![20]);
    }

    #[test]
    fn auto_detect_picks_8b10b_at_its_offset() {
        let symbols: Vec<(u8, bool)> = (0..400u32).map(|index| ((index * 73 % 256) as u8, false)).collect();
        let mut bits = vec![false, true, true];
        bits.extend(encode_stream_8b10b(&symbols));
        let best = best_decode(&pack_padded(&bits), BitOrder::MsbFirst).expect("a decode");
        assert_eq!((best.code, best.bit_offset), (LineCode::EightBTenB, 3));
    }

    #[test]
    fn gray_code_decodes_per_byte_and_per_word() {
        let values: Vec<u8> = (0..=255).collect();
        let gray: Vec<u8> = values.iter().map(|&v| v ^ (v >> 1)).collect();
        assert_eq!(decode(&gray, BitOrder::MsbFirst, 0, LineCode::GrayByte).bytes, values);
        let word: u16 = 0xBEEF;
        let gray_word = (word ^ (word >> 1)).to_be_bytes();
        assert_eq!(decode(&gray_word, BitOrder::MsbFirst, 0, LineCode::GrayWord).bytes, word.to_be_bytes().to_vec());
    }

    #[test]
    fn packed_bcd_gives_digits_and_flags_invalid_nibbles() {
        let decoded = decode(&[0x12, 0x34, 0x5A], BitOrder::MsbFirst, 0, LineCode::PackedBcd);
        assert_eq!(decoded.bytes, b"12345?".to_vec());
        assert_eq!(decoded.errors, 1);
        assert_eq!(bcd_value(0x99), Some(99));
        assert_eq!(bcd_value(0x1F), None);
    }

    #[test]
    fn bcd_timestamps_are_found() {
        let data = [0xFF, 0x24, 0x03, 0x15, 0x13, 0x45, 0x30, 0xFF, 0x24, 0x13, 0x01, 0x00, 0x00, 0x00];
        let found = find_bcd_timestamps(&data);
        assert_eq!(found, vec![BcdTimestamp { offset: 1, text: "2024-03-15 13:45:30".to_string() }], "month 13 is rejected");
    }

    #[test]
    fn decoders_survive_empty_and_tiny_input() {
        for code in LineCode::ALL {
            let result = decode(&[], BitOrder::LsbFirst, 5, code);
            assert!(result.bytes.is_empty());
            let _ = decode(&[0xAB], BitOrder::MsbFirst, 100, code);
        }
        assert!(auto_detect(&[0x55], BitOrder::MsbFirst).is_empty());
    }
}
