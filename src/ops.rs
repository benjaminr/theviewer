//! Pure byte- and bit-level transformations applied to a selection.

/// Flip every bit.
pub fn invert_bits(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        *byte = !*byte;
    }
}

/// Shift the bit stream formed by `bytes` by `shift` bits. Positive shifts move
/// bits towards the start of the slice (left, towards the most significant
/// end); negative shifts move them towards the end. Vacated bits become zero.
pub fn shift_bits(bytes: &[u8], shift: i64) -> Vec<u8> {
    let len = bytes.len();
    if len == 0 || shift == 0 {
        return bytes.to_vec();
    }
    let magnitude = shift.unsigned_abs() as usize;
    if magnitude >= len * 8 {
        return vec![0u8; len];
    }
    let byte_shift = magnitude / 8;
    let bit_shift = (magnitude % 8) as u32;
    let at = |index: isize| -> u8 {
        if index < 0 || index as usize >= len { 0 } else { bytes[index as usize] }
    };
    let mut out = vec![0u8; len];
    for (index, slot) in out.iter_mut().enumerate() {
        let index = index as isize;
        *slot = if shift > 0 {
            let source = index + byte_shift as isize;
            if bit_shift == 0 {
                at(source)
            } else {
                (at(source) << bit_shift) | (at(source + 1) >> (8 - bit_shift))
            }
        } else {
            let source = index - byte_shift as isize;
            if bit_shift == 0 {
                at(source)
            } else {
                (at(source) >> bit_shift) | (at(source - 1) << (8 - bit_shift))
            }
        };
    }
    out
}

/// Reverse the order of the bits within each byte.
pub fn reverse_bits_in_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        *byte = byte.reverse_bits();
    }
}

/// Parse loosely formatted hex ("de ad be:ef", "0xDEAD", "dead") into bytes.
/// Returns `None` if any character is not hex or a separator, or the digit
/// count is odd.
pub fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text
        .replace("0x", "")
        .replace("0X", "")
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | ',' | '\n' | '\t' | '-' | '_'))
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&cleaned[index..index + 2], 16).ok())
        .collect()
}

/// Format bytes as space-separated upper-case hex pairs.
pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            text.push(' ');
        }
        text.push_str(&format!("{byte:02X}"));
    }
    text
}

/// Parse an offset typed by the user: "0x1F4", "1f4h", or decimal "500".
pub fn parse_offset(text: &str) -> Option<usize> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return usize::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = text.strip_suffix('h').or_else(|| text.strip_suffix('H')) {
        return usize::from_str_radix(hex, 16).ok();
    }
    text.parse().ok()
}

/// Bytes as compact lower-case hex ("deadbeef"), the form the data API uses
/// for bytes in JSON.
pub fn to_compact_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Serde support for byte vectors written as hex strings: written compact
/// ("deadbeef"), read loosely, as [`parse_hex`] reads them. Use with
/// `#[serde(with = "crate::ops::hex_bytes")]` and `#[schemars(with = "String")]`.
pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::to_compact_hex(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        super::parse_hex(&text).ok_or_else(|| serde::de::Error::custom(format!("'{text}' is not hex bytes, such as \"de ad be ef\"")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn left_shift_carries_bits_across_bytes() {
        assert_eq!(shift_bits(&[0b0000_0001, 0b1000_0000], 1), vec![0b0000_0011, 0b0000_0000]);
    }

    #[test]
    fn right_shift_carries_bits_across_bytes() {
        assert_eq!(shift_bits(&[0b0000_0001, 0b0000_0000], -1), vec![0b0000_0000, 0b1000_0000]);
    }

    #[test]
    fn whole_byte_shifts_move_bytes() {
        assert_eq!(shift_bits(&[1, 2, 3], 8), vec![2, 3, 0]);
        assert_eq!(shift_bits(&[1, 2, 3], -16), vec![0, 0, 1]);
        assert_eq!(shift_bits(&[1, 2, 3], 9), vec![4, 6, 0]);
    }

    #[test]
    fn shifting_everything_out_gives_zeros() {
        assert_eq!(shift_bits(&[0xFF, 0xFF], 16), vec![0, 0]);
    }

    #[test]
    fn hex_parsing_accepts_common_separators() {
        assert_eq!(parse_hex("DE AD:be,ef"), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(parse_hex("0xff"), Some(vec![0xFF]));
        assert_eq!(parse_hex("abc"), None);
        assert_eq!(parse_hex("zz"), None);
    }

    #[test]
    fn offset_parsing_handles_hex_and_decimal() {
        assert_eq!(parse_offset("0x10"), Some(16));
        assert_eq!(parse_offset("10h"), Some(16));
        assert_eq!(parse_offset("10"), Some(10));
        assert_eq!(parse_offset("nope"), None);
    }

    #[test]
    fn invert_flips_every_bit() {
        let mut bytes = [0x0F, 0xFF];
        invert_bits(&mut bytes);
        assert_eq!(bytes, [0xF0, 0x00]);
    }
}
