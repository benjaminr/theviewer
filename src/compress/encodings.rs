//! Text encodings among the built-in codecs: base32, base64, base64url,
//! hex text and two 6-bit character sets.
//!
//! The radix encodings (base32, base64, base64url and hex) read the run of
//! their characters at the start of the input, line breaks inside it
//! included, and stop at padding (`=`) or at the first character that is
//! not theirs. Base32 and hex take either case, as DNS names and hex dumps
//! come in both; padding is optional, as tunnels strip it.
//!
//! The 6-bit sets pack four characters into three bytes, most significant
//! bit first, and decode any bytes at all: DEC SIXBIT is the character's
//! ASCII code minus 32 (0 is a space, 33 is `A`), and AIS 6-bit ASCII (as
//! ship transponders send it) has 0 to 31 for `@` to `_` and 32 to 63 for
//! a space to `?`.

/// A text encoding the viewer decodes and encodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextEncoding {
    Base32,
    Base64,
    Base64Url,
    Hex,
    Sixbit,
    Ais6,
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Bits a 6-bit character takes.
const SIXBIT_BITS: u32 = 6;
/// The ASCII code DEC SIXBIT's 0 stands for (a space).
const SIXBIT_ZERO: u8 = 0x20;
/// The ASCII code AIS 6-bit's 0 stands for (`@`); its 32 to 63 are
/// themselves.
const AIS_ZERO: u8 = 0x40;

/// Characters a run must have before detection offers an encoding there.
pub const DETECT_RUN: usize = 32;

/// What decoding read from the start of the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedText {
    pub data: Vec<u8>,
    /// Input bytes read, padding and line breaks inside the run included.
    pub consumed: usize,
    /// Output was cut at the caller's limit.
    pub truncated: bool,
}

impl TextEncoding {
    /// The radix encoding's alphabet and bits a character holds; `None`
    /// for the 6-bit character sets.
    fn alphabet(self) -> Option<(&'static [u8], u32)> {
        match self {
            TextEncoding::Base32 => Some((BASE32, 5)),
            TextEncoding::Base64 => Some((BASE64, 6)),
            TextEncoding::Base64Url => Some((BASE64_URL, 6)),
            TextEncoding::Hex => Some((HEX, 4)),
            TextEncoding::Sixbit | TextEncoding::Ais6 => None,
        }
    }

    /// Whether the encoding takes upper and lower case as the same.
    fn ignores_case(self) -> bool {
        matches!(self, TextEncoding::Base32 | TextEncoding::Hex)
    }

    /// Whether it ends with `=` padding.
    fn is_padded(self) -> bool {
        matches!(self, TextEncoding::Base32 | TextEncoding::Base64 | TextEncoding::Base64Url)
    }

    /// The value of character `byte`, if it is one of the alphabet's.
    fn value_of(self, byte: u8) -> Option<u8> {
        let (alphabet, _) = self.alphabet()?;
        let byte = if self.ignores_case() { byte.to_ascii_lowercase() } else { byte };
        alphabet.iter().position(|&c| if self.ignores_case() { c.to_ascii_lowercase() == byte } else { c == byte }).map(|value| value as u8)
    }

    /// Decode from the start of `input`, at most `max_out` bytes.
    pub fn decode(self, input: &[u8], max_out: usize) -> Result<DecodedText, String> {
        match self {
            TextEncoding::Sixbit => Ok(decode_six_bit(input, max_out, |code| code + SIXBIT_ZERO)),
            TextEncoding::Ais6 => Ok(decode_six_bit(input, max_out, |code| if code < 32 { code + AIS_ZERO } else { code })),
            _ => self.decode_radix(input, max_out),
        }
    }

    fn decode_radix(self, input: &[u8], max_out: usize) -> Result<DecodedText, String> {
        let (_, bits) = self.alphabet().expect("a radix encoding");
        let mut data = Vec::new();
        let (mut buffer, mut buffered) = (0u32, 0u32);
        let mut consumed = 0usize;
        let mut truncated = false;
        let mut at = if self == TextEncoding::Hex && (input.starts_with(b"0x") || input.starts_with(b"0X")) { 2 } else { 0 };
        while at < input.len() {
            let byte = input[at];
            if let Some(value) = self.value_of(byte) {
                if data.len() >= max_out {
                    truncated = true;
                    break;
                }
                buffer = (buffer << bits) | u32::from(value);
                buffered += bits;
                if buffered >= 8 {
                    buffered -= 8;
                    data.push((buffer >> buffered) as u8);
                    buffer &= (1 << buffered) - 1;
                }
                at += 1;
                consumed = at;
            } else if self.allows_space(byte, buffered) && input[at + 1..].iter().find(|&&next| !next.is_ascii_whitespace()).is_some_and(|&next| self.value_of(next).is_some()) {
                at += 1;
            } else {
                break;
            }
        }
        if self.is_padded() && !truncated {
            consumed += input[consumed..].iter().take_while(|&&byte| byte == b'=').count();
        }
        if data.is_empty() && !truncated {
            return Err(format!("no {} text starts here (it needs at least two of its characters)", self.label()));
        }
        Ok(DecodedText { data, consumed, truncated })
    }

    /// Whether white space may sit between characters here: line breaks in
    /// base32 and base64, and any space between whole bytes of hex.
    fn allows_space(self, byte: u8, buffered: u32) -> bool {
        match self {
            TextEncoding::Hex => byte.is_ascii_whitespace() && buffered == 0,
            _ => matches!(byte, b'\r' | b'\n'),
        }
    }

    /// Encode `data`.
    pub fn encode(self, data: &[u8]) -> Vec<u8> {
        match self {
            TextEncoding::Sixbit => encode_six_bit(data, |character| character.wrapping_sub(SIXBIT_ZERO)),
            TextEncoding::Ais6 => encode_six_bit(data, |character| if character >= AIS_ZERO { character - AIS_ZERO } else { character }),
            _ => self.encode_radix(data),
        }
    }

    fn encode_radix(self, data: &[u8]) -> Vec<u8> {
        let (alphabet, bits) = self.alphabet().expect("a radix encoding");
        let mut out = Vec::new();
        let (mut buffer, mut buffered) = (0u32, 0u32);
        for &byte in data {
            buffer = (buffer << 8) | u32::from(byte);
            buffered += 8;
            while buffered >= bits {
                buffered -= bits;
                out.push(alphabet[((buffer >> buffered) & ((1 << bits) - 1)) as usize]);
            }
            buffer &= (1 << buffered) - 1;
        }
        if buffered > 0 {
            out.push(alphabet[((buffer << (bits - buffered)) & ((1 << bits) - 1)) as usize]);
        }
        let group = match self {
            TextEncoding::Base32 => 8,
            TextEncoding::Base64 | TextEncoding::Base64Url => 4,
            _ => 1,
        };
        while !out.len().is_multiple_of(group) {
            out.push(b'=');
        }
        out
    }

    /// Whether `bytes` start with a run of this encoding long enough
    /// (`min_run` characters) and in its character set to be offered: base32
    /// in one case, base64 with both cases, base64url with a `-` or `_`, hex
    /// in hex digits. The 6-bit sets read any bytes, so are never offered.
    pub fn starts(self, bytes: &[u8], min_run: usize) -> bool {
        if self.alphabet().is_none() {
            return false;
        }
        let run: Vec<u8> = bytes.iter().copied().take_while(|&byte| self.value_of(byte).is_some()).collect();
        if run.len() < min_run {
            return false;
        }
        let has = |test: fn(&u8) -> bool| run.iter().any(test);
        match self {
            TextEncoding::Base32 => !(has(u8::is_ascii_uppercase) && has(u8::is_ascii_lowercase)),
            TextEncoding::Base64 => has(u8::is_ascii_uppercase) && has(u8::is_ascii_lowercase),
            TextEncoding::Base64Url => has(|&byte| byte == b'-' || byte == b'_'),
            _ => true,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TextEncoding::Base32 => "base32",
            TextEncoding::Base64 => "base64",
            TextEncoding::Base64Url => "base64url",
            TextEncoding::Hex => "hex text",
            TextEncoding::Sixbit => "DEC SIXBIT",
            TextEncoding::Ais6 => "AIS 6-bit ASCII",
        }
    }
}

/// Every 6 bits of `input`, most significant first, as the character
/// `character` gives the code; bits left over that make no whole character
/// are dropped.
fn decode_six_bit(input: &[u8], max_out: usize, character: impl Fn(u8) -> u8) -> DecodedText {
    let mut data = Vec::new();
    let (mut buffer, mut buffered) = (0u32, 0u32);
    for (index, &byte) in input.iter().enumerate() {
        buffer = (buffer << 8) | u32::from(byte);
        buffered += 8;
        while buffered >= SIXBIT_BITS {
            buffered -= SIXBIT_BITS;
            if data.len() >= max_out {
                return DecodedText { data, consumed: index, truncated: true };
            }
            data.push(character(((buffer >> buffered) & 0x3F) as u8));
        }
        buffer &= (1 << buffered) - 1;
    }
    DecodedText { data, consumed: input.len(), truncated: false }
}

/// Each character of `text` as the 6-bit code `code` gives, packed most
/// significant bit first, the last byte filled out with zeros.
fn encode_six_bit(text: &[u8], code: impl Fn(u8) -> u8) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buffer, mut buffered) = (0u32, 0u32);
    for &character in text {
        buffer = (buffer << SIXBIT_BITS) | u32::from(code(character) & 0x3F);
        buffered += SIXBIT_BITS;
        while buffered >= 8 {
            buffered -= 8;
            out.push((buffer >> buffered) as u8);
        }
        buffer &= (1 << buffered) - 1;
    }
    if buffered > 0 {
        out.push((buffer << (8 - buffered)) as u8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(encoding: TextEncoding, input: &[u8]) -> (Vec<u8>, usize) {
        let found = encoding.decode(input, usize::MAX).unwrap();
        (found.data, found.consumed)
    }

    #[test]
    fn base32_from_a_dns_tunnel_reads_in_either_case_with_or_without_padding() {
        assert_eq!(decoded(TextEncoding::Base32, b"MZXW6YTBOI======"), (b"foobar".to_vec(), 16));
        assert_eq!(decoded(TextEncoding::Base32, b"mzxw6ytboi.example.com"), (b"foobar".to_vec(), 10));
        assert_eq!(TextEncoding::Base32.encode(b"foobar"), b"MZXW6YTBOI======".to_vec());
        assert!(TextEncoding::Base32.decode(b"!nope", 100).is_err());
    }

    #[test]
    fn base64_and_its_url_form_read_their_own_alphabets_across_line_breaks() {
        assert_eq!(decoded(TextEncoding::Base64, b"aGVsbG8s\r\nIHdvcmxk\n;"), (b"hello, world".to_vec(), 18));
        assert_eq!(decoded(TextEncoding::Base64, b"aGk=\"rest"), (b"hi".to_vec(), 4));
        assert_eq!(decoded(TextEncoding::Base64Url, b"-_-_"), (vec![0xFB, 0xFF, 0xBF], 4));
        assert!(TextEncoding::Base64.decode(b"-_-_", 9).is_err(), "not base64's alphabet");
        for data in [&b""[..], b"f", b"fo", b"foo", b"\x00\xff\x10\x80"] {
            for encoding in [TextEncoding::Base32, TextEncoding::Base64, TextEncoding::Base64Url, TextEncoding::Hex] {
                let text = encoding.encode(data);
                let back = encoding.decode(&text, usize::MAX).map(|found| found.data).unwrap_or_default();
                assert_eq!(back, data, "{encoding:?} round trip of {data:?} through {:?}", String::from_utf8_lossy(&text));
            }
        }
    }

    #[test]
    fn hex_text_reads_a_dump_with_spaces_between_bytes() {
        assert_eq!(decoded(TextEncoding::Hex, b"0xDEADbeef;"), (vec![0xDE, 0xAD, 0xBE, 0xEF], 10));
        assert_eq!(decoded(TextEncoding::Hex, b"de ad\nbe ef zz"), (vec![0xDE, 0xAD, 0xBE, 0xEF], 11));
        assert_eq!(decoded(TextEncoding::Hex, b"abc;"), (vec![0xAB], 3), "a lone last digit makes no byte");
    }

    #[test]
    fn six_bit_text_reads_a_technician_id_in_both_character_sets() {
        let packed = TextEncoding::Sixbit.encode(b"SERVICE-JB22");
        assert_eq!(packed.len(), 9, "four characters in three bytes");
        assert_eq!(decoded(TextEncoding::Sixbit, &packed), (b"SERVICE-JB22".to_vec(), 9));
        let ais = TextEncoding::Ais6.encode(b"SERVICE-JB22");
        assert_ne!(ais, packed, "the letters are coded apart");
        assert_eq!(decoded(TextEncoding::Ais6, &ais).0, b"SERVICE-JB22".to_vec());
        assert_eq!(TextEncoding::Sixbit.decode(&packed, 4).unwrap(), DecodedText { data: b"SERV".to_vec(), consumed: 3, truncated: true });
    }

    #[test]
    fn runs_are_offered_only_when_long_and_in_the_encoding_s_character_set() {
        let base32 = TextEncoding::Base32.encode(&[0x5A; 40]);
        assert!(TextEncoding::Base32.starts(&base32, DETECT_RUN));
        assert!(!TextEncoding::Base64.starts(&base32, DETECT_RUN), "one case only is base32's");
        let base64 = TextEncoding::Base64.encode(b"some bytes that are long enough to be offered");
        assert!(TextEncoding::Base64.starts(&base64, DETECT_RUN));
        assert!(!TextEncoding::Base32.starts(&base64, DETECT_RUN));
        assert!(!TextEncoding::Base64Url.starts(&base64, DETECT_RUN), "nothing of the url alphabet's own");
        assert!(TextEncoding::Hex.starts(&TextEncoding::Hex.encode(&[0x19; 20]), DETECT_RUN));
        assert!(!TextEncoding::Hex.starts(b"0123456789", DETECT_RUN), "too short");
        assert!(!TextEncoding::Sixbit.starts(&base32, 1), "6-bit text is never offered");
    }
}
