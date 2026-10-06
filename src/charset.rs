//! Text charset and language identification.
//!
//! Each candidate encoding is scored in two steps:
//!
//! 1. **Validity.** The bytes are decoded strictly (with `encoding_rs` for
//!    the WHATWG encodings, and a table for EBCDIC code page 037). Malformed
//!    sequences rule an encoding out.
//! 2. **Plausibility.** The decoded characters are weighed: control
//!    characters count against every encoding, and each non-ASCII character
//!    is weighed by what that encoding's text usually contains (kana for
//!    Japanese, common hanzi for Chinese, common Hangul syllables for
//!    Korean, accented letters inside Latin words for Windows-1252, letters
//!    inside Cyrillic words for KOI8-R).
//!
//! The language of the decoded text is then identified from its script, and
//! for Latin-script text from small stop-word lists and distinctive letters.
//!
//! At most [`MAX_TEXT_SAMPLE`] bytes are examined.

use std::borrow::Cow;

/// Most bytes examined when ranking encodings.
pub const MAX_TEXT_SAMPLE: usize = 64 * 1024;
/// Characters of decoded text shown as a preview.
pub const PREVIEW_CHARS: usize = 96;

/// Confidence penalties for supersets of ASCII when the bytes are pure ASCII.
const PURE_ASCII_UTF8: f32 = 0.9;
const PURE_ASCII_SINGLE_BYTE: f32 = 0.8;
const PURE_ASCII_MULTI_BYTE: f32 = 0.7;
/// Confidence floor for a valid decode that starts with a byte-order mark.
const BOM_CONFIDENCE: f32 = 0.97;
/// Minimum share of kana among CJK characters for Japanese text.
const MIN_KANA_SHARE: f64 = 0.1;
/// EBCDIC text: letters, digits and spaces make up most characters, and
/// spaces fall in this share.
const EBCDIC_WORD_SHARE: f64 = 0.75;
const EBCDIC_SPACE_SHARE: std::ops::RangeInclusive<f64> = 0.03..=0.4;
/// Below this confidence the top encoding is not used for language identification.
const MIN_CONFIDENCE_FOR_LANGUAGE: f32 = 0.3;
/// Letters needed before a language is named.
const MIN_LETTERS_FOR_LANGUAGE: usize = 8;

/// An encoding that can be scored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TextEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Windows1252,
    ShiftJis,
    EucJp,
    Gbk,
    Big5,
    EucKr,
    Koi8R,
    Ebcdic037,
}

impl TextEncoding {
    pub const ALL: [TextEncoding; 12] = [
        TextEncoding::Ascii,
        TextEncoding::Utf8,
        TextEncoding::Utf16Le,
        TextEncoding::Utf16Be,
        TextEncoding::Windows1252,
        TextEncoding::ShiftJis,
        TextEncoding::EucJp,
        TextEncoding::Gbk,
        TextEncoding::Big5,
        TextEncoding::EucKr,
        TextEncoding::Koi8R,
        TextEncoding::Ebcdic037,
    ];

    pub fn label(self) -> &'static str {
        match self {
            TextEncoding::Ascii => "ASCII",
            TextEncoding::Utf8 => "UTF-8",
            TextEncoding::Utf16Le => "UTF-16LE",
            TextEncoding::Utf16Be => "UTF-16BE",
            TextEncoding::Windows1252 => "Windows-1252 / Latin-1",
            TextEncoding::ShiftJis => "Shift-JIS",
            TextEncoding::EucJp => "EUC-JP",
            TextEncoding::Gbk => "GBK / GB18030",
            TextEncoding::Big5 => "Big5",
            TextEncoding::EucKr => "EUC-KR",
            TextEncoding::Koi8R => "KOI8-R",
            TextEncoding::Ebcdic037 => "EBCDIC (code page 037)",
        }
    }

    /// The `encoding_rs` decoder, for encodings it implements.
    fn whatwg(self) -> Option<&'static encoding_rs::Encoding> {
        Some(match self {
            TextEncoding::Utf8 => encoding_rs::UTF_8,
            TextEncoding::Utf16Le => encoding_rs::UTF_16LE,
            TextEncoding::Utf16Be => encoding_rs::UTF_16BE,
            TextEncoding::Windows1252 => encoding_rs::WINDOWS_1252,
            TextEncoding::ShiftJis => encoding_rs::SHIFT_JIS,
            TextEncoding::EucJp => encoding_rs::EUC_JP,
            TextEncoding::Gbk => encoding_rs::GB18030,
            TextEncoding::Big5 => encoding_rs::BIG5,
            TextEncoding::EucKr => encoding_rs::EUC_KR,
            TextEncoding::Koi8R => encoding_rs::KOI8_R,
            TextEncoding::Ascii | TextEncoding::Ebcdic037 => return None,
        })
    }

    fn bom(self) -> Option<&'static [u8]> {
        match self {
            TextEncoding::Utf8 => Some(&[0xEF, 0xBB, 0xBF]),
            TextEncoding::Utf16Le => Some(&[0xFF, 0xFE]),
            TextEncoding::Utf16Be => Some(&[0xFE, 0xFF]),
            _ => None,
        }
    }

    /// What the decoded characters of this encoding usually are.
    fn expectation(self) -> Expectation {
        match self {
            TextEncoding::Windows1252 => Expectation::LatinWords,
            TextEncoding::Koi8R => Expectation::CyrillicWords,
            TextEncoding::ShiftJis | TextEncoding::EucJp => Expectation::Japanese,
            TextEncoding::Gbk => Expectation::SimplifiedChinese,
            TextEncoding::Big5 => Expectation::TraditionalChinese,
            TextEncoding::EucKr => Expectation::Korean,
            TextEncoding::Ascii | TextEncoding::Utf8 | TextEncoding::Utf16Le | TextEncoding::Utf16Be | TextEncoding::Ebcdic037 => Expectation::Any,
        }
    }

    fn is_multi_byte_legacy(self) -> bool {
        matches!(self, TextEncoding::ShiftJis | TextEncoding::EucJp | TextEncoding::Gbk | TextEncoding::Big5 | TextEncoding::EucKr)
    }
}

/// One ranked encoding.
#[derive(Clone, Debug, PartialEq)]
pub struct EncodingGuess {
    pub encoding: TextEncoding,
    /// 0 to 1; 0 when the bytes are not valid in this encoding.
    pub confidence: f32,
    pub reason: String,
    /// The start of the decoded text, with control characters made visible.
    pub preview: String,
    pub has_bom: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Language {
    English,
    French,
    German,
    Spanish,
    Italian,
    Portuguese,
    Dutch,
    Russian,
    Japanese,
    Chinese,
    Korean,
    Arabic,
}

impl Language {
    pub fn label(self) -> &'static str {
        match self {
            Language::English => "English",
            Language::French => "French",
            Language::German => "German",
            Language::Spanish => "Spanish",
            Language::Italian => "Italian",
            Language::Portuguese => "Portuguese",
            Language::Dutch => "Dutch",
            Language::Russian => "Russian",
            Language::Japanese => "Japanese",
            Language::Chinese => "Chinese",
            Language::Korean => "Korean",
            Language::Arabic => "Arabic",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LanguageGuess {
    pub language: Language,
    pub confidence: f32,
    pub reason: String,
}

/// Ranked encodings and, for the best one, ranked languages.
#[derive(Clone, Debug, PartialEq)]
pub struct TextReport {
    pub sample_len: usize,
    pub encodings: Vec<EncodingGuess>,
    pub languages: Vec<LanguageGuess>,
}

impl TextReport {
    pub fn best(&self) -> Option<&EncodingGuess> {
        self.encodings.first().filter(|guess| guess.confidence > 0.0)
    }
}

/// Rank encodings for `bytes` and identify the language of the best decode.
pub fn characterise_text(bytes: &[u8]) -> TextReport {
    let sample = &bytes[..bytes.len().min(MAX_TEXT_SAMPLE)];
    let encodings = rank_encodings(sample);
    let languages = encodings
        .first()
        .filter(|guess| guess.confidence >= MIN_CONFIDENCE_FOR_LANGUAGE)
        .and_then(|guess| decode_strict(sample, guess.encoding))
        .map(|text| identify_language(&text))
        .unwrap_or_default();
    TextReport { sample_len: sample.len(), encodings, languages }
}

/// Decode `bytes` as `encoding`, replacing malformed sequences with U+FFFD.
/// A byte-order mark for the encoding is skipped; EBCDIC line ends (NL,
/// 0x15) become `\n`.
pub fn decode(bytes: &[u8], encoding: TextEncoding) -> String {
    let bytes = strip_bom(bytes, encoding);
    match encoding {
        TextEncoding::Ascii => bytes.iter().map(|&byte| if byte.is_ascii() { byte as char } else { char::REPLACEMENT_CHARACTER }).collect(),
        TextEncoding::Ebcdic037 => decode_ebcdic(bytes),
        _ => match encoding.whatwg() {
            Some(decoder) => decoder.decode_without_bom_handling(bytes).0.into_owned(),
            None => String::new(),
        },
    }
}

/// Decode `bytes` as `encoding`, or `None` if any sequence is malformed. An
/// incomplete character cut off at the end of the bytes is ignored.
pub fn decode_strict(bytes: &[u8], encoding: TextEncoding) -> Option<String> {
    const MAX_CUT_OFF: usize = 3;
    let bytes = strip_bom(bytes, encoding);
    match encoding {
        TextEncoding::Ascii => bytes.is_ascii().then(|| bytes.iter().map(|&byte| byte as char).collect()),
        TextEncoding::Ebcdic037 => Some(decode_ebcdic(bytes)),
        _ => {
            let decoder = encoding.whatwg()?;
            (0..=MAX_CUT_OFF.min(bytes.len()))
                .find_map(|cut| decoder.decode_without_bom_handling_and_without_replacement(&bytes[..bytes.len() - cut]))
                .map(Cow::into_owned)
        }
    }
}

fn strip_bom(bytes: &[u8], encoding: TextEncoding) -> &[u8] {
    match encoding.bom() {
        Some(bom) if bytes.starts_with(bom) => &bytes[bom.len()..],
        _ => bytes,
    }
}

// ---------------------------------------------------------------------------
// Ranking
// ---------------------------------------------------------------------------

/// Score every encoding for `bytes` (up to [`MAX_TEXT_SAMPLE`]), best first.
pub fn rank_encodings(bytes: &[u8]) -> Vec<EncodingGuess> {
    let sample = &bytes[..bytes.len().min(MAX_TEXT_SAMPLE)];
    let mut guesses: Vec<EncodingGuess> = TextEncoding::ALL.iter().map(|&encoding| score_encoding(sample, encoding)).collect();
    guesses.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
    guesses
}

fn score_encoding(sample: &[u8], encoding: TextEncoding) -> EncodingGuess {
    let has_bom = encoding.bom().is_some_and(|bom| sample.starts_with(bom));
    let Some(text) = decode_strict(sample, encoding) else {
        return EncodingGuess { encoding, confidence: 0.0, reason: "not valid: malformed byte sequences".to_string(), preview: String::new(), has_bom };
    };
    let tally = Tally::of(&text, encoding.expectation());
    let (mut confidence, mut reason) = match encoding {
        TextEncoding::Ebcdic037 => ebcdic_score(&text, &tally),
        _ => general_score(sample, encoding, &tally),
    };
    if has_bom && !text.is_empty() {
        confidence = confidence.max(BOM_CONFIDENCE);
        reason = format!("starts with the {} byte-order mark; {reason}", encoding.label());
    }
    EncodingGuess { encoding, confidence: confidence.clamp(0.0, 1.0), reason, preview: preview(&text), has_bom }
}

/// The confidence and reason for every encoding but EBCDIC.
fn general_score(sample: &[u8], encoding: TextEncoding, tally: &Tally) -> (f32, String) {
    if tally.total == 0 {
        return (0.0, "no characters".to_string());
    }
    let text_factor = tally.text_factor();
    let controls = format!("{:.0}% control characters", tally.control_share() * 100.0);
    let pure_ascii = sample.is_ascii();
    if tally.non_ascii == 0 {
        let factor = match encoding {
            TextEncoding::Ascii | TextEncoding::Utf16Le | TextEncoding::Utf16Be => 1.0,
            TextEncoding::Utf8 => PURE_ASCII_UTF8,
            encoding if encoding.is_multi_byte_legacy() => PURE_ASCII_MULTI_BYTE,
            _ => PURE_ASCII_SINGLE_BYTE,
        };
        let reason = match encoding {
            TextEncoding::Ascii => format!("only 7-bit bytes; {controls}"),
            TextEncoding::Utf16Le | TextEncoding::Utf16Be => format!("every character decodes to ASCII ({}); {controls}", zero_byte_pattern(sample)),
            _ => format!("only ASCII characters, which this encoding shares; {controls}"),
        };
        return (text_factor * factor, reason);
    }
    let weight = tally.mean_weight();
    let mut confidence = text_factor * weight as f32;
    let mut reason = format!("{} non-ASCII characters, plausibility {:.0}%; {controls}", tally.non_ascii, weight * 100.0);
    match encoding {
        TextEncoding::Utf8 => {
            // Valid multi-byte UTF-8 rarely happens by accident.
            confidence = text_factor * (0.85 + 0.15 * weight as f32);
            reason = format!("valid UTF-8 with {} multi-byte characters; {controls}", tally.non_ascii);
        }
        TextEncoding::ShiftJis | TextEncoding::EucJp if tally.kana_share() < MIN_KANA_SHARE => {
            confidence *= 0.5;
            reason.push_str("; little kana, so unlikely Japanese");
        }
        TextEncoding::Utf16Le | TextEncoding::Utf16Be => reason.push_str(&format!("; {}", zero_byte_pattern(sample))),
        _ => {}
    }
    if pure_ascii && encoding != TextEncoding::Ascii {
        confidence = confidence.min(PURE_ASCII_SINGLE_BYTE);
    }
    (confidence, reason)
}

/// Where the zero bytes fall, which tells UTF-16 byte order for Latin text.
fn zero_byte_pattern(sample: &[u8]) -> String {
    let pairs = sample.as_chunks::<2>().0;
    let even = pairs.iter().filter(|pair| pair[0] == 0).count();
    let odd = pairs.iter().filter(|pair| pair[1] == 0).count();
    let total = pairs.len().max(1) as f64;
    format!("zero bytes at {:.0}% of even and {:.0}% of odd positions", even as f64 / total * 100.0, odd as f64 / total * 100.0)
}

fn ebcdic_score(text: &str, tally: &Tally) -> (f32, String) {
    if tally.total == 0 {
        return (0.0, "no characters".to_string());
    }
    let total = tally.total as f64;
    let spaces = text.chars().filter(|&c| c == ' ').count() as f64 / total;
    let words = text.chars().filter(|c| c.is_ascii_alphanumeric() || *c == ' ').count() as f64 / total;
    let word_factor = (words / EBCDIC_WORD_SHARE).min(1.0);
    let space_factor = if EBCDIC_SPACE_SHARE.contains(&spaces) { 1.0 } else { 0.5 };
    let confidence = tally.text_factor() * (word_factor * space_factor) as f32;
    let reason = format!("{:.0}% letters, digits and spaces in EBCDIC positions, {:.0}% spaces (0x40); {:.0}% control characters", words * 100.0, spaces * 100.0, tally.control_share() * 100.0);
    (confidence, reason)
}

fn preview(text: &str) -> String {
    text.chars()
        .take(PREVIEW_CHARS)
        .map(|c| match c {
            '\n' => '↵',
            '\r' | '\t' => ' ',
            c if is_control(c) => '·',
            c => c,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Character weights
// ---------------------------------------------------------------------------

/// What a decoder's text is expected to contain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expectation {
    Any,
    LatinWords,
    CyrillicWords,
    Japanese,
    SimplifiedChinese,
    TraditionalChinese,
    Korean,
}

/// The most frequent simplified Chinese characters.
const COMMON_SIMPLIFIED: &str = "的一是不了在人有我他这个们中来上大为和国地到以说时要就出会可也你对生能而子那得于着下自之年过发后作里用道行所然家种事成方多经么去法学如都同现当没动面起看定天分还进好小部其些主样理心她本前开但因只从想实日";
/// The most frequent traditional Chinese characters.
const COMMON_TRADITIONAL: &str = "的一是不了在人有我他這個們中來上大為和國地到以說時要就出會可也你對生能而子那得於著下自之年過發後作裏用道行所然家種事成方多經麼去法學如都同現當沒動面起看定天分還進好小部其些主樣理心她本前開但因只從想實日";
/// The most frequent Hangul syllables.
const COMMON_HANGUL: &str = "이다는의에하고가을지서기사로한를리대자도수일정그어시나인아있게적으해들것요니보우전라부상주제여만했되면성장국과까원소무히계동방할구신경세내화말용개없위러연공";

fn is_control(c: char) -> bool {
    (c < ' ' && !matches!(c, '\t' | '\n' | '\r' | '\x0c')) || ('\u{7f}'..='\u{9f}').contains(&c) || c == char::REPLACEMENT_CHARACTER
}

fn is_kana(c: char) -> bool {
    ('\u{3040}'..='\u{30ff}').contains(&c)
}

fn is_han(c: char) -> bool {
    ('\u{4e00}'..='\u{9fff}').contains(&c)
}

fn is_hangul(c: char) -> bool {
    ('\u{ac00}'..='\u{d7a3}').contains(&c)
}

fn is_cyrillic_letter(c: char) -> bool {
    ('\u{0410}'..='\u{044f}').contains(&c) || c == 'ё' || c == 'Ё'
}

fn is_latin1_letter(c: char) -> bool {
    (('\u{00c0}'..='\u{00ff}').contains(&c) && c != '×' && c != '÷') || ('\u{0100}'..='\u{017f}').contains(&c)
}

/// CJK punctuation and full-width forms.
fn is_cjk_punctuation(c: char) -> bool {
    ('\u{3000}'..='\u{303f}').contains(&c) || ('\u{ff01}'..='\u{ff60}').contains(&c)
}

/// A character whose UTF-16 code unit is a byte-swapped ASCII character.
fn is_swapped_ascii(c: char) -> bool {
    let code = c as u32;
    code > 0xFF && code <= 0xFFFF && code & 0xFF == 0 && (0x20..0x7F).contains(&(code >> 8))
}

fn common_han_weight(c: char, common: &str) -> f64 {
    if common.contains(c) { 1.0 } else { 0.3 }
}

/// How typical `c` is of text in an encoding with this expectation, given
/// its neighbours. 0 is implausible, 1 is typical.
fn char_weight(c: char, previous: Option<char>, next: Option<char>, expectation: Expectation) -> f64 {
    let neighbours = [previous, next];
    let beside = |test: fn(char) -> bool| neighbours.iter().flatten().any(|&n| test(n));
    match expectation {
        Expectation::LatinWords => {
            if is_latin1_letter(c) {
                if beside(|n| n.is_ascii_alphabetic()) {
                    1.0
                } else if beside(is_latin1_letter) {
                    0.4
                } else {
                    0.15
                }
            } else {
                0.3
            }
        }
        Expectation::CyrillicWords => {
            if !is_cyrillic_letter(c) {
                0.0
            } else if !beside(is_cyrillic_letter) {
                0.2
            } else if c.is_lowercase() {
                1.0
            } else {
                0.7
            }
        }
        Expectation::Japanese => match c {
            c if is_kana(c) => 1.0,
            c if is_cjk_punctuation(c) => 0.9,
            c if is_han(c) => 0.6,
            '\u{0391}'..='\u{03c9}' | '\u{0410}'..='\u{044f}' => 0.2,
            '\u{ff61}'..='\u{ff9f}' => 0.1,
            _ => 0.0,
        },
        Expectation::SimplifiedChinese | Expectation::TraditionalChinese => {
            let common = if expectation == Expectation::SimplifiedChinese { COMMON_SIMPLIFIED } else { COMMON_TRADITIONAL };
            match c {
                c if is_han(c) => common_han_weight(c, common),
                c if is_cjk_punctuation(c) => 0.8,
                c if is_kana(c) => 0.1,
                _ => 0.0,
            }
        }
        Expectation::Korean => match c {
            c if is_hangul(c) => {
                if COMMON_HANGUL.contains(c) {
                    1.0
                } else {
                    0.3
                }
            }
            c if is_cjk_punctuation(c) => 0.8,
            c if is_han(c) => 0.2,
            _ => 0.0,
        },
        Expectation::Any => match c {
            c if is_swapped_ascii(c) => 0.0,
            c if is_kana(c) => 1.0,
            c if is_hangul(c) => {
                if COMMON_HANGUL.contains(c) {
                    1.0
                } else {
                    0.3
                }
            }
            c if is_han(c) => {
                if COMMON_SIMPLIFIED.contains(c) || COMMON_TRADITIONAL.contains(c) {
                    1.0
                } else {
                    0.3
                }
            }
            c if is_latin1_letter(c) || c.is_alphabetic() && (c as u32) < 0x0800 => 0.9,
            c if is_cjk_punctuation(c) || ('\u{2000}'..='\u{206f}').contains(&c) || ('\u{00a0}'..='\u{00bf}').contains(&c) => 0.6,
            '\u{e000}'..='\u{f8ff}' => 0.0,
            _ => 0.3,
        },
    }
}

/// Counts over decoded text.
#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    total: usize,
    controls: usize,
    non_ascii: usize,
    weight_sum: f64,
    kana: usize,
    cjk: usize,
}

impl Tally {
    fn of(text: &str, expectation: Expectation) -> Tally {
        let chars: Vec<char> = text.chars().collect();
        let mut tally = Tally { total: chars.len(), ..Tally::default() };
        for (index, &c) in chars.iter().enumerate() {
            if is_control(c) {
                tally.controls += 1;
                continue;
            }
            if c.is_ascii() {
                continue;
            }
            tally.non_ascii += 1;
            let previous = index.checked_sub(1).map(|i| chars[i]);
            let next = chars.get(index + 1).copied();
            tally.weight_sum += char_weight(c, previous, next, expectation);
            if is_kana(c) {
                tally.kana += 1;
            }
            if is_kana(c) || is_han(c) {
                tally.cjk += 1;
            }
        }
        tally
    }

    fn control_share(&self) -> f64 {
        self.controls as f64 / self.total.max(1) as f64
    }

    /// 1 for clean text, falling quickly as control characters appear.
    fn text_factor(&self) -> f32 {
        let clean = 1.0 - self.control_share();
        (clean * clean) as f32
    }

    fn mean_weight(&self) -> f64 {
        self.weight_sum / self.non_ascii.max(1) as f64
    }

    fn kana_share(&self) -> f64 {
        self.kana as f64 / self.cjk.max(1) as f64
    }
}

// ---------------------------------------------------------------------------
// EBCDIC
// ---------------------------------------------------------------------------

/// IBM code page 037 (US/Canada EBCDIC) to Unicode.
#[rustfmt::skip]
const CP037: [u16; 256] = [
    0x0000, 0x0001, 0x0002, 0x0003, 0x009C, 0x0009, 0x0086, 0x007F, 0x0097, 0x008D, 0x008E, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F,
    0x0010, 0x0011, 0x0012, 0x0013, 0x009D, 0x0085, 0x0008, 0x0087, 0x0018, 0x0019, 0x0092, 0x008F, 0x001C, 0x001D, 0x001E, 0x001F,
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x000A, 0x0017, 0x001B, 0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x0005, 0x0006, 0x0007,
    0x0090, 0x0091, 0x0016, 0x0093, 0x0094, 0x0095, 0x0096, 0x0004, 0x0098, 0x0099, 0x009A, 0x009B, 0x0014, 0x0015, 0x009E, 0x001A,
    0x0020, 0x00A0, 0x00E2, 0x00E4, 0x00E0, 0x00E1, 0x00E3, 0x00E5, 0x00E7, 0x00F1, 0x00A2, 0x002E, 0x003C, 0x0028, 0x002B, 0x007C,
    0x0026, 0x00E9, 0x00EA, 0x00EB, 0x00E8, 0x00ED, 0x00EE, 0x00EF, 0x00EC, 0x00DF, 0x0021, 0x0024, 0x002A, 0x0029, 0x003B, 0x00AC,
    0x002D, 0x002F, 0x00C2, 0x00C4, 0x00C0, 0x00C1, 0x00C3, 0x00C5, 0x00C7, 0x00D1, 0x00A6, 0x002C, 0x0025, 0x005F, 0x003E, 0x003F,
    0x00F8, 0x00C9, 0x00CA, 0x00CB, 0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x0060, 0x003A, 0x0023, 0x0040, 0x0027, 0x003D, 0x0022,
    0x00D8, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x00AB, 0x00BB, 0x00F0, 0x00FD, 0x00FE, 0x00B1,
    0x00B0, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F, 0x0070, 0x0071, 0x0072, 0x00AA, 0x00BA, 0x00E6, 0x00B8, 0x00C6, 0x00A4,
    0x00B5, 0x007E, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078, 0x0079, 0x007A, 0x00A1, 0x00BF, 0x00D0, 0x00DD, 0x00DE, 0x00AE,
    0x005E, 0x00A3, 0x00A5, 0x00B7, 0x00A9, 0x00A7, 0x00B6, 0x00BC, 0x00BD, 0x00BE, 0x005B, 0x005D, 0x00AF, 0x00A8, 0x00B4, 0x00D7,
    0x007B, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047, 0x0048, 0x0049, 0x00AD, 0x00F4, 0x00F6, 0x00F2, 0x00F3, 0x00F5,
    0x007D, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F, 0x0050, 0x0051, 0x0052, 0x00B9, 0x00FB, 0x00FC, 0x00F9, 0x00FA, 0x00FF,
    0x005C, 0x00F7, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059, 0x005A, 0x00B2, 0x00D4, 0x00D6, 0x00D2, 0x00D3, 0x00D5,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x00B3, 0x00DB, 0x00DC, 0x00D9, 0x00DA, 0x009F,
];

/// The EBCDIC new-line control (NL, 0x15), used as the line end.
const EBCDIC_NEW_LINE: u8 = 0x15;

fn decode_ebcdic(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| if byte == EBCDIC_NEW_LINE { '\n' } else { char::from_u32(CP037[byte as usize] as u32).unwrap_or(char::REPLACEMENT_CHARACTER) })
        .collect()
}

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

/// Stop words and distinctive letters of a Latin-script language.
struct LatinProfile {
    language: Language,
    stop_words: &'static [&'static str],
    distinctive: &'static str,
}

const LATIN_PROFILES: [LatinProfile; 7] = [
    LatinProfile {
        language: Language::English,
        stop_words: &["the", "and", "of", "to", "in", "is", "that", "it", "was", "for", "with", "as", "on", "be", "at", "by", "this", "are", "have", "from", "not", "you", "he", "she", "they", "which", "or"],
        distinctive: "",
    },
    LatinProfile {
        language: Language::French,
        stop_words: &["le", "la", "les", "des", "du", "et", "est", "un", "une", "que", "qui", "dans", "pour", "pas", "sur", "au", "avec", "ce", "il", "elle", "nous", "vous", "sont", "mais", "ou", "aux"],
        distinctive: "èêëâîïûùœç",
    },
    LatinProfile {
        language: Language::German,
        stop_words: &["der", "die", "das", "und", "ist", "nicht", "ein", "eine", "zu", "den", "von", "mit", "sich", "des", "auf", "für", "im", "dem", "auch", "es", "wir", "ich", "sie", "wird", "auf", "aber"],
        distinctive: "ßäöü",
    },
    LatinProfile {
        language: Language::Spanish,
        stop_words: &["el", "los", "las", "y", "en", "es", "por", "con", "para", "no", "se", "del", "al", "lo", "como", "más", "pero", "su", "una", "muy", "está", "son"],
        distinctive: "ñ¿¡íóúá",
    },
    LatinProfile {
        language: Language::Italian,
        stop_words: &["il", "gli", "di", "che", "è", "per", "non", "sono", "con", "della", "nel", "si", "da", "ma", "come", "anche", "questo", "una", "alla", "dei", "le"],
        distinctive: "ìòàè",
    },
    LatinProfile {
        language: Language::Portuguese,
        stop_words: &["o", "os", "as", "do", "da", "em", "um", "uma", "não", "para", "com", "por", "no", "na", "dos", "mais", "é", "são", "ao", "também", "que"],
        distinctive: "ãõçôê",
    },
    LatinProfile {
        language: Language::Dutch,
        stop_words: &["de", "het", "een", "en", "van", "is", "dat", "niet", "op", "te", "zijn", "met", "voor", "er", "ook", "aan", "maar", "die", "wij", "ik", "hij", "worden"],
        distinctive: "",
    },
];

/// Weight of one distinctive letter relative to one stop word.
const DISTINCTIVE_WEIGHT: f64 = 2.0;
/// Stop-word share at which a Latin language's coverage counts as full.
const FULL_STOP_WORD_SHARE: f64 = 0.25;

/// Letters of `text` by script.
#[derive(Clone, Copy, Debug, Default)]
struct Scripts {
    latin: usize,
    cyrillic: usize,
    arabic: usize,
    kana: usize,
    han: usize,
    hangul: usize,
}

impl Scripts {
    fn of(text: &str) -> Scripts {
        let mut scripts = Scripts::default();
        for c in text.chars() {
            match c {
                c if c.is_ascii_alphabetic() || is_latin1_letter(c) => scripts.latin += 1,
                '\u{0400}'..='\u{04ff}' => scripts.cyrillic += 1,
                '\u{0600}'..='\u{06ff}' => scripts.arabic += 1,
                c if is_kana(c) => scripts.kana += 1,
                c if is_han(c) => scripts.han += 1,
                c if is_hangul(c) => scripts.hangul += 1,
                _ => {}
            }
        }
        scripts
    }

    fn total(&self) -> usize {
        self.latin + self.cyrillic + self.arabic + self.kana + self.han + self.hangul
    }
}

/// Rank the likely languages of `text`, best first; empty when there are
/// too few letters to say.
pub fn identify_language(text: &str) -> Vec<LanguageGuess> {
    let scripts = Scripts::of(text);
    let total = scripts.total();
    if total < MIN_LETTERS_FOR_LANGUAGE {
        return Vec::new();
    }
    let share = |count: usize| count as f64 / total as f64;
    let script_guess = |language: Language, count: usize, script: &str| LanguageGuess { language, confidence: share(count) as f32, reason: format!("{:.0}% of letters are {script}", share(count) * 100.0) };
    let mut guesses = Vec::new();
    if scripts.kana > 0 && share(scripts.kana) >= MIN_KANA_SHARE {
        guesses.push(script_guess(Language::Japanese, scripts.kana + scripts.han, "kana or kanji"));
    } else if scripts.han > 0 {
        guesses.push(script_guess(Language::Chinese, scripts.han, "hanzi without kana"));
    }
    if scripts.hangul > 0 {
        guesses.push(script_guess(Language::Korean, scripts.hangul, "Hangul"));
    }
    if scripts.cyrillic > 0 {
        guesses.push(script_guess(Language::Russian, scripts.cyrillic, "Cyrillic"));
    }
    if scripts.arabic > 0 {
        guesses.push(script_guess(Language::Arabic, scripts.arabic, "Arabic script"));
    }
    if scripts.latin > 0 {
        let latin_share = share(scripts.latin) as f32;
        guesses.extend(latin_languages(text).into_iter().map(|guess| LanguageGuess { confidence: guess.confidence * latin_share, ..guess }));
    }
    guesses.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
    guesses
}

/// Rank Latin-script languages by stop words and distinctive letters.
fn latin_languages(text: &str) -> Vec<LanguageGuess> {
    let lower = text.to_lowercase();
    let words: Vec<&str> = lower.split(|c: char| !c.is_alphabetic()).filter(|word| !word.is_empty()).collect();
    if words.is_empty() {
        return Vec::new();
    }
    let scored: Vec<(Language, f64, usize, usize)> = LATIN_PROFILES
        .iter()
        .map(|profile| {
            let hits = words.iter().filter(|word| profile.stop_words.contains(word)).count();
            let marks = lower.chars().filter(|&c| profile.distinctive.contains(c)).count();
            (profile.language, hits as f64 + DISTINCTIVE_WEIGHT * marks as f64, hits, marks)
        })
        .filter(|(_, score, _, _)| *score > 0.0)
        .collect();
    let score_sum: f64 = scored.iter().map(|(_, score, _, _)| score).sum();
    let mut guesses: Vec<LanguageGuess> = scored
        .into_iter()
        .map(|(language, score, hits, marks)| {
            let coverage = (hits as f64 / words.len() as f64 / FULL_STOP_WORD_SHARE).min(1.0);
            let confidence = (score / score_sum) * (0.5 + 0.5 * coverage);
            LanguageGuess { language, confidence: confidence as f32, reason: format!("{hits} of {} words are common {} words; {marks} distinctive letters", words.len(), language.label()) }
        })
        .collect();
    guesses.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
    guesses
}

#[cfg(test)]
mod tests {
    use super::*;

    fn best(bytes: &[u8]) -> TextEncoding {
        rank_encodings(bytes)[0].encoding
    }

    fn utf16(text: &str, big_endian: bool) -> Vec<u8> {
        text.encode_utf16().flat_map(|unit| if big_endian { unit.to_be_bytes() } else { unit.to_le_bytes() }).collect()
    }

    fn top_language(text: &str) -> Option<Language> {
        identify_language(text).first().map(|guess| guess.language)
    }

    #[test]
    fn plain_ascii_is_ranked_ascii_first() {
        let ranked = rank_encodings(b"Plain old text, nothing more.\n");
        assert_eq!(ranked[0].encoding, TextEncoding::Ascii);
        assert!(ranked[0].confidence > 0.9);
    }

    #[test]
    fn utf8_with_accents_is_ranked_utf8_first() {
        assert_eq!(best("Le café est très chaud, déjà prêt.".as_bytes()), TextEncoding::Utf8);
    }

    #[test]
    fn latin1_accents_inside_words_are_ranked_windows_1252_first() {
        let bytes = encoding_rs::WINDOWS_1252.encode("Le café est très chaud, déjà prêt à boire.").0.into_owned();
        assert_eq!(best(&bytes), TextEncoding::Windows1252);
    }

    #[test]
    fn utf16_big_endian_without_a_bom_is_identified() {
        let ranked = rank_encodings(&utf16("Hello world, this is UTF-16 text.", true));
        assert_eq!(ranked[0].encoding, TextEncoding::Utf16Be, "{ranked:?}");
        assert!(ranked[0].preview.starts_with("Hello world"));
    }

    #[test]
    fn utf16_little_endian_with_a_bom_is_identified() {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(utf16("日本語のテキスト", false));
        let ranked = rank_encodings(&bytes);
        assert_eq!(ranked[0].encoding, TextEncoding::Utf16Le);
        assert!(ranked[0].has_bom);
    }

    #[test]
    fn hand_encoded_shift_jis_kana_is_identified_as_japanese() {
        // こんにちは、さようなら in Shift-JIS, hand-encoded.
        let bytes = [0x82, 0xB1, 0x82, 0xF1, 0x82, 0xC9, 0x82, 0xBF, 0x82, 0xCD, 0x81, 0x41, 0x82, 0xB3, 0x82, 0xE6, 0x82, 0xA4, 0x82, 0xC8, 0x82, 0xE7];
        let report = characterise_text(&bytes);
        assert_eq!(report.encodings[0].encoding, TextEncoding::ShiftJis, "{:?}", report.encodings);
        assert_eq!(decode(&bytes, TextEncoding::ShiftJis), "こんにちは、さようなら");
        assert_eq!(report.languages[0].language, Language::Japanese);
    }

    #[test]
    fn euc_kr_korean_is_identified() {
        let bytes = encoding_rs::EUC_KR.encode("대한민국은 민주공화국이다. 나는 학교에 간다.").0.into_owned();
        let report = characterise_text(&bytes);
        assert_eq!(report.encodings[0].encoding, TextEncoding::EucKr, "{:?}", report.encodings);
        assert_eq!(report.languages[0].language, Language::Korean);
    }

    #[test]
    fn gbk_chinese_is_identified() {
        let bytes = encoding_rs::GBK.encode("我们是中国人，我们在这里学习和工作。").0.into_owned();
        let report = characterise_text(&bytes);
        assert_eq!(report.encodings[0].encoding, TextEncoding::Gbk, "{:?}", report.encodings);
        assert_eq!(report.languages[0].language, Language::Chinese);
    }

    #[test]
    fn koi8_r_russian_is_identified() {
        let bytes = encoding_rs::KOI8_R.encode("Привет, мир! Это простой текст на русском языке.").0.into_owned();
        let report = characterise_text(&bytes);
        assert_eq!(report.encodings[0].encoding, TextEncoding::Koi8R, "{:?}", report.encodings);
        assert_eq!(report.languages[0].language, Language::Russian);
    }

    #[test]
    fn ebcdic_text_is_identified_and_decoded() {
        // "HELLO WORLD 123" in code page 037.
        let bytes = [0xC8, 0xC5, 0xD3, 0xD3, 0xD6, 0x40, 0xE6, 0xD6, 0xD9, 0xD3, 0xC4, 0x40, 0xF1, 0xF2, 0xF3];
        let ranked = rank_encodings(&bytes);
        assert_eq!(ranked[0].encoding, TextEncoding::Ebcdic037, "{ranked:?}");
        assert_eq!(decode(&bytes, TextEncoding::Ebcdic037), "HELLO WORLD 123");
    }

    #[test]
    fn lowercase_ebcdic_prose_with_punctuation_decodes() {
        // "a, b." then a new line.
        assert_eq!(decode(&[0x81, 0x6B, 0x40, 0x82, 0x4B, 0x15], TextEncoding::Ebcdic037), "a, b.\n");
    }

    #[test]
    fn invalid_utf8_scores_zero_for_utf8() {
        let ranked = rank_encodings(&[b'a', 0xC3, 0x28, b'b', b'c']);
        let utf8 = ranked.iter().find(|guess| guess.encoding == TextEncoding::Utf8).unwrap();
        assert_eq!(utf8.confidence, 0.0);
    }

    #[test]
    fn a_character_cut_off_at_the_end_does_not_invalidate_utf8() {
        let mut bytes = "naïve résumé".as_bytes().to_vec();
        bytes.extend_from_slice(&[0xE2, 0x82]);
        assert_eq!(best(&bytes), TextEncoding::Utf8);
    }

    #[test]
    fn binary_data_has_low_confidence_everywhere() {
        let binary: Vec<u8> = (0..4096u32).map(|index| (index.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        let ranked = rank_encodings(&binary);
        assert!(ranked[0].confidence < 0.6, "{:?}", ranked[0]);
    }

    #[test]
    fn french_and_german_sentences_are_identified() {
        assert_eq!(top_language("Le chat est sur la table et il regarde les oiseaux dans le jardin avec une grande attention."), Some(Language::French));
        assert_eq!(top_language("Der Hund ist nicht im Haus, und die Katze schläft auf dem Sofa, weil es draußen regnet."), Some(Language::German));
    }

    #[test]
    fn other_latin_languages_are_identified() {
        assert_eq!(top_language("The weather is fine and the children are playing in the garden with their friends."), Some(Language::English));
        assert_eq!(top_language("El perro está en la casa y los niños juegan en el jardín con sus amigos."), Some(Language::Spanish));
        assert_eq!(top_language("Il gatto è sulla sedia e i bambini giocano nel giardino della scuola con gli amici."), Some(Language::Italian));
        assert_eq!(top_language("O cão está em casa e as crianças não brincam no jardim com os amigos."), Some(Language::Portuguese));
        assert_eq!(top_language("De hond is in het huis en de kinderen spelen in de tuin met hun vrienden."), Some(Language::Dutch));
    }

    #[test]
    fn arabic_script_is_identified_as_arabic() {
        assert_eq!(top_language("مرحبا بالعالم هذا نص عربي بسيط"), Some(Language::Arabic));
    }

    #[test]
    fn too_few_letters_name_no_language() {
        assert!(identify_language("12 34 ok").is_empty());
    }

    #[test]
    fn empty_input_is_handled() {
        let report = characterise_text(&[]);
        assert!(report.best().is_none());
        assert!(report.languages.is_empty());
    }
}
