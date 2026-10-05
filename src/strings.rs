//! String extraction in ASCII, UTF-8 and UTF-16 (both byte orders), with
//! tags for the strings most worth a reverse engineer's attention.

use rayon::prelude::*;

/// Text encodings the extractor looks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Encoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Encoding {
    pub const ALL: [Encoding; 4] = [Encoding::Ascii, Encoding::Utf8, Encoding::Utf16Le, Encoding::Utf16Be];

    pub fn label(self) -> &'static str {
        match self {
            Encoding::Ascii => "ASCII",
            Encoding::Utf8 => "UTF-8",
            Encoding::Utf16Le => "UTF-16LE",
            Encoding::Utf16Be => "UTF-16BE",
        }
    }
}

/// A string found in the data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundString {
    /// Document offset of the first byte.
    pub offset: usize,
    pub len_bytes: usize,
    pub encoding: Encoding,
    pub text: String,
}

impl FoundString {
    pub fn end(&self) -> usize {
        self.offset + self.len_bytes
    }
}

/// Bytes each parallel task scans.
const CHUNK: usize = 1024 * 1024;
/// Longest string kept whole; longer runs are split.
const MAX_STRING_BYTES: usize = 64 * 1024;

/// Find strings of at least `min_chars` characters in the chosen encodings.
/// `base` is the document offset of `bytes[0]`. Results are sorted by
/// offset, a UTF-16 run is not also reported as ASCII fragments, and at most
/// `max_results` are returned.
pub fn extract(bytes: &[u8], base: usize, min_chars: usize, encodings: &[Encoding], max_results: usize) -> Vec<FoundString> {
    extract_with_chunk(bytes, base, min_chars, encodings, max_results, CHUNK)
}

/// [`extract`] with a chosen chunk size, so tests can cross chunk boundaries.
pub(crate) fn extract_with_chunk(bytes: &[u8], base: usize, min_chars: usize, encodings: &[Encoding], max_results: usize, chunk: usize) -> Vec<FoundString> {
    let min_chars = min_chars.max(1);
    let chunk = chunk.max(16);
    // Each task owns the strings that START in its chunk, and may read past
    // the chunk's end to finish them, so boundary strings come out whole once.
    let starts: Vec<usize> = (0..bytes.len()).step_by(chunk).collect();
    let mut found: Vec<FoundString> = starts
        .par_iter()
        .flat_map_iter(|&start| {
            let end = (start + chunk).min(bytes.len());
            let mut local = Vec::new();
            for &encoding in encodings {
                match encoding {
                    Encoding::Ascii | Encoding::Utf8 => {
                        if encodings.contains(&Encoding::Ascii) && encoding == Encoding::Utf8 {
                            // One pass reports both; avoid scanning twice.
                            continue;
                        }
                        scan_byte_text(bytes, start, end, min_chars, encodings, &mut local);
                    }
                    Encoding::Utf16Le => scan_utf16(bytes, start, end, min_chars, false, &mut local),
                    Encoding::Utf16Be => scan_utf16(bytes, start, end, min_chars, true, &mut local),
                }
            }
            local
        })
        .collect();
    found.sort_by_key(|s| (s.offset, std::cmp::Reverse(s.len_bytes)));
    let found = remove_overlaps(found);
    found
        .into_iter()
        .take(max_results)
        .map(|mut s| {
            s.offset += base;
            s
        })
        .collect()
}

/// Is this ASCII byte part of a printable run?
fn printable_ascii(byte: u8) -> bool {
    (0x20..0x7F).contains(&byte) || byte == b'\t'
}

/// ASCII and UTF-8 runs that start in `start..end`. A run with a valid
/// multi-byte character is UTF-8 (when asked for); otherwise ASCII.
fn scan_byte_text(bytes: &[u8], start: usize, end: usize, min_chars: usize, encodings: &[Encoding], out: &mut Vec<FoundString>) {
    let want_ascii = encodings.contains(&Encoding::Ascii);
    let want_utf8 = encodings.contains(&Encoding::Utf8);
    // Begin at a run boundary so a run straddling `start` belongs to the previous chunk.
    let mut at = start;
    if start > 0 {
        while at < end && text_char_len(bytes, at, want_utf8).is_some() && text_char_len(bytes, at - 1, want_utf8).is_some() {
            at += 1;
        }
    }
    while at < end {
        let Some(_) = text_char_len(bytes, at, want_utf8) else {
            at += 1;
            continue;
        };
        let run_start = at;
        let mut chars = 0;
        let mut multibyte = false;
        while at < bytes.len() && at - run_start < MAX_STRING_BYTES {
            match text_char_len(bytes, at, want_utf8) {
                Some(width) => {
                    multibyte |= width > 1;
                    chars += 1;
                    at += width;
                }
                None => break,
            }
        }
        if chars >= min_chars {
            let slice = &bytes[run_start..at];
            let encoding = if multibyte { Encoding::Utf8 } else { Encoding::Ascii };
            let wanted = (encoding == Encoding::Utf8 && want_utf8) || (encoding == Encoding::Ascii && want_ascii);
            if wanted {
                out.push(FoundString { offset: run_start, len_bytes: slice.len(), encoding, text: String::from_utf8_lossy(slice).into_owned() });
            }
        }
        if at == run_start {
            at += 1;
        }
    }
}

/// Width of a printable character at `at`: 1 for ASCII, 2–4 for a valid,
/// printable UTF-8 sequence (when allowed), `None` otherwise.
fn text_char_len(bytes: &[u8], at: usize, utf8: bool) -> Option<usize> {
    let byte = *bytes.get(at)?;
    if printable_ascii(byte) {
        return Some(1);
    }
    if !utf8 || byte < 0xC2 {
        return None;
    }
    let width = match byte {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let sequence = bytes.get(at..at + width)?;
    let character = std::str::from_utf8(sequence).ok()?.chars().next()?;
    (!character.is_control()).then_some(width)
}

/// Is this UTF-16 code unit plausible text? Printable ASCII and tab, plus
/// letters in Latin-1, Latin Extended, Greek and Cyrillic (up to U+052F).
/// CJK and other scripts are left out on purpose: two arbitrary ASCII bytes
/// read as one code unit are almost always a valid CJK character, which would
/// glue unrelated text into nonsense strings (the same trade-off `strings -el`
/// makes). Surrogates and controls are rejected.
fn printable_utf16(unit: u16) -> bool {
    match unit {
        0x09 | 0x20..=0x7E => true,
        0xA0..=0x52F => char::from_u32(unit as u32).is_some_and(|c| c.is_alphanumeric() || c.is_ascii_punctuation() || c == '\u{A0}'),
        _ => false,
    }
}

fn scan_utf16(bytes: &[u8], start: usize, end: usize, min_chars: usize, big_endian: bool, out: &mut Vec<FoundString>) {
    let unit_at = |at: usize| -> Option<u16> {
        let pair = bytes.get(at..at + 2)?;
        Some(if big_endian { u16::from_be_bytes([pair[0], pair[1]]) } else { u16::from_le_bytes([pair[0], pair[1]]) })
    };
    let printable_at = |at: usize| unit_at(at).is_some_and(printable_utf16);
    // Try both alignments; a run starts where the previous unit is not printable.
    for phase in 0..2 {
        let mut at = start + phase;
        while at < end {
            // Runs are consumed whole below, so a printable unit preceded by
            // another one can only be the tail of a run from the previous chunk.
            if !printable_at(at) || (at >= 2 && printable_at(at - 2)) {
                at += 2;
                continue;
            }
            let run_start = at;
            let mut units = Vec::new();
            while at - run_start < MAX_STRING_BYTES {
                match unit_at(at) {
                    Some(unit) if printable_utf16(unit) => {
                        units.push(unit);
                        at += 2;
                    }
                    _ => break,
                }
            }
            // Trim non-ASCII units at the edges: a string read one byte out of
            // alignment (big-endian text read as little-endian) gains a stray
            // Latin-1 character such as 'ÿ' from neighbouring padding.
            let leading = units.iter().take_while(|&&u| u >= 0x80).count();
            let trailing = units[leading..].iter().rev().take_while(|&&u| u >= 0x80).count();
            let units = &units[leading..units.len() - trailing];
            let run_start = run_start + leading * 2;
            if units.len() >= min_chars {
                out.push(FoundString {
                    offset: run_start,
                    len_bytes: units.len() * 2,
                    encoding: if big_endian { Encoding::Utf16Be } else { Encoding::Utf16Le },
                    text: String::from_utf16_lossy(units),
                });
            }
        }
    }
}

/// Keep the longest of overlapping strings (input sorted by offset, longest first).
fn remove_overlaps(sorted: Vec<FoundString>) -> Vec<FoundString> {
    let mut kept: Vec<FoundString> = Vec::with_capacity(sorted.len());
    for candidate in sorted {
        match kept.last() {
            Some(last) if candidate.offset < last.end() => {
                if candidate.len_bytes > last.len_bytes {
                    kept.pop();
                    kept.push(candidate);
                }
            }
            _ => kept.push(candidate),
        }
    }
    kept
}

/// Tag a string that is likely to matter. Cheap checks, no regex.
pub fn classify(text: &str) -> Option<&'static str> {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    if ["http://", "https://", "ftp://", "ws://", "wss://", "file://"].iter().any(|p| lower.contains(p)) {
        return Some("URL");
    }
    if is_uuid(trimmed) {
        return Some("UUID");
    }
    if is_email(trimmed) {
        return Some("email");
    }
    if is_ipv4(trimmed) {
        return Some("IPv4");
    }
    if ["select ", "insert into ", "update ", "delete from ", "create table ", "drop table "].iter().any(|k| lower.starts_with(k)) {
        return Some("SQL");
    }
    if ["%s", "%d", "%x", "%u", "%p", "%f", "%02x", "%08x", "%lu", "%ld", "{}"].iter().any(|f| trimmed.contains(f)) {
        return Some("format string");
    }
    if is_path(trimmed) {
        return Some("path");
    }
    if is_version(trimmed) {
        return Some("version");
    }
    if is_key_value(trimmed) {
        return Some("key/value");
    }
    if trimmed.len() >= 16 && trimmed.len().is_multiple_of(2) && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some("hex-like");
    }
    if is_base64_like(trimmed) {
        return Some("base64-like");
    }
    None
}

fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups.iter().all(|g| g.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_email(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else { return false };
    !local.is_empty()
        && !text.contains(' ')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && local.chars().all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || ".-".contains(c))
}

fn is_ipv4(text: &str) -> bool {
    let address = text.split(':').next().unwrap_or(text);
    let parts: Vec<&str> = address.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
}

fn is_path(text: &str) -> bool {
    if text.contains(' ') && !text.starts_with('/') && !text.contains(":\\") {
        return false;
    }
    let unix = text.starts_with('/') && text.len() > 1 && text[1..].contains('/') || text.starts_with("./") || text.starts_with("../") || text.starts_with("~/");
    let windows = text.len() > 3 && text.as_bytes()[1] == b':' && (text.as_bytes()[2] == b'\\' || text.as_bytes()[2] == b'/') || text.starts_with("\\\\");
    unix || windows
}

fn is_version(text: &str) -> bool {
    let core = text.trim_start_matches(['v', 'V']);
    let digits_end = core.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(core.len());
    let number = &core[..digits_end];
    let parts: Vec<&str> = number.split('.').collect();
    (2..=4).contains(&parts.len()) && parts.iter().all(|p| !p.is_empty() && p.len() <= 5) && digits_end >= 3
        && (digits_end == core.len() || core[digits_end..].starts_with(['-', '+', ' ']))
}

fn is_key_value(text: &str) -> bool {
    let Some((key, value)) = text.split_once(['=', ':']) else { return false };
    let key = key.trim();
    !key.is_empty()
        && key.len() <= 40
        && !value.trim().is_empty()
        && key.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
        && key.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
}

fn is_base64_like(text: &str) -> bool {
    if text.len() < 20 {
        return false;
    }
    let body = text.trim_end_matches('=');
    let valid = body.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '-' || c == '_');
    let has_upper = body.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = body.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = body.chars().any(|c| c.is_ascii_digit());
    valid && has_upper && has_lower && has_digit && text.len().is_multiple_of(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(text: &str, big_endian: bool) -> Vec<u8> {
        text.encode_utf16().flat_map(|u| if big_endian { u.to_be_bytes() } else { u.to_le_bytes() }).collect()
    }

    fn sample() -> (Vec<u8>, [usize; 4]) {
        let mut bytes = vec![0u8; 8];
        let ascii_at = bytes.len();
        bytes.extend_from_slice(b"Hello, plain text");
        bytes.extend_from_slice(&[0, 1, 2]);
        let utf8_at = bytes.len();
        bytes.extend_from_slice("café crème".as_bytes());
        bytes.extend_from_slice(&[0, 0, 0xFF]);
        let le_at = bytes.len();
        bytes.extend_from_slice(&utf16("Configuration", false));
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        let be_at = bytes.len();
        bytes.extend_from_slice(&utf16("BigEndianText", true));
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        (bytes, [ascii_at, utf8_at, le_at, be_at])
    }

    #[test]
    fn finds_each_encoding_at_its_offset() {
        let (bytes, [ascii_at, utf8_at, le_at, be_at]) = sample();
        let found = extract(&bytes, 1000, 6, &Encoding::ALL, 100);
        let find = |encoding| found.iter().find(|s| s.encoding == encoding).unwrap_or_else(|| panic!("{encoding:?} in {found:?}"));
        assert_eq!((find(Encoding::Ascii).offset, find(Encoding::Ascii).text.as_str()), (1000 + ascii_at, "Hello, plain text"));
        assert_eq!((find(Encoding::Utf8).offset, find(Encoding::Utf8).text.as_str()), (1000 + utf8_at, "café crème"));
        assert_eq!((find(Encoding::Utf16Le).offset, find(Encoding::Utf16Le).text.as_str()), (1000 + le_at, "Configuration"));
        assert_eq!((find(Encoding::Utf16Be).offset, find(Encoding::Utf16Be).text.as_str()), (1000 + be_at, "BigEndianText"));
        // The UTF-16 runs are not also reported as single-letter ASCII fragments.
        assert_eq!(found.len(), 4, "{found:?}");
        assert!(found.windows(2).all(|w| w[0].offset <= w[1].offset));
    }

    #[test]
    fn minimum_length_and_result_cap_are_respected() {
        let (bytes, _) = sample();
        let found = extract(&bytes, 0, 14, &Encoding::ALL, 100);
        assert!(found.iter().all(|s| s.text.chars().count() >= 14), "{found:?}");
        assert_eq!(extract(&bytes, 0, 4, &Encoding::ALL, 2).len(), 2);
        assert!(extract(&[], 0, 4, &Encoding::ALL, 10).is_empty());
        let ascii_only = extract(&bytes, 0, 6, &[Encoding::Ascii], 100);
        assert!(ascii_only.iter().all(|s| s.encoding == Encoding::Ascii));
    }

    #[test]
    fn strings_spanning_chunk_boundaries_come_out_whole_and_once() {
        let mut bytes = vec![0u8; 50];
        bytes.extend_from_slice(b"this string crosses the chunk boundary");
        bytes.extend_from_slice(&[0u8; 30]);
        bytes.extend_from_slice(&utf16("wide string across", false));
        bytes.extend_from_slice(&[0u8; 40]);
        let found = extract_with_chunk(&bytes, 0, 6, &Encoding::ALL, 100, 64);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].text, "this string crosses the chunk boundary");
        assert_eq!(found[1].text, "wide string across");
    }

    #[test]
    fn interesting_strings_are_tagged() {
        assert_eq!(classify("https://example.com/api"), Some("URL"));
        assert_eq!(classify("ops@example.co.uk"), Some("email"));
        assert_eq!(classify("/usr/lib/libssl.so.3"), Some("path"));
        assert_eq!(classify("C:\\Windows\\System32\\kernel32.dll"), Some("path"));
        assert_eq!(classify("192.168.1.20"), Some("IPv4"));
        assert_eq!(classify("v2.14.3"), Some("version"));
        assert_eq!(classify("baud_rate=115200"), Some("key/value"));
        assert_eq!(classify("error %d at %s"), Some("format string"));
        assert_eq!(classify("SGVsbG8gV29ybGQgZnJvbSBiYXNlNjQ="), Some("base64-like"));
        assert_eq!(classify("deadbeefcafebabe0011"), Some("hex-like"));
        assert_eq!(classify("123e4567-e89b-12d3-a456-426614174000"), Some("UUID"));
        assert_eq!(classify("SELECT id FROM users"), Some("SQL"));
        assert_eq!(classify("just some words"), None);
    }
}
