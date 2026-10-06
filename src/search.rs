//! Byte, text and value search over the whole document.

use crate::document::Document;

/// How the search box text is interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchMode {
    Hex,
    Text,
    TextUtf16,
    Integer,
}

impl SearchMode {
    pub const ALL: [SearchMode; 4] = [SearchMode::Hex, SearchMode::Text, SearchMode::TextUtf16, SearchMode::Integer];

    pub fn label(self) -> &'static str {
        match self {
            SearchMode::Hex => "Hex",
            SearchMode::Text => "Text",
            SearchMode::TextUtf16 => "UTF-16",
            SearchMode::Integer => "Integer",
        }
    }
}

/// Turn the typed query into the byte needle to look for.
pub fn needle_for(mode: SearchMode, query: &str, little_endian: bool) -> Result<Vec<u8>, String> {
    match mode {
        SearchMode::Hex => crate::ops::parse_hex(query).filter(|b| !b.is_empty()).ok_or_else(|| "Type hex bytes, e.g. DE AD BE EF".to_string()),
        SearchMode::Text => {
            if query.is_empty() {
                Err("Type some text".to_string())
            } else {
                Ok(query.as_bytes().to_vec())
            }
        }
        SearchMode::TextUtf16 => {
            if query.is_empty() {
                return Err("Type some text".to_string());
            }
            Ok(query.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect())
        }
        SearchMode::Integer => {
            let value: i128 = if let Some(hex) = query.trim().strip_prefix("0x") {
                i128::from_str_radix(hex, 16).map_err(|_| "Not a number".to_string())?
            } else {
                query.trim().parse().map_err(|_| "Type a decimal or 0x hex integer".to_string())?
            };
            // Smallest width that holds the value, matching how it would be stored.
            let bytes: Vec<u8> = if (-128..=255).contains(&value) {
                vec![value as u8]
            } else if (-32_768..=65_535).contains(&value) {
                let v = value as u16;
                if little_endian { v.to_le_bytes().to_vec() } else { v.to_be_bytes().to_vec() }
            } else if (-2_147_483_648..=4_294_967_295).contains(&value) {
                let v = value as u32;
                if little_endian { v.to_le_bytes().to_vec() } else { v.to_be_bytes().to_vec() }
            } else {
                let v = value as u64;
                if little_endian { v.to_le_bytes().to_vec() } else { v.to_be_bytes().to_vec() }
            };
            Ok(bytes)
        }
    }
}

const CHUNK: usize = 4 * 1024 * 1024;

/// Offset of the first occurrence of `needle` at or after `from`, searching
/// the document in chunks that overlap by the needle length.
pub fn find_next(document: &mut Document, needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || document.len() < needle.len() {
        return None;
    }
    let finder = memchr_like::Finder::new(needle);
    let mut start = from.min(document.len());
    while start + needle.len() <= document.len() {
        let len = CHUNK.min(document.len() - start);
        let chunk = document.read_range(start, len);
        if let Some(position) = finder.find(&chunk) {
            return Some(start + position);
        }
        if start + len >= document.len() {
            break;
        }
        start += len - (needle.len() - 1);
    }
    None
}

/// Offset of the last occurrence of `needle` that starts strictly before
/// `before`. It may overlap `before`, so stepping back from one match finds
/// the overlapping match just before it.
pub fn find_previous(document: &mut Document, needle: &[u8], before: usize) -> Option<usize> {
    if needle.is_empty() || document.len() < needle.len() {
        return None;
    }
    let finder = memchr_like::Finder::new(needle);
    // A match starting at `before - 1` ends `needle.len() - 1` bytes past it.
    let mut end = (before + needle.len() - 1).min(document.len());
    while end >= needle.len() {
        let start = end.saturating_sub(CHUNK);
        let chunk = document.read_range(start, end - start);
        if let Some(position) = finder.rfind(&chunk) {
            return Some(start + position);
        }
        if start == 0 {
            break;
        }
        end = start + needle.len() - 1;
    }
    None
}

/// Count occurrences in the whole document (capped so huge files stay quick).
pub fn count_matches(document: &mut Document, needle: &[u8], cap: usize) -> usize {
    let mut count = 0;
    let mut from = 0;
    while let Some(at) = find_next(document, needle, from) {
        count += 1;
        if count >= cap {
            break;
        }
        from = at + 1;
    }
    count
}

/// Every offset in `haystack` where `needle` starts, overlapping matches
/// included, up to `cap` of them.
pub fn find_all(haystack: &[u8], needle: &[u8], cap: usize) -> Vec<usize> {
    let mut found = Vec::new();
    if needle.is_empty() {
        return found;
    }
    let finder = memchr_like::Finder::new(needle);
    let mut from = 0;
    while found.len() < cap
        && from < haystack.len()
        && let Some(position) = finder.find(&haystack[from..])
    {
        found.push(from + position);
        from += position + 1;
    }
    found
}

/// A small substring finder; the needle is short and the haystack chunked, so
/// a first-byte scan with a comparison is plenty fast.
mod memchr_like {
    pub struct Finder<'a> {
        needle: &'a [u8],
    }

    impl<'a> Finder<'a> {
        pub fn new(needle: &'a [u8]) -> Self {
            Finder { needle }
        }

        pub fn find(&self, haystack: &[u8]) -> Option<usize> {
            let first = self.needle[0];
            let mut position = 0;
            while position + self.needle.len() <= haystack.len() {
                {
                    let offset = haystack[position..].iter().position(|&b| b == first)?;
                    let candidate = position + offset;
                    if haystack[candidate..].starts_with(self.needle) {
                        return Some(candidate);
                    }
                    position = candidate + 1;
                }
            }
            None
        }

        pub fn rfind(&self, haystack: &[u8]) -> Option<usize> {
            if haystack.len() < self.needle.len() {
                return None;
            }
            (0..=haystack.len() - self.needle.len()).rev().find(|&at| haystack[at..].starts_with(self.needle))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_hex_text_and_integer_needles() {
        let mut document = Document::from_bytes(b"xxDEADxx\xDE\xAD\xBE\xEFxx\x2A\x00\x00\x00".to_vec());
        assert_eq!(find_next(&mut document, &needle_for(SearchMode::Text, "DEAD", true).unwrap(), 0), Some(2));
        assert_eq!(find_next(&mut document, &needle_for(SearchMode::Hex, "DE AD BE EF", true).unwrap(), 0), Some(8));
        assert_eq!(find_next(&mut document, &needle_for(SearchMode::Integer, "42", true).unwrap(), 0), Some(14));
        assert_eq!(needle_for(SearchMode::Integer, "0x1234", true).unwrap(), vec![0x34, 0x12]);
        assert_eq!(needle_for(SearchMode::Integer, "0x1234", false).unwrap(), vec![0x12, 0x34]);
        assert_eq!(needle_for(SearchMode::TextUtf16, "A", true).unwrap(), vec![0x41, 0x00]);
    }

    #[test]
    fn next_and_previous_wrap_the_cursor_correctly() {
        let mut document = Document::from_bytes(b"ab-ab-ab".to_vec());
        let needle = b"ab";
        assert_eq!(find_next(&mut document, needle, 0), Some(0));
        assert_eq!(find_next(&mut document, needle, 1), Some(3));
        assert_eq!(find_next(&mut document, needle, 7), None);
        assert_eq!(find_previous(&mut document, needle, 8), Some(6));
        assert_eq!(find_previous(&mut document, needle, 6), Some(3));
        assert_eq!(find_previous(&mut document, needle, 1), Some(0));
        assert_eq!(find_previous(&mut document, needle, 0), None);
        assert_eq!(count_matches(&mut document, needle, 100), 3);
    }

    #[test]
    fn find_previous_steps_back_through_overlapping_matches() {
        let mut document = Document::from_bytes(b"AAAAAA".to_vec());
        let needle = b"AAAA";
        assert_eq!(find_previous(&mut document, needle, 2), Some(1));
        assert_eq!(find_previous(&mut document, needle, 1), Some(0));
        assert_eq!(find_previous(&mut document, needle, 6), Some(2));
    }

    #[test]
    fn matches_spanning_chunk_boundaries_are_found() {
        let mut bytes = vec![0u8; CHUNK + 10];
        bytes[CHUNK - 2..CHUNK + 2].copy_from_slice(b"NEED");
        let mut document = Document::from_bytes(bytes);
        assert_eq!(find_next(&mut document, b"NEED", 0), Some(CHUNK - 2));
        assert_eq!(find_previous(&mut document, b"NEED", CHUNK + 10), Some(CHUNK - 2));
    }

    #[test]
    fn find_all_lists_every_match_including_overlaps_up_to_the_cap() {
        assert_eq!(find_all(b"ab-ab-ab", b"ab", 10), vec![0, 3, 6]);
        assert_eq!(find_all(b"AAAA", b"AA", 10), vec![0, 1, 2]);
        assert_eq!(find_all(b"AAAA", b"AA", 2), vec![0, 1]);
        assert!(find_all(b"abc", b"", 10).is_empty());
    }
}
