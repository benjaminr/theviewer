//! Small helpers for text shown to people.

/// `text` cut to its first `max_chars` characters with "…" added, or
/// whole when it is no longer than that.
pub fn truncate_chars(text: &str, max_chars: usize) -> String {
    match text.char_indices().nth(max_chars) {
        Some((cut_at, _)) => format!("{}…", &text[..cut_at]),
        None => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_text_is_cut_at_a_character_and_marked_as_cut() {
        assert_eq!(truncate_chars("héllo wörld", 5), "héllo…");
        assert_eq!(truncate_chars("héllo", 5), "héllo", "text at the limit is kept whole");
        assert_eq!(truncate_chars("", 0), "");
    }
}
