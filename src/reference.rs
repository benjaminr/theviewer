//! Reference notes on known formats and protocols: how the data is organised,
//! what each field means and which specification defines it.
//!
//! Entries live in TOML files under `reference/`, embedded at build time, and
//! are looked up by the names the rest of the app already uses for a format:
//! parser finding ids (`png`, `pcap`, `dns`), packet layer names
//! (`Internet Protocol version 4`), stream ids (`stream:zlib`) and MIME
//! types from the signature catalogue (`image/png`). The notes are written
//! for this project; the specifications themselves are cited by number,
//! section and link, and RFC sections can be fetched on request (see
//! [`rfc_text_url`] and [`rfc_section`]).

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

/// The embedded reference files, by name.
const SOURCES: [(&str, &str); 2] = [
    ("network.toml", include_str!("../reference/network.toml")),
    ("files.toml", include_str!("../reference/files.toml")),
];

/// Where RFC plain text is fetched from.
const RFC_TEXT_BASE: &str = "https://www.rfc-editor.org/rfc";

/// Notes on one format or protocol.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormatReference {
    /// Stable identifier, such as `ipv4`.
    pub id: String,
    /// Display name, such as "Internet Protocol version 4".
    pub name: String,
    /// Every name the app may use for this format: finding ids, layer names,
    /// stream ids and MIME types. Matched without regard to case.
    pub keys: Vec<String>,
    /// One or two sentences: what the format is for.
    pub summary: String,
    /// How the bytes are laid out, in a few short paragraphs.
    pub organisation: String,
    /// Ids of formats commonly carried inside this one.
    #[serde(default)]
    pub carries: Vec<String>,
    #[serde(default)]
    pub specs: Vec<Specification>,
    #[serde(default)]
    pub fields: Vec<FieldNote>,
}

/// A document that defines a format.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Specification {
    /// Short citation, such as "RFC 791" or "PKWARE APPNOTE 6.3.10".
    pub document: String,
    pub title: String,
    pub url: String,
    /// The RFC number, when the document is an RFC, so its text can be fetched.
    #[serde(default)]
    pub rfc: Option<u32>,
    /// The section describing the layout, such as "3.1".
    #[serde(default)]
    pub section: Option<String>,
}

/// What one field means.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldNote {
    /// The field's name as the app shows it. A trailing `*` matches any
    /// name with that prefix, for numbered fields such as "Partition 2".
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub meaning: String,
    /// Section of the first specification that defines the field.
    #[serde(default)]
    pub section: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceFile {
    #[serde(default)]
    format: Vec<FormatReference>,
}

/// Every embedded entry, with an index from lower-case key to entry.
pub struct Library {
    entries: Vec<FormatReference>,
    by_key: HashMap<String, usize>,
}

impl Library {
    /// Parse reference files. Fails on malformed TOML, a duplicate id or a
    /// key claimed by two entries, so mistakes show up in the tests.
    pub fn parse(sources: &[(&str, &str)]) -> Result<Library, String> {
        let mut entries = Vec::new();
        for (name, text) in sources {
            let file: ReferenceFile = toml::from_str(text).map_err(|error| format!("reference/{name}: {error}"))?;
            entries.extend(file.format);
        }
        let mut by_key: HashMap<String, usize> = HashMap::new();
        let mut ids = HashMap::new();
        for (index, entry) in entries.iter().enumerate() {
            if let Some(previous) = ids.insert(entry.id.clone(), index) {
                return Err(format!("reference id '{}' is used twice (entries {previous} and {index})", entry.id));
            }
            for key in entry.keys.iter().chain(std::iter::once(&entry.id)) {
                let key = key.to_lowercase();
                if let Some(&other) = by_key.get(&key)
                    && other != index
                {
                    return Err(format!("reference key '{key}' is claimed by both '{}' and '{}'", entries[other].id, entry.id));
                }
                by_key.insert(key, index);
            }
        }
        Ok(Library { entries, by_key })
    }

    pub fn entries(&self) -> &[FormatReference] {
        &self.entries
    }

    /// The entry for a finding id, layer name, stream id or MIME type.
    /// Decorations the app adds to names, such as " (malformed)", and a
    /// `signature:` prefix are ignored.
    pub fn lookup(&self, key: &str) -> Option<&FormatReference> {
        let key = normalise_key(key);
        self.by_key.get(&key).map(|&index| &self.entries[index])
    }

    pub fn by_id(&self, id: &str) -> Option<&FormatReference> {
        self.entries.iter().find(|entry| entry.id == id)
    }
}

/// The embedded library, parsed once.
pub fn library() -> &'static Library {
    static LIBRARY: OnceLock<Library> = OnceLock::new();
    LIBRARY.get_or_init(|| Library::parse(&SOURCES).unwrap_or_else(|error| panic!("embedded reference notes are invalid: {error}")))
}

/// The entry for `key` in the embedded library.
pub fn lookup(key: &str) -> Option<&'static FormatReference> {
    library().lookup(key)
}

fn normalise_key(key: &str) -> String {
    let key = key.trim();
    let key = key.strip_prefix("signature:").unwrap_or(key);
    let key = match key.rfind(" (") {
        Some(at) if key.ends_with(')') => &key[..at],
        _ => key,
    };
    key.trim().to_lowercase()
}

impl FormatReference {
    /// The note for a field called `name`, if there is one.
    pub fn field(&self, name: &str) -> Option<&FieldNote> {
        let name = name.trim();
        self.fields.iter().find(|note| note.matches(name))
    }

    /// The specification a field's section refers to: the first one listed.
    pub fn primary_spec(&self) -> Option<&Specification> {
        self.specs.first()
    }

    /// The whole entry as plain text, for the assistant's context.
    pub fn to_plain_text(&self) -> String {
        let mut text = format!("{}\n{}\n\n{}\n", self.name, self.summary, self.organisation.trim());
        if !self.specs.is_empty() {
            text.push_str("\nSpecifications:\n");
            for spec in &self.specs {
                let section = spec.section.as_deref().map(|section| format!(" §{section}")).unwrap_or_default();
                text.push_str(&format!("- {}{section}: {} <{}>\n", spec.document, spec.title, spec.url));
            }
        }
        if !self.fields.is_empty() {
            text.push_str("\nFields:\n");
            for note in &self.fields {
                text.push_str(&format!("- {}: {}\n", note.name.trim_end_matches('*').trim(), note.meaning));
            }
        }
        text
    }
}

impl FieldNote {
    fn matches(&self, name: &str) -> bool {
        std::iter::once(&self.name).chain(&self.aliases).any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => name.len() >= prefix.len() && name[..prefix.len()].eq_ignore_ascii_case(prefix),
            None => pattern.eq_ignore_ascii_case(name),
        })
    }
}

/// Where the plain text of RFC `number` can be downloaded.
pub fn rfc_text_url(number: u32) -> String {
    format!("{RFC_TEXT_BASE}/rfc{number}.txt")
}

/// Where RFC `number` can be read in a browser, at `section` if given.
pub fn rfc_html_url(number: u32, section: Option<&str>) -> String {
    match section {
        Some(section) => format!("{RFC_TEXT_BASE}/rfc{number}.html#section-{section}"),
        None => format!("{RFC_TEXT_BASE}/rfc{number}.html"),
    }
}

/// The text of `section` (such as "3.1") from an RFC's plain text, including
/// its subsections, with page headers and footers removed. `None` when the
/// heading is not found.
///
/// Section headings in RFC text start at the first column with the number,
/// a full stop and the title: `3.1.  Internet Header Format`. Older RFCs
/// leave out the trailing full stop on subsections (`3.1  Title`), so both
/// forms are accepted.
pub fn rfc_section(text: &str, section: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().filter(|line| !is_page_furniture(line)).collect();
    let start = lines.iter().position(|line| heading_number(line).is_some_and(|number| number == section))?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| heading_number(line).is_some_and(|number| !is_within(number, section)))
        .map_or(lines.len(), |offset| start + 1 + offset);
    let body = collapse_blank_lines(&lines[start..end]);
    Some(body.trim_end().to_string())
}

/// The section number a heading line starts with, such as "3.1".
fn heading_number(line: &str) -> Option<&str> {
    let first = line.chars().next()?;
    if !first.is_ascii_digit() {
        return None;
    }
    let number_end = line.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(line.len());
    let number = line[..number_end].trim_end_matches('.');
    let rest = &line[number_end..];
    // A heading has its title after at least one space; a line such as
    // "1234 bytes" in a figure would otherwise count, so require a title
    // that starts with a capital letter.
    let title = rest.trim_start();
    let spaced = rest.starts_with(' ');
    let titled = title.chars().next().is_some_and(|c| c.is_ascii_uppercase());
    (spaced && titled && !number.is_empty() && number.split('.').all(|part| !part.is_empty())).then_some(number)
}

/// Whether `number` is `section` or one of its subsections.
fn is_within(number: &str, section: &str) -> bool {
    number == section || number.strip_prefix(section).is_some_and(|rest| rest.starts_with('.'))
}

/// Page headers ("RFC 791 ... September 1981"), footers ("Postel [Page 11]")
/// and form feeds, which break up the text of older RFCs.
fn is_page_furniture(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed == "\u{c}" || trimmed.ends_with(']') && trimmed.contains("[Page ") || line.starts_with("RFC ") && line.len() > 60
}

fn collapse_blank_lines(lines: &[&str]) -> String {
    let mut out = String::new();
    let mut previous_blank = false;
    for line in lines {
        let blank = line.trim().is_empty();
        if blank && previous_blank {
            continue;
        }
        out.push_str(line.trim_end_matches('\u{c}'));
        out.push('\n');
        previous_blank = blank;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[[format]]
id = "udp"
name = "User Datagram Protocol"
keys = ["UDP", "User Datagram Protocol"]
summary = "Datagrams between ports."
organisation = "An eight-byte header, then the payload."
[[format.specs]]
document = "RFC 768"
title = "User Datagram Protocol"
url = "https://www.rfc-editor.org/rfc/rfc768"
rfc = 768
[[format.fields]]
name = "Length"
meaning = "Header plus data, in bytes."
[[format.fields]]
name = "Option *"
meaning = "One numbered option."
"#;

    fn sample() -> Library {
        Library::parse(&[("sample.toml", SAMPLE)]).unwrap()
    }

    #[test]
    fn a_layer_name_finds_its_notes_whatever_the_case_or_decoration() {
        let library = sample();
        assert_eq!(library.lookup("udp").unwrap().id, "udp");
        assert_eq!(library.lookup("User Datagram Protocol (malformed)").unwrap().id, "udp");
        assert!(library.lookup("tcp").is_none());
    }

    #[test]
    fn numbered_fields_share_one_note() {
        let library = sample();
        let udp = library.lookup("udp").unwrap();
        assert_eq!(udp.field("length").unwrap().meaning, "Header plus data, in bytes.");
        assert_eq!(udp.field("Option 3").unwrap().meaning, "One numbered option.");
        assert!(udp.field("Checksum").is_none());
    }

    #[test]
    fn a_key_claimed_twice_is_rejected() {
        let twice = format!("{SAMPLE}{}", SAMPLE.replace("id = \"udp\"", "id = \"udp2\""));
        let error = Library::parse(&[("twice.toml", &twice)]).err().unwrap();
        assert!(error.contains("claimed by both"), "{error}");
    }

    #[test]
    fn the_embedded_notes_load_and_cite_well_formed_links() {
        let library = library();
        assert!(!library.entries().is_empty());
        for entry in library.entries() {
            assert!(!entry.summary.trim().is_empty(), "{} has no summary", entry.id);
            assert!(!entry.organisation.trim().is_empty(), "{} has no organisation", entry.id);
            for spec in &entry.specs {
                assert!(spec.url.starts_with("https://"), "{}: {}", entry.id, spec.url);
            }
            for carried in &entry.carries {
                assert!(library.by_id(carried).is_some(), "{} carries unknown '{carried}'", entry.id);
            }
        }
    }

    const RFC_TEXT: &str = "\
3.  SPECIFICATION

3.1.  Internet Header Format

  A summary of the contents of the internet header follows:

    0                   1
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5

Postel                                                         [Page 11]
\u{c}
RFC 791                                                   September 1981
                                                Internet Protocol

  Version:  4 bits

3.1.1.  Subsection

  Detail.

3.2.  Discussion

  Next.
";

    #[test]
    fn an_rfc_section_is_cut_out_with_its_subsections_and_without_page_breaks() {
        let section = rfc_section(RFC_TEXT, "3.1").unwrap();
        assert!(section.starts_with("3.1.  Internet Header Format"), "{section}");
        assert!(section.contains("Version:  4 bits"));
        assert!(section.contains("3.1.1.  Subsection"));
        assert!(!section.contains("[Page 11]"));
        assert!(!section.contains("September 1981"));
        assert!(!section.contains("Discussion"));
        assert!(rfc_section(RFC_TEXT, "9.9").is_none());
    }

    #[test]
    fn rfc_links_point_at_the_rfc_editor() {
        assert_eq!(rfc_text_url(791), "https://www.rfc-editor.org/rfc/rfc791.txt");
        assert_eq!(rfc_html_url(791, Some("3.1")), "https://www.rfc-editor.org/rfc/rfc791.html#section-3.1");
    }
}
