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
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;

/// The embedded reference files, by name.
const SOURCES: [(&str, &str); 5] = [
    ("network.toml", include_str!("../reference/network.toml")),
    ("network-infrastructure.toml", include_str!("../reference/network-infrastructure.toml")),
    ("network-applications.toml", include_str!("../reference/network-applications.toml")),
    ("files.toml", include_str!("../reference/files.toml")),
    ("files-catalogue.toml", include_str!("../reference/files-catalogue.toml")),
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
    /// A heading to list the entry under when browsing, such as "Routing"
    /// or "Industrial control".
    #[serde(default)]
    pub group: Option<String>,
    /// Transport ports the protocol is registered on or commonly found on,
    /// as `tcp/502`, `udp/53` or `sctp/2905`, so a payload that is not
    /// dissected can be named by its port.
    #[serde(default)]
    pub ports: Vec<String>,
    /// EtherTypes that announce this protocol in an Ethernet frame.
    #[serde(default)]
    pub ethertypes: Vec<u16>,
    /// IP protocol numbers that announce this protocol in an IP header.
    #[serde(default)]
    pub ip_protocols: Vec<u8>,
    #[serde(default)]
    pub specs: Vec<Specification>,
    #[serde(default)]
    pub fields: Vec<FieldNote>,
}

/// A transport the ports of [`FormatReference::ports`] belong to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
    Sctp,
}

impl Transport {
    pub fn name(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
            Transport::Sctp => "sctp",
        }
    }
}

/// Parse `tcp/502` into its transport and port.
pub fn parse_port(text: &str) -> Option<(Transport, u16)> {
    let (transport, port) = text.trim().split_once('/')?;
    let transport = match transport.to_ascii_lowercase().as_str() {
        "tcp" => Transport::Tcp,
        "udp" => Transport::Udp,
        "sctp" => Transport::Sctp,
        _ => return None,
    };
    Some((transport, port.parse().ok()?))
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

/// Every embedded entry, with indexes from lower-case key, port, EtherType
/// and IP protocol number to entries.
pub struct Library {
    entries: Vec<FormatReference>,
    by_key: HashMap<String, usize>,
    by_port: HashMap<(Transport, u16), Vec<usize>>,
    by_ethertype: HashMap<u16, Vec<usize>>,
    by_ip_protocol: HashMap<u8, Vec<usize>>,
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
        let mut by_port: HashMap<(Transport, u16), Vec<usize>> = HashMap::new();
        let mut by_ethertype: HashMap<u16, Vec<usize>> = HashMap::new();
        let mut by_ip_protocol: HashMap<u8, Vec<usize>> = HashMap::new();
        for (index, entry) in entries.iter().enumerate() {
            for text in &entry.ports {
                let port = parse_port(text).ok_or_else(|| format!("reference '{}' lists port '{text}'; write ports as tcp/N, udp/N or sctp/N", entry.id))?;
                by_port.entry(port).or_default().push(index);
            }
            for &ethertype in &entry.ethertypes {
                by_ethertype.entry(ethertype).or_default().push(index);
            }
            for &protocol in &entry.ip_protocols {
                by_ip_protocol.entry(protocol).or_default().push(index);
            }
        }
        Ok(Library { entries, by_key, by_port, by_ethertype, by_ip_protocol })
    }

    /// Entries registered on, or commonly found on, a transport port.
    pub fn by_port(&self, transport: Transport, port: u16) -> Vec<&FormatReference> {
        self.by_port.get(&(transport, port)).map_or_else(Vec::new, |indexes| indexes.iter().map(|&index| &self.entries[index]).collect())
    }

    /// Entries an EtherType announces.
    pub fn by_ethertype(&self, ethertype: u16) -> Vec<&FormatReference> {
        self.by_ethertype.get(&ethertype).map_or_else(Vec::new, |indexes| indexes.iter().map(|&index| &self.entries[index]).collect())
    }

    /// Entries an IP protocol number announces.
    pub fn by_ip_protocol(&self, protocol: u8) -> Vec<&FormatReference> {
        self.by_ip_protocol.get(&protocol).map_or_else(Vec::new, |indexes| indexes.iter().map(|&index| &self.entries[index]).collect())
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

    /// The entry for a finding: by its id, else by its title. Findings that
    /// share one id across formats (every compressed stream is
    /// `compressed-streams`) name the format only in the title, such as
    /// "gzip stream" or "ext4 superblock".
    pub fn lookup_finding(&self, id: &str, title: &str) -> Option<&FormatReference> {
        self.lookup(id).or_else(|| if title.trim().is_empty() { None } else { self.lookup(title) })
    }

    pub fn by_id(&self, id: &str) -> Option<&FormatReference> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    /// An entry's notes as plain text for the assistant, looked up by id or
    /// any of its keys; when nothing matches, the ids that are known.
    pub fn describe_for_assistant(&self, name: &str) -> String {
        match self.lookup(name) {
            Some(entry) => entry.to_plain_text(),
            None => {
                let ids: Vec<&str> = self.entries.iter().map(|entry| entry.id.as_str()).collect();
                format!("No reference notes for '{}'. Known ids: {}.", name.trim(), ids.join(", "))
            }
        }
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

/// The entry for a finding, by id or else title, in the embedded library.
pub fn lookup_finding(id: &str, title: &str) -> Option<&'static FormatReference> {
    library().lookup_finding(id, title)
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

    /// Where a field is defined, such as "RFC 791 §3.1": the primary
    /// specification, at the field's own section or else the entry's.
    pub fn citation(&self, note: &FieldNote) -> Option<String> {
        let spec = self.primary_spec()?;
        Some(match note.section.as_deref().or(spec.section.as_deref()) {
            Some(section) => format!("{} §{section}", spec.document),
            None => spec.document.clone(),
        })
    }

    /// What a field means, with its citation on a line of its own, for
    /// tooltips wherever the field is shown.
    pub fn explain_field(&self, name: &str) -> Option<String> {
        let note = self.field(name)?;
        Some(match self.citation(note) {
            Some(citation) => format!("{}\n\n{citation}", note.meaning),
            None => note.meaning.clone(),
        })
    }

    /// A short name for breadcrumbs, such as "UDP" for "User Datagram
    /// Protocol": the shortest key written with a capital letter that is not
    /// a MIME type or stream id.
    pub fn short_name(&self) -> &str {
        self.keys
            .iter()
            .filter(|key| key.chars().any(|c| c.is_ascii_uppercase()) && !key.contains(['/', ':']))
            .min_by_key(|key| key.len())
            .map_or(self.name.as_str(), String::as_str)
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

/// Where fetched RFC text is kept: `$HOME/.cache/theviewer/rfc`.
pub fn rfc_cache_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache/theviewer/rfc"))
}

/// The plain text of RFC `number`, from the cache in `cache_dir` when it is
/// there, otherwise from `fetch` (given the download URL), which is then
/// cached. Only called when the user asks for an RFC's text.
pub fn load_rfc_text(cache_dir: Option<&Path>, number: u32, fetch: impl FnOnce(&str) -> Result<String, String>) -> Result<String, String> {
    let cached = cache_dir.map(|dir| dir.join(format!("rfc{number}.txt")));
    if let Some(text) = cached.as_ref().and_then(|path| std::fs::read_to_string(path).ok()).filter(|text| !text.trim().is_empty()) {
        return Ok(text);
    }
    let text = fetch(&rfc_text_url(number))?;
    if let Some(path) = &cached {
        // A cache that cannot be written only means fetching again next time.
        let _ = path.parent().map(std::fs::create_dir_all);
        let _ = std::fs::write(path, &text);
    }
    Ok(text)
}

/// The text of `section` (such as "3.1") from an RFC's plain text, including
/// its subsections, with page headers and footers removed. `None` when the
/// heading is not found.
///
/// Section headings in RFC text start at the first column with the number,
/// a full stop and the title: `3.1.  Internet Header Format`. Older RFCs
/// leave out the trailing full stop on subsections (`3.1  Title`) or indent
/// subsections by up to three spaces (`   2.2. Data format`), so those forms
/// are accepted too.
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

/// Deepest indent of a subsection heading in older RFCs.
const MAX_HEADING_INDENT: usize = 3;

/// The section number a heading line starts with, such as "3.1".
fn heading_number(line: &str) -> Option<&str> {
    let unindented = line.trim_start_matches(' ');
    let indent = line.len() - unindented.len();
    if !unindented.starts_with(|c: char| c.is_ascii_digit()) || indent > MAX_HEADING_INDENT || is_contents_line(line) {
        return None;
    }
    let number_end = unindented.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(unindented.len());
    let written = &unindented[..number_end];
    let number = written.trim_end_matches('.');
    if number.is_empty() || !number.split('.').all(|part| !part.is_empty()) {
        return None;
    }
    // Indented numbers are headings only for subsections ("2.2"): indented
    // "1." starts an item of a numbered list in body text.
    if indent > 0 && !number.contains('.') {
        return None;
    }
    // A heading has its title after at least one space. Figures hold lines
    // such as "1234 bytes", so a title in lower case (RFC 5280's
    // "4.1.1.2.  signatureAlgorithm") counts only after a number ending in
    // a full stop.
    let rest = &unindented[number_end..];
    let title = rest.trim_start();
    let first = title.chars().next()?;
    let titled = first.is_ascii_uppercase() || first.is_ascii_lowercase() && written.ends_with('.');
    (rest.starts_with(' ') && titled).then_some(number)
}

/// A table of contents line: a title, a row of dots and a page number.
fn is_contents_line(line: &str) -> bool {
    line.contains("....") || line.contains(". . .")
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
    fn a_finding_whose_id_is_shared_is_found_by_its_title() {
        let library = sample();
        assert_eq!(library.lookup_finding("compressed-streams", "UDP").unwrap().id, "udp");
        assert_eq!(library.lookup_finding("udp", "").unwrap().id, "udp");
        assert!(library.lookup_finding("compressed-streams", "").is_none());
    }

    #[test]
    fn a_payload_can_be_named_by_its_port_ethertype_or_ip_protocol() {
        let extra = r#"
[[format]]
id = "dhcp"
name = "Dynamic Host Configuration Protocol"
keys = ["DHCP"]
summary = "Hands out addresses."
organisation = "A BOOTP message with options."
ports = ["udp/67", "UDP/68"]
ethertypes = [0x88cc]
ip_protocols = [47]
"#;
        let library = Library::parse(&[("sample.toml", SAMPLE), ("extra.toml", extra)]).unwrap();
        assert_eq!(library.by_port(Transport::Udp, 68)[0].id, "dhcp");
        assert!(library.by_port(Transport::Tcp, 67).is_empty());
        assert_eq!(library.by_ethertype(0x88cc)[0].id, "dhcp");
        assert_eq!(library.by_ip_protocol(47)[0].id, "dhcp");
        let bad = extra.replace("udp/67", "port 67");
        let error = Library::parse(&[("bad.toml", &bad)]).err().unwrap();
        assert!(error.contains("tcp/N"), "{error}");
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

    const OLDER_RFC_TEXT: &str = "\
   2.1. Overview ................................................ 3
   2.2. Data format ............................................. 4

2. Detailed specification

   2.1. Overview

      A zlib stream has the following structure:

       1.  First, a list item.

   2.2. Data format

      CMF and FLG.

4.1.1.2.  signatureAlgorithm

   The algorithm.

4.1.1.3.  signatureValue
";

    #[test]
    fn older_rfcs_with_indented_or_lower_case_headings_are_cut_too() {
        let overview = rfc_section(OLDER_RFC_TEXT, "2.1").unwrap();
        assert!(overview.starts_with("   2.1. Overview\n"), "{overview}");
        assert!(overview.contains("First, a list item."));
        assert!(!overview.contains("CMF"));
        let algorithm = rfc_section(OLDER_RFC_TEXT, "4.1.1.2").unwrap();
        assert!(algorithm.contains("The algorithm."));
        assert!(!algorithm.contains("signatureValue"));
    }

    #[test]
    fn a_field_is_explained_with_its_citation() {
        let library = sample();
        let udp = library.lookup("udp").unwrap();
        assert_eq!(udp.explain_field("Length").unwrap(), "Header plus data, in bytes.\n\nRFC 768");
        assert_eq!(udp.short_name(), "UDP");
        assert!(udp.explain_field("Checksum").is_none());
    }

    #[test]
    fn the_assistant_gets_notes_by_name_or_the_ids_it_could_ask_for() {
        let library = sample();
        assert!(library.describe_for_assistant("User Datagram Protocol").starts_with("User Datagram Protocol\nDatagrams between ports."));
        assert_eq!(library.describe_for_assistant("gopher"), "No reference notes for 'gopher'. Known ids: udp.");
    }

    #[test]
    fn rfc_text_is_fetched_once_and_then_read_from_the_cache() {
        let cache = std::env::temp_dir().join(format!("theviewer-rfc-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache);
        let fetched = load_rfc_text(Some(&cache), 768, |url| {
            assert_eq!(url, "https://www.rfc-editor.org/rfc/rfc768.txt");
            Ok("User Datagram Protocol".to_string())
        });
        assert_eq!(fetched.unwrap(), "User Datagram Protocol");
        let cached = load_rfc_text(Some(&cache), 768, |_| panic!("the cached copy should be used"));
        assert_eq!(cached.unwrap(), "User Datagram Protocol");
        let failed = load_rfc_text(Some(&cache), 791, |_| Err("offline".to_string()));
        assert_eq!(failed.unwrap_err(), "offline");
        let _ = std::fs::remove_dir_all(&cache);
    }

    #[test]
    fn rfc_links_point_at_the_rfc_editor() {
        assert_eq!(rfc_text_url(791), "https://www.rfc-editor.org/rfc/rfc791.txt");
        assert_eq!(rfc_html_url(791, Some("3.1")), "https://www.rfc-editor.org/rfc/rfc791.html#section-3.1");
    }
}
