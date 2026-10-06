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
//! [`rfc_text_url`] and [`rfc_section`]). Protocols and fields also carry
//! their Wireshark display-filter names (`wireshark = "ip.ttl"`), which
//! `check_reference` verifies against the installed tshark; only the names
//! come from Wireshark.
//!
//! Your own notes, in the same TOML form, are read once at startup from
//! `~/.config/theviewer/reference/*.toml` (see [`user_notes_dir`]). An entry
//! whose `id` matches an embedded one replaces it; other entries are added.
//!
//! Entries are listed for browsing under their `group`. The groups in use,
//! which new entries should share where they fit:
//!
//! - Network: "Capture files", "Link layer", "Internet layer", "Transport",
//!   "Naming and time", "Web and remote access", "Messaging",
//!   "Industrial control".
//! - Files: "Images", "Archives", "Executables", "Disks and filesystems",
//!   "Firmware", "Serialisation", "Text", "Certificates and keys",
//!   "Compression", "Media streams".
//!
//! Entries without a group are listed under "Other".

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

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
    /// The protocol's Wireshark display-filter name, such as `ip`, `dhcp`
    /// or `smb2`, so the notes can be matched with Wireshark and tshark.
    #[serde(default)]
    pub wireshark: Option<String>,
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
    /// The field's Wireshark display-filter name, such as `ip.ttl`.
    #[serde(default)]
    pub wireshark: Option<String>,
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

/// The entries of one reference file, with their ports checked.
fn parse_file(text: &str) -> Result<Vec<FormatReference>, String> {
    let file: ReferenceFile = toml::from_str(text).map_err(|error| error.to_string())?;
    for entry in &file.format {
        if let Some(text) = entry.ports.iter().find(|text| parse_port(text).is_none()) {
            return Err(format!("reference '{}' lists port '{text}'; write ports as tcp/N, udp/N or sctp/N", entry.id));
        }
    }
    Ok(file.format)
}

/// What to do when two entries claim one key.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyClash {
    /// Fail, so a mistake in the embedded notes shows up in the tests.
    Reject,
    /// The later entry takes the key, so your own notes can claim a name.
    LaterWins,
}

/// The library in use, with what became of your own notes.
pub struct LoadedNotes {
    pub library: Library,
    /// Your reference files that were read.
    pub user_files: usize,
    /// Your reference files that could not be read, as "path: error".
    pub problems: Vec<String>,
}

/// Every embedded entry, with indexes from lower-case key, port, EtherType,
/// IP protocol number and Wireshark protocol name to entries.
pub struct Library {
    entries: Vec<FormatReference>,
    by_key: HashMap<String, usize>,
    by_wireshark: HashMap<String, usize>,
    by_port: HashMap<(Transport, u16), Vec<usize>>,
    by_ethertype: HashMap<u16, Vec<usize>>,
    by_ip_protocol: HashMap<u8, Vec<usize>>,
}

impl Library {
    /// Parse reference files. Fails on malformed TOML, a duplicate id, or a
    /// key or Wireshark protocol name claimed by two entries, so mistakes
    /// show up in the tests.
    pub fn parse(sources: &[(&str, &str)]) -> Result<Library, String> {
        let mut entries = Vec::new();
        for (name, text) in sources {
            entries.extend(parse_file(text).map_err(|error| format!("reference/{name}: {error}"))?);
        }
        let mut ids = HashMap::new();
        for (index, entry) in entries.iter().enumerate() {
            if let Some(previous) = ids.insert(entry.id.clone(), index) {
                return Err(format!("reference id '{}' is used twice (entries {previous} and {index})", entry.id));
            }
        }
        Library::index(entries, KeyClash::Reject)
    }

    /// The embedded `sources` with your own reference files laid over them:
    /// an entry whose id is already known replaces that entry, and any other
    /// entry is added. A key your entry shares with another entry becomes
    /// yours. A file that cannot be read or parsed is left out and described
    /// in [`LoadedNotes::problems`]; only invalid embedded files are an error.
    pub fn with_user_notes(sources: &[(&str, &str)], user_files: &[(PathBuf, Result<String, String>)]) -> Result<LoadedNotes, String> {
        let mut entries = Library::parse(sources)?.entries;
        let mut problems = Vec::new();
        let mut loaded_files = 0;
        for (path, text) in user_files {
            let parsed = text.as_ref().map_err(String::clone).and_then(|text| parse_file(text));
            let user_entries = match parsed {
                Ok(user_entries) => user_entries,
                Err(error) => {
                    problems.push(format!("{}: {error}", path.display()));
                    continue;
                }
            };
            loaded_files += 1;
            for entry in user_entries {
                match entries.iter_mut().find(|existing| existing.id == entry.id) {
                    Some(existing) => *existing = entry,
                    None => entries.push(entry),
                }
            }
        }
        let library = Library::index(entries, KeyClash::LaterWins)?;
        Ok(LoadedNotes { library, user_files: loaded_files, problems })
    }

    /// Index entries by key, port, EtherType, IP protocol number and
    /// Wireshark protocol name.
    fn index(entries: Vec<FormatReference>, clash: KeyClash) -> Result<Library, String> {
        let mut by_key: HashMap<String, usize> = HashMap::new();
        let mut by_wireshark: HashMap<String, usize> = HashMap::new();
        for (index, entry) in entries.iter().enumerate() {
            if let Some(name) = &entry.wireshark {
                let name = name.trim().to_lowercase();
                if let Some(&other) = by_wireshark.get(&name)
                    && clash == KeyClash::Reject
                {
                    return Err(format!("Wireshark name '{name}' is claimed by both '{}' and '{}'", entries[other].id, entry.id));
                }
                by_wireshark.insert(name, index);
            }
            for key in entry.keys.iter().chain(std::iter::once(&entry.id)) {
                let key = key.to_lowercase();
                if let Some(&other) = by_key.get(&key)
                    && other != index
                    && clash == KeyClash::Reject
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
        Ok(Library { entries, by_key, by_wireshark, by_port, by_ethertype, by_ip_protocol })
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

    /// The entry for a Wireshark protocol name such as `ip` or `dhcp`,
    /// whatever its case. Kept apart from [`Library::lookup`], whose keys
    /// are the app's own names.
    pub fn by_wireshark(&self, name: &str) -> Option<&FormatReference> {
        self.by_wireshark.get(&name.trim().to_lowercase()).map(|&index| &self.entries[index])
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

    /// Entries on a port number over any transport.
    pub fn by_port_number(&self, port: u16) -> Vec<&FormatReference> {
        let mut found = Vec::new();
        for transport in [Transport::Tcp, Transport::Udp, Transport::Sctp] {
            for entry in self.by_port(transport, port) {
                if !found.iter().any(|known: &&FormatReference| known.id == entry.id) {
                    found.push(entry);
                }
            }
        }
        found
    }

    /// Entries a number may name: a port on any transport, an IP protocol
    /// number or an EtherType. Written `0x…`, it is read as hexadecimal.
    fn by_number(&self, text: &str) -> Option<Vec<&FormatReference>> {
        let text = text.trim();
        let number = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => text.parse::<u32>().ok()?,
        };
        let number = u16::try_from(number).ok()?;
        let mut found = self.by_port_number(number);
        let others = u8::try_from(number).map_or_else(|_| Vec::new(), |protocol| self.by_ip_protocol(protocol)).into_iter().chain(self.by_ethertype(number));
        for entry in others {
            if !found.iter().any(|known| known.id == entry.id) {
                found.push(entry);
            }
        }
        Some(found)
    }

    /// Entries matching what the user typed: a port such as `udp/67`; a
    /// number, as a port, IP protocol number or EtherType; or else words found
    /// in an entry's id, name, keys, summary, group, cited documents or
    /// Wireshark names, with the entries Wireshark itself calls that name
    /// (`dhcp`, or a field such as `ip.ttl`) first. Every entry for an empty
    /// query.
    pub fn search(&self, query: &str) -> Vec<&FormatReference> {
        let query = query.trim();
        if query.is_empty() {
            return self.entries.iter().collect();
        }
        if let Some((transport, port)) = parse_port(query) {
            return self.by_port(transport, port);
        }
        if let Some(found) = self.by_number(query) {
            return found;
        }
        let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        let mut found: Vec<&FormatReference> = self.entries.iter().filter(|entry| words.iter().all(|word| entry.mentions(word))).collect();
        found.sort_by_key(|entry| !entry.has_wireshark_name(query));
        found
    }

    /// An entry's notes as plain text for the assistant, looked up by id or
    /// any of its keys, or by a port (`udp/67`) or number (a port, IP protocol
    /// number or EtherType); when nothing matches, the ids that are known.
    pub fn describe_for_assistant(&self, name: &str) -> String {
        if let Some(entry) = self.lookup(name) {
            return entry.to_plain_text();
        }
        let by_number = parse_port(name).map(|(transport, port)| self.by_port(transport, port)).or_else(|| self.by_number(name));
        match by_number {
            Some(found) if !found.is_empty() => {
                let mut text = format!("Notes on what '{}' usually carries:\n", name.trim());
                for entry in found.iter().take(ASSISTANT_MATCHES_IN_FULL) {
                    text.push('\n');
                    text.push_str(&entry.to_plain_text());
                }
                let rest: Vec<&str> = found.iter().skip(ASSISTANT_MATCHES_IN_FULL).map(|entry| entry.id.as_str()).collect();
                if !rest.is_empty() {
                    text.push_str(&format!("\nAlso: {}.\n", rest.join(", ")));
                }
                text
            }
            _ => {
                let ids: Vec<&str> = self.entries.iter().map(|entry| entry.id.as_str()).collect();
                format!("No reference notes for '{}'. Known ids: {}.", name.trim(), ids.join(", "))
            }
        }
    }
}

/// Most entries matching a port or number sent to the assistant in full.
const ASSISTANT_MATCHES_IN_FULL: usize = 3;

/// The heading of entries without a group.
pub const OTHER_GROUP: &str = "Other";

/// Entries under their groups, groups in alphabetical order with
/// [`OTHER_GROUP`] last, entries by name within each.
pub fn grouped<'a>(entries: &[&'a FormatReference]) -> Vec<(&'a str, Vec<&'a FormatReference>)> {
    let mut groups: Vec<(&'a str, Vec<&'a FormatReference>)> = Vec::new();
    for &entry in entries {
        let group = entry.group.as_deref().filter(|group| !group.trim().is_empty()).unwrap_or(OTHER_GROUP);
        match groups.iter_mut().find(|(name, _)| *name == group) {
            Some((_, members)) => members.push(entry),
            None => groups.push((group, vec![entry])),
        }
    }
    groups.sort_by_key(|(name, _)| (*name == OTHER_GROUP, name.to_lowercase()));
    for (_, members) in &mut groups {
        members.sort_by_key(|entry| entry.name.to_lowercase());
    }
    groups
}

/// Where your own reference files live: `~/.config/theviewer/reference`.
pub fn user_notes_dir() -> Option<PathBuf> {
    crate::config::config_file("reference")
}

/// Every `*.toml` file in `dir`, in name order, with its text or why it
/// could not be read. A missing folder holds no files.
pub fn read_user_notes(dir: &Path) -> Vec<(PathBuf, Result<String, String>)> {
    let Ok(listing) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut paths: Vec<PathBuf> = listing.filter_map(Result::ok).map(|entry| entry.path()).filter(|path| path.extension().is_some_and(|ext| ext == "toml")).collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).map_err(|error| error.to_string());
            (path, text)
        })
        .collect()
}

/// The embedded notes alone, without your own.
pub fn embedded_library() -> Result<Library, String> {
    Library::parse(&SOURCES)
}

/// The embedded notes with your own from [`user_notes_dir`].
fn load_notes() -> LoadedNotes {
    let user_files = user_notes_dir().map(|dir| read_user_notes(&dir)).unwrap_or_default();
    Library::with_user_notes(&SOURCES, &user_files).unwrap_or_else(|error| panic!("embedded reference notes are invalid: {error}"))
}

/// The notes in use. Loaded on first use and replaced by
/// [`reload_user_notes`]; each version is leaked so entries handed out
/// earlier stay valid, which costs little as reloading is rare.
static LOADED: RwLock<Option<&'static LoadedNotes>> = RwLock::new(None);

/// The notes in use, with what became of your own.
pub fn loaded_notes() -> &'static LoadedNotes {
    if let Some(loaded) = *LOADED.read().unwrap_or_else(|poisoned| poisoned.into_inner()) {
        return loaded;
    }
    let mut slot = LOADED.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    slot.get_or_insert_with(|| Box::leak(Box::new(load_notes())))
}

/// Read your own notes again, for when you have edited them.
pub fn reload_user_notes() -> &'static LoadedNotes {
    let loaded: &'static LoadedNotes = Box::leak(Box::new(load_notes()));
    *LOADED.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(loaded);
    loaded
}

/// The library in use: the embedded notes and your own.
pub fn library() -> &'static Library {
    &loaded_notes().library
}

/// The entry for `key` in the library in use.
pub fn lookup(key: &str) -> Option<&'static FormatReference> {
    library().lookup(key)
}

/// The entry for a finding, by id or else title, in the library in use.
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

    /// What a field means, with its citation and Wireshark name on lines of
    /// their own, for tooltips wherever the field is shown.
    pub fn explain_field(&self, name: &str) -> Option<String> {
        let note = self.field(name)?;
        let wireshark = note.wireshark.as_ref().map(|name| format!("Wireshark: {name}"));
        let footer: Vec<String> = self.citation(note).into_iter().chain(wireshark).collect();
        Some(if footer.is_empty() { note.meaning.clone() } else { format!("{}\n\n{}", note.meaning, footer.join("\n")) })
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

    /// Whether a lower-case `word` appears in the entry's id, name, keys,
    /// summary, group, ports, cited documents or Wireshark names.
    fn mentions(&self, word: &str) -> bool {
        let contains = |text: &str| text.to_lowercase().contains(word);
        contains(&self.id)
            || contains(&self.name)
            || contains(&self.summary)
            || self.group.as_deref().is_some_and(contains)
            || self.keys.iter().chain(&self.ports).any(|text| contains(text))
            || self.specs.iter().any(|spec| contains(&spec.document) || contains(&spec.title))
            || self.wireshark_names().any(contains)
    }

    /// The entry's Wireshark protocol name, then its fields' names.
    pub fn wireshark_names(&self) -> impl Iterator<Item = &str> {
        self.wireshark.iter().chain(self.fields.iter().filter_map(|note| note.wireshark.as_ref())).map(String::as_str)
    }

    /// Whether Wireshark calls the protocol, or one of its fields, `name`.
    fn has_wireshark_name(&self, name: &str) -> bool {
        self.wireshark_names().any(|known| known.eq_ignore_ascii_case(name.trim()))
    }

    /// The whole entry as plain text, for the assistant's context.
    pub fn to_plain_text(&self) -> String {
        let mut text = format!("{}\n{}\n", self.name, self.summary);
        if let Some(name) = &self.wireshark {
            text.push_str(&format!("Wireshark display filter: {name}\n"));
        }
        text.push_str(&format!("\n{}\n", self.organisation.trim()));
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
                let wireshark = note.wireshark.as_ref().map(|name| format!(" (Wireshark {name})")).unwrap_or_default();
                text.push_str(&format!("- {}{wireshark}: {}\n", note.name.trim_end_matches('*').trim(), note.meaning));
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
        // Lettered sections ("A.3.1") are appendices, anchored as such.
        Some(section) if section.starts_with(|c: char| c.is_ascii_alphabetic()) => format!("{RFC_TEXT_BASE}/rfc{number}.html#appendix-{section}"),
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
    load_cached_text(cache_dir, &format!("rfc{number}.txt"), &rfc_text_url(number), fetch)
}

/// The text kept as `file_name` in `cache_dir` when it is there, otherwise
/// fetched from `url` with `fetch` and then cached.
pub fn load_cached_text(cache_dir: Option<&Path>, file_name: &str, url: &str, fetch: impl FnOnce(&str) -> Result<String, String>) -> Result<String, String> {
    let cached = cache_dir.map(|dir| dir.join(file_name));
    if let Some(text) = cached.as_ref().and_then(|path| std::fs::read_to_string(path).ok()).filter(|text| !text.trim().is_empty()) {
        return Ok(text);
    }
    let text = fetch(url)?;
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
    let section_end = |start: usize| {
        lines[start + 1..]
            .iter()
            .position(|line| heading_number(line).is_some_and(|number| !is_within(number, section)))
            .map_or(lines.len(), |offset| start + 1 + offset)
    };
    // A contents page can list the heading first; the section itself is the
    // first match with text of its own before the next heading.
    let (start, end) = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| heading_number(line).is_some_and(|number| number == section))
        .map(|(start, _)| (start, section_end(start)))
        .find(|&(start, end)| lines[start + 1..end].iter().any(|line| !line.trim().is_empty() && heading_number(line).is_none()))?;
    let body = collapse_blank_lines(&lines[start..end]);
    Some(body.trim_end().to_string())
}

/// Deepest indent of a subsection heading in older RFCs: RFC 959 indents
/// its third level by six spaces.
const MAX_HEADING_INDENT: usize = 6;
/// Section numbers stay below this in every part; larger ones are addresses
/// or values in the text, such as RFC 951's "255.255.255.255.  This address".
const MAX_SECTION_PART: u32 = 100;

/// The section number a heading line starts with, such as "3.1", or "A.3.1"
/// for a lettered appendix.
fn heading_number(line: &str) -> Option<&str> {
    let unindented = line.trim_start_matches(' ');
    let indent = line.len() - unindented.len();
    if indent > MAX_HEADING_INDENT || is_contents_line(line) {
        return None;
    }
    let appendix = unindented.len() > 2 && unindented.as_bytes()[0].is_ascii_uppercase() && unindented[1..].starts_with('.') && unindented.as_bytes()[2].is_ascii_digit();
    if !appendix && !unindented.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let number_start = if appendix { 2 } else { 0 };
    let number_end = unindented[number_start..].find(|c: char| !(c.is_ascii_digit() || c == '.')).map_or(unindented.len(), |end| number_start + end);
    let written = &unindented[..number_end];
    let number = written.trim_end_matches('.');
    let numeric_parts = &number[number_start..];
    let parts_valid = numeric_parts.split('.').all(|part| part.parse::<u32>().is_ok_and(|value| value < MAX_SECTION_PART));
    if numeric_parts.is_empty() || !parts_valid {
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

/// A table of contents line: a title, then a row of dots or a wide gap, and
/// a page number.
fn is_contents_line(line: &str) -> bool {
    if line.contains("....") || line.contains(". . .") {
        return true;
    }
    let trimmed = line.trim_end();
    let page_number = trimmed.rsplit(' ').next().unwrap_or("");
    !page_number.is_empty() && page_number.chars().all(|c| c.is_ascii_digit()) && trimmed[..trimmed.len() - page_number.len()].ends_with("   ")
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

    const DHCP: &str = r#"
[[format]]
id = "dhcp"
name = "Dynamic Host Configuration Protocol"
keys = ["DHCP"]
summary = "Hands out addresses."
organisation = "A BOOTP message with options."
group = "Addressing"
ports = ["udp/67", "udp/68"]
ip_protocols = [99]
"#;

    #[test]
    fn the_library_is_searched_by_port_number_or_words() {
        let library = Library::parse(&[("sample.toml", SAMPLE), ("dhcp.toml", DHCP)]).unwrap();
        let ids = |query: &str| library.search(query).iter().map(|entry| entry.id.as_str()).collect::<Vec<_>>();
        assert_eq!(ids(""), ["udp", "dhcp"]);
        assert_eq!(ids("udp/67"), ["dhcp"]);
        assert!(ids("tcp/67").is_empty());
        assert_eq!(ids("68"), ["dhcp"], "a bare number is a port on any transport");
        assert_eq!(ids("99"), ["dhcp"], "or an IP protocol number");
        assert_eq!(ids("datagram"), ["udp"]);
        assert_eq!(ids("host addresses"), ["dhcp"], "every word must appear");
        assert_eq!(ids("RFC 768"), ["udp"], "cited documents are searched");
        let groups: Vec<(&str, usize)> = grouped(&library.search("")).iter().map(|(name, members)| (*name, members.len())).collect();
        assert_eq!(groups, [("Addressing", 1), (OTHER_GROUP, 1)]);
    }

    #[test]
    fn the_assistant_can_ask_by_port_or_number() {
        let library = Library::parse(&[("sample.toml", SAMPLE), ("dhcp.toml", DHCP)]).unwrap();
        assert!(library.describe_for_assistant("udp/67").contains("Dynamic Host Configuration Protocol\nHands out addresses."));
        assert!(library.describe_for_assistant("68").contains("Dynamic Host Configuration Protocol"));
        assert!(library.describe_for_assistant("tcp/67").starts_with("No reference notes for 'tcp/67'"));
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("theviewer-reference-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn your_notes_replace_an_entry_with_the_same_id_and_add_new_ones() {
        let dir = temp_dir("override");
        let mine = r#"
[[format]]
id = "udp"
name = "UDP, my way"
keys = ["UDP", "my datagrams"]
summary = "My own summary."
organisation = "As I see it."
"#;
        std::fs::write(dir.join("b-mine.toml"), mine).unwrap();
        std::fs::write(dir.join("a-dhcp.toml"), DHCP).unwrap();
        std::fs::write(dir.join("notes.txt"), "not a reference file").unwrap();
        let loaded = Library::with_user_notes(&[("sample.toml", SAMPLE)], &read_user_notes(&dir)).unwrap();
        assert!(loaded.problems.is_empty(), "{:?}", loaded.problems);
        assert_eq!(loaded.user_files, 2);
        let library = &loaded.library;
        assert_eq!(library.entries().len(), 2, "udp is replaced, not doubled");
        assert_eq!(library.lookup("udp").unwrap().summary, "My own summary.");
        assert_eq!(library.lookup("my datagrams").unwrap().id, "udp", "the new keys are indexed");
        assert!(library.lookup("User Datagram Protocol").is_none(), "the replaced entry's keys are dropped");
        assert_eq!(library.by_port(Transport::Udp, 67)[0].id, "dhcp");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_broken_file_of_your_notes_is_skipped_and_reported() {
        let dir = temp_dir("broken");
        std::fs::write(dir.join("broken.toml"), "[[format]]\nid = \"x\"\nname = ").unwrap();
        std::fs::write(dir.join("bad-port.toml"), DHCP.replace("udp/67", "port 67")).unwrap();
        std::fs::write(dir.join("good.toml"), DHCP.replace("\"udp/67\", ", "")).unwrap();
        let loaded = Library::with_user_notes(&[("sample.toml", SAMPLE)], &read_user_notes(&dir)).unwrap();
        assert_eq!(loaded.problems.len(), 2, "{:?}", loaded.problems);
        assert!(loaded.problems.iter().any(|problem| problem.contains("broken.toml: ")));
        assert!(loaded.problems.iter().any(|problem| problem.contains("bad-port.toml: ") && problem.contains("tcp/N")));
        assert_eq!(loaded.user_files, 1);
        assert_eq!(loaded.library.entries().len(), 2, "the good file still loads");
        let missing = Library::with_user_notes(&[("sample.toml", SAMPLE)], &read_user_notes(&dir.join("absent"))).unwrap();
        assert!(missing.problems.is_empty() && missing.user_files == 0);
        let _ = std::fs::remove_dir_all(&dir);
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

    const IPV4: &str = r#"
[[format]]
id = "ipv4"
name = "Internet Protocol version 4"
keys = ["IPv4"]
wireshark = "ip"
summary = "Datagrams between hosts."
organisation = "A 20-byte header, then the payload."
[[format.specs]]
document = "RFC 791"
title = "Internet Protocol"
url = "https://www.rfc-editor.org/rfc/rfc791"
section = "3.1"
[[format.fields]]
name = "Time to live"
wireshark = "ip.ttl"
meaning = "Hops left."
[[format.fields]]
name = "Options"
meaning = "Rare extras."
"#;

    #[test]
    fn a_wireshark_protocol_name_finds_its_entry_but_is_not_a_lookup_key() {
        let library = Library::parse(&[("sample.toml", SAMPLE), ("ipv4.toml", IPV4)]).unwrap();
        assert_eq!(library.by_wireshark("ip").unwrap().id, "ipv4");
        assert_eq!(library.by_wireshark(" IP ").unwrap().id, "ipv4", "case and spacing do not matter");
        assert!(library.by_wireshark("udp").is_none(), "an entry without a Wireshark name is not found by its id");
        assert!(library.lookup("ip").is_none(), "Wireshark names are not the app's keys");
    }

    #[test]
    fn a_wireshark_protocol_name_claimed_twice_is_rejected_but_your_notes_may_take_it() {
        let other = IPV4.replace("id = \"ipv4\"", "id = \"ip-again\"").replace("keys = [\"IPv4\"]", "keys = [\"IP again\"]");
        let error = Library::parse(&[("ipv4.toml", IPV4), ("other.toml", &other)]).err().unwrap();
        assert!(error.contains("Wireshark name 'ip' is claimed by both 'ipv4' and 'ip-again'"), "{error}");
        let mine = vec![(PathBuf::from("mine.toml"), Ok(other.clone()))];
        let loaded = Library::with_user_notes(&[("ipv4.toml", IPV4)], &mine).unwrap();
        assert_eq!(loaded.library.by_wireshark("ip").unwrap().id, "ip-again");
    }

    #[test]
    fn the_library_is_searched_by_wireshark_filter_names() {
        let udp_mentions_ip = SAMPLE.replace("Datagrams between ports.", "Datagrams between ports, carried in ip.");
        let library = Library::parse(&[("sample.toml", &udp_mentions_ip), ("ipv4.toml", IPV4)]).unwrap();
        let ids = |query: &str| library.search(query).iter().map(|entry| entry.id.as_str()).collect::<Vec<_>>();
        assert_eq!(ids("ip.ttl"), ["ipv4"], "a field's filter name finds its protocol");
        assert_eq!(ids("IP.TTL"), ["ipv4"]);
        assert_eq!(ids("ip"), ["ipv4", "udp"], "the entry Wireshark calls 'ip' comes first");
    }

    #[test]
    fn a_fields_wireshark_name_is_shown_in_its_tooltip_and_the_assistants_text() {
        let library = Library::parse(&[("ipv4.toml", IPV4)]).unwrap();
        let ipv4 = library.lookup("IPv4").unwrap();
        assert_eq!(ipv4.explain_field("Time to live").unwrap(), "Hops left.\n\nRFC 791 §3.1\nWireshark: ip.ttl");
        assert_eq!(ipv4.explain_field("Options").unwrap(), "Rare extras.\n\nRFC 791 §3.1");
        let text = ipv4.to_plain_text();
        assert!(text.contains("Wireshark display filter: ip\n"), "{text}");
        assert!(text.contains("- Time to live (Wireshark ip.ttl): Hops left."), "{text}");
        assert!(text.contains("- Options: Rare extras."), "{text}");
    }

    /// Fields of an entry that have a Wireshark name, and all its fields.
    fn wireshark_coverage(entry: &FormatReference) -> (usize, usize) {
        (entry.fields.iter().filter(|note| note.wireshark.is_some()).count(), entry.fields.len())
    }

    #[test]
    fn the_main_network_notes_carry_wireshark_names() {
        let library = embedded_library().unwrap();
        for id in ["ethernet", "ipv4", "ipv6", "tcp", "udp", "dns", "http", "tls-record", "dhcp", "arp", "icmp"] {
            let entry = library.by_id(id).unwrap_or_else(|| panic!("no entry {id}"));
            let name = entry.wireshark.as_deref().unwrap_or_else(|| panic!("{id} has no Wireshark name"));
            assert_eq!(library.by_wireshark(name).unwrap().id, id);
        }
        for id in ["ipv4", "tcp", "udp"] {
            let (named, all) = wireshark_coverage(library.by_id(id).unwrap());
            assert!(named * 3 >= all * 2, "{id}: only {named} of {all} fields have Wireshark names");
        }
        assert_eq!(library.by_id("ipv4").unwrap().field("Time to live").unwrap().wireshark.as_deref(), Some("ip.ttl"));
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

    const OLDEST_RFC_LAYOUTS: &str = "\
  4.1  NAME FORMAT                                                   5
     4.2.1  GENERAL FORMAT OF NAME SERVICE PACKETS                   7

3. Packet Format

   All numbers shown are decimal.  The address
   255.255.255.255.  This address means broadcast on the local cable.

4.  FILE TRANSFER FUNCTIONS

   4.1.  FTP COMMANDS

      4.1.2.  TRANSFER PARAMETER COMMANDS

         PORT and TYPE.

   4.2.  FTP REPLIES

4.1.  NAME FORMAT

   Names are encoded in halves.

A.3 OSPF Packet Formats

A.3.1 The OSPF packet header

    Every OSPF packet starts with a 24-byte header.

A.3.2 The Hello packet

    Hello.
";

    #[test]
    fn the_oldest_rfc_layouts_still_give_their_sections() {
        // Third-level headings indented six spaces (RFC 959).
        let commands = rfc_section(OLDEST_RFC_LAYOUTS, "4.1.2").unwrap();
        assert!(commands.contains("PORT and TYPE") && !commands.contains("FTP REPLIES"), "{commands}");
        // An address in the text is not a heading (RFC 951).
        let format = rfc_section(OLDEST_RFC_LAYOUTS, "3").unwrap();
        assert!(format.contains("broadcast on the local cable"), "{format}");
        // A contents line without dot leaders is passed over for the section itself (RFC 1002).
        let name_format = rfc_section(OLDEST_RFC_LAYOUTS, "4.1").unwrap();
        assert!(name_format.contains("PORT and TYPE") || name_format.contains("Names are encoded"), "{name_format}");
        // Lettered appendix sections (RFC 2328).
        let header = rfc_section(OLDEST_RFC_LAYOUTS, "A.3.1").unwrap();
        assert!(header.contains("24-byte header") && !header.contains("Hello."), "{header}");
    }

    #[test]
    fn rfc_links_point_at_the_rfc_editor() {
        assert_eq!(rfc_text_url(791), "https://www.rfc-editor.org/rfc/rfc791.txt");
        assert_eq!(rfc_html_url(791, Some("3.1")), "https://www.rfc-editor.org/rfc/rfc791.html#section-3.1");
        assert_eq!(rfc_html_url(2328, Some("A.3.1")), "https://www.rfc-editor.org/rfc/rfc2328.html#appendix-A.3.1");
    }
}
