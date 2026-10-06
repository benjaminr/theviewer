//! Checks the reference notes' citations against their sources, for the
//! `check_reference` tool: that each cited RFC exists under the title given
//! and is not obsoleted, that each cited section can be found in the RFC's
//! text, that each port is registered with the IANA to something like the
//! protocol, that every link is https, and that every Wireshark name is one
//! the installed tshark knows.
//!
//! The sources (the RFC Editor's index, RFC text, the IANA port registry and
//! tshark's lists of names) are passed in already fetched, so the checks need
//! no network and can be tested on small samples.

use std::collections::{HashMap, HashSet};

use crate::reference::{self, FormatReference, Transport};

/// What the RFC Editor's index says about one RFC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RfcRecord {
    pub title: String,
    /// RFCs that replace this one.
    pub obsoleted_by: Vec<u32>,
}

/// The RFC Editor's index (`rfc-index.xml`) by RFC number.
pub fn parse_rfc_index(xml: &str) -> Result<HashMap<u32, RfcRecord>, String> {
    let document = roxmltree::Document::parse(xml).map_err(|error| format!("the RFC index is not valid XML: {error}"))?;
    let mut records = HashMap::new();
    for entry in document.root_element().children().filter(|node| node.has_tag_name("rfc-entry")) {
        let child_text = |name: &str| entry.children().find(|node| node.has_tag_name(name)).and_then(|node| node.text()).map(str::trim);
        let Some(number) = child_text("doc-id").and_then(rfc_number) else { continue };
        let obsoleted_by = entry
            .children()
            .filter(|node| node.has_tag_name("obsoleted-by"))
            .flat_map(|node| node.children())
            .filter(|node| node.has_tag_name("doc-id"))
            .filter_map(|node| node.text().and_then(rfc_number))
            .collect();
        records.insert(number, RfcRecord { title: child_text("title").unwrap_or_default().to_string(), obsoleted_by });
    }
    Ok(records)
}

/// The number of a document id such as "RFC791" or "RFC0791".
fn rfc_number(doc_id: &str) -> Option<u32> {
    doc_id.trim().strip_prefix("RFC")?.parse().ok()
}

/// A service registered on a port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub description: String,
}

/// The IANA's services by transport and port.
pub type ServiceRegistry = HashMap<(Transport, u16), Vec<Service>>;

/// The IANA's service name and port number registry, from its CSV form
/// (`service-names-port-numbers.csv`). Rows without a single port, such as
/// ranges and unassigned blocks, are left out.
pub fn parse_service_registry(csv: &str) -> ServiceRegistry {
    let mut registry: ServiceRegistry = HashMap::new();
    for record in csv_records(csv).into_iter().skip(1) {
        let [name, port, transport, description, ..] = record.as_slice() else { continue };
        let Some(key) = reference::parse_port(&format!("{transport}/{port}")) else { continue };
        if name.is_empty() && description.trim().eq_ignore_ascii_case("reserved") {
            continue;
        }
        registry.entry(key).or_default().push(Service { name: name.clone(), description: description.clone() });
    }
    registry
}

/// The records of a CSV text, allowing quoted fields with commas, doubled
/// quotes and line breaks in them.
fn csv_records(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (true, _) => field.push(c),
            (false, '"') => quoted = true,
            (false, ',') => record.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            (false, _) => field.push(c),
        }
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    records
}

/// The display-filter names a Wireshark installation knows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WiresharkNames {
    /// Protocol names, such as `ip` and `dhcp`.
    pub protocols: HashSet<String>,
    /// Field names, such as `ip.ttl`.
    pub fields: HashSet<String>,
}

impl WiresharkNames {
    /// The names in the output of `tshark -G protocols` (each line a full
    /// name, a short name and the filter name, separated by tabs) and
    /// `tshark -G fields` (a `P` line for each protocol and an `F` line for
    /// each field, the filter name third). A line without tabs is a name by
    /// itself, as [`WiresharkNames::to_cache`] writes them.
    pub fn parse(protocols: &str, fields: &str) -> WiresharkNames {
        let mut names = WiresharkNames::default();
        for line in protocols.lines() {
            let columns: Vec<&str> = line.split('\t').collect();
            let name = if columns.len() == 1 { columns[0] } else { columns.get(2).copied().unwrap_or_default() };
            insert_name(&mut names.protocols, name);
        }
        for line in fields.lines() {
            let columns: Vec<&str> = line.split('\t').collect();
            match columns.as_slice() {
                [name] => insert_name(&mut names.fields, name),
                ["P", _, name, ..] => insert_name(&mut names.protocols, name),
                ["F", _, name, ..] => insert_name(&mut names.fields, name),
                _ => {}
            }
        }
        names
    }

    /// The protocol and field names, one a line in name order, for the
    /// cache that `--offline` reads.
    pub fn to_cache(&self) -> (String, String) {
        let lines = |names: &HashSet<String>| {
            let mut sorted: Vec<&str> = names.iter().map(String::as_str).collect();
            sorted.sort_unstable();
            sorted.join("\n") + "\n"
        };
        (lines(&self.protocols), lines(&self.fields))
    }
}

fn insert_name(names: &mut HashSet<String>, name: &str) {
    let name = name.trim();
    if !name.is_empty() {
        names.insert(name.to_string());
    }
}

/// Whether a cited title is the official one, ignoring case, punctuation
/// and spacing. Citing only the main title, before a colon or " -- ", is
/// enough: RFC 826 is "An Ethernet Address Resolution Protocol: Or
/// Converting Network Protocol Addresses ...".
pub fn titles_match(cited: &str, official: &str) -> bool {
    let cited = normalise_title(cited);
    let main_title = official.split(':').next().unwrap_or(official).split(" -- ").next().unwrap_or(official);
    cited == normalise_title(official) || cited == normalise_title(main_title)
}

fn normalise_title(title: &str) -> String {
    title.split(|c: char| !c.is_alphanumeric()).filter(|word| !word.is_empty()).map(str::to_lowercase).collect::<Vec<_>>().join(" ")
}

/// Words too common in protocol names to show that a registered service is
/// the entry's protocol.
const COMMON_WORDS: [&str; 16] = ["protocol", "the", "and", "for", "over", "with", "version", "via", "see", "port", "server", "service", "system", "data", "network", "alternate"];

/// The distinctive words of a name: lower case, at least three letters,
/// without [`COMMON_WORDS`].
fn distinctive_words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
        .filter(|word| word.len() >= 3 && !COMMON_WORDS.contains(&word.as_str()))
        .collect()
}

/// Whether a registered service looks like the entry's protocol: they share
/// a distinctive word, such as "dns" or "modbus".
fn resembles(entry: &FormatReference, service: &Service) -> bool {
    let service_words = distinctive_words(&format!("{} {}", service.name, service.description));
    let entry_text = format!("{} {} {}", entry.id, entry.name, entry.keys.join(" "));
    distinctive_words(&entry_text).iter().any(|word| service_words.contains(word))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// A citation that is wrong: the tool fails.
    Error,
    /// Worth a look, such as an obsoleted RFC or an unregistered port.
    Warning,
}

/// One thing found wrong with an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub severity: Severity,
    /// The entry's id.
    pub entry: String,
    pub message: String,
}

/// What the checks compare the notes with. A source left out is not checked.
pub struct Sources<'a> {
    pub rfc_index: Option<&'a HashMap<u32, RfcRecord>>,
    pub services: Option<&'a ServiceRegistry>,
    /// The plain text of an RFC, or why it is not available.
    pub rfc_text: &'a dyn Fn(u32) -> Result<String, String>,
    /// The names the installed Wireshark knows.
    pub wireshark: Option<&'a WiresharkNames>,
}

/// How much was checked, for the report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub rfcs: usize,
    pub sections: usize,
    pub ports: usize,
    pub links: usize,
    pub wireshark_names: usize,
}

impl std::ops::AddAssign for Counts {
    fn add_assign(&mut self, other: Counts) {
        self.rfcs += other.rfcs;
        self.sections += other.sections;
        self.ports += other.ports;
        self.links += other.links;
        self.wireshark_names += other.wireshark_names;
    }
}

/// Check one entry's citations, links and ports.
pub fn check_entry(entry: &FormatReference, sources: &Sources) -> (Vec<Problem>, Counts) {
    let mut problems = Vec::new();
    let mut counts = Counts::default();
    let mut problem = |severity: Severity, message: String| problems.push(Problem { severity, entry: entry.id.clone(), message });
    for (index, spec) in entry.specs.iter().enumerate() {
        counts.links += 1;
        if !spec.url.starts_with("https://") {
            problem(Severity::Error, format!("{} links to {}, which is not https", spec.document, spec.url));
        }
        let Some(number) = spec.rfc else { continue };
        counts.rfcs += 1;
        if let Some(index) = sources.rfc_index {
            match index.get(&number) {
                None => problem(Severity::Error, format!("RFC {number} is not in the RFC Editor's index")),
                Some(record) => {
                    if !titles_match(&spec.title, &record.title) {
                        problem(Severity::Error, format!("RFC {number} is titled \"{}\", but the notes say \"{}\"", record.title, spec.title));
                    }
                    if !record.obsoleted_by.is_empty() {
                        let by: Vec<String> = record.obsoleted_by.iter().map(|number| format!("RFC {number}")).collect();
                        problem(Severity::Warning, format!("RFC {number} is obsoleted by {}", by.join(", ")));
                    }
                }
            }
        }
        // Fields' sections refer to the first specification.
        let mut sections: Vec<(&str, Option<&str>)> = spec.section.iter().map(|section| (section.as_str(), None)).collect();
        if index == 0 {
            for note in &entry.fields {
                if let Some(section) = &note.section
                    && !sections.iter().any(|(known, _)| known == section)
                {
                    sections.push((section, Some(note.name.as_str())));
                }
            }
        }
        if sections.is_empty() {
            continue;
        }
        let text = match (sources.rfc_text)(number) {
            Ok(text) => text,
            Err(error) => {
                problem(Severity::Warning, format!("RFC {number}'s sections were not checked: {error}"));
                continue;
            }
        };
        for (section, field) in sections {
            counts.sections += 1;
            if reference::rfc_section(&text, section).is_none() {
                let cited_by = field.map(|field| format!(" (cited for field \"{field}\")")).unwrap_or_default();
                problem(Severity::Error, format!("RFC {number} has no section {section}{cited_by}"));
            }
        }
    }
    if let Some(services) = sources.services {
        for text in &entry.ports {
            let Some(port) = reference::parse_port(text) else { continue };
            counts.ports += 1;
            match services.get(&port) {
                None => problem(Severity::Warning, format!("{text} is not registered to any service")),
                Some(registered) if !registered.iter().any(|service| resembles(entry, service)) => {
                    let names: Vec<String> = registered.iter().map(|service| format!("{} ({})", service.name, service.description)).collect();
                    problem(Severity::Warning, format!("{text} is registered to {}", names.join(", ")));
                }
                Some(_) => {}
            }
        }
    }
    if let Some(known) = sources.wireshark {
        if let Some(name) = &entry.wireshark {
            counts.wireshark_names += 1;
            if !known.protocols.contains(name) {
                problem(Severity::Error, format!("Wireshark has no protocol called '{name}'"));
            }
        }
        // A display filter can name a protocol where a field would go, so a
        // field may be given a protocol's name.
        for note in &entry.fields {
            let Some(name) = &note.wireshark else { continue };
            counts.wireshark_names += 1;
            if !known.fields.contains(name) && !known.protocols.contains(name) {
                problem(Severity::Error, format!("Wireshark has no field called '{name}' (given for field \"{}\")", note.name));
            }
        }
    }
    (problems, counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::Library;

    const INDEX: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<rfc-index xmlns="https://www.rfc-editor.org/rfc-index">
  <bcp-entry><doc-id>BCP1</doc-id></bcp-entry>
  <rfc-entry>
    <doc-id>RFC0768</doc-id>
    <title>User Datagram Protocol</title>
  </rfc-entry>
  <rfc-entry>
    <doc-id>RFC2616</doc-id>
    <title>Hypertext Transfer Protocol -- HTTP/1.1</title>
    <obsoleted-by><doc-id>RFC7230</doc-id><doc-id>RFC7231</doc-id></obsoleted-by>
  </rfc-entry>
</rfc-index>"#;

    const SERVICES: &str = "Service Name,Port Number,Transport Protocol,Description,Assignee\n\
mbap,502,tcp,Modbus Application Protocol,[Somebody]\n\
http-alt,8080,tcp,\"HTTP Alternate (see port 80)\",\n\
secure-mqtt,8883,tcp,\"Secure MQTT, with a\nline break and \"\"quotes\"\"\",\n\
,993,udp,Reserved,\n\
,49152-65535,tcp,Dynamic Ports,\n";

    const NOTES: &str = r#"
[[format]]
id = "http"
name = "Hypertext Transfer Protocol"
keys = ["HTTP"]
summary = "Requests and responses."
organisation = "Text."
ports = ["tcp/8080", "tcp/502", "udp/993"]
[[format.specs]]
document = "RFC 2616"
title = "Hypertext Transfer Protocol: HTTP/1.1"
url = "https://www.rfc-editor.org/rfc/rfc2616"
rfc = 2616
section = "4"
[[format.specs]]
document = "RFC 768"
title = "User Datagram Protocol (UDP)"
url = "http://example.com/rfc768"
rfc = 768
[[format.specs]]
document = "RFC 99999"
title = "Nothing"
url = "https://www.rfc-editor.org/rfc/rfc99999"
rfc = 99999
[[format.fields]]
name = "Method"
meaning = "What to do."
section = "5.1"
"#;

    const RFC_2616: &str = "4.  HTTP Message\n\n   Text.\n\n5.  Request\n\n   More.\n";

    fn messages(problems: &[Problem], severity: Severity) -> Vec<&str> {
        problems.iter().filter(|problem| problem.severity == severity).map(|problem| problem.message.as_str()).collect()
    }

    #[test]
    fn the_rfc_index_gives_titles_and_what_obsoletes_them() {
        let index = parse_rfc_index(INDEX).unwrap();
        assert_eq!(index.len(), 2);
        assert_eq!(index[&768].title, "User Datagram Protocol");
        assert_eq!(index[&2616].obsoleted_by, [7230, 7231]);
        assert!(parse_rfc_index("<rfc-index").is_err());
    }

    #[test]
    fn the_port_registry_reads_quoted_fields_and_skips_ranges_and_reserved_ports() {
        let registry = parse_service_registry(SERVICES);
        assert_eq!(registry[&(Transport::Tcp, 502)][0].name, "mbap");
        assert_eq!(registry[&(Transport::Tcp, 8883)][0].description, "Secure MQTT, with a\nline break and \"quotes\"");
        assert!(!registry.contains_key(&(Transport::Udp, 993)), "reserved");
        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn titles_match_whatever_the_case_and_punctuation() {
        assert!(titles_match("Hypertext Transfer Protocol: HTTP/1.1", "Hypertext Transfer Protocol -- HTTP/1.1"));
        assert!(titles_match("internet protocol", "Internet Protocol"));
        assert!(titles_match("An Ethernet Address Resolution Protocol", "An Ethernet Address Resolution Protocol: Or Converting Network Protocol Addresses"));
        assert!(titles_match("Hypertext Transfer Protocol", "Hypertext Transfer Protocol -- HTTP/1.1"));
        assert!(!titles_match("Hypertext", "Hypertext Transfer Protocol -- HTTP/1.1"));
        assert!(!titles_match("User Datagram Protocol (UDP)", "User Datagram Protocol"));
    }

    #[test]
    fn wrong_citations_are_errors_and_doubtful_ones_warnings() {
        let library = Library::parse(&[("notes.toml", NOTES)]).unwrap();
        let index = parse_rfc_index(INDEX).unwrap();
        let services = parse_service_registry(SERVICES);
        let rfc_text = |number: u32| if number == 2616 { Ok(RFC_2616.to_string()) } else { Err("not cached".to_string()) };
        let sources = Sources { rfc_index: Some(&index), services: Some(&services), rfc_text: &rfc_text, wireshark: None };
        let (problems, counts) = check_entry(&library.entries()[0], &sources);
        assert_eq!(
            messages(&problems, Severity::Error),
            [
                "RFC 2616 has no section 5.1 (cited for field \"Method\")",
                "RFC 768 links to http://example.com/rfc768, which is not https",
                "RFC 768 is titled \"User Datagram Protocol\", but the notes say \"User Datagram Protocol (UDP)\"",
                "RFC 99999 is not in the RFC Editor's index",
            ]
        );
        assert_eq!(
            messages(&problems, Severity::Warning),
            [
                "RFC 2616 is obsoleted by RFC 7230, RFC 7231",
                "tcp/502 is registered to mbap (Modbus Application Protocol)",
                "udp/993 is not registered to any service",
            ],
            "tcp/8080 is http-alt, which resembles HTTP"
        );
        assert_eq!(counts, Counts { rfcs: 3, sections: 2, ports: 3, links: 3, wireshark_names: 0 });
    }

    #[test]
    fn sources_left_out_are_not_checked() {
        let library = Library::parse(&[("notes.toml", NOTES)]).unwrap();
        let rfc_text = |_: u32| Err("offline".to_string());
        let sources = Sources { rfc_index: None, services: None, rfc_text: &rfc_text, wireshark: None };
        let (problems, counts) = check_entry(&library.entries()[0], &sources);
        assert_eq!(messages(&problems, Severity::Error), ["RFC 768 links to http://example.com/rfc768, which is not https"]);
        assert_eq!(messages(&problems, Severity::Warning), ["RFC 2616's sections were not checked: offline"]);
        assert_eq!(counts.ports, 0);
        assert_eq!(counts.wireshark_names, 0);
    }

    const TSHARK_PROTOCOLS: &str = "Internet Protocol Version 4\tIPv4\tip\tT\tT\tT\n\
Dynamic Host Configuration Protocol\tDHCP\tdhcp\tT\tT\tT\n";

    const TSHARK_FIELDS: &str = "P\tInternet Protocol Version 4\tip\n\
F\tTime to Live\tip.ttl\tFT_UINT8\tip\t\t0x0\t\n\
F\tTotal Length\tip.len\tFT_UINT16\tip\t\t0x0\t\n\
P\tFragment Header for IPv6\tipv6.fraghdr\n";

    const WIRESHARK_NOTES: &str = r#"
[[format]]
id = "ipv4"
name = "Internet Protocol version 4"
keys = ["IPv4"]
wireshark = "ip"
summary = "Datagrams."
organisation = "A header."
[[format.fields]]
name = "Time to live"
wireshark = "ip.ttl"
meaning = "Hops left."
[[format.fields]]
name = "Fragment header"
wireshark = "ipv6.fraghdr"
meaning = "A protocol's name standing for a field."
[[format.fields]]
name = "Total length"
wireshark = "ip.total_length"
meaning = "Bytes in the packet."
[[format]]
id = "gopher"
name = "Gopher"
keys = ["Gopher"]
wireshark = "gopher"
summary = "Menus."
organisation = "Lines."
"#;

    #[test]
    fn tsharks_lists_give_protocol_and_field_names_and_survive_the_cache() {
        let names = WiresharkNames::parse(TSHARK_PROTOCOLS, TSHARK_FIELDS);
        let sorted = |set: &HashSet<String>| {
            let mut names: Vec<String> = set.iter().cloned().collect();
            names.sort();
            names
        };
        assert_eq!(sorted(&names.protocols), ["dhcp", "ip", "ipv6.fraghdr"]);
        assert_eq!(sorted(&names.fields), ["ip.len", "ip.ttl"]);
        let (protocols, fields) = names.to_cache();
        assert_eq!(fields, "ip.len\nip.ttl\n");
        assert_eq!(WiresharkNames::parse(&protocols, &fields), names, "the cache reads back the same names");
    }

    #[test]
    fn a_wireshark_name_tshark_does_not_know_is_an_error() {
        let library = Library::parse(&[("notes.toml", WIRESHARK_NOTES)]).unwrap();
        let names = WiresharkNames::parse(TSHARK_PROTOCOLS, TSHARK_FIELDS);
        let rfc_text = |_: u32| Err("offline".to_string());
        let sources = Sources { rfc_index: None, services: None, rfc_text: &rfc_text, wireshark: Some(&names) };
        let (problems, counts) = check_entry(&library.entries()[0], &sources);
        assert_eq!(messages(&problems, Severity::Error), ["Wireshark has no field called 'ip.total_length' (given for field \"Total length\")"]);
        assert_eq!(counts.wireshark_names, 4);
        let (problems, _) = check_entry(&library.entries()[1], &sources);
        assert_eq!(messages(&problems, Severity::Error), ["Wireshark has no protocol called 'gopher'"]);
        let unchecked = Sources { wireshark: None, ..sources };
        let (problems, counts) = check_entry(&library.entries()[1], &unchecked);
        assert!(problems.is_empty() && counts.wireshark_names == 0, "without tshark's lists nothing is checked");
    }
}
