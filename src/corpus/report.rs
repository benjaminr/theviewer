//! The corpus run's findings as Markdown and CSV.
//!
//! Reports hold counts, file names, protocol filter names and our own layer
//! and field names, never tshark's display text.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use super::run::{Comparisons, Failure, FileResult, ProtocolTally};
use crate::packets::LinkKind;
use crate::packets::tshark::is_data_protocol;

/// Rows in each "top" list of the summary.
const TOP_PROTOCOLS: usize = 40;
const TOP_MISMATCHES: usize = 20;

/// Everything learned from the corpus.
#[derive(Clone, Debug, Default)]
pub struct CorpusReport {
    pub files: usize,
    pub opened: usize,
    pub packets_ours: usize,
    pub tshark_used: bool,
    pub packets_tshark: usize,
    /// Files we could not open, by what they appear to be: (files, of which tshark reads).
    pub unreadable_formats: BTreeMap<String, (usize, usize)>,
    /// tshark's outermost protocol in files we could not open, with counts.
    pub unreadable_contents: BTreeMap<String, usize>,
    /// pcap LINKTYPE number → (files, packets).
    pub link_types: BTreeMap<u32, (usize, usize)>,
    pub failures: Vec<Failure>,
    pub slow: Vec<(String, Duration)>,
    pub comparisons: Comparisons,
}

impl CorpusReport {
    pub fn add(&mut self, result: FileResult) {
        self.files += 1;
        let tshark_packets = result.tshark.as_ref().and_then(|outcome| outcome.as_ref().ok()).copied().unwrap_or(0);
        self.packets_tshark += tshark_packets;
        match &result.opened {
            Some(Ok(packets)) => {
                self.opened += 1;
                self.packets_ours += (*packets).min(super::run::MAX_PACKETS_PER_FILE);
            }
            Some(Err(_)) => {
                let entry = self.unreadable_formats.entry(result.format.clone()).or_default();
                entry.0 += 1;
                entry.1 += usize::from(tshark_packets > 0);
                if let Some(link) = &result.tshark_link {
                    *self.unreadable_contents.entry(link.clone()).or_default() += 1;
                }
            }
            None => {}
        }
        for (&link_type, &packets) in &result.link_types {
            let entry = self.link_types.entry(link_type).or_default();
            entry.0 += 1;
            entry.1 += packets;
        }
        if result.elapsed > super::run::SLOW_FILE {
            self.slow.push((result.file.clone(), result.elapsed));
        }
        self.failures.extend(result.failures);
        self.comparisons.absorb(result.comparisons);
    }

    /// Write `summary.md`, `coverage.csv`, `mismatches.csv` and `failures.csv`.
    pub fn write(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        for (name, text) in [("summary.md", self.summary()), ("coverage.csv", self.coverage_csv()), ("mismatches.csv", self.mismatches_csv()), ("failures.csv", self.failures_csv())] {
            std::fs::write(dir.join(name), text).map_err(|error| format!("{name}: {error}"))?;
        }
        Ok(())
    }

    fn panics(&self) -> Vec<&Failure> {
        self.failures.iter().filter(|failure| failure.detail.starts_with("panic:")).collect()
    }

    /// The headline numbers and top lists, as Markdown.
    pub fn summary(&self) -> String {
        let c = &self.comparisons;
        let mut out = String::from("# Capture corpus report\n\n");
        out.push_str("Our capture readers and dissectors run over Wireshark's sample captures");
        out.push_str(if self.tshark_used { ", compared with tshark (run with `-n`).\n\n" } else { ". tshark was not found, so nothing was compared.\n\n" });
        let _ = writeln!(out, "## Headline\n");
        let _ = writeln!(out, "- Captures: {} ({} opened by us, {} not)", self.files, self.opened, self.files - self.opened);
        let _ = writeln!(out, "- Packets read by us: {} (at most {} per file)", self.packets_ours, super::run::MAX_PACKETS_PER_FILE);
        if self.tshark_used {
            let _ = writeln!(out, "- Packets dissected by tshark: {}; compared with ours: {} ({} skipped because the captured lengths differed)", self.packets_tshark, c.compared_packets, c.misaligned);
            let stopped: usize = c.we_stop_earlier.values().sum();
            let differs: usize = c.top_differs.values().sum();
            let total = (c.top_agree + stopped + differs).max(1);
            let percent = |count: usize| 100.0 * count as f64 / total as f64;
            let _ = writeln!(
                out,
                "- Innermost protocol: same as tshark {} ({:.1}%), tshark decodes further {} ({:.1}%), different {} ({:.1}%); {} packets had nothing of ours to compare",
                c.top_agree,
                percent(c.top_agree),
                stopped,
                percent(stopped),
                differs,
                percent(differs),
                c.top_not_compared
            );
            let layers: usize = c.layers.values().map(|tally| tally.compared).sum();
            let layer_offsets: usize = c.layers.values().map(|tally| tally.offset_differs).sum();
            let layer_lengths: usize = c.layers.values().map(|tally| tally.len_differs).sum();
            let _ = writeln!(out, "- Layers compared: {layers}; start differs {layer_offsets}, length differs {layer_lengths}");
            let fields: usize = c.fields.values().map(|tally| tally.compared).sum();
            let field_differs: usize = c.fields.values().map(|tally| tally.differs).sum();
            let _ = writeln!(out, "- Fields compared: {fields}; position or size differs {field_differs}");
            let decoded = c.protocols.values().filter(|tally| tally.decoded_by_us > 0).count();
            let noted = c.protocols.values().filter(|tally| tally.reference_named).count();
            let _ = writeln!(out, "- Protocols tshark found: {}; we decode {decoded}; reference notes name {noted}", c.protocols.len());
        }
        let panics = self.panics();
        let mut locations: Vec<&str> = panics.iter().map(|failure| failure.detail.as_str()).collect();
        locations.sort_unstable();
        locations.dedup();
        let timeouts = self.failures.iter().filter(|failure| failure.stage == "timeout").count();
        let _ = writeln!(out, "- Panics: {} ({} distinct); files abandoned after the time limit: {timeouts}; slow files: {}", panics.len(), locations.len(), self.slow.len());
        let other_failures = self.failures.iter().filter(|failure| !failure.detail.starts_with("panic:") && !matches!(failure.stage.as_str(), "timeout" | "slow")).count();
        let _ = writeln!(out, "- Other failures: {other_failures} (see failures.csv)\n");

        if self.tshark_used {
            self.write_undecoded(&mut out);
            self.write_mismatches(&mut out);
        }
        self.write_panics(&mut out, &panics);
        self.write_unreadable(&mut out);
        if !self.slow.is_empty() {
            let _ = writeln!(out, "## Slow files\n");
            let mut slow = self.slow.clone();
            slow.sort_by_key(|(_, elapsed)| std::cmp::Reverse(*elapsed));
            for (file, elapsed) in slow.iter().take(TOP_MISMATCHES) {
                let _ = writeln!(out, "- {file}: {:.1} s", elapsed.as_secs_f64());
            }
            out.push('\n');
        }
        out
    }

    fn write_undecoded(&self, out: &mut String) {
        let _ = writeln!(out, "## Top {TOP_PROTOCOLS} protocols we do not decode, by packets\n");
        let _ = writeln!(out, "| Protocol | Packets not decoded | Files | Reference notes | Over a port: notes name it / lower-port guess right | Over an EtherType: named | Over an IP protocol: named |");
        let _ = writeln!(out, "| --- | ---: | ---: | --- | --- | --- | --- |");
        for (name, tally) in undecoded_protocols(&self.comparisons).into_iter().take(TOP_PROTOCOLS) {
            let ratio = |named: usize, of: usize| if of == 0 { "–".to_string() } else { format!("{named}/{of}") };
            let _ = writeln!(
                out,
                "| {name} | {} | {} | {} | {} / {} | {} | {} |",
                tally.packets - tally.decoded_by_us,
                tally.files.len(),
                if tally.reference_named { "yes" } else { "no" },
                ratio(tally.port_named, tally.over_port),
                ratio(tally.port_guess_right, tally.over_port),
                ratio(tally.ethertype_named, tally.over_ethertype),
                ratio(tally.ip_protocol_named, tally.over_ip_protocol),
            );
        }
        out.push('\n');
    }

    fn write_mismatches(&self, out: &mut String) {
        let c = &self.comparisons;
        let _ = writeln!(out, "## Where tshark decodes further than we do\n");
        for (name, count) in sorted_counts(&c.we_stop_earlier).into_iter().take(TOP_MISMATCHES) {
            let _ = writeln!(out, "- {name}: {count} packets");
        }
        let _ = writeln!(out, "\n## Innermost protocol differs (ours → tshark's)\n");
        for ((ours, theirs), count) in sorted_counts(&c.top_differs).into_iter().take(TOP_MISMATCHES) {
            let _ = writeln!(out, "- {ours} → {theirs}: {count} packets");
        }
        let _ = writeln!(out, "\n## Layers whose start or length differs\n");
        let mut layers: Vec<_> = c.layers.iter().filter(|(_, tally)| tally.offset_differs + tally.len_differs > 0).collect();
        layers.sort_by_key(|(_, tally)| std::cmp::Reverse(tally.offset_differs + tally.len_differs));
        for ((ours, theirs), tally) in layers.into_iter().take(TOP_MISMATCHES) {
            let example = tally.example.as_ref().map(|e| format!(" — e.g. {} packet {}: ours +{}/{} bytes, tshark's +{}/{}", e.file, e.packet, e.ours.0, e.ours.1, e.theirs.0, e.theirs.1)).unwrap_or_default();
            let _ = writeln!(out, "- {ours} vs {theirs}: {} compared, start differs {}, length differs {}{example}", tally.compared, tally.offset_differs, tally.len_differs);
        }
        let _ = writeln!(out, "\n## Fields whose position or size differs\n");
        let mut fields: Vec<_> = c.fields.iter().filter(|(_, tally)| tally.differs > 0).collect();
        fields.sort_by_key(|(_, tally)| std::cmp::Reverse(tally.differs));
        for ((layer, field, filter), tally) in fields.into_iter().take(TOP_MISMATCHES) {
            let example = tally.example.as_ref().map(|e| format!(" — e.g. {} packet {}: ours +{}/{}, tshark's +{}/{}", e.file, e.packet, e.ours.0, e.ours.1, e.theirs.0, e.theirs.1)).unwrap_or_default();
            let _ = writeln!(out, "- {layer} / {field} vs {filter}: {} of {} differ{example}", tally.differs, tally.compared);
        }
        out.push('\n');
    }

    fn write_panics(&self, out: &mut String, panics: &[&Failure]) {
        let _ = writeln!(out, "## Panics\n");
        if panics.is_empty() {
            let _ = writeln!(out, "None.\n");
            return;
        }
        let mut by_detail: BTreeMap<&str, Vec<&Failure>> = BTreeMap::new();
        for failure in panics {
            by_detail.entry(failure.detail.as_str()).or_default().push(failure);
        }
        for (detail, seen) in by_detail {
            let first = seen[0];
            let packet = first.packet.map(|number| format!(" packet {number}")).unwrap_or_default();
            let _ = writeln!(out, "- {detail} — {} times, first in {} ({}{packet})", seen.len(), first.file, first.stage);
        }
        out.push('\n');
    }

    fn write_unreadable(&self, out: &mut String) {
        let _ = writeln!(out, "## Capture formats and link types we do not read\n");
        for (format, (files, tshark_reads)) in &self.unreadable_formats {
            let _ = writeln!(out, "- Not opened: {format}: {files} files ({tshark_reads} of which tshark reads)");
        }
        for (link, files) in sorted_counts(&self.unreadable_contents) {
            let _ = writeln!(out, "- In files we do not open, tshark's outermost protocol is {link}: {files} files");
        }
        for (&link_type, &(files, packets)) in &self.link_types {
            if LinkKind::from_pcap_link_type(link_type) == LinkKind::Unknown {
                let _ = writeln!(out, "- Opened, but read as raw frames: LINKTYPE {link_type} ({}): {files} files, {packets} packets", link_type_name(link_type));
            }
        }
        out.push('\n');
    }

    pub fn coverage_csv(&self) -> String {
        let mut out = String::from("protocol,packets,files,decoded_by_us,reference_notes,over_port,port_named,port_guess_right,over_ethertype,ethertype_named,over_ip_protocol,ip_protocol_named\n");
        let mut protocols: Vec<(&String, &ProtocolTally)> = self.comparisons.protocols.iter().collect();
        protocols.sort_by_key(|(_, tally)| std::cmp::Reverse(tally.packets));
        for (name, t) in protocols {
            let _ = writeln!(
                out,
                "{},{},{},{},{},{},{},{},{},{},{},{}",
                csv(name),
                t.packets,
                t.files.len(),
                t.decoded_by_us,
                t.reference_named,
                t.over_port,
                t.port_named,
                t.port_guess_right,
                t.over_ethertype,
                t.ethertype_named,
                t.over_ip_protocol,
                t.ip_protocol_named
            );
        }
        out
    }

    pub fn mismatches_csv(&self) -> String {
        let c = &self.comparisons;
        let mut out = String::from("kind,ours,tshark,count,compared,example_file,example_packet,ours_offset,ours_len,tshark_offset,tshark_len\n");
        for ((ours, theirs), count) in sorted_counts(&c.top_differs) {
            let _ = writeln!(out, "innermost-protocol,{},{},{count},,,,,,,", csv(&ours), csv(&theirs));
        }
        for (theirs, count) in sorted_counts(&c.we_stop_earlier) {
            let _ = writeln!(out, "tshark-decodes-further,,{},{count},,,,,,,", csv(&theirs));
        }
        for ((ours, theirs), tally) in c.layers.iter().filter(|(_, tally)| tally.offset_differs + tally.len_differs > 0) {
            let example = example_columns(tally.example.as_ref());
            let _ = writeln!(out, "layer,{},{},{},{},{example}", csv(ours), csv(theirs), tally.offset_differs.max(tally.len_differs), tally.compared);
        }
        for ((layer, field, filter), tally) in c.fields.iter().filter(|(_, tally)| tally.differs > 0) {
            let example = example_columns(tally.example.as_ref());
            let _ = writeln!(out, "field,{},{},{},{},{example}", csv(&format!("{layer} / {field}")), csv(filter), tally.differs, tally.compared);
        }
        out
    }

    pub fn failures_csv(&self) -> String {
        let mut out = String::from("file,stage,packet,detail\n");
        for failure in &self.failures {
            let _ = writeln!(out, "{},{},{},{}", csv(&failure.file), csv(&failure.stage), failure.packet.map(|n| n.to_string()).unwrap_or_default(), csv(&failure.detail));
        }
        out
    }
}

/// Protocols with packets none of our layers covered, most such packets first.
fn undecoded_protocols(comparisons: &Comparisons) -> Vec<(&String, &ProtocolTally)> {
    let mut list: Vec<(&String, &ProtocolTally)> =
        comparisons.protocols.iter().filter(|(name, tally)| tally.packets > tally.decoded_by_us && !is_data_protocol(name)).collect();
    list.sort_by_key(|(name, tally)| (std::cmp::Reverse(tally.packets - tally.decoded_by_us), name.to_string()));
    list
}

fn sorted_counts<K: Clone + Ord>(counts: &BTreeMap<K, usize>) -> Vec<(K, usize)> {
    let mut list: Vec<(K, usize)> = counts.iter().map(|(key, &count)| (key.clone(), count)).collect();
    list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    list
}

fn example_columns(example: Option<&super::run::Example>) -> String {
    match example {
        Some(e) => format!("{},{},{},{},{},{}", csv(&e.file), e.packet, e.ours.0, e.ours.1, e.theirs.0, e.theirs.1),
        None => ",,,,,".to_string(),
    }
}

/// A CSV cell, quoted when it holds a comma, quote or line break.
pub fn csv(text: &str) -> String {
    if text.contains([',', '"', '\n', '\r']) { format!("\"{}\"", text.replace('"', "\"\"")) } else { text.to_string() }
}

/// tcpdump.org's name for a LINKTYPE number, for the common ones.
pub fn link_type_name(link_type: u32) -> &'static str {
    match link_type {
        0 => "NULL",
        1 => "ETHERNET",
        6 => "IEEE802_5",
        7 => "ARCNET_BSD",
        8 => "SLIP",
        9 => "PPP",
        10 => "FDDI",
        50 => "PPP_HDLC",
        51 => "PPP_ETHER",
        100 => "ATM_RFC1483",
        101 => "RAW",
        104 => "C_HDLC",
        105 => "IEEE802_11",
        107 => "FRELAY",
        108 => "LOOP",
        113 => "LINUX_SLL",
        119 => "IEEE802_11_PRISM",
        127 => "IEEE802_11_RADIOTAP",
        129 => "ARCNET_LINUX",
        143 => "DOCSIS",
        147..=162 => "USER",
        163 => "IEEE802_11_AVS",
        189 => "USB_LINUX",
        192 => "PPI",
        195 => "IEEE802_15_4_WITHFCS",
        201 => "BLUETOOTH_HCI_H4_WITH_PHDR",
        220 => "USB_LINUX_MMAPPED",
        228 => "IPV4",
        229 => "IPV6",
        249 => "NETLINK",
        251 => "BLUETOOTH_LE_LL",
        276 => "LINUX_SLL2",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::run::{FieldTally, ProtocolTally};

    #[test]
    fn csv_cells_with_commas_or_quotes_are_quoted() {
        assert_eq!(csv("plain"), "plain");
        assert_eq!(csv("a,b"), "\"a,b\"");
        assert_eq!(csv("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn the_summary_lists_undecoded_protocols_by_volume_and_failures() {
        let mut report = CorpusReport { tshark_used: true, ..CorpusReport::default() };
        let mut comparisons = Comparisons::default();
        comparisons.protocols.insert("dhcp".to_string(), ProtocolTally { packets: 10, files: ["a".to_string()].into(), over_port: 10, port_named: 10, ..ProtocolTally::default() });
        comparisons.protocols.insert("snmp".to_string(), ProtocolTally { packets: 30, files: ["b".to_string()].into(), ..ProtocolTally::default() });
        comparisons.protocols.insert("udp".to_string(), ProtocolTally { packets: 40, decoded_by_us: 40, ..ProtocolTally::default() });
        comparisons.protocols.insert("data".to_string(), ProtocolTally { packets: 99, ..ProtocolTally::default() });
        comparisons.fields.insert(("User Datagram Protocol".into(), "Length".into(), "udp.length".into()), FieldTally { compared: 40, differs: 2, example: None });
        let result = FileResult {
            file: "a.pcap".to_string(),
            opened: Some(Ok(40)),
            failures: vec![Failure { file: "a.pcap".into(), stage: "dissect".into(), packet: Some(3), detail: "panic: index out of bounds at src/x.rs:1".into() }],
            comparisons,
            ..FileResult::default()
        };
        report.add(result);
        let summary = report.summary();
        let snmp = summary.find("| snmp | 30 |").expect("snmp listed");
        let dhcp = summary.find("| dhcp | 10 |").expect("dhcp listed");
        assert!(snmp < dhcp, "most packets first");
        assert!(!summary.contains("| udp |"), "protocols we decode are left out");
        assert!(!summary.contains("| data |"), "bytes tshark did not dissect are not a protocol");
        assert!(summary.contains("10/10"), "{summary}");
        assert!(summary.contains("Panics: 1 (1 distinct)"));
        assert!(summary.contains("udp.length: 2 of 40 differ"));
        assert!(report.failures_csv().contains("a.pcap,dissect,3,panic: index out of bounds at src/x.rs:1"));
        assert!(report.coverage_csv().lines().nth(2).unwrap().starts_with("udp,40,"), "most packets first, data included");
    }
}
