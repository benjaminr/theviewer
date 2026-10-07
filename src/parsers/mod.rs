//! Structure parsers built on existing crates and small hand-written walkers:
//! executables, images, archives, PDF documents, captures and protocols,
//! ASN.1, disks and filesystems, and schemaless serialisation formats.
//!
//! Every parser implements [`plugin::Parser`] and reports a [`Finding`] whose
//! field offsets are document offsets. [`builtin_detectors`] wraps the parsers
//! in an anchor scanner and adds the window-scanning heuristics.

pub mod archive;
pub mod asn1;
pub mod captures;
pub mod disk;
pub mod executable;
pub mod image;
pub mod pdf;
pub mod protocol;
pub mod serial;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use crate::plugin::{Category, Detector, Finding, Parser, ScanContext};

pub use image::{Preview, image_preview};

/// Largest extent any parser will claim.
pub const MAX_EXTENT: usize = 64 * 1024 * 1024;
/// Most children a single field tree level will list.
pub const MAX_CHILDREN: usize = 4096;

/// All structure parsers, in the order they are tried.
pub fn builtin_parsers() -> Vec<Arc<dyn Parser>> {
    vec![
        Arc::new(executable::ElfParser),
        Arc::new(executable::PeParser),
        Arc::new(executable::MachOParser),
        Arc::new(image::PngParser),
        Arc::new(image::JpegParser),
        Arc::new(image::GifParser),
        Arc::new(image::BmpParser),
        Arc::new(archive::ZipParser),
        Arc::new(archive::TarParser),
        Arc::new(archive::ArParser),
        Arc::new(archive::CpioParser),
        Arc::new(pdf::PdfParser),
        Arc::new(protocol::PcapParser),
        Arc::new(protocol::PcapNgParser),
        Arc::new(captures::SnoopParser),
        Arc::new(captures::NetMonParser),
        Arc::new(captures::ErfParser),
        Arc::new(captures::GzipCaptureParser),
        Arc::new(asn1::DerParser),
        Arc::new(disk::MbrParser),
        Arc::new(disk::GptParser),
        Arc::new(disk::FatParser),
        Arc::new(disk::NtfsParser),
        Arc::new(disk::ExtParser),
        Arc::new(serial::ProtobufParser),
        Arc::new(serial::MessagePackParser),
        Arc::new(serial::CborParser),
        Arc::new(serial::JsonParser),
        Arc::new(serial::XmlParser),
    ]
}

/// Window-scanning detectors: protocol heuristics, serialisation checks, and
/// the anchor scanner that runs the structural parsers wherever their magic
/// appears.
pub fn builtin_detectors() -> Vec<Arc<dyn Detector>> {
    // Serialisation parsers are heuristic and fire everywhere on binary data,
    // so they are left to their own window detector rather than the anchors.
    let anchored: Vec<Arc<dyn Parser>> = builtin_parsers()
        .into_iter()
        .filter(|parser| !parser.id().starts_with("serial."))
        .collect();
    vec![
        Arc::new(protocol::ProtocolHeuristics),
        Arc::new(serial::SerialisationDetector),
        Arc::new(AnchorsDetector::new(anchored)),
    ]
}

/// Runs every parser's cheap `looks_like` at each window offset and parses
/// where it matches, keeping the longest of any overlapping results.
pub struct AnchorsDetector {
    parsers: Vec<Arc<dyn Parser>>,
}

impl AnchorsDetector {
    pub fn new(parsers: Vec<Arc<dyn Parser>>) -> Self {
        AnchorsDetector { parsers }
    }
}

impl Detector for AnchorsDetector {
    fn id(&self) -> &str {
        "parsers.anchors"
    }

    fn name(&self) -> &str {
        "Structure parsers"
    }

    fn categories(&self) -> Vec<Category> {
        vec![
            Category::Executable,
            Category::Image,
            Category::Archive,
            Category::Protocol,
            Category::Structure,
            Category::Filesystem,
        ]
    }

    fn scan(&self, window: &[u8], context: &ScanContext) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();
        let mut offset = 0;
        while offset < window.len() {
            let slice = &window[offset..];
            let mut best: Option<Finding> = None;
            for parser in &self.parsers {
                if !parser.looks_like(slice) {
                    continue;
                }
                if let Some(finding) = parser.parse(slice, context.base + offset)
                    && best.as_ref().is_none_or(|current| finding.len > current.len)
                {
                    best = Some(finding);
                }
            }
            match best {
                Some(finding) => {
                    // Confident structures own their extent; skip past them so
                    // nested magics inside are not reported again.
                    let skip = if finding.confidence >= 0.8 { finding.len.max(1) } else { 1 };
                    findings.push(finding);
                    offset += skip;
                }
                None => offset += 1,
            }
            if findings.len() >= MAX_CHILDREN {
                break;
            }
        }
        dedupe_overlapping(findings)
    }
}

/// Keep the longest finding among those that overlap with the same category.
pub(crate) fn dedupe_overlapping(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| b.len.cmp(&a.len).then(a.start.cmp(&b.start)));
    let mut kept: Vec<Finding> = Vec::new();
    for finding in findings {
        let overlaps = kept
            .iter()
            .any(|other| other.category == finding.category && other.start < finding.end() && finding.start < other.end());
        if !overlaps {
            kept.push(finding);
        }
    }
    kept.sort_by_key(|finding| finding.start);
    kept
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Run a parse that might panic on malformed input and treat a panic as
/// "did not parse".
pub(crate) fn guarded<T>(parse: impl FnOnce() -> Option<T>) -> Option<T> {
    catch_unwind(AssertUnwindSafe(parse)).ok().flatten()
}

pub(crate) fn u16le(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

pub(crate) fn u16be(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

pub(crate) fn u32le(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub(crate) fn u32be(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..at + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

pub(crate) fn u64le(bytes: &[u8], at: usize) -> Option<u64> {
    bytes.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
}

/// Printable preview of bytes, with non-printables shown as dots.
pub(crate) fn text_preview(bytes: &[u8], max: usize) -> String {
    let shown: String = bytes
        .iter()
        .take(max)
        .map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' })
        .collect();
    if bytes.len() > max { format!("{shown}…") } else { shown }
}

/// Hex preview of bytes.
pub(crate) fn hex_preview(bytes: &[u8], max: usize) -> String {
    let shown: Vec<String> = bytes.iter().take(max).map(|b| format!("{b:02x}")).collect();
    let mut text = shown.join(" ");
    if bytes.len() > max {
        text.push('…');
    }
    text
}

/// Text from a fixed-size, NUL-padded field.
pub(crate) fn fixed_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim_end().to_string()
}

pub(crate) fn human_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[cfg(test)]
pub(crate) fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detectors_report_nothing_confident_in_noise() {
        let window = noise(65536, 0x2545_F491);
        let context = ScanContext { base: 0, document_len: window.len(), strides: vec![] };
        for detector in builtin_detectors() {
            let confident: Vec<&Finding> = Vec::new();
            let findings = detector.scan(&window, &context);
            let confident: Vec<&Finding> = findings.iter().filter(|f| f.confidence >= 0.5).chain(confident).collect();
            assert!(confident.is_empty(), "{}: {:?}", detector.id(), confident.iter().map(|f| (&f.id, f.start, f.confidence)).collect::<Vec<_>>());
        }
    }

    #[test]
    fn overlapping_findings_keep_the_longest() {
        let a = Finding::new("a", "t", Category::Image, 0, 100);
        let b = Finding::new("b", "t", Category::Image, 10, 20);
        let c = Finding::new("c", "t", Category::Archive, 10, 20);
        let kept = dedupe_overlapping(vec![b, a, c]);
        assert_eq!(kept.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec!["a", "c"]);
    }
}
